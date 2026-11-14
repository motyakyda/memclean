//! memclean — умный фоновый очищатор ОЗУ для слабых ПК.
//!
//! Идея: не "чистить всё подряд по таймеру" (это только вызывает подкачку),
//! а при реальной нехватке памяти выдавливать рабочие наборы *простаивающих*
//! фоновых процессов, чтобы активной программе досталось больше RAM.
//!
//! Что делает "умно":
//! * гистерезис: начинает при загрузке >= trigger_load, останавливается на target_load;
//! * трогает только процессы, которые не жрут CPU (реально простаивают);
//! * никогда не трогает окно на переднем плане и недавно активные окна (alt-tab);
//! * если процесс после очистки быстро "отрастил" память обратно — значит он нужен,
//!   кулдаун для него удваивается (до x16), чтобы не было пинг-понга с подкачкой;
//! * когда пользователь отошёл от ПК — работает агрессивнее;
//! * лимит на объём за один проход, чтобы не забить диск записью в pagefile;
//! * сам сидит на idle-приоритете в фоновом режиме и держит себя ~1-2 МБ.
//!
//! Запуск:
//!   memclean.exe              — фоновый режим (без окна)
//!   memclean.exe --once       — один агрессивный проход, вывод в консоль
//!   memclean.exe --status     — состояние памяти и хвост лога
//!   memclean.exe --install    — скопировать в %LOCALAPPDATA%\memclean и включить автозапуск
//!   memclean.exe --uninstall  — убрать автозапуск и остановить

#![windows_subsystem = "windows"]

use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, SE_PROF_SINGLE_PROCESS_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    K32EmptyWorkingSet, K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
use windows_sys::Win32::System::SystemInformation::{
    GetLocalTime, GetTickCount, GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX,
};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, IDLE_PRIORITY_CLASS,
    OpenProcess, OpenProcessToken, PROCESS_MODE_BACKGROUND_BEGIN, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_QUOTA, SetPriorityClass,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows_sys::core::w;

const MB: u64 = 1024 * 1024;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const APP: &str = "memclean";

/// Процессы, которые трогать нельзя или бессмысленно (тормоза ввода/звука/рабочего стола).
const ALWAYS_EXCLUDE: &[&str] = &[
    "system",
    "registry",
    "memory compression",
    "secure system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "dwm.exe",
    "audiodg.exe",
    "fontdrvhost.exe",
    "ctfmon.exe",
    "explorer.exe",
    "textinputhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "sihost.exe",
    "memclean.exe",
    "bestdesk.exe",
];

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtSetSystemInformation(class: u32, info: *mut c_void, len: u32) -> i32;
}
const SYSTEM_COMBINE_PHYSICAL_MEMORY_INFORMATION: u32 = 130;
#[repr(C)]
struct MemoryCombineInfoEx {
    handle: HANDLE,
    pages_combined: usize,
    flags: u32,
}

// ---------------------------------------------------------------- config

struct Cfg {
    interval_sec: u64,
    trigger_load: u32,
    target_load: u32,
    min_ws_mb: u64,
    idle_cpu_pct: f64,
    cooldown_sec: u64,
    max_trim_mb_per_pass: u64,
    recent_fg_sec: u64,
    user_away_sec: u64,
    combine: bool,
    exclude: Vec<String>,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            interval_sec: 5,
            trigger_load: 82,
            target_load: 72,
            min_ws_mb: 25,
            idle_cpu_pct: 1.0,
            cooldown_sec: 300,
            max_trim_mb_per_pass: 400,
            recent_fg_sec: 120,
            user_away_sec: 180,
            combine: true,
            exclude: Vec::new(),
        }
    }
}

const DEFAULT_INI: &str = "\
# memclean — настройки. После изменения перезапусти memclean (или перелогинься).
# Загрузка памяти (%), при которой начинается очистка
trigger_load=82
# До какой загрузки (%) чистить, потом стоп (гистерезис)
target_load=72
# Как часто проверять память, сек (при нехватке — автоматически каждые 2 сек)
interval_sec=5
# Не трогать процессы с рабочим набором меньше N МБ
min_ws_mb=25
# Процесс считается простаивающим, если ест меньше N% одного ядра
idle_cpu_pct=1.0
# Минимальная пауза перед повторной очисткой того же процесса, сек
cooldown_sec=300
# Максимум МБ, выдавливаемых за один проход (бережёт диск)
max_trim_mb_per_pass=400
# Сколько секунд защищать окно после ухода с него (alt-tab)
recent_fg_sec=120
# Через сколько секунд бездействия пользователя работать агрессивнее
user_away_sec=180
# Дедупликация одинаковых страниц памяти, когда ты отошёл (нужен админ): 1/0
combine=1
# Доп. исключения через запятую, например: obs64.exe,discord.exe
exclude=
";

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn load_cfg() -> Cfg {
    let path = exe_dir().join("memclean.ini");
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => {
            let _ = fs::write(&path, DEFAULT_INI);
            DEFAULT_INI.to_string()
        }
    };
    let mut c = Cfg::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        let num = |d: u64| v.parse::<u64>().unwrap_or(d);
        match k {
            "interval_sec" => c.interval_sec = num(c.interval_sec).clamp(1, 600),
            "trigger_load" => c.trigger_load = num(c.trigger_load as u64).clamp(30, 99) as u32,
            "target_load" => c.target_load = num(c.target_load as u64).clamp(20, 98) as u32,
            "min_ws_mb" => c.min_ws_mb = num(c.min_ws_mb),
            "idle_cpu_pct" => c.idle_cpu_pct = v.parse().unwrap_or(c.idle_cpu_pct),
            "cooldown_sec" => c.cooldown_sec = num(c.cooldown_sec),
            "max_trim_mb_per_pass" => c.max_trim_mb_per_pass = num(c.max_trim_mb_per_pass).max(16),
            "recent_fg_sec" => c.recent_fg_sec = num(c.recent_fg_sec),
            "user_away_sec" => c.user_away_sec = num(c.user_away_sec),
            "combine" => c.combine = v != "0",
            "exclude" => {
                c.exclude = v
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            _ => {}
        }
    }
    if c.target_load >= c.trigger_load {
        c.target_load = c.trigger_load.saturating_sub(5);
    }
    c
}

// ---------------------------------------------------------------- logging

fn now_str() -> String {
    unsafe {
        let mut t = std::mem::zeroed();
        GetLocalTime(&mut t);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        )
    }
}

fn log(msg: &str) {
    let path = exe_dir().join("memclean.log");
    if fs::metadata(&path).map(|m| m.len() > 512 * 1024).unwrap_or(false) {
        let _ = fs::rename(&path, exe_dir().join("memclean.log.old"));
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{} {}", now_str(), msg);
    }
}

// ---------------------------------------------------------------- win32 helpers

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn ft(f: &FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

fn mem_status() -> MEMORYSTATUSEX {
    unsafe {
        let mut m: MEMORYSTATUSEX = std::mem::zeroed();
        m.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut m);
        m
    }
}

fn foreground_pid() -> u32 {
    unsafe {
        let mut pid = 0u32;
        let hwnd = GetForegroundWindow();
        if !hwnd.is_null() {
            GetWindowThreadProcessId(hwnd, &mut pid);
        }
        pid
    }
}

fn user_idle_ms() -> u32 {
    unsafe {
        let mut li = LASTINPUTINFO { cbSize: size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        if GetLastInputInfo(&mut li) == 0 {
            return 0;
        }
        GetTickCount().wrapping_sub(li.dwTime)
    }
}

fn enable_privilege(name: windows_sys::core::PCWSTR) -> bool {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let tok = Handle(tok);
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        if LookupPrivilegeValueW(std::ptr::null(), name, &mut luid) == 0 {
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        AdjustTokenPrivileges(tok.0, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0
            && GetLastError() == 0
    }
}

fn working_set(h: HANDLE) -> Option<u64> {
    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if K32GetProcessMemoryInfo(h, &mut pmc, pmc.cb) == 0 {
            return None;
        }
        Some(pmc.WorkingSetSize as u64)
    }
}

/// Дедупликация одинаковых физических страниц (Win10+). Возвращает освобождённые байты.
fn combine_memory() -> Option<u64> {
    let mut info = MemoryCombineInfoEx { handle: std::ptr::null_mut(), pages_combined: 0, flags: 0 };
    let st = unsafe {
        NtSetSystemInformation(
            SYSTEM_COMBINE_PHYSICAL_MEMORY_INFORMATION,
            &mut info as *mut _ as *mut c_void,
            size_of::<MemoryCombineInfoEx>() as u32,
        )
    };
    (st >= 0).then_some(info.pages_combined as u64 * 4096)
}

// ---------------------------------------------------------------- process sampling

struct Sample {
    key: (u32, u64), // pid + creation time (защита от переиспользования pid)
    name: String,
    ws: u64,
    cpu_pct: Option<f64>,
    h: Handle,
}

#[derive(Default)]
struct Track {
    cpu: u64,
    seen: u64,
    trimmed_at: u64,
    ws_before: u64,
    ws_after: u64,
    regrow_checked: bool,
    backoff: u32,
}

struct State {
    cfg: Cfg,
    tracks: HashMap<(u32, u64), Track>,
    recent_fg: HashMap<u32, u64>,
    self_pid: u32,
    admin: bool,
    cleaning: bool,
    last_combine: u64,
}

impl State {
    fn excluded(&self, name: &str) -> bool {
        ALWAYS_EXCLUDE.contains(&name) || self.cfg.exclude.iter().any(|e| e == name)
    }

    /// Снимок всех процессов + обновление статистики CPU и детектор "отрастания" памяти.
    fn sample(&mut self, now: u64) -> Vec<Sample> {
        let mut out = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let snap = Handle(snap);
            let mut pe: PROCESSENTRY32W = std::mem::zeroed();
            pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap.0, &mut pe) != 0;
            while ok {
                let pid = pe.th32ProcessID;
                if pid > 4 && pid != self.self_pid {
                    let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
                    let name = String::from_utf16_lossy(&pe.szExeFile[..len]).to_lowercase();
                    if !self.excluded(&name) {
                        if let Some(s) = self.sample_one(pid, name, now) {
                            out.push(s);
                        }
                    }
                }
                ok = Process32NextW(snap.0, &mut pe) != 0;
            }
        }
        // выкинуть умершие процессы
        self.tracks.retain(|_, t| t.seen == now);
        out
    }

    unsafe fn sample_one(&mut self, pid: u32, name: String, now: u64) -> Option<Sample> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, 0, pid) };
        if h.is_null() {
            return None;
        }
        let h = Handle(h);
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        if unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } == 0 {
            return None;
        }
        let ws = working_set(h.0)?;
        let key = (pid, ft(&c));
        let cpu = ft(&k) + ft(&u);
        let t = self.tracks.entry(key).or_insert_with(|| Track { backoff: 1, ..Default::default() });

        let cpu_pct = if t.seen > 0 && now > t.seen && now - t.seen <= 30_000 {
            // cpu в 100нс, wall в мс → % одного ядра
            Some((cpu.saturating_sub(t.cpu)) as f64 / ((now - t.seen) as f64 * 10_000.0) * 100.0)
        } else {
            None
        };
        t.cpu = cpu;
        t.seen = now;

        // процесс "отрастил" память после очистки → он реально нужен, реже его трогаем
        if t.trimmed_at > 0 && !t.regrow_checked {
            let freed = t.ws_before.saturating_sub(t.ws_after);
            if ws > t.ws_after + freed * 7 / 10 {
                t.regrow_checked = true;
                if now - t.trimmed_at < 60_000 {
                    t.backoff = (t.backoff * 2).min(16);
                    log(&format!("{name}: быстро вернул память, кулдаун x{}", t.backoff));
                }
            } else if now - t.trimmed_at >= 60_000 {
                t.regrow_checked = true;
                t.backoff = (t.backoff / 2).max(1);
            }
        }
        Some(Sample { key, name, ws, cpu_pct, h })
    }

    /// Один проход очистки. `need` — сколько байт хотим освободить.
    fn clean(&mut self, procs: &[Sample], now: u64, need: u64, force: bool) -> (u64, Vec<String>) {
        let fg = foreground_pid();
        let away = user_idle_ms() as u64 >= self.cfg.user_away_sec * 1000;
        let emergency = mem_status().dwMemoryLoad >= 95;
        let min_ws = if away || force { self.cfg.min_ws_mb * MB / 2 } else { self.cfg.min_ws_mb * MB };
        let idle_cpu = if away { self.cfg.idle_cpu_pct * 3.0 } else { self.cfg.idle_cpu_pct };
        let budget = if force { u64::MAX } else { self.cfg.max_trim_mb_per_pass * MB };

        let mut cand: Vec<&Sample> = procs
            .iter()
            .filter(|s| {
                let pid = s.key.0;
                if pid == fg || s.ws < min_ws {
                    return false;
                }
                if !emergency && !force {
                    if let Some(&t) = self.recent_fg.get(&pid) {
                        if now - t < self.cfg.recent_fg_sec * 1000 {
                            return false;
                        }
                    }
                }
                match s.cpu_pct {
                    Some(p) if p <= idle_cpu => {}
                    _ => return false,
                }
                let t = &self.tracks[&s.key];
                let mult = if emergency || force { 1 } else { t.backoff as u64 };
                t.trimmed_at == 0 || now - t.trimmed_at >= self.cfg.cooldown_sec * 1000 * mult
            })
            .collect();
        cand.sort_by(|a, b| b.ws.cmp(&a.ws));

        let mut freed = 0u64;
        let mut report = Vec::new();
        for s in cand {
            if freed >= need || freed >= budget {
                break;
            }
            if unsafe { K32EmptyWorkingSet(s.h.0) } == 0 {
                continue;
            }
            let after = working_set(s.h.0).unwrap_or(s.ws);
            let got = s.ws.saturating_sub(after);
            freed += got;
            if let Some(t) = self.tracks.get_mut(&s.key) {
                t.trimmed_at = now;
                t.ws_before = s.ws;
                t.ws_after = after;
                t.regrow_checked = false;
            }
            if got >= MB {
                report.push(format!("{} {}M", s.name, got / MB));
            }
        }
        (freed, report)
    }

    fn tick(&mut self) -> u64 {
        let now = unsafe { GetTickCount64() };
        let m = mem_status();
        let load = m.dwMemoryLoad;

        let fg = foreground_pid();
        if fg != 0 {
            self.recent_fg.insert(fg, now);
        }
        self.recent_fg.retain(|_, t| now - *t < self.cfg.recent_fg_sec * 1000);

        let warm = load + 10 >= self.cfg.trigger_load;
        if !warm {
            self.cleaning = false;
            return self.cfg.interval_sec * 3000;
        }

        let procs = self.sample(now);
        if load >= self.cfg.trigger_load && !self.cleaning {
            self.cleaning = true;
        }
        if self.cleaning && load <= self.cfg.target_load {
            self.cleaning = false;
        }

        if self.cleaning {
            let need = (m.ullTotalPhys / 100 * (load - self.cfg.target_load) as u64).max(64 * MB);
            let (freed, rep) = self.clean(&procs, now, need, false);
            if freed > 0 {
                let after = mem_status().dwMemoryLoad;
                log(&format!(
                    "загрузка {load}% -> {after}%, освобождено ~{} МБ: {}",
                    freed / MB,
                    rep.join(", ")
                ));
            }

            let away = user_idle_ms() as u64 >= self.cfg.user_away_sec * 1000;
            if self.cfg.combine && self.admin && away && now - self.last_combine > 15 * 60_000 {
                self.last_combine = now;
                if let Some(b) = combine_memory() {
                    if b >= MB {
                        log(&format!("дедупликация страниц: ~{} МБ", b / MB));
                    }
                }
            }
        }
        drop(procs);
        // держим себя маленьким
        unsafe { K32EmptyWorkingSet(GetCurrentProcess()) };

        if self.cleaning { 2000 } else { self.cfg.interval_sec * 1000 }
    }
}

fn new_state() -> State {
    let admin = unsafe { IsUserAnAdmin() } != 0;
    enable_privilege(SE_DEBUG_NAME);
    enable_privilege(SE_PROF_SINGLE_PROCESS_NAME);
    State {
        cfg: load_cfg(),
        tracks: HashMap::new(),
        recent_fg: HashMap::new(),
        self_pid: unsafe { GetCurrentProcessId() },
        admin,
        cleaning: false,
        last_combine: 0,
    }
}

// ---------------------------------------------------------------- modes

fn run_daemon() {
    unsafe {
        let m = CreateMutexW(std::ptr::null(), 0, w!("Local\\memclean_single_instance"));
        if m.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
            return; // уже запущен
        }
        std::mem::forget(Handle(m));
        SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
        SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
    }
    let mut st = new_state();
    let m = mem_status();
    log(&format!(
        "старт: ОЗУ {} МБ, порог {}% -> {}%, админ: {}",
        m.ullTotalPhys / MB,
        st.cfg.trigger_load,
        st.cfg.target_load,
        if st.admin { "да" } else { "нет (только свои процессы)" }
    ));
    loop {
        let sleep = st.tick();
        std::thread::sleep(Duration::from_millis(sleep));
    }
}

fn print_mem(label: &str) {
    let m = mem_status();
    println!(
        "{label}: загрузка {}%, свободно {} из {} МБ, файл подкачки свободно {} МБ",
        m.dwMemoryLoad,
        m.ullAvailPhys / MB,
        m.ullTotalPhys / MB,
        m.ullAvailPageFile / MB
    );
}

fn run_once() {
    let mut st = new_state();
    print_mem("до");
    let t0 = unsafe { GetTickCount64() };
    st.sample(t0);
    std::thread::sleep(Duration::from_millis(1500));
    let now = unsafe { GetTickCount64() };
    let procs = st.sample(now);
    let (freed, rep) = st.clean(&procs, now, u64::MAX, true);
    for r in &rep {
        println!("  {r}");
    }
    println!("освобождено рабочих наборов ~{} МБ (простаивающие процессы)", freed / MB);
    if st.admin && st.cfg.combine {
        if let Some(b) = combine_memory() {
            println!("дедупликация страниц ~{} МБ", b / MB);
        }
    }
    print_mem("после");
    log(&format!("--once: освобождено ~{} МБ", freed / MB));
}

fn running_pids() -> Vec<u32> {
    let me = unsafe { GetCurrentProcessId() };
    let mut v = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return v;
        }
        let snap = Handle(snap);
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap.0, &mut pe) != 0;
        while ok {
            let len = pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let name = String::from_utf16_lossy(&pe.szExeFile[..len]).to_lowercase();
            if name == "memclean.exe" && pe.th32ProcessID != me {
                v.push(pe.th32ProcessID);
            }
            ok = Process32NextW(snap.0, &mut pe) != 0;
        }
    }
    v
}

fn run_status() {
    print_mem("память");
    let pids = running_pids();
    if pids.is_empty() {
        println!("memclean в фоне: НЕ запущен");
    } else {
        println!("memclean в фоне: работает (pid {pids:?})");
    }
    let dir = install_dir();
    for d in [exe_dir(), dir] {
        if let Ok(t) = fs::read_to_string(d.join("memclean.log")) {
            println!("--- {}", d.join("memclean.log").display());
            let lines: Vec<&str> = t.lines().collect();
            for l in &lines[lines.len().saturating_sub(15)..] {
                println!("{l}");
            }
            break;
        }
    }
}

fn install_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into())).join(APP)
}

fn quiet(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn stop_others() {
    for pid in running_pids() {
        quiet("taskkill", &["/F", "/PID", &pid.to_string()]);
    }
}

fn write_task_xml(exe: &Path) -> Option<PathBuf> {
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default()
    );
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>memclean: smart RAM trimmer</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{}</Command></Exec></Actions>
</Task>"#,
        exe.display()
    );
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let p = std::env::temp_dir().join("memclean_task.xml");
    fs::write(&p, bytes).ok()?;
    Some(p)
}

fn run_install() {
    let dir = install_dir();
    let _ = fs::create_dir_all(&dir);
    let target = dir.join("memclean.exe");
    stop_others();
    std::thread::sleep(Duration::from_millis(500));
    let src = std::env::current_exe().expect("current_exe");
    if src != target {
        if let Err(e) = fs::copy(&src, &target) {
            println!("не удалось скопировать в {}: {e}", target.display());
            return;
        }
    }
    let admin = unsafe { IsUserAnAdmin() } != 0;
    let mut how = "";
    if admin {
        if let Some(xml) = write_task_xml(&target) {
            let x = xml.to_string_lossy().to_string();
            if quiet("schtasks", &["/Create", "/TN", APP, "/XML", &x, "/F"]) {
                // если раньше стоял HKCU\Run — убираем, чтобы не было двух способов запуска
                quiet("reg", &["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", APP, "/f"]);
                how = "планировщик задач (с правами админа)";
            }
            let _ = fs::remove_file(xml);
        }
    }
    if how.is_empty() {
        let val = format!("\"{}\"", target.display());
        if quiet("reg", &["add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", APP, "/d", &val, "/f"]) {
            how = "HKCU\\Run (без админа — чистит только твои процессы)";
        } else {
            println!("не удалось включить автозапуск");
            return;
        }
    }
    // полностью отвязать от консоли/пайпов родителя
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    unsafe {
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        for s in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            SetHandleInformation(GetStdHandle(s), HANDLE_FLAG_INHERIT, 0);
        }
    }
    let _ = Command::new(&target)
        .current_dir(&dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn();
    println!("установлено: {}", target.display());
    println!("автозапуск: {how}");
    println!("настройки: {}", dir.join("memclean.ini").display());
    println!("лог:       {}", dir.join("memclean.log").display());
}

fn run_uninstall() {
    quiet("schtasks", &["/Delete", "/TN", APP, "/F"]);
    quiet("reg", &["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", APP, "/f"]);
    stop_others();
    println!("автозапуск убран, фоновый memclean остановлен");
    println!("файлы остались в {} — удали папку вручную, если не нужна", install_dir().display());
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if !arg.is_empty() {
        unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
    }
    match arg.as_str() {
        "" => run_daemon(),
        "--once" => run_once(),
        "--status" => run_status(),
        "--install" => run_install(),
        "--uninstall" => run_uninstall(),
        _ => println!("memclean [--once | --status | --install | --uninstall]"),
    }
}
