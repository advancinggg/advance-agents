//! In-process pid-lock probe used under [`ProcessPolicy::Forbid`](advance_shared_types::process_policy::ProcessPolicy).
//!
//! Gate A is `kill(pid, 0)`. Gate B reads the process start time in-process (ADR 2026-10-03
//! D3): [`platform_uid`] writes the `lstart` bytes `ps -o lstart=` prints for that process
//! under this process's LANG / LC_* / TZ, and [`platform_uid_names`] reads a lock by start
//! instant, so a lock that `ps` wrote under another locale, time zone or procps-ng version
//! still names its live writer. Do not mutate the process environment while a Forbid lock
//! read or compose runs: TZ and the locale variables are read through libc.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::ffi::CStr;

/// The `lstart` of a writer that could not read a start time: its `ps` failed or is absent.
const UNKNOWN_LSTART: &str = "unknown";

/// The locale [`format_time`] renders under: the env-derived locale `ps` gets from
/// `setlocale(LC_ALL, "")` (`Env`), or "C" (`C`).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocaleChoice {
    Env,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    C,
}

/// `kill(pid, 0) == 0`; any error (ESRCH, EPERM) → false, exactly as `kill -0` exits non-zero;
/// a pid above `i32::MAX` → false (never handed to `kill`, which would address a process group).
/// Pid 0 addresses the caller's own process group, so a lock naming pid 0 reads as alive, the
/// verdict `kill -0 0` gives.
pub(crate) fn pid_alive(pid: u32) -> bool {
    if pid > i32::MAX as u32 {
        return false;
    }
    #[cfg(unix)]
    {
        ffi::pid_alive(pid as i32)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// `"{os}:{pid}:{lstart}"`, `lstart` = the bytes `ps -o lstart= -p <pid>` prints for that
/// process under this process's LANG / LC_* / TZ, `.trim()`ed; `"unknown"` when the start
/// time cannot be read (as when `ps` fails).
pub(crate) fn platform_uid(pid: u32) -> String {
    uid_with_start(pid, start_secs(pid))
}

fn uid_with_start(pid: u32, start: Option<i64>) -> String {
    let lstart = start
        .and_then(render_lstart)
        .unwrap_or_else(|| UNKNOWN_LSTART.to_string());
    format!("{}:{}:{}", std::env::consts::OS, pid, lstart)
}

/// Gate B under `Forbid`: whether `stored`, the `platform_uid` of a lock that names `pid`,
/// names the process that has that pid now. Its OS and pid parts must be this OS and `pid`,
/// and its `lstart` must be
/// - byte-identical to this probe's [`platform_uid`] (the rule of the `ps`-based probe), or
/// - `"unknown"`: the writer's `ps` failed or was absent, so the pid alone names the process,
///   as it does for the `ps`-based probe on such a host, or
/// - the process's start instant in any rendering a `ps` prints ([`lstart_names_start`]), so a
///   lock written by `ps` under another locale, time zone or procps-ng version names its live
///   writer and is never taken over.
pub(crate) fn platform_uid_names(pid: u32, stored: &str) -> bool {
    let start = start_secs(pid);
    if stored == uid_with_start(pid, start) {
        return true;
    }
    let Some(lstart) = stored_lstart(stored, pid) else {
        return false;
    };
    lstart == UNKNOWN_LSTART || start.is_some_and(|start| lstart_names_start(lstart, start))
}

/// The `lstart` part of `stored` when its OS part is this OS and its pid part is `pid`.
fn stored_lstart(stored: &str, pid: u32) -> Option<&str> {
    let rest = stored
        .strip_prefix(std::env::consts::OS)?
        .strip_prefix(':')?;
    let (stored_pid, lstart) = rest.split_once(':')?;
    (stored_pid == pid.to_string()).then_some(lstart)
}

/// Start of process `pid` in whole seconds since the epoch, the instant `ps -o lstart=` prints:
/// `pbi_start_tvsec` on macOS, `btime + starttime / CLK_TCK` on Linux (procps-ng's formula).
pub(crate) fn start_secs(pid: u32) -> Option<i64> {
    #[cfg(target_os = "macos")]
    {
        ffi::macos_start_tvsec(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux_start_secs(pid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

/// `start` as `ps -o lstart=` prints it on this host under this process's LANG / LC_* / TZ:
/// BSD `ps` prints `strftime("%c")`; procps-ng 4.0.3 and later print
/// `strftime("%a %b %e %H:%M:%S %Y")`, and earlier procps-ng `ctime()`, which is that layout
/// with English names whatever the locale ([`procps_prints_ctime`]).
fn render_lstart(start: i64) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        format_time(start, c"%c", LocaleChoice::Env)
    }
    #[cfg(target_os = "linux")]
    {
        let locale = if procps_prints_ctime() {
            LocaleChoice::C
        } else {
            LocaleChoice::Env
        };
        format_time(start, c"%a %b %e %H:%M:%S %Y", locale)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = start;
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_start_secs(pid: u32) -> Option<i64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    let starttime: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
    let btime = linux_btime()?;
    let hz = ffi::clk_tck()?;
    btime.checked_add(i64::try_from(starttime / hz).ok()?)
}

#[cfg(target_os = "linux")]
fn linux_btime() -> Option<i64> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Whether the `ps` the `ps`-based probe runs is procps-ng before 4.0.3, which prints
/// `lstart` with `ctime()`: English names in every locale. Read once, without running it,
/// from the `procps-ng <version>` string of the first `ps` on PATH; any other `ps`, or none,
/// counts as printing `strftime` in the env locale.
#[cfg(target_os = "linux")]
fn procps_prints_ctime() -> bool {
    static PRINTS_CTIME: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PRINTS_CTIME.get_or_init(|| {
        ps_on_path()
            .and_then(|ps| read_prefix(&ps, PS_BINARY_READ_LIMIT))
            .and_then(|bytes| procps_ng_version(&bytes))
            .is_some_and(prints_ctime)
    })
}

/// How much of the `ps` binary [`procps_prints_ctime`] reads.
#[cfg(target_os = "linux")]
const PS_BINARY_READ_LIMIT: u64 = 16 << 20;

/// The `ps` that `Command::new("ps")` runs: the first executable `ps` file on PATH.
#[cfg(target_os = "linux")]
fn ps_on_path() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("ps"))
        .find(|ps| {
            std::fs::metadata(ps)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

#[cfg(target_os = "linux")]
fn read_prefix(path: &std::path::Path, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

/// The version of the first `procps-ng <major>.<minor>[.<patch>]` in `bytes`.
#[cfg(any(target_os = "linux", test))]
fn procps_ng_version(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    const MARK: &[u8] = b"procps-ng ";
    let at = bytes.windows(MARK.len()).position(|w| w == MARK)? + MARK.len();
    let digits: Vec<u8> = bytes[at..]
        .iter()
        .take_while(|b| b.is_ascii_digit() || **b == b'.')
        .copied()
        .collect();
    let text = std::str::from_utf8(&digits).ok()?;
    let mut parts = text.split('.').map(str::parse::<u32>);
    let major = parts.next()?.ok()?;
    let minor = parts.next()?.ok()?;
    let patch = match parts.next() {
        Some(patch) => patch.ok()?,
        None => 0,
    };
    Some((major, minor, patch))
}

/// procps-ng prints `lstart` with `ctime()` before 4.0.3 and with `strftime` in the env locale
/// from 4.0.3 on.
#[cfg(any(target_os = "linux", test))]
fn prints_ctime(version: (u32, u32, u32)) -> bool {
    version < (4, 0, 3)
}

// ---------------------------------------------------------------------------
// Reading a `ps` rendering of a start instant
// ---------------------------------------------------------------------------

/// The UTC offsets a time zone uses: whole quarter hours from −12:00 to +14:00.
const QUARTER_HOUR_SECS: i64 = 15 * 60;
const MIN_OFFSET_QUARTERS: i64 = -12 * 4;
const MAX_OFFSET_QUARTERS: i64 = 14 * 4;

/// Weekday and month names as the C locale (and every procps-ng before 4.0.3) prints them.
const ENGLISH_WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const ENGLISH_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Whether `lstart`, a start time as a `ps -o lstart=` printed it, names the instant `start`
/// (whole seconds since the epoch).
///
/// `ps` prints the start in its own time zone and locale: procps-ng before 4.0.3 prints
/// `ctime()` (`Fri Oct  9 09:33:38 2026`, English in every locale), procps-ng 4.0.3 and later
/// `strftime("%a %b %e %H:%M:%S %Y")` in its locale (`Fr Okt  9 …`, `五 10月  9 …`), macOS
/// `strftime("%c")` in its locale (`Fri  9 Oct …`, `五 10月/ 9 …`,
/// `2026년 10월  9일 금요일 02시 41분 22초`). `lstart` names `start` when, at some UTC offset a
/// time zone uses, its numbers are that instant's wall-clock fields: three consecutive numbers
/// are the hour, minute and second; one is the year (four digits, or its last two); the rest
/// are the day of the month, or the month and then the day. A number written right after an
/// ASCII letter (part of a name, such as Luganda's `Lw2`) or a sign (a numeric zone name, such
/// as `+0330`) is not a field; padding and separators do not count. An English rendering (its
/// first word an English weekday name) must also carry that instant's weekday and month names.
///
/// Names in other languages are not interpreted, and the writer's offset is not recorded, so a
/// start a whole number of months later (same day and time), or a whole number of quarter
/// hours away within 26 hours (same second), also matches. Such a match keeps a dead writer's
/// lock live only until its heartbeat ages out; a missed match would take over a live writer's
/// lock.
pub(crate) fn lstart_names_start(lstart: &str, start: i64) -> bool {
    let numbers = numbers_in(lstart);
    if !(5..=6).contains(&numbers.len()) {
        return false;
    }
    (MIN_OFFSET_QUARTERS..=MAX_OFFSET_QUARTERS).any(|quarters| {
        let Some(wall) = start.checked_add(quarters * QUARTER_HOUR_SECS) else {
            return false;
        };
        let civil = Civil::at(wall);
        numbers_are(&numbers, &civil) && english_names_are(lstart, &civil)
    })
}

/// A number in a rendering and how many digits it was written with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Number {
    value: u64,
    digits: usize,
}

/// The numbers of `lstart` in order, without those written right after an ASCII letter or a
/// sign (see [`lstart_names_start`]).
fn numbers_in(lstart: &str) -> Vec<Number> {
    let mut numbers = Vec::new();
    let mut before_run: Option<char> = None;
    let mut run: Option<(Number, Option<char>)> = None;
    for ch in lstart.chars() {
        if let Some(digit) = ch.to_digit(10) {
            let (number, _) = run.get_or_insert((
                Number {
                    value: 0,
                    digits: 0,
                },
                before_run,
            ));
            number.value = number
                .value
                .saturating_mul(10)
                .saturating_add(u64::from(digit));
            number.digits += 1;
        } else {
            if let Some((number, before)) = run.take() {
                keep_field(&mut numbers, number, before);
            }
            before_run = Some(ch);
        }
    }
    if let Some((number, before)) = run.take() {
        keep_field(&mut numbers, number, before);
    }
    numbers
}

fn keep_field(numbers: &mut Vec<Number>, number: Number, before: Option<char>) {
    let attached = before.is_some_and(|c| c.is_ascii_alphabetic() || c == '+' || c == '-');
    if !attached {
        numbers.push(number);
    }
}

/// Whether `numbers` are `civil`'s time of day, year and day (and month) as described in
/// [`lstart_names_start`].
fn numbers_are(numbers: &[Number], civil: &Civil) -> bool {
    let field = |n: &Number, value: u32| (1..=2).contains(&n.digits) && n.value == u64::from(value);
    let year = |n: &Number| match (n.digits, u64::try_from(civil.year)) {
        (4, Ok(year)) => n.value == year,
        (2, Ok(year)) => n.value == year % 100,
        _ => false,
    };
    (0..numbers.len().saturating_sub(2)).any(|i| {
        let time_of_day = field(&numbers[i], civil.hour)
            && field(&numbers[i + 1], civil.minute)
            && field(&numbers[i + 2], civil.second);
        if !time_of_day {
            return false;
        }
        let rest: Vec<Number> = numbers[..i]
            .iter()
            .chain(&numbers[i + 3..])
            .copied()
            .collect();
        (0..rest.len()).any(|j| {
            if !year(&rest[j]) {
                return false;
            }
            let date: Vec<Number> = rest[..j].iter().chain(&rest[j + 1..]).copied().collect();
            match date.as_slice() {
                [day] => field(day, civil.day),
                [month, day] => field(month, civil.month) && field(day, civil.day),
                _ => false,
            }
        })
    })
}

/// Whether the English names of `lstart`, when it is English (its first word an English
/// weekday name), are `civil`'s weekday and month.
fn english_names_are(lstart: &str, civil: &Civil) -> bool {
    let mut words = lstart.split_whitespace();
    match words.next() {
        Some(first) if ENGLISH_WEEKDAYS.contains(&first) => {
            first == ENGLISH_WEEKDAYS[civil.weekday]
                && words.all(|word| {
                    !ENGLISH_MONTHS.contains(&word) || word == ENGLISH_MONTHS[civil.month0()]
                })
        }
        _ => true,
    }
}

/// A date and time of day on the UTC (proleptic Gregorian) calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Civil {
    year: i64,
    /// 1..=12
    month: u32,
    /// 1..=31
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    /// 0 = Sunday
    weekday: usize,
}

impl Civil {
    /// The UTC date and time `secs` seconds after the epoch (days-from-civil inverted, as in
    /// H. Hinnant's "chrono-Compatible Low-Level Date Algorithms").
    fn at(secs: i64) -> Self {
        let days = secs.div_euclid(86_400);
        let time_of_day = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let day_of_era = z.rem_euclid(146_097);
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_from_march = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
        let month = if month_from_march < 10 {
            month_from_march + 3
        } else {
            month_from_march - 9
        };
        Civil {
            year: era * 400 + year_of_era + i64::from(month <= 2),
            month: month as u32,
            day: day as u32,
            hour: (time_of_day / 3_600) as u32,
            minute: (time_of_day % 3_600 / 60) as u32,
            second: (time_of_day % 60) as u32,
            // 1970-01-01 was a Thursday.
            weekday: (days + 4).rem_euclid(7) as usize,
        }
    }

    fn month0(&self) -> usize {
        self.month as usize - 1
    }
}

// ---------------------------------------------------------------------------
// Rendering a start instant
// ---------------------------------------------------------------------------

/// `strftime_l(fmt)` of `t` in this process's time zone under `locale`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn format_time(t: i64, fmt: &CStr, locale: LocaleChoice) -> Option<String> {
    match locale {
        // The env-derived locale `ps` gets from `setlocale(LC_ALL, "")`, or "C" when it is not
        // valid, as a failed `setlocale` leaves `ps`.
        LocaleChoice::Env => ffi::format_time(t, fmt, c"", true),
        LocaleChoice::C => ffi::format_time(t, fmt, c"C", false),
    }
}

/// Test seam: `strftime_l(fmt)` of `t` in this process's time zone under the locale named
/// `locale`; `None` when it is not installed.
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(crate) fn format_time_in(t: i64, fmt: &CStr, locale: &CStr) -> Option<String> {
    ffi::format_time(t, fmt, locale, false)
}

/// The one FFI module of this crate: `kill`, `proc_pidinfo`, `tzset`, `localtime_r`,
/// `newlocale`, `strftime_l`, `freelocale`, `sysconf`. Every block is a single libc
/// query whose pointers this module keeps alive for the duration of the call.
#[allow(unsafe_code)]
mod ffi {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::ffi::CStr;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::mem::MaybeUninit;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::ptr;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe extern "C" {
        fn tzset();
    }

    #[cfg(unix)]
    pub(super) fn pid_alive(pid: i32) -> bool {
        // SAFETY: `kill(pid, 0)` is a liveness query. `pid` is a process id, or 0
        // which addresses the caller's process group — the same as `kill -0 0`.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn macos_start_tvsec(pid: u32) -> Option<i64> {
        if pid > i32::MAX as u32 {
            return None;
        }
        let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: `info` is a `proc_bsdinfo`-sized buffer; `PROC_PIDTBSDINFO` writes
        // that type. A short write is rejected before `assume_init`.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if n != size {
            return None;
        }
        // SAFETY: `proc_pidinfo` returned the full size, so every field is written.
        let info = unsafe { info.assume_init() };
        i64::try_from(info.pbi_start_tvsec).ok()
    }

    #[cfg(target_os = "linux")]
    pub(super) fn clk_tck() -> Option<u64> {
        // SAFETY: `sysconf(_SC_CLK_TCK)` is a query with no pointer arguments.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            None
        } else {
            u64::try_from(hz).ok()
        }
    }

    /// `strftime_l(fmt)` of `t` in this process's time zone under the locale `name` (`""`:
    /// the env-derived one). When `newlocale` refuses `name`: the "C" locale if
    /// `fall_back_to_c`, else `None`.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn format_time(
        t: i64,
        fmt: &CStr,
        name: &CStr,
        fall_back_to_c: bool,
    ) -> Option<String> {
        let time = libc::time_t::try_from(t).ok()?;
        let mut tm = MaybeUninit::<libc::tm>::zeroed();
        // SAFETY: `tzset` re-reads TZ from the environment. `localtime_r` writes
        // `tm` and returns null on failure; the pointer is not retained.
        let tm_ptr = unsafe {
            tzset();
            libc::localtime_r(&time, tm.as_mut_ptr())
        };
        if tm_ptr.is_null() {
            return None;
        }
        // SAFETY: `localtime_r` returned non-null, so `tm` is initialised.
        let tm = unsafe { tm.assume_init() };

        // SAFETY: `newlocale` copies the locale name; a null return means the name
        // was not valid. The empty name is the env-derived locale `ps` gets from
        // `setlocale(LC_ALL, "")`.
        let mut loc = unsafe { libc::newlocale(libc::LC_ALL_MASK, name.as_ptr(), ptr::null_mut()) };
        if loc.is_null() && fall_back_to_c {
            // SAFETY: fallback to the "C" locale, matching a failed `setlocale`.
            loc = unsafe { libc::newlocale(libc::LC_ALL_MASK, c"C".as_ptr(), ptr::null_mut()) };
        }
        if loc.is_null() {
            return None;
        }
        let mut buf = [0 as libc::c_char; 256];
        // SAFETY: `buf` is 256 writable bytes; `fmt` and `tm` live for the call;
        // `loc` is a locale this function created.
        let n = unsafe { libc::strftime_l(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), &tm, loc) };
        // SAFETY: `loc` was created by `newlocale` in this function and is not used
        // after this call.
        unsafe {
            libc::freelocale(loc);
        }
        if n == 0 {
            return None;
        }
        let n = usize::try_from(n).ok()?;
        // SAFETY: `strftime_l` wrote `n` bytes into `buf` (not counting a trailing NUL
        // it may also store). `n` is in `1..buf.len()`.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
        Some(String::from_utf8_lossy(bytes).trim().to_string())
    }
}

#[cfg(test)]
mod module_001_ac32_tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for ent in fs::read_dir(dir).expect("read src") {
            let ent = ent.expect("dirent");
            let path = ent.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    fn code_without_line_comment(line: &str) -> &str {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            return "";
        }
        match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        }
    }

    fn ffi_range(process_probe: &str) -> (usize, usize) {
        let lines: Vec<&str> = process_probe.lines().collect();
        let mut allow_at = None;
        for (i, line) in lines.iter().enumerate() {
            if *line == "#[allow(unsafe_code)]" {
                assert!(
                    allow_at.is_none(),
                    "exactly one column-0 #[allow(unsafe_code)]"
                );
                allow_at = Some(i);
            }
        }
        let allow_at = allow_at.expect("one column-0 #[allow(unsafe_code)] in process_probe.rs");
        let mut j = allow_at + 1;
        while j < lines.len() {
            let t = lines[j].trim();
            if t.is_empty() || t.starts_with('#') {
                j += 1;
                continue;
            }
            assert_eq!(
                lines[j], "mod ffi {",
                "next non-blank, non-attribute line after the allow must be `mod ffi {{` at column 0"
            );
            break;
        }
        let open = j;
        let mut close = None;
        for (i, line) in lines.iter().enumerate().skip(open + 1) {
            if *line == "}" {
                close = Some(i);
                break;
            }
        }
        let close = close.expect("column-0 closing brace of mod ffi");
        (open, close)
    }

    #[test]
    fn module_001_ac32_runtime_unsafe_code_is_only_the_pid_probe_ffi() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        files.sort();

        let process_probe_path = src.join("process_probe.rs");
        let process_probe =
            fs::read_to_string(&process_probe_path).expect("process_probe.rs readable");
        let (ffi_open, ffi_close) = ffi_range(&process_probe);

        let mut allow_count = 0;
        let mut ffi_unsafe_blocks = 0;

        for path in &files {
            let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            let rel = path.strip_prefix(&src).unwrap_or(path);
            for (idx, line) in text.lines().enumerate() {
                let code = code_without_line_comment(line);
                if !code.contains("unsafe") {
                    continue;
                }
                let n = idx + 1;
                if rel == Path::new("lib.rs") && code.contains("#![deny(unsafe_code)]") {
                    continue;
                }
                if rel == Path::new("process_probe.rs") {
                    if idx > ffi_close {
                        continue;
                    }
                    if line == "#[allow(unsafe_code)]" {
                        allow_count += 1;
                        continue;
                    }
                    if idx > ffi_open && idx < ffi_close {
                        if code.contains("unsafe {") || code.contains("unsafe{") {
                            ffi_unsafe_blocks += 1;
                        }
                        continue;
                    }
                }
                panic!(
                    "unsafe token outside the pid-probe ffi: {}:{}: {line}",
                    rel.display(),
                    n
                );
            }
        }

        assert_eq!(allow_count, 1, "exactly one #[allow(unsafe_code)]");
        assert!(
            ffi_unsafe_blocks >= 1,
            "ffi must contain at least one unsafe block"
        );
    }
}

#[cfg(test)]
mod module_001_ac32_lstart_tests {
    use super::*;

    /// Real `ps -o lstart= -p <pid>` output for one process, trimmed as a lock carries it:
    /// (`ps`, that process's start instant, [(the environment `ps` ran under, its output)]).
    /// Captured on 2026-10-09 from macOS 27.0 `ps`, procps-ng 3.3.17 (Ubuntu 22.04), procps-ng
    /// 4.0.2 (Debian 12) and procps-ng 4.0.4 (Debian 13). The start instant is
    /// `btime + starttime / CLK_TCK` on Linux and the `TZ=UTC LC_ALL=C ps` output on macOS; an
    /// unset TZ is America/Los_Angeles on the macOS host and UTC on the Linux ones.
    const PS_SAMPLES: [(&str, i64, &[(&str, &str)]); 4] = [
        ("macOS 27.0 ps", MACOS_START, MACOS_PS),
        ("procps-ng 3.3.17", 1_791_538_418, PROCPS_3_3_17),
        ("procps-ng 4.0.2", 1_791_538_858, PROCPS_4_0_2),
        ("procps-ng 4.0.4", 1_791_538_308, PROCPS_4_0_4),
    ];
    const MACOS_START: i64 = 1_791_538_882;
    const MACOS_PS: &[(&str, &str)] = &[
        ("LANG=en_US.UTF-8", "Fri Oct  9 02:41:22 2026"),
        ("LC_ALL=C", "Fri Oct  9 02:41:22 2026"),
        ("TZ=UTC", "Fri Oct  9 09:41:22 2026"),
        ("TZ=Asia/Shanghai", "Fri Oct  9 17:41:22 2026"),
        ("TZ=America/New_York", "Fri Oct  9 05:41:22 2026"),
        ("TZ=Asia/Kathmandu", "Fri Oct  9 15:26:22 2026"),
        ("LC_ALL=en_GB.UTF-8", "Fri  9 Oct 02:41:22 2026"),
        ("LC_ALL=de_DE.UTF-8", "Fr.  9 Okt. 02:41:22 2026"),
        ("LC_ALL=zh_CN.UTF-8", "五 10月/ 9 02:41:22 2026"),
        ("LANG=zh_CN.UTF-8", "五 10月/ 9 02:41:22 2026"),
        ("LANG=C LC_TIME=zh_CN.UTF-8", "五 10月/ 9 02:41:22 2026"),
        (
            "LC_ALL=de_DE.UTF-8 TZ=Asia/Shanghai",
            "Fr.  9 Okt. 17:41:22 2026",
        ),
        (
            "LC_ALL=zh_CN.UTF-8 TZ=Asia/Shanghai",
            "五 10月/ 9 17:41:22 2026",
        ),
        ("LC_ALL=fr_FR.UTF-8", "ven.  9 oct. 02:41:22 2026"),
        ("LC_ALL=ja_JP.UTF-8", "金 10/ 9 02:41:22 2026"),
        (
            "LC_ALL=ko_KR.UTF-8",
            "2026년 10월  9일 금요일 02시 41분 22초",
        ),
        ("LC_ALL=ru_RU.UTF-8", "пятница,  9 октября 2026 г. 02:41:22"),
        ("LC_ALL=he_IL.UTF-8", "אוק׳ 09 2026 02:41:22"),
        ("LC_ALL=et_EE.UTF-8", "reede  9 oktoober 2026 02:41.22"),
        ("LC_ALL=nb_NO.UTF-8", "fre.  9 okt. 02.41.22 2026"),
        ("LC_ALL=eu_ES.UTF-8", "2026 - urr. -  9 or. 02:41:22"),
        (
            "LC_ALL=fa_IR.UTF-8 TZ=Asia/Tehran",
            "9 اکتبر 26، ساعت 13:11:22 (+0330)",
        ),
        (
            "LC_ALL=fa_IR.UTF-8 TZ=America/Sao_Paulo",
            "9 اکتبر 26، ساعت 06:41:22 (-03)",
        ),
    ];
    const PROCPS_3_3_17: &[(&str, &str)] = &[
        ("TZ unset", "Fri Oct  9 09:33:38 2026"),
        ("TZ=Asia/Shanghai", "Fri Oct  9 17:33:38 2026"),
        ("TZ=America/New_York", "Fri Oct  9 05:33:38 2026"),
        ("TZ=Asia/Kathmandu", "Fri Oct  9 15:18:38 2026"),
        ("LC_ALL=en_GB.UTF-8", "Fri Oct  9 09:33:38 2026"),
        ("LC_ALL=de_DE.UTF-8", "Fri Oct  9 09:33:38 2026"),
        ("LC_ALL=zh_CN.UTF-8", "Fri Oct  9 09:33:38 2026"),
        ("LANG=C LC_TIME=zh_CN.UTF-8", "Fri Oct  9 09:33:38 2026"),
        (
            "LC_ALL=zh_CN.UTF-8 TZ=Asia/Shanghai",
            "Fri Oct  9 17:33:38 2026",
        ),
    ];
    const PROCPS_4_0_2: &[(&str, &str)] = &[
        ("TZ unset", "Fri Oct  9 09:40:58 2026"),
        ("TZ=Asia/Shanghai", "Fri Oct  9 17:40:58 2026"),
        ("TZ=Asia/Kathmandu", "Fri Oct  9 15:25:58 2026"),
        ("LC_ALL=de_DE.UTF-8", "Fri Oct  9 09:40:58 2026"),
        ("LC_ALL=zh_CN.UTF-8", "Fri Oct  9 09:40:58 2026"),
        (
            "LC_ALL=de_DE.UTF-8 TZ=Asia/Shanghai",
            "Fri Oct  9 17:40:58 2026",
        ),
    ];
    const PROCPS_4_0_4: &[(&str, &str)] = &[
        ("TZ unset", "Fri Oct  9 09:31:48 2026"),
        ("TZ=Asia/Shanghai", "Fri Oct  9 17:31:48 2026"),
        ("TZ=America/New_York", "Fri Oct  9 05:31:48 2026"),
        ("TZ=Asia/Kathmandu", "Fri Oct  9 15:16:48 2026"),
        ("LC_ALL=en_GB.UTF-8", "Fri Oct  9 09:31:48 2026"),
        ("LC_ALL=de_DE.UTF-8", "Fr Okt  9 09:31:48 2026"),
        ("LC_ALL=zh_CN.UTF-8", "五 10月  9 09:31:48 2026"),
        ("LANG=zh_CN.UTF-8", "五 10月  9 09:31:48 2026"),
        ("LANG=C LC_TIME=zh_CN.UTF-8", "五 10月  9 09:31:48 2026"),
        (
            "LC_ALL=de_DE.UTF-8 TZ=Asia/Shanghai",
            "Fr Okt  9 17:31:48 2026",
        ),
        (
            "LC_ALL=zh_CN.UTF-8 TZ=Asia/Shanghai",
            "五 10月  9 17:31:48 2026",
        ),
    ];

    /// Shifts no rendering absorbs: a second, a minute, seven minutes (not a whole quarter
    /// hour), two days (beyond the 26 hours the UTC offsets span) and a year.
    const NEVER_THE_SAME_START: [i64; 7] =
        [-1, 1, 60, 7 * 60, -2 * 86_400, 2 * 86_400, 366 * 86_400];

    /// Month shifts that keep the day and time: an English rendering (its names are read) or
    /// one with a numeric month refuses them.
    const OTHER_MONTH: [i64; 2] = [-30 * 86_400, 31 * 86_400];

    fn month_is_read(lstart: &str) -> bool {
        let english = lstart
            .split_whitespace()
            .next()
            .is_some_and(|first| ENGLISH_WEEKDAYS.contains(&first));
        english || numbers_in(lstart).len() == 6
    }

    #[test]
    fn module_001_ac32_real_ps_output_names_its_process_start() {
        let mut month_read = 0;
        for (ps, start, outputs) in PS_SAMPLES {
            for &(env, lstart) in outputs {
                assert!(
                    lstart_names_start(lstart, start),
                    "{ps} under {env}: {lstart:?} must name {start}"
                );
                for shift in NEVER_THE_SAME_START {
                    assert!(
                        !lstart_names_start(lstart, start + shift),
                        "{ps} under {env}: {lstart:?} must not name {start}{shift:+}"
                    );
                }
                if month_is_read(lstart) {
                    month_read += 1;
                    for shift in OTHER_MONTH {
                        assert!(
                            !lstart_names_start(lstart, start + shift),
                            "{ps} under {env}: {lstart:?} must not name {start}{shift:+}"
                        );
                    }
                }
            }
        }
        assert!(month_read >= 30, "month read in {month_read} samples");
    }

    #[test]
    fn module_001_ac32_lstart_reading_rules() {
        const NEW_YEAR: i64 = 1_704_067_200; // 2024-01-01 00:00:00 UTC
                                             // `strftime` output for NEW_YEAR with the formats `ps` uses (macOS `date -r`, glibc
                                             // `date -d`), at the ends of the UTC offset range and across the year boundary.
        for lstart in [
            "Mon Jan  1 14:00:00 2024",  // +14:00, C
            "一 1月  1 14:00:00 2024",   // +14:00, procps-ng 4.0.4 zh_CN
            "一  1月/ 1 14:00:00 2024",  // +14:00, macOS zh_CN
            "Sun Dec 31 12:00:00 2023",  // −12:00, C
            "So Dez 31 12:00:00 2023",   // −12:00, procps-ng 4.0.4 de_DE
            "So. 31 Dez. 12:00:00 2023", // −12:00, macOS de_DE
            "日 12月/31 12:00:00 2023",  // −12:00, macOS zh_CN
            "Sun Dec 31 19:00:00 2023",  // America/New_York, C
            "日 12月 31 19:00:00 2023",  // America/New_York, procps-ng 4.0.4 zh_CN
            "Mon Jan 01 00:00:00 2024",  // zero-padded day
            "Mon Jan 1 00:00:00 2024",   // unpadded day
        ] {
            assert!(lstart_names_start(lstart, NEW_YEAR), "{lstart:?}");
        }
        for lstart in [
            "Mon Jan  1 14:15:00 2024", // +14:15: beyond the range
            "Sun Dec 31 11:45:00 2023", // −12:15: beyond the range
            "Sun Dec 31 19:00:00 2024", // another year
            "Sun Dec 31 19:00:00 24",   // two-digit year of another year
            "Tue Jan  1 00:00:00 2024", // English weekday of another day
            "Mon Feb  1 00:00:00 2024", // English month of another month
            "Mon  1 Feb 00:00:00 2024", // the same, day before month
            "一 2月  1 00:00:00 2024",  // numeric month of another month
            "日 1月/31 19:00:00 2023",  // numeric month of another month
        ] {
            assert!(!lstart_names_start(lstart, NEW_YEAR), "{lstart:?}");
        }
        // A number written right after a letter is part of a name (glibc lg_UG weekday `Lw5`).
        assert!(lstart_names_start("Lw5 Oki  9 09:41:22 2026", MACOS_START));
        // A number right after a sign is a numeric zone name; without the sign it is a field.
        assert!(lstart_names_start(
            "9 اکتبر 26، ساعت 13:11:22 (+0330)",
            MACOS_START
        ));
        assert!(!lstart_names_start(
            "9 اکتبر 26، ساعت 13:11:22 (0330)",
            MACOS_START
        ));
        // Not a rendering of a start instant.
        for lstart in [
            "",
            "unknown",
            "never",
            "Fri Oct  9 2026",
            "09:41:22",
            "Fri Oct  9 09:41:22",
            "Fri Oct  9 09:41:22 2026 7",
            "Fri Oct  9 09:41:22 20260",
        ] {
            assert!(!lstart_names_start(lstart, MACOS_START), "{lstart:?}");
        }
    }

    #[test]
    fn module_001_ac32_procps_ng_version_picks_the_lstart_format() {
        assert_eq!(
            procps_ng_version(b"\x7fELF\0ps from procps-ng 3.3.17\n\0"),
            Some((3, 3, 17))
        );
        assert_eq!(procps_ng_version(b"\0procps-ng 4.0.2\0"), Some((4, 0, 2)));
        assert_eq!(procps_ng_version(b"\0procps-ng 4.0.4\0"), Some((4, 0, 4)));
        assert_eq!(procps_ng_version(b"procps-ng 4.1"), Some((4, 1, 0)));
        assert_eq!(
            procps_ng_version(b"BusyBox v1.36.1 multi-call binary"),
            None
        );
        assert_eq!(procps_ng_version(b"procps-ng x"), None);
        assert_eq!(procps_ng_version(b"procps-ng 4."), None);
        for ctime in [(3, 3, 17), (4, 0, 0), (4, 0, 2)] {
            assert!(prints_ctime(ctime), "{ctime:?}");
        }
        for strftime in [(4, 0, 3), (4, 0, 4), (4, 0, 6), (4, 1, 0), (5, 0, 0)] {
            assert!(!prints_ctime(strftime), "{strftime:?}");
        }
    }

    /// The version read from the `ps` binary without running it is the one `ps --version`
    /// reports.
    #[cfg(target_os = "linux")]
    #[test]
    fn module_001_ac32_procps_ng_version_read_from_the_binary_is_ps_version() {
        let out = std::process::Command::new("ps")
            .arg("--version")
            .output()
            .expect("ps --version");
        let said = String::from_utf8_lossy(&out.stdout).to_string();
        let reported = procps_ng_version(said.as_bytes());
        assert!(reported.is_some(), "ps --version: {said:?}");
        let read = ps_on_path()
            .and_then(|ps| read_prefix(&ps, PS_BINARY_READ_LIMIT))
            .and_then(|bytes| procps_ng_version(&bytes));
        assert_eq!(read, reported, "ps --version: {said:?}");
        assert_eq!(procps_prints_ctime(), prints_ctime(read.expect("version")));
    }

    #[test]
    fn module_001_ac32_civil_dates_and_weekdays() {
        let civil = |year, month, day, hour, minute, second, weekday| Civil {
            year,
            month,
            day,
            hour,
            minute,
            second,
            weekday,
        };
        assert_eq!(Civil::at(0), civil(1970, 1, 1, 0, 0, 0, 4));
        assert_eq!(Civil::at(-1), civil(1969, 12, 31, 23, 59, 59, 3));
        assert_eq!(Civil::at(951_782_400), civil(2000, 2, 29, 0, 0, 0, 2));
        assert_eq!(Civil::at(1_704_067_199), civil(2023, 12, 31, 23, 59, 59, 0));
        assert_eq!(Civil::at(MACOS_START), civil(2026, 10, 9, 9, 41, 22, 5));
        assert_eq!(Civil::at(1_798_761_599), civil(2026, 12, 31, 23, 59, 59, 4));
        assert_eq!(Civil::at(4_102_444_800), civil(2100, 1, 1, 0, 0, 0, 5));
        assert_eq!(Civil::at(-62_135_596_800), civil(1, 1, 1, 0, 0, 0, 1));
        assert_eq!(
            Civil::at(253_402_300_799),
            civil(9999, 12, 31, 23, 59, 59, 5)
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn module_001_ac32_platform_uid_names_reads_the_os_pid_and_unknown_parts() {
        let own = std::process::id();
        let start = start_secs(own).expect("own start time");
        let os = std::env::consts::OS;
        let english =
            |t: i64| format_time(t, c"%a %b %e %H:%M:%S %Y", LocaleChoice::C).expect("C strftime");
        assert!(platform_uid_names(own, &platform_uid(own)));
        assert!(platform_uid_names(
            own,
            &format!("{os}:{own}:{}", english(start))
        ));
        assert!(platform_uid_names(own, &format!("{os}:{own}:unknown")));
        assert!(!platform_uid_names(
            own,
            &format!("{os}:{own}:{}", english(start - 1))
        ));
        assert!(!platform_uid_names(
            own,
            &format!("{os}:{own}:{}", english(start + 2 * 86_400))
        ));
        assert!(!platform_uid_names(
            own,
            &format!("{os}:{}:{}", own + 1, english(start))
        ));
        assert!(!platform_uid_names(
            own,
            &format!("{os}:{}:unknown", own + 1)
        ));
        assert!(!platform_uid_names(
            own,
            &format!("fake:{own}:{}", english(start))
        ));
        assert!(!platform_uid_names(own, &format!("fake:{own}:unknown")));
        assert!(!platform_uid_names(own, &format!("{os}:{own}")));
        assert!(!platform_uid_names(own, ""));
    }

    /// Every `ps` rendering this host's C library produces — the host `ps` format in every
    /// installed UTF-8 locale, for this process's start and three fixed instants — names its
    /// instant and no shifted one.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn module_001_ac32_every_installed_locale_rendering_names_its_start() {
        use std::ffi::CString;

        let require_locales =
            cfg!(target_os = "macos") || std::env::var_os("ADVANCE_TEST_REQUIRE_LOCALES").is_some();
        let listed = std::process::Command::new("locale")
            .arg("-a")
            .output()
            .expect("locale -a");
        assert!(listed.status.success(), "locale -a: {listed:?}");
        let mut names = vec!["C".to_string(), "POSIX".to_string()];
        names.extend(
            String::from_utf8_lossy(&listed.stdout)
                .lines()
                .map(str::trim)
                .filter(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower.ends_with(".utf-8") || lower.ends_with(".utf8")
                })
                .map(str::to_string),
        );
        // BSD `ps` prints `%c`; procps-ng 4.0.3 and later the format below (in the C locale
        // also `ctime()`'s bytes, procps-ng before 4.0.3).
        let format: &CStr = if cfg!(target_os = "macos") {
            c"%c"
        } else {
            c"%a %b %e %H:%M:%S %Y"
        };
        let instants = [
            start_secs(std::process::id()).expect("own start time"),
            MACOS_START,
            1_704_067_200,
            1_798_761_599,
        ];
        let mut rendered = Vec::new();
        for name in &names {
            let locale = CString::new(name.as_str()).expect("locale name");
            let mut any = false;
            for start in instants {
                let Some(lstart) = format_time_in(start, format, &locale) else {
                    continue;
                };
                any = true;
                assert!(
                    lstart_names_start(&lstart, start),
                    "{name}: {lstart:?} must name {start}"
                );
                for shift in NEVER_THE_SAME_START {
                    assert!(
                        !lstart_names_start(&lstart, start + shift),
                        "{name}: {lstart:?} must not name {start}{shift:+}"
                    );
                }
            }
            if any {
                rendered.push(name.as_str());
            }
        }
        assert!(rendered.contains(&"C"), "C locale rendered: {rendered:?}");
        if require_locales {
            for wanted in ["de_DE", "en_GB", "zh_CN"] {
                assert!(
                    rendered.iter().any(|name| name.starts_with(wanted)),
                    "{wanted} not installed (rendered: {rendered:?})"
                );
            }
        }
        println!("rendered {} locales", rendered.len());
    }
}
