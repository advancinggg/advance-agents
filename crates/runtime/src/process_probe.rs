//! In-process pid-lock probe used under [`ProcessPolicy::Forbid`](advance_shared_types::process_policy::ProcessPolicy).
//!
//! Gate A is `kill(pid, 0)`; Gate B formats the same `lstart` bytes `ps -o lstart=`
//! prints for that process under this process's LANG / LC_* / TZ. Do not mutate the
//! process environment while a Forbid lock read or compose runs: TZ and the locale
//! variables are read through libc.

use std::ffi::CStr;

/// Test seam for the `platform_uid` env-matrix test: `strftime_l(fmt)` of `t` under the env-derived locale (`Env`) or "C" (`C`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocaleChoice {
    Env,
    #[allow(dead_code)]
    C,
}

/// `kill(pid, 0) == 0`; any error (ESRCH, EPERM) → false, exactly as `kill -0` exits non-zero;
/// a pid above `i32::MAX` → false (never handed to `kill`, which would address a process group).
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
/// time cannot be read (as when `ps` fails today).
pub(crate) fn platform_uid(pid: u32) -> String {
    let lstart = lstart(pid).unwrap_or_else(|| "unknown".to_string());
    format!("{}:{}:{}", std::env::consts::OS, pid, lstart)
}

fn lstart(pid: u32) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let tvsec = ffi::macos_start_tvsec(pid)?;
        format_time(tvsec, c"%c", LocaleChoice::Env)
    }
    #[cfg(target_os = "linux")]
    {
        let t = linux_start_secs(pid)?;
        format_time(t, c"%a %b %e %H:%M:%S %Y", LocaleChoice::Env)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
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

/// Test seam for the `platform_uid` env-matrix test: `strftime_l(fmt)` of `t` under the env-derived locale (`Env`) or "C" (`C`).
pub(crate) fn format_time(t: i64, fmt: &CStr, locale: LocaleChoice) -> Option<String> {
    #[cfg(unix)]
    {
        ffi::format_time(t, fmt, locale)
    }
    #[cfg(not(unix))]
    {
        let _ = (t, fmt, locale);
        None
    }
}

/// The one FFI module of this crate: `kill`, `proc_pidinfo`, `tzset`, `localtime_r`,
/// `newlocale`, `strftime_l`, `freelocale`, `sysconf`. Every block is a single libc
/// query whose pointers this module keeps alive for the duration of the call.
#[allow(unsafe_code)]
mod ffi {
    #[cfg(unix)]
    use super::LocaleChoice;
    #[cfg(unix)]
    use std::ffi::CStr;
    #[cfg(unix)]
    use std::mem::MaybeUninit;
    #[cfg(unix)]
    use std::ptr;

    #[cfg(unix)]
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

    #[cfg(unix)]
    pub(super) fn format_time(t: i64, fmt: &CStr, locale: LocaleChoice) -> Option<String> {
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

        let name = match locale {
            LocaleChoice::Env => c"",
            LocaleChoice::C => c"C",
        };
        // SAFETY: `newlocale` copies the locale name; a null return means the name
        // was not valid. The empty name is the env-derived locale `ps` gets from
        // `setlocale(LC_ALL, "")`.
        let mut loc = unsafe { libc::newlocale(libc::LC_ALL_MASK, name.as_ptr(), ptr::null_mut()) };
        if loc.is_null() {
            // SAFETY: fallback to the "C" locale, matching a failed `setlocale`.
            loc = unsafe { libc::newlocale(libc::LC_ALL_MASK, c"C".as_ptr(), ptr::null_mut()) };
        }
        if loc.is_null() {
            return None;
        }
        let mut buf = [0 as libc::c_char; 128];
        // SAFETY: `buf` is 128 writable bytes; `fmt` and `tm` live for the call;
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
