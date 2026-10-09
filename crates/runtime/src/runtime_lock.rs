//! Single active runtime constraint via `/.runtime/runtime.lock`.
//!
//! Canonical source: `docs/modules/MODULE-001-runtime-host.md` §1.4.3 (lines 380–423)
//! and §2.5 (lines 855–863).
//!
//! The lock file prevents multiple runtime processes from operating on the same workspace
//! simultaneously. Three gates must ALL pass for an existing lock to be considered active:
//!
//! 1. **PID alive** — spawned `kill -0 {pid}` under `ProcessPolicy::Allow`, in-process
//!    `kill(pid, 0)` under `ProcessPolicy::Forbid`.
//! 2. **platform_uid matches** — the stored UID names the process that has the PID now
//!    (prevents PID-reuse false positives after reboot). Under Allow the spawned
//!    `ps -o lstart=` must reproduce it byte for byte; under Forbid the in-process probe reads
//!    its start time as an instant, in any rendering a `ps` prints.
//! 3. **Heartbeat fresh** — `heartbeat_at` is within the staleness threshold (default 120s).
//!
//! If any gate fails, the lock is considered stale and overwritten.

use advance_shared_types::process_policy::{ProcessPolicy, SpawnSite};
use chrono::Utc;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinHandle;

/// Default heartbeat interval per MODULE-001 §2.11 line 992: 30 seconds.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Default staleness threshold per MODULE-001 §2.11 line 993: 2 minutes.
const STALENESS_THRESHOLD: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// LockData — manual YAML (no serde_yaml, which is deprecated)
// ---------------------------------------------------------------------------

struct LockData {
    pid: u32,
    platform_uid: String,
    started_at: String,
    heartbeat_at: String,
    workspace_root: String,
    version: String,
}

impl LockData {
    fn to_yaml(&self) -> String {
        // Escape quotes and newlines in string fields to prevent YAML injection
        // (adversarial finding: workspace_root could contain " or \n).
        fn esc(s: &str) -> String {
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        }
        format!(
            "pid: {}\nplatform_uid: \"{}\"\nstarted_at: \"{}\"\nheartbeat_at: \"{}\"\nworkspace_root: \"{}\"\nversion: \"{}\"",
            self.pid, esc(&self.platform_uid), esc(&self.started_at), esc(&self.heartbeat_at), esc(&self.workspace_root), esc(&self.version),
        )
    }

    fn from_yaml(s: &str) -> Result<Self, LockError> {
        fn extract(lines: &[&str], key: &str) -> Result<String, LockError> {
            for line in lines {
                if let Some(rest) = line.strip_prefix(key) {
                    let val = rest.trim().trim_matches('"');
                    return Ok(val.to_string());
                }
            }
            Err(LockError::Parse(format!("missing key: {key}")))
        }

        let lines: Vec<&str> = s.lines().collect();
        Ok(LockData {
            pid: extract(&lines, "pid:")?
                .parse::<u32>()
                .map_err(|e| LockError::Parse(format!("pid parse: {e}")))?,
            platform_uid: extract(&lines, "platform_uid:")?,
            started_at: extract(&lines, "started_at:")?,
            heartbeat_at: extract(&lines, "heartbeat_at:")?,
            workspace_root: extract(&lines, "workspace_root:")?,
            version: extract(&lines, "version:")?,
        })
    }
}

// ---------------------------------------------------------------------------
// LockError
// ---------------------------------------------------------------------------

/// Read-only view of `{workspace}/.runtime/runtime.lock` (CONTRACT-243).
/// Does not acquire or rewrite the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockInspection {
    Absent,
    Live { pid: u32 },
    Stale { pid: u32 },
}

/// Unchanged behaviour: [`inspect_lock_with_policy`] with [`ProcessPolicy::Allow`].
pub fn inspect_lock(workspace: &Path) -> LockInspection {
    inspect_lock_with_policy(workspace, ProcessPolicy::Allow)
}

/// Classify the lock without acquiring it. AC-06 acquire semantics are unchanged.
///
/// Gate A + B use the in-process probe under `Forbid` (no `kill` / `ps` child), the spawned
/// `kill -0` / `ps -o lstart=` under `Allow`. Both give the same verdict for the same lock when
/// the prober runs under the same LANG / LC_* / TZ as the lock's writer. The `Forbid` probe
/// also judges live a lock that `ps` wrote for a live process under another locale, time zone
/// or procps-ng version, or wrote with an `unknown` start where `ps` failed; the `Allow` probe
/// still compares bytes, so it judges such a lock stale, as before the in-process probe
/// existed. Under `Forbid` the probe reads TZ and the locale variables through libc: do not
/// mutate the process environment while it runs.
pub fn inspect_lock_with_policy(workspace: &Path, policy: ProcessPolicy) -> LockInspection {
    let path = workspace.join(".runtime").join("runtime.lock");
    let meta = match std::fs::symlink_metadata(&path) {
        Err(_) => return LockInspection::Absent,
        Ok(m) => m,
    };
    if !meta.file_type().is_file() || meta.len() > 4096 {
        return LockInspection::Stale { pid: 0 };
    }
    let content = {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let Ok(mut f) = opts.open(&path) else {
            return LockInspection::Stale { pid: 0 };
        };
        let mut buf = String::new();
        if std::io::Read::read_to_string(&mut f, &mut buf).is_err() || buf.len() > 4096 {
            return LockInspection::Stale { pid: 0 };
        }
        buf
    };
    let Ok(existing) = LockData::from_yaml(&content) else {
        return LockInspection::Stale { pid: 0 };
    };
    if is_pid_alive(existing.pid, policy)
        && platform_uid_matches(existing.pid, &existing.platform_uid, policy)
        && heartbeat_fresh(&existing.heartbeat_at)
    {
        LockInspection::Live { pid: existing.pid }
    } else {
        LockInspection::Stale { pid: existing.pid }
    }
}

/// Errors from `RuntimeLock::acquire`.
#[derive(Debug)]
pub enum LockError {
    /// Another runtime process holds the lock and is alive + fresh.
    ActiveRuntime(u32),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// Lock file exists but cannot be parsed (treated as stale on acquire).
    Parse(String),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::ActiveRuntime(pid) => write!(f, "another runtime active (pid={pid})"),
            LockError::Io(e) => write!(f, "lock I/O error: {e}"),
            LockError::Parse(msg) => write!(f, "lock parse error: {msg}"),
        }
    }
}

impl std::error::Error for LockError {}

impl From<std::io::Error> for LockError {
    fn from(e: std::io::Error) -> Self {
        LockError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// RuntimeLock
// ---------------------------------------------------------------------------

/// Holds the `/.runtime/runtime.lock` file and a background heartbeat task.
///
/// When dropped, aborts the heartbeat task and removes the lock file (best-effort).
/// An owner that can await uses [`RuntimeLock::release`] instead, which joins the
/// heartbeat before it removes the file.
#[derive(Debug)]
pub struct RuntimeLock {
    path: PathBuf,
    /// `None` once [`RuntimeLock::release`] joined it.
    heartbeat: Option<JoinHandle<()>>,
    /// Set by [`RuntimeLock::release`]: the file is already removed, so `Drop` leaves
    /// the path alone (a newer lock may own it by then).
    released: bool,
}

impl RuntimeLock {
    /// Unchanged behaviour: [`Self::acquire_with_policy`] with [`ProcessPolicy::Allow`].
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime context (`tokio::spawn` requirement).
    pub async fn acquire(
        workspace: &Path,
        heartbeat_interval: Duration,
    ) -> Result<Self, LockError> {
        Self::acquire_with_policy(workspace, heartbeat_interval, ProcessPolicy::Allow).await
    }

    /// As [`Self::acquire`]; the lock's own `platform_uid` and the liveness check of an
    /// existing lock use the probe `policy` selects. The written `platform_uid` is
    /// byte-identical either way.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime context (`tokio::spawn` requirement).
    pub async fn acquire_with_policy(
        workspace: &Path,
        heartbeat_interval: Duration,
        policy: ProcessPolicy,
    ) -> Result<Self, LockError> {
        let lock_dir = workspace.join(".runtime");
        tokio::fs::create_dir_all(&lock_dir).await?;
        let path = lock_dir.join("runtime.lock");

        // Same leaf rules as inspect_lock (no follow / no FIFO hang / size cap).
        match inspect_lock_with_policy(workspace, policy) {
            LockInspection::Live { pid } => return Err(LockError::ActiveRuntime(pid)),
            LockInspection::Absent | LockInspection::Stale { .. } => {}
        }

        // Write new claim
        let pid = std::process::id();
        let now = Utc::now().to_rfc3339();
        let uid = generate_platform_uid(pid, policy);
        let workspace_root = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.to_path_buf())
            .display()
            .to_string();

        let data = LockData {
            pid,
            platform_uid: uid,
            started_at: now.clone(),
            heartbeat_at: now,
            workspace_root,
            version: "0.1.0".to_string(),
        };

        // Write lock file with 0o600 permissions from the start.
        // Use sync std::fs::File with explicit mode to avoid a permission window
        // where the file is briefly world-readable (adversarial finding W5).
        {
            #[cfg(unix)]
            {
                use std::fs::OpenOptions;
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true).mode(0o600);
                opts.custom_flags(libc::O_NOFOLLOW);
                let mut f = match opts.open(&path) {
                    Ok(f) => f,
                    Err(_) => {
                        // Replace a planted symlink / special file rather than follow it.
                        let _ = std::fs::remove_file(&path);
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .custom_flags(libc::O_NOFOLLOW)
                            .open(&path)?
                    }
                };
                f.write_all(data.to_yaml().as_bytes())?;
            }
            #[cfg(not(unix))]
            {
                tokio::fs::write(&path, data.to_yaml()).await?;
            }
        }

        // Spawn heartbeat task
        let hb_path = path.clone();
        let task = tokio::spawn(heartbeat_loop(hb_path, heartbeat_interval));

        Ok(RuntimeLock {
            path,
            heartbeat: Some(task),
            released: false,
        })
    }

    /// Returns the path to the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Release the lock: abort the heartbeat task and await it, THEN remove the lock
    /// file. Joining first means no heartbeat rewrite can run after the unlink (on a
    /// multi-thread runtime an aborted-but-running heartbeat could otherwise re-create
    /// the file it reads and rewrites). The removal is best-effort, as in `Drop`.
    pub async fn release(mut self) {
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
            let _ = heartbeat.await;
        }
        let _ = std::fs::remove_file(&self.path);
        self.released = true;
    }
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
        }
        if !self.released {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------
// Heartbeat loop
// ---------------------------------------------------------------------------

async fn heartbeat_loop(path: PathBuf, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        let _ = touch_heartbeat(&path);
    }
}

fn touch_heartbeat(path: &Path) -> Result<(), std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let now = Utc::now().to_rfc3339();
    // Replace the heartbeat_at line
    let updated: String = content
        .lines()
        .map(|line| {
            if line.starts_with("heartbeat_at:") {
                format!("heartbeat_at: \"{now}\"")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, updated)
}

// ---------------------------------------------------------------------------
// Liveness checks
// ---------------------------------------------------------------------------

/// Gate A: check if a PID is alive via `kill -0`.
fn is_pid_alive(pid: u32, policy: ProcessPolicy) -> bool {
    if policy.admit(SpawnSite::PidLockProbe).is_err() {
        return crate::process_probe::pid_alive(pid);
    }
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Gate B: whether the stored platform_uid names the process that has `pid` now. `Allow`:
/// regenerate it with `ps` and compare bytes. `Forbid`: the in-process probe compares the
/// stored start time as an instant (`process_probe::platform_uid_names`).
fn platform_uid_matches(pid: u32, stored_uid: &str, policy: ProcessPolicy) -> bool {
    if policy.check(SpawnSite::PidLockProbe).is_err() {
        return crate::process_probe::platform_uid_names(pid, stored_uid);
    }
    let current = generate_platform_uid(pid, policy);
    current == stored_uid
}

/// Generate a platform UID: "{os}:{pid}:{lstart_raw}".
///
/// Uses `ps -o lstart= -p {pid}` to get the process start time as a raw string.
/// Equality comparison is sufficient — no date parsing needed.
fn generate_platform_uid(pid: u32, policy: ProcessPolicy) -> String {
    if policy.admit(SpawnSite::PidLockProbe).is_err() {
        return crate::process_probe::platform_uid(pid);
    }
    let lstart = std::process::Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    format!("{}:{}:{}", std::env::consts::OS, pid, lstart)
}

/// Gate C: check if heartbeat_at is within the staleness threshold.
///
/// Also rejects future timestamps (negative age) — a lock with `heartbeat_at` in the
/// future is treated as stale to prevent permanent DoS from clock skew or tampering
/// (adversarial finding W7).
fn heartbeat_fresh(heartbeat_at: &str) -> bool {
    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(heartbeat_at) else {
        return false;
    };
    let age = Utc::now().signed_duration_since(ts);
    // Reject if age is negative (future timestamp) or exceeds staleness threshold
    let threshold =
        chrono::Duration::from_std(STALENESS_THRESHOLD).unwrap_or(chrono::Duration::seconds(120));
    age >= chrono::Duration::zero() && age < threshold
}

#[cfg(test)]
mod module_001_ac32_tests {
    use super::*;
    use advance_shared_types::process_policy::spawn_counter;
    use std::process::Command;
    use std::time::Duration;

    static COUNTER_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        COUNTER_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn module_001_ac32_in_process_platform_uid_equals_ps_for_this_process() {
        let _guard = serial();
        let own = std::process::id();
        for i in 0..20 {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(50));
            }
            let allow = generate_platform_uid(own, ProcessPolicy::Allow);
            let forbid = generate_platform_uid(own, ProcessPolicy::Forbid);
            assert_eq!(allow, forbid, "round {i}");
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            assert!(
                !allow.ends_with(":unknown"),
                "platform_uid must not be unknown with ps present: {allow}"
            );
        }
    }

    #[test]
    fn module_001_ac32_in_process_platform_uid_equals_ps_for_a_child() {
        let _guard = serial();
        let mut child = Command::new("sleep").arg("5").spawn().expect("sleep 5");
        let pid = child.id();
        let allow = generate_platform_uid(pid, ProcessPolicy::Allow);
        let forbid = generate_platform_uid(pid, ProcessPolicy::Forbid);
        assert_eq!(allow, forbid, "live child uid");
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(
            !allow.ends_with(":unknown"),
            "live child uid must not be unknown: {allow}"
        );
        let _ = child.kill();
        let _ = child.wait();
        assert!(!is_pid_alive(pid, ProcessPolicy::Allow));
        assert!(!is_pid_alive(pid, ProcessPolicy::Forbid));
        assert!(
            generate_platform_uid(pid, ProcessPolicy::Allow).ends_with(":unknown"),
            "reaped child Allow uid"
        );
        assert!(
            generate_platform_uid(pid, ProcessPolicy::Forbid).ends_with(":unknown"),
            "reaped child Forbid uid"
        );
    }

    #[test]
    fn module_001_ac32_in_process_liveness_matches_kill_0() {
        let _guard = serial();
        let own = std::process::id();
        assert_eq!(
            is_pid_alive(own, ProcessPolicy::Allow),
            is_pid_alive(own, ProcessPolicy::Forbid)
        );
        assert_eq!(
            is_pid_alive(1, ProcessPolicy::Allow),
            is_pid_alive(1, ProcessPolicy::Forbid)
        );
        let mut child = Command::new("true").spawn().expect("true");
        let pid = child.id();
        let _ = child.wait();
        assert_eq!(
            is_pid_alive(pid, ProcessPolicy::Allow),
            is_pid_alive(pid, ProcessPolicy::Forbid)
        );
        assert_eq!(
            is_pid_alive(4_000_000_000, ProcessPolicy::Allow),
            is_pid_alive(4_000_000_000, ProcessPolicy::Forbid)
        );
    }

    #[test]
    #[ignore]
    fn module_001_ac32_platform_uid_env_matrix_child() {
        const T: i64 = 1_704_067_200;
        const ROUNDS: usize = 10;
        let own = std::process::id();
        for _ in 0..ROUNDS {
            let allow = generate_platform_uid(own, ProcessPolicy::Allow);
            let forbid = generate_platform_uid(own, ProcessPolicy::Forbid);
            assert_eq!(allow, forbid);
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            assert!(!allow.ends_with(":unknown"), "{allow}");
        }
        let mut child = Command::new("sleep").arg("5").spawn().expect("sleep 5");
        let pid = child.id();
        let allow = generate_platform_uid(pid, ProcessPolicy::Allow);
        let forbid = generate_platform_uid(pid, ProcessPolicy::Forbid);
        assert_eq!(allow, forbid, "child uid");
        let _ = child.kill();
        let _ = child.wait();
        assert!(!is_pid_alive(pid, ProcessPolicy::Allow));
        assert!(!is_pid_alive(pid, ProcessPolicy::Forbid));
        assert!(generate_platform_uid(pid, ProcessPolicy::Allow).ends_with(":unknown"));
        assert!(generate_platform_uid(pid, ProcessPolicy::Forbid).ends_with(":unknown"));

        let c = crate::process_probe::format_time(T, c"%c", crate::process_probe::LocaleChoice::C)
            .expect("C locale strftime");
        let resolved =
            crate::process_probe::format_time(T, c"%c", crate::process_probe::LocaleChoice::Env)
                .expect("Env locale strftime");
        println!("PLATFORM_UID_MATRIX_OK rounds={ROUNDS} c={c} resolved={resolved}");
    }

    #[test]
    fn module_001_ac32_platform_uid_env_matrix() {
        let _guard = serial();
        let require_locales =
            cfg!(target_os = "macos") || std::env::var_os("ADVANCE_TEST_REQUIRE_LOCALES").is_some();

        run_matrix_leg("inherited", false, |_| {});
        run_matrix_leg("LC_ALL=C", false, |cmd| {
            cmd.env("LC_ALL", "C");
        });
        run_matrix_leg("TZ=UTC", false, |cmd| {
            cmd.env("TZ", "UTC");
        });
        run_matrix_leg("TZ=Asia/Shanghai", false, |cmd| {
            cmd.env("TZ", "Asia/Shanghai");
        });
        run_matrix_leg("LC_ALL=en_GB.UTF-8", require_locales, |cmd| {
            cmd.env("LC_ALL", "en_GB.UTF-8");
        });
        run_matrix_leg("LC_ALL=de_DE.UTF-8", require_locales, |cmd| {
            cmd.env("LC_ALL", "de_DE.UTF-8");
        });
        run_matrix_leg("LC_ALL=zh_CN.UTF-8", require_locales, |cmd| {
            cmd.env("LC_ALL", "zh_CN.UTF-8");
        });
        run_matrix_leg("LANG=zh_CN.UTF-8", require_locales, |cmd| {
            cmd.env("LANG", "zh_CN.UTF-8");
            cmd.env_remove("LC_ALL");
        });
        run_matrix_leg("LANG=C LC_TIME=zh_CN.UTF-8", require_locales, |cmd| {
            cmd.env("LANG", "C");
            cmd.env("LC_TIME", "zh_CN.UTF-8");
            cmd.env_remove("LC_ALL");
        });
    }

    fn run_matrix_leg(name: &str, require_resolved: bool, configure: impl FnOnce(&mut Command)) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = Command::new(exe);
        cmd.args([
            "runtime_lock::module_001_ac32_tests::module_001_ac32_platform_uid_env_matrix_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ]);
        configure(&mut cmd);
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("{name}: spawn child: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{name} exit {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            out.status.code()
        );
        const MARK: &str = "PLATFORM_UID_MATRIX_OK rounds=10 ";
        let start = stdout.find(MARK).unwrap_or_else(|| {
            panic!("{name} missing OK line\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });
        let rest = stdout[start + MARK.len()..]
            .split('\n')
            .next()
            .unwrap_or("")
            .trim_end();
        if require_resolved {
            let (c_part, resolved) = rest
                .split_once(" resolved=")
                .unwrap_or_else(|| panic!("{name} missing resolved=: {rest}\nstdout:\n{stdout}"));
            let c = c_part
                .strip_prefix("c=")
                .unwrap_or_else(|| panic!("{name} missing c=: {rest}"));
            assert_ne!(
                resolved, c,
                "{name} locale did not resolve (resolved == C): {rest}"
            );
        }
    }

    #[test]
    fn module_001_ac32_forbid_writer_and_reader_agree_with_the_spawn_probe() {
        let _guard = serial();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let own = std::process::id();
            let lock = RuntimeLock::acquire_with_policy(
                dir.path(),
                Duration::from_secs(30),
                ProcessPolicy::Forbid,
            )
            .await
            .expect("acquire Forbid");
            match inspect_lock(dir.path()) {
                LockInspection::Live { pid } => assert_eq!(pid, own),
                other => panic!("expected Live after Forbid writer: {other:?}"),
            }
            drop(lock);

            let lock = RuntimeLock::acquire(dir.path(), Duration::from_secs(30))
                .await
                .expect("acquire Allow");
            match inspect_lock_with_policy(dir.path(), ProcessPolicy::Forbid) {
                LockInspection::Live { pid } => assert_eq!(pid, own),
                other => panic!("expected Live after Allow writer: {other:?}"),
            }
            drop(lock);
        });
    }

    /// Writes `.runtime/runtime.lock` under `home` naming this process with `platform_uid`
    /// and a fresh heartbeat.
    fn write_own_lock(home: &Path, platform_uid: &str) {
        let now = Utc::now().to_rfc3339();
        let data = LockData {
            pid: std::process::id(),
            platform_uid: platform_uid.to_string(),
            started_at: now.clone(),
            heartbeat_at: now,
            workspace_root: home.display().to_string(),
            version: "0.1.0".to_string(),
        };
        let dir = home.join(".runtime");
        std::fs::create_dir_all(&dir).expect("runtime dir");
        std::fs::write(dir.join("runtime.lock"), data.to_yaml()).expect("write lock");
    }

    /// ADR 2026-10-03 D3: a lock that `ps` wrote for this live process under another locale or
    /// time zone than this process's reads live to the in-process probe, which spawns nothing.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn module_001_ac32_forbid_probe_judges_live_a_lock_ps_wrote_under_another_locale_or_time_zone()
    {
        let _guard = serial();
        let own = std::process::id();
        let in_process = generate_platform_uid(own, ProcessPolicy::Forbid);
        let legs: [(&str, &[(&str, &str)]); 9] = [
            ("TZ=UTC", &[("TZ", "UTC")]),
            ("TZ=Asia/Shanghai", &[("TZ", "Asia/Shanghai")]),
            ("TZ=Asia/Kathmandu", &[("TZ", "Asia/Kathmandu")]),
            ("TZ=Pacific/Kiritimati", &[("TZ", "Pacific/Kiritimati")]),
            ("TZ=Etc/GMT+12", &[("TZ", "Etc/GMT+12")]),
            ("LC_ALL=en_GB.UTF-8", &[("LC_ALL", "en_GB.UTF-8")]),
            ("LC_ALL=de_DE.UTF-8", &[("LC_ALL", "de_DE.UTF-8")]),
            (
                "LC_ALL=zh_CN.UTF-8 TZ=Asia/Shanghai",
                &[("LC_ALL", "zh_CN.UTF-8"), ("TZ", "Asia/Shanghai")],
            ),
            (
                "LANG=C LC_TIME=zh_CN.UTF-8",
                &[("LANG", "C"), ("LC_TIME", "zh_CN.UTF-8")],
            ),
        ];
        let home = tempfile::tempdir().expect("tempdir");
        let before = spawn_counter::snapshot();
        let mut other_bytes = Vec::new();
        for (leg, vars) in legs {
            let mut ps = Command::new("ps");
            ps.args(["-o", "lstart=", "-p", &own.to_string()]);
            if !vars.iter().any(|(name, _)| *name == "LC_ALL") {
                ps.env_remove("LC_ALL");
            }
            for (name, value) in vars {
                ps.env(name, value);
            }
            let out = ps.output().expect("ps -o lstart=");
            assert!(out.status.success(), "{leg}: {out:?}");
            let lstart = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let uid = format!("{}:{own}:{lstart}", std::env::consts::OS);
            write_own_lock(home.path(), &uid);
            match inspect_lock_with_policy(home.path(), ProcessPolicy::Forbid) {
                LockInspection::Live { pid } => assert_eq!(pid, own, "{leg}"),
                other => {
                    panic!("{leg}: {uid:?} must read live, got {other:?} (own: {in_process:?})")
                }
            }
            if uid != in_process {
                other_bytes.push(leg);
            }
        }
        assert!(
            !other_bytes.is_empty(),
            "every leg printed this process's own bytes {in_process:?}"
        );
        let delta = spawn_counter::snapshot().since(&before);
        assert_eq!(delta.admitted(SpawnSite::PidLockProbe), 0);
        assert_eq!(
            delta.refused(SpawnSite::PidLockProbe),
            2 * legs.len() as u64
        );
        println!("legs with other bytes than {in_process:?}: {other_bytes:?}");
    }

    /// The in-process probe still refuses a lock that names another start of this pid, another
    /// pid or another OS, and judges live one whose writer could not read a start time.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn module_001_ac32_forbid_probe_refuses_another_start_and_reads_unknown_live() {
        let _guard = serial();
        let own = std::process::id();
        let os = std::env::consts::OS;
        let start = crate::process_probe::start_secs(own).expect("own start time");
        let english = |t: i64| {
            crate::process_probe::format_time(
                t,
                c"%a %b %e %H:%M:%S %Y",
                crate::process_probe::LocaleChoice::C,
            )
            .expect("C strftime")
        };
        let home = tempfile::tempdir().expect("tempdir");
        let cases = [
            (format!("{os}:{own}:{}", english(start)), true),
            (format!("{os}:{own}:unknown"), true),
            (format!("{os}:{own}:{}", english(start - 1)), false),
            (
                format!("{os}:{own}:{}", english(start + 366 * 86_400)),
                false,
            ),
            (format!("{os}:{}:{}", own + 1, english(start)), false),
            (format!("fake:{own}:{}", english(start)), false),
        ];
        for (uid, live) in &cases {
            write_own_lock(home.path(), uid);
            let got = inspect_lock_with_policy(home.path(), ProcessPolicy::Forbid);
            let want = if *live {
                LockInspection::Live { pid: own }
            } else {
                LockInspection::Stale { pid: own }
            };
            assert_eq!(got, want, "{uid:?}");
        }
    }

    #[test]
    fn module_001_ac32_forbid_probe_spawns_nothing() {
        let _guard = serial();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let lock = RuntimeLock::acquire(dir.path(), Duration::from_secs(30))
                .await
                .expect("acquire");
            let before = spawn_counter::snapshot();
            match inspect_lock_with_policy(dir.path(), ProcessPolicy::Forbid) {
                LockInspection::Live { pid } => assert_eq!(pid, std::process::id()),
                other => panic!("expected Live: {other:?}"),
            }
            let delta = spawn_counter::snapshot().since(&before);
            assert_eq!(delta.admitted(SpawnSite::PidLockProbe), 0);
            assert_eq!(delta.refused(SpawnSite::PidLockProbe), 2);
            drop(lock);
        });
    }
}
