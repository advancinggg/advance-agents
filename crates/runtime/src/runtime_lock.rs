//! Single active runtime constraint via `/.runtime/runtime.lock`.
//!
//! Canonical source: `docs/modules/MODULE-001-runtime-host.md` §1.4.3 (lines 380–423)
//! and §2.5 (lines 855–863).
//!
//! The lock file prevents multiple runtime processes from operating on the same workspace
//! simultaneously. Three gates must ALL pass for an existing lock to be considered active:
//!
//! 1. **PID alive** — `kill -0 {pid}` returns exit code 0.
//! 2. **platform_uid matches** — regenerated UID for the existing PID equals the stored UID
//!    (prevents PID-reuse false positives after reboot).
//! 3. **Heartbeat fresh** — `heartbeat_at` is within the staleness threshold (default 120s).
//!
//! If any gate fails, the lock is considered stale and overwritten.

use chrono::Utc;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::AbortHandle;

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
#[derive(Debug)]
pub struct RuntimeLock {
    path: PathBuf,
    _heartbeat_abort: AbortHandle,
}

impl RuntimeLock {
    /// Acquire the runtime lock for the given workspace.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime context (`tokio::spawn` requirement).
    pub async fn acquire(
        workspace: &Path,
        heartbeat_interval: Duration,
    ) -> Result<Self, LockError> {
        let lock_dir = workspace.join(".runtime");
        tokio::fs::create_dir_all(&lock_dir).await?;
        let path = lock_dir.join("runtime.lock");

        // Check existing lock
        if path.exists() {
            match tokio::fs::read_to_string(&path).await {
                Ok(content) => match LockData::from_yaml(&content) {
                    Ok(existing) => {
                        if is_pid_alive(existing.pid)
                            && platform_uid_matches(existing.pid, &existing.platform_uid)
                            && heartbeat_fresh(&existing.heartbeat_at)
                        {
                            return Err(LockError::ActiveRuntime(existing.pid));
                        }
                        // Stale — fall through to overwrite
                    }
                    Err(_) => {
                        // Malformed — treat as stale, overwrite
                    }
                },
                Err(_) => {
                    // Read error — treat as stale, overwrite
                }
            }
        }

        // Write new claim
        let pid = std::process::id();
        let now = Utc::now().to_rfc3339();
        let uid = generate_platform_uid(pid);
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
                let mut f = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)?;
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
        let abort_handle = task.abort_handle();

        Ok(RuntimeLock {
            path,
            _heartbeat_abort: abort_handle,
        })
    }

    /// Returns the path to the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        self._heartbeat_abort.abort();
        let _ = std::fs::remove_file(&self.path);
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
fn is_pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Gate B: regenerate platform_uid for the given PID and compare.
fn platform_uid_matches(pid: u32, stored_uid: &str) -> bool {
    let current = generate_platform_uid(pid);
    current == stored_uid
}

/// Generate a platform UID: "{os}:{pid}:{lstart_raw}".
///
/// Uses `ps -o lstart= -p {pid}` to get the process start time as a raw string.
/// Equality comparison is sufficient — no date parsing needed.
fn generate_platform_uid(pid: u32) -> String {
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
