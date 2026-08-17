//! Supervise mode: spawn child on GLOBAL_RT, readiness line or file.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::config::{confine_under_workspace, resolve_config_path, BridgeConfig};
use crate::error::BridgeError;
use crate::handle::{default_lifecycle, BridgeHandle, BridgeInner, ModeState};
use crate::registry;
use crate::runtime_rt;
use crate::types::SuperviseReadiness;
use crate::workspace::prepare_workspace;

const STOP_GRACE: Duration = Duration::from_secs(5);
const LINE_CAP: usize = 4096;

/// Supervise start (must run on GLOBAL_RT).
pub async fn start_supervise(
    workspace_root: &Path,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    config.validate()?;
    let workspace = prepare_workspace(workspace_root)?;
    reject_nondefault_supervise_config(&workspace, &config)?;
    let reservation = registry::Reservation::acquire(workspace.clone())?;

    let result = start_supervise_inner(workspace, config).await;
    if result.is_ok() {
        reservation.persist();
    }
    result
}

fn reject_nondefault_supervise_config(
    workspace: &Path,
    config: &BridgeConfig,
) -> Result<(), BridgeError> {
    if let Some(ref p) = config.config_path {
        let resolved = confine_under_workspace(workspace, p)?;
        let default = workspace.join(".advance").join("runtime-config.yaml");
        let default_canon = default.canonicalize().unwrap_or(default);
        if resolved != default_canon && resolved != workspace.join(".advance").join("runtime-config.yaml")
        {
            return Err(BridgeError::InvalidConfig(
                "supervise ignores custom config_path; CLI start only loads <ws>/.advance/runtime-config.yaml"
                    .into(),
            ));
        }
    }
    if config.supervise_ready_file.is_some() && config.supervise_command.is_none() {
        return Err(BridgeError::InvalidConfig(
            "supervise_ready_file requires custom supervise_command (default advance has no ready-file protocol)"
                .into(),
        ));
    }
    Ok(())
}

fn require_ready_file_shape(workspace: &Path, rf: &Path) -> Result<(), BridgeError> {
    let runtime_dir = workspace.join(".runtime");
    let name_ok = rf
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_ascii_lowercase().contains("ready"))
        .unwrap_or(false);
    let parent = rf.parent().ok_or_else(|| {
        BridgeError::InvalidConfig("supervise_ready_file has no parent".into())
    })?;
    if !parent.exists() {
        return Err(BridgeError::InvalidConfig(
            "supervise_ready_file parent directory must exist".into(),
        ));
    }
    let parent_canon = parent.canonicalize().map_err(|e| {
        BridgeError::InvalidConfig(format!("canonicalize ready_file parent: {e}"))
    })?;
    let runtime_canon = runtime_dir.canonicalize().unwrap_or(runtime_dir);
    let under_runtime = parent_canon.starts_with(&runtime_canon);
    if !(under_runtime && name_ok) {
        return Err(BridgeError::InvalidConfig(
            "supervise_ready_file must be under .runtime/ with 'ready' in the filename".into(),
        ));
    }
    Ok(())
}

async fn start_supervise_inner(
    workspace: PathBuf,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    let cmd_path = resolve_command(&config)?;
    let ready_file = if let Some(ref rf) = config.supervise_ready_file {
        let confined = confine_under_workspace(&workspace, rf)?;
        require_ready_file_shape(&workspace, &confined)?;
        Some(confined)
    } else {
        None
    };

    if let Some(ref rf) = ready_file {
        clear_ready_file_if_regular(rf)?;
    }

    let kill_on_drop = config.supervise_kill_on_drop;
    // Plan: kill_on_drop true → piped + continuous drain; keep-available → null.
    let pipe_stdio = kill_on_drop;
    let mut command = Command::new(&cmd_path);
    command
        .arg("start")
        .arg("--workspace")
        .arg(&workspace)
        .stdin(Stdio::null())
        .kill_on_drop(false);

    if pipe_stdio {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let child = command
        .spawn()
        .map_err(|e| BridgeError::Supervise(format!("spawn: {e}")))?;
    // Reap on cancel / early return so start_async abort cannot orphan the child.
    let mut guard = SpawnGuard::new(child);

    let spawn_at = Instant::now();
    let timeout = config.ready_timeout();
    let marker = config.ready_marker().to_string();

    let mut drain_tasks = Vec::new();
    if pipe_stdio && ready_file.is_some() {
        if let Some(stdout) = guard.child_mut().stdout.take() {
            drain_tasks.push(tokio::spawn(async move {
                drain_discard(stdout).await;
            }));
        }
        if let Some(stderr) = guard.child_mut().stderr.take() {
            drain_tasks.push(tokio::spawn(async move {
                drain_discard(stderr).await;
            }));
        }
    }

    let readiness = if let Some(ref rf) = ready_file {
        let rf = rf.clone();
        let deadline = spawn_at + timeout;
        loop {
            if Instant::now() > deadline {
                return Err(BridgeError::SuperviseStartTimeout);
            }
            match guard.child_mut().try_wait() {
                Ok(Some(status)) => {
                    return Err(BridgeError::Supervise(format!(
                        "child exited before ready: {status}"
                    )));
                }
                Ok(None) => {
                    if file_ready_regular(&rf) {
                        match guard.child_mut().try_wait() {
                            Ok(None) => break SuperviseReadiness::ReadyFile,
                            Ok(Some(status)) => {
                                return Err(BridgeError::Supervise(format!(
                                    "child exited before ready: {status}"
                                )));
                            }
                            Err(e) => {
                                return Err(BridgeError::Supervise(format!("try_wait: {e}")));
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(BridgeError::Supervise(format!("try_wait: {e}")));
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    } else {
        let stdout = guard
            .child_mut()
            .stdout
            .take()
            .ok_or_else(|| BridgeError::Supervise("missing stdout".into()))?;
        let stderr = guard
            .child_mut()
            .stderr
            .take()
            .ok_or_else(|| BridgeError::Supervise("missing stderr".into()))?;
        let seen = Arc::new(AtomicBool::new(false));
        let s1 = Arc::clone(&seen);
        let s2 = Arc::clone(&seen);
        let m1 = marker.clone();
        let m2 = marker.clone();
        drain_tasks.push(tokio::spawn(async move {
            scan_limited_lines(stdout, &m1, &s1).await;
        }));
        drain_tasks.push(tokio::spawn(async move {
            scan_limited_lines(stderr, &m2, &s2).await;
        }));
        let deadline = spawn_at + timeout;
        loop {
            if Instant::now() > deadline {
                for t in drain_tasks.drain(..) {
                    t.abort();
                }
                return Err(BridgeError::SuperviseStartTimeout);
            }
            match guard.child_mut().try_wait() {
                Ok(Some(status)) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    for t in drain_tasks.drain(..) {
                        t.abort();
                    }
                    return Err(BridgeError::Supervise(format!(
                        "child exited before ready: {status}"
                    )));
                }
                Ok(None) => {
                    if seen.load(Ordering::SeqCst) {
                        match guard.child_mut().try_wait() {
                            Ok(None) => break SuperviseReadiness::DaemonReadyLine,
                            Ok(Some(status)) => {
                                for t in drain_tasks.drain(..) {
                                    t.abort();
                                }
                                return Err(BridgeError::Supervise(format!(
                                    "child exited before ready: {status}"
                                )));
                            }
                            Err(e) => {
                                for t in drain_tasks.drain(..) {
                                    t.abort();
                                }
                                return Err(BridgeError::Supervise(format!("try_wait: {e}")));
                            }
                        }
                    }
                }
                Err(e) => {
                    for t in drain_tasks.drain(..) {
                        t.abort();
                    }
                    return Err(BridgeError::Supervise(format!("try_wait: {e}")));
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };

    let child = guard.into_child();
    let inner = Arc::new(BridgeInner {
        workspace,
        config,
        lifecycle: Mutex::new(default_lifecycle()),
        mode: Mutex::new(ModeState::Supervise {
            child: Some(child),
            drain_tasks,
            kill_on_drop,
            readiness,
        }),
        stopped: AtomicBool::new(false),
        reserved: AtomicBool::new(true),
    });
    Ok(BridgeHandle::new(inner))
}

/// Kills the child if start is cancelled or fails after spawn.
struct SpawnGuard {
    child: Option<tokio::process::Child>,
}

impl SpawnGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child.as_mut().expect("spawn guard armed")
    }

    fn into_child(mut self) -> tokio::process::Child {
        self.child.take().expect("spawn guard armed")
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
            runtime_rt::block_on_global_best_effort(async move {
                let _ = tokio::time::timeout(STOP_GRACE, c.wait()).await;
            });
        }
    }
}

fn clear_ready_file_if_regular(rf: &Path) -> Result<(), BridgeError> {
    match std::fs::symlink_metadata(rf) {
        Ok(meta) if meta.file_type().is_symlink() => Err(BridgeError::InvalidConfig(
            "supervise_ready_file must not be a symlink".into(),
        )),
        Ok(meta) if meta.file_type().is_file() => std::fs::remove_file(rf).map_err(|e| {
            BridgeError::Supervise(format!("failed to clear ready_file before spawn: {e}"))
        }),
        Ok(_) => Err(BridgeError::InvalidConfig(
            "supervise_ready_file exists and is not a regular file".into(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BridgeError::Supervise(format!(
            "ready_file metadata: {e}"
        ))),
    }
}

/// True when `rf` is a non-empty regular file (symlink_metadata, no follow).
fn file_ready_regular(rf: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(rf) else {
        return false;
    };
    meta.file_type().is_file() && meta.len() > 0
}

async fn drain_discard<R>(mut reader: R)
where
    R: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 4096];
    loop {
        match reader.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Read chunks; cap each line at LINE_CAP so a newline-free flood cannot grow without bound.
async fn scan_limited_lines<R>(mut reader: R, marker: &str, seen: &AtomicBool)
where
    R: AsyncRead + Unpin,
{
    let mut acc = Vec::with_capacity(256);
    let mut tmp = [0u8; 4096];
    loop {
        let n = match reader.read(&mut tmp).await {
            Ok(0) => {
                if !acc.is_empty() && line_contains_marker(&String::from_utf8_lossy(&acc), marker) {
                    seen.store(true, Ordering::SeqCst);
                }
                break;
            }
            Ok(n) => n,
            Err(_) => break,
        };
        for &b in &tmp[..n] {
            if b == b'\n' {
                if line_contains_marker(&String::from_utf8_lossy(&acc), marker) {
                    seen.store(true, Ordering::SeqCst);
                }
                acc.clear();
            } else if acc.len() < LINE_CAP {
                acc.push(b);
            }
        }
    }
}

fn resolve_command(config: &BridgeConfig) -> Result<PathBuf, BridgeError> {
    if let Some(ref p) = config.supervise_command {
        return Ok(p.clone());
    }
    which_advance().ok_or_else(|| {
        BridgeError::InvalidConfig(
            "supervise requires advance binary on PATH or supervise_command".into(),
        )
    })
}

fn which_advance() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("advance");
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join("advance.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub fn line_contains_marker(line: &str, marker: &str) -> bool {
    line.contains(marker)
}

/// Silence unused import if resolve_config_path is kept for future CLI flags.
#[allow(dead_code)]
fn _cfg_path_hint(workspace: &Path, config: &BridgeConfig) -> Result<PathBuf, BridgeError> {
    resolve_config_path(workspace, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t12b_ready_detector() {
        assert!(line_contains_marker(
            "advance: runtime ready (workspace=foo)",
            "advance: runtime ready"
        ));
        assert!(!line_contains_marker(
            "still starting",
            "advance: runtime ready"
        ));
    }
}
