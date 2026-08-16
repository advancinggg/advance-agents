//! Supervise mode: spawn child on GLOBAL_RT, readiness line or file.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::config::{confine_under_workspace, BridgeConfig};
use crate::error::BridgeError;
use crate::handle::{default_lifecycle, BridgeHandle, BridgeInner, ModeState};
use crate::registry;
use crate::types::SuperviseReadiness;
use crate::workspace::prepare_workspace;

const STOP_GRACE: Duration = Duration::from_secs(5);

/// Supervise start (must run on GLOBAL_RT).
pub async fn start_supervise(
    workspace_root: &Path,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    config.validate()?;
    let workspace = prepare_workspace(workspace_root)?;
    registry::reserve(workspace.clone())?;

    let result = start_supervise_inner(workspace.clone(), config).await;
    if result.is_err() {
        registry::release(&workspace);
    }
    result
}

async fn start_supervise_inner(
    workspace: PathBuf,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    let cmd_path = resolve_command(&config)?;
    let ready_file = if let Some(ref rf) = config.supervise_ready_file {
        Some(confine_under_workspace(&workspace, rf)?)
    } else {
        None
    };

    if let Some(ref rf) = ready_file {
        if rf.exists() {
            std::fs::remove_file(rf).map_err(|e| {
                BridgeError::Supervise(format!("failed to clear ready_file before spawn: {e}"))
            })?;
        }
    }

    let kill_on_drop = config.supervise_kill_on_drop;
    let use_file_ready = ready_file.is_some();
    // Pipe only when we need line readiness; file readiness uses null stdio so
    // pipes never fill. Keep-available also uses null.
    let pipe_stdio = kill_on_drop && !use_file_ready;
    let mut command = Command::new(&cmd_path);
    command
        .arg("start")
        .arg("--workspace")
        .arg(&workspace)
        .kill_on_drop(false);

    if pipe_stdio {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let mut child = command
        .spawn()
        .map_err(|e| BridgeError::Supervise(format!("spawn: {e}")))?;

    let spawn_at = Instant::now();
    let spawn_sys = SystemTime::now();
    let timeout = config.ready_timeout();
    let marker = config.ready_marker().to_string();

    let mut drain_tasks = Vec::new();
    let readiness = if let Some(ref rf) = ready_file {
        // File readiness: require post-spawn mtime (no fail-open on stale content).
        let rf = rf.clone();
        let deadline = spawn_at + timeout;
        loop {
            if Instant::now() > deadline {
                reap_child(&mut child).await;
                return Err(BridgeError::SuperviseStartTimeout);
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(BridgeError::Supervise(format!(
                    "child exited before ready: {status}"
                )));
            }
            if rf.is_file() {
                if let Ok(meta) = std::fs::metadata(&rf) {
                    let post_spawn = meta
                        .modified()
                        .ok()
                        .and_then(|m| m.duration_since(spawn_sys).ok())
                        .is_some();
                    if post_spawn && meta.len() > 0 {
                        break SuperviseReadiness::ReadyFile;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    } else {
        // Line readiness with continuous drain
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BridgeError::Supervise("missing stdout".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BridgeError::Supervise("missing stderr".into()))?;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let tx2 = tx.clone();
        let m1 = marker.clone();
        drain_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(line);
            }
        }));
        drain_tasks.push(tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx2.send(line);
            }
        }));
        let deadline = spawn_at + timeout;
        let mut latched = false;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                for t in drain_tasks.drain(..) {
                    t.abort();
                }
                return Err(BridgeError::Supervise(format!(
                    "child exited before ready: {status}"
                )));
            }
            while let Ok(line) = rx.try_recv() {
                if line_contains_marker(&line, &m1) {
                    latched = true;
                    break;
                }
            }
            if latched {
                // Keep draining in background until exit (tasks already running).
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if !latched {
            for t in drain_tasks.drain(..) {
                t.abort();
            }
            reap_child(&mut child).await;
            return Err(BridgeError::SuperviseStartTimeout);
        }
        // Continue draining remaining lines on existing tasks; spawn a no-op consumer.
        drain_tasks.push(tokio::spawn(async move {
            while rx.recv().await.is_some() {}
        }));
        SuperviseReadiness::DaemonReadyLine
    };

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

async fn reap_child(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(STOP_GRACE, child.wait()).await;
    let _ = child.start_kill();
    let _ = tokio::time::timeout(STOP_GRACE, child.wait()).await;
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
        assert!(!line_contains_marker("still starting", "advance: runtime ready"));
    }
}
