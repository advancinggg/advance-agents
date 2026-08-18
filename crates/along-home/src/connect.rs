//! start_or_attach / adopt / ProcessLauncher.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::cancel::CancelToken;
use crate::contract::{AdoptError, ConnectError, ConnectedAlong, RuntimeState};
use crate::discovery::read_client_api_discovery;
use crate::ports::{AdoptPort, RuntimeLauncher};
use crate::runtime_state::{committed_provider_id, read_selected_provider, runtime_state};

pub struct FileAdoptPort {
    pub timeout: Duration,
}

impl Default for FileAdoptPort {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }
}

impl AdoptPort for FileAdoptPort {
    fn wait_adopted(
        &self,
        home: &Path,
        expected_provider: &str,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError> {
        if runtime_state(home) != RuntimeState::Running {
            return Err(AdoptError::NotRunning);
        }
        let start = Instant::now();
        loop {
            if cancel.is_cancelled() {
                return Err(AdoptError::Cancelled);
            }
            if let Some(sel) = read_selected_provider(home) {
                let lock_ok = matches!(
                    advance_runtime::runtime_lock::inspect_lock(home),
                    advance_runtime::runtime_lock::LockInspection::Live { pid } if pid == sel.pid
                );
                if lock_ok && sel.provider_id == expected_provider {
                    return Ok(());
                }
            }
            if start.elapsed() >= self.timeout {
                return Err(AdoptError::ProviderNotAdopted {
                    reason: "timeout".into(),
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

pub struct ProcessLauncher;

impl RuntimeLauncher for ProcessLauncher {
    fn start(&self, home: &Path, cancel: &CancelToken) -> Result<(), ConnectError> {
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        let bin = resolve_advance_bin().ok_or(ConnectError::LaunchFailed {
            reason: "advance-bin-not-found".into(),
        })?;
        let mut cmd = Command::new(bin);
        cmd.arg("start")
            .arg("--workspace")
            .arg(home)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        if let Ok(Some(key)) = cap_secrets::read_workspace_master_key(home) {
            let rendered = zeroize::Zeroizing::new(hex::encode(*key));
            let env_name = advance_runtime::config::load_config(
                &home.join(".advance").join("runtime-config.yaml"),
            )
            .map(|c| c.secrets.env_var_name)
            .unwrap_or_else(|_| "SECRETS_MASTER_KEY".into());
            cmd.env(env_name, rendered.as_str());
        }
        cmd.spawn().map_err(|_| ConnectError::LaunchFailed {
            reason: "spawn-failed".into(),
        })?;
        Ok(())
    }
}

fn launch_claim_path(home: &Path) -> std::path::PathBuf {
    home.join(".runtime").join("launch.lock")
}

fn claim_launch(home: &Path) -> bool {
    let _ = std::fs::create_dir_all(home.join(".runtime"));
    let path = launch_claim_path(home);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    if opts.open(&path).is_ok() {
        return true;
    }
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        let stale = match meta.modified() {
            Ok(t) => t
                .elapsed()
                .map(|d| d > Duration::from_secs(2))
                .unwrap_or(true),
            Err(_) => true,
        };
        if stale || !meta.file_type().is_file() {
            let _ = std::fs::remove_file(&path);
            return opts.open(&path).is_ok();
        }
    }
    false
}

fn release_launch(home: &Path) {
    let _ = std::fs::remove_file(launch_claim_path(home));
}

fn resolve_advance_bin() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("ADVANCE_BIN") {
        let candidate = std::path::PathBuf::from(p);
        return candidate.is_file().then_some(candidate);
    }
    if let Ok(exe) = std::env::current_exe() {
        if exe
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n == "advance" || n == "advance.exe")
        {
            return Some(exe);
        }
    }
    which_advance()
}

fn which_advance() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("advance");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn start_or_attach(
    home: &Path,
    cancel: &CancelToken,
    launcher: &dyn RuntimeLauncher,
    adopt: &dyn AdoptPort,
    wait_bound: Duration,
) -> Result<ConnectedAlong, ConnectError> {
    if cancel.is_cancelled() {
        return Err(ConnectError::Cancelled);
    }
    match runtime_state(home) {
        RuntimeState::Starting => {
            wait_until_running(home, cancel, false, wait_bound)?;
            adopt_if_needed(home, cancel, adopt)?;
        }
        RuntimeState::Running => adopt_if_needed(home, cancel, adopt)?,
        RuntimeState::Idle => {
            if !claim_launch(home) {
                wait_until_running(home, cancel, false, wait_bound)?;
            } else {
                let started = launcher.start(home, cancel);
                if started.is_err() {
                    release_launch(home);
                    started?;
                }
                let waited = wait_until_running(home, cancel, true, wait_bound);
                release_launch(home);
                waited?;
            }
            adopt_if_needed(home, cancel, adopt)?;
        }
    }
    attach(home, cancel)
}

fn adopt_if_needed(
    home: &Path,
    cancel: &CancelToken,
    adopt: &dyn AdoptPort,
) -> Result<(), ConnectError> {
    if let Some(committed) = committed_provider_id(home) {
        let lock_pid = match advance_runtime::runtime_lock::inspect_lock(home) {
            advance_runtime::runtime_lock::LockInspection::Live { pid } => Some(pid),
            _ => None,
        };
        let already = read_selected_provider(home)
            .zip(lock_pid)
            .map(|(s, pid)| s.provider_id == committed && s.pid == pid)
            .unwrap_or(false);
        if !already {
            adopt
                .wait_adopted(home, &committed, cancel)
                .map_err(|e| match e {
                    AdoptError::Cancelled => ConnectError::Cancelled,
                    AdoptError::NotRunning | AdoptError::ProviderNotAdopted { .. } => {
                        ConnectError::AdoptFailed {
                            reason: format!("{e:?}"),
                        }
                    }
                })?;
        }
    }
    Ok(())
}

fn wait_until_running(
    home: &Path,
    cancel: &CancelToken,
    after_launch: bool,
    bound: Duration,
) -> Result<(), ConnectError> {
    let start = Instant::now();
    loop {
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        if runtime_state(home) == RuntimeState::Running {
            return Ok(());
        }
        if start.elapsed() >= bound {
            if after_launch {
                return Err(ConnectError::LaunchFailed {
                    reason: "timeout".into(),
                });
            }
            // one more attach attempt is done by attach() below
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn attach(home: &Path, cancel: &CancelToken) -> Result<ConnectedAlong, ConnectError> {
    if cancel.is_cancelled() {
        return Err(ConnectError::Cancelled);
    }
    // Always re-bind pid + health so a swapped discovery file cannot redirect attach.
    if let Some(d) = read_client_api_discovery(home) {
        let pid_ok = matches!(
            advance_runtime::runtime_lock::inspect_lock(home),
            advance_runtime::runtime_lock::LockInspection::Live { pid } if pid == d.pid
        );
        if pid_ok && crate::discovery::client_api_accepts(&d.client_api_base) {
            return Ok(ConnectedAlong {
                home: home.to_path_buf(),
                client_api_base: d.client_api_base,
            });
        }
    }
    Err(ConnectError::UnattachableThenFailed {
        reason: "unattachable".into(),
    })
}

pub fn adopt_on_running(
    home: &Path,
    cancel: &CancelToken,
    adopt: &dyn AdoptPort,
) -> Result<(), AdoptError> {
    if cancel.is_cancelled() {
        return Err(AdoptError::Cancelled);
    }
    let expected = committed_provider_id(home).ok_or(AdoptError::ProviderNotAdopted {
        reason: "no-committed-provider".into(),
    })?;
    adopt.wait_adopted(home, &expected, cancel)
}
