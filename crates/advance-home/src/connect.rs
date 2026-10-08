//! start_or_attach / adopt / ProcessLauncher.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cancel::CancelToken;
use crate::contract::{AdoptError, ConnectError, ConnectedRuntime, RuntimeState};
use crate::discovery::read_client_api_discovery;
use crate::ports::{AdoptPort, AttachTarget, RuntimeAttachSource, RuntimeLauncher};
use crate::runtime_state::{
    committed_provider_id, read_selected_provider, runtime_state_with_policy, SelectedProvider,
};
use advance_runtime::runtime_lock::inspect_lock_with_policy;
use advance_shared_types::process_policy::{ProcessPolicy, SpawnSite, PROCESS_FORBIDDEN};

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
        wait_adopted_via(
            &FileAttachSource::new(),
            self.timeout,
            home,
            expected_provider,
            cancel,
        )
    }
}

fn wait_adopted_via(
    source: &dyn RuntimeAttachSource,
    timeout: Duration,
    home: &Path,
    expected_provider: &str,
    cancel: &CancelToken,
) -> Result<(), AdoptError> {
    if source.runtime_state(home) != RuntimeState::Running {
        return Err(AdoptError::NotRunning);
    }
    let start = Instant::now();
    loop {
        if cancel.is_cancelled() {
            return Err(AdoptError::Cancelled);
        }
        if let Some(sel) = source.selected_provider(home) {
            let lock_ok = source.live_pid(home) == Some(sel.pid);
            if lock_ok && sel.provider_id == expected_provider {
                return Ok(());
            }
        }
        if start.elapsed() >= timeout {
            return Err(AdoptError::ProviderNotAdopted {
                reason: "timeout".into(),
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// [`AdoptPort`] over an attach source: [`FileAdoptPort`]'s wait, reading `source`.
pub struct SourceAdoptPort {
    source: Arc<dyn RuntimeAttachSource>,
    pub timeout: Duration,
}

impl SourceAdoptPort {
    pub fn new(source: Arc<dyn RuntimeAttachSource>) -> Self {
        Self {
            source,
            timeout: Duration::from_secs(30),
        }
    }
}

impl AdoptPort for SourceAdoptPort {
    fn wait_adopted(
        &self,
        home: &Path,
        expected_provider: &str,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError> {
        wait_adopted_via(
            self.source.as_ref(),
            self.timeout,
            home,
            expected_provider,
            cancel,
        )
    }
}

/// The policy-aware adopt port: [`FileAdoptPort`]'s wait, with lock reads under `policy`.
pub struct GuardedFileAdoptPort {
    pub timeout: Duration,
    pub policy: ProcessPolicy,
}

impl GuardedFileAdoptPort {
    pub fn new(policy: ProcessPolicy) -> Self {
        Self {
            timeout: Duration::from_secs(30),
            policy,
        }
    }
}

impl AdoptPort for GuardedFileAdoptPort {
    fn wait_adopted(
        &self,
        home: &Path,
        expected_provider: &str,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError> {
        wait_adopted_via(
            &FileAttachSource::with_policy(self.policy),
            self.timeout,
            home,
            expected_provider,
            cancel,
        )
    }
}

pub struct ProcessLauncher;

/// CONTRACT-243 launcher that obeys a `ProcessPolicy`: under `Forbid`
/// `Err(ConnectError::LaunchFailed { reason: "process_forbidden" })`, nothing spawned and
/// no key or config read; under `Allow` exactly [`ProcessLauncher`].
pub struct GuardedProcessLauncher {
    policy: ProcessPolicy,
}

impl GuardedProcessLauncher {
    pub fn new(policy: ProcessPolicy) -> Self {
        Self { policy }
    }
}

impl RuntimeLauncher for ProcessLauncher {
    fn start(&self, home: &Path, cancel: &CancelToken) -> Result<(), ConnectError> {
        launch_daemon(home, cancel, ProcessPolicy::Allow)
    }
}

impl RuntimeLauncher for GuardedProcessLauncher {
    fn start(&self, home: &Path, cancel: &CancelToken) -> Result<(), ConnectError> {
        launch_daemon(home, cancel, self.policy)
    }
}

pub(crate) fn launch_daemon(
    home: &Path,
    cancel: &CancelToken,
    policy: ProcessPolicy,
) -> Result<(), ConnectError> {
    if cancel.is_cancelled() {
        return Err(ConnectError::Cancelled);
    }
    if policy.check(SpawnSite::DaemonLauncher).is_err() {
        return Err(ConnectError::LaunchFailed {
            reason: PROCESS_FORBIDDEN.into(),
        });
    }
    let bin = resolve_advance_bin().ok_or(ConnectError::LaunchFailed {
        reason: "advance-bin-not-found".into(),
    })?;
    if policy.admit(SpawnSite::DaemonLauncher).is_err() {
        return Err(ConnectError::LaunchFailed {
            reason: PROCESS_FORBIDDEN.into(),
        });
    }
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

/// The default attach source: the AC-06 pid lock, `.runtime/client-api`, `.runtime/selected-provider`
/// and `.runtime/launch.lock`, exactly as OSS v0.1.28 reads and writes them. Lock reads use
/// `policy`'s liveness probe (the spawned `kill -0` / `ps` under `Allow`, the in-process probe under
/// `Forbid`); nothing else depends on the policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileAttachSource {
    policy: ProcessPolicy,
}

impl FileAttachSource {
    /// `ProcessPolicy::Allow`: the reads and writes `start_or_attach` makes.
    pub const fn new() -> Self {
        Self {
            policy: ProcessPolicy::Allow,
        }
    }

    /// The reads and writes `start_or_attach_with_policy(.., policy)` makes.
    pub const fn with_policy(policy: ProcessPolicy) -> Self {
        Self { policy }
    }

    pub const fn policy(&self) -> ProcessPolicy {
        self.policy
    }
}

impl RuntimeAttachSource for FileAttachSource {
    fn runtime_state(&self, home: &Path) -> RuntimeState {
        runtime_state_with_policy(home, self.policy)
    }

    fn live_pid(&self, home: &Path) -> Option<u32> {
        match inspect_lock_with_policy(home, self.policy) {
            advance_runtime::runtime_lock::LockInspection::Live { pid } => Some(pid),
            _ => None,
        }
    }

    fn selected_provider(&self, home: &Path) -> Option<SelectedProvider> {
        read_selected_provider(home)
    }

    fn attach(&self, home: &Path) -> Option<AttachTarget> {
        let d = read_client_api_discovery(home)?;
        let pid_ok = self.live_pid(home) == Some(d.pid);
        if pid_ok && crate::discovery::client_api_accepts(&d.client_api_base) {
            Some(AttachTarget {
                client_api_base: d.client_api_base,
                session: None,
            })
        } else {
            None
        }
    }

    fn claim_launch(&self, home: &Path) -> bool {
        claim_launch(home)
    }

    fn release_launch(&self, home: &Path) {
        release_launch(home)
    }
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
) -> Result<ConnectedRuntime, ConnectError> {
    start_or_attach_via(
        home,
        cancel,
        launcher,
        adopt,
        &FileAttachSource::new(),
        wait_bound,
    )
}

pub fn start_or_attach_with_policy(
    home: &Path,
    cancel: &CancelToken,
    launcher: &dyn RuntimeLauncher,
    adopt: &dyn AdoptPort,
    wait_bound: Duration,
    policy: ProcessPolicy,
) -> Result<ConnectedRuntime, ConnectError> {
    start_or_attach_via(
        home,
        cancel,
        launcher,
        adopt,
        &FileAttachSource::with_policy(policy),
        wait_bound,
    )
}

/// `start_or_attach` over an injected attach source (MODULE-001-AC-34). Synchronous: it sleeps and
/// probes on the calling thread (see `InProcessLauncher` for the in-process calling rule).
pub fn start_or_attach_via(
    home: &Path,
    cancel: &CancelToken,
    launcher: &dyn RuntimeLauncher,
    adopt: &dyn AdoptPort,
    source: &dyn RuntimeAttachSource,
    wait_bound: Duration,
) -> Result<ConnectedRuntime, ConnectError> {
    if cancel.is_cancelled() {
        return Err(ConnectError::Cancelled);
    }
    match source.runtime_state(home) {
        RuntimeState::Starting => {
            wait_until_running(home, cancel, false, wait_bound, source)?;
            adopt_if_needed(home, cancel, adopt, source)?;
        }
        RuntimeState::Running => adopt_if_needed(home, cancel, adopt, source)?,
        RuntimeState::Idle => {
            if !source.claim_launch(home) {
                wait_until_running(home, cancel, false, wait_bound, source)?;
            } else {
                let started = launcher.start(home, cancel);
                if started.is_err() {
                    source.release_launch(home);
                    started?;
                }
                let waited = wait_until_running(home, cancel, true, wait_bound, source);
                source.release_launch(home);
                waited?;
            }
            adopt_if_needed(home, cancel, adopt, source)?;
        }
    }
    attach_via(home, cancel, source)
}

fn adopt_if_needed(
    home: &Path,
    cancel: &CancelToken,
    adopt: &dyn AdoptPort,
    source: &dyn RuntimeAttachSource,
) -> Result<(), ConnectError> {
    if let Some(committed) = committed_provider_id(home) {
        let lock_pid = source.live_pid(home);
        let already = source
            .selected_provider(home)
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
    source: &dyn RuntimeAttachSource,
) -> Result<(), ConnectError> {
    let start = Instant::now();
    loop {
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        if source.runtime_state(home) == RuntimeState::Running {
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

fn attach_via(
    home: &Path,
    cancel: &CancelToken,
    source: &dyn RuntimeAttachSource,
) -> Result<ConnectedRuntime, ConnectError> {
    if cancel.is_cancelled() {
        return Err(ConnectError::Cancelled);
    }
    source
        .attach(home)
        .map(|t| ConnectedRuntime {
            home: home.to_path_buf(),
            client_api_base: t.client_api_base,
            session: t.session,
        })
        .ok_or(ConnectError::UnattachableThenFailed {
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

#[cfg(test)]
mod module_001_ac32_tests {
    use super::*;
    use crate::contract::WorkspaceHomeHandle;
    use crate::impls::HostWorkspaceHome;
    use crate::runtime_state::runtime_state;
    use crate::WorkspaceHomeFirstOpen;
    use advance_runtime::runtime_lock::RuntimeLock;
    use advance_shared_types::process_policy::spawn_counter;
    use std::sync::Mutex;

    static COUNTER_SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        COUNTER_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn module_001_ac32_t113_3_process_launcher_refused_under_forbid() {
        let _guard = serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path();
        let cancel = CancelToken::new();
        let w0 = spawn_counter::snapshot();
        let err = GuardedProcessLauncher::new(ProcessPolicy::Forbid)
            .start(home, &cancel)
            .expect_err("forbid start");
        assert!(
            matches!(err, ConnectError::LaunchFailed { reason } if reason == PROCESS_FORBIDDEN)
        );
        let handle = WorkspaceHomeHandle {
            path: home.to_path_buf(),
        };
        let err = HostWorkspaceHome::production_with_policy(ProcessPolicy::Forbid)
            .start_or_attach(&handle, &cancel)
            .expect_err("forbid attach");
        assert!(
            matches!(err, ConnectError::LaunchFailed { reason } if reason == PROCESS_FORBIDDEN)
        );
        let delta = spawn_counter::snapshot().since(&w0);
        assert_eq!(delta.refused(SpawnSite::DaemonLauncher), 2);
        assert_eq!(delta.admitted(SpawnSite::DaemonLauncher), 0);
        assert!(!home.join(".runtime").join("launch.lock").exists());
    }

    #[test]
    fn module_001_ac32_host_home_lock_reads_use_the_in_process_probe_under_forbid() {
        let _guard = serial();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let home = dir.path();
            let lock = RuntimeLock::acquire(home, Duration::from_secs(30))
                .await
                .expect("acquire");
            let w0 = spawn_counter::snapshot();
            assert_eq!(
                runtime_state_with_policy(home, ProcessPolicy::Forbid),
                RuntimeState::Starting
            );
            let delta = spawn_counter::snapshot().since(&w0);
            assert_eq!(delta.admitted(SpawnSite::PidLockProbe), 0);
            assert_eq!(delta.refused(SpawnSite::PidLockProbe), 2);
            assert_eq!(runtime_state(home), RuntimeState::Starting);
            drop(lock);
        });
    }
}
