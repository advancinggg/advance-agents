//! MODULE-001-AC-34 — injectable `RuntimeAttachSource` and the pid-lock default.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_home::discovery::{client_api_accepts, read_client_api_discovery};
use advance_home::runtime_state::{read_selected_provider, runtime_state};
use advance_home::{
    write_client_api_discovery, write_recognizable_home, write_selected_provider, AttachSession,
    AttachTarget, CancelToken, ConnectError, ConnectedRuntime, FileAttachSource, HostWorkspaceHome,
    PreflightFail, PreflightPort, RuntimeAttachSource, RuntimeLauncher, RuntimeState, SecretBytes,
    SelectedProvider, SourceAdoptPort, WorkspaceHomeFirstOpen, WorkspaceHomeHandle,
};
use advance_runtime::config::LlmProviderConfig;
use advance_runtime::runtime_lock::{inspect_lock, inspect_lock_with_policy, LockInspection};
use advance_shared_types::process_policy::ProcessPolicy;

struct RecordingSource {
    calls: Mutex<Vec<&'static str>>,
    state: Mutex<RuntimeState>,
    live_pid: Mutex<Option<u32>>,
    selected: Mutex<Option<SelectedProvider>>,
    target: Mutex<Option<AttachTarget>>,
    claim: Mutex<bool>,
}

impl RecordingSource {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            state: Mutex::new(RuntimeState::Idle),
            live_pid: Mutex::new(None),
            selected: Mutex::new(None),
            target: Mutex::new(None),
            claim: Mutex::new(true),
        }
    }

    fn record(&self, name: &'static str) {
        self.calls.lock().expect("calls").push(name);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("calls").clone()
    }
}

impl RuntimeAttachSource for RecordingSource {
    fn runtime_state(&self, _home: &Path) -> RuntimeState {
        self.record("runtime_state");
        *self.state.lock().expect("state")
    }

    fn live_pid(&self, _home: &Path) -> Option<u32> {
        self.record("live_pid");
        *self.live_pid.lock().expect("live_pid")
    }

    fn selected_provider(&self, _home: &Path) -> Option<SelectedProvider> {
        self.record("selected_provider");
        self.selected.lock().expect("selected").clone()
    }

    fn attach(&self, _home: &Path) -> Option<AttachTarget> {
        self.record("attach");
        self.target.lock().expect("target").clone()
    }

    fn claim_launch(&self, _home: &Path) -> bool {
        self.record("claim_launch");
        *self.claim.lock().expect("claim")
    }

    fn release_launch(&self, _home: &Path) {
        self.record("release_launch");
    }
}

struct FlipLauncher {
    count: AtomicUsize,
    source: Arc<RecordingSource>,
}

impl RuntimeLauncher for FlipLauncher {
    fn start(&self, _home: &Path, cancel: &CancelToken) -> Result<(), ConnectError> {
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        self.count.fetch_add(1, Ordering::SeqCst);
        *self.source.state.lock().expect("state") = RuntimeState::Running;
        *self.source.live_pid.lock().expect("live_pid") = Some(4242);
        *self.source.selected.lock().expect("selected") = Some(SelectedProvider {
            pid: 4242,
            provider_id: "anthropic".into(),
        });
        Ok(())
    }
}

struct PanicLauncher;
impl RuntimeLauncher for PanicLauncher {
    fn start(&self, _home: &Path, _cancel: &CancelToken) -> Result<(), ConnectError> {
        panic!("launcher must not start a second process against a live lock");
    }
}

struct PassPreflight;
impl PreflightPort for PassPreflight {
    fn preflight(
        &self,
        _home: &Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        if cancel.is_cancelled() {
            return Err(PreflightFail::Cancelled);
        }
        Ok(())
    }
}

struct NoPreflight;
impl PreflightPort for NoPreflight {
    fn preflight(
        &self,
        _home: &Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        _cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        panic!("preflight must not run")
    }
}

struct LoopbackHealth {
    base: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl LoopbackHealth {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let mut buf = [0u8; 64];
                        let _ = s.read(&mut buf);
                        let _ = s.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self { base, stop }
    }
}

impl Drop for LoopbackHealth {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn write_live_lock(home: &Path, pid: u32) {
    fs::create_dir_all(home.join(".runtime")).unwrap();
    let lstart = std::process::Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|o| {
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    let uid = format!("{}:{pid}:{lstart}", std::env::consts::OS);
    let now = chrono::Utc::now().to_rfc3339();
    let body = format!(
        "pid: {pid}\nplatform_uid: \"{uid}\"\nstarted_at: \"{now}\"\nheartbeat_at: \"{now}\"\nworkspace_root: \"{}\"\nversion: \"0.1.0\"\n",
        home.display()
    );
    fs::write(home.join(".runtime").join("runtime.lock"), body).unwrap();
    assert!(matches!(
        inspect_lock(home),
        LockInspection::Live { pid: p } if p == pid
    ));
}

fn write_stale_dead_pid_lock(home: &Path) {
    fs::create_dir_all(home.join(".runtime")).unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    let body = format!(
        "pid: 999999\nplatform_uid: \"dead\"\nstarted_at: \"{now}\"\nheartbeat_at: \"{now}\"\nworkspace_root: \"{}\"\nversion: \"0.1.0\"\n",
        home.display()
    );
    fs::write(home.join(".runtime").join("runtime.lock"), body).unwrap();
    assert!(matches!(inspect_lock(home), LockInspection::Stale { .. }));
}

fn materialize_running(home: &Path, base: &str, provider: &str) {
    let pid = std::process::id();
    write_live_lock(home, pid);
    write_client_api_discovery(home, pid, base).unwrap();
    write_selected_provider(home, pid, provider).unwrap();
}

fn expected_live_pid(home: &Path, policy: ProcessPolicy) -> Option<u32> {
    match inspect_lock_with_policy(home, policy) {
        LockInspection::Live { pid } => Some(pid),
        _ => None,
    }
}

fn expected_attach(home: &Path, policy: ProcessPolicy) -> Option<AttachTarget> {
    let d = read_client_api_discovery(home)?;
    let pid_ok = expected_live_pid(home, policy) == Some(d.pid);
    if pid_ok && client_api_accepts(&d.client_api_base) {
        Some(AttachTarget {
            client_api_base: d.client_api_base,
            session: None,
        })
    } else {
        None
    }
}

fn expected_runtime_state(home: &Path, policy: ProcessPolicy) -> RuntimeState {
    match inspect_lock_with_policy(home, policy) {
        LockInspection::Absent | LockInspection::Stale { .. } => RuntimeState::Idle,
        LockInspection::Live { pid } => {
            let Some(disc) = read_client_api_discovery(home) else {
                return RuntimeState::Starting;
            };
            if disc.pid != pid {
                return RuntimeState::Starting;
            }
            if client_api_accepts(&disc.client_api_base) {
                RuntimeState::Running
            } else {
                RuntimeState::Starting
            }
        }
    }
}

fn assert_source_matches_free_functions(home: &Path, policy: ProcessPolicy) {
    let source = FileAttachSource::with_policy(policy);
    assert_eq!(
        source.runtime_state(home),
        expected_runtime_state(home, policy)
    );
    assert_eq!(source.live_pid(home), expected_live_pid(home, policy));
    assert_eq!(source.selected_provider(home), read_selected_provider(home));
    let got = source.attach(home);
    let want = expected_attach(home, policy);
    assert_eq!(got, want);
    if let Some(t) = got {
        assert!(t.session.is_none());
    }
    if policy == ProcessPolicy::Allow {
        assert_eq!(source.runtime_state(home), runtime_state(home));
        assert_eq!(
            FileAttachSource::new().runtime_state(home),
            runtime_state(home)
        );
        assert_eq!(FileAttachSource::new().attach(home), want);
    }
}

fn no_c243_files(home: &Path) {
    let runtime = home.join(".runtime");
    assert!(!runtime.join("launch.lock").exists());
    assert!(!runtime.join("client-api").exists());
    assert!(!runtime.join("runtime.lock").exists());
}

fn created_home(tmp: &tempfile::TempDir) -> (HostWorkspaceHome, WorkspaceHomeHandle) {
    let host = HostWorkspaceHome::production();
    let handle = host.create(tmp.path(), "home").unwrap();
    (host, handle)
}

#[test]
fn module_001_ac34_injected_source_drives_start_or_attach_and_attach() {
    let tmp = tempfile::tempdir().unwrap();
    let (_created, handle) = created_home(&tmp);
    let source = Arc::new(RecordingSource::new());
    *source.target.lock().expect("target") = Some(AttachTarget {
        client_api_base: "http://127.0.0.1:4242".into(),
        session: Some(AttachSession::new("sess_rec", "tok-rec".into(), u64::MAX)),
    });
    let launcher = Arc::new(FlipLauncher {
        count: AtomicUsize::new(0),
        source: Arc::clone(&source),
    });
    let host = HostWorkspaceHome::with_attach_source(
        Arc::new(NoPreflight),
        launcher.clone(),
        source.clone(),
    );
    assert_eq!(host.runtime_state(&handle), RuntimeState::Idle);
    let cancel = CancelToken::new();
    let connected = host.start_or_attach(&handle, &cancel).unwrap();
    assert_eq!(connected.client_api_base, "http://127.0.0.1:4242");
    let session = connected.session.expect("session");
    assert_eq!(session.session_id(), "sess_rec");
    assert_eq!(session.bearer_token(), "tok-rec");
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        source.calls(),
        [
            "runtime_state",
            "runtime_state",
            "claim_launch",
            "runtime_state",
            "release_launch",
            "live_pid",
            "selected_provider",
            "attach",
        ]
    );
    source.calls.lock().expect("calls").clear();
    let connected2 = host.start_or_attach(&handle, &cancel).unwrap();
    assert_eq!(connected2.client_api_base, connected.client_api_base);
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        source.calls(),
        ["runtime_state", "live_pid", "selected_provider", "attach",]
    );
    no_c243_files(handle.path());
}

#[test]
fn module_001_ac34_injected_source_drives_adopt_through_source_adopt_port() {
    let tmp = tempfile::tempdir().unwrap();
    let (_created, handle) = created_home(&tmp);
    let source = Arc::new(RecordingSource::new());
    *source.target.lock().expect("target") = Some(AttachTarget {
        client_api_base: "http://127.0.0.1:4242".into(),
        session: Some(AttachSession::new("sess_rec", "tok-rec".into(), u64::MAX)),
    });
    let launcher = Arc::new(FlipLauncher {
        count: AtomicUsize::new(0),
        source: Arc::clone(&source),
    });
    let host = HostWorkspaceHome::with_attach_source(
        Arc::new(PassPreflight),
        launcher.clone(),
        source.clone(),
    );
    let cancel = CancelToken::new();
    host.start_or_attach(&handle, &cancel).unwrap();
    host.store_and_preflight(
        &handle,
        "openai",
        SecretBytes::new("sk-test-ac34-adopt"),
        &cancel,
    )
    .unwrap();
    source.calls.lock().expect("calls").clear();
    let source_for_thread = Arc::clone(&source);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        *source_for_thread.selected.lock().expect("selected") = Some(SelectedProvider {
            pid: 4242,
            provider_id: "openai".into(),
        });
    });
    let connected = host.start_or_attach(&handle, &cancel).unwrap();
    assert_eq!(connected.client_api_base, "http://127.0.0.1:4242");
    let selected_reads = source
        .calls()
        .into_iter()
        .filter(|c| *c == "selected_provider")
        .count();
    assert!(
        selected_reads >= 2,
        "SourceAdoptPort must poll selected_provider, got {:?}",
        source.calls()
    );
    host.adopt_provider_on_running(&handle, &cancel).unwrap();
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);

    let mut short = SourceAdoptPort::new(source.clone());
    short.timeout = Duration::from_millis(200);
    *source.selected.lock().expect("selected") = Some(SelectedProvider {
        pid: 4242,
        provider_id: "anthropic".into(),
    });
    let host_short = HostWorkspaceHome::with_ports_source_and_wait(
        Arc::new(PassPreflight),
        launcher.clone(),
        Arc::new(short),
        source.clone(),
        Duration::from_secs(30),
    );
    host_short
        .store_and_preflight(
            &handle,
            "openai",
            SecretBytes::new("sk-test-ac34-adopt-neg"),
            &cancel,
        )
        .unwrap();
    let err = host_short
        .start_or_attach(&handle, &cancel)
        .expect_err("adopt timeout");
    assert!(matches!(err, ConnectError::AdoptFailed { .. }));
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
    no_c243_files(handle.path());
}

#[test]
fn module_001_ac34_process_policy_setter_keeps_an_injected_source() {
    let tmp = tempfile::tempdir().unwrap();
    let (_created, handle) = created_home(&tmp);
    let source = Arc::new(RecordingSource::new());
    let launcher = Arc::new(PanicLauncher);
    let host =
        HostWorkspaceHome::with_attach_source(Arc::new(NoPreflight), launcher, source.clone())
            .with_process_policy(ProcessPolicy::Forbid);
    assert_eq!(host.runtime_state(&handle), RuntimeState::Idle);
    assert_eq!(source.calls(), ["runtime_state"]);
}

#[test]
fn module_001_ac34_default_source_equals_the_free_functions() {
    let tmp = tempfile::tempdir().unwrap();
    write_recognizable_home(tmp.path()).unwrap();
    let home = tmp.path();
    let health = LoopbackHealth::bind();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_base = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let pid = std::process::id();

    let check = |home: &Path| {
        for policy in [ProcessPolicy::Allow, ProcessPolicy::Forbid] {
            assert_source_matches_free_functions(home, policy);
        }
    };

    let _ = fs::remove_dir_all(home.join(".runtime"));
    check(home);

    let _ = fs::remove_dir_all(home.join(".runtime"));
    write_stale_dead_pid_lock(home);
    check(home);

    let _ = fs::remove_dir_all(home.join(".runtime"));
    write_live_lock(home, pid);
    check(home);

    let _ = fs::remove_dir_all(home.join(".runtime"));
    write_live_lock(home, pid);
    write_client_api_discovery(home, pid.wrapping_add(1), &health.base).unwrap();
    check(home);

    let _ = fs::remove_dir_all(home.join(".runtime"));
    materialize_running(home, &health.base, "anthropic");
    check(home);

    let _ = fs::remove_dir_all(home.join(".runtime"));
    write_live_lock(home, pid);
    write_client_api_discovery(home, pid, &closed_base).unwrap();
    check(home);
}

#[test]
fn module_001_ac34_default_launch_claim_is_the_launch_lock_file() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let source = FileAttachSource::new();
    assert!(source.claim_launch(home));
    let path = home.join(".runtime").join("launch.lock");
    let meta = fs::metadata(&path).unwrap();
    assert!(meta.is_file());
    assert_eq!(meta.len(), 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
    assert!(!source.claim_launch(home));
    let dest = std::time::SystemTime::now() - Duration::from_secs(3);
    fs::File::open(&path).unwrap().set_modified(dest).unwrap();
    assert!(source.claim_launch(home));
    source.release_launch(home);
    assert!(!path.exists());
    source.release_launch(home);
    assert!(!path.exists());
}

#[test]
fn module_001_ac34_runtime_launcher_trait_is_unchanged() {
    let src = include_str!("../src/ports.rs");
    assert!(
        src.contains(
            "pub trait RuntimeLauncher: Send + Sync {\n    fn start(&self, home: &Path, cancel: &CancelToken) -> Result<(), ConnectError>;\n}"
        ),
        "RuntimeLauncher trait block moved or changed"
    );
}

#[test]
fn module_001_ac34_connected_runtime_debug_redacts_the_session() {
    let session = AttachSession::new("sess_x", "tok-T115-redact".into(), 1);
    assert_eq!(session.bearer_token(), "tok-T115-redact");
    let target = AttachTarget {
        client_api_base: "http://127.0.0.1:1".into(),
        session: Some(session.clone()),
    };
    let connected = ConnectedRuntime {
        home: PathBuf::from("/tmp/x"),
        client_api_base: "http://127.0.0.1:1".into(),
        session: Some(session),
    };
    for dbg in [format!("{connected:?}"), format!("{target:?}")] {
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(dbg.contains("sess_x"), "{dbg}");
        assert!(!dbg.contains("tok-T115-redact"), "{dbg}");
    }
}
