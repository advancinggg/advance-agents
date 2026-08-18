//! T105 / T107 — MODULE-001-AC-26 / AC-27 start-or-attach.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_along_home::{
    write_client_api_discovery, write_recognizable_home, write_selected_provider, AdoptError,
    AdoptPort, AlongHomeFirstOpen, CancelToken, ConnectError, HostAlongHome, PreflightFail,
    PreflightPort, RuntimeLauncher, RuntimeState, SecretBytes,
};
use advance_runtime::config::LlmProviderConfig;
use advance_runtime::runtime_lock::{inspect_lock, LockInspection};

struct CountLauncher {
    count: AtomicUsize,
    health: Arc<LoopbackHealth>,
    selected: Mutex<String>,
}

impl RuntimeLauncher for CountLauncher {
    fn start(&self, home: &Path, cancel: &CancelToken) -> Result<(), ConnectError> {
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        self.count.fetch_add(1, Ordering::SeqCst);
        materialize_running(home, &self.health.base, &self.selected.lock().unwrap());
        Ok(())
    }
}

struct PanicLauncher;
impl RuntimeLauncher for PanicLauncher {
    fn start(&self, _home: &Path, _cancel: &CancelToken) -> Result<(), ConnectError> {
        panic!("launcher must not start a second process against a live lock");
    }
}

struct InstantAdopt;
impl AdoptPort for InstantAdopt {
    fn wait_adopted(
        &self,
        _home: &Path,
        _expected: &str,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError> {
        if cancel.is_cancelled() {
            return Err(AdoptError::Cancelled);
        }
        Ok(())
    }
}

struct FailAdopt;
impl AdoptPort for FailAdopt {
    fn wait_adopted(
        &self,
        _home: &Path,
        _expected: &str,
        _cancel: &CancelToken,
    ) -> Result<(), AdoptError> {
        Err(AdoptError::ProviderNotAdopted {
            reason: "forced".into(),
        })
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

fn host(launcher: Arc<dyn RuntimeLauncher>, adopt: Arc<dyn AdoptPort>) -> HostAlongHome {
    HostAlongHome::with_ports_and_wait(
        Arc::new(PassPreflight),
        launcher,
        adopt,
        Duration::from_millis(400),
    )
}

#[test]
fn t105_idle_start_attach_no_second_launch() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let health = Arc::new(LoopbackHealth::bind());
    let launcher = Arc::new(CountLauncher {
        count: AtomicUsize::new(0),
        health: Arc::clone(&health),
        selected: Mutex::new("anthropic".into()),
    });
    let h = host(launcher.clone(), Arc::new(InstantAdopt));
    let handle = h.open(&path).unwrap();
    assert_eq!(h.runtime_state(&handle), RuntimeState::Idle);

    let connected = h
        .start_or_attach(&handle, &CancelToken::new())
        .expect("idle start");
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
    assert_eq!(h.runtime_state(&handle), RuntimeState::Running);
    assert_eq!(connected.client_api_base, health.base);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path.join(".runtime").join("client-api"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let again = h
        .start_or_attach(&handle, &CancelToken::new())
        .expect("attach while live");
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
    assert_eq!(again.client_api_base, health.base);
    assert_eq!(h.runtime_state(&handle), RuntimeState::Running);
}

#[test]
fn t105_starting_wait_then_attach() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let health = LoopbackHealth::bind();
    let pid = std::process::id();
    write_live_lock(&path, pid);
    let h = host(Arc::new(PanicLauncher), Arc::new(InstantAdopt));
    let handle = h.open(&path).unwrap();
    assert_eq!(h.runtime_state(&handle), RuntimeState::Starting);

    let home = path.clone();
    let base = health.base.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        write_client_api_discovery(&home, pid, &base).unwrap();
        write_selected_provider(&home, pid, "anthropic").unwrap();
    });

    let connected = h
        .start_or_attach(&handle, &CancelToken::new())
        .expect("starting wait");
    assert_eq!(connected.client_api_base, health.base);
    assert_eq!(h.runtime_state(&handle), RuntimeState::Running);
}

#[test]
fn t105_unattachable_then_failed_no_second_launch() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let pid = std::process::id();
    write_live_lock(&path, pid);
    write_client_api_discovery(&path, pid, "http://127.0.0.1:59999").unwrap();
    let launcher = Arc::new(CountLauncher {
        count: AtomicUsize::new(0),
        health: Arc::new(LoopbackHealth::bind()),
        selected: Mutex::new("anthropic".into()),
    });
    let h = host(launcher.clone(), Arc::new(InstantAdopt));
    let handle = h.open(&path).unwrap();
    let err = h.start_or_attach(&handle, &CancelToken::new()).unwrap_err();
    assert!(
        matches!(err, ConnectError::UnattachableThenFailed { .. }),
        "{err:?}"
    );
    assert_eq!(launcher.count.load(Ordering::SeqCst), 0);
}

#[test]
fn t105_stale_dead_pid_recovers_and_starts() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    write_stale_dead_pid_lock(&path);
    let health = Arc::new(LoopbackHealth::bind());
    let launcher = Arc::new(CountLauncher {
        count: AtomicUsize::new(0),
        health: Arc::clone(&health),
        selected: Mutex::new("anthropic".into()),
    });
    let h = host(launcher.clone(), Arc::new(InstantAdopt));
    let handle = h.open(&path).unwrap();
    assert_eq!(h.runtime_state(&handle), RuntimeState::Idle);
    let connected = h
        .start_or_attach(&handle, &CancelToken::new())
        .expect("stale recover");
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
    assert_eq!(connected.client_api_base, health.base);
    assert_eq!(h.runtime_state(&handle), RuntimeState::Running);
}

#[test]
fn t105_cancel_during_idle_start() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let h = host(
        Arc::new(CountLauncher {
            count: AtomicUsize::new(0),
            health: Arc::new(LoopbackHealth::bind()),
            selected: Mutex::new("anthropic".into()),
        }),
        Arc::new(InstantAdopt),
    );
    let handle = h.open(&path).unwrap();
    let cxl = CancelToken::new();
    cxl.cancel();
    assert!(matches!(
        h.start_or_attach(&handle, &cxl),
        Err(ConnectError::Cancelled)
    ));
}

#[test]
fn t105_adopt_ok_on_running_no_second_launch() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let health = Arc::new(LoopbackHealth::bind());
    let launcher = Arc::new(CountLauncher {
        count: AtomicUsize::new(0),
        health: Arc::clone(&health),
        selected: Mutex::new("anthropic".into()),
    });
    let adopt = Arc::new(advance_along_home::connect::FileAdoptPort {
        timeout: Duration::from_millis(400),
    });
    let h = host(launcher.clone(), adopt);
    let handle = h.open(&path).unwrap();
    h.start_or_attach(&handle, &CancelToken::new()).unwrap();
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);

    h.store_and_preflight(
        &handle,
        "openai",
        SecretBytes::new("sk-test-T105-adopt-ok"),
        &CancelToken::new(),
    )
    .unwrap();

    let home = path.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        write_selected_provider(&home, std::process::id(), "openai").unwrap();
    });

    let connected = h
        .start_or_attach(&handle, &CancelToken::new())
        .expect("adopt ok");
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
    assert_eq!(connected.client_api_base, health.base);
}

#[test]
fn t105_adopt_fail_on_running_no_second_launch() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("h");
    write_recognizable_home(&path).unwrap();
    let health = Arc::new(LoopbackHealth::bind());
    let launcher = Arc::new(CountLauncher {
        count: AtomicUsize::new(0),
        health: Arc::clone(&health),
        selected: Mutex::new("anthropic".into()),
    });
    let h = host(launcher.clone(), Arc::new(FailAdopt));
    let handle = h.open(&path).unwrap();
    h.start_or_attach(&handle, &CancelToken::new()).unwrap();
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);

    h.store_and_preflight(
        &handle,
        "openai",
        SecretBytes::new("sk-test-T105-adopt-fail"),
        &CancelToken::new(),
    )
    .unwrap();
    let err = h.start_or_attach(&handle, &CancelToken::new()).unwrap_err();
    assert!(matches!(err, ConnectError::AdoptFailed { .. }), "{err:?}");
    assert_eq!(launcher.count.load(Ordering::SeqCst), 1);
}

#[test]
fn t107_pre_daemon_full_trait() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path();
    let health = Arc::new(LoopbackHealth::bind());
    let h = host(
        Arc::new(CountLauncher {
            count: AtomicUsize::new(0),
            health: Arc::clone(&health),
            selected: Mutex::new("anthropic".into()),
        }),
        Arc::new(InstantAdopt),
    );
    let created = h.create(parent, "home").unwrap();
    assert!(matches!(
        h.recognize(created.path()),
        advance_along_home::RecognizeClass::Recognized { .. }
    ));
    let _ = h.provider_status(&created);
    h.store_and_preflight(
        &created,
        "anthropic",
        SecretBytes::new("sk-test-T107"),
        &CancelToken::new(),
    )
    .unwrap();
    h.set_display_name(&created, "Atlas").unwrap();
    assert_eq!(h.current_display_name(&created).as_deref(), Some("Atlas"));
    let started = h
        .start_or_attach(&created, &CancelToken::new())
        .expect("pre-daemon start_or_attach");
    assert_eq!(started.client_api_base, health.base);
}
