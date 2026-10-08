//! MODULE-001-T113 (7) — an in-process `compose` of the desktop embedded row
//! is refused by a live `advance start` pid lock (Allow and Forbid), and a
//! v2 `full` handle is refused by the same live lock.
#![cfg(unix)]

#[path = "support/live_daemon.rs"]
mod live_daemon;

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use advance_client_api::API_VERSION;
use advance_embedded_runtime_bridge::ffi::{
    advance_bridge_last_error, advance_bridge_start_v2, AdvanceBridgeHandle,
};
use advance_runtime_compose::{
    compose, ClientApiOptions, ComposeError, ComposeOptions, HostPlatform, LockFailure,
    MasterKeyInput, NullComposeLog, ProcessPolicy, Zeroizing,
};
use advance_shared_types::process_policy::{spawn_counter, SpawnSite};

#[test]
fn module_001_ac32_t113_7_embedded_compose_refused_by_live_advance_start() {
    let _serial = live_daemon::SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut daemon = live_daemon::LiveDaemon::start();
    let fields0 = daemon.lock_fields();
    let state_root = tempfile::tempdir().expect("state root");
    let state_root = std::fs::canonicalize(state_root.path()).expect("canonical state root");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    runtime.block_on(async {
        let platform = HostPlatform::compiled().unwrap_or(HostPlatform::Linux);
        let key = Zeroizing::new([0x11u8; 32]);
        let s0 = spawn_counter::snapshot();
        let error = compose(
            ComposeOptions::embedded(daemon.home.clone(), platform, Arc::new(NullComposeLog) as _)
                .with_client_api(ClientApiOptions::Off)
                .with_state_root(&state_root)
                .with_master_key(MasterKeyInput::Provided(key.clone())),
            Vec::new(),
        )
        .await
        .expect_err("Allow compose vs live daemon");
        match error {
            ComposeError::Lock(LockFailure::ActiveRuntime { pid }) => {
                assert_eq!(pid, daemon.pid, "Allow ActiveRuntime pid");
            }
            other => panic!("expected ActiveRuntime, got {other:?}"),
        }
        let s1 = spawn_counter::snapshot();
        let d1 = s1.since(&s0);
        assert_eq!(d1.admitted(SpawnSite::PidLockProbe), 2);
        assert_eq!(d1.refused(SpawnSite::PidLockProbe), 0);

        let error = compose(
            ComposeOptions::embedded(daemon.home.clone(), platform, Arc::new(NullComposeLog) as _)
                .with_client_api(ClientApiOptions::Off)
                .with_state_root(&state_root)
                .with_master_key(MasterKeyInput::Provided(key))
                .with_processes(ProcessPolicy::Forbid),
            Vec::new(),
        )
        .await
        .expect_err("Forbid compose vs live daemon");
        match error {
            ComposeError::Lock(LockFailure::ActiveRuntime { pid }) => {
                assert_eq!(pid, daemon.pid, "Forbid ActiveRuntime pid");
            }
            other => panic!("expected ActiveRuntime, got {other:?}"),
        }
        let s2 = spawn_counter::snapshot();
        let d2 = s2.since(&s1);
        assert_eq!(d2.admitted_total(), 0);
        assert_eq!(d2.refused(SpawnSite::PidLockProbe), 2);
    });

    assert_eq!(daemon.lock_fields(), fields0, "live lock fields moved");
    assert_eq!(get_health(&daemon.client_api_base()), 200);
    let status = daemon.sigterm_and_wait();
    assert_eq!(status.code(), Some(0), "{status:?}");
    runtime.shutdown_timeout(Duration::from_secs(10));
}

#[test]
fn module_001_ac32_t113_7_v2_full_handle_refused_by_live_advance_start() {
    let _serial = live_daemon::SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut daemon = live_daemon::LiveDaemon::start();
    let fields0 = daemon.lock_fields();
    let state_root = tempfile::tempdir().expect("state root");
    let state_root = std::fs::canonicalize(state_root.path()).expect("canonical state root");
    let home = daemon.home.clone();
    let pid = daemon.pid;

    for processes in [None, Some("forbid")] {
        let home = home.clone();
        let state_root = state_root.clone();
        let err = std::thread::spawn(move || start_v2_lock_error(&home, &state_root, processes))
            .join()
            .expect("C ABI thread");
        assert_eq!(
            err,
            format!("failed to acquire runtime lock: another runtime active (pid={pid})"),
            "processes={processes:?}"
        );
    }

    assert_eq!(daemon.lock_fields(), fields0, "live lock fields moved");
    assert_eq!(get_health(&daemon.client_api_base()), 200);
    let status = daemon.sigterm_and_wait();
    assert_eq!(status.code(), Some(0), "{status:?}");
}

fn start_v2_lock_error(home: &Path, state_root: &Path, processes: Option<&str>) -> String {
    let mut value = serde_json::json!({ "state_root": state_root.to_str().expect("utf-8") });
    if let Some(processes) = processes {
        value.as_object_mut().expect("object").insert(
            "processes".into(),
            serde_json::Value::String(processes.into()),
        );
    }
    let json = value.to_string();
    let ws = CString::new(home.to_str().expect("utf-8 home")).expect("home cstr");
    let opt = CString::new(json).expect("options cstr");
    let mut out: *mut AdvanceBridgeHandle = ptr::null_mut();
    let code = unsafe { advance_bridge_start_v2(ws.as_ptr(), opt.as_ptr(), &mut out) };
    let err = unsafe { CStr::from_ptr(advance_bridge_last_error()) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(code, 15, "{err}");
    assert!(out.is_null(), "out_handle must stay NULL");
    err
}

fn get_health(base: &str) -> u16 {
    let hostport = base
        .trim()
        .trim_end_matches('/')
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("client_api_base is not http: {base}"));
    let mut stream = TcpStream::connect(hostport).unwrap_or_else(|e| {
        panic!("connect {hostport}: {e}");
    });
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    let req = format!(
        "GET /client/health HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\nx-advance-api-version: {API_VERSION}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("write health");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read health");
    let text = String::from_utf8_lossy(&raw);
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in health reply:\n{text}"))
}
