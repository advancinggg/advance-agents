//! FFI smoke + supervise lifecycle with a stub ready-line binary.

use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::process::Command;

use advance_embedded_runtime_bridge::{
    health, start, stop, BridgeConfig, BridgePlatform, CompositionMode, EngineMode,
    ADVANCE_BRIDGE_ABI_VERSION,
};

const MINIMAL_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#;

fn write_workspace() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let workspace = fs::canonicalize(dir.path()).unwrap();
    fs::create_dir_all(workspace.join(".advance")).unwrap();
    fs::create_dir_all(workspace.join(".runtime")).unwrap();
    fs::write(
        workspace.join(".advance").join("runtime-config.yaml"),
        MINIMAL_YAML,
    )
    .unwrap();
    (dir, workspace)
}

/// Stub that accepts `start --workspace X`, prints ready line, sleeps.
#[cfg(unix)]
fn write_ready_stub(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("fake-advance");
    fs::write(
        &path,
        r#"#!/bin/sh
# consume args
while [ $# -gt 0 ]; do shift; done
echo "advance: runtime ready (workspace=stub)"
# keep alive until killed
sleep 60
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

#[test]
fn t13_ffi_abi_version() {
    let v = advance_embedded_runtime_bridge::advance_bridge_abi_version();
    assert_eq!(v, ADVANCE_BRIDGE_ABI_VERSION);
    assert_eq!(v, 1);
}

#[cfg(unix)]
#[test]
fn t12_supervise_ready_line_start_stop() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    let stub = write_ready_stub(dir.path());
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(stub),
        supervise_kill_on_drop: true,
        ..BridgeConfig::default()
    };
    let h = start(&ws, cfg).expect("supervise start");
    let health = health(&h).expect("health");
    assert!(health.runtime_up);
    assert!(health.supervise_readiness.is_some());
    stop(h).expect("stop");
}

#[cfg(unix)]
#[test]
fn t20_supervise_timeout_reaps() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    // Stub never prints ready
    let path = dir.path().join("silent-advance");
    fs::write(
        &path,
        r#"#!/bin/sh
sleep 60
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(path),
        supervise_ready_timeout: Some(std::time::Duration::from_millis(300)),
        supervise_kill_on_drop: true,
        ..BridgeConfig::default()
    };
    let err = start(&ws, cfg).unwrap_err();
    assert!(matches!(
        err,
        advance_embedded_runtime_bridge::BridgeError::SuperviseStartTimeout
            | advance_embedded_runtime_bridge::BridgeError::Supervise(_)
    ));
}

#[test]
fn t14_facade_types_reachable() {
    // Compile-time: advance-core re-export path used via direct crate in this package.
    // Smoke that EmbeddedRuntimeBridge name exists.
    let _: Option<&dyn advance_embedded_runtime_bridge::EmbeddedRuntimeBridge> = None;
}

#[test]
fn header_exists_and_mentions_abi() {
    let header = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include/advance_bridge.h");
    let text = fs::read_to_string(header).unwrap();
    assert!(text.contains("ADVANCE_BRIDGE_ABI_VERSION"));
    assert!(text.contains("advance_bridge_start"));
}

#[cfg(unix)]
#[test]
fn shell_available() {
    let st = Command::new("sh").arg("-c").arg("echo ok").status().unwrap();
    assert!(st.success());
}

#[cfg(unix)]
#[test]
fn t34_ready_file_must_be_under_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    let stub = write_ready_stub(dir.path());
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(stub),
        supervise_ready_file: Some(ws.join(".advance").join("not-ready.txt")),
        supervise_kill_on_drop: true,
        ..BridgeConfig::default()
    };
    let err = start(&ws, cfg).unwrap_err();
    assert!(matches!(
        err,
        advance_embedded_runtime_bridge::BridgeError::InvalidConfig(_)
    ));
}

#[cfg(unix)]
fn chmod_755(path: &std::path::Path) {
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

#[cfg(unix)]
fn write_ready_file_stub(dir: &std::path::Path, name: &str, extra: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
ws=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--workspace" ]; then
    shift
    ws="$1"
  else
    shift
  fi
done
{extra}
"#
        ),
    )
    .unwrap();
    chmod_755(&path);
    path
}

/// Plan T30: keep-available Drop detaches, child stays up, registry is free.
#[cfg(all(unix, target_os = "macos"))]
#[test]
fn t30_keep_available_drop_releases_registry() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    let ready = ws.join(".runtime").join("daemon.ready");
    let stub = write_ready_file_stub(
        dir.path(),
        "keep-advance",
        r#"echo $$ > "$ws/.runtime/keep.pid"
printf ready > "$ws/.runtime/daemon.ready"
exec sleep 60
"#,
    );
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(stub),
        supervise_ready_file: Some(ready),
        supervise_kill_on_drop: false,
        supervise_ready_timeout: Some(std::time::Duration::from_secs(5)),
        ..BridgeConfig::default()
    };
    let h = start(&ws, cfg.clone()).expect("keep-available start");
    let pid1 = fs::read_to_string(ws.join(".runtime").join("keep.pid")).ok();
    drop(h);
    // Registry must be free (plan T30). Second start is allowed.
    let h2 = start(&ws, cfg).expect("second start after detach");
    let pid2 = fs::read_to_string(ws.join(".runtime").join("keep.pid")).ok();
    for pid in [pid1, pid2].into_iter().flatten() {
        let _ = Command::new("kill").arg(pid.trim()).status();
    }
    stop(h2).expect("stop second");
}

/// Plan T32: pre-existing stale ready file is deleted; start waits for a new file.
#[cfg(unix)]
#[test]
fn t32_stale_ready_file_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    let ready = ws.join(".runtime").join("daemon.ready");
    fs::write(&ready, b"stale").unwrap();
    let stub = write_ready_file_stub(
        dir.path(),
        "fresh-advance",
        r#"sleep 0.2
printf ready > "$ws/.runtime/daemon.ready"
exec sleep 60
"#,
    );
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(stub),
        supervise_ready_file: Some(ready.clone()),
        supervise_kill_on_drop: true,
        supervise_ready_timeout: Some(std::time::Duration::from_secs(5)),
        ..BridgeConfig::default()
    };
    let h = start(&ws, cfg).expect("start after stale ready deleted");
    let text = fs::read_to_string(&ready).unwrap();
    assert_eq!(text, "ready");
    stop(h).expect("stop");
}

/// Ready-file must work when the caller passes a non-canonical workspace
/// (macOS `/var` vs `/private/var`) and an absolute ready path next to it.
#[cfg(unix)]
#[test]
fn t32b_ready_file_noncanonical_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let raw = dir.path().to_path_buf();
    fs::create_dir_all(raw.join(".advance")).unwrap();
    fs::create_dir_all(raw.join(".runtime")).unwrap();
    fs::write(
        raw.join(".advance").join("runtime-config.yaml"),
        MINIMAL_YAML,
    )
    .unwrap();
    let stub = write_ready_file_stub(
        dir.path(),
        "noncanon-advance",
        r#"printf ready > "$ws/.runtime/daemon.ready"
exec sleep 60
"#,
    );
    let ready = raw.join(".runtime").join("daemon.ready");
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(stub),
        supervise_ready_file: Some(ready),
        supervise_kill_on_drop: true,
        supervise_ready_timeout: Some(std::time::Duration::from_secs(5)),
        ..BridgeConfig::default()
    };
    let h = start(&raw, cfg).expect("start with non-canonical workspace/ready path");
    stop(h).expect("stop");
}

/// Ready-file writer that exits immediately must not publish a live handle.
#[cfg(unix)]
#[test]
fn t36_ready_file_then_exit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    let ready = ws.join(".runtime").join("daemon.ready");
    let stub = write_ready_file_stub(
        dir.path(),
        "exit-advance",
        r#"printf ready > "$ws/.runtime/daemon.ready"
exit 0
"#,
    );
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(stub),
        supervise_ready_file: Some(ready),
        supervise_kill_on_drop: true,
        supervise_ready_timeout: Some(std::time::Duration::from_secs(5)),
        ..BridgeConfig::default()
    };
    let err = start(&ws, cfg).unwrap_err();
    assert!(matches!(
        err,
        advance_embedded_runtime_bridge::BridgeError::Supervise(_)
            | advance_embedded_runtime_bridge::BridgeError::SuperviseStartTimeout
    ));
}

/// Line-mode writer that prints the marker then exits must not publish a live handle.
#[cfg(unix)]
#[test]
fn t36b_ready_line_then_exit_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    let path = dir.path().join("exit-line-advance");
    fs::write(
        &path,
        r#"#!/bin/sh
echo "advance: runtime ready (workspace=stub)"
exit 0
"#,
    )
    .unwrap();
    chmod_755(&path);
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(path),
        supervise_kill_on_drop: true,
        supervise_ready_timeout: Some(std::time::Duration::from_secs(5)),
        ..BridgeConfig::default()
    };
    let err = start(&ws, cfg).unwrap_err();
    assert!(matches!(
        err,
        advance_embedded_runtime_bridge::BridgeError::Supervise(_)
            | advance_embedded_runtime_bridge::BridgeError::SuperviseStartTimeout
    ));
}

/// Plan T30c: default Drop reaps the child.
#[cfg(unix)]
#[test]
fn t30c_default_drop_reaps() {
    let dir = tempfile::tempdir().unwrap();
    let (_g, ws) = write_workspace();
    let stub = write_ready_stub(dir.path());
    let cfg = BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Supervise,
        supervise_command: Some(stub),
        supervise_kill_on_drop: true,
        ..BridgeConfig::default()
    };
    let h = start(&ws, cfg).expect("start");
    drop(h);
}

/// Plan T13 subset: invoke the C ABI from Rust (null args, buffer, start/stop/double-stop/free).
#[test]
fn t13_c_abi_lifecycle() {
    use std::ffi::CString;
    use advance_embedded_runtime_bridge::ffi::{
        advance_bridge_free_handle, advance_bridge_health, advance_bridge_on_lifecycle,
        advance_bridge_start, advance_bridge_stop, AdvanceBridgeHandle,
    };

    let rc = unsafe {
        advance_bridge_start(
            std::ptr::null(),
            0,
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
            1,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 1);

    let (_g, ws) = write_workspace();
    let ws_c = CString::new(ws.to_str().unwrap()).unwrap();
    let mut handle: *mut AdvanceBridgeHandle = std::ptr::null_mut();
    let rc = unsafe {
        advance_bridge_start(
            ws_c.as_ptr(),
            0,
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
            1,
            std::ptr::null(),
            &mut handle,
        )
    };
    assert_eq!(rc, 0);
    assert!(!handle.is_null());

    let mut needed = 0usize;
    let rc = unsafe { advance_bridge_health(handle, std::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(rc, 12);
    assert!(needed > 1);

    let mut buf = vec![0u8; needed];
    let rc = unsafe {
        advance_bridge_health(
            handle,
            buf.as_mut_ptr() as *mut std::os::raw::c_char,
            buf.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);

    let rc = unsafe { advance_bridge_on_lifecycle(handle, 0, 80, std::ptr::null()) };
    assert_eq!(rc, 0);
    let rc = unsafe { advance_bridge_on_lifecycle(handle, 0, 101, std::ptr::null()) };
    assert_eq!(rc, 1);

    assert_eq!(unsafe { advance_bridge_stop(handle) }, 0);
    assert_eq!(unsafe { advance_bridge_stop(handle) }, 0);
    unsafe { advance_bridge_free_handle(handle) };
}
