//! FFI smoke + supervise lifecycle with a stub ready-line binary.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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

// Ensure shell is available for stub tests
#[test]
fn shell_available() {
    let st = Command::new("sh").arg("-c").arg("echo ok").status().unwrap();
    assert!(st.success());
}
