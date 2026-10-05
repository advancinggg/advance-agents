//! MODULE-001-AC-32 (T113 (7)) / MODULE-001-AC-30 — the embedded runtime bridge and
//! `compose` share one process-local registry of composed homes: whichever comes first
//! holds the home, the other is refused before any runtime lock is tried (the bridge with
//! `AlreadyRunning`, `compose` with `Lock(HeldInProcess)`), and once the holder stops the
//! other one starts.
//!
//! The bridge's v1 entry is driven through `start_async` / `stop_async`, which run on the
//! bridge's own runtime and are therefore legal inside this tokio test.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_embedded_runtime_bridge::{
    start_async, stop_async, BridgeConfig, BridgeError, BridgePlatform, CompositionMode, EngineMode,
};
use advance_runtime_compose::{compose, ComposeError, ComposeOptions, LockFailure, NullComposeLog};

const MINIMAL_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

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
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = fs::canonicalize(dir.path()).expect("canonical workspace");
    fs::create_dir_all(workspace.join(".advance")).unwrap();
    fs::create_dir_all(workspace.join(".runtime")).unwrap();
    fs::write(
        workspace.join(".advance").join("runtime-config.yaml"),
        MINIMAL_YAML,
    )
    .unwrap();
    (dir, workspace)
}

fn embed_cfg() -> BridgeConfig {
    BridgeConfig {
        platform: BridgePlatform::Mac,
        engine_mode: EngineMode::Jit,
        composition_mode: CompositionMode::Embed,
        ..BridgeConfig::default()
    }
}

fn daemon(workspace: &Path) -> ComposeOptions {
    ComposeOptions::daemon(workspace, Arc::new(NullComposeLog))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_7_registry_shared_with_bridge_v1() {
    // (a) A composition holds the home: the bridge is refused before any lock.
    let (_a, home_a) = write_workspace();
    let composed = compose(daemon(&home_a), Vec::new())
        .await
        .expect("compose the home");
    match start_async(&home_a, embed_cfg()).await {
        Err(BridgeError::AlreadyRunning) => {}
        Err(other) => panic!("expected AlreadyRunning, got {other:?}"),
        Ok(_) => panic!("the bridge started on a composed home"),
    }
    composed.shutdown().await.expect("shutdown");

    // (b) The bridge holds the home: `compose` is refused before any lock; once the bridge
    // stops, the home composes.
    let (_b, home_b) = write_workspace();
    let bridged = start_async(&home_b, embed_cfg())
        .await
        .expect("the bridge starts the home");
    let error = compose(daemon(&home_b), Vec::new())
        .await
        .expect_err("the bridge holds the home");
    assert!(
        matches!(error, ComposeError::Lock(LockFailure::HeldInProcess)),
        "{error:?}"
    );
    stop_async(bridged).await.expect("stop the bridge");
    let composed = compose(daemon(&home_b), Vec::new())
        .await
        .expect("the home composes once the bridge stopped");
    composed.shutdown().await.expect("shutdown");
}
