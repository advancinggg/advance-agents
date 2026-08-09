//! Slice AE (2026-05-09) — bootstrap construction-surface integration tests.
//!
//! T64 happy-path RuntimeHost::new on tempdir + valid YAML.
//! T65 Arc-graph identity stable across accessor calls.
//! T66 SqliteIndexHandle constructed at startup is migrated.

use std::sync::Arc;

use advance_runtime::{BootstrapError, RuntimeHost};

const MINIMAL_VALID_YAML: &str = "\
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
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

/// Build a tempdir workspace with `<dir>/.advance/runtime-config.yaml` and the
/// `.runtime/` parent dir for the SQLite file. Returns the canonicalized
/// workspace path along with the config-file path.
fn fresh_workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    let config_path = workspace.join(".advance").join("runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_VALID_YAML).unwrap();
    (dir, workspace, config_path)
}

#[tokio::test]
async fn t64_runtime_host_new_happy_path() {
    let (_guard, workspace, config_path) = fresh_workspace();
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");
    assert!(host.config().wasm.max_memory_pages > 0);
    assert_eq!(host.workspace_root(), workspace.as_path());
    // Schema version must be > 0 post-migration.
    assert!(host.sqlite_index_handle().schema_version() > 0);
    // host_registry is empty (no host fns registered yet — that's downstream).
    assert!(host.host_registry().lookup("nonexistent").is_empty());
}

#[tokio::test]
async fn t65_arc_graph_identity_stable_across_accessor_calls() {
    let (_guard, workspace, config_path) = fresh_workspace();
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");

    // Each accessor must return Arc clones pointing at the same allocation.
    // Catches the "freshly Arc::new on each accessor call" pathological bug.
    assert!(Arc::ptr_eq(&host.host_registry(), &host.host_registry()));
    assert!(Arc::ptr_eq(
        &host.circuit_breaker_bus(),
        &host.circuit_breaker_bus()
    ));
    assert!(Arc::ptr_eq(&host.grant_check(), &host.grant_check()));
    assert!(Arc::ptr_eq(
        &host.capability_injector(),
        &host.capability_injector()
    ));
    assert!(Arc::ptr_eq(
        &host.sqlite_index_handle(),
        &host.sqlite_index_handle()
    ));
    assert!(Arc::ptr_eq(
        &host.component_runtime(),
        &host.component_runtime()
    ));
    assert!(Arc::ptr_eq(&host.config_watcher(), &host.config_watcher()));
}

#[tokio::test]
async fn t66_sqlite_index_handle_post_bootstrap_is_migrated() {
    let (_guard, workspace, config_path) = fresh_workspace();
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");
    let handle = host.sqlite_index_handle();
    let version = handle.schema_version();
    assert!(version > 0, "schema must be migrated post-bootstrap");
    // get_conn round-trip
    let _conn = handle.get_conn().expect("pool checkout");
    // db file exists at the expected path.
    assert!(workspace.join(".runtime").join("index.db").exists());
}

#[tokio::test]
async fn t_db_path_symlink_rejected() {
    // R-AE-3 / R3 fix coverage: an EXISTING symlink at the resolved db_path
    // is rejected before R2d2 opens it.
    let (_guard, workspace, config_path) = fresh_workspace();
    // Create a target file the symlink will point at.
    let target = workspace.join("decoy-target.txt");
    std::fs::write(&target, b"decoy").unwrap();
    let db_path = workspace.join(".runtime").join("index.db");
    // Ensure the parent dir is empty so we can place a fresh symlink.
    if db_path.exists() {
        std::fs::remove_file(&db_path).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &db_path).unwrap();

    match RuntimeHost::new(&config_path, &workspace).await {
        Ok(_) => panic!("symlink at db_path must be rejected (existing-target case)"),
        Err(BootstrapError::DbPathSymlink(_)) => {}
        Err(other) => panic!("expected DbPathSymlink, got {other:?}"),
    }
}

#[tokio::test]
async fn t_db_path_dangling_symlink_rejected() {
    // R3 fix specific: dangling symlinks (where target does not exist) must
    // ALSO be rejected — Path::exists() would have followed the symlink and
    // returned false, bypassing the check.
    let (_guard, workspace, config_path) = fresh_workspace();
    let dangling_target = workspace.join("nope-does-not-exist");
    let db_path = workspace.join(".runtime").join("index.db");
    if db_path.exists() {
        std::fs::remove_file(&db_path).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&dangling_target, &db_path).unwrap();

    match RuntimeHost::new(&config_path, &workspace).await {
        Ok(_) => panic!("dangling symlink at db_path must be rejected"),
        Err(BootstrapError::DbPathSymlink(_)) => {}
        Err(other) => panic!("expected DbPathSymlink, got {other:?}"),
    }
}

#[tokio::test]
#[cfg(unix)]
async fn t_adv_w1_ancestor_symlink_swap_rejected() {
    // Adversarial R1 W1: an attacker who swaps `<workspace>/.runtime/`
    // (the parent of the resolved db_path) for a symlink targeting
    // /etc/ or another sensitive directory must be rejected at bootstrap.
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    // Don't create .runtime/ as a directory; instead make it a symlink to
    // an attacker-controlled victim directory under the same workspace.
    let victim = workspace.join("victim-dir");
    std::fs::create_dir_all(&victim).unwrap();
    std::os::unix::fs::symlink(&victim, workspace.join(".runtime")).unwrap();
    let config_path = workspace.join(".advance").join("runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_VALID_YAML).unwrap();

    match RuntimeHost::new(&config_path, &workspace).await {
        Ok(_) => panic!("ancestor-symlink swap on .runtime/ must be rejected"),
        Err(BootstrapError::DbPathSymlink(_)) => {}
        Err(other) => panic!("expected DbPathSymlink, got {other:?}"),
    }
}

#[tokio::test]
async fn t_circuit_breakers_seeded_from_config() {
    // Verifies that an Open breaker in the YAML produces a queryable Open
    // state on the bootstrapped CircuitBreakerBus.
    let (_guard, workspace, config_path) = fresh_workspace();
    // Append circuit-breakers section by rewriting the yaml.
    let yaml_with_breaker = MINIMAL_VALID_YAML.replace(
        "post-processor:",
        "circuit-breakers:\n  - scope: capability\n    target: llm\n    state: open\n    reason: \"bootstrap-seed-test\"\npost-processor:",
    );
    std::fs::write(&config_path, &yaml_with_breaker).unwrap();
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");
    let bus = host.circuit_breaker_bus();
    assert_eq!(
        bus.is_open_capability("llm").as_deref(),
        Some("bootstrap-seed-test")
    );
}
