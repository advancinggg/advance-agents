//! Slice G (2026-05-09) — MODULE-004 AC-18 verification.
//!
//! AC-18 (§1.5): Runtime-host host function registration: rusqlite pool
//! bootstrap happens during MODULE-001 startup injection; this module
//! exposes no agent-facing WIT, but its setup path participates in
//! CONTRACT-001 bootstrap lifecycle.
//!
//! This test goes beyond Slice AE's T64+T66 (which assert structural facts:
//! `schema_version > 0`, `get_conn().is_ok()`). It exercises the
//! bootstrap-injected handle through a real upsert + recall round via the
//! new `host.recall()` accessor — proving AC-18's "bootstrap lifecycle
//! participation" criterion functionally.

use advance_runtime::RuntimeHost;

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

# Slice G: explicit values pin the contract — yaml flows through the
# bootstrap path into `host.config().database` and the live Tunables.
database:
  db-path: \".runtime/index.db\"
  pool-size: 6
  wal-mode: true
  embedding-dim: 768
  recall-max-depth: 3
";

/// Local helper: 768-dim one-hot encoding (different crate than recall.rs's
/// test module, can't reuse — keep this tiny inline helper).
fn make_one_hot_768(i: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; 768];
    if i < v.len() {
        v[i] = 1.0;
    }
    v
}

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
async fn mod004_ac18_runtime_host_bootstrap_injection() {
    let (_guard, workspace, config_path) = fresh_workspace();
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new should succeed with valid yaml");

    // Step 1: bootstrap handed back a migrated SQLite handle.
    assert!(
        host.sqlite_index_handle().schema_version() > 0,
        "schema_version > 0 proves migrations ran post-bootstrap"
    );
    assert!(
        host.sqlite_index_handle().get_conn().is_ok(),
        "get_conn must succeed on a bootstrap-injected handle"
    );

    // Step 2: yaml values flowed through the bootstrap path into the
    // RuntimeConfig snapshot (i.e., we're not just defaulting via
    // `#[serde(default)]`).
    assert_eq!(
        host.config().database.pool_size,
        6,
        "pool-size from yaml flowed into config snapshot"
    );
    assert_eq!(
        host.config().database.embedding_dim,
        768,
        "embedding-dim from yaml flowed into config snapshot"
    );
    assert_eq!(
        host.config().database.recall_max_depth,
        3,
        "recall-max-depth from yaml flowed into config snapshot"
    );
    assert!(
        host.config().database.wal_mode,
        "wal-mode from yaml flowed into config snapshot"
    );

    // Step 3: exercise the bootstrap-injected handle through an actual
    // upsert+recall round — proves AC-18's "bootstrap lifecycle
    // participation" functionally, beyond Slice AE's structural assertions.
    let handle = host.sqlite_index_handle();
    let one_hot = make_one_hot_768(0);
    handle
        .upsert_content_index(
            "/",
            "/notes.md",
            "test content",
            Some(&one_hot),
            Some("2026-01-01T00:00:00.000Z"),
        )
        .expect("upsert_content_index via bootstrap-injected handle");

    let results = host
        .recall()
        .recall("/", "test", &one_hot, 10)
        .await
        .expect("recall via bootstrap-injected handle");
    assert!(
        !results.is_empty(),
        "recall via host.recall() returns the upserted row"
    );
    assert_eq!(
        results[0].id, "/\u{1F}/notes.md",
        "recall result id matches the upserted row"
    );

    // Step 4: db file exists at the configured path (proves db-path
    // resolution from M001 bootstrap went through).
    assert!(
        workspace.join(".runtime").join("index.db").exists(),
        "index.db file exists at the configured workspace-relative path"
    );
}
