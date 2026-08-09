//! Slice G (2026-05-09) — MODULE-004 AC-19 verification.
//!
//! AC-19 (§1.5): RuntimeConfig `db.pool_size`, `db.wal_mode`,
//! `db.embedding_dim`, `db.recall_max_depth` read from
//! `/.advance/runtime-config.yaml` and hot-reloaded on change.
//!
//! Behavioral verification: not just snapshot-observation. The hot-reload
//! tests rewrite the yaml file and assert that subsequent recall/upsert
//! calls observe the new values via the `RuntimeConfigDatabaseTunables`
//! read-through-snapshot adapter.

use std::time::Duration;

use advance_runtime::config::RuntimeConfigProvider;
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

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
  wal-mode: true
  embedding-dim: 768
  recall-max-depth: 3
";

fn make_one_hot(i: usize, dim: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; dim];
    if i < v.len() {
        v[i] = 1.0;
    }
    v
}

fn fresh_workspace_with_yaml(
    yaml: &str,
) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    let config_path = workspace.join(".advance").join("runtime-config.yaml");
    std::fs::write(&config_path, yaml).unwrap();
    (dir, workspace, config_path)
}

/// Test 1: Explicit yaml fields persist through bootstrap.
#[tokio::test]
async fn mod004_ac19_db_fields_round_trip_at_startup() {
    let yaml = MINIMAL_VALID_YAML
        .replace("pool-size: 4", "pool-size: 8")
        .replace("wal-mode: true", "wal-mode: false")
        .replace("embedding-dim: 768", "embedding-dim: 1024")
        .replace("recall-max-depth: 3", "recall-max-depth: 5");

    let (_guard, workspace, config_path) = fresh_workspace_with_yaml(&yaml);
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");

    let db = &host.config().database;
    assert_eq!(db.pool_size, 8);
    assert!(!db.wal_mode);
    assert_eq!(db.embedding_dim, 1024);
    assert_eq!(db.recall_max_depth, 5);
}

/// Test 2: hot-reload `recall-max-depth` 3 → 5 changes recall behavior
/// behaviorally (not just snapshot-observation). Seeds an
/// `a/b/c/d/e/leaf.md` fixture with meta_index sims tuned via one-hot
/// embeddings; depth-3 vs depth-5 ancestor folds yield measurably
/// different `parent_score` per the formula at recall.rs:335-366.
#[tokio::test]
async fn mod004_ac19_hot_reload_recall_max_depth_changes_recall_behavior() {
    let (_guard, workspace, config_path) = fresh_workspace_with_yaml(MINIMAL_VALID_YAML);
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");

    // Subscribe before the rewrite so we're sure to catch the notification.
    let mut rx = host.config_watcher().subscribe();
    let dim = 768;

    // Seed: a content row at a/b/c/d/e/leaf.md with one-hot(7) embedding
    // (orthogonal to the query embedding so the global dense_content
    // similarity is 0.5, which is above DENSE_THRESHOLD=0.3 — content
    // surfaces in the global scan).
    //
    // Meta hits at all 5 ancestor levels, each tuned to give the declared
    // similarity to the query one_hot(0).
    //
    // The recall.rs `recall_blocking` constructs meta_scores from the
    // raw cosine similarity returned by sqlite-vec's KNN search; one_hot(0)
    // ⋅ one_hot(0) = 1.0, one_hot(0) ⋅ one_hot(j) = 0.0 (j != 0).
    // So we tune ancestor sims by mixing two basis vectors and normalizing.
    fn emb_with_sim(target: f32, dim: usize) -> Vec<f32> {
        // We want cosine(emb, one_hot(0)) = target.
        // emb = target * e0 + sqrt(1 - target^2) * e1 (then normalized — but
        // the basis is already orthonormal so emb is unit-length).
        let mut v = vec![0.0_f32; dim];
        let off = (1.0_f32 - target * target).sqrt();
        v[0] = target;
        if dim > 1 {
            v[1] = off;
        }
        v
    }

    let handle = host.sqlite_index_handle();

    // Content row at the deepest level (similarity 1.0 with one_hot(0) so
    // the leaf surfaces in the global dense scan).
    handle
        .upsert_content_index(
            "/",
            "/a/b/c/d/e/leaf.md",
            "leaf",
            Some(&make_one_hot(0, dim)),
            Some("2026-01-01T00:00:00.000Z"),
        )
        .expect("upsert leaf content");

    // Meta hits at each ancestor level. recall.rs sim = (1 + cos)/2, so
    // we choose target cos values that produce the ancestors listed in the
    // plan: a (cos=-0.2 → sim 0.4), a/b (cos=0 → sim 0.5), a/b/c (cos=0.2
    // → sim 0.6), a/b/c/d (cos=0.4 → sim 0.7), a/b/c/d/e (cos=0.6 → sim 0.8).
    let levels = [
        ("/a", -0.2_f32),
        ("/a/b", 0.0_f32),
        ("/a/b/c", 0.2_f32),
        ("/a/b/c/d", 0.4_f32),
        ("/a/b/c/d/e", 0.6_f32),
    ];
    for (dir, cos_target) in levels.iter() {
        handle
            .upsert_meta_index(
                "/",
                dir,
                "_scope",
                Some("scope description"),
                None,
                Some(&emb_with_sim(*cos_target, dim)),
            )
            .expect("upsert meta ancestor");
    }

    // Recall at default depth=3.
    let r3 = host
        .recall()
        .recall("/", "leaf", &make_one_hot(0, dim), 5)
        .await
        .expect("recall at default depth=3");
    let leaf3 = r3
        .iter()
        .find(|x| x.id == "/\u{1F}/a/b/c/d/e/leaf.md")
        .expect("leaf row in result");
    let parent_score_d3 = leaf3.parent_score;

    // Hot-reload: bump recall-max-depth from 3 to 5.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let new_yaml = MINIMAL_VALID_YAML.replace("recall-max-depth: 3", "recall-max-depth: 5");
    std::fs::write(&config_path, &new_yaml).expect("rewrite yaml");

    // Wait for subscriber notification (matches existing hot_reload pattern's 5s timeout).
    let _new_cfg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("config-reload notification within 5s")
        .expect("subscriber channel closed");
    assert_eq!(
        host.config().database.recall_max_depth,
        5,
        "post-reload snapshot reflects new recall-max-depth"
    );

    // Recall again with same fixture; depth=5 walks the full ancestor chain.
    let r5 = host
        .recall()
        .recall("/", "leaf", &make_one_hot(0, dim), 5)
        .await
        .expect("recall at depth=5");
    let leaf5 = r5
        .iter()
        .find(|x| x.id == "/\u{1F}/a/b/c/d/e/leaf.md")
        .expect("leaf row still in result");
    let parent_score_d5 = leaf5.parent_score;

    // Behavioral assertion: parent_score differs measurably between
    // depth-3 and depth-5 — proves the recall pipeline picked up the new
    // value via `tunables.current().recall_max_depth`.
    let delta = (parent_score_d5 - parent_score_d3).abs();
    assert!(
        delta > 0.001,
        "parent_score changed measurably after recall-max-depth hot-reload \
         (depth-3 {parent_score_d3:.4} vs depth-5 {parent_score_d5:.4}, delta {delta:.4})"
    );
}

/// Test 3: hot-reload `embedding-dim` 768 → 1536 flips upsert validation
/// outcome — a subsequent 768-dim upsert now FAILS with InvalidConfig
/// containing the new dim. Proves the live snapshot value flows through
/// `validate_embedding(emb, expected_dim)` per call.
#[tokio::test]
async fn mod004_ac19_hot_reload_embedding_dim_changes_validate_behavior() {
    let (_guard, workspace, config_path) = fresh_workspace_with_yaml(MINIMAL_VALID_YAML);
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");
    let mut rx = host.config_watcher().subscribe();

    // Pre-reload: 768-dim upsert succeeds (matches default).
    let one_hot_768 = make_one_hot(0, 768);
    host.sqlite_index_handle()
        .upsert_content_index(
            "/",
            "/baseline.md",
            "baseline",
            Some(&one_hot_768),
            Some("2026-01-01T00:00:00.000Z"),
        )
        .expect("768-dim upsert succeeds at default embedding-dim=768");

    // Hot-reload: bump embedding-dim from 768 to 1536.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let new_yaml = MINIMAL_VALID_YAML.replace("embedding-dim: 768", "embedding-dim: 1536");
    std::fs::write(&config_path, &new_yaml).expect("rewrite yaml");

    // Wait for notification.
    let _new_cfg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("config-reload notification within 5s")
        .expect("subscriber channel closed");
    assert_eq!(host.config().database.embedding_dim, 1536);

    // Post-reload: subsequent 768-dim upsert is now rejected because the
    // live snapshot says expected_dim=1536. Proves the validate_embedding
    // helper consults the current Tunables, not a compile-time constant.
    let result = host.sqlite_index_handle().upsert_content_index(
        "/",
        "/post_reload.md",
        "post-reload",
        Some(&one_hot_768),
        Some("2026-01-01T00:00:00.000Z"),
    );
    let err = result.expect_err("768-dim upsert should fail post-reload (expected_dim=1536)");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("1536"),
        "error message should name the new expected dim 1536: {msg}"
    );
}

/// Test 4: invalid `recall-max-depth` rewrite is ignored; snapshot
/// unchanged. Confirms validate_config gates apply to reload too, not
/// just to startup.
#[tokio::test]
async fn mod004_ac19_hot_reload_invalid_db_value_ignored() {
    let (_guard, workspace, config_path) = fresh_workspace_with_yaml(MINIMAL_VALID_YAML);
    let host = RuntimeHost::new(&config_path, &workspace)
        .await
        .expect("RuntimeHost::new");

    let original_depth = host.config().database.recall_max_depth;
    assert_eq!(original_depth, 3);

    // Rewrite with out-of-range value (validation rejects > 10).
    tokio::time::sleep(Duration::from_millis(100)).await;
    let bad_yaml = MINIMAL_VALID_YAML.replace("recall-max-depth: 3", "recall-max-depth: 999");
    std::fs::write(&config_path, &bad_yaml).expect("rewrite yaml");

    // Give the watcher time to process the rewrite.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Snapshot must be unchanged (validation rejected the reload).
    assert_eq!(
        host.config().database.recall_max_depth,
        original_depth,
        "invalid-rewrite leaves snapshot at original value"
    );
}
