//! MODULE-001-AC-30 — a home declaring `lifecycle` composes again in the same process
//! after a shutdown: the root agent registered with the CONTRACT-219 projector by the first
//! composition is live in the home's durable registry, and the second composition reuses
//! that registration (the same root agent id) instead of failing to register it a second
//! time. Only a registration made in this process is reused: a new process registers the
//! root agent as `advance start` always has (`crates/cli/tests/module_001_t111_exit_codes.rs`
//! pins what a restart does).

use std::path::PathBuf;
use std::sync::{Arc, Once};

use advance_runtime_compose::{compose, ComposeOptions, NullComposeLog};

const MASTER_KEY_ENV: &str = "ADVANCE_LIFECYCLE_AGAIN_MASTER_KEY";

fn runtime_yaml() -> String {
    format!(
        r#"wasm:
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
  env-var-name: {MASTER_KEY_ENV}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    )
}

/// A home declaring `fs` and `lifecycle`, and a state root beside it.
fn lifecycle_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
    static KEY: Once = Once::new();
    KEY.call_once(|| std::env::set_var(MASTER_KEY_ENV, "ab".repeat(32)));
    let dir = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(dir.path()).expect("canonical temp root");
    let home = root.join("home");
    let state_root = root.join("state");
    for path in [
        home.join(".advance"),
        home.join(".runtime/events/jsonl"),
        home.join(".agent"),
        state_root.clone(),
    ] {
        std::fs::create_dir_all(path).expect("create home dirs");
    }
    std::fs::write(home.join(".advance/runtime-config.yaml"), runtime_yaml())
        .expect("write runtime config");
    std::fs::write(
        home.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  lifecycle: true\n",
    )
    .expect("write agent config");
    (dir, home, state_root)
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_lifecycle_home_composes_again() {
    let (_dir, home, state_root) = lifecycle_home();
    let options =
        || ComposeOptions::daemon(&home, Arc::new(NullComposeLog)).with_state_root(&state_root);

    let first = compose(options(), Vec::new())
        .await
        .expect("the first composition of the lifecycle home");
    let root_agent = first.root_agent_id().to_owned();
    first.shutdown().await.expect("shutdown");

    let second = compose(options(), Vec::new())
        .await
        .expect("the lifecycle home composes again");
    assert_eq!(
        second.root_agent_id(),
        root_agent,
        "the same root agent, registered once"
    );
    second.shutdown().await.expect("second shutdown");
}
