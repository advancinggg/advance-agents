//! MODULE-001-AC-30 lower-crate witnesses for the runtime side of the ordered shutdown:
//! `RuntimeLock::release` joins the heartbeat before it unlinks the lock file;
//! `RuntimeConfigWatcher::stop` closes every subscriber channel (and keeps answering
//! `current()`); `RuntimeHostBuilder::take_wal_observer` hands out the WAL-mode observer
//! task, which ends once the watcher is stopped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime::config::{RuntimeConfigProvider, RuntimeConfigWatcher};
use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::RuntimeHostBuilder;

/// Bound on the OS watcher's release inside `RuntimeConfigWatcher::stop`. Generous on purpose:
/// on macOS it waits for the FSEvents run loop, whose latency is the platform's.
const OS_WATCHER_RELEASE_BOUND: Duration = Duration::from_secs(60);

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

fn fresh_workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    let config_path = workspace.join(".advance").join("runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_VALID_YAML).unwrap();
    (dir, workspace, config_path)
}

/// A 1 ms heartbeat rewrites the lock file continuously on another worker thread; after
/// `release()` returns the file is gone and stays gone (no late heartbeat re-creates it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_runtime_lock_release_joins_heartbeat() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(dir.path()).unwrap();
    let lock_path = workspace.join(".runtime").join("runtime.lock");
    for round in 0..20 {
        let lock = RuntimeLock::acquire(&workspace, Duration::from_millis(1))
            .await
            .expect("acquire");
        assert!(lock_path.exists(), "round {round}: lock file written");
        tokio::time::sleep(Duration::from_millis(5)).await;
        lock.release().await;
        assert!(!lock_path.exists(), "round {round}: removed by release");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !lock_path.exists(),
            "round {round}: a heartbeat re-created the file after release"
        );
    }
    // The workspace can be locked again at once.
    let again = RuntimeLock::acquire(&workspace, Duration::from_secs(30))
        .await
        .expect("re-acquire after release");
    drop(again);
    assert!(!lock_path.exists(), "Drop still removes an unreleased lock");
}

/// `stop` closes every subscriber channel without waiting for the OS watcher's release: on
/// macOS that release waits for the FSEvents run-loop thread, which can take seconds right
/// after the watch started, so the subscribers are checked while `stop` may still be
/// waiting, and `stop` itself only has to finish within a generous bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_config_watcher_stop_clears_subscribers() {
    let (_dir, _workspace, config_path) = fresh_workspace();
    let watcher = Arc::new(
        RuntimeConfigWatcher::new(&config_path)
            .await
            .expect("watch"),
    );
    let mut first = watcher.subscribe();
    let mut second = watcher.subscribe();
    let before = watcher.current();

    let stopping = tokio::spawn({
        let watcher = Arc::clone(&watcher);
        async move { watcher.stop().await }
    });

    for (name, rx) in [("first", &mut first), ("second", &mut second)] {
        let next = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{name} subscriber not closed within 2s of stop"));
        assert!(next.is_none(), "{name} subscriber channel is closed");
    }
    tokio::time::timeout(OS_WATCHER_RELEASE_BOUND, stopping)
        .await
        .expect("stop finished once the OS watcher was released")
        .expect("stop did not panic");
    // The last applied config is still served.
    assert!(Arc::ptr_eq(&before, &watcher.current()));

    // A rewrite after stop is not applied (nothing watches any more).
    let rewritten = MINIMAL_VALID_YAML.replace("max_memory_pages: 1024", "max_memory_pages: 2048");
    std::fs::write(&config_path, rewritten).unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(watcher.current().wasm.max_memory_pages, 1024);

    // Idempotent.
    tokio::time::timeout(Duration::from_secs(2), watcher.stop())
        .await
        .expect("second stop returned");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_wal_observer_is_taken_once_and_ends_after_watcher_stop() {
    let (_dir, workspace, config_path) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("builder");
    let observer = builder.take_wal_observer().expect("observer handle");
    assert!(builder.take_wal_observer().is_none(), "taken once");
    assert!(
        !observer.is_finished(),
        "observer runs while the watcher does"
    );

    builder.config_watcher().stop().await;
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(2), observer)
        .await
        .expect("observer ended after the watcher stopped")
        .expect("observer did not panic");
    assert!(started.elapsed() < Duration::from_secs(2));
}
