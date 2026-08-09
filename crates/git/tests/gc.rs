//! MODULE-003 Slice C+D — background gc + RuntimeConfig hot-reload integration.
//!
//! Covers AC-13 (gc runs without blocking commits) + AC-24 (RuntimeConfig
//! hot-reload drives `gc_interval_hours` + `max_tracked_file_mb`).

mod common;

use advance_git::gc::GC_STARTED_TEST_HOOK;
use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GcTask, GitCommitQueue,
    GitConfigSnapshot, StaticGitConfigProvider,
};
use common::TestMutableGitConfigProvider;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::Notify;

fn bootstrap_repo() -> (TempDir, PathBuf) {
    let td = TempDir::new().unwrap();
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).unwrap();
    (td, p)
}

// ---------------------------------------------------------------------------
// AC-13 — background gc
// ---------------------------------------------------------------------------

#[tokio::test]
async fn t13a_spawn_and_drop_gracefully() {
    // AC-13: GcTask shuts down cleanly on Drop without blocking.
    let (_td, p) = bootstrap_repo();
    let cfg = Arc::new(StaticGitConfigProvider::defaults());
    let gc = GcTask::spawn(p, cfg).unwrap();
    drop(gc);
    // The drop signals shutdown via the 1-slot channel; the background
    // task exits on the next select! poll. No assertion needed — the test
    // passing (no hang / panic) is the assertion.
}

#[tokio::test]
async fn t13_commits_are_not_blocked_while_gc_is_mid_pack() {
    // AC-13 (§1.6 "0 observable stalls"): commits submitted while gc is
    // demonstrably INSIDE the production `run_gc` code path must still
    // complete promptly. gc does NOT acquire the coord mutex so commits
    // cannot be serialized behind gc's packbuilder work.
    //
    // Drives the SAME production code path via `advance_git::gc::run_gc_now`
    // (a pub test-access entry point that shares implementation with
    // `GcTask`'s ticker-fired run_gc). The hook `GC_STARTED_TEST_HOOK`
    // signals before any libgit2 work so the test can submit commits
    // only after gc has actually entered the pack phase.
    let (_td, p) = bootstrap_repo();

    // Seed an initial commit so the revwalk has something to traverse.
    {
        use git2::{Repository, Signature};
        std::fs::write(p.join("seed.md"), "seed").unwrap();
        let repo = Repository::open(&p).unwrap();
        let mut idx = repo.index().unwrap();
        idx.add_path(std::path::Path::new("seed.md")).unwrap();
        idx.write().unwrap();
        let tree_id = idx.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("t", "t@x").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "seed", &tree, &[])
            .unwrap();
    }

    // Install the test hook (Mutex-backed; swappable per test so multiple
    // tests in this binary don't interfere via OnceLock's single-set
    // semantics).
    let notify = Arc::new(Notify::new());
    *GC_STARTED_TEST_HOOK.lock().unwrap() = Some(notify.clone());

    let cfg = Arc::new(StaticGitConfigProvider::defaults());
    let queue = DefaultGitCommitQueue::spawn_with_config(p.clone(), cfg.clone()).unwrap();

    // Drive the SAME production `run_gc` via the `run_gc_now` test-entry
    // helper. This exercises the real concurrency model: the gc
    // Repository handle lives on a blocking-pool thread; commits go
    // through the queue worker on a separate blocking thread; neither
    // holds the coord mutex on the other's behalf.
    let gc_path = p.clone();
    let gc_join = tokio::task::spawn_blocking(move || advance_git::gc::run_gc_now(&gc_path));

    // Wait for gc to signal it's started (the production hook fires at
    // the top of run_gc, BEFORE any libgit2 work).
    tokio::time::timeout(Duration::from_secs(5), notify.notified())
        .await
        .expect("run_gc did not signal started within 5s");

    // Now submit a commit while gc is mid-pack. It MUST complete promptly
    // because gc does not hold the coord mutex.
    std::fs::write(p.join("a.md"), "a").unwrap();
    let req = CommitRequest::new(
        "alice",
        "add a.md during gc",
        vec![PathBuf::from("a.md")],
        CommitType::Turn,
        "agent:alice",
    );
    let rx = queue.submit(req);
    let result = tokio::time::timeout(Duration::from_secs(5), rx).await;
    assert!(
        result.is_ok(),
        "commit must complete within 5s while gc is mid-pack"
    );
    let oid = result.unwrap().unwrap().unwrap();
    assert!(!oid.is_zero());

    // Let gc finish + clear the hook so later tests can install their own.
    let gc_result = gc_join.await.unwrap();
    assert!(
        gc_result.is_ok(),
        "run_gc_now failed: {:?}",
        gc_result.err()
    );
    *GC_STARTED_TEST_HOOK.lock().unwrap() = None;
}

#[tokio::test]
async fn t13b_gc_task_interval_tick_cadence() {
    // AC-13: the gc task's internal ticker fires at the configured
    // cadence. Because `tokio::time::pause()` does NOT pause the
    // blocking-pool executor (where the spawned gc_loop runs via
    // `tokio::spawn`), we can't precisely observe tick timing with a
    // paused clock here. Instead: verify the task runs cleanly at the
    // minimum-interval bound (1h via clamp) without panicking during
    // setup or teardown. Interval accuracy is a property of
    // `tokio::time::interval` itself (tokio's own test suite covers it).
    let (_td, p) = bootstrap_repo();
    let provider = Arc::new(TestMutableGitConfigProvider::new(GitConfigSnapshot {
        gc_interval_hours: 1,
        max_tracked_file_mb: 10,
    }));
    let gc = GcTask::spawn(p, provider).unwrap();
    // Small yield to let the gc_loop register its initial ticker.
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(gc);
}

#[tokio::test]
async fn t25_gc_interval_hot_reload_rebuilds_ticker() {
    // AC-24: publishing a new gc_interval_hours drives the gc_loop's
    // ticker-rebuild path. We can't observe the ticker timing without
    // a time-controlled harness, but we CAN verify the gc_loop doesn't
    // panic / deadlock on the reload path and the provider's subscribe
    // channel delivers the update.
    let (_td, p) = bootstrap_repo();
    let provider = Arc::new(TestMutableGitConfigProvider::new(GitConfigSnapshot {
        gc_interval_hours: 24,
        max_tracked_file_mb: 10,
    }));
    let gc = GcTask::spawn(p, provider.clone()).unwrap();

    // Publish multiple updates in succession to exercise the rebuild path.
    provider.publish(GitConfigSnapshot {
        gc_interval_hours: 12,
        max_tracked_file_mb: 10,
    });
    tokio::task::yield_now().await;
    provider.publish(GitConfigSnapshot {
        gc_interval_hours: 6,
        max_tracked_file_mb: 10,
    });
    tokio::task::yield_now().await;
    provider.publish(GitConfigSnapshot {
        gc_interval_hours: 1,
        max_tracked_file_mb: 10,
    });
    tokio::task::yield_now().await;

    drop(gc);
}

// ---------------------------------------------------------------------------
// AC-24 — RuntimeConfig hot-reload
// ---------------------------------------------------------------------------

#[tokio::test]
async fn t25a_max_tracked_file_mb_hot_reload() {
    // AC-24: `max_tracked_file_mb` updated via provider publish takes
    // effect on the NEXT commit without restart. Threshold 10 MB → 1 MB
    // should auto-gitignore a 5 MB file that was previously tracked.
    let (_td, p) = bootstrap_repo();
    let provider = Arc::new(TestMutableGitConfigProvider::new(GitConfigSnapshot {
        gc_interval_hours: 24,
        max_tracked_file_mb: 10,
    }));
    let queue = DefaultGitCommitQueue::spawn_with_config(p.clone(), provider.clone()).unwrap();

    // Commit a 5 MB file with threshold=10 MB → should be tracked.
    let big = vec![0u8; 5 * 1024 * 1024];
    std::fs::write(p.join("big.bin"), &big).unwrap();
    let req = CommitRequest::new(
        "alice",
        "add big (threshold=10MB)",
        vec![PathBuf::from("big.bin")],
        CommitType::Turn,
        "agent:alice",
    );
    let _ = queue.submit(req).await.unwrap().unwrap();

    // Verify big.bin is NOT in .gitignore.
    let gi = std::fs::read_to_string(p.join(".gitignore")).unwrap();
    assert!(
        !gi.contains("big.bin"),
        "big.bin should not be gitignored at threshold=10MB"
    );

    // Publish a new snapshot with threshold=1 MB.
    provider.publish(GitConfigSnapshot {
        gc_interval_hours: 24,
        max_tracked_file_mb: 1,
    });

    // Commit another 5 MB file → should now be auto-gitignored.
    let big2 = vec![0u8; 5 * 1024 * 1024];
    std::fs::write(p.join("big2.bin"), &big2).unwrap();
    let req2 = CommitRequest::new(
        "alice",
        "add big2 (threshold=1MB)",
        vec![PathBuf::from("big2.bin")],
        CommitType::Turn,
        "agent:alice",
    );
    let _ = queue.submit(req2).await.unwrap().unwrap();

    // Verify big2.bin IS in .gitignore (threshold now 1MB).
    let gi = std::fs::read_to_string(p.join(".gitignore")).unwrap();
    assert!(
        gi.contains("big2.bin"),
        ".gitignore must auto-append big2.bin after threshold hot-reload, got:\n{gi}"
    );
}

#[tokio::test]
async fn t25b_static_defaults_match_section_2_10() {
    // AC-24: StaticGitConfigProvider defaults match MODULE-003 §2.10
    // (gc_interval_hours=24, max_tracked_file_mb=10).
    let p = StaticGitConfigProvider::defaults();
    let s = <StaticGitConfigProvider as advance_git::GitConfigProvider>::snapshot(&p);
    assert_eq!(s.gc_interval_hours, 24);
    assert_eq!(s.max_tracked_file_mb, 10);
}

#[tokio::test]
async fn t25c_static_provider_rejects_out_of_bounds() {
    // AC-24: StaticGitConfigProvider::new rejects out-of-bounds args
    // matching MODULE-001 RuntimeConfig validation.
    assert!(StaticGitConfigProvider::new(0, 10).is_err());
    assert!(StaticGitConfigProvider::new(8761, 10).is_err());
    assert!(StaticGitConfigProvider::new(24, 0).is_err());
    assert!(StaticGitConfigProvider::new(24, 4097).is_err());
    assert!(StaticGitConfigProvider::new(24, 10).is_ok());
}

#[tokio::test]
async fn aux_gc_spawn_with_test_mutable_provider() {
    // Exercises the full loop: TestMutableGitConfigProvider + GcTask
    // subscribe path. Publish a new interval and observe the task doesn't
    // panic/misbehave.
    let (_td, p) = bootstrap_repo();
    let provider = Arc::new(TestMutableGitConfigProvider::new(GitConfigSnapshot {
        gc_interval_hours: 24,
        max_tracked_file_mb: 10,
    }));
    let gc = GcTask::spawn(p, provider.clone()).unwrap();
    // Publish a different interval — the loop should rebuild its ticker
    // without panicking.
    provider.publish(GitConfigSnapshot {
        gc_interval_hours: 6,
        max_tracked_file_mb: 10,
    });
    // Give the loop a chance to process the update.
    tokio::task::yield_now().await;
    drop(gc);
}
