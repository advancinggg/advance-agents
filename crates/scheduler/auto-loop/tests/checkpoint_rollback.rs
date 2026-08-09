//! AC-10 (per-iteration checkpoint via Git tag) + AC-11 (rollback restores
//! workspace, excludes `.agent/**`).
//!
//! All rollback tests use `agent_id = "root"` → MODULE-003's
//! `resolve_agent_root` ROOT_AGENT_SENTINEL short-circuit returns
//! `(workdir, "")` with no `.agent/config.yaml` fixture needed (verified
//! against rollback.rs:235-236). Checkpoint tests don't call
//! `resolve_agent_root`, but use `"root"` for cross-test uniformity.

mod common;

use std::sync::Arc;

use advance_git::{DefaultNamedCheckpoint, DefaultWorkspaceRollback};
use advance_scheduler_auto_loop::{
    AutoLoopError, DefaultAutoLoopDriver, DefaultIterationCheckpoint, DefaultIterationRollback,
};

use common::{bootstrap_repo_with_initial_commit, commit_file, read_tag_message, tag_exists};

fn driver_for(repo: &std::path::Path) -> DefaultAutoLoopDriver {
    let ckpt = DefaultNamedCheckpoint::new(repo.to_path_buf()).expect("DefaultNamedCheckpoint");
    let rb = DefaultWorkspaceRollback::new(repo.to_path_buf()).expect("DefaultWorkspaceRollback");
    DefaultAutoLoopDriver::new(
        Arc::new(DefaultIterationCheckpoint::new(Arc::new(ckpt))),
        Arc::new(DefaultIterationRollback::new(Arc::new(rb))),
    )
}

// MODULE-015-T10-slA — checkpoint_iteration creates the git tag (msg "{}").
#[tokio::test]
async fn checkpoint_iteration_creates_git_tag() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    let driver = driver_for(temp.path());

    driver
        .checkpoint_iteration("root", 1)
        .await
        .expect("checkpoint_iteration ok");

    let full_ref = "refs/tags/checkpoint/root/auto-iter-1";
    assert!(
        tag_exists(temp.path(), full_ref),
        "iteration tag must exist"
    );
    assert_eq!(
        read_tag_message(temp.path(), full_ref),
        "{}",
        "full-directory checkpoint tag message must be {{}}"
    );
}

// MODULE-015-T10b-slA — checkpoint_baseline creates the baseline tag.
#[tokio::test]
async fn checkpoint_baseline_creates_git_tag() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    let driver = driver_for(temp.path());

    driver
        .checkpoint_baseline("root")
        .await
        .expect("checkpoint_baseline ok");

    assert!(
        tag_exists(temp.path(), "refs/tags/checkpoint/root/auto-baseline"),
        "baseline tag must exist (hyphen form)"
    );
}

// MODULE-015-T11-slA — rollback restores a file present in the checkpoint tree.
#[tokio::test]
async fn rollback_restores_workspace() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    commit_file(temp.path(), "work.txt", b"v1"); // in the checkpoint tree
    let driver = driver_for(temp.path());

    driver.checkpoint_iteration("root", 1).await.unwrap();
    commit_file(temp.path(), "work.txt", b"v2"); // post-checkpoint mutation

    driver
        .rollback_iteration("root", 1)
        .await
        .expect("rollback ok");

    let restored = std::fs::read(temp.path().join("work.txt")).unwrap();
    assert_eq!(restored, b"v1", "work.txt must be reverted v2 -> v1");
}

// MODULE-015-T11b-slA — rollback to a nonexistent checkpoint errors.
#[tokio::test]
async fn rollback_nonexistent_checkpoint_errors() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    commit_file(temp.path(), "work.txt", b"v1"); // born HEAD + resolvable workspace
    let driver = driver_for(temp.path());

    let r = driver.rollback_iteration("root", 99).await;
    assert!(
        matches!(r, Err(AutoLoopError::Rollback(_))),
        "missing checkpoint must surface as Rollback error, got {r:?}"
    );
}

// MODULE-015-T11c-slA — non-vacuous `.agent/` exclusion.
#[tokio::test]
async fn rollback_excludes_dot_agent() {
    let temp = tempfile::tempdir().unwrap();
    bootstrap_repo_with_initial_commit(temp.path());
    // BOTH tracked + present in the checkpoint tree at v1.
    commit_file(temp.path(), "work.txt", b"v1");
    commit_file(temp.path(), ".agent/keep.txt", b"v1");
    let driver = driver_for(temp.path());

    driver.checkpoint_iteration("root", 1).await.unwrap();

    // Mutate both to v2.
    commit_file(temp.path(), "work.txt", b"v2");
    commit_file(temp.path(), ".agent/keep.txt", b"v2");

    driver.rollback_iteration("root", 1).await.unwrap();

    // work.txt reverted (in checkout set); .agent/keep.txt NOT reverted
    // (filtered out of expand_full_domain by is_excluded_from_writable_domain
    // .agent/ branch) — the ONLY reason it stays v2 is the exclusion.
    assert_eq!(
        std::fs::read(temp.path().join("work.txt")).unwrap(),
        b"v1",
        "normal file must be rolled back"
    );
    assert_eq!(
        std::fs::read(temp.path().join(".agent/keep.txt")).unwrap(),
        b"v2",
        ".agent/ file must SURVIVE rollback (exclusion honored)"
    );
}
