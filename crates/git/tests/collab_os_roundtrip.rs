//! MODULE-003 Slice E — AC-14 filesystem-as-collaboration-OS invariant.
//!
//! T14: commit → checkpoint → modify → rollback_to_checkpoint round trip
//! using `std::fs::write` directly (MODULE-002 filesystem mount not yet
//! built; no M002 dependency). Exercises CONTRACT-020 (commit queue) +
//! CONTRACT-021 (workspace rollback) + CONTRACT-022 (named checkpoint).
//! `agent_id = "root"` per the ROOT_AGENT_SENTINEL short-circuit.
//!
//! AC-14 scope = audit-trail round-trip invariant. Event emit observation
//! is AC-07's concern (covered in `rollback_event_emit.rs`). T14 uses the
//! legacy `DefaultWorkspaceRollback::new` constructor so the internal
//! `NoopEventBus` silently absorbs the emit — no `CollectingEventBus`
//! needed.

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, DefaultNamedCheckpoint,
    DefaultWorkspaceRollback, GitCommitQueue, NamedCheckpoint, WorkspaceRollback,
};
use git2::Repository;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn t14_collab_os_round_trip_commit_checkpoint_rollback() {
    // Setup.
    let td = TempDir::new().unwrap();
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).unwrap();

    // Seed content via direct std::fs::write (no M002 dependency).
    let report = p.join("report.md");
    std::fs::write(&report, b"v1 content").unwrap();

    // First turn-commit via CommitQueue (CONTRACT-020).
    let queue = DefaultGitCommitQueue::spawn(p.clone()).unwrap();
    let req1 = CommitRequest::new(
        "root",
        "seed turn",
        vec![PathBuf::from("report.md")],
        CommitType::Turn,
        "root",
    );
    let oid1 = queue.submit(req1).await.unwrap().unwrap();

    // Full-directory checkpoint "v1" (CONTRACT-022).
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("root", "v1", None).unwrap();

    // Modify + second turn-commit.
    std::fs::write(&report, b"v2 content").unwrap();
    let req2 = CommitRequest::new(
        "root",
        "drift turn",
        vec![PathBuf::from("report.md")],
        CommitType::Turn,
        "root",
    );
    let _oid2 = queue.submit(req2).await.unwrap().unwrap();

    // Shut the queue down before rollback so the worker thread releases
    // its process-wide `ACTIVE_QUEUES` registration for this repo path.
    drop(queue);

    // Rollback to checkpoint v1 via the legacy `::new` (internal NoopEventBus).
    let rb = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let paths = rb.rollback_to_checkpoint("root", "v1").await.unwrap();
    assert!(
        !paths.is_empty(),
        "rollback must return the checked-out paths"
    );

    // --- AC-14 assertions ---

    // (i) Content restored to v1.
    let restored = std::fs::read_to_string(&report).unwrap();
    assert_eq!(restored, "v1 content");

    // (ii) git log shows both commit subjects prefixed [turn].
    let repo = Repository::open(&p).unwrap();
    let mut revwalk = repo.revwalk().unwrap();
    revwalk.push_head().unwrap();
    let subjects: Vec<String> = revwalk
        .map(|oid| {
            let oid = oid.unwrap();
            let commit = repo.find_commit(oid).unwrap();
            commit.summary().unwrap_or("").to_string()
        })
        .collect();
    assert!(
        subjects.len() >= 2,
        "at least two commits in history, got {:?}",
        subjects
    );
    for s in &subjects[..2] {
        assert!(
            s.starts_with("[turn]"),
            "commit subject must start with [turn]: {s:?}"
        );
    }

    // (iii) `refs/tags/checkpoint/root/v1` tag resolves to a commit with
    // tree content matching v1.
    let tag_ref = repo
        .find_reference("refs/tags/checkpoint/root/v1")
        .expect("checkpoint tag exists");
    let tag_commit = tag_ref.peel_to_commit().unwrap();
    assert_eq!(
        tag_commit.id(),
        oid1,
        "checkpoint tag points at seed commit"
    );
    let tag_tree = tag_commit.tree().unwrap();
    let blob_entry = tag_tree
        .get_path(std::path::Path::new("report.md"))
        .unwrap();
    let blob = repo.find_blob(blob_entry.id()).unwrap();
    assert_eq!(std::str::from_utf8(blob.content()).unwrap(), "v1 content");

    // (iv) Tag message is `{}` (FullDirectory checkpoint; checkpoint.rs:124 / 334-335).
    let tag_object = tag_ref.peel(git2::ObjectType::Tag).unwrap();
    let tag = tag_object.as_tag().expect("annotated tag");
    let tag_msg = tag.message().unwrap_or("");
    assert_eq!(
        tag_msg.trim(),
        "{}",
        "full-directory checkpoint tag message must be empty JSON object"
    );
}
