//! MODULE-001-AC-30 lower-crate witness for the git side of the ordered shutdown:
//! `DefaultGitCommitQueue::close_and_join` closes the channel, lets the worker commit
//! everything already queued, joins it, and only then releases the repo's process-wide
//! registration; a later `Drop` of the old queue never removes a newer queue's entry.
//!
//! Assertions on the process-wide registry name this test's own (unique) repo path, so
//! they hold while other tests of the binary run in parallel.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use advance_git::commit_queue::active_queue_paths_for_test;
use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue, GitError,
};
use tempfile::TempDir;

fn registered(path: &PathBuf) -> bool {
    active_queue_paths_for_test().contains(path)
}

fn commit_count(workdir: &std::path::Path) -> usize {
    let repo = git2::Repository::open(workdir).unwrap();
    let mut walk = repo.revwalk().unwrap();
    // A freshly bootstrapped repository has an unborn HEAD: no commit yet.
    if walk.push_head().is_err() {
        return 0;
    }
    walk.count()
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_git_close_and_join_releases_after_drain() {
    const N: usize = 5;
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let canonical = std::fs::canonicalize(&workdir).unwrap();
    let commits_before = commit_count(&workdir);

    let queue = Arc::new(DefaultGitCommitQueue::spawn(workdir.clone()).unwrap());
    assert!(registered(&canonical), "spawn registers the repo");

    // Queue N commits without awaiting any of them.
    let mut replies = Vec::new();
    for i in 0..N {
        let name = format!("file-{i}.md");
        std::fs::write(workdir.join(&name), format!("{i}")).unwrap();
        replies.push(queue.submit(CommitRequest::new(
            "tester",
            format!("commit-{i}"),
            vec![PathBuf::from(name)],
            CommitType::Turn,
            "agent:tester",
        )));
    }

    tokio::time::timeout(Duration::from_secs(30), queue.close_and_join())
        .await
        .expect("close_and_join finished");

    // Every queued request was committed BEFORE the join returned: each reply is
    // already resolved (no waiting) and the history has all N commits.
    for (i, mut reply) in replies.into_iter().enumerate() {
        match reply.try_recv() {
            Ok(Ok(_oid)) => {}
            other => panic!("commit {i} was not answered before the join: {other:?}"),
        }
    }
    assert_eq!(commit_count(&workdir), commits_before + N);
    assert!(
        !registered(&canonical),
        "the entry is released after the join"
    );

    // A submit after the close answers WorkerClosed at once.
    let late = queue
        .submit(CommitRequest::new(
            "tester",
            "late",
            vec![],
            CommitType::Turn,
            "agent:tester",
        ))
        .await
        .expect("pre-resolved reply");
    assert!(matches!(late, Err(GitError::WorkerClosed)), "{late:?}");

    // A new queue can register the same repo while the old Arc is still alive.
    let newer = DefaultGitCommitQueue::spawn(workdir.clone()).expect("re-spawn after release");
    assert!(registered(&canonical));

    // A second close_and_join and the late Drop of the old queue leave the newer
    // queue's entry alone.
    queue.close_and_join().await;
    assert!(
        registered(&canonical),
        "a repeated close keeps the newer entry"
    );
    drop(queue);
    assert!(
        registered(&canonical),
        "the old queue's Drop keeps the newer entry"
    );

    // Drop semantics of a queue that was never closed are unchanged.
    drop(newer);
    assert!(
        !registered(&canonical),
        "Drop of an unclosed queue releases"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_git_concurrent_close_and_join_both_wait_for_the_worker() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let canonical = std::fs::canonicalize(&workdir).unwrap();
    let queue = Arc::new(DefaultGitCommitQueue::spawn(workdir.clone()).unwrap());
    std::fs::write(workdir.join("a.md"), b"a").unwrap();
    let mut reply = queue.submit(CommitRequest::new(
        "tester",
        "a",
        vec![PathBuf::from("a.md")],
        CommitType::Turn,
        "agent:tester",
    ));

    let (q1, q2) = (Arc::clone(&queue), Arc::clone(&queue));
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { q1.close_and_join().await }),
        tokio::spawn(async move { q2.close_and_join().await }),
    );
    r1.unwrap();
    r2.unwrap();
    // Whichever call returned, the worker had committed the queued request first.
    assert!(matches!(reply.try_recv(), Ok(Ok(_))));
    assert!(!registered(&canonical));
}
