//! MODULE-001-AC-30 lower-crate witness for the git side of the ordered shutdown:
//! `DefaultGitCommitQueue::close_and_join` closes the channel, lets the worker commit
//! everything already queued, joins it, and only then releases the repo's process-wide
//! registration; a later `Drop` of the old queue never removes a newer queue's entry.
//!
//! Assertions on the process-wide registry name this test's own (unique) repo path, so
//! they hold while other tests of the binary run in parallel.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use advance_git::commit_queue::active_queue_paths_for_test;
use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue, GitError,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use tempfile::TempDir;
use tokio::sync::oneshot;

fn registered(path: &PathBuf) -> bool {
    active_queue_paths_for_test().contains(path)
}

/// A gate the held worker waits on; opening it is idempotent.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    fn wait_open(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.opened.wait(open).unwrap();
        }
    }

    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }
}

/// Lets the held worker go on. It also opens the gate when dropped, so a failing assertion
/// never leaves the worker held: the runtime's drop waits for its blocking pool, and the
/// test would hang instead of failing.
struct Release(Arc<Gate>);

impl Release {
    fn now(&self) {
        self.0.open();
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.0.open();
    }
}

/// Holds the commit worker inside `emit` (after its commit, before its reply): it reports
/// that it got there, then waits for the gate.
struct HoldingBus {
    entered: std::sync::mpsc::Sender<()>,
    gate: Arc<Gate>,
}

impl EventBusEmit for HoldingBus {
    fn emit(&self, _event: Event) {
        let _ = self.entered.send(());
        self.gate.wait_open();
    }
}

/// A queue on `workdir` whose worker has committed one request and is now held before its
/// reply. Returns the queue, that reply and the handle that releases the worker.
fn held_queue(
    workdir: &Path,
) -> (
    Arc<DefaultGitCommitQueue>,
    oneshot::Receiver<Result<git2::Oid, GitError>>,
    Release,
) {
    let (entered, reached) = std::sync::mpsc::channel();
    let gate = Arc::new(Gate::default());
    let release = Release(Arc::clone(&gate));
    let bus = Arc::new(HoldingBus { entered, gate });
    let queue =
        Arc::new(DefaultGitCommitQueue::spawn_with_event_bus(workdir.to_path_buf(), bus).unwrap());
    std::fs::write(workdir.join("a.md"), b"a").unwrap();
    let reply = queue.submit(CommitRequest::new(
        "tester",
        "a",
        vec![PathBuf::from("a.md")],
        CommitType::Turn,
        "agent:tester",
    ));
    reached
        .recv_timeout(Duration::from_secs(30))
        .expect("the worker committed and reached emit");
    (queue, reply, release)
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

/// `close_and_join` is cancel-safe: a call dropped while the worker still runs (an owner's
/// timeout) leaves the worker's handle in its slot, so nothing is released, and the next
/// call joins the worker before it releases the entry.
#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_git_close_and_join_is_cancel_safe() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let canonical = std::fs::canonicalize(&workdir).unwrap();
    let (queue, mut reply, release) = held_queue(&workdir);

    let dropped = tokio::time::timeout(Duration::from_millis(200), queue.close_and_join()).await;
    assert!(dropped.is_err(), "the held worker keeps the call waiting");
    assert!(registered(&canonical), "the dropped call released nothing");

    let retry = tokio::spawn({
        let queue = Arc::clone(&queue);
        async move { queue.close_and_join().await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !retry.is_finished(),
        "the next call joins the worker the dropped call left"
    );
    assert!(
        registered(&canonical),
        "the entry stays while the worker runs"
    );

    release.now();
    retry.await.unwrap();
    assert!(
        matches!(reply.try_recv(), Ok(Ok(_))),
        "the worker answered before the join returned"
    );
    assert!(
        !registered(&canonical),
        "the entry is released after the join"
    );
}
