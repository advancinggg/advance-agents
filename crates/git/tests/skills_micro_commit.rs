//! Slice H (REQ-275 foundation, M003-side) — `CommitType::Micro` queue
//! mechanics verification.
//!
//! This file is a FOUNDATION test contribution to the deferred MODULE-003-AC-21
//! / MODULE-017-AC-22 integrated-loop slice. It proves that:
//!   T22a — a single `CommitType::Micro` request produces the canonical
//!          `[micro] [runtime:auto-loop] <message>` prefix in the resulting
//!          commit's message.
//!   T22b — 5 concurrent `CommitType::Micro` submits reach disk in FIFO order
//!          (the M003 §1.4.1 serialized-queue invariant holds for the new
//!          variant).
//!   T22c — interleaved Turn + Micro + L6 submits (9 total) enter the same
//!          serialized queue and produce the correct mixed-prefix `git log`.
//!
//! NO source change is required in `crates/git/src/` — `CommitType::Micro`
//! already exists at `commit_queue.rs:39` and the queue is type-agnostic
//! (formats `[<commit_type>] [<initiator>] <message>` regardless of variant).
//! Per the slice plan (NO-AC-flip pure-waived-scope), these tests do NOT
//! flip MODULE-003-AC-21 in §3.4; they are foundation for the future
//! MODULE-014 integrated-loop slice. See M003 §3.7 (Slice H entry) +
//! M017 §3.6 (uu) for the deferred-work explanation.

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue,
};
use git2::Repository;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

/// Write a small probe file under the repo workdir so the commit has actual
/// content to stage — keeps the queue's `add_path` branch exercised. Returns
/// the relative path inside the workdir.
async fn seed_probe_file(workdir: &std::path::Path, name: &str, content: &str) -> PathBuf {
    let path = workdir.join(name);
    tokio::fs::write(&path, content.as_bytes()).await.unwrap();
    path
}

/// Read the canonical `[<type>] [<initiator>] <subject>` prefix from the most
/// recent commit's message subject line.
fn last_commit_subject(workdir: &std::path::Path) -> String {
    let repo = Repository::open(workdir).expect("open repo");
    let head = repo.head().expect("head").peel_to_commit().expect("commit");
    head.summary().expect("summary").to_string()
}

/// Read every commit in the current branch (newest first) and return their
/// subject lines.
fn list_commit_subjects(workdir: &std::path::Path) -> Vec<String> {
    let repo = Repository::open(workdir).expect("open repo");
    let mut walk = repo.revwalk().expect("revwalk");
    walk.push_head().expect("push_head");
    let mut out = Vec::new();
    for oid in walk {
        let oid = oid.expect("walk oid");
        let c = repo.find_commit(oid).expect("find commit");
        out.push(c.summary().unwrap_or("").to_string());
    }
    out
}

#[tokio::test]
async fn t22a_single_micro_commit_prefix() {
    let dir = TempDir::new().unwrap();
    bootstrap_repo_at(dir.path()).unwrap();
    let queue = DefaultGitCommitQueue::spawn(dir.path().to_path_buf()).unwrap();

    let path = seed_probe_file(dir.path(), "iter1.md", "# iter 1\n").await;

    let req = CommitRequest::new(
        "root",
        "rollback web-search v1",
        vec![path.clone()],
        CommitType::Micro,
        "runtime:auto-loop",
    );
    let rx = queue.submit(req);
    let oid = rx.await.expect("worker open").expect("commit ok");
    assert!(!oid.is_zero());

    let subject = last_commit_subject(dir.path());
    assert_eq!(
        subject,
        "[micro] [runtime:auto-loop] rollback web-search v1"
    );

    drop(queue);
    // Brief settle to let ACTIVE_QUEUES dereg run before the tempdir Drop.
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn t22b_five_concurrent_micro_commits_fifo() {
    let dir = TempDir::new().unwrap();
    bootstrap_repo_at(dir.path()).unwrap();
    let queue = DefaultGitCommitQueue::spawn(dir.path().to_path_buf()).unwrap();

    let mut receivers = Vec::new();
    for i in 0..5 {
        let path =
            seed_probe_file(dir.path(), &format!("iter{i}.md"), &format!("# iter {i}\n")).await;
        let req = CommitRequest::new(
            "root",
            format!("micro op {i}"),
            vec![path],
            CommitType::Micro,
            "runtime:auto-loop",
        );
        receivers.push(queue.submit(req));
    }

    // Await all submits in order; FIFO is verified by the order they
    // resolve AND by the resulting `git log` order.
    let mut oids = Vec::new();
    for (i, rx) in receivers.into_iter().enumerate() {
        let oid = rx
            .await
            .unwrap_or_else(|_| panic!("worker closed before reply {i}"))
            .unwrap_or_else(|e| panic!("commit {i} failed: {e:?}"));
        oids.push(oid);
    }
    assert_eq!(oids.len(), 5);

    let subjects = list_commit_subjects(dir.path());
    // Most recent first per revwalk default ordering.
    let micro_subjects: Vec<&String> = subjects
        .iter()
        .filter(|s| s.starts_with("[micro] [runtime:auto-loop]"))
        .collect();
    assert_eq!(micro_subjects.len(), 5);
    // FIFO ordering: the FIRST submitted op ("micro op 0") is the OLDEST
    // commit, so it appears LAST in revwalk-from-head order.
    let oldest_first: Vec<String> = micro_subjects.iter().rev().map(|s| (*s).clone()).collect();
    for (i, subj) in oldest_first.iter().enumerate() {
        assert_eq!(
            subj,
            &format!("[micro] [runtime:auto-loop] micro op {i}"),
            "FIFO ordering violated at index {i}"
        );
    }

    drop(queue);
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn t22c_interleaved_turn_micro_l6_same_queue() {
    let dir = TempDir::new().unwrap();
    bootstrap_repo_at(dir.path()).unwrap();
    let queue = DefaultGitCommitQueue::spawn(dir.path().to_path_buf()).unwrap();

    // Submit 9 requests in a Turn → Micro → L6 round-robin pattern,
    // exercising the SAME serialized queue.
    let scripted: Vec<(CommitType, &str, &str)> = vec![
        (CommitType::Turn, "agent:a", "turn-1"),
        (CommitType::Micro, "runtime:auto-loop", "micro-1"),
        (CommitType::L6, "runtime:l6", "l6-1"),
        (CommitType::Turn, "agent:a", "turn-2"),
        (CommitType::Micro, "runtime:auto-loop", "micro-2"),
        (CommitType::L6, "runtime:l6", "l6-2"),
        (CommitType::Turn, "agent:a", "turn-3"),
        (CommitType::Micro, "runtime:auto-loop", "micro-3"),
        (CommitType::L6, "runtime:l6", "l6-3"),
    ];

    let mut receivers = Vec::new();
    for (i, (ctype, initiator, label)) in scripted.iter().enumerate() {
        let path = seed_probe_file(dir.path(), &format!("op{i}.md"), &format!("# op {i}\n")).await;
        let req = CommitRequest::new("root", (*label).to_string(), vec![path], *ctype, *initiator);
        receivers.push((queue.submit(req), *ctype, *initiator, (*label).to_string()));
    }

    for (rx, _ctype, _initiator, label) in receivers {
        rx.await
            .unwrap_or_else(|_| panic!("worker closed before reply for {label}"))
            .unwrap_or_else(|e| panic!("commit {label} failed: {e:?}"));
    }

    let subjects = list_commit_subjects(dir.path());
    // Build the EXPECTED prefix list in FIFO (oldest→newest) order then
    // reverse for revwalk-from-head comparison.
    let expected_oldest_first: Vec<String> = scripted
        .iter()
        .map(|(c, i, l)| format!("[{}] [{}] {}", c, i, l))
        .collect();
    let expected_newest_first: Vec<String> = expected_oldest_first.iter().rev().cloned().collect();

    // The first 9 entries of subjects should match (there's no bootstrap
    // commit before the queue's first submit since `bootstrap_repo_at` only
    // initializes the repo + `.gitignore`; the `.gitignore` is staged by the
    // queue's first `do_commit` invocation, embedded INTO that commit).
    let observed: Vec<String> = subjects.iter().take(9).cloned().collect();
    assert_eq!(observed, expected_newest_first);

    // Sanity: counts by prefix.
    let n_turn = observed.iter().filter(|s| s.starts_with("[turn]")).count();
    let n_micro = observed.iter().filter(|s| s.starts_with("[micro]")).count();
    let n_l6 = observed.iter().filter(|s| s.starts_with("[l6]")).count();
    assert_eq!(n_turn, 3);
    assert_eq!(n_micro, 3);
    assert_eq!(n_l6, 3);

    drop(queue);
    tokio::time::sleep(Duration::from_millis(10)).await;
}
