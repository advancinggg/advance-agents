//! Lifecycle-harvest — SYS-J-01 git.commit observability e2e witness
//! (SYS-AC-247).
//!
//! Wired system: the standard harness wired turn (production
//! `build_agent_loop` + `WasmMessageHandler` + real cap-fs + the REAL
//! bus-wired `DefaultGitCommitQueue` — the harness build() spawns the queue
//! via `spawn_with_event_bus` over the SUT event sink, the same wiring the
//! production cli now uses). The `guest-rust-j01-skeleton` turn performs one
//! `agent-fs::write`, whose `Adv003GitSync` leg submits a `CommitType::Turn`
//! commit; the queue worker emits `git.commit` after the successful commit
//! (MODULE-003-AC-25), observable via `events()`.
//!
//! The emit happens before the submitter's oneshot ack, and the fs-write turn
//! awaits the commit ack before returning — so by the time `run_turn()`
//! resolves the event is deterministically visible (no sleeps).

use system_acceptance::{Cap, SystemUnderTest};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_247_turn_emits_git_commit_event_with_sha_and_paths() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .build(J01_SKELETON)
        .await;

    let payload = b"sys-j01-git-commit-event";
    sut.inject_message("alice", payload).await;
    sut.run_turn().await;

    // Premise: the turn's write landed and produced exactly one turn commit.
    sut.read_workspace_file("j01.txt")
        .expect("the turn's fs.write landed in the agent workspace");
    let commits = sut.turn_commits();
    assert_eq!(commits.len(), 1, "exactly one new turn commit");

    // SYS-AC-247: the turn emitted git.commit with commit_type=turn, a
    // non-empty SHA, and the turn's affected_paths.
    let events = sut.events();
    let commit_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "git.commit")
        .collect();
    assert_eq!(
        commit_events.len(),
        1,
        "exactly one git.commit event: {events:?}"
    );
    let e = commit_events[0];
    assert_eq!(e.payload["commit_type"], "turn");

    let sha = e.payload["sha"].as_str().expect("sha is a string");
    assert!(!sha.is_empty(), "non-empty SHA");
    assert_eq!(sha.len(), 40, "full oid hex");
    assert!(sha.chars().all(|c| c.is_ascii_hexdigit()), "hex SHA: {sha}");

    let paths: Vec<&str> = e.payload["affected_paths"]
        .as_array()
        .expect("affected_paths array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        paths.iter().any(|p| p.ends_with("j01.txt")),
        "the turn's written file is in affected_paths: {paths:?}"
    );
    for p in &paths {
        assert!(!p.starts_with('/'), "repo-relative paths only: {p}");
    }
    assert!(e.payload["affected_paths_count"].as_u64().unwrap() >= 1);
    assert!(e.payload["files_changed"].as_u64().unwrap() >= 1);
    assert!(
        e.payload["initiator"].as_str().is_some(),
        "initiator present: {:?}",
        e.payload
    );
    // Redaction: no absolute workspace prefix anywhere in the payload.
    let dump = serde_json::to_string(&e.payload).unwrap();
    assert!(
        !dump.contains(sut.workspace_root().to_str().unwrap()),
        "absolute workspace leaked into payload: {dump}"
    );
}
