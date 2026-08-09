//! /dev Slice BS-3 — SYS-J-01 in-process core journey.
//!
//! Witnesses the slice's gated system acceptance criteria through the reusable
//! harness driving the REAL production agent loop:
//!  - **SYS-AC-002** — the turn emits a `msg.received` event at turn start.
//!  - **SYS-AC-190** — that event carries `delivery_latency_ms` < 1000 ms.
//!  - **SYS-AC-003** (small-witness 2026-06-11) — after the reply, git log shows
//!    exactly one new turn commit whose TREE contains the agent's file writes.
//!    Driven by the NEW `guest-rust-j01-reply-write` fixture (writes `j01.txt`
//!    AND returns a reply action — no prior fixture did both) +
//!    `.with_reply_capture()` (the real `OutboundActionSink` post-dispatch seam)
//!    + `CommitInfo.tree_paths` (recursive commit-tree walk).

use system_acceptance::SystemUnderTest;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const J01_REPLY_WRITE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-reply-write.core.wasm");

#[tokio::test]
async fn sys_j01_core_witnesses_msg_received_and_turn_commit() {
    let sut = SystemUnderTest::start(J01_SKELETON).await;
    let payload = b"sys-j01-hello";

    sut.inject_message("alice", payload).await;
    sut.run_turn().await;

    // SYS-AC-002 — msg.received emitted (at delivery, which triggers the turn).
    let evt = sut.assert_event("msg.received", |e| {
        e.payload.get("to").and_then(|v| v.as_str()) == Some(sut.agent_id())
    });
    // SYS-AC-190 — delivery_latency_ms under the 1000 ms mailbox-wake SLO.
    let latency = evt
        .payload
        .get("delivery_latency_ms")
        .and_then(|v| v.as_u64())
        .expect("msg.received carries delivery_latency_ms");
    assert!(
        latency < 1000,
        "SYS-AC-190: delivery_latency_ms {latency} < 1000"
    );

    // SYS-AC-003 capability — exactly one new turn commit whose tree contains the write.
    let file = sut
        .read_workspace_file("j01.txt")
        .expect("the turn's fs.write landed in the agent workspace");
    assert_eq!(file, payload, "file content == injected payload");
    let commits = sut.turn_commits();
    assert_eq!(
        commits.len(),
        1,
        "exactly one new turn commit since bootstrap"
    );
    assert!(
        commits[0].is_turn,
        "the commit is a CommitType::Turn commit"
    );
}

/// SYS-AC-003 — after the reply, git log shows exactly one new turn commit whose
/// tree contains the agent's file writes from that turn.
#[tokio::test]
async fn sys_ac_003_turn_commit_tree_contains_writes_after_reply() {
    let sut = SystemUnderTest::builder()
        .with_reply_capture()
        .build(J01_REPLY_WRITE)
        .await;
    let payload = b"sys-j01-reply-write";

    sut.inject_message("alice", payload).await;
    sut.run_turn().await;

    // The REPLY leg ran: the guest's action was dispatched through the real
    // post-turn OutboundActionSink seam ("after the reply").
    let replies = sut.delivered_replies();
    assert_eq!(
        replies.len(),
        1,
        "the turn delivered exactly one reply action"
    );
    assert_eq!(
        replies[0], b"j01-reply",
        "the guest's reply payload was delivered"
    );

    // The write leg landed in the workspace...
    let file = sut
        .read_workspace_file("j01.txt")
        .expect("the turn's fs.write landed in the agent workspace");
    assert_eq!(file, payload);

    // ...and git log shows EXACTLY ONE new turn commit whose TREE contains
    // the turn's file write (workspace-relative path `agent/j01.txt`).
    let commit = sut.assert_exactly_one_turn_commit();
    assert!(
        commit.tree_paths.iter().any(|p| p == "agent/j01.txt"),
        "turn commit tree contains the write; tree = {:?}",
        commit.tree_paths
    );
}
