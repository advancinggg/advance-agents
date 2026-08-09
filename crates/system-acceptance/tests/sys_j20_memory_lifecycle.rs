//! /dev Track B — SYS-J-20 memory remember/recall/forget lifecycle witness.
//!
//! Drives ONE real wired turn (the production agent loop + `WasmMessageHandler`) with
//! `.caps([Cap::Memory])`, loading the `guest-rust-b-mem-seq` fixture, which calls the
//! REAL versioned `agent-memory` host fns in sequence:
//!   remember(payload, ["insight"]) -> recall(payload) -> forget(id) -> recall(payload)
//! No mock/stub stands in for any module in the memory chain (witness-floor): the real
//! `register_agent_memory` handlers run through the production `CapabilityInjector`.
//!
//!  - **SYS-AC-060** — a `recall` for the stored insight returns it, emitting
//!    `memory.recall {.., result_count, top_score}` with `result_count >= 1`.
//!  - **SYS-AC-061** — `forget` emits `memory.forget {agent_id, memory_id}` and a
//!    subsequent `recall` no longer returns the forgotten entry (`result_count == 0`).
//!
//! Scope note (witness-floor honesty): SYS-AC-059's `memory.remember` event leg is also
//! observed here, but its *"persisted to knowledge.jsonl"* clause is a product gap — the
//! harness (and production, `cli/wiring.rs`) wire an in-memory `MemoryStore`, no jsonl/
//! SQLite — so SYS-AC-059 stays an accepted system-acceptance deferral (SYSTEM-ACCEPTANCE.md
//! §3), NOT flipped here. Likewise the other 39 SYS-J-02/03/04/20-24/54/60 SYS-AC are
//! deferred (HF harness primitive: real ContextAssembler / decomposition host-fn
//! registration; or product gaps: post-turn extraction / L6 runnable / VLM / skill-candidate
//! writer / git-tracked rollback / on-disk persistence).

use system_acceptance::{Cap, SystemUnderTest};

const B_MEM_SEQ_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-b-mem-seq.core.wasm");

const INSIGHT: &[u8] = b"track-b durable insight for the lifecycle witness";

/// SYS-AC-060: `recall` for the stored insight returns it; `memory.recall` carries
/// `result_count >= 1`.
#[tokio::test]
async fn sys_ac_060_recall_returns_remembered_insight() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory])
        .build(B_MEM_SEQ_CORE)
        .await;
    sut.inject_message("harness", INSIGHT).await;
    sut.run_turn().await;

    // The remember leg fires (content_preview present). NOTE: this is SYS-AC-059's event
    // leg only — its knowledge.jsonl-persistence clause is a deferred product gap.
    let remember = sut.assert_event("memory.remember", |_| true);
    assert!(
        remember
            .payload
            .get("content_preview")
            .and_then(|v| v.as_str())
            .is_some(),
        "memory.remember carries a content_preview"
    );

    // The first recall must report at least one hit for the just-stored insight.
    let recalls = sut.events_of_types(&["memory.recall"]);
    assert!(
        !recalls.is_empty(),
        "at least one memory.recall event was emitted by the guest turn"
    );
    let first_recall_count = recalls[0]
        .payload
        .get("result_count")
        .and_then(|v| v.as_u64())
        .expect("memory.recall carries a numeric result_count");
    assert!(
        first_recall_count >= 1,
        "SYS-AC-060: first memory.recall result_count {first_recall_count} >= 1 \
         (the remembered insight is recall-able)"
    );
}

/// SYS-AC-061: `forget` emits `memory.forget {agent_id, memory_id}` and the subsequent
/// `recall` excludes the forgotten entry (`result_count == 0`).
#[tokio::test]
async fn sys_ac_061_forget_then_recall_absent() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory])
        .build(B_MEM_SEQ_CORE)
        .await;
    sut.inject_message("harness", INSIGHT).await;
    sut.run_turn().await;

    let events = sut.events();

    // Guard FIRST: the guest must have completed the full lifecycle — exactly two
    // memory.recall events. This defends against a guest early-return / dropped call /
    // reorder making a single-recall run silently pass the count assertions below.
    let recalls: Vec<&_> = events
        .iter()
        .filter(|e| e.event_type == "memory.recall")
        .collect();
    assert_eq!(
        recalls.len(),
        2,
        "the lifecycle guest emits exactly two memory.recall events (before + after forget); \
         got {}",
        recalls.len()
    );

    // SYS-AC-061a: forget emitted with a populated {agent_id, memory_id}.
    let forget = sut.assert_event("memory.forget", |_| true);
    assert!(
        !forget.agent_id.is_empty(),
        "SYS-AC-061: memory.forget carries an agent_id"
    );
    let memory_id = forget
        .payload
        .get("memory_id")
        .and_then(|v| v.as_str())
        .expect("SYS-AC-061: memory.forget carries a memory_id");
    assert!(
        !memory_id.is_empty(),
        "SYS-AC-061: memory.forget memory_id is non-empty"
    );

    // SYS-AC-061b: the SECOND recall (post-forget) returns zero hits — the forgotten
    // entry is excluded from recall.
    let second_recall_count = recalls[1]
        .payload
        .get("result_count")
        .and_then(|v| v.as_u64())
        .expect("memory.recall carries a numeric result_count");
    assert_eq!(
        second_recall_count, 0,
        "SYS-AC-061: post-forget memory.recall result_count == 0 (forgotten entry absent)"
    );

    // Cross-check emission order: forget precedes recall #2 (Capturing preserves emit order).
    let forget_pos = events
        .iter()
        .position(|e| e.event_type == "memory.forget")
        .unwrap();
    let recall_positions: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.event_type == "memory.recall")
        .map(|(i, _)| i)
        .collect();
    assert!(
        forget_pos > recall_positions[0] && forget_pos < recall_positions[1],
        "forget is emitted between the first and second recall (lifecycle ordering)"
    );
}
