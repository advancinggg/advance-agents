//! Mode smoke (Slice S2): `EventSink::RealBus` persists turn events to the real
//! EventBus JSONL + SQLite, queryable back through the harness's SQLite read-back
//! path. Proves the substrate's real-event-bus mode without a real journey.
//!
//! Runs under `multi_thread` because the synchronous bus writes inline during the
//! turn (bounded per-turn I/O on a worker thread; deterministic read-back, no drain).

use system_acceptance::{Cap, EventSink, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test(flavor = "multi_thread")]
async fn real_eventbus_persists_and_queries_msg_received() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .events(EventSink::RealBus)
        .build(CORE_BYTES)
        .await;

    sut.inject_message("harness", b"hello-realbus").await;
    sut.run_turn().await;

    // Read back from the REAL SQLite events table (inline-written by the sync bus).
    let row = sut.assert_db_event("msg.received", |r| {
        r.agent_id.as_deref() == Some(sut.agent_id())
    });
    assert!(row.payload.is_some(), "msg.received row carries a payload");
    assert!(!row.id.is_empty(), "row has an id");

    // The real bus dropped nothing (oversize / dup-id / backpressure).
    sut.assert_no_dropped_events();
    assert!(
        sut.db_event_count(Some("msg.received")) >= 1,
        "at least one msg.received row persisted"
    );

    // RealBus does NOT populate the in-memory `events()` accessor.
    assert!(
        sut.events().is_empty(),
        "in-memory events() is empty for RealBus"
    );
}
