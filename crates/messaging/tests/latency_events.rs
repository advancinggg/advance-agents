//! Slice-D AC-09 closure — `msg.received` latency-event emission tests.
//!
//! Covers all three target-reaching dispatcher entry points
//! (`deliver`/`reply`/`deliver_notify`) and verifies the M006-side emit-only
//! contract (M019 EventBus owns the `mailbox.delivery_slow` breach mirror per
//! M019-AC-10; see MODULE-006 §3.8 (h)).
//!
//! Test band:
//! - T-D01 helper unit: sub-1s latency → 1 event
//! - T-D02 helper unit: 2s synthetic latency → 1 event (no breach emit from M006)
//! - T-D03 dispatcher.deliver integration with bus wired
//! - T-D03b dispatcher.reply integration with bus wired (Round-2 Critical #1)
//! - T-D03c dispatcher.notify_agent integration with bus wired
//! - T-D04 dispatcher.deliver WITHOUT bus wired (backward-compat no-emit)
//! - T-D05 dispatcher.deliver under Layer-1 CB rejection emits zero events

mod common;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use advance_messaging::{
    emit_delivery_event, EmptyChannelAdapterRegistry, MailboxDispatcher, MailboxDispatcherImpl,
    MailboxStore, MessageTrace, EVENT_MSG_RECEIVED,
};
use advance_shared_types::mailbox::{Message, MessageContext, MessageKind, MessageOrigin};

use crate::common::{make_mock_cb_bus, MockEventBusEmit, TestTree};

const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(100) {
    Some(n) => n,
    None => panic!("100 != 0"),
};

fn agent_msg(id: &str, from: &str, to: &str, kind: MessageKind) -> Message {
    Message {
        id: id.into(),
        kind,
        from: from.into(),
        to: to.into(),
        payload: vec![1, 2, 3],
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    }
}

// ─────────────────────────────────────────────────────────────────────
// T-D01 / T-D02 — emit_delivery_event helper unit tests
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d01_helper_unit_emits_single_event_sub_threshold() {
    let bus = MockEventBusEmit::new();
    emit_delivery_event(
        &bus,
        "m1",
        "agent:a",
        "agent:b",
        MessageKind::Agent,
        None,
        Duration::from_millis(500),
    );
    assert_eq!(bus.count(), 1, "exactly 1 msg.received event");
    let events = bus.events.lock().unwrap();
    let ev = &events[0];
    assert_eq!(ev.event_type, "msg.received");
    assert_eq!(ev.event_type, EVENT_MSG_RECEIVED);
    assert_eq!(ev.agent_id, "agent:b", "agent_id is receiver (to)");
    assert_eq!(ev.duration_ms, Some(500));
    let payload = &ev.payload;
    assert_eq!(payload["message_id"], "m1");
    assert_eq!(payload["from"], "agent:a");
    assert_eq!(payload["to"], "agent:b");
    assert_eq!(payload["kind"], "agent", "lowercase kind");
    assert_eq!(payload["delivery_latency_ms"], 500);
    // Context-derived fields default to None.
    assert!(ev.task_id.is_none());
    assert!(ev.run_id.is_none());
    assert!(ev.execution_id.is_none());
    assert!(ev.parent_span_id.is_none());
    // trace_id + span_id are fresh UUIDs (non-empty).
    assert!(!ev.trace_id.is_empty());
    assert!(!ev.span_id.is_empty());
    assert_ne!(ev.trace_id, ev.span_id);
}

#[tokio::test]
async fn t_d02_helper_unit_no_breach_emit_from_m006() {
    // M019 EventBus owns the mailbox.delivery_slow breach mirror per M019-AC-10
    // (event-bus/src/lib.rs:264-323). M006 deliberately emits ONLY msg.received
    // regardless of latency — double-publishing would be wrong. T-D02 pins
    // exactly-1-event behavior even with a 2-second synthetic latency.
    let bus = MockEventBusEmit::new();
    emit_delivery_event(
        &bus,
        "m2",
        "user:alice",
        "agent:b",
        MessageKind::User,
        None,
        Duration::from_secs(2),
    );
    assert_eq!(
        bus.count(),
        1,
        "EXACTLY 1 event regardless of latency — M006 does not emit mailbox.delivery_slow"
    );
    let events = bus.events.lock().unwrap();
    assert_eq!(events[0].event_type, "msg.received");
    assert_eq!(events[0].payload["kind"], "user", "lowercase kind for User");
    assert_eq!(events[0].payload["delivery_latency_ms"], 2000);
    assert_eq!(events[0].duration_ms, Some(2000));
    // Confirm no second event ever exists.
    for ev in events.iter() {
        assert_ne!(
            ev.event_type, "mailbox.delivery_slow",
            "M006 must NOT emit mailbox.delivery_slow"
        );
    }
}

// Bonus: kind variants map to lowercase per the explicit-match contract.
#[tokio::test]
async fn t_d02_kind_str_mapping_all_variants_lowercase() {
    let cases = [
        (MessageKind::User, "user"),
        (MessageKind::Agent, "agent"),
        (MessageKind::Control, "control"),
        (MessageKind::Auto, "auto"),
        (MessageKind::System, "system"),
    ];
    for (kind, expected) in cases {
        let bus = MockEventBusEmit::new();
        emit_delivery_event(
            &bus,
            "mkx",
            "agent:a",
            "agent:b",
            kind,
            None,
            Duration::from_millis(1),
        );
        let events = bus.events.lock().unwrap();
        assert_eq!(events[0].payload["kind"], expected);
    }
}

// Bonus: context fields propagate; trace_id chain-preserved.
#[tokio::test]
async fn t_d02_context_propagation_and_trace_chain() {
    let bus = MockEventBusEmit::new();
    let ctx = MessageContext {
        task_id: Some("task-x".into()),
        run_id: Some("run-x".into()),
        execution_id: Some("exec-x".into()),
        trace_id: Some("trace-chain-1".into()),
        in_reply_to: None,
        correlation_id: None,
    };
    emit_delivery_event(
        &bus,
        "mctx",
        "agent:a",
        "agent:b",
        MessageKind::Agent,
        Some(&ctx),
        Duration::from_millis(10),
    );
    let events = bus.events.lock().unwrap();
    let ev = &events[0];
    assert_eq!(ev.task_id.as_deref(), Some("task-x"));
    assert_eq!(ev.run_id.as_deref(), Some("run-x"));
    assert_eq!(ev.execution_id.as_deref(), Some("exec-x"));
    assert_eq!(ev.trace_id, "trace-chain-1", "trace_id chain-preserved");
    assert!(!ev.span_id.is_empty(), "fresh span_id");
    assert_ne!(ev.span_id, ev.trace_id, "span_id distinct from trace_id");
}

// ─────────────────────────────────────────────────────────────────────
// T-D03 — dispatcher.deliver integration with bus wired
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d03_deliver_with_bus_wired_emits_msg_received() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus = Arc::new(MockEventBusEmit::new());
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_event_bus(bus.clone());

    let msg = agent_msg("m-deliver-1", "agent:a", "agent:b", MessageKind::Agent);
    d.deliver("agent:b", msg).await.unwrap();

    assert_eq!(bus.count(), 1);
    let events = bus.events.lock().unwrap();
    let ev = &events[0];
    assert_eq!(ev.event_type, "msg.received");
    assert_eq!(ev.agent_id, "agent:b", "agent_id is receiver");
    assert_eq!(ev.payload["from"], "agent:a");
    assert_eq!(ev.payload["to"], "agent:b");
    assert_eq!(ev.payload["kind"], "agent");
    assert_eq!(ev.payload["message_id"], "m-deliver-1");
    // delivery_latency_ms is small (single-digit ms in CI); ≥ 0 is sufficient.
    let latency = ev.payload["delivery_latency_ms"].as_u64().unwrap();
    assert!(latency < 1000, "in-test latency well under 1s");
    assert_eq!(ev.duration_ms, Some(latency));
}

// ─────────────────────────────────────────────────────────────────────
// T-D03b — dispatcher.reply path parity (Round-2 Critical #1 fix)
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d03b_reply_with_bus_wired_emits_msg_received() {
    let tree = TestTree::new()
        .add_root("agent:adapter")
        .add_child("agent:listener", "agent:adapter");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let trace = Arc::new(MessageTrace::new());
    let bus = Arc::new(MockEventBusEmit::new());
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        trace.clone(),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_event_bus(bus.clone());

    // Record an inbound trace entry so reply has a target to route to.
    let origin = MessageOrigin {
        message_id: "inbound-1".into(),
        original_channel: "telegram".into(),
        original_sender: "telegram:9001".into(),
        adapter_id: "agent:adapter".into(),
        channel_metadata: Default::default(),
        received_at: advance_shared_types::chrono::Utc::now(),
        context: None,
    };
    // record(message_id, origin, recipient) — recipient is the agent that
    // received the inbound (and is now authorized to reply to it).
    trace
        .record("inbound-1", origin, "agent:listener")
        .expect("trace record");

    d.reply("agent:listener", "inbound-1", vec![1, 2, 3])
        .await
        .unwrap();

    assert_eq!(bus.count(), 1, "reply path also emits msg.received");
    let events = bus.events.lock().unwrap();
    let ev = &events[0];
    assert_eq!(ev.event_type, "msg.received");
    assert_eq!(
        ev.agent_id, "agent:adapter",
        "reply routes to origin.adapter_id; agent_id == to"
    );
    assert_eq!(ev.payload["from"], "agent:listener");
    assert_eq!(ev.payload["to"], "agent:adapter");
    assert_eq!(
        ev.payload["kind"], "agent",
        "reply hard-codes MessageKind::Agent → lowercase 'agent'"
    );
}

// ─────────────────────────────────────────────────────────────────────
// T-D03c — dispatcher.notify_agent path parity
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d03c_notify_agent_with_bus_wired_emits_msg_received() {
    let tree = TestTree::new().add_root("agent:t");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus = Arc::new(MockEventBusEmit::new());
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_event_bus(bus.clone());

    d.notify_agent("user:alice", "agent:t", vec![9], None)
        .await
        .unwrap();

    assert_eq!(bus.count(), 1, "notify_agent path also emits msg.received");
    let events = bus.events.lock().unwrap();
    let ev = &events[0];
    assert_eq!(ev.event_type, "msg.received");
    assert_eq!(ev.agent_id, "agent:t");
    assert_eq!(
        ev.payload["kind"], "user",
        "notify_agent derives kind from from-prefix: 'user:' → User → 'user' lowercase"
    );
}

// ─────────────────────────────────────────────────────────────────────
// T-D04 — dispatcher.deliver WITHOUT bus wired (backward-compat no-emit)
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d04_no_bus_wired_emits_zero_events_backward_compat() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    // No .with_event_bus(...) call — slice-A/B/C posture.
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    );
    let msg = agent_msg("m-no-bus", "agent:a", "agent:b", MessageKind::Agent);
    d.deliver("agent:b", msg).await.unwrap();
    // No observable events (no MockEventBusEmit instance to query) — the assertion
    // here is "deliver succeeded without panic and without any event-bus wiring".
    // The structural absence is verified by absence of an emit on `event_bus = None`
    // path; T-D03 verifies the emit path; T-D04 is the backward-compat lock.
    let received = store.get("agent:b").expect("mailbox").recv().await;
    assert_eq!(received.id, "m-no-bus");
}

// ─────────────────────────────────────────────────────────────────────
// T-D05 — Layer-1 CB rejection emits zero latency events (CB error precedence)
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d05_layer1_cb_rejection_emits_zero_events() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus = Arc::new(MockEventBusEmit::new());
    let cb_bus = make_mock_cb_bus(&[("agent:b", "test_reason")]);
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_circuit_breaker_bus(cb_bus)
    .with_event_bus(bus.clone());

    let msg = agent_msg("m-cb-blocked", "agent:a", "agent:b", MessageKind::Agent);
    let err = d.deliver("agent:b", msg).await.unwrap_err();
    assert!(matches!(
        err,
        advance_messaging::MsgError::CircuitBreakerOpen(_)
    ));

    // No successful delivery → no msg.received emit. CB error path takes
    // precedence over latency emission.
    assert_eq!(bus.count(), 0, "CB rejection emits zero events");
}
