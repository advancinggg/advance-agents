//! sched-triggers (trigger-chain product pre-build): light reinforcement of the
//! already-real Trigger Bus dispatch gates (visited-set re-entry, max-chain-depth,
//! non-whitelisted reject) plus a membership check for the `trigger.fired` event
//! family this slice emits.
//!
//! These gates were built + tested in Slice B (`trigger_bus_dispatch.rs`); this
//! file adds focused reinforcement targeting the future witnesses SYS-AC-102
//! (visited-set cycle prevention), SYS-AC-103 (max-chain-depth reject), and
//! SYS-AC-104 (non-whitelisted reject). No new product; 0 SYS-AC flip.

use advance_scheduler::trigger_bus::{
    is_event_whitelisted, CycleRejection, TriggerBusDispatchImpl,
};
use advance_scheduler::trigger_emit::TRIGGER_FIRED_EVENT_TYPE;
use advance_scheduler::types::{SubscriptionId, TriggerSubscription};
use advance_scheduler::TriggerBusDispatch;
use advance_shared_types::event::Event;
use chrono::Utc;

fn sub(event_type: &str) -> TriggerSubscription {
    TriggerSubscription {
        event_type: event_type.into(),
        filter: None,
        debounce_ms: None,
    }
}

fn make_event(event_type: &str, id: &str) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "trigger-guard-test".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace".into(),
        span_id: "span".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: serde_json::Value::Object(serde_json::Map::new()),
        duration_ms: None,
    }
}

// `trigger.fired` (the family this slice emits) is itself a whitelisted event,
// so the EventBus accepts it without a WHITELIST edit.
#[test]
fn trigger_fired_is_whitelisted() {
    assert!(is_event_whitelisted(TRIGGER_FIRED_EVENT_TYPE));
}

// SYS-AC-104 — a non-whitelisted event subscription is rejected, and dispatch of
// a non-whitelisted event enqueues nothing (logs the rejection).
#[test]
fn non_whitelisted_event_is_rejected_not_enqueued() {
    let bus = TriggerBusDispatchImpl::new();
    assert_eq!(bus.subscribe(sub("fs.write")), SubscriptionId::REJECTED);

    bus.dispatch(make_event("fs.write", "evt-nonwl"));
    assert_eq!(bus.pending_total(), 0);
    assert!(bus
        .cycle_rejected_log()
        .iter()
        .any(|r| matches!(r, CycleRejection::EventTypeNotWhitelisted { .. })));
}

// SYS-AC-103 — a chain exceeding max-chain-depth (default 10) is rejected
// without dispatch.
#[test]
fn over_max_depth_is_rejected_without_dispatch() {
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    let mut event = make_event("git.commit", "evt-deep");
    event.payload = serde_json::json!({ "chain_depth": 10 }); // next_depth 11 > 10
    bus.dispatch(event);

    assert_eq!(bus.pending_total(), 0);
    assert!(bus
        .cycle_rejected_log()
        .iter()
        .any(|r| matches!(r, CycleRejection::MaxDepthExceeded { depth: 11, .. })));
}

// SYS-AC-102 — re-entering the same (chain_id, subscriber) within a chain is not
// dispatched a second time (visited-set prevents the cycle).
#[test]
fn visited_set_skips_second_entry_in_same_chain() {
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("git.commit"));
    assert_ne!(sub_id, SubscriptionId::REJECTED);

    // Two dispatches sharing the same explicit trigger_chain_id.
    let mut e1 = make_event("git.commit", "evt-1");
    e1.payload = serde_json::json!({ "trigger_chain_id": "chain-A", "chain_depth": 0 });
    bus.dispatch(e1);

    let mut e2 = make_event("git.commit", "evt-2");
    e2.payload = serde_json::json!({ "trigger_chain_id": "chain-A", "chain_depth": 0 });
    bus.dispatch(e2);

    // First enqueued; second is an AlreadyVisited skip.
    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(drained.len(), 1, "only the first chain entry is dispatched");
    assert!(bus
        .cycle_rejected_log()
        .iter()
        .any(|r| matches!(r, CycleRejection::AlreadyVisited { .. })));
}
