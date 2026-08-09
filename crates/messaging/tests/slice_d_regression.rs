//! Slice-D regression locks — T-D12..T-D14.
//!
//! No new AC claims. Verifies slice-D additions (`with_event_bus`,
//! `BreakerSubscriber`) do NOT loosen or break slice-A/B/C invariants:
//!
//! - T-D12 pins T-A03 (over-capacity deliver returns MailboxFull AND emits 0
//!   latency events when bus wired)
//! - T-D13 pins T-A04 + T-B26 (deliver still rejects cross-hierarchy;
//!   notify_agent still bypasses hierarchy — both under slice-D additions)
//! - T-D14 pins slice-C `t_a03c_freeze_toggle_observable`
//!   (Mailbox::deliver succeeds while frozen — slice-A observable-only
//!   semantics) with `BreakerSubscriber` active

mod common;

use std::num::NonZeroUsize;
use std::sync::Arc;

use advance_messaging::{
    BreakerSubscriber, EmptyChannelAdapterRegistry, MailboxDispatcher, MailboxDispatcherImpl,
    MailboxStore, MessageTrace, MsgError, NotifyError,
};
use advance_runtime::circuit_breaker::{
    BreakerScope, BreakerState, CircuitBreaker, CircuitBreakerBus, DefaultCircuitBreakerBus,
};
use advance_shared_types::mailbox::{Message, MessageKind};

use crate::common::{wait_until, MockEventBusEmit, TestTree};

const SMALL_CAPACITY: NonZeroUsize = match NonZeroUsize::new(2) {
    Some(n) => n,
    None => panic!("2 != 0"),
};

const DEFAULT_CAPACITY: NonZeroUsize = match NonZeroUsize::new(100) {
    Some(n) => n,
    None => panic!("100 != 0"),
};

fn msg(id: &str, from: &str, to: &str, kind: MessageKind) -> Message {
    Message {
        id: id.into(),
        kind,
        from: from.into(),
        to: to.into(),
        payload: vec![1],
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    }
}

// ─────────────────────────────────────────────────────────────────────
// T-D12 — over-capacity deliver returns MailboxFull AND emits 0 events
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d12_overcapacity_deliver_emits_zero_events() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let store = Arc::new(MailboxStore::new(SMALL_CAPACITY));
    let bus = Arc::new(MockEventBusEmit::new());
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_event_bus(bus.clone());

    // Fill capacity (2 messages → 2 emits).
    d.deliver(
        "agent:b",
        msg("m1", "agent:a", "agent:b", MessageKind::Agent),
    )
    .await
    .unwrap();
    d.deliver(
        "agent:b",
        msg("m2", "agent:a", "agent:b", MessageKind::Agent),
    )
    .await
    .unwrap();
    assert_eq!(bus.count(), 2);

    // 3rd deliver → MailboxFull, no extra emit.
    let err = d
        .deliver(
            "agent:b",
            msg("m3", "agent:a", "agent:b", MessageKind::Agent),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MsgError::MailboxFull));
    assert_eq!(
        bus.count(),
        2,
        "MailboxFull error path emits 0 latency events"
    );
}

// ─────────────────────────────────────────────────────────────────────
// T-D13 — deliver still rejects cross-hierarchy; notify_agent still bypasses
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d13_hierarchy_invariants_preserved_under_slice_d() {
    // Tree: agent:a (root) → agent:b (child). agent:x is unrelated root.
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a")
        .add_root("agent:x");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus = Arc::new(MockEventBusEmit::new());
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_event_bus(bus.clone());

    // Cross-hierarchy deliver still fails (T-A04 invariant): agent:x has no
    // adjacency to agent:b.
    let err = d
        .deliver(
            "agent:b",
            msg("cross-1", "agent:x", "agent:b", MessageKind::Agent),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MsgError::InvalidTarget(_)));

    // notify_agent still bypasses hierarchy (T-B26 invariant): even
    // unrelated-tree sender succeeds via notify.
    d.notify_agent("agent:x", "agent:b", vec![9], None)
        .await
        .unwrap();

    // Bus should have exactly 1 event — the successful notify_agent
    // (deliver rejected → no emit).
    assert_eq!(
        bus.count(),
        1,
        "only the successful notify_agent emits; cross-hierarchy deliver did not"
    );
}

// notify_agent backward-compat: rejecting unknown target still returns
// NotifyError::InvalidTarget (no panic from slice-D bus wiring).
#[tokio::test]
async fn t_d13b_notify_agent_unknown_target_still_rejects() {
    let tree = TestTree::new().add_root("agent:a");
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let d = MailboxDispatcherImpl::new_full(
        store,
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    );
    let err = d
        .notify_agent("agent:a", "agent:unknown", vec![1], None)
        .await
        .unwrap_err();
    assert!(matches!(err, NotifyError::InvalidTarget(_)));
}

// ─────────────────────────────────────────────────────────────────────
// T-D14 — slice-C t_a03c_freeze_toggle_observable preserved
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d14_mailbox_deliver_succeeds_while_frozen_with_subscriber() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let _sub = BreakerSubscriber::spawn(bus.clone(), store.clone());

    // Create mailbox via Open (lazy-create per slice-D AC-13 trade-off).
    bus.open(CircuitBreaker {
        scope: BreakerScope::Agent,
        target: "agent:t".into(),
        state: BreakerState::Open,
        kill_existing: false,
        reason: "test".into(),
    })
    .unwrap();
    let frozen = wait_until(
        || store.get("agent:t").map(|m| m.is_frozen()).unwrap_or(false),
        200,
    )
    .await;
    assert!(frozen);

    // Slice-A regression-lock: Mailbox::deliver succeeds while frozen
    // (observable-only semantics). Slice-D BreakerSubscriber must NOT change
    // this behavior — Layer-1 enforcement is the dispatcher's job, not
    // Mailbox::deliver's. T-D14 is the explicit pin.
    let mb = store.get("agent:t").unwrap();
    assert!(mb.is_frozen());
    mb.deliver(msg(
        "under-freeze",
        "agent:a",
        "agent:t",
        MessageKind::Agent,
    ))
    .expect("Mailbox::deliver succeeds while frozen (slice-A invariant)");
    assert!(
        mb.is_frozen(),
        "delivery does not unfreeze; only Closed/HalfOpen events do"
    );
}
