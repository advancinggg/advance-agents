//! Slice-D AC-13 end-to-end closure tests — T-D06..T-D11 + T-D11b.
//!
//! Wires the REAL [`DefaultCircuitBreakerBus`] (NOT the mock — `MockCircuitBreakerBus::subscribe()`
//! returns an immediately-closed receiver, see MODULE-006 §3.6 residual row).
//! Closes AC-13 by demonstrating the production driver `BreakerSubscriber::spawn(bus, store)`
//! routes BreakerEvent records to per-agent `Mailbox::freeze`/`unfreeze` per the
//! three-state matrix (Open→freeze, Closed→unfreeze, HalfOpen→unfreeze).
//!
//! Test band:
//! - T-D06 spawn + Open → freeze
//! - T-D07 Layer-1 reject + Layer-4 hold simultaneously during Open
//! - T-D08 Closed → unfreeze + high-priority-first drain order
//! - T-D09 HalfOpen → unfreeze (probe-mode dispatcher-alignment; split-state safety)
//! - T-D10 race-resilient `get_or_create` on Open for never-used agent
//! - T-D11 cooperative shutdown via handle().abort() + yield_now
//! - T-D11b drop-without-explicit-abort safety via impl Drop

mod common;

use std::num::NonZeroUsize;
use std::sync::Arc;

use advance_messaging::{
    BreakerSubscriber, EmptyChannelAdapterRegistry, MailboxDispatcher, MailboxDispatcherImpl,
    MailboxStore, MessageTrace, MsgError,
};
use advance_runtime::circuit_breaker::{
    BreakerScope, BreakerState, CircuitBreaker, CircuitBreakerBus, DefaultCircuitBreakerBus,
};
use advance_shared_types::mailbox::{Message, MessageKind};

use crate::common::{wait_until, TestTree};

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

fn open_spec(target: &str, reason: &str) -> CircuitBreaker {
    CircuitBreaker {
        scope: BreakerScope::Agent,
        target: target.into(),
        state: BreakerState::Open,
        kill_existing: false,
        reason: reason.into(),
    }
}

// ─────────────────────────────────────────────────────────────────────
// T-D06 — spawn + Open → freeze
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d06_spawn_open_triggers_freeze() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let _sub = BreakerSubscriber::spawn(bus.clone(), store.clone());

    bus.open(open_spec("agent:t", "test")).unwrap();

    // Yield-bounded poll: BreakerSubscriber runs in a spawned task; needs at
    // least one yield to receive the event.
    let frozen = wait_until(
        || store.get("agent:t").map(|m| m.is_frozen()).unwrap_or(false),
        200,
    )
    .await;
    assert!(
        frozen,
        "Open event freezes mailbox within yield-bounded window"
    );
}

// ─────────────────────────────────────────────────────────────────────
// T-D07 — Layer-1 reject + Layer-4 hold simultaneously during Open
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d07_layer1_reject_plus_layer4_hold_during_open() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:t", "agent:a");

    let dispatcher = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_circuit_breaker_bus(bus.clone());

    let _sub = BreakerSubscriber::spawn(bus.clone(), store.clone());

    // Deliver one "old" message BEFORE Open so it's queued in the mailbox.
    let old_msg = agent_msg("old", "agent:a", "agent:t", MessageKind::Agent);
    dispatcher.deliver("agent:t", old_msg).await.unwrap();

    // Trigger Open — subscriber freezes the mailbox.
    bus.open(open_spec("agent:t", "test")).unwrap();
    let frozen = wait_until(
        || store.get("agent:t").map(|m| m.is_frozen()).unwrap_or(false),
        200,
    )
    .await;
    assert!(frozen, "mailbox frozen");

    // Layer-4: spawn a recv task — it blocks because mailbox is frozen.
    let store_for_recv = store.clone();
    let recv_handle = tokio::spawn(async move {
        let mb = store_for_recv.get("agent:t").expect("mailbox exists");
        mb.recv().await
    });
    // After a bounded number of yields, recv MUST still be pending.
    for _ in 0..50 {
        tokio::task::yield_now().await;
        assert!(
            !recv_handle.is_finished(),
            "recv stays blocked while mailbox frozen"
        );
    }

    // Layer-1: new deliver attempt rejects with CircuitBreakerOpen.
    let new_msg = agent_msg("new", "agent:a", "agent:t", MessageKind::Agent);
    let err = dispatcher.deliver("agent:t", new_msg).await.unwrap_err();
    match err {
        MsgError::CircuitBreakerOpen(scope) => assert_eq!(scope, "agent"),
        other => panic!("expected CircuitBreakerOpen, got {other:?}"),
    }

    recv_handle.abort();
}

// ─────────────────────────────────────────────────────────────────────
// T-D08 — Closed → unfreeze + high-priority-first drain
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d08_closed_unfreezes_and_drains_high_priority_first() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let _sub = BreakerSubscriber::spawn(bus.clone(), store.clone());

    // Create mailbox by delivering an Auto message first; then freeze via Open.
    let mb = store.get_or_create("agent:t").unwrap();
    mb.deliver(agent_msg("auto-1", "agent:a", "agent:t", MessageKind::Auto))
        .unwrap();

    bus.open(open_spec("agent:t", "test")).unwrap();
    wait_until(|| mb.is_frozen(), 200).await;
    assert!(mb.is_frozen());

    // Queue a Control (high-priority) and another Auto under freeze. Slice-A
    // `Mailbox::deliver` is observable-only under freeze (delivers succeed;
    // recv is gated).
    mb.deliver(agent_msg(
        "control-1",
        "agent:a",
        "agent:t",
        MessageKind::Control,
    ))
    .unwrap();
    mb.deliver(agent_msg("auto-2", "agent:a", "agent:t", MessageKind::Auto))
        .unwrap();

    // Close the breaker → subscriber unfreezes the mailbox.
    bus.close(BreakerScope::Agent, "agent:t").unwrap();
    let unfrozen = wait_until(|| !mb.is_frozen(), 200).await;
    assert!(unfrozen, "mailbox unfrozen within yield-bounded window");

    // Recv pops high_priority first (Control) before normal queue (Auto FIFO).
    let m1 = mb.recv().await;
    assert_eq!(m1.id, "control-1", "Control drains first");
    let m2 = mb.recv().await;
    assert_eq!(m2.id, "auto-1", "Auto FIFO: auto-1 before auto-2");
    let m3 = mb.recv().await;
    assert_eq!(m3.id, "auto-2");
}

// ─────────────────────────────────────────────────────────────────────
// T-D09 — HalfOpen → unfreeze (probe-mode dispatcher-alignment)
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d09_half_open_unfreezes_dispatcher_aligned() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:t", "agent:a");

    let dispatcher = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    )
    .with_circuit_breaker_bus(bus.clone());

    let _sub = BreakerSubscriber::spawn(bus.clone(), store.clone());

    // Step 1: Open → mailbox frozen.
    bus.open(open_spec("agent:t", "test")).unwrap();
    wait_until(
        || store.get("agent:t").map(|m| m.is_frozen()).unwrap_or(false),
        200,
    )
    .await;
    assert!(store.get("agent:t").unwrap().is_frozen());

    // Step 2: HalfOpen → subscriber unfreezes (probe-mode dispatcher-alignment).
    bus.half_open(BreakerScope::Agent, "agent:t").unwrap();
    let unfrozen = wait_until(
        || !store.get("agent:t").map(|m| m.is_frozen()).unwrap_or(true),
        200,
    )
    .await;
    assert!(
        unfrozen,
        "HalfOpen unfreezes mailbox to match dispatcher probe-mode acceptance"
    );

    // Step 3: dispatcher.deliver returns Ok (Layer-1 gate doesn't fire on HalfOpen
    // because is_open_agent returns None for HalfOpen).
    let probe_msg = agent_msg("probe-1", "agent:a", "agent:t", MessageKind::Agent);
    dispatcher
        .deliver("agent:t", probe_msg)
        .await
        .expect("HalfOpen accepts new deliveries");

    // Step 4: recv drains the probe (Layer-4 not gated either).
    let received = store.get("agent:t").unwrap().recv().await;
    assert_eq!(received.id, "probe-1");
}

// ─────────────────────────────────────────────────────────────────────
// T-D10 — race-resilient get_or_create on Open for never-used agent
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d10_open_lazily_creates_mailbox_for_never_used_agent() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let _sub = BreakerSubscriber::spawn(bus.clone(), store.clone());

    // No prior deliver/get_or_create for "agent:never-used".
    assert!(store.get("agent:never-used").is_none());

    bus.open(open_spec("agent:never-used", "test")).unwrap();
    let frozen = wait_until(
        || {
            store
                .get("agent:never-used")
                .map(|m| m.is_frozen())
                .unwrap_or(false)
        },
        200,
    )
    .await;
    assert!(
        frozen,
        "subscriber creates a fresh mailbox via get_or_create and freezes it"
    );
    assert!(store.get("agent:never-used").is_some());
}

// ─────────────────────────────────────────────────────────────────────
// T-D11 — cooperative shutdown via handle().abort() + yield_now ordering
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d11_handle_abort_stops_subscriber() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let sub = BreakerSubscriber::spawn(bus.clone(), store.clone());

    sub.handle().abort();
    // Yield-bounded wait for the abort to propagate.
    for _ in 0..50 {
        if sub.handle().is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(sub.handle().is_finished(), "subscriber task aborted");

    // Subsequent Open does NOT freeze anything because the subscriber is gone.
    bus.open(open_spec("agent:t", "test")).unwrap();
    // Yield a few times to confirm no event-processing happens.
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(
        store.get("agent:t").is_none(),
        "no lazy mailbox creation by the now-dead subscriber"
    );
}

// ─────────────────────────────────────────────────────────────────────
// T-D11b — drop-without-explicit-abort safety via impl Drop
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_d11b_drop_aborts_subscriber_without_explicit_call() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());

    {
        // No `.abort()` call — rely on Drop impl when the scope exits.
        let _sub = BreakerSubscriber::spawn(bus.clone(), store.clone());
    } // Drop fires here, aborting the spawned task.

    // Yield to let the abort propagate.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    bus.open(open_spec("agent:t", "test")).unwrap();
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(
        store.get("agent:t").is_none(),
        "Drop impl auto-aborts; subsequent Open is not processed"
    );
}
