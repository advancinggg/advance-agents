//! Slice m001-slice-bootstrap (2026-05-28) — MODULE-001-AC-08 closure witness.
//!
//! AC-08 §1.5 criterion: "Circuit-breaker blocks new dispatch in all 3 scopes;
//! admin control messages bypass; mailbox old messages are frozen during open
//! state and drained on close."
//!
//! - Clauses 1+2 (block dispatch in 3 scopes + admin bypass): already closed
//!   by Slice E's 19 CircuitBreakerBus tests at the bus-level (M001 §3.5
//!   "CircuitBreakerBus | Slice E" row). This test re-confirms clause 2
//!   admin bypass at the production dispatcher integration layer.
//! - Clause 3 (freeze on open + drain on close): closed THIS slice via the
//!   `BreakerSubscriber` (m006-slice-d) routing `BreakerEvent` records to
//!   per-agent `Mailbox::freeze`/`unfreeze`. Equivalent coverage exists in
//!   `crates/messaging/tests/breaker_subscriber_e2e.rs` (T-D06..T-D11); this
//!   cli-level test is the M001-side witness that the production wiring
//!   path (runtime CB bus + messaging dispatcher + subscriber) composes
//!   end-to-end.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use advance_messaging::{
    BreakerSubscriber, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore,
};
use advance_runtime::circuit_breaker::{
    BreakerScope, BreakerState, CircuitBreaker, CircuitBreakerBus, DefaultCircuitBreakerBus,
};
use advance_shared_types::agent_tree::{AgentKind, AgentTreeReader, Capability};
use advance_shared_types::mailbox::{Message, MessageKind, MsgError};

const DEFAULT_CAP: NonZeroUsize = match NonZeroUsize::new(64) {
    Some(n) => n,
    None => unreachable!(),
};

/// Minimal AgentTreeReader stub returning a flat root + child topology so
/// `validate_routing` accepts parent↔child agent deliveries.
struct FlatTree;

impl AgentTreeReader for FlatTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        if agent_id == "agent:child" {
            Some("agent:root".into())
        } else {
            None
        }
    }
    fn children_of(&self, agent_id: &str) -> Vec<String> {
        if agent_id == "agent:root" {
            vec!["agent:child".into()]
        } else {
            vec![]
        }
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        vec![]
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        matches!(agent_id, "agent:root" | "agent:child")
    }
    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        match agent_id {
            "agent:root" => Some(AgentKind::Root),
            "agent:child" => Some(AgentKind::Child),
            _ => None,
        }
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        vec![]
    }
}

fn make_msg(id: &str, from: &str, to: &str, kind: MessageKind) -> Message {
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

fn open_agent_breaker(target: &str, reason: &str) -> CircuitBreaker {
    CircuitBreaker {
        scope: BreakerScope::Agent,
        target: target.into(),
        state: BreakerState::Open,
        kill_existing: false,
        reason: reason.into(),
    }
}

/// MODULE-001-T56-cb-freeze-drain — AC-08 closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_t56_cb_freeze_drain() {
    // 1. Wire production components: runtime CB bus + messaging store/dispatcher
    //    + BreakerSubscriber driver.
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let store = Arc::new(MailboxStore::new(DEFAULT_CAP));
    let tree: Arc<dyn AgentTreeReader> = Arc::new(FlatTree);
    let dispatcher =
        MailboxDispatcherImpl::new(store.clone(), tree).with_circuit_breaker_bus(bus.clone());
    let _subscriber = BreakerSubscriber::spawn(bus.clone(), store.clone());

    // Ensure target mailbox exists so freeze/unfreeze can act on it.
    let _mb = store
        .get_or_create("agent:child")
        .expect("mailbox create should succeed");

    // 2. Pre-load a baseline message BEFORE opening the breaker (proves drain
    //    later — clause 3b).
    let baseline = make_msg("m-1", "agent:root", "agent:child", MessageKind::Agent);
    dispatcher
        .deliver("agent:child", baseline.clone())
        .await
        .expect("baseline delivery should succeed");

    // 3. Open the agent-scope breaker. BreakerSubscriber will freeze the
    //    "agent:child" mailbox.
    bus.open(open_agent_breaker("agent:child", "test-open"))
        .expect("bus.open should succeed");

    // Poll until BreakerSubscriber consumes the BreakerEvent and freezes the
    // mailbox (W6 R1 fix — fixed sleeps are CI-flaky; poll the observable
    // freeze state instead with a 2s cap).
    let mb_check = store.get_or_create("agent:child").expect("mailbox lookup");
    let mut frozen_observed = false;
    for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        if mb_check.is_frozen() {
            frozen_observed = true;
            break;
        }
    }
    assert!(
        frozen_observed,
        "BreakerSubscriber should freeze the mailbox within 2s of bus.open"
    );

    // 4. Clause 1 (dispatcher agent-scope gate): a non-Control delivery to
    //    the open-breaker agent returns CircuitBreakerOpen.
    let blocked = make_msg("m-2", "agent:root", "agent:child", MessageKind::Agent);
    let result = dispatcher.deliver("agent:child", blocked).await;
    assert!(
        matches!(result, Err(MsgError::CircuitBreakerOpen(_))),
        "Agent delivery to open-breaker agent should be blocked at dispatcher gate, got {:?}",
        result
    );

    // 5. Clause 2 (admin bypass): MessageKind::Control delivery to the same
    //    target SUCCEEDS — admin control messages bypass the breaker. We
    //    use the agent:root → agent:child path so hierarchy validation
    //    (which runs BEFORE the CB check) admits the routing; the breaker
    //    bypass is the assertion under test.
    let admin = make_msg("m-3", "agent:root", "agent:child", MessageKind::Control);
    dispatcher
        .deliver("agent:child", admin)
        .await
        .expect("admin Control delivery should bypass the open breaker");

    // 6. Clause 3a (freeze on open): the pre-existing baseline message is
    //    NOT pollable while the breaker is open (mailbox frozen).
    let mb = store
        .get_or_create("agent:child")
        .expect("mailbox lookup should succeed");
    assert!(
        mb.poll().is_none(),
        "baseline message should be invisible (frozen) while breaker is open"
    );

    // 7. Close the breaker. BreakerSubscriber will unfreeze the mailbox.
    bus.close(BreakerScope::Agent, "agent:child")
        .expect("bus.close should succeed");

    // Poll until BreakerSubscriber observes the close + unfreezes
    // (W6 R1 fix — polling-based wait instead of fixed sleep).
    let mut unfrozen_observed = false;
    for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        if !mb_check.is_frozen() {
            unfrozen_observed = true;
            break;
        }
    }
    assert!(
        unfrozen_observed,
        "BreakerSubscriber should unfreeze the mailbox within 2s of bus.close"
    );

    // 8. Clause 3b (drain on close): the baseline message + the admin
    //    bypass message are now drainable.
    let mut drained: Vec<Message> = Vec::new();
    while let Some(m) = mb.poll() {
        drained.push(m);
    }
    assert!(
        !drained.is_empty(),
        "mailbox should drain at least one frozen message after close"
    );
    // Specifically, the baseline (m-1) and admin (m-3) should both be in
    // the drained set; m-2 was rejected at the dispatcher gate and never
    // entered the mailbox.
    let ids: Vec<&str> = drained.iter().map(|m| m.id.as_str()).collect();
    assert!(
        ids.contains(&"m-1"),
        "baseline message m-1 should drain after close; ids: {ids:?}"
    );
    assert!(
        ids.contains(&"m-3"),
        "admin bypass message m-3 should drain after close; ids: {ids:?}"
    );
    assert!(
        !ids.contains(&"m-2"),
        "blocked message m-2 should NOT be in the mailbox (rejected at dispatcher gate)"
    );
}
