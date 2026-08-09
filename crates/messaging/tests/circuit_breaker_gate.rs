//! Slice-C AC-13 infrastructure evidence — T-C01..T-C12 + T-C04b + T-C05b
//! (14 cases; T-C04b and T-C05b were added in audit-fix round 1 to cover
//! the closed-path for `notify_agent` / `notify_channel` so each of the four
//! dispatcher entry points has both an open-rejection and a closed-passes
//! test under a wired CB bus).
//!
//! Verifies the Layer-1 dispatcher circuit-breaker query on all four
//! target-reaching dispatcher paths (deliver / reply / notify_agent /
//! notify_channel), Layer-1 `MessageKind::Control` admin-bypass, and the
//! Layer-4 mailbox recv/poll freeze gate with FIFO drain on unfreeze.
//!
//! AC-13 itself stays `untested` in MODULE-006 §3.4 — this slice ships the
//! Layer-1 + Layer-4 mechanisms as infrastructure (mirrors slice-B's
//! AC-02/AC-08 infra-ship-but-stay-untested posture); the production
//! BreakerEvent subscriber driver is the next slice's work. See MODULE-006
//! §3.6 deferred-driver row + §3.8 (f) Two-layer CB gate infra.

mod common;

use std::num::NonZeroUsize;
use std::sync::Arc;

use advance_messaging::{
    EmptyChannelAdapterRegistry, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore,
    MessageTrace, MsgError, NotifyError, DEFAULT_CAPACITY,
};
use advance_shared_types::mailbox::{Message, MessageContext, MessageKind, MessageOrigin};

use crate::common::{
    make_mock_cb_bus, make_origin, static_registry, wait_for_recv_completion, TestTree,
};

// ─────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────

fn dispatcher_without_bus(tree: TestTree) -> (Arc<MailboxStore>, MailboxDispatcherImpl) {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        Arc::new(EmptyChannelAdapterRegistry),
    );
    (store, d)
}

fn dispatcher_with_open_bus(
    tree: TestTree,
    opened: &[(&str, &str)],
) -> (Arc<MailboxStore>, MailboxDispatcherImpl) {
    let (store, d) = dispatcher_without_bus(tree);
    let d = d.with_circuit_breaker_bus(make_mock_cb_bus(opened));
    (store, d)
}

fn dispatcher_with_channel_registry(
    tree: TestTree,
    opened: &[(&str, &str)],
    channels: &[(&str, &str)],
) -> (Arc<MailboxStore>, MailboxDispatcherImpl) {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let registry: Arc<dyn advance_messaging::ChannelAdapterRegistry> =
        Arc::new(static_registry(channels));
    let d = MailboxDispatcherImpl::new_full(
        store.clone(),
        Arc::new(tree),
        Arc::new(MessageTrace::new()),
        registry,
    )
    .with_circuit_breaker_bus(make_mock_cb_bus(opened));
    (store, d)
}

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

fn auto_msg(id: &str, from: &str, to: &str) -> Message {
    agent_msg(id, from, to, MessageKind::Auto)
}

// ─────────────────────────────────────────────────────────────────────
// Layer-1 dispatcher CB query — `deliver` path (T-C01..T-C03, T-C06)
// ─────────────────────────────────────────────────────────────────────

// T-C01 — dispatcher.deliver rejects with CircuitBreakerOpen("agent") when
// CB open for target. PII discipline (Adversarial R1 Critical fix): the
// operator-supplied breaker reason MUST NOT leak to the guest-visible
// MsgError — the dispatcher returns the slice-A §1.3.2 invariant identifier
// `"agent"` (the scope name) instead. The operator-side observability stack
// is the correct surface for the actual reason. T-C01's open-bus reason
// `"test_reason_x_with_pii"` (deliberately distinguishable from "agent") is
// constructed but NEVER returned to the caller.
#[tokio::test]
async fn t_c01_deliver_rejects_with_invariant_scope_identifier_pii_discipline() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let (_store, d) = dispatcher_with_open_bus(tree, &[("agent:b", "test_reason_x_with_pii")]);
    let msg = auto_msg("m1", "agent:a", "agent:b");
    let err = d.deliver("agent:b", msg).await.unwrap_err();
    match err {
        MsgError::CircuitBreakerOpen(reason) => {
            assert_eq!(
                reason, "agent",
                "PII discipline: breaker reason must be scope invariant, not bus's verbatim string"
            );
            assert_ne!(
                reason, "test_reason_x_with_pii",
                "PII discipline: bus's operator-supplied reason MUST NOT leak to caller"
            );
        }
        other => panic!("expected CircuitBreakerOpen, got {other:?}"),
    }
}

// T-C02 — dispatcher.deliver succeeds when CB reports the target closed.
#[tokio::test]
async fn t_c02_deliver_succeeds_when_bus_closed() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let (store, d) = dispatcher_with_open_bus(tree, &[("agent:other", "unused")]);
    let msg = auto_msg("m2", "agent:a", "agent:b");
    d.deliver("agent:b", msg).await.unwrap();
    let received = store.get("agent:b").expect("mailbox").recv().await;
    assert_eq!(received.id, "m2");
}

// T-C03 — dispatcher.deliver succeeds with cb_bus = None (backward-compat
// assertion against slice-A/B fixtures that don't wire CB).
#[tokio::test]
async fn t_c03_deliver_backward_compat_no_bus_wired() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let (store, d) = dispatcher_without_bus(tree);
    let msg = auto_msg("m3", "agent:a", "agent:b");
    d.deliver("agent:b", msg).await.unwrap();
    assert_eq!(store.get("agent:b").expect("mailbox").recv().await.id, "m3");
}

// T-C06 — admin bypass: MessageKind::Control passes through even when the
// target's breaker is open. Cancel-run / pause-run scenario per
// MODULE-001 §1.4.4 lines 644-650 admin-bypass clause.
#[tokio::test]
async fn t_c06_deliver_control_kind_bypasses_open_breaker() {
    let tree = TestTree::new()
        .add_root("agent:a")
        .add_child("agent:b", "agent:a");
    let (store, d) = dispatcher_with_open_bus(tree, &[("agent:b", "irrelevant")]);
    let msg = agent_msg("m6", "agent:a", "agent:b", MessageKind::Control);
    d.deliver("agent:b", msg)
        .await
        .expect("Control bypasses breaker");
    let received = store.get("agent:b").expect("mailbox").recv().await;
    assert_eq!(received.id, "m6");
    assert!(matches!(received.kind, MessageKind::Control));
}

// ─────────────────────────────────────────────────────────────────────
// Layer-1 dispatcher CB query — notify paths (T-C04, T-C05)
// ─────────────────────────────────────────────────────────────────────

// T-C04 — dispatcher.notify_agent maps breaker-open to
// NotifyError::CapabilityDenied("breaker_open"). Direct construction in
// deliver_notify, NOT via map_msg_to_notify — PII discipline: the
// breaker reason is NOT exposed across the notify mapping boundary
// per MODULE-006 §3.8 (c).
#[tokio::test]
async fn t_c04_notify_agent_rejects_with_capability_denied_breaker_open() {
    let tree = TestTree::new().add_root("agent:research");
    let (_store, d) = dispatcher_with_open_bus(tree, &[("agent:research", "sensitive-reason")]);
    let err = d
        .notify_agent("system", "agent:research", vec![1], None)
        .await
        .unwrap_err();
    match err {
        NotifyError::CapabilityDenied(s) => assert_eq!(s, "breaker_open"),
        other => panic!("expected CapabilityDenied(breaker_open), got {other:?}"),
    }
}

// T-C04b — closed-path complement to T-C04: dispatcher.notify_agent with a
// wired CB bus succeeds when the target's breaker is closed. Locks the
// regression that a wired bus does not silently break the notify path —
// pairs with T-C02 (deliver-closed) and T-C08 (reply-closed) so all four
// dispatcher entry points have BOTH open and closed paths covered.
#[tokio::test]
async fn t_c04b_notify_agent_succeeds_when_bus_closed() {
    let tree = TestTree::new().add_root("agent:research");
    let (store, d) = dispatcher_with_open_bus(tree, &[("agent:other", "unused")]);
    d.notify_agent("system", "agent:research", vec![9], None)
        .await
        .unwrap();
    let received = store.get("agent:research").expect("mailbox").recv().await;
    assert_eq!(received.payload, vec![9]);
    assert_eq!(received.from, "system");
}

// T-C05 — dispatcher.notify_channel: when the resolved adapter agent is
// CB-open, rejects with NotifyError::CapabilityDenied("breaker_open"). The
// gate fires on the ADAPTER agent (the actual mailbox target), not the
// `user_id` (which is the envelope recipient).
#[tokio::test]
async fn t_c05_notify_channel_rejects_when_adapter_breaker_open() {
    let tree = TestTree::new().add_root("agent:adapter-tg");
    let (_store, d) = dispatcher_with_channel_registry(
        tree,
        &[("agent:adapter-tg", "sensitive-reason")],
        &[("telegram", "agent:adapter-tg")],
    );
    let err = d
        .notify_channel("system", "telegram", "user:alice", vec![1, 2, 3], None)
        .await
        .unwrap_err();
    match err {
        NotifyError::CapabilityDenied(s) => assert_eq!(s, "breaker_open"),
        other => panic!("expected CapabilityDenied(breaker_open), got {other:?}"),
    }
}

// T-C05b — closed-path complement to T-C05: notify_channel with a wired CB
// bus succeeds when the adapter's breaker is closed. Locks the regression
// that wiring the bus does not silently break the channel-notify path.
#[tokio::test]
async fn t_c05b_notify_channel_succeeds_when_adapter_closed() {
    let tree = TestTree::new().add_root("agent:adapter-tg");
    let (store, d) = dispatcher_with_channel_registry(
        tree,
        &[("agent:other", "unused")],
        &[("telegram", "agent:adapter-tg")],
    );
    d.notify_channel("system", "telegram", "user:alice", vec![7], None)
        .await
        .unwrap();
    let received = store.get("agent:adapter-tg").expect("mailbox").recv().await;
    assert_eq!(received.from, "system");
    // payload is the serialized ChannelDelivery envelope, not the raw body.
    assert!(!received.payload.is_empty());
}

// ─────────────────────────────────────────────────────────────────────
// Layer-1 dispatcher CB query — reply path (T-C07, T-C08)
// ─────────────────────────────────────────────────────────────────────

// T-C07 — dispatcher.reply rejects with MsgError::CircuitBreakerOpen("agent")
// when the reply target adapter is CB-open. Reply hard-codes
// MessageKind::Agent — no admin-bypass branch applies; the gate fires
// unconditionally on open. PII discipline applies same as T-C01 — the
// operator-supplied reason MUST NOT leak.
#[tokio::test]
async fn t_c07_reply_rejects_with_invariant_scope_identifier_pii_discipline() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (_store, d) =
        dispatcher_with_open_bus(tree, &[("agent:adapter-tg", "adapter-blocked-pii")]);
    d.trace()
        .record(
            "m7",
            make_origin("m7", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    let err = d.reply("agent:bob", "m7", vec![1, 2, 3]).await.unwrap_err();
    match err {
        MsgError::CircuitBreakerOpen(reason) => {
            assert_eq!(reason, "agent", "PII discipline: scope invariant only");
            assert_ne!(
                reason, "adapter-blocked-pii",
                "PII discipline: bus reason MUST NOT leak via reply"
            );
        }
        other => panic!("expected CircuitBreakerOpen, got {other:?}"),
    }
}

// T-C08 — dispatcher.reply succeeds when bus reports the adapter closed.
#[tokio::test]
async fn t_c08_reply_succeeds_when_bus_closed() {
    let tree = TestTree::new()
        .add_root("agent:adapter-tg")
        .add_root("agent:bob");
    let (store, d) = dispatcher_with_open_bus(tree, &[("agent:other", "unused")]);
    d.trace()
        .record(
            "m8",
            make_origin("m8", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    d.reply("agent:bob", "m8", vec![1, 2, 3]).await.unwrap();
    let received = store.get("agent:adapter-tg").expect("mailbox").recv().await;
    assert_eq!(received.from, "agent:bob");
    assert!(matches!(received.kind, MessageKind::Agent));
}

// ─────────────────────────────────────────────────────────────────────
// Layer-4 mailbox recv/poll freeze gate (T-C09..T-C12)
// ─────────────────────────────────────────────────────────────────────

// T-C09 — mailbox.recv blocks while frozen, then drains on unfreeze. Uses
// the slice-D `wait_for_recv_completion` poll pattern: under
// start_paused=true the spawned recv task can only progress on
// `yield_now`, so the 200-iter cap is deterministic (the recv path is
// timer-free; only the future Mailbox idle monitor sleeps, which doesn't
// exist this slice).
#[tokio::test(start_paused = true)]
async fn t_c09_recv_holds_while_frozen_then_drains() {
    use advance_messaging::Mailbox;
    let mb = Arc::new(Mailbox::new(NonZeroUsize::new(4).unwrap()));
    let m1 = auto_msg("m1", "agent:a", "agent:b");
    mb.deliver(m1).unwrap();
    mb.freeze();
    let mb_clone = mb.clone();
    let mut handle: tokio::task::JoinHandle<advance_shared_types::mailbox::Message> =
        tokio::spawn(async move { mb_clone.recv().await });
    // Frozen → recv should NOT complete within the bounded poll.
    let still_pending = wait_for_recv_completion(&mut handle, 200).await;
    assert!(
        still_pending.is_none(),
        "recv must remain blocked while mailbox is frozen"
    );
    // Unfreeze → recv should produce the message within the bound.
    mb.unfreeze();
    let received = wait_for_recv_completion(&mut handle, 100)
        .await
        .expect("recv must complete within 100 yields after unfreeze");
    assert_eq!(received.id, "m1");
}

// T-C10 — mailbox.poll returns None while frozen even with a non-empty
// queue. Layer-4 freeze blocks all kinds (admin-bypass is intentionally
// NOT applied to recv/poll — see MODULE-006 §3.8 (f) (ii)/(vii)). After
// unfreeze, poll returns the msg in priority order.
#[tokio::test]
async fn t_c10_poll_returns_none_while_frozen() {
    use advance_messaging::Mailbox;
    let mb = Mailbox::new(NonZeroUsize::new(4).unwrap());
    mb.deliver(auto_msg("p1", "agent:a", "agent:b")).unwrap();
    mb.deliver(agent_msg("c1", "agent:a", "agent:b", MessageKind::Control))
        .unwrap();
    mb.freeze();
    assert!(mb.poll().is_none(), "frozen poll returns None for any kind");
    mb.unfreeze();
    // High-priority Control should pop first per slice-A semantics.
    let first = mb.poll().expect("unfrozen poll returns msg");
    assert_eq!(first.id, "c1");
    assert!(matches!(first.kind, MessageKind::Control));
    let second = mb.poll().expect("second poll returns the Auto msg");
    assert_eq!(second.id, "p1");
}

// T-C11 — Mailbox::deliver still succeeds while frozen. Slice-A
// regression-lock invariant — Layer-1 (rejecting NEW deliveries) is the
// dispatcher's job, not the mailbox's. This test duplicates the existing
// slice-A `t_a03c_freeze_toggle_observable` assertion from the slice-C
// side as a forward-compat guard.
#[tokio::test]
async fn t_c11_deliver_succeeds_while_frozen_regression_lock() {
    use advance_messaging::Mailbox;
    let mb = Mailbox::new(NonZeroUsize::new(4).unwrap());
    mb.freeze();
    mb.deliver(auto_msg("rl", "agent:a", "agent:b"))
        .expect("slice-A invariant: Mailbox::deliver does NOT consult frozen flag");
}

// T-C12 — end-to-end close-drain FIFO with high-priority-first ordering.
// Freeze; deliver Auto m1, Control c1, Auto m2; recv loop blocks; unfreeze;
// drain produces [c1, m1, m2] — Control drains ahead of normal-queue Auto
// per slice-A `recv` semantics (high_priority pops first on each
// iteration). Note: T-C12's Auto+Control input does NOT verify
// "Control ahead of OLDER User in high_priority" — User+Control share
// the high_priority VecDeque FIFO per slice-A, so older User would drain
// first; see MODULE-006 §3.8 (f) (vii) for the precise bound.
#[tokio::test(start_paused = true)]
async fn t_c12_close_drain_fifo_with_high_priority_first() {
    use advance_messaging::Mailbox;
    let mb = Arc::new(Mailbox::new(NonZeroUsize::new(8).unwrap()));
    let m1 = auto_msg("m1", "agent:a", "agent:b");
    let c1 = agent_msg("c1", "agent:a", "agent:b", MessageKind::Control);
    let m2 = auto_msg("m2", "agent:a", "agent:b");
    mb.freeze();
    mb.deliver(m1).unwrap();
    mb.deliver(c1).unwrap();
    mb.deliver(m2).unwrap();
    let mb_clone = mb.clone();
    let mut handle: tokio::task::JoinHandle<Vec<String>> = tokio::spawn(async move {
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(mb_clone.recv().await.id);
        }
        got
    });
    // Frozen → recv blocks.
    let still_pending = wait_for_recv_completion(&mut handle, 200).await;
    assert!(
        still_pending.is_none(),
        "recv loop must remain blocked while mailbox is frozen"
    );
    // Unfreeze → recv loop drains all 3 in [c1, m1, m2] order:
    //   c1 first (high_priority pops before normal queue),
    //   then m1, m2 in FIFO order from the normal queue.
    mb.unfreeze();
    let drained = wait_for_recv_completion(&mut handle, 200)
        .await
        .expect("recv loop must complete within 200 yields after unfreeze");
    assert_eq!(
        drained,
        vec!["c1".to_string(), "m1".to_string(), "m2".to_string()],
        "close-drain order: Control (high_priority) first, then Auto FIFO"
    );
}

// Silence "unused import" warnings for items that future tests may consume.
#[allow(dead_code)]
fn _unused_imports_silencer(_: MessageContext, _: MessageOrigin, _: NotifyError) {}
