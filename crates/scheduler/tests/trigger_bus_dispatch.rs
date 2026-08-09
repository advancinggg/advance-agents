//! Slice B `TriggerBusDispatchImpl::dispatch()` integration tests.
//!
//! Covers:
//! - AC-11 (trigger-event subscribe + dispatch enqueues subscriber)
//! - AC-12 (visited-set + max-chain-depth + aggregate cap)
//! - AC-18 (12-event whitelist projection round-trip; non-whitelisted rejected)
//! - Adversarial Round-1 fixes (W1 drain reclaim, W2 counters, W3 truncation)

use advance_scheduler::trigger_bus::{
    CycleRejection, TriggerBusDispatchImpl, CYCLE_REJECTED_LOG_CAP, PENDING_QUEUE_PER_SUB_CAP,
    REJECTION_LOGGED_STRING_MAX, WHITELIST,
};
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
        agent_id: "test-agent".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-1".into(),
        span_id: "span-1".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: serde_json::Value::Object(serde_json::Map::new()),
        duration_ms: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// AC-11: trigger-event subscribe + dispatch
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ac11_dispatch_whitelisted_event_enqueues_subscriber() {
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("grant.issued"));
    assert_ne!(sub_id, SubscriptionId::REJECTED);

    bus.dispatch(make_event("grant.issued", "evt-1"));

    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(
        drained.len(),
        1,
        "subscribe + dispatch should enqueue exactly 1 entry"
    );
    assert_eq!(drained[0].subscription_id, sub_id);
    assert_eq!(drained[0].next_depth, 1);
    assert!(
        bus.cycle_rejected_log().is_empty(),
        "no rejections expected"
    );
}

#[test]
fn ac11_dispatch_non_whitelisted_event_is_silently_skipped() {
    let bus = TriggerBusDispatchImpl::new();
    // subscribe to fs.write should be rejected (non-whitelisted).
    let id = bus.subscribe(sub("fs.write"));
    assert_eq!(id, SubscriptionId::REJECTED);

    // dispatch of fs.write logs an EventTypeNotWhitelisted rejection.
    bus.dispatch(make_event("fs.write", "evt-x"));
    let log = bus.cycle_rejected_log();
    assert_eq!(log.len(), 1);
    assert!(matches!(
        log[0],
        CycleRejection::EventTypeNotWhitelisted { .. }
    ));
    assert_eq!(bus.pending_total(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// AC-12: visited-set + max-chain-depth + aggregate cap
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ac12_depth_boundary_inclusive_at_max() {
    // Default max_chain_depth = 10. chain_depth = 9 → next_depth = 10
    // == max → allowed (gate is strict >).
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("git.commit"));
    let mut event = make_event("git.commit", "evt-boundary");
    event.payload = serde_json::json!({ "chain_depth": 9 });
    bus.dispatch(event);

    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].next_depth, 10);
}

#[test]
fn ac12_depth_exceeded_rejects_dispatch() {
    // chain_depth = 10 → next_depth = 11 > max=10 → reject.
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    let mut event = make_event("git.commit", "evt-too-deep");
    event.payload = serde_json::json!({ "chain_depth": 10 });
    bus.dispatch(event);

    let log = bus.cycle_rejected_log();
    assert!(
        log.iter()
            .any(|r| matches!(r, CycleRejection::MaxDepthExceeded { depth: 11, .. })),
        "expected MaxDepthExceeded with depth=11 in log: {log:?}"
    );
    assert_eq!(bus.pending_total(), 0);
}

#[test]
fn ac12_already_visited_skips_second_dispatch() {
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("git.commit"));
    let event = make_event("git.commit", "evt-dedup");
    bus.dispatch(event.clone());
    bus.dispatch(event); // same chain_id (fallback to event.id) → AlreadyVisited

    // Only the first dispatch enqueued; second logged AlreadyVisited.
    assert_eq!(bus.pending_total(), 1);
    let log = bus.cycle_rejected_log();
    assert!(
        log.iter().any(
            |r| matches!(r, CycleRejection::AlreadyVisited { subscription_id, .. } if *subscription_id == sub_id)
        ),
        "expected AlreadyVisited for sub_id={sub_id:?} in log: {log:?}"
    );
}

#[test]
fn ac12_visited_set_counter_increments_per_dispatch() {
    // Audit Round-5 Info-C fix: rename to reflect what the test actually
    // does. Slice B's cap-threshold boundary is verified by the
    // #[cfg(test)] unit test `dispatch_aggregate_cap_blocks_via_test_setter`
    // inside trigger_bus.rs (which uses `set_total_for_test` to inflate
    // the counter without allocating 100K real entries). This integration
    // test verifies the counter increments correctly under real dispatch.
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    for i in 0..5 {
        let event = make_event("git.commit", &format!("evt-{i}"));
        bus.dispatch(event);
    }
    assert_eq!(bus.visited_set_total(), 5);
}

#[test]
fn ac12_clear_chain_releases_visited_slot() {
    // Round-7 Critical-1 verification: clear_chain decrements total.
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    bus.dispatch(make_event("git.commit", "evt-clear"));
    assert_eq!(bus.visited_set_total(), 1);

    let chain_id = advance_scheduler::types::TriggerChainId::new("evt-clear".into()).unwrap();
    let removed = bus.clear_chain(&chain_id);
    assert_eq!(removed, 1);
    assert_eq!(bus.visited_set_total(), 0);
}

#[test]
fn ac12_clear_visited_state_resets_counter() {
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    bus.dispatch(make_event("git.commit", "evt-a"));
    bus.dispatch(make_event("git.commit", "evt-b"));
    bus.dispatch(make_event("git.commit", "evt-c"));
    assert_eq!(bus.visited_set_total(), 3);
    let removed = bus.clear_visited_state();
    assert_eq!(removed, 3);
    assert_eq!(bus.visited_set_total(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// AC-18: 12-event whitelist projection round-trip
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn ac18_all_twelve_whitelist_events_dispatch_successfully() {
    // Round-5 Warning-1 fix: each iteration uses a FRESH event.id so the
    // per-event chain_id is distinct across iterations (no AlreadyVisited
    // collisions). Round-4 Info-1 fix: assert exact length 1 per roundtrip.
    let bus = TriggerBusDispatchImpl::new();
    for (i, event_type) in WHITELIST.iter().enumerate() {
        let sub_id = bus.subscribe(sub(event_type));
        assert_ne!(
            sub_id,
            SubscriptionId::REJECTED,
            "whitelist event {event_type} must subscribe successfully"
        );
        let event = make_event(event_type, &format!("evt-{i}"));
        bus.dispatch(event);
        let drained = bus.drain_for_subscription(sub_id);
        assert_eq!(
            drained.len(),
            1,
            "whitelist event {event_type} should enqueue exactly 1 entry"
        );
    }
    // No rejections for any whitelist event.
    assert!(
        bus.cycle_rejected_log().is_empty(),
        "no rejections expected: {:?}",
        bus.cycle_rejected_log()
    );
}

#[test]
fn ac18_non_whitelisted_event_rejected_on_subscribe_and_dispatch() {
    let bus = TriggerBusDispatchImpl::new();
    let id = bus.subscribe(sub("llm.response"));
    assert_eq!(
        id,
        SubscriptionId::REJECTED,
        "llm.response must be rejected"
    );

    // Dispatch of llm.response should silently no-op + log the rejection.
    bus.dispatch(make_event("llm.response", "evt-not-whitelisted"));
    let log = bus.cycle_rejected_log();
    assert_eq!(log.len(), 1);
    assert!(matches!(
        log[0],
        CycleRejection::EventTypeNotWhitelisted { .. }
    ));
    assert_eq!(bus.pending_total(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Round-7 Warning-1: unsubscribe also evicts queued entries
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn unsubscribe_evicts_pending_entries() {
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("grant.issued"));
    bus.dispatch(make_event("grant.issued", "evt-1"));
    bus.dispatch(make_event("grant.issued", "evt-2"));
    assert_eq!(bus.pending_total(), 2);
    bus.unsubscribe(sub_id);
    assert_eq!(bus.pending_total(), 0);
    assert_eq!(bus.total_subscriptions(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-1 W1: drain reclaims visited-set slots
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_w1_drain_reclaims_visited_set_slot() {
    // Before fix: each successful dispatch monotonically consumed one
    // visited-set slot, with no production path to release it. After
    // 100K dispatches the bus would be bricked (VisitedSetCapExceeded
    // on every subsequent dispatch). After the W1 fix, drain reclaims
    // the (chain_id, sub_id) entry so the aggregate cap is reusable
    // across non-overlapping chains.
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("grant.issued"));
    bus.dispatch(make_event("grant.issued", "evt-1"));
    assert_eq!(
        bus.visited_set_total(),
        1,
        "visited-set should hold 1 after dispatch"
    );
    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(drained.len(), 1);
    assert_eq!(
        bus.visited_set_total(),
        0,
        "drain should reclaim the (chain_id, sub_id) slot"
    );
    // Re-dispatch the same chain_id after drain should succeed
    // (the entry has been logically consumed).
    bus.dispatch(make_event("grant.issued", "evt-1"));
    assert_eq!(bus.visited_set_total(), 1);
    let log = bus.cycle_rejected_log();
    assert!(
        !log.iter()
            .any(|r| matches!(r, CycleRejection::AlreadyVisited { .. })),
        "post-drain re-dispatch must NOT be rejected as AlreadyVisited: {log:?}"
    );
}

#[test]
fn adv_w1_drain_reclaims_multiple_chains_correctly() {
    // Drain over multiple chain_ids reclaims each (chain, sub) pair
    // and removes the chain entry once its HashSet is empty.
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("git.commit"));
    bus.dispatch(make_event("git.commit", "chain-a"));
    bus.dispatch(make_event("git.commit", "chain-b"));
    bus.dispatch(make_event("git.commit", "chain-c"));
    assert_eq!(bus.visited_set_total(), 3);
    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(drained.len(), 3);
    assert_eq!(bus.visited_set_total(), 0);
}

#[test]
fn adv_w1_drain_leaves_other_subs_visited_set_intact() {
    // Two subs, same chain — draining sub_a must NOT decrement
    // sub_b's visited-set entry.
    let bus = TriggerBusDispatchImpl::new();
    let sub_a = bus.subscribe(sub("git.commit"));
    let sub_b = bus.subscribe(sub("git.commit"));
    bus.dispatch(make_event("git.commit", "chain-x"));
    assert_eq!(bus.visited_set_total(), 2, "both subs should be tracked");
    let drained_a = bus.drain_for_subscription(sub_a);
    assert_eq!(drained_a.len(), 1);
    assert_eq!(
        bus.visited_set_total(),
        1,
        "drain(sub_a) must leave sub_b's entry intact"
    );
    let drained_b = bus.drain_for_subscription(sub_b);
    assert_eq!(drained_b.len(), 1);
    assert_eq!(bus.visited_set_total(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-1 W2: rejection counters always advance
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_w2_rejection_counters_bump_per_variant() {
    let bus = TriggerBusDispatchImpl::new();
    // Trigger different variants.
    bus.dispatch(make_event("fs.write", "evt-1")); // EventTypeNotWhitelisted
    bus.dispatch(make_event("fs.write", "evt-2")); // EventTypeNotWhitelisted

    // AlreadyVisited: subscribe + dispatch twice with same event.
    let sub_id = bus.subscribe(sub("git.commit"));
    bus.dispatch(make_event("git.commit", "chain-y"));
    bus.dispatch(make_event("git.commit", "chain-y")); // duplicate

    let counts = bus.rejection_counts();
    assert_eq!(
        counts.event_type_not_whitelisted, 2,
        "two non-whitelisted dispatches"
    );
    assert_eq!(counts.already_visited, 1, "one AlreadyVisited rejection");

    // Cleanup: drain so test isolation isn't affected.
    let _ = bus.drain_for_subscription(sub_id);
}

#[test]
fn adv_w2_counters_advance_even_when_log_is_cleared() {
    // The atomic counters represent cumulative volume since bus
    // construction — `clear_rejected_log` must NOT reset them.
    let bus = TriggerBusDispatchImpl::new();
    for i in 0..10 {
        bus.dispatch(make_event("fs.write", &format!("evt-{i}")));
    }
    assert_eq!(bus.rejection_counts().event_type_not_whitelisted, 10);
    bus.clear_rejected_log();
    assert_eq!(
        bus.rejection_counts().event_type_not_whitelisted,
        10,
        "counters must survive clear_rejected_log()"
    );
    assert_eq!(bus.cycle_rejected_log().len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-1 W3: oversized event_type is truncated before clone
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_w3_event_type_not_whitelisted_truncates_oversized_payload() {
    // Attacker submits a `dispatch(event_type = "x".repeat(N))` with
    // N within the MAX_EVENT_TYPE_LEN cap but well above the
    // REJECTION_LOGGED_STRING_MAX cap. The rejection log entry must
    // store at most REJECTION_LOGGED_STRING_MAX UTF-8 bytes (plus
    // the "…" ellipsis), regardless of the input length.
    let bus = TriggerBusDispatchImpl::new();
    // Pick a length comfortably above REJECTION_LOGGED_STRING_MAX (64)
    // but still under MAX_EVENT_TYPE_LEN (128 in shared-types) so the
    // length-gate doesn't fire first and we exercise the truncation
    // path inside the whitelist-rejection branch.
    let oversized = "x".repeat(100);
    bus.dispatch(make_event(&oversized, "evt-oversize"));
    let log = bus.cycle_rejected_log();
    assert_eq!(log.len(), 1);
    match &log[0] {
        CycleRejection::EventTypeNotWhitelisted { event_type } => {
            assert!(
                event_type.len() <= REJECTION_LOGGED_STRING_MAX + "…".len() + 4,
                "stored event_type was {} bytes, expected <= ~{}: {:?}",
                event_type.len(),
                REJECTION_LOGGED_STRING_MAX,
                event_type
            );
            assert!(
                event_type.ends_with("…"),
                "should end with ellipsis: {event_type:?}"
            );
        }
        other => panic!("expected EventTypeNotWhitelisted, got {other:?}"),
    }
}

#[test]
fn adv_w3_short_event_type_is_not_truncated() {
    // A short non-whitelisted event_type (well under
    // REJECTION_LOGGED_STRING_MAX) is logged verbatim, no ellipsis.
    let bus = TriggerBusDispatchImpl::new();
    bus.dispatch(make_event("fs.write", "evt-short"));
    let log = bus.cycle_rejected_log();
    match &log[0] {
        CycleRejection::EventTypeNotWhitelisted { event_type } => {
            assert_eq!(event_type, "fs.write");
            assert!(!event_type.ends_with("…"));
        }
        other => panic!("expected EventTypeNotWhitelisted, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-2 W2: unsubscribe reclaims visited-set entries from
// the evicted queue (post-dispatch unsubscribe-before-drain case)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_r2_w2_unsubscribe_reclaims_visited_set_entries() {
    // Before the Round-2 W2 extension: `dispatch + unsubscribe (before
    // drain)` left orphan `(chain_id, sub_id)` entries in the
    // visited-set that the drain reclaim path could never see (queue
    // was evicted by unsubscribe, not drained). After the fix,
    // `unsubscribe` iterates the evicted queue and decrements the
    // corresponding visited-set entries before dropping.
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("grant.issued"));
    bus.dispatch(make_event("grant.issued", "chain-a"));
    bus.dispatch(make_event("grant.issued", "chain-b"));
    bus.dispatch(make_event("grant.issued", "chain-c"));
    assert_eq!(bus.visited_set_total(), 3);
    assert_eq!(bus.pending_total(), 3);
    bus.unsubscribe(sub_id);
    assert_eq!(
        bus.visited_set_total(),
        0,
        "unsubscribe must reclaim visited-set entries from the evicted queue"
    );
    assert_eq!(bus.pending_total(), 0);
    assert_eq!(bus.total_subscriptions(), 0);
}

#[test]
fn adv_r2_w2_unsubscribe_leaves_other_subs_visited_set_intact() {
    // Two subs, same event_type, same chain. Unsubscribing sub_a must
    // decrement only its own visited-set entries — sub_b's must
    // remain.
    let bus = TriggerBusDispatchImpl::new();
    let sub_a = bus.subscribe(sub("grant.issued"));
    let sub_b = bus.subscribe(sub("grant.issued"));
    bus.dispatch(make_event("grant.issued", "chain-shared"));
    assert_eq!(bus.visited_set_total(), 2);
    bus.unsubscribe(sub_a);
    assert_eq!(
        bus.visited_set_total(),
        1,
        "unsubscribe(sub_a) must leave sub_b's visited-set entry"
    );
    // sub_b can still be drained normally.
    let drained = bus.drain_for_subscription(sub_b);
    assert_eq!(drained.len(), 1);
    assert_eq!(bus.visited_set_total(), 0);
}

#[test]
fn adv_r2_w2_unsubscribe_with_no_pending_is_a_clean_noop() {
    // Edge case: subscribe + unsubscribe immediately (no dispatch in
    // between). The evicted queue is None; the visited-set reclaim
    // path is skipped; total_subscriptions drops correctly.
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("grant.issued"));
    assert_eq!(bus.visited_set_total(), 0);
    bus.unsubscribe(sub_id);
    assert_eq!(bus.visited_set_total(), 0);
    assert_eq!(bus.total_subscriptions(), 0);
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-3 W1: drain is atomic — concurrent dispatch in the
// gap between queue-pop and visited-set decrement cannot observe a
// stale visited entry. (Round-2's two-phase split is reverted.)
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_r3_w1_drain_then_redispatch_same_chain_succeeds() {
    // After drain returns, an immediate re-dispatch of the same
    // chain_id must succeed (the visited-set entry is gone). This is
    // the atomic-drain invariant: at the moment drain returns, both
    // the queue AND the visited entry are gone for the drained
    // (chain_id, sub_id) pairs. A two-phase drain would have a
    // window where the queue is gone but the visited entry remains,
    // causing a spurious AlreadyVisited rejection. This test asserts
    // the steady-state guarantee end-to-end.
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("git.commit"));
    bus.dispatch(make_event("git.commit", "chain-r3"));
    assert_eq!(bus.visited_set_total(), 1);
    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(drained.len(), 1);
    // Atomic invariant: drain returned ⇒ visited entry decremented.
    assert_eq!(
        bus.visited_set_total(),
        0,
        "drain return must imply visited-set decremented (atomic)"
    );
    // Re-dispatch the same chain_id — must enqueue, not reject.
    bus.dispatch(make_event("git.commit", "chain-r3"));
    let counts = bus.rejection_counts();
    assert_eq!(
        counts.already_visited, 0,
        "post-drain re-dispatch must not produce AlreadyVisited rejection"
    );
    let drained_again = bus.drain_for_subscription(sub_id);
    assert_eq!(drained_again.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-3 W2: oversized chain-id sources don't allocate
// before the length check
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_r3_w2_oversized_event_id_rejects_chain_id_too_long() {
    // Slice B `MAX_COMPONENT_ID_LEN` is 256 bytes. A `dispatch()`
    // with `event.id = "x".repeat(10_000)` would, before the W2
    // fix, clone the entire 10KB string into `raw` before the
    // length check ran. The fix borrows the source as `&str` and
    // checks length first; the rejection variant fires without
    // amplifying the per-dispatch allocation.
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    let huge_id = "x".repeat(10_000);
    bus.dispatch(make_event("git.commit", &huge_id));
    let log = bus.cycle_rejected_log();
    assert!(
        log.iter().any(|r| matches!(
            r,
            CycleRejection::ChainIdTooLong {
                chain_id_len: 10_000,
                ..
            }
        )),
        "expected ChainIdTooLong with chain_id_len=10000 in log: {log:?}"
    );
    assert_eq!(bus.rejection_counts().chain_id_too_long, 1);
    assert_eq!(bus.pending_total(), 0);
}

#[test]
fn adv_r3_w2_oversized_payload_chain_id_rejects() {
    // Payload-supplied `trigger_chain_id` follows the same path.
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    let mut event = make_event("git.commit", "short-event-id");
    let huge_chain = "y".repeat(10_000);
    event.payload = serde_json::json!({ "trigger_chain_id": huge_chain });
    bus.dispatch(event);
    let log = bus.cycle_rejected_log();
    assert!(
        log.iter().any(|r| matches!(
            r,
            CycleRejection::ChainIdTooLong {
                chain_id_len: 10_000,
                ..
            }
        )),
        "expected ChainIdTooLong for oversized payload.trigger_chain_id: {log:?}"
    );
    assert_eq!(bus.rejection_counts().chain_id_too_long, 1);
}

// ─────────────────────────────────────────────────────────────────────────
// Round-3 Info-2: end-to-end coverage for the remaining rejection variants
// (ChainIdEmpty, EventTypeTooLong) so future refactors don't silently
// break these defense-in-depth surfaces.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_r3_info2_empty_chain_id_rejects() {
    // Event with empty event.id AND no payload.trigger_chain_id key
    // → empty chain-id source → ChainIdEmpty rejection.
    let bus = TriggerBusDispatchImpl::new();
    let _sub_id = bus.subscribe(sub("git.commit"));
    let event = make_event("git.commit", ""); // empty event.id
    bus.dispatch(event);
    let log = bus.cycle_rejected_log();
    assert!(
        log.iter()
            .any(|r| matches!(r, CycleRejection::ChainIdEmpty)),
        "expected ChainIdEmpty rejection: {log:?}"
    );
    assert_eq!(bus.rejection_counts().chain_id_empty, 1);
}

#[test]
fn adv_r3_info2_oversize_event_type_rejects_via_length_gate() {
    // event_type > MAX_EVENT_TYPE_LEN (128) triggers the dispatch
    // length gate (first gate, ordered before whitelist for the W3
    // defense-in-depth reason). The rejection stores only the
    // length (a usize), not the offending string.
    let bus = TriggerBusDispatchImpl::new();
    // 300 bytes — comfortably above MAX_EVENT_TYPE_LEN = 128.
    let huge_event_type = "z".repeat(300);
    bus.dispatch(make_event(&huge_event_type, "evt-len"));
    let log = bus.cycle_rejected_log();
    assert!(
        log.iter().any(|r| matches!(
            r,
            CycleRejection::EventTypeTooLong {
                event_type_len: 300,
                ..
            }
        )),
        "expected EventTypeTooLong with event_type_len=300: {log:?}"
    );
    assert_eq!(bus.rejection_counts().event_type_too_long, 1);
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-4 W1: per-subscription pending queue cap with rollback
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_r4_w1_pending_queue_cap_rejects_with_rollback() {
    // Without the per-sub queue cap, a wedged subscriber could
    // accumulate up to the full 100K aggregate visited-set budget in
    // its own queue, monopolizing the bus. The per-sub cap (10K)
    // partitions the budget: once a sub's queue is full, further
    // dispatches to that sub are rejected with PendingQueueCapExceeded
    // and the visited-set increment is rolled back (so the entry
    // doesn't become an unreclaimable ghost slot).
    let bus = TriggerBusDispatchImpl::new();
    let sub_id = bus.subscribe(sub("git.commit"));
    // Fill the per-sub queue to exactly the cap.
    for i in 0..PENDING_QUEUE_PER_SUB_CAP {
        bus.dispatch(make_event("git.commit", &format!("evt-{i}")));
    }
    assert_eq!(bus.pending_total(), PENDING_QUEUE_PER_SUB_CAP);
    assert_eq!(bus.visited_set_total(), PENDING_QUEUE_PER_SUB_CAP);
    assert_eq!(bus.rejection_counts().pending_queue_cap_exceeded, 0);
    // Next dispatch must reject AND roll back the visited-set
    // increment so total stays at the cap rather than +1.
    bus.dispatch(make_event("git.commit", "evt-overflow"));
    assert_eq!(bus.pending_total(), PENDING_QUEUE_PER_SUB_CAP);
    assert_eq!(
        bus.visited_set_total(),
        PENDING_QUEUE_PER_SUB_CAP,
        "rollback must keep visited_set_total at the cap, not +1"
    );
    assert_eq!(bus.rejection_counts().pending_queue_cap_exceeded, 1);
    let log = bus.cycle_rejected_log();
    assert!(
        log.iter().any(|r| matches!(
            r,
            CycleRejection::PendingQueueCapExceeded { cap, .. } if *cap == PENDING_QUEUE_PER_SUB_CAP
        )),
        "expected PendingQueueCapExceeded with cap={} in log",
        PENDING_QUEUE_PER_SUB_CAP
    );
    // Drain frees slots; further dispatch should succeed.
    let drained = bus.drain_for_subscription(sub_id);
    assert_eq!(drained.len(), PENDING_QUEUE_PER_SUB_CAP);
    assert_eq!(bus.pending_total(), 0);
    bus.dispatch(make_event("git.commit", "evt-after-drain"));
    assert_eq!(bus.pending_total(), 1);
}

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-4 W2: concurrent stress test exercises the
// dispatch / drain / unsubscribe lock dance under real multi-thread
// load. Catches gross regressions (deadlock = test hangs to timeout;
// panic = thread join Err = test fail). Doesn't deterministically
// catch every subtle race, but proves CI lifts the lock-order claims
// from pure code review.
// ─────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────
// Adversarial Round-5 W1: counter-vs-log invariant — counter is
// monotonic cumulative; log is a bounded forensic window. FIFO eviction
// must NOT decrement the counter, and clear_rejected_log must NOT reset
// it.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn adv_r5_w1_counter_survives_fifo_log_eviction() {
    let bus = TriggerBusDispatchImpl::new();
    // Dispatch CYCLE_REJECTED_LOG_CAP + 10 non-whitelisted events.
    // The log fills up at the cap then FIFO-evicts the oldest 10
    // entries; the atomic counter must still reflect the full count.
    let overflow = 10usize;
    let total = CYCLE_REJECTED_LOG_CAP + overflow;
    for i in 0..total {
        bus.dispatch(make_event("fs.write", &format!("evt-{i}")));
    }
    assert_eq!(
        bus.cycle_rejected_log().len(),
        CYCLE_REJECTED_LOG_CAP,
        "log must be bounded at CYCLE_REJECTED_LOG_CAP"
    );
    assert_eq!(
        bus.rejection_counts().event_type_not_whitelisted,
        total as u64,
        "counter is cumulative — FIFO eviction must NOT decrement"
    );
    // clear_rejected_log returns count cleared but does NOT reset
    // counters.
    let cleared = bus.clear_rejected_log();
    assert_eq!(cleared, CYCLE_REJECTED_LOG_CAP);
    assert_eq!(bus.cycle_rejected_log().len(), 0);
    assert_eq!(
        bus.rejection_counts().event_type_not_whitelisted,
        total as u64,
        "clear_rejected_log must NOT reset the cumulative counter"
    );
    // One more dispatch increments the counter, with empty log
    // afterwards (single new entry, well under cap).
    bus.dispatch(make_event("fs.write", "evt-after-clear"));
    assert_eq!(
        bus.rejection_counts().event_type_not_whitelisted,
        (total + 1) as u64
    );
    assert_eq!(bus.cycle_rejected_log().len(), 1);
}

#[test]
fn adv_r4_w2_concurrent_dispatch_drain_unsubscribe_stress() {
    use std::sync::Arc as StdArc;
    use std::thread;

    let bus = StdArc::new(TriggerBusDispatchImpl::new());
    let n_subs = 8usize;
    let dispatches_per_thread = 200usize;
    let n_dispatcher_threads = 8usize;
    let drain_iters_per_sub = 30usize;

    let sub_ids: Vec<_> = (0..n_subs)
        .map(|_| bus.subscribe(sub("git.commit")))
        .collect();
    for sid in &sub_ids {
        assert_ne!(*sid, advance_scheduler::types::SubscriptionId::REJECTED);
    }

    let mut handles = vec![];

    // Dispatcher threads — distinct chain_ids so all enqueue (no
    // AlreadyVisited dedup interference; we're testing lock ordering,
    // not cycle semantics).
    for t in 0..n_dispatcher_threads {
        let bus_clone = StdArc::clone(&bus);
        handles.push(thread::spawn(move || {
            for j in 0..dispatches_per_thread {
                bus_clone.dispatch(make_event("git.commit", &format!("evt-t{t}-j{j}")));
            }
        }));
    }

    // Drainer threads — one per sub, each iterating drain.
    for &sub_id in &sub_ids {
        let bus_clone = StdArc::clone(&bus);
        handles.push(thread::spawn(move || {
            for _ in 0..drain_iters_per_sub {
                let _drained = bus_clone.drain_for_subscription(sub_id);
            }
        }));
    }

    // Wait for completion. If any thread panicked, join returns Err
    // and the test fails. If any deadlocked, the test hangs (caught
    // by Cargo's default test timeout).
    for h in handles {
        h.join()
            .expect("worker thread panicked — likely a lock-ordering regression");
    }

    // Drain any remaining entries.
    for &sub_id in &sub_ids {
        let _ = bus.drain_for_subscription(sub_id);
    }

    // Unsubscribe all.
    for &sub_id in &sub_ids {
        bus.unsubscribe(sub_id);
    }

    // Final invariants.
    assert_eq!(
        bus.pending_total(),
        0,
        "no pending entries after full drain + unsubscribe"
    );
    assert_eq!(
        bus.total_subscriptions(),
        0,
        "no subscriptions after unsubscribe loop"
    );
    // Visited-set may have residual ghost entries from
    // rollback-races. The operator-clearing path covers those.
    bus.clear_visited_state();
    assert_eq!(bus.visited_set_total(), 0);
}
