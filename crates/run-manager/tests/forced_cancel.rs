//! Stage B2 — forced agent-keyed cancel (`RunManager::cancel_run_for_agent`),
//! the SYS-AC-156 product half. Witnesses the forced immediate `*→Cancelled`
//! settle at the run-manager crate level (the system-level SYS-AC-156 e2e
//! witness + cascade-adapter rewire are mainline-harvest's job — see
//! MODULE-008 §3.6 Hand-off).

use std::sync::{Arc, Mutex};

use advance_run_manager::{AgentRunResolver, RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::EventBusEmit;

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn fresh() -> (RunManager, Arc<MockBus>) {
    let bus = Arc::new(MockBus::default());
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    (mgr, bus)
}

fn cancelled_events(bus: &MockBus) -> Vec<Event> {
    bus.events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event_type == "run.cancelled")
        .cloned()
        .collect()
}

/// Forced-immediate Active→Cancelled + `run.cancelled` emit + `live_by_task`
/// drop, all observed SYNCHRONOUSLY right after the no-`.await` call (the
/// anti-race witness for the cascade rewire). Tail also asserts idempotency.
#[test]
fn forced_cancel_active_run_settles_to_cancelled() {
    let (mgr, bus) = fresh();
    let id = mgr
        .ensure_run("taskX", "agentX", RunConfig::default())
        .unwrap();
    assert!(
        matches!(
            mgr.snapshot_status_for_test(&id),
            Some(TaskRunStatus::Active)
        ),
        "run should start Active"
    );

    // Sync call — no `.await`. Post-state must be observable the instant it returns.
    mgr.cancel_run_for_agent("agentX", "terminate-cascade".to_string())
        .unwrap();

    match mgr.snapshot_status_for_test(&id) {
        Some(TaskRunStatus::Cancelled(r)) => assert_eq!(r, "terminate-cascade"),
        other => panic!("expected Cancelled(\"terminate-cascade\"), got {other:?}"),
    }
    // live_by_task dropped + status no longer live → resolve yields no run id.
    assert_eq!(mgr.resolve("agentX").0, None);

    // Exactly one run.cancelled event carrying the right reason (asserted unconditionally).
    let cancelled = cancelled_events(&bus);
    assert_eq!(
        cancelled.len(),
        1,
        "expected exactly one run.cancelled event"
    );
    assert_eq!(
        cancelled[0].payload.get("reason").and_then(|v| v.as_str()),
        Some("terminate-cascade")
    );

    // Idempotent: a second forced cancel resolves 0 live → no-op Ok, no second event.
    mgr.cancel_run_for_agent("agentX", "again".to_string())
        .unwrap();
    assert_eq!(
        cancelled_events(&bus).len(),
        1,
        "second forced cancel (now 0 live) must not emit"
    );
}

/// 0 live runs for the agent → clean no-op `Ok(())`, nothing emitted, store untouched.
#[test]
fn forced_cancel_zero_live_runs_is_noop_ok() {
    let (mgr, bus) = fresh();
    mgr.cancel_run_for_agent("ghost", "x".to_string()).unwrap();
    assert_eq!(mgr.store_len_for_test(), 0);
    assert!(
        bus.events.lock().unwrap().is_empty(),
        "no event should be emitted for a 0-live no-op"
    );
}

/// Two-or-more (ambiguous) live runs for one agent → resolve() collapses to None,
/// and the method must SURFACE an `Err` rather than silently no-op; neither run is
/// cancelled.
#[test]
fn forced_cancel_ambiguous_multiple_live_runs_errs() {
    let (mgr, bus) = fresh();
    let id_a = mgr
        .ensure_run("taskA", "agentX", RunConfig::default())
        .unwrap();
    let id_b = mgr
        .ensure_run("taskB", "agentX", RunConfig::default())
        .unwrap();

    let res = mgr.cancel_run_for_agent("agentX", "x".to_string());
    assert!(
        res.is_err(),
        "ambiguous (>1 live) must surface an Err, not silently no-op"
    );

    // Err returned BEFORE the settle block → both runs untouched.
    assert!(matches!(
        mgr.snapshot_status_for_test(&id_a),
        Some(TaskRunStatus::Active)
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&id_b),
        Some(TaskRunStatus::Active)
    ));
    assert!(
        bus.events
            .lock()
            .unwrap()
            .iter()
            .all(|e| e.event_type != "run.cancelled"),
        "ambiguous refusal must emit no run.cancelled"
    );
}

/// Terminate-cascade helper intentionally differs from `cancel_run_for_agent`:
/// it force-cancels every live run for the agent so a terminating agent cannot
/// retain an unrelated live run merely because the agent key was ambiguous.
#[test]
fn forced_cancel_all_live_runs_for_agent() {
    let (mgr, bus) = fresh();
    let id_a = mgr
        .ensure_run("taskA", "agentX", RunConfig::default())
        .unwrap();
    let id_b = mgr
        .ensure_run("taskB", "agentX", RunConfig::default())
        .unwrap();

    mgr.cancel_all_runs_for_agent("agentX", "terminate-cascade".to_string())
        .unwrap();

    assert!(matches!(
        mgr.snapshot_status_for_test(&id_a),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "terminate-cascade"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&id_b),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "terminate-cascade"
    ));
    assert_eq!(mgr.resolve("agentX").0, None);
    assert_eq!(
        cancelled_events(&bus).len(),
        2,
        "each live run should emit one run.cancelled event"
    );
}

/// The terminate-cascade cancel-all helper first blocks future run creation
/// for the agent, then scans live rows. This closes the empty-scan race where
/// a new run could appear immediately after the final scan returned `Ok(())`.
#[test]
fn forced_cancel_all_blocks_new_runs_after_empty_scan() {
    let (mgr, bus) = fresh();

    mgr.cancel_all_runs_for_agent("agentZ", "terminate-cascade".to_string())
        .unwrap();

    let err = mgr
        .ensure_run("task-after-empty", "agentZ", RunConfig::default())
        .unwrap_err();
    assert!(
        matches!(err, advance_shared_types::run::RunError::PermissionDenied(reason)
            if reason.contains("run-creation-blocked-for-terminating-agent"))
    );
    assert_eq!(mgr.store_len_for_test(), 0);
    assert!(
        bus.events.lock().unwrap().is_empty(),
        "empty cancel-all emits no cancellation events"
    );
}

/// Decision-3 robustness: a single live run that is Paused also force-settles to
/// Cancelled. Installs Paused via the sync test-util helper (it keeps the
/// `live_by_task` index via `ensure_live`); `pause_run` is async and on an Active
/// run only sets `pause_pending`, so it would NOT produce a Paused run here.
#[test]
fn forced_cancel_paused_run_settles_to_cancelled() {
    let (mgr, bus) = fresh();
    let id = mgr
        .ensure_run("taskP", "agentP", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Paused)
        .unwrap();
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Paused)
    ));

    mgr.cancel_run_for_agent("agentP", "x".to_string()).unwrap();

    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Cancelled(_))
    ));
    assert_eq!(mgr.resolve("agentP").0, None);
    assert_eq!(cancelled_events(&bus).len(), 1);
}

/// The forced path runs the SAME `truncate_reason` sanitization as `cancel_run`:
/// an embedded control char (newline) is stripped to `_` on both the settled
/// status reason and the emitted `run.cancelled` payload.
#[test]
fn forced_cancel_reason_is_truncated_and_propagated() {
    let (mgr, bus) = fresh();
    let id = mgr
        .ensure_run("taskR", "agentR", RunConfig::default())
        .unwrap();

    mgr.cancel_run_for_agent("agentR", "force\ncancel".to_string())
        .unwrap();

    match mgr.snapshot_status_for_test(&id) {
        Some(TaskRunStatus::Cancelled(r)) => assert_eq!(r, "force_cancel"),
        other => panic!("expected Cancelled(\"force_cancel\"), got {other:?}"),
    }
    let cancelled = cancelled_events(&bus);
    assert_eq!(cancelled.len(), 1);
    assert_eq!(
        cancelled[0].payload.get("reason").and_then(|v| v.as_str()),
        Some("force_cancel")
    );
}

/// Settle-invariant witness (closes the under-asserted-fields fake-green gap): the forced
/// settle must DRAIN budget reservations AND CLEAR the cooperative `cancel_pending` —
/// forced supersedes cooperative. Without these asserts, a regression dropping the
/// `budget.token_reserved/cost_reserved = 0` or `cancel_pending = None` lines would ship green
/// (a reservation-leak DoS class). Async because `cancel_run` is async.
#[tokio::test]
async fn forced_cancel_drains_budget_and_supersedes_cancel_pending() {
    use advance_shared_types::traits::RunBudget;
    let (mgr, _bus) = fresh();
    let id = mgr
        .ensure_run(
            "taskB",
            "agentB",
            RunConfig {
                token_limit: Some(1000),
                cost_usd_limit: Some(1.0),
                ..RunConfig::default()
            },
        )
        .unwrap();

    // Reserve real budget headroom so the post-cancel zeroing assertion is non-vacuous.
    let budget = mgr.budget();
    let _ = budget.check(id.as_ref(), 500, 0.5);
    let pre = mgr.budget_state_snapshot(&id).unwrap();
    assert!(
        pre.token_reserved > 0,
        "precondition: tokens must be reserved"
    );
    assert!(
        pre.cost_reserved > 0.0,
        "precondition: cost must be reserved"
    );

    // Arm the cooperative cancel_pending (cancel_run on Active keeps status Active).
    mgr.cancel_run(&id, "coop".to_string()).await.unwrap();
    assert!(
        matches!(
            mgr.snapshot_status_for_test(&id),
            Some(TaskRunStatus::Active)
        ),
        "cooperative cancel keeps status Active"
    );
    assert_eq!(
        mgr.snapshot_cancel_pending_for_test(&id),
        Some(Some("coop".to_string()))
    );

    // Forced cancel SUPERSEDES the pending and drains reservations synchronously.
    mgr.cancel_run_for_agent("agentB", "forced".to_string())
        .unwrap();

    match mgr.snapshot_status_for_test(&id) {
        Some(TaskRunStatus::Cancelled(r)) => assert_eq!(r, "forced"),
        other => panic!("expected Cancelled(\"forced\"), got {other:?}"),
    }
    assert_eq!(
        mgr.snapshot_cancel_pending_for_test(&id),
        Some(None),
        "cancel_pending must be cleared on forced settle"
    );
    let post = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(post.token_reserved, 0, "token reservation must be drained");
    assert!(
        (post.cost_reserved - 0.0).abs() < f64::EPSILON,
        "cost reservation must be drained"
    );
}

/// Settle-invariant witness for `pause_pending`: a forced cancel of an Active run carrying a
/// cooperative `pause_pending` clears it on settle.
#[tokio::test]
async fn forced_cancel_clears_pause_pending() {
    let (mgr, _bus) = fresh();
    let id = mgr
        .ensure_run("taskQ", "agentQ", RunConfig::default())
        .unwrap();
    // pause_run on an Active run (root_await None) arms pause_pending and keeps status Active.
    mgr.pause_run(&id, "p".to_string()).await.unwrap();
    assert_eq!(
        mgr.snapshot_pause_pending_for_test(&id),
        Some(Some("p".to_string()))
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));

    mgr.cancel_run_for_agent("agentQ", "x".to_string()).unwrap();
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Cancelled(_))
    ));
    assert_eq!(
        mgr.snapshot_pause_pending_for_test(&id),
        Some(None),
        "pause_pending must be cleared on forced settle"
    );
}

/// Decision-3 Suspended branch (closes the entirely-untested gap): a single live run that is
/// Suspended with a live `root_await` force-settles to Cancelled and clears `root_await`
/// synchronously. The M007 await-session is intentionally NOT closed on the sync path
/// (decision 3 — the async `cancel_run` owns clean session close); this witnesses only the
/// documented sync settle + the `root_await = None` clearing.
#[test]
fn forced_cancel_suspended_run_clears_root_await() {
    let (mgr, bus) = fresh();
    let id = mgr
        .ensure_run("taskS", "agentS", RunConfig::default())
        .unwrap();
    mgr.with_root_await_for_test(&id, Some("sid-orphan".to_string()))
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();
    let pre = mgr.snapshot_run_for_test(&id).unwrap();
    assert!(matches!(pre.status, TaskRunStatus::Suspended));
    assert_eq!(pre.root_await, Some("sid-orphan".to_string()));

    mgr.cancel_run_for_agent("agentS", "x".to_string()).unwrap();

    let post = mgr.snapshot_run_for_test(&id).unwrap();
    assert!(
        matches!(post.status, TaskRunStatus::Cancelled(_)),
        "Suspended must force-settle to Cancelled"
    );
    assert_eq!(
        post.root_await, None,
        "root_await must be cleared on settle"
    );
    assert_eq!(mgr.resolve("agentS").0, None);
    assert_eq!(cancelled_events(&bus).len(), 1);
}
