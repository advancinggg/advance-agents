//! Slice B AC-05 / AC-06 integration tests: pause/resume/cancel
//! branches (a) Suspended + (b) Active; resume_run dispatch (Paused +
//! Suspended); reason-whitelist enforcement; cancel-supersedes-pause
//! precedence.

use std::sync::{Arc, Mutex};

use advance_run_manager::{RepetitionAction, RunConfig, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RunError, TaskRunStatus};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl MockBus {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn types(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }
    fn find(&self, ty: &str) -> Option<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.event_type == ty)
            .cloned()
    }
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct MockAwaitRef {
    close_calls: Mutex<Vec<(String, String)>>, // (session_id, reason)
    close_err: Mutex<Option<OrchestrationError>>,
    exists_returns: Mutex<Option<bool>>,
}

impl MockAwaitRef {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn close_count(&self) -> usize {
        self.close_calls.lock().unwrap().len()
    }
    fn close_arg(&self, i: usize) -> Option<(String, String)> {
        self.close_calls.lock().unwrap().get(i).cloned()
    }
    fn set_close_err(&self, e: OrchestrationError) {
        *self.close_err.lock().unwrap() = Some(e);
    }
}

#[async_trait]
impl AwaitSessionRef for MockAwaitRef {
    fn exists(&self, _: &SessionId) -> bool {
        self.exists_returns.lock().unwrap().unwrap_or(true)
    }
    fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(&self, sid: &SessionId, reason: &str) -> Result<(), OrchestrationError> {
        self.close_calls
            .lock()
            .unwrap()
            .push((sid.0.clone(), reason.to_string()));
        if let Some(e) = self.close_err.lock().unwrap().clone() {
            return Err(e);
        }
        Ok(())
    }
}

fn fresh() -> (Arc<MockBus>, Arc<MockAwaitRef>, RunManager) {
    let bus = MockBus::new_arc();
    let ar = MockAwaitRef::new_arc();
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
        .with_await_session_ref(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>);
    (bus, ar, mgr)
}

/// T48 — pause_run on Suspended Run with root_await=Some closes the
/// session, emits run.paused, status → Paused.
#[tokio::test]
async fn t48_pause_run_branch_a_closes_session() {
    let (bus, ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-abc").unwrap();

    mgr.pause_run(&id, "paused".into()).await.unwrap();

    assert_eq!(ar.close_count(), 1);
    assert_eq!(
        ar.close_arg(0).unwrap(),
        ("sid-abc".to_string(), "paused".to_string())
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Paused)
    ));
    let types = bus.types();
    assert!(types.contains(&"run.paused".to_string()));
    let evt = bus.find("run.paused").unwrap();
    assert_eq!(
        evt.payload.get("reason").and_then(|v| v.as_str()),
        Some("paused")
    );
}

/// T49 — cancel_run on Suspended closes session, status → Cancelled.
#[tokio::test]
async fn t49_cancel_run_branch_a_closes_session() {
    let (bus, ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-abc").unwrap();

    mgr.cancel_run(&id, "user-cancelled".into()).await.unwrap();

    assert_eq!(ar.close_count(), 1);
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Cancelled(s)) if s == "user-cancelled"
    ));
    let evt = bus.find("run.cancelled").unwrap();
    assert_eq!(
        evt.payload.get("reason").and_then(|v| v.as_str()),
        Some("user-cancelled")
    );
}

/// T50 — close() Err is non-fatal; run still transitions to Paused.
#[tokio::test]
async fn t50_pause_run_close_err_non_fatal() {
    let (bus, ar, mgr) = fresh();
    ar.set_close_err(OrchestrationError::SessionClosed("already-closed".into()));
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-abc").unwrap();

    mgr.pause_run(&id, "paused".into()).await.unwrap();

    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Paused)
    ));
    assert!(bus.types().contains(&"run.paused".to_string()));
}

/// T51 — pause_run branch (b) on Active sets pause_pending; NO event.
#[tokio::test]
async fn t51_pause_run_branch_b_sets_pending() {
    let (bus, ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    // Active by default, no root_await.

    mgr.pause_run(&id, "ops-pause".into()).await.unwrap();

    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    assert_eq!(
        mgr.snapshot_pause_pending_for_test(&id).flatten(),
        Some("ops-pause".to_string())
    );
    assert_eq!(ar.close_count(), 0);
    // Only run.created should have been emitted (no run.paused yet).
    let types = bus.types();
    assert!(!types.contains(&"run.paused".to_string()));
}

/// T52 — complete_round settles pause_pending: run.round_completed THEN run.paused.
#[tokio::test]
async fn t52_complete_round_settles_pause_pending() {
    use advance_shared_types::run::RoundResult;
    let (bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.pause_run(&id, "ops-pause".into()).await.unwrap();

    let decision = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();

    assert!(matches!(
        decision,
        advance_shared_types::run::RoundDecision::ContinueAllowed
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Paused)
    ));
    // pause_pending cleared.
    assert_eq!(mgr.snapshot_pause_pending_for_test(&id).flatten(), None);
    // Event ordering: round_completed FIRST, then paused.
    let types = bus.types();
    let rci = types
        .iter()
        .position(|t| t == "run.round_completed")
        .unwrap();
    let pi = types.iter().position(|t| t == "run.paused").unwrap();
    assert!(rci < pi, "run.round_completed must precede run.paused");
    // rounds_used advanced.
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.rounds_used, 1);
}

/// T53 — cancel_pending settle: rounds_used IS advanced; Blocked("cancel-pending").
#[tokio::test]
async fn t53_complete_round_settles_cancel_pending() {
    use advance_shared_types::run::{RoundDecision, RoundResult};
    let (bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.cancel_run(&id, "user-cancelled".into()).await.unwrap();

    let decision = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();

    assert!(matches!(decision, RoundDecision::Blocked(ref s) if s == "cancel-pending"));
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Cancelled(s)) if s == "user-cancelled"
    ));
    let snap = mgr.budget_state_snapshot(&id).unwrap();
    assert_eq!(snap.rounds_used, 1);
    // Ordering: round_completed (with decision=blocked:cancel-pending) THEN cancelled.
    let types = bus.types();
    let rci = types
        .iter()
        .position(|t| t == "run.round_completed")
        .unwrap();
    let ci = types.iter().position(|t| t == "run.cancelled").unwrap();
    assert!(rci < ci);
    let rc = bus.find("run.round_completed").unwrap();
    assert_eq!(
        rc.payload.get("decision").and_then(|v| v.as_str()),
        Some("blocked:cancel-pending")
    );
    // live_by_task cleared: a new ensure_run for task-1 returns a new id.
    let id2 = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    assert_ne!(id, id2);
}

/// T54 — pause_run twice: first-write-wins, no event.
#[tokio::test]
async fn t54_pause_run_twice_first_write_wins() {
    let (bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();

    mgr.pause_run(&id, "reason-1".into()).await.unwrap();
    mgr.pause_run(&id, "reason-2".into()).await.unwrap();

    assert_eq!(
        mgr.snapshot_pause_pending_for_test(&id).flatten(),
        Some("reason-1".to_string())
    );
    // No run.paused event before complete_round settles.
    assert!(!bus.types().contains(&"run.paused".to_string()));
}

/// T55 — resume_run(Paused, "manual") → Active.
#[tokio::test]
async fn t55_resume_run_paused_manual() {
    let (bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Paused)
        .unwrap();

    mgr.resume_run(&id, "manual".into()).unwrap();

    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    let evt = bus.find("run.resumed").unwrap();
    assert_eq!(
        evt.payload.get("reason").and_then(|v| v.as_str()),
        Some("manual")
    );
}

/// T55b — resume_run(Suspended, "await_complete") → Active (M007 path).
#[tokio::test]
async fn t55b_resume_run_suspended_await_complete() {
    let (bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-abc").unwrap();

    mgr.resume_run(&id, "await_complete".into()).unwrap();

    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    // root_await cleared.
    let run = mgr.snapshot_run_for_test(&id).unwrap();
    assert_eq!(run.root_await, None);
    let evt = bus.find("run.resumed").unwrap();
    assert_eq!(
        evt.payload.get("reason").and_then(|v| v.as_str()),
        Some("await_complete")
    );
}

/// T55c — reason whitelist enforcement.
#[tokio::test]
async fn t55c_resume_run_invalid_reason_rejected() {
    let (_bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Paused)
        .unwrap();

    let err = mgr.resume_run(&id, "bogus-string".into()).unwrap_err();
    assert!(matches!(err, RunError::PermissionDenied(_)));
    // State unchanged.
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Paused)
    ));
}

/// T56 — resume_run from non-resumable states → InvalidState.
#[tokio::test]
async fn t56_resume_run_non_resumable() {
    let (_bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    // Active.
    assert!(matches!(
        mgr.resume_run(&id, "manual".into()),
        Err(RunError::InvalidState(_))
    ));
    // Completed.
    mgr.with_status_for_test(&id, TaskRunStatus::Completed)
        .unwrap();
    assert!(matches!(
        mgr.resume_run(&id, "manual".into()),
        Err(RunError::InvalidState(_))
    ));
    // Failed.
    mgr.with_status_for_test(&id, TaskRunStatus::Failed("x".into()))
        .unwrap();
    assert!(matches!(
        mgr.resume_run(&id, "manual".into()),
        Err(RunError::InvalidState(_))
    ));
    // Cancelled.
    mgr.with_status_for_test(&id, TaskRunStatus::Cancelled("x".into()))
        .unwrap();
    assert!(matches!(
        mgr.resume_run(&id, "manual".into()),
        Err(RunError::InvalidState(_))
    ));
}

/// T56b — cancel-already-set rejects pause; cancel SUPERSEDES pause.
#[tokio::test]
async fn t56b_cancel_supersedes_pause() {
    let (_bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();

    mgr.cancel_run(&id, "user-cancelled".into()).await.unwrap();
    // Now pause_run should fail.
    let err = mgr.pause_run(&id, "ops".into()).await.unwrap_err();
    assert!(matches!(err, RunError::InvalidState(_)));

    // Reverse: fresh run, set pause first then cancel — pause_pending should be cleared.
    let id2 = mgr
        .ensure_run("task-2", "root", RunConfig::default())
        .unwrap();
    mgr.pause_run(&id2, "ops".into()).await.unwrap();
    mgr.cancel_run(&id2, "cancel-wins".into()).await.unwrap();
    assert_eq!(mgr.snapshot_pause_pending_for_test(&id2).flatten(), None);
    assert_eq!(
        mgr.snapshot_cancel_pending_for_test(&id2).flatten(),
        Some("cancel-wins".to_string())
    );
}

/// T-extra — pause_run requires with_await_session_ref for Suspended.
#[tokio::test]
async fn t_extra_pause_run_branch_a_requires_await_session_ref() {
    let bus = MockBus::new_arc();
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    // No with_await_session_ref.
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();

    let err = mgr.pause_run(&id, "paused".into()).await.unwrap_err();
    assert!(matches!(err, RunError::PermissionDenied(_)));
}

/// T-extra-2 — RepetitionAction enum still constructs cleanly + reachable from RunManager::build_repetition_guard.
#[tokio::test]
async fn t_extra_2_build_repetition_guard_smoke() {
    let bus = MockBus::new_arc();
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    let _guard = mgr.build_repetition_guard(10, 3, RepetitionAction::WarnThenTerminate);
}

/// Adversarial round 2 W1 regression: pause_run Suspended → Paused must
/// clear `root_await`. Without this, a subsequent Paused→Active resume
/// followed by pause_run(Active) would hit the
/// "active-with-root-await invariant violation" check and permanently
/// block the pause lifecycle.
#[tokio::test]
async fn t_adv_pause_suspended_clears_root_await() {
    let (_bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-abc").unwrap();
    assert_eq!(
        mgr.snapshot_run_for_test(&id)
            .unwrap()
            .root_await
            .as_deref(),
        Some("sid-abc")
    );
    mgr.pause_run(&id, "paused".into()).await.unwrap();
    // root_await must be cleared post-Suspended→Paused.
    assert_eq!(mgr.snapshot_run_for_test(&id).unwrap().root_await, None);
    // Round-trip: Paused → Active → pause_run again must NOT hit the
    // active-with-root-await invariant.
    mgr.resume_run(&id, "manual".into()).unwrap();
    mgr.pause_run(&id, "paused-again".into()).await.unwrap();
    assert_eq!(
        mgr.snapshot_pause_pending_for_test(&id).flatten(),
        Some("paused-again".to_string())
    );
}

/// Adversarial round 2 W3 regression: reason strings are stripped of
/// ASCII control characters BEFORE truncation, preventing log injection
/// via newlines/NUL embedded in operator-supplied reasons.
#[tokio::test]
async fn t_adv_reason_control_chars_stripped() {
    let (_bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let injected = "legit\n[FAKE-LOG] admin=true\rsubsequent".to_string();

    mgr.fail_run(&id, injected).unwrap();

    let run = mgr.snapshot_run_for_test(&id).unwrap();
    let stored = match run.status {
        TaskRunStatus::Failed(s) => s,
        _ => panic!("expected Failed status"),
    };
    // Newlines and \r must be replaced with `_`.
    assert!(!stored.contains('\n'));
    assert!(!stored.contains('\r'));
    assert!(stored.contains("legit_[FAKE-LOG]"));
}

/// Adversarial round 4 regression: pause_run Suspended-branch must
/// double-recheck BOTH status == Suspended AND root_await ==
/// captured_snapshot before mutating, to prevent orphan-M007-session
/// leak in the resume_run → suspend_run re-entry race.
///
/// Simulation: a MockAwaitRef::close callback that mutates the
/// manager's root_await mid-flight (between Phase 1 read-snapshot drop
/// and Phase 2 write-lock acquire). The mutation simulates a
/// concurrent resume_run + suspend_run race that swapped the session
/// id under the pause_run.
#[tokio::test]
async fn t_adv_pause_suspended_double_recheck_root_await() {
    use std::sync::OnceLock;

    static MANAGER_HANDLE: OnceLock<Arc<RunManager>> = OnceLock::new();
    static TARGET_ID: OnceLock<advance_run_manager::RunId> = OnceLock::new();

    struct SwappingAwait;
    #[async_trait]
    impl AwaitSessionRef for SwappingAwait {
        fn exists(&self, _: &SessionId) -> bool {
            true
        }
        fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
            None
        }
        async fn close(&self, _: &SessionId, _: &str) -> Result<(), OrchestrationError> {
            if let (Some(mgr), Some(rid)) = (MANAGER_HANDLE.get(), TARGET_ID.get()) {
                mgr.with_root_await_for_test(rid, Some("sid-NEW-after-race".to_string()))
                    .ok();
            }
            Ok(())
        }
    }

    let bus = MockBus::new_arc();
    let swapping: Arc<dyn AwaitSessionRef> = Arc::new(SwappingAwait);
    let mgr = Arc::new(
        RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>).with_await_session_ref(swapping),
    );
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-original").unwrap();

    MANAGER_HANDLE.set(Arc::clone(&mgr)).ok();
    TARGET_ID.set(id.clone()).ok();

    // Phase 1 snapshot captures (Suspended, Some("sid-original")). The
    // close() callback during await swaps root_await to "sid-NEW-after-race".
    // Phase 2 double-recheck must observe root_await mismatch → refuse.
    let result = mgr.pause_run(&id, "racing-pause".into()).await;
    assert!(result.is_ok());

    // Race caught — status stays Suspended, root_await preserved as the NEW sid.
    let status = mgr.snapshot_status_for_test(&id).unwrap();
    assert!(
        matches!(status, TaskRunStatus::Suspended),
        "Expected race-caught Suspended, got {:?}",
        status
    );
    let run = mgr.snapshot_run_for_test(&id).unwrap();
    assert_eq!(
        run.root_await.as_deref(),
        Some("sid-NEW-after-race"),
        "Race-caught run should preserve new root_await"
    );
}

/// Adversarial round 2 Info #8 regression: complete_run clears
/// pause_pending / cancel_pending fields on terminal transition.
#[tokio::test]
async fn t_adv_complete_run_clears_pending_flags() {
    let (_bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.pause_run(&id, "ops".into()).await.unwrap();
    assert!(mgr.snapshot_pause_pending_for_test(&id).flatten().is_some());

    // Force complete_run from Active (pause_pending is still Some but
    // Active is the legitimate complete_run source state).
    mgr.complete_run(&id, "done".into()).unwrap();

    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Completed)
    ));
    assert_eq!(mgr.snapshot_pause_pending_for_test(&id).flatten(), None);
    assert_eq!(mgr.snapshot_cancel_pending_for_test(&id).flatten(), None);
}

// ── Backbone Step 4b (2026-06-08): atomic await-completion resume ──

/// resume_run_if_suspended from Suspended → resumes (Ok(true)), status Active,
/// run.resumed emitted.
#[tokio::test]
async fn t_step4b_resume_if_suspended_from_suspended() {
    let (bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-abc").unwrap();
    let resumed = mgr
        .resume_run_if_suspended(&id, "await_complete".into())
        .unwrap();
    assert!(resumed, "must resume from Suspended");
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    assert!(bus.find("run.resumed").is_some());
}

/// resume_run_if_suspended is a NO-OP on a Paused run — it NEVER clobbers a
/// concurrent pause back to Active (the resume-vs-pause race fix). Returns
/// Ok(false), status stays Paused, NO stray run.resumed.
#[tokio::test]
async fn t_step4b_resume_if_suspended_noop_on_paused() {
    let (bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Paused)
        .unwrap();
    let resumed = mgr
        .resume_run_if_suspended(&id, "await_complete".into())
        .unwrap();
    assert!(
        !resumed,
        "must NOT resume (no clobber of the operator pause)"
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Paused)
    ));
    assert!(
        bus.find("run.resumed").is_none(),
        "no stray run.resumed when the run already left Suspended"
    );
}

/// resume_run_if_suspended rejects any reason other than await_complete.
#[tokio::test]
async fn t_step4b_resume_if_suspended_rejects_bad_reason() {
    let (_bus, _ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-abc").unwrap();
    assert!(mgr.resume_run_if_suspended(&id, "manual".into()).is_err());
}
