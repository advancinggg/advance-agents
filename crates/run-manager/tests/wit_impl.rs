//! Slice C AC-12 tests (T86, T86b, T86c, T87, T87b): AgentRunWitImpl
//! 7-method WIT surface + Option<String> reason None handling +
//! WitRunError From<RunError> value-pin.

use std::sync::{Arc, Mutex};

use advance_run_manager::{AgentRunWitImpl, RunManager, WitRunConfig, WitRunError};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RoundResult, RunError};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct MockAwaitRef;

#[async_trait]
impl AwaitSessionRef for MockAwaitRef {
    fn exists(&self, _sid: &SessionId) -> bool {
        true
    }
    fn walk_tree(&self, _sid: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(&self, _sid: &SessionId, _reason: &str) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

fn fresh_impl() -> AgentRunWitImpl {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef);
    let mgr = Arc::new(RunManager::new(bus).with_await_session_ref(ar));
    AgentRunWitImpl::new(mgr)
}

/// T86 — Call all 7 WIT methods successfully (each on an appropriately
/// staged Run, since state-machine constraints forbid e.g. resume from
/// Active or complete after cancel).
#[tokio::test]
async fn t86_seven_method_surface_all_ok() {
    let api = fresh_impl();

    // Run #1 — ensure-run + run-status + complete-round + complete-run.
    let rid1 = api
        .ensure_run("task-1".into(), WitRunConfig::default())
        .unwrap();
    let _ = api.run_status(rid1.clone()).unwrap();
    let _dec = api
        .complete_round(
            rid1.clone(),
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    api.complete_run(rid1, "done".into()).unwrap();

    // Run #2 — pause-run + resume-run via suspend_run staging.
    // (Use the inner RunManager to suspend; the WIT surface doesn't expose
    // suspend.)
    let rid2 = api
        .ensure_run("task-2".into(), WitRunConfig::default())
        .unwrap();
    // pause-run on Active → branch (b) pending; we then complete_round to
    // settle → Paused.
    api.pause_run(rid2.clone(), Some("ops".into()))
        .await
        .unwrap();
    let _ = api
        .complete_round(
            rid2.clone(),
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    // Now Paused → resume-run.
    api.resume_run(rid2.clone()).unwrap();

    // Run #3 — cancel-run on Active branch (b) sets cancel_pending.
    let rid3 = api
        .ensure_run("task-3".into(), WitRunConfig::default())
        .unwrap();
    api.cancel_run(rid3, Some("user".into())).await.unwrap();
}

/// T86b — `pause_run(rid, None)` defaults reason to empty string;
/// pause_pending flows through with `Some("")`.
#[cfg(feature = "__test-util")]
#[tokio::test]
async fn t86b_pause_run_none_reason_defaults_to_empty() {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    let mgr = Arc::new(RunManager::new(bus));
    let api = AgentRunWitImpl::new(Arc::clone(&mgr));
    let rid_str = api
        .ensure_run("task-1".into(), WitRunConfig::default())
        .unwrap();
    api.pause_run(rid_str.clone(), None).await.unwrap();
    let rid = advance_run_manager::RunId::from_string(rid_str).unwrap();
    let pending = mgr.snapshot_pause_pending_for_test(&rid).unwrap();
    assert_eq!(pending.as_deref(), Some(""));
}

/// T86c — `cancel_run(rid, None)` on Active Run defaults reason to empty
/// string; cancel_pending flows through with `Some("")`.
#[cfg(feature = "__test-util")]
#[tokio::test]
async fn t86c_cancel_run_none_reason_defaults_to_empty() {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    let mgr = Arc::new(RunManager::new(bus));
    let api = AgentRunWitImpl::new(Arc::clone(&mgr));
    let rid_str = api
        .ensure_run("task-1".into(), WitRunConfig::default())
        .unwrap();
    api.cancel_run(rid_str.clone(), None).await.unwrap();
    let rid = advance_run_manager::RunId::from_string(rid_str).unwrap();
    let pending = mgr.snapshot_cancel_pending_for_test(&rid).unwrap();
    assert_eq!(pending.as_deref(), Some(""));
}

/// T87c — caller-agent ownership enforcement: an `AgentRunWitImpl`
/// constructed for caller_agent "alice" cannot operate on a run owned by
/// caller_agent "bob". Closes adversarial Critical: any guest with a
/// stolen run_id could otherwise control another agent's run.
#[tokio::test]
async fn t87c_caller_agent_ownership_enforcement() {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef);
    let mgr = Arc::new(RunManager::new(bus).with_await_session_ref(ar));
    // Alice creates a run.
    let api_alice = AgentRunWitImpl::new_with_caller_agent(Arc::clone(&mgr), "alice");
    let rid = api_alice
        .ensure_run("task-alice".into(), WitRunConfig::default())
        .unwrap();
    // Bob tries to operate on Alice's run — every method must return
    // NotFound (do NOT leak presence via PermissionDenied).
    let api_bob = AgentRunWitImpl::new_with_caller_agent(Arc::clone(&mgr), "bob");
    let cases: Vec<(&str, Result<(), WitRunError>)> = vec![
        ("complete_round", {
            let r = api_bob
                .complete_round(
                    rid.clone(),
                    RoundResult {
                        summary: None,
                        metrics: vec![],
                    },
                )
                .await;
            r.map(|_| ()).map_err(|e| e)
        }),
        (
            "complete_run",
            api_bob.complete_run(rid.clone(), "x".into()),
        ),
        ("pause_run", api_bob.pause_run(rid.clone(), None).await),
        ("resume_run", api_bob.resume_run(rid.clone())),
        ("cancel_run", api_bob.cancel_run(rid.clone(), None).await),
        ("run_status", api_bob.run_status(rid.clone()).map(|_| ())),
    ];
    for (name, res) in cases {
        let err = res.expect_err(&format!("{name} should have returned Err"));
        assert!(
            matches!(err, WitRunError::NotFound(_)),
            "{name}: expected NotFound (presence-leak defense), got {:?}",
            err
        );
    }
    // Alice CAN still operate on her own run.
    api_alice.run_status(rid).unwrap();
}

/// T87 — WitRunError 4 reachable variants via the impl surface.
/// (AlreadyExists is value-pinned by T87b; no production path emits it.)
#[tokio::test]
async fn t87_wit_run_error_variants_reachable() {
    let api = fresh_impl();
    // NotFound — query unknown run_id.
    let nf = api.run_status("run-unknown".into()).unwrap_err();
    assert!(matches!(nf, WitRunError::NotFound(_)));

    // InvalidState — complete_round on a Completed Run.
    let rid = api
        .ensure_run("task-1".into(), WitRunConfig::default())
        .unwrap();
    api.complete_run(rid.clone(), "done".into()).unwrap();
    let inv = api
        .complete_round(
            rid.clone(),
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(inv, WitRunError::InvalidState(_)));

    // PermissionDenied — invalid task_id at ensure_run.
    let pd = api
        .ensure_run("".into(), WitRunConfig::default())
        .unwrap_err();
    assert!(matches!(pd, WitRunError::PermissionDenied(_)));

    // BudgetExceeded is reachable via the budget gate at trait level (not
    // via AgentRunWitImpl directly today since the wit interface does not
    // expose budget check directly). The variant is value-pinned by T87b.
}

/// T87b — From<RunError> value-level regression-pin for ALL 5 variants.
#[test]
fn t87b_from_run_error_value_level_pin_all_five_variants() {
    assert_eq!(
        WitRunError::from(RunError::NotFound("x".into())),
        WitRunError::NotFound("x".into())
    );
    assert_eq!(
        WitRunError::from(RunError::AlreadyExists("x".into())),
        WitRunError::AlreadyExists("x".into())
    );
    assert_eq!(
        WitRunError::from(RunError::InvalidState("x".into())),
        WitRunError::InvalidState("x".into())
    );
    assert_eq!(
        WitRunError::from(RunError::BudgetExceeded("x".into())),
        WitRunError::BudgetExceeded("x".into())
    );
    assert_eq!(
        WitRunError::from(RunError::PermissionDenied("x".into())),
        WitRunError::PermissionDenied("x".into())
    );

    // Roundtrip (WitRunError → RunError → WitRunError).
    let we = WitRunError::NotFound("y".into());
    let rt: WitRunError = RunError::from(we.clone()).into();
    assert_eq!(rt, we);
}
