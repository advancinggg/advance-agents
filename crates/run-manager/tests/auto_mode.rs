//! Slice C AC-14 tests (T88–T91d): Auto-mode complete_round buffer-only
//! dispatch; pause_run / cancel_run mode-blind.

use std::sync::{Arc, Mutex};

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::{
    RoundAdvancer, RoundDecision, RoundResult, RunError, TaskRunStatus,
};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl MockBus {
    fn types(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct MockRoundAdvancer {
    calls_count: Mutex<u32>,
    next_decision: Mutex<RoundDecision>,
}

impl MockRoundAdvancer {
    fn new(d: RoundDecision) -> Arc<Self> {
        Arc::new(Self {
            calls_count: Mutex::new(0),
            next_decision: Mutex::new(d),
        })
    }
    fn count(&self) -> u32 {
        *self.calls_count.lock().unwrap()
    }
}

#[async_trait]
impl RoundAdvancer for MockRoundAdvancer {
    async fn on_complete_round(
        &self,
        _run_id: &str,
        _result: RoundResult,
    ) -> Result<RoundDecision, RunError> {
        *self.calls_count.lock().unwrap() += 1;
        Ok(self.next_decision.lock().unwrap().clone())
    }
}

fn fresh(advancer: Option<Arc<dyn RoundAdvancer>>) -> (Arc<MockBus>, Arc<RunManager>) {
    let bus = Arc::new(MockBus::default());
    let mut mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    if let Some(ra) = advancer {
        mgr = mgr.with_round_advancer(ra);
    }
    (bus, Arc::new(mgr))
}

/// T88 — Auto task_id + round_advancer wired; mock returns ContinueAllowed;
/// complete_round returns ContinueAllowed; NO M008 events emitted; counters
/// unchanged.
#[tokio::test]
async fn t88_auto_mode_buffer_only_continue_allowed() {
    let mock = MockRoundAdvancer::new(RoundDecision::ContinueAllowed);
    let (bus, mgr) = fresh(Some(Arc::clone(&mock) as Arc<dyn RoundAdvancer>));
    let id = mgr
        .ensure_run("auto:agent-foo", "root", RunConfig::default())
        .unwrap();
    let dec = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    assert!(matches!(dec, RoundDecision::ContinueAllowed));
    assert_eq!(mock.count(), 1);
    // NO M008 events emitted (M008's only event for this run is run.created
    // from ensure_run; no run.round_completed / paused / cancelled).
    let types = bus.types();
    assert!(types.iter().any(|t| t == "run.created"));
    assert!(!types.iter().any(|t| t == "run.round_completed"));
    assert!(!types.iter().any(|t| t == "run.paused"));
    assert!(!types.iter().any(|t| t == "run.cancelled"));
}

/// T89 — Auto + mock returns Blocked("auto-budget") → complete_round
/// returns ContinueAllowed regardless (PRD §4.7.7 line 871 invariant).
#[tokio::test]
async fn t89_auto_mode_blocked_decision_still_returns_continue_allowed() {
    let mock = MockRoundAdvancer::new(RoundDecision::Blocked("auto-budget".into()));
    let (bus, mgr) = fresh(Some(Arc::clone(&mock) as Arc<dyn RoundAdvancer>));
    let id = mgr
        .ensure_run("auto:agent-foo", "root", RunConfig::default())
        .unwrap();
    let dec = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    // Agent UNAWARE per PRD A.24 — always sees ContinueAllowed.
    assert!(matches!(dec, RoundDecision::ContinueAllowed));
    assert_eq!(mock.count(), 1);
    assert!(!bus.types().iter().any(|t| t == "run.round_completed"));
}

/// T90 — Normal mode (task_id NOT starting with `auto:`) — Slice A/B
/// behavior intact: run.round_completed emitted; mock NOT called.
#[tokio::test]
async fn t90_normal_mode_unchanged_behavior() {
    let mock = MockRoundAdvancer::new(RoundDecision::ContinueAllowed);
    let (bus, mgr) = fresh(Some(Arc::clone(&mock) as Arc<dyn RoundAdvancer>));
    let id = mgr
        .ensure_run("task-001", "root", RunConfig::default())
        .unwrap();
    let _ = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(mock.count(), 0, "Normal mode does not call round_advancer");
    assert!(bus.types().iter().any(|t| t == "run.round_completed"));
}

/// T91 — Auto task_id WITHOUT round_advancer wired → Err(PermissionDenied).
#[tokio::test]
async fn t91_auto_mode_without_advancer_returns_err() {
    let (_bus, mgr) = fresh(None);
    let id = mgr
        .ensure_run("auto:agent-foo", "root", RunConfig::default())
        .unwrap();
    let err = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, RunError::PermissionDenied(ref s) if s.contains("auto-mode-requires-round-advancer"))
    );
}

/// T91b — Auto-mode pause_run is mode-blind: branch-(b) pending semantics.
#[cfg(feature = "__test-util")]
#[tokio::test]
async fn t91b_auto_mode_pause_run_mode_blind_pending() {
    let (bus, mgr) = fresh(None);
    let id = mgr
        .ensure_run("auto:agent-foo", "root", RunConfig::default())
        .unwrap();
    mgr.pause_run(&id, "ops".into()).await.unwrap();
    // Run stays Active; pause_pending set; NO event emitted.
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    assert_eq!(
        mgr.snapshot_pause_pending_for_test(&id)
            .flatten()
            .as_deref(),
        Some("ops")
    );
    assert!(!bus.types().iter().any(|t| t == "run.paused"));
}

/// T91c — Auto-mode cancel_run is mode-blind: branch-(b) pending semantics.
#[cfg(feature = "__test-util")]
#[tokio::test]
async fn t91c_auto_mode_cancel_run_mode_blind_pending() {
    let (bus, mgr) = fresh(None);
    let id = mgr
        .ensure_run("auto:agent-foo", "root", RunConfig::default())
        .unwrap();
    mgr.cancel_run(&id, "user".into()).await.unwrap();
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    assert_eq!(
        mgr.snapshot_cancel_pending_for_test(&id)
            .flatten()
            .as_deref(),
        Some("user")
    );
    assert!(!bus.types().iter().any(|t| t == "run.cancelled"));
}

/// T91d — Auto-mode complete_round with cancel_pending set does NOT
/// settle. Distinguishes Auto-mode behavior from Normal-mode.
#[cfg(feature = "__test-util")]
#[tokio::test]
async fn t91d_auto_mode_complete_round_does_not_settle_pending() {
    let mock = MockRoundAdvancer::new(RoundDecision::ContinueAllowed);
    let (bus, mgr) = fresh(Some(Arc::clone(&mock) as Arc<dyn RoundAdvancer>));
    let id = mgr
        .ensure_run("auto:agent-foo", "root", RunConfig::default())
        .unwrap();
    // Set cancel_pending via cancel_run.
    mgr.cancel_run(&id, "user".into()).await.unwrap();
    let dec = mgr
        .complete_round(
            &id,
            RoundResult {
                summary: None,
                metrics: vec![],
            },
        )
        .await
        .unwrap();
    // Auto-mode complete_round returns ContinueAllowed (no settle).
    assert!(matches!(dec, RoundDecision::ContinueAllowed));
    // Run STILL Active; cancel_pending STILL Some("user"); no run.cancelled emit.
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    assert_eq!(
        mgr.snapshot_cancel_pending_for_test(&id)
            .flatten()
            .as_deref(),
        Some("user")
    );
    assert!(!bus.types().iter().any(|t| t == "run.cancelled"));
    assert!(!bus.types().iter().any(|t| t == "run.round_completed"));
    assert_eq!(mock.count(), 1, "round_advancer was called once");
}
