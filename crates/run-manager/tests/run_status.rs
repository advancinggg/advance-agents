//! Slice C AC-18 tests (T81–T84b): run_status with await-tree dispatch.

use std::sync::{Arc, Mutex};

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId, SessionSummary,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::TaskRunStatus;
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

struct MockAwaitRef {
    tree: Option<AwaitTreeSummary>,
}

#[async_trait]
impl AwaitSessionRef for MockAwaitRef {
    fn exists(&self, _sid: &SessionId) -> bool {
        true
    }
    fn walk_tree(&self, _sid: &SessionId) -> Option<AwaitTreeSummary> {
        self.tree.clone()
    }
    async fn close(&self, _sid: &SessionId, _reason: &str) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

fn fresh(ar: Option<Arc<dyn AwaitSessionRef>>) -> Arc<RunManager> {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    let mut mgr = RunManager::new(bus);
    if let Some(a) = ar {
        mgr = mgr.with_await_session_ref(a);
    }
    Arc::new(mgr)
}

fn sample_tree() -> AwaitTreeSummary {
    AwaitTreeSummary {
        depth: 3,
        total_sessions: 3,
        pending_replies: 2,
        sessions: vec![
            SessionSummary {
                session_id: "sid-A".into(),
                parent_session_id: None,
                agent_id: "agent-A".into(),
                mode: "all-of".into(),
                expected: 2,
                received: 1,
                status: "open".into(),
            },
            SessionSummary {
                session_id: "sid-B".into(),
                parent_session_id: Some("sid-A".into()),
                agent_id: "agent-B".into(),
                mode: "any-of".into(),
                expected: 1,
                received: 0,
                status: "open".into(),
            },
            SessionSummary {
                session_id: "sid-C".into(),
                parent_session_id: Some("sid-A".into()),
                agent_id: "agent-C".into(),
                mode: "all-of".into(),
                expected: 1,
                received: 1,
                status: "completed".into(),
            },
        ],
    }
}

/// T81 — run_status on fresh Active Run.
#[test]
fn t81_run_status_active_no_await_tree() {
    let mgr = fresh(None);
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let state = mgr.run_status(&id).unwrap();
    assert!(matches!(state.status, TaskRunStatus::Active));
    assert!(state.await_tree.is_none());
    assert_eq!(state.iteration, 0);
    assert!((state.cost_usd - 0.0).abs() < f64::EPSILON);
}

/// T82 — Suspended Run + AwaitSessionRef wired; walk_tree returns a
/// 3-session tree. Pin pending-replies + session-summary fields.
#[test]
fn t82_run_status_suspended_populates_await_tree() {
    let tree = sample_tree();
    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef {
        tree: Some(tree.clone()),
    });
    let mgr = fresh(Some(ar));
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-A").unwrap();
    let state = mgr.run_status(&id).unwrap();
    assert!(matches!(state.status, TaskRunStatus::Suspended));
    let summary = state.await_tree.expect("await_tree must be Some");
    assert_eq!(summary.depth, 3);
    assert_eq!(summary.total_sessions, 3);
    assert_eq!(summary.pending_replies, 2);
    assert_eq!(summary.sessions.len(), 3);
}

/// T82b — fail-closed when AwaitSessionRef is None on a Suspended Run.
#[test]
fn t82b_run_status_suspended_no_walker_returns_none() {
    // No AwaitSessionRef wired.
    let mgr = fresh(None);
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    // We can't use suspend_run without AwaitSessionRef in the cancel/pause
    // branches, but suspend_run itself doesn't require it. Suspend the run.
    mgr.suspend_run(&id, "sid-A").unwrap();
    let state = mgr.run_status(&id).unwrap();
    assert!(matches!(state.status, TaskRunStatus::Suspended));
    assert!(
        state.await_tree.is_none(),
        "await_tree must be None when AwaitSessionRef is unwired"
    );
}

/// T82c — walk_tree returns None (session not found in M007).
#[test]
fn t82c_run_status_walker_returns_none() {
    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef { tree: None });
    let mgr = fresh(Some(ar));
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-A").unwrap();
    let state = mgr.run_status(&id).unwrap();
    assert!(state.await_tree.is_none());
}

/// T82d — invalid session_id charset on Suspended Run (corrupted YAML
/// scenario): await_tree = None (fail-closed); no panic.
#[cfg(feature = "__test-util")]
#[test]
fn t82d_run_status_invalid_session_id_charset() {
    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef {
        tree: Some(sample_tree()),
    });
    let mgr = fresh(Some(ar));
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    // Use test-util to install an invalid root_await (the production
    // suspend_run path validates, but a corrupted YAML reload could
    // install garbage).
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();
    mgr.with_root_await_for_test(&id, Some("../etc/passwd".to_string()))
        .unwrap();
    let state = mgr.run_status(&id).unwrap();
    assert!(matches!(state.status, TaskRunStatus::Suspended));
    assert!(
        state.await_tree.is_none(),
        "await_tree must be None when root_await has invalid charset"
    );
}

/// T83 — Pause (via Suspended branch a) then run_status → status=Paused,
/// await_tree=None.
#[tokio::test]
async fn t83_run_status_paused_no_await_tree() {
    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef {
        tree: Some(sample_tree()),
    });
    let mgr = fresh(Some(ar));
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-A").unwrap();
    mgr.pause_run(&id, "paused".into()).await.unwrap();
    let state = mgr.run_status(&id).unwrap();
    assert!(matches!(state.status, TaskRunStatus::Paused));
    assert!(state.await_tree.is_none());
}

/// T84 — complete_run → run_status: status=Completed, await_tree=None,
/// root_await=None.
#[test]
fn t84_run_status_completed_clears_root_await() {
    let mgr = fresh(None);
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.complete_run(&id, "done".into()).unwrap();
    let state = mgr.run_status(&id).unwrap();
    assert!(matches!(state.status, TaskRunStatus::Completed));
    assert!(state.root_await.is_none());
    assert!(state.await_tree.is_none());
}

/// T84b — AC-18 PRD §9.5.1 contract: SessionSummary 7-field completeness
/// (session-id, parent-session-id, agent-id, mode, expected, received,
/// status).
#[test]
fn t84b_session_summary_seven_fields() {
    let tree = sample_tree();
    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef {
        tree: Some(tree.clone()),
    });
    let mgr = fresh(Some(ar));
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.suspend_run(&id, "sid-A").unwrap();
    let state = mgr.run_status(&id).unwrap();
    let summary = state.await_tree.unwrap();
    let first = &summary.sessions[0];
    assert_eq!(first.session_id, "sid-A");
    assert!(first.parent_session_id.is_none());
    assert_eq!(first.agent_id, "agent-A");
    assert_eq!(first.mode, "all-of");
    assert_eq!(first.expected, 2);
    assert_eq!(first.received, 1);
    assert_eq!(first.status, "open");
    // Second + third assert parent_session_id is populated downstream.
    assert_eq!(
        summary.sessions[1].parent_session_id.as_deref(),
        Some("sid-A")
    );
    assert_eq!(
        summary.sessions[2].parent_session_id.as_deref(),
        Some("sid-A")
    );
}
