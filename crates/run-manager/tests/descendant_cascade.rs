//! Wave-21 descendant cascade tests for run-id pause/cancel settlement.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
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
    fn count(&self, event_type: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.event_type == event_type)
            .count()
    }
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

type CloseHook = Arc<dyn Fn(&SessionId) + Send + Sync>;

#[derive(Default)]
struct MockAwaitRef {
    close_calls: Mutex<Vec<(String, String)>>,
    on_close: Mutex<Option<CloseHook>>,
    fail_close_for: Mutex<HashSet<String>>,
}

impl MockAwaitRef {
    fn close_sessions(&self) -> Vec<String> {
        self.close_calls
            .lock()
            .unwrap()
            .iter()
            .map(|(sid, _)| sid.clone())
            .collect()
    }

    fn set_on_close(&self, hook: CloseHook) {
        *self.on_close.lock().unwrap() = Some(hook);
    }

    fn fail_close_for(&self, sid: &str) {
        self.fail_close_for.lock().unwrap().insert(sid.to_string());
    }

    fn clear_fail_close_for(&self, sid: &str) {
        self.fail_close_for.lock().unwrap().remove(sid);
    }
}

#[async_trait]
impl AwaitSessionRef for MockAwaitRef {
    fn exists(&self, _: &SessionId) -> bool {
        true
    }

    fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }

    async fn close(&self, sid: &SessionId, reason: &str) -> Result<(), OrchestrationError> {
        self.close_calls
            .lock()
            .unwrap()
            .push((sid.0.clone(), reason.to_string()));
        if self.fail_close_for.lock().unwrap().contains(&sid.0) {
            return Err(OrchestrationError::Downstream("close-failed".into()));
        }
        let hook = self.on_close.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(sid);
        }
        Ok(())
    }
}

struct MockTree {
    data: AgentTreeSnapshotData,
}

impl AgentTreeReader for MockTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.data
            .parent_of
            .get(&AgentId(agent_id.to_string()))
            .and_then(|parent| parent.as_ref().map(|id| id.0.clone()))
    }

    fn children_of(&self, agent_id: &str) -> Vec<String> {
        self.data
            .children_of
            .get(&AgentId(agent_id.to_string()))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|id| id.0)
            .collect()
    }

    fn siblings_of(&self, agent_id: &str) -> Vec<String> {
        let Some(parent) = self.parent_of(agent_id) else {
            return Vec::new();
        };
        self.children_of(&parent)
            .into_iter()
            .filter(|id| id != agent_id)
            .collect()
    }

    fn agent_exists(&self, agent_id: &str) -> bool {
        self.data.nodes.iter().any(|node| node.id.0 == agent_id)
    }

    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        self.data
            .nodes
            .iter()
            .find(|node| node.id.0 == agent_id)
            .map(|node| node.kind.clone())
    }

    fn capabilities(&self, agent_id: &str) -> Vec<Capability> {
        self.data
            .nodes
            .iter()
            .find(|node| node.id.0 == agent_id)
            .map(|node| node.capabilities.clone())
            .unwrap_or_default()
    }
}

impl AgentTreeSnapshot for MockTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        self.data.clone()
    }
}

fn mock_tree(edges: &[(&str, &str)]) -> Arc<MockTree> {
    let mut ids: HashSet<String> = HashSet::new();
    let mut parent_of: HashMap<AgentId, Option<AgentId>> = HashMap::new();
    let mut children_of: HashMap<AgentId, Vec<AgentId>> = HashMap::new();

    for (parent, child) in edges {
        ids.insert((*parent).to_string());
        ids.insert((*child).to_string());
        parent_of
            .entry(AgentId((*parent).to_string()))
            .or_insert(None);
        parent_of.insert(
            AgentId((*child).to_string()),
            Some(AgentId((*parent).to_string())),
        );
        children_of
            .entry(AgentId((*parent).to_string()))
            .or_default()
            .push(AgentId((*child).to_string()));
        children_of
            .entry(AgentId((*child).to_string()))
            .or_default();
    }

    let mut sorted: Vec<String> = ids.into_iter().collect();
    sorted.sort();
    for id in &sorted {
        parent_of.entry(AgentId(id.clone())).or_insert(None);
        children_of.entry(AgentId(id.clone())).or_default();
    }

    let nodes = sorted
        .into_iter()
        .map(|id| {
            let parent = parent_of.get(&AgentId(id.clone())).cloned().unwrap_or(None);
            AgentNode {
                id: AgentId(id.clone()),
                kind: if parent.is_none() {
                    AgentKind::Root
                } else {
                    AgentKind::Child
                },
                parent,
                workspace_path: PathBuf::from(format!("/workspace/{id}")),
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            }
        })
        .collect();

    Arc::new(MockTree {
        data: AgentTreeSnapshotData {
            nodes,
            parent_of,
            children_of,
            peer_slug_map: HashMap::new(),
            revision: 1,
        },
    })
}

struct MockRoundAdvancer {
    calls: Mutex<u32>,
}

impl MockRoundAdvancer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(0),
        })
    }

    fn count(&self) -> u32 {
        *self.calls.lock().unwrap()
    }
}

#[async_trait]
impl RoundAdvancer for MockRoundAdvancer {
    async fn on_complete_round(&self, _: &str, _: RoundResult) -> Result<RoundDecision, RunError> {
        *self.calls.lock().unwrap() += 1;
        Ok(RoundDecision::ContinueAllowed)
    }
}

fn fresh(
    tree: Option<Arc<dyn AgentTreeSnapshot>>,
    advancer: Option<Arc<dyn RoundAdvancer>>,
) -> (Arc<MockBus>, Arc<MockAwaitRef>, Arc<RunManager>) {
    let bus = Arc::new(MockBus::default());
    let ar = Arc::new(MockAwaitRef::default());
    let mut mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
        .with_await_session_ref(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>);
    if let Some(tree) = tree {
        mgr = mgr.with_agent_tree(tree);
    }
    if let Some(advancer) = advancer {
        mgr = mgr.with_round_advancer(advancer);
    }
    (bus, ar, Arc::new(mgr))
}

fn ensure(mgr: &RunManager, task_id: &str, agent_id: &str) -> RunId {
    mgr.ensure_run(task_id, agent_id, RunConfig::default())
        .unwrap()
}

fn round_result() -> RoundResult {
    RoundResult {
        summary: None,
        metrics: Vec::new(),
    }
}

#[tokio::test]
async fn no_tree_keeps_root_only_pause_behavior() {
    let (_bus, ar, mgr) = fresh(None, None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&root, "sid-root").unwrap();
    mgr.suspend_run(&child, "sid-child").unwrap();

    mgr.pause_run(&root, "ops".into()).await.unwrap();

    assert_eq!(ar.close_sessions(), vec!["sid-root"]);
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Paused)
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Suspended)
    ));
}

#[tokio::test]
async fn no_tree_keeps_root_only_cancel_behavior() {
    let (_bus, ar, mgr) = fresh(None, None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&root, "sid-root").unwrap();
    mgr.suspend_run(&child, "sid-child").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();

    assert_eq!(ar.close_sessions(), vec!["sid-root"]);
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Suspended)
    ));
}

#[tokio::test]
async fn suspended_root_pause_cancels_descendants_leaves_first() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child"), ("child", "grand")]);
    let (bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    let grand = ensure(&mgr, "task-grand", "grand");
    mgr.suspend_run(&root, "sid-root").unwrap();
    mgr.suspend_run(&child, "sid-child").unwrap();
    mgr.suspend_run(&grand, "sid-grand").unwrap();

    mgr.pause_run(&root, "ops".into()).await.unwrap();

    assert_eq!(
        ar.close_sessions(),
        vec!["sid-root", "sid-grand", "sid-child"]
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Paused)
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&grand),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert_eq!(bus.count("run.cancelled"), 2);
}

#[tokio::test]
async fn suspended_root_cancel_cancels_descendants_leaves_first() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child"), ("child", "grand")]);
    let (bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    let grand = ensure(&mgr, "task-grand", "grand");
    mgr.suspend_run(&root, "sid-root").unwrap();
    mgr.suspend_run(&child, "sid-child").unwrap();
    mgr.suspend_run(&grand, "sid-grand").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();

    assert_eq!(
        ar.close_sessions(),
        vec!["sid-root", "sid-grand", "sid-child"]
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&grand),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert_eq!(bus.count("run.cancelled"), 3);
}

#[tokio::test]
async fn paused_root_cancel_cascades_descendants() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child"), ("child", "grand")]);
    let (bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    let grand = ensure(&mgr, "task-grand", "grand");
    mgr.with_status_for_test(&root, TaskRunStatus::Paused)
        .unwrap();
    mgr.suspend_run(&child, "sid-child").unwrap();
    mgr.suspend_run(&grand, "sid-grand").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();

    assert_eq!(ar.close_sessions(), vec!["sid-grand", "sid-child"]);
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&grand),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert_eq!(bus.count("run.cancelled"), 3);
}

#[tokio::test]
async fn normal_pause_settlement_cascades_after_complete_round() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child"), ("child", "grand")]);
    let (_bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    let grand = ensure(&mgr, "task-grand", "grand");
    mgr.suspend_run(&child, "sid-child").unwrap();
    mgr.suspend_run(&grand, "sid-grand").unwrap();

    mgr.pause_run(&root, "ops".into()).await.unwrap();
    assert!(ar.close_sessions().is_empty());

    mgr.complete_round(&root, round_result()).await.unwrap();

    assert_eq!(ar.close_sessions(), vec!["sid-grand", "sid-child"]);
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Paused)
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(_))
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&grand),
        Some(TaskRunStatus::Cancelled(_))
    ));
}

#[tokio::test]
async fn normal_cancel_settlement_cascades_after_complete_round() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child")]);
    let (_bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&child, "sid-child").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    assert!(ar.close_sessions().is_empty());
    let decision = mgr.complete_round(&root, round_result()).await.unwrap();

    assert!(matches!(&decision, RoundDecision::Blocked(reason) if reason == "cancel-pending"));
    assert_eq!(ar.close_sessions(), vec!["sid-child"]);
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(_))
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(_))
    ));
}

#[tokio::test]
async fn terminal_descendants_are_idempotent() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[
        ("root", "done"),
        ("root", "failed"),
        ("root", "already-cancelled"),
        ("root", "child"),
    ]);
    let (bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let done = ensure(&mgr, "task-done", "done");
    let failed = ensure(&mgr, "task-failed", "failed");
    let already_cancelled = ensure(&mgr, "task-cancelled", "already-cancelled");
    let child = ensure(&mgr, "task-child", "child");
    mgr.with_status_for_test(&done, TaskRunStatus::Completed)
        .unwrap();
    mgr.with_status_for_test(&failed, TaskRunStatus::Failed("boom".into()))
        .unwrap();
    mgr.with_status_for_test(&already_cancelled, TaskRunStatus::Cancelled("prior".into()))
        .unwrap();
    mgr.suspend_run(&child, "sid-child").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    let decision = mgr.complete_round(&root, round_result()).await.unwrap();

    assert!(matches!(&decision, RoundDecision::Blocked(reason) if reason == "cancel-pending"));
    assert_eq!(ar.close_sessions(), vec!["sid-child"]);
    assert_eq!(
        bus.count("run.cancelled"),
        2,
        "only the root and the one live child emit cancellation events"
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&done),
        Some(TaskRunStatus::Completed)
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&failed),
        Some(TaskRunStatus::Failed(reason)) if reason == "boom"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&already_cancelled),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "prior"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
}

#[tokio::test]
async fn auto_complete_round_does_not_settle_or_cascade() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child")]);
    let advancer = MockRoundAdvancer::new();
    let (_bus, ar, mgr) = fresh(
        Some(tree),
        Some(Arc::clone(&advancer) as Arc<dyn RoundAdvancer>),
    );
    let root = ensure(&mgr, "auto:root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&child, "sid-child").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    let decision = mgr.complete_round(&root, round_result()).await.unwrap();

    assert!(matches!(decision, RoundDecision::ContinueAllowed));
    assert_eq!(advancer.count(), 1);
    assert!(ar.close_sessions().is_empty());
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Active)
    ));
    assert_eq!(
        mgr.snapshot_cancel_pending_for_test(&root)
            .flatten()
            .as_deref(),
        Some("ops")
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Suspended)
    ));
}

#[tokio::test]
async fn descendant_close_failure_preserves_child_session_and_reports_error() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child")]);
    let (bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&child, "sid-child").unwrap();
    ar.fail_close_for("sid-child");

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    let err = mgr.complete_round(&root, round_result()).await.unwrap_err();

    assert!(
        matches!(err, RunError::InvalidState(reason) if reason == "descendant-cascade-await-close-failed")
    );
    assert_eq!(
        ar.close_sessions(),
        vec!["sid-child", "sid-child", "sid-child"]
    );
    assert_eq!(
        bus.count("run.cancelled"),
        1,
        "the root cancellation is committed, but descendant cancellation is not emitted"
    );
    let child_snapshot = mgr.snapshot_run_for_test(&child).unwrap();
    assert!(matches!(child_snapshot.status, TaskRunStatus::Suspended));
    assert_eq!(child_snapshot.root_await.as_deref(), Some("sid-child"));
}

#[tokio::test]
async fn descendant_close_failure_continues_to_siblings_before_reporting_error() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "bad"), ("root", "good")]);
    let (bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let bad = ensure(&mgr, "task-bad", "bad");
    let good = ensure(&mgr, "task-good", "good");
    mgr.suspend_run(&bad, "sid-bad").unwrap();
    mgr.suspend_run(&good, "sid-good").unwrap();
    ar.fail_close_for("sid-bad");

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    let err = mgr.complete_round(&root, round_result()).await.unwrap_err();

    assert!(
        matches!(err, RunError::InvalidState(reason) if reason == "descendant-cascade-await-close-failed")
    );
    let close_sessions = ar.close_sessions();
    assert!(
        close_sessions.iter().any(|sid| sid == "sid-good"),
        "healthy sibling must still be closed before the cascade reports the failing child"
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&good),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    let bad_snapshot = mgr.snapshot_run_for_test(&bad).unwrap();
    assert!(matches!(bad_snapshot.status, TaskRunStatus::Suspended));
    assert_eq!(bad_snapshot.root_await.as_deref(), Some("sid-bad"));
    assert_eq!(
        bus.count("run.cancelled"),
        2,
        "root and healthy sibling cancellation events should be emitted"
    );
}

#[tokio::test]
async fn cancelled_root_can_retry_descendant_cascade_after_close_failure() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child")]);
    let (bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&child, "sid-child").unwrap();
    ar.fail_close_for("sid-child");

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    let err = mgr.complete_round(&root, round_result()).await.unwrap_err();
    assert!(
        matches!(err, RunError::InvalidState(reason) if reason == "descendant-cascade-await-close-failed")
    );
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Suspended)
    ));
    assert_eq!(ar.close_sessions().len(), 3);

    ar.clear_fail_close_for("sid-child");
    mgr.cancel_run(&root, "retry".into()).await.unwrap();

    assert_eq!(ar.close_sessions().len(), 4);
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "retry"
    ));
    assert_eq!(
        bus.count("run.cancelled"),
        2,
        "root was already cancelled; retry emits only the descendant cancellation"
    );
}

#[tokio::test]
async fn descendant_cascade_blocks_late_live_descendant_run_creation() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child"), ("root", "late")]);
    let (_bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&child, "sid-child").unwrap();

    let late_id = Arc::new(Mutex::new(None));
    let late_error = Arc::new(Mutex::new(None::<String>));
    let weak_mgr = Arc::downgrade(&mgr);
    let late_id_for_hook = Arc::clone(&late_id);
    let late_error_for_hook = Arc::clone(&late_error);
    ar.set_on_close(Arc::new(move |sid: &SessionId| {
        if sid.0 != "sid-child" {
            return;
        }
        let Some(mgr) = weak_mgr.upgrade() else {
            return;
        };
        let mut slot = late_id_for_hook.lock().unwrap();
        if slot.is_none() {
            match mgr.ensure_run("task-late", "late", RunConfig::default()) {
                Ok(id) => {
                    mgr.suspend_run(&id, "sid-late").unwrap();
                    *slot = Some(id);
                }
                Err(err) => {
                    *late_error_for_hook.lock().unwrap() = Some(format!("{err:?}"));
                }
            }
        }
    }));

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    mgr.complete_round(&root, round_result()).await.unwrap();

    assert_eq!(ar.close_sessions(), vec!["sid-child"]);
    assert!(
        late_id.lock().unwrap().is_none(),
        "known descendants are run-creation-blocked before cascade scanning"
    );
    assert!(
        late_error
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|err| err.contains("run-creation-blocked-for-terminating-agent")),
        "late descendant run creation must be rejected by the cascade creation block"
    );
    let late_after = mgr
        .ensure_run("task-late-after-cascade", "late", RunConfig::default())
        .unwrap();
    assert!(matches!(
        mgr.snapshot_status_for_test(&late_after),
        Some(TaskRunStatus::Active)
    ));
}

#[tokio::test]
async fn descendant_agent_multiple_live_runs_are_all_cancelled() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child")]);
    let (_bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child_a = ensure(&mgr, "task-child-a", "child");
    let child_b = ensure(&mgr, "task-child-b", "child");
    mgr.suspend_run(&root, "sid-root").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();

    assert_eq!(ar.close_sessions(), vec!["sid-root"]);
    assert!(matches!(
        mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child_a),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&child_b),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    let child_c = mgr
        .ensure_run("task-child-c", "child", RunConfig::default())
        .unwrap();
    assert!(matches!(
        mgr.snapshot_status_for_test(&child_c),
        Some(TaskRunStatus::Active)
    ));
}

#[tokio::test]
async fn descendant_resuspend_race_retries_new_session_before_cancel() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child")]);
    let (_bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&child, "sid-child-1").unwrap();

    let swapped = Arc::new(AtomicBool::new(false));
    let weak_mgr = Arc::downgrade(&mgr);
    let child_for_hook = child.clone();
    let swapped_for_hook = Arc::clone(&swapped);
    ar.set_on_close(Arc::new(move |sid: &SessionId| {
        if sid.0 == "sid-child-1" && !swapped_for_hook.swap(true, Ordering::SeqCst) {
            if let Some(mgr) = weak_mgr.upgrade() {
                mgr.with_root_await_for_test(&child_for_hook, Some("sid-child-2".to_string()))
                    .unwrap();
            }
        }
    }));

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    mgr.complete_round(&root, round_result()).await.unwrap();

    assert_eq!(ar.close_sessions(), vec!["sid-child-1", "sid-child-2"]);
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(_))
    ));
}

#[tokio::test]
async fn cancel_run_for_agent_remains_sync_run_state_only() {
    let (_bus, ar, mgr) = fresh(None, None);
    let run = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&run, "sid-child").unwrap();

    mgr.cancel_run_for_agent("child", "ops".into()).unwrap();

    assert!(ar.close_sessions().is_empty());
    assert!(matches!(
        mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
}

#[tokio::test]
async fn descendant_tree_cycle_returns_error_without_touching_child() {
    let tree: Arc<dyn AgentTreeSnapshot> = mock_tree(&[("root", "child"), ("child", "root")]);
    let (_bus, ar, mgr) = fresh(Some(tree), None);
    let root = ensure(&mgr, "task-root", "root");
    let child = ensure(&mgr, "task-child", "child");
    mgr.suspend_run(&child, "sid-child").unwrap();

    mgr.cancel_run(&root, "ops".into()).await.unwrap();
    let err = mgr.complete_round(&root, round_result()).await.unwrap_err();

    assert!(
        matches!(err, RunError::InvalidState(reason) if reason == "agent-tree-cycle-in-descendant-cascade")
    );
    assert!(ar.close_sessions().is_empty());
    assert!(matches!(
        mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Suspended)
    ));
}
