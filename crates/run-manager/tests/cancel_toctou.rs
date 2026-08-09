//! Item-1 witnesses (grok-repass fix lane): `cancel_run` TOCTOU lost-cancel.
//!
//! Today `cancel_run`'s Suspended/Paused recheck-failure legs silently drop
//! the operator's cancel and return `Ok(())` even when the run is still live.
//! These tests inject the race deterministically — no sleeps, no threads —
//! and witness the bounded carry-forward re-dispatch fix.
//!
//! Race injection: [`RacingTree`] is an `AgentTreeSnapshot` double whose
//! `snapshot()` mutates run state via the `__test-util` helpers. This
//! DELIBERATELY violates the trait's implementer invariant 2 ("consistent
//! snapshot", `crates/shared-types/src/agent_tree.rs`) — the double exists to
//! fire inside `cancel_run`'s TOCTOU window (`run.rs` preflight →
//! `tree.snapshot()`, called with no store lock held). Two further deliberate
//! test-double deviations, so a reader does not mistake them for production
//! behaviour:
//! (a) `Paused → Suspended` is not a MODULE-008 state-diagram edge (production
//!     reaches it via the compound `Paused → Active → Suspended`); the
//!     injector installs it directly.
//! (b) a `Suspended → Paused` injection leaves `root_await = Some(..)` on a
//!     Paused row, and the Paused settle arm never clears it, so those tests
//!     end `Cancelled` while still carrying a session id. Harmless for the
//!     stated assertions; an artefact of the double, not of the fix.
//!
//! Every hook is a bounded-count latch (or a status toggle used only by tests
//! that never call `complete_round`): `complete_round`'s in-store preflight
//! calls `tree.snapshot()` WHILE the store write guard is held, and
//! `with_status_for_test` takes `store.write()` — an unspent latch firing
//! there would self-deadlock. Spent latches make the injector inert.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use advance_run_manager::{AgentRunWitImpl, RunConfig, RunId, RunManager, WitRunError};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RoundDecision, RoundResult, RunError, TaskRunStatus};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

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

    fn count_for_run(&self, event_type: &str, run_id: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                event.event_type == event_type && event.run_id.as_deref() == Some(run_id)
            })
            .count()
    }
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct MockAwaitRef {
    close_calls: Mutex<Vec<(String, String)>>,
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

    fn fail_close_for(&self, sid: &str) {
        self.fail_close_for.lock().unwrap().insert(sid.to_string());
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
        Ok(())
    }
}

type RaceHook = Box<dyn FnMut() + Send>;

/// The mutating snapshot double. See the file header for the deliberate
/// invariant violations. The hook is installed AFTER the manager is built so
/// it can hold a `Weak<RunManager>` back-handle.
struct RacingTree {
    data: AgentTreeSnapshotData,
    hook: Mutex<Option<RaceHook>>,
}

impl RacingTree {
    fn install_hook(&self, hook: RaceHook) {
        *self.hook.lock().unwrap() = Some(hook);
    }
}

impl AgentTreeReader for RacingTree {
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

impl AgentTreeSnapshot for RacingTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        if let Some(hook) = self.hook.lock().unwrap().as_mut() {
            hook();
        }
        self.data.clone()
    }
}

fn racing_tree(edges: &[(&str, &str)]) -> Arc<RacingTree> {
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

    Arc::new(RacingTree {
        data: AgentTreeSnapshotData {
            nodes,
            parent_of,
            children_of,
            peer_slug_map: HashMap::new(),
            revision: 1,
        },
        hook: Mutex::new(None),
    })
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    bus: Arc<MockBus>,
    ar: Arc<MockAwaitRef>,
    tree: Arc<RacingTree>,
    mgr: Arc<RunManager>,
}

fn fixture(edges: &[(&str, &str)], with_await_ref: bool) -> Fixture {
    let bus = Arc::new(MockBus::default());
    let ar = Arc::new(MockAwaitRef::default());
    let tree = racing_tree(edges);
    let mut mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    if with_await_ref {
        mgr = mgr.with_await_session_ref(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>);
    }
    let mgr = Arc::new(mgr.with_agent_tree(Arc::clone(&tree) as Arc<dyn AgentTreeSnapshot>));
    Fixture { bus, ar, tree, mgr }
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

/// Flip a run's status (and optionally its `root_await`) through the
/// `__test-util` helpers. `root_await: None` means "leave the field alone";
/// `Some(x)` installs `x`. A real Suspended → Active resume clears
/// `root_await`, so Active flips must pass `Some(None)` (injector rule 2).
fn flip(
    mgr: &Weak<RunManager>,
    run: &RunId,
    status: TaskRunStatus,
    root_await: Option<Option<String>>,
) {
    let Some(mgr) = mgr.upgrade() else {
        return;
    };
    mgr.with_status_for_test(run, status).unwrap();
    if let Some(value) = root_await {
        mgr.with_root_await_for_test(run, value).unwrap();
    }
}

/// A latch that fires `f` on the first `charges` invocations, then goes
/// permanently inert (see the file header for why spent latches matter).
fn bounded_hook(mut charges: usize, mut f: impl FnMut() + Send + 'static) -> RaceHook {
    Box::new(move || {
        if charges > 0 {
            charges -= 1;
            f();
        }
    })
}

// ---------------------------------------------------------------------------
// L1-T1 .. L1-T14
// ---------------------------------------------------------------------------

/// L1-T1 — Suspended arm raced to Active: the retry re-dispatches into the
/// documented branch (b) and arms `cancel_pending` instead of dropping.
#[tokio::test]
async fn t01_suspended_raced_to_active_rearms_cancel_pending() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr.suspend_run(&run, "sid-1").unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(&weak, &run_for_hook, TaskRunStatus::Active, Some(None));
    }));

    f.mgr.cancel_run(&run, "op-cancel".into()).await.unwrap();

    assert_eq!(
        f.mgr
            .snapshot_cancel_pending_for_test(&run)
            .flatten()
            .as_deref(),
        Some("op-cancel"),
        "raced cancel must re-arm as cancel_pending, not be dropped"
    );
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Active)
    ));
    assert_eq!(f.bus.count("run.cancelled"), 0);
}

/// L1-T2 — the re-armed cancel from L1-T1 settles at the next
/// `complete_round` exactly like a branch-(b) cancel.
#[tokio::test]
async fn t02_rearmed_cancel_settles_at_complete_round() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr.suspend_run(&run, "sid-1").unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(&weak, &run_for_hook, TaskRunStatus::Active, Some(None));
    }));

    f.mgr.cancel_run(&run, "op-cancel".into()).await.unwrap();
    let decision = f.mgr.complete_round(&run, round_result()).await.unwrap();

    assert!(matches!(&decision, RoundDecision::Blocked(reason) if reason == "cancel-pending"));
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "op-cancel"
    ));
    assert_eq!(f.bus.count("run.cancelled"), 1);
}

/// L1-T3 — Paused arm raced to Active: same re-arm outcome, second arm.
#[tokio::test]
async fn t03_paused_raced_to_active_rearms_cancel_pending() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr
        .with_status_for_test(&run, TaskRunStatus::Paused)
        .unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(&weak, &run_for_hook, TaskRunStatus::Active, Some(None));
    }));

    f.mgr.cancel_run(&run, "op-cancel".into()).await.unwrap();

    assert_eq!(
        f.mgr
            .snapshot_cancel_pending_for_test(&run)
            .flatten()
            .as_deref(),
        Some("op-cancel")
    );
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Active)
    ));
}

/// L1-T4 — Suspended arm raced to Paused: the retry settles in the Paused
/// arm (branch (a')): Cancelled immediately, event emitted.
#[tokio::test]
async fn t04_suspended_raced_to_paused_settles_in_paused_arm() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr.suspend_run(&run, "sid-1").unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        // Deviation (b): root_await stays Some on the Paused row.
        flip(&weak, &run_for_hook, TaskRunStatus::Paused, None);
    }));

    f.mgr.cancel_run(&run, "op-cancel".into()).await.unwrap();

    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "op-cancel"
    ));
    assert_eq!(f.bus.count("run.cancelled"), 1);
    // Attempt 0's Suspended arm closed the then-current session before its
    // recheck — same ordering as today.
    assert_eq!(f.ar.close_sessions(), vec!["sid-1"]);
}

/// L1-T5 — Paused arm raced to Suspended: the retry settles in the Suspended
/// arm — session closed, Cancelled, event emitted. This row is the reason the
/// Paused recheck must capture `root_await` for carry-forward.
#[tokio::test]
async fn t05_paused_raced_to_suspended_settles_in_suspended_arm() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr
        .with_status_for_test(&run, TaskRunStatus::Paused)
        .unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(
            &weak,
            &run_for_hook,
            TaskRunStatus::Suspended,
            Some(Some("sid-late".to_string())),
        );
    }));

    f.mgr.cancel_run(&run, "op-cancel".into()).await.unwrap();

    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "op-cancel"
    ));
    assert_eq!(f.bus.count("run.cancelled"), 1);
    assert_eq!(f.ar.close_sessions(), vec!["sid-late"]);
}

/// L1-T6 — CONTROL: Suspended arm raced to Completed (terminal). Today's
/// behaviour verbatim: log, no mutation, Ok. A cancel racing a normal
/// completion must never flip a terminal run.
#[tokio::test]
async fn t06_suspended_raced_to_completed_stays_terminal() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr.suspend_run(&run, "sid-1").unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(&weak, &run_for_hook, TaskRunStatus::Completed, None);
    }));

    f.mgr.cancel_run(&run, "op-cancel".into()).await.unwrap();

    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Completed)
    ));
    assert_eq!(f.mgr.snapshot_cancel_pending_for_test(&run).flatten(), None);
    assert_eq!(f.bus.count("run.cancelled"), 0);
}

/// L1-T7 — CONTROL: Paused arm raced to Failed (terminal). Second arm.
#[tokio::test]
async fn t07_paused_raced_to_failed_stays_terminal() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr
        .with_status_for_test(&run, TaskRunStatus::Paused)
        .unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(
            &weak,
            &run_for_hook,
            TaskRunStatus::Failed("boom".into()),
            None,
        );
    }));

    f.mgr.cancel_run(&run, "op-cancel".into()).await.unwrap();

    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Failed(reason)) if reason == "boom"
    ));
    assert_eq!(f.mgr.snapshot_cancel_pending_for_test(&run).flatten(), None);
    assert_eq!(f.bus.count("run.cancelled"), 0);
}

/// L1-T8 — an alternating Suspended/Paused flap exhausts the bounded retry
/// and surfaces the loss as an error instead of a silent drop. The run is
/// left live; no cancellation event is emitted. (This test never calls
/// `complete_round`, so the unbounded toggle cannot deadlock.)
#[tokio::test]
async fn t08_alternating_flap_exhausts_with_cancel_run_raced() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr.suspend_run(&run, "sid-1").unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    let mut to_paused = true;
    f.tree.install_hook(Box::new(move || {
        let status = if to_paused {
            TaskRunStatus::Paused
        } else {
            TaskRunStatus::Suspended
        };
        to_paused = !to_paused;
        flip(&weak, &run_for_hook, status, None);
    }));

    let err = f
        .mgr
        .cancel_run(&run, "op-cancel".into())
        .await
        .unwrap_err();

    assert!(matches!(err, RunError::InvalidState(reason) if reason == "cancel-run-raced"));
    assert_eq!(f.bus.count("run.cancelled"), 0);
    // Audit round 7: pin the status-only-flap close shape — attempts 0 and 2
    // (Suspended arm) each close the STILL-INSTALLED session (root_await
    // never changes in this flap); attempt 1 (Paused arm) closes nothing.
    // Complements t08b, which pins the root_await-flap shape where every
    // closed session is stale.
    assert_eq!(f.ar.close_sessions(), vec!["sid-1", "sid-1"]);
    let status = f.mgr.snapshot_status_for_test(&run).unwrap();
    assert!(
        matches!(
            status,
            TaskRunStatus::Active | TaskRunStatus::Suspended | TaskRunStatus::Paused
        ),
        "run must be left live after exhaustion, got {status:?}"
    );
}

/// L1-T8b — a `root_await`-only flap (status stays Suspended) also exhausts:
/// the Suspended recheck is a conjunction, so retry is driven by the failed
/// `root_await` conjunct alone. Pins that the loop is not a status-only test.
#[tokio::test]
async fn t08b_root_await_only_flap_exhausts_with_cancel_run_raced() {
    let f = fixture(&[], true);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr.suspend_run(&run, "sid-1").unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    let mut next = 2usize;
    f.tree.install_hook(Box::new(move || {
        let Some(mgr) = weak.upgrade() else {
            return;
        };
        mgr.with_root_await_for_test(&run_for_hook, Some(format!("sid-{next}")))
            .unwrap();
        next += 1;
    }));

    let err = f
        .mgr
        .cancel_run(&run, "op-cancel".into())
        .await
        .unwrap_err();

    assert!(matches!(err, RunError::InvalidState(reason) if reason == "cancel-run-raced"));
    // Each attempt closed the session its seed snapshot named.
    assert_eq!(f.ar.close_sessions(), vec!["sid-1", "sid-2", "sid-3"]);
    assert_eq!(f.bus.count("run.cancelled"), 0);
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Suspended)
    ));
}

/// L1-T9 — CONTROL: un-raced Suspended, Paused and Active cancels are
/// OUTCOME-identical to today (final status, cancel_pending, close list,
/// event count; no injector installed, tree wired but inert). The byte-level
/// un-raced regression gate is the full run-manager test suite, not this
/// row.
#[tokio::test]
async fn t09_unraced_paths_outcome_identical() {
    let f = fixture(&[], true);

    let suspended = ensure(&f.mgr, "task-suspended", "root");
    f.mgr.suspend_run(&suspended, "sid-s").unwrap();
    f.mgr.cancel_run(&suspended, "ops".into()).await.unwrap();
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&suspended),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));
    assert_eq!(f.ar.close_sessions(), vec!["sid-s"]);

    let paused = ensure(&f.mgr, "task-paused", "root");
    f.mgr
        .with_status_for_test(&paused, TaskRunStatus::Paused)
        .unwrap();
    f.mgr.cancel_run(&paused, "ops".into()).await.unwrap();
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&paused),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "ops"
    ));

    let active = ensure(&f.mgr, "task-active", "root");
    f.mgr.cancel_run(&active, "ops".into()).await.unwrap();
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&active),
        Some(TaskRunStatus::Active)
    ));
    assert_eq!(
        f.mgr
            .snapshot_cancel_pending_for_test(&active)
            .flatten()
            .as_deref(),
        Some("ops")
    );

    assert_eq!(f.bus.count("run.cancelled"), 2);
}

/// L1-T10 — two-shot Suspended → Paused → Suspended flap with a live
/// descendant: attempt 3 settles in the Suspended arm. Equalities that fail
/// if the retry loop is deleted OR if it over-iterates: root `run.cancelled`
/// exactly once; root session closed exactly twice (once per Suspended
/// attempt); exactly one descendant `run.cancelled`.
#[tokio::test]
async fn t10_two_shot_flap_settles_exactly_once() {
    let f = fixture(&[("root", "child")], true);
    let root = ensure(&f.mgr, "task-root", "root");
    let child = ensure(&f.mgr, "task-child", "child");
    f.mgr.suspend_run(&root, "sid-root").unwrap();
    f.mgr.suspend_run(&child, "sid-child").unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let root_for_hook = root.clone();
    let mut fires = 0usize;
    f.tree.install_hook(bounded_hook(2, move || {
        fires += 1;
        let status = if fires == 1 {
            TaskRunStatus::Paused
        } else {
            TaskRunStatus::Suspended
        };
        // Status-only flips: root_await stays "sid-root" throughout, so the
        // settling attempt's conjunction recheck matches.
        flip(&weak, &root_for_hook, status, None);
    }));

    f.mgr.cancel_run(&root, "op-cancel".into()).await.unwrap();

    assert!(matches!(
        f.mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "op-cancel"
    ));
    assert_eq!(f.bus.count_for_run("run.cancelled", root.as_ref()), 1);
    assert_eq!(f.bus.count_for_run("run.cancelled", child.as_ref()), 1);
    let closes = f.ar.close_sessions();
    assert_eq!(
        closes.iter().filter(|sid| *sid == "sid-root").count(),
        2,
        "one close per Suspended attempt; got {closes:?}"
    );
    assert_eq!(closes.iter().filter(|sid| *sid == "sid-child").count(), 1);
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Cancelled(_))
    ));
}

/// L1-T12 — outcome 3: on a manager built WITHOUT `with_await_session_ref`,
/// a Paused cancel raced into Suspended re-dispatches into the Suspended arm
/// and returns the same `PermissionDenied` an un-raced Suspended cancel
/// already returns on that composition. Today the race returns `Ok(())` and
/// the cancel is silently lost.
#[tokio::test]
async fn t12_no_await_ref_raced_to_suspended_returns_permission_denied() {
    let f = fixture(&[], false);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr
        .with_status_for_test(&run, TaskRunStatus::Paused)
        .unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(
            &weak,
            &run_for_hook,
            TaskRunStatus::Suspended,
            Some(Some("sid-x".to_string())),
        );
    }));

    let err = f
        .mgr
        .cancel_run(&run, "op-cancel".into())
        .await
        .unwrap_err();

    assert!(
        matches!(err, RunError::PermissionDenied(reason) if reason == "await-session-ref-not-configured")
    );
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&run),
        Some(TaskRunStatus::Suspended)
    ));
    assert_eq!(f.bus.count("run.cancelled"), 0);
}

/// L1-T13 — outcome family 4: a raced cancel that now actually settles runs
/// the descendant cascade, so a descendant whose `AwaitSessionRef::close`
/// hard-fails surfaces `descendant-cascade-await-close-failed` where today
/// the raced call returned `Ok(())` and never cascaded.
#[tokio::test]
async fn t13_raced_settle_surfaces_descendant_cascade_close_failure() {
    let f = fixture(&[("root", "child")], true);
    let root = ensure(&f.mgr, "task-root", "root");
    let child = ensure(&f.mgr, "task-child", "child");
    f.mgr.suspend_run(&root, "sid-root").unwrap();
    f.mgr.suspend_run(&child, "sid-child").unwrap();
    f.ar.fail_close_for("sid-child");

    let weak = Arc::downgrade(&f.mgr);
    let root_for_hook = root.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(&weak, &root_for_hook, TaskRunStatus::Paused, None);
    }));

    let err = f
        .mgr
        .cancel_run(&root, "op-cancel".into())
        .await
        .unwrap_err();

    assert!(
        matches!(err, RunError::InvalidState(reason) if reason == "descendant-cascade-await-close-failed")
    );
    // The root settle itself committed (Paused arm, attempt 2) before the
    // cascade failed — same partial-commit shape as the existing
    // descendant_close_failure tests.
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&root),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "op-cancel"
    ));
    assert_eq!(f.bus.count_for_run("run.cancelled", root.as_ref()), 1);
    assert!(matches!(
        f.mgr.snapshot_status_for_test(&child),
        Some(TaskRunStatus::Suspended)
    ));
}

/// L1-T14 — the CONTRACT-070 reachable-outcome widening, witnessed at the
/// WIT surface: L1-T12's scenario driven through `AgentRunWitImpl::cancel_run`
/// flips the guest-visible result from `ok` (today) to
/// `permission-denied("await-session-ref-not-configured")`. The fixture's
/// run is owned by the WIT impl's caller agent ("root"), so
/// `assert_caller_owns` passes and the row exercises the raced path rather
/// than the ownership gate.
#[tokio::test]
async fn t14_wit_surface_flips_ok_to_permission_denied() {
    let f = fixture(&[], false);
    let run = ensure(&f.mgr, "task-root", "root");
    f.mgr
        .with_status_for_test(&run, TaskRunStatus::Paused)
        .unwrap();

    let weak = Arc::downgrade(&f.mgr);
    let run_for_hook = run.clone();
    f.tree.install_hook(bounded_hook(1, move || {
        flip(
            &weak,
            &run_for_hook,
            TaskRunStatus::Suspended,
            Some(Some("sid-x".to_string())),
        );
    }));

    let wit = AgentRunWitImpl::new_with_caller_agent(Arc::clone(&f.mgr), "root");
    let result = wit
        .cancel_run(run.as_ref().to_string(), Some("op-cancel".to_string()))
        .await;

    assert!(
        matches!(
            result,
            Err(WitRunError::PermissionDenied(ref reason)) if reason == "await-session-ref-not-configured"
        ),
        "guest-visible result must flip ok to permission-denied; got {result:?}"
    );
}
