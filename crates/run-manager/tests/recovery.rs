//! Slice B AC-07 crash-recovery integration tests (T57–T60b).

use std::sync::{Arc, Mutex};

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::TaskRunStatus;
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
    fn find_all(&self, ty: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .cloned()
            .collect()
    }
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct MockAwaitRef {
    /// Returns the session-existence answer per SessionId; default true.
    exists_map: Mutex<std::collections::HashMap<String, bool>>,
}

impl MockAwaitRef {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self {
            exists_map: Mutex::new(std::collections::HashMap::new()),
        })
    }
    fn set_exists(&self, sid: &str, ok: bool) {
        self.exists_map.lock().unwrap().insert(sid.to_string(), ok);
    }
}

#[async_trait]
impl AwaitSessionRef for MockAwaitRef {
    fn exists(&self, sid: &SessionId) -> bool {
        *self.exists_map.lock().unwrap().get(&sid.0).unwrap_or(&true)
    }
    fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(&self, _: &SessionId, _: &str) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

fn fresh() -> (Arc<MockBus>, Arc<MockAwaitRef>, RunManager) {
    let bus = MockBus::new_arc();
    let ar = MockAwaitRef::new_arc();
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    (bus, ar, mgr)
}

/// T57 — Suspended Run with root_await=Some(sid); exists=false →
/// status flips to Active, root_await cleared, run.interrupted emitted,
/// live_by_task invariant preserved.
#[tokio::test]
async fn t57_recovery_suspended_missing_session() {
    let (bus, ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();
    mgr.with_root_await_for_test(&id, Some("sid-abc".into()))
        .unwrap();
    ar.set_exists("sid-abc", false);

    let report = mgr
        .recover_on_startup(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>)
        .await;

    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(report.interrupted_emitted, 1);
    assert_eq!(report.invalid_session_id, 0);
    assert_eq!(report.raced_skipped, 0);
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Active)
    ));
    let run = mgr.snapshot_run_for_test(&id).unwrap();
    assert_eq!(run.root_await, None);
    let evts = bus.find_all("run.interrupted");
    assert_eq!(evts.len(), 1);
    assert_eq!(
        evts[0].payload.get("reason").and_then(|v| v.as_str()),
        Some("crash-recovery")
    );
    // live_by_task invariant: ensure_run("task-1") returns same id.
    let id_again = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    assert_eq!(id_again, id);
    assert_eq!(mgr.store_len_for_test(), 1);
}

/// T58 — Suspended Run, session still alive (exists=true) → no transition.
#[tokio::test]
async fn t58_recovery_session_alive_no_op() {
    let (bus, ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();
    mgr.with_root_await_for_test(&id, Some("sid-abc".into()))
        .unwrap();
    ar.set_exists("sid-abc", true);

    let report = mgr
        .recover_on_startup(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>)
        .await;

    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(report.interrupted_emitted, 0);
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Suspended)
    ));
    assert!(!bus.types().contains(&"run.interrupted".to_string()));
}

/// T59 — Suspended Run with root_await=None (inconsistent) — skipped.
#[tokio::test]
async fn t59_recovery_suspended_no_root_await() {
    let (_bus, ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();
    // No with_root_await_for_test → root_await stays None.

    let report = mgr
        .recover_on_startup(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>)
        .await;

    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(report.interrupted_emitted, 0);
    assert_eq!(report.invalid_session_id, 0);
    // Status unchanged.
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Suspended)
    ));
}

/// T59b — Suspended Run with invalid charset root_await → invalid_session_id counter.
#[tokio::test]
async fn t59b_recovery_invalid_session_charset() {
    let (bus, ar, mgr) = fresh();
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();
    mgr.with_root_await_for_test(&id, Some("../etc/passwd".into()))
        .unwrap();

    let report = mgr
        .recover_on_startup(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>)
        .await;

    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(report.interrupted_emitted, 0);
    assert_eq!(report.invalid_session_id, 1);
    // Status unchanged.
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Suspended)
    ));
    assert!(!bus.types().contains(&"run.interrupted".to_string()));
}

/// T60 — Mixed store: Active + Suspended-missing-session + Paused.
/// Recovery only touches the middle one.
#[tokio::test]
async fn t60_recovery_mixed_store() {
    let (bus, ar, mgr) = fresh();

    let id_active = mgr
        .ensure_run("task-a", "root", RunConfig::default())
        .unwrap();

    let id_suspended = mgr
        .ensure_run("task-b", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id_suspended, TaskRunStatus::Suspended)
        .unwrap();
    mgr.with_root_await_for_test(&id_suspended, Some("sid-b".into()))
        .unwrap();
    ar.set_exists("sid-b", false);

    let id_paused = mgr
        .ensure_run("task-c", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id_paused, TaskRunStatus::Paused)
        .unwrap();

    let report = mgr
        .recover_on_startup(Arc::clone(&ar) as Arc<dyn AwaitSessionRef>)
        .await;

    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(report.interrupted_emitted, 1);
    // Active + Paused untouched.
    assert!(matches!(
        mgr.snapshot_status_for_test(&id_active),
        Some(TaskRunStatus::Active)
    ));
    assert!(matches!(
        mgr.snapshot_status_for_test(&id_paused),
        Some(TaskRunStatus::Paused)
    ));
    // Only one run.interrupted emitted, with the correct run_id.
    let evts = bus.find_all("run.interrupted");
    assert_eq!(evts.len(), 1);
    assert_eq!(evts[0].run_id.as_deref(), Some(id_suspended.as_ref()));
}

/// T60b — TOCTOU race: status changes between Phase 1 and Phase 2.
/// Phase 2 double-recheck must skip the candidate.
#[tokio::test]
async fn t60b_recovery_toctou_race_recheck() {
    // This test simulates the race by:
    //   1. Pre-seeding Suspended + root_await=Some(sid).
    //   2. Using an AwaitSessionRef::exists impl that BEFORE returning false,
    //      mutates the store via the captured RunManager handle to flip status
    //      to Active (simulating a concurrent resume_run that won the race).
    //   3. Recovery's Phase 2 double-recheck must observe status != Suspended
    //      AND/OR root_await != captured_sid, and increment raced_skipped.
    use std::sync::Weak;

    struct RacingAwaitRef {
        // We need a back-reference to the RunManager to mutate it during exists().
        mgr: Mutex<Option<Weak<RunManager>>>,
        run_id: Mutex<Option<advance_run_manager::RunId>>,
    }

    #[async_trait]
    impl AwaitSessionRef for RacingAwaitRef {
        fn exists(&self, _: &SessionId) -> bool {
            if let (Some(weak), Some(rid)) = (
                self.mgr.lock().unwrap().clone(),
                self.run_id.lock().unwrap().clone(),
            ) {
                if let Some(mgr) = weak.upgrade() {
                    // Race: flip status BEFORE returning false. Phase 2 will
                    // re-acquire the write lock and observe Active.
                    mgr.with_status_for_test(&rid, TaskRunStatus::Active).ok();
                    mgr.with_root_await_for_test(&rid, None).ok();
                }
            }
            false
        }
        fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
            None
        }
        async fn close(&self, _: &SessionId, _: &str) -> Result<(), OrchestrationError> {
            Ok(())
        }
    }

    let bus = MockBus::new_arc();
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.with_status_for_test(&id, TaskRunStatus::Suspended)
        .unwrap();
    mgr.with_root_await_for_test(&id, Some("sid-x".into()))
        .unwrap();

    let racing = Arc::new(RacingAwaitRef {
        mgr: Mutex::new(Some(Arc::downgrade(&mgr))),
        run_id: Mutex::new(Some(id.clone())),
    });

    let report = mgr
        .recover_on_startup(Arc::clone(&racing) as Arc<dyn AwaitSessionRef>)
        .await;

    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(report.interrupted_emitted, 0);
    assert_eq!(report.raced_skipped, 1);
    // No phantom run.interrupted.
    assert!(!bus.types().contains(&"run.interrupted".to_string()));
}
