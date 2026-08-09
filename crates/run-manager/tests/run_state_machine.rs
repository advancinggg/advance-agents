//! Slice A AC-01, AC-02, AC-03 integration tests (T20, T22-T28).

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RunError, TaskRunStatus};
use advance_shared_types::traits::EventBusEmit;

#[derive(Default)]
struct MockEventBus {
    events: Mutex<Vec<Event>>,
}

impl MockEventBus {
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

    fn find<F: Fn(&Event) -> bool>(&self, pred: F) -> Option<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|e| pred(e))
            .cloned()
    }
}

impl EventBusEmit for MockEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn fresh_manager() -> (Arc<MockEventBus>, RunManager) {
    let bus = MockEventBus::new_arc();
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    (bus, mgr)
}

fn default_cfg() -> RunConfig {
    RunConfig::default()
}

/// T20 — AC-01: Run struct has all 9 documented fields, all `pub` and
/// serde-serializable.
#[test]
fn t20_run_struct_has_all_documented_fields() {
    let (_bus, mgr) = fresh_manager();
    let id = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    let run = mgr.snapshot_run_for_test(&id).expect("run present");

    let _ = &run.id;
    let _ = &run.task_id;
    let _ = &run.controller_agent;
    let _ = &run.status;
    let _ = &run.root_await;
    let _ = &run.budget;
    let _ = run.iteration;
    let _ = run.created_at;
    let _ = run.updated_at;

    let json = serde_json::to_string(&run).expect("serde serialization");
    for name in [
        "\"id\"",
        "\"task_id\"",
        "\"controller_agent\"",
        "\"status\"",
        "\"root_await\"",
        "\"budget\"",
        "\"iteration\"",
        "\"created_at\"",
        "\"updated_at\"",
    ] {
        assert!(
            json.contains(name),
            "serialized JSON missing field {name}: {json}"
        );
    }
}

/// T22 — AC-02: ensure_run lands in TaskRunStatus::Active.
#[test]
fn t22_ensure_run_lands_in_active() {
    let (_bus, mgr) = fresh_manager();
    let id = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    let snap = mgr.snapshot_status_for_test(&id).unwrap();
    assert!(matches!(snap, TaskRunStatus::Active));
}

/// T23 — AC-02: complete_run transitions Active → Completed; second call
/// → InvalidState.
#[test]
fn t23_complete_run_active_to_completed_then_invalid() {
    let (bus, mgr) = fresh_manager();
    let id = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    mgr.complete_run(&id, "ok".into()).unwrap();
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Completed)
    ));
    let err = mgr.complete_run(&id, "again".into()).unwrap_err();
    assert!(matches!(err, RunError::InvalidState(_)));
    let types = bus.types();
    assert_eq!(types, vec!["run.created", "run.completed"]);
}

/// T24 — AC-02: complete_run on Completed/Failed/Cancelled/Suspended/Paused
/// → InvalidState.
#[test]
fn t24_complete_run_from_non_active_is_invalid() {
    let (_bus, mgr) = fresh_manager();
    let cases = [
        ("task-c", TaskRunStatus::Completed),
        ("task-f", TaskRunStatus::Failed("oops".into())),
        ("task-x", TaskRunStatus::Cancelled("user".into())),
        ("task-s", TaskRunStatus::Suspended),
        ("task-p", TaskRunStatus::Paused),
    ];
    for (task_id, status) in cases {
        let id = mgr.ensure_run(task_id, "root", default_cfg()).unwrap();
        mgr.with_status_for_test(&id, status.clone()).unwrap();
        let err = mgr.complete_run(&id, "x".into()).unwrap_err();
        assert!(
            matches!(err, RunError::InvalidState(_)),
            "expected InvalidState for status {:?}",
            status
        );
    }
}

/// T25 — AC-02 + AC-17: fail_run transitions Active → Failed(reason);
/// Slice B amends fail_run to emit `run.failed` with payload `{reason}`.
#[test]
fn t25_fail_run_active_to_failed_emits_run_failed() {
    let (bus, mgr) = fresh_manager();
    let id = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    mgr.fail_run(&id, "runtime-error".into()).unwrap();
    assert!(matches!(
        mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Failed(s)) if s == "runtime-error"
    ));
    let types = bus.types();
    assert_eq!(types, vec!["run.created", "run.failed"]);
    // Verify the run.failed payload carries the reason.
    let evt = bus
        .find(|e| e.event_type == "run.failed")
        .expect("run.failed");
    assert_eq!(
        evt.payload.get("reason").and_then(|v| v.as_str()),
        Some("runtime-error")
    );
    assert_eq!(evt.run_id.as_deref(), Some(id.as_ref()));
    assert_eq!(evt.agent_id, "root");
}

/// T26 — AC-03: two ensure_run calls return identical RunId; store size 1.
#[test]
fn t26_ensure_run_returns_existing_active_run() {
    let (bus, mgr) = fresh_manager();
    let id1 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    let id2 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    assert_eq!(id1, id2);
    assert_eq!(mgr.store_len_for_test(), 1);
    let types = bus.types();
    assert_eq!(types, vec!["run.created", "run.reused"]);
}

/// T26b — AC-03: Suspended is "live"; ensure_run returns existing.
#[test]
fn t26b_ensure_run_returns_existing_suspended_run() {
    let (_bus, mgr) = fresh_manager();
    let id1 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    mgr.with_status_for_test(&id1, TaskRunStatus::Suspended)
        .unwrap();
    let id2 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    assert_eq!(id1, id2);
    assert_eq!(mgr.store_len_for_test(), 1);
}

/// T26c — AC-03: Paused is "live"; ensure_run returns existing.
#[test]
fn t26c_ensure_run_returns_existing_paused_run() {
    let (_bus, mgr) = fresh_manager();
    let id1 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    mgr.with_status_for_test(&id1, TaskRunStatus::Paused)
        .unwrap();
    let id2 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    assert_eq!(id1, id2);
    assert_eq!(mgr.store_len_for_test(), 1);
}

/// T27 — AC-03: after complete_run, ensure_run creates a new RunId.
#[test]
fn t27_ensure_run_after_completed_creates_new_run() {
    let (_bus, mgr) = fresh_manager();
    let id1 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    mgr.complete_run(&id1, "done".into()).unwrap();
    let id2 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    assert_ne!(id1, id2);
    assert_eq!(mgr.store_len_for_test(), 2);
}

/// T27b — AC-03: after fail_run, ensure_run creates a new RunId.
#[test]
fn t27b_ensure_run_after_failed_creates_new_run() {
    let (_bus, mgr) = fresh_manager();
    let id1 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    mgr.fail_run(&id1, "boom".into()).unwrap();
    let id2 = mgr.ensure_run("task-1", "root", default_cfg()).unwrap();
    assert_ne!(id1, id2);
    assert_eq!(mgr.store_len_for_test(), 2);
}

/// T28 — AC-03: 16 parallel threads call ensure_run; all return same RunId.
#[test]
fn t28_ensure_run_concurrent_calls_no_split_brain() {
    let (_bus, mgr) = fresh_manager();
    let mgr = Arc::new(mgr);
    let n = 16;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let m = Arc::clone(&mgr);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            m.ensure_run("task-1", "root", RunConfig::default())
                .unwrap()
        }));
    }
    let mut ids: Vec<RunId> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    ids.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    ids.dedup();
    assert_eq!(ids.len(), 1, "all 16 threads must see the same RunId");
    assert_eq!(mgr.store_len_for_test(), 1);
}
