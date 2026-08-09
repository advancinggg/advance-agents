//! Stage-F obs SLICE 1 — T4: `complete_round_with_trace` threads the chain
//! `trace_id` + chain-root `parent_span_id` onto `run.round_completed` ONLY, with
//! the override invariant (None -> keep base_event fresh-v4) and the run.*
//! conflation guard (run.created / run.reused unchanged).

use std::sync::{Arc, Mutex};

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::RoundResult;
use advance_shared_types::traits::EventBusEmit;
use uuid::{Uuid, Version};

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}
impl MockBus {
    fn find_first(&self, ty: &str) -> Option<Event> {
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

fn is_uuid_v4(s: &str) -> bool {
    Uuid::parse_str(s)
        .map(|u| u.get_version() == Some(Version::Random))
        .unwrap_or(false)
}

fn empty_round() -> RoundResult {
    RoundResult {
        summary: None,
        metrics: vec![],
    }
}

#[tokio::test]
async fn complete_round_with_trace_threads_only_round_completed() {
    let bus = Arc::new(MockBus::default());
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);

    // Normal-mode run (no auto: prefix) so run.round_completed IS emitted.
    let id = mgr
        .ensure_run("task-trace", "root", RunConfig::default())
        .unwrap();

    // --- Threaded path: trace + parent flow onto run.round_completed ---
    mgr.complete_round_with_trace(
        &id,
        empty_round(),
        Some("chain-trace-XYZ".to_string()),
        Some("chain-root-span-S".to_string()),
    )
    .await
    .unwrap();

    let rc = bus
        .find_first("run.round_completed")
        .expect("run.round_completed emitted");
    assert_eq!(
        rc.trace_id, "chain-trace-XYZ",
        "chain trace_id threaded (137)"
    );
    assert_eq!(
        rc.parent_span_id.as_deref(),
        Some("chain-root-span-S"),
        "chain-root parent_span_id threaded (138 child)"
    );
    assert!(
        is_uuid_v4(&rc.span_id),
        "span_id must STILL be fresh-v4 (never overridden), got {:?}",
        rc.span_id
    );

    // --- Conflation guard: run.created is UNTOUCHED (fresh-v4 trace, no parent) ---
    let created = bus.find_first("run.created").expect("run.created emitted");
    assert!(
        is_uuid_v4(&created.trace_id),
        "run.created trace_id must stay fresh-v4 (NOT joined to the chain), got {:?}",
        created.trace_id
    );
    assert!(
        created.parent_span_id.is_none(),
        "run.created must have no parent_span_id (run.* conflation guard)"
    );
}

#[tokio::test]
async fn complete_round_none_keeps_base_event_v4() {
    let bus = Arc::new(MockBus::default());
    let mgr = RunManager::new_arc(Arc::clone(&bus) as Arc<dyn EventBusEmit>);
    let id = mgr
        .ensure_run("task-none", "root", RunConfig::default())
        .unwrap();

    // The W3 override invariant: None LEAVES base_event's fresh-v4 trace intact
    // (NOT an empty string) and parent None.
    mgr.complete_round_with_trace(&id, empty_round(), None, None)
        .await
        .unwrap();
    let rc = bus
        .find_first("run.round_completed")
        .expect("run.round_completed");
    assert!(
        is_uuid_v4(&rc.trace_id),
        "None trace_id MUST keep base_event fresh-v4 (never empty), got {:?}",
        rc.trace_id
    );
    assert!(rc.parent_span_id.is_none(), "None parent stays None");

    // The legacy delegating complete_round is byte-identical to (None, None).
    let bus2 = Arc::new(MockBus::default());
    let mgr2 = RunManager::new_arc(Arc::clone(&bus2) as Arc<dyn EventBusEmit>);
    let id2 = mgr2
        .ensure_run("task-legacy", "root", RunConfig::default())
        .unwrap();
    mgr2.complete_round(&id2, empty_round()).await.unwrap();
    let rc2 = bus2
        .find_first("run.round_completed")
        .expect("run.round_completed");
    assert!(
        is_uuid_v4(&rc2.trace_id),
        "legacy complete_round keeps fresh-v4 trace"
    );
    assert!(
        rc2.parent_span_id.is_none(),
        "legacy complete_round keeps None parent"
    );
}
