//! T47 — regression-pin per-emit UUID v4 placeholder for `event.id` /
//! `trace_id` / `span_id` on all 4 Slice A event helpers.

use std::sync::{Arc, Mutex};

use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::event::Event;
use advance_shared_types::run::RoundResult;
use advance_shared_types::traits::EventBusEmit;
use uuid::{Uuid, Version};

#[derive(Default)]
struct MockEventBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for MockEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn assert_uuid_v4(field: &str, value: &str) {
    let uuid = Uuid::parse_str(value)
        .unwrap_or_else(|e| panic!("{field}={value:?} not a parseable UUID: {e}"));
    assert_eq!(
        uuid.get_version(),
        Some(Version::Random),
        "{field}={value:?} must be UUID v4 (Version::Random)"
    );
}

/// T47 — every emitted Slice A event has `id` / `trace_id` / `span_id`
/// formatted as UUID v4. Locks in the per-emit-UUID placeholder so a
/// later "real trace_id" slice surfaces in the diff.
#[tokio::test]
async fn t47_event_helpers_emit_uuid_v4_id_trace_id_span_id() {
    let bus = Arc::new(MockEventBus::default());
    let mgr = RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>);

    // Exercise all 4 event helpers via the public API:
    //   run.created  ← ensure_run (first call)
    //   run.reused   ← ensure_run (second call for same task)
    //   run.round_completed ← complete_round
    //   run.completed ← complete_run
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let _id_reused = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.complete_round(
        &id,
        RoundResult {
            summary: None,
            metrics: vec![],
        },
    )
    .await
    .unwrap();
    mgr.complete_run(&id, "done".into()).unwrap();

    let events = bus.events.lock().unwrap();
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(
        types,
        vec![
            "run.created",
            "run.reused",
            "run.round_completed",
            "run.completed"
        ]
    );

    for evt in events.iter() {
        assert_uuid_v4("event.id", &evt.id);
        assert_uuid_v4("event.trace_id", &evt.trace_id);
        assert_uuid_v4("event.span_id", &evt.span_id);
    }
}
