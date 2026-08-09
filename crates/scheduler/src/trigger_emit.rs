//! Trigger-chain product pre-build (sched-triggers slice): a zero-new-dependency
//! `trigger.fired` emission helper.
//!
//! Emission goes through the dependency-inverted
//! `advance_shared_types::traits::EventBusEmit` trait (already a scheduler
//! compile-time dep via `advance-shared-types`) rather than a direct edge to
//! `advance-event-bus`. This keeps the MODULE-014 §2.2 trait-inversion posture
//! intact (no new crate dependency) and matches the in-crate plug-in pattern of
//! `RunBootstrap` / `MessageHandler` / `TurnObserver`.
//!
//! `trigger.fired` is already a member of the Trigger Bus `WHITELIST`
//! (`trigger_bus.rs`), so the emitted event passes EventBus whitelist validation
//! without any change to `WHITELIST`.
//!
//! Future-witness target: SYS-AC-099 (each cron fire emits a `trigger.fired`
//! event with `trigger_type == "cron"`). This slice builds + crate-tests the
//! emission product; the e2e witness is the future harness-witness slice's job.

use std::sync::Arc;

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use serde_json::json;

/// The canonical event type emitted on every trigger fire.
pub const TRIGGER_FIRED_EVENT_TYPE: &str = "trigger.fired";

/// Emit a `trigger.fired` observability event for a single component fire.
///
/// - `emitter`: the optional dependency-inverted sink. **No-op when `None`** —
///   drivers stay fully functional without an event bus wired (preserves the
///   pre-existing `run_periodic` semantics).
/// - `component_id`: the firing component's id (used as the event `agent_id` and
///   echoed in the payload).
/// - `trigger_type`: the trigger family that fired (e.g. `"cron"`).
///
/// The event is built via `Event::observability`, which stamps a fresh UUID id +
/// `Utc::now()` timestamp and leaves correlation fields empty (the cap-grant /
/// observability-emitter precedent). `EventBusEmit::emit` is synchronous and
/// non-blocking by contract, so this helper does not need to be `async`.
pub fn emit_trigger_fired(
    emitter: Option<&Arc<dyn EventBusEmit>>,
    component_id: &str,
    trigger_type: &str,
) {
    if let Some(bus) = emitter {
        let payload = json!({
            "trigger_type": trigger_type,
            "component_id": component_id,
        });
        let event = Event::observability(TRIGGER_FIRED_EVENT_TYPE, component_id, payload, None);
        bus.emit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Minimal in-memory `EventBusEmit` recording every emitted event.
    #[derive(Default)]
    struct RecordingBus {
        events: Mutex<Vec<Event>>,
    }

    impl EventBusEmit for RecordingBus {
        fn emit(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn emit_with_none_is_noop() {
        // Must not panic; nothing to assert beyond "no sink, no work".
        emit_trigger_fired(None, "cron-a", "cron");
    }

    #[test]
    fn emit_records_trigger_fired_with_type() {
        // Keep the concrete recorder to assert on; hand a dyn clone to the helper.
        let recorder = Arc::new(RecordingBus::default());
        let sink: Arc<dyn EventBusEmit> = recorder.clone();
        emit_trigger_fired(Some(&sink), "cron-b", "cron");

        let events = recorder.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, TRIGGER_FIRED_EVENT_TYPE);
        assert_eq!(ev.agent_id, "cron-b");
        assert_eq!(ev.payload["trigger_type"], "cron");
        assert_eq!(ev.payload["component_id"], "cron-b");
    }
}
