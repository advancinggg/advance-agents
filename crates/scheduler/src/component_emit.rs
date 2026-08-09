//! Scheduler-residue slice: zero-new-dependency `component.*` lifecycle
//! emission helpers for the runnable driver paths (cron / daemon / task /
//! watcher).
//!
//! Mirrors the `trigger_emit.rs` pattern byte-for-byte in posture: emission
//! goes through the dependency-inverted
//! `advance_shared_types::traits::EventBusEmit` trait (already a scheduler
//! compile-time dep) rather than a direct edge to `advance-event-bus`, the
//! event types are string literals whose values match the event-bus taxonomy
//! constants (`taxonomy::component::{STARTED,FINISHED,ERROR}`), and every
//! helper is a synchronous no-op when `emitter == None`.
//!
//! Payloads per PRD §15.3.14:
//! - `component.started`: `{id, component_type}`
//! - `component.finished`: `{id, component_type, duration_ms, status}` (the
//!   PRD's `actions_count` is an agent-loop concept — `RunResult = {status,
//!   output}` carries no actions at the driver layer; deviation recorded in
//!   MODULE-014 §3.2/§3.8)
//! - `component.error`: `{id, component_type, error_type, message}`
//!
//! Whitelist asymmetry (intended, not a bug): `component.finished` and
//! `component.error` are members of the 12-entry Trigger Bus `WHITELIST`
//! (re-dispatchable as trigger sources under a production bus);
//! `component.started` is observability-only by design.
//!
//! Lifecycle pairing contract: `started`/`finished` do NOT pair 1:1 under
//! cancellation. The drivers race `hook.run_once` against a
//! `CancellationToken` inside `select!`, so an orphan `started` is the
//! NORMAL outcome of cancelling mid-hook (plus future-drop and hook-panic) —
//! the same accepted posture as `trigger.fired`-at-tick-time (`cron.rs`).
//! `finished`-without-`started` is impossible: every finished/error site is
//! strictly dominated by its started site in the same iteration.
//! `Ok(RunResult{status: Failed})` emits `component.finished` with
//! `status == "failed"` (drivers define success as `result.is_ok()`, see
//! `restart_decision`); `component.error` is reserved for
//! `Err(HookError::Failure)`. `Err(HookError::Cancelled)` emits nothing
//! (cancellation is not failure).

use std::sync::Arc;

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use serde_json::json;

use crate::types::RunStatus;

/// Canonical event type emitted when a runnable component's run begins.
pub const COMPONENT_STARTED_EVENT_TYPE: &str = "component.started";

/// Canonical event type emitted when a runnable component's run completes
/// (the hook returned `Ok`, regardless of the embedded `RunStatus`).
pub const COMPONENT_FINISHED_EVENT_TYPE: &str = "component.finished";

/// Canonical event type emitted when a runnable component's run fails
/// (`Err(HookError::Failure)`).
pub const COMPONENT_ERROR_EVENT_TYPE: &str = "component.error";

/// Cap on the error-message bytes echoed into a `component.error` payload.
/// Bounded-echo discipline matches `trigger_bus.rs`'s
/// `REJECTION_LOGGED_STRING_MAX` precedent — an attacker-influenced hook
/// error string must not amplify into multi-MB event payloads.
pub const ERROR_MESSAGE_ECHO_MAX: usize = 256;

/// Truncate `s` to at most `cap` UTF-8 bytes at a char boundary, appending
/// `"…"` if truncated. Local replica of the private `trigger_bus.rs`
/// helper (kept private there; duplicating 8 lines beats widening that
/// module's surface).
fn truncate_message(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 3);
    out.push_str(&s[..end]);
    out.push_str("…");
    out
}

/// Emit `component.started` for a single run begin. No-op when `emitter`
/// is `None`.
pub fn emit_component_started(
    emitter: Option<&Arc<dyn EventBusEmit>>,
    component_id: &str,
    component_type: &str,
) {
    if let Some(bus) = emitter {
        let payload = json!({
            "id": component_id,
            "component_type": component_type,
        });
        let event = Event::observability(COMPONENT_STARTED_EVENT_TYPE, component_id, payload, None);
        bus.emit(event);
    }
}

/// Emit `component.finished` for a run that returned `Ok(RunResult)`.
/// `status` maps `RunStatus::Completed` → `"completed"`,
/// `RunStatus::Failed(_)` → `"failed"` (an Ok-with-Failed-status run is
/// finished-with-status, NOT `component.error` — matching the drivers'
/// `result.is_ok()` success semantics). `duration_ms` is stamped both in
/// the payload (PRD §15.3.14) and as `Event::duration_ms`. No-op when
/// `emitter` is `None`.
pub fn emit_component_finished(
    emitter: Option<&Arc<dyn EventBusEmit>>,
    component_id: &str,
    component_type: &str,
    duration_ms: u64,
    status: &RunStatus,
) {
    if let Some(bus) = emitter {
        let status_str = match status {
            RunStatus::Completed => "completed",
            RunStatus::Failed(_) => "failed",
        };
        let payload = json!({
            "id": component_id,
            "component_type": component_type,
            "duration_ms": duration_ms,
            "status": status_str,
        });
        let event = Event::observability(
            COMPONENT_FINISHED_EVENT_TYPE,
            component_id,
            payload,
            Some(duration_ms),
        );
        bus.emit(event);
    }
}

/// Emit `component.error` for a run that returned `Err(HookError::Failure)`.
/// The message echo is truncated to [`ERROR_MESSAGE_ECHO_MAX`] bytes.
/// Callers must NOT route `HookError::Cancelled` here (cancellation is not
/// failure — see module rustdoc). No-op when `emitter` is `None`.
pub fn emit_component_error(
    emitter: Option<&Arc<dyn EventBusEmit>>,
    component_id: &str,
    component_type: &str,
    message: &str,
) {
    if let Some(bus) = emitter {
        let payload = json!({
            "id": component_id,
            "component_type": component_type,
            "error_type": "hook-failure",
            "message": truncate_message(message, ERROR_MESSAGE_ECHO_MAX),
        });
        let event = Event::observability(COMPONENT_ERROR_EVENT_TYPE, component_id, payload, None);
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
    fn none_emitter_is_noop_for_all_three() {
        emit_component_started(None, "c-1", "cron");
        emit_component_finished(None, "c-1", "cron", 5, &RunStatus::Completed);
        emit_component_error(None, "c-1", "cron", "boom");
    }

    #[test]
    fn started_payload_fields() {
        let recorder = Arc::new(RecordingBus::default());
        let sink: Arc<dyn EventBusEmit> = recorder.clone();
        emit_component_started(Some(&sink), "task-a", "task");

        let events = recorder.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, COMPONENT_STARTED_EVENT_TYPE);
        assert_eq!(ev.agent_id, "task-a");
        assert_eq!(ev.payload["id"], "task-a");
        assert_eq!(ev.payload["component_type"], "task");
        assert_eq!(ev.duration_ms, None);
    }

    #[test]
    fn finished_payload_maps_status_and_duration() {
        let recorder = Arc::new(RecordingBus::default());
        let sink: Arc<dyn EventBusEmit> = recorder.clone();
        emit_component_finished(Some(&sink), "d-1", "daemon", 42, &RunStatus::Completed);
        emit_component_finished(
            Some(&sink),
            "d-1",
            "daemon",
            7,
            &RunStatus::Failed("app-level".into()),
        );

        let events = recorder.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, COMPONENT_FINISHED_EVENT_TYPE);
        assert_eq!(events[0].payload["status"], "completed");
        assert_eq!(events[0].payload["duration_ms"], 42);
        assert_eq!(events[0].duration_ms, Some(42));
        assert_eq!(events[1].payload["status"], "failed");
        assert_eq!(events[1].duration_ms, Some(7));
    }

    #[test]
    fn error_payload_truncates_long_message() {
        let recorder = Arc::new(RecordingBus::default());
        let sink: Arc<dyn EventBusEmit> = recorder.clone();
        let long = "x".repeat(10_000);
        emit_component_error(Some(&sink), "w-1", "watcher", &long);

        let events = recorder.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, COMPONENT_ERROR_EVENT_TYPE);
        assert_eq!(ev.payload["error_type"], "hook-failure");
        let msg = ev.payload["message"].as_str().unwrap();
        assert!(msg.len() <= ERROR_MESSAGE_ECHO_MAX + "…".len());
        assert!(msg.ends_with("…"));
    }

    #[test]
    fn error_payload_short_message_unmodified() {
        let recorder = Arc::new(RecordingBus::default());
        let sink: Arc<dyn EventBusEmit> = recorder.clone();
        emit_component_error(Some(&sink), "w-2", "watcher", "boom");
        let events = recorder.events.lock().unwrap();
        assert_eq!(events[0].payload["message"], "boom");
    }
}
