//! Shared test fixtures for cap-tools integration-test binaries (Slice F).
//!
//! Integration tests under `tests/` each compile as a separate binary, so this
//! `tests/common/mod.rs` is included via `mod common;` to share emit sinks.

use std::sync::Mutex;

use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck};

/// Records every emitted event for assertion.
#[derive(Default)]
pub struct RecordingEmitter {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for RecordingEmitter {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

impl RecordingEmitter {
    /// Snapshot of the recorded events.
    pub fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    /// Ordered list of `event_type` strings.
    #[allow(dead_code)] // used by some test binaries; `common` is compiled per-binary
    pub fn types(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }
}

/// No-op emit sink.
#[allow(dead_code)] // used by some test binaries; `common` is compiled per-binary
#[derive(Default)]
pub struct NoopEmitter;

impl EventBusEmit for NoopEmitter {
    fn emit(&self, _event: Event) {}
}

/// Wave-11 Lane C — no-op repetition guard for tests that construct
/// `AgentToolsInvokeHandler` directly but don't exercise repetition (always
/// `Pass`). Mirrors the production `NoopRepetitionGuard` the byte-identical
/// 3-arg `register_agent_tools` delegates to.
#[allow(dead_code)]
#[derive(Default)]
pub struct NoopGuard;

impl RepetitionGuardCheck for NoopGuard {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _agent_id: &str, _output_hash: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}
