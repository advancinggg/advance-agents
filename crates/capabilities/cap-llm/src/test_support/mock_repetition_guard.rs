//! Test fixture: `MockRepetitionGuard` for Slice D AC-16 tests.
//!
//! Implements `advance_shared_types::traits::RepetitionGuardCheck` (CONTRACT-072)
//! with three configurable policies:
//! - `AlwaysPass`           — every `record_output` returns `Pass` (the default).
//! - `WarnOnce`             — first `record_output` returns `Warn`, then Pass.
//! - `TerminateOnce(reason)` — first `record_output` returns `Terminate(reason)`,
//!                             then Pass (allows test code to assert exactly one
//!                             Terminate observation).
//!
//! `record_tool_call` is unused by cap-llm but provided as a no-op `Pass` to
//! satisfy the trait surface (MODULE-017 cap-tools consumes the tool-call
//! method per shared-types::repetition rustdoc).
//!
//! All `record_output` calls are recorded into a `Mutex<Vec<(agent_id, OutputHash)>>`
//! so tests can assert call counts.

#![cfg(test)]

use std::sync::{Arc, Mutex};

use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::traits::RepetitionGuardCheck;

#[derive(Clone)]
pub(crate) enum RepGuardPolicy {
    AlwaysPass,
    WarnOnce,
    TerminateOnce(String),
}

pub(crate) struct MockRepetitionGuard {
    policy: RepGuardPolicy,
    record_output_calls: Mutex<Vec<(String, OutputHash)>>,
    fired_count: Mutex<u32>,
}

impl MockRepetitionGuard {
    pub(crate) fn new(policy: RepGuardPolicy) -> Self {
        Self {
            policy,
            record_output_calls: Mutex::new(Vec::new()),
            fired_count: Mutex::new(0),
        }
    }

    #[allow(dead_code)] // test-support surface: suites consume this accessor selectively
    pub(crate) fn record_output_calls(&self) -> Vec<(String, OutputHash)> {
        self.record_output_calls.lock().unwrap().clone()
    }

    pub(crate) fn record_output_call_count(&self) -> usize {
        self.record_output_calls.lock().unwrap().len()
    }
}

impl RepetitionGuardCheck for MockRepetitionGuard {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }

    fn record_output(&self, agent_id: &str, output_hash: OutputHash) -> RepetitionDecision {
        self.record_output_calls
            .lock()
            .unwrap()
            .push((agent_id.to_string(), output_hash.clone()));
        let mut fired = self.fired_count.lock().unwrap();
        *fired += 1;
        let fired_now = *fired;
        match &self.policy {
            RepGuardPolicy::AlwaysPass => RepetitionDecision::Pass,
            RepGuardPolicy::WarnOnce => {
                if fired_now == 1 {
                    RepetitionDecision::Warn("warn-once".into())
                } else {
                    RepetitionDecision::Pass
                }
            }
            RepGuardPolicy::TerminateOnce(reason) => {
                if fired_now == 1 {
                    RepetitionDecision::Terminate(reason.clone())
                } else {
                    RepetitionDecision::Pass
                }
            }
        }
    }
}

/// Convenience helper for fixtures that don't care about the guard's behavior —
/// returns an `Arc<MockRepetitionGuard>` with `AlwaysPass` policy.
pub(crate) fn no_op_repetition_guard() -> Arc<MockRepetitionGuard> {
    Arc::new(MockRepetitionGuard::new(RepGuardPolicy::AlwaysPass))
}
