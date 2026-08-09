//! /dev Phase-2 Step-3 — stateful counter guest fixture (SYS-AC-263 / SYS-AC-264).
//!
//! Targets `world advance-host` — exports `message-driven` + `runnable`, imports
//! NOTHING (no host capability). On each `handle-message` it:
//! 1. reads the counter from the **host-passed `state` argument** (empty → 0),
//! 2. increments,
//! 3. returns `ActionResult { new_state = (n+1) little-endian, actions = [reply] }`
//!    where the reply payload is the new counter value as a decimal string.
//!
//! **Witness-floor (SYS-AC-264)**: the reply derives ONLY from the `state` arg,
//! never from a guest `static`/global — there is NO mutable module state here.
//! The daemon reuses one Wasmtime Store across turns, so guest linear memory
//! also persists; a memory-derived counter would FALSELY witness cross-turn
//! state. The opaque `state` blob alone carries the value (proven additionally
//! by the harness fresh-Store-seeded continuation for SYS-AC-264).
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component
//! at test time (`build_agent::encode_core_to_component`).

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host",
});

use advance::runtime::types::{Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct Counter;

impl MessageDrivenGuest for Counter {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        // Initial state: counter 0 (empty blob; handle_message treats empty as 0).
        Ok(Vec::new())
    }

    fn handle_message(_msg: Message, state: Vec<u8>) -> Result<ActionResult, String> {
        // Read the counter from the HOST-PASSED state arg (never guest memory).
        let current: u64 = if state.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&state);
            u64::from_le_bytes(b)
        } else {
            // Empty / unexpected → start from 0.
            0
        };
        let next = current.saturating_add(1);
        Ok(ActionResult {
            new_state: next.to_le_bytes().to_vec(),
            // The reply is the new counter value as a decimal string — observable
            // by the OutboundActionSink / reply registry across turns.
            actions: vec![Action {
                payload: next.to_string().into_bytes(),
            }],
        })
    }
}

impl RunnableGuest for Counter {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(Counter with_types_in crate);
