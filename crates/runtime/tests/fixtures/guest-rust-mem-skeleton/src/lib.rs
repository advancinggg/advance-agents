//! /dev Slice S2 (2026-06-03) — memory guest fixture for the system-acceptance
//! harness's `.caps([Cap::Memory])` witness.
//!
//! Targets the `advance-host-mem` world (imports `agent-memory`, exports
//! `message-driven` + `runnable`). On `handle-message` it calls
//! `agent-memory::remember(payload, ["insight"])` then `agent-memory::recall(payload, …)`
//! — the two load-bearing host calls the harness witnesses (real `memory.remember` +
//! `memory.recall` events through the injector). The returned state encodes the
//! remembered id plus a final byte: `1` if recall returned the just-remembered entry,
//! else `0`.
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component at
//! test time via `wit_component::ComponentEncoder` (same pattern as the j01 fixture).

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-mem",
});

use advance::runtime::agent_memory;
use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct MemGuest;

impl MessageDrivenGuest for MemGuest {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let content = String::from_utf8_lossy(&msg.payload).into_owned();
        // Load-bearing host call 1: remember (emits memory.remember).
        let id = agent_memory::remember(&content, &["insight".to_string()])
            .map_err(|e| format!("remember failed: {e:?}"))?;
        // Load-bearing host call 2: recall by the same content (emits memory.recall).
        let entries = agent_memory::recall(&content, 10)
            .map_err(|e| format!("recall failed: {e:?}"))?;
        let found = entries.iter().any(|e| e.content == content);
        let mut state = id.into_bytes();
        state.push(if found { 1 } else { 0 });
        Ok(ActionResult { new_state: state, actions: Vec::new() })
    }
}

impl RunnableGuest for MemGuest {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult { status: RunStatus::Completed, output: None })
    }
}

export!(MemGuest with_types_in crate);
