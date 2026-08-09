//! /dev Track B (2026-06-04) — memory-lifecycle guest fixture for the
//! system-acceptance harness's `.caps([Cap::Memory])` witness of SYS-J-20.
//!
//! Targets the `advance-host-mem` world (imports `agent-memory`, exports
//! `message-driven` + `runnable`). On `handle-message` it drives the full
//! remember -> recall -> forget -> recall lifecycle through the REAL versioned
//! agent-memory host fns (`advance:runtime/agent-memory@0.1.0`):
//!   1. `remember(payload, ["insight"])`  -> emits `memory.remember`
//!   2. `recall(payload, 10)`             -> emits `memory.recall` (#1, hit)
//!   3. `forget(id)`                      -> emits `memory.forget`
//!   4. `recall(payload, 10)`             -> emits `memory.recall` (#2, miss)
//!
//! The harness witnesses the event spine (two `memory.recall` events with
//! `result_count` 1 then 0, plus `memory.forget`) for SYS-AC-060 / SYS-AC-061.
//! The returned `new_state` self-documents the lifecycle as the 4 bytes
//! `[found1, r1_len, found2, r2_len]` (mirrors the skeleton's found-flag idiom):
//! a healthy run yields `[1, 1, 0, 0]`.
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component
//! at test time via `wit_component::ComponentEncoder` (same as the mem skeleton).

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-mem",
});

use advance::runtime::agent_memory;
use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct MemSeqGuest;

impl MessageDrivenGuest for MemSeqGuest {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let content = String::from_utf8_lossy(&msg.payload).into_owned();

        // 1) remember (emits memory.remember).
        let id = agent_memory::remember(&content, &["insight".to_string()])
            .map_err(|e| format!("remember failed: {e:?}"))?;

        // 2) recall by the same content (emits memory.recall #1, result_count >= 1).
        let r1 = agent_memory::recall(&content, 10)
            .map_err(|e| format!("recall #1 failed: {e:?}"))?;
        let found1 = r1.iter().any(|e| e.content == content);

        // 3) forget the remembered entry (emits memory.forget {agent_id, memory_id}).
        agent_memory::forget(&id).map_err(|e| format!("forget failed: {e:?}"))?;

        // 4) recall again (emits memory.recall #2, result_count == 0 — entry excluded).
        let r2 = agent_memory::recall(&content, 10)
            .map_err(|e| format!("recall #2 failed: {e:?}"))?;
        let found2 = r2.iter().any(|e| e.content == content);

        // Self-documenting lifecycle witness: [found1, r1_len, found2, r2_len].
        let state = vec![found1 as u8, r1.len() as u8, found2 as u8, r2.len() as u8];
        Ok(ActionResult { new_state: state, actions: Vec::new() })
    }
}

impl RunnableGuest for MemSeqGuest {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult { status: RunStatus::Completed, output: None })
    }
}

export!(MemSeqGuest with_types_in crate);
