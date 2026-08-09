//! MAINLINE Wave-5 harvest (2026-06-21) — trapping guest for SYS-AC-029.
//!
//! Targets the `advance-host-fs` world (exports `message-driven` + `runnable`).
//! Its `handle-message` ALWAYS returns `Err`. The production
//! `AgentLoopDriverImpl::run_turn_once` maps a `handle_message` `Err(Failure)`
//! to `TrapError::Crash` and calls `handle_trap` (scheduler agent_loop.rs:328-330)
//! → which emits a `component.error` event via the wired
//! `with_component_error_emitter` and applies the configured `RestartPolicy`. So
//! this is a REAL guest trap, distinct from the harness mock `TrappingHandler`.
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component
//! at test time via `build_agent::encode_core_to_component`.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-fs",
});

use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct Trap;

impl MessageDrivenGuest for Trap {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    /// ALWAYS trap: a real guest failure on every turn. The host's run_turn_once
    /// treats this Err as a trap-equivalent → handle_trap → component.error.
    fn handle_message(_msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        Err("intentional guest trap: handle_message is unreachable".to_string())
    }
}

impl RunnableGuest for Trap {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(Trap with_types_in crate);
