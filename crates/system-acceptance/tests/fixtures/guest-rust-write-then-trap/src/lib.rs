//! /dev Wave-19 Lane 4 (2026-06-26) — write-then-trap guest for SYS-AC-028.
//!
//! Targets the `advance-host-fs` world (imports `agent-fs`, exports `message-driven` +
//! `runnable`). Its `handle-message`:
//!   1. performs ONE `agent-fs::write` of a witness file at the territory ROOT
//!      (a BARE filename — so cap-fs creates exactly one `<territory>/.meta.yaml` sidecar,
//!      keeping the rollback sink's single-sidecar cleanup exact), then
//!   2. ALWAYS returns `Err`.
//!
//! The production `AgentLoopDriverImpl::run_turn_once` maps the `Err` to `TrapError::Crash`
//! → `handle_trap`, which (after the crash cascade) invokes the wired `WorkspaceRollbackSink`.
//! Because cap-fs commits each write synchronously (`CommitType::Turn`) BEFORE the trap, the
//! witness file is genuinely committed — so the rollback has a REAL committed write to
//! compensate (anti-fake-green; distinct from `guest-rust-trap`, which never writes). The
//! axis-off control (no `.with_workspace_rollback()`) proves the file would otherwise persist.
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component at test time
//! via `build_agent::encode_core_to_component`. Derived from `guest-rust-trap` (same WIT +
//! world) by adding the `agent-fs::write` call before the trap.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-fs",
});

use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

/// The witness file, written at the territory root (BARE filename). The 028 oracle asserts
/// this blob is ABSENT from the child territory's HEAD-committed subtree after rollback, and
/// PRESENT under the axis-off control.
const WITNESS_PATH: &str = "child-out.txt";
const WITNESS_BYTES: &[u8] = b"wave19-028-write-then-trap";

struct WriteThenTrap;

impl MessageDrivenGuest for WriteThenTrap {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    /// Write the witness file (genuinely committed per-write by cap-fs), THEN trap. The write
    /// result is intentionally not unwrapped — even on a write error the guest still traps, so
    /// the trap path is reached regardless; the witness's axis-off control independently proves
    /// the write succeeded + persisted, making the rollback's absence non-vacuous.
    fn handle_message(_msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let _ = advance::runtime::agent_fs::write(WITNESS_PATH, WITNESS_BYTES);
        Err("intentional guest trap after write: handle_message traps".to_string())
    }
}

impl RunnableGuest for WriteThenTrap {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(WriteThenTrap with_types_in crate);
