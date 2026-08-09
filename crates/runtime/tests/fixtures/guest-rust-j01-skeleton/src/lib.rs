//! /dev Slice BS-3 (2026-06-03) — J-01 skeleton guest fixture.
//!
//! Targets the `advance-host-fs` world (imports `agent-fs`, exports
//! `message-driven` + `runnable`). On `handle-message` it writes ONE file via the
//! imported `agent-fs` host fn (provided dynamically by the host
//! `CapabilityInjector` under the **versioned** namespace
//! `advance:runtime/agent-fs@0.1.0`) and returns an empty action. This is the
//! single load-bearing host call the system-acceptance harness witnesses: it must
//! reach cap-fs and produce exactly one `CommitType::Turn` git commit.
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component at
//! test time via `wit_component::ComponentEncoder` (same pattern as
//! `guest-rust-minimal` / `guest-rust-with-caps`). The host instantiates it through
//! the existing `advance-host-with-capabilities` bindgen — only the EXPORTS
//! (`message-driven`/`runnable`) must match; the `agent-fs` IMPORT is satisfied by
//! the linker (the injector), not the host bindgen world.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-fs",
});

use advance::runtime::agent_fs;
use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct Skeleton;

/// Path written in the agent's own territory (resolved by cap-fs's VirtualPathResolver).
const WRITE_PATH: &str = "j01.txt";
/// Default content when the inbound message carries no payload.
const DEFAULT_CONTENT: &[u8] = b"j01-skeleton";
/// Witness state returned after a successful write.
const STATE_WROTE: [u8; 4] = [0xAC, 0x17, 0xF5, 0x01];

impl MessageDrivenGuest for Skeleton {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        // The one load-bearing host call: write the inbound payload (or a default
        // marker) to a single file. Must reach cap-fs -> git Turn commit.
        let content: Vec<u8> = if msg.payload.is_empty() {
            DEFAULT_CONTENT.to_vec()
        } else {
            msg.payload.clone()
        };
        match agent_fs::write(WRITE_PATH, &content) {
            Ok(()) => Ok(ActionResult {
                new_state: STATE_WROTE.to_vec(),
                // The reply leg is deferred (SYS-AC-001); the gate-only dispatcher
                // would not deliver a reply anyway. Return no actions.
                actions: Vec::new(),
            }),
            Err(e) => Err(format!("fs_write_failed: {e:?}")),
        }
    }
}

impl RunnableGuest for Skeleton {
    /// sched-harvest 1B: echo the received `trigger-context` (when present)
    /// into the run output as `event_type|chain_id|depth`, so an e2e witness
    /// can prove the GUEST genuinely received a populated context
    /// (SYS-AC-101) — a host-side conversion that silently dropped the
    /// context (the message-driven path's historic posture) would fail the
    /// witness. A `None` context (the cron shape, SYS-AC-098) keeps the
    /// pre-1B `output: None`, so every earlier caller observes identical
    /// behavior.
    fn run(config: ComponentConfig) -> Result<RunResult, String> {
        let output = config.trigger_context.map(|tc| {
            format!(
                "{}|{}|{}",
                tc.event_type, tc.trigger_chain_id, tc.chain_depth
            )
            .into_bytes()
        });
        Ok(RunResult {
            status: RunStatus::Completed,
            output,
        })
    }
}

export!(Skeleton with_types_in crate);
