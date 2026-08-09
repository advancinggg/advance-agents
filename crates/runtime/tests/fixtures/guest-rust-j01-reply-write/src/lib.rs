//! Small-witness 2026-06-11 — J-01 reply+write guest fixture (SYS-AC-003).
//!
//! A `guest-rust-j01-skeleton` copy whose `handle-message` does BOTH legs the
//! SYS-AC-003 criterion needs in one turn:
//!  1. writes ONE file via the imported `agent-fs` host fn (versioned namespace
//!     `advance:runtime/agent-fs@0.1.0`, satisfied by the host
//!     `CapabilityInjector`) — must reach cap-fs and produce exactly one
//!     `CommitType::Turn` git commit whose TREE contains the write;
//!  2. returns a NON-empty reply action (the `guest-rust-counter` pattern) so
//!     the turn's reply leg runs through the real `OutboundActionSink` dispatch
//!     seam (`.with_reply_capture()` observes it).
//!
//! No existing fixture does both — j01-skeleton writes but returns
//! `actions: Vec::new()` ("reply leg deferred"); counter/hello-llm reply but
//! never touch cap-fs. Built for `wasm32-unknown-unknown`; wrapped to a
//! Component at test time via `wit_component::ComponentEncoder`.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-fs",
});

use advance::runtime::agent_fs;
use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct ReplyWrite;

/// Path written in the agent's own territory (resolved by cap-fs's VirtualPathResolver).
const WRITE_PATH: &str = "j01.txt";
/// Default content when the inbound message carries no payload.
const DEFAULT_CONTENT: &[u8] = b"j01-reply-write";
/// The reply payload returned as the turn's first action.
const REPLY_PAYLOAD: &[u8] = b"j01-reply";
/// Witness state returned after a successful write.
const STATE_WROTE: [u8; 4] = [0xAC, 0x17, 0xF5, 0x02];

impl MessageDrivenGuest for ReplyWrite {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let content: Vec<u8> = if msg.payload.is_empty() {
            DEFAULT_CONTENT.to_vec()
        } else {
            msg.payload.clone()
        };
        match agent_fs::write(WRITE_PATH, &content) {
            Ok(()) => Ok(ActionResult {
                new_state: STATE_WROTE.to_vec(),
                // The reply leg: one non-empty action, dispatched by the agent
                // loop through the real OutboundActionSink after the turn.
                actions: vec![Action {
                    payload: REPLY_PAYLOAD.to_vec(),
                }],
            }),
            Err(e) => Err(format!("fs_write_failed: {e:?}")),
        }
    }
}

impl RunnableGuest for ReplyWrite {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(ReplyWrite with_types_in crate);
