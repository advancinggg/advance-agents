//! await-leg B-3 (2026-06-22) — Rust guest fixture targeting
//! `world advance-host-with-capabilities` that IMPORTS + CALLS the
//! agent-messaging `send` host fn.
//!
//! This is a dedicated clone of `guest-rust-with-caps` with one added branch:
//!   - `b"send"`: handle-message calls
//!     `send("agent:parent", SEND_PAYLOAD, None)`. Because the guest's core
//!     module actually CALLS `send`, the encoded component IMPORTS `send`, so
//!     `instantiate_pre` requires the linker to provide it — exercising the
//!     `crates/messaging/reply-tracker/src/host_fn.rs:769-778` LinkerTypecheck
//!     gap that B-3 closes. (The shared `guest-rust-with-caps` deliberately does
//!     NOT call `send`, so its import is tree-shaken and its co-instantiating
//!     tests stay green.)
//!
//! Other branches mirror `guest-rust-with-caps` so the fixture stays a faithful
//! sibling (default / `b"heartbeat"` / `b"await-replies"` / `b"return-action"`).
//! The `progress-result` and `progress-error` branches are repository-owned
//! CONTRACT-215 witnesses: each returns three ordinary payload-only Actions
//! carrying the reserved `ADVPRG\0` v1 envelope, with no WIT widening.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-with-capabilities",
});

use advance::runtime::agent_messaging::{
    self, AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, TimeoutPolicy,
};
use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct SendAgent;

const STATE_OK: [u8; 4] = [0xAD, 0x11, 0xCE, 0x10];
const STATE_HEARTBEAT_OK: [u8; 4] = [0xAC, 0x17, 0xBE, 0xAF];
const STATE_AWAIT_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x01];
const ACTION_PAYLOAD: [u8; 3] = [0xAC, 0x17, 0x01];

// await-leg B-3: the `send` witness payload + witness state. The cli test
// (`send_host_fn.rs`) seeds a parent await session expecting this child, then
// asserts the resolved reply payload == SEND_PAYLOAD (proving the send routed
// through the production ingress into `on_reply`).
const SEND_PAYLOAD: [u8; 4] = [0x5E, 0x4D, 0xB3, 0x01];
const STATE_SEND_OK: [u8; 4] = [0x5E, 0x4D, 0x0C, 0x01];

// The send target — the awaiting parent. The cli test owns a parent session
// under agent id "parent" (canonical "agent:parent").
const SEND_TARGET: &str = "agent:parent";

fn progress_action(body: &[u8], phase: &str, value: Option<&str>) -> Action {
    let metadata_count = 1 + usize::from(value.is_some());
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ADVPRG\0");
    payload.extend_from_slice(&[1, 0, 0]);
    payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
    payload.extend_from_slice(&(metadata_count as u16).to_be_bytes());
    payload.extend_from_slice(body);
    for (key, metadata_value) in
        core::iter::once(("progress.phase", phase)).chain(value.map(|v| ("progress.value", v)))
    {
        payload.extend_from_slice(&(key.len() as u16).to_be_bytes());
        payload.extend_from_slice(&(metadata_value.len() as u32).to_be_bytes());
        payload.extend_from_slice(key.as_bytes());
        payload.extend_from_slice(metadata_value.as_bytes());
    }
    Action { payload }
}

fn progress_actions(terminal_phase: &str) -> Vec<Action> {
    vec![
        progress_action(b"Accepted", "ack", None),
        progress_action(b"Working", "progress", Some("0.5")),
        progress_action(
            if terminal_phase == "result" {
                b"Completed"
            } else {
                b"Failed"
            },
            terminal_phase,
            None,
        ),
    ]
}

fn dispatch_branch(config: &ComponentConfig) -> &'static str {
    if let Some(data) = &config.config_data {
        match data.as_slice() {
            b"heartbeat" => "heartbeat",
            b"await-replies" => "await-replies",
            b"return-action" => "return-action",
            b"send" => "send",
            b"progress-result" => "progress-result",
            b"progress-error" => "progress-error",
            _ => "default",
        }
    } else {
        "default"
    }
}

fn dispatch_branch_from_state(state: &[u8]) -> &'static str {
    // The host can pass routing intent via the `state` arg on handle-message
    // (since `init` returns the initial state).
    match state {
        b"heartbeat" => "heartbeat",
        b"await-replies" => "await-replies",
        b"return-action" => "return-action",
        b"send" => "send",
        b"progress-result" => "progress-result",
        b"progress-error" => "progress-error",
        _ => "default",
    }
}

impl MessageDrivenGuest for SendAgent {
    fn init(config: ComponentConfig) -> Result<Vec<u8>, String> {
        // The init's returned bytes become the next handle-message's `state`,
        // which the message-driven loop consumes. To let tests select the
        // handle-message branch, pass the routing intent in config_data.
        if let Some(data) = &config.config_data {
            return Ok(data.clone());
        }
        Ok(STATE_OK.to_vec())
    }

    fn handle_message(_msg: Message, state: Vec<u8>) -> Result<ActionResult, String> {
        match dispatch_branch_from_state(&state) {
            "heartbeat" => {
                match agent_messaging::heartbeat(Some(&"agent-direct-call".to_string())) {
                    Ok(_) => Ok(ActionResult {
                        new_state: STATE_HEARTBEAT_OK.to_vec(),
                        actions: vec![],
                    }),
                    Err(_) => Err("heartbeat_host_fn_failed".into()),
                }
            }
            "await-replies" => {
                let req = AwaitRequest::AgentRequest(AgentAwaitRequest {
                    target: "agent:test-target".to_string(),
                    payload: vec![1, 2, 3],
                    correlation_id: "test-corr".to_string(),
                    context: None,
                });
                let opts = AwaitOptions {
                    mode: AwaitMode::AllOf,
                    idle_timeout_secs: Some(60),
                    on_idle_timeout: TimeoutPolicy::Fail,
                    keep_losers: false,
                };
                match agent_messaging::await_replies(&[req], opts) {
                    Ok(_result) => Ok(ActionResult {
                        new_state: STATE_AWAIT_OK.to_vec(),
                        actions: vec![],
                    }),
                    Err(_e) => Ok(ActionResult {
                        new_state: STATE_AWAIT_OK.to_vec(),
                        actions: vec![],
                    }),
                }
            }
            "send" => {
                // await-leg B-3 witness: call the `send` host fn (child→parent
                // reply). With a seeded parent await session expecting this
                // child, the host routes the payload into `on_reply` and `send`
                // returns Ok. Return the witness state on Ok; surface a guest
                // Err if `send` itself errored (so the test sees a routing fault).
                match agent_messaging::send(SEND_TARGET, &SEND_PAYLOAD, None) {
                    Ok(()) => Ok(ActionResult {
                        new_state: STATE_SEND_OK.to_vec(),
                        actions: vec![],
                    }),
                    Err(_e) => Err("send_host_fn_returned_err".into()),
                }
            }
            "return-action" => Ok(ActionResult {
                new_state: STATE_OK.to_vec(),
                actions: vec![Action {
                    payload: ACTION_PAYLOAD.to_vec(),
                }],
            }),
            "progress-result" => Ok(ActionResult {
                new_state: STATE_OK.to_vec(),
                actions: progress_actions("result"),
            }),
            "progress-error" => Ok(ActionResult {
                new_state: STATE_OK.to_vec(),
                actions: progress_actions("error"),
            }),
            _ => Ok(ActionResult {
                new_state: STATE_OK.to_vec(),
                actions: vec![],
            }),
        }
    }
}

impl RunnableGuest for SendAgent {
    fn run(config: ComponentConfig) -> Result<RunResult, String> {
        match dispatch_branch(&config) {
            "heartbeat" => {
                match agent_messaging::heartbeat(Some(&"runnable-direct-call".to_string())) {
                    Ok(_) => Ok(RunResult {
                        status: RunStatus::Completed,
                        output: Some(STATE_HEARTBEAT_OK.to_vec()),
                    }),
                    Err(_) => Err("heartbeat_host_fn_failed".into()),
                }
            }
            "send" => match agent_messaging::send(SEND_TARGET, &SEND_PAYLOAD, None) {
                Ok(()) => Ok(RunResult {
                    status: RunStatus::Completed,
                    output: Some(STATE_SEND_OK.to_vec()),
                }),
                Err(_e) => Err("send_host_fn_returned_err".into()),
            },
            _ => Ok(RunResult {
                status: RunStatus::Completed,
                output: Some(STATE_OK.to_vec()),
            }),
        }
    }
}

export!(SendAgent with_types_in crate);
