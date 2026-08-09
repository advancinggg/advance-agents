//! Slice m001-slice-bootstrap (2026-05-28) — Rust guest fixture targeting
//! `world advance-host-with-capabilities` (imports agent-messaging).
//!
//! Single .wasm with `config-data` switch routing for the 4 test scenarios:
//!   - default (None or unrecognized): no host-fn call; returns Ok with
//!     baseline state bytes.
//!   - `b"heartbeat"`: calls `heartbeat(Some("p"))` from handle-message OR
//!     run(); returns the witness state.
//!   - `b"await-replies"`: calls `await-replies(empty list, default opts)`
//!     to trigger fiber suspension (host-fn handler awaits oneshot).
//!   - `b"return-action"`: handle-message returns ActionResult with one
//!     action carrying payload [0xAC, 0x17, 0x01].

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

struct WithCapsAgent;

const STATE_OK: [u8; 4] = [0xAD, 0x11, 0xCE, 0x10];
const STATE_HEARTBEAT_OK: [u8; 4] = [0xAC, 0x17, 0xBE, 0xAF];
const STATE_AWAIT_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x01];
const ACTION_PAYLOAD: [u8; 3] = [0xAC, 0x17, 0x01];

fn dispatch_branch(config: &ComponentConfig) -> &'static str {
    if let Some(data) = &config.config_data {
        match data.as_slice() {
            b"heartbeat" => "heartbeat",
            b"await-replies" => "await-replies",
            b"return-action" => "return-action",
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
        _ => "default",
    }
}

impl MessageDrivenGuest for WithCapsAgent {
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
                // AC-17 Agent direct-call witness: invoke heartbeat host fn,
                // receive Ok result, return witness state.
                match agent_messaging::heartbeat(Some(&"agent-direct-call".to_string())) {
                    Ok(_) => Ok(ActionResult {
                        new_state: STATE_HEARTBEAT_OK.to_vec(),
                        actions: vec![],
                    }),
                    Err(_) => Err("heartbeat_host_fn_failed".into()),
                }
            }
            "await-replies" => {
                // M007-AC-08 fiber-suspend witness: call await-replies with
                // a single agent-request slot targeting a known agent. The
                // host-side AwaitRepliesHandler invokes
                // `manager.start_with_run` within `call_async`, suspending
                // the WASM fiber until the test driver resolves the session.
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
                    Err(_e) => {
                        // For the fiber-resume test the session resolution
                        // typically returns an Err (e.g. SessionClosed when
                        // the test driver calls manager.close), which still
                        // proves the fiber unsuspended. Return witness state.
                        Ok(ActionResult {
                            new_state: STATE_AWAIT_OK.to_vec(),
                            actions: vec![],
                        })
                    }
                }
            }
            "return-action" => {
                // AC-17 return-action witness: handle-message returns an
                // ActionResult carrying actions. The host (test driver)
                // observes the action post-return + invokes
                // AgentActionDispatcherImpl.dispatch on it.
                Ok(ActionResult {
                    new_state: STATE_OK.to_vec(),
                    actions: vec![Action {
                        payload: ACTION_PAYLOAD.to_vec(),
                    }],
                })
            }
            _ => Ok(ActionResult {
                new_state: STATE_OK.to_vec(),
                actions: vec![],
            }),
        }
    }
}

impl RunnableGuest for WithCapsAgent {
    fn run(config: ComponentConfig) -> Result<RunResult, String> {
        match dispatch_branch(&config) {
            "heartbeat" => {
                // AC-17 Runnable direct-call witness: invoke heartbeat from
                // run(), receive Ok result, return witness output.
                match agent_messaging::heartbeat(Some(&"runnable-direct-call".to_string())) {
                    Ok(_) => Ok(RunResult {
                        status: RunStatus::Completed,
                        output: Some(STATE_HEARTBEAT_OK.to_vec()),
                    }),
                    Err(_) => Err("heartbeat_host_fn_failed".into()),
                }
            }
            _ => Ok(RunResult {
                status: RunStatus::Completed,
                output: Some(STATE_OK.to_vec()),
            }),
        }
    }
}

export!(WithCapsAgent with_types_in crate);
