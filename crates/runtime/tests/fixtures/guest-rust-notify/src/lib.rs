//! Wave-20 Lane `messagingabi` (2026-06-27) — Rust guest fixture targeting
//! `world advance-host-with-capabilities` that IMPORTS + CALLS the `notify`
//! host fns (M006-AC-02/AC-15).
//!
//! A faithful sibling of `guest-rust-send`. Branches (selected via the `state`
//! arg on handle-message, seeded from `init`'s returned bytes which come from
//! `config_data`):
//!   - `b"notify-agent"`: handle-message calls
//!     `notify::notify_agent("agent:target", NOTIFY_PAYLOAD, None)`. Because the
//!     guest's core module actually CALLS notify-agent, the encoded component
//!     IMPORTS notify-agent, so `instantiate_pre` requires the linker to provide
//!     it — exercising the Wave-20 `register_typed_notify_agent` injector path.
//!     On Ok → witness state; on Err → a guest Err so the test sees the fault.
//!   - `b"notify-channel"`: calls
//!     `notify::notify_channel("channel:test", "user:bob", NOTIFY_PAYLOAD, None)`.
//!   - default: returns the OK sentinel (no host call).

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-with-capabilities",
});

use advance::runtime::notify;
use advance::runtime::agent_messaging::MessageContext;
use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct NotifyAgent;

const STATE_OK: [u8; 4] = [0xAD, 0x11, 0xCE, 0x10];
// The notify witness payload + witness states. The cli test
// (`notify_host_fn.rs`) registers a target agent, drives this guest's
// notify-agent call, and asserts the payload lands in the target's REAL mailbox.
const NOTIFY_PAYLOAD: [u8; 4] = [0x07, 0x1F, 0xAB, 0x01];
const SECRET_PAYLOAD: &[u8] = b"AKIAEXAMPLE123456789";
const STATE_NOTIFY_AGENT_OK: [u8; 4] = [0x07, 0x1F, 0x0A, 0x01];
const STATE_NOTIFY_CHANNEL_OK: [u8; 4] = [0x07, 0x1F, 0x0C, 0x01];
const STATE_NOTIFY_AGENT_FULL: [u8; 4] = [0x07, 0x1F, 0xF0, 0x01];
const STATE_NOTIFY_AGENT_BLOCKED: [u8; 4] = [0x07, 0x1F, 0xB0, 0x01];
const STATE_NOTIFY_CHANNEL_BLOCKED: [u8; 4] = [0x07, 0x1F, 0xB0, 0x02];

// The notify-agent target — a registered agent. The cli test owns a target
// under the canonical colon id "agent:target".
const NOTIFY_AGENT_TARGET: &str = "agent:target";
const NOTIFY_AGENT_DEFAULT: &str = "agent:default";
const NOTIFY_AGENT_HARNESS: &str = "agent:harness";
const NOTIFY_AGENT_UNKNOWN: &str = "agent:does-not-exist";
const NOTIFY_CHANNEL_ID: &str = "channel:test";
const NOTIFY_CHANNEL_USER: &str = "user:bob";

fn branch(state: &[u8]) -> &'static str {
    match state {
        b"notify-agent" => "notify-agent",
        b"notify-agent-default" => "notify-agent-default",
        b"notify-agent-harness" => "notify-agent-harness",
        b"notify-agent-harness-full" => "notify-agent-harness-full",
        b"notify-agent-harness-context" => "notify-agent-harness-context",
        b"notify-agent-unknown" => "notify-agent-unknown",
        b"notify-agent-secret" => "notify-agent-secret",
        b"notify-channel" => "notify-channel",
        b"notify-channel-secret" => "notify-channel-secret",
        _ => "default",
    }
}

fn notify_scan_blocked(e: &notify::NotifyError) -> bool {
    match e {
        notify::NotifyError::InvalidTarget(reason) => reason.contains("NotifyOutbound"),
        _ => false,
    }
}

fn notify_context() -> MessageContext {
    MessageContext {
        task_id: Some("task-175".to_string()),
        run_id: Some("run-175".to_string()),
        execution_id: Some("exec-175".to_string()),
    }
}

fn completed(output: &[u8]) -> RunResult {
    RunResult {
        status: RunStatus::Completed,
        output: Some(output.to_vec()),
    }
}

fn notify_agent_run(
    target: &str,
    payload: &[u8],
    context: Option<MessageContext>,
) -> Result<RunResult, String> {
    match notify::notify_agent(target, payload, context.as_ref()) {
        Ok(()) => Ok(completed(&STATE_NOTIFY_AGENT_OK)),
        Err(_e) => Err("notify_agent_host_fn_returned_err".into()),
    }
}

impl MessageDrivenGuest for NotifyAgent {
    fn init(config: ComponentConfig) -> Result<Vec<u8>, String> {
        if let Some(data) = &config.config_data {
            return Ok(data.clone());
        }
        Ok(STATE_OK.to_vec())
    }

    fn handle_message(_msg: Message, state: Vec<u8>) -> Result<ActionResult, String> {
        match branch(&state) {
            "notify-agent" => match notify::notify_agent(NOTIFY_AGENT_TARGET, &NOTIFY_PAYLOAD, None) {
                Ok(()) => Ok(ActionResult {
                    new_state: STATE_NOTIFY_AGENT_OK.to_vec(),
                    actions: vec![],
                }),
                Err(_e) => Err("notify_agent_host_fn_returned_err".into()),
            },
            "notify-channel" => {
                match notify::notify_channel(
                    NOTIFY_CHANNEL_ID,
                    NOTIFY_CHANNEL_USER,
                    &NOTIFY_PAYLOAD,
                    None,
                ) {
                    Ok(()) => Ok(ActionResult {
                        new_state: STATE_NOTIFY_CHANNEL_OK.to_vec(),
                        actions: vec![],
                    }),
                    Err(_e) => Err("notify_channel_host_fn_returned_err".into()),
                }
            }
            _ => Ok(ActionResult {
                new_state: STATE_OK.to_vec(),
                actions: vec![],
            }),
        }
    }
}

impl RunnableGuest for NotifyAgent {
    fn run(config: ComponentConfig) -> Result<RunResult, String> {
        let intent = config.config_data.unwrap_or_default();
        match branch(&intent) {
            "notify-agent" => notify_agent_run(NOTIFY_AGENT_TARGET, &NOTIFY_PAYLOAD, None),
            "notify-agent-default" => notify_agent_run(NOTIFY_AGENT_DEFAULT, &NOTIFY_PAYLOAD, None),
            "notify-agent-harness" => notify_agent_run(NOTIFY_AGENT_HARNESS, &NOTIFY_PAYLOAD, None),
            "notify-agent-harness-full" => {
                match notify::notify_agent(NOTIFY_AGENT_HARNESS, &NOTIFY_PAYLOAD, None) {
                    Ok(()) => Err("notify_agent_full_unexpected_ok".into()),
                    Err(notify::NotifyError::MailboxFull) => Ok(completed(&STATE_NOTIFY_AGENT_FULL)),
                    Err(_e) => Err("notify_agent_full_wrong_error".into()),
                }
            }
            "notify-agent-harness-context" => {
                notify_agent_run(NOTIFY_AGENT_HARNESS, &NOTIFY_PAYLOAD, Some(notify_context()))
            }
            "notify-agent-unknown" => {
                match notify::notify_agent(NOTIFY_AGENT_UNKNOWN, &NOTIFY_PAYLOAD, None) {
                    Ok(()) => Err("notify_agent_unknown_unexpected_ok".into()),
                    Err(notify::NotifyError::InvalidTarget(reason))
                        if reason == "target_unknown" =>
                    {
                        Ok(completed(&STATE_NOTIFY_AGENT_OK))
                    }
                    Err(_e) => Err("notify_agent_unknown_wrong_error".into()),
                }
            }
            "notify-agent-secret" => {
                match notify::notify_agent(NOTIFY_AGENT_DEFAULT, SECRET_PAYLOAD, None) {
                    Ok(()) => Err("notify_agent_secret_unexpected_ok".into()),
                    Err(e) if notify_scan_blocked(&e) => {
                        Ok(completed(&STATE_NOTIFY_AGENT_BLOCKED))
                    }
                    Err(_e) => Err("notify_agent_secret_wrong_error".into()),
                }
            }
            "notify-channel" => {
                match notify::notify_channel(
                    NOTIFY_CHANNEL_ID,
                    NOTIFY_CHANNEL_USER,
                    &NOTIFY_PAYLOAD,
                    None,
                ) {
                    Ok(()) => Ok(completed(&STATE_NOTIFY_CHANNEL_OK)),
                    Err(_e) => Err("notify_channel_host_fn_returned_err".into()),
                }
            }
            "notify-channel-secret" => {
                match notify::notify_channel(
                    NOTIFY_CHANNEL_ID,
                    NOTIFY_CHANNEL_USER,
                    SECRET_PAYLOAD,
                    None,
                ) {
                    Ok(()) => Err("notify_channel_secret_unexpected_ok".into()),
                    Err(e) if notify_scan_blocked(&e) => {
                        Ok(completed(&STATE_NOTIFY_CHANNEL_BLOCKED))
                    }
                    Err(_e) => Err("notify_channel_secret_wrong_error".into()),
                }
            }
            _ => Ok(RunResult {
                status: RunStatus::Completed,
                output: Some(STATE_OK.to_vec()),
            }),
        }
    }
}

export!(NotifyAgent with_types_in crate);
