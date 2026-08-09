//! Wave-11 Lane A (SYS-AC-014/018/251) — await-park + fs-write guest fixture.
//!
//! Imports BOTH `agent-messaging` (await-replies) AND `agent-fs` (write) via the
//! `advance-host-messaging-fs` world; both are satisfied dynamically by the host
//! `CapabilityInjector` under their versioned namespaces. `handle-message`
//! dispatches on the `state` arg (the host passes routing intent via `init`'s
//! returned bytes, which become the next `handle-message`'s `state` — the
//! `guest-rust-with-caps` convention):
//!
//!   - `b"await-write"` [014/018]: `await-replies([agent:test-target], AllOf,
//!     long idle)` PARKS the run. On `Ok` (a child reply resumed it) the guest
//!     performs exactly ONE `agent-fs::write` → a single `CommitType::Turn`
//!     commit whose tree carries the file (014's "one turn commit"). On `Err`
//!     (the await session was closed by pause/cancel) the guest returns WITHOUT
//!     writing → no commit, filesystem unchanged (018).
//!   - `b"await-partial"` [251]: `await-replies([agent:test-target], AllOf,
//!     ReturnPartial, SHORT idle)` PARKS, then the REAL per-session idle monitor
//!     resolves `Ok(PartialTimeout)` past the idle timeout → the parent fiber
//!     resumes and the turn completes. No write (251's criterion has no
//!     turn-commit conjunct).
//!
//! Built for `wasm32-unknown-unknown`; wrapped to a Component at test time via
//! `wit_component::ComponentEncoder`.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-messaging-fs",
});

use advance::runtime::agent_fs;
use advance::runtime::agent_messaging::{
    self, AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, TimeoutPolicy,
};
use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct AwaitWriteAgent;

/// The awaited peer target (a non-ancestor sibling — ADR-compliant, not a deadlock edge).
const TARGET: &str = "agent:test-target";
/// File written in the agent's own territory after a reply-driven resume (014).
const WRITE_PATH: &str = "await-out.txt";
const WRITE_BODY: &[u8] = b"await-resumed-write";

/// Witness states (distinct per branch/outcome so the host can discriminate).
const STATE_AWAIT_WRITE_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x77]; // 014: resumed by reply -> wrote
const STATE_AWAIT_INTERRUPTED: [u8; 4] = [0xAC, 0x01, 0x18, 0x00]; // 018: session-closed -> no write
const STATE_AWAIT_PARTIAL_OK: [u8; 4] = [0xAC, 0x02, 0x51, 0x01]; // 251: idle ReturnPartial -> resumed
const STATE_OK: [u8; 4] = [0xAD, 0x11, 0xCE, 0x10];

fn branch(state: &[u8]) -> &'static str {
    match state {
        b"await-write" => "await-write",
        b"await-partial" => "await-partial",
        _ => "default",
    }
}

fn one_agent_request(corr: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: TARGET.to_string(),
        payload: vec![1, 2, 3],
        correlation_id: corr.to_string(),
        context: None,
    })
}

impl MessageDrivenGuest for AwaitWriteAgent {
    fn init(config: ComponentConfig) -> Result<Vec<u8>, String> {
        // Routing intent in config_data becomes the initial state, consumed by
        // the next handle-message (the with-caps convention).
        if let Some(data) = &config.config_data {
            return Ok(data.clone());
        }
        Ok(STATE_OK.to_vec())
    }

    fn handle_message(_msg: Message, state: Vec<u8>) -> Result<ActionResult, String> {
        match branch(&state) {
            "await-write" => {
                // Park (AllOf, long idle). Resumed by a child reply (Ok) -> write
                // one file; closed by pause/cancel (Err) -> return without writing.
                let opts = AwaitOptions {
                    mode: AwaitMode::AllOf,
                    idle_timeout_secs: Some(3600),
                    on_idle_timeout: TimeoutPolicy::Fail,
                    keep_losers: false,
                };
                match agent_messaging::await_replies(&[one_agent_request("await-write-corr")], opts) {
                    Ok(_result) => match agent_fs::write(WRITE_PATH, WRITE_BODY) {
                        Ok(()) => Ok(ActionResult {
                            new_state: STATE_AWAIT_WRITE_OK.to_vec(),
                            actions: vec![],
                        }),
                        Err(e) => Err(format!("fs_write_failed: {e:?}")),
                    },
                    Err(_e) => Ok(ActionResult {
                        // Interrupted (session-closed): NO write -> no turn commit (018).
                        new_state: STATE_AWAIT_INTERRUPTED.to_vec(),
                        actions: vec![],
                    }),
                }
            }
            "await-partial" => {
                // Park (ReturnPartial, SHORT idle). The real idle monitor resolves
                // Ok(PartialTimeout) past the timeout -> resume. No write (251).
                let opts = AwaitOptions {
                    mode: AwaitMode::AllOf,
                    idle_timeout_secs: Some(1),
                    on_idle_timeout: TimeoutPolicy::ReturnPartial,
                    keep_losers: false,
                };
                // Either resolution (Ok PartialTimeout, or any Err) proves the
                // fiber unsuspended; return the partial-resume witness state.
                let _ =
                    agent_messaging::await_replies(&[one_agent_request("await-partial-corr")], opts);
                Ok(ActionResult {
                    new_state: STATE_AWAIT_PARTIAL_OK.to_vec(),
                    actions: vec![],
                })
            }
            _ => Ok(ActionResult {
                new_state: STATE_OK.to_vec(),
                actions: vec![],
            }),
        }
    }
}

impl RunnableGuest for AwaitWriteAgent {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: Some(STATE_OK.to_vec()),
        })
    }
}

export!(AwaitWriteAgent with_types_in crate);
