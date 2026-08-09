//! /dev WS-B (2026-06-04) — `hello-llm` reference guest.
//!
//! The FIRST real `wasm32-unknown-unknown` guest that calls the LLM. It targets the
//! `advance-host-llm` world (imports `agent-llm`, exports `message-driven` + `runnable`).
//! On `handle-message` it reads `msg.payload` as the prompt and calls the imported
//! `agent-llm` `generate` host fn (provided dynamically by the host `CapabilityInjector`
//! under the **versioned** namespace `advance:runtime/agent-llm@0.1.0`), then returns the
//! LLM response `text` as the payload of a single `action`. This is the load-bearing host
//! call the loopback turn test witnesses: it must reach cap-llm's gateway and round-trip
//! the scripted reply back through the WASM linker.
//!
//! Built for `wasm32-unknown-unknown`; the core module is wrapped to a Component (in
//! production via the `build-agent` tool; at test time via `wit_component::ComponentEncoder`
//! — same pattern as `guest-rust-j01-skeleton`). The host instantiates it through the
//! existing `advance-host-with-capabilities` bindgen — only the EXPORTS
//! (`message-driven`/`runnable`) must match; the `agent-llm` IMPORT is satisfied by the
//! linker (the injector), not the host bindgen world.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-llm",
});

use advance::runtime::agent_llm::{self, LlmRequest};
use advance::runtime::types::{Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct HelloLlm;

/// Prompt used when the inbound message carries no payload. The host
/// `decode_llm_request` fails closed on an empty prompt, so the guest MUST never send
/// one — this fallback keeps a payload-less trigger turn well-formed.
const DEFAULT_PROMPT: &str = "hello";

impl MessageDrivenGuest for HelloLlm {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        // Read the inbound payload as the prompt; fall back to a non-empty default so the
        // request always satisfies cap-llm's empty-prompt rejection.
        let prompt = String::from_utf8(msg.payload.clone()).unwrap_or_default();
        let prompt = if prompt.trim().is_empty() {
            DEFAULT_PROMPT.to_string()
        } else {
            prompt
        };

        // The one load-bearing host call: invoke `agent-llm` `generate`. Must reach
        // cap-llm's gateway through the CapabilityInjector + WASM linker.
        let request = LlmRequest {
            task_id: None,
            prompt,
            params: None,
            output_schema: None,
        };
        match agent_llm::generate(&request) {
            Ok(response) => Ok(ActionResult {
                new_state: Vec::new(),
                // Carry the LLM response text out as a single action payload — the witness
                // the loopback turn test asserts on.
                actions: vec![Action {
                    payload: response.text.into_bytes(),
                }],
            }),
            Err(e) => Err(format!("llm_generate_failed: {e:?}")),
        }
    }
}

impl RunnableGuest for HelloLlm {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(HelloLlm with_types_in crate);
