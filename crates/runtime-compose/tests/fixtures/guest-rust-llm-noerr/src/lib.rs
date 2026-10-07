//! Never-`Err` LLM guest: same WIT world as `guest-rust-hello-llm`, but
//! `handle-message` always returns `Ok` so a host-side LLM error cannot poison
//! the store.
//!
//! Payload `llm:<p>` uses `<p>` as the prompt; any other payload uses the whole
//! text. An empty prompt falls back to `hello`. The action is `llm-ok:<text>`
//! or `llm-err:<e:?>`.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-llm",
});

use advance::runtime::agent_llm::{self, LlmRequest};
use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct LlmNoErr;

const DEFAULT_PROMPT: &str = "hello";

impl MessageDrivenGuest for LlmNoErr {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let raw = String::from_utf8(msg.payload).unwrap_or_default();
        let prompt = raw.strip_prefix("llm:").unwrap_or(raw.as_str());
        let prompt = if prompt.trim().is_empty() {
            DEFAULT_PROMPT.to_string()
        } else {
            prompt.to_string()
        };
        let request = LlmRequest {
            task_id: None,
            prompt,
            params: None,
            output_schema: None,
        };
        let payload = match agent_llm::generate(&request) {
            Ok(response) => format!("llm-ok:{}", response.text),
            Err(error) => format!("llm-err:{error:?}"),
        };
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: vec![Action {
                payload: payload.into_bytes(),
            }],
        })
    }
}

impl RunnableGuest for LlmNoErr {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(LlmNoErr with_types_in crate);
