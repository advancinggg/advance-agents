//! SYS-J-72 abandon guest: `handle-message` calls `agent-llm` `%stream` and
//! returns immediately without polling, so the live stream is unconsumed when
//! the turn ends (SYS-AC-308 Terminal(Reaped)).

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-llm",
});

use advance::runtime::agent_llm::{self, LlmRequest};
use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct AbandonGuest;

const DEFAULT_PROMPT: &str = "hello";

impl MessageDrivenGuest for AbandonGuest {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let prompt = String::from_utf8(msg.payload.clone()).unwrap_or_default();
        let prompt = if prompt.trim().is_empty() {
            DEFAULT_PROMPT.to_string()
        } else {
            prompt
        };
        let request = LlmRequest {
            task_id: None,
            prompt,
            params: None,
            output_schema: None,
        };
        let _handle =
            agent_llm::stream(&request).map_err(|e| format!("llm_stream_failed: {e:?}"))?;
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: Vec::new(),
        })
    }
}

impl RunnableGuest for AbandonGuest {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(AbandonGuest with_types_in crate);
