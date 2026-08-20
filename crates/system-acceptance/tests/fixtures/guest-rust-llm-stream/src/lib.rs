//! SYS-J-72 stream guest: `handle-message` calls `agent-llm` `%stream` then
//! `poll-stream` until `done`. Action payload is concat of `chunk.delta` while
//! `!done` only — never `response.text` on the done chunk (AC-30: `claim_done`
//! re-serves the full buffer).

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-llm",
});

use advance::runtime::agent_llm::{self, LlmRequest};
use advance::runtime::types::{Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct StreamGuest;

const DEFAULT_PROMPT: &str = "hello";

impl MessageDrivenGuest for StreamGuest {
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
        let handle = agent_llm::stream(&request).map_err(|e| format!("llm_stream_failed: {e:?}"))?;
        let mut acc = String::new();
        loop {
            let chunk = agent_llm::poll_stream(handle)
                .map_err(|e| format!("llm_poll_failed: {e:?}"))?;
            if let Some(delta) = chunk.delta.as_ref() {
                if !chunk.done {
                    acc.push_str(delta);
                }
            }
            if chunk.done {
                break;
            }
        }
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: vec![Action {
                payload: acc.into_bytes(),
            }],
        })
    }
}

impl RunnableGuest for StreamGuest {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(StreamGuest with_types_in crate);
