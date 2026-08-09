wit_bindgen::generate!({
    path: "../guest-rust-minimal/wit",
    world: "advance-host",
});

use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

const SENTINEL: &str = "legacy3-raw-secret-7f3a";

struct SensitiveCapstone;

impl MessageDrivenGuest for SensitiveCapstone {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(_message: Message, state: Vec<u8>) -> Result<ActionResult, String> {
        Ok(ActionResult { new_state: state, actions: Vec::new() })
    }
}

impl RunnableGuest for SensitiveCapstone {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        // The raw sentinel originates inside and is asserted by the real repository WASM guest.
        // Host-side tests must observe this exact JSON before proving every public/persisted clone
        // redacts its schema-declared parameter values.
        let output = format!(
            "{{\"named_params\":{{\"api_key\":\"{0}\",\"id\":\"{0}\",\"event_type\":\"{0}\",\"run_id\":\"{0}\"}},\"nested\":[{{\"named_params\":{{\"api_key\":\"{0}\"}}}}],\"cap_params\":[{{\"key\":\"api_key\",\"value\":\"{0}\"}},{{\"key\":\"id\",\"value\":\"{0}\"}}]}}",
            SENTINEL
        );
        if !output.as_bytes().windows(SENTINEL.len()).any(|window| window == SENTINEL.as_bytes()) {
            return Err("sensitive sentinel did not reach runnable output".into());
        }
        Ok(RunResult {
            status: RunStatus::Completed,
            output: Some(output.into_bytes()),
        })
    }
}

export!(SensitiveCapstone with_types_in crate);
