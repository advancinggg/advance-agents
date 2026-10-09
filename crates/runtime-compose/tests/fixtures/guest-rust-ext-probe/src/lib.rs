//! Probe guest.
//!
//! Targets the `advance-host-ext-probe` world (imports `fixture:probe/host@0.1.0`,
//! exports `message-driven` + `runnable`). On `handle-message` a payload of
//! `call <arg>` calls `call` and replies `ok:<v>` or `err:<e>`; `plain <arg>` calls
//! `call-plain` (no error slot) and replies `plain:<v>`; `trap` traps the guest
//! itself; any other payload replies `noop`. The guest never returns `Err`, so a
//! host-side error cannot poison the store.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-ext-probe",
    generate_all,
});

use advance::runtime::types::{
    Action, ActionResult, ComponentConfig, Message, RunResult, RunStatus,
};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct ProbeGuest;

impl MessageDrivenGuest for ProbeGuest {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        let line = String::from_utf8_lossy(&msg.payload);
        let payload = if let Some(arg) = line.strip_prefix("call ") {
            match fixture::probe::host::call(arg) {
                Ok(value) => format!("ok:{value}"),
                Err(error) => format!("err:{error}"),
            }
        } else if let Some(arg) = line.strip_prefix("plain ") {
            format!("plain:{}", fixture::probe::host::call_plain(arg))
        } else if line == "trap" {
            core::arch::wasm32::unreachable()
        } else {
            "noop".to_string()
        };
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: vec![Action {
                payload: payload.into_bytes(),
            }],
        })
    }
}

impl RunnableGuest for ProbeGuest {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

export!(ProbeGuest with_types_in crate);
