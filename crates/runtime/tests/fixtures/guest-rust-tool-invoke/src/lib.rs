//! Wave-14 Lane C (SYS-AC-080) — L2 skill-tool-invoke guest fixture.
//!
//! Imports BOTH `agent-tools` (tool-invoke) AND `agent-fs` (write) via the
//! `advance-host-tools-fs` world. `handle-message` UNCONDITIONALLY invokes the
//! skill-bundled tool at the PRD §12.4.4 canonical id `skill::echo-skill`:
//!
//!   tool-invoke("skill::echo-skill", "echo", PAYLOAD)
//!     - Ok(bytes) -> agent-fs::write("tool-result.bin", &bytes); state = STATE_TOOL_OK
//!     - Err(_)    -> state = STATE_TOOL_ERR (NO write)
//!
//! The witness reads "tool-result.bin" back via the real `fs.read` host-fn and
//! asserts the bytes == a real registry `execute` of the same tool (the committed
//! `echo_tool` returns its params verbatim). Discriminators (080-b / 080-c): with
//! no production bridge, OR an unregistered tool-id, `tool-invoke` returns
//! not-found -> no file is written.
//!
//! The tool-id is HARDCODED (not parameterized) because `handle-message(msg, state)`
//! carries no `config-data` — that field lives on `component-config`, passed only to
//! `init`/`run`, so a message-driven guest has no per-turn tool-id selector. The
//! discriminators vary the input at the HARNESS level (seed name match/mismatch;
//! bridge run/not-run), never via the guest.
//!
//! Built for `wasm32-unknown-unknown`; wrapped to a Component at test time via
//! `wit_component::ComponentEncoder`.

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host-tools-fs",
});

use advance::runtime::agent_fs;
use advance::runtime::agent_tools;
use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

struct ToolInvokeAgent;

/// The skill-bundled tool's canonical registry id (PRD §12.4.4 `skill::{name}`) —
/// must match the skill the witness materializes (`echo-skill`) once the
/// production bridge registers its `tool.wasm` sidecar.
const TOOL_ID: &str = "skill::echo-skill";
/// The echo tool's method (the committed `echo_tool` exports `execute("echo",p)==p`).
const METHOD: &str = "echo";
/// A distinctive non-trivial payload — the echo tool returns it verbatim, so the
/// witness asserts the written file == PAYLOAD == a real registry execute.
const PAYLOAD: &[u8] = &[
    0x5E, 0xC0, 0x80, 0x17, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xAC, 0x08, 0x00, 0xFF, 0x42, 0x5A,
];
/// Where the executed bytes land (read back by the witness via `fs.read`).
const RESULT_PATH: &str = "tool-result.bin";

/// Witness states (distinct per outcome so the host can discriminate).
const STATE_TOOL_OK: [u8; 4] = [0x70, 0x01, 0x08, 0x00]; // tool-invoke Ok -> wrote result
const STATE_TOOL_ERR: [u8; 4] = [0x70, 0x01, 0xE2, 0x20]; // tool-invoke Err -> no write
const STATE_OK: [u8; 4] = [0xAD, 0x11, 0xCE, 0x10];

impl MessageDrivenGuest for ToolInvokeAgent {
    fn init(config: ComponentConfig) -> Result<Vec<u8>, String> {
        if let Some(data) = &config.config_data {
            return Ok(data.clone());
        }
        Ok(STATE_OK.to_vec())
    }

    fn handle_message(_msg: Message, _state: Vec<u8>) -> Result<ActionResult, String> {
        // L2: invoke the skill-bundled tool through the production `tool-invoke`
        // host-fn -> the bridged `LazyToolRegistry` -> the real component `execute`.
        match agent_tools::tool_invoke(TOOL_ID, METHOD, PAYLOAD) {
            Ok(bytes) => match agent_fs::write(RESULT_PATH, &bytes) {
                Ok(()) => Ok(ActionResult {
                    new_state: STATE_TOOL_OK.to_vec(),
                    actions: vec![],
                }),
                Err(e) => Err(format!("fs_write_failed: {e:?}")),
            },
            // not-found / any tool-error -> no write; the witness sees the absent
            // file + the ERR state (the 080-b/080-c discriminators).
            Err(_e) => Ok(ActionResult {
                new_state: STATE_TOOL_ERR.to_vec(),
                actions: vec![],
            }),
        }
    }
}

impl RunnableGuest for ToolInvokeAgent {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: Some(STATE_OK.to_vec()),
        })
    }
}

export!(ToolInvokeAgent with_types_in crate);
