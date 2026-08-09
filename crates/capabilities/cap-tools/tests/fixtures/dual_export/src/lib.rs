//! dual_export — mutual-exclusion-violating fixture for SYS-AC-085.
//!
//! Exports BOTH `advance:runtime/tool-exports@0.1.0` (describe + execute) AND
//! `advance:runtime/runnable@0.1.0` (run). The cap-tools validator
//! (`validate_tool_component`) rejects `has_runnable && has_any_tool_export` at
//! cold load → the binary enters the `failed` set → hidden from `list-tools` and
//! a subsequent `tool-invoke` returns `tool-error::not-found`.
//!
//! Built for `wasm32-unknown-unknown` then `wasm-tools component new` — see
//! README. The committed `../dual_export.component.wasm` lets tests load it with
//! no wasm toolchain.

wit_bindgen::generate!({
    path: "wit",
    world: "dual-export",
});

use exports::advance::runtime::runnable::Guest as RunnableGuest;
use exports::advance::runtime::tool_exports::{
    Guest as ToolGuest, MethodInfo, ToolDescription,
};

struct DualExport;

impl ToolGuest for DualExport {
    fn describe() -> ToolDescription {
        ToolDescription {
            description: "dual-export fixture: ALSO exports runnable (mutual-exclusion violation)"
                .to_string(),
            methods: vec![MethodInfo {
                name: "echo".to_string(),
                description: Some("never reached — the validator rejects this component".to_string()),
                input_schema: None,
                output_schema: None,
                idempotent: Some(true),
            }],
        }
    }

    fn execute(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        match method.as_str() {
            "echo" => Ok(params),
            other => Err(format!("method-not-found: {other}")),
        }
    }
}

impl RunnableGuest for DualExport {
    fn run() -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

export!(DualExport with_types_in crate);
