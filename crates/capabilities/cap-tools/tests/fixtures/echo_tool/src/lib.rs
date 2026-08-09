//! echo_tool — minimal `tool-exports` fixture for cap-tools in-WASM tests.
//!
//! Exports `advance:runtime/tool-exports@0.1.0` (CONTRACT-163):
//!   - `describe()` → one method `echo` (idempotent).
//!   - `execute("echo", params)` → `Ok(params)` (echoes input bytes verbatim).
//!   - `execute(other, _)` → `Err("method-not-found: <other>")`.
//!
//! Built for `wasm32-unknown-unknown` (no WASI imports) then converted to a
//! component via `wasm-tools component new` — see README.md. The pre-built
//! artifact is committed at `../echo_tool.component.wasm` so cap-tools tests
//! load a real component without any wasm toolchain (mirrors the existing
//! `guest-rust-minimal.core.wasm` fixture pattern).

wit_bindgen::generate!({
    path: "wit",
    world: "echo-tool",
});

use exports::advance::runtime::tool_exports::{Guest, MethodInfo, ToolDescription};

struct EchoTool;

impl Guest for EchoTool {
    fn describe() -> ToolDescription {
        ToolDescription {
            description: "echo tool fixture: returns input params unchanged".to_string(),
            methods: vec![MethodInfo {
                name: "echo".to_string(),
                description: Some("returns the params bytes unchanged".to_string()),
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

export!(EchoTool with_types_in crate);
