//! schema_tool — `tool-exports` fixture that DECLARES an input JSON schema.
//!
//! For SYS-AC-084: a `tool-invoke` whose input violates the declared schema is
//! rejected with `tool-error::input-validation-failed` and `execute` is NEVER
//! run (the cap-tools input gate fires before `execute_in_wasm`). The `check`
//! method declares `input-schema` requiring an object with a numeric `x`:
//!   - valid input (e.g. `{"x":1}`) → execute runs → echoes the bytes;
//!   - invalid input (e.g. `{"y":1}` or non-JSON) → gate fails, execute skipped.
//!
//! Built for `wasm32-unknown-unknown` then `wasm-tools component new` — see
//! README. The committed `../schema_tool.component.wasm` lets tests load it
//! with no wasm toolchain (mirrors echo_tool).

wit_bindgen::generate!({
    path: "wit",
    world: "schema-tool",
});

use exports::advance::runtime::tool_exports::{Guest, MethodInfo, ToolDescription};

struct SchemaTool;

impl Guest for SchemaTool {
    fn describe() -> ToolDescription {
        ToolDescription {
            description: "schema tool fixture: input-schema requires {x:number}".to_string(),
            methods: vec![MethodInfo {
                name: "check".to_string(),
                description: Some("echoes params; input gated by JSON schema".to_string()),
                input_schema: Some(
                    r#"{"type":"object","properties":{"x":{"type":"number"}},"required":["x"],"additionalProperties":false}"#
                        .to_string(),
                ),
                output_schema: None,
                idempotent: Some(true),
            }],
        }
    }

    fn execute(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        match method.as_str() {
            // The host already validated the input against the declared schema
            // before reaching here, so execute just echoes (observable proof that
            // execute RAN on the valid path; on the invalid path it is never hit).
            "check" => Ok(params),
            other => Err(format!("method-not-found: {other}")),
        }
    }
}

export!(SchemaTool with_types_in crate);
