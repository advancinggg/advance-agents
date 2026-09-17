//! clock_tool — `tool-exports` fixture that reads the WASI wall clock.
//!
//! - `describe()` → one method `now` (not idempotent: it reads a clock).
//! - `execute("now", _)` → RFC 3339 text of `SystemTime::now()` (seconds resolution, `Z`).
//! - `execute(other, _)` → `Err("method-not-found: <other>")`.
//!
//! Under `LazyToolRegistry::invoke_deterministic` the host freezes the wall clock, so `now`
//! returns the injected instant; under the ordinary `invoke` it returns the system clock.
//! Built for `wasm32-wasip2` — see README.md; the committed
//! `../clock_tool.component.wasm` lets cap-tools tests load it without a wasm toolchain.

wit_bindgen::generate!({
    path: "wit",
    world: "clock-tool",
});

use exports::advance::runtime::tool_exports::{Guest, MethodInfo, ToolDescription};

struct ClockTool;

impl Guest for ClockTool {
    fn describe() -> ToolDescription {
        ToolDescription {
            description: "clock tool fixture: returns the wall clock as RFC 3339".to_string(),
            methods: vec![MethodInfo {
                name: "now".to_string(),
                description: Some("current wall-clock time".to_string()),
                input_schema: None,
                output_schema: None,
                idempotent: Some(false),
            }],
        }
    }

    fn execute(method: String, _params: Vec<u8>) -> Result<Vec<u8>, String> {
        match method.as_str() {
            "now" => {
                let since_epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| format!("clock before epoch: {e}"))?;
                let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(since_epoch.as_secs() as i64, 0)
                    .ok_or_else(|| "timestamp out of range".to_string())?;
                Ok(dt
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    .into_bytes())
            }
            other => Err(format!("method-not-found: {other}")),
        }
    }
}

export!(ClockTool with_types_in crate);
