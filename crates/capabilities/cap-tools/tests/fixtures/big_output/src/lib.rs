//! big_output — `tool-exports` fixture for SYS-AC-219 (oversized-result fail-closed).
//!
//! `execute("big")` returns 2 MiB. The SYS-AC-219 witness sets a REDUCED
//! `max_result_bytes` cap (256 KiB) so this output exceeds it → the HOST's
//! result-size cap (cap-tools lazy_registry, not a guest OOM) rejects it with
//! `tool-error::output-validation-failed` and NO truncated result is returned.
//! The literal 16 MiB+ production default is NOT used: a 16 MiB+ result `list<u8>`
//! traps/times out during the component Val-boundary lift BEFORE the host size
//! check (the documented §3.6(g) limitation that also deferred the 64 MiB
//! SYS-AC-235), so the witness exercises the IDENTICAL fail-closed check at a
//! reduced cap. `small` returns a tiny output as the under-cap discriminator control.
//!
//! Built for `wasm32-unknown-unknown` then `wasm-tools component new` — see
//! README. The committed `../big_output.component.wasm` lets tests load it with
//! no wasm toolchain.

wit_bindgen::generate!({
    path: "wit",
    world: "big-output",
});

use exports::advance::runtime::tool_exports::{Guest, MethodInfo, ToolDescription};

// 2 MiB — comfortably over a reduced test `max_result_bytes` cap, and small
// enough that the result `list<u8>` lifts across the component Val boundary in
// well under the 5 s invoke timeout. (Returning the literal 16 MiB+1 default is
// blocked by the documented §3.6(g) Val-lifting limitation — a 16 MiB+ result
// list traps/times out during the lift BEFORE the host's size check; SYS-AC-219
// therefore witnesses the identical fail-closed check at a reduced cap. The same
// component Val-boundary boundary deferred the 64 MiB SYS-AC-235.)
const BIG_LEN: usize = 2 * 1024 * 1024;

struct BigOutput;

impl Guest for BigOutput {
    fn describe() -> ToolDescription {
        ToolDescription {
            description: "big-output fixture: `big` returns 2 MiB, `small` returns a few bytes"
                .to_string(),
            methods: vec![
                MethodInfo {
                    name: "big".to_string(),
                    description: Some("returns 2 MiB (> a reduced result cap)".to_string()),
                    input_schema: None,
                    output_schema: None,
                    idempotent: Some(true),
                },
                MethodInfo {
                    name: "small".to_string(),
                    description: Some("returns a few bytes (< cap, control)".to_string()),
                    input_schema: None,
                    output_schema: None,
                    idempotent: Some(true),
                },
            ],
        }
    }

    fn execute(method: String, _params: Vec<u8>) -> Result<Vec<u8>, String> {
        match method.as_str() {
            // Distinct non-zero byte so a (forbidden) truncated return would still
            // be detectably this method's output, not empty.
            "big" => Ok(vec![0xABu8; BIG_LEN]),
            "small" => Ok(b"ok".to_vec()),
            other => Err(format!("method-not-found: {other}")),
        }
    }
}

export!(BigOutput with_types_in crate);
