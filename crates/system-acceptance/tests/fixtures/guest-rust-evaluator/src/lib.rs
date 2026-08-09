//! Wave-14 Lane B (2026-06-24) — runnable evaluator fixture for SYS-AC-201.
//!
//! Targets the import-free `advance-host` world (exports `message-driven` +
//! `runnable`), mirroring `guest-rust-minimal`, so the production no-injector
//! `instantiate_advance_host_async` path links it cleanly. Its `run()` returns a
//! JSON metric object `{"score": <N>}` in `RunResult.output`; the production
//! `ExecutingComponentMetricReader` parses `output_key = "score"` from those bytes.
//!
//! The score lives ONLY inside the compiled WASM (NOT fed by the host), so a
//! reader that didn't actually execute this binary cannot know it — the two
//! committed variants (default 0.95 / `--features low` 0.40) bind the metric to
//! the real run (anti-fake-green). 0.95 BREACHES a `Gt 0.8` guardrail (→ crash);
//! 0.40 does not (→ no crash).

wit_bindgen::generate!({
    path: "wit",
    world: "advance-host",
});

use advance::runtime::types::{ActionResult, ComponentConfig, Message, RunResult, RunStatus};
use exports::advance::runtime::message_driven::Guest as MessageDrivenGuest;
use exports::advance::runtime::runnable::Guest as RunnableGuest;

/// The metric this evaluator scores. Compiled into the binary; `--features low`
/// selects the non-breaching discriminator value.
#[cfg(not(feature = "low"))]
const SCORE_JSON: &[u8] = br#"{"score":0.95}"#;
#[cfg(feature = "low")]
const SCORE_JSON: &[u8] = br#"{"score":0.40}"#;

struct Evaluator;

impl MessageDrivenGuest for Evaluator {
    fn init(_config: ComponentConfig) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn handle_message(_msg: Message, state: Vec<u8>) -> Result<ActionResult, String> {
        // The evaluator is run via `run()`, not the message path; a trivial
        // no-op keeps the `advance-host` world's `message-driven` export satisfied.
        Ok(ActionResult {
            new_state: state,
            actions: Vec::new(),
        })
    }
}

impl RunnableGuest for Evaluator {
    fn run(_config: ComponentConfig) -> Result<RunResult, String> {
        // Return the scored metric as JSON bytes — the value the host-side
        // `ExecutingComponentMetricReader` parses for `output_key`.
        Ok(RunResult {
            status: RunStatus::Completed,
            output: Some(SCORE_JSON.to_vec()),
        })
    }
}

export!(Evaluator with_types_in crate);
