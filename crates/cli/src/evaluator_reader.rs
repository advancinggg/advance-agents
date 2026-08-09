//! Production evaluator-executing [`ComponentMetricReader`] — the SYS-AC-201
//! witness-floor seam (Wave-14 Lane B).
//!
//! [`ExecutingComponentMetricReader`] is the CONCRETE evaluator-executing
//! `ComponentMetricReader` that MODULE-015 §3.6 install-point (a) recorded as
//! "does NOT exist". It REALLY RUNS a resolved evaluator runnable component and
//! reads its `output_key` metric — closing the guardrail-metric→crash chain at
//! the product level so [`crate::crash_coordinator::run_guarded_iteration`]'s
//! guardrail branch can drive a real crash from a real evaluator output (NOT a
//! hand-fed value).
//!
//! ## Why an async factory + a sync trait method
//!
//! [`ComponentMetricReader::read_component_metric`] is **synchronous**, but
//! executing a WASM component (`instantiate_advance_host_async` + `call_run`) is
//! **async** AND `run_guarded_iteration` calls the reader from inside its own
//! async/tokio context — a `block_on` inside the sync trait method would panic
//! (nested runtime). So the reader **pre-executes** the evaluator once in the
//! async factory [`ExecutingComponentMetricReader::run`], caches the parsed
//! output JSON, and the sync `read_component_metric` is then a pure in-memory
//! JSON lookup.
//!
//! ## Contract
//!
//! - **Binary normalization** — mirrors `start.rs`'s `is_core_module`
//!   (`\0asm` magic + version byte `0x01` = `wasm32` core module, `0x0d` =
//!   component-model): `PackEvaluatorResolver` forwards `res.binary` RAW and the
//!   pack manifest does NOT guarantee component-model bytes, but
//!   `load_component`→`Component::from_binary` rejects a bare core module — so
//!   the reader encodes a core module via `build_agent::encode_core_to_component`
//!   before loading, and passes an already-encoded Component through unchanged.
//! - **No-caps execution** — instantiates over the import-free `advance-host`
//!   world via `instantiate_advance_host_async` (no `CapabilityInjector`). A
//!   cap-bearing evaluator (whose world IMPORTS host fns) leaves those imports
//!   unsatisfied → `LinkerTypecheck`, surfaced here fail-CLOSED as
//!   [`MetricReadError::Parse`] (the coordinator then crashes, which is the safe
//!   posture). `spec.capabilities` is therefore expected empty for this path.
//! - **Fail-CLOSED** — a trap, a `RunStatus::Failed`, a missing/oversized
//!   (`MAX_WIRE_BYTES_LEN`) output, or non-JSON output all yield
//!   [`MetricReadError::Parse`]; an absent or non-numeric/non-finite
//!   `output_key` yields [`MetricReadError::NotFound`] / [`MetricReadError::Parse`].
//!   `run_guarded_iteration` treats any `Err` as a crash (an unreadable guardrail
//!   metric must NOT silently pass).
//!
//! The metric source is the RETURNED `RunResult.output` bytes — the `advance-host`
//! world declares no WASI, so the guest cannot self-write a file; `spec.output_dir`
//! is reserved for a future best-effort host-side persist hook and is not consulted
//! for the metric.
//!
//! **Harvest hand-off (NOT built here):** the production scheduler tick-loop
//! CALLER of `run_guarded_iteration` that would construct this reader per
//! iteration (MODULE-015 §3.6 install-point (b)) — the production auto loop does
//! NOT yet execute evaluator components on its own. The reader is driven by the
//! SYS-AC-201 system-acceptance witness (the "drive-prod-fn, no-production-caller-yet"
//! precedent shared with SYS-AC-202/098/101/109).

use std::time::Duration;

use advance_runtime::wit_bindings::advance::runtime::types as wit_types;
use advance_runtime::{ComponentCtx, ComponentRuntime};
use advance_scheduler::types::MAX_WIRE_BYTES_LEN;
use advance_scheduler_auto_loop::{ComponentMetricReader, EvaluatorSpec, MetricReadError};

/// Wall-clock budget for a single evaluator `run()` execution. The host engine
/// uses a COOPERATIVE epoch yield (not a hard trap) and host components run with
/// fuel disabled, so a non-terminating evaluator (`run()` tight-loops) would
/// otherwise hang the reader — and the future production tick-loop caller —
/// indefinitely (adversarial round-8 DoS finding). On elapse the `call_run`
/// future is dropped (its `Store` torn down) and the read fails-CLOSED →
/// `run_guarded_iteration` crashes the iteration. Generous because a no-caps
/// pure-compute evaluator should finish in well under a second.
const EVALUATOR_RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// A [`ComponentMetricReader`] backed by a single real execution of a resolved
/// evaluator runnable component. Built via the async [`Self::run`] factory; the
/// sync `read_component_metric` reads the cached output JSON.
pub struct ExecutingComponentMetricReader {
    /// The parsed JSON the evaluator's `run()` returned (its `RunResult.output`).
    output: serde_json::Value,
}

impl ExecutingComponentMetricReader {
    /// Execute `spec`'s evaluator runnable component ONCE over `runtime` and
    /// capture its output JSON. `component_id` / `trace_id` stamp the
    /// `ComponentCtx` (capability attribution); a no-caps evaluator never uses
    /// them. Async because WASM instantiation + `call_run` are async; call this
    /// BEFORE handing the reader to the synchronous guardrail branch.
    pub async fn run(
        runtime: &ComponentRuntime,
        spec: &EvaluatorSpec,
        component_id: &str,
        trace_id: &str,
    ) -> Result<Self, MetricReadError> {
        // 0) No-caps path: this reader instantiates over the import-free
        // `advance-host` world (no `CapabilityInjector`). A cap-bearing evaluator
        // would leave its host-fn imports unsatisfied; reject it explicitly +
        // fail-CLOSED rather than relying on a later opaque `LinkerTypecheck`
        // trap (adversarial round-8: make the capability trust boundary loud).
        if !spec.capabilities.is_empty() {
            return Err(MetricReadError::Parse(format!(
                "evaluator declares {} capability/-ies, but the no-caps execution path supports \
                 only capability-free evaluators (cap injection is a future install-point)",
                spec.capabilities.len()
            )));
        }

        // 1) Normalize core module -> Component (robust to raw pack bytes).
        let component_bytes = normalize_to_component(&spec.binary)?;

        // 2) Compile + instantiate over the import-free `advance-host` world.
        let loaded = runtime.load_component(&component_bytes).map_err(|e| {
            MetricReadError::Parse(format!("evaluator component failed to load: {e:?}"))
        })?;
        let ctx = ComponentCtx::new(component_id.to_string(), trace_id.to_string(), Vec::new());
        // The component's start function (if any) runs DURING instantiation under the
        // same cooperative-yield epoch model as `run()`, so a non-terminating start
        // would hang here BEFORE the call_run timeout — bound it too (adversarial r9 W1).
        let instantiate = runtime.instantiate_advance_host_async(&loaded, ctx);
        let (bindings, mut store) = tokio::time::timeout(EVALUATOR_RUN_TIMEOUT, instantiate)
            .await
            .map_err(|_elapsed| {
                MetricReadError::Parse(format!(
                    "evaluator instantiation exceeded the {}s time budget (non-terminating start function)",
                    EVALUATOR_RUN_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| {
                MetricReadError::Parse(format!("evaluator failed to instantiate: {e:?}"))
            })?;

        // 3) Run the evaluator. `call_run` is two-arg (`&mut store`, `&cfg`) and
        //    double-Result: the OUTER layer is a wasmtime trap, the INNER layer is
        //    the WIT `result<run-result, string>`. Both fail-CLOSED.
        let cfg = wit_types::ComponentConfig {
            id: component_id.to_string(),
            config_data: None,
            trigger_context: None,
        };
        let call = bindings
            .advance_runtime_runnable()
            .call_run(&mut store, &cfg);
        let run_result = tokio::time::timeout(EVALUATOR_RUN_TIMEOUT, call)
            .await
            .map_err(|_elapsed| {
                MetricReadError::Parse(format!(
                    "evaluator run exceeded the {}s time budget (non-terminating component)",
                    EVALUATOR_RUN_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| MetricReadError::Parse(format!("evaluator run trapped: {e:?}")))?
            .map_err(|e| {
                MetricReadError::Parse(format!(
                    "evaluator run returned error: {}",
                    truncate_guest_text(&e)
                ))
            })?;

        // 4) Require a Completed run with bounded, present output.
        match run_result.status {
            wit_types::RunStatus::Completed => {}
            wit_types::RunStatus::Failed(msg) => {
                return Err(MetricReadError::Parse(format!(
                    "evaluator reported a failure status: {}",
                    truncate_guest_text(&msg)
                )));
            }
        }
        let bytes = run_result.output.ok_or_else(|| {
            MetricReadError::Parse("evaluator produced no output to read a metric from".to_string())
        })?;
        if bytes.len() > MAX_WIRE_BYTES_LEN {
            return Err(MetricReadError::Parse(format!(
                "evaluator output {} bytes exceeds MAX_WIRE_BYTES_LEN ({MAX_WIRE_BYTES_LEN})",
                bytes.len()
            )));
        }

        // 5) Parse the returned bytes as JSON (the metric source).
        let output: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            MetricReadError::Parse(format!("evaluator output is not valid JSON: {e}"))
        })?;
        Ok(Self { output })
    }
}

/// Discriminate a `wasm32` core module from an encoded Component by the binary
/// header (mirrors `start.rs::is_core_module`: shared `\0asm` magic, version
/// byte `0x01` = core, `0x0d` = component-model) and encode a core module via
/// `build_agent::encode_core_to_component`. An already-encoded Component (or any
/// non-core buffer, so `load_component` surfaces the real parse error) passes
/// through unchanged.
fn normalize_to_component(binary: &[u8]) -> Result<Vec<u8>, MetricReadError> {
    let is_core_module = binary.len() >= 8 && &binary[0..4] == b"\0asm" && binary[4] == 0x01;
    if is_core_module {
        build_agent::encode_core_to_component(binary).map_err(|e| {
            MetricReadError::Parse(format!("evaluator core module failed to encode: {e:?}"))
        })
    } else {
        Ok(binary.to_vec())
    }
}

/// Truncate a guest-controlled string to a bounded prefix (char-boundary safe)
/// before embedding it in an error message, so a hostile multi-MB `run()` inner
/// error / `Failed` payload cannot amplify into a large transient error
/// allocation (adversarial round-9 W2). Downstream `close_iteration` additionally
/// sanitizes + caps the crash reason; this bounds the in-reader allocation too.
fn truncate_guest_text(s: &str) -> String {
    const MAX_GUEST_TEXT: usize = 200;
    if s.len() <= MAX_GUEST_TEXT {
        return s.to_string();
    }
    let mut end = MAX_GUEST_TEXT;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes total, truncated)", &s[..end], s.len())
}

/// A bounded, constant-size label for a JSON value's kind — used in error
/// messages instead of the value itself, so a hostile/oversized non-numeric
/// metric value cannot amplify into a large transient error string.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

impl ComponentMetricReader for ExecutingComponentMetricReader {
    fn read_component_metric(&self, output_key: &str) -> Result<f64, MetricReadError> {
        let value = self
            .output
            .get(output_key)
            .ok_or_else(|| MetricReadError::NotFound(output_key.to_string()))?;
        let metric = value.as_f64().ok_or_else(|| {
            // Do NOT embed the raw JSON value: an attacker-sized non-numeric value
            // (e.g. a multi-MB string) would amplify into a large transient error
            // string (adversarial round-8). The key + bounded type label suffice.
            MetricReadError::Parse(format!(
                "metric `{output_key}` is not a JSON number (got a {})",
                json_kind(value)
            ))
        })?;
        if !metric.is_finite() {
            return Err(MetricReadError::Parse(format!(
                "metric `{output_key}` is non-finite: {metric}"
            )));
        }
        Ok(metric)
    }
}
