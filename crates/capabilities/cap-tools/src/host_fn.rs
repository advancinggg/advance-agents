//! `agent-tools` host-function registration. MODULE-017 Slice B.
//!
//! Mirrors the cap-llm pattern at `crates/capabilities/cap-llm/src/host_fn.rs`:
//! decode WIT-shaped `Val` parameters, route into the
//! `Arc<dyn ToolRegistry>`, encode the result back into a WIT
//! `result<...,tool-error>`.
//!
//! Registers two `HostFunctionSpec` entries under capability `"tools"`,
//! namespace `"advance:runtime/agent-tools@0.1.0"`:
//! - `tool-invoke` → [`AgentToolsInvokeHandler`] (idempotent=false).
//! - `list-tools` → [`AgentToolsListHandler`] (idempotent=true).
//!
//! GrantCheck enforcement is the responsibility of `CapabilityInjector::inject`
//! one layer up — these handlers are pure dispatch wrappers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use advance_shared_types::capability::GrantDecision;
use advance_shared_types::repetition::{RepetitionDecision, ToolCallSignature};
use advance_shared_types::traits::{EventBusEmit, GrantCheck, RepetitionGuardCheck};
use wasmtime::component::Val;

use crate::web::{check_web_grant, is_web_tool_id, web_tool_visible, WebFamilyDispatcher};

use crate::events::{tool_error_event, tool_invoke_event, tool_result_event, ToolEventContext};
use crate::registry::{MethodInfo, ToolError, ToolInfo, ToolRegistry};

const CAPABILITY: &str = "tools";
const NAMESPACE: &str = "advance:runtime/agent-tools@0.1.0";

/// Maximum byte length for `tool-id` / `method` WIT string parameters.
/// Matches `advance_runtime::host_registry::MAX_SPEC_STRING_LEN`.
pub const MAX_TOOL_STRING_PARAM_BYTES: usize = 256;

/// Maximum bytes for the agent-supplied `params: list<u8>` field.
/// Matches the MCP/HTTP/SSE symmetric pin documented in MODULE-017 §2.11.
pub const MAX_TOOL_PARAMS_BYTES: usize = 4 * 1024 * 1024;

/// Register both `tool-invoke` and `list-tools` host functions against
/// the supplied [`HostRegistry`] under capability `"tools"`.
///
/// Wired upstream by `advance_cli::wiring::wire_capabilities` (Slice C+
/// when the CLI integrates the new registry handler).
///
/// **Slice F**: gains a third positional argument `emitter: Arc<dyn EventBusEmit>`
/// (CONTRACT-180). Both handlers emit `tool.*` observability events (PRD §15.3.16)
/// via the bare `emitter.emit(event)` trait method, closing the two cap-tools
/// entries in `observability-allowlist.toml` (MODULE-019 AC-14 lint). This is a
/// source-incompatible API break for external callers (MODULE-017 §3.6 (nn));
/// the only in-tree caller is the inline test below.
///
/// **Wave-11 Lane C**: this 3-arg form is RETAINED byte-identical (callers that
/// don't repetition-guard — the system-acceptance harness + tests — stay
/// unchanged); it delegates to [`register_agent_tools_with_guard`] with a no-op
/// guard. Production wiring that wants the CONTRACT-072 repetition guard calls
/// `register_agent_tools_with_guard` directly.
pub fn register_agent_tools(
    registry: &dyn HostRegistry,
    tools: Arc<dyn ToolRegistry>,
    emitter: Arc<dyn EventBusEmit>,
) {
    register_agent_tools_with_guard(
        registry,
        tools,
        emitter,
        Arc::new(NoopRepetitionGuard) as Arc<dyn RepetitionGuardCheck>,
    );
}

/// Wave-11 Lane C — register `tool-invoke` + `list-tools` with a CONTRACT-072
/// [`RepetitionGuardCheck`] threaded into the `tool-invoke` handler. The guard
/// is the run-manager's process-global `RepetitionGuard` (per-agent-keyed
/// sliding window), built once at the cli composition root via
/// `RunManager::build_repetition_guard_from_config` and shared here as
/// `Arc<dyn RepetitionGuardCheck>`. `list-tools` does not feed the guard
/// (read-only enumeration is not a repeatable tool invocation).
pub fn register_agent_tools_with_guard(
    registry: &dyn HostRegistry,
    tools: Arc<dyn ToolRegistry>,
    emitter: Arc<dyn EventBusEmit>,
    repetition_guard: Arc<dyn RepetitionGuardCheck>,
) {
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.to_string(),
        namespace: NAMESPACE.to_string(),
        name: "tool-invoke".to_string(),
        handler: Arc::new(AgentToolsInvokeHandler {
            tools: Arc::clone(&tools),
            emitter: Arc::clone(&emitter),
            repetition_guard,
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.to_string(),
        namespace: NAMESPACE.to_string(),
        name: "list-tools".to_string(),
        handler: Arc::new(AgentToolsListHandler { tools, emitter }),
        idempotent: true,
    });
}

/// CONTRACT-239 registrar. 3-arg/4-arg signatures stay byte-identical.
pub fn register_agent_tools_for_web(
    registry: &dyn HostRegistry,
    tools: Arc<dyn ToolRegistry>,
    emitter: Arc<dyn EventBusEmit>,
    repetition_guard: Arc<dyn RepetitionGuardCheck>,
    web_grant: Arc<dyn GrantCheck>,
    dispatcher: Option<Arc<WebFamilyDispatcher>>,
) {
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.to_string(),
        namespace: NAMESPACE.to_string(),
        name: "tool-invoke".to_string(),
        handler: Arc::new(WebAwareInvokeHandler {
            tools: Arc::clone(&tools),
            emitter: Arc::clone(&emitter),
            repetition_guard,
            web_grant: Arc::clone(&web_grant),
            dispatcher: dispatcher.clone(),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.to_string(),
        namespace: NAMESPACE.to_string(),
        name: "list-tools".to_string(),
        handler: Arc::new(WebAwareListHandler {
            tools,
            emitter,
            web_grant,
            dispatcher,
        }),
        idempotent: true,
    });
}

pub struct WebAwareInvokeHandler {
    pub tools: Arc<dyn ToolRegistry>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub repetition_guard: Arc<dyn RepetitionGuardCheck>,
    pub web_grant: Arc<dyn GrantCheck>,
    pub dispatcher: Option<Arc<WebFamilyDispatcher>>,
}

pub struct WebAwareListHandler {
    pub tools: Arc<dyn ToolRegistry>,
    pub emitter: Arc<dyn EventBusEmit>,
    pub web_grant: Arc<dyn GrantCheck>,
    pub dispatcher: Option<Arc<WebFamilyDispatcher>>,
}

/// `tool-invoke(tool-id, method, params) -> result<list<u8>, tool-error>`.
pub struct AgentToolsInvokeHandler {
    pub tools: Arc<dyn ToolRegistry>,
    /// Slice F — observability emit sink (CONTRACT-180).
    pub emitter: Arc<dyn EventBusEmit>,
    /// Wave-11 Lane C — CONTRACT-072 repetition guard fed the decoded
    /// tool-call signature after each invocation. A no-op `Pass`-only guard
    /// (`NoopRepetitionGuard`) on the 3-arg `register_agent_tools` path.
    pub repetition_guard: Arc<dyn RepetitionGuardCheck>,
}

/// Wave-11 Lane C — no-op `RepetitionGuardCheck` used by the byte-identical
/// 3-arg [`register_agent_tools`] delegation: every record returns `Pass`, so
/// callers that don't wire the run-manager guard (the system-acceptance
/// harness + tests) keep their pre-Lane-C behavior exactly.
struct NoopRepetitionGuard;

impl RepetitionGuardCheck for NoopRepetitionGuard {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(
        &self,
        _agent_id: &str,
        _output_hash: advance_shared_types::repetition::OutputHash,
    ) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}

/// Wave-11 Lane C — FNV-1a 64-bit digest of the decoded `params` bytes, the
/// `params_hash` component of [`ToolCallSignature`]. Dependency-free and
/// deterministic; the hash is only ever compared within ONE process's
/// in-memory repetition sliding window (never persisted, never sent across the
/// wire), so cross-release stability is irrelevant. Collision-resistance is
/// non-security-critical: an agent that varies its params trivially evades
/// detection, and crafting a collision only self-terminates its own run.
fn params_signature_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Wave-11 Lane C — true if any char is an ASCII/Unicode control character.
/// `shared-types::repetition` requires the producer (cap-tools) to reject or
/// sanitize newlines / `\r` / `\0` / control chars in `tool_id` / `method`
/// before constructing a [`ToolCallSignature`] (keeps the canonical `Display`
/// infallible + prevents log injection via `sig.to_string()`). We REJECT at
/// decode (fail-closed) rather than strip, to avoid signature false-merge
/// collisions (`"a\nb"` vs `"ab"`).
fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

/// `list-tools() -> result<list<tool-info>, tool-error>`.
pub struct AgentToolsListHandler {
    pub tools: Arc<dyn ToolRegistry>,
    /// Slice F — observability emit sink (CONTRACT-180).
    pub emitter: Arc<dyn EventBusEmit>,
}

/// Map a [`ToolError`] to its kebab-case `tool-error` variant tag + the fixed
/// safe-class redacted message (SB-22 discipline). Shared by both the WIT
/// encoder ([`encode_tool_error`]) and the `tool.error` event payload, so the
/// agent-facing error class and the observed `error_type` stay in lockstep.
pub(crate) fn tool_error_class(err: &ToolError) -> (&'static str, &'static str) {
    match err {
        ToolError::NotFound(_) => ("not-found", "tool not found"),
        ToolError::MethodNotFound(_) => ("method-not-found", "method not found"),
        ToolError::InvocationFailed(_) => ("invocation-failed", "invocation failed"),
        ToolError::PermissionDenied(_) => ("permission-denied", "permission denied"),
        ToolError::InputValidationFailed(_) => {
            ("input-validation-failed", "input validation failed")
        }
        ToolError::OutputValidationFailed(_) => {
            ("output-validation-failed", "output validation failed")
        }
    }
}

/// Build a [`ToolEventContext`] from the host-call context (Slice F).
fn event_ctx(ctx: &HostCallContext) -> ToolEventContext {
    ToolEventContext {
        agent_id: ctx.agent_id.clone(),
        trace_id: ctx.trace_id.clone(),
        run_id: ctx.run_id.clone(),
    }
}

impl HostFunctionHandler for AgentToolsInvokeHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let tools = Arc::clone(&self.tools);
        let emitter = Arc::clone(&self.emitter);
        let repetition_guard = Arc::clone(&self.repetition_guard);
        let ev_ctx = event_ctx(&ctx);
        Box::pin(async move {
            let decoded = match decode_invoke_params(&params) {
                Ok(d) => d,
                Err(err) => {
                    // Decode failed before the call started: emit tool.error
                    // ONLY (no preceding tool.invoke). tool_id may not have been
                    // parseable, so use the empty-string sentinel.
                    let (error_type, message) = tool_error_class(&err);
                    emitter.emit(tool_error_event(&ev_ctx, "", error_type, message));
                    return Ok(vec![encode_tool_error(&err)]);
                }
            };
            // tool.invoke at call start.
            emitter.emit(tool_invoke_event(
                &ev_ctx,
                &decoded.tool_id,
                &decoded.method,
            ));

            // Wave-11 Lane C — feed the CONTRACT-072 repetition guard with the
            // decoded tool-call signature BEFORE dispatch, so a `Terminate`
            // decision PREVENTS the Nth identical invocation's side effect
            // rather than merely suppressing its result (adversarial round-7 W1:
            // the guard is an action-prevention safety valve, not value
            // suppression — a runaway loop on a side-effecting tool must be
            // stopped before the call executes, not after). The tool-call
            // signature is INPUT-derived, so it is fully known pre-invoke (the
            // cap-llm `record_output` path records after generation only because
            // an output hash is inherently output-derived — a principled
            // per-signal difference, not an inconsistency). Every decoded call is
            // recorded (a repeated identical call to a missing/failing tool is
            // also a runaway). `tool_id`/`method` already passed the control-char
            // gate in `decode_invoke_params`, so `sig.to_string()` is
            // log-injection-safe. The guard emits `run.repetition_detected`
            // internally on the Nth identical triplet; we apply the decision:
            //   Pass | Warn -> proceed to invoke (Warn is non-fatal; the Tier-3
            //                  warn-inject is a harvest hand-off — see §3.6).
            //   Terminate   -> skip `tools.invoke()` entirely, return the generic
            //                  `invocation-failed` (cap-tools has no dedicated
            //                  `repetition-terminated` class — the
            //                  `run.repetition_detected{terminate}` event carries
            //                  the discriminating signal).
            let sig = ToolCallSignature {
                tool_id: decoded.tool_id.clone(),
                method: decoded.method.clone(),
                params_hash: params_signature_hash(&decoded.params),
            };
            if let RepetitionDecision::Terminate(_reason) =
                repetition_guard.record_tool_call(&ev_ctx.agent_id, sig)
            {
                let err = ToolError::InvocationFailed("repetition guard terminated".to_string());
                let (error_type, message) = tool_error_class(&err);
                emitter.emit(tool_error_event(
                    &ev_ctx,
                    &decoded.tool_id,
                    error_type,
                    message,
                ));
                return Ok(vec![encode_tool_error(&err)]);
            }

            let start = Instant::now();
            let result = tools
                .invoke(&decoded.tool_id, &decoded.method, &decoded.params)
                .await;
            let duration_ms = start.elapsed().as_millis() as u64;
            match &result {
                Ok(bytes) => emitter.emit(tool_result_event(
                    &ev_ctx,
                    &decoded.tool_id,
                    &decoded.method,
                    duration_ms,
                    bytes.len(),
                )),
                Err(err) => {
                    let (error_type, message) = tool_error_class(err);
                    emitter.emit(tool_error_event(
                        &ev_ctx,
                        &decoded.tool_id,
                        error_type,
                        message,
                    ));
                }
            }
            Ok(vec![encode_invoke_result(result)])
        })
    }
}

impl HostFunctionHandler for AgentToolsListHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let tools = Arc::clone(&self.tools);
        let emitter = Arc::clone(&self.emitter);
        let ev_ctx = event_ctx(&ctx);
        Box::pin(async move {
            // Read-only enumeration re-uses the canonical tool.invoke / tool.result
            // events with sentinel tool_id="" + method="list-tools" (MODULE-017
            // §3.6 (ll) — does NOT introduce a tool.list_tools event type).
            const LIST_METHOD: &str = "list-tools";
            emitter.emit(tool_invoke_event(&ev_ctx, "", LIST_METHOD));
            let start = Instant::now();
            let infos = tools.list().await;
            let duration_ms = start.elapsed().as_millis() as u64;
            emitter.emit(tool_result_event(
                &ev_ctx,
                "",
                LIST_METHOD,
                duration_ms,
                infos.len(),
            ));
            let listed: Vec<Val> = infos.iter().map(encode_tool_info).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(listed)))))])
        })
    }
}

impl HostFunctionHandler for WebAwareInvokeHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let tools = Arc::clone(&self.tools);
        let emitter = Arc::clone(&self.emitter);
        let repetition_guard = Arc::clone(&self.repetition_guard);
        let web_grant = Arc::clone(&self.web_grant);
        let dispatcher = self.dispatcher.clone();
        let ev_ctx = event_ctx(&ctx);
        let agent_id = ctx.agent_id.clone();
        Box::pin(async move {
            let decoded = match decode_invoke_params(&params) {
                Ok(d) => d,
                Err(err) => {
                    let (error_type, message) = tool_error_class(&err);
                    emitter.emit(tool_error_event(&ev_ctx, "", error_type, message));
                    return Ok(vec![encode_tool_error(&err)]);
                }
            };
            emitter.emit(tool_invoke_event(
                &ev_ctx,
                &decoded.tool_id,
                &decoded.method,
            ));
            let sig = ToolCallSignature {
                tool_id: decoded.tool_id.clone(),
                method: decoded.method.clone(),
                params_hash: params_signature_hash(&decoded.params),
            };
            if let RepetitionDecision::Terminate(_reason) =
                repetition_guard.record_tool_call(&ev_ctx.agent_id, sig)
            {
                let err = ToolError::InvocationFailed("repetition guard terminated".to_string());
                let (error_type, message) = tool_error_class(&err);
                emitter.emit(tool_error_event(
                    &ev_ctx,
                    &decoded.tool_id,
                    error_type,
                    message,
                ));
                return Ok(vec![encode_tool_error(&err)]);
            }
            if is_web_tool_id(&decoded.tool_id) {
                match check_web_grant(web_grant.as_ref(), &agent_id) {
                    GrantDecision::Deny(_) => {
                        let err = ToolError::PermissionDenied("web grant denied".into());
                        let (error_type, message) = tool_error_class(&err);
                        emitter.emit(tool_error_event(
                            &ev_ctx,
                            &decoded.tool_id,
                            error_type,
                            message,
                        ));
                        return Ok(vec![encode_tool_error(&err)]);
                    }
                    GrantDecision::Allow => {
                        let Some(disp) = dispatcher else {
                            let err = ToolError::PermissionDenied("web family withheld".into());
                            let (error_type, message) = tool_error_class(&err);
                            emitter.emit(tool_error_event(
                                &ev_ctx,
                                &decoded.tool_id,
                                error_type,
                                message,
                            ));
                            return Ok(vec![encode_tool_error(&err)]);
                        };
                        let start = Instant::now();
                        let result = disp
                            .invoke(
                                &agent_id,
                                &decoded.tool_id,
                                &decoded.method,
                                &decoded.params,
                            )
                            .await;
                        let duration_ms = start.elapsed().as_millis() as u64;
                        match &result {
                            Ok(bytes) => emitter.emit(tool_result_event(
                                &ev_ctx,
                                &decoded.tool_id,
                                &decoded.method,
                                duration_ms,
                                bytes.len(),
                            )),
                            Err(err) => {
                                let (error_type, message) = tool_error_class(err);
                                emitter.emit(tool_error_event(
                                    &ev_ctx,
                                    &decoded.tool_id,
                                    error_type,
                                    message,
                                ));
                            }
                        }
                        return Ok(vec![encode_invoke_result(result)]);
                    }
                }
            }
            let start = Instant::now();
            let result = tools
                .invoke(&decoded.tool_id, &decoded.method, &decoded.params)
                .await;
            let duration_ms = start.elapsed().as_millis() as u64;
            match &result {
                Ok(bytes) => emitter.emit(tool_result_event(
                    &ev_ctx,
                    &decoded.tool_id,
                    &decoded.method,
                    duration_ms,
                    bytes.len(),
                )),
                Err(err) => {
                    let (error_type, message) = tool_error_class(err);
                    emitter.emit(tool_error_event(
                        &ev_ctx,
                        &decoded.tool_id,
                        error_type,
                        message,
                    ));
                }
            }
            Ok(vec![encode_invoke_result(result)])
        })
    }
}

impl HostFunctionHandler for WebAwareListHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let tools = Arc::clone(&self.tools);
        let emitter = Arc::clone(&self.emitter);
        let web_grant = Arc::clone(&self.web_grant);
        let dispatcher = self.dispatcher.clone();
        let ev_ctx = event_ctx(&ctx);
        let agent_id = ctx.agent_id.clone();
        Box::pin(async move {
            const LIST_METHOD: &str = "list-tools";
            emitter.emit(tool_invoke_event(&ev_ctx, "", LIST_METHOD));
            let start = Instant::now();
            let mut infos = tools.list().await;
            let show_web =
                dispatcher.is_some() && web_tool_visible(Some(web_grant.as_ref()), &agent_id);
            if !show_web {
                infos.retain(|i| !is_web_tool_id(&i.id));
            }
            let duration_ms = start.elapsed().as_millis() as u64;
            emitter.emit(tool_result_event(
                &ev_ctx,
                "",
                LIST_METHOD,
                duration_ms,
                infos.len(),
            ));
            let listed: Vec<Val> = infos.iter().map(encode_tool_info).collect();
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::List(listed)))))])
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Decoders
// ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct InvokeParams {
    pub tool_id: String,
    pub method: String,
    pub params: Vec<u8>,
}

pub(crate) fn decode_invoke_params(params: &[Val]) -> Result<InvokeParams, ToolError> {
    if params.len() < 3 {
        return Err(ToolError::InputValidationFailed(format!(
            "tool-invoke expects 3 params, got {}",
            params.len()
        )));
    }
    let tool_id = decode_string(&params[0], "tool-id")?;
    let method = decode_string(&params[1], "method")?;
    let bytes = decode_byte_list(&params[2])?;
    if tool_id.len() > MAX_TOOL_STRING_PARAM_BYTES {
        return Err(ToolError::InputValidationFailed(format!(
            "tool-id exceeds {MAX_TOOL_STRING_PARAM_BYTES} bytes"
        )));
    }
    if method.len() > MAX_TOOL_STRING_PARAM_BYTES {
        return Err(ToolError::InputValidationFailed(format!(
            "method exceeds {MAX_TOOL_STRING_PARAM_BYTES} bytes"
        )));
    }
    if bytes.len() > MAX_TOOL_PARAMS_BYTES {
        return Err(ToolError::InputValidationFailed(format!(
            "params exceeds {MAX_TOOL_PARAMS_BYTES} bytes"
        )));
    }
    // Wave-11 Lane C — producer-side `ToolCallSignature` sanitization mandated
    // by `shared-types::repetition`: reject control chars in tool_id/method
    // BEFORE any signature construction (keeps the canonical Display infallible
    // + prevents log injection via `sig.to_string()`). Reject (not strip) to
    // avoid signature false-merge collisions.
    if has_control_chars(&tool_id) {
        return Err(ToolError::InputValidationFailed(
            "tool-id contains control characters".to_string(),
        ));
    }
    if has_control_chars(&method) {
        return Err(ToolError::InputValidationFailed(
            "method contains control characters".to_string(),
        ));
    }
    Ok(InvokeParams {
        tool_id,
        method,
        params: bytes,
    })
}

fn decode_string(val: &Val, field: &str) -> Result<String, ToolError> {
    match val {
        Val::String(s) => Ok(s.clone()),
        other => Err(ToolError::InputValidationFailed(format!(
            "{field}: expected string, got {other:?}"
        ))),
    }
}

fn decode_byte_list(val: &Val) -> Result<Vec<u8>, ToolError> {
    match val {
        Val::List(items) => {
            // Reject at the bound check BEFORE the .iter().map().collect()
            // pulls full-size allocation (round-11 W2 fix): each `Val::U8`
            // wrapper carries ~24 bytes on 64-bit, so a 4 M-element
            // `Vec<Val>` already occupies ~96 MiB of upstream lifter
            // memory; we add another `Vec<u8>` of the same length on
            // top via collect. Failing at length-check inside cap-tools
            // bounds the WIT-boundary allocation deterministically
            // before the iterator walk.
            if items.len() > MAX_TOOL_PARAMS_BYTES {
                return Err(ToolError::InputValidationFailed(format!(
                    "params exceeds {MAX_TOOL_PARAMS_BYTES} bytes"
                )));
            }
            items
                .iter()
                .map(|v| match v {
                    Val::U8(b) => Ok(*b),
                    other => Err(ToolError::InputValidationFailed(format!(
                        "params: expected list<u8>, got element {other:?}"
                    ))),
                })
                .collect()
        }
        other => Err(ToolError::InputValidationFailed(format!(
            "params: expected list<u8>, got {other:?}"
        ))),
    }
}

// ────────────────────────────────────────────────────────────────────
// Encoders
// ────────────────────────────────────────────────────────────────────

pub(crate) fn encode_invoke_result(result: Result<Vec<u8>, ToolError>) -> Val {
    match result {
        Ok(bytes) => {
            let list: Vec<Val> = bytes.iter().map(|b| Val::U8(*b)).collect();
            Val::Result(Ok(Some(Box::new(Val::List(list)))))
        }
        Err(err) => encode_tool_error(&err),
    }
}

/// Encode a `ToolError` as a WIT `result<_, tool-error>` Err arm.
///
/// **Guest-visible message redaction (round-11 W1 fix)**: the WASM
/// guest is an untrusted trust boundary; the rich `ToolError(String)`
/// payload may carry internal scope-state ("slice-B: in-WASM execute
/// deferred ..."), validator detail ("missing tool-exports: describe,
/// execute"), or future Slice B' wasmtime trap diagnostics (file paths,
/// pointer addresses, fuel state). Mirroring the cap-llm
/// `encode_llm_error` discipline at
/// `crates/capabilities/cap-llm/src/host_fn.rs:279-295`, each variant
/// is collapsed to a fixed safe class string before crossing the WIT
/// boundary. Full diagnostic context stays in host-side tracing logs
/// (out of scope for Slice B; future event-emission slice will surface
/// the rich message via the tracing pipeline).
pub(crate) fn encode_tool_error(err: &ToolError) -> Val {
    // Slice F: the (case, redacted) classification is shared with the
    // `tool.error` event payload via `tool_error_class`, so the agent-facing
    // WIT error class and the observed `error_type` stay in lockstep.
    let (case, redacted) = tool_error_class(err);
    Val::Result(Err(Some(Box::new(Val::Variant(
        case.to_string(),
        Some(Box::new(Val::String(redacted.to_string()))),
    )))))
}

pub(crate) fn encode_tool_info(info: &ToolInfo) -> Val {
    Val::Record(vec![
        ("id".into(), Val::String(info.id.clone())),
        ("description".into(), Val::String(info.description.clone())),
        (
            "methods".into(),
            Val::List(info.methods.iter().map(encode_method_info).collect()),
        ),
    ])
}

fn encode_method_info(m: &MethodInfo) -> Val {
    let opt_string = |s: &Option<String>| -> Val {
        match s {
            Some(v) => Val::Option(Some(Box::new(Val::String(v.clone())))),
            None => Val::Option(None),
        }
    };
    Val::Record(vec![
        ("name".into(), Val::String(m.name.clone())),
        ("description".into(), opt_string(&m.description)),
        ("input-schema".into(), opt_string(&m.input_schema)),
        ("output-schema".into(), opt_string(&m.output_schema)),
        (
            "idempotent".into(),
            match m.idempotent {
                Some(b) => Val::Option(Some(Box::new(Val::Bool(b)))),
                None => Val::Option(None),
            },
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::InMemoryToolRegistry;
    use advance_runtime::host_registry::InMemoryHostRegistry;
    use advance_shared_types::event::Event;
    use std::sync::Mutex;

    /// No-op emit sink for tests that don't inspect events (Slice F).
    #[derive(Default)]
    struct NoopEmitter;
    impl EventBusEmit for NoopEmitter {
        fn emit(&self, _event: Event) {}
    }

    /// Recording emit sink for tests that assert the emitted event sequence.
    #[derive(Default)]
    struct RecordingEmitter {
        events: Mutex<Vec<Event>>,
    }
    impl EventBusEmit for RecordingEmitter {
        fn emit(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }
    impl RecordingEmitter {
        fn types(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.event_type.clone())
                .collect()
        }
    }

    fn noop_emitter() -> Arc<dyn EventBusEmit> {
        Arc::new(NoopEmitter)
    }

    /// Wave-11 Lane C — no-op repetition guard for the existing inline tests
    /// (they assert decode/dispatch/emit behavior, not repetition).
    fn noop_guard() -> Arc<dyn RepetitionGuardCheck> {
        Arc::new(NoopRepetitionGuard)
    }

    // ──────────────────────────────────────────────────────────────
    // SB-22 — Redaction: WIT-encoded tool-error payload MUST be a
    //          fixed-class redacted string (not the rich rust message).
    //          Mirrors cap-llm encode_llm_error redaction discipline.
    // ──────────────────────────────────────────────────────────────
    #[test]
    fn sb_22_encode_tool_error_redacts_payload() {
        let cases = [
            (
                ToolError::NotFound("internal-tool-id-with-secret".into()),
                "not-found",
                "tool not found",
            ),
            (
                ToolError::MethodNotFound("internal-method-name".into()),
                "method-not-found",
                "method not found",
            ),
            (
                ToolError::InvocationFailed(
                    "slice-B: in-WASM execute deferred — see MODULE-017 §2.7 scope reduction"
                        .into(),
                ),
                "invocation-failed",
                "invocation failed",
            ),
            (
                ToolError::PermissionDenied("agent /usr/bin/secret".into()),
                "permission-denied",
                "permission denied",
            ),
            (
                ToolError::InputValidationFailed("schema /etc/foo.json".into()),
                "input-validation-failed",
                "input validation failed",
            ),
            (
                ToolError::OutputValidationFailed(
                    "tool result exceeds max_result_bytes ...".into(),
                ),
                "output-validation-failed",
                "output validation failed",
            ),
        ];
        for (err, expected_case, expected_payload) in cases {
            match encode_tool_error(&err) {
                Val::Result(Err(Some(boxed))) => match *boxed {
                    Val::Variant(ref case, Some(ref pl)) => {
                        assert_eq!(case, expected_case);
                        match pl.as_ref() {
                            Val::String(s) => assert_eq!(
                                s, expected_payload,
                                "expected redacted payload {expected_payload:?}, got {s:?}"
                            ),
                            other => panic!("expected Val::String payload, got {other:?}"),
                        }
                    }
                    other => panic!("expected Val::Variant(case, Some(_)), got {other:?}"),
                },
                other => panic!("expected Val::Result(Err(Some(_))), got {other:?}"),
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // SB-23 — Oversize Val::List length rejected BEFORE the .collect()
    //          allocation pulls memory proportional to the list length
    //          (round-11 W2 defense-in-depth — early bound check).
    // ──────────────────────────────────────────────────────────────
    #[test]
    fn sb_23_oversize_list_length_rejected_before_collect() {
        // Construct a Val::List whose length exceeds MAX_TOOL_PARAMS_BYTES.
        // We can't actually allocate 4M+ Val::U8 entries cheaply, so we use
        // a list of NON-U8 elements at exactly length MAX_TOOL_PARAMS_BYTES+1
        // — if the early length check fires, we get InputValidationFailed
        // with "params exceeds" message; without the early check, the iter
        // would walk the whole list, allocating ~24 bytes/entry.
        //
        // Use the smallest cheap allocation: a list of MAX_TOOL_PARAMS_BYTES+1
        // copies of a single Val::U8(0). Length-only matters; values cheap.
        let items: Vec<Val> = vec![Val::U8(0); MAX_TOOL_PARAMS_BYTES + 1];
        let params = vec![
            Val::String("t".into()),
            Val::String("m".into()),
            Val::List(items),
        ];
        let err = decode_invoke_params(&params).expect_err("must reject");
        match err {
            ToolError::InputValidationFailed(msg) => {
                assert!(msg.contains("params exceeds"), "got {msg:?}")
            }
            other => panic!("expected InputValidationFailed got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // SB-03 — Oversize params rejected at handler boundary.
    // ──────────────────────────────────────────────────────────────
    #[test]
    fn sb_03_oversize_params_rejected() {
        let bytes: Vec<Val> = (0..(MAX_TOOL_PARAMS_BYTES + 1) as usize)
            .map(|_| Val::U8(0))
            .collect();
        let params = vec![
            Val::String("tool-a".into()),
            Val::String("m".into()),
            Val::List(bytes),
        ];
        let err = decode_invoke_params(&params).expect_err("must reject");
        match err {
            ToolError::InputValidationFailed(msg) => assert!(msg.contains("params exceeds")),
            other => panic!("expected InputValidationFailed got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // SB-04 — Oversize tool-id rejected.
    // ──────────────────────────────────────────────────────────────
    #[test]
    fn sb_04_oversize_tool_id_rejected() {
        let too_long = "x".repeat(MAX_TOOL_STRING_PARAM_BYTES + 1);
        let params = vec![
            Val::String(too_long),
            Val::String("m".into()),
            Val::List(vec![]),
        ];
        let err = decode_invoke_params(&params).expect_err("must reject");
        match err {
            ToolError::InputValidationFailed(msg) => assert!(msg.contains("tool-id exceeds")),
            other => panic!("expected InputValidationFailed got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // SB-05 — register lookup returns 2 specs with correct idempotent flags.
    // ──────────────────────────────────────────────────────────────
    #[test]
    fn sb_05_register_lookup_idempotent() {
        let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
        let tools: Arc<dyn ToolRegistry> = Arc::new(InMemoryToolRegistry::new());
        register_agent_tools(&*registry, tools, noop_emitter());
        let specs = registry.lookup("tools");
        assert_eq!(specs.len(), 2);
        let mut by_name: Vec<(&str, bool)> = specs
            .iter()
            .map(|s| (s.name.as_str(), s.idempotent))
            .collect();
        by_name.sort();
        assert_eq!(by_name, vec![("list-tools", true), ("tool-invoke", false),]);
        for spec in &specs {
            assert_eq!(spec.namespace, NAMESPACE);
            assert_eq!(spec.capability, CAPABILITY);
        }
    }

    // Helper: dummy HostCallContext.
    fn dummy_ctx() -> HostCallContext {
        HostCallContext {
            agent_id: "test-agent".into(),
            trace_id: "test-trace".into(),
            turn_id: None,
            capability: CAPABILITY.into(),
            function: format!("{NAMESPACE}::tool-invoke"),
            run_id: None,
            iteration: None,
        }
    }

    // ──────────────────────────────────────────────────────────────
    // SB-01 — Tool-invoke round-trips through Val + emits result-arm
    //          even when registry returns NotFound (empty registry).
    // ──────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn sb_01_tool_invoke_round_trips_via_val() {
        let tools: Arc<dyn ToolRegistry> = Arc::new(InMemoryToolRegistry::new());
        let handler = AgentToolsInvokeHandler {
            tools,
            emitter: noop_emitter(),
            repetition_guard: noop_guard(),
        };
        let params = vec![
            Val::String("nope".into()),
            Val::String("m".into()),
            Val::List(vec![Val::U8(1), Val::U8(2)]),
        ];
        let out = handler.call(dummy_ctx(), params, 1).await.unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(case, _) => assert_eq!(case, "not-found"),
                other => panic!("expected Variant got {other:?}"),
            },
            other => panic!("expected Result(Err(...)) got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────────
    // MODULE-017-T75 — invoke handler emits tool.invoke THEN tool.error
    //          (error_type="not-found") on empty registry, in order.
    // ──────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn t75_invoke_emits_invoke_then_error() {
        let tools: Arc<dyn ToolRegistry> = Arc::new(InMemoryToolRegistry::new());
        let rec = Arc::new(RecordingEmitter::default());
        let handler = AgentToolsInvokeHandler {
            tools,
            emitter: rec.clone(),
            repetition_guard: noop_guard(),
        };
        let params = vec![
            Val::String("nope".into()),
            Val::String("m".into()),
            Val::List(vec![Val::U8(1)]),
        ];
        handler.call(dummy_ctx(), params, 1).await.unwrap();
        assert_eq!(rec.types(), vec!["tool.invoke", "tool.error"]);
        let events = rec.events.lock().unwrap();
        assert_eq!(events[1].payload["error_type"], "not-found");
        assert_eq!(events[1].payload["tool_id"], "nope");
    }

    // ──────────────────────────────────────────────────────────────
    // MODULE-017-T78 — decode-failure path emits tool.error ONLY (no
    //          preceding tool.invoke); error_type input-validation-failed.
    // ──────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn t78_decode_failure_emits_error_only() {
        let tools: Arc<dyn ToolRegistry> = Arc::new(InMemoryToolRegistry::new());
        let rec = Arc::new(RecordingEmitter::default());
        let handler = AgentToolsInvokeHandler {
            tools,
            emitter: rec.clone(),
            repetition_guard: noop_guard(),
        };
        // Only 2 Vals — decode_invoke_params requires 3 → InputValidationFailed.
        let params = vec![Val::String("t".into()), Val::String("m".into())];
        handler.call(dummy_ctx(), params, 1).await.unwrap();
        assert_eq!(rec.types(), vec!["tool.error"]);
        let events = rec.events.lock().unwrap();
        assert_eq!(events[0].payload["error_type"], "input-validation-failed");
        assert_eq!(events[0].payload["tool_id"], "");
    }

    // ──────────────────────────────────────────────────────────────
    // SB-02 — list-tools encodes 3-field canonical tool-info records.
    // ──────────────────────────────────────────────────────────────
    #[tokio::test]
    async fn sb_02_list_tools_returns_canonical_records() {
        // Use a tiny ad-hoc registry that returns one entry.
        use async_trait::async_trait;

        struct OneToolRegistry;
        #[async_trait]
        impl ToolRegistry for OneToolRegistry {
            async fn load(&self, _: &str) -> Result<crate::registry::ToolInstance, ToolError> {
                Err(ToolError::NotFound("unused".into()))
            }
            async fn invoke(&self, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>, ToolError> {
                Err(ToolError::NotFound("unused".into()))
            }
            async fn list(&self) -> Vec<ToolInfo> {
                vec![ToolInfo {
                    id: "echo".into(),
                    description: "echoes input".into(),
                    methods: vec![MethodInfo {
                        name: "say".into(),
                        description: Some("say a thing".into()),
                        input_schema: None,
                        output_schema: None,
                        idempotent: Some(true),
                    }],
                }]
            }
            async fn evict_lru(&self) {}
        }

        let tools: Arc<dyn ToolRegistry> = Arc::new(OneToolRegistry);
        let rec = Arc::new(RecordingEmitter::default());
        let handler = AgentToolsListHandler {
            tools,
            emitter: rec.clone(),
        };
        let out = handler.call(dummy_ctx(), vec![], 1).await.unwrap();
        // MODULE-017-T77 — list handler emits tool.invoke THEN tool.result
        // with sentinel tool_id="" + method="list-tools", result_size=N.
        assert_eq!(rec.types(), vec!["tool.invoke", "tool.result"]);
        {
            let events = rec.events.lock().unwrap();
            assert_eq!(events[0].payload["method"], "list-tools");
            assert_eq!(events[0].payload["tool_id"], "");
            assert_eq!(events[1].payload["method"], "list-tools");
            assert_eq!(events[1].payload["result_size"], 1);
        }
        assert_eq!(out.len(), 1);
        // Outer: Val::Result(Ok(Some(Val::List([Val::Record(...)]))))
        let list_val = match &out[0] {
            Val::Result(Ok(Some(boxed))) => boxed.as_ref(),
            other => panic!("expected Ok(Some(...)) got {other:?}"),
        };
        let items = match list_val {
            Val::List(items) => items,
            other => panic!("expected List got {other:?}"),
        };
        assert_eq!(items.len(), 1);
        let fields = match &items[0] {
            Val::Record(fields) => fields,
            other => panic!("expected Record got {other:?}"),
        };
        // 3-field WIT record: id, description, methods (kebab-case keys
        // already match WIT — no kebab-renaming needed because they have
        // no underscores).
        let names: Vec<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["id", "description", "methods"]);
    }
}
