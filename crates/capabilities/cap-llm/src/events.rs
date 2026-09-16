//! `llm.*` event builders. MODULE-009 §3.5.1 + AC-18 four-event surface.
//!
//! Four builders, all consuming `&dyn EventBusEmit` (CONTRACT-180):
//! - `emit_llm_request`  — at call start (chat / generate / embed)
//! - `emit_llm_response` — at success, with tokens / cost / structured-retry / latency
//! - `emit_llm_retry`    — on retryable error, with attempt + delay + error_type
//! - `emit_llm_error`    — on terminal non-retryable failure
//!
//! ## Envelope rules (MODULE-009 §3.5.1 + round-4 C2 fix)
//!
//! - `event.id`          = `Uuid::new_v4()` (per-event)
//! - `event.timestamp`   = `chrono::Utc::now()`
//! - `event.agent_id`    = `ctx.agent_id`
//! - `event.task_id`     = `ctx.task_id`  (None for direct Rust callers via `chat()`)
//! - `event.run_id`      = `ctx.run_id`   (round-4 C2: passed through verbatim;
//!                          None for `chat()`, Some(rid) for `chat_for_run("rid")`)
//! - `event.execution_id`= None (future MODULE-019 W3C trace context propagation)
//! - `event.trace_id`    = ctx.trace_id (HostCallContext.trace_id always Some on WIT
//!                          path); fall back to ctx.task_id; fall back to "none"
//! - `event.span_id`     = `Uuid::new_v4()` (per-event, round-trip-correlation surface)
//! - `event.parent_span_id` = None (W3C trace context propagation: future MODULE-019)
//! - `event.event_type`  = one of the 4 LLM_* string constants
//! - `event.payload`     = `serde_json::json!({...})` per-event-type fields
//! - `event.duration_ms` = None for llm.request / llm.retry / llm.error;
//!                         Some(latency_ms) for llm.response (request → response wall-time)
//!
//! ## Sensitive-params discipline (MODULE-009 §1.7)
//!
//! - Error events use only the kebab-case `error_type` discriminant (NEVER the
//!   `LlmError` payload string, which may carry upstream body bytes).
//! - Request/response events do NOT inline the upstream body; only model name +
//!   token counts + cost.

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::gateway::{ChatResponse, LlmRequestContext};

/// `llm.request` event_type constant.
pub const LLM_REQUEST: &str = "llm.request";
/// `llm.response` event_type constant.
pub const LLM_RESPONSE: &str = "llm.response";
/// `llm.retry` event_type constant.
pub const LLM_RETRY: &str = "llm.retry";
/// `llm.error` event_type constant.
pub const LLM_ERROR: &str = "llm.error";

/// Resolve the event-envelope `trace_id` per the §3.5.1 fallback chain:
/// `ctx.trace_id` (always Some on WIT path) → `ctx.task_id` → `"none"`.
fn resolve_trace_id(ctx: &LlmRequestContext) -> String {
    ctx.trace_id
        .clone()
        .or_else(|| ctx.task_id.clone())
        .unwrap_or_else(|| "none".into())
}

/// Build an envelope shell with the seven shared envelope fields populated
/// from `ctx`. Caller fills `event_type`, `payload`, and `duration_ms`.
fn envelope(ctx: &LlmRequestContext, event_type: &str) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: ctx.agent_id.clone(),
        task_id: ctx.task_id.clone(),
        run_id: ctx.run_id.clone(),
        execution_id: None,
        trace_id: resolve_trace_id(ctx),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: json!({}),
        duration_ms: None,
    }
}

/// Emit an `llm.request` event. Fired before the chain.execute() HTTP call.
/// Payload carries: model + input_tokens (placeholder 0 — actual count is
/// reported on the paired `llm.response` event per §1.4.2) + iteration (if
/// Some). The placeholder field exists so consumer schemas can join request /
/// response events on a stable token-count slot.
pub(crate) fn emit_llm_request(emit: &dyn EventBusEmit, ctx: &LlmRequestContext, model: &str) {
    let mut event = envelope(ctx, LLM_REQUEST);
    let mut payload = json!({ "model": model, "input_tokens": 0 });
    if let Some(iter) = ctx.iteration {
        payload["iteration"] = json!(iter);
    }
    if let Some(p) = &ctx.placement {
        payload["endpoint_id"] = json!(p.endpoint_id);
        payload["model_revision"] = json!(p.model_revision);
        payload["placement_reason"] = json!(p.placement_reason);
    }
    event.payload = payload;
    emit.emit(event);
}

/// Emit an `llm.response` event. Fired after a successful upstream call.
/// Payload carries: model + tokens + cost_usd + structured_retry_attempt +
/// schema_validation + iteration (if Some) + provider (if Some). `duration_ms = Some(latency_ms)`.
pub(crate) fn emit_llm_response(
    emit: &dyn EventBusEmit,
    ctx: &LlmRequestContext,
    response: &ChatResponse,
    cost_usd: f64,
    latency_ms: u64,
    structured_retry_attempt: Option<u32>,
    schema_validation: Option<&str>,
    provider_id: Option<&str>,
) {
    let mut event = envelope(ctx, LLM_RESPONSE);
    event.duration_ms = Some(latency_ms);
    // Slice m019-E (closes M019 §3.6 item 17): payload uses TOP-LEVEL
    // `input_tokens` / `output_tokens` per PRD §15.3.5 canonical shape.
    // Downstream consumers (event-bus stats_aggregator + cost-tracker +
    // rebuild.rs) already read top-level shape; the previous nested
    // `tokens.{input,output}` form caused silent zero-counts across the
    // observability stack.
    let mut payload = json!({
        "model": response.model,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "cost_usd": cost_usd,
        "finish_reason": response.finish_reason,
        "structured_retry_attempt": structured_retry_attempt,
        "schema_validation": schema_validation,
    });
    if let Some(iter) = ctx.iteration {
        payload["iteration"] = json!(iter);
    }
    // Lane cost-attribution (2026-09-16): the resolved provider id, so the
    // durable ledger can bill per provider API. Absent only on legacy rows.
    if let Some(provider) = provider_id {
        payload["provider"] = json!(provider);
    }
    event.payload = payload;
    emit.emit(event);
}

/// Emit an `llm.retry` event. Fired between attempts after a retryable error.
/// Payload carries: attempt + delay_ms + error_type (kebab-case discriminant).
pub(crate) fn emit_llm_retry(
    emit: &dyn EventBusEmit,
    ctx: &LlmRequestContext,
    attempt: u32,
    delay_ms: u64,
    error_type: &str,
) {
    let mut event = envelope(ctx, LLM_RETRY);
    event.payload = json!({
        "attempt": attempt,
        "delay_ms": delay_ms,
        "error_type": error_type,
    });
    emit.emit(event);
}

/// Emit an `llm.error` event. Fired on terminal non-retryable failure.
/// Payload carries: model + error_type (kebab-case discriminant) + retry_count.
/// For live stream terminals (S4), includes optional submitted_* (Δ7).
pub(crate) fn emit_llm_error(
    emit: &dyn EventBusEmit,
    ctx: &LlmRequestContext,
    model: &str,
    error_type: &str,
    retry_count: u32,
    submitted_input_tokens: Option<u64>,
    submitted_output_tokens: Option<u64>,
    submitted_cost_usd: Option<f64>,
) {
    let mut event = envelope(ctx, LLM_ERROR);
    event.payload = json!({
        "model": model,
        "error_type": error_type,
        "retry_count": retry_count,
    });
    // Δ7 (2026-07-29): count-only submitted-bill fields, injected ONLY when the
    // caller supplies them — i.e. by the LIVE-STREAM settlement winner. Buffered
    // callers pass None, so buffered `llm.error` payloads stay byte-identical
    // (the same conditional discipline `iteration?` uses on llm.request).
    if let Some(v) = submitted_input_tokens {
        event.payload["submitted_input_tokens"] = json!(v);
    }
    if let Some(v) = submitted_output_tokens {
        event.payload["submitted_output_tokens"] = json!(v);
    }
    if let Some(v) = submitted_cost_usd {
        event.payload["submitted_cost_usd"] = json!(v);
    }
    emit.emit(event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecBus(Mutex<Vec<Event>>);
    impl EventBusEmit for RecBus {
        fn emit(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn ctx() -> LlmRequestContext {
        LlmRequestContext {
            agent_id: "agent-a".into(),
            task_id: None,
            run_id: Some("run-1".into()),
            iteration: Some(2),
            trace_id: None,
            messages: vec![],
            params: crate::gateway::ChatParams::default(),
            output_schema: None,
            tee_live: false,
            user_constraints: Vec::new(),
            hard_task_class: false,
            placement: None,
        }
    }

    fn resp() -> ChatResponse {
        ChatResponse {
            text: "hi".into(),
            model: "m-1".into(),
            input_tokens: 10,
            output_tokens: 5,
            finish_reason: "stop".into(),
            parsed_output: None,
        }
    }

    /// Lane cost-attribution: `llm.response` carries the resolved provider id at the
    /// TOP-LEVEL `provider` key (the durable ledger's attribution key) alongside the
    /// canonical token/cost fields, and stays byte-compatible when no provider is given.
    #[test]
    fn llm_response_carries_provider_when_resolved() {
        let bus = RecBus::default();
        emit_llm_response(
            &bus,
            &ctx(),
            &resp(),
            0.25,
            42,
            None,
            None,
            Some("anthropic"),
        );
        emit_llm_response(&bus, &ctx(), &resp(), 0.25, 42, None, None, None);
        let events = bus.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        let with = &events[0];
        assert_eq!(with.event_type, LLM_RESPONSE);
        assert_eq!(with.agent_id, "agent-a");
        assert_eq!(with.run_id.as_deref(), Some("run-1"));
        assert_eq!(with.payload["provider"], json!("anthropic"));
        assert_eq!(with.payload["input_tokens"], json!(10));
        assert_eq!(with.payload["output_tokens"], json!(5));
        assert_eq!(with.payload["cost_usd"], json!(0.25));
        assert_eq!(with.payload["iteration"], json!(2));
        assert_eq!(with.duration_ms, Some(42));
        let without = &events[1];
        assert!(without.payload.get("provider").is_none());
        let mut expect = with.payload.clone();
        expect.as_object_mut().unwrap().remove("provider");
        assert_eq!(without.payload, expect);
    }
}
