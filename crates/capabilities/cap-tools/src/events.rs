//! `tool.*` observability event builders. MODULE-017 Slice F.
//!
//! Three builders returning [`Event`] (CONTRACT-180 envelope). The builders do
//! NOT call `.emit()` themselves — the `agent-tools` host handler invokes
//! `emitter.emit(event)` directly so the MODULE-019 AC-14 observability lint's
//! bare-`emit` recognition fires (the handler body, not a helper, carries the
//! emit-eligible call).
//!
//! Envelope rules mirror the cap-llm precedent at
//! `crates/capabilities/cap-llm/src/events.rs` (MODULE-009 §3.5.1):
//! - `id` / `span_id` = fresh `Uuid::new_v4().to_string()` per event.
//! - `timestamp`      = `Utc::now()`.
//! - `agent_id`       = `ctx.agent_id`.
//! - `trace_id`       = `ctx.trace_id` (HostCallContext.trace_id is `String`,
//!                      NOT `Option` — there is no fallback chain, unlike
//!                      cap-llm's `LlmRequestContext.trace_id: Option<String>`).
//! - `run_id`         = `ctx.run_id` (passed through verbatim).
//! - `task_id` / `execution_id` / `parent_span_id` = None (HostCallContext
//!                      carries neither task_id nor execution_id).
//! - `duration_ms`    = Some(_) only for `tool.result`; None otherwise.
//!
//! Note: `HostCallContext` DOES carry `iteration: Option<u32>` (AutoMode loop
//! tick), which cap-llm threads into `llm.request` / `llm.response` payloads.
//! Slice F intentionally does NOT thread `iteration` into the `tool.*` payloads
//! to keep the slice scoped to emit + jsonschema; per-iteration tool-call
//! correlation is a follow-on observability enhancement (MODULE-017 §3.6 (rr)).
//!
//! ## Redaction discipline (MODULE-017 §2.9, SB-22)
//!
//! `tool.error` payloads carry only the kebab-case `error_type` discriminant +
//! a fixed safe-class `message` (never the rich `ToolError` payload, which may
//! carry internal scope-state). `tool.invoke` / `tool.result` carry only
//! `tool_id` / `method` / `duration_ms` / `result_size` — never params or
//! result bytes.

use advance_shared_types::event::Event;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

/// `tool.invoke` event_type constant (PRD §15.3.16).
pub(crate) const TOOL_INVOKE: &str = "tool.invoke";
/// `tool.result` event_type constant (PRD §15.3.16).
pub(crate) const TOOL_RESULT: &str = "tool.result";
/// `tool.error` event_type constant (PRD §15.3.16).
pub(crate) const TOOL_ERROR: &str = "tool.error";

/// Envelope carrier built from `HostCallContext` at handler entry. Holds the
/// three envelope fields cap-tools events populate from the call context.
#[derive(Clone, Debug)]
pub(crate) struct ToolEventContext {
    pub agent_id: String,
    pub trace_id: String,
    pub run_id: Option<String>,
}

/// Build the shared envelope shell. Caller fills `event_type`, `payload`, and
/// (for `tool.result`) `duration_ms`.
fn envelope(ctx: &ToolEventContext, event_type: &str) -> Event {
    Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: ctx.agent_id.clone(),
        task_id: None,
        run_id: ctx.run_id.clone(),
        execution_id: None,
        trace_id: ctx.trace_id.clone(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: json!({}),
        duration_ms: None,
    }
}

/// `tool.invoke` — fired at the start of a `tool-invoke` / `list-tools` host
/// call (after params decode succeeds). Payload: `{tool_id, method}`. The
/// agent identity is carried by the envelope `agent_id` field (not duplicated
/// in the payload — mirrors the cap-llm precedent and keeps the payload schema
/// consistent across `tool.invoke` / `tool.result` / `tool.error`; the PRD
/// §15.3.16 `agent_id` field is satisfied by `event.agent_id`). For
/// `list-tools` the handler passes `tool_id = ""` + `method = "list-tools"`.
pub(crate) fn tool_invoke_event(ctx: &ToolEventContext, tool_id: &str, method: &str) -> Event {
    let mut event = envelope(ctx, TOOL_INVOKE);
    event.payload = json!({
        "tool_id": tool_id,
        "method": method,
    });
    event
}

/// `tool.result` — fired on a successful return. Payload:
/// `{tool_id, method, duration_ms, result_size}`; `duration_ms` is also set on
/// the envelope (request → response wall-time). `result_size` = result byte
/// length (for `list-tools`, the entry count).
pub(crate) fn tool_result_event(
    ctx: &ToolEventContext,
    tool_id: &str,
    method: &str,
    duration_ms: u64,
    result_size: usize,
) -> Event {
    let mut event = envelope(ctx, TOOL_RESULT);
    event.duration_ms = Some(duration_ms);
    event.payload = json!({
        "tool_id": tool_id,
        "method": method,
        "duration_ms": duration_ms,
        "result_size": result_size,
    });
    event
}

/// `tool.error` — fired on a failed return. Payload:
/// `{tool_id, error_type, message}`. `error_type` is the kebab-case `tool-error`
/// variant tag; `message` is the SB-22 fixed safe-class redacted string (never
/// the rich `ToolError` payload).
pub(crate) fn tool_error_event(
    ctx: &ToolEventContext,
    tool_id: &str,
    error_type: &str,
    message: &str,
) -> Event {
    let mut event = envelope(ctx, TOOL_ERROR);
    event.payload = json!({
        "tool_id": tool_id,
        "error_type": error_type,
        "message": message,
    });
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ToolEventContext {
        ToolEventContext {
            agent_id: "agent-1".into(),
            trace_id: "trace-1".into(),
            run_id: Some("run-9".into()),
        }
    }

    // MODULE-017-T72 — tool.invoke envelope shape.
    #[test]
    fn t72_tool_invoke_event_envelope() {
        let ev = tool_invoke_event(&ctx(), "tool-a", "do");
        assert_eq!(ev.event_type, TOOL_INVOKE);
        assert_eq!(ev.agent_id, "agent-1");
        assert_eq!(ev.trace_id, "trace-1");
        assert_eq!(ev.run_id.as_deref(), Some("run-9"));
        assert_eq!(ev.task_id, None);
        assert_eq!(ev.execution_id, None);
        assert_eq!(ev.parent_span_id, None);
        assert_eq!(ev.duration_ms, None);
        assert_eq!(ev.payload["tool_id"], "tool-a");
        assert_eq!(ev.payload["method"], "do");
        // agent_id is the envelope field, NOT duplicated in the payload.
        assert!(ev.payload.get("agent_id").is_none());
        // id / span_id are fresh UUID strings (non-empty, parseable).
        assert!(Uuid::parse_str(&ev.id).is_ok());
        assert!(Uuid::parse_str(&ev.span_id).is_ok());
        assert_ne!(ev.id, ev.span_id);
    }

    // MODULE-017-T73 — tool.result envelope sets duration_ms + result_size.
    #[test]
    fn t73_tool_result_event_envelope() {
        let ev = tool_result_event(&ctx(), "tool-a", "do", 42, 1024);
        assert_eq!(ev.event_type, TOOL_RESULT);
        assert_eq!(ev.duration_ms, Some(42));
        assert_eq!(ev.payload["duration_ms"], 42);
        assert_eq!(ev.payload["result_size"], 1024);
        assert_eq!(ev.payload["tool_id"], "tool-a");
        assert_eq!(ev.payload["method"], "do");
    }

    // MODULE-017-T74 — tool.error carries kebab-case error_type + redacted
    // message; the rich ToolError payload is NOT echoed.
    #[test]
    fn t74_tool_error_event_redacted() {
        let ev = tool_error_event(&ctx(), "tool-a", "invocation-failed", "invocation failed");
        assert_eq!(ev.event_type, TOOL_ERROR);
        assert_eq!(ev.payload["tool_id"], "tool-a");
        assert_eq!(ev.payload["error_type"], "invocation-failed");
        assert_eq!(ev.payload["message"], "invocation failed");
        // The message must be the fixed safe-class string, never internal detail.
        let msg = ev.payload["message"].as_str().unwrap();
        assert!(!msg.contains("slice-B"));
        assert!(!msg.contains("§"));
    }
}
