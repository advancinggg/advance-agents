//! OpenAI Responses API adapter (`/v1/responses`; ADR 2026-07-22 D4,
//! backend `openai-responses`). Reachable ONLY via an explicit
//! `backend: openai-responses` in config — `backend_of` inference never
//! selects it, so no pre-existing config changes behavior.
//!
//! STATELESS hard constraints (MODULE-009-AC-21 / AC-03 class):
//! - `store: false` on every request — the upstream must not persist state;
//! - `previous_response_id` is NEVER sent (each call is self-contained);
//! - encrypted reasoning is requested (`include: ["reasoning.encrypted_content"]`)
//!   but reasoning items are EXCLUDED from the concatenated text.
//!
//! Terminal set (streaming) is CLOSED AND THREE-MEMBERED:
//! `response.completed`, `response.failed`, `response.incomplete` —
//! `response.incomplete` is a legitimate usage-carrying terminal mapping to
//! a non-retryable truncation-class finish. Any OTHER single-segment
//! `response.*` status event fails CLOSED (enum-coded static reason);
//! unknown MULTI-segment item events are Ignored. Embeddings delegate to
//! the OpenAI-compatible adapter (same `/v1/embeddings` shape).

use advance_shared_types::security_validator::{HttpMethod, HttpRequest};
use serde_json::{json, Value};

use crate::error::LlmError;
use crate::executor::ExecutionOutcome;
use crate::gateway::{ChatMessage, ChatParams, ChatRole};
use crate::provider::ResolvedProvider;
use crate::providers::openai::{OpenAiAdapter, OPENAI_EMBED_MODEL};
use crate::providers::sse::{SseEvent, SseFrame, SseUsage};
use crate::providers::{auth_header_for, ProviderAdapter};

pub struct OpenAiResponsesAdapter;

/// Static-reason non-200 mapper for the Responses backend (ADR 2026-07-22
/// "no upstream bytes in errors" — CONTRACT-111 Invariant 7). Unlike the
/// shared OpenAI Chat mapper, this NEVER echoes upstream body bytes: it
/// classifies by status + a bounded, hardcoded type probe only. 400s carry
/// a context-overflow type detector so the retry classifier can route
/// `ContextTooLong` correctly, but the reason string is static.
fn map_status_static(status: u16, body: &[u8]) -> LlmError {
    match status {
        400 => {
            if let Ok(v) = serde_json::from_slice::<Value>(body) {
                if v["error"]["type"].as_str() == Some("context_length_exceeded") {
                    return LlmError::ContextTooLong("context too long".into());
                }
            }
            LlmError::ProviderError("http 400".into())
        }
        401 | 403 => LlmError::ProviderError("auth failed".into()),
        404 => LlmError::ModelNotAvailable("model not found".into()),
        429 => LlmError::RateLimited("rate limited".into()),
        500..=599 => {
            // grok-repass Item 3 (see providers/mod.rs predicates). Message
            // probe PLUS the normalized positive type acceptance, both under
            // the negative type gate; reason stays STATIC per this mapper's
            // charter. The positive acceptance was added in audit round 4:
            // this IS an OpenAI backend, so a proxy-rewritten 5xx carrying
            // the canonical context_length_exceeded type (any spelling) with
            // a non-descriptive message was still classified retryable —
            // the exact retry storm Item 3 exists to close, and an
            // intra-backend split (the Responses EMBED path reaches openai's
            // mapper transitively and already accepted the type). With it,
            // the 5xx arm is more permissive than this adapter's own 400
            // arm (exact-type-only, no message probe — kept byte-identical
            // per the lane's 400-path obligation; /spec territory to
            // change): every NON-CONTRADICTORY body the 400 arm accepts is
            // accepted here — the canonical type cannot trip the transient
            // gate on its own field, but a transient literal in the OTHER
            // structured field vetoes acceptance per the documented conflict
            // rule (providers/mod.rs): self-contradictory bodies are not the
            // unambiguous signal this classifier requires and stay
            // retryable. Buffered chat/embed only: the live-stream head is
            // classified in gateway.rs and runs no provider mapper.
            if let Ok(v) = serde_json::from_slice::<Value>(body) {
                let err_type = v["error"]["type"].as_str().unwrap_or("");
                let err_code = v["error"]["code"].as_str().unwrap_or("");
                let err_msg = v["error"]["message"].as_str().unwrap_or("");
                // Audit round 5: mirror of the openai arm — the real vendor
                // envelope carries the overflow literal in error.code (with
                // type invalid_request_error), so both structured fields
                // feed both classifier sides symmetrically.
                if !crate::providers::is_transient_error_type_5xx(err_type)
                    && !crate::providers::is_transient_error_type_5xx(err_code)
                    && (crate::providers::normalize_error_type(err_type) == "contextlengthexceeded"
                        || crate::providers::normalize_error_type(err_code)
                            == "contextlengthexceeded"
                        || crate::providers::is_context_overflow_message_5xx(err_msg))
                {
                    return LlmError::ContextTooLong("context too long".into());
                }
            }
            LlmError::ProviderError(format!("upstream {status}"))
        }
        other => LlmError::ProviderError(format!("http {other}")),
    }
}

/// Map the Responses `incomplete_details.reason` onto the CLOSED
/// finish_reason passthrough set. `max_output_tokens` aligns with the chat
/// convention's `"length"`; anything unrecognized collapses to the static
/// `"incomplete"` (never free-form upstream text).
fn map_incomplete_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("max_output_tokens") => "length",
        Some("content_filter") => "content_filter",
        _ => "incomplete",
    }
}

/// In-band error probe (MODULE-009-AC-21): both OpenAI error shapes —
/// the object form `{"error":{...}}` and the flat `{code, error}` form —
/// fold to an enum-coded STATIC reason before any typed decode. Called only
/// from `parse_sse_frame` (S4-wired), so dead-code on the non-test build.
#[allow(dead_code)]
fn probe_error_shapes(value: &Value) -> Result<(), LlmError> {
    if value.get("error").map(Value::is_object) == Some(true) {
        return Err(LlmError::ProviderError("in-band error frame".into()));
    }
    if value.get("code").is_some() && value.get("error").is_some() {
        return Err(LlmError::ProviderError("in-band error frame".into()));
    }
    Ok(())
}

impl OpenAiResponsesAdapter {
    fn chat_body(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<Value, LlmError> {
        // The Responses API has no `stop` parameter; silently dropping the
        // caller's stop-sequences would change semantics, so fail CLOSED
        // with a static reason instead.
        if params.stop_sequences.is_some() {
            return Err(LlmError::ProviderError(
                "stop-sequences unsupported for openai-responses backend".into(),
            ));
        }
        let mut instructions: Vec<&str> = Vec::new();
        let mut input: Vec<Value> = Vec::new();
        for m in messages {
            match m.role {
                ChatRole::System => instructions.push(&m.content),
                ChatRole::User | ChatRole::Assistant => {
                    input.push(json!({ "role": m.role.as_str(), "content": m.content }));
                }
            }
        }
        let mut body = json!({
            "model": provider.model,
            "input": Value::Array(input),
            // Stateless hard constraint: never persist server-side state,
            // never send previous_response_id.
            "store": false,
            "include": ["reasoning.encrypted_content"],
        });
        if !instructions.is_empty() {
            body["instructions"] = Value::String(instructions.join("\n\n"));
        }
        if let Some(t) = params.temperature {
            body["temperature"] = json!(t);
        }
        if let Some(m) = params.max_tokens {
            body["max_output_tokens"] = json!(m);
        }
        Ok(body)
    }

    fn request_from_body(
        &self,
        provider: &ResolvedProvider,
        body: &Value,
        streaming: bool,
    ) -> Result<HttpRequest, LlmError> {
        let url = format!("{}/v1/responses", provider.endpoint.trim_end_matches('/'));
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| LlmError::ProviderError(format!("serialize chat body: {e}")))?;
        let mut headers = vec![
            auth_header_for(provider),
            ("Content-Type".into(), "application/json".into()),
        ];
        if streaming {
            headers.push(("Accept".into(), "text/event-stream".into()));
        }
        Ok(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers,
            body: body_bytes,
        })
    }
}

impl ProviderAdapter for OpenAiResponsesAdapter {
    fn build_chat_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        let body = self.chat_body(provider, messages, params)?;
        self.request_from_body(provider, &body, false)
    }

    fn parse_chat_response(&self, status: u16, body: &[u8]) -> Result<ExecutionOutcome, LlmError> {
        if status == 200 {
            let value: Value = serde_json::from_slice(body)
                .map_err(|_| LlmError::ProviderError("invalid response shape".into()))?;
            match value["status"].as_str() {
                Some("completed") | Some("incomplete") => {}
                Some("failed") => {
                    // Static reason only — the upstream error object is not echoed.
                    return Err(LlmError::ProviderError("upstream response failed".into()));
                }
                _ => return Err(LlmError::ProviderError("invalid response shape".into())),
            }
            // Concatenate output_text parts of message items; reasoning
            // items are EXCLUDED from text by construction.
            let output = value["output"]
                .as_array()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            let mut parts: Vec<&str> = Vec::new();
            for item in output {
                if item["type"].as_str() != Some("message") {
                    continue;
                }
                if let Some(content) = item["content"].as_array() {
                    for c in content {
                        if c["type"].as_str() == Some("output_text") {
                            if let Some(s) = c["text"].as_str() {
                                parts.push(s);
                            }
                        }
                    }
                }
            }
            if parts.is_empty() {
                return Err(LlmError::ProviderError("invalid response shape".into()));
            }
            let text = parts.concat();
            let model = value["model"].as_str().unwrap_or("").to_string();
            // Round-AUDIT-5 C1 discipline: usage MUST NOT coerce to 0.
            let input_tokens = value["usage"]["input_tokens"]
                .as_u64()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            let output_tokens = value["usage"]["output_tokens"]
                .as_u64()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            let finish_reason = if value["status"].as_str() == Some("incomplete") {
                map_incomplete_reason(value["incomplete_details"]["reason"].as_str()).to_string()
            } else {
                "stop".to_string()
            };
            return Ok(ExecutionOutcome {
                text,
                model,
                input_tokens,
                output_tokens,
                finish_reason,
            });
        }
        Err(map_status_static(status, body))
    }

    fn build_stream_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        let mut body = self.chat_body(provider, messages, params)?;
        body["stream"] = json!(true);
        self.request_from_body(provider, &body, true)
    }

    fn parse_sse_frame(&self, frame: &SseFrame) -> Result<SseEvent, LlmError> {
        // ── Classification by EVENT NAME first (audit round-1 fix) ──
        // The terminal-family / error decision must NOT depend on the data
        // body parsing cleanly: an `event: response.failed` (or an unknown
        // single-segment `response.*` terminal-family event) carrying a
        // MALFORMED body must still fail CLOSED, not slip to Ignore because
        // the JSON decode errored. So we resolve the event name from the
        // reliable `event:` line before touching `data:`.
        if frame.event.as_deref() == Some("error") {
            return Err(LlmError::ProviderError("in-band error frame".into()));
        }
        // Fail-closed terminal-family gate keyed on the `event:` name alone,
        // BEFORE parsing data. `response.failed` → error; an unknown
        // single-segment `response.*` outside the known non-terminal set and
        // outside {completed, incomplete} → fail CLOSED. Keying on the
        // reliable `event:` line (not the payload) means an adversarial
        // terminal-family frame carrying a malformed body — or the alien
        // `[DONE]` token — still fails closed here instead of slipping to
        // Ignore.
        if let Some(ev) = frame.event.as_deref() {
            if let Some(rest) = ev.strip_prefix("response.") {
                let single_segment = !rest.contains('.');
                match rest {
                    "failed" => {
                        return Err(LlmError::ProviderError("upstream response failed".into()))
                    }
                    "completed" | "incomplete" | "created" | "in_progress" | "queued" => {}
                    _ if single_segment => {
                        return Err(LlmError::ProviderError(
                            "unrecognized terminal-family event".into(),
                        ))
                    }
                    _ => {}
                }
            }
        }
        // NOTE: the Responses protocol has NO `[DONE]` sentinel — it
        // terminates via `response.completed`/`failed`/`incomplete` events.
        // We therefore do NOT special-case `data: [DONE]`; it is not valid
        // JSON, so it falls through to the decode-fail arm below, which
        // fails CLOSED on a recognized terminal/content event (a
        // `response.completed`/`incomplete` carrying `[DONE]` is a corrupt
        // terminal, not a keep-alive) and Ignores it on a nameless /
        // non-terminal event. (Audit round-3 fix: a standalone
        // `[DONE] → IGNORE` short-circuit here would let a
        // `response.incomplete`/`completed` frame slip to Ignore, violating
        // AC-21's "terminal never Ignore" rule.)
        let value: Value = match serde_json::from_str(&frame.data) {
            Ok(v) => v,
            Err(_) => {
                // A recognized event whose payload is needed (delta /
                // completed / incomplete) but does not decode is a corrupt
                // terminal/content frame → fail CLOSED. A nameless or
                // multi-segment frame with unparseable data is Ignored (we
                // cannot classify it, and it is not on a terminal path).
                return match frame.event.as_deref() {
                    Some(
                        "response.output_text.delta" | "response.completed" | "response.incomplete",
                    ) => Err(LlmError::ProviderError("invalid stream frame".into())),
                    _ => Ok(SseEvent::IGNORE),
                };
            }
        };
        probe_error_shapes(&value)?;
        let name = frame
            .event
            .clone()
            .or_else(|| value["type"].as_str().map(str::to_string));
        let Some(name) = name else {
            return Ok(SseEvent::IGNORE);
        };
        match name.as_str() {
            // Data-shape error without an `event: error` line (Claude diff
            // round-1 parity gap vs the Anthropic adapter).
            "error" => Err(LlmError::ProviderError("in-band error frame".into())),
            "response.output_text.delta" => {
                let delta = value["delta"].as_str().unwrap_or("");
                if delta.is_empty() {
                    return Ok(SseEvent::IGNORE);
                }
                Ok(SseEvent {
                    delta: Some(delta.to_string()),
                    ..SseEvent::IGNORE
                })
            }
            "response.completed" | "response.incomplete" => {
                let usage_val = &value["response"]["usage"];
                let usage = SseUsage {
                    input_tokens: usage_val["input_tokens"].as_u64(),
                    output_tokens: usage_val["output_tokens"].as_u64(),
                };
                let finish = if name == "response.incomplete" {
                    map_incomplete_reason(
                        value["response"]["incomplete_details"]["reason"].as_str(),
                    )
                    .to_string()
                } else {
                    "stop".to_string()
                };
                Ok(SseEvent {
                    delta: None,
                    usage: (usage.input_tokens.is_some() || usage.output_tokens.is_some())
                        .then_some(usage),
                    finish_reason: Some(finish),
                    terminal: true,
                })
            }
            "response.failed" => {
                // Static reason only (CONTRACT-111 Invariant 7).
                Err(LlmError::ProviderError("upstream response failed".into()))
            }
            other => {
                // CLOSED terminal-family rule: a single-segment
                // `response.<status>` event outside the three-member set is
                // an unrecognized TERMINAL-family event → fail CLOSED.
                // Multi-segment item events (response.output_item.*,
                // response.content_part.*, response.output_text.done, …)
                // and non-`response.` events are non-terminal → Ignore.
                if let Some(rest) = other.strip_prefix("response.") {
                    let single_segment = !rest.contains('.');
                    let known_non_terminal = matches!(rest, "created" | "in_progress" | "queued");
                    if single_segment && !known_non_terminal {
                        return Err(LlmError::ProviderError(
                            "unrecognized terminal-family event".into(),
                        ));
                    }
                }
                Ok(SseEvent::IGNORE)
            }
        }
    }

    fn build_embed_request(
        &self,
        provider: &ResolvedProvider,
        text: &str,
    ) -> Result<HttpRequest, LlmError> {
        // Embeddings are protocol-orthogonal to the chat backend: the
        // OpenAI platform serves them at /v1/embeddings for both chat and
        // responses deployments. Delegate to the OpenAI-compatible impl.
        OpenAiAdapter.build_embed_request(provider, text)
    }

    fn parse_embed_response(&self, status: u16, body: &[u8]) -> Result<Vec<f32>, LlmError> {
        OpenAiAdapter.parse_embed_response(status, body)
    }

    fn embedding_model(&self) -> Option<&'static str> {
        Some(OPENAI_EMBED_MODEL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{ChatMessage, ChatParams, ChatRole};
    use advance_runtime::config::ProviderBackend;

    // ── grok-repass Item 3: 5xx-disguised context overflow (L3 rows, responses arm).
    // NOTE this mapper's single production call site is the BUFFERED parse
    // (chat + embed); the live-stream head is classified in gateway.rs and
    // runs no provider mapper — deliberately out of Item 3's scope. ──

    /// L3-T3 — 5xx + overflow message maps to ContextTooLong, static reason.
    #[test]
    fn t_grok3_responses_5xx_overflow_maps_context_too_long_static() {
        let body = br#"{"error":{"message":"input exceeds the maximum context for this model"}}"#;
        match map_status_static(500, body) {
            LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
            other => panic!("expected ContextTooLong, got {other:?}"),
        }
    }

    /// L3-T6 — CONTROL: adversarial transient bodies at the narrowed edge.
    #[test]
    fn t_grok3_responses_5xx_adversarial_transient_bodies_stay_retryable() {
        let bodies: [&[u8]; 3] = [
            br#"{"error":{"message":"token limit reached, please retry"}}"#,
            br#"{"error":{"message":"context too busy, retry shortly"}}"#,
            br#"{"error":{"message":"capacity exceeded; context too many concurrent requests"}}"#,
        ];
        for body in bodies {
            match map_status_static(503, body) {
                LlmError::ProviderError(msg) => {
                    assert_eq!(msg, "upstream 503");
                    assert!(crate::retry::classify_retryable(&LlmError::ProviderError(
                        msg
                    )));
                }
                other => panic!("expected retryable ProviderError, got {other:?}"),
            }
        }
    }

    /// L3-T7 (responses arm) — the six-member type gate, one witness each.
    #[test]
    fn t_grok3_responses_5xx_transient_type_gate_wins_over_phrase_probe() {
        let types = [
            "overloaded_error",
            "rate_limit_error",
            "timeout_error",
            "service_unavailable",
            "server_error",
            "internal_error",
        ];
        for err_type in types {
            let body = format!(
                r#"{{"error":{{"type":"{err_type}","message":"request exceeds the maximum context capacity right now, retry"}}}}"#
            );
            match map_status_static(500, body.as_bytes()) {
                LlmError::ProviderError(msg) => assert_eq!(msg, "upstream 500"),
                other => panic!("type {err_type}: expected ProviderError, got {other:?}"),
            }
        }
    }

    /// L3-T7b (responses arm) — the pinned residual. Since audit round 4 the
    /// 5xx arm is strictly MORE permissive than this adapter's own 400 arm
    /// (which requires the exact type and probes no message): the 5xx arm
    /// accepts the normalized type OR an overflow-complete message, and the
    /// canonical type cannot trip the transient gate — the deliberate,
    /// disclosed asymmetry of the type-distrusting 5xx design.
    #[test]
    fn t_grok3_responses_5xx_residual_unknown_type_with_overflow_message() {
        let body = br#"{"error":{"type":"quota_exhausted_error","message":"context length exceeded for this request"}}"#;
        match map_status_static(500, body) {
            LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
            other => panic!("expected ContextTooLong (pinned residual), got {other:?}"),
        }
    }

    /// Audit round 5 — the REAL OpenAI envelope: overflow signalled as type
    /// invalid_request_error + CODE context_length_exceeded with a flat
    /// message. RED against the type-only round-4 arm.
    #[test]
    fn t_grok3_responses_5xx_code_field_overflow_maps_context_too_long() {
        let body = br#"{"error":{"type":"invalid_request_error","code":"context_length_exceeded","message":"request failed"}}"#;
        match map_status_static(500, body) {
            LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
            other => panic!("expected ContextTooLong (code acceptance), got {other:?}"),
        }
        assert!(!crate::retry::classify_retryable(&map_status_static(
            500, body
        )));
    }

    /// Audit round 6 — the CONFLICT RULE, pinned in both directions: a body
    /// carrying an overflow literal in one structured field and a transient
    /// literal in the other is self-contradictory and stays retryable
    /// (see providers/mod.rs conflict-rule doc).
    #[test]
    fn t_grok3_responses_5xx_contradictory_fields_stay_retryable() {
        let overflow_type_transient_code = br#"{"error":{"type":"context_length_exceeded","code":"server_error","message":"request failed"}}"#;
        assert!(matches!(
            map_status_static(500, overflow_type_transient_code),
            LlmError::ProviderError(msg) if msg == "upstream 500"
        ));
        let transient_type_overflow_code = br#"{"error":{"type":"overloaded_error","code":"context_length_exceeded","message":"request failed"}}"#;
        assert!(matches!(
            map_status_static(500, transient_type_overflow_code),
            LlmError::ProviderError(msg) if msg == "upstream 500"
        ));
    }

    /// Audit round 5 — the negative gate reads code symmetrically: a
    /// transient CODE with an overflow-complete message stays retryable
    /// (discriminates the code-side gate leg specifically).
    #[test]
    fn t_grok3_responses_5xx_transient_code_gates_over_phrase_probe() {
        let body = br#"{"error":{"code":"rate_limit_exceeded","message":"request exceeds the maximum context capacity right now, retry"}}"#;
        match map_status_static(500, body) {
            LlmError::ProviderError(msg) => assert_eq!(msg, "upstream 500"),
            other => panic!("expected ProviderError (code-side gate), got {other:?}"),
        }
    }

    /// Audit round 5 — 400-arm shape controls: the subset invariant rests on
    /// the 400 arm staying exact-type-only with no message probe; pin that
    /// shape so a future widening trips a test instead of silently inverting
    /// the disclosed geometry.
    #[test]
    fn t_grok3_responses_400_shape_exact_type_only_no_message_probe() {
        let kebab = br#"{"error":{"type":"context-length-exceeded","message":"too long"}}"#;
        assert!(matches!(
            map_status_static(400, kebab),
            LlmError::ProviderError(msg) if msg == "http 400"
        ));
        let message_only = br#"{"error":{"message":"prompt is too long for the context window"}}"#;
        assert!(matches!(
            map_status_static(400, message_only),
            LlmError::ProviderError(msg) if msg == "http 400"
        ));
    }

    /// Audit round 4 — the retry-storm closure this arm was still missing:
    /// a 5xx carrying the canonical OpenAI overflow TYPE (any spelling) with
    /// a non-descriptive message must classify ContextTooLong, matching the
    /// openai arm and the Responses EMBED path (which reaches openai's
    /// mapper transitively). RED against the message-probe-only arm.
    #[test]
    fn t_grok3_responses_5xx_type_only_overflow_maps_context_too_long() {
        for body in [
            br#"{"error":{"type":"context_length_exceeded","message":"request failed"}}"#
                .as_slice(),
            br#"{"error":{"type":"context-length-exceeded","message":"request failed"}}"#
                .as_slice(),
        ] {
            match map_status_static(500, body) {
                LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
                other => panic!("expected ContextTooLong (type acceptance), got {other:?}"),
            }
            assert!(
                !crate::retry::classify_retryable(&map_status_static(500, body)),
                "type-only 5xx overflow must not be retried"
            );
        }
    }

    /// L3-T8 (responses arm) — CONTROL: plain 5xx unchanged.
    #[test]
    fn t_grok3_responses_5xx_plain_error_body_unchanged() {
        match map_status_static(502, br#"{"error":{"message":"bad gateway"}}"#) {
            LlmError::ProviderError(msg) => assert_eq!(msg, "upstream 502"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    fn provider() -> ResolvedProvider {
        ResolvedProvider {
            id: "openai".into(),
            endpoint: "https://api.openai.com".into(),
            api_key_secret: "openai-api-key".into(),
            model: "gpt-5.2".into(),
            cost_per_mtoken_in: 1.25,
            cost_per_mtoken_out: 10.0,
            backend: ProviderBackend::OpenAiResponses,
            auth_scheme: None,
            backend_class: advance_runtime::config::InferenceBackendClass::CloudHttp,
            embedding_model: None,
        }
    }

    fn frame(event: Option<&str>, data: &str) -> SseFrame {
        SseFrame {
            event: event.map(str::to_string),
            data: data.to_string(),
        }
    }

    /// MODULE-009-T116 (request leg) — stateless hard constraints:
    /// store:false, no previous_response_id, encrypted-reasoning include,
    /// system → instructions, Bearer auth default, /v1/responses path.
    #[test]
    fn t116_build_chat_request_stateless_constraints() {
        let adapter = OpenAiResponsesAdapter;
        let messages = vec![
            ChatMessage {
                role: ChatRole::System,
                content: "be brief".into(),
            },
            ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            },
        ];
        let req = adapter
            .build_chat_request(&provider(), &messages, &ChatParams::default())
            .unwrap();
        assert_eq!(req.url, "https://api.openai.com/v1/responses");
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["store"], json!(false));
        assert!(body.get("previous_response_id").is_none());
        assert_eq!(body["include"], json!(["reasoning.encrypted_content"]));
        assert_eq!(body["instructions"], json!("be brief"));
        assert_eq!(body["input"][0]["role"], json!("user"));
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "Authorization" && v == "Bearer {openai-api-key}"));
    }

    /// stop-sequences fail CLOSED with a static reason (Responses API has
    /// no stop parameter; silent dropping would change semantics).
    #[test]
    fn t116_stop_sequences_fail_closed() {
        let adapter = OpenAiResponsesAdapter;
        let params = ChatParams {
            stop_sequences: Some(vec!["END".into()]),
            ..ChatParams::default()
        };
        match adapter.build_chat_request(&provider(), &[], &params) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(
                    msg,
                    "stop-sequences unsupported for openai-responses backend"
                );
            }
            other => panic!("expected static ProviderError, got {other:?}"),
        }
    }

    /// MODULE-009-T117 — buffered parse: output_text concatenated,
    /// reasoning items excluded, usage extracted, completed → stop.
    #[test]
    fn t117_parse_chat_response_completed() {
        let body = br#"{"status":"completed","model":"gpt-5.2","output":[{"type":"reasoning","encrypted_content":"zzz"},{"type":"message","content":[{"type":"output_text","text":"hel"},{"type":"output_text","text":"lo"}]}],"usage":{"input_tokens":11,"output_tokens":4}}"#;
        let outcome = OpenAiResponsesAdapter
            .parse_chat_response(200, body)
            .unwrap();
        assert_eq!(outcome.text, "hello");
        assert_eq!(outcome.input_tokens, 11);
        assert_eq!(outcome.output_tokens, 4);
        assert_eq!(outcome.finish_reason, "stop");
    }

    /// MODULE-009-T117 — buffered incomplete maps to the closed
    /// truncation-class finish and still carries usage.
    #[test]
    fn t117_parse_chat_response_incomplete_maps_length() {
        let body = br#"{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"model":"gpt-5.2","output":[{"type":"message","content":[{"type":"output_text","text":"trunc"}]}],"usage":{"input_tokens":9,"output_tokens":100}}"#;
        let outcome = OpenAiResponsesAdapter
            .parse_chat_response(200, body)
            .unwrap();
        assert_eq!(outcome.finish_reason, "length");
        assert_eq!(outcome.output_tokens, 100);
    }

    /// MODULE-009-T117 — streaming terminal set is CLOSED AND
    /// THREE-MEMBERED; response.incomplete is a usage-carrying terminal.
    #[test]
    fn t117_sse_terminal_set_closed_three_membered() {
        let adapter = OpenAiResponsesAdapter;
        // completed
        let done = adapter
            .parse_sse_frame(&frame(
                Some("response.completed"),
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":5,"output_tokens":9}}}"#,
            ))
            .unwrap();
        assert!(done.terminal);
        assert_eq!(done.usage.unwrap().output_tokens, Some(9));
        assert_eq!(done.finish_reason.as_deref(), Some("stop"));
        // incomplete → usage-carrying non-retryable truncation-class finish
        let inc = adapter
            .parse_sse_frame(&frame(
                Some("response.incomplete"),
                r#"{"type":"response.incomplete","response":{"usage":{"input_tokens":5,"output_tokens":42},"incomplete_details":{"reason":"max_output_tokens"}}}"#,
            ))
            .unwrap();
        assert!(inc.terminal);
        assert_eq!(inc.usage.unwrap().output_tokens, Some(42));
        assert_eq!(inc.finish_reason.as_deref(), Some("length"));
        // failed → enum-coded static error
        match adapter.parse_sse_frame(&frame(
            Some("response.failed"),
            r#"{"type":"response.failed","response":{"error":{"message":"SECRET upstream text"}}}"#,
        )) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "upstream response failed");
                assert!(!msg.contains("SECRET"));
            }
            other => panic!("expected static ProviderError, got {other:?}"),
        }
    }

    /// MODULE-009-T117 — an unrecognized single-segment terminal-family
    /// event fails CLOSED; unknown multi-segment item events are Ignored.
    #[test]
    fn t117_unknown_terminal_family_fails_closed_multi_segment_ignored() {
        let adapter = OpenAiResponsesAdapter;
        match adapter.parse_sse_frame(&frame(
            Some("response.cancelled"),
            r#"{"type":"response.cancelled"}"#,
        )) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "unrecognized terminal-family event");
            }
            other => panic!("expected fail-closed, got {other:?}"),
        }
        // known non-terminal single-segment statuses are Ignored
        for name in [
            "response.created",
            "response.in_progress",
            "response.queued",
        ] {
            let ev = adapter
                .parse_sse_frame(&frame(Some(name), &format!(r#"{{"type":"{name}"}}"#)))
                .unwrap();
            assert!(ev.is_ignore(), "{name} must be Ignore");
        }
        // unknown multi-segment item event → Ignore
        let ev = adapter
            .parse_sse_frame(&frame(
                Some("response.audio.delta"),
                r#"{"type":"response.audio.delta","delta":"AAA"}"#,
            ))
            .unwrap();
        assert!(ev.is_ignore());
    }

    /// MODULE-009-T117 — delta extraction; empty delta normalizes to
    /// Ignore (never Some("")); concat of deltas equals the final text.
    #[test]
    fn t117_delta_concat_equals_done_text() {
        let adapter = OpenAiResponsesAdapter;
        let mut acc = String::new();
        for d in ["hel", "", "lo"] {
            let ev = adapter
                .parse_sse_frame(&frame(
                    Some("response.output_text.delta"),
                    &format!(r#"{{"type":"response.output_text.delta","delta":"{d}"}}"#),
                ))
                .unwrap();
            if let Some(s) = ev.delta {
                assert!(!s.is_empty(), "delta must never be Some(empty)");
                acc.push_str(&s);
            }
        }
        assert_eq!(acc, "hello");
    }

    /// MODULE-009-T117 (audit round-1) — a terminal-family event whose data
    /// body is MALFORMED still fails CLOSED (classification is keyed on the
    /// `event:` name, not on the data parsing cleanly). Non-terminal /
    /// nameless malformed frames are Ignored.
    #[test]
    fn t117_malformed_data_on_terminal_event_fails_closed() {
        let adapter = OpenAiResponsesAdapter;
        // response.failed with garbage data → fail closed (was: slipped to Ignore)
        match adapter.parse_sse_frame(&frame(Some("response.failed"), "{ not json")) {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "upstream response failed"),
            other => panic!("response.failed w/ bad data must fail closed, got {other:?}"),
        }
        // unknown single-segment terminal-family with garbage data → fail closed
        match adapter.parse_sse_frame(&frame(Some("response.cancelled"), "garbage")) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "unrecognized terminal-family event")
            }
            other => panic!("expected fail-closed, got {other:?}"),
        }
        // completed with malformed data → corrupt terminal → fail closed
        match adapter.parse_sse_frame(&frame(Some("response.completed"), "not json")) {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid stream frame"),
            other => panic!("expected fail-closed on corrupt terminal, got {other:?}"),
        }
        // nameless malformed frame → Ignore (cannot classify, not terminal)
        assert!(adapter
            .parse_sse_frame(&frame(None, "not json"))
            .unwrap()
            .is_ignore());
    }

    /// MODULE-009-T117 (audit round-2/3) — `data: [DONE]` (an alien
    /// Chat-Completions sentinel the Responses protocol never emits) never
    /// lets a terminal-family event slip to Ignore. `response.failed` and
    /// unknown single-segment `response.*` fail closed at the event-name
    /// gate; `response.completed`/`incomplete` carrying `[DONE]` are corrupt
    /// terminals → fail closed at the decode arm (AC-21 "terminal never
    /// Ignore"); only a nameless / non-terminal `[DONE]` is a harmless
    /// keep-alive.
    #[test]
    fn t117_done_data_does_not_bypass_terminal_gate() {
        let adapter = OpenAiResponsesAdapter;
        match adapter.parse_sse_frame(&frame(Some("response.failed"), "[DONE]")) {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "upstream response failed"),
            other => panic!("response.failed + [DONE] must fail closed, got {other:?}"),
        }
        match adapter.parse_sse_frame(&frame(Some("response.cancelled"), "[DONE]")) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "unrecognized terminal-family event")
            }
            other => panic!("unknown terminal-family + [DONE] must fail closed, got {other:?}"),
        }
        // recognized TERMINAL events carrying the alien [DONE] token are
        // corrupt terminals → fail CLOSED, never Ignore (AC-21).
        for ev in ["response.completed", "response.incomplete"] {
            match adapter.parse_sse_frame(&frame(Some(ev), "[DONE]")) {
                Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid stream frame"),
                other => panic!("{ev} + [DONE] must fail closed, got {other:?}"),
            }
        }
        // bare [DONE] with no event → harmless keep-alive (decode-fail Ignore)
        assert!(adapter
            .parse_sse_frame(&frame(None, "[DONE]"))
            .unwrap()
            .is_ignore());
        // a non-terminal single-segment event carrying [DONE] → Ignore
        assert!(adapter
            .parse_sse_frame(&frame(Some("response.created"), "[DONE]"))
            .unwrap()
            .is_ignore());
    }

    /// MODULE-009-T118 (audit round-1) — the Responses non-200 mapper emits
    /// STATIC reasons only; upstream 400/404 body bytes never leak into the
    /// error (CONTRACT-111 Invariant 7), unlike the shared Chat mapper.
    #[test]
    fn t118_non_200_static_reasons_no_body_echo() {
        let adapter = OpenAiResponsesAdapter;
        let body = br#"{"error":{"type":"server_error","message":"LEAK https://k?key=sk-1"}}"#;
        match adapter.parse_chat_response(400, body) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "http 400");
                assert!(!msg.contains("LEAK"));
            }
            other => panic!("expected static http 400, got {other:?}"),
        }
        // context overflow still routes to ContextTooLong (retry classifier)
        // but with a STATIC reason.
        let ctx =
            br#"{"error":{"type":"context_length_exceeded","message":"LEAK too long detail"}}"#;
        match adapter.parse_chat_response(400, ctx) {
            Err(LlmError::ContextTooLong(msg)) => {
                assert_eq!(msg, "context too long");
                assert!(!msg.contains("LEAK"));
            }
            other => panic!("expected static ContextTooLong, got {other:?}"),
        }
        match adapter.parse_chat_response(404, b"LEAK model detail") {
            Err(LlmError::ModelNotAvailable(_)) => {}
            other => panic!("expected ModelNotAvailable, got {other:?}"),
        }
    }

    /// MODULE-009-T118 — in-band error frames fold to enum-coded static
    /// reasons BEFORE typed decode; upstream bytes never leak.
    #[test]
    fn t118_in_band_error_frames_static_enum_coded() {
        let adapter = OpenAiResponsesAdapter;
        for (event, data) in [
            (Some("error"), r#"{"type":"error","message":"LEAK me"}"#),
            (
                None,
                r#"{"error":{"message":"LEAK https://k.example?key=s"}}"#,
            ),
            (None, r#"{"code":429,"error":"LEAK rate limit text"}"#),
        ] {
            match adapter.parse_sse_frame(&frame(event, data)) {
                Err(LlmError::ProviderError(msg)) => {
                    assert_eq!(msg, "in-band error frame");
                    assert!(!msg.contains("LEAK"));
                }
                other => panic!("expected static in-band error, got {other:?}"),
            }
        }
    }
}
