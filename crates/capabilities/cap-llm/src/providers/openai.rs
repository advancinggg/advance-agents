//! OpenAI-compatible REST adapter (covers `openai`, `local-llm`, `mistral`,
//! `together-ai`, etc.). Embedding model is hardcoded to
//! `text-embedding-3-small` per the round-4 W2 accepted limitation
//! (Slice C will add `LlmProviderConfig.embedding_model`).

use advance_shared_types::security_validator::{HttpMethod, HttpRequest};
use serde_json::{json, Value};

use crate::cost::CacheUsage;
use crate::error::LlmError;
use crate::executor::ExecutionOutcome;
use crate::gateway::{ChatMessage, ChatParams, ChatRole, ToolCall};
use crate::provider::ResolvedProvider;
use crate::providers::sse::{SseEvent, SseFrame, SseToolCallDelta, SseUsage};
use crate::providers::{auth_header_for, ProviderAdapter};

pub struct OpenAiAdapter;

pub(crate) const OPENAI_EMBED_MODEL: &str = "text-embedding-3-small";

impl OpenAiAdapter {
    /// Shared chat body for the buffered and streaming builders (ADR
    /// 2026-07-22 D4 — the stream variant only ADDS fields).
    fn chat_body(
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Value {
        let mut body = json!({
            "model": provider.model,
            "messages": json_messages(messages),
        });
        if let Some(t) = params.temperature {
            body["temperature"] = json!(t);
        }
        if let Some(m) = params.max_tokens {
            body["max_tokens"] = json!(m);
        }
        if let Some(stop) = &params.stop_sequences {
            body["stop"] = json!(stop);
        }
        if let Some(tools) = params.tools.as_ref().filter(|t| !t.is_empty()) {
            body["tools"] = json!(tools
                .iter()
                .map(|t| json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                }))
                .collect::<Vec<_>>());
        }
        // The entry's reasoning setting, top-level as OpenAI-compatible reasoning models take
        // it. Absent = the body is byte-identical to an entry without one.
        if let Some(effort) = provider.reasoning_effort {
            body["reasoning_effort"] = json!(effort.as_str());
        }
        body
    }
}

/// Whether `object` (a chat `message` or a stream `delta`) carries non-empty reasoning output:
/// `reasoning_content` or `reasoning`, the two spellings OpenAI-compatible servers use.
pub(crate) fn has_reasoning(object: &Value) -> bool {
    ["reasoning_content", "reasoning"]
        .iter()
        .any(|key| object[*key].as_str().is_some_and(|s| !s.is_empty()))
}

fn parse_message_tool_calls(message: &Value) -> Vec<ToolCall> {
    let Some(arr) = message.get("tool_calls").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        let name = item["function"]["name"]
            .as_str()
            .or_else(|| item["name"].as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let arguments = match &item["function"]["arguments"] {
            Value::String(s) => s.clone(),
            Value::Null => item["arguments"].as_str().unwrap_or("{}").to_string(),
            other => other.to_string(),
        };
        out.push(ToolCall {
            id: item["id"].as_str().unwrap_or("").to_string(),
            name,
            arguments,
        });
    }
    out
}

fn parse_sse_tool_call_deltas(value: &Value) -> Option<Vec<SseToolCallDelta>> {
    let arr = value["choices"][0]["delta"]
        .get("tool_calls")
        .and_then(Value::as_array)?;
    if arr.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for item in arr {
        let index = item["index"].as_u64().unwrap_or(0) as usize;
        let name = item["function"]["name"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let arguments = item["function"]["arguments"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let id = item["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if name.is_none() && arguments.is_none() && id.is_none() {
            continue;
        }
        out.push(SseToolCallDelta {
            index,
            id,
            name,
            arguments,
        });
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn json_messages(messages: &[ChatMessage]) -> Value {
    let arr: Vec<Value> = messages.iter().map(chat_message_to_json).collect();
    Value::Array(arr)
}

fn chat_message_to_json(m: &ChatMessage) -> Value {
    match m.role {
        ChatRole::Tool => {
            let mut obj = json!({
                "role": "tool",
                "content": m.content,
            });
            if let Some(id) = &m.tool_call_id {
                obj["tool_call_id"] = json!(id);
            }
            obj
        }
        ChatRole::Assistant if !m.tool_calls.is_empty() => {
            json!({
                "role": "assistant",
                "content": if m.content.is_empty() { Value::Null } else { json!(m.content) },
                "tool_calls": m.tool_calls.iter().map(|c| json!({
                    "id": c.id,
                    "type": "function",
                    "function": {
                        "name": c.name,
                        "arguments": c.arguments,
                    }
                })).collect::<Vec<_>>(),
            })
        }
        _ => json!({ "role": m.role.as_str(), "content": m.content }),
    }
}

impl ProviderAdapter for OpenAiAdapter {
    fn build_chat_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        let url = format!(
            "{}/v1/chat/completions",
            provider.endpoint.trim_end_matches('/')
        );
        let body = Self::chat_body(provider, messages, params);
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| LlmError::ProviderError(format!("serialize chat body: {e}")))?;
        Ok(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: vec![
                auth_header_for(provider),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: body_bytes,
        })
    }

    fn build_stream_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        let url = format!(
            "{}/v1/chat/completions",
            provider.endpoint.trim_end_matches('/')
        );
        let mut body = Self::chat_body(provider, messages, params);
        body["stream"] = json!(true);
        // Terminal-only usage (MODULE-009-AC-21): the final chunk before
        // [DONE] carries prompt/completion totals only when requested.
        body["stream_options"] = json!({ "include_usage": true });
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| LlmError::ProviderError(format!("serialize chat body: {e}")))?;
        Ok(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: vec![
                auth_header_for(provider),
                ("Content-Type".into(), "application/json".into()),
                ("Accept".into(), "text/event-stream".into()),
            ],
            body: body_bytes,
        })
    }

    fn parse_sse_frame(&self, frame: &SseFrame) -> Result<SseEvent, LlmError> {
        // Chat Completions terminates via the [DONE] sentinel.
        if frame.data == "[DONE]" {
            return Ok(SseEvent {
                terminal: true,
                ..SseEvent::IGNORE
            });
        }
        let value: Value = serde_json::from_str(&frame.data).map_err(|_| {
            // Chat SSE data is strictly JSON-or-[DONE]; anything else is a
            // protocol violation → fail CLOSED with a static reason.
            LlmError::ProviderError("invalid stream frame".into())
        })?;
        // In-band error probe BEFORE typed decode (MODULE-009-AC-21):
        // object form {"error":{...}} and flat form {code, error}.
        if value.get("error").map(Value::is_object) == Some(true)
            || (value.get("code").is_some() && value.get("error").is_some())
        {
            return Err(LlmError::ProviderError("in-band error frame".into()));
        }
        let delta = value["choices"][0]["delta"]["content"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let finish_reason = value["choices"][0]["finish_reason"]
            .as_str()
            .map(str::to_string);
        let usage = value
            .get("usage")
            .filter(|u| u.is_object())
            .map(|u| SseUsage {
                // `prompt_tokens` is the TOTAL; `cached_tokens` is a subset.
                input_tokens: u["prompt_tokens"].as_u64(),
                output_tokens: u["completion_tokens"].as_u64(),
                cache_read_tokens: u["prompt_tokens_details"]["cached_tokens"].as_u64(),
                cache_write_tokens: None,
                cache_write_1h_tokens: None,
            });
        let tool_call_deltas = parse_sse_tool_call_deltas(&value);
        // Reasoning output is never text, but it is progress: a reasoning model may stream
        // many such chunks before its first content delta.
        let reasoning = has_reasoning(&value["choices"][0]["delta"]);
        if delta.is_none()
            && finish_reason.is_none()
            && usage.is_none()
            && tool_call_deltas.is_none()
        {
            if reasoning {
                return Ok(SseEvent::REASONING);
            }
            // Role-only first chunk / keep-alive → Ignore, never Some("").
            return Ok(SseEvent::IGNORE);
        }
        Ok(SseEvent {
            delta,
            usage,
            finish_reason,
            terminal: false,
            tool_call_deltas,
            reasoning,
        })
    }

    fn parse_chat_response(&self, status: u16, body: &[u8]) -> Result<ExecutionOutcome, LlmError> {
        if status == 200 {
            let value: Value = serde_json::from_slice(body)
                .map_err(|_| LlmError::ProviderError("invalid response shape".into()))?;
            let message = &value["choices"][0]["message"];
            let tool_calls = parse_message_tool_calls(message);
            // `content` is JSON null when the model returns only tool_calls, and when a
            // reasoning model spends its whole budget reasoning (`reasoning_content` /
            // `reasoning` set, typically with finish_reason "length"): both are answers with
            // empty text. A null `content` with neither is still a malformed answer.
            let text = match message["content"].as_str() {
                Some(content) => content.to_string(),
                None if !tool_calls.is_empty() => String::new(),
                // `Index` yields `Null` for an absent key too.
                None if message["content"].is_null() && has_reasoning(message) => String::new(),
                None => return Err(LlmError::ProviderError("invalid response shape".into())),
            };
            let model = value["model"].as_str().unwrap_or("").to_string();
            // Round-AUDIT-5 C1 fix: missing usage fields MUST NOT silently
            // coerce to 0. The earlier `unwrap_or(0)` would let a malformed
            // upstream response bypass run-budget accumulation (cost would
            // commit as 0 even though the call succeeded). OpenAI's API
            // contract always returns usage on 200; missing values indicate
            // a malformed proxy or upstream-spec violation.
            let input_tokens = value["usage"]["prompt_tokens"]
                .as_u64()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            let output_tokens = value["usage"]["completion_tokens"]
                .as_u64()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            // Prompt-cache hits: `prompt_tokens_details.cached_tokens` is a
            // SUBSET of `prompt_tokens` (already counted in the total) and is
            // billed at the cache-read rate. Optional — absent → 0.
            let cache = CacheUsage {
                read_tokens: value["usage"]["prompt_tokens_details"]["cached_tokens"]
                    .as_u64()
                    .unwrap_or(0),
                write_tokens: 0,
                write_1h_tokens: 0,
            }
            .clamped_to(input_tokens);
            let finish_reason = value["choices"][0]["finish_reason"]
                .as_str()
                .unwrap_or("stop")
                .to_string();
            return Ok(ExecutionOutcome {
                text,
                model,
                input_tokens,
                output_tokens,
                cache,
                finish_reason,
                tool_calls,
            });
        }
        Err(map_status_to_llm_err(status, body))
    }

    fn build_embed_request(
        &self,
        provider: &ResolvedProvider,
        text: &str,
    ) -> Result<HttpRequest, LlmError> {
        let url = format!("{}/v1/embeddings", provider.endpoint.trim_end_matches('/'));
        let model = provider
            .embedding_model
            .as_deref()
            .unwrap_or(OPENAI_EMBED_MODEL);
        let body = json!({
            "model": model,
            "input": text,
        });
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| LlmError::ProviderError(format!("serialize embed body: {e}")))?;
        Ok(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: vec![
                auth_header_for(provider),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: body_bytes,
        })
    }

    fn parse_embed_response(&self, status: u16, body: &[u8]) -> Result<Vec<f32>, LlmError> {
        if status == 200 {
            let value: Value = serde_json::from_slice(body)
                .map_err(|_| LlmError::ProviderError("invalid response shape".into()))?;
            let arr = value["data"][0]["embedding"]
                .as_array()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            // Round-AUDIT-5 W1 fix: non-numeric embedding elements MUST NOT
            // silently coerce to 0.0. A poisoned embedding would degrade
            // MODULE-004/010/011 retrieval quality without surfacing any
            // error. Reject malformed entries with ProviderError.
            let mut embedding: Vec<f32> = Vec::with_capacity(arr.len());
            for v in arr {
                let f = v
                    .as_f64()
                    .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
                embedding.push(f as f32);
            }
            return Ok(embedding);
        }
        Err(map_status_to_llm_err(status, body))
    }

    fn embedding_model(&self) -> Option<&'static str> {
        Some(OPENAI_EMBED_MODEL)
    }
}

/// Shared OpenAI-status → LlmError mapper for THIS adapter's chat + embed
/// paths (module-private). NOTE: this mapper echoes up to 200 upstream body
/// bytes on 400/404 — the OpenAI Responses adapter's CHAT/SSE error path
/// deliberately does NOT use it (that path has its own body-suppressing
/// `map_status_static` for CONTRACT-111 Invariant 7). The Responses EMBED
/// path DOES reach it transitively (via `parse_embed_response` delegation),
/// which is a pre-existing, host-side-only surface (host_fn emits static WIT
/// messages — no guest-visible leak). Do not widen this fn or route the
/// Responses CHAT/SSE error path through it.
fn map_status_to_llm_err(status: u16, body: &[u8]) -> LlmError {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    match status {
        400 => {
            // Try to detect context_length_exceeded.
            if let Ok(v) = serde_json::from_str::<Value>(body_str) {
                if v["error"]["type"].as_str() == Some("context_length_exceeded") {
                    let msg = v["error"]["message"].as_str().unwrap_or("context too long");
                    return LlmError::ContextTooLong(msg.to_string());
                }
            }
            LlmError::ProviderError(format!("http 400: {}", truncate(body_str, 200)))
        }
        401 | 403 => LlmError::ProviderError("auth failed".into()),
        404 => {
            if body_str.to_ascii_lowercase().contains("model") {
                LlmError::ModelNotAvailable("model not found".into())
            } else {
                LlmError::ProviderError(format!("http 404: {}", truncate(body_str, 200)))
            }
        }
        429 => LlmError::RateLimited("rate limited".into()),
        500..=599 => {
            // grok-repass Item 3 (see providers/mod.rs predicates + the
            // anthropic arm's rationale). This arm ADDITIONALLY accepts the
            // `context_length_exceeded` type on 5xx, separator-normalized
            // (any kebab/camel/spaced spelling). DELIBERATE BOUNDARY (audit
            // round 3): the 400 arm above keeps its historical EXACT-literal
            // acceptance — 400-path byte-identity is a lane obligation, so
            // the same proxy spelling classifies differently on 400 vs 5xx;
            // that widened asymmetry is accepted and disclosed here, and
            // changing the 400 arms is /spec territory, not this lane's.
            // STATIC reason only — this does not widen the 400/404 body-echo
            // surface the doc above guards, and the Responses CHAT/SSE
            // routing is unchanged (the Responses EMBED path reaches this
            // arm transitively, a disclosed third adapter surface).
            if let Ok(v) = serde_json::from_str::<Value>(body_str) {
                let err_type = v["error"]["type"].as_str().unwrap_or("");
                let err_code = v["error"]["code"].as_str().unwrap_or("");
                let err_msg = v["error"]["message"].as_str().unwrap_or("");
                // Audit round 5: the REAL OpenAI envelope signals overflow as
                // type invalid_request_error + CODE context_length_exceeded,
                // so both structured fields feed both sides of the
                // classifier symmetrically — gate and acceptance alike.
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

fn truncate(s: &str, max: usize) -> String {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{ChatMessage, ChatParams, ChatRole};
    use crate::providers::sse::SseUsageFold;

    // ── grok-repass Item 3: 5xx-disguised context overflow (L3 rows, openai arm) ──

    /// L3-T2 — 5xx + overflow message maps to ContextTooLong with the STATIC
    /// reason; the openai arm ADDITIONALLY accepts the canonical
    /// `context_length_exceeded` type on 5xx.
    #[test]
    fn t_grok3_openai_5xx_overflow_maps_context_too_long_static() {
        let by_message =
            br#"{"error":{"message":"This model's maximum context length is 128000 tokens"}}"#;
        match map_status_to_llm_err(500, by_message) {
            LlmError::ContextTooLong(msg) => {
                assert_eq!(msg, "context too long");
                assert!(!msg.contains("128000"), "no upstream body fragment");
            }
            other => panic!("expected ContextTooLong (message probe), got {other:?}"),
        }
        let by_type = br#"{"error":{"type":"context_length_exceeded","message":"proxied"}}"#;
        match map_status_to_llm_err(502, by_type) {
            LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
            other => panic!("expected ContextTooLong (type acceptance), got {other:?}"),
        }
        // Audit round 2: the positive acceptance is separator-insensitive,
        // symmetric with the negative gate.
        for body in [
            br#"{"error":{"type":"context-length-exceeded","message":"proxied"}}"#.as_slice(),
            br#"{"error":{"type":"contextLengthExceeded","message":"proxied"}}"#.as_slice(),
        ] {
            match map_status_to_llm_err(502, body) {
                LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
                other => panic!("expected ContextTooLong (normalized type), got {other:?}"),
            }
        }
    }

    /// Audit round 5 — the REAL OpenAI envelope on the openai arm: overflow
    /// as type invalid_request_error + CODE context_length_exceeded. RED
    /// against the type-only round-4 arm; plus the code-side gate leg.
    #[test]
    fn t_grok3_openai_5xx_code_field_overflow_and_code_side_gate() {
        let overflow = br#"{"error":{"type":"invalid_request_error","code":"context_length_exceeded","message":"request failed"}}"#;
        match map_status_to_llm_err(500, overflow) {
            LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
            other => panic!("expected ContextTooLong (code acceptance), got {other:?}"),
        }
        let transient_code = br#"{"error":{"code":"rate_limit_exceeded","message":"request exceeds the maximum context capacity right now, retry"}}"#;
        match map_status_to_llm_err(500, transient_code) {
            LlmError::ProviderError(msg) => assert_eq!(msg, "upstream 500"),
            other => panic!("expected ProviderError (code-side gate), got {other:?}"),
        }
    }

    /// Audit round 6 — the CONFLICT RULE on the openai arm, both directions
    /// (see providers/mod.rs conflict-rule doc): contradictory structured
    /// fields are not an unambiguous overflow signal; stay retryable.
    #[test]
    fn t_grok3_openai_5xx_contradictory_fields_stay_retryable() {
        let overflow_type_transient_code = br#"{"error":{"type":"context_length_exceeded","code":"server_error","message":"request failed"}}"#;
        assert!(matches!(
            map_status_to_llm_err(500, overflow_type_transient_code),
            LlmError::ProviderError(msg) if msg == "upstream 500"
        ));
        let transient_type_overflow_code = br#"{"error":{"type":"overloaded_error","code":"context_length_exceeded","message":"request failed"}}"#;
        assert!(matches!(
            map_status_to_llm_err(500, transient_type_overflow_code),
            LlmError::ProviderError(msg) if msg == "upstream 500"
        ));
    }

    /// Audit round 3 — CONTROL pinning the DELIBERATE 400-vs-5xx boundary:
    /// the 400 arm keeps its historical exact-literal acceptance (the lane's
    /// 400-path byte-identity obligation), so a non-canonical spelling that
    /// the 5xx arm accepts falls through to the plain 400 mapping. Green
    /// before and after; it exists so the disclosed asymmetry is tested,
    /// not just prose.
    #[test]
    fn t_grok3_openai_400_keeps_exact_literal_type_acceptance() {
        let canonical = br#"{"error":{"type":"context_length_exceeded","message":"too long"}}"#;
        assert!(matches!(
            map_status_to_llm_err(400, canonical),
            LlmError::ContextTooLong(_)
        ));
        let kebab = br#"{"error":{"type":"context-length-exceeded","message":"too long"}}"#;
        match map_status_to_llm_err(400, kebab) {
            LlmError::ProviderError(msg) => {
                assert!(msg.starts_with("http 400"), "pre-lane 400 behaviour: {msg}")
            }
            other => panic!("400 arm must keep exact-literal acceptance, got {other:?}"),
        }
    }

    /// L3-T5 — CONTROL: adversarial transient bodies at the narrowed edge.
    #[test]
    fn t_grok3_openai_5xx_adversarial_transient_bodies_stay_retryable() {
        let bodies: [&[u8]; 3] = [
            br#"{"error":{"message":"token limit reached, please retry"}}"#,
            br#"{"error":{"message":"context too busy, retry shortly"}}"#,
            br#"{"error":{"message":"capacity exceeded; context too many concurrent requests"}}"#,
        ];
        for body in bodies {
            match map_status_to_llm_err(503, body) {
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

    /// L3-T7 (openai arm) — the six-member type gate, one witness each; every
    /// message trips the phrase probe so a deleted gate fails the row.
    #[test]
    fn t_grok3_openai_5xx_transient_type_gate_wins_over_phrase_probe() {
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
            match map_status_to_llm_err(500, body.as_bytes()) {
                LlmError::ProviderError(msg) => assert_eq!(msg, "upstream 500"),
                other => panic!("type {err_type}: expected ProviderError, got {other:?}"),
            }
        }
    }

    /// L3-T7b (openai arm) — the pinned residual.
    #[test]
    fn t_grok3_openai_5xx_residual_unknown_type_with_overflow_message() {
        let body = br#"{"error":{"type":"quota_exhausted_error","message":"prompt is too long for this deployment"}}"#;
        match map_status_to_llm_err(500, body) {
            LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
            other => panic!("expected ContextTooLong (pinned residual), got {other:?}"),
        }
    }

    /// L3-T8 (openai arm) — CONTROL: plain 5xx unchanged.
    #[test]
    fn t_grok3_openai_5xx_plain_error_body_unchanged() {
        match map_status_to_llm_err(502, br#"{"error":{"message":"bad gateway"}}"#) {
            LlmError::ProviderError(msg) => assert_eq!(msg, "upstream 502"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    /// Cache billing — `prompt_tokens` is already the TOTAL and
    /// `prompt_tokens_details.cached_tokens` is a SUBSET: the outcome keeps
    /// the total as-is and carries the cached share as a read (never a write).
    #[test]
    fn t_openai_parse_chat_response_cached_tokens_is_subset_read() {
        let body = br#"{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":800}},"model":"gpt-4o"}"#;
        let outcome = OpenAiAdapter.parse_chat_response(200, body).unwrap();
        assert_eq!(
            outcome.input_tokens, 1000,
            "total must NOT be inflated by the subset"
        );
        assert_eq!(
            outcome.cache,
            CacheUsage {
                read_tokens: 800,
                write_tokens: 0,
                write_1h_tokens: 0,
            }
        );
    }

    /// Cache billing — a `cached_tokens` larger than `prompt_tokens` is
    /// malformed; the cached share is clamped to the total.
    #[test]
    fn t_openai_parse_chat_response_cached_tokens_clamped_to_prompt() {
        let body = br#"{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":999}},"model":"gpt-4o"}"#;
        let outcome = OpenAiAdapter.parse_chat_response(200, body).unwrap();
        assert_eq!(outcome.cache.read_tokens, 10);
    }

    /// Cache billing (stream) — the terminal usage chunk's
    /// `prompt_tokens_details.cached_tokens` folds as a cache read.
    #[test]
    fn t_openai_chat_stream_usage_chunk_folds_cached_tokens() {
        let mut fold = SseUsageFold::default();
        let frame = SseFrame {
            event: None,
            data: r#"{"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":800}}}"#.to_string(),
        };
        fold.apply(&OpenAiAdapter.parse_sse_frame(&frame).unwrap());
        assert_eq!(
            (fold.input_tokens, fold.output_tokens),
            (Some(1000), Some(5))
        );
        assert_eq!(fold.cache_read_tokens, Some(800));
        assert_eq!(fold.cache_write_tokens, None);
    }

    /// Round-AUDIT-5 C1 — chat 200 response without `usage.prompt_tokens`
    /// must reject as ProviderError("invalid response shape"). Prevents
    /// silent zero-token commits to RunBudget on malformed proxies.
    #[test]
    fn t_openai_parse_chat_response_missing_prompt_tokens_rejected() {
        let body = br#"{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"completion_tokens":5},"model":"gpt-4o"}"#;
        let result = OpenAiAdapter.parse_chat_response(200, body);
        match result {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid response shape"),
            other => panic!("expected ProviderError(invalid response shape), got {other:?}"),
        }
    }

    /// Round-AUDIT-5 C1 — chat 200 response without `usage.completion_tokens`
    /// must reject (output_tokens cannot be silently 0).
    #[test]
    fn t_openai_parse_chat_response_missing_completion_tokens_rejected() {
        let body = br#"{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3},"model":"gpt-4o"}"#;
        let result = OpenAiAdapter.parse_chat_response(200, body);
        match result {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid response shape"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    /// Round-AUDIT-5 C1 — chat 200 response without `usage` object at all
    /// must reject. Defends against complete usage-stripping proxies.
    #[test]
    fn t_openai_parse_chat_response_missing_usage_object_rejected() {
        let body = br#"{"choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"model":"gpt-4o"}"#;
        let result = OpenAiAdapter.parse_chat_response(200, body);
        assert!(
            matches!(result, Err(LlmError::ProviderError(_))),
            "expected ProviderError on missing usage, got {result:?}"
        );
    }

    /// Round-AUDIT-5 W1 — embedding response with non-numeric element must
    /// reject (cannot poison vector store with silent 0.0 coercion).
    #[test]
    fn t_openai_parse_embed_response_non_numeric_rejected() {
        let body = br#"{"data":[{"embedding":[0.1, "not-a-number", 0.3]}]}"#;
        let result = OpenAiAdapter.parse_embed_response(200, body);
        match result {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid response shape"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    fn provider(endpoint: &str) -> ResolvedProvider {
        ResolvedProvider {
            id: "openai".into(),
            endpoint: endpoint.into(),
            api_key_secret: "openai-api-key".into(),
            model: "gpt-4o".into(),
            cost_per_mtoken_in: 2.5,
            cost_per_mtoken_out: 10.0,
            cache_cost: Default::default(),
            backend: advance_runtime::config::ProviderBackend::OpenAiChat,
            auth_scheme: None,
            backend_class: advance_runtime::config::InferenceBackendClass::CloudHttp,
            embedding_model: None,
            auth_source: advance_runtime::config::ProviderAuthSource::ApiKey,
            generate_timeout: None,
            reasoning_effort: None,
        }
    }

    /// MODULE-009-T69 — OpenAi build_chat_request: Bearer header + content-type + url path.
    #[test]
    fn t69_build_chat_request_shape() {
        let adapter = OpenAiAdapter;
        let p = provider("https://api.openai.com");
        let messages = vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
        }];
        let params = ChatParams::default();
        let req = adapter.build_chat_request(&p, &messages, &params).unwrap();
        assert_eq!(req.url, "https://api.openai.com/v1/chat/completions");
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "Authorization" && v == "Bearer {openai-api-key}"));
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "Content-Type" && v == "application/json"));
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert!(body.get("tools").is_none(), "empty params must omit tools");
    }

    #[test]
    fn t_openai_chat_body_serializes_tools() {
        let adapter = OpenAiAdapter;
        let p = provider("https://api.openai.com");
        let messages = vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
        }];
        let params = ChatParams {
            tools: Some(vec![crate::gateway::ToolDefinition {
                name: "write".into(),
                description: "Write a file".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                }),
            }]),
            ..ChatParams::default()
        };
        let req = adapter.build_chat_request(&p, &messages, &params).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "write");
        assert_eq!(body["tools"][0]["function"]["description"], "Write a file");
    }

    #[test]
    fn t_openai_parse_chat_response_tool_calls_null_content() {
        let adapter = OpenAiAdapter;
        let body = br#"{"choices":[{"message":{"content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"write","arguments":"{\"path\":\"roadmap.md\",\"content\":\"hi\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":8},"model":"deepseek-flash"}"#;
        let outcome = adapter.parse_chat_response(200, body).unwrap();
        assert_eq!(outcome.text, "");
        assert_eq!(outcome.finish_reason, "tool_calls");
        assert_eq!(outcome.tool_calls.len(), 1);
        assert_eq!(outcome.tool_calls[0].name, "write");
        assert!(outcome.tool_calls[0].arguments.contains("roadmap.md"));
    }

    #[test]
    fn t_openai_parse_sse_tool_call_deltas() {
        let adapter = OpenAiAdapter;
        let open = adapter
            .parse_sse_frame(&data_frame(
                r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"write","arguments":""}}]}}]}"#,
            ))
            .unwrap();
        assert_eq!(
            open.tool_call_deltas.as_ref().unwrap()[0].name.as_deref(),
            Some("write")
        );
        let args = adapter
            .parse_sse_frame(&data_frame(
                r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":\"a.md\"}"}}]}}]}"#,
            ))
            .unwrap();
        assert_eq!(
            args.tool_call_deltas.as_ref().unwrap()[0]
                .arguments
                .as_deref(),
            Some("{\"path\":\"a.md\"}")
        );
        let mut fold = crate::providers::sse::ToolCallFold::default();
        fold.apply(&open);
        fold.apply(&args);
        let calls = fold.finish();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "write");
        assert_eq!(calls[0].arguments, "{\"path\":\"a.md\"}");
    }

    /// The 16-token preflight answer of an OpenAI-compatible reasoning model: the whole budget
    /// went to reasoning, so `content` is null and the reasoning field is set.
    const REASONING_ONLY_CONTENT: &[u8] = br#"{"choices":[{"index":0,"message":{"role":"assistant","content":null,"reasoning_content":"The user says ping. I should answer"},"finish_reason":"length"}],"usage":{"prompt_tokens":9,"completion_tokens":16,"completion_tokens_details":{"reasoning_tokens":16}},"model":"reasoner-1"}"#;

    #[test]
    fn t_openai_parse_chat_response_reasoning_content_only_is_an_empty_answer() {
        let outcome = OpenAiAdapter
            .parse_chat_response(200, REASONING_ONLY_CONTENT)
            .expect("a reasoning-only answer is valid");
        assert_eq!(outcome.text, "");
        assert_eq!(outcome.finish_reason, "length");
        assert_eq!((outcome.input_tokens, outcome.output_tokens), (9, 16));
        assert!(outcome.tool_calls.is_empty());
        assert_eq!(outcome.model, "reasoner-1");
    }

    #[test]
    fn t_openai_parse_chat_response_reasoning_only_is_an_empty_answer_for_both_spellings() {
        // `reasoning` instead of `reasoning_content`, and `content` absent instead of null.
        for body in [
            br#"{"choices":[{"message":{"content":null,"reasoning":"thinking"},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":16}}"#.as_slice(),
            br#"{"choices":[{"message":{"reasoning":"thinking"},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":16}}"#.as_slice(),
            br#"{"choices":[{"message":{"reasoning_content":"thinking"},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":16}}"#.as_slice(),
        ] {
            let outcome = OpenAiAdapter
                .parse_chat_response(200, body)
                .unwrap_or_else(|e| panic!("{e:?}: {}", String::from_utf8_lossy(body)));
            assert_eq!(outcome.text, "");
            assert_eq!(outcome.output_tokens, 16);
        }
    }

    #[test]
    fn t_openai_parse_chat_response_null_content_without_reasoning_or_tools_stays_invalid() {
        for body in [
            // Round-AUDIT-5 intent: a null answer is not silently an empty one.
            br#"{"choices":[{"message":{"content":null},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}"#.as_slice(),
            // Empty or non-string reasoning is no reasoning.
            br#"{"choices":[{"message":{"content":null,"reasoning_content":""},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}"#.as_slice(),
            br#"{"choices":[{"message":{"content":null,"reasoning":{"text":"x"}},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}"#.as_slice(),
            // A non-null, non-string content is malformed even beside reasoning.
            br#"{"choices":[{"message":{"content":7,"reasoning_content":"x"},"finish_reason":"length"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}"#.as_slice(),
        ] {
            match OpenAiAdapter.parse_chat_response(200, body) {
                Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid response shape"),
                other => panic!("{}: {other:?}", String::from_utf8_lossy(body)),
            }
        }
    }

    #[test]
    fn t_openai_parse_chat_response_reasoning_answer_still_requires_usage() {
        let body = br#"{"choices":[{"message":{"content":null,"reasoning_content":"thinking"},"finish_reason":"length"}]}"#;
        match OpenAiAdapter.parse_chat_response(200, body) {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid response shape"),
            other => panic!("missing usage must stay an error, got {other:?}"),
        }
    }

    #[test]
    fn t_openai_parse_chat_response_string_content_is_unchanged_beside_reasoning() {
        let body = br#"{"choices":[{"message":{"content":"pong","reasoning_content":"The user says ping."},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":40}}"#;
        let outcome = OpenAiAdapter.parse_chat_response(200, body).unwrap();
        assert_eq!(outcome.text, "pong", "reasoning never joins the text");
        assert_eq!(outcome.finish_reason, "stop");
    }

    #[test]
    fn t_openai_reasoning_stream_frames_are_progress_never_text() {
        let adapter = OpenAiAdapter;
        for data in [
            r#"{"choices":[{"index":0,"delta":{"reasoning_content":"The user"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"role":"assistant","content":null,"reasoning":" says"}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"content":"","reasoning_content":" ping"}}]}"#,
        ] {
            let ev = adapter.parse_sse_frame(&data_frame(data)).unwrap();
            assert_eq!(ev, SseEvent::REASONING, "{data}");
        }
        // Reasoning beside a usage or finish frame keeps those, flagged as reasoning.
        let ev = adapter
            .parse_sse_frame(&data_frame(
                r#"{"choices":[{"index":0,"delta":{"reasoning_content":"x"},"finish_reason":"length"}]}"#,
            ))
            .unwrap();
        assert!(ev.reasoning);
        assert_eq!(ev.finish_reason.as_deref(), Some("length"));
        assert_eq!(ev.delta, None);
        // Empty reasoning is not reasoning: the frame stays ignorable.
        let ev = adapter
            .parse_sse_frame(&data_frame(
                r#"{"choices":[{"index":0,"delta":{"reasoning_content":""}}]}"#,
            ))
            .unwrap();
        assert!(ev.is_ignore());
        // A content frame is unchanged.
        let ev = adapter
            .parse_sse_frame(&data_frame(
                r#"{"choices":[{"index":0,"delta":{"content":"pong"}}]}"#,
            ))
            .unwrap();
        assert_eq!(ev.delta.as_deref(), Some("pong"));
        assert!(!ev.reasoning);
    }

    #[test]
    fn t_openai_reasoning_effort_is_sent_top_level_on_chat_and_stream_requests() {
        use advance_runtime::config::ReasoningEffort;
        let messages = vec![ChatMessage {
            role: ChatRole::User,
            content: "ping".into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
        }];
        let params = ChatParams {
            max_tokens: Some(16),
            ..ChatParams::default()
        };
        let plain = provider("https://gw.example");
        let buffered = OpenAiAdapter
            .build_chat_request(&plain, &messages, &params)
            .unwrap();
        // Absent: byte-identical to the request of an entry without the key.
        assert_eq!(
            String::from_utf8(buffered.body.clone()).unwrap(),
            r#"{"max_tokens":16,"messages":[{"content":"ping","role":"user"}],"model":"gpt-4o"}"#
        );
        let streamed = OpenAiAdapter
            .build_stream_request(&plain, &messages, &params)
            .unwrap();
        assert_eq!(
            String::from_utf8(streamed.body).unwrap(),
            r#"{"max_tokens":16,"messages":[{"content":"ping","role":"user"}],"model":"gpt-4o","stream":true,"stream_options":{"include_usage":true}}"#
        );

        for effort in ReasoningEffort::ALL {
            let p = ResolvedProvider {
                reasoning_effort: Some(effort),
                ..provider("https://gw.example")
            };
            let buffered = OpenAiAdapter
                .build_chat_request(&p, &messages, &params)
                .unwrap();
            assert_eq!(
                String::from_utf8(buffered.body).unwrap(),
                format!(
                    r#"{{"max_tokens":16,"messages":[{{"content":"ping","role":"user"}}],"model":"gpt-4o","reasoning_effort":"{}"}}"#,
                    effort.as_str()
                )
            );
            let streamed = OpenAiAdapter
                .build_stream_request(&p, &messages, &params)
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&streamed.body).unwrap();
            assert_eq!(body["reasoning_effort"], effort.as_str());
            assert_eq!(body["stream"], true);
        }
        // Never on an embedding request.
        let p = ResolvedProvider {
            reasoning_effort: Some(ReasoningEffort::High),
            ..provider("https://gw.example")
        };
        let embed = OpenAiAdapter.build_embed_request(&p, "hello").unwrap();
        assert!(!String::from_utf8(embed.body).unwrap().contains("reasoning"));
    }

    /// MODULE-009-T70 — OpenAi parse_chat_response status mapping.
    #[test]
    fn t70_parse_chat_response_200() {
        let adapter = OpenAiAdapter;
        let body = br#"{"choices":[{"message":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":5},"model":"gpt-4o-mini"}"#;
        let outcome = adapter.parse_chat_response(200, body).unwrap();
        assert_eq!(outcome.text, "hello");
        assert_eq!(outcome.input_tokens, 3);
        assert_eq!(outcome.output_tokens, 5);
        assert_eq!(outcome.finish_reason, "stop");
    }

    #[test]
    fn t70_parse_chat_response_400_context_too_long() {
        let adapter = OpenAiAdapter;
        let body = br#"{"error":{"type":"context_length_exceeded","message":"too long"}}"#;
        match adapter.parse_chat_response(400, body) {
            Err(LlmError::ContextTooLong(msg)) => assert!(msg.contains("too long")),
            other => panic!("expected ContextTooLong, got {other:?}"),
        }
    }

    #[test]
    fn t70_parse_chat_response_401_provider_error() {
        let adapter = OpenAiAdapter;
        match adapter.parse_chat_response(401, b"unauthorized") {
            Err(LlmError::ProviderError(_)) => {}
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    #[test]
    fn t70_parse_chat_response_404_model_not_available() {
        let adapter = OpenAiAdapter;
        let body = br#"{"error":{"message":"model not found"}}"#;
        match adapter.parse_chat_response(404, body) {
            Err(LlmError::ModelNotAvailable(_)) => {}
            other => panic!("expected ModelNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn t70_parse_chat_response_429_rate_limited() {
        let adapter = OpenAiAdapter;
        match adapter.parse_chat_response(429, b"") {
            Err(LlmError::RateLimited(_)) => {}
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn t70_parse_chat_response_500_provider_error() {
        let adapter = OpenAiAdapter;
        match adapter.parse_chat_response(500, b"") {
            Err(LlmError::ProviderError(msg)) => assert!(msg.contains("500")),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    #[test]
    fn t70_parse_chat_response_malformed() {
        let adapter = OpenAiAdapter;
        match adapter.parse_chat_response(200, b"not json") {
            Err(LlmError::ProviderError(_)) => {}
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    #[test]
    fn t_openai_build_embed_request_shape() {
        let adapter = OpenAiAdapter;
        let p = provider("https://api.openai.com");
        let req = adapter.build_embed_request(&p, "hello").unwrap();
        assert_eq!(req.url, "https://api.openai.com/v1/embeddings");
        let body_str = std::str::from_utf8(&req.body).unwrap();
        assert!(body_str.contains("text-embedding-3-small"));
        assert!(body_str.contains("hello"));
    }

    #[test]
    fn t_openai_parse_embed_response_200() {
        let adapter = OpenAiAdapter;
        let body = br#"{"data":[{"embedding":[0.1, 0.2, 0.3]}]}"#;
        let v = adapter.parse_embed_response(200, body).unwrap();
        assert_eq!(v.len(), 3);
    }

    use crate::providers::sse::SseFrame;

    fn data_frame(data: &str) -> SseFrame {
        SseFrame {
            event: None,
            data: data.to_string(),
        }
    }

    /// MODULE-009-T116 (request leg) — stream request adds stream:true +
    /// stream_options.include_usage + SSE Accept; buffered body unchanged.
    #[test]
    fn t116_build_stream_request_adds_stream_fields() {
        let adapter = OpenAiAdapter;
        let p = provider("https://api.openai.com");
        let messages = vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
            tool_call_id: None,
            tool_calls: Vec::new(),
        }];
        let req = adapter
            .build_stream_request(&p, &messages, &ChatParams::default())
            .unwrap();
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["stream"], Value::Bool(true));
        assert_eq!(body["stream_options"]["include_usage"], Value::Bool(true));
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "Accept" && v == "text/event-stream"));
    }

    /// MODULE-009-T117 — chat streaming: terminal-ONLY usage (final chunk
    /// carries totals, [DONE] terminates), delta concat == done text,
    /// role-only first chunk is Ignore (never Some("")).
    #[test]
    fn t117_chat_stream_terminal_only_usage_and_concat() {
        let adapter = OpenAiAdapter;
        let mut acc = String::new();
        let mut fold = crate::providers::sse::SseUsageFold::default();
        let frames = [
            r#"{"choices":[{"delta":{"role":"assistant"},"index":0}]}"#,
            r#"{"choices":[{"delta":{"content":"hel"},"index":0}]}"#,
            r#"{"choices":[{"delta":{"content":"lo"},"index":0}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop","index":0}]}"#,
            r#"{"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5}}"#,
        ];
        let mut saw_finish = None;
        for f in frames {
            let ev = adapter.parse_sse_frame(&data_frame(f)).unwrap();
            if let Some(d) = &ev.delta {
                assert!(!d.is_empty());
                acc.push_str(d);
            }
            if let Some(fr) = &ev.finish_reason {
                saw_finish = Some(fr.clone());
            }
            fold.apply(&ev);
            assert!(!ev.terminal, "only [DONE] terminates chat streams");
        }
        let done = adapter.parse_sse_frame(&data_frame("[DONE]")).unwrap();
        assert!(done.terminal);
        assert_eq!(acc, "hello");
        assert_eq!(saw_finish.as_deref(), Some("stop"));
        assert_eq!(
            (fold.input_tokens, fold.output_tokens),
            (Some(3), Some(5)),
            "usage arrives ONLY in the terminal-adjacent chunk"
        );
        // Role-only chunk normalizes to Ignore.
        let role_only = adapter
            .parse_sse_frame(&data_frame(
                r#"{"choices":[{"delta":{"role":"assistant"},"index":0}]}"#,
            ))
            .unwrap();
        assert!(role_only.is_ignore());
    }

    /// MODULE-009-T118 — in-band error frames (object + flat forms) fold to
    /// enum-coded static reasons; non-JSON garbage fails CLOSED static.
    #[test]
    fn t118_chat_in_band_error_frames_static() {
        let adapter = OpenAiAdapter;
        for data in [
            r#"{"error":{"message":"LEAK https://api?key=sk-1","type":"server_error"}}"#,
            r#"{"code":500,"error":"LEAK internal text"}"#,
        ] {
            match adapter.parse_sse_frame(&data_frame(data)) {
                Err(LlmError::ProviderError(msg)) => {
                    assert_eq!(msg, "in-band error frame");
                    assert!(!msg.contains("LEAK"));
                }
                other => panic!("expected static in-band error, got {other:?}"),
            }
        }
        match adapter.parse_sse_frame(&data_frame("not json garbage")) {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid stream frame"),
            other => panic!("expected static invalid-frame error, got {other:?}"),
        }
    }
}
