//! Anthropic Messages API adapter. Chat-only; embed returns
//! `LlmError::ModelNotAvailable` (round-3 W6: `supports_embedding()` is false,
//! so the gateway's `select_embedding_provider` skips this adapter for embed).

use advance_shared_types::security_validator::{HttpMethod, HttpRequest};
use serde_json::{json, Value};

use crate::error::LlmError;
use crate::executor::ExecutionOutcome;
use crate::gateway::{ChatMessage, ChatParams, ChatRole};
use crate::provider::ResolvedProvider;
use crate::providers::sse::{SseEvent, SseFrame, SseUsage};
use crate::providers::{auth_header_for, ProviderAdapter};

pub struct AnthropicAdapter;

const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 4096;

impl AnthropicAdapter {
    /// Shared chat body for the buffered and streaming builders.
    ///
    /// Round-AUDIT-2 W1: Anthropic's Messages API rejects role=system
    /// entries inside the `messages` array (HTTP 400 invalid_request_error).
    /// System prompts MUST go via the top-level `system` field, so incoming
    /// ChatMessages are partitioned — System messages concatenate (joined
    /// with double newlines) into `system`; User/Assistant stay in
    /// `messages`.
    fn chat_body(
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Value {
        let mut system_parts: Vec<&str> = Vec::new();
        let mut convo: Vec<Value> = Vec::new();
        for m in messages {
            match m.role {
                ChatRole::System => system_parts.push(&m.content),
                ChatRole::User | ChatRole::Assistant => {
                    convo.push(json!({ "role": m.role.as_str(), "content": m.content }));
                }
            }
        }
        let mut body = json!({
            "model": provider.model,
            "messages": convo,
            "max_tokens": params.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS),
        });
        if !system_parts.is_empty() {
            body["system"] = Value::String(system_parts.join("\n\n"));
        }
        if let Some(t) = params.temperature {
            body["temperature"] = json!(t);
        }
        if let Some(stop) = &params.stop_sequences {
            body["stop_sequences"] = json!(stop);
        }
        body
    }

    fn base_headers(provider: &ResolvedProvider) -> Vec<(String, String)> {
        vec![
            auth_header_for(provider),
            ("anthropic-version".into(), ANTHROPIC_VERSION.into()),
            ("content-type".into(), "application/json".into()),
        ]
    }
}

impl ProviderAdapter for AnthropicAdapter {
    fn build_chat_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        let url = format!("{}/v1/messages", provider.endpoint.trim_end_matches('/'));
        let body = Self::chat_body(provider, messages, params);
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| LlmError::ProviderError(format!("serialize chat body: {e}")))?;
        Ok(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers: Self::base_headers(provider),
            body: body_bytes,
        })
    }

    fn build_stream_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        let url = format!("{}/v1/messages", provider.endpoint.trim_end_matches('/'));
        let mut body = Self::chat_body(provider, messages, params);
        body["stream"] = json!(true);
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| LlmError::ProviderError(format!("serialize chat body: {e}")))?;
        let mut headers = Self::base_headers(provider);
        headers.push(("Accept".into(), "text/event-stream".into()));
        Ok(HttpRequest {
            method: HttpMethod::Post,
            url,
            headers,
            body: body_bytes,
        })
    }

    fn parse_sse_frame(&self, frame: &SseFrame) -> Result<SseEvent, LlmError> {
        // In-band error probe BEFORE typed decode (MODULE-009-AC-21):
        // `event: error` and the `{"type":"error",...}` data shape both
        // fold to an enum-coded STATIC reason.
        if frame.event.as_deref() == Some("error") {
            return Err(LlmError::ProviderError("in-band error frame".into()));
        }
        let value: Value = serde_json::from_str(&frame.data).map_err(|_| {
            // Anthropic SSE data is strictly JSON; anything else is a
            // protocol violation → fail CLOSED with a static reason.
            LlmError::ProviderError("invalid stream frame".into())
        })?;
        let name = frame
            .event
            .clone()
            .or_else(|| value["type"].as_str().map(str::to_string));
        match name.as_deref() {
            Some("error") => Err(LlmError::ProviderError("in-band error frame".into())),
            Some("message_start") => {
                let input = value["message"]["usage"]["input_tokens"].as_u64();
                Ok(SseEvent {
                    usage: input.map(|i| SseUsage {
                        input_tokens: Some(i),
                        output_tokens: None,
                    }),
                    ..SseEvent::IGNORE
                })
            }
            Some("content_block_delta") => {
                if value["delta"]["type"].as_str() == Some("text_delta") {
                    let text = value["delta"]["text"].as_str().unwrap_or("");
                    if text.is_empty() {
                        return Ok(SseEvent::IGNORE);
                    }
                    return Ok(SseEvent {
                        delta: Some(text.to_string()),
                        ..SseEvent::IGNORE
                    });
                }
                // input_json_delta / thinking_delta etc. carry no chat text.
                Ok(SseEvent::IGNORE)
            }
            Some("message_delta") => {
                // CUMULATIVE snapshot (MODULE-009-AC-21): output_tokens is
                // the running total, folded last-write-wins by the caller —
                // NEVER summed.
                let output = value["usage"]["output_tokens"].as_u64();
                Ok(SseEvent {
                    usage: output.map(|o| SseUsage {
                        input_tokens: None,
                        output_tokens: Some(o),
                    }),
                    finish_reason: value["delta"]["stop_reason"].as_str().map(str::to_string),
                    ..SseEvent::IGNORE
                })
            }
            Some("message_stop") => Ok(SseEvent {
                terminal: true,
                ..SseEvent::IGNORE
            }),
            // ping / content_block_start / content_block_stop / unknown
            // events: Anthropic's SSE contract instructs clients to ignore
            // event types they don't recognize.
            _ => Ok(SseEvent::IGNORE),
        }
    }

    fn parse_chat_response(&self, status: u16, body: &[u8]) -> Result<ExecutionOutcome, LlmError> {
        if status == 200 {
            let value: Value = serde_json::from_slice(body)
                .map_err(|_| LlmError::ProviderError("invalid response shape".into()))?;
            // content is `[{"type":"text", "text": "..."}, ...]`. Round-AUDIT-6 W2
            // fix: concatenate ALL text blocks (joined by newline) instead of
            // returning only the first one. Anthropic occasionally splits long
            // outputs across multiple text blocks (e.g. when interleaved with
            // tool_use blocks); the earlier `find_map(...).map(first)` path
            // silently truncated those completions.
            let arr = value["content"]
                .as_array()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            let mut parts: Vec<&str> = Vec::new();
            for item in arr {
                if item["type"].as_str() == Some("text") {
                    if let Some(s) = item["text"].as_str() {
                        parts.push(s);
                    }
                }
            }
            if parts.is_empty() {
                return Err(LlmError::ProviderError("invalid response shape".into()));
            }
            let text = parts.join("\n");
            let model = value["model"].as_str().unwrap_or("").to_string();
            // Round-AUDIT-5 C1 fix: missing usage fields MUST NOT silently
            // coerce to 0 — would let a malformed proxy or upstream-spec
            // violation bypass run-budget accumulation. Anthropic's API
            // contract always returns usage on 200.
            let input_tokens = value["usage"]["input_tokens"]
                .as_u64()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            let output_tokens = value["usage"]["output_tokens"]
                .as_u64()
                .ok_or_else(|| LlmError::ProviderError("invalid response shape".into()))?;
            let finish_reason = value["stop_reason"]
                .as_str()
                .unwrap_or("end_turn")
                .to_string();
            return Ok(ExecutionOutcome {
                text,
                model,
                input_tokens,
                output_tokens,
                finish_reason,
            });
        }
        Err(map_anthropic_status(status, body))
    }

    fn build_embed_request(
        &self,
        _provider: &ResolvedProvider,
        _text: &str,
    ) -> Result<HttpRequest, LlmError> {
        Err(LlmError::ModelNotAvailable(
            "anthropic embeddings not supported, use openai-compatible provider".into(),
        ))
    }

    fn parse_embed_response(&self, _status: u16, _body: &[u8]) -> Result<Vec<f32>, LlmError> {
        unreachable!("AnthropicAdapter::build_embed_request errors first; parse never invoked")
    }

    fn supports_embedding(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{ChatMessage, ChatParams, ChatRole};

    fn provider() -> ResolvedProvider {
        ResolvedProvider {
            id: "anthropic".into(),
            endpoint: "https://api.anthropic.com".into(),
            api_key_secret: "anthropic-api-key".into(),
            model: "claude-sonnet-4-5".into(),
            cost_per_mtoken_in: 3.0,
            cost_per_mtoken_out: 15.0,
            backend: advance_runtime::config::ProviderBackend::AnthropicMessages,
            auth_scheme: None,
        }
    }

    /// MODULE-009-T71 — Anthropic build_chat_request: x-api-key (NOT Bearer) +
    /// anthropic-version + url path /v1/messages.
    #[test]
    fn t71_build_chat_request_shape() {
        let adapter = AnthropicAdapter;
        let p = provider();
        let messages = vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }];
        let params = ChatParams {
            max_tokens: Some(100),
            ..Default::default()
        };
        let req = adapter.build_chat_request(&p, &messages, &params).unwrap();
        assert_eq!(req.url, "https://api.anthropic.com/v1/messages");
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "x-api-key" && v == "{anthropic-api-key}"));
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "anthropic-version" && v == ANTHROPIC_VERSION));
        // Should NOT contain Authorization Bearer
        assert!(!req
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("authorization")));
    }

    /// Round-AUDIT-5 C1 — Anthropic chat 200 without `usage.input_tokens`
    /// must reject (no silent zero-token RunBudget commit).
    #[test]
    fn t_anthropic_parse_chat_response_missing_input_tokens_rejected() {
        let body = br#"{"content":[{"type":"text","text":"hi"}],"usage":{"output_tokens":5},"stop_reason":"end_turn","model":"claude"}"#;
        let result = AnthropicAdapter.parse_chat_response(200, body);
        match result {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid response shape"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    /// Round-AUDIT-5 C1 — Anthropic chat 200 without `usage.output_tokens`
    /// must reject.
    #[test]
    fn t_anthropic_parse_chat_response_missing_output_tokens_rejected() {
        let body = br#"{"content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":3},"stop_reason":"end_turn","model":"claude"}"#;
        let result = AnthropicAdapter.parse_chat_response(200, body);
        match result {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid response shape"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    /// Round-AUDIT-6 W2 — multiple text blocks must concatenate (joined by
    /// newline), NOT silently truncate to the first block.
    #[test]
    fn t_anthropic_parse_chat_response_multi_text_blocks_concatenated() {
        let body = br#"{"content":[{"type":"text","text":"first"},{"type":"text","text":"second"},{"type":"text","text":"third"}],"usage":{"input_tokens":3,"output_tokens":5},"stop_reason":"end_turn","model":"claude"}"#;
        let outcome = AnthropicAdapter.parse_chat_response(200, body).unwrap();
        assert_eq!(outcome.text, "first\nsecond\nthird");
    }

    /// Round-AUDIT-6 W2 — text + non-text (e.g. tool_use) blocks: only text
    /// blocks contribute to the concatenated output.
    #[test]
    fn t_anthropic_parse_chat_response_skips_non_text_blocks() {
        let body = br#"{"content":[{"type":"text","text":"intro"},{"type":"tool_use","id":"t1","name":"x"},{"type":"text","text":"outro"}],"usage":{"input_tokens":3,"output_tokens":5},"stop_reason":"end_turn","model":"claude"}"#;
        let outcome = AnthropicAdapter.parse_chat_response(200, body).unwrap();
        assert_eq!(outcome.text, "intro\noutro");
    }

    /// MODULE-009-T72 — Anthropic parse_chat_response: extract content[0].text
    /// + usage.{input_tokens,output_tokens} + stop_reason.
    #[test]
    fn t72_parse_chat_response_200() {
        let adapter = AnthropicAdapter;
        let body = br#"{"content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":3,"output_tokens":5},"stop_reason":"end_turn","model":"claude-sonnet-4-5"}"#;
        let outcome = adapter.parse_chat_response(200, body).unwrap();
        assert_eq!(outcome.text, "hello");
        assert_eq!(outcome.input_tokens, 3);
        assert_eq!(outcome.output_tokens, 5);
        assert_eq!(outcome.finish_reason, "end_turn");
    }

    /// MODULE-009-T73 — Anthropic build_embed_request explicit ModelNotAvailable.
    #[test]
    fn t73_anthropic_embed_not_supported() {
        let adapter = AnthropicAdapter;
        let p = provider();
        match adapter.build_embed_request(&p, "hello") {
            Err(LlmError::ModelNotAvailable(msg)) => {
                assert!(msg.contains("anthropic embeddings not supported"));
            }
            other => panic!("expected ModelNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn t_anthropic_supports_embedding_false() {
        let adapter = AnthropicAdapter;
        assert!(!adapter.supports_embedding());
    }

    /// Round-AUDIT-2 W1 — System messages must be hoisted to the top-level
    /// `system` field; the `messages` array must contain only User/Assistant.
    #[test]
    fn t_anthropic_system_message_hoisted_to_top_level() {
        let adapter = AnthropicAdapter;
        let p = provider();
        let messages = vec![
            ChatMessage {
                role: ChatRole::System,
                content: "You are a helpful assistant.".into(),
            },
            ChatMessage {
                role: ChatRole::User,
                content: "Hello".into(),
            },
            ChatMessage {
                role: ChatRole::System,
                content: "Schema validation failed: foo. Please return valid JSON.".into(),
            },
        ];
        let req = adapter
            .build_chat_request(&p, &messages, &ChatParams::default())
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        // Top-level system contains both system parts joined with double newlines.
        assert_eq!(
            body["system"].as_str().unwrap(),
            "You are a helpful assistant.\n\nSchema validation failed: foo. Please return valid JSON."
        );
        // messages array contains only the User entry — no role:"system" leaked.
        let arr = body["messages"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["role"].as_str().unwrap(), "user");
        assert_eq!(arr[0]["content"].as_str().unwrap(), "Hello");
    }

    #[test]
    fn t_anthropic_no_system_field_when_no_system_messages() {
        let adapter = AnthropicAdapter;
        let p = provider();
        let messages = vec![ChatMessage {
            role: ChatRole::User,
            content: "Hi".into(),
        }];
        let req = adapter
            .build_chat_request(&p, &messages, &ChatParams::default())
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        // When no System messages exist, the top-level `system` key is absent.
        assert!(
            body.get("system").is_none(),
            "expected no `system` key when no system messages present, got {body:?}"
        );
    }

    /// Round-AUDIT-3 W2 — `map_anthropic_status` 400 + `is_context_overflow_message`
    /// keyword family: context-overflow phrases yield `ContextTooLong` (non-
    /// retryable), unrelated 400 messages yield `ProviderError("http 400")`
    /// (also non-retryable per the round-AUDIT-2 whitelist).
    #[test]
    fn t_anthropic_map_status_400_context_overflow_keywords() {
        let cases_overflow = [
            "prompt is too long for context window",
            "context window exceeded",
            "context length 200000 tokens exceeded",
            "context too long",
            "input exceeds the maximum token limit",
            "token limit exceeded",
        ];
        for msg in cases_overflow {
            let body =
                format!(r#"{{"error":{{"type":"invalid_request_error","message":"{msg}"}}}}"#);
            match map_anthropic_status(400, body.as_bytes()) {
                LlmError::ContextTooLong(detail) => assert_eq!(detail, msg),
                other => panic!("expected ContextTooLong for {msg:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn t_anthropic_map_status_400_max_tokens_not_overflow() {
        // `max_tokens` is NOT in the overflow keyword family (round-AUDIT-3 W2 fix)
        // — bad-parameter errors must NOT be misclassified as ContextTooLong.
        let body = br#"{"error":{"type":"invalid_request_error","message":"max_tokens must be a positive integer"}}"#;
        match map_anthropic_status(400, body) {
            LlmError::ProviderError(detail) => assert_eq!(detail, "http 400"),
            other => {
                panic!("expected ProviderError(\"http 400\") for non-overflow 400, got {other:?}")
            }
        }
    }

    /// Round-AUDIT-4 W1 — standalone `exceeds the maximum` (without `context`)
    /// must NOT classify as ContextTooLong. Anthropic returns this phrase
    /// for many bad-parameter 400 errors that aren't context-related.
    #[test]
    fn t_anthropic_map_status_400_exceeds_maximum_without_context_not_overflow() {
        for msg in [
            "max_tokens exceeds the maximum allowed value",
            "stop_sequences count exceeds the maximum of 4",
            "tool count exceeds the maximum of 64",
        ] {
            let body =
                format!(r#"{{"error":{{"type":"invalid_request_error","message":"{msg}"}}}}"#);
            match map_anthropic_status(400, body.as_bytes()) {
                LlmError::ProviderError(detail) => assert_eq!(
                    detail, "http 400",
                    "non-context 'exceeds the maximum' must NOT be ContextTooLong, got: {msg:?}"
                ),
                other => panic!("expected ProviderError for {msg:?}, got {other:?}"),
            }
        }
        // But the explicit `exceeds the maximum context` IS overflow.
        let body = br#"{"error":{"type":"invalid_request_error","message":"prompt exceeds the maximum context window of 200000 tokens"}}"#;
        match map_anthropic_status(400, body) {
            LlmError::ContextTooLong(_) => {}
            other => {
                panic!("expected ContextTooLong for explicit 'maximum context', got {other:?}")
            }
        }
    }

    #[test]
    fn t_anthropic_map_status_400_unrelated_invalid_request() {
        let body = br#"{"error":{"type":"invalid_request_error","message":"messages array cannot be empty"}}"#;
        match map_anthropic_status(400, body) {
            LlmError::ProviderError(detail) => assert_eq!(detail, "http 400"),
            other => panic!("expected ProviderError(\"http 400\"), got {other:?}"),
        }
    }

    #[test]
    fn t_anthropic_map_status_400_malformed_body_falls_through() {
        // Non-JSON body still maps to ProviderError("http 400") (no panic).
        let body = b"not json at all";
        match map_anthropic_status(400, body) {
            LlmError::ProviderError(detail) => assert_eq!(detail, "http 400"),
            other => {
                panic!("expected ProviderError(\"http 400\") for malformed body, got {other:?}")
            }
        }
    }

    #[test]
    fn t_anthropic_map_status_401_403_auth_failed() {
        for status in [401u16, 403u16] {
            match map_anthropic_status(status, b"") {
                LlmError::ProviderError(msg) => assert_eq!(msg, "auth failed"),
                other => panic!("expected ProviderError(auth failed) for {status}, got {other:?}"),
            }
        }
    }

    #[test]
    fn t_anthropic_map_status_404_with_model_keyword() {
        let body = br#"{"error":{"message":"unknown model claude-x"}}"#;
        match map_anthropic_status(404, body) {
            LlmError::ModelNotAvailable(msg) => assert_eq!(msg, "model not found"),
            other => panic!("expected ModelNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn t_anthropic_map_status_404_without_model_keyword() {
        let body = br#"{"error":{"message":"endpoint missing"}}"#;
        match map_anthropic_status(404, body) {
            LlmError::ProviderError(msg) => assert_eq!(msg, "http 404"),
            other => panic!("expected ProviderError(http 404), got {other:?}"),
        }
    }

    #[test]
    fn t_anthropic_map_status_429_rate_limited() {
        match map_anthropic_status(429, b"") {
            LlmError::RateLimited(msg) => assert_eq!(msg, "rate limited"),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn t_anthropic_map_status_5xx_upstream() {
        for status in [500u16, 502, 503, 504, 599] {
            match map_anthropic_status(status, b"") {
                LlmError::ProviderError(msg) => {
                    assert_eq!(msg, format!("upstream {status}"));
                }
                other => panic!("expected ProviderError upstream for {status}, got {other:?}"),
            }
        }
    }

    #[test]
    fn t_anthropic_map_status_4xx_default_branch() {
        match map_anthropic_status(418, b"") {
            LlmError::ProviderError(msg) => assert_eq!(msg, "http 418"),
            other => panic!("expected ProviderError(http 418), got {other:?}"),
        }
    }

    // ── grok-repass Item 3: 5xx-disguised context overflow (L3 rows, anthropic arm) ──

    /// L3-T1 — a 5xx whose body carries an unambiguous overflow signal maps to
    /// `ContextTooLong` with the STATIC reason (CONTRACT-111 Invariant 7: no
    /// upstream bytes ever echoed on this path).
    #[test]
    fn t_grok3_anthropic_5xx_overflow_maps_context_too_long_static() {
        let body = br#"{"error":{"type":"invalid_request_error","message":"prompt is too long: 213413 tokens exceed the context window"}}"#;
        for status in [500u16, 529] {
            match map_anthropic_status(status, body) {
                LlmError::ContextTooLong(msg) => {
                    assert_eq!(msg, "context too long", "reason must be the static string");
                    assert!(!msg.contains("213413"), "no upstream body fragment");
                }
                other => panic!("expected ContextTooLong for {status}, got {other:?}"),
            }
        }
    }

    /// L3-T4/T5/T6 — CONTROL: adversarial transient bodies at the narrowed
    /// keyword edge stay retryable ProviderError (pins that the 5xx phrase
    /// family did NOT over-reach: `token limit` and the bare `context too`
    /// prefix are excluded).
    #[test]
    fn t_grok3_anthropic_5xx_adversarial_transient_bodies_stay_retryable() {
        let bodies: [&[u8]; 3] = [
            br#"{"error":{"message":"organization token limit reached, please retry"}}"#,
            br#"{"error":{"message":"context too busy, retry shortly"}}"#,
            br#"{"error":{"message":"capacity exceeded; context too many concurrent requests"}}"#,
        ];
        for body in bodies {
            match map_anthropic_status(503, body) {
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

    /// L3-T7 — the negative type gate, exhaustive over the SIX-member
    /// substring family, one witness each. Every message DOES trip the 5xx
    /// phrase list, so the row fails if the gate is deleted (the probe would
    /// classify ContextTooLong) — that is its discriminating power.
    #[test]
    fn t_grok3_anthropic_5xx_transient_type_gate_wins_over_phrase_probe() {
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
            match map_anthropic_status(529, body.as_bytes()) {
                LlmError::ProviderError(msg) => {
                    assert_eq!(msg, "upstream 529", "type {err_type} must stay transient");
                    assert!(crate::retry::classify_retryable(&LlmError::ProviderError(
                        msg
                    )));
                }
                other => panic!("type {err_type}: expected ProviderError, got {other:?}"),
            }
        }
    }

    /// Audit round 7 — the conflict rule on the anthropic arm: a
    /// proxy-stamped transient CODE alongside an overflow-complete message
    /// stays retryable (the code-side gate leg; RED against the
    /// type-and-message-only arm), while a code-free overflow message is
    /// unaffected (covered by the L3-T1 row above).
    #[test]
    fn t_grok3_anthropic_5xx_transient_code_gates_over_phrase_probe() {
        let body = br#"{"error":{"code":"server_error","message":"context window exceeded"}}"#;
        match map_anthropic_status(500, body) {
            LlmError::ProviderError(msg) => {
                assert_eq!(msg, "upstream 500");
                assert!(crate::retry::classify_retryable(&LlmError::ProviderError(
                    msg
                )));
            }
            other => panic!("expected retryable ProviderError (code-side gate), got {other:?}"),
        }
    }

    /// L3-T7b — the STATED RESIDUAL, pinned as a tested boundary: a type
    /// OUTSIDE the transient family + an overflow-complete message classifies
    /// permanent even though the 5xx could in principle be transient.
    #[test]
    fn t_grok3_anthropic_5xx_residual_unknown_type_with_overflow_message() {
        let body = br#"{"error":{"type":"quota_exhausted_error","message":"conversation exceeds the context window for this model"}}"#;
        match map_anthropic_status(500, body) {
            LlmError::ContextTooLong(msg) => assert_eq!(msg, "context too long"),
            other => panic!("expected ContextTooLong (pinned residual), got {other:?}"),
        }
    }

    /// L3-T8 — CONTROL: 5xx with a JSON body that carries no overflow signal
    /// stays retryable (the empty-body case is t_anthropic_map_status_5xx_upstream).
    #[test]
    fn t_grok3_anthropic_5xx_plain_error_body_unchanged() {
        let body = br#"{"error":{"message":"something broke"}}"#;
        match map_anthropic_status(502, body) {
            LlmError::ProviderError(msg) => assert_eq!(msg, "upstream 502"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }

    /// L3-T9 — the retry-storm closure, composed through the classifier: a
    /// 5xx-disguised overflow must be non-retryable end to end.
    #[test]
    fn t_grok3_5xx_overflow_is_not_retryable_end_to_end() {
        let body = br#"{"error":{"type":"invalid_request_error","message":"prompt is too long for the context window"}}"#;
        let mapped = map_anthropic_status(529, body);
        assert!(
            !crate::retry::classify_retryable(&mapped),
            "5xx-disguised overflow must not be retried; mapped to {mapped:?}"
        );
    }
}

fn map_anthropic_status(status: u16, body: &[u8]) -> LlmError {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    match status {
        400 => {
            // Round-AUDIT-2 W2 fix: tighten context-too-long detection.
            // Anthropic 400 invalid_request_error message must contain a
            // context-window keyword (case-insensitive prefix family) —
            // not a loose substring match against the entire body, which
            // would misfire on unrelated 400 bodies that happen to mention
            // "context" anywhere (e.g. JSON field names).
            if let Ok(v) = serde_json::from_str::<Value>(body_str) {
                let err_type = v["error"]["type"].as_str().unwrap_or("");
                let err_msg = v["error"]["message"].as_str().unwrap_or("");
                if err_type == "invalid_request_error" && is_context_overflow_message(err_msg) {
                    return LlmError::ContextTooLong(err_msg.to_string());
                }
            }
            LlmError::ProviderError("http 400".into())
        }
        401 | 403 => LlmError::ProviderError("auth failed".into()),
        404 => {
            if body_str.to_ascii_lowercase().contains("model") {
                LlmError::ModelNotAvailable("model not found".into())
            } else {
                LlmError::ProviderError("http 404".into())
            }
        }
        429 => LlmError::RateLimited("rate limited".into()),
        500..=599 => {
            // grok-repass Item 3: some providers/proxies disguise context
            // overflow as a 5xx, which the retry classifier treats as
            // transport-transient ("upstream 5" prefix) — a deterministic
            // same-payload retry storm. Probe the body with the NARROWED 5xx
            // family (see providers/mod.rs): a transient error.type wins over
            // any message text; the reason is STATIC (CONTRACT-111 Inv. 7 —
            // never echo a 5xx body).
            if let Ok(v) = serde_json::from_str::<Value>(body_str) {
                let err_type = v["error"]["type"].as_str().unwrap_or("");
                let err_code = v["error"]["code"].as_str().unwrap_or("");
                let err_msg = v["error"]["message"].as_str().unwrap_or("");
                // Audit round 7: the negative gate reads BOTH structured
                // fields here too, so the conflict rule (providers/mod.rs)
                // holds uniformly across all three 5xx arms. The Anthropic
                // envelope itself carries no code field (err_code is ""
                // on every vendor-shaped body — a no-op), but a proxy that
                // stamps a transient code alongside an overflow-complete
                // message must stay retryable, not fail permanent. The
                // POSITIVE side remains message-only by design: Anthropic
                // signals overflow via invalid_request_error + message,
                // never an overflow type/code literal.
                if !crate::providers::is_transient_error_type_5xx(err_type)
                    && !crate::providers::is_transient_error_type_5xx(err_code)
                    && crate::providers::is_context_overflow_message_5xx(err_msg)
                {
                    return LlmError::ContextTooLong("context too long".into());
                }
            }
            LlmError::ProviderError(format!("upstream {status}"))
        }
        other => LlmError::ProviderError(format!("http {other}")),
    }
}

/// Heuristic for "model returned a context-overflow signal" applied to the
/// Anthropic invalid_request_error.message string (not the whole body). The
/// canonical phrases Anthropic returns for context overflow mention a
/// "context" / "prompt is too long" / "token limit" keyword family. We
/// accept a small keyword family rather than a single magic string so the
/// heuristic tolerates wording drift without misfiring on unrelated 400
/// errors.
///
/// Round-AUDIT-3 W2 fix: `max_tokens` REMOVED from the keyword family —
/// Anthropic also returns `max_tokens` in invalid_request_error messages
/// for ordinary parameter-validation failures (e.g. "max_tokens must be
/// positive"), which would misclassify a bad-parameter caller error as
/// context overflow and route it to the wrong remediation path.
///
/// Round-AUDIT-4 W1 fix: standalone `exceeds the maximum` REMOVED — that
/// phrase appears in many non-context Anthropic 400 errors (e.g.
/// "max_tokens exceeds the maximum allowed", "stop_sequences exceeds the
/// maximum count"), so it would misfire the same way `max_tokens` did.
/// Only the explicit "exceeds the maximum context" sub-phrase is accepted.
fn is_context_overflow_message(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("context window")
        || lower.contains("context length")
        || lower.contains("context too")
        || lower.contains("prompt is too long")
        || lower.contains("token limit")
        || lower.contains("exceeds the maximum context")
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use crate::providers::sse::{SseFrame, SseUsageFold};
    use advance_runtime::config::ProviderBackend;

    fn provider() -> ResolvedProvider {
        ResolvedProvider {
            id: "anthropic".into(),
            endpoint: "https://api.anthropic.com".into(),
            api_key_secret: "anthropic-api-key".into(),
            model: "claude-sonnet-4-5".into(),
            cost_per_mtoken_in: 3.0,
            cost_per_mtoken_out: 15.0,
            backend: ProviderBackend::AnthropicMessages,
            auth_scheme: None,
        }
    }

    fn ev_frame(event: &str, data: &str) -> SseFrame {
        SseFrame {
            event: Some(event.into()),
            data: data.into(),
        }
    }

    /// MODULE-009-T116 (request leg) — stream request adds stream:true +
    /// SSE Accept; x-api-key default credential position preserved.
    #[test]
    fn t116_build_stream_request_shape() {
        let req = AnthropicAdapter
            .build_stream_request(
                &provider(),
                &[ChatMessage {
                    role: ChatRole::User,
                    content: "hi".into(),
                }],
                &ChatParams::default(),
            )
            .unwrap();
        assert_eq!(req.url, "https://api.anthropic.com/v1/messages");
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["stream"], Value::Bool(true));
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "x-api-key" && v == "{anthropic-api-key}"));
        assert!(req
            .headers
            .iter()
            .any(|(n, v)| n == "Accept" && v == "text/event-stream"));
    }

    /// MODULE-009-T117 — message_start input_tokens + content_block_delta
    /// text + message_delta CUMULATIVE output_tokens (last-write-wins,
    /// NEVER summed: 10 then 12 folds to 12, not 22) + message_stop
    /// terminal; ping and content_block_start/stop are Ignore.
    #[test]
    fn t117_anthropic_stream_cumulative_usage_and_concat() {
        let adapter = AnthropicAdapter;
        let mut acc = String::new();
        let mut fold = SseUsageFold::default();
        let script: Vec<SseFrame> = vec![
            ev_frame(
                "message_start",
                r#"{"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":1}}}"#,
            ),
            ev_frame("ping", r#"{"type":"ping"}"#),
            ev_frame(
                "content_block_start",
                r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            ),
            ev_frame(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hel"}}"#,
            ),
            ev_frame(
                "content_block_delta",
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}"#,
            ),
            ev_frame(
                "message_delta",
                r#"{"type":"message_delta","delta":{},"usage":{"output_tokens":10}}"#,
            ),
            ev_frame(
                "message_delta",
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}"#,
            ),
        ];
        let mut finish = None;
        for f in &script {
            let ev = adapter.parse_sse_frame(f).unwrap();
            if let Some(d) = &ev.delta {
                assert!(!d.is_empty(), "delta must never be Some(empty)");
                acc.push_str(d);
            }
            if let Some(fr) = &ev.finish_reason {
                finish = Some(fr.clone());
            }
            fold.apply(&ev);
            assert!(!ev.terminal);
        }
        let stop = adapter
            .parse_sse_frame(&ev_frame("message_stop", r#"{"type":"message_stop"}"#))
            .unwrap();
        assert!(stop.terminal);
        assert_eq!(acc, "hello");
        assert_eq!(finish.as_deref(), Some("end_turn"));
        assert_eq!(
            (fold.input_tokens, fold.output_tokens),
            (Some(7), Some(12)),
            "cumulative output_tokens must fold last-write-wins (12), never sum (22)"
        );
        // ping normalizes to Ignore
        let ping = adapter
            .parse_sse_frame(&ev_frame("ping", r#"{"type":"ping"}"#))
            .unwrap();
        assert!(ping.is_ignore());
    }

    /// MODULE-009-T118 — `event: error` and the `{"type":"error"}` data
    /// shape fold to enum-coded STATIC reasons; non-JSON data fails CLOSED.
    #[test]
    fn t118_anthropic_in_band_error_static() {
        let adapter = AnthropicAdapter;
        match adapter.parse_sse_frame(&ev_frame(
            "error",
            r#"{"type":"error","error":{"type":"overloaded_error","message":"LEAK upstream text"}}"#,
        )) {
            Err(LlmError::ProviderError(msg)) => {
                assert_eq!(msg, "in-band error frame");
                assert!(!msg.contains("LEAK"));
            }
            other => panic!("expected static in-band error, got {other:?}"),
        }
        // data-shape error without the event name
        match adapter.parse_sse_frame(&SseFrame {
            event: None,
            data: r#"{"type":"error","error":{"message":"LEAK"}}"#.into(),
        }) {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "in-band error frame"),
            other => panic!("expected static in-band error, got {other:?}"),
        }
        match adapter.parse_sse_frame(&ev_frame("message_delta", "not json")) {
            Err(LlmError::ProviderError(msg)) => assert_eq!(msg, "invalid stream frame"),
            other => panic!("expected static invalid-frame error, got {other:?}"),
        }
    }
}
