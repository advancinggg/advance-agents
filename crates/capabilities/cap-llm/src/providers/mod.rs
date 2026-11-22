//! Per-provider HTTP request builders + response/SSE parsers.
//!
//! `ProviderAdapter` is the strategy interface; concrete impls live in
//! sibling modules `openai`, `responses`, and `anthropic`. The
//! `select_adapter` factory routes by `ProviderBackend` (ADR 2026-07-22 D4).
//! The historical id-keyed routing ("anthropic" → Anthropic, everything else
//! → OpenAI-compatible) survives byte-compatibly inside
//! `provider::backend_of`, which derives the enum when config omits
//! `backend:`.

use std::borrow::Cow;

use advance_runtime::config::{AuthScheme, ProviderBackend};
use advance_shared_types::security_validator::{CredentialPosition, HttpRequest};

use crate::error::LlmError;
use crate::executor::ExecutionOutcome;
use crate::gateway::{ChatMessage, ChatParams, ChatRole};
use crate::provider::ResolvedProvider;
use crate::providers::sse::{SseEvent, SseFrame};

/// The messages a request of `provider` sends: `messages` as they stand, unless the entry
/// merges its system messages (`system-messages: merge`). Then the text of every system
/// message, in order and joined by a blank line, is one system message at index 0 and the
/// other messages keep their relative order; a request without system messages is unchanged.
/// Every chat-completions body of a `cloud-http` entry (chat, stream, image, preflight) and the
/// request of a `local` entry, built before its sidecar IR, go through here.
pub(crate) fn outgoing_messages<'a>(
    provider: &ResolvedProvider,
    messages: &'a [ChatMessage],
) -> Cow<'a, [ChatMessage]> {
    if !provider.merges_system_messages() {
        return Cow::Borrowed(messages);
    }
    merge_system_messages(messages)
}

/// [`outgoing_messages`] of an entry that merges its system messages.
pub(crate) fn merge_system_messages(messages: &[ChatMessage]) -> Cow<'_, [ChatMessage]> {
    let systems: Vec<&str> = messages
        .iter()
        .filter(|m| m.role == ChatRole::System)
        .map(|m| m.content.as_str())
        .collect();
    let already_one =
        systems.len() == 1 && messages.first().map(|m| m.role) == Some(ChatRole::System);
    if systems.is_empty() || already_one {
        return Cow::Borrowed(messages);
    }
    let mut merged = Vec::with_capacity(messages.len() - systems.len() + 1);
    merged.push(ChatMessage::new(ChatRole::System, systems.join("\n\n")));
    merged.extend(
        messages
            .iter()
            .filter(|m| m.role != ChatRole::System)
            .cloned(),
    );
    Cow::Owned(merged)
}

pub mod anthropic;
pub mod local;
pub mod openai;
pub mod responses;
pub mod sse;

/// HTTP request/response strategy per LLM provider.
///
/// Implementers MUST be `Send + Sync` because gateway invocations are
/// async and the chain is shared across tasks.
pub trait ProviderAdapter: Send + Sync {
    fn build_chat_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError>;

    fn parse_chat_response(&self, status: u16, body: &[u8]) -> Result<ExecutionOutcome, LlmError>;

    /// Streaming variant of `build_chat_request` (ADR 2026-07-22 D4; the S4
    /// live-stream slice is the production consumer). Adds the backend's
    /// stream field(s) plus an SSE `Accept` header; credential handling is
    /// identical to the buffered path (placeholder substitution by the
    /// CONTRACT-111 chain's single step-4 injection site).
    ///
    /// Build-ahead-of-wiring: the production consumer is the S4 live-stream
    /// slice; until then only unit tests call it (dead-code on non-test build).
    #[allow(dead_code)]
    fn build_stream_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError>;

    /// Parse one complete SSE frame into a normalized [`SseEvent`].
    ///
    /// Contract (MODULE-009-AC-21): in-band error frames are probed BEFORE
    /// typed decode and fold to enum-coded `LlmError` with STATIC reasons —
    /// never upstream message/code/URL bytes (CONTRACT-111 Invariant 7).
    /// Ignorable frames (keep-alives, role-only chunks, unknown non-terminal
    /// events) return [`SseEvent::IGNORE`] — never `delta: Some("")`.
    ///
    /// Build-ahead-of-wiring: the production consumer is the S4 live-stream
    /// slice; until then only unit tests call it (dead-code on non-test build).
    #[allow(dead_code)]
    fn parse_sse_frame(&self, frame: &SseFrame) -> Result<SseEvent, LlmError>;

    fn build_embed_request(
        &self,
        provider: &ResolvedProvider,
        text: &str,
    ) -> Result<HttpRequest, LlmError>;

    fn parse_embed_response(&self, status: u16, body: &[u8]) -> Result<Vec<f32>, LlmError>;

    /// Whether this dialect has an embeddings endpoint at all. Default `true`; only
    /// `AnthropicAdapter` answers `false`. Not what decides an embedding route: the
    /// gateway's `embedding_model_for` reads the entry's backend and backend class,
    /// and refuses an Anthropic Messages entry there.
    #[allow(dead_code)]
    fn supports_embedding(&self) -> bool {
        true
    }

    /// The embedding model this dialect's FIRST-PARTY endpoint serves when an
    /// entry names no `embedding-model` (`text-embedding-3-small` on OpenAI's own
    /// API). The gateway applies it only to that endpoint: for every other
    /// endpoint speaking the dialect the entry's `embedding-model` is required,
    /// so a model id is never guessed. Anthropic returns `None` because it
    /// doesn't expose embeddings.
    fn embedding_model(&self) -> Option<&'static str> {
        None
    }
}

/// The widest embedding a provider's answer may carry. Above every embedding model in
/// use (the widest produce 4096 values), and a bound on what one stored index row and one
/// recall scan can cost.
pub(crate) const MAX_EMBEDDING_DIMENSIONS: usize = 8192;

/// Refuse a vector that cannot be an embedding — empty, wider than
/// [`MAX_EMBEDDING_DIMENSIONS`], or carrying a value that is not finite. One check for
/// every dialect and for the local inference port; the message is fixed and carries
/// nothing of the answer.
pub(crate) fn validate_embedding(vector: &[f32]) -> Result<(), LlmError> {
    if vector.is_empty()
        || vector.len() > MAX_EMBEDDING_DIMENSIONS
        || vector.iter().any(|value| !value.is_finite())
    {
        return Err(LlmError::ProviderError("invalid response shape".into()));
    }
    Ok(())
}

/// Route a backend to its adapter (ADR 2026-07-22 D4). The historical
/// id-keyed routing is preserved byte-compatibly by `provider::backend_of`,
/// which derives the enum when config omits `backend:` — witnessed by
/// MODULE-009-T116.
pub fn select_adapter(backend: ProviderBackend) -> Box<dyn ProviderAdapter> {
    match backend {
        ProviderBackend::AnthropicMessages => Box::new(anthropic::AnthropicAdapter),
        ProviderBackend::OpenAiResponses => Box::new(responses::OpenAiResponsesAdapter),
        ProviderBackend::OpenAiChat => Box::new(openai::OpenAiAdapter),
    }
}

/// Credential position for a resolved provider: an explicit `auth-scheme`
/// override wins; absent → the backend default (ADR 2026-07-22 fork f).
/// `build_http_cap` (capability allowlist position) and [`auth_header_for`]
/// (request header) BOTH derive from this one function, so the allowlist
/// and the outgoing header can never disagree. Query-param credentials are
/// deliberately not offered (CONTRACT-111: URL-embedded secrets leak
/// through error cause-chains).
pub(crate) fn credential_position_for(provider: &ResolvedProvider) -> CredentialPosition {
    match (provider.auth_scheme, provider.backend) {
        (Some(AuthScheme::Bearer), _) => CredentialPosition::BearerToken,
        (Some(AuthScheme::XApiKey), _) => CredentialPosition::CustomHeader {
            key: "x-api-key".into(),
        },
        (Some(AuthScheme::ApiKey), _) => CredentialPosition::CustomHeader {
            key: "api-key".into(),
        },
        (None, ProviderBackend::AnthropicMessages) => CredentialPosition::CustomHeader {
            key: "x-api-key".into(),
        },
        (None, ProviderBackend::OpenAiChat | ProviderBackend::OpenAiResponses) => {
            CredentialPosition::BearerToken
        }
    }
}

/// The auth header `(name, placeholder-value)` matching
/// [`credential_position_for`]. Single-brace `{secret-name}` placeholder;
/// the CONTRACT-111 chain's step-4 substitutes the resolved secret value.
pub(crate) fn auth_header_for(provider: &ResolvedProvider) -> (String, String) {
    match credential_position_for(provider) {
        CredentialPosition::CustomHeader { key } => {
            (key, format!("{{{}}}", provider.api_key_secret))
        }
        // BearerToken (the only other variant this crate constructs).
        _ => (
            "Authorization".into(),
            format!("Bearer {{{}}}", provider.api_key_secret),
        ),
    }
}

#[cfg(test)]
mod cred_tests {
    use super::*;
    use advance_runtime::config::AuthScheme;

    fn provider(backend: ProviderBackend, auth: Option<AuthScheme>) -> ResolvedProvider {
        ResolvedProvider {
            id: "p".into(),
            endpoint: "https://x.example".into(),
            api_key_secret: "s".into(),
            model: "m".into(),
            cost_per_mtoken_in: 0.0,
            cost_per_mtoken_out: 0.0,
            cache_cost: Default::default(),
            backend,
            auth_scheme: auth,
            backend_class: advance_runtime::config::InferenceBackendClass::CloudHttp,
            embedding_model: None,
            auth_source: advance_runtime::config::ProviderAuthSource::ApiKey,
            generate_timeout: None,
            reasoning_effort: None,
            system_messages: None,
        }
    }

    /// MODULE-009-T116 (auth-scheme leg) — explicit `auth_scheme` overrides
    /// the backend default in BOTH the allowlist position and the outgoing
    /// header, which are derived from the same helper so they cannot
    /// disagree (ADR 2026-07-22 fork f).
    #[test]
    fn t116_credential_position_explicit_override_and_default() {
        // Azure-style api-key on an OpenAI backend.
        let azure = provider(ProviderBackend::OpenAiChat, Some(AuthScheme::ApiKey));
        assert!(matches!(
            credential_position_for(&azure),
            CredentialPosition::CustomHeader { ref key } if key == "api-key"
        ));
        assert_eq!(auth_header_for(&azure).0, "api-key");

        // Explicit x-api-key.
        let xapi = provider(ProviderBackend::OpenAiChat, Some(AuthScheme::XApiKey));
        assert_eq!(auth_header_for(&xapi).0, "x-api-key");

        // Explicit bearer on an Anthropic backend (override wins).
        let bear = provider(ProviderBackend::AnthropicMessages, Some(AuthScheme::Bearer));
        assert!(matches!(
            credential_position_for(&bear),
            CredentialPosition::BearerToken
        ));
        assert_eq!(auth_header_for(&bear).0, "Authorization");

        // Absent → backend defaults: OpenAI→Bearer, Anthropic→x-api-key.
        assert_eq!(
            auth_header_for(&provider(ProviderBackend::OpenAiChat, None)).0,
            "Authorization"
        );
        assert_eq!(
            auth_header_for(&provider(ProviderBackend::AnthropicMessages, None)).0,
            "x-api-key"
        );
        assert_eq!(
            auth_header_for(&provider(ProviderBackend::OpenAiResponses, None)).0,
            "Authorization"
        );
    }

    #[test]
    fn t_openai_chat_default_credential_position() {
        let local = provider(ProviderBackend::OpenAiChat, None);
        assert!(matches!(
            credential_position_for(&local),
            CredentialPosition::BearerToken
        ));
        assert_eq!(auth_header_for(&local).0, "Authorization");
    }
}

/// grok-repass Item 3 — the 5xx context-overflow phrase family, deliberately
/// NARROWER than the 400-path `is_context_overflow_message` in `anthropic.rs`
/// (which stays untouched): on the 400 path the probe is co-gated by
/// `err_type == "invalid_request_error"`, while a 5xx body has no such gate,
/// so only overflow-COMPLETE phrases are accepted here. Exclusions are
/// load-bearing, not stylistic: `token limit` plausibly denotes a transient
/// org-quota condition in a 5xx envelope, and the bare `context too` prefix
/// would swallow transient wordings like "context too busy". Do not widen
/// without a witness per phrase.
pub(crate) fn is_context_overflow_message_5xx(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("context window")
        || lower.contains("context length")
        || lower.contains("context too long")
        || lower.contains("prompt is too long")
        || lower.contains("exceeds the maximum context")
}

/// grok-repass Item 3 — the NEGATIVE type gate for the 5xx overflow probe: a
/// body whose `error.type` names a transient class stays a retryable
/// `ProviderError` regardless of message text. A substring family of exactly
/// SIX members, each justified by a real vendor type (`overloaded_error` —
/// Anthropic, in this repo's own fixtures — `rate_limit_error`,
/// `timeout_error`, `service_unavailable`, `server_error`, `internal_error`)
/// and each pinned by one witness per adapter arm. The gate cannot make
/// "ambiguous 5xx stays retryable" universal — a type OUTSIDE this family
/// plus an overflow-complete message still classifies permanent (the stated,
/// tested residual): requiring a positive overflow type instead would gut
/// the fix exactly where a proxy rewrote the status and the type field is
/// least trustworthy.
///
/// SEPARATOR-NORMALIZED matching (audit round 1): vendor spellings vary
/// across snake_case / kebab-case / camelCase / spaced forms, and two family
/// members embed a separator — literal `rate_limit` would let a genuine
/// transient spelled `rate-limit-error` or `rateLimitError` through the gate
/// straight into a permanent `ContextTooLong`. The type string is lowercased
/// with every non-alphanumeric byte stripped, then matched against
/// separator-free members, so all separator conventions gate identically
/// while `context_length_exceeded` still does not.
///
/// CONFLICT RULE (audit rounds 6-7, documented + witnessed design choice):
/// ALL THREE 5xx arms apply this gate to BOTH structured fields
/// (`error.type` and `error.code`), conjunctively, BEFORE any acceptance —
/// so a transient literal in either field vetoes an overflow signal from
/// any other source (the anthropic arm has no positive type/code
/// acceptance, so there the veto applies to its message probe). A body
/// carrying both (e.g. type `context_length_exceeded` + code
/// `server_error`, or the reverse) is SELF-CONTRADICTORY, and this
/// classifier acts only on unambiguous overflow signals: contradictory
/// bodies stay retryable `ProviderError` — the status quo ante, bounded by
/// the retry caps. The opposite precedence would let a proxy-stamped field
/// convert a genuine transient into a permanent failure, which is the worse
/// error: an over-retried true overflow keeps 5xx-ing into the caps, while
/// an over-permanented transient fails the request outright.
pub(crate) fn is_transient_error_type_5xx(err_type: &str) -> bool {
    let normalized = normalize_error_type(err_type);
    [
        "overload",
        "ratelimit",
        "timeout",
        "unavailable",
        "servererror",
        "internal",
    ]
    .iter()
    .any(|t| normalized.contains(t))
}

/// Separator-normalized form of an `error.type` (lowercase, every
/// non-alphanumeric byte stripped). Shared by the negative gate above AND
/// the openai arm's positive `context_length_exceeded` acceptance (audit
/// round 2: both sides of the 5xx classifier must be spelling-insensitive,
/// or a kebab/camel proxy spelling gates asymmetrically).
///
/// SCOPE (audit rounds 3-5): this rule governs the 5xx classifier ONLY, and
/// the positive normalized acceptance lands in BOTH OpenAI-family 5xx arms
/// (openai's and responses' — round 4 closed the responses type gap; round
/// 5 extended BOTH arms to read error.code symmetrically on both classifier
/// sides, because the real OpenAI envelope signals overflow as type
/// invalid_request_error + code context_length_exceeded). anthropic's 5xx
/// arm stays message-probe-only deliberately: its vendor vocabulary signals
/// overflow via invalid_request_error + message, with neither an overflow
/// type nor a code field.
/// On 400 the openai arm accepts the same structured signals since MODULE-010
/// S6 ([`is_context_overflow_refusal`]), its message probe co-gated by
/// `invalid_request_error`; the responses arm keeps its exact-type-only shape.
pub(crate) fn normalize_error_type(err_type: &str) -> String {
    err_type
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// MODULE-010 S6 — whether the body of a 400 refusal says the request does not fit the
/// model's context window, in the envelope OpenAI-compatible services and Anthropic share:
/// `error.type` or `error.code` `context_length_exceeded` in any spelling (OpenAI sends the
/// code), or an `invalid_request_error` whose message is an overflow-complete phrase
/// ([`is_context_overflow_message_5xx`]) — as NEAR AI's vLLM stack sends it (witnessed
/// 2026-11-21: "This model's maximum context length is 32768 tokens. However, your prompt
/// contains at least 32769 input tokens, …", type `invalid_request_error`, code null). A
/// transient type or code vetoes it, as on the 5xx path. A completion budget past the window
/// ("max_tokens=… cannot be greater than max_model_len=…") is a parameter error, not an
/// overflow of the request, and stays out. The bytes only select the fixed reason of the
/// caller: nothing of them reaches an error, an event or a log.
pub(crate) fn is_context_overflow_refusal(body: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let err = &v["error"];
    let err_type = err["type"].as_str().unwrap_or("");
    let err_code = err["code"].as_str().unwrap_or("");
    let err_msg = err["message"].as_str().unwrap_or("");
    if is_transient_error_type_5xx(err_type) || is_transient_error_type_5xx(err_code) {
        return false;
    }
    normalize_error_type(err_type) == "contextlengthexceeded"
        || normalize_error_type(err_code) == "contextlengthexceeded"
        || (normalize_error_type(err_type) == "invalidrequesterror"
            && is_context_overflow_message_5xx(err_msg))
}

#[cfg(test)]
mod overflow_refusal_tests {
    use super::is_context_overflow_refusal;

    #[test]
    fn the_overflow_refusals_of_real_services_are_recognised() {
        let rows: [(&[u8], bool); 9] = [
            // NEAR AI (vLLM), witnessed 2026-11-21.
            (br#"{"error":{"message":"This model's maximum context length is 32768 tokens. However, your prompt contains at least 32769 input tokens, which exceeds this limit even without any output tokens. Please reduce the length of the input prompt. (parameter=input_tokens, value=32769)","type":"invalid_request_error","param":null,"code":null}}"#, true),
            // OpenAI: the code names the overflow.
            (
                br#"{"error":{"message":"This model's maximum context length is 128000 tokens.","type":"invalid_request_error","param":"messages","code":"context_length_exceeded"}}"#,
                true,
            ),
            // Anthropic: an invalid request whose message says the prompt is too long.
            (
                br#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 213413 tokens > 200000 maximum"}}"#,
                true,
            ),
            // The type in another spelling.
            (br#"{"error":{"type":"context-length-exceeded"}}"#, true),
            // NEAR AI, witnessed 2026-11-21: a completion budget past the window.
            (br#"{"error":{"message":"Provider failed for model 'deepseek-ai/DeepSeek-V4.1-Flash-1017': max_tokens=2000000 cannot be greater than max_model_len=1048576. Please request fewer output tokens. (parameter=max_tokens, value=2000000)","type":"invalid_request_error","param":null,"code":null}}"#, false),
            // A transient type or code vetoes every other signal.
            (
                br#"{"error":{"type":"rate_limit_error","code":"context_length_exceeded","message":"context length"}}"#,
                false,
            ),
            // On 400 an overflow phrase needs an invalid request around it.
            (
                br#"{"error":{"type":"BadRequestError","message":"This model's maximum context length is 4096 tokens."}}"#,
                false,
            ),
            (
                br#"{"error":{"type":"invalid_request_error","message":"context too busy"}}"#,
                false,
            ),
            (b"not json", false),
        ];
        for (body, expected) in rows {
            assert_eq!(
                is_context_overflow_refusal(body),
                expected,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}

#[cfg(test)]
mod grok3_predicate_tests {
    /// Audit round 1 — the type gate is separator-insensitive: every real
    /// spelling convention of a family member gates, and overflow /
    /// non-family types still do not. This is the witness the 18 canonical
    /// snake_case rows in the three adapter suites structurally could not
    /// provide (one spelling each).
    #[test]
    fn t_grok3_transient_type_gate_is_separator_insensitive() {
        // The five separator-variant rows are the fix-specific
        // discrimination (each returns false under the pre-fix literal
        // snake_case matcher); the canonical spellings ride along as
        // controls (audit round 2 tidied a message-shaped row and a vacuous
        // empty-string row out of this list).
        let transient = [
            "rate_limit_error",
            "rate-limit-error",
            "rateLimitError",
            "RateLimitExceeded",
            "server_error",
            "server error",
            "serverError",
            "overloaded_error",
            "SERVICE_UNAVAILABLE",
            "timeout-error",
            "internalError",
        ];
        for spelling in transient {
            assert!(
                super::is_transient_error_type_5xx(spelling),
                "{spelling:?} must gate as transient"
            );
        }
        let not_transient = [
            "context_length_exceeded",
            "context-length-exceeded",
            "contextLengthExceeded",
            "quota_exhausted_error",
            "invalid_request_error",
            // The production DEFAULT for an absent error.type
            // (.as_str().unwrap_or("") at all three call sites) — kept as an
            // explicit control (audit round 3 corrected the earlier
            // "vacuous" deletion rationale).
            "",
        ];
        for spelling in not_transient {
            assert!(
                !super::is_transient_error_type_5xx(spelling),
                "{spelling:?} must NOT gate"
            );
        }
    }

    /// Audit round 2 — the shared normalizer keeps BOTH sides of the 5xx
    /// classifier spelling-insensitive: the positive openai acceptance
    /// compares against the same normal form.
    #[test]
    fn t_grok3_normalize_error_type_canonicalizes_spellings() {
        for spelling in [
            "context_length_exceeded",
            "context-length-exceeded",
            "contextLengthExceeded",
            "Context Length Exceeded",
        ] {
            assert_eq!(
                super::normalize_error_type(spelling),
                "contextlengthexceeded"
            );
        }
    }

    /// The 5xx phrase family stays overflow-complete: transient wordings at
    /// the narrowed edge do not match; complete phrases do.
    #[test]
    fn t_grok3_overflow_phrase_family_edges() {
        assert!(super::is_context_overflow_message_5xx(
            "prompt is too long for the context window"
        ));
        assert!(super::is_context_overflow_message_5xx(
            "input exceeds the maximum context"
        ));
        assert!(!super::is_context_overflow_message_5xx(
            "organization token limit reached, please retry"
        ));
        assert!(!super::is_context_overflow_message_5xx(
            "context too busy, retry shortly"
        ));
    }
}
