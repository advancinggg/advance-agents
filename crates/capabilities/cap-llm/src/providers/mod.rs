//! Per-provider HTTP request builders + response/SSE parsers.
//!
//! `ProviderAdapter` is the strategy interface; concrete impls live in
//! sibling modules `openai`, `responses`, and `anthropic`. The
//! `select_adapter` factory routes by `ProviderBackend` (ADR 2026-07-22 D4).
//! The historical id-keyed routing ("anthropic" → Anthropic, everything else
//! → OpenAI-compatible) survives byte-compatibly inside
//! `provider::backend_of`, which derives the enum when config omits
//! `backend:`.

use advance_runtime::config::{AuthScheme, ProviderBackend};
use advance_shared_types::security_validator::{CredentialPosition, HttpRequest};

use crate::error::LlmError;
use crate::executor::ExecutionOutcome;
use crate::gateway::{ChatMessage, ChatParams};
use crate::provider::ResolvedProvider;
use crate::providers::sse::{SseEvent, SseFrame};

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

    /// Round-3 W6 fix: gateway's `select_embedding_provider` skips providers
    /// whose adapter advertises `false`. Default `true`; only `AnthropicAdapter`
    /// overrides to `false` (Anthropic ships no native embedding endpoint).
    #[allow(dead_code)]
    fn supports_embedding(&self) -> bool {
        true
    }

    /// Embedding-model identifier the adapter sends to upstream and that the
    /// gateway records on `llm.request` / `llm.response` events. Slice B-2
    /// hardcodes `text-embedding-3-small` for OpenAI-compatible per the
    /// round-4 W2 accepted limitation; Slice C will read from
    /// `LlmProviderConfig.embedding_model` once that field exists.
    /// Anthropic returns `None` because it doesn't expose embeddings.
    fn embedding_model(&self) -> Option<&'static str> {
        None
    }
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
            backend,
            auth_scheme: auth,
            backend_class: advance_runtime::config::InferenceBackendClass::CloudHttp,
            embedding_model: None,
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
/// The pre-existing 400 arms (openai's exact-literal acceptance, responses'
/// exact-type-only shape) are untouched — the lane's 400-path byte-identity
/// obligation — so on 400 a non-canonical spelling still falls through
/// (pinned by the openai 400-boundary control). Disclosed, accepted; a
/// 400-arm change belongs to a /spec pass.
pub(crate) fn normalize_error_type(err_type: &str) -> String {
    err_type
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
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
