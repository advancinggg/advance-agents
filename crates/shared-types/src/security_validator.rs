//! MODULE-012 security canonical dependency-inversion surface.
//!
//! Canonical source: `docs/modules/MODULE-012-security.md` §2.3
//! (ActionValidator + PromptInjectionHelpers + InjectionFlag + Severity +
//! SecurityError + TrustLevel canonical).
//!
//! `AgentAction` is re-exported from [`crate::mailbox`] (MODULE-006 owner)
//! because ActionValidator is a consumer of AgentAction (MODULE-012 validates
//! actions MODULE-006 dispatches).
//!
//! Verbatim hoist — if the owner module's declaration changes, run
//! `/spec MODULE-012` and re-hoist via a follow-on /dev slice.
//!
//! # Security posture
//!
//! - **Error payload PII policy**: [`SecurityError`] 4 variants carry
//!   `String` payloads flowing into operator logs / EventBus JSONL /
//!   WebSocket broadcast. Implementers MUST NOT embed user content,
//!   API-key fragments, or attacker-controlled input snippets; MODULE-012
//!   owns the LeakDetector component (invoked on emit by MODULE-019's
//!   EventBus output path) as defense-in-depth, not a primary gate.
//! - **`InjectionFlag` / `Finding` span is byte offsets** (Slice B amendment):
//!   `offset` + `length` are byte offsets into the **implementation-defined
//!   scanned-content derivative**, NOT necessarily into the caller's input.
//!   Implementations may pre-process the input (e.g. strip invisible Unicode
//!   codepoints to defeat zero-width-smuggling attacks against `\s`-based
//!   regexes). See the per-trait `LeakDetector` invariant 2 + `InjectionFlag`
//!   struct rustdoc for the canonical semantic. Downstream consumers
//!   rendering the flagged substring into LLM context or logs MUST
//!   re-boundary-wrap via [`PromptInjectionHelpers::wrap_with_boundary`] to
//!   prevent prompt-injection escape at the render site.
//! - **`PromptInjectionHelpers::wrap_with_boundary` boundary safety** (Slice B
//!   amendment): implementers MUST defend against attacker-forged boundary
//!   sequences in body content. Two acceptable strategies: (a) nonce-based
//!   boundary markers (rotated per call so an attacker cannot predict the
//!   token), or (b) escape attacker-controlled boundary tokens in the body
//!   before emission (e.g. via zero-width-character injection between the
//!   `<` and `/` of a `</data>` closer, paired with an upstream invisible-
//!   strip pass that defeats the inverse smuggling attack). The shipped
//!   `DefaultPromptInjectionHelpers` uses strategy (b). Strategy (a) remains
//!   available for future implementations that need stronger guarantees
//!   (e.g. nested-data-block parsing). Re-wrap of the output through
//!   `wrap_with_boundary` is UNSAFE under strategy (b) — see invariant 4
//!   re-wrap-unsafety note.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

pub use crate::mailbox::AgentAction;

/// MODULE-012 §2.3:578-583 — injection-pattern severity. **Critical / High /
/// Medium** (NOT Low — MODULE-012's canonical declaration uses this 3-level
/// scale, Low is not a canonical variant).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
}

/// MODULE-012 §2.3:536-541 — injection flag record. Produced by
/// [`PromptInjectionHelpers::flag_injection_patterns`] scanning text for
/// known injection patterns.
///
/// **Implementer Invariants**: bounded `pattern_name` length (recommended ≤ 256
/// bytes); `offset` + `length` are byte offsets into the **implementation-
/// defined scanned-content derivative** (Slice B amendment). Implementations
/// may pre-process the input (e.g. strip invisible Unicode codepoints to
/// defeat zero-width-smuggling attacks against `\s`-based regexes), in which
/// case offsets reference the derivative form, NOT the caller's input. See
/// MODULE-012 §3.6 known-gap row "InjectionFlag / Finding offsets are post-
/// strip-invisibles" for the canonical implementer-defined derivative used by
/// `DefaultPromptInjectionHelpers` (i.e. `strip_invisibles(input)`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectionFlag {
    pub offset: usize,
    pub length: usize,
    pub pattern_name: String,
    pub severity: Severity,
}

/// MODULE-012 §2.3:551-562 — ActionValidator rejection reason. 4 variants.
///
/// Consumers of [`crate::mailbox::DispatchError::ValidationFailed`] discriminate
/// on the wrapped `SecurityError` rather than parsing a string.
///
/// **Implementer Invariants**: variant payloads are operator-facing — MUST
/// NOT contain user PII; bounded string lengths (≤ 256 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityError {
    /// Action rejected by ActionValidator — oversize, forbidden target, or
    /// rate limit exceeded on the target. Message carries the specific reason.
    InvalidAction(String),
    /// Oversized message payload beyond configured `max_message_size`.
    OversizedMessage,
    /// Rate limit exceeded against a specific target agent / component.
    RateExceeded(String),
    /// Caller's capability set is insufficient for the attempted action.
    CapabilityDenied(String),
}

/// MODULE-012 §2.3:585-613 — canonical trust classification for LLM-exposed
/// artifacts. Two consumers:
/// - CONTRACT-114 `PromptInjectionHelpers::wrap_with_boundary(content, source, trust)`
///   (this module) — routes untrusted content through boundary-markup
///   sanitization before LLM inclusion.
/// - CONTRACT-164 `SkillInfo.trust_level` (MODULE-017 §2.3) — trusted skills
///   reject agent-initiated patch/rollback/delete per `skill-error::trust-violation`.
///
/// **Canonical declaration**: here. Re-exported from [`crate::skills`] for
/// MODULE-017 consumer ergonomics.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Artifact originates from a trusted source — inlined verbatim into
    /// LLM context; admin-gated mutation in the skill-trust path.
    Trusted,
    /// Artifact originates from an untrusted source — wrapped with data-
    /// block boundary markers in the content-trust path; agent-mutable in
    /// the skill-trust path.
    Untrusted,
}

/// CONTRACT-113 — action validation trait. MODULE-012 §2.3:519-521.
/// Invoked by MODULE-006 AgentActionDispatcher as the FIRST step of
/// `dispatch` (per REQ-101 / MODULE-006 §2.3 prose). Rejection
/// short-circuits delivery and halts the batch.
///
/// # Implementer Invariants
///
/// 1. **Deterministic**: no I/O; no clock; no RNG. Same `(agent_id, actions)`
///    input MUST produce the same output.
/// 2. **Bounded execution per action**: the total work scales linearly with
///    `actions.len()` and each per-action check is O(1) relative to policy
///    state size.
/// 3. **Identifier validation**: `agent_id` MUST be whitelist-validated.
/// 4. **Fail-closed on uncertainty**: when a decision would require more
///    context than available, return [`SecurityError`] rather than Ok.
pub trait ActionValidator: Send + Sync {
    fn validate(&self, agent_id: &str, actions: &[AgentAction]) -> Result<(), SecurityError>;
}

/// CONTRACT-114 — prompt-injection primitives. MODULE-012 §2.3:526-533.
/// Consumed by MODULE-010 context-engine to implement PRD §5.5 layers 1
/// (sanitization) + 2 (boundary marking).
///
/// # Implementer Invariants
///
/// 1. **Pure functions where possible**: `flag_injection_patterns` is a
///    pattern-matching scan (Aho-Corasick + Regex); no LLM call; no I/O.
///    `wrap_with_boundary` is a deterministic string transformation.
/// 2. **Bounded pattern set**: the implementer MUST cap the internal
///    pattern list (recommended ≤ 1024 patterns) to prevent unbounded
///    scan cost.
/// 3. **Output safety**: `wrap_with_boundary` MUST produce output that
///    cannot be unescaped by an attacker injecting matching boundary
///    sequences (use nonce-based boundaries if needed).
/// 4. **TrustLevel semantics**: Untrusted → always wrap; Trusted → inline
///    in-body. **Slice B clarification**: "inline" is subject to two unconditional
///    transforms applied to BOTH trust levels: (a) zero-width / bidi-control
///    invisible Unicode codepoints (21-codepoint set) are stripped upstream
///    to defeat smuggle-pattern attacks against `\s`-based regexes; (b)
///    `Severity::Critical` flagged spans (e.g. `<|system|>`) are always
///    neutralized regardless of trust because Critical patterns are LLM
///    lexer attack vectors that bypass trust-level-based gating. Thus
///    "inline verbatim" means "with the same byte-for-byte content modulo
///    invisibles + Critical-neutralization that the wrapped Untrusted body
///    also receives". `Severity::High` is the trust-discriminating threshold:
///    inlined for Trusted, neutralized for Untrusted.
///
///    **Re-wrap unsafety**: do NOT pipe the output of `wrap_with_boundary`
///    BACK through `wrap_with_boundary`. The closing-boundary defense
///    inserts `<\u{200B}/data>` into the body; the second wrap's upstream
///    invisible-strip pass would strip the U+200B and re-expose the literal
///    `</data>`, breaking the outer wrapper. Treat the helper as a one-shot
///    operation at the LLM-context-assembly boundary. See MODULE-012 §3.6
///    "wrap_with_boundary opening-boundary defense + re-wrap unsafety"
///    known-gap row.
/// 5. **Bounded input size (DoS defense, fail-CLOSED — Slice B addition)**:
///    both methods MUST refuse oversize input (recommended
///    `MAX_INJECTION_BYTES` = 1 MiB to mirror [`LeakDetector::scan`]
///    invariant 4). For [`PromptInjectionHelpers::flag_injection_patterns`]
///    the contract is to return a single synthetic
///    `InjectionFlag { pattern_name: "input_overflow", offset: 0, length: 0,
///    severity: Severity::Critical }` so the consumer can DISTINGUISH
///    overflow from clean input (NOT empty Vec — that would be fail-OPEN).
///    For [`PromptInjectionHelpers::wrap_with_boundary`] the contract is
///    to truncate the body content to `MAX_INJECTION_BYTES` at a UTF-8
///    char boundary + append the marker `[...truncated for size...]` in
///    the body — so a 1 GiB attacker payload doesn't cause `String`
///    allocation thrashing.
pub trait PromptInjectionHelpers: Send + Sync {
    fn flag_injection_patterns(&self, content: &str) -> Vec<InjectionFlag>;
    fn wrap_with_boundary(&self, content: &str, source: &str, trust: TrustLevel) -> String;
}

/// CONTRACT-112 — leak-detection two-pass engine (Slice B addition).
/// Aho-Corasick fast path + Regex confirmation; returns block/redact/warn
/// per the matched pattern's declared severity.
///
/// MODULE-012 §2.3 (canonical declaration is the trait body in the doc;
/// this hoist mirrors that under the verbatim-hoist invariant declared
/// at the top of this file).
///
/// Consumed by MODULE-010 context-engine (output scrubbing) and
/// MODULE-016 channel-system (bidirectional message scans).
///
/// # Implementer Invariants
///
/// 1. **Pattern bound**: pattern set MUST be ≤ 1024 (mirroring the
///    `PromptInjectionHelpers` invariant) to bound scan cost.
/// 2. **Implementation-defined "scanned content"**: `Finding.offset` and
///    `Finding.length` are byte offsets into the implementation-defined
///    scanned-content derivative, not necessarily into the caller-supplied
///    `text`. Implementations that pre-process the input (e.g. by stripping
///    invisible Unicode codepoints to defeat zero-width-smuggling attacks)
///    MUST measure offsets against the post-processed string AND MUST emit
///    a `redacted` field (when applicable) that lives in the same index
///    space. The contract does NOT pin "scanned content" to the caller's
///    input — implementers document their derivative in their own rustdoc.
///    Callers needing original-input correlation MUST keep the input around
///    AND understand the implementer's derivative.
/// 3. **`ScanResult::Redacted` index space**: `redacted` AND
///    `findings.offset` share the SAME implementation-defined index space.
///    Cross-correlating findings with `redacted` is safe; cross-correlating
///    either with the caller's original input is implementer-specific.
/// 4. **Overflow fail-CLOSED**: oversize input (beyond the implementer's
///    declared max-scan-bytes ceiling, measured against the raw caller
///    input BEFORE any derivative pre-processing) MUST return
///    `ScanResult::Blocked` with a synthetic
///    `Finding { pattern_name: "scan_overflow", action: Block }`, NOT
///    `Clean`. Pre-strip-amplification attacks (where 1 MiB of invisibles
///    would strip down below the cap) are denied by the BEFORE-strip cap.
/// 5. **Read-only**: `scan` and `scan_headers` MUST NOT mutate the input
///    or perform I/O.
/// 6. **scan_headers offset attribution**: `Finding.offset` returned from
///    `scan_headers` is implementation-defined and SHOULD NOT be relied on
///    for per-header rendering. Implementers may synthesize a flat string
///    from headers; consumers should use `Finding.pattern_name` and
///    `Finding.action` only.
pub trait LeakDetector: Send + Sync {
    fn scan(&self, text: &str, context: ScanContext) -> ScanResult;
    fn scan_headers(&self, headers: &[(String, String)]) -> ScanResult;
}

/// Severity-action mapping primitive. `Block` short-circuits the result;
/// `Redact` substitutes `[REDACTED]` at the finding range; `Warn` logs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Block,
    Redact,
    Warn,
}

/// Where in the runtime pipeline this scan was invoked. Used for telemetry
/// and Tier-2 routing decisions in MODULE-010 / MODULE-016.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScanContext {
    HttpOutbound,
    HttpInbound,
    HttpRedirect,
    NotifyOutbound,
    ChannelBidi,
    LogOutput,
}

/// Single pattern hit. `pattern_name` is bounded ≤ 256 bytes (implementer
/// invariant). `offset` + `length` index space is governed by [`LeakDetector`]
/// invariant 2 (implementation-defined scanned-content derivative); see that
/// invariant for the canonical semantic — this struct's rustdoc deliberately
/// avoids restating the index space here so a future invariant amendment
/// remains single-sourced.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub pattern_name: String,
    pub offset: usize,
    pub length: usize,
    pub action: Action,
}

/// Result of a scan.
///
/// # `Redacted` index-space note (security-critical)
///
/// The `Redacted` arm carries both the post-derivative-and-redaction
/// `redacted` string AND the per-finding metadata. **Both `redacted` and
/// `findings.offset` live in the SAME implementation-defined index space**
/// (per invariant 3 of [`LeakDetector`]). For implementations that strip
/// invisible Unicode codepoints upstream (e.g. `DefaultLeakDetector`),
/// this index space is the post-strip-and-pre-redaction form, NOT the
/// caller's original input.
///
/// **Consumer guidance**: a downstream consumer that needs to render the
/// caller's *original* input with redaction highlights cannot rely on the
/// `findings.offset` values directly — they index into the post-strip
/// derivative. Either (a) re-run the strip on the caller's original input
/// to recover the same derivative and use offsets against that, or (b)
/// accept that observability/UI shows the post-strip view (which is what
/// the LLM downstream would see anyway).
///
/// `serde(deny_unknown_fields)` is applied to `Finding` (struct) but NOT
/// to the `ScanResult` variants (serde does not propagate that attribute
/// to enum variants); this is consistent with `InjectionFlag` and accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanResult {
    Clean,
    Blocked {
        findings: Vec<Finding>,
    },
    Redacted {
        redacted: String,
        findings: Vec<Finding>,
    },
    Warned {
        findings: Vec<Finding>,
    },
}

impl ScanResult {
    pub fn is_clean(&self) -> bool {
        matches!(self, ScanResult::Clean)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// CONTRACT-111 — HttpSecurityChain (Slice C addition)
// ─────────────────────────────────────────────────────────────────────────
//
// Canonical hoist: trait + supporting types live here. `DefaultHttpSecurityChain`
// impl ships in `crates/capabilities/cap-http`. Re-exported via traits.rs.
// `#[async_trait]` is required for `Box<dyn HttpSecurityChain>` object-safety
// (native AFIT is not dyn-compatible).

/// 10-step HTTP security chain (per MODULE-012 §1.4.3).
///
/// # Implementer Invariants
///
/// 1. **Step ordering and termination**: implementations MUST execute steps in
///    declared order (1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10). On a step
///    failure, the chain MUST short-circuit. Reordering is forbidden.
/// 2. **Step 2 outbound scan**: scans URL, headers, and body as THREE SEPARATE
///    `LeakDetector` invocations (URL via `scan(&url, HttpOutbound)`; headers
///    via `scan_headers(&headers)`; body via `scan(&from_utf8_lossy(&body),
///    HttpOutbound)`). Aggregation: if ANY returns Blocked → step 2 returns
///    `LeakBlocked`. NOT a single concatenated `format!`.
/// 3. **Step 4 single injection**: credentials are injected exactly once on
///    the first request. Redirect callback re-runs only steps 1, 2, 5
///    (allowlist, leak scan, SSRF) — credentials are NOT re-injected.
/// 4. **Step 5 SSRF partial-match**: rejects if ANY resolved IP is in a
///    forbidden CIDR (defends DNS rebinding at resolution time).
/// 5. **Step 6 rate limit**: per `(agent_id, destination-host)` token bucket.
/// 6. **Step 8+9 redaction split**: step 8 scans response BODY; step 9 scans
///    response HEADERS on ALL status codes (distinct surface, defense-in-depth;
///    Slice C adversarial-R1 upgrade in
///    `DefaultHttpSecurityChain::execute` step 9 — the original 4xx/5xx-only
///    gate was removed because 2xx responses can also carry credentials in
///    Set-Cookie auth tokens, X-Debug-* dev artifacts, session/jwt headers).
/// 7. **HttpError URL-carrying allowlist**: only `AllowlistBlocked(String)`,
///    `RedirectRejected{target}`, and `InvalidUrl(String)` (pre-step-3 only)
///    carry URL bytes. All other variants are enum-coded. Post-step-3
///    URL-parse failures route through `Transport(TransportErrorKind::Other)`.
#[async_trait]
pub trait HttpSecurityChain: Send + Sync {
    async fn execute(
        &self,
        agent_id: &str,
        req: HttpRequest,
        cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError>;
}

/// HTTP method enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

/// HTTP request shape passed into `HttpSecurityChain::execute`.
///
/// **Manual Debug impl** redacts sensitive header values (per the global
/// redaction set: Authorization / Proxy-Authorization / X-API-Key /
/// X-Auth-Token / X-Access-Token / Cookie / Set-Cookie + suffix `-key` /
/// `-token` / `-secret` / `-password`, all case-insensitive) AND replaces
/// body bytes with `[BODY_LEN={N}]`. URL renders verbatim — post-step-4
/// query-param secrets in the URL are a documented §3.6 known gap.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &RedactedHeaders(&self.headers))
            .field("body", &format_args!("[BODY_LEN={}]", self.body.len()))
            .finish()
    }
}

/// HTTP response shape returned from `HttpSecurityChain::execute`.
///
/// **Manual Debug impl** applies the FULL global redaction set (same predicate
/// as `HttpRequest`) to response headers — upstream cannot be trusted to
/// limit reflected sensitive material to a known subset. Body bytes render
/// as `[BODY_LEN={N}]`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &RedactedHeaders(&self.headers))
            .field("body", &format_args!("[BODY_LEN={}]", self.body.len()))
            .finish()
    }
}

/// HTTP capability config (per-component), passed into `HttpSecurityChain::execute`.
///
/// **Manual Debug impl** delegates to `CredentialBinding`'s redacting Debug
/// for each entry (so `secret_name` renders as `[SECRET_NAME]`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCapability {
    pub allowlist: Allowlist,
    pub credentials: Vec<CredentialBinding>,
    pub component_id: String,
}

impl fmt::Debug for HttpCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCapability")
            .field("allowlist", &self.allowlist)
            .field("credentials", &self.credentials)
            .field("component_id", &self.component_id)
            .finish()
    }
}

/// Per-position credential injection rule.
///
/// **Manual Debug impl** renders `secret_name` as `[SECRET_NAME]` — secret
/// NAMES are sensitive metadata per MODULE-009 §1.7 sensitive_params discipline.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBinding {
    pub position: CredentialPosition,
    pub secret_name: String,
}

impl fmt::Debug for CredentialBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialBinding")
            .field("position", &self.position)
            .field("secret_name", &format_args!("[SECRET_NAME]"))
            .finish()
    }
}

/// Five injection positions (AC-05). Variants carry their own selector data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialPosition {
    /// Authorization: Bearer <secret>
    BearerToken,
    /// Authorization: Basic <standard-base64(username:secret)> (RFC 7617)
    BasicAuth { username: String },
    /// <key>: <secret>
    CustomHeader { key: String },
    /// ?<key>=<percent-encoded(secret)> appended to URL
    QueryParam { key: String },
    /// {key} placeholder substitution in URL path
    UrlPath { key: String },
}

/// Tag-only enum for `SecretResolutionReason::MissingSecretFor`. Carries position
/// info for triage but NOT the secret name itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialPositionTag {
    BearerToken,
    BasicAuth,
    CustomHeader,
    QueryParam,
    UrlPath,
}

impl CredentialPosition {
    /// Returns the tag-only enum form (drops selector data) for error reporting.
    pub fn tag(&self) -> CredentialPositionTag {
        match self {
            CredentialPosition::BearerToken => CredentialPositionTag::BearerToken,
            CredentialPosition::BasicAuth { .. } => CredentialPositionTag::BasicAuth,
            CredentialPosition::CustomHeader { .. } => CredentialPositionTag::CustomHeader,
            CredentialPosition::QueryParam { .. } => CredentialPositionTag::QueryParam,
            CredentialPosition::UrlPath { .. } => CredentialPositionTag::UrlPath,
        }
    }
}

/// Allowlist matcher for outbound HTTP destinations.
///
/// # Pattern grammar
///
/// - **Exact host**: `api.example.com` — matches any port; scheme MUST be
///   `https://` or `http://` (other schemes always rejected).
/// - **Subdomain wildcard**: `*.example.com` — matches `a.example.com`,
///   `a.b.example.com`; does NOT match bare `example.com`. **Suffix anchor on
///   a literal `.` boundary** — does NOT match `evil-example.com`.
/// - **URL prefix**: `https://api.example.com/v1/` — full prefix match
///   including scheme + host + port + path prefix. Port semantic:
///   default-port explicit (`:443` for https / `:80` for http) and
///   default-port implicit (no port) are CANONICALLY EQUIVALENT — both
///   normalize to the no-port form via `url::Url::as_str()`. So a pattern
///   `https://x.com:443/` matches both `https://x.com:443/foo` and
///   `https://x.com/foo`, but rejects `https://x.com:8443/foo`. Explicit
///   non-default port (e.g. `:8443`) requires the URL to ALSO carry
///   `:8443` explicitly.
/// - **Empty list** = deny all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowlist {
    pub patterns: Vec<String>,
}

impl Allowlist {
    /// Returns `true` iff `url` matches at least one pattern in `patterns`.
    /// Empty pattern list returns `false` (deny-all).
    pub fn matches(&self, url: &str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }

        // Parse the URL minimally — extract scheme, host, port, path. We only
        // accept http(s); other schemes are rejected outright.
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return false;
        }

        let url_host = match parsed.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };

        for pat in &self.patterns {
            // URL prefix grammar — pattern starts with http:// or https://
            if pat.starts_with("https://") || pat.starts_with("http://") {
                if url_starts_with_prefix(&parsed, pat) {
                    return true;
                }
                continue;
            }

            // Subdomain wildcard
            if let Some(suffix) = pat.strip_prefix("*.") {
                let suffix_lc = suffix.to_ascii_lowercase();
                // Must end with `.<suffix>` AND have at least one label before
                // the dot — anchors on the dot boundary so `evil-example.com`
                // does NOT match `*.example.com`.
                let needle = format!(".{}", suffix_lc);
                if url_host.ends_with(&needle) && url_host.len() > needle.len() {
                    return true;
                }
                continue;
            }

            // Exact host (case-insensitive)
            if url_host == pat.to_ascii_lowercase() {
                return true;
            }
        }
        false
    }
}

fn url_starts_with_prefix(parsed: &url::Url, pattern: &str) -> bool {
    // R3 fix: explicit-port patterns (`https://x.com:443/`) must distinguish
    // from no-port patterns (`https://x.com/`). `url::Url::parse` normalizes
    // default ports OUT of both, defeating the comparison. We instead parse
    // the pattern AND build a canonical "with-port-always-explicit" form for
    // both pattern and URL, then prefix-compare on that.
    let pattern_url = match url::Url::parse(pattern) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Pattern must have the same scheme as the URL.
    if parsed.scheme() != pattern_url.scheme() {
        return false;
    }
    // If pattern has an explicit port (the original raw string contained
    // ":<port>" between the host and the path), require the URL port to match.
    let pattern_explicit_port = pattern_string_has_explicit_port(pattern);
    if pattern_explicit_port {
        // Pattern's `port_or_known_default()` includes the explicit value.
        let pat_port = pattern_url.port_or_known_default();
        let url_port = parsed.port_or_known_default();
        if pat_port != url_port {
            return false;
        }
    }
    // Path + query prefix match. Use the scheme://host[:explicit_port] prefix
    // length from pattern_url.as_str() — but as_str() drops default ports
    // even from explicit-port patterns. So we build the "no-port" canonical
    // for both and compare. Explicit-port-required patterns short-circuited
    // above; remaining cases share canonical no-port form.
    let pat_canonical = pattern_url.as_str();
    let url_canonical = parsed.as_str();
    url_canonical.starts_with(pat_canonical)
}

/// True iff the pattern string explicitly carries `:<port>` between the
/// host and the path (or end of authority). Detects both default-port
/// (`:443`) and non-default-port (`:8443`) patterns.
fn pattern_string_has_explicit_port(pattern: &str) -> bool {
    // Strip scheme://
    let after_scheme = match pattern.find("://") {
        Some(i) => &pattern[i + 3..],
        None => return false,
    };
    // Authority ends at first `/` or `?` or `#` or end of string.
    let authority_end = after_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Authority is `host[:port]` (no userinfo expected for our patterns; the
    // grammar excludes it). A literal `:` in the authority indicates explicit
    // port. (IPv6 literals would have `[...]:port` — not in scope for the
    // current pattern grammar.)
    authority.contains(':')
}

/// HTTP chain error variants. All payloads are enum-coded or static-string only,
/// EXCEPT the explicit URL-carrying allowlist documented in invariant 7:
///   - `AllowlistBlocked(String)` — pre-injection URL; non-sensitive
///   - `RedirectRejected{target}` — redirect target URL (no creds re-injected)
///   - `InvalidUrl(String)` — pre-step-3 syntactic invalidity ONLY
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpError {
    AllowlistBlocked(String),
    LeakBlocked(Vec<Finding>),
    SecretResolution(SecretResolutionReason),
    SsrfBlocked(CidrClass),
    RateLimited {
        retry_after_ms: u64,
    },
    Transport(TransportErrorKind),
    InboundLeakBlocked(Vec<Finding>),
    RedirectRejected {
        reason: RedirectRejectReason,
        target: String,
    },
    InvalidUrl(String),
}

/// Reason discriminator for `HttpError::SecretResolution`. Enum-coded to
/// preserve position triage info while eliding the secret name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretResolutionReason {
    /// Placeholder substitution: secret name appears in `{name}` placeholder
    /// or position binding but not in store.
    MissingSecretFor(CredentialPositionTag),
    /// `UrlPath { key }` placeholder name not found in URL path.
    PlaceholderNotInUrl,
}

/// Transport-layer error kind (no inner string carrying network bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportErrorKind {
    Dns,
    Tls,
    ConnectionRefused,
    Timeout,
    Other,
}

/// Reason discriminator for `HttpError::RedirectRejected`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedirectRejectReason {
    AllowlistBlocked,
    LeakBlocked,
    HeaderLeakBlocked,
    SsrfBlocked,
}

/// SSRF guard — rejects outbound HTTP to private/loopback/cloud-metadata IPs.
///
/// Single canonical async `check` method used by both initial step 5 AND the
/// redirect callback (no separate sync `check_sync` path).
#[async_trait]
pub trait SsrfGuard: Send + Sync {
    async fn check(&self, url: &str) -> Result<(), SsrfError>;
}

/// SSRF-specific error variants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsrfError {
    /// URL parse failure (echoes URL — non-sensitive).
    InvalidUrl(String),
    /// URL had no host component.
    NoHost,
    /// `tokio::net::lookup_host` returned error.
    DnsFailed,
    /// Exceeded `security.ssrf.dns_timeout_ms`.
    DnsTimeout,
    /// Resolved IP fell into a forbidden CIDR (CIDR class label only — exact IP elided).
    Forbidden(CidrClass),
}

/// Forbidden-CIDR class label for telemetry + error reporting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CidrClass {
    /// 10/8, 172.16/12, 192.168/16
    PrivateIpv4,
    /// 127/8, ::1/128
    Loopback,
    /// 169.254/16, fe80::/10 (excluding the cloud metadata pin)
    LinkLocal,
    /// fd00::/8
    UniqueLocalIpv6,
    /// 169.254.169.254/32, fd00:ec2::254/128 — matched BEFORE LinkLocal in
    /// first-match-wins iteration so cloud-metadata exfiltration attempts
    /// classify correctly (per MODULE-012 §1.4.4).
    CloudMetadata,
}

/// Async per-hop revalidation hook handed to `HttpExecutor::execute`. The
/// executor invokes it for each redirect target before following the redirect.
#[async_trait]
pub trait RedirectCheck: Send + Sync {
    async fn check(
        &self,
        target_url: &str,
        target_headers: &[(String, String)],
    ) -> Result<(), RedirectRejectReason>;
}

// ─────────────────────────────────────────────────────────────────────────
// CONTRACT-233 — HttpStreamingChain (ADR 2026-07-22 D1/D3, slice S3)
// ─────────────────────────────────────────────────────────────────────────
//
// Streaming transport variant of the CONTRACT-111 chain, for the real
// per-token SSE path (MODULE-009 HF-2). A deliberately INDEPENDENT trait:
// the shared `HttpExecutor`/`HttpSecurityChain` traits and the fail-closed
// `NotWiredHttpExecutor` sentinel are untouched (a defaulted streaming
// method would silently grant NotWired a streaming path; a required one
// would break ~15 implementors). Implemented ONLY by cap-http's
// `DefaultHttpSecurityChain` (opt-in `with_stream_executor`; unwired →
// fail-closed). MODULE-009's cap-llm `LlmGateway` is the PLANNED slice-S4
// consumer; it does not hold or consume this trait in the shipped S3 slice.
//
// Dependency-clean by construction: `async-trait` + `Vec<u8>` chunks — no
// `futures-core`/`bytes` edge. The mid-stream error type is the chain-level
// `HttpError` (enum-coded static reasons; the ADR's pinned `ExecutorError`
// is cap-http-internal and maps into `HttpError` inside the implementor —
// MODULE-012 §2.3 signature-precision record).

/// Validated response HEAD returned by [`HttpStreamingChain::execute_streaming`]
/// before any body chunk. Headers have already passed the chain's inbound
/// header scan. The streaming implementation returns Clean/Warned heads
/// verbatim and fails CLOSED on Blocked/Redacted; unlike buffered step 9, it
/// never rewrites a Redacted head.
///
/// **Manual Debug impl** applies the same header-redaction predicate as
/// [`HttpResponse`] (upstream cannot be trusted to limit reflected sensitive
/// material).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl fmt::Debug for HttpResponseHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponseHead")
            .field("status", &self.status)
            .field("headers", &RedactedHeaders(&self.headers))
            .finish()
    }
}

/// Boxed pull object yielding POST-SCAN wire chunks for a streaming HTTP
/// response body.
///
/// # Implementer Invariants (CONTRACT-233)
///
/// 1. **Post-scan only**: every returned chunk has passed the implementor's
///    per-chunk inbound leak scan (MODULE-012 §2.9 terms 2–5) — a consumer
///    may hand these bytes onward without re-running the wire-layer scan.
/// 2. **Terminal is absorbing**: after the first `Some(Err(_))` or `None`,
///    every subsequent call MUST return `None`.
/// 3. **Enum-coded errors**: `HttpError` values carry no upstream
///    message/code/URL bytes beyond CONTRACT-111 invariant 7's explicit
///    URL-carrying allowlist.
/// 4. **No resume surface**: there is deliberately no reconnect /
///    `Last-Event-ID` / resume API (it would replay the injected auth
///    header). A broken stream is terminal.
/// 5. **Bounded lifecycle**: cancelling/dropping a `next_chunk` future and
///    dropping the body object MUST be bounded, non-blocking and panic-free;
///    cancellation/destruction MUST NOT perform network I/O or wait for
///    transport/application progress. This is the body specialization of the
///    transitive composition invariant on [`HttpStreamingChain`].
#[async_trait]
pub trait HttpBodyStream: Send {
    async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, HttpError>>;
}

// Opaque Debug so containers of `Box<dyn HttpBodyStream>` (and Results over
// them) stay debuggable without exposing any stream internals.
impl fmt::Debug for dyn HttpBodyStream + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpBodyStream")
    }
}

/// CONTRACT-233 — head-first streaming HTTP security chain (ADR 2026-07-22).
///
/// # Implementer Invariants
///
/// 1. **Outbound steps 1–6 identical to CONTRACT-111**: allowlist, outbound
///    leak scan, placeholder substitution, single step-4 credential
///    injection, SSRF, rate limit — same order, same short-circuit, same
///    error variants as [`HttpSecurityChain::execute`].
/// 2. **Head-first error gating**: connect errors, rejected redirects, and
///    head-scan blocks return `Err` from `execute_streaming` itself — no
///    body stream is handed out on a failed begin.
/// 3. **Every byte scanned**: the returned [`HttpBodyStream`] yields only
///    post-scan chunks (MODULE-012 §2.9 streaming scan contract, including
///    the wire-layer Redact→Block sanctioned divergence).
/// 4. **Composition gate and bounded lifecycle**: an implementation MUST be
///    fully composed under the CONTRACT-233 streaming precondition before it
///    invokes any collaborator, or fail CLOSED before collaborator work. Once
///    composed, every transitively reached synchronous callback,
///    future-cancellation/drop path, and object `Drop` MUST be bounded,
///    non-blocking and panic-free; cancellation/destruction MUST NOT perform
///    network I/O or wait for transport/application progress. A deadline-bound
///    implementation MUST arbitrate that deadline after every synchronous
///    collaborator before dispatching the next callback or network-capable
///    future, so expiry gates work instead of merely reclassifying the final
///    result. The default cap-http implementation enforces the entry half by
///    checking its opt-in executor slot as the first operation; an unwired call
///    returns before deadline construction or outbound steps. This behavioral
///    invariant does not change collaborator trait signatures or buffered-path
///    semantics.
#[async_trait]
pub trait HttpStreamingChain: Send + Sync {
    async fn execute_streaming(
        &self,
        agent_id: &str,
        req: HttpRequest,
        cap: &HttpCapability,
    ) -> Result<(HttpResponseHead, Box<dyn HttpBodyStream>), HttpError>;
}

// ─────────────────────────────────────────────────────────────────────────
// Manual-Debug header-redaction predicate (R3-C5 + R7-W1 + R8-W1).
// ─────────────────────────────────────────────────────────────────────────

struct RedactedHeaders<'a>(&'a [(String, String)]);

impl<'a> fmt::Debug for RedactedHeaders<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for (name, value) in self.0.iter() {
            if is_sensitive_header_name(name) {
                list.entry(&(name, "[REDACTED]"));
            } else {
                list.entry(&(name, value.as_str()));
            }
        }
        list.finish()
    }
}

/// Returns `true` if `name` matches the sensitive-header redaction set
/// (case-insensitive on the header NAME). The set is the unified rule used
/// for both `HttpRequest` and `HttpResponse` Debug impls (upstream cannot be
/// trusted to limit reflected sensitive material).
///
/// Exact-match: Authorization, Proxy-Authorization, X-API-Key, X-Auth-Token,
/// X-Access-Token, Cookie, Set-Cookie.
/// Suffix-match: header NAMEs ending in `-key`, `-token`, `-secret`, `-password`.
pub(crate) fn is_sensitive_header_name(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "cookie",
        "set-cookie",
    ];
    let lc = name.to_ascii_lowercase();
    if EXACT.iter().any(|e| *e == lc.as_str()) {
        return true;
    }
    const SUFFIX: &[&str] = &["-key", "-token", "-secret", "-password"];
    SUFFIX.iter().any(|s| lc.ends_with(s))
}
