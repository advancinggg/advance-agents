//! cap-http — MODULE-012 HTTP-side security primitives.
//!
//! Slice B (shipped): `LeakDetector` + `PromptInjectionHelpers` impls.
//! Slice C (shipped): `HttpSecurityChain` 10-step pipeline + `SsrfGuard` +
//!   `RateLimiter` + credential injection (5 positions) + `HttpExecutor`
//!   abstraction. See MODULE-012-security.md §3.2.
//! Slice D (shipped): `DefaultActionValidator` (CONTRACT-113 first impl).
//! Slice E (shipped): `ReqwestHttpExecutor` — production `reqwest`-backed
//!   `HttpExecutor` (rustls-tls; redirect(none) + per-hop zero-carry clean-GET).
//! Wave-25A Order 2: build-and-hold CONTRACT-219 redactor provider core.  Production issuers and
//! consumers remain deliberately unwired until the later activation orders.
//! ADR 2026-07-22 slice S3 (shipped): CONTRACT-233 `HttpStreamingChain` impl —
//!   cap-http-owned `HttpStreamExecutor` seam (`ReqwestHttpExecutor` chunk pull +
//!   `MockHttpExecutor` `MockFixture::Stream`; `pub` for wiring, not re-exported
//!   at the crate root), opt-in `with_stream_executor`, per-chunk wire scan with
//!   overlap window + Block/Redact viability hold (`streaming` module).

pub(crate) mod invisible;
pub mod leak_detector;
pub mod patterns;
pub mod prompt_injection;

// Slice C modules
pub mod credential_injection;
pub mod executor;
pub mod local_transport;
pub mod rate_limit;
pub mod security_chain;
pub mod ssrf;
pub mod streaming;

// Slice D module
pub mod action_validator;
pub mod sensitive_observation;

pub use leak_detector::DefaultLeakDetector;
pub use prompt_injection::DefaultPromptInjectionHelpers;

// Slice C public surface
pub use credential_injection::{inject_credentials, substitute_placeholders};
pub use executor::{
    DefaultRedirectCheck, ExecutorError, HttpExecutor, MockHttpExecutor, ReqwestExecutorConfig,
    ReqwestHttpExecutor, DEFAULT_MAX_REDIRECTS, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_TIMEOUT,
};
// NOTE (audit round 1): `HttpStreamExecutor` / `WireChunkStream` /
// `MAX_STREAM_DURATION` are deliberately NOT re-exported at the crate root.
// They remain reachable at `cap_http::executor::…` because the composition
// root must name the trait to wire `with_stream_executor`, but the seam's
// chunks are PRE-scan transport bytes — the only sanctioned consumer is
// `DefaultHttpSecurityChain::execute_streaming`'s scanning wrapper, and
// keeping the front door narrow makes accidental raw consumption harder.
pub use local_transport::DefaultLocalInferenceTransport;
pub use rate_limit::{DefaultRateLimiter, RateLimiter};
pub use security_chain::DefaultHttpSecurityChain;
pub use ssrf::{DefaultSsrfGuard, MockResolver, RealResolver, Resolver};

// ADR 2026-07-22 slice S3 public surface (CONTRACT-233)
pub use streaming::MAX_HOLD_BYTES;

// S4 (ADR 2026-07-22): pub facade over the existing audited canonical-text
// machinery (per-char feed + raw-offset map, canonical length, invisible-strip
// iterator, bounded_pattern_window derived from LEAK_PATTERNS). Visibility-only;
// no behavior change. Used by M009 decoded-layer release pipeline (single scan
// authority via the injected detector). The geometry is canonical space so
// invisible/confusable inflation cannot push matches out of retention.
pub mod canonical_facade {
    pub use crate::patterns::bounded_pattern_window;
    pub use crate::streaming::{canonical_len_with_limit, canonical_map_with_limit};
    // Re-export the invisible strip for per-char feed (M009 decoded pipeline).
    pub use crate::invisible::strip_invisibles as strip_invisible;
    // The EXACT canonicalization `DefaultLeakDetector::scan` applies to its input
    // (strip-invisibles then whole-string NFKC). Consumers that must align an
    // offset or a prefix with a `Finding`/`Redacted` derivative MUST use this —
    // the per-char `canonical_len_with_limit` above is a different (deliberately
    // divergent) index space.
    pub use crate::invisible::canonical_scan_text;
    // S4 (2026-07-29): the AUDITED viability-hold primitives the wire layer uses
    // (anchored dense-DFA prefix viability over the canonical feed + the
    // non-short-circuiting EOF sweep). Re-exported — NOT reimplemented — so the
    // decoded layer's hold geometry is the same machinery MODULE-012 §2.9 hardened
    // over four audit rounds (M009 plan stance 4 / Δ5). Visibility-only.
    pub use crate::streaming::{decoded_hold_split, decoded_region_has_completed_match};
}

// Slice D public surface
pub use action_validator::{
    DefaultActionValidator, DEFAULT_MAX_DUPLICATE_PAYLOADS, DEFAULT_MAX_MESSAGE_SIZE_BYTES,
};
pub use sensitive_observation::DefaultSensitiveObservationRedactor;
