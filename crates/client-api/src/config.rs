//! CONTRACT-193 / CONTRACT-190 configuration surface (MODULE-020 §2.10 + §2.11).
//!
//! This is the crate-local config the foundation slice owns. A later composition-root slice
//! maps `RuntimeConfig` (CONTRACT-003) into this struct; the enforcement logic AC-01/02/04
//! witness does not depend on where the values come from.

use std::net::IpAddr;

/// Duration constants (milliseconds).
const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;

/// Client API configuration and operational parameters.
#[derive(Debug, Clone)]
pub struct ClientApiConfig {
    /// Default HTTP/WebSocket bind address (§2.10). Loopback by default.
    pub bind_addr: IpAddr,
    /// Whether non-loopback binds/peers are permitted. Default `false` (loopback-only).
    pub remote_bind_enabled: bool,
    /// Browser CORS allowlist (§2.10). Default empty → browser mutations fail closed until the
    /// console origin is configured; native clients (no `Origin`) are unaffected.
    pub allowed_origins: Vec<String>,
    /// Session lifetime before refresh (§2.10, `session_ttl_minutes` default 480).
    pub session_ttl_ms: u64,
    /// Hard cap on retained sessions (bounds memory; expired sessions are also swept on insert).
    pub session_store_cap: usize,
    /// Per-session projected event buffer (§2.10). Carried for later slices.
    pub max_event_buffer: usize,
    /// Generated SDK targets (§2.10).
    pub sdk_targets: Vec<String>,
    /// Mutating idempotency TTL (§2.11, 24 hours).
    pub idempotency_ttl_ms: u64,
    /// Max request body size in bytes (§2.11, 1 MiB default).
    pub max_body_bytes: usize,
    /// Bootstrap one-time-code lifetime.
    pub bootstrap_code_ttl_ms: u64,
    /// Max wrong bootstrap-code attempts before the code is invalidated.
    pub bootstrap_max_attempts: u32,
    /// Hard cap on retained idempotency (`Done`) records (bounds memory; live reservations are
    /// bounded separately by the number of concurrent in-flight requests).
    pub idempotency_store_cap: usize,
    /// Max accepted idempotency-key length in bytes (bounds per-reservation memory; an over-long
    /// key is rejected before a reservation is taken).
    pub max_idempotency_key_len: usize,
    /// Max accepted request path length in bytes (bounds the pre-auth `family` allocation +
    /// audit label; an over-long path is rejected at the very front of the pipeline).
    pub max_path_len: usize,
    // ── m020-s3 CONTRACT-191 event resource bounds ────────────────────────────────────────
    /// Max concurrent event reads (history + stream) per ClientApi instance. Hard max 4.
    pub max_concurrent_event_reads: usize,
    /// Max serialized client event response bytes (hard max 1 MiB).
    pub max_event_response_bytes: usize,
    /// Stream ResumeStream per-recv idle timeout in milliseconds (50..=250).
    pub event_stream_recv_idle_ms: u64,
    /// Max concurrent transport dispatches (HTTP requests + WebSocket seeds) that may run
    /// `handle()` on the blocking pool at once. Bounds blocking-pool submission so a caller cannot
    /// pin the pool / grow an unbounded queue on the uncapped provider families; a request that
    /// exceeds it fails closed with `module_unavailable` rather than queueing. The WebSocket poll
    /// loop is NOT counted here (it is bounded by `max_concurrent_event_reads` / the stream slot).
    pub max_concurrent_dispatch: usize,
    // ── tee T2 (CONTRACT-235) LLM delta-subscription kill switch (§2.13) ──────────────────
    /// Whether the LLM token-delta subscription surface (`/client/llm/deltas/stream`) is served.
    /// Default `true`. When `false` the surface returns the EXISTING `module_unavailable` code
    /// (routes stay registered, never a routing oracle; NO new error
    /// code). Evaluated AFTER the `Scope::ReadLlmDeltas` gate, so flag state never leaks to
    /// unauthorized callers (an under-scoped caller sees 403 regardless of the flag). Gates
    /// route + subscription only — producer-side tee cost is NOT stopped (§2.4).
    pub llm_deltas_enabled: bool,
}

impl Default for ClientApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: IpAddr::from([127, 0, 0, 1]),
            remote_bind_enabled: false,
            allowed_origins: Vec::new(),
            session_ttl_ms: 480 * MINUTE_MS,
            session_store_cap: 10_000,
            max_event_buffer: 10_000,
            sdk_targets: vec![
                "web".into(),
                "mac".into(),
                "ios".into(),
                "android".into(),
                "windows".into(),
            ],
            idempotency_ttl_ms: 24 * HOUR_MS,
            max_body_bytes: 1024 * 1024,
            bootstrap_code_ttl_ms: 10 * MINUTE_MS,
            bootstrap_max_attempts: 5,
            idempotency_store_cap: 10_000,
            max_idempotency_key_len: 256,
            max_path_len: 512,
            max_concurrent_event_reads: 4,
            max_event_response_bytes: 1024 * 1024,
            event_stream_recv_idle_ms: 250,
            max_concurrent_dispatch: 64,
            llm_deltas_enabled: true,
        }
    }
}

impl ClientApiConfig {
    /// True iff `origin` is exactly present in the allowlist (exact match, never substring).
    pub fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == origin)
    }

    /// True iff `addr` is a loopback address.
    pub fn is_loopback(addr: &IpAddr) -> bool {
        addr.is_loopback()
    }
}
