//! Runtime observability event payload.
//!
//! The [`Event`] struct is the single wire-format record that flows through the
//! `EventBusEmit` trait (CONTRACT-180). Every module emits events through this struct;
//! MODULE-019 observability persists them to JSONL, SQLite, WebSocket, and stats aggregator.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical source: `docs/modules/MODULE-019-observability.md` lines 88–101
/// (§1.3.1 Event Struct).
///
/// 12-field record matching the MODULE-019 spec byte-for-byte. `timestamp` uses
/// nanosecond-precision `DateTime<Utc>` (chrono); the canonical JSONL format is
/// RFC 3339 with nine-digit sub-second digits (e.g. `2026-04-09T10:00:00.123456789Z`
/// per MODULE-019:409).
///
/// Derives `PartialEq` (not `Eq`) because the struct contains `serde_json::Value` —
/// a defensive forward-compatible choice matching the `ToolEntry` rationale from Slice A'
/// (`capability.rs:40–42`), since future `serde_json` features (e.g. `arbitrary_precision`)
/// may affect the `Number` arm's `Eq` impl.
///
/// `#[serde(deny_unknown_fields)]` rejects any extra fields at deserialization time,
/// locking the event envelope shape. The `payload: serde_json::Value` field accepts
/// arbitrary JSON *inside* its value — `deny_unknown_fields` applies only to the
/// outer struct's field set, not to the contents of a `Value` field.
///
/// # Implementer Invariants (emit-site hygiene)
///
/// 1. **No secrets in payload**: `Event.payload` values flow through EventBus JSONL
///    writers and WebSocket broadcasters. Emit sites must NEVER inline API keys,
///    credentials, or user PII into `payload`. MODULE-012 LeakDetector scrubs the
///    JSONL output path per MODULE-019-AC-18 as a defense-in-depth second gate,
///    but emit-site hygiene remains the primary guarantee.
/// 2. **Bounded field lengths**: all `String` fields (`id`, `agent_id`, `event_type`,
///    `trace_id`, `span_id`, and the `Option<String>` variants) and the `payload`
///    `serde_json::Value` are **structurally unbounded** at the type level — this
///    struct intentionally matches the MODULE-019:88-101 canonical shape without
///    adding validation that would change the interface. The **EventBus implementer**
///    (MODULE-019) MUST enforce per-event size limits before fanning out to JSONL /
///    SQLite / WebSocket / stats / Trigger Bus sinks. A single oversized event can
///    amplify memory and storage pressure across all sinks. Recommended caps:
///    `event_type` ≤ 128 bytes, `id` / `trace_id` / `span_id` ≤ 256 bytes (aligned to MODULE-006 `MAX_ID_BYTES`; raised from 64),
///    `payload` serialized size ≤ 64 KiB.
/// 3. **`id` format**: use UUID v4 or ULID; do not use sequential integers or
///    user-controlled strings (injection risk in downstream SQL indexers). String
///    fields may contain null bytes or unicode control characters at the type level;
///    the EventBus implementer MUST sanitize or reject such content before persisting
///    to SQL or rendering in logs (null-byte truncation / bidi-override attacks).
/// 4. **`trace_id` / `span_id` semantics**: per MODULE-019 §1.3.1 link-tracing
///    semantics, `trace_id` is one `handle-message` complete chain, `run_id` is
///    business-level execution wave, `execution_id` is single dispatch in fan-out.
///    Emitters must not conflate `trace_id` with `run_id`.
/// 5. **`timestamp` deserialization accepts non-UTC offsets**: chrono's serde impl
///    silently normalizes `+08:00` to `Z` on deserialization. The canonical wire
///    format is RFC 3339 with trailing `Z` (per MODULE-019:409). Downstream systems
///    that compare raw JSON strings for deduplication must canonicalize first.
/// 6. **Caller-controlled `timestamp` — repudiation risk**: `timestamp` is set by
///    the emitter, not stamped by the EventBus. A compromised module can backdate
///    or future-date events. The EventBus implementer SHOULD overwrite or validate
///    `timestamp` against a server-side clock if audit integrity requires it.
/// 7. **`#[derive(Debug)]` exposes payload in panic/log paths**: the `Debug` impl
///    serializes all 12 fields including `payload`. If secrets accidentally enter
///    `payload`, they will appear in `{:?}` format strings, panic backtraces, and
///    debug log lines — bypassing the MODULE-012 LeakDetector scrubbing (which
///    covers only the JSONL output path). Callers formatting `Event` with `{:?}`
///    must route the output through the same scrubbing pipeline, or the EventBus
///    implementer should provide a redacted `Display` impl for safe logging.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub task_id: Option<String>,
    pub run_id: Option<String>,
    pub execution_id: Option<String>,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub duration_ms: Option<u64>,
}

impl Event {
    /// Phase-3 kickoff (2026-06-06): lightweight constructor for **library-side
    /// observability emits** that lack a run/trace correlation context (cap-http
    /// security chain, cap-channel transport). Generates a v4 `id` + `Utc::now()`
    /// timestamp; leaves `trace_id`/`span_id` empty and `run_id`/`task_id`/
    /// `execution_id`/`parent_span_id` `None` — mirroring the existing
    /// `cap-grant` `new_event` / `authz.checked` precedent (a known correlation
    /// gap for emitters without a run context; full trace correlation is a
    /// separate MODULE-019 concern). `duration_ms` is the canonical top-level
    /// latency field (NOT a payload key).
    ///
    /// **Redaction is the caller's responsibility**: `payload` must carry only
    /// non-secret fields (host/scheme/method/status/sizes/counts/static-labels) —
    /// NEVER path/query/userinfo/headers/body/leak-findings/secret values.
    pub fn observability(
        event_type: impl Into<String>,
        agent_id: impl Into<String>,
        payload: serde_json::Value,
        duration_ms: Option<u64>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: agent_id.into(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            event_type: event_type.into(),
            payload,
            duration_ms,
        }
    }
}

/// Fixed UUIDv5 namespace for handle-message chain-root span ids (Stage-F obs
/// SLICE 1). A stable random constant — NOT a secret, NOT security-load-bearing
/// (span ids are opaque correlation strings). Used only to namespace
/// [`chain_root_span_id`].
const CHAIN_SPAN_NAMESPACE: uuid::Uuid = uuid::uuid!("6f9c1e2a-3b4d-5c6e-7f80-91a2b3c4d5e6");

/// Deterministic chain-ROOT span id for a handle-message chain, derived from the
/// triggering message id (MODULE-019 §1.3.1 link-tracing semantics).
///
/// Every emitter in one handle-message chain computes the SAME root span from the
/// SAME `message_id` via this single helper, so the chain-root anchor
/// (`context.assembled.span_id`) and a child's `parent_span_id`
/// (`run.round_completed.parent_span_id`) match BY CONSTRUCTION without needing to
/// persist the span on the wire. UUIDv5 over [`CHAIN_SPAN_NAMESPACE`] makes the
/// result deterministic-per-message, distinct-across-messages, and UUID-shaped
/// (so any `Uuid::parse_str` / shape consumer is satisfied).
pub fn chain_root_span_id(message_id: &str) -> String {
    uuid::Uuid::new_v5(&CHAIN_SPAN_NAMESPACE, message_id.as_bytes()).to_string()
}

#[cfg(test)]
mod chain_span_tests {
    use super::chain_root_span_id;

    // T2 — deterministic, distinct-per-id, UUID-shaped.
    #[test]
    fn chain_root_span_id_is_stable_distinct_and_uuid_shaped() {
        let a1 = chain_root_span_id("msg-A");
        let a2 = chain_root_span_id("msg-A");
        let b = chain_root_span_id("msg-B");
        assert_eq!(a1, a2, "same message id -> same root span (deterministic)");
        assert_ne!(a1, b, "different message ids -> different root spans");
        // UUID-shaped: parseable as a Uuid (8-4-4-4-12 hex).
        assert!(
            uuid::Uuid::parse_str(&a1).is_ok(),
            "chain_root_span_id must be UUID-shaped, got {a1:?}"
        );
    }
}
