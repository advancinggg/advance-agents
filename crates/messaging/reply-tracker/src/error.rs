//! Admission + dispatch error categorization for the slice-A foundation.
//!
//! Two enums + three pure functions encapsulate the §1.3.4 error-triage rules:
//!
//! - [`AdmissionError`] — admission-stage errors that produce a whole-call
//!   `Err(OrchestrationError)` from `AwaitSessionManager::start()`.
//! - [`DispatchSlotError`] — per-target dispatch errors recorded into the
//!   session's `received` Vec as `ReplyStatus::Failed("{kind}:{id}")` strings.
//! - [`classify_admission`] — `AdmissionError → OrchestrationError` projection.
//! - [`classify_dispatch`] — exhaustive `MsgError → DispatchSlotError` mapping
//!   over all 5 `MsgError` variants. `target_id` is injected by the caller
//!   because `MsgError::MailboxFull` is payloadless on the Rust side.
//! - [`format_per_slot_reason`] — produces the PRD §9.2 canonical per-slot
//!   reason strings (the 5 `MsgError`-derived prefixes plus the AC-09
//!   `deadlock:{target}` prefix, which is synthesized by `dispatch_slots`
//!   for the some-but-not-all-cycle case rather than projected from a
//!   `MsgError`).
//!
//! # WIT projection rule for the 3 Rust-only `OrchestrationError` variants
//!
//! `crates/shared-types/src/await_session.rs::OrchestrationError` has 9 variants
//! while PRD §9.2 `orchestration-error` (WIT) has 6. The 3 extra Rust variants
//! map to WIT `invalid-target(...)` at the host-fn boundary with an `internal:`
//! prefix:
//!
//! | Rust variant | WIT projection |
//! |--------------|----------------|
//! | `NotFound(s)` | `invalid-target("internal:not-found:" + s)` |
//! | `InvalidRequest(s)` | `invalid-target("internal:invalid-request:" + s)` |
//! | `Downstream(s)` | `invalid-target("internal:downstream:" + s)` |
//!
//! Documented in slice m007-A (2026-05-18) so the slice-C M006 host-fn handler
//! has a fixed mapping to implement. The `internal:` prefix is a PII-safe invariant
//! identifier (no user data leaks into the projected string).
//!
//! # PII discipline
//!
//! All per-slot reason strings produced by [`format_per_slot_reason`] are
//! invariant identifiers (`{kind}:{target-id}`). Implementers MUST NOT pass
//! user prompts, API keys, session tokens, or filesystem paths into the
//! `target_id` parameter — the `is_safe_id` grammar restriction
//! (`agent:[A-Za-z0-9_-]+`) bounds the id surface, but callers building error
//! messages from arbitrary strings could leak. See shared-types
//! `crates/shared-types/src/await_session.rs` file-level security posture note.

use advance_shared_types::await_session::OrchestrationError;
use advance_shared_types::mailbox::MsgError;

/// Admission-stage errors. Produces whole-call `Err(OrchestrationError)` from
/// `AwaitSessionManager::start()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// Caller lacks the `await-replies` capability (per PRD §9.2).
    CapabilityDenied(String),
    /// Caller's concurrent open sessions ≥ `MAX_INFLIGHT`.
    SessionLimitExceeded(String),
    /// All requested agent targets would create a cycle in the AwaitSession
    /// graph. Produced by the AC-09 admission deadlock gate (§1.3.4
    /// admission deadlock-all) via the `crate::deadlock::forms_cycle`
    /// `parent_of` ancestry walk; projects to
    /// `OrchestrationError::DeadlockDetected`.
    DeadlockAll(String),
    /// Invalid `AwaitOptions` / `AwaitRequest` (empty requests list, bad mode
    /// combo, malformed target id).
    InvalidRequest(String),
}

/// Per-target dispatch errors. Recorded into the session's `received` Vec as
/// `ReplyStatus::Failed("{kind}:{id}")` strings.
///
/// The first 5 variants are distinct (one per `MsgError` variant) so the
/// per-slot reason string can be faithfully derived from a dispatcher
/// failure; the 6th (`Deadlock`) is synthesized by `dispatch_slots` for the
/// AC-09 some-but-not-all-cycle case (no dispatcher call). Future slices may
/// add `CircuitBreakerFreeze` or related variants when the CONTRACT-002
/// wiring lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchSlotError {
    InvalidTarget(String),
    /// Mailbox-full carries the target id (injected by classify_dispatch
    /// because the underlying `MsgError::MailboxFull` is payloadless).
    MailboxFull(String),
    CircuitBreakerOpen(String),
    CapabilityDenied(String),
    /// Slice-A retains InvalidPayload as a dedicated variant rather than
    /// collapsing it into CapabilityDenied — preserves triage fidelity.
    InvalidPayload(String),
    /// AC-09 some-but-not-all-cycle: this slot's target would form an
    /// AwaitSession cycle. Not a `MsgError` projection (the dispatcher is
    /// never invoked for it) — synthesized by `dispatch_slots` so the
    /// canonical per-slot `deadlock:{target}` reason flows through the
    /// existing recording path. Carries the canonical `agent:<name>` target.
    Deadlock(String),
}

/// Project an admission error to the canonical [`OrchestrationError`]
/// variant. Exhaustive over the 4 [`AdmissionError`] variants.
pub fn classify_admission(err: AdmissionError) -> OrchestrationError {
    match err {
        AdmissionError::CapabilityDenied(s) => OrchestrationError::CapabilityDenied(s),
        AdmissionError::SessionLimitExceeded(s) => OrchestrationError::SessionLimitExceeded(s),
        AdmissionError::DeadlockAll(s) => OrchestrationError::DeadlockDetected(s),
        AdmissionError::InvalidRequest(s) => OrchestrationError::InvalidRequest(s),
    }
}

/// Project a [`MsgError`] (from `MailboxDispatcher::deliver`) to a slot-scoped
/// [`DispatchSlotError`]. Exhaustive over all 5 [`MsgError`] variants.
///
/// `target_id` is the canonical agent id passed into `deliver`; it's threaded
/// in here because `MsgError::MailboxFull` is payloadless on the Rust side.
pub fn classify_dispatch(err: MsgError, target_id: &str) -> DispatchSlotError {
    match err {
        MsgError::InvalidTarget(s) => DispatchSlotError::InvalidTarget(s),
        MsgError::MailboxFull => DispatchSlotError::MailboxFull(target_id.to_string()),
        MsgError::CircuitBreakerOpen(s) => DispatchSlotError::CircuitBreakerOpen(s),
        MsgError::CapabilityDenied(s) => DispatchSlotError::CapabilityDenied(s),
        MsgError::InvalidPayload(s) => DispatchSlotError::InvalidPayload(s),
    }
}

/// Maximum length of a per-slot reason string after sanitization
/// (Adversarial round 1 W9). Bounds the size of strings flowing into logs /
/// JSONL events / downstream callers.
pub const MAX_REASON_LEN: usize = 256;

/// Format a [`DispatchSlotError`] as the PRD §9.2 canonical per-slot reason
/// string (`"{kind}:{id}"`). One distinct prefix per variant (the 5
/// `MsgError`-derived prefixes plus the AC-09 `deadlock` prefix).
///
/// **Adversarial round 1 W9 hardening**: the `id` component is sanitized to
/// strip ASCII control characters and bound the result at `MAX_REASON_LEN`.
/// Upstream `MsgError` variants may carry attacker-controlled strings
/// (especially for `CircuitBreakerOpen`/`CapabilityDenied`/`InvalidPayload`);
/// the slice-A foundation does not trust the upstream surface to be safe for
/// log lines and so applies a defensive sanitization here.
pub fn format_per_slot_reason(err: &DispatchSlotError) -> String {
    let (kind, id) = match err {
        DispatchSlotError::InvalidTarget(id) => ("invalid-target", id),
        DispatchSlotError::MailboxFull(id) => ("mailbox-full", id),
        DispatchSlotError::CircuitBreakerOpen(id) => ("circuit-breaker-open", id),
        DispatchSlotError::CapabilityDenied(id) => ("capability-denied", id),
        DispatchSlotError::InvalidPayload(id) => ("invalid-payload", id),
        // AC-09 some-but-not-all-cycle per-slot reason. `id` is the
        // canonical `agent:<name>` target, so this renders e.g.
        // `deadlock:agent:b` — same `{kind}:{canonical-target}` shape as
        // `invalid-target:agent:zzz`.
        DispatchSlotError::Deadlock(id) => ("deadlock", id),
    };
    let sanitized: String = id
        .chars()
        .filter(|c| !c.is_ascii_control()) // strip newlines / nulls / CR / etc.
        .take(MAX_REASON_LEN.saturating_sub(kind.len() + 1))
        .collect();
    format!("{kind}:{sanitized}")
}
