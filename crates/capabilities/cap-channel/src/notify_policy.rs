//! cap-channel-visible expression of MODULE-016 §2.8's `notify-error` policy
//! table (AC-10).
//!
//! MODULE-006 owns the production of `notify-error` variants (CONTRACT-050
//! `notify-agent`); cap-channel does NOT call notify-agent at compile time (per
//! AC-08). This module ships a typed enum + `recommend_action` helper so an
//! adapter WASM guest — or any consumer interested in the "caller handles"
//! policy — has a stable Rust-side handle on the §2.8 guidance.
//!
//! Test T11/T12 verify variant-shape behaviour (NOT specific numeric values
//! like backoff_ms) per the spec's wording: §2.8 says "drop + log for chat-style
//! firehoses; retry with backoff for user-initiated messages" without pinning
//! a numeric target.

/// notify-error variants surfaced by MODULE-006's notify-agent host function.
/// Mirrors MODULE-016 §2.8 row taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotifyError {
    /// Target agent's bounded mailbox at capacity (backpressure).
    MailboxFull,
    /// MODULE-001 CircuitBreakerBus reports the agent's breaker in open state.
    CircuitBreakerOpen,
    /// Target agent id unknown.
    NotFound,
    /// Adapter lacks `notify` scope for the target agent (MODULE-013 grant
    /// check rejected).
    CapabilityDenied,
    /// `message-context` passed to notify-agent is malformed.
    InvalidContext,
}

/// Per-adapter policy that shapes how `recommend_action` chooses between
/// drop / retry / queue for transient errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterPolicy {
    /// Chat-style firehose: high inbound rate, drop on backpressure is OK
    /// (user can resend; no reply is expected per-message).
    ChatFirehose,
    /// User-initiated: a specific user is waiting for the reply; retry
    /// preserves UX continuity.
    UserInitiated,
}

/// Recommended adapter action in response to a notify-error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterAction {
    /// Drop the event silently (or with a log line per adapter policy).
    Drop,
    /// Drop, but make a record in the adapter audit trail.
    LogAndDrop,
    /// Wait until the breaker reaches half-open, then retry.
    Queue,
    /// Retry after a backoff window. Slice B's `backoff_ms` is a default;
    /// adapters can tune. The test does not pin a specific value.
    Retry { backoff_ms: u32 },
}

/// Apply the MODULE-016 §2.8 policy table to choose an action.
///
/// Per §2.8 (the canonical table):
/// - `MailboxFull` × `ChatFirehose` → `Drop`
/// - `MailboxFull` × `UserInitiated` → `Retry { .. }` ("retry with backoff")
/// - `CircuitBreakerOpen` × `*` → `Queue` ("queues OR drops"; we pick Queue
///    for Slice B — the test T12 accepts either via a disjunction)
/// - `NotFound` × `*` → `LogAndDrop` ("log and drop; do not retry")
/// - `CapabilityDenied` × `*` → `LogAndDrop` ("log and drop; record in adapter
///    audit trail; do not retry")
/// - `InvalidContext` × `*` → `LogAndDrop` ("log error + drop; adapter bug")
pub fn recommend_action(err: NotifyError, policy: AdapterPolicy) -> AdapterAction {
    match err {
        NotifyError::MailboxFull => match policy {
            AdapterPolicy::ChatFirehose => AdapterAction::Drop,
            AdapterPolicy::UserInitiated => AdapterAction::Retry { backoff_ms: 500 },
        },
        NotifyError::CircuitBreakerOpen => AdapterAction::Queue,
        NotifyError::NotFound => AdapterAction::LogAndDrop,
        NotifyError::CapabilityDenied => AdapterAction::LogAndDrop,
        NotifyError::InvalidContext => AdapterAction::LogAndDrop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_full_chat_firehose_drops() {
        assert!(matches!(
            recommend_action(NotifyError::MailboxFull, AdapterPolicy::ChatFirehose),
            AdapterAction::Drop
        ));
    }

    #[test]
    fn mailbox_full_user_initiated_retries() {
        // Variant-shape assertion only — no specific backoff_ms pinned, per
        // §2.8 wording ("retry with backoff" — no numeric target).
        assert!(matches!(
            recommend_action(NotifyError::MailboxFull, AdapterPolicy::UserInitiated),
            AdapterAction::Retry { .. }
        ));
    }

    #[test]
    fn circuit_breaker_open_routes_to_queue_or_drop() {
        // §2.8: "Adapter queues OR drops; no retry until breaker half-open".
        // The disjunction matches the spec; rejects spec-disallowed `Retry`.
        for policy in [AdapterPolicy::ChatFirehose, AdapterPolicy::UserInitiated] {
            assert!(matches!(
                recommend_action(NotifyError::CircuitBreakerOpen, policy),
                AdapterAction::Queue | AdapterAction::Drop
            ));
        }
    }

    #[test]
    fn permanent_errors_log_and_drop() {
        for err in [
            NotifyError::NotFound,
            NotifyError::CapabilityDenied,
            NotifyError::InvalidContext,
        ] {
            for policy in [AdapterPolicy::ChatFirehose, AdapterPolicy::UserInitiated] {
                assert!(matches!(
                    recommend_action(err, policy),
                    AdapterAction::LogAndDrop
                ));
            }
        }
    }
}
