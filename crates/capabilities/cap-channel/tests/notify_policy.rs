//! Integration tests for the `notify-error` policy table (AC-10).
//!
//! T11/T12 verify the §2.8 policy table via variant-shape assertions (no
//! plan-invented numeric constants pinned).

use cap_channel::{recommend_action, AdapterAction, AdapterPolicy, NotifyError};

/// T11 (AC-10): MailboxFull policy — drop for chat firehose, retry for
/// user-initiated. Variant-shape only (no specific backoff_ms pinned, per
/// §2.8 wording "retry with backoff").
#[test]
fn t11_mailbox_full_policy_table() {
    // ChatFirehose drops on backpressure.
    assert!(matches!(
        recommend_action(NotifyError::MailboxFull, AdapterPolicy::ChatFirehose),
        AdapterAction::Drop
    ));
    // UserInitiated retries with backoff (variant shape, value unbound).
    assert!(matches!(
        recommend_action(NotifyError::MailboxFull, AdapterPolicy::UserInitiated),
        AdapterAction::Retry { .. }
    ));
}

/// T12 (AC-10): CircuitBreakerOpen — adapter queues OR drops (per §2.8:
/// "queues or drops"). Disjunction accepts either spec-allowed variant;
/// rejects spec-disallowed `Retry`.
#[test]
fn t12_circuit_breaker_open_policy_table() {
    for policy in [AdapterPolicy::ChatFirehose, AdapterPolicy::UserInitiated] {
        let action = recommend_action(NotifyError::CircuitBreakerOpen, policy);
        assert!(
            matches!(action, AdapterAction::Queue | AdapterAction::Drop),
            "circuit-breaker-open under {policy:?} got {action:?}; expected Queue or Drop"
        );
        // The spec explicitly excludes Retry until the breaker half-opens.
        assert!(!matches!(action, AdapterAction::Retry { .. }));
    }
}

/// Permanent errors (NotFound / CapabilityDenied / InvalidContext) all map to
/// LogAndDrop per §2.8.
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
