//! Slice C AC-11 tests (T96–T98b): repetition-terminated stable
//! identifier + retry-classifier predicates.

use advance_run_manager::{is_retryable_repetition_decision, is_terminate_decision};
use advance_shared_types::repetition::{RepetitionDecision, REPETITION_TERMINATED_TAG};

/// T96 — Stable wire identifier `"repetition-terminated"`.
#[test]
fn t96_repetition_terminated_tag_is_stable() {
    assert_eq!(REPETITION_TERMINATED_TAG, "repetition-terminated");
}

/// T97 — is_terminate_decision discriminates only the Terminate variant.
#[test]
fn t97_is_terminate_decision_discriminant() {
    assert!(!is_terminate_decision(&RepetitionDecision::Pass));
    assert!(!is_terminate_decision(&RepetitionDecision::Warn(
        "x".into()
    )));
    assert!(is_terminate_decision(&RepetitionDecision::Terminate(
        "x".into()
    )));
}

/// Stub M009-style retry classifier matrix. M009 owns the actual classifier
/// in cap-llm; this stub mimics its policy so we can prove M008-side
/// invariants hold WITHOUT introducing a compile-time edge M009→M008.
fn is_retryable_llm_error_tag(tag: &str) -> bool {
    match tag {
        // Retryable per PRD §4.6 retry classification table.
        "rate-limited" | "provider-error" => true,
        // Non-retryable per PRD §4.6 + §4.2.3.
        "model-not-available"
        | "context-too-long"
        | "budget-exceeded"
        | "structured-output-failed"
        | "repetition-terminated" => false,
        _ => false,
    }
}

/// T98 — REPETITION_TERMINATED_TAG must be in the non-retryable set; no
/// overlap with the retryable patterns. is_retryable_repetition_decision
/// on Terminate(_) returns false.
#[test]
fn t98_repetition_terminated_in_non_retryable_set() {
    assert!(!is_retryable_llm_error_tag(REPETITION_TERMINATED_TAG));
    // Crosscheck: retryable set distinct.
    for retryable in ["rate-limited", "provider-error"] {
        assert!(
            is_retryable_llm_error_tag(retryable),
            "{} expected retryable",
            retryable
        );
        assert_ne!(retryable, REPETITION_TERMINATED_TAG);
    }
    // is_retryable_repetition_decision on Terminate(...) returns false.
    assert!(!is_retryable_repetition_decision(
        &RepetitionDecision::Terminate("output-repeat".into())
    ));
}

/// T98b — is_retryable_repetition_decision on Pass / Warn returns true
/// (only Terminate is non-retryable per AC-11).
#[test]
fn t98b_pass_and_warn_are_retryable() {
    assert!(is_retryable_repetition_decision(&RepetitionDecision::Pass));
    assert!(is_retryable_repetition_decision(&RepetitionDecision::Warn(
        "x".into()
    )));
}
