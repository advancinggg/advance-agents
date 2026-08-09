//! **NOT AC-08 production evidence** (helper tripwire only).
//! Progress-helper infra tripwires (T-B33..T-B35). **NOT AC-08 evidence.**
//!
//! AC-08 end-to-end remains untested: gap is absent outbound agent-metadata
//! carrier + zero production parse_progress (NOT a WIT host_fn flexible
//! message-context map — SUPERSEDED 2026-07-12). These tests pin the shipped boundary
//! helper + constants so a future regression is caught early.

use advance_messaging::{is_progress_key, validate_metadata_boundary, PROGRESS_PHASE};

// T-B33 — is_progress_key recognizes the namespace and rejects near-misses.
#[test]
fn t_b33_is_progress_key() {
    assert!(is_progress_key("progress.phase"));
    assert!(is_progress_key(PROGRESS_PHASE));
    assert!(!is_progress_key("phase"));
    assert!(!is_progress_key("progressive")); // no dot — not the namespace
}

// T-B34 — validate_metadata_boundary rejects a progress.* context key,
// reporting the leaked key.
#[test]
fn t_b34_boundary_rejects_progress_context_key() {
    let err = validate_metadata_boundary(&["task_id".to_string(), "progress.phase".to_string()])
        .unwrap_err();
    assert_eq!(err.leaked_key, "progress.phase");
}

// T-B35 — validate_metadata_boundary accepts a clean (identity-only)
// context-key set.
#[test]
fn t_b35_boundary_accepts_clean_context() {
    validate_metadata_boundary(&[
        "task_id".to_string(),
        "run_id".to_string(),
        "execution_id".to_string(),
    ])
    .expect("clean context keys must pass");
}
