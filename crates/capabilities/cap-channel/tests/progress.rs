//! Helper/unit tests for the structured progress convention (T07 AC-07 helper behavior,
//! T13 AC-11).
//! **NOT production end-to-end AC-07/AC-11/M006-AC-08 evidence** (no production caller / no outbound carrier).

use cap_channel::{
    build_progress_metadata, parse_progress, validate_metadata_boundary, CapParam, ProgressPhase,
    PROGRESS_PHASE, PROGRESS_SUMMARY, PROGRESS_VALUE,
};

/// Reference adapter — minimal example that adapters can crib from. Builds
/// the metadata for an ack→work→result chain.
struct ReferenceAdapter;

impl ReferenceAdapter {
    fn ack() -> Vec<CapParam> {
        build_progress_metadata(ProgressPhase::Ack, None, Some("received, working on it"))
    }

    fn progress(value: f64, summary: &str) -> Vec<CapParam> {
        build_progress_metadata(ProgressPhase::Progress, Some(value), Some(summary))
    }

    fn result() -> Vec<CapParam> {
        build_progress_metadata(ProgressPhase::Result, None, Some("done"))
    }

    fn error() -> Vec<CapParam> {
        build_progress_metadata(ProgressPhase::Error, None, Some("something broke"))
    }
}

/// T07 (AC-07 helper): structured progress convention — ack → progress → result (helper only)
/// chain works for a reference adapter; all 4 phases recognized.
#[test]
fn t07_ack_progress_result_chain() {
    let ack = ReferenceAdapter::ack();
    let progress = ReferenceAdapter::progress(0.7, "3/5 files");
    let result = ReferenceAdapter::result();
    let error = ReferenceAdapter::error();

    assert_eq!(parse_progress(&ack), Some(ProgressPhase::Ack));
    assert_eq!(parse_progress(&progress), Some(ProgressPhase::Progress));
    assert_eq!(parse_progress(&result), Some(ProgressPhase::Result));
    assert_eq!(parse_progress(&error), Some(ProgressPhase::Error));

    // ack carries no value, but does carry a summary.
    assert!(!ack.iter().any(|p| p.key == PROGRESS_VALUE));
    assert!(ack.iter().any(|p| p.key == PROGRESS_SUMMARY));

    // progress carries phase + value + summary.
    let value_pair = progress.iter().find(|p| p.key == PROGRESS_VALUE).unwrap();
    assert_eq!(value_pair.value, "0.7");

    // Phase key is always present.
    for m in [&ack, &progress, &result, &error] {
        assert!(m.iter().any(|p| p.key == PROGRESS_PHASE));
    }
}

/// Unknown progress.phase values pass through unchanged (the adapter that
/// doesn't understand them sees `None`, per §10.6).
#[test]
fn t07_unknown_phase_passes_through() {
    let m = vec![CapParam::new(PROGRESS_PHASE, "unknown-phase")];
    assert!(parse_progress(&m).is_none());
}

/// T13 (AC-11 helper): `validate_metadata_boundary` rejects when `progress.*` leaks (tripwire only; not production runtime gate)
/// into `context_keys` (PRD §10.6 — progress is per-reply ephemeral; must
/// live on metadata, not message-context).
#[test]
fn t13_progress_lives_on_metadata_rejects_context_leak() {
    let context_keys = vec![
        "task_id".to_string(),
        "progress.phase".to_string(), // leak!
    ];
    let err = validate_metadata_boundary(&context_keys).unwrap_err();
    assert_eq!(err.leaked_key, "progress.phase");
}

/// Clean message-context (no progress.* keys) is accepted; metadata is
/// allowed to carry as many progress.* keys as it wants.
#[test]
fn t13_clean_context_accepted_metadata_unconstrained() {
    // metadata is held by the reference adapter — the validator only
    // inspects context_keys.
    let _metadata = vec![
        CapParam::new(PROGRESS_PHASE, "progress"),
        CapParam::new(PROGRESS_VALUE, "0.5"),
        CapParam::new(PROGRESS_SUMMARY, "halfway"),
    ];
    let context_keys = vec![
        "task_id".to_string(),
        "run_id".to_string(),
        "execution_id".to_string(),
    ];
    assert!(validate_metadata_boundary(&context_keys).is_ok());
}
