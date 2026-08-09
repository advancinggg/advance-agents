//! Structured progress convention helpers (MODULE-016 §1.4.3 + PRD §10.6 + AC-07/AC-11 share).
//!
//! **Helper/test only (2026-07-12 keeplosers-2 SUPERSESSION).** Constants, [`parse_progress`],
//! and [`validate_metadata_boundary`] exist for unit/integration tripwires. There is **no**
//! production caller of [`parse_progress`] and **no** agent-authored outbound reply/action
//! metadata carrier on the shipped payload-only action/reply/egress path. Do **not** treat
//! these helpers as production "reference adapter honors" evidence for MODULE-006-AC-08.
//!
//! Inbound `RawEvent.metadata` / `MessageOrigin.channel_metadata` is host-owned provenance
//! and routing state — not agent progress intent. Future honor work starts at agent output
//! and ends at adapter parse/render; it is not a flexible `message-context` free-form map
//! (forbidden by PRD §10.6 for progress).
//!
//! AC-07/AC-11 criterion text and ledger statuses are unchanged by this documentation
//! correction; a separate witness-floor audit may re-examine their passed evidence.

use crate::types::CapParam;

/// Metadata key for the progress phase.
pub const PROGRESS_PHASE: &str = "progress.phase";

/// Metadata key for the progress value (optional, 0.0..=1.0 as a string).
pub const PROGRESS_VALUE: &str = "progress.value";

/// Metadata key for the human-readable progress summary.
pub const PROGRESS_SUMMARY: &str = "progress.summary";

/// Common prefix; helper `is_progress_key` uses this.
pub const PROGRESS_PREFIX: &str = "progress.";

/// Progress phase enum mirroring the 4 documented `progress.phase` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProgressPhase {
    /// "ack" — immediate acknowledgement within seconds; "received, working on it".
    Ack,
    /// "progress" — intermediate updates during long-running work.
    Progress,
    /// "result" — final outcome (success).
    Result,
    /// "error" — final outcome (failure).
    Error,
}

impl ProgressPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Progress => "progress",
            Self::Result => "result",
            Self::Error => "error",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "ack" => Self::Ack,
            "progress" => Self::Progress,
            "result" => Self::Result,
            "error" => Self::Error,
            _ => return None,
        })
    }
}

/// Return the parsed [`ProgressPhase`] if `metadata` carries a recognized
/// `progress.phase` value. Unknown phase values produce `None` (per §10.6 —
/// adapters that don't understand pass through unchanged).
pub fn parse_progress(metadata: &[CapParam]) -> Option<ProgressPhase> {
    metadata
        .iter()
        .find(|p| p.key == PROGRESS_PHASE)
        .and_then(|p| ProgressPhase::from_str(&p.value))
}

/// True iff the supplied key falls under the `progress.*` namespace.
pub fn is_progress_key(key: &str) -> bool {
    key.starts_with(PROGRESS_PREFIX)
}

/// Boundary-validation error: a `progress.*` key was found among context keys.
///
/// Display string kept for compatibility. Helper/test only — not a production
/// AC-11 runtime gate. Agent-authored outbound reply metadata is the missing
/// AC-08 carrier; inbound channel_metadata is provenance only.
#[derive(Debug, PartialEq, Eq)]
pub struct ProgressBoundaryError {
    pub leaked_key: String,
}

impl std::fmt::Display for ProgressBoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "progress.* key {:?} leaked into message-context (must live on message.metadata per PRD §10.6)",
            self.leaked_key
        )
    }
}

impl std::error::Error for ProgressBoundaryError {}

/// Reject any `progress.*` key appearing among the supplied context-key strings.
///
/// Helper/test tripwire only. **Not** a production AC-11 runtime gate and **not**
/// end-to-end AC-08 evidence. Future honor work starts at agent-authored outbound
/// reply metadata → channel egress → adapter parse/render (not a flexible
/// message-context consumer; PRD §10.6).

pub fn validate_metadata_boundary(context_keys: &[String]) -> Result<(), ProgressBoundaryError> {
    for key in context_keys {
        if is_progress_key(key) {
            return Err(ProgressBoundaryError {
                leaked_key: key.clone(),
            });
        }
    }
    Ok(())
}

/// Max length of the `progress.summary` value. Matches the
/// `MAX_PARAM_VALUE_BYTES` cap enforced at the WIT lift boundary so
/// in-process callers don't construct values that the WIT layer would
/// reject. Adversarial Eval R19 Info #1.
pub const MAX_SUMMARY_BYTES: usize = 4096;

/// Reference-adapter helper that builds the `metadata` portion of a progress
/// reply per the §1.4.3 convention. Adapters typically construct their own
/// metadata directly; this helper exists for tests and example documentation.
/// `summary` values longer than `MAX_SUMMARY_BYTES` are truncated at the
/// nearest char boundary.
pub fn build_progress_metadata(
    phase: ProgressPhase,
    value: Option<f64>,
    summary: Option<&str>,
) -> Vec<CapParam> {
    let mut out = vec![CapParam::new(PROGRESS_PHASE, phase.as_str())];
    if let Some(v) = value {
        out.push(CapParam::new(PROGRESS_VALUE, v.to_string()));
    }
    if let Some(s) = summary {
        let bounded = if s.len() > MAX_SUMMARY_BYTES {
            // Truncate at the largest char boundary <= MAX_SUMMARY_BYTES.
            let cutoff = s
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|&i| i <= MAX_SUMMARY_BYTES)
                .last()
                .unwrap_or(0);
            &s[..cutoff]
        } else {
            s
        };
        out.push(CapParam::new(PROGRESS_SUMMARY, bounded));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_progress_recognizes_all_phases() {
        for phase in [
            ProgressPhase::Ack,
            ProgressPhase::Progress,
            ProgressPhase::Result,
            ProgressPhase::Error,
        ] {
            let metadata = vec![CapParam::new(PROGRESS_PHASE, phase.as_str())];
            assert_eq!(parse_progress(&metadata), Some(phase));
        }
    }

    #[test]
    fn parse_progress_returns_none_for_unknown() {
        let metadata = vec![CapParam::new(PROGRESS_PHASE, "wibble")];
        assert!(parse_progress(&metadata).is_none());
    }

    #[test]
    fn parse_progress_returns_none_when_key_absent() {
        let metadata = vec![CapParam::new("reply_style", "buttons")];
        assert!(parse_progress(&metadata).is_none());
    }

    #[test]
    fn validate_metadata_boundary_rejects_progress_in_context() {
        let context_keys = vec!["progress.phase".to_string(), "task_id".to_string()];
        let err = validate_metadata_boundary(&context_keys).unwrap_err();
        assert_eq!(err.leaked_key, "progress.phase");
    }

    #[test]
    fn validate_metadata_boundary_accepts_clean_context() {
        let context_keys = vec!["task_id".to_string(), "run_id".to_string()];
        assert!(validate_metadata_boundary(&context_keys).is_ok());
    }

    #[test]
    fn build_progress_metadata_with_value_and_summary() {
        let m = build_progress_metadata(ProgressPhase::Progress, Some(0.7), Some("3/5 files"));
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].key, PROGRESS_PHASE);
        assert_eq!(m[0].value, "progress");
        assert_eq!(m[1].key, PROGRESS_VALUE);
        assert_eq!(m[2].key, PROGRESS_SUMMARY);
    }

    #[test]
    fn build_progress_metadata_phase_only() {
        let m = build_progress_metadata(ProgressPhase::Ack, None, None);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].key, PROGRESS_PHASE);
        assert_eq!(m[0].value, "ack");
    }
}
