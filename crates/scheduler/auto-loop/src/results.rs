//! `.agent/auto/results.jsonl` writer + `IterationResult` schema per PRD §4.7.10
//! (MODULE-015 §1.3.6 + §3.5 — slice B foundation for AC-15).
//!
//! Slice-B scope: ships the writer + schema as INDEPENDENT PRIMITIVES. The
//! integrated §4.7.7 iteration-close loop (per-iteration row emission) is
//! deferred; this slice unit-tests the schema and append mechanics.
//!
//! Single-writer-per-agent append-no-fsync semantics (MODULE-015 §3.8 note 4):
//! `OpenOptions::append(true).create(true)` is sufficient because each agent's
//! auto loop owns its results.jsonl exclusively (no concurrent writer). A
//! process crash mid-write may produce a torn final line which downstream
//! readers MUST skip; recovery is via EventBus replay since each iteration
//! emits `auto.iteration_completed`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::error::AutoLoopError;

/// Iteration disposition per PRD §4.7.7 (keep/discard/crash). The JSONL wire
/// form uses snake_case per PRD §4.7.10 schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IterationStatus {
    Keep,
    Discard,
    Crash,
}

impl IterationStatus {
    /// Stable lowercase identifier — used by `compose_complete_cycle_decision`
    /// to format the `final_status: {status}` portion of the round_completed
    /// decision text (PRD §4.7.7 line 934).
    pub fn as_str(&self) -> &'static str {
        match self {
            IterationStatus::Keep => "keep",
            IterationStatus::Discard => "discard",
            IterationStatus::Crash => "crash",
        }
    }
}

/// One row in `.agent/auto/results.jsonl` per PRD §4.7.10 schema verbatim.
/// Field names are snake_case (the PRD example uses snake_case here,
/// contrasting with the `auto-loop:` outer config key).
///
/// `metric` is a `BTreeMap` for deterministic JSON key ordering across runs
/// (HashMap would emit keys in random order). `summary: Option<String>`
/// serializes as `null` when None.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IterationResult {
    pub iter: u32,
    pub checkpoint: String,
    pub metric: BTreeMap<String, f64>,
    pub status: IterationStatus,
    pub cost_usd: f64,
    pub wall_time_sec: u64,
    pub summary: Option<String>,
}

/// Append-only writer for `.agent/auto/results.jsonl`. One instance per
/// agent's auto loop (single-writer assumption per MODULE-015 §3.8 note 4).
pub struct ResultsWriter {
    workspace_root: PathBuf,
}

impl ResultsWriter {
    /// `workspace_root` is the agent workspace root (PRD §6.4); the writer
    /// resolves the JSONL path to `<workspace_root>/.agent/auto/results.jsonl`.
    pub fn new(workspace_root: PathBuf) -> Self {
        Self { workspace_root }
    }

    /// Resolve the absolute jsonl path used by this writer.
    pub fn jsonl_path(&self) -> PathBuf {
        self.workspace_root
            .join(".agent")
            .join("auto")
            .join("results.jsonl")
    }

    /// Append one row. Creates `.agent/auto/` parent if absent. Schema:
    /// one JSONL line, no trailing newline before serialization; `\n` is
    /// appended after.
    ///
    /// All I/O + serialization failures surface as
    /// [`AutoLoopError::ResultsIo`] — distinct from `Parse` (which is for
    /// `success_criteria` YAML parse failures) so observability + operators
    /// can tell results.jsonl write failure from config parse failure.
    ///
    /// **Non-finite metric handling** (adversarial Round-2 Warning fix):
    /// `serde_json` rejects `f64::NaN` / `f64::INFINITY` at serialization
    /// time, which previously caused a hostile or buggy metric source to
    /// silently destroy the entire audit row (the iteration was never
    /// persisted). To prevent audit-trail destruction, `append` pre-sanitizes
    /// the `metric` map by **dropping any non-finite values** — the JSON
    /// row is written without those keys, so the iteration's other fields
    /// (iter, checkpoint, status, cost_usd, wall_time_sec, summary) and
    /// the well-formed metrics are still recorded. The dropped keys are
    /// observable by their absence (downstream readers can detect a
    /// missing expected key). This is fail-CLOSED at the audit layer: the
    /// row IS written, but malformed metrics don't leak through.
    pub async fn append(&self, result: &IterationResult) -> Result<(), AutoLoopError> {
        let path = self.jsonl_path();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| AutoLoopError::ResultsIo(format!("create .agent/auto: {e}")))?;
        }

        // Adversarial Round-2 fix: pre-sanitize non-finite metric values
        // so a NaN/Infinity in one key doesn't fail serialization for the
        // whole iteration row (which would silently destroy the audit
        // trail).
        let sanitized = sanitize_for_serialization(result);

        let mut line = serde_json::to_string(&sanitized)
            .map_err(|e| AutoLoopError::ResultsIo(format!("serialize IterationResult: {e}")))?;
        line.push('\n');

        let mut f = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .await
            .map_err(|e| AutoLoopError::ResultsIo(format!("open results.jsonl: {e}")))?;
        f.write_all(line.as_bytes())
            .await
            .map_err(|e| AutoLoopError::ResultsIo(format!("write results.jsonl: {e}")))?;
        f.flush()
            .await
            .map_err(|e| AutoLoopError::ResultsIo(format!("flush results.jsonl: {e}")))?;
        Ok(())
    }
}

/// Drop non-finite (`NaN` / `+inf` / `-inf`) metric values from the row
/// before JSON serialization, and clamp non-finite `cost_usd` to 0.0.
/// Adversarial Round-2 Warning fix — see [`ResultsWriter::append`] docstring
/// for the rationale. Pure function: returns a sanitized clone, leaving
/// the input untouched.
pub fn sanitize_for_serialization(result: &IterationResult) -> IterationResult {
    let mut sanitized_metric = std::collections::BTreeMap::new();
    for (k, v) in &result.metric {
        if v.is_finite() {
            sanitized_metric.insert(k.clone(), *v);
        }
        // Non-finite values are intentionally dropped — see docstring.
    }
    // `cost_usd` non-finite would also fail serde_json::to_string; clamp
    // to 0.0 so the iteration row is preserved. A non-finite cost is a
    // CostTracker bug; the integrated-loop slice's CostTracker is the
    // authoritative dedup/sanitization layer.
    let cost_usd = if result.cost_usd.is_finite() {
        result.cost_usd
    } else {
        0.0
    };
    IterationResult {
        iter: result.iter,
        checkpoint: result.checkpoint.clone(),
        metric: sanitized_metric,
        status: result.status,
        cost_usd,
        wall_time_sec: result.wall_time_sec,
        summary: result.summary.clone(),
    }
}

/// Audit signal: list of metric keys that [`sanitize_for_serialization`]
/// would drop from `result.metric` (adversarial Round-1 W4 fix).
/// Returns the keys whose values are NaN / +Inf / -Inf — these keys
/// will be silently absent from the written jsonl row, so callers MUST
/// emit a separate audit event (e.g., `auto.metric_dropped`) whenever
/// this returns a non-empty list. The integrated-loop slice is
/// responsible for wiring the audit emission; slice-C ships the
/// detection primitive only.
pub fn dropped_metric_keys(result: &IterationResult) -> Vec<String> {
    let mut dropped = Vec::new();
    for (k, v) in &result.metric {
        if !v.is_finite() {
            dropped.push(k.clone());
        }
    }
    dropped
}

/// Audit signal: whether [`sanitize_for_serialization`] would clamp
/// `result.cost_usd` to 0.0 (adversarial Round-1 W4 fix). Returns
/// `true` if the original `cost_usd` is non-finite, so the resulting
/// jsonl row will under-report cost — callers MUST emit an audit event
/// (e.g., `auto.cost_clamped`) whenever this returns `true`.
pub fn cost_clamped_to_zero(result: &IterationResult) -> bool {
    !result.cost_usd.is_finite()
}

/// Compose an [`IterationResult`] from the close-iteration sequence's
/// outputs (slice-C). Pure constructor over the PRD §4.7.10 schema —
/// schema unchanged; the helper exists so the close-iteration sequence
/// has one canonical row builder instead of every call site spelling out
/// the 7 fields.
///
/// Field provenance for the integrated-loop slice:
/// - `iter` — current iteration counter (from `AutoState.iteration`).
/// - `checkpoint_label` — `crate::checkpoint::iteration_label(n)` /
///   [`crate::checkpoint::BASELINE_LABEL`].
/// - `metric` — primary + guardrail readings collected this iteration,
///   keyed by metric name.
/// - `status` — keep / discard / crash final disposition.
/// - `cost_usd` — accumulated USD cost for this iteration (per-iter
///   budget cost).
/// - `wall_time_sec` — wall-clock elapsed seconds since
///   `AutoState.per_iter_budget_start`.
/// - `summary` — `Some(...)` on keep; `None` on crash; flexible on
///   discard.
///
/// Existing [`ResultsWriter::append`] continues to gate writes
/// through [`sanitize_for_serialization`] (NaN / Infinity protection).
pub fn row_from_outcome(
    iter: u32,
    checkpoint_label: String,
    metric: std::collections::BTreeMap<String, f64>,
    status: IterationStatus,
    cost_usd: f64,
    wall_time_sec: u64,
    summary: Option<String>,
) -> IterationResult {
    IterationResult {
        iter,
        checkpoint: checkpoint_label,
        metric,
        status,
        cost_usd,
        wall_time_sec,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iteration_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&IterationStatus::Keep).unwrap(),
            "\"keep\""
        );
        assert_eq!(
            serde_json::to_string(&IterationStatus::Discard).unwrap(),
            "\"discard\""
        );
        assert_eq!(
            serde_json::to_string(&IterationStatus::Crash).unwrap(),
            "\"crash\""
        );
    }

    #[test]
    fn iteration_status_as_str() {
        assert_eq!(IterationStatus::Keep.as_str(), "keep");
        assert_eq!(IterationStatus::Discard.as_str(), "discard");
        assert_eq!(IterationStatus::Crash.as_str(), "crash");
    }
}
