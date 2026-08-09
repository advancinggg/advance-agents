//! `turn-index.yaml` schema — MODULE-011 §1.3.4.
//!
//! Combined L0 (`collapsed_view`) + L2 (`digest`) + L3 (`epochs`) index
//! used for progressive context loading. Slice A scaffolds the schema +
//! serde round-trip only; L1 vector embedding (AC-19), L3 epoch trigger
//! (AC-20), and reference_count sync-back (AC-31) are deferred.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// `_meta` block for the turn-index. Tracks the latest epoch boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnIndexMeta {
    pub last_epoch_turn: u32,
    pub last_epoch_at: String,
}

/// Line-range cursor into `llm-turns.jsonl`. MODULE-011 §1.3.4
/// `log_offset` field — the precedent for [`crate::knowledge::LineRange`].
///
/// **Inverted-range guard**: [`LogOffset::validate`] enforces
/// `start_line <= end_line` so a tampered fixture with
/// `{"start_line": 100, "end_line": 50}` can be rejected at the caller's
/// boundary (Adversarial Round 2 fix).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogOffset {
    pub start_line: u32,
    pub end_line: u32,
}

impl LogOffset {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.start_line > self.end_line {
            return Err("LogOffset.start_line must be <= end_line (inverted range rejected)");
        }
        Ok(())
    }
}

/// Turn importance gating. Drives the per-frequency update cadence of
/// the summary (MODULE-011 §1.3.3) and the L3 epoch trigger logic
/// (§1.3.6, AC-20). Wire form is lowercase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Importance {
    Normal,
    Notable,
    Critical,
}

/// Read-file blob snapshot captured at turn boundary. Used by L6 stale
/// detection to compare `blob_id` against the current MODULE-002 entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFileVersion {
    pub path: String,
    pub blob_id: String,
}

/// Per-turn index entry. MODULE-011 §1.3.4 `turns[]`. Carries L0
/// `collapsed_view` + L2 `digest` + token counters + git fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnEntry {
    pub turn: u32,
    pub timestamp: String,
    pub agent_id: String,
    pub task_id: String,
    pub log_offset: LogOffset,
    pub has_user_instruction: bool,
    pub has_user_correction: bool,
    pub has_tool_use: bool,
    pub has_decision: bool,
    pub importance: Importance,
    /// L2 digest (≈25 token summary line).
    pub digest: String,
    /// L0 collapsed view (≈85 token excerpt of the turn).
    pub collapsed_view: String,
    pub git_commit: String,
    pub git_diff_summary: String,
    pub git_checkpoints: Vec<String>,
    pub reference_count: u32,
    pub content_identifiers: Vec<String>,
    pub read_file_versions: Vec<ReadFileVersion>,
    pub tokens_digest: u32,
    pub tokens_collapse_excerpt: u32,
    pub tokens_l0_processed: u32,
}

/// Deterministic single-sentence digest used when no LLM-derived digest is
/// available (the mechanical-digest fallback path — AC-38 / T50-c). A constant
/// (not derived from message bytes) so it never side-channels payload sizes,
/// mirroring the `mechanical_digest_fallback` opaque-marker posture.
pub const MECHANICAL_TURN_DIGEST: &str =
    "Turn processed without an LLM-derived digest (mechanical fallback).";

/// Max bytes for a stored `TurnEntry.digest` (adversarial-round W2). The
/// digest is a single-sentence (~25-token) summary; the LLM that produces it
/// is driven by guest/user-influenced turn content, so `build_turn_digest`
/// bounds + single-lines it before it reaches `turn-index.yaml` / the
/// downstream embedding text — closing the verbatim-unbounded stored-injection
/// / size-amplification surface.
pub const MAX_TURN_DIGEST_BYTES: usize = 512;

/// Git-association inputs for an L2 turn digest (AC-38). A turn that produced a
/// commit carries the SHA + diff summary + checkpoint labels; a turn that
/// produced NO commit uses [`GitAssociation::none`] (all empty) — the digest is
/// still emitted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GitAssociation {
    pub git_commit: String,
    pub git_diff_summary: String,
    pub git_checkpoints: Vec<String>,
}

impl GitAssociation {
    /// The no-commit case: all git fields empty.
    pub fn none() -> Self {
        Self::default()
    }

    /// A turn produced no commit (no SHA and no checkpoints).
    pub fn is_empty(&self) -> bool {
        self.git_commit.is_empty()
            && self.git_diff_summary.is_empty()
            && self.git_checkpoints.is_empty()
    }
}

/// Compute the L2 turn digest from an [`crate::extractor::Extraction`] (AC-38,
/// REQ-227). The BatchExtractor success path carries `Some(digest)` → that
/// single-sentence summary is propagated (provenance: the digest came FROM the
/// extractor, not a local default), after a `sanitize_digest` pass. The
/// mechanical-digest fallback path carries `None` (or an empty/whitespace
/// digest) → a deterministic [`MECHANICAL_TURN_DIGEST`] single sentence is
/// synthesized.
///
/// **Bound + single-line (adversarial-round W2):** the BatchExtractor digest
/// is LLM-derived from guest-influenced content, so it is collapsed to a single
/// line (control chars / newlines → spaces, runs collapsed, trimmed) and capped
/// at [`MAX_TURN_DIGEST_BYTES`] (char-boundary-safe, `…` marker when truncated)
/// before it reaches `turn-index.yaml` / the downstream embedding text. The
/// non-empty/whitespace provenance content is preserved (T50-a still asserts a
/// short digest round-trips verbatim); only oversize/multiline input is bounded.
pub fn build_turn_digest(extraction: &crate::extractor::Extraction) -> String {
    match &extraction.digest {
        Some(d) if !d.trim().is_empty() => {
            let s = sanitize_digest(d);
            // A digest of pure control chars collapses to "" under sanitize;
            // fall back to the mechanical marker rather than store an empty
            // digest (adversarial-round Info-2).
            if s.is_empty() {
                MECHANICAL_TURN_DIGEST.to_string()
            } else {
                s
            }
        }
        _ => MECHANICAL_TURN_DIGEST.to_string(),
    }
}

/// Collapse a digest to a single bounded line: replace control chars (incl.
/// newlines/tabs) with spaces, collapse whitespace runs, trim, and truncate at
/// a char boundary to [`MAX_TURN_DIGEST_BYTES`] (appending `…` when cut).
fn sanitize_digest(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_TURN_DIGEST_BYTES + 3));
    let mut prev_space = false;
    for ch in raw.chars() {
        // Map to space: C0/C1 controls + DEL (is_control), BOM, AND the Unicode
        // line/paragraph separators U+2028/U+2029 (which is_control does NOT
        // cover) so the single-line guarantee is absolute (adversarial-round Info-1).
        let c = if ch.is_control() || ch == '\u{feff}' || ch == '\u{2028}' || ch == '\u{2029}' {
            ' '
        } else {
            ch
        };
        if c == ' ' {
            if prev_space {
                continue;
            }
            prev_space = true;
        } else {
            prev_space = false;
        }
        out.push(c);
    }
    let out = out.trim().to_string();
    if out.len() <= MAX_TURN_DIGEST_BYTES {
        return out;
    }
    // Char-boundary-safe truncation.
    let mut end = MAX_TURN_DIGEST_BYTES;
    while end > 0 && !out.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = out[..end].trim_end().to_string();
    truncated.push('…');
    truncated
}

/// Populate a [`TurnEntry`]'s L2 `digest` + git-association fields from an
/// extraction + git inputs (AC-38). The digest is derived via
/// [`build_turn_digest`] (verbatim BatchExtractor digest, else mechanical);
/// the git fields are copied from `git` (empty for a no-commit turn). The
/// resulting entry "carries git-association fields" alongside its digest —
/// the AC-38 §1.5 invariant — and a no-commit turn keeps the git fields empty
/// while still emitting a non-empty digest.
pub fn apply_turn_digest(
    entry: &mut TurnEntry,
    extraction: &crate::extractor::Extraction,
    git: &GitAssociation,
) {
    entry.digest = build_turn_digest(extraction);
    entry.git_commit = git.git_commit.clone();
    entry.git_diff_summary = git.git_diff_summary.clone();
    entry.git_checkpoints = git.git_checkpoints.clone();
}

/// L3 recurring-pattern observation aggregated across an epoch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringPattern {
    pub pattern: String,
    pub occurrences: Vec<u32>,
}

/// L3 preference-signal observation aggregated across an epoch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceSignal {
    pub signal: String,
    pub related_turns: Vec<u32>,
    pub confidence: f64,
}

/// L3 correction-drift observation aggregated across an epoch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrectionDrift {
    pub from: String,
    pub to: String,
    pub drift_turns: Vec<u32>,
}

/// Epoch-level L3 aggregation (every 20 turns or 2h per AC-20, but the
/// trigger logic itself is deferred to a later slice).
///
/// **Inverted-range guard**: [`Epoch::validate`] enforces
/// `turns.0 <= turns.1` (Adversarial Round 3 fix; closes the parity
/// gap with `LineRange::validate` and `LogOffset::validate`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub id: String,
    /// Inclusive `[first_turn, last_turn]` 2-tuple.
    pub turns: (u32, u32),
    pub generated_at: String,
    pub summary: String,
    pub key_turns: Vec<u32>,
    pub tokens: u32,
    pub recurring_patterns: Vec<RecurringPattern>,
    pub preference_signals: Vec<PreferenceSignal>,
    pub correction_drift: Vec<CorrectionDrift>,
}

impl Epoch {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.turns.0 > self.turns.1 {
            return Err(
                "Epoch.turns (first, last) must satisfy first <= last (inverted range rejected)",
            );
        }
        Ok(())
    }
}

/// Combined per-task turn index. Stored at
/// `.agent/memory/tasks/{task_id}/turn-index.yaml`. MODULE-011 §1.3.4.
///
/// **Bounded-input responsibility**: `turns: Vec<TurnEntry>`, `epochs:
/// Vec<Epoch>`, plus every nested `Vec<u32>` and `String` field is
/// uncapped by serde alone; consumers reading from untrusted YAML
/// MUST cap input size before deserialization. Same DoS-class concern
/// as [`crate::knowledge::MemoryEntry`] and
/// [`crate::summary::Summary`]; bounds are not normatively pinned by
/// PRD §11.2.1 in this slice. Future I/O-wiring slices SHOULD impose
/// per-field caps consistent with their threat model.
///
/// **Range invariants**: `LogOffset` and `Epoch.turns` shapes
/// (inclusive ranges) admit `start > end` inversions at the type
/// level. [`LogOffset::validate`] enforces the canonical
/// `start_line <= end_line` ordering for log offsets; future slices
/// adding cross-entry consistency checks may want to validate epoch
/// `turns` ordering similarly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnIndex {
    #[serde(rename = "_meta")]
    pub meta: TurnIndexMeta,
    pub turns: Vec<TurnEntry>,
    pub epochs: Vec<Epoch>,
}

impl TurnIndex {
    /// Run the inverted-range guards on every nested `LogOffset` and
    /// `Epoch.turns`. Adversarial Round 3 fix — wires
    /// [`LogOffset::validate`] and [`Epoch::validate`] into a single
    /// entry point so callers reading from untrusted YAML have a
    /// well-known method to enforce ordering invariants. Idempotent.
    pub fn validate_invariants(&self) -> Result<(), &'static str> {
        for turn in &self.turns {
            turn.log_offset.validate()?;
        }
        for epoch in &self.epochs {
            epoch.validate()?;
        }
        Ok(())
    }
}

/// MODULE-011 §1.4 AC-20 (REQ-228) L3 epoch turn-count threshold per §1.3.6 + PRD §11.3.3.
pub const EPOCH_TURN_THRESHOLD: u32 = 20;

/// MODULE-011 §1.4 AC-20 (REQ-228) L3 epoch wall-clock threshold (2 hours).
pub const EPOCH_TIME_THRESHOLD: Duration = Duration::from_secs(2 * 3600);

impl TurnIndex {
    /// MODULE-011 §1.4 AC-20 (REQ-228): pure-compute L3 epoch trigger.
    ///
    /// Returns `true` iff EITHER `turns_since_last_epoch >= 20` OR
    /// `time_since_last_epoch >= Duration::from_secs(2 * 3600)`. The trigger
    /// is the **cap-memory deliverable** for AC-20; the "injects task-local
    /// enhancements" clause (§1.4 line 375) is MODULE-010 context-engine
    /// territory (L3 epoch payload assembly + injection into the LLM context),
    /// partitioned out as out-of-crate the same way AC-25's identity/skills/
    /// raw-turns categories are partitioned (§3.8 note 11).
    ///
    /// Boundary semantics (inclusive `>=`): the 20th turn-since-last-epoch and
    /// the 2-hour mark both fire. Either-of: time alone can fire even when
    /// turns is 0, and vice versa.
    pub fn should_trigger_epoch(
        turns_since_last_epoch: u32,
        time_since_last_epoch: Duration,
    ) -> bool {
        turns_since_last_epoch >= EPOCH_TURN_THRESHOLD
            || time_since_last_epoch >= EPOCH_TIME_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_turn_index() -> TurnIndex {
        TurnIndex {
            meta: TurnIndexMeta {
                last_epoch_turn: 40,
                last_epoch_at: "2026-03-23T08:00:00Z".into(),
            },
            turns: vec![TurnEntry {
                turn: 47,
                timestamp: "2026-03-23T10:00:00Z".into(),
                agent_id: "research".into(),
                task_id: "task-001".into(),
                log_offset: LogOffset {
                    start_line: 1240,
                    end_line: 1380,
                },
                has_user_instruction: true,
                has_user_correction: false,
                has_tool_use: true,
                has_decision: true,
                importance: Importance::Notable,
                digest: "分析竞品A定价，发现Q3涨价15%".into(),
                collapsed_view: "[user] '分析竞品A的定价' → ...".into(),
                git_commit: "abc1234".into(),
                git_diff_summary: "+45 reports/a-analysis.md".into(),
                git_checkpoints: vec!["checkpoint-before-analysis".into()],
                reference_count: 3,
                content_identifiers: vec![
                    "data/pricing.csv".into(),
                    "reports/a-analysis.md".into(),
                ],
                read_file_versions: vec![ReadFileVersion {
                    path: "data/pricing.csv".into(),
                    blob_id: "a1b2c3d4".into(),
                }],
                tokens_digest: 25,
                tokens_collapse_excerpt: 85,
                tokens_l0_processed: 2400,
            }],
            epochs: vec![Epoch {
                id: "epoch-001".into(),
                turns: (1, 20),
                generated_at: "2026-03-22T14:00:00Z".into(),
                summary: "确定范围：5家竞品。".into(),
                key_turns: vec![2, 5, 12, 18],
                tokens: 120,
                recurring_patterns: vec![RecurringPattern {
                    pattern: "web-search → file-write → summarize".into(),
                    occurrences: vec![43, 48, 52, 57],
                }],
                preference_signals: vec![PreferenceSignal {
                    signal: "用户第3次要求先列大纲再写全文".into(),
                    related_turns: vec![44, 51, 58],
                    confidence: 0.7,
                }],
                correction_drift: vec![CorrectionDrift {
                    from: "markdown 格式输出".into(),
                    to: "YAML 格式输出".into(),
                    drift_turns: vec![45, 52, 58],
                }],
            }],
        }
    }

    #[test]
    fn turn_index_roundtrip_l0_l2_l3() {
        let index = example_turn_index();
        let yaml = serde_yml::to_string(&index).expect("serialize");
        let parsed: TurnIndex = serde_yml::from_str(&yaml).expect("deserialize");
        assert_eq!(index, parsed);

        // L0 + L2 + L3 fields must all round-trip through the YAML.
        assert!(yaml.contains("collapsed_view:"));
        assert!(yaml.contains("digest:"));
        assert!(yaml.contains("epochs:"));
        assert!(yaml.contains("recurring_patterns:"));
        assert!(yaml.contains("preference_signals:"));
        assert!(yaml.contains("correction_drift:"));
    }

    /// Fixture test based on the §1.3.4 example. Uses a single-turn / single-epoch
    /// fixture to exercise the L0/L2/L3 fields end-to-end.
    #[test]
    fn turn_index_deserialize_from_module_doc_example() {
        let fixture = r#"_meta:
  last_epoch_turn: 40
  last_epoch_at: "2026-03-23T08:00:00Z"
turns:
  - turn: 47
    timestamp: "2026-03-23T10:00:00Z"
    agent_id: research
    task_id: task-001
    log_offset:
      start_line: 1240
      end_line: 1380
    has_user_instruction: true
    has_user_correction: false
    has_tool_use: true
    has_decision: true
    importance: notable
    digest: "分析竞品A定价，发现Q3涨价15%"
    collapsed_view: "[user] '分析竞品A的定价'"
    git_commit: "abc1234"
    git_diff_summary: "+45 reports/a-analysis.md"
    git_checkpoints:
      - "checkpoint-before-analysis"
    reference_count: 3
    content_identifiers:
      - data/pricing.csv
      - reports/a-analysis.md
    read_file_versions:
      - path: data/pricing.csv
        blob_id: a1b2c3d4
    tokens_digest: 25
    tokens_collapse_excerpt: 85
    tokens_l0_processed: 2400
epochs:
  - id: epoch-001
    turns: [1, 20]
    generated_at: "2026-03-22T14:00:00Z"
    summary: "确定范围：5家竞品。"
    key_turns: [2, 5, 12, 18]
    tokens: 120
    recurring_patterns:
      - pattern: "web-search → file-write → summarize"
        occurrences: [43, 48, 52, 57]
    preference_signals:
      - signal: "用户第3次要求先列大纲再写全文"
        related_turns: [44, 51, 58]
        confidence: 0.7
    correction_drift:
      - from: "markdown 格式输出"
        to: "YAML 格式输出"
        drift_turns: [45, 52, 58]
"#;
        let parsed: TurnIndex = serde_yml::from_str(fixture).expect("parse fixture");
        assert_eq!(parsed.meta.last_epoch_turn, 40);
        assert_eq!(parsed.turns.len(), 1);
        assert_eq!(parsed.turns[0].importance, Importance::Notable);
        assert_eq!(parsed.turns[0].log_offset.start_line, 1240);
        assert_eq!(parsed.turns[0].log_offset.end_line, 1380);
        assert_eq!(parsed.epochs.len(), 1);
        assert_eq!(parsed.epochs[0].turns, (1, 20));
        assert_eq!(parsed.epochs[0].recurring_patterns.len(), 1);
        assert_eq!(
            parsed.epochs[0].correction_drift[0].drift_turns,
            vec![45, 52, 58]
        );
    }

    #[test]
    fn turn_index_log_offset_inclusive_range() {
        let offset = LogOffset {
            start_line: 100,
            end_line: 200,
        };
        let yaml = serde_yml::to_string(&offset).expect("serialize");
        let parsed: LogOffset = serde_yml::from_str(&yaml).expect("deserialize");
        assert_eq!(offset, parsed);
        assert!(yaml.contains("start_line:"));
        assert!(yaml.contains("end_line:"));
    }

    /// Adversarial Round 2 fix: `LogOffset.validate` rejects inverted
    /// ranges (mirroring `LineRange::validate`).
    #[test]
    fn log_offset_validate_rejects_inverted() {
        let bad = LogOffset {
            start_line: 200,
            end_line: 100,
        };
        assert!(bad.validate().is_err());
        let ok = LogOffset {
            start_line: 100,
            end_line: 200,
        };
        assert!(ok.validate().is_ok());
        let eq = LogOffset {
            start_line: 7,
            end_line: 7,
        };
        assert!(eq.validate().is_ok());
    }

    /// Adversarial Round 3 fix: `Epoch.validate` rejects inverted
    /// `turns` (parity with `LineRange` / `LogOffset`).
    #[test]
    fn epoch_validate_rejects_inverted_turns() {
        let mut epoch = example_turn_index().epochs.pop().unwrap();
        epoch.turns = (200, 100);
        assert!(epoch.validate().is_err());
        epoch.turns = (1, 20);
        assert!(epoch.validate().is_ok());
        epoch.turns = (7, 7);
        assert!(epoch.validate().is_ok());
    }

    /// Adversarial Round 3 fix: `TurnIndex::validate_invariants` wires
    /// `LogOffset::validate` + `Epoch::validate` into a single entry
    /// point so callers reading from untrusted YAML have a well-known
    /// method to enforce ordering invariants.
    #[test]
    fn turn_index_validate_invariants_propagates_log_offset() {
        let mut index = example_turn_index();
        index.turns[0].log_offset = LogOffset {
            start_line: 500,
            end_line: 100,
        };
        assert!(index.validate_invariants().is_err());
    }

    #[test]
    fn turn_index_validate_invariants_propagates_epoch_turns() {
        let mut index = example_turn_index();
        index.epochs[0].turns = (500, 100);
        assert!(index.validate_invariants().is_err());
    }

    #[test]
    fn turn_index_validate_invariants_accepts_well_formed() {
        let index = example_turn_index();
        assert!(index.validate_invariants().is_ok());
    }

    #[test]
    fn turn_index_importance_enum() {
        for (variant, wire) in [
            (Importance::Normal, "normal"),
            (Importance::Notable, "notable"),
            (Importance::Critical, "critical"),
        ] {
            let yaml = serde_yml::to_string(&variant).unwrap();
            assert!(yaml.contains(wire));
            let parsed: Importance = serde_yml::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(parsed, variant);
        }
        let invalid: Result<Importance, _> = serde_yml::from_str("\"foo\"");
        assert!(invalid.is_err(), "expected reject of invalid importance");
    }

    #[test]
    fn turn_index_epoch_correction_drift_shape() {
        let drift = CorrectionDrift {
            from: "markdown".into(),
            to: "yaml".into(),
            drift_turns: vec![1, 2, 3],
        };
        let yaml = serde_yml::to_string(&drift).expect("serialize");
        let parsed: CorrectionDrift = serde_yml::from_str(&yaml).expect("deserialize");
        assert_eq!(drift, parsed);
    }

    // ─────────────────────────── AC-20 (REQ-228) ───────────────────────────
    //
    // L3 epoch trigger compute. §1.4 line 375 + PRD §11.3.3: "20 turns or 2h".
    // The "injects task-local enhancements" clause is partitioned out to the
    // context-engine; cap-memory provides the boolean trigger primitive only.

    #[test]
    fn epoch_trigger_below_both_thresholds_no_fire() {
        // 19 turns, 7199s = 2h-1s → both below.
        assert!(!TurnIndex::should_trigger_epoch(
            19,
            Duration::from_secs(7199)
        ));
    }

    #[test]
    fn epoch_trigger_fires_at_exactly_20_turns() {
        // Boundary inclusive: 20 turns fires regardless of elapsed time.
        assert!(TurnIndex::should_trigger_epoch(20, Duration::ZERO));
    }

    #[test]
    fn epoch_trigger_fires_at_exactly_2_hours() {
        // Boundary inclusive: 7200s = 2h fires regardless of turn count.
        assert!(TurnIndex::should_trigger_epoch(
            0,
            Duration::from_secs(7200)
        ));
    }

    #[test]
    fn epoch_trigger_fires_when_both_thresholds_met() {
        assert!(TurnIndex::should_trigger_epoch(
            20,
            Duration::from_secs(7200)
        ));
    }

    #[test]
    fn epoch_trigger_time_alone_fires_with_zero_turns() {
        // Either-of: time alone (e.g., long idle followed by 1 turn) fires.
        assert!(TurnIndex::should_trigger_epoch(
            0,
            Duration::from_secs(10_000)
        ));
    }

    #[test]
    fn epoch_trigger_turns_alone_fires_with_zero_time() {
        // Either-of: turn-count alone fires regardless of elapsed time.
        assert!(TurnIndex::should_trigger_epoch(100, Duration::ZERO));
    }

    // ───────── AC-38 L2 turn digest (T50) ─────────

    use crate::extractor::Extraction;

    /// Minimal `TurnEntry` whose digest + git fields are blank — the subject
    /// `build_turn_digest`/`apply_turn_digest` populate.
    fn blank_turn_entry() -> TurnEntry {
        TurnEntry {
            turn: 1,
            timestamp: "2026-06-07T00:00:00Z".into(),
            agent_id: "agent:r".into(),
            task_id: "task-001".into(),
            log_offset: LogOffset {
                start_line: 0,
                end_line: 0,
            },
            has_user_instruction: false,
            has_user_correction: false,
            has_tool_use: false,
            has_decision: false,
            importance: Importance::Normal,
            digest: String::new(),
            collapsed_view: String::new(),
            git_commit: String::new(),
            git_diff_summary: String::new(),
            git_checkpoints: vec![],
            reference_count: 0,
            content_identifiers: vec![],
            read_file_versions: vec![],
            tokens_digest: 0,
            tokens_collapse_excerpt: 0,
            tokens_l0_processed: 0,
        }
    }

    // T50-a: a BatchExtractor digest is propagated VERBATIM into TurnEntry.digest
    // (provenance — proves it came from the extractor, not a local default), and
    // the git-association fields are populated.
    #[test]
    fn t50a_digest_propagated_verbatim_with_git_association() {
        let extraction = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("Refactored the auth module to use magic-link sessions.".into()),
        };
        let git = GitAssociation {
            git_commit: "abc1234".into(),
            git_diff_summary: "+45 src/auth.rs".into(),
            git_checkpoints: vec!["checkpoint-before-auth".into()],
        };
        // The pure digest function returns the extractor's digest verbatim.
        assert_eq!(
            build_turn_digest(&extraction),
            "Refactored the auth module to use magic-link sessions."
        );
        // apply_turn_digest carries BOTH the digest AND the git fields on the entry.
        let mut entry = blank_turn_entry();
        apply_turn_digest(&mut entry, &extraction, &git);
        assert_eq!(
            entry.digest,
            "Refactored the auth module to use magic-link sessions."
        );
        assert_eq!(entry.git_commit, "abc1234");
        assert_eq!(entry.git_diff_summary, "+45 src/auth.rs");
        assert_eq!(entry.git_checkpoints, vec!["checkpoint-before-auth"]);
        assert!(!git.is_empty());
    }

    // T50-b: a turn that produced NO commit leaves the git fields empty while
    // STILL emitting a (non-empty) digest.
    #[test]
    fn t50b_no_commit_leaves_git_empty_but_digest_present() {
        let extraction = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("Read the pricing CSV; no files changed.".into()),
        };
        let git = GitAssociation::none();
        assert!(git.is_empty());
        let mut entry = blank_turn_entry();
        apply_turn_digest(&mut entry, &extraction, &git);
        assert_eq!(entry.git_commit, "");
        assert_eq!(entry.git_diff_summary, "");
        assert!(entry.git_checkpoints.is_empty());
        assert!(!entry.digest.is_empty());
        assert_eq!(entry.digest, "Read the pricing CSV; no files changed.");
    }

    // T50-c: the mechanical-digest fallback (digest: None) synthesizes a
    // deterministic single-sentence mechanical digest.
    #[test]
    fn t50c_fallback_synthesizes_mechanical_digest() {
        let none_digest = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: None,
        };
        assert_eq!(build_turn_digest(&none_digest), MECHANICAL_TURN_DIGEST);
        // Whitespace-only digest is also treated as absent → mechanical.
        let blank_digest = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("   ".into()),
        };
        let mech = build_turn_digest(&blank_digest);
        assert_eq!(mech, MECHANICAL_TURN_DIGEST);
        // Mechanical digest is a single non-empty sentence (ends with a period).
        assert!(!mech.is_empty());
        assert!(mech.ends_with('.'));

        let mut entry = blank_turn_entry();
        apply_turn_digest(&mut entry, &none_digest, &GitAssociation::none());
        assert_eq!(entry.digest, MECHANICAL_TURN_DIGEST);
    }

    // W2: an LLM-influenced digest is single-lined + length-bounded before it
    // reaches TurnEntry.digest (no verbatim-unbounded multiline injection).
    #[test]
    fn build_turn_digest_sanitizes_and_bounds() {
        // Newlines/tabs/control chars collapse to single spaces; runs collapse.
        let multiline = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("line one\n\nline two\twith\ttabs   and   spaces".into()),
        };
        let d = build_turn_digest(&multiline);
        assert!(!d.contains('\n') && !d.contains('\t'));
        assert!(!d.contains("  "), "whitespace runs collapsed: {d:?}");
        assert_eq!(d, "line one line two with tabs and spaces");

        // Oversize is truncated at a char boundary with a … marker.
        let huge = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("a".repeat(MAX_TURN_DIGEST_BYTES + 100)),
        };
        let d = build_turn_digest(&huge);
        assert!(
            d.len() <= MAX_TURN_DIGEST_BYTES + 3,
            "len {} bounded",
            d.len()
        );
        assert!(d.ends_with('…'));

        // Multi-byte truncation: 200×'€' (3 bytes each = 600B) forces the
        // char-boundary back-off (byte 512 falls mid-char) — no panic, the cut
        // lands on a boundary so every retained char is intact.
        let multibyte = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("€".repeat(200)),
        };
        let d = build_turn_digest(&multibyte);
        assert!(d.len() <= MAX_TURN_DIGEST_BYTES + 3);
        assert!(d.ends_with('…'));
        assert!(
            d.strip_suffix('…').unwrap().chars().all(|c| c == '€'),
            "truncation landed on a char boundary; no partial char"
        );

        // A normal short single-line sentence is preserved verbatim (T50-a path).
        let normal = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("Refactored auth to magic-link.".into()),
        };
        assert_eq!(build_turn_digest(&normal), "Refactored auth to magic-link.");

        // Info-1: Unicode line/paragraph separators (U+2028/U+2029) also collapse
        // to a single line (is_control does not cover them).
        let uniline = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("a\u{2028}b\u{2029}c".into()),
        };
        let d = build_turn_digest(&uniline);
        assert_eq!(d, "a b c");
        assert!(!d.contains('\u{2028}') && !d.contains('\u{2029}'));

        // Info-2: a pure-control digest passes the trim()-non-empty guard but
        // sanitizes to "" → falls back to the mechanical marker (never empty).
        let pure_control = Extraction {
            descriptions: vec![],
            knowledge: vec![],
            digest: Some("\u{0}\u{1}\u{7}".into()),
        };
        assert_eq!(build_turn_digest(&pure_control), MECHANICAL_TURN_DIGEST);
    }
}
