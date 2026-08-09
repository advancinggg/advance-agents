//! `summary.yaml` L4 task-summary schema — MODULE-011 §1.3.3.
//!
//! Captures the per-task brief + key_decisions + findings +
//! open_questions + current_state + errors_and_corrections + workflow,
//! with a `_meta` block tracking per-frequency update cursors. Slice A
//! scaffolds the schema only; per-frequency update gating (AC-28) is
//! deferred to a later slice.

use serde::{Deserialize, Serialize};

use crate::turn_index::Importance;

/// `_meta` block of [`Summary`]. Carries per-frequency update cursors
/// (`last_brief_update`, `last_decisions_update`, `last_state_update`)
/// per MODULE-011 §1.3.3.
///
/// Slice A retains `status` and `profile` as `String` rather than typed
/// enums — PRD §11.1.2 enumerates allowed status / profile values, but
/// enum tightening is deferred to a future slice per Risk Assessment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SummaryMeta {
    pub task_id: String,
    pub agent_id: String,
    pub title: String,
    pub status: String,
    pub profile: String,
    pub turns_total: u32,
    /// ISO-8601 UTC timestamp string.
    pub last_updated: String,
    pub last_turn_at: String,
    pub last_brief_update: u32,
    pub last_decisions_update: u32,
    pub last_state_update: u32,
}

/// Confidence level for a [`Finding`]. Matches MODULE-011 §1.3.3
/// example. Slice A's serde-rename rule is `lowercase` so the wire form
/// is `high` / `medium` / `low`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// A noteworthy decision recorded at a specific turn. MODULE-011 §1.3.3
/// `key_decisions[]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDecision {
    pub turn: u32,
    pub content: String,
}

/// A research / analysis finding linked to its origin turn. MODULE-011
/// §1.3.3 `findings[]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub content: String,
    pub confidence: Confidence,
    pub turn: u32,
}

/// An error + correction event. MODULE-011 §1.3.3
/// `errors_and_corrections[]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    pub turn: u32,
    pub content: String,
}

/// Per-task L4 summary stored at `.agent/memory/tasks/{task_id}/summary.yaml`.
/// 7 top-level fields + `_meta` block matching MODULE-011 §1.3.3.
///
/// **Bounded-input responsibility**: every `Vec<T>` and `String` field
/// is uncapped by serde alone; consumers reading `Summary` from
/// untrusted YAML (tampered workspace file, future host-fn payload)
/// MUST apply an input-size cap **before** deserialization (e.g.,
/// `io::Read::take(MAX_BYTES)` on the underlying reader, or validate
/// on-disk file size first). Same DoS-class concern as
/// [`crate::knowledge::MemoryEntry`]; bounds are not normatively
/// pinned by PRD §11.2 in this slice. Future I/O-wiring slices SHOULD
/// impose per-field caps consistent with their threat model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    #[serde(rename = "_meta")]
    pub meta: SummaryMeta,
    pub brief: String,
    pub key_decisions: Vec<KeyDecision>,
    pub findings: Vec<Finding>,
    pub open_questions: Vec<String>,
    pub current_state: String,
    pub errors_and_corrections: Vec<Correction>,
    pub workflow: String,
}

/// MODULE-011 §1.4 AC-28 (REQ-229): per-cadence brief update threshold.
/// §1.3.3 line 164: "brief: every 3 turns or notable turn".
pub const BRIEF_UPDATE_THRESHOLD: u32 = 3;

/// MODULE-011 §1.4 AC-28 (REQ-229): per-cadence decisions-group update threshold.
/// §1.3.3 line 165: "key_decisions/findings/open_questions: every 5 turns or
/// critical turn". §1.4 AC-28's `key_progress every 5 turns` label aliases this
/// cadence tier.
pub const DECISIONS_UPDATE_THRESHOLD: u32 = 5;

/// MODULE-011 §1.4 AC-28 (REQ-229): per-cadence state-group update threshold.
/// §1.3.3 line 166: "current_state/errors/workflow: every 10 turns or direction
/// change". §1.4 AC-28's `key_findings every 10 turns` label aliases this
/// cadence tier.
pub const STATE_UPDATE_THRESHOLD: u32 = 10;

impl Summary {
    /// MODULE-011 §1.4 AC-28 (REQ-229): should the `brief` field be refreshed
    /// on the current turn?
    ///
    /// Returns `true` iff EITHER:
    /// - `current_turn - meta.last_brief_update >= 3` (cadence threshold; `>=`
    ///   inclusive at the boundary), OR
    /// - `importance ∈ {Notable, Critical}` (§1.3.3 line 164 "or notable turn"
    ///   override; `Critical` strictly dominates `Notable` per the natural
    ///   `Normal < Notable < Critical` precedence ordering).
    ///
    /// Saturating arithmetic: a malformed cursor where `meta.last_brief_update
    /// > current_turn` (tampered YAML, counter-wrap, etc.) clamps the delta to
    /// `0`. This avoids panic; the override path still fires on `Notable` or
    /// `Critical` if applicable.
    ///
    /// §1.4 AC-28 cross-walk: `brief` label maps to this cursor directly.
    pub fn should_update_brief(&self, current_turn: u32, importance: Importance) -> bool {
        let delta = current_turn.saturating_sub(self.meta.last_brief_update);
        delta >= BRIEF_UPDATE_THRESHOLD
            || matches!(importance, Importance::Notable | Importance::Critical)
    }

    /// MODULE-011 §1.4 AC-28 (REQ-229): should the `key_decisions` / `findings`
    /// / `open_questions` cadence group be refreshed on the current turn?
    ///
    /// Returns `true` iff EITHER:
    /// - `current_turn - meta.last_decisions_update >= 5`, OR
    /// - `importance == Critical` (§1.3.3 line 165 "or critical turn").
    ///
    /// §1.4 AC-28 cross-walk: AC-28's `key_progress every 5 turns` label
    /// aliases this cadence group; the cursor `meta.last_decisions_update`
    /// embodies the tier per §1.3.3's concrete field membership
    /// (`key_decisions` + `findings` + `open_questions`).
    ///
    /// Saturating arithmetic: same as `should_update_brief`.
    pub fn should_update_decisions(&self, current_turn: u32, importance: Importance) -> bool {
        let delta = current_turn.saturating_sub(self.meta.last_decisions_update);
        delta >= DECISIONS_UPDATE_THRESHOLD || matches!(importance, Importance::Critical)
    }

    /// MODULE-011 §1.4 AC-28 (REQ-229): should the `current_state` /
    /// `errors_and_corrections` / `workflow` cadence group be refreshed on the
    /// current turn?
    ///
    /// Returns `true` iff ANY of:
    /// - `current_turn - meta.last_state_update >= 10`,
    /// - `importance == Critical`,
    /// - `direction_changed == true`.
    ///
    /// `direction_changed: bool` is a separate input axis because §1.3.3 line
    /// 166's "or direction change" override has no representation in the
    /// `Importance` enum (`Normal`/`Notable`/`Critical` only). Passing the
    /// override as an explicit boolean argument faithfully encodes the §1.3.3
    /// + §1.4 cross-walk without overloading `Importance`; a future direction-
    /// change detector (M010 or M014 wiring) supplies the boolean from its own
    /// signal.
    ///
    /// §1.4 AC-28 cross-walk: AC-28's `key_findings every 10 turns` label
    /// aliases this cadence group; the cursor `meta.last_state_update`
    /// embodies the tier per §1.3.3's concrete field membership
    /// (`current_state` + `errors_and_corrections` + `workflow`).
    ///
    /// Saturating arithmetic: same as `should_update_brief`.
    pub fn should_update_state(
        &self,
        current_turn: u32,
        importance: Importance,
        direction_changed: bool,
    ) -> bool {
        let delta = current_turn.saturating_sub(self.meta.last_state_update);
        delta >= STATE_UPDATE_THRESHOLD
            || matches!(importance, Importance::Critical)
            || direction_changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_summary() -> Summary {
        Summary {
            meta: SummaryMeta {
                task_id: "task-001".into(),
                agent_id: "research".into(),
                title: "Q3 竞品定价分析".into(),
                status: "active".into(),
                profile: "research".into(),
                turns_total: 62,
                last_updated: "2026-03-23T10:00:00Z".into(),
                last_turn_at: "2026-03-23T10:00:00Z".into(),
                last_brief_update: 60,
                last_decisions_update: 55,
                last_state_update: 50,
            },
            brief: "分析5家竞品Q3定价。A涨价15%因AI功能。".into(),
            key_decisions: vec![KeyDecision {
                turn: 5,
                content: "确定分析范围为 5 家竞品的 SaaS 定价".into(),
            }],
            findings: vec![Finding {
                content: "竞品A涨价原因是新增AI功能模块".into(),
                confidence: Confidence::High,
                turn: 28,
            }],
            open_questions: vec!["ROI分析维度的具体指标待确认".into()],
            current_state: "已完成5家竞品数据收集".into(),
            errors_and_corrections: vec![Correction {
                turn: 18,
                content: "最初用了过期的竞品C价格，用户纠正后重新采集".into(),
            }],
            workflow: "数据收集 → 清洗 → 横向对比 → 趋势分析 → ROI估算".into(),
        }
    }

    #[test]
    fn summary_roundtrip_full_schema() {
        let summary = example_summary();
        let yaml = serde_yml::to_string(&summary).expect("serialize");
        let parsed: Summary = serde_yml::from_str(&yaml).expect("deserialize");
        assert_eq!(summary, parsed);
        assert!(yaml.contains("_meta:"));
        assert!(yaml.contains("last_brief_update:"));
        assert!(yaml.contains("last_decisions_update:"));
        assert!(yaml.contains("last_state_update:"));
    }

    /// Fixture-based test against the MODULE-011 §1.3.3 example YAML.
    #[test]
    fn summary_deserialize_from_module_doc_example() {
        let fixture = r#"_meta:
  task_id: task-001
  agent_id: research
  title: "Q3 竞品定价分析"
  status: active
  profile: research
  turns_total: 62
  last_updated: "2026-03-23T10:00:00Z"
  last_turn_at: "2026-03-23T10:00:00Z"
  last_brief_update: 60
  last_decisions_update: 55
  last_state_update: 50

brief: "分析5家竞品Q3定价。A涨价15%因AI功能。"

key_decisions:
  - turn: 5
    content: "确定分析范围为 5 家竞品的 SaaS 定价"
  - turn: 55
    content: "对竞品E采用等效月费估算方法"

findings:
  - content: "竞品A涨价原因是新增AI功能模块"
    confidence: high
    turn: 28

open_questions:
  - "ROI分析维度的具体指标待确认"

current_state: "已完成5家竞品数据收集"
errors_and_corrections:
  - turn: 18
    content: "最初用了过期的竞品C价格，用户纠正后重新采集"
workflow: "数据收集 → 清洗 → 横向对比 → 趋势分析 → ROI估算"
"#;
        let parsed: Summary = serde_yml::from_str(fixture).expect("parse fixture");
        assert_eq!(parsed.meta.task_id, "task-001");
        assert_eq!(parsed.meta.turns_total, 62);
        assert_eq!(parsed.meta.last_brief_update, 60);
        assert_eq!(parsed.key_decisions.len(), 2);
        assert_eq!(parsed.findings[0].confidence, Confidence::High);
    }

    #[test]
    fn summary_meta_cursors_present() {
        let meta = SummaryMeta::default();
        assert_eq!(meta.last_brief_update, 0);
        assert_eq!(meta.last_decisions_update, 0);
        assert_eq!(meta.last_state_update, 0);
    }

    #[test]
    fn summary_key_decisions_shape() {
        let mut summary = example_summary();
        summary.key_decisions = vec![];
        let yaml = serde_yml::to_string(&summary).expect("serialize");
        let parsed: Summary = serde_yml::from_str(&yaml).expect("deserialize");
        assert_eq!(parsed.key_decisions, Vec::<KeyDecision>::new());

        let multi = vec![
            KeyDecision {
                turn: 5,
                content: "a".into(),
            },
            KeyDecision {
                turn: 12,
                content: "b".into(),
            },
        ];
        let yaml = serde_yml::to_string(&multi).unwrap();
        let parsed: Vec<KeyDecision> = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(parsed, multi);
    }

    #[test]
    fn summary_findings_confidence() {
        let valid = r#"
content: "x"
confidence: high
turn: 1
"#;
        let parsed: Finding = serde_yml::from_str(valid).expect("high accepted");
        assert_eq!(parsed.confidence, Confidence::High);

        let invalid = r#"
content: "x"
confidence: foo
turn: 1
"#;
        let result: Result<Finding, _> = serde_yml::from_str(invalid);
        assert!(result.is_err(), "expected reject of invalid confidence");
    }

    // ─────────────────────────── AC-28 (REQ-229) ───────────────────────────
    //
    // L4 update frequencies per-field. §1.3.3 lines 163-166:
    //   - brief: every 3 turns or notable turn
    //   - key_decisions/findings/open_questions: every 5 turns or critical turn
    //   - current_state/errors/workflow: every 10 turns or direction change
    //
    // §1.4 AC-28 cross-walk: `brief` / `key_progress` / `key_findings` labels
    // alias the 3 cadence tiers; cursors `last_brief_update` /
    // `last_decisions_update` / `last_state_update` embody them.

    fn summary_with_cursors(brief: u32, decisions: u32, state: u32) -> Summary {
        Summary {
            meta: SummaryMeta {
                task_id: "task-test".into(),
                agent_id: "agent".into(),
                title: "test".into(),
                status: "active".into(),
                profile: "research".into(),
                turns_total: 0,
                last_updated: "2026-03-23T10:00:00Z".into(),
                last_turn_at: "2026-03-23T10:00:00Z".into(),
                last_brief_update: brief,
                last_decisions_update: decisions,
                last_state_update: state,
            },
            brief: String::new(),
            key_decisions: vec![],
            findings: vec![],
            open_questions: vec![],
            current_state: String::new(),
            errors_and_corrections: vec![],
            workflow: String::new(),
        }
    }

    // ── should_update_brief ──

    #[test]
    fn should_update_brief_fires_at_exactly_3_turns_normal() {
        let s = summary_with_cursors(10, 0, 0);
        // delta = 13 - 10 = 3 (inclusive threshold) → true.
        assert!(s.should_update_brief(13, Importance::Normal));
    }

    #[test]
    fn should_update_brief_no_fire_at_2_turn_delta_normal() {
        let s = summary_with_cursors(10, 0, 0);
        assert!(!s.should_update_brief(12, Importance::Normal));
    }

    #[test]
    fn should_update_brief_fires_on_notable_below_threshold() {
        // delta = 11 - 10 = 1 (< 3); Notable triggers override.
        let s = summary_with_cursors(10, 0, 0);
        assert!(s.should_update_brief(11, Importance::Notable));
    }

    #[test]
    fn should_update_brief_fires_on_critical_below_threshold() {
        // Critical strictly dominates Notable per natural ordering.
        let s = summary_with_cursors(10, 0, 0);
        assert!(s.should_update_brief(11, Importance::Critical));
    }

    #[test]
    fn should_update_brief_saturating_sub_against_malformed_cursor() {
        // Tampered cursor where last_brief_update > current_turn. delta
        // clamps to 0; no panic; under-trigger unless override fires.
        let s = summary_with_cursors(1000, 0, 0);
        assert!(!s.should_update_brief(5, Importance::Normal));
        assert!(s.should_update_brief(5, Importance::Notable));
    }

    // ── should_update_decisions ──

    #[test]
    fn should_update_decisions_fires_at_exactly_5_turns_normal() {
        let s = summary_with_cursors(0, 20, 0);
        assert!(s.should_update_decisions(25, Importance::Normal));
    }

    #[test]
    fn should_update_decisions_no_fire_at_4_turn_delta_normal() {
        let s = summary_with_cursors(0, 20, 0);
        assert!(!s.should_update_decisions(24, Importance::Normal));
    }

    #[test]
    fn should_update_decisions_notable_does_not_override() {
        // §1.3.3 line 165 says "or critical turn" — Notable is NOT enough
        // for the decisions tier (only Critical overrides).
        let s = summary_with_cursors(0, 20, 0);
        assert!(!s.should_update_decisions(21, Importance::Notable));
    }

    #[test]
    fn should_update_decisions_fires_on_critical_below_threshold() {
        let s = summary_with_cursors(0, 20, 0);
        assert!(s.should_update_decisions(21, Importance::Critical));
    }

    #[test]
    fn should_update_decisions_saturating_sub_against_malformed_cursor() {
        let s = summary_with_cursors(0, 1000, 0);
        assert!(!s.should_update_decisions(5, Importance::Normal));
        assert!(s.should_update_decisions(5, Importance::Critical));
    }

    // ── should_update_state ──

    #[test]
    fn should_update_state_fires_at_exactly_10_turns_normal() {
        let s = summary_with_cursors(0, 0, 30);
        assert!(s.should_update_state(40, Importance::Normal, false));
    }

    #[test]
    fn should_update_state_no_fire_at_9_turn_delta_normal() {
        let s = summary_with_cursors(0, 0, 30);
        assert!(!s.should_update_state(39, Importance::Normal, false));
    }

    #[test]
    fn should_update_state_notable_does_not_override() {
        // §1.3.3 line 166: "or direction change" — Notable is NOT enough.
        let s = summary_with_cursors(0, 0, 30);
        assert!(!s.should_update_state(31, Importance::Notable, false));
    }

    #[test]
    fn should_update_state_fires_on_critical_below_threshold() {
        let s = summary_with_cursors(0, 0, 30);
        assert!(s.should_update_state(31, Importance::Critical, false));
    }

    #[test]
    fn should_update_state_fires_on_direction_changed_below_threshold() {
        // direction_changed: bool is a separate axis from Importance — fires
        // even when importance is Normal.
        let s = summary_with_cursors(0, 0, 30);
        assert!(s.should_update_state(31, Importance::Normal, true));
    }

    #[test]
    fn should_update_state_saturating_sub_against_malformed_cursor() {
        let s = summary_with_cursors(0, 0, 1000);
        assert!(!s.should_update_state(5, Importance::Normal, false));
        assert!(s.should_update_state(5, Importance::Normal, true));
        assert!(s.should_update_state(5, Importance::Critical, false));
    }

    #[test]
    fn should_update_critical_fires_all_three_cursors_simultaneously() {
        // Critical importance fires brief AND decisions AND state on the same
        // turn — Critical universally dominates per natural ordering. delta
        // = 30 - 0 = 30 (> all thresholds) but the assertion holds even at
        // smaller deltas because Critical overrides every cursor.
        let s = summary_with_cursors(0, 0, 0);
        let turn = 1; // smaller than every cadence threshold
        assert!(s.should_update_brief(turn, Importance::Critical));
        assert!(s.should_update_decisions(turn, Importance::Critical));
        assert!(s.should_update_state(turn, Importance::Critical, false));
    }
}
