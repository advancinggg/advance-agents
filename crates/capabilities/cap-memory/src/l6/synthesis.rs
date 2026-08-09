//! L6 Step 3b — synthesis generation + the 5-gate check (AC-33). MODULE-011
//! §1.3.6 step 4. Internal cap-memory seam; production wires MODULE-009, Slice
//! C ships `StubSynthesisGenerator`. §2.10 `max_syntheses=3` per L6 run is
//! enforced by the runnable.

use crate::knowledge::{MemoryEntry, MemorySource, MemoryStatus};

use super::classifier::ClusterClassification;

/// §2.10 `memory.l6.max_syntheses`.
pub const MAX_SYNTHESES: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynthesisGate {
    EntriesCount,
    Consistent,
    HasFileRef,
    NoContested,
    NoOrphaned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SynthesisGateResult {
    Pass,
    Fail {
        gate: SynthesisGate,
        reason: &'static str,
    },
}

/// AC-33 5-gate check (ALL must pass), evaluated in the §1.3.6 PRD order:
/// (a) entries ≥ 3, (b) classification = consistent, (c) ≥ 1 entry with a
/// file-ref source, (d) NO contested entries, (e) NO orphaned entries.
pub fn should_synthesize(
    cluster: &[MemoryEntry],
    classification: ClusterClassification,
) -> SynthesisGateResult {
    if cluster.len() < 3 {
        return SynthesisGateResult::Fail {
            gate: SynthesisGate::EntriesCount,
            reason: "cluster must have >= 3 entries",
        };
    }
    if classification != ClusterClassification::Consistent {
        return SynthesisGateResult::Fail {
            gate: SynthesisGate::Consistent,
            reason: "Step 3a classification must be consistent",
        };
    }
    let has_file_ref = cluster.iter().any(|e| {
        e.sources
            .iter()
            .any(|s| matches!(s, MemorySource::FileRef { .. }))
    });
    if !has_file_ref {
        return SynthesisGateResult::Fail {
            gate: SynthesisGate::HasFileRef,
            reason: "cluster must contain >= 1 entry with a file-ref source",
        };
    }
    if cluster.iter().any(|e| e.status == MemoryStatus::Contested) {
        return SynthesisGateResult::Fail {
            gate: SynthesisGate::NoContested,
            reason: "cluster must contain NO contested entries",
        };
    }
    if cluster.iter().any(|e| e.status == MemoryStatus::Orphaned) {
        return SynthesisGateResult::Fail {
            gate: SynthesisGate::NoOrphaned,
            reason: "cluster must contain NO orphaned entries",
        };
    }
    SynthesisGateResult::Pass
}

#[derive(Clone, Debug)]
pub struct SynthesisInput {
    pub cluster_id: String,
    pub topic_slug: String,
    pub entries: Vec<MemoryEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synthesis {
    pub path: String,
    pub content: String,
}

pub trait SynthesisGenerator: Send + Sync {
    fn generate(&self, input: &SynthesisInput) -> Synthesis;
}

#[derive(Clone, Debug, Default)]
pub struct StubSynthesisGenerator;

impl SynthesisGenerator for StubSynthesisGenerator {
    fn generate(&self, input: &SynthesisInput) -> Synthesis {
        Synthesis {
            path: format!("syntheses/{}.md", input.topic_slug),
            content: format!(
                "# {}\n\n{} entries consolidated (cluster {}).\n",
                input.topic_slug,
                input.entries.len(),
                input.cluster_id
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryStatus, MemoryType};

    fn entry(id: &str, status: MemoryStatus, file_ref: bool) -> MemoryEntry {
        let sources = if file_ref {
            vec![MemorySource::FileRef {
                agent_id: "a".into(),
                vpath: "p".into(),
                commit_ish: "c".into(),
                blob_id: "b".into(),
                line_range: None,
            }]
        } else {
            vec![MemorySource::TaskTurn {
                task_id: "t".into(),
                turn: 1,
            }]
        };
        MemoryEntry {
            id: id.into(),
            agent_id: "a".into(),
            entry_type: MemoryType::Fact,
            content: "x".into(),
            tags: vec![],
            created_at: "1970-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active: !matches!(status, MemoryStatus::Superseded | MemoryStatus::Forgotten),
            superseded_by: None,
            status,
            supersession_reason: None,
            cluster_id: None,
            sources,
        }
    }

    fn three_valid() -> Vec<MemoryEntry> {
        vec![
            entry("a", MemoryStatus::Active, true),
            entry("b", MemoryStatus::Active, false),
            entry("c", MemoryStatus::Active, false),
        ]
    }

    #[test]
    fn positive_all_five_gates_pass() {
        assert_eq!(
            should_synthesize(&three_valid(), ClusterClassification::Consistent),
            SynthesisGateResult::Pass
        );
    }

    #[test]
    fn gate_a_entries_count() {
        let two = vec![
            entry("a", MemoryStatus::Active, true),
            entry("b", MemoryStatus::Active, true),
        ];
        assert!(matches!(
            should_synthesize(&two, ClusterClassification::Consistent),
            SynthesisGateResult::Fail {
                gate: SynthesisGate::EntriesCount,
                ..
            }
        ));
    }

    #[test]
    fn gate_b_consistent() {
        assert!(matches!(
            should_synthesize(&three_valid(), ClusterClassification::Contested),
            SynthesisGateResult::Fail {
                gate: SynthesisGate::Consistent,
                ..
            }
        ));
    }

    #[test]
    fn gate_c_has_file_ref() {
        let no_fr = vec![
            entry("a", MemoryStatus::Active, false),
            entry("b", MemoryStatus::Active, false),
            entry("c", MemoryStatus::Active, false),
        ];
        assert!(matches!(
            should_synthesize(&no_fr, ClusterClassification::Consistent),
            SynthesisGateResult::Fail {
                gate: SynthesisGate::HasFileRef,
                ..
            }
        ));
    }

    #[test]
    fn gate_d_no_contested() {
        let mut v = three_valid();
        v[1].status = MemoryStatus::Contested;
        assert!(matches!(
            should_synthesize(&v, ClusterClassification::Consistent),
            SynthesisGateResult::Fail {
                gate: SynthesisGate::NoContested,
                ..
            }
        ));
    }

    #[test]
    fn gate_e_no_orphaned() {
        let mut v = three_valid();
        v[2].status = MemoryStatus::Orphaned;
        assert!(matches!(
            should_synthesize(&v, ClusterClassification::Consistent),
            SynthesisGateResult::Fail {
                gate: SynthesisGate::NoOrphaned,
                ..
            }
        ));
    }

    #[test]
    fn stub_generates_path_from_slug() {
        let g = StubSynthesisGenerator;
        let s = g.generate(&SynthesisInput {
            cluster_id: "cl-pricing-b0c1d2e3".into(),
            topic_slug: "pricing".into(),
            entries: three_valid(),
        });
        assert_eq!(s.path, "syntheses/pricing.md");
        assert!(s.content.contains("cl-pricing-b0c1d2e3"));
    }
}
