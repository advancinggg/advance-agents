//! L6 Step 3a — batch LLM classification. MODULE-011 §1.3.6 step 3. Internal
//! cap-memory seam. **Production wires MODULE-009 CONTRACT-081 light LLM via the
//! cli `LlmL6Classifier` (slice wave6-laneB); `StubL6Classifier` is the test
//! stub.** §2.10 caps (`max_stale_entries=20`, `max_clusters=10`,
//! `max_task_extracts=5`) are clamped by the runnable before calling `classify`.

use std::collections::HashMap;

use advance_shared_types::memory::L6Error;
use async_trait::async_trait;

use crate::knowledge::MemoryEntry;

use super::cluster::ClusterAssignment;

/// §2.10 bounds.
pub const MAX_STALE_ENTRIES: usize = 20;
pub const MAX_CLUSTERS: usize = 10;
pub const MAX_TASK_EXTRACTS: usize = 5;

/// Minimal completed-task reference. Slice C does NOT wire real
/// task-completion detection (MODULE-008/MODULE-005) — `waived_scope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskRef {
    pub task_id: String,
    pub turns: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterClassification {
    Consistent,
    Contested,
}

#[derive(Clone, Debug)]
pub struct L6ClassificationInput {
    pub agent_id: String,
    pub batch_id: String,
    pub stale_candidates: Vec<MemoryEntry>,
    pub clusters: Vec<(ClusterAssignment, Vec<MemoryEntry>)>,
    pub completed_tasks: Vec<TaskRef>,
}

#[derive(Clone, Debug)]
pub struct SkillHealthEntry {
    pub skill: String,
    pub status: String, // healthy | stale | unhealthy
}

#[derive(Clone, Debug)]
pub struct TaskSummary {
    pub task_id: String,
    pub summary: String,
}

#[derive(Clone, Debug)]
pub struct L6ClassificationOutput {
    /// cluster_id → consistent|contested.
    pub cluster_decisions: HashMap<String, ClusterClassification>,
    /// consolidated_preference contents (the runnable appends each as a
    /// `type=user-preference` entry tagged `l6_batch:{batch_id}`).
    pub consolidated_preferences: Vec<String>,
    pub task_summaries: Vec<TaskSummary>,
    /// (slice wave6-laneB) The L6 producer promotes each `stale`/`unhealthy` entry
    /// here into a skill candidate at Step-5a and emits `skill.candidate_generated`
    /// at Step-5c. (Only the separate `_skill_health.yaml` flush stays deferred.)
    pub skill_health: Vec<SkillHealthEntry>,
    pub batch_id: String,
}

/// Production wires the MODULE-009 CONTRACT-081 light LLM via the cli composition
/// root's `LlmL6Classifier`. The seam is **async + fallible** (slice wave6-laneB):
/// `classify` must be able to `.await` the gateway AND surface a transport/malformed
/// LLM failure as `L6Error::LlmFailure` — that fallibility is what makes SYS-AC-216
/// ("the L6 batch LLM call fails → component.error, lease cleared, no commit/event")
/// reachable. Called from inside the already-async `L6Runnable::handle` at Step 3,
/// so no sync→async bridge is needed (unlike `GitQueueL6Committer`).
#[async_trait]
pub trait L6Classifier: Send + Sync {
    async fn classify(
        &self,
        input: &L6ClassificationInput,
    ) -> Result<L6ClassificationOutput, L6Error>;
}

/// Deterministic test stub. Default: every cluster `Consistent`, no
/// consolidated_preferences. Builder methods configure contested clusters and
/// consolidated_preferences. Echoes `input.batch_id` into `output.batch_id`.
#[derive(Clone, Debug, Default)]
pub struct StubL6Classifier {
    contested: Vec<String>,
    consolidated_preferences: Vec<String>,
    skill_health: Vec<(String, String)>,
}

impl StubL6Classifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_contested(mut self, cluster_id: &str) -> Self {
        self.contested.push(cluster_id.to_string());
        self
    }

    pub fn with_consolidated_preference(mut self, content: &str) -> Self {
        self.consolidated_preferences.push(content.to_string());
        self
    }

    pub fn with_skill_health(mut self, skill: &str, status: &str) -> Self {
        self.skill_health
            .push((skill.to_string(), status.to_string()));
        self
    }
}

#[async_trait]
impl L6Classifier for StubL6Classifier {
    async fn classify(
        &self,
        input: &L6ClassificationInput,
    ) -> Result<L6ClassificationOutput, L6Error> {
        let mut cluster_decisions = HashMap::new();
        for (assignment, _) in &input.clusters {
            let cls = if self.contested.contains(&assignment.cluster_id) {
                ClusterClassification::Contested
            } else {
                ClusterClassification::Consistent
            };
            cluster_decisions.insert(assignment.cluster_id.clone(), cls);
        }
        // The deterministic stub never fails (no LLM dialed). Production failure
        // semantics live in the cli `LlmL6Classifier`.
        Ok(L6ClassificationOutput {
            cluster_decisions,
            consolidated_preferences: self.consolidated_preferences.clone(),
            task_summaries: input
                .completed_tasks
                .iter()
                .map(|t| TaskSummary {
                    task_id: t.task_id.clone(),
                    summary: format!("summary of {} ({} turns)", t.task_id, t.turns),
                })
                .collect(),
            skill_health: self
                .skill_health
                .iter()
                .map(|(s, st)| SkillHealthEntry {
                    skill: s.clone(),
                    status: st.clone(),
                })
                .collect(),
            batch_id: input.batch_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(batch: &str, clusters: Vec<&str>) -> L6ClassificationInput {
        L6ClassificationInput {
            agent_id: "a".into(),
            batch_id: batch.into(),
            stale_candidates: vec![],
            clusters: clusters
                .into_iter()
                .map(|cid| {
                    (
                        ClusterAssignment {
                            cluster_id: cid.into(),
                            entry_ids: vec![],
                        },
                        vec![],
                    )
                })
                .collect(),
            completed_tasks: vec![TaskRef {
                task_id: "task-1".into(),
                turns: 12,
            }],
        }
    }

    #[tokio::test]
    async fn default_all_consistent_echoes_batch_id() {
        let c = StubL6Classifier::new();
        let out = c
            .classify(&input("b0c1d2e3", vec!["cl-a-b0c1d2e3", "cl-b-b0c1d2e3"]))
            .await
            .expect("stub never fails");
        assert_eq!(out.batch_id, "b0c1d2e3");
        assert_eq!(
            out.cluster_decisions["cl-a-b0c1d2e3"],
            ClusterClassification::Consistent
        );
        assert_eq!(
            out.cluster_decisions["cl-b-b0c1d2e3"],
            ClusterClassification::Consistent
        );
        assert!(out.consolidated_preferences.is_empty());
        assert_eq!(out.task_summaries.len(), 1);
    }

    #[tokio::test]
    async fn contested_and_consolidated_pref_configured() {
        let c = StubL6Classifier::new()
            .with_contested("cl-a-b0c1d2e3")
            .with_consolidated_preference("prefer-concise");
        let out = c
            .classify(&input("b0c1d2e3", vec!["cl-a-b0c1d2e3", "cl-b-b0c1d2e3"]))
            .await
            .expect("stub never fails");
        assert_eq!(
            out.cluster_decisions["cl-a-b0c1d2e3"],
            ClusterClassification::Contested
        );
        assert_eq!(
            out.cluster_decisions["cl-b-b0c1d2e3"],
            ClusterClassification::Consistent
        );
        assert_eq!(out.consolidated_preferences, vec!["prefer-concise"]);
    }
}
