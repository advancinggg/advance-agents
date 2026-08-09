//! `_knowledge_map.yaml` in-memory model + 500-token budget (AC-16).
//! MODULE-011 §1.3.4 / §1.2. Slice C holds this in-memory (on-disk yaml
//! deferred — `waived_scope`); serde round-trips for AC-16 shape verification.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Tier-1b injection budget (§1.2 "500-token budget").
pub const TOKEN_BUDGET: u32 = 500;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeMapTopic {
    pub topic_slug: String,
    pub synthesis_path: String,
    pub cluster_id: String,
    pub tokens: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeMapTaskSynthesis {
    pub task_id: String,
    pub synthesis_path: String,
    pub tokens: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeMap {
    #[serde(default)]
    pub topics: Vec<KnowledgeMapTopic>,
    #[serde(default)]
    pub task_syntheses: Vec<KnowledgeMapTaskSynthesis>,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum KnowledgeMapError {
    #[error("knowledge_map token budget exceeded: {current} + {add} > {budget}")]
    BudgetExceeded { current: u32, add: u32, budget: u32 },
}

impl KnowledgeMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn total_tokens(&self) -> u32 {
        let t: u32 = self
            .topics
            .iter()
            .map(|x| x.tokens)
            .fold(0u32, |a, b| a.saturating_add(b));
        let s: u32 = self
            .task_syntheses
            .iter()
            .map(|x| x.tokens)
            .fold(0u32, |a, b| a.saturating_add(b));
        t.saturating_add(s)
    }

    pub fn token_budget_exceeded(&self) -> bool {
        self.total_tokens() > TOKEN_BUDGET
    }

    /// Add a topic, rejecting if it would push the cumulative budget over
    /// `TOKEN_BUDGET`.
    pub fn add_topic(&mut self, topic: KnowledgeMapTopic) -> Result<(), KnowledgeMapError> {
        let current = self.total_tokens();
        if current.saturating_add(topic.tokens) > TOKEN_BUDGET {
            return Err(KnowledgeMapError::BudgetExceeded {
                current,
                add: topic.tokens,
                budget: TOKEN_BUDGET,
            });
        }
        self.topics.push(topic);
        Ok(())
    }

    pub fn add_task_synthesis(
        &mut self,
        t: KnowledgeMapTaskSynthesis,
    ) -> Result<(), KnowledgeMapError> {
        let current = self.total_tokens();
        if current.saturating_add(t.tokens) > TOKEN_BUDGET {
            return Err(KnowledgeMapError::BudgetExceeded {
                current,
                add: t.tokens,
                budget: TOKEN_BUDGET,
            });
        }
        self.task_syntheses.push(t);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.topics.is_empty() && self.task_syntheses.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic(slug: &str, tokens: u32) -> KnowledgeMapTopic {
        KnowledgeMapTopic {
            topic_slug: slug.into(),
            synthesis_path: format!("syntheses/{slug}.md"),
            cluster_id: format!("cl-{slug}-b0c1d2e3"),
            tokens,
        }
    }

    #[test]
    fn yaml_roundtrip_preserves_shape() {
        let mut km = KnowledgeMap::new();
        km.add_topic(topic("pricing", 100)).unwrap();
        km.add_task_synthesis(KnowledgeMapTaskSynthesis {
            task_id: "task-1".into(),
            synthesis_path: "syntheses/task-1.md".into(),
            tokens: 50,
        })
        .unwrap();
        let yaml = serde_yml::to_string(&km).expect("serialize");
        assert!(yaml.contains("topics:"));
        assert!(yaml.contains("task_syntheses:"));
        let back: KnowledgeMap = serde_yml::from_str(&yaml).expect("deserialize");
        assert_eq!(km, back);
    }

    #[test]
    fn total_tokens_and_budget_gate() {
        let mut km = KnowledgeMap::new();
        km.add_topic(topic("a", 300)).unwrap();
        assert_eq!(km.total_tokens(), 300);
        assert!(!km.token_budget_exceeded());
        km.add_topic(topic("b", 200)).unwrap(); // 500 exactly — OK
        assert_eq!(km.total_tokens(), 500);
        assert!(!km.token_budget_exceeded(), "500 == budget, not > budget");
        let err = km.add_topic(topic("c", 1)).unwrap_err();
        assert!(matches!(err, KnowledgeMapError::BudgetExceeded { .. }));
        // The rejected topic must NOT have been pushed.
        assert_eq!(km.topics.len(), 2);
        assert_eq!(km.total_tokens(), 500);
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_key() {
        let bad = r#"{"topics":[],"task_syntheses":[],"smuggled":1}"#;
        let r: Result<KnowledgeMap, _> = serde_json::from_str(bad);
        assert!(r.is_err());
    }
}
