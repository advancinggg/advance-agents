//! Data-port pre-build (2026-06-08) — dep-light REAL `KnowledgeMapReader`.
//!
//! [`ProjectingKnowledgeMap`] is a production (non-stub) implementation of the
//! existing crate-local [`crate::ports::KnowledgeMapReader`] port: it projects
//! caller-supplied per-agent [`KnowledgeRecord`]s into the
//! [`crate::ports::KnowledgeMap`] carrier (`topics` + `task_syntheses`). It is
//! dep-light — no `advance-cap-memory` dep — and operates over data the caller
//! loads in; B1's downstream adapter reads cap-memory's knowledge/synthesis
//! source and fills [`KnowledgeRecord`]s, replacing the `cli` `StubKnowledgeMap`
//! (which returned `None`).
//!
//! **Reader-returns-raw / render-sanitizes split:** the reader returns the RAW
//! projected map. The §1.4.3⑨/§2.11 caps (≤ 500 tokens / ≤ 10 topics / ≤ 5
//! syntheses) AND the Trojan-Source sanitization of the untrusted
//! (agent-authored) topic/synthesis bodies stay owned by the render path
//! [`crate::knowledge_map::build_knowledge_map_section`] — the existing
//! reader/render division of labour (cf. `crate::tier1::build_tier1b`).

use std::collections::HashMap;

use async_trait::async_trait;

use crate::ports::{KnowledgeMap, KnowledgeMapReader, KnowledgeTopic, TaskSynthesis};

/// One caller-supplied knowledge record, projected into the [`KnowledgeMap`]
/// carrier by [`ProjectingKnowledgeMap`]. `body` is untrusted (agent-authored)
/// — sanitized at render time, not here.
#[derive(Clone, Debug, PartialEq)]
pub enum KnowledgeRecord {
    /// A knowledge-map topic (→ [`KnowledgeTopic`]).
    Topic { name: String, body: String },
    /// A per-task synthesis (→ [`TaskSynthesis`]).
    Synthesis { task_id: String, body: String },
}

/// Real `KnowledgeMapReader` over caller-supplied records keyed by `agent_id`.
pub struct ProjectingKnowledgeMap {
    records: HashMap<String, Vec<KnowledgeRecord>>,
}

impl ProjectingKnowledgeMap {
    pub fn new(records: HashMap<String, Vec<KnowledgeRecord>>) -> Self {
        Self { records }
    }
}

#[async_trait]
impl KnowledgeMapReader for ProjectingKnowledgeMap {
    /// Project the agent's records into a [`KnowledgeMap`]. An unknown agent OR
    /// an agent with zero records → `None` ("no knowledge map"), matching the
    /// stub's `None` contract; the render path also treats an empty map as an
    /// omitted section. Variant order is preserved within each kind.
    async fn read_knowledge_map(&self, agent_id: &str) -> Option<KnowledgeMap> {
        let records = self.records.get(agent_id)?;
        if records.is_empty() {
            return None;
        }
        let mut topics = Vec::new();
        let mut task_syntheses = Vec::new();
        for record in records {
            match record {
                KnowledgeRecord::Topic { name, body } => topics.push(KnowledgeTopic {
                    name: name.clone(),
                    body: body.clone(),
                }),
                KnowledgeRecord::Synthesis { task_id, body } => {
                    task_syntheses.push(TaskSynthesis {
                        task_id: task_id.clone(),
                        body: body.clone(),
                    })
                }
            }
        }
        Some(KnowledgeMap {
            topics,
            task_syntheses,
        })
    }
}
