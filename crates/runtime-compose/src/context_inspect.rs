//! Context inspection — the per-agent latest [`AssemblyReport`] store the
//! assembler feeds on every turn, and the Client API adapter that projects it
//! to `GET /client/agents/{agent_id}/context`.
//!
//! The assembler reports under the id it assembled for (the colon routing id,
//! `agent:root`); a client names the bare handle (`root`). The store keeps
//! alias GROUPS (`{bare, colon}` per agent) so either id resolves to the same
//! record. Only labels + sizes are stored — never the prompt text.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_client_api::{
    ClientContextAssembly, ClientContextEmbedding, ClientContextHistory, ClientContextIndex,
    ClientContextRecall, ClientContextRouting, ClientContextSection, ClientContextSnapshot,
    ClientContextTierTokens, ContextInspectProvider, ProviderError, CONTEXT_TOKEN_ESTIMATE,
};
use advance_context_engine::{AssemblyReport, AssemblyReportSink};

/// One recorded assembly.
#[derive(Clone, Debug)]
pub struct ContextSnapshot {
    pub report: AssemblyReport,
    pub assembled_at: SystemTime,
    /// Per-agent monotonic counter (1 for the first assembled turn).
    pub sequence: u64,
}

/// The embedding posture the daemon resolved at spawn.
#[derive(Clone, Debug, Default)]
pub struct EmbeddingPosture {
    pub active: bool,
    pub model: Option<String>,
}

/// Latest-report-per-agent store. Sync, lock-copy-release; never does I/O.
#[derive(Default)]
pub struct ContextSnapshotStore {
    latest: Mutex<HashMap<String, ContextSnapshot>>,
    /// Alias groups: every id in a group names the same agent.
    aliases: Mutex<Vec<Vec<String>>>,
}

impl ContextSnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare that every id in `group` names one agent (`{bare, colon}`).
    pub fn register_aliases(&self, group: &[String]) {
        let mut guard = self.aliases.lock().unwrap_or_else(|p| p.into_inner());
        let group: Vec<String> = group.iter().filter(|s| !s.is_empty()).cloned().collect();
        if !group.is_empty() && !guard.iter().any(|g| g == &group) {
            guard.push(group);
        }
    }

    /// Every id that names the same agent as `agent_id` (itself included).
    fn ids_for(&self, agent_id: &str) -> Vec<String> {
        let guard = self.aliases.lock().unwrap_or_else(|p| p.into_inner());
        let mut ids = vec![agent_id.to_string()];
        for group in guard.iter() {
            if group.iter().any(|g| g == agent_id) {
                for g in group {
                    if g != agent_id {
                        ids.push(g.clone());
                    }
                }
            }
        }
        ids
    }

    /// `true` when `agent_id` is a registered alias (a known agent, assembled or not).
    pub fn knows(&self, agent_id: &str) -> bool {
        let guard = self.aliases.lock().unwrap_or_else(|p| p.into_inner());
        guard.iter().any(|g| g.iter().any(|a| a == agent_id))
    }

    /// The latest snapshot for `agent_id` (or any of its aliases).
    pub fn snapshot(&self, agent_id: &str) -> Option<ContextSnapshot> {
        let guard = self.latest.lock().unwrap_or_else(|p| p.into_inner());
        self.ids_for(agent_id)
            .iter()
            .filter_map(|id| guard.get(id))
            .max_by_key(|s| s.sequence)
            .cloned()
    }
}

impl AssemblyReportSink for ContextSnapshotStore {
    fn record(&self, report: AssemblyReport) {
        let mut guard = self.latest.lock().unwrap_or_else(|p| p.into_inner());
        let sequence = guard
            .get(&report.agent_id)
            .map(|s| s.sequence.saturating_add(1))
            .unwrap_or(1);
        guard.insert(
            report.agent_id.clone(),
            ContextSnapshot {
                report,
                assembled_at: SystemTime::now(),
                sequence,
            },
        );
    }
}

/// The Client API `ContextInspectProvider` over one [`ContextSnapshotStore`] +
/// the agent's embedding posture + (optionally) its cap-memory SQLite index for
/// the row counts.
pub struct ContextInspectAdapter {
    store: Arc<ContextSnapshotStore>,
    embedding: EmbeddingPosture,
    index: Option<Arc<dyn cap_memory::SqliteIndex + Send + Sync>>,
    /// The bare id the index rows are written under.
    write_agent_id: String,
}

impl ContextInspectAdapter {
    pub fn new(
        store: Arc<ContextSnapshotStore>,
        embedding: EmbeddingPosture,
        index: Option<Arc<dyn cap_memory::SqliteIndex + Send + Sync>>,
        write_agent_id: &str,
    ) -> Self {
        Self {
            store,
            embedding,
            index,
            write_agent_id: write_agent_id.to_string(),
        }
    }
}

fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn clamp_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Project a recorded snapshot onto the wire DTO.
pub fn project_assembly(snapshot: &ContextSnapshot) -> ClientContextAssembly {
    let r = &snapshot.report;
    let used_ratio = if r.budget_tokens == 0 {
        1.0
    } else {
        (r.used_tokens as f32 / r.budget_tokens as f32).clamp(0.0, 1.0)
    };
    ClientContextAssembly {
        assembled_at: rfc3339(snapshot.assembled_at),
        sequence: snapshot.sequence,
        message_id: r.message_id.clone(),
        trace_id: r.trace_id.clone(),
        task_id: r.task_id.clone(),
        model: r.model.clone(),
        model_context_window: r.model_context_window,
        response_reserve: r.response_reserve,
        budget_tokens: r.budget_tokens,
        used_tokens: r.used_tokens,
        remaining_tokens: r.remaining_tokens,
        used_ratio,
        progressive_mode: r.progressive_mode.clone(),
        degraded: r.degraded,
        tiers: ClientContextTierTokens {
            tier1a: r.tier1a_tokens,
            tier1b: r.tier1b_tokens,
            tier2: r.tier2_tokens,
            tier3: r.tier3_tokens,
        },
        sections: r
            .sections
            .iter()
            .map(|s| ClientContextSection {
                tier: s.tier.clone(),
                label: s.label.clone(),
                role: s.role.clone(),
                tokens: s.tokens,
                bytes: s.bytes,
            })
            .collect(),
        routing: ClientContextRouting {
            method: r.routing_method.clone(),
            confidence: r.routing_confidence,
            is_new_task: r.is_new_task,
        },
        recall: ClientContextRecall {
            attempted: r.recall.attempted,
            tasks: r.recall.tasks,
            turns: r.recall.turns,
            contents: r.recall.contents,
            memories: r.recall.memories,
        },
        history: ClientContextHistory {
            turn_buffer_in: r.history.turn_buffer_in,
            turn_buffer_kept: r.history.turn_buffer_kept,
            l0_compressed: r.history.l0_compressed,
            l2_digests: r.history.l2_digests,
            l3_epoch: r.history.l3_epoch,
            l4_task_summary: r.history.l4_task_summary,
            l5_related_briefs: r.history.l5_related_briefs,
        },
        prompt_bytes: r.prompt_bytes,
        warnings: r.warnings,
    }
}

impl ContextInspectProvider for ContextInspectAdapter {
    fn snapshot(&self, agent_id: &str) -> Result<ClientContextSnapshot, ProviderError> {
        if !self.store.knows(agent_id) {
            return Err(ProviderError::NotFound(format!("unknown agent {agent_id}")));
        }
        let latest = self.store.snapshot(agent_id).map(|s| project_assembly(&s));
        let (turns, tasks) = match &self.index {
            Some(idx) => (
                clamp_u32(idx.list_turns_for_agent(&self.write_agent_id).len()),
                clamp_u32(idx.list_tasks_for_agent(&self.write_agent_id).len()),
            ),
            None => (0, 0),
        };
        Ok(ClientContextSnapshot {
            agent_id: agent_id.to_string(),
            estimate: CONTEXT_TOKEN_ESTIMATE.to_string(),
            latest,
            embedding: ClientContextEmbedding {
                active: self.embedding.active,
                model: self.embedding.model.clone(),
            },
            index: ClientContextIndex { turns, tasks },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_context_engine::{AssemblyHistoryReport, AssemblyRecallReport, AssemblySection};

    fn report(agent: &str, used: u32) -> AssemblyReport {
        AssemblyReport {
            agent_id: agent.into(),
            task_id: None,
            message_id: "m-1".into(),
            trace_id: Some("t-1".into()),
            model: "gpt-4o".into(),
            model_context_window: 128_000,
            response_reserve: 19_200,
            budget_tokens: 108_800,
            used_tokens: used,
            remaining_tokens: 108_800 - used,
            progressive_mode: "wide".into(),
            degraded: false,
            tier1a_tokens: used / 2,
            tier1b_tokens: 0,
            tier2_tokens: used / 4,
            tier3_tokens: used - used / 2 - used / 4,
            sections: vec![AssemblySection {
                tier: "1a".into(),
                label: "Agent Identity".into(),
                role: "system".into(),
                tokens: used / 2,
                bytes: used * 2,
            }],
            routing_method: "search".into(),
            routing_confidence: 0.0,
            is_new_task: true,
            recall: AssemblyRecallReport::default(),
            history: AssemblyHistoryReport::default(),
            prompt_bytes: 12,
            warnings: 0,
        }
    }

    #[test]
    fn colon_report_resolves_under_bare_alias_with_sequence() {
        let store = Arc::new(ContextSnapshotStore::new());
        store.register_aliases(&["root".to_string(), "agent:root".to_string()]);
        store.record(report("agent:root", 100));
        store.record(report("agent:root", 200));
        let snap = store.snapshot("root").expect("bare alias resolves");
        assert_eq!(snap.sequence, 2);
        assert_eq!(snap.report.used_tokens, 200);
        assert!(store.snapshot("other").is_none());

        let adapter = ContextInspectAdapter::new(
            store.clone(),
            EmbeddingPosture {
                active: true,
                model: Some("text-embedding-3-small".into()),
            },
            None,
            "root",
        );
        let dto = adapter.snapshot("root").unwrap();
        let latest = dto.latest.expect("assembled");
        assert_eq!(latest.sequence, 2);
        assert_eq!(latest.tiers.tier1a, 100);
        assert!((latest.used_ratio - 200.0 / 108_800.0).abs() < 1e-6);
        assert_eq!(latest.sections[0].label, "Agent Identity");
        assert!(dto.embedding.active);
        assert_eq!(dto.estimate, CONTEXT_TOKEN_ESTIMATE);
        assert!(matches!(
            adapter.snapshot("nobody"),
            Err(ProviderError::NotFound(_))
        ));
    }

    #[test]
    fn known_agent_without_assembly_has_no_latest() {
        let store = Arc::new(ContextSnapshotStore::new());
        store.register_aliases(&["root".to_string(), "agent:root".to_string()]);
        let adapter = ContextInspectAdapter::new(store, EmbeddingPosture::default(), None, "root");
        let dto = adapter.snapshot("agent:root").unwrap();
        assert!(dto.latest.is_none());
        assert!(!dto.embedding.active);
    }
}
