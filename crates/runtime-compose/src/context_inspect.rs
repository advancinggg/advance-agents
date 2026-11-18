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

/// One agent's embedding posture: whether its chat provider serves embeddings
/// right now, and with which model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmbeddingPosture {
    pub active: bool,
    pub model: Option<String>,
}

/// Answers an agent's [`EmbeddingPosture`] by its BARE cap id at the moment it
/// is asked. Embedding follows each agent's own chat provider, so the posture is
/// per agent and changes with the provider config / the agent's `llm:` policy —
/// never a value frozen at daemon start.
pub type EmbeddingPostureSource = Arc<dyn Fn(&str) -> EmbeddingPosture + Send + Sync>;

/// The live posture over the gateway's per-agent embedding route.
pub fn gateway_embedding_posture(gateway: Arc<cap_llm::LlmGateway>) -> EmbeddingPostureSource {
    Arc::new(
        move |agent_id| match gateway.embedding_route_for(agent_id) {
            Ok(route) => EmbeddingPosture {
                active: true,
                model: Some(route.model),
            },
            Err(_) => EmbeddingPosture::default(),
        },
    )
}

/// A posture that never changes (no LLM gateway, and tests).
pub fn fixed_embedding_posture(posture: EmbeddingPosture) -> EmbeddingPostureSource {
    Arc::new(move |_| posture.clone())
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

    /// The agent `bare_id` is gone: drop the report recorded under it and under each of
    /// `colon_ids` (the colon ids it held), and every alias group it is in, so it is
    /// not a known agent any more and an agent created later under one of its ids does
    /// not answer with its report.
    ///
    /// A group with `bare_id` in it is one this agent registered: a bare id is never a
    /// colon id (`agent:` is not a bare id). No other report is dropped — not that of
    /// another id such a group ties `bare_id` to.
    pub fn forget(&self, bare_id: &str, colon_ids: &[&str]) {
        let mut ids = vec![bare_id];
        ids.extend_from_slice(colon_ids);
        self.forget_reports(&ids);
        let mut guard = self.aliases.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|group| !group.iter().any(|alias| alias == bare_id));
    }

    /// Drop the report recorded under each of `ids`, and keep the ids known.
    pub fn forget_reports(&self, ids: &[&str]) {
        let mut guard = self.latest.lock().unwrap_or_else(|p| p.into_inner());
        for id in ids {
            guard.remove(*id);
        }
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
    /// Asked with the inspected agent's bare id on every snapshot.
    embedding: EmbeddingPostureSource,
    index: Option<Arc<dyn cap_memory::SqliteIndex + Send + Sync>>,
    /// The root's bare id (fallback when an alias group has no colon-free id).
    write_agent_id: String,
}

impl ContextInspectAdapter {
    pub fn new(
        store: Arc<ContextSnapshotStore>,
        embedding: EmbeddingPostureSource,
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

    /// Prefer the colon-free alias (the cap-memory write bucket) for `agent_id`.
    fn write_id_for(&self, agent_id: &str) -> String {
        let resolved = self
            .store
            .ids_for(agent_id)
            .into_iter()
            .find(|id| !id.contains(':'))
            .unwrap_or_else(|| {
                agent_id
                    .strip_prefix("agent:")
                    .unwrap_or(agent_id)
                    .to_string()
            });
        if resolved.is_empty() {
            self.write_agent_id.clone()
        } else {
            resolved
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
        let write_id = self.write_id_for(agent_id);
        // Counted, not read: an agent's whole history, vectors and all, is not loaded at
        // every look.
        let (turns, tasks) = match &self.index {
            Some(idx) => (
                clamp_u32(idx.count_turns_for_agent(&write_id)),
                clamp_u32(idx.count_tasks_for_agent(&write_id)),
            ),
            None => (0, 0),
        };
        // The posture of THIS agent, now: its bare id is what its `llm:` policy
        // (and so its chat provider, which embedding follows) is keyed by.
        let posture = (self.embedding)(&write_id);
        Ok(ClientContextSnapshot {
            agent_id: agent_id.to_string(),
            estimate: CONTEXT_TOKEN_ESTIMATE.to_string(),
            latest,
            embedding: ClientContextEmbedding {
                active: posture.active,
                model: posture.model,
            },
            index: ClientContextIndex { turns, tasks },
        })
    }
}

/// A report of a turn of `agent` that used `used` tokens (tests).
#[cfg(test)]
pub(crate) fn test_report(agent: &str, used: u32) -> AssemblyReport {
    use advance_context_engine::{AssemblyHistoryReport, AssemblyRecallReport, AssemblySection};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn report(agent: &str, used: u32) -> AssemblyReport {
        test_report(agent, used)
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
            fixed_embedding_posture(EmbeddingPosture {
                active: true,
                model: Some("text-embedding-3-small".into()),
            }),
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

    /// A forgotten agent is no longer known and answers with no report, under either
    /// of its ids; an agent registered under the same ids afterwards starts at
    /// sequence 1. Another agent is untouched — also one an alias group ties to an id
    /// that is forgotten.
    #[test]
    fn a_forgotten_agent_is_unknown_and_leaves_no_report() {
        let store = ContextSnapshotStore::new();
        store.register_aliases(&["root".to_string(), "agent:root".to_string()]);
        store.register_aliases(&["kid".to_string(), "agent:kid".to_string()]);
        // A group that ties another agent's id to the root's (as v0.1.54 registered for a
        // child refused for colliding with the root; now only a retained loop registers one).
        store.register_aliases(&["default".to_string(), "agent:root".to_string()]);
        store.record(report("agent:root", 100));
        store.record(report("agent:kid", 200));
        store.record(report("agent:kid", 300));

        store.forget("kid", &["agent:kid"]);
        assert!(!store.knows("kid") && !store.knows("agent:kid"));
        assert!(store.snapshot("kid").is_none() && store.snapshot("agent:kid").is_none());
        assert_eq!(
            store.snapshot("root").expect("root").report.used_tokens,
            100
        );

        store.register_aliases(&["kid".to_string(), "agent:kid".to_string()]);
        assert!(
            store.snapshot("kid").is_none(),
            "nothing of the agent before"
        );
        store.record(report("agent:kid", 400));
        let again = store.snapshot("kid").expect("the new agent's report");
        assert_eq!((again.sequence, again.report.used_tokens), (1, 400));

        // Forgetting an id an alias group ties to the root's drops that group and leaves
        // the root alone.
        store.forget("default", &[]);
        assert!(!store.knows("default"));
        assert_eq!(
            store.snapshot("root").expect("root").report.used_tokens,
            100
        );
        assert!(store.knows("root") && store.knows("agent:root"));

        // A group the agent registered under a colon id another agent holds now goes
        // with it; that agent's report and group stay.
        store.register_aliases(&["gone".to_string(), "agent:helper".to_string()]);
        store.register_aliases(&["newcomer".to_string(), "agent:helper".to_string()]);
        store.record(report("agent:helper", 500));
        store.forget("gone", &[]);
        assert!(!store.knows("gone"));
        assert_eq!(
            store
                .snapshot("newcomer")
                .expect("the newcomer's report")
                .report
                .used_tokens,
            500
        );

        // A colon id forgotten with the agent drops the report under it, and no group but
        // the agent's own: one another agent registered with that colon id stays.
        store.register_aliases(&["gone".to_string(), "agent:helper".to_string()]);
        store.forget("gone", &["agent:helper"]);
        assert!(!store.knows("gone"));
        assert!(
            store.snapshot("newcomer").is_none(),
            "the report under it went"
        );
        assert!(store.knows("newcomer"), "the newcomer's group stays");
    }

    /// Dropping the reports of some ids keeps the ids known.
    #[test]
    fn forgetting_reports_keeps_the_ids_known() {
        let store = ContextSnapshotStore::new();
        store.register_aliases(&["kid".to_string(), "agent:kid".to_string()]);
        store.record(report("agent:kid", 200));
        store.forget_reports(&["kid", "agent:kid"]);
        assert!(store.knows("kid"));
        assert!(store.snapshot("kid").is_none());
    }

    #[test]
    fn known_agent_without_assembly_has_no_latest() {
        let store = Arc::new(ContextSnapshotStore::new());
        store.register_aliases(&["root".to_string(), "agent:root".to_string()]);
        let adapter = ContextInspectAdapter::new(
            store,
            fixed_embedding_posture(EmbeddingPosture::default()),
            None,
            "root",
        );
        let dto = adapter.snapshot("agent:root").unwrap();
        assert!(dto.latest.is_none());
        assert!(!dto.embedding.active);
    }

    /// The embedding posture is the INSPECTED agent's own, asked by its bare id
    /// at snapshot time: two agents on different chat providers report different
    /// postures from one adapter, and a change shows on the next snapshot.
    #[test]
    fn embedding_posture_is_per_agent_and_read_at_snapshot_time() {
        let store = Arc::new(ContextSnapshotStore::new());
        store.register_aliases(&["root".to_string(), "agent:root".to_string()]);
        store.register_aliases(&["researcher".to_string(), "agent:researcher".to_string()]);
        let root_model = Arc::new(Mutex::new(Some("embed-a".to_string())));
        let asked = Arc::new(Mutex::new(Vec::<String>::new()));
        let source: EmbeddingPostureSource = {
            let (root_model, asked) = (root_model.clone(), asked.clone());
            Arc::new(move |agent_id| {
                asked.lock().unwrap().push(agent_id.to_string());
                let model = match agent_id {
                    "root" => root_model.lock().unwrap().clone(),
                    _ => None,
                };
                EmbeddingPosture {
                    active: model.is_some(),
                    model,
                }
            })
        };
        let adapter = ContextInspectAdapter::new(store, source, None, "root");

        // Either alias of the root resolves to its bare id.
        let dto = adapter.snapshot("agent:root").unwrap();
        assert!(dto.embedding.active);
        assert_eq!(dto.embedding.model.as_deref(), Some("embed-a"));
        // The child's chat provider serves no embeddings: its own posture.
        let child = adapter.snapshot("researcher").unwrap();
        assert!(!child.embedding.active);
        assert_eq!(child.embedding.model, None);
        // The root's provider changes: the next snapshot shows it.
        *root_model.lock().unwrap() = None;
        assert!(!adapter.snapshot("root").unwrap().embedding.active);
        assert_eq!(
            *asked.lock().unwrap(),
            vec!["root", "researcher", "root"],
            "the source is asked with the bare id, once per snapshot"
        );
    }

    #[test]
    fn child_alias_resolves_and_write_id_is_bare() {
        let store = Arc::new(ContextSnapshotStore::new());
        store.register_aliases(&["root".to_string(), "agent:root".to_string()]);
        store.register_aliases(&["researcher".to_string(), "agent:researcher".to_string()]);
        store.record(report("agent:researcher", 40));
        let adapter = ContextInspectAdapter::new(
            store,
            fixed_embedding_posture(EmbeddingPosture::default()),
            None,
            "root",
        );
        let dto = adapter.snapshot("researcher").unwrap();
        assert_eq!(dto.latest.expect("child assembled").used_tokens, 40);
        assert_eq!(dto.agent_id, "researcher");
    }
}
