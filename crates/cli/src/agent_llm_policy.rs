//! Lane agent-llm-policy (2026-09-16) — the production [`AgentLlmPolicySource`].
//!
//! Resolves the caller agent's `llm:` block (`<workspace>/.agent/config.yaml`, parsed by
//! [`crate::agent_config::parse_agent_llm_config`]) into a cap-llm [`AgentLlmPolicy`] for the
//! gateway, on EVERY request:
//!
//! - agent id → workspace: the shared `AgentTreeStore` (`get_node`), the daemon root when the id
//!   is the root's (or when no tree exists — an fs-less boot has only the root);
//! - one `stat` per call; the file is re-read and re-parsed only when its mtime (or presence)
//!   changed since the cached answer — no explicit invalidation, so an API `:update` (which
//!   rewrites the file) is visible at the agent's next LLM call;
//! - a PRESENT but malformed block is treated as absent (the request proceeds on the default
//!   path) and `agent.llm_policy_invalid` is emitted ONCE per (agent, mtime) — the API path
//!   refuses such a block, so this only fires for hand-edited files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_event_bus::taxonomy::extensions::AGENT_LLM_POLICY_INVALID;
use advance_shared_types::agent_tree::AgentId;
use advance_shared_types::event::Event;
use advance_shared_types::traits::AgentTreeSnapshot;
use advance_shared_types::traits::EventBusEmit;
use cap_lifecycle::AgentTreeStore;
use cap_llm::{parse_constraint, AgentLlmPolicy, AgentLlmPolicySource};

use crate::agent_config::{parse_agent_llm_config, read_agent_yaml, AgentLlmDecl};
use crate::client_api_providers::ProviderReferenceCheck;

/// Convert a validated block into the gateway's policy. `None` when the block is empty or its
/// constraint does not parse (validation already rejects that; defensive).
pub fn policy_from_decl(decl: &AgentLlmDecl) -> Result<Option<AgentLlmPolicy>, String> {
    if decl.is_empty() {
        return Ok(None);
    }
    let constraint = match &decl.constraint {
        Some(c) => Some(parse_constraint(c).map_err(|e| e.to_string())?),
        None => None,
    };
    Ok(Some(AgentLlmPolicy {
        provider: decl.provider.clone(),
        model: decl.model.clone(),
        constraint,
    }))
}

/// The file identity the cache keys on: `None` when the file is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp(Option<SystemTime>);

struct Cached {
    stamp: Stamp,
    policy: Option<AgentLlmPolicy>,
}

/// The production source over the daemon's agent tree.
pub struct WorkspaceAgentLlmPolicy {
    tree: Option<Arc<AgentTreeStore>>,
    root_id: String,
    root: PathBuf,
    bus: Arc<dyn EventBusEmit>,
    cache: Mutex<HashMap<String, Cached>>,
}

impl WorkspaceAgentLlmPolicy {
    pub fn new(
        tree: Option<Arc<AgentTreeStore>>,
        root_id: impl Into<String>,
        root: impl Into<PathBuf>,
        bus: Arc<dyn EventBusEmit>,
    ) -> Self {
        Self {
            tree,
            root_id: root_id.into(),
            root: root.into(),
            bus,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The agent's workspace: the tree node's territory, the root for the root id, `None` for an
    /// unknown id (no policy).
    fn workspace_for(&self, agent_id: &str) -> Option<PathBuf> {
        if agent_id == self.root_id {
            return Some(self.root.clone());
        }
        let tree = self.tree.as_ref()?;
        tree.get_node(&AgentId(agent_id.to_string()))
            .map(|n| n.workspace_path)
            .or_else(|| {
                // A colon-scoped served id (`agent:<bare>`) resolves to its bare tree id.
                agent_id
                    .strip_prefix("agent:")
                    .and_then(|bare| tree.get_node(&AgentId(bare.to_string())))
                    .map(|n| n.workspace_path)
            })
    }

    fn stamp(workspace: &Path) -> Stamp {
        let path = workspace.join(".agent").join("config.yaml");
        Stamp(
            std::fs::symlink_metadata(&path)
                .ok()
                .filter(|m| m.file_type().is_file())
                .and_then(|m| m.modified().ok()),
        )
    }

    /// Read + parse the block; a malformed block reports `Err(reason)`.
    fn load(workspace: &Path) -> Result<Option<AgentLlmPolicy>, String> {
        let bytes = read_agent_yaml(workspace);
        let decl = parse_agent_llm_config(bytes.as_deref()).map_err(|e| e.to_string())?;
        match decl {
            Some(decl) => policy_from_decl(&decl),
            None => Ok(None),
        }
    }

    fn emit_invalid(&self, agent_id: &str, reason: &str) {
        // Never echo config content: the reason is the parser's message (key names / grammar),
        // bounded so a pathological document cannot inflate the event.
        let reason: String = reason.chars().take(256).collect();
        self.bus.emit(Event::observability(
            AGENT_LLM_POLICY_INVALID,
            agent_id,
            serde_json::json!({ "agent_id": agent_id, "reason": reason }),
            None,
        ));
    }
}

impl AgentLlmPolicySource for WorkspaceAgentLlmPolicy {
    fn policy_for(&self, agent_id: &str) -> Option<AgentLlmPolicy> {
        let workspace = self.workspace_for(agent_id)?;
        let stamp = Self::stamp(&workspace);
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(cached) = cache.get(agent_id) {
            if cached.stamp == stamp {
                return cached.policy.clone();
            }
        }
        let policy = match Self::load(&workspace) {
            Ok(policy) => policy,
            Err(reason) => {
                // Cached under this stamp so the event fires once per (agent, mtime).
                self.emit_invalid(agent_id, &reason);
                None
            }
        };
        cache.insert(
            agent_id.to_string(),
            Cached {
                stamp,
                policy: policy.clone(),
            },
        );
        policy
    }
}

impl WorkspaceAgentLlmPolicy {
    /// Every agent — the root plus every tree node — whose `.agent/config.yaml` `llm.provider`
    /// names `provider_id`, sorted and de-duplicated. Reads the files directly (not the
    /// per-agent cache) so a pin written a moment ago is seen. A malformed block pins nothing
    /// (the same posture as [`AgentLlmPolicySource::policy_for`]).
    pub fn pinned_agents(&self, provider_id: &str) -> Vec<String> {
        let mut agents: Vec<(String, PathBuf)> = vec![(self.root_id.clone(), self.root.clone())];
        if let Some(tree) = &self.tree {
            for node in tree.snapshot().nodes {
                if node.id.0 != self.root_id {
                    agents.push((node.id.0.clone(), node.workspace_path.clone()));
                }
            }
        }
        let mut pinned: Vec<String> = agents
            .into_iter()
            .filter(|(_, workspace)| {
                matches!(
                    Self::load(workspace),
                    Ok(Some(policy)) if policy.provider.as_deref() == Some(provider_id)
                )
            })
            .map(|(id, _)| id)
            .collect();
        pinned.sort();
        pinned.dedup();
        pinned
    }
}

/// The providers family's delete guard: a provider some agent pins through
/// its `llm.provider` cannot be deleted out from under it.
impl ProviderReferenceCheck for WorkspaceAgentLlmPolicy {
    fn referenced_by(&self, provider_id: &str) -> Vec<String> {
        self.pinned_agents(provider_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct RecBus(StdMutex<Vec<Event>>);
    impl EventBusEmit for RecBus {
        fn emit(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn write_config(ws: &Path, text: &str) {
        std::fs::create_dir_all(ws.join(".agent")).unwrap();
        std::fs::write(ws.join(".agent/config.yaml"), text).unwrap();
    }

    /// Force a distinct mtime (coarse filesystems round to a second).
    fn bump_mtime(ws: &Path) {
        let path = ws.join(".agent/config.yaml");
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let t = SystemTime::now() + std::time::Duration::from_secs(5);
        f.set_modified(t).unwrap();
    }

    #[test]
    fn root_only_source_resolves_root_block_and_tracks_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().to_path_buf();
        write_config(
            &ws,
            "capabilities:\n  llm: true\nllm:\n  provider: local\n  model: tiny\n",
        );
        let bus = Arc::new(RecBus::default());
        let src = WorkspaceAgentLlmPolicy::new(None, "default-agent", &ws, bus.clone());
        let p = src.policy_for("default-agent").expect("policy");
        assert_eq!(p.provider.as_deref(), Some("local"));
        assert_eq!(p.model.as_deref(), Some("tiny"));
        assert!(p.constraint.is_none());
        // Unknown agent (no tree) → no policy, no event.
        assert!(src.policy_for("research").is_none());
        // Rewrite with a new mtime → the new block is served (no explicit invalidation).
        write_config(&ws, "llm:\n  constraint: never-cloud\n");
        bump_mtime(&ws);
        let p = src.policy_for("default-agent").expect("policy");
        assert!(p.provider.is_none());
        assert_eq!(p.constraint, Some(cap_llm::UserHardConstraint::NeverCloud));
        // Remove the file → absent.
        std::fs::remove_file(ws.join(".agent/config.yaml")).unwrap();
        assert!(src.policy_for("default-agent").is_none());
        assert!(
            bus.0.lock().unwrap().is_empty(),
            "valid blocks emit nothing"
        );
    }

    #[test]
    fn malformed_block_is_absent_and_reported_once_per_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().to_path_buf();
        write_config(&ws, "llm:\n  providr: local\n");
        let bus = Arc::new(RecBus::default());
        let src = WorkspaceAgentLlmPolicy::new(None, "default-agent", &ws, bus.clone());
        assert!(src.policy_for("default-agent").is_none());
        assert!(src.policy_for("default-agent").is_none());
        assert!(src.policy_for("default-agent").is_none());
        let events = bus.0.lock().unwrap();
        assert_eq!(events.len(), 1, "once per (agent, mtime)");
        assert_eq!(events[0].event_type, "agent.llm_policy_invalid");
        assert_eq!(events[0].agent_id, "default-agent");
        assert_eq!(events[0].payload["agent_id"], "default-agent");
        let reason = events[0].payload["reason"].as_str().unwrap();
        assert!(reason.starts_with("llm:"), "{reason}");
        drop(events);
        // A fixed file (new mtime) serves the policy, no further event.
        write_config(&ws, "llm:\n  provider: local\n");
        bump_mtime(&ws);
        assert!(src.policy_for("default-agent").is_some());
        assert_eq!(bus.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn root_only_source_reports_pinned_agents() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().to_path_buf();
        let bus = Arc::new(RecBus::default());
        let src = WorkspaceAgentLlmPolicy::new(None, "default-agent", &ws, bus.clone());
        // No config at all → nothing pinned.
        assert!(src.pinned_agents("openai").is_empty());
        write_config(
            &ws,
            "capabilities:\n  llm: true\nllm:\n  provider: openai\n",
        );
        assert_eq!(
            src.pinned_agents("openai"),
            vec!["default-agent".to_string()]
        );
        assert!(src.pinned_agents("anthropic").is_empty());
        assert_eq!(
            src.referenced_by("openai"),
            vec!["default-agent".to_string()]
        );
        // A malformed block pins nothing (and the delete guard emits no event).
        write_config(&ws, "llm:\n  providr: openai\n");
        assert!(src.pinned_agents("openai").is_empty());
        assert!(bus.0.lock().unwrap().is_empty());
    }

    #[test]
    fn decl_conversion() {
        let decl = AgentLlmDecl {
            provider: Some("p".into()),
            model: None,
            constraint: Some("device:phone".into()),
        };
        let p = policy_from_decl(&decl).unwrap().unwrap();
        assert_eq!(
            p.constraint,
            Some(cap_llm::UserHardConstraint::DevicePin("phone".into()))
        );
        assert!(policy_from_decl(&AgentLlmDecl::default())
            .unwrap()
            .is_none());
        let bad = AgentLlmDecl {
            constraint: Some("gpu".into()),
            ..Default::default()
        };
        assert!(policy_from_decl(&bad).is_err());
    }
}
