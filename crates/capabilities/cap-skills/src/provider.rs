//! Slice C — `SkillStoreProvider` trait for per-agent SkillStore resolution
//! at the `agent-skills` host_fn boundary.
//!
//! Slice C ships `SingleAgentSkillStoreProvider` only — serves exactly ONE
//! `agent_id`; returns `Err(SkillNotFound)` for unknown `agent_id`. Production
//! multi-agent provider (VirtualPathResolver-backed, M005 child-spawn-aware)
//! is deferred per MODULE-017 §3.6 known gap (b).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, OnceCell};

use crate::error::SkillError;
use crate::lifecycle::SkillStore;
use crate::persistence::DiskSkillStorage;

/// Resolve the SkillStore for the calling agent. Implementations decide
/// how `agent_id` maps to the underlying storage root.
#[async_trait]
pub trait SkillStoreProvider: Send + Sync {
    /// Get the SkillStore for the given agent. Returns
    /// `Err(SkillNotFound)` if the agent_id is unknown.
    async fn get(&self, agent_id: &str) -> Result<Arc<Mutex<SkillStore>>, SkillError>;
}

/// Slice C single-agent provider. Bound to one `agent_id` at construction;
/// `get(agent_id)` returns `Err` for any other id.
///
/// The first `get` call lazily instantiates a `SkillStore` wrapping a
/// `DiskSkillStorage` rooted at `agent_root`. Subsequent calls return the
/// same Arc (cached via `OnceCell`).
pub struct SingleAgentSkillStoreProvider {
    pub agent_id: String,
    pub agent_root: PathBuf,
    /// slice wave6-laneB (leg 3): the cap-memory `_skill_candidates.jsonl`
    /// directory (`<ws>/.agent/memory` — distinct from `agent_root` = `<ws>/.agent`),
    /// threaded onto the lazily-built `SkillStore` so `list/resolve_skill_candidate`
    /// read the real producer store. `None` ⇒ the Slice-C candidate stub.
    candidate_dir: Option<PathBuf>,
    store: OnceCell<Arc<Mutex<SkillStore>>>,
}

impl SingleAgentSkillStoreProvider {
    pub fn new(agent_id: impl Into<String>, agent_root: impl Into<PathBuf>) -> Self {
        Self {
            agent_id: agent_id.into(),
            agent_root: agent_root.into(),
            candidate_dir: None,
            store: OnceCell::new(),
        }
    }

    /// slice wave6-laneB (leg 3): set the cap-memory candidate-store directory
    /// (`<ws>/.agent/memory`) so the lazily-built `SkillStore` wires
    /// `list/resolve_skill_candidate` to the real producer JSONL. Consuming builder.
    pub fn with_candidate_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.candidate_dir = Some(dir.into());
        self
    }

    pub fn shared(agent_id: impl Into<String>, agent_root: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self::new(agent_id, agent_root))
    }
}

#[async_trait]
impl SkillStoreProvider for SingleAgentSkillStoreProvider {
    async fn get(&self, agent_id: &str) -> Result<Arc<Mutex<SkillStore>>, SkillError> {
        if agent_id != self.agent_id {
            return Err(SkillError::SkillNotFound(format!(
                "unknown agent: {agent_id}"
            )));
        }
        let store = self
            .store
            .get_or_init(|| async {
                let storage = Arc::new(DiskSkillStorage::with_default_writer(
                    self.agent_root.clone(),
                ));
                let mut skill_store = SkillStore::with_storage(storage);
                if let Some(dir) = &self.candidate_dir {
                    skill_store = skill_store.with_candidate_dir(dir.clone());
                }
                Arc::new(Mutex::new(skill_store))
            })
            .await;
        Ok(store.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// SC-provider-single — provider returns Ok for its own agent_id,
    /// Err(SkillNotFound) for any other agent_id.
    #[tokio::test]
    async fn sc_provider_single_agent_isolation() {
        let dir = TempDir::new().unwrap();
        let provider = SingleAgentSkillStoreProvider::new("alice", dir.path().to_path_buf());

        // Own agent_id: Ok.
        let store_a = provider.get("alice").await;
        assert!(store_a.is_ok(), "own agent_id should resolve");

        // Different agent_id: Err.
        let store_b = provider.get("bob").await;
        assert!(matches!(store_b, Err(SkillError::SkillNotFound(_))));
    }

    /// SC-provider-cached — repeated `get` for the same agent_id returns
    /// the SAME Arc (cached via OnceCell).
    #[tokio::test]
    async fn sc_provider_caches_store() {
        let dir = TempDir::new().unwrap();
        let provider = SingleAgentSkillStoreProvider::new("alice", dir.path().to_path_buf());
        let a = provider.get("alice").await.unwrap();
        let b = provider.get("alice").await.unwrap();
        assert!(Arc::ptr_eq(&a, &b), "subsequent gets must return same Arc");
    }
}
