//! Slice C — agent stats (MODULE-005 AC-17, REQ-318).
//!
//! `self-stats` / `child-stats` WIT methods read the M019-owned `agent_stats`
//! SQLite table (CONTRACT-030 `SqliteIndexHandle`, read-only). M005 does NOT
//! populate the table — it only serves the lifecycle WIT read surface.
//!
//! `AgentStatsReader` is a dependency-inversion seam (no library default —
//! tests use recorder impls); `SqliteAgentStatsReader` (sibling module) is
//! the production impl over `advance_database::SqliteIndexHandle`.

use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentTreeSnapshot};

use crate::error::LifecycleError;
use crate::identifier::validate_agent_id;
use crate::tree::AgentTreeStore;

/// PRD §9.5 `agent-stats` record.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentStats {
    pub active_tasks: u32,
    pub completed_tasks: u32,
    pub avg_turns_per_task: f32,
    pub avg_completion_time_hours: f32,
    pub memory_entries: u32,
    pub llm_tokens_24h: u64,
    pub error_count_24h: u32,
    /// ISO 8601.
    pub last_active: String,
}

/// Read-only accessor over the M019-owned `agent_stats` table.
pub trait AgentStatsReader: Send + Sync {
    fn read_stats(&self, agent_id: &str) -> Result<AgentStats, LifecycleError>;
}

pub trait StatsController: Send + Sync {
    fn self_stats(&self, agent_id: &str) -> Result<AgentStats, LifecycleError>;
    /// Parent-only view of a child's stats.
    fn child_stats(&self, caller_id: &str, child_id: &str) -> Result<AgentStats, LifecycleError>;
}

#[derive(Clone)]
pub struct DefaultStatsController {
    tree: AgentTreeStore,
    reader: Arc<dyn AgentStatsReader>,
}

impl DefaultStatsController {
    pub fn new(tree: AgentTreeStore, reader: Arc<dyn AgentStatsReader>) -> Self {
        Self { tree, reader }
    }
}

impl StatsController for DefaultStatsController {
    fn self_stats(&self, agent_id: &str) -> Result<AgentStats, LifecycleError> {
        if validate_agent_id(agent_id).is_err() {
            return Err(LifecycleError::NotFound(format!(
                "invalid agent id: {agent_id}"
            )));
        }
        self.reader.read_stats(agent_id)
    }

    fn child_stats(&self, caller_id: &str, child_id: &str) -> Result<AgentStats, LifecycleError> {
        if validate_agent_id(caller_id).is_err() {
            return Err(LifecycleError::PermissionDenied(format!(
                "invalid caller id: {caller_id}"
            )));
        }
        if validate_agent_id(child_id).is_err() {
            return Err(LifecycleError::NotFound(format!(
                "invalid child id: {child_id}"
            )));
        }
        let snap = self.tree.snapshot();
        let child = AgentId(child_id.to_string());
        if !snap.parent_of.contains_key(&child) {
            return Err(LifecycleError::NotFound(format!("agent {child_id}")));
        }
        match snap.parent_of.get(&child).and_then(|p| p.clone()) {
            Some(p) if p.0 == caller_id => {}
            _ => {
                return Err(LifecycleError::PermissionDenied(format!(
                    "{caller_id} is not the parent of {child_id}"
                )));
            }
        }
        self.reader.read_stats(child_id)
    }
}
