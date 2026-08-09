//! Slice C — checkpoint controller (MODULE-005 AC-01 checkpoint methods).
//!
//! `NamedCheckpointGate` mirrors CONTRACT-022 `NamedCheckpoint` **create +
//! list only** — the surface the WIT methods `checkpoint` /
//! `list-checkpoints` / `list-child-checkpoints` consume. CONTRACT-022's
//! `delete` is intentionally NOT mirrored: PRD §9.5 exposes no
//! `delete-checkpoint` WIT method, so mirroring it would be dead surface
//! (matches the `WorkspaceRollbackGate` "mirror only consumed surface"
//! discipline). The WIT `rollback-to-checkpoint` routes through the existing
//! Slice-B `WorkspaceRollbackGate` with `RollbackTargetSpec::Checkpoint`.
//!
//! No library-side gate impl (Slice A/B seam discipline).

use std::path::PathBuf;
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentTreeSnapshot};

use crate::error::LifecycleError;
use crate::identifier::validate_agent_id;
use crate::rollback::{RollbackTargetSpec, WorkspaceRollbackGate};
use crate::tree::AgentTreeStore;

const MAX_LABEL_BYTES: usize = 128;

/// Local mirror of CONTRACT-022 `git::CheckpointEntry` (consumed shape).
#[derive(Clone, Debug, PartialEq)]
pub struct CheckpointEntry {
    pub label: String,
    pub agent: String,
    /// Unix seconds as a decimal string (matches CONTRACT-022 §1.4.3).
    pub timestamp: String,
    pub paths: Option<Vec<PathBuf>>,
    pub valid: bool,
}

/// Sync seam mirroring CONTRACT-022 `NamedCheckpoint::{create,list}` (NOT
/// `delete` — not WIT-exposed). No library impl; tests provide recorders.
pub trait NamedCheckpointGate: Send + Sync {
    fn create(
        &self,
        agent_id: &str,
        label: &str,
        paths: Option<Vec<PathBuf>>,
    ) -> Result<(), LifecycleError>;
    fn list(&self, agent_id: &str) -> Result<Vec<CheckpointEntry>, LifecycleError>;
}

pub trait CheckpointController: Send + Sync {
    fn checkpoint(
        &self,
        caller_id: &str,
        label: &str,
        paths: Option<Vec<PathBuf>>,
    ) -> Result<(), LifecycleError>;

    fn list_checkpoints(&self, caller_id: &str) -> Result<Vec<CheckpointEntry>, LifecycleError>;

    fn list_child_checkpoints(
        &self,
        caller_id: &str,
        child_id: &str,
    ) -> Result<Vec<CheckpointEntry>, LifecycleError>;

    /// Routes through the Slice-B `WorkspaceRollbackGate` with a
    /// `Checkpoint` target (CONTRACT-021), NOT a NamedCheckpoint method.
    fn rollback_to_checkpoint(
        &self,
        caller_id: &str,
        label: &str,
    ) -> Result<Vec<PathBuf>, LifecycleError>;
}

#[derive(Clone)]
pub struct DefaultCheckpointController {
    tree: AgentTreeStore,
    gate: Arc<dyn NamedCheckpointGate>,
    rollback_gate: Arc<dyn WorkspaceRollbackGate>,
}

impl DefaultCheckpointController {
    pub fn new(
        tree: AgentTreeStore,
        gate: Arc<dyn NamedCheckpointGate>,
        rollback_gate: Arc<dyn WorkspaceRollbackGate>,
    ) -> Self {
        Self {
            tree,
            gate,
            rollback_gate,
        }
    }

    pub fn tree(&self) -> &AgentTreeStore {
        &self.tree
    }
}

fn validate_label(label: &str) -> Result<(), LifecycleError> {
    if label.is_empty() || label.len() > MAX_LABEL_BYTES {
        return Err(LifecycleError::InvalidTarget(format!(
            "checkpoint label length {} invalid (1..={MAX_LABEL_BYTES})",
            label.len()
        )));
    }
    if label.bytes().any(|b| b.is_ascii_control()) {
        return Err(LifecycleError::InvalidTarget(
            "checkpoint label contains control chars".to_string(),
        ));
    }
    if label.contains("..") {
        return Err(LifecycleError::InvalidTarget(
            "checkpoint label contains '..'".to_string(),
        ));
    }
    if label.starts_with('/') {
        return Err(LifecycleError::InvalidTarget(
            "checkpoint label must not start with '/'".to_string(),
        ));
    }
    Ok(())
}

fn require_caller(tree: &AgentTreeStore, caller_id: &str) -> Result<(), LifecycleError> {
    if validate_agent_id(caller_id).is_err() {
        return Err(LifecycleError::PermissionDenied(format!(
            "invalid caller id: {caller_id}"
        )));
    }
    if !tree.contains(&AgentId(caller_id.to_string())) {
        return Err(LifecycleError::PermissionDenied(format!(
            "caller {caller_id} is not a registered agent"
        )));
    }
    Ok(())
}

impl CheckpointController for DefaultCheckpointController {
    fn checkpoint(
        &self,
        caller_id: &str,
        label: &str,
        paths: Option<Vec<PathBuf>>,
    ) -> Result<(), LifecycleError> {
        require_caller(&self.tree, caller_id)?;
        validate_label(label)?;
        self.gate.create(caller_id, label, paths)
    }

    fn list_checkpoints(&self, caller_id: &str) -> Result<Vec<CheckpointEntry>, LifecycleError> {
        require_caller(&self.tree, caller_id)?;
        self.gate.list(caller_id)
    }

    fn list_child_checkpoints(
        &self,
        caller_id: &str,
        child_id: &str,
    ) -> Result<Vec<CheckpointEntry>, LifecycleError> {
        require_caller(&self.tree, caller_id)?;
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
        self.gate.list(child_id)
    }

    fn rollback_to_checkpoint(
        &self,
        caller_id: &str,
        label: &str,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        require_caller(&self.tree, caller_id)?;
        validate_label(label)?;
        // Pre-validate the checkpoint-label target shape, then delegate to
        // the CONTRACT-021 rollback gate (NOT a NamedCheckpoint method).
        let _ = RollbackTargetSpec::Checkpoint(label.to_string());
        self.rollback_gate.rollback_to_checkpoint(caller_id, label)
    }
}
