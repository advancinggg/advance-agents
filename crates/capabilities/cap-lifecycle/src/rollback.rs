//! Slice-B `rollback-child` parent-privilege validation + delegation
//! (MODULE-005 AC-24, consumes CONTRACT-021 via a sync gate seam).
//!
//! Public surface:
//! - [`WorkspaceRollbackGate`] trait — mirrors CONTRACT-021's
//!   `WorkspaceRollback` byte-for-byte (incl. the `RollbackMode` arg),
//!   sync. Production wiring is a Slice C blocking adapter; Slice B
//!   ships zero library-side impl (matches Slice A `SpawnerSubsetGate`
//!   discipline).
//! - [`RollbackTargetSpec`] / [`RollbackModeSpec`] — input shapes
//!   mirroring CONTRACT-021's `RollbackTarget` / `RollbackMode`.
//! - [`RollbackController`] trait + [`DefaultRollbackController`] —
//!   parent-child + kind + target-format validation, then delegate to
//!   the gate.

use std::path::PathBuf;
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentKind};

use crate::error::LifecycleError;
use crate::identifier::validate_agent_id;
use crate::tree::AgentTreeStore;

#[derive(Debug, Clone)]
pub enum RollbackTargetSpec {
    /// 40-char hex SHA-1 (case-insensitive at the cap-lifecycle boundary;
    /// the controller normalizes to lowercase before passing to the gate).
    Commit(String),
    /// Checkpoint label. Cap-lifecycle's pre-validation is permissive
    /// (rejects empty / len > 128 / control chars / `..` path-segment);
    /// MODULE-003's `validate_ref_component` is the authoritative check.
    Checkpoint(String),
}

#[derive(Debug, Clone)]
pub enum RollbackModeSpec {
    /// Walks the target commit's tree under the agent's writable domain.
    /// Default for the no-mode `rollback-child(child-id, version)` WIT
    /// entry point.
    FullDirectory,
    /// Caller-supplied paths (relative to agent root). Reserved for
    /// future-Slice WIT additions; Slice B's `rollback_child` always
    /// passes `FullDirectory`.
    PathScoped(Vec<PathBuf>),
}

pub trait WorkspaceRollbackGate: Send + Sync {
    fn rollback(
        &self,
        agent_id: &str,
        target: RollbackTargetSpec,
        mode: RollbackModeSpec,
    ) -> Result<Vec<PathBuf>, LifecycleError>;

    fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
    ) -> Result<Vec<PathBuf>, LifecycleError>;
}

pub trait RollbackController: Send + Sync {
    fn rollback_child(
        &self,
        caller_id: &AgentId,
        child_id: &AgentId,
        version: String,
    ) -> Result<Vec<PathBuf>, LifecycleError>;

    fn rollback_child_to_checkpoint(
        &self,
        caller_id: &AgentId,
        child_id: &AgentId,
        label: String,
    ) -> Result<Vec<PathBuf>, LifecycleError>;
}

#[derive(Clone)]
pub struct DefaultRollbackController {
    tree: AgentTreeStore,
    gate: Arc<dyn WorkspaceRollbackGate>,
}

impl DefaultRollbackController {
    pub fn new(tree: AgentTreeStore, gate: Arc<dyn WorkspaceRollbackGate>) -> Self {
        Self { tree, gate }
    }

    pub fn tree(&self) -> &AgentTreeStore {
        &self.tree
    }

    /// Common validation flow shared by both rollback paths. Returns
    /// `Ok(())` if the caller is permitted to roll back the child.
    fn validate_parent_child(
        &self,
        caller_id: &AgentId,
        child_id: &AgentId,
    ) -> Result<(), LifecycleError> {
        if validate_agent_id(&caller_id.0).is_err() {
            return Err(LifecycleError::PermissionDenied(
                "caller id is invalid".to_string(),
            ));
        }
        if validate_agent_id(&child_id.0).is_err() {
            return Err(LifecycleError::PermissionDenied(
                "child id is invalid".to_string(),
            ));
        }
        if self.tree.get_node(caller_id).is_none() {
            return Err(LifecycleError::NotFound(format!("caller {:?}", caller_id)));
        }
        let child = self
            .tree
            .get_node(child_id)
            .ok_or_else(|| LifecycleError::NotFound(format!("child {:?}", child_id)))?;
        match child.parent {
            Some(p) if &p == caller_id => {}
            _ => {
                return Err(LifecycleError::PermissionDenied(
                    "caller is not the parent of child".to_string(),
                ));
            }
        }
        if child.kind != AgentKind::Child {
            return Err(LifecycleError::PermissionDenied(
                "rollback-child target must have kind=Child".to_string(),
            ));
        }
        Ok(())
    }
}

/// Validate a 40-char hex string (case-insensitive). On success, returns
/// the lowercase form for forwarding to the gate.
fn validate_commit_hex(s: &str) -> Result<String, LifecycleError> {
    if s.len() != 40 {
        return Err(LifecycleError::InvalidTarget(format!(
            "commit hash must be 40 hex chars; got {}",
            s.len()
        )));
    }
    for c in s.chars() {
        if !c.is_ascii_hexdigit() {
            return Err(LifecycleError::InvalidTarget(format!(
                "commit hash contains non-hex char {c:?}"
            )));
        }
    }
    Ok(s.to_ascii_lowercase())
}

/// Permissive checkpoint-label pre-check. The authoritative validation
/// lives in MODULE-003's `validate_ref_component`.
fn validate_checkpoint_label(label: &str) -> Result<(), LifecycleError> {
    if label.is_empty() {
        return Err(LifecycleError::InvalidTarget(
            "checkpoint label is empty".to_string(),
        ));
    }
    if label.len() > 128 {
        return Err(LifecycleError::InvalidTarget(format!(
            "checkpoint label length {} exceeds 128",
            label.len()
        )));
    }
    if label.starts_with('/') || label.ends_with('/') {
        return Err(LifecycleError::InvalidTarget(
            "checkpoint label cannot start or end with `/`".to_string(),
        ));
    }
    for c in label.chars() {
        if c.is_control() {
            return Err(LifecycleError::InvalidTarget(
                "checkpoint label contains control character".to_string(),
            ));
        }
    }
    // Reject the literal `..` path-segment. Embedded `..` substrings inside
    // a single component (e.g. `foo..bar`) pass; MODULE-003 will catch the
    // Git-ref-grammar specifics on the gate's far side.
    for seg in label.split('/') {
        if seg == ".." {
            return Err(LifecycleError::InvalidTarget(
                "checkpoint label contains `..` path-segment".to_string(),
            ));
        }
    }
    Ok(())
}

impl RollbackController for DefaultRollbackController {
    fn rollback_child(
        &self,
        caller_id: &AgentId,
        child_id: &AgentId,
        version: String,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        self.validate_parent_child(caller_id, child_id)?;
        let normalized = validate_commit_hex(&version)?;
        let target = RollbackTargetSpec::Commit(normalized);
        self.gate
            .rollback(child_id.0.as_str(), target, RollbackModeSpec::FullDirectory)
            .map_err(|e| match e {
                LifecycleError::RollbackGate(_) => e,
                other => LifecycleError::RollbackGate(other.to_string()),
            })
    }

    fn rollback_child_to_checkpoint(
        &self,
        caller_id: &AgentId,
        child_id: &AgentId,
        label: String,
    ) -> Result<Vec<PathBuf>, LifecycleError> {
        self.validate_parent_child(caller_id, child_id)?;
        validate_checkpoint_label(&label)?;
        self.gate
            .rollback_to_checkpoint(child_id.0.as_str(), &label)
            .map_err(|e| match e {
                LifecycleError::RollbackGate(_) => e,
                other => LifecycleError::RollbackGate(other.to_string()),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_hex_accepts_lowercase() {
        let s = "0".repeat(40);
        assert_eq!(validate_commit_hex(&s).unwrap(), s);
    }

    #[test]
    fn commit_hex_accepts_uppercase_normalizes() {
        let s = "A".repeat(40);
        assert_eq!(validate_commit_hex(&s).unwrap(), "a".repeat(40));
    }

    #[test]
    fn commit_hex_accepts_mixed_case_normalizes() {
        let s: String = "aBcDeF".chars().cycle().take(40).collect();
        let got = validate_commit_hex(&s).unwrap();
        assert_eq!(got, s.to_ascii_lowercase());
    }

    #[test]
    fn commit_hex_rejects_short() {
        let err = validate_commit_hex("abc").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTarget(_)));
    }

    #[test]
    fn commit_hex_rejects_non_hex() {
        let s: String = "g".repeat(40);
        let err = validate_commit_hex(&s).unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTarget(_)));
    }

    #[test]
    fn checkpoint_label_rejects_empty() {
        assert!(matches!(
            validate_checkpoint_label(""),
            Err(LifecycleError::InvalidTarget(_))
        ));
    }

    #[test]
    fn checkpoint_label_rejects_traversal() {
        assert!(matches!(
            validate_checkpoint_label("foo/../bar"),
            Err(LifecycleError::InvalidTarget(_))
        ));
    }

    #[test]
    fn checkpoint_label_accepts_git_ref_chars() {
        // `auto:iter-3` is a real MODULE-003 label form.
        validate_checkpoint_label("auto:iter-3").unwrap();
        // `release/v1.2` — cap-lifecycle is permissive (passes); MODULE-003
        // gate-side will reject the `/` per validate_ref_component.
        validate_checkpoint_label("release/v1.2").unwrap();
    }

    #[test]
    fn checkpoint_label_rejects_overlong() {
        let s = "a".repeat(129);
        assert!(matches!(
            validate_checkpoint_label(&s),
            Err(LifecycleError::InvalidTarget(_))
        ));
    }

    #[test]
    fn checkpoint_label_rejects_control() {
        assert!(matches!(
            validate_checkpoint_label("foo\nbar"),
            Err(LifecycleError::InvalidTarget(_))
        ));
    }
}
