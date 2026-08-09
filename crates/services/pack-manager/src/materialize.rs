//! `MaterializeAction` trait surface (CONTRACT-171) — Slice A declared the 10
//! §19.3 method signatures verbatim per MODULE-018 §2.3; the AC-17 slice
//! (m018-rescap) adds the 11th, `register_resource_capability` (the
//! register-not-copy REGISTRATION surface for the `resource-capabilities`
//! category). No concrete impl is provided in this crate module: the trait is a
//! contract surface for `DefaultMaterializer` and any test stubs callers want to provide.
//! Downstream consumers (M005 template materialization, M014 component
//! submission) compile against this surface; when their slices land, they
//! either supply a concrete impl or — for Slice B test scaffolding — provide
//! a stub that returns `PackError::NotImplemented` per method.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::PackError;

pub trait MaterializeAction: Send + Sync {
    fn materialize_binary(&self, pack_ref: &str, target: &Path) -> Result<PathBuf, PackError>;
    fn materialize_template(&self, pack_ref: &str, target: &Path) -> Result<(), PackError>;
    fn materialize_skill(&self, pack_ref: &str, target: &Path) -> Result<(), PackError>;
    fn materialize_component(&self, pack_ref: &str, target: &Path) -> Result<PathBuf, PackError>;
    fn materialize_channel_adapter(
        &self,
        pack_ref: &str,
        target: &Path,
    ) -> Result<PathBuf, PackError>;
    fn register_mcp_server(
        &self,
        pack_ref: &str,
        secret_refs: &HashMap<String, String>,
    ) -> Result<McpServerId, PackError>;
    fn apply_preset(
        &self,
        pack_ref: &str,
        target_agent_id: &str,
    ) -> Result<Vec<GrantId>, PackError>;
    fn apply_workflow(
        &self,
        pack_ref: &str,
        context: WorkflowContext,
    ) -> Result<WorkflowReport, PackError>;
    fn copy_memory_seed(&self, pack_ref: &str, target: &Path) -> Result<(), PackError>;
    fn merge_meta_schema_extension(
        &self,
        pack_ref: &str,
        target_schema: &Path,
    ) -> Result<(), PackError>;
    /// Type 11 (AC-17, REQ-380) — the register-not-copy REGISTRATION surface for the
    /// `resource-capabilities` category (the `apply_preset` precedent). Resolves
    /// `pack_ref` to `ComponentKind::ResourceCapability`, validates the on-disk
    /// `resource-capabilities/{name}/capability.yaml` (bounded / symlink-safe), and
    /// returns a content-derived [`ResourceCapabilityId`] (the manifest `id`). Nothing is
    /// copied into an agent workspace — there is no `target` parameter. Install/rescan
    /// separately validate the manifest and the pack registry resolves the capability;
    /// the MODULE-017 §3.6 (ddd) runtime-ToolRegistry bridge + exposure legs (that make
    /// the capability's tools callable by agents) remain deferred.
    fn register_resource_capability(
        &self,
        pack_ref: &str,
    ) -> Result<ResourceCapabilityId, PackError>;
}

// Slice A placeholder types — minimal shapes; Slice C flesh out.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantId(pub String);

/// Content-derived identifier of a registered pack resource capability (AC-17) —
/// the `id` field of `resource-capabilities/{name}/capability.yaml` (e.g.
/// `advance.structured-data`). Returned by
/// [`MaterializeAction::register_resource_capability`]; register-not-copy (nothing is
/// materialized into an agent workspace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceCapabilityId(pub String);

#[derive(Debug, Clone, Default)]
pub struct WorkflowContext {
    pub admin_id: String,
    pub target_workspace: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct WorkflowReport {
    pub steps_executed: Vec<String>,
}
