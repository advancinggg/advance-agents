//! `MaterializeAction` trait surface (CONTRACT-171) — the 10 §19.3 method
//! signatures verbatim per MODULE-018 §2.3, one per content kind. No concrete impl
//! is provided in this crate module: the trait is a contract surface for
//! `DefaultMaterializer` and any test stubs callers want to provide.
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
}

// Slice A placeholder types — minimal shapes; Slice C flesh out.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantId(pub String);

#[derive(Debug, Clone, Default)]
pub struct WorkflowContext {
    pub admin_id: String,
    pub target_workspace: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct WorkflowReport {
    pub steps_executed: Vec<String>,
}
