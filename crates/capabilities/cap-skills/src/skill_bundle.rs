//! Slice E — `SkillBundle` multi-file skill representation per PRD §12.4.
//!
//! `SkillBundle` is the in-memory shape of a complete skill bundle (admin
//! pool or in-flight import). Optional fields support the PRD §12.4 Path A
//! (knowledge-only, importer-produced) vs Path B (admin offline
//! WASM-ization, direct admin pool write) distinction:
//!
//! - `skill_md` — required SKILL.md body.
//! - `tool_wasm` — Path B output ONLY; the Path A `SkillImporter` always
//!   leaves this `None`.
//! - `tool_capabilities` — `tool.capabilities.json` sidecar (Path B
//!   companion to `tool_wasm`).
//! - `templates` — `(filename, text body)` pairs for knowledge templates
//!   under `templates/`.
//! - `source_scripts` — `(filename, text body)` pairs for non-knowledge
//!   files at the source root (PRD §12.4 "脚本移到 `source-scripts/`"
//!   semantic). Path A importer reads via `read_to_string`, so BINARY
//!   files (incl. pre-existing `tool.wasm`) fail UTF-8 decode and reject
//!   the import. Admin Path B is the only channel that populates the
//!   bundle's `tool_wasm` field.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use advance_shared_types::skills::{Provenance, TrustLevel};

use crate::error::SkillError;
use crate::security_scan::{validate_skill_filename, validate_skill_name};

/// Maximum bytes for the SKILL.md body. Mirrors `SecurityScan` check 2.
pub const MAX_SKILL_MD_BYTES: usize = 50_000;

/// Maximum bytes for the optional `tool.wasm` binary blob. Bounded to
/// prevent pathological large blobs in tests/CI.
pub const MAX_TOOL_WASM_BYTES: usize = 16 * 1024 * 1024;

/// Maximum bytes for the optional `tool.capabilities.json` sidecar.
pub const MAX_TOOL_CAPABILITIES_BYTES: usize = 256 * 1024;

/// Maximum templates entries (each entry ≤ 50_000 byte body).
pub const MAX_TEMPLATES: usize = 32;

/// Maximum source-scripts entries (each entry ≤ 50_000 byte body).
pub const MAX_SOURCE_SCRIPTS: usize = 32;

/// In-memory shape of a complete skill bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillBundle {
    pub name: String,
    pub skill_md: String,
    pub tool_wasm: Option<Vec<u8>>,
    pub tool_capabilities: Option<String>,
    pub templates: Vec<(String, String)>,
    pub source_scripts: Vec<(String, String)>,
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
    pub created_at: DateTime<Utc>,
}

impl SkillBundle {
    /// Validating constructor.
    ///
    /// The Slice E `SkillImporter` library always passes `tool_wasm: None`
    /// and `tool_capabilities: None` (Path A strict). Admin Path B callers
    /// outside Slice E construct bundles with `Some(...)` for direct admin
    /// pool placement via `AdminPoolStorage::write_bundle`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        skill_md: String,
        tool_wasm: Option<Vec<u8>>,
        tool_capabilities: Option<String>,
        templates: Vec<(String, String)>,
        source_scripts: Vec<(String, String)>,
        provenance: Provenance,
        trust_level: TrustLevel,
    ) -> Result<Self, SkillError> {
        validate_skill_name(&name)?;
        if skill_md.len() > MAX_SKILL_MD_BYTES {
            return Err(SkillError::ContentTooLarge(skill_md.len()));
        }
        if let Some(blob) = tool_wasm.as_ref() {
            if blob.len() > MAX_TOOL_WASM_BYTES {
                return Err(SkillError::ContentTooLarge(blob.len()));
            }
        }
        if let Some(caps) = tool_capabilities.as_ref() {
            if caps.len() > MAX_TOOL_CAPABILITIES_BYTES {
                return Err(SkillError::ContentTooLarge(caps.len()));
            }
        }
        if templates.len() > MAX_TEMPLATES {
            return Err(SkillError::InvalidTransition(format!(
                "templates count {} exceeds {MAX_TEMPLATES}",
                templates.len()
            )));
        }
        for (filename, body) in &templates {
            validate_skill_filename(filename)?;
            if body.len() > MAX_SKILL_MD_BYTES {
                return Err(SkillError::ContentTooLarge(body.len()));
            }
        }
        if source_scripts.len() > MAX_SOURCE_SCRIPTS {
            return Err(SkillError::InvalidTransition(format!(
                "source_scripts count {} exceeds {MAX_SOURCE_SCRIPTS}",
                source_scripts.len()
            )));
        }
        for (filename, body) in &source_scripts {
            validate_skill_filename(filename)?;
            if body.len() > MAX_SKILL_MD_BYTES {
                return Err(SkillError::ContentTooLarge(body.len()));
            }
        }
        Ok(Self {
            name,
            skill_md,
            tool_wasm,
            tool_capabilities,
            templates,
            source_scripts,
            provenance,
            trust_level,
            created_at: Utc::now(),
        })
    }

    /// Build the YAML sidecar projection for on-disk persistence.
    pub(crate) fn meta(&self) -> BundleMeta {
        BundleMeta {
            name: self.name.clone(),
            provenance: self.provenance.clone(),
            trust_level: self.trust_level.clone(),
            template_files: self.templates.iter().map(|(f, _)| f.clone()).collect(),
            source_script_files: self.source_scripts.iter().map(|(f, _)| f.clone()).collect(),
            has_tool_wasm: self.tool_wasm.is_some(),
            has_tool_capabilities: self.tool_capabilities.is_some(),
            created_at: self.created_at,
        }
    }
}

/// On-disk YAML sidecar for `SkillBundle`. Stored at
/// `<root>/{name}/.meta.yaml` in the admin pool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleMeta {
    pub name: String,
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
    pub template_files: Vec<String>,
    pub source_script_files: Vec<String>,
    pub has_tool_wasm: bool,
    pub has_tool_capabilities: bool,
    pub created_at: DateTime<Utc>,
}

/// JSON descriptor for `SkillImporter::import_from_mcp_source`. Carries
/// enough text to synthesize a knowledge-only SKILL.md.
///
/// `Deserialize` (Slice I) lets the `advance skill import --mcp-descriptor
/// <spec.json>` CLI read this from a JSON file via `serde_json`; `Serialize`
/// is added symmetrically for round-trip tests / tooling. Additive — no
/// behavior change to the existing library API.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpImportSpec {
    pub source_name: String,
    pub prompt_text: String,
    pub description: String,
    pub tags: Vec<String>,
}
