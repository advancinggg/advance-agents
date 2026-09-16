//! Pack lane P2 — pack → subsystem bridges.
//!
//! The pack-manager materializer resolves an installed pack's components to
//! paths (and, for the file-backed kinds, validates them), but the subsystems
//! that CONSUME those components — cap-skills' admin pool, cap-grant's preset
//! registry, cap-mcp's server whitelist, cap-fs's live meta-schema loader, the
//! knowledge JSONL the SQLite index rebuild scans — each have their own loader
//! with their own grammar and security posture. These composition-root
//! adapters (same tier as `client_api_adapters.rs`) connect the two sides by
//! calling the subsystem's OWN loader on the resolved path, so no grammar is
//! duplicated and every existing guard (size caps, symlink refusal, built-in
//! preset shadow refusal, …) applies unchanged.
//!
//! Trust propagation (§3.2) is decided HERE from the pack's EFFECTIVE trust —
//! the admin-approved `.meta.yaml` value the registry reports as
//! `PackMetadata::trust_level` (P3 made it "trusted iff claimed AND signed by a
//! configured root"), never the pack.yaml self-claim:
//! 1. a skill imported from a pack is `Trusted` iff the pack is `trusted`;
//! 2. an MCP `stdio` transport (subprocess = arbitrary code execution) is
//!    refused (`TrustDenied`) unless the pack is `trusted`; `http` transports
//!    are admitted from any pack because the cap-http security chain governs
//!    them.
//!
//! `channel-adapters` have no bridge by decision: cap-channel has no
//! path-loaded adapter surface, so `DefaultMaterializer::materialize_channel_adapter`
//! is an explicit `NotImplemented` (see the plan §3.1).

pub mod mcp;
pub mod memory_seed;
pub mod meta_schema;
pub mod presets;
pub mod skills;

pub use mcp::{InMemoryMcpEntrySink, McpEntrySink, PackMcpBridge};
pub use memory_seed::{PackMemorySeedBridge, SeedReport};
pub use meta_schema::{MergeReport, PackMetaSchemaBridge};
pub use presets::PackPresetBridge;
pub use skills::{ImportedSkill, PackSkillBridge};

use advance_pack_manager::{ComponentKind, PackError, PackRegistry, PackResolution, TrustLevel};

/// Shared bridge error (plan §3).
#[derive(Debug)]
pub enum PackBridgeError {
    /// Pack-manager resolution / parse / validation failure.
    Pack(PackError),
    /// cap-skills importer / admin pool failure.
    Skill(cap_skills::SkillError),
    /// cap-grant preset loader failure (its Display; `CapGrantError` is not
    /// `Clone`/`PartialEq` and carries a database variant).
    Grant(String),
    /// cap-mcp whitelist failure (duplicate server id, pattern compile, …).
    Mcp(cap_mcp::McpError),
    /// Filesystem / loader failure outside the pack tree (target JSONL, schema
    /// reload, …).
    Io(String),
    /// A meta-schema extension redeclares an existing field with a different
    /// spec (`existing` / `incoming` are single-line renderings).
    SchemaConflict {
        field: String,
        existing: String,
        incoming: String,
    },
    /// The pack's effective trust does not permit the operation (§3.2).
    TrustDenied { pack: String, reason: String },
}

impl std::fmt::Display for PackBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackBridgeError::Pack(e) => write!(f, "pack: {e}"),
            PackBridgeError::Skill(e) => write!(f, "skill import: {e}"),
            PackBridgeError::Grant(m) => write!(f, "preset: {m}"),
            PackBridgeError::Mcp(e) => write!(f, "mcp: {e}"),
            PackBridgeError::Io(m) => write!(f, "io: {m}"),
            PackBridgeError::SchemaConflict {
                field,
                existing,
                incoming,
            } => write!(
                f,
                "meta-schema conflict on field `{field}`: existing {existing}, incoming {incoming}"
            ),
            PackBridgeError::TrustDenied { pack, reason } => {
                write!(f, "trust denied for pack {pack}: {reason}")
            }
        }
    }
}

impl std::error::Error for PackBridgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PackBridgeError::Pack(e) => Some(e),
            PackBridgeError::Skill(e) => Some(e),
            PackBridgeError::Mcp(e) => Some(e),
            _ => None,
        }
    }
}

impl From<PackError> for PackBridgeError {
    fn from(e: PackError) -> Self {
        PackBridgeError::Pack(e)
    }
}

impl From<cap_skills::SkillError> for PackBridgeError {
    fn from(e: cap_skills::SkillError) -> Self {
        PackBridgeError::Skill(e)
    }
}

impl From<cap_mcp::McpError> for PackBridgeError {
    fn from(e: cap_mcp::McpError) -> Self {
        PackBridgeError::Mcp(e)
    }
}

/// Resolve `pack_ref` and require `expected` (wrong kind →
/// `MaterializeMissingProvide`, exactly like `DefaultMaterializer`).
pub(crate) fn resolve_kind(
    registry: &dyn PackRegistry,
    pack_ref: &str,
    expected: ComponentKind,
) -> Result<PackResolution, PackBridgeError> {
    let resolution = registry.resolve(pack_ref)?;
    if resolution.component_kind != expected {
        return Err(PackBridgeError::Pack(
            PackError::MaterializeMissingProvide {
                kind: format!("{expected:?}"),
                name: resolution.manifest_snippet.name.clone(),
            },
        ));
    }
    Ok(resolution)
}

/// The EFFECTIVE trust of the installed pack `{name}@{version}` — the
/// admin-approved `.meta.yaml` value (`PackMetadata::trust_level`), never the
/// manifest self-claim. A pack the registry no longer lists → `PackNotFound`
/// (fail-closed: no trust is ever inferred for an unknown pack).
pub(crate) fn effective_trust(
    registry: &dyn PackRegistry,
    name: &str,
    version: &str,
) -> Result<TrustLevel, PackBridgeError> {
    registry
        .list_installed()
        .into_iter()
        .find(|m| m.name == name && m.version == version)
        .map(|m| m.trust_level)
        .ok_or_else(|| {
            PackBridgeError::Pack(PackError::PackNotFound(
                name.to_string(),
                version.to_string(),
            ))
        })
}

/// `"{name}@{version}"` for messages.
pub(crate) fn pack_id(resolution: &PackResolution) -> String {
    format!("{}@{}", resolution.pack_name, resolution.version)
}
