//! Skills bridge (§3.1 row 1, §3.2 rule 1): an installed pack's
//! `skills/{name}/` → cap-skills' admin pool through `SkillImporter`'s Path-A
//! walk (`import_from_local_path_with_trust`), so every importer guard
//! (SKILL.md required + 50 KB cap, per-file symlink refusal, UTF-8 only,
//! templates / source-scripts caps) applies to pack content unchanged.
//!
//! Trust: `Trusted` iff the pack's EFFECTIVE `.meta.yaml` trust is `trusted`;
//! the pack.yaml claim is never consulted. Provenance is always `Imported`.

use std::path::Path;
use std::sync::Arc;

use advance_pack_manager::{ComponentKind, PackRegistry, TrustLevel as PackTrust};
use cap_skills::{AdminPoolStorage, Provenance, SkillImporter, TrustLevel};

use super::{effective_trust, resolve_kind, PackBridgeError};

/// What `PackSkillBridge::import` wrote to the admin pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSkill {
    /// The bundle name (= the pack's skill name).
    pub name: String,
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
}

pub struct PackSkillBridge {
    registry: Arc<dyn PackRegistry>,
}

impl PackSkillBridge {
    pub fn new(registry: Arc<dyn PackRegistry>) -> Self {
        Self { registry }
    }

    /// Import `{pack}@{ver}/skills/{name}` into `admin`. `work_dir` is the
    /// importer's scratch parent (unused by the local-path walk, kept for the
    /// importer's constructor contract).
    pub async fn import(
        &self,
        pack_ref: &str,
        admin: &AdminPoolStorage,
        work_dir: &Path,
    ) -> Result<ImportedSkill, PackBridgeError> {
        let resolution = resolve_kind(&*self.registry, pack_ref, ComponentKind::Skill)?;
        let trust =
            match effective_trust(&*self.registry, &resolution.pack_name, &resolution.version)? {
                PackTrust::Trusted => TrustLevel::Trusted,
                PackTrust::Untrusted => TrustLevel::Untrusted,
            };
        let name = resolution.manifest_snippet.name.clone();
        SkillImporter::new(work_dir.to_path_buf())
            .import_from_local_path_with_trust(&resolution.local_path, &name, admin, trust.clone())
            .await?;
        Ok(ImportedSkill {
            name,
            provenance: Provenance::Imported,
            trust_level: trust,
        })
    }
}
