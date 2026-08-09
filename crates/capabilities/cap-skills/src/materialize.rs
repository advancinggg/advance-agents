//! Slice E — `materialize_skill` library function.
//!
//! Copies a bundle from `AdminPoolStorage` (admin pool) to an agent-local
//! `&dyn SkillStorage` tree. Write order is **clear sidecars FIRST (Step 0)
//! → write new sidecars (Step 1) → `write_active` LAST (Step 2)** — see
//! `materialize_skill` for the detailed contract and §3.6 (aa) /
//! §3.6 (y) for the disclosed partial-write semantics.
//!
//! Materialize is SYNCHRONIZING (round-6 fix; was ADDITIVE in earlier
//! Slice E revisions). Step 0 calls `SkillStorage::clear_skill_sidecars`
//! which removes pre-existing tool.wasm / tool.capabilities.json /
//! templates/ / source-scripts/ so that re-materializing a SHRUNK admin
//! bundle drops the stale agent-local files. SKILL.md + .meta.yaml are
//! preserved through Step 0 and overwritten last by `write_active`,
//! keeping the prior SkillBlob intact if any later step fails.

use crate::admin_pool::AdminPoolStorage;
use crate::error::SkillError;
use crate::persistence::{SkillBlob, SkillSidecar, SkillStorage};
use crate::security_scan::validate_skill_name;

/// Copy bundle `name` from admin pool into the agent-local storage.
///
/// Returns `Err(SkillError::SkillNotFound)` if the admin pool has no
/// bundle with that name.
///
/// Three-step ordering (round-6 sync model, see MODULE-017 §3.6 (aa)
/// and §3.6 (y)):
///
/// 1. **Step 0** — `to.clear_skill_sidecars(name)` removes any
///    pre-existing tool.wasm / tool.capabilities.json / templates/ /
///    source-scripts/ for this skill. This is what makes re-materializing
///    a SHRUNK bundle correctly drop the stale agent-local files.
///    SKILL.md + .meta.yaml are NOT touched here.
/// 2. **Step 1** — write the bundle's new sidecars
///    (`write_skill_sidecar` for each).
/// 3. **Step 2** — `write_active` writes SKILL.md + .meta.yaml LAST.
///
/// Failure modes:
/// - Step 0 fails → no agent-local mutation; prior bundle intact.
/// - Step 1 fails partway → prior SkillBlob (SKILL.md + .meta.yaml)
///   intact (write_active hasn't run), but prior sidecars are already
///   cleared by Step 0 and only a partial new sidecar set was written.
///   This is the documented round-6 trade-off: the bundle being
///   materialized is the new source-of-truth so the prior sidecars
///   were going to be cleared anyway.
/// - Step 2 fails after SKILL.md but before .meta.yaml → SkillBlob
///   shape may temporarily desync (inherited Slice-C
///   `DiskSkillStorage::write_active` limitation per §3.6 (y)).
pub async fn materialize_skill(
    name: &str,
    from: &AdminPoolStorage,
    to: &dyn SkillStorage,
) -> Result<(), SkillError> {
    validate_skill_name(name)?;

    let bundle = match from.read_bundle(name).await? {
        Some(b) => b,
        None => return Err(SkillError::SkillNotFound(name.to_string())),
    };

    // Step 0 (round-6 fix) — clear any pre-existing sidecars for this
    // skill. Closes the round-6 audit's additive-not-synchronizing gap:
    // when admin bundle has DROPPED tool.wasm / templates / etc.,
    // re-materializing must remove the stale files. Cleared FIRST so
    // any subsequent write failure can't leave the agent worse off than
    // the pre-materialize state — the cleared sidecars belonged to the
    // prior bundle and are being explicitly removed regardless of which
    // new sidecars succeed. SKILL.md + .meta.yaml are NOT cleared (those
    // are write_active's domain, written LAST in Step 2 below).
    to.clear_skill_sidecars(name).await?;

    // Step 1 — Write sidecars FIRST (tool.wasm, tool.capabilities.json,
    // templates, source_scripts). If any of these fail, the agent's
    // prior active SkillBlob is untouched.
    if let Some(wasm) = bundle.tool_wasm.as_ref() {
        to.write_skill_sidecar(name, SkillSidecar::ToolWasm, wasm)
            .await?;
    }
    if let Some(caps) = bundle.tool_capabilities.as_ref() {
        to.write_skill_sidecar(name, SkillSidecar::ToolCapabilitiesJson, caps.as_bytes())
            .await?;
    }
    for (filename, body) in &bundle.templates {
        to.write_skill_sidecar(
            name,
            SkillSidecar::Template(filename.clone()),
            body.as_bytes(),
        )
        .await?;
    }
    for (filename, body) in &bundle.source_scripts {
        to.write_skill_sidecar(
            name,
            SkillSidecar::SourceScript(filename.clone()),
            body.as_bytes(),
        )
        .await?;
    }

    // Step 2 — Write the SkillBlob (SKILL.md + .meta.yaml) LAST via
    // write_active. The materialized skill takes the admin bundle's
    // provenance + trust_level (typically Imported + Untrusted).
    let blob = SkillBlob {
        skill_id: name.to_string(),
        version: 1,
        content: bundle.skill_md.clone(),
        tags: Vec::new(),
        provenance: bundle.provenance.clone(),
        trust_level: bundle.trust_level.clone(),
    };
    to.write_active(&blob).await?;

    Ok(())
}
