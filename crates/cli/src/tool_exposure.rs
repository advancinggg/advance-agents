//! PACK-GAP-CLOSURE P2 (§3.3, #5 exposure leg) — reconcile the `tools[].name`
//! every installed pack resource-capability declares against the host-native
//! tools actually registered in the `LazyToolRegistry`.
//!
//! A resource-capability's tools are store-backed, so they can only exist as
//! host code ([`cap_tools::HostTool`]); a pack can DECLARE them but cannot ship
//! them. The composition root runs this at boot: declared ∩ registered →
//! `bound`; declared ∖ registered → `missing` (logged as a WARN, never blocking
//! — an agent simply does not see a tool nobody provides). Both lists are
//! sorted, de-duplicated names. A capability whose manifest no longer parses
//! (tampered after install) is reported in `errors` rather than silently
//! skipped.

use std::collections::BTreeSet;

use advance_pack_manager::{
    path_for_kind, resource_capability_tool_names, ComponentKind, PackRegistry,
};
use cap_tools::LazyToolRegistry;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposureReport {
    /// Declared by an installed resource-capability AND registered as a host tool.
    pub bound: Vec<String>,
    /// Declared but not registered (the runtime has no implementation).
    pub missing: Vec<String>,
    /// `"{pack}@{version}/resource-capabilities/{name}: {error}"` for manifests
    /// that failed to parse at reconcile time.
    pub errors: Vec<String>,
}

impl ExposureReport {
    /// One-line summary for the boot log.
    pub fn summary(&self) -> String {
        format!(
            "pack tool exposure: {} bound, {} missing{}",
            self.bound.len(),
            self.missing.len(),
            if self.errors.is_empty() {
                String::new()
            } else {
                format!(", {} unreadable capability manifests", self.errors.len())
            }
        )
    }
}

/// See the module docs.
pub async fn reconcile_pack_tool_exposure(
    tools: &LazyToolRegistry,
    packs: &dyn PackRegistry,
) -> ExposureReport {
    let host: BTreeSet<String> = tools.host_tool_ids().await.into_iter().collect();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    let mut errors = Vec::new();
    for pack in packs.list_installed() {
        let Some(entries) = packs.provides(&pack.name, &pack.version) else {
            continue;
        };
        for entry in entries
            .into_iter()
            .filter(|e| e.kind == ComponentKind::ResourceCapability)
        {
            let cap_dir = path_for_kind(
                &pack.install_path,
                ComponentKind::ResourceCapability,
                &entry.name,
            );
            match resource_capability_tool_names(&cap_dir) {
                Ok(names) => declared.extend(names),
                Err(e) => errors.push(format!(
                    "{}@{}/resource-capabilities/{}: {e}",
                    pack.name, pack.version, entry.name
                )),
            }
        }
    }
    let (bound, missing): (Vec<String>, Vec<String>) =
        declared.into_iter().partition(|n| host.contains(n));
    ExposureReport {
        bound,
        missing,
        errors,
    }
}
