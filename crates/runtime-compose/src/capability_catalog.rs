//! The capability catalog shared by `advance pack install` (`advance-cli`) and the
//! Client API packs family ([`crate::client_api_packs`]): both wrap their approval
//! strategy in `CatalogCheckedApproval` over this catalog, so an unknown
//! requirement is refused before any decision.

use advance_pack_manager::{InMemoryPackRegistry, PackError, StaticCapabilityCatalog};

use crate::agent_config::KNOWN_CAPABILITIES;

/// The catalog a pack's `required-capabilities` are checked against at install (CLI and
/// Client API alike): exactly the runtime's capability names. A pack never adds one.
pub fn capability_catalog() -> StaticCapabilityCatalog {
    build_capability_catalog_with(&InMemoryPackRegistry::new(std::path::PathBuf::new()), &[])
        .expect("KNOWN-only catalog")
}

/// KNOWN ∪ `extension_capabilities`. Pack resource capabilities are retired;
/// `registry` is accepted so the installer can pass the live registry.
pub fn build_capability_catalog_with(
    registry: &InMemoryPackRegistry,
    extension_capabilities: &[String],
) -> Result<StaticCapabilityCatalog, PackError> {
    let _ = registry;
    Ok(StaticCapabilityCatalog::new(
        KNOWN_CAPABILITIES
            .iter()
            .copied()
            .map(str::to_string)
            .chain(extension_capabilities.iter().cloned()),
    ))
}
