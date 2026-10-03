//! The capability catalog shared by `advance pack install` (`advance-cli`) and the
//! Client API packs family ([`crate::client_api_packs`]): both wrap their approval
//! strategy in `CatalogCheckedApproval` over this catalog, so an unknown
//! requirement is refused before any decision.

use advance_pack_manager::StaticCapabilityCatalog;

use crate::agent_config::KNOWN_CAPABILITIES;

/// The catalog a pack's `required-capabilities` are checked against at install (CLI and
/// Client API alike): exactly the runtime's capability names. A pack never adds one.
pub fn capability_catalog() -> StaticCapabilityCatalog {
    StaticCapabilityCatalog::new(KNOWN_CAPABILITIES.iter().copied())
}
