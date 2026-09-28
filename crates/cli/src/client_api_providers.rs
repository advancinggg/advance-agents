//! CLI-facing re-export of the production providers-family adapter. The implementation
//! moved to `advance_home::provider_admin` on 2026-09-28 (OPEN-CORE-BOUNDARY §7.4 hoist) so
//! product composition roots can install the same family; every path under this module keeps
//! resolving.

pub use advance_home::provider_admin::*;
