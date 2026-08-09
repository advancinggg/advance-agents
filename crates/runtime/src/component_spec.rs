//! PRD §3.1 Component primitive — `ComponentSpec`.
//!
//! The four framework-level fields required by REQ-020 (id, type, capabilities,
//! binary). Decoupled from `wasmtime::component::Component` (the compiled
//! binary result): a `ComponentSpec` is the inert descriptor the runtime
//! consumes, instantiates from, and eventually dispatches via the two WIT
//! interfaces.
//!
//! NOT part of CONTRACT-001 (see MODULE-001 §2.3): CONTRACT-001 covers
//! HostRegistry + CapabilityInjector (host-fn registration + linker wrapping),
//! not the Component primitive data type.

use advance_shared_types::{capability::CapabilityId, component::ComponentType};

/// The Component primitive per PRD §3.1 / MODULE-001 REQ-020.
///
/// `binary` uses `#[serde(with = "serde_bytes")]` so JSON / CBOR / bincode
/// encode it as a compact byte sequence rather than the default JSON
/// array-of-integers representation.
///
/// `deny_unknown_fields` protects against field drift — when a manifest
/// source (pack installer, runtime-config discovery) hands us an unexpected
/// key it fails loud rather than silently dropping data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSpec {
    pub id: String,
    pub r#type: ComponentType,
    pub capabilities: Vec<CapabilityId>,
    #[serde(with = "serde_bytes")]
    pub binary: Vec<u8>,
}
