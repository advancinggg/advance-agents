//! `advance-runtime` — runtime host implementation for advance-agents.
//!
//! **Slice T** promotes the internal component loader to a public surface
//! (`ComponentRuntime` + opaque handle types), ships `CapabilityInjector`
//! (linker-wrapping half of CONTRACT-001), adds the `ComponentSpec` primitive
//! (PRD §3.1 / REQ-020), and migrates `HostFunctionHandler` from zero-method
//! marker to real async callable.
//!
//! **Slice D** adds `RuntimeConfig` loader + hot-reload (CONTRACT-003).
//! **Slice C** ships the `RuntimeLock` (single active runtime constraint).

// The one FFI module of this crate is `process_probe::ffi`;
// `module_001_ac32_runtime_unsafe_code_is_only_the_pid_probe_ffi` keeps it the only one.
#![deny(unsafe_code)]

pub mod agent_genui;
pub mod bootstrap;
pub mod capability_injector;
pub mod circuit_breaker;
pub mod component_loader;
pub mod component_spec;
pub mod config;
pub mod host_registry;
mod process_probe;
pub mod runtime_lock;
pub use runtime_lock::{inspect_lock, inspect_lock_with_policy, LockInspection};
pub mod wit_bindings;

// Top-level re-exports of the Slice T public surface.
// Slice AE: AllowAllGrantCheck is intentionally NOT re-exported (it's a
// pub(crate) construction-seam stub; see bootstrap.rs rustdoc).
pub use agent_genui::register_agent_genui;
pub use bootstrap::{BootstrapError, RuntimeHost, RuntimeHostBuilder};
pub use capability_injector::{add_wasi_to_linker, CapabilityInjector, ComponentCtx, HostError};
pub use component_loader::{
    ComponentLoadError, ComponentRuntime, EngineReport, EngineSettings, HostEngineHandle,
    InstantiateError, LoadedComponent, ToolEngineHandle, WasmBackend,
};
// Slice m001-slice-bootstrap (2026-05-28) — sibling bindgen exports for the new
// `advance-host-with-capabilities` world.
pub use component_spec::ComponentSpec;
pub use host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
    InMemoryHostRegistry,
};
pub use wit_bindings::{AdvanceHostWithCapabilities, AdvanceHostWithCapabilitiesPre};
