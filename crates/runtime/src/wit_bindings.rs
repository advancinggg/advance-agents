//! Slice X — host-side typed bindings generated from `crates/runtime/wit/advance.wit`.
//!
//! `wasmtime::component::bindgen!` emits `AdvanceHost` + `AdvanceHostPre<T>` at this
//! module's top level along with the typed-export accessors under
//! `exports::advance::runtime::{message_driven, runnable}`. The `exports:` config
//! sets `default: async` so all guest-export call methods (`call_init`,
//! `call_handle_message`, `call_run`) return `impl Future` and require an async
//! Wasmtime store.
//!
//! No `imports:` block — the `advance-host` world declares no imports.
//! No `with:` block — the WIT has no resources.
//!
//! **Slice m001-slice-bootstrap (2026-05-28)** adds sibling bindings for
//! `world advance-host-with-capabilities` in the [`with_caps`] module below.
//! That world imports `agent-messaging` (so guests can call send/heartbeat/
//! await-replies host fns). The generated **Host trait + `add_to_linker`**
//! helpers stay UNUSED — the host never implements the import trait. **However
//! (await-leg slice 1, 2026-06-21) the generated TYPES under
//! [`with_caps::advance::runtime::agent_messaging`] ARE now consumed**:
//! `CapabilityInjector::inject` registers `await-replies`/`heartbeat` through
//! the TYPED `LinkerInstance::func_wrap_async` over those structs (Wasmtime's
//! typed canonical-ABI lift fixes the `list<await-request>` variant shape the
//! untyped `func_new_async` `&[Val]` lift gets wrong), then host-builds the
//! canonical `Val` the existing reply-tracker decoder consumes. Every other
//! capability's host fn still wires dynamically via `func_new_async`. The
//! generated `AdvanceHostWithCapabilities` typed handle provides the typed
//! `call_init` / `call_handle_message` / `call_run` accessors over guests
//! that target the new world. Bindings are isolated in a nested module to
//! avoid top-level type-name collisions with `AdvanceHost` /
//! `AdvanceHostPre`.

wasmtime::component::bindgen!({
    path: "wit/advance.wit",
    world: "advance-host",
    exports: { default: async },
});

// Re-export only the nested module path so callers can write
// `crate::wit_bindings::message_driven::Guest` etc. Do NOT re-export
// AdvanceHost / AdvanceHostPre — the macro already emits them at this module's
// top level; an additional `pub use` would trigger E0255 "name defined multiple
// times".
pub use exports::advance::runtime::{message_driven, runnable};

/// Slice m001-slice-bootstrap sibling bindgen for `world advance-host-with-capabilities`.
///
/// Isolated module to avoid AdvanceHost / AdvanceHostPre type-name collisions
/// with the top-level `advance-host` world bindings above. Emits
/// `AdvanceHostWithCapabilities` + `AdvanceHostWithCapabilitiesPre<T>` plus
/// the same `exports::advance::runtime::{message_driven, runnable}` accessor
/// hierarchy nested inside this module.
///
/// The new world imports `agent-messaging` (declared in the same package
/// `advance:runtime@0.1.0` — single-path bindgen). The macro generates
/// import bindings (Host trait + add_to_linker helpers + the interface
/// TYPES). The host does NOT implement the generated Host trait / call
/// `add_to_linker`; the linker is populated by `CapabilityInjector::inject`
/// before `instantiate_pre`. As of await-leg slice 1 (2026-06-21) that
/// population is split: `await-replies`/`heartbeat` register via the TYPED
/// `LinkerInstance::func_wrap_async` (consuming the generated
/// `agent_messaging` TYPES), and every other host fn via the dynamic
/// `LinkerInstance::func_new_async`. Either way the bindgen
/// `AdvanceHostWithCapabilitiesPre::new(linker.instantiate_pre(...))` accepts
/// the pre-loaded linker transparently.
///
/// Default config is used. Wasmtime 43's component bindgen does not accept
/// `trappable_imports`; if a future caller skips the `CapabilityInjector::inject`
/// step the resulting `instantiate_pre` returns `Err(LinkerTypecheck(...))`
/// (no panic, no silent corruption — the typecheck rejects the
/// unsatisfied import as a normal error).
pub mod with_caps {
    wasmtime::component::bindgen!({
        path: "wit/advance.wit",
        world: "advance-host-with-capabilities",
        exports: { default: async },
    });
}

pub use with_caps::{AdvanceHostWithCapabilities, AdvanceHostWithCapabilitiesPre};
