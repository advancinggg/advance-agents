//! HostRegistry (CONTRACT-001, data-only portion) — source of truth for
//! "which host functions exist" per MODULE-001 §1.4.1 + §2.3.
//!
//! `CapabilityInjector` (the WASM linker wrapping side of CONTRACT-001) is
//! deferred to a future slice that requires Wasmtime, MODULE-013 GrantCheck,
//! and EventBusEmit. This module lands only the pure data-store + trait
//! contract so downstream modules can begin declaring host functions without
//! waiting for Wasmtime integration.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use advance_shared_types::capability::CapabilityId;
use wasmtime::component::Val;

/// Call-context bundle passed to every host-function invocation.
///
/// Owned fields (no lifetimes) — simpler across the `async move` boundary
/// inside `CapabilityInjector::inject`'s per-call closure.
///
/// Slice C (2026-05-09) added `run_id` + `iteration` (additive on CONTRACT-001).
/// The fields are populated from `ComponentCtx.run_id` / `ComponentCtx.iteration`
/// via `ComponentCtx::to_host_call_context`. Producer-side wiring of these
/// `ComponentCtx` fields by M008 RunManager / M015 AutoMode at WASM Store
/// construction time remains deferred — see MODULE-001 §3.6.
#[derive(Debug, Clone)]
pub struct HostCallContext {
    pub agent_id: String,
    pub trace_id: String,
    /// Host-authenticated CONTRACT-216 turn key.  It is stamped from the
    /// runtime-owned `ComponentCtx` when a mailbox turn is activated and is
    /// never decoded from guest parameters or message context.
    pub turn_id: Option<String>,
    pub capability: String,
    /// `"{namespace}::{name}"` — for logging / error messages only.
    pub function: String,
    /// Slice C: business-execution wave id (M008 `run_id` per CONTRACT-073).
    /// Read by host_fn handlers (e.g. MODULE-009 cap-llm) into emitted event
    /// payloads (`event.run_id`). `None` until producer-side wiring lands.
    pub run_id: Option<String>,
    /// Slice C: per-iteration counter inside a run (M015 AutoMode loop tick).
    /// Conditionally injected into `llm.request` / `llm.response` event
    /// payloads when `Some`. `None` until producer-side wiring lands.
    pub iteration: Option<u32>,
}

/// Errors returned by concrete `HostFunctionHandler` implementations.
///
/// The `From<HostCallError> for wasmtime::Error` impl lets the injector's
/// outer closure propagate handler failures into the Wasmtime guest as
/// guest-visible traps.
#[derive(Debug)]
pub enum HostCallError {
    /// Host-side handler body reported an error (arbitrary string).
    HandlerError(String),
    /// A Wasmtime operation inside the handler returned an error.
    WasmError(wasmtime::Error),
}

impl std::fmt::Display for HostCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostCallError::HandlerError(s) => write!(f, "host handler error: {s}"),
            HostCallError::WasmError(e) => write!(f, "host wasmtime error: {e}"),
        }
    }
}

impl std::error::Error for HostCallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HostCallError::HandlerError(_) => None,
            HostCallError::WasmError(e) => Some(e.root_cause()),
        }
    }
}

// NOTE: no manual `impl From<HostCallError> for wasmtime::Error`.
// `wasmtime::Error` is `anyhow::Error`, which provides the blanket
// `impl<E: std::error::Error + Send + Sync + 'static> From<E>`; since
// `HostCallError` implements `Error + Send + Sync + 'static`, the blanket
// already covers the conversion. A manual impl would conflict (E0119).

/// Maximum number of distinct capabilities a single registry can hold.
/// Protects against accidental or compromised boot-time registrant loops
/// that would otherwise grow the backing map without bound.
pub const MAX_CAPABILITIES: usize = 1024;

/// Maximum number of specs permitted under a single capability.
pub const MAX_SPECS_PER_CAPABILITY: usize = 256;

/// Maximum length for capability / namespace / name strings in a spec.
pub const MAX_SPEC_STRING_LEN: usize = 256;

/// Real async callable trait for host function implementations (Slice T).
///
/// Slice H shipped this as a zero-method marker so `HostFunctionSpec.handler`
/// could be populated with typed stubs while Wasmtime integration was pending.
/// Slice T promotes it to a proper async callable matching Wasmtime 43's
/// `LinkerInstance::func_new_async` dynamic-dispatch shape: owned `Vec<Val>`
/// params, owned return `Vec<Val>`. The trait method returns `Pin<Box<dyn
/// Future + Send + 'static>>` — concrete impls use `Box::pin(async move { ... })`
/// capturing only owned data.
///
/// The outer `func_new_async` closure (in `CapabilityInjector::inject`)
/// returns `Box<dyn Future + Send + 'a>` per Wasmtime's closure bound; the
/// inner `Pin<Box<_>>` return is awaitable and composes cleanly.
pub trait HostFunctionHandler: Send + Sync + 'static {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>;
}

/// Specification for a host function. Per MODULE-001 §2.3.
///
/// The registry is append-only: `register` does NOT deduplicate by
/// `(capability, namespace, name)` triple. Duplicate registrations are
/// caller-visible via `lookup` (returns all matching specs in insertion
/// order). The eventual `CapabilityInjector` slice will fail hard at
/// WASM linker wiring time if two specs with the same `(namespace, name)`
/// exist under a requested capability — callers should deduplicate at
/// their boundary.
#[derive(Clone)]
pub struct HostFunctionSpec {
    pub capability: String,
    pub namespace: String,
    pub name: String,
    pub handler: Arc<dyn HostFunctionHandler>,
    pub idempotent: bool,
}

impl std::fmt::Debug for HostFunctionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostFunctionSpec")
            .field("capability", &self.capability)
            .field("namespace", &self.namespace)
            .field("name", &self.name)
            .field("idempotent", &self.idempotent)
            .field("handler", &"<HostFunctionHandler>")
            .finish()
    }
}

/// CONTRACT-001 trait (data side). Concrete impl: `InMemoryHostRegistry`.
pub trait HostRegistry: Send + Sync {
    fn register(&self, spec: HostFunctionSpec);
    fn lookup(&self, cap: &str) -> Vec<HostFunctionSpec>;
}

/// Default `HostRegistry` implementation backed by an in-memory map.
pub struct InMemoryHostRegistry {
    caps: RwLock<HashMap<CapabilityId, Vec<HostFunctionSpec>>>,
}

impl Default for InMemoryHostRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryHostRegistry {
    pub fn new() -> Self {
        Self {
            caps: RwLock::new(HashMap::new()),
        }
    }

    /// Number of distinct capabilities currently registered. Testing helper.
    pub fn capability_count(&self) -> usize {
        self.caps.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl HostRegistry for InMemoryHostRegistry {
    fn register(&self, spec: HostFunctionSpec) {
        // Boot-time invariants — panic on violation. register() is a void
        // trait method so there is no error return path; these bounds
        // prevent a buggy or compromised in-process registrant from growing
        // the map without bound (DoS defense in depth).
        assert!(
            spec.capability.len() <= MAX_SPEC_STRING_LEN,
            "host_registry: capability string exceeds MAX_SPEC_STRING_LEN ({MAX_SPEC_STRING_LEN})"
        );
        assert!(
            spec.namespace.len() <= MAX_SPEC_STRING_LEN,
            "host_registry: namespace string exceeds MAX_SPEC_STRING_LEN ({MAX_SPEC_STRING_LEN})"
        );
        assert!(
            spec.name.len() <= MAX_SPEC_STRING_LEN,
            "host_registry: name string exceeds MAX_SPEC_STRING_LEN ({MAX_SPEC_STRING_LEN})"
        );

        let mut caps = self.caps.write().unwrap_or_else(|e| e.into_inner());

        // If this is a new capability, enforce the distinct-capability cap.
        // contains_key uses CapabilityId: Borrow<str> for &str probe; entry
        // takes the owned key, so we materialize CapabilityId only on insert.
        if !caps.contains_key(spec.capability.as_str()) {
            assert!(
                caps.len() < MAX_CAPABILITIES,
                "host_registry: MAX_CAPABILITIES ({MAX_CAPABILITIES}) exceeded"
            );
        }

        let bucket = caps
            .entry(CapabilityId::from(spec.capability.clone()))
            .or_default();
        assert!(
            bucket.len() < MAX_SPECS_PER_CAPABILITY,
            "host_registry: MAX_SPECS_PER_CAPABILITY ({MAX_SPECS_PER_CAPABILITY}) exceeded for capability {:?}",
            spec.capability
        );
        bucket.push(spec);
    }

    fn lookup(&self, cap: &str) -> Vec<HostFunctionSpec> {
        let caps = self.caps.read().unwrap_or_else(|e| e.into_inner());
        caps.get(cap).cloned().unwrap_or_default()
    }
}
