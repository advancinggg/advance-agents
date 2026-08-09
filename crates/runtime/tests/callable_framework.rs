//! AC-16 — Callable Framework three-layer architectural enforcement at the
//! runtime-host layer (REQ-034 / PRD §3.9 / ARCH §8 Decision 15).
//!
//! This file materializes the MODULE-001 §3.3 T17 umbrella row via three
//! tests (T48 / T49 / T50). It pins the **structural** presence of the
//! enforcement pipeline at the code level. Runtime-time closure-body
//! invocation semantics (L1 GrantCheck trap-on-Deny, CircuitBreaker open
//! branch) are not yet guarded by any existing test: the T25/T26 rows in
//! MODULE-001 §3.3 today cover only the inject-time closure-binding path
//! (see MODULE-001 §3.6 bullet beginning `CapabilityInjector invocation-path
//! tests (T25, T26)`). A future slice must ship a driving WAT export that
//! invokes an imported host function from a WASM guest; only then can
//! T25/T26 be extended to assert the `capability-denied: {reason}` /
//! `circuit-breaker: {reason}` return paths.
//!
//! - **T48 (Layer 1)**: constructor-signature pin + 3 canonical-import
//!   dep-inversion pins + end-to-end `inject` exercise.
//! - **T49 (Layer 2)**: trait-method fn-body bind + TypeId anti-alias
//!   tripwire on `CallableInventoryReader`.
//! - **T50 (Layer 3)**: filesystem tripwire scanning `crates/runtime/src/`
//!   for forbidden Layer 3 assembly literals.

use std::any::TypeId;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{
    BreakerError, BreakerEvent, BreakerScope, CircuitBreaker, CircuitBreakerBus,
};
use advance_runtime::component_loader::ComponentRuntime;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
    InMemoryHostRegistry,
};
use advance_shared_types::capability::{
    CapParams, CapRequest, CapabilityId, GrantDecision, McpToolEntry, ToolEntry,
};
use advance_shared_types::component::ComponentType;
use advance_shared_types::traits::{CallableInventoryReader, GrantCheck};
use wasmtime::component::Val;

// ---------------- Mocks ----------------

struct AlwaysOkHandler;
impl HostFunctionHandler for AlwaysOkHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct MockGrantAllow;
impl GrantCheck for MockGrantAllow {
    fn check(
        &self,
        _agent_id: &str,
        _capability: &str,
        _function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct MockBreakerClosed;
impl CircuitBreakerBus for MockBreakerClosed {
    fn is_open_capability(&self, _cap: &str) -> Option<String> {
        None
    }
    fn is_open_component_type(&self, _kind: ComponentType) -> Option<String> {
        None
    }
    fn is_open_agent(&self, _agent_id: &str) -> Option<String> {
        None
    }
    fn open(&self, _b: CircuitBreaker) -> Result<(), BreakerError> {
        Ok(())
    }
    fn close(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        Ok(())
    }
    fn half_open(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        Ok(())
    }
    fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<BreakerEvent> {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        rx
    }
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

// ======================================================================
// T48 — Layer 1: L0 HostRegistry + L1 dependency-inverted GrantCheck gate
//       structural wiring present.
// ======================================================================

// Constructor-signature pin. Any change to CapabilityInjector::new's parameter
// count, argument types, or return type fails to compile here.
const _T48_CTOR_SHAPE: fn(
    Arc<dyn HostRegistry>,
    Arc<dyn GrantCheck>,
    Arc<dyn CircuitBreakerBus>,
) -> CapabilityInjector = CapabilityInjector::new;

#[test]
fn module_001_t48_layer1_capability_enforcement_wiring() {
    // Public-module-path pins: if any of these three traits moves off its
    // current canonical path (and no pub-use re-export is added), the use
    // statements at the top of this file fail to resolve.
    //   - advance_shared_types::traits::GrantCheck
    //   - advance_runtime::host_registry::HostRegistry
    //   - advance_runtime::circuit_breaker::CircuitBreakerBus

    // End-to-end inject-time exercise — proves L0 lookup + Linker::instance(ns)
    // + func_new_async closure binding all succeed. The closure BODY's L1 /
    // breaker invocation is the waived T25/T26 follow-on scope (see §3.6).
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    registry.register(HostFunctionSpec {
        capability: "t48-cap".to_string(),
        namespace: "t48-ns".to_string(),
        name: "ping".to_string(),
        handler: Arc::new(AlwaysOkHandler),
        idempotent: true,
    });

    let grant_check: Arc<dyn GrantCheck> = Arc::new(MockGrantAllow);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(MockBreakerClosed);

    let injector = CapabilityInjector::new(registry, grant_check, breaker);

    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker: wasmtime::component::Linker<ComponentCtx> =
        wasmtime::component::Linker::new(runtime.host_engine_handle().engine());

    let caps = vec![CapRequest {
        capability: CapabilityId::from("t48-cap"),
    }];

    // Inject-time Ok(()) proves L0 lookup + Linker::instance(ns) + func_new_async
    // closure binding. It does NOT prove the closure BODY's L1/breaker invocation;
    // that remains pending a future slice with a driving WAT export (the extended
    // T25/T26 scope). See the module rustdoc above.
    injector
        .inject(&mut linker, &caps)
        .expect("inject-time L0 lookup + Linker::instance + func_new_async binding must succeed");
}

// ======================================================================
// T49 — Layer 2: CallableInventoryReader exposes two distinct methods with
//       two distinct return types (anti-alias tripwire).
// ======================================================================

// Step 1: fn-body binds — calling the trait methods inside the binder means a
// rename / removal / signature change of either method fails at compile time.
const _T49_CHECK_WASM_TOOLS: fn(&dyn CallableInventoryReader, &str) -> Vec<ToolEntry> = {
    fn check(r: &dyn CallableInventoryReader, agent_id: &str) -> Vec<ToolEntry> {
        r.list_wasm_tools(agent_id)
    }
    check
};
const _T49_CHECK_MCP_TOOLS: fn(&dyn CallableInventoryReader, &str) -> Vec<McpToolEntry> = {
    fn check(r: &dyn CallableInventoryReader, agent_id: &str) -> Vec<McpToolEntry> {
        r.list_mcp_tools(agent_id)
    }
    check
};

#[test]
fn module_001_t49_layer2_wasm_and_mcp_tools_distinct_types() {
    // Step 2 — anti-alias tripwire. Catches `pub type McpToolEntry = ToolEntry`
    // alias collapse (which step 1 would NOT catch because fn-pointer sigs
    // compare structurally).
    //
    // Not caught here: newtype-wrap collapse (`pub struct McpToolEntry(ToolEntry)`)
    // — preserves TypeId distinctness. Field-level non-merge (McpToolEntry's
    // server_id) is owned by MODULE-017-AC-30 + shared-types serde round-trip
    // tests, not this tripwire.
    assert_ne!(
        TypeId::of::<ToolEntry>(),
        TypeId::of::<McpToolEntry>(),
        "CONTRACT-165: ToolEntry and McpToolEntry must remain distinct nominal types",
    );
}

// ======================================================================
// T50 — Layer 3: runtime-host source tree holds no context-assembly strings.
// ======================================================================

const T50_FORBIDDEN_LITERALS: &[&str] = &["# Available Tools", "Available Delegates"];
const T50_ANCHOR_FILE: &str = "capability_injector.rs";

fn t50_collect_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("T50 walker: read_dir({}) failed: {e}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| {
                panic!(
                    "T50 walker: dir entry read failed in {}: {e}",
                    dir.display()
                )
            });
            let file_type = entry.file_type().unwrap_or_else(|e| {
                panic!(
                    "T50 walker: file_type({}) failed: {e}",
                    entry.path().display()
                )
            });
            // Skip symlinks: avoids unbounded chains. Uses DirEntry::file_type
            // (does NOT follow symlinks) — plain metadata() WOULD follow them
            // and silently bypass the guard.
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rs")
            {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn module_001_t50_layer3_no_context_assembly_strings_in_runtime_src() {
    // env!("CARGO_MANIFEST_DIR") is baked in at compile time and resolves to
    // the advance-runtime crate root since this is an integration test of
    // that crate. CWD-independent at run time.
    let src_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = t50_collect_rs_files(&src_dir);

    // Directory-reached anchor — if the walker resolved to an empty or wrong
    // directory, this assertion fails loudly. capability_injector.rs is a
    // known-present file in crates/runtime/src/.
    assert!(
        files
            .iter()
            .any(|p| p.file_name().and_then(|s| s.to_str()) == Some(T50_ANCHOR_FILE)),
        "T50 walker: anchor file '{T50_ANCHOR_FILE}' not found under {} — walker did not reach the expected directory (found {} files)",
        src_dir.display(),
        files.len()
    );

    for path in &files {
        let contents = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!("T50 walker: read_to_string({}) failed: {e}", path.display())
        });
        for forbidden in T50_FORBIDDEN_LITERALS {
            assert!(
                !contents.contains(forbidden),
                "T50 tripwire: forbidden Layer 3 assembly literal {forbidden:?} found in {}",
                path.display()
            );
        }
    }
}
