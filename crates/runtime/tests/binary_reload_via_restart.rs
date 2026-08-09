//! AC-13 closure — binary reload requires runtime restart.
//!
//! Two materializers for the umbrella §3.3 T21 row:
//! - T51 (behavioral + compile-time pin): API contract witness. Compile-time signature
//!   pins ensure `ComponentRuntime::load_component` / `load_component_spec` retain their
//!   byte-taking (not path-taking) signatures. Behavioral witness demonstrates that
//!   explicit re-load is required to pick up source-file changes. The byte-capture
//!   portion is tautological **under the current `LoadedComponent` design** (direct
//!   Arc-backed `wasmtime::component::Component` newtype, no interior-mutability
//!   primitive, no subscribe-to-changes API) — the load-bearing evidence sits on the
//!   compile-time pins + the distinct-load `BindgenExportLookup` witness; see the
//!   in-test inline rustdoc for the full framing.
//! - T52 (architectural tripwire): `crates/runtime/src/` and `crates/cli/src/` contain
//!   no hot-reload API surface and no file-watcher naming conventions on agent-binary
//!   `.wasm` files. Recursive walker (Slice Z T50 pattern) with negative-contains
//!   assertions. **T52 is not a complete audit** — it is calibrated for net-new
//!   prospective naming conventions, and a motivated author could pick novel names
//!   that evade the 4-literal FORBIDDEN list (see §3.3 T52 row; `behavior.wasm` was
//!   reconciled out by MODULE-001-AC-20's 024 loader — a one-shot boot load is not
//!   hot-reload).
//!
//! AC-13 scope notes:
//! - Clause (b) — "no mid-run hot reload" — is what this file verifies.
//! - Clause (a) — "binary changes require runtime restart (positive flow)" — is
//!   architecturally-entailed by (b); positive CLI E2E is deferred
//!   (advance start/stop are stubs today per crates/cli/src/main.rs:33+).

use advance_runtime::{
    component_loader::{ComponentLoadError, InstantiateError},
    component_spec::ComponentSpec,
    config::WasmConfig,
    wit_bindings::advance::runtime::types as wit_types,
    ComponentCtx, ComponentRuntime, LoadedComponent,
};
use wit_component::ComponentEncoder;

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time signature pins — the non-tautological core of T51's regression
// protection. A future PR that changes these signatures (e.g., replaces
// `&[u8]` with `&Path`) will fail the build at these lines.
// ─────────────────────────────────────────────────────────────────────────────
#[allow(dead_code)]
const _LOAD_COMPONENT_SIGNATURE_PIN: fn(
    &ComponentRuntime,
    &[u8],
) -> Result<LoadedComponent, ComponentLoadError> = ComponentRuntime::load_component;

#[allow(dead_code)]
const _LOAD_COMPONENT_SPEC_SIGNATURE_PIN: fn(
    &ComponentRuntime,
    &ComponentSpec,
) -> Result<LoadedComponent, ComponentLoadError> = ComponentRuntime::load_component_spec;

const CORE_MODULE_BYTES: &[u8] = include_bytes!("fixtures/guest-rust-minimal.core.wasm");

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn ctx() -> ComponentCtx {
    ComponentCtx::new("agent-ac13".into(), "trace-ac13".into(), Vec::new())
}

fn guest_rust_component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_MODULE_BYTES)
        .expect("core module accepted")
        .encode()
        .expect("component encoded")
}

#[tokio::test]
async fn module_001_t51_byte_capture_witness() {
    // Compile-time pins above establish: load API is byte-taking only. The runtime
    // portion demonstrates that after load, the returned LoadedComponent is
    // independent of the source file (no implicit refresh on file mutation).
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let path = tmpdir.path().join("behavior.wasm");

    let bytes_a = guest_rust_component_bytes();
    std::fs::write(&path, &bytes_a).expect("write bytes_a");

    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let loaded_a = runtime
        .load_component(&std::fs::read(&path).expect("read A"))
        .expect("load A");

    let cfg = wit_types::ComponentConfig {
        id: "t51".into(),
        config_data: None,
        trigger_context: None,
    };
    let (bindings, mut store) = runtime
        .instantiate_advance_host_async(&loaded_a, ctx())
        .await
        .expect("instantiate A (baseline)");
    let init_a = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("call_init A")
        .expect("init A Ok");
    assert_eq!(
        init_a,
        vec![0xAD, 0x11, 0xCE, 0x01],
        "baseline sentinel mismatch"
    );

    // Swap the source file with a structurally distinct empty Component (no
    // advance-host exports). No sleep — the assertion below is correct at 0ms
    // **under the current LoadedComponent design**: the newtype wraps
    // `wasmtime::component::Component` directly (Arc-backed compiled artifact,
    // no interior-mutability primitive, no subscribe-to-changes API surface).
    // A future refactor that added interior mutability (e.g., `Arc<Mutex<Component>>`
    // or a `watch_component`-style subscribe API) may surface through T52's
    // FORBIDDEN tripwire if it uses any of the 4 pinned naming conventions
    // (`reload_component`, `watch_component`, etc.), but T52 is not a complete
    // audit — a motivated author could pick novel names that evade the
    // forbidden list. The load-bearing evidence of T51 sits on the compile-time
    // signature pins (top of file) + the distinct-load `BindgenExportLookup`
    // witness at the bottom; this middle assertion is a byte-capture witness
    // at the API-contract layer, not a regression catcher.
    let bytes_b = wat::parse_str("(component)").expect("wat compile empty");
    std::fs::write(&path, &bytes_b).expect("write bytes_b");

    // Re-instantiate the ORIGINAL loaded_a handle. Witness: unchanged semantics.
    let (bindings2, mut store2) = runtime
        .instantiate_advance_host_async(&loaded_a, ctx())
        .await
        .expect("re-instantiate A (post-swap)");
    let init_a2 = bindings2
        .advance_runtime_message_driven()
        .call_init(&mut store2, &cfg)
        .await
        .expect("call_init A-post-swap")
        .expect("init A-post-swap Ok");
    assert_eq!(
        init_a2,
        vec![0xAD, 0x11, 0xCE, 0x01],
        "byte-capture witness failed: loaded_a behavior changed after source-file swap"
    );

    // Distinct-load witness: an EXPLICIT re-load picks up the new bytes and produces
    // a materially different LoadedComponent (one that lacks advance-host exports).
    let loaded_b = runtime
        .load_component(&std::fs::read(&path).expect("read B"))
        .expect("load B");
    let inst_b = runtime
        .instantiate_advance_host_async(&loaded_b, ctx())
        .await;
    let err_b = match inst_b {
        Ok(_) => panic!(
            "distinct-load witness failed: empty Component unexpectedly instantiated \
             successfully against advance-host world"
        ),
        Err(e) => e,
    };
    assert!(
        matches!(err_b, InstantiateError::BindgenExportLookup(_)),
        "distinct-load witness failed: expected BindgenExportLookup for empty \
         Component; got {err_b:?}"
    );
}

#[test]
fn module_001_t52_no_hot_reload_api_in_module_001_src() {
    // Walker roots: MODULE-001's source crates per §2.1 Module Boundary +
    // ARCHITECTURE.md §4.1. shared-types is omitted (pure data-type crate;
    // no watcher plausible there).
    let ws_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ parent")
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let runtime_src = ws_root.join("crates/runtime/src");
    let cli_src = ws_root.join("crates/cli/src");

    let mut runtime_files: Vec<std::path::PathBuf> = Vec::new();
    walk(&runtime_src, &mut runtime_files);
    let mut cli_files: Vec<std::path::PathBuf> = Vec::new();
    walk(&cli_src, &mut cli_files);

    // Anchors guard against a refactor/rename silently emptying the walker.
    assert!(
        runtime_files.iter().any(|p| p
            .file_name()
            .map(|n| n == "component_loader.rs")
            .unwrap_or(false)),
        "walker did not reach runtime/src/component_loader.rs"
    );
    assert!(
        cli_files
            .iter()
            .any(|p| p.file_name().map(|n| n == "main.rs").unwrap_or(false)),
        "walker did not reach cli/src/main.rs"
    );

    // MODULE-001-AC-20 (024, 2026-06-19): `behavior.wasm` was reconciled OUT of this
    // list. The production deploy loader (cli `start.rs`) now references the
    // materialized `behavior.wasm` for a ONE-SHOT boot load (AC-13 clause (a) — "read
    // exactly once at boot"), which is loading, NOT hot-reload. The no-mid-run-hot-
    // reload guarantee (clause (b)) stays carried by T51's byte-capture + compile-time
    // signature pins and these 4 reload/watch verbs (the real hot-reload smells).
    const FORBIDDEN: &[&str] = &[
        "reload_component",
        "watch_component",
        "reload_agent_binary",
        "reload_agent_behavior",
    ];

    for rs in runtime_files.iter().chain(cli_files.iter()) {
        let contents = std::fs::read_to_string(rs).unwrap_or_else(|e| panic!("read {rs:?}: {e}"));
        for needle in FORBIDDEN {
            assert!(
                !contents.contains(needle),
                "{} contains forbidden literal {:?} — AC-13 tripwire fired \
                 (a hot-reload API surface or agent-binary file-watcher appears to \
                 have been introduced into MODULE-001's source crates)",
                rs.display(),
                needle
            );
        }
    }
}

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let iter = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in iter {
        let entry = entry.unwrap_or_else(|e| panic!("dir entry in {dir:?}: {e}"));
        let ft = entry
            .file_type()
            .unwrap_or_else(|e| panic!("file_type {:?}: {e}", entry.path()));
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            walk(&path, out);
        } else if ft.is_file() && path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}
