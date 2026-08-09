//! AC-01 — Component primitive load coverage for each of the 5 execution modes.
//!
//! Five integration tests (T31..T35), one per `ComponentType` variant
//! (Agent / Cron / Watcher / Daemon / Task), each builds a `ComponentSpec`
//! with a minimal valid `(component)` WAT binary and asserts
//! `ComponentRuntime::load_component_spec(&spec)` returns `Ok(LoadedComponent)`.
//!
//! Closes MODULE-001-AC-01 against literal criterion: *"Component primitive
//! defined and loaded for each of the 5 execution modes (Agent, Cron, Watcher,
//! Daemon, Task)"*.
//!
//! `load_component_spec` (`crates/runtime/src/component_loader.rs`) is
//! type-agnostic by design — it consumes only `spec.binary` and never reads
//! `spec.r#type`. The 5-test pattern provides failure isolation, parametric
//! AC coverage matching the criterion's per-mode enumeration, and a
//! future-proofing scaffold against accidental ComponentType-discrimination
//! regressions in the loader.
//!
//! T31 (Agent variant) overlaps intentionally with the existing
//! `tests/component_spec.rs::t30_load_component_spec_loads_valid_binary` (AC-05)
//! — T30 verifies the loader accepts a single ComponentSpec; T31..T35 verify
//! the integration boundary handles every `ComponentType` enum variant the
//! framework defines.

use advance_runtime::component_loader::{ComponentRuntime, LoadedComponent};
use advance_runtime::component_spec::ComponentSpec;
use advance_runtime::config::WasmConfig;
use advance_shared_types::{capability::CapabilityId, component::ComponentType};

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn make_spec(id: &str, ct: ComponentType, binary: Vec<u8>) -> ComponentSpec {
    ComponentSpec {
        id: id.to_string(),
        r#type: ct,
        capabilities: vec![CapabilityId::from("cap-fs")],
        binary,
    }
}

fn assert_loads_for(ct: ComponentType, id: &str) {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let bytes = wat::parse_str("(component)").expect("wat compile");
    let spec = make_spec(id, ct, bytes);
    let loaded: LoadedComponent = runtime
        .load_component_spec(&spec)
        .unwrap_or_else(|err| panic!("load_component_spec failed for {id} ({ct:?}): {err:?}"));
    let _: &wasmtime::component::Component = loaded.component();
}

#[test]
fn t31_load_agent_mode() {
    assert_loads_for(ComponentType::Agent, "agent-min");
}

#[test]
fn t32_load_cron_mode() {
    assert_loads_for(ComponentType::Cron, "cron-min");
}

#[test]
fn t33_load_watcher_mode() {
    assert_loads_for(ComponentType::Watcher, "watcher-min");
}

#[test]
fn t34_load_daemon_mode() {
    assert_loads_for(ComponentType::Daemon, "daemon-min");
}

#[test]
fn t35_load_task_mode() {
    assert_loads_for(ComponentType::Task, "task-min");
}
