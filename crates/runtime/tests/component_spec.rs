//! Integration tests for the `ComponentSpec` primitive (Slice T, REQ-020).

use advance_runtime::component_loader::{ComponentRuntime, LoadedComponent};
use advance_runtime::component_spec::ComponentSpec;
use advance_runtime::config::WasmConfig;
use advance_shared_types::{capability::CapabilityId, component::ComponentType};

fn sample_spec(binary: Vec<u8>) -> ComponentSpec {
    ComponentSpec {
        id: "agent-alpha".to_string(),
        r#type: ComponentType::Agent,
        capabilities: vec![CapabilityId::from("cap-fs"), CapabilityId::from("cap-llm")],
        binary,
    }
}

#[test]
fn t29_serde_round_trip_preserves_fields() {
    let spec = sample_spec(vec![0x00, 0x61, 0x73, 0x6d]); // "\0asm" prefix
    let json = serde_json::to_string(&spec).expect("serialize");
    let decoded: ComponentSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.id, spec.id);
    assert_eq!(decoded.r#type, spec.r#type);
    assert_eq!(decoded.capabilities, spec.capabilities);
    assert_eq!(decoded.binary, spec.binary);
}

#[test]
fn t29_deny_unknown_fields_rejects_extras() {
    // Extra field "rogue" must fail deserialization under #[serde(deny_unknown_fields)].
    let rogue = r#"{
        "id": "agent-alpha",
        "type": "agent",
        "capabilities": ["cap-fs"],
        "binary": [0, 97, 115, 109],
        "rogue": "not allowed"
    }"#;
    let result: Result<ComponentSpec, _> = serde_json::from_str(rogue);
    assert!(result.is_err(), "deny_unknown_fields must reject extras");
}

#[test]
fn t30_load_component_spec_loads_valid_binary() {
    let wasm_cfg = WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    };
    let runtime = ComponentRuntime::new(&wasm_cfg).expect("runtime");
    let bytes = wat::parse_str("(component)").expect("wat compile");
    let spec = sample_spec(bytes);
    let loaded: LoadedComponent = runtime.load_component_spec(&spec).expect("load spec");
    // Compile-time check the return type is LoadedComponent; sanity via ref.
    let _: &wasmtime::component::Component = loaded.component();
}

#[test]
fn component_spec_clone_preserves_all_fields() {
    let spec = sample_spec(vec![0x01, 0x02, 0x03]);
    let cloned = spec.clone();
    assert_eq!(cloned.id, spec.id);
    assert_eq!(cloned.binary, spec.binary);
}
