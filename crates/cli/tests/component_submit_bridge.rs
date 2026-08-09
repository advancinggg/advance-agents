//! CONTRACT-217 v0.2 → real scheduler/registry composition witness.

use std::sync::Arc;

use advance_cli::component_submit_bridge::SchedulerSubmitBridge;
use advance_cli::sensitive_params::RegistrySensitiveParamsSource;
use advance_event_bus::SensitiveParamsSource;
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::{InMemoryComponentSubmitApi, SubmitSubsetGate};
use advance_shared_types::agent_tree::Capability;
use cap_lifecycle::{ComponentSubmitConfigV2, ComponentSubmitGate};
use serde_json::json;
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-legacy3-sensitive.core.wasm");

struct AllowSubset;
impl SubmitSubsetGate for AllowSubset {
    fn check(
        &self,
        _submitter: &str,
        _requested: &[Capability],
    ) -> Result<(), advance_scheduler::SpawnError> {
        Ok(())
    }
}

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .unwrap()
        .encode()
        .unwrap()
}

#[tokio::test]
async fn v02_submit_persists_complete_sensitive_declaration_and_publishes_live_source() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Arc::new(
        ComponentRegistry::open_in(temp.path(), "components.db")
            .await
            .unwrap(),
    );
    let source = Arc::new(RegistrySensitiveParamsSource::empty());
    let api = Arc::new(
        InMemoryComponentSubmitApi::new()
            .with_registry(Arc::clone(&registry))
            .with_subset_gate(Arc::new(AllowSubset)),
    );
    let bridge = SchedulerSubmitBridge::new(api, Arc::clone(&source));
    let binary = component_bytes();
    let config = ComponentSubmitConfigV2::from_canonical_json(json!({
        "id": "legacy3-sensitive",
        "component-type": "task",
        "binary": binary,
        "capabilities": [],
        "output-dir": null,
        "trigger": null,
        "restart-policy": null,
        "delay": null,
        "initial-grants": null,
        "preset": null,
        "retry": null,
        "sensitive-params": ["api_key", "id", "event_type", "run_id"]
    }))
    .unwrap();

    let id = bridge
        .submit_component_v2("agent:root", config)
        .await
        .expect("real scheduler admission");
    assert_eq!(id.0, "legacy3-sensitive");

    let rows = registry.list().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].submit_config.sensitive_params,
        ["api_key", "id", "event_type", "run_id"]
    );
    let published = source
        .names_for("legacy3-sensitive")
        .expect("post-commit declaration published without restart");
    for name in ["api_key", "id", "event_type", "run_id"] {
        assert!(published.contains(name));
    }
}
