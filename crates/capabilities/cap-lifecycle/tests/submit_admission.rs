//! AC-29 point 3 (m017-slice-l) — `submit-component` admission rejects a binary
//! that does not export `runnable` (tools and runnables are mutually exclusive,
//! AC-11). Exercises the gate both directly (`admit_runnable_binary`) and
//! through the real `SubsetCheckedComponentSubmit` admission seam.
//!
//! Component fixtures are synthesized in-test via `wit_component::dummy_module`
//! (no committed `.wasm` classifies as `runnable` per the validator's matcher).

use std::sync::{Arc, Mutex};

use advance_shared_types::agent_tree::Capability;
use cap_lifecycle::{
    admit_runnable_binary, ComponentId, ComponentInfo, ComponentState, ComponentSubmitConfig,
    ComponentSubmitGate, SpawnError, SpawnerSubsetGate, SubsetCheckedComponentSubmit,
};
use wit_component::{embed_component_metadata, ComponentEncoder, StringEncoding};
use wit_parser::{ManglingAndAbi, Resolve};

// Canonical `advance:runtime` package so dummy_module emits exports mangled as
// the validator expects (`advance:runtime/runnable@0.1.0#run`, etc.).
const WIT_TOOL_EXPORTS: &str = r#"
package advance:runtime@0.1.0;

interface tool-exports {
    record method-info { name: string }
    record tool-description { description: string, methods: list<method-info> }
    describe: func() -> tool-description;
    execute: func(method: string, params: list<u8>) -> result<list<u8>, string>;
}

world tool-world { export tool-exports; }
"#;

const WIT_RUNNABLE: &str = r#"
package advance:runtime@0.1.0;

interface runnable { run: func(); }

world runnable-world { export runnable; }
"#;

fn build_dummy_component(wit: &str, world: &str) -> Vec<u8> {
    let mut resolve = Resolve::default();
    let pkg = resolve.push_str("inline.wit", wit).expect("WIT parses");
    let world = resolve
        .select_world(&[pkg], Some(world))
        .expect("world found");
    let mut core = wit_component::dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut core, &resolve, world, StringEncoding::UTF8)
        .expect("embed metadata");
    ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .expect("module accepted")
        .encode()
        .expect("component encoded")
}

fn config(id: &str, binary: Vec<u8>) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        id: id.to_string(),
        component_type: "task".to_string(),
        binary,
        capabilities: Vec::new(),
        output_dir: None,
    }
}

/// No-op subset gate so the wrapper tests isolate the AC-29 SHAPE gate from
/// cap-grant's capability-subset semantics (which has its own coverage in
/// `tests/subset_enforcement.rs`).
struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _parent: &[Capability], _child: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

/// Records how many times the inner gate is actually invoked.
struct RecordingSubmitGate {
    calls: Arc<Mutex<usize>>,
}
impl RecordingSubmitGate {
    fn new() -> (Arc<Self>, Arc<Mutex<usize>>) {
        let calls = Arc::new(Mutex::new(0));
        (
            Arc::new(Self {
                calls: calls.clone(),
            }),
            calls,
        )
    }
}
#[async_trait::async_trait]
impl ComponentSubmitGate for RecordingSubmitGate {
    async fn submit_component(
        &self,
        _submitter: &str,
        config: ComponentSubmitConfig,
    ) -> Result<ComponentId, SpawnError> {
        *self.calls.lock().unwrap() += 1;
        Ok(ComponentId(config.id))
    }
    async fn kill_component(&self, _id: &str) -> Result<(), SpawnError> {
        Ok(())
    }
    async fn component_status(&self, _id: &str) -> Result<ComponentState, SpawnError> {
        Ok(ComponentState::Completed)
    }
    async fn list_components(&self) -> Vec<ComponentInfo> {
        Vec::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Direct gate — admit_runnable_binary
// ─────────────────────────────────────────────────────────────────────
#[test]
fn ac29_admit_accepts_runnable_rejects_non_runnable() {
    // Runnable component → accepted.
    let runnable = build_dummy_component(WIT_RUNNABLE, "runnable-world");
    admit_runnable_binary(&runnable).expect("runnable binary admitted");

    // Tool-exports component → rejected (not a runnable; AC-11 mutual exclusion).
    let tool = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    match admit_runnable_binary(&tool) {
        Err(SpawnError::InvalidConfig(msg)) => assert!(
            msg.contains("submit-component") && msg.contains("runnable"),
            "expected submit-component runnable rejection, got: {msg}"
        ),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }

    // Empty binary → admitted (pre-advance.wit-lift placeholder; the future
    // M014 bridge routes its lifted bytes through this same gate).
    admit_runnable_binary(&[]).expect("empty binary passes through");

    // Unparseable / non-component bytes → rejected.
    match admit_runnable_binary(&[0, 0, 0, 0]) {
        Err(SpawnError::InvalidConfig(msg)) => assert!(
            msg.contains("invalid wasm"),
            "expected invalid-wasm rejection, got: {msg}"
        ),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Through the SubsetCheckedComponentSubmit admission seam
// ─────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn ac29_wrapper_accepts_runnable_and_calls_inner() {
    let (inner, calls) = RecordingSubmitGate::new();
    let subset_gate: Arc<dyn SpawnerSubsetGate> = Arc::new(AlwaysOkGate);
    let wrapper = SubsetCheckedComponentSubmit::new(inner, subset_gate);

    let runnable = build_dummy_component(WIT_RUNNABLE, "runnable-world");
    let id = wrapper
        .submit_component_with_subset("submitter", config("c-run", runnable), &[], &[])
        .await
        .expect("runnable binary admitted through the wrapper");
    assert_eq!(id.0, "c-run");
    assert_eq!(*calls.lock().unwrap(), 1, "inner gate called exactly once");
}

#[tokio::test]
async fn ac29_wrapper_rejects_tool_before_inner() {
    let (inner, calls) = RecordingSubmitGate::new();
    let subset_gate: Arc<dyn SpawnerSubsetGate> = Arc::new(AlwaysOkGate);
    let wrapper = SubsetCheckedComponentSubmit::new(inner, subset_gate);

    let tool = build_dummy_component(WIT_TOOL_EXPORTS, "tool-world");
    let err = wrapper
        .submit_component_with_subset("submitter", config("c-tool", tool), &[], &[])
        .await
        .expect_err("a tool-exports binary must be rejected at submit-component admission");
    assert!(
        matches!(err, SpawnError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        0,
        "inner gate MUST NOT be called when the shape gate rejects"
    );
}

#[tokio::test]
async fn ac29_wrapper_empty_binary_passes_through() {
    let (inner, calls) = RecordingSubmitGate::new();
    let subset_gate: Arc<dyn SpawnerSubsetGate> = Arc::new(AlwaysOkGate);
    let wrapper = SubsetCheckedComponentSubmit::new(inner, subset_gate);

    // The current WIT submit-component path passes Vec::new() — must still flow
    // through to the inner gate (gate is inert until advance.wit lifts a binary).
    wrapper
        .submit_component_with_subset("submitter", config("c-empty", Vec::new()), &[], &[])
        .await
        .expect("empty binary passes the shape gate");
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "inner gate called for empty binary"
    );
}
