//! Wave-23 `perchild-daemon-1` seam (a) witness (T-A2/A3): the WIT `spawn-child`
//! host-fn decodes a real `child-agent-config` `Val::Record` (id + capabilities +
//! binary) and MATERIALIZES the child's driver — driven through the PRODUCTION
//! `register_agent_spawn` dispatch path (a `HostFunctionHandler` call with `Val`s),
//! NOT a direct `SpawnChildConfig`. This closes the record-decode + binary-
//! materialization leg of seam (a) that the SYS-AC-279 composed witness
//! (`system-acceptance/tests/sys_j68_perchild_daemon.rs`) drives via the Rust
//! spawner. (A dedicated `agent-lifecycle`-importing GUEST fixture — a real
//! wasm caller — is a disclosed follow-up; the dynamic linker's ability to link
//! `agent-lifecycle` for a declaring guest is architecturally established by the
//! grant/llm/mem fixture precedent that import interfaces absent from the host
//! bindgen world yet instantiate through the same capabilities path.)

use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use cap_lifecycle::{
    register_agent_spawn, AgentTreeStore, DefaultSpawner, SpawnError, Spawner, SpawnerSubsetGate,
};
use tempfile::TempDir;
use wasmtime::component::Val;

const AGENT_LIFECYCLE_CAPABILITY: &str = "lifecycle";
// A minimal valid wasm CORE header (magic `\0asm` + version 1): passes the
// materializer's magic + size gate; spawn writes it verbatim to the driver path.
const MINI_WASM: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

struct AllowAllSubset;
impl SpawnerSubsetGate for AllowAllSubset {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

/// T-A2/A3: a top-level `Val::Record` `spawn-child` call decodes id+capabilities+
/// binary AND materializes `<child_ws>/.agent/behavior.component.wasm`.
#[test]
fn spawn_child_val_record_decodes_binary_and_materializes() {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("default-agent".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: tmp.path().to_path_buf(),
        capabilities: vec![],
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner: Arc<dyn Spawner> =
        Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(AllowAllSubset)));
    let reg = InMemoryHostRegistry::new();
    register_agent_spawn(&reg, spawner);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let handler = &specs
        .iter()
        .find(|s| s.name == "spawn-child")
        .expect("spawn-child registered")
        .handler;

    let ctx = HostCallContext {
        agent_id: "default-agent".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "advance:runtime/agent-lifecycle::spawn-child".into(),
        run_id: None,
        iteration: None,
    };
    // The REAL wit-bindgen shape: a single `child-agent-config` Val::Record.
    let record = Val::Record(vec![
        ("id".into(), Val::String("kid".into())),
        ("capabilities".into(), Val::List(vec![])),
        (
            "binary".into(),
            Val::List(MINI_WASM.iter().map(|b| Val::U8(*b)).collect()),
        ),
    ]);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt
        .block_on(HostFunctionHandler::call(
            handler.as_ref(),
            ctx,
            vec![record],
            1,
        ))
        .expect("spawn-child dispatch ok");

    // Ok(agent-id) result → the record's `id` was decoded + spawned.
    match &res[0] {
        Val::Result(Ok(Some(b))) => match b.as_ref() {
            Val::String(id) => assert_eq!(id, "kid", "decoded child id"),
            other => panic!("expected ok string id, got {other:?}"),
        },
        other => panic!("expected Ok(agent-id), got {other:?}"),
    }

    // The child node was recorded (record decode → spawn_child).
    let child = AgentId("kid".into());
    assert!(tree.get_node(&child).is_some(), "child node in the tree");

    // seam (a): the `binary` field was materialized as the child's driver.
    let child_ws = tree.get_node(&child).unwrap().workspace_path;
    let driver = child_ws.join(".agent").join("behavior.component.wasm");
    assert!(
        driver.is_file(),
        "child driver materialized at {}",
        driver.display()
    );
    assert_eq!(
        std::fs::read(&driver).unwrap(),
        MINI_WASM.to_vec(),
        "materialized bytes == the decoded WIT binary"
    );
}

/// T-A2 (dual-shape): the positional convention (param0 = id) stays byte-identical
/// — no `Val::Record` → the pre-Wave-23 path, no binary materialized.
#[test]
fn spawn_child_positional_fallback_unchanged() {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("default-agent".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: tmp.path().to_path_buf(),
        capabilities: vec![],
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner: Arc<dyn Spawner> =
        Arc::new(DefaultSpawner::new(tree.clone(), Arc::new(AllowAllSubset)));
    let reg = InMemoryHostRegistry::new();
    register_agent_spawn(&reg, spawner);
    let specs = reg.lookup(AGENT_LIFECYCLE_CAPABILITY);
    let handler = &specs
        .iter()
        .find(|s| s.name == "spawn-child")
        .unwrap()
        .handler;
    let ctx = HostCallContext {
        agent_id: "default-agent".into(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "lifecycle".into(),
        function: "f".into(),
        run_id: None,
        iteration: None,
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Positional: param0 = child id string (the in-repo spawn_wiring_011 convention).
    let res = rt
        .block_on(HostFunctionHandler::call(
            handler.as_ref(),
            ctx,
            vec![Val::String("posi".into())],
            1,
        ))
        .expect("dispatch ok");
    assert!(
        matches!(&res[0], Val::Result(Ok(Some(_)))),
        "positional spawn ok"
    );
    let child = AgentId("posi".into());
    assert!(tree.get_node(&child).is_some());
    // No binary → no driver materialized (byte-identical to pre-Wave-23).
    let child_ws = tree.get_node(&child).unwrap().workspace_path;
    assert!(
        !child_ws
            .join(".agent")
            .join("behavior.component.wasm")
            .exists(),
        "positional path materializes no driver"
    );
}
