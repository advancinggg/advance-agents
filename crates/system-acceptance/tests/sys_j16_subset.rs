//! SYS-J-16 — granting a child more capability than the parent holds is rejected by the
//! parameter-level subset validator at spawn or submit-component admission.
//! Chain: MODULE-005 → MODULE-013 → MODULE-014.
//!
//! Witnessed since the small-witness slice (2026-06-11): the harness `.agents()` spawner
//! wires the REAL production `cap_lifecycle::CapGrantSubsetAdapter` (→ cap-grant
//! `validate_capability_subset` → `SubsetValidatorImpl`, CONTRACT-122) instead of the
//! old `AlwaysOkSubsetGate` stub, and `SystemUnderTest::submit_admission()` exposes the
//! REAL `SubsetCheckedComponentSubmit` admission composition (subset gate →
//! `admit_runnable_binary` → the SUT's registry-backed scheduler
//! `InMemoryComponentSubmitApi` via the M005→M014 type bridge). Parent capability sets
//! ride the new `AgentSpec.capabilities` field into the spawn-witness tree store.

use std::path::PathBuf;

use advance_shared_types::agent_tree::{AgentId, AgentKind, Capability};
use advance_shared_types::capability::{CapParams, CapabilityId};
use cap_lifecycle::ComponentSubmitConfig;
use cap_lifecycle::{SpawnChildConfig, SpawnError, Spawner};
use serde_json::json;
use system_acceptance::{AgentSpec, Cap, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

fn cap(id: &str, params: serde_json::Value) -> Capability {
    Capability {
        id: CapabilityId::from(id),
        params: CapParams::new(params),
    }
}

/// A single-root tree whose root holds `fs { write-paths: ["/ws/parent"] }` —
/// the restricted parent grant the subset gate checks children against.
fn restricted_root() -> Vec<AgentSpec> {
    vec![AgentSpec {
        id: "agent:root".into(),
        kind: AgentKind::Root,
        parent: None,
        caps: vec![Cap::Fs],
        capabilities: vec![cap("fs", json!({"write-paths": ["/ws/parent"]}))],
    }]
}

/// SYS-AC-046 — spawn-child requesting a capability param exceeding the parent's grant
/// is rejected with spawn-error::subset-violation BEFORE any workspace materialization.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_046_spawn_child_super_parent_rejected() {
    let sut = SystemUnderTest::builder()
        .agents(&restricted_root())
        .build(CORE_BYTES)
        .await;
    let spawner = sut.spawner().expect(".agents() configured");

    // Child requests write access OUTSIDE the parent's prefix → super-parent.
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".into()),
            child_id: AgentId("gc-evil".into()),
            child_workspace_path: PathBuf::from("children/gc-evil"),
            capabilities: vec![cap("fs", json!({"write-paths": ["/etc"]}))],
            template_ref: None,
            binary: None,
        })
        .expect_err("super-parent capability must be rejected");
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );

    // Rejected BEFORE workspace materialization: no node in the tree, no dir on disk.
    let snap = sut.tree_snapshot();
    assert!(
        !snap.nodes.iter().any(|n| n.id.0 == "gc-evil"),
        "no tree node for the rejected child"
    );
    let root_node = snap
        .nodes
        .iter()
        .find(|n| n.id.0 == "root")
        .expect("root node present");
    let child_dir = root_node.workspace_path.join("children").join("gc-evil");
    assert!(
        !child_dir.exists(),
        "no child workspace dir materialized for the rejected spawn"
    );
}

/// SYS-AC-048 — a child requesting a true subset (an fs write-path prefix-subpath of
/// the parent's) succeeds, proving the validator discriminates rather than blanket-denies.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_048_true_subset_spawn_succeeds() {
    let sut = SystemUnderTest::builder()
        .agents(&restricted_root())
        .build(CORE_BYTES)
        .await;
    let spawner = sut.spawner().expect(".agents() configured");

    // Same gate, same parent — a prefix-subpath request passes (discrimination).
    let child = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".into()),
            child_id: AgentId("gc-sub".into()),
            child_workspace_path: PathBuf::from("children/gc-sub"),
            capabilities: vec![cap("fs", json!({"write-paths": ["/ws/parent/sub"]}))],
            template_ref: None,
            binary: None,
        })
        .expect("true-subset capability must be admitted");
    assert_eq!(child.0, "gc-sub");

    // The admitted child IS in the tree (the discriminating pair with 046).
    let snap = sut.tree_snapshot();
    let node = snap
        .nodes
        .iter()
        .find(|n| n.id.0 == "gc-sub")
        .expect("admitted child present in the spawn-witness store");
    assert_eq!(node.parent.as_ref().map(|p| p.0.as_str()), Some("root"));
}

/// SYS-AC-047 — submit-component admitting a component with a super-parent capability
/// is rejected by the SubsetValidator (grant-error::subset-violation); the
/// discriminating subset request is admitted into the REAL registry-backed scheduler
/// submit api.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_047_submit_component_super_parent_rejected() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_triggers()
        .build(CORE_BYTES)
        .await;
    let admission = sut.submit_admission();

    let parent_caps = vec![cap("fs", json!({"write-paths": ["/ws/parent"]}))];

    // Rejection leg: requested capability exceeds the parent's grant → the REAL
    // cap-grant SubsetValidator rejects (grant-error::subset-violation projected as
    // SpawnError::SubsetViolation) BEFORE the inner scheduler api is touched.
    let evil = ComponentSubmitConfig {
        id: "j16-evil-1".to_string(),
        component_type: "task".to_string(),
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
    };
    let err = admission
        .submit_component_with_subset(
            "agent:root",
            evil,
            &parent_caps,
            &[cap("fs", json!({"write-paths": ["/etc"]}))],
        )
        .await
        .expect_err("super-parent submit must be rejected");
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );
    assert!(
        !sut.submit_api()
            .list_components_persisted()
            .await
            .expect("registry list ok")
            .iter()
            .any(|c| c.id.0 == "j16-evil-1"),
        "rejected component never reached the registry-backed api"
    );

    // Admit leg (discrimination): a true-subset request passes the SAME gate and is
    // admitted into the REAL registry-backed api (Rules 1-3 + quota + persistence).
    let ok = ComponentSubmitConfig {
        id: "j16-admit-1".to_string(),
        component_type: "task".to_string(),
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
    };
    let id = admission
        .submit_component_with_subset(
            "agent:root",
            ok,
            &parent_caps,
            &[cap("fs", json!({"write-paths": ["/ws/parent/sub"]}))],
        )
        .await
        .expect("true-subset submit admitted");
    assert_eq!(id.0, "j16-admit-1");
    assert!(
        sut.submit_api()
            .list_components_persisted()
            .await
            .expect("registry list ok")
            .iter()
            .any(|c| c.id.0 == "j16-admit-1"),
        "admitted component persisted in the real registry-backed api"
    );
}
