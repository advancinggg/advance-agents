//! T-SE-01..T-SE-09 joint integration tests for MODULE-005-AC-06 +
//! MODULE-013-AC-15 (m013-slice-e, 2026-05-23). Exercises the 4
//! enforcement points end-to-end: spawn-child, spawn-sub, submit-component
//! (Rust-API via SubsetCheckedComponentSubmit), and delegate-grant
//! (cap-grant GrantStore::delegate_grant). Both allow and reject paths
//! plus a fail-closed exotic case.
//!
//! The subset gate threaded through every spawn / submit path is the
//! production [`CapGrantSubsetAdapter`], which wraps
//! `cap_grant::validate_capability_subset` (Capability-first entry with
//! a fail-closed projection — see cap_grant_adapter.rs rustdoc).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use advance_shared_types::capability::{CapParams, CapabilityId};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

use cap_grant::data::{
    Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{CapGrantError, GrantSqliteIndex, GrantStore, SubsetValidatorImpl};

use cap_lifecycle::{
    AgentTreeStore, CapGrantSubsetAdapter, ComponentId, ComponentInfo, ComponentState,
    ComponentSubmitConfig, ComponentSubmitGate, DefaultSpawner, SpawnChildConfig, SpawnError,
    SpawnSubConfig, Spawner, SubsetCheckedComponentSubmit,
};

use async_trait::async_trait;
use serde_json::json;
use tempfile::TempDir;

// =============================================================================
// Test helpers — local to this file (test fixtures are NOT shared across
// the cap-lifecycle test crate per workspace convention).
// =============================================================================

fn cap(id: &str, params: serde_json::Value) -> Capability {
    Capability {
        id: CapabilityId::from(id),
        params: CapParams::new(params),
    }
}

/// Build (workspace_root_tmp, AgentTreeStore, DefaultSpawner-with-real-adapter).
/// Root agent has `parent_caps` as its capability set.
fn setup_with_parent_caps(
    parent_caps: Vec<Capability>,
) -> (TempDir, AgentTreeStore, DefaultSpawner) {
    let tmp = TempDir::new().unwrap();
    let workspace_root = tmp.path().to_path_buf();
    let tree = AgentTreeStore::new(workspace_root).expect("AgentTreeStore::new");
    let root_ws = tree.workspace_root().join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    let root_node = AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: parent_caps,
        template_ref: None,
        status: AgentStatus::Active,
    };
    tree.insert_root(root_node).expect("insert_root");
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(CapGrantSubsetAdapter::new()));
    (tmp, tree, spawner)
}

/// Recording ComponentSubmitGate that tracks call count + records the
/// submitter id. Used to verify the inner gate IS / IS NOT invoked
/// across allow / reject paths.
struct RecordingSubmitGate {
    calls: Arc<Mutex<Vec<String>>>,
}

impl RecordingSubmitGate {
    fn new() -> (Arc<Self>, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(Self {
            calls: calls.clone(),
        });
        (gate, calls)
    }
}

#[async_trait]
impl ComponentSubmitGate for RecordingSubmitGate {
    async fn submit_component(
        &self,
        submitter: &str,
        config: ComponentSubmitConfig,
    ) -> Result<ComponentId, SpawnError> {
        self.calls.lock().unwrap().push(submitter.to_string());
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

/// Bus that ignores emitted events (delegate-grant only needs the trait
/// satisfied; we don't assert on events here — coverage is in cap-grant
/// delegate.rs).
struct SilentBus;
impl EventBusEmit for SilentBus {
    fn emit(&self, _event: Event) {}
}

/// Build an in-memory GrantStore for the delegate-grant tests. Seeds one
/// `fs.read-paths=/a` static Grant for `alice`. The cap-grant test
/// fixture pattern is replicated here because `tests/common/` is per-crate.
fn make_alice_store_with_fs_a() -> (Arc<GrantStore>, GrantId) {
    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
    let bus: Arc<dyn EventBusEmit> = Arc::new(SilentBus);
    let index = GrantSqliteIndex::new(handle);
    index.ensure_schema().expect("ensure_schema");
    let store = Arc::new(GrantStore::new(index, bus));
    let parent_id = GrantId::new("static-alice-fs");
    let parent_grant = Grant {
        id: parent_id.clone(),
        grantee: "alice".to_string(),
        capability: "fs".to_string(),
        params: vec![cap_grant::data::CapParam {
            key: "read-paths".to_string(),
            value: "/a".to_string(),
        }],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: chrono::Utc::now(),
        expires_at: None,
    };
    store.insert(parent_grant).expect("insert parent");
    (store, parent_id)
}

// =============================================================================
// T-SE-01 / T-SE-02 — spawn-child enforcement via CapGrantSubsetAdapter
// =============================================================================
#[test]
fn t_se_01_spawn_child_allow() {
    let parent_caps = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    let (_tmp, _tree, spawner) = setup_with_parent_caps(parent_caps);
    let result = spawner.spawn_child(SpawnChildConfig {
        parent_id: AgentId("root".to_string()),
        child_id: AgentId("foo".to_string()),
        child_workspace_path: PathBuf::from("agents/foo"),
        capabilities: vec![cap("fs", json!({"read-paths": "/tmp/sub"}))],
        template_ref: None,
        binary: None,
    });
    result.expect("spawn-child must succeed with /tmp/sub ⊆ /tmp");
}

#[test]
fn t_se_02_spawn_child_reject() {
    let parent_caps = vec![cap("fs", json!({"read-paths": "/tmp"}))];
    let (_tmp, _tree, spawner) = setup_with_parent_caps(parent_caps);
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: vec![cap("fs", json!({"read-paths": "/etc"}))],
            template_ref: None,
            binary: None,
        })
        .expect_err("spawn-child must reject /etc ⊄ /tmp");
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );
}

// =============================================================================
// T-SE-03 / T-SE-04 — spawn-sub enforcement via CapGrantSubsetAdapter
// =============================================================================
#[test]
fn t_se_03_spawn_sub_allow() {
    let parent_caps = vec![cap("tools", json!({"ids": ["a", "b"]}))];
    let (_tmp, _tree, spawner) = setup_with_parent_caps(parent_caps);
    let result = spawner.spawn_sub(SpawnSubConfig {
        parent_id: AgentId("root".to_string()),
        capabilities: vec![cap("tools", json!({"ids": ["a"]}))],
        template_ref: None,
    });
    result.expect("spawn-sub must succeed with [a] ⊆ [a, b]");
}

#[test]
fn t_se_04_spawn_sub_reject() {
    let parent_caps = vec![cap("tools", json!({"ids": ["a"]}))];
    let (_tmp, _tree, spawner) = setup_with_parent_caps(parent_caps);
    let err = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".to_string()),
            capabilities: vec![cap("tools", json!({"ids": ["a", "b"]}))],
            template_ref: None,
        })
        .expect_err("spawn-sub must reject [a, b] ⊄ [a]");
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );
}

// =============================================================================
// T-SE-05 / T-SE-06 — submit-component enforcement via
//   SubsetCheckedComponentSubmit wrapping a RecordingSubmitGate.
// =============================================================================
#[tokio::test]
async fn t_se_05_submit_component_allow() {
    let (inner, calls) = RecordingSubmitGate::new();
    let subset_gate: Arc<dyn cap_lifecycle::SpawnerSubsetGate> =
        Arc::new(CapGrantSubsetAdapter::new());
    let wrapper = SubsetCheckedComponentSubmit::new(inner, subset_gate);

    let parent_caps = vec![cap(
        "http",
        json!({"allowlist": "https://api.example.com/*"}),
    )];
    let requested = vec![cap(
        "http",
        json!({"allowlist": "https://api.example.com/users/*"}),
    )];
    let config = ComponentSubmitConfig {
        id: "comp-1".to_string(),
        component_type: "task".to_string(),
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
    };
    let id = wrapper
        .submit_component_with_subset("submitter", config, &parent_caps, &requested)
        .await
        .expect("submit allowed");
    assert_eq!(id.0, "comp-1");
    let recorded = calls.lock().unwrap();
    assert_eq!(recorded.len(), 1, "inner gate must be called exactly once");
    assert_eq!(recorded[0], "submitter");
}

#[tokio::test]
async fn t_se_06_submit_component_reject() {
    let (inner, calls) = RecordingSubmitGate::new();
    let subset_gate: Arc<dyn cap_lifecycle::SpawnerSubsetGate> =
        Arc::new(CapGrantSubsetAdapter::new());
    let wrapper = SubsetCheckedComponentSubmit::new(inner, subset_gate);

    let parent_caps = vec![cap(
        "http",
        json!({"allowlist": "https://api.example.com/*"}),
    )];
    let requested = vec![cap(
        "http",
        json!({"allowlist": "https://evil.example.com/*"}),
    )];
    let config = ComponentSubmitConfig {
        id: "comp-evil".to_string(),
        component_type: "task".to_string(),
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
    };
    let err = wrapper
        .submit_component_with_subset("submitter", config, &parent_caps, &requested)
        .await
        .expect_err("subset violation must reject");
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );
    assert_eq!(
        calls.lock().unwrap().len(),
        0,
        "inner gate MUST NOT be called when subset rejects"
    );
}

// =============================================================================
// T-SE-07 / T-SE-08 — delegate-grant enforcement via the existing
//   GrantStore::delegate_grant path (M013-AC-15 facet 4).
//
// The cap-grant delegate.rs T-C5..T-C9 already covers caller-auth + parent-
// active + subset-violation across delegate_grant; here we add the joint
// view to demonstrate AC-15 closure at the integration-test level.
// =============================================================================
#[test]
fn t_se_07_delegate_grant_allow() {
    let (store, parent_id) = make_alice_store_with_fs_a();
    let validator = SubsetValidatorImpl::new();
    let draft = GrantDraft {
        capability: "fs".to_string(),
        params: vec![cap_grant::data::CapParam {
            key: "read-paths".to_string(),
            value: "/a/b".to_string(),
        }],
        ttl: GrantTtl::Lifecycle,
    };
    let new_id = store
        .delegate_grant(parent_id.as_str(), "bob", draft, "alice", &validator)
        .expect("delegate-grant must Ok when child /a/b ⊆ parent /a");
    let child = store.get(new_id.as_str()).expect("child stored");
    assert_eq!(child.grantee, "bob");
    assert_eq!(child.capability, "fs");
}

#[test]
fn t_se_08_delegate_grant_reject() {
    let (store, parent_id) = make_alice_store_with_fs_a();
    let validator = SubsetValidatorImpl::new();
    let draft = GrantDraft {
        capability: "fs".to_string(),
        params: vec![cap_grant::data::CapParam {
            key: "read-paths".to_string(),
            value: "/c".to_string(),
        }],
        ttl: GrantTtl::Lifecycle,
    };
    let err = store
        .delegate_grant(parent_id.as_str(), "bob", draft, "alice", &validator)
        .expect_err("delegate-grant must reject /c ⊄ /a");
    assert!(
        matches!(err, CapGrantError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );
}

// =============================================================================
// T-SE-09 — fail-closed exotic: parent Capability with unrecognized param
//   key. The projection rejects the parent BEFORE the inner SubsetValidator
//   runs, demonstrating the fail-closed posture from M005 §3.6's previous
//   deferral note.
// =============================================================================
#[test]
fn t_se_09_fail_closed_unrecognized_parent_key() {
    let parent_caps = vec![cap("fs", json!({"symlink-paths": "/etc/passwd"}))];
    let (_tmp, _tree, spawner) = setup_with_parent_caps(parent_caps);
    let err = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("foo".to_string()),
            child_workspace_path: PathBuf::from("agents/foo"),
            capabilities: vec![cap("fs", json!({"read-paths": "/tmp"}))],
            template_ref: None,
            binary: None,
        })
        .expect_err("parent with unrecognized key must fail closed");
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );
}
