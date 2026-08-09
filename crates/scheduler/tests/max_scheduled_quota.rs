//! AC-09 (MODULE-014-AC-09 / REQ-057, T07) verification: per-agent
//! `max-scheduled-components` quota (default 20) rejects the excess submit
//! with `SpawnError::ResourceLimit`.
//!
//! The quota counts the submitter's rows in the in-memory admission store
//! (Slice-D admission model; AC-09/T07's criterion is the in-process
//! "(N+1)th rejected", NOT cross-restart durability). The gate runs BEFORE
//! the AC-05 write-through registry persist, so an over-quota submit never
//! persists.

use std::sync::Arc;

use advance_scheduler::{
    ComponentRegistry, ComponentSubmitApi, ComponentSubmitConfig, InMemoryComponentSubmitApi,
    SpawnError,
};
use advance_shared_types::component::ComponentType;

fn task_cfg(id: &str) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

// T07.a + T07.b — default quota 20: 20 distinct submits from one submitter
// Ok; the 21st rejected with ResourceLimit.
#[tokio::test]
async fn t07ab_default_quota_20_then_21st_rejected() {
    let api = InMemoryComponentSubmitApi::new();
    for i in 0..20 {
        api.submit_component("agent:root", task_cfg(&format!("c{i}")))
            .await
            .unwrap_or_else(|e| panic!("submit {i} should be within quota: {e:?}"));
    }
    let err = api
        .submit_component("agent:root", task_cfg("c20"))
        .await
        .expect_err("21st submit must be rejected");
    assert!(
        matches!(err, SpawnError::ResourceLimit(_)),
        "expected ResourceLimit, got {err:?}"
    );
}

// T07.c — quota is per-submitter: agent:a fills its budget; agent:b is
// independent.
#[tokio::test]
async fn t07c_quota_is_per_submitter() {
    let api = InMemoryComponentSubmitApi::new();
    for i in 0..20 {
        api.submit_component("agent:a", task_cfg(&format!("a{i}")))
            .await
            .expect("agent:a within budget");
    }
    // agent:a is now at the cap; the 21st for agent:a is rejected...
    let err = api
        .submit_component("agent:a", task_cfg("a20"))
        .await
        .expect_err("agent:a 21st rejected");
    assert!(matches!(err, SpawnError::ResourceLimit(_)));
    // ...but agent:b has its own independent budget.
    api.submit_component("agent:b", task_cfg("b0"))
        .await
        .expect("agent:b independent budget");
}

// T07.d — with_quota override honored.
#[tokio::test]
async fn t07d_quota_override_honored() {
    let api = InMemoryComponentSubmitApi::new().with_quota(2);
    api.submit_component("agent:root", task_cfg("q0"))
        .await
        .expect("1st");
    api.submit_component("agent:root", task_cfg("q1"))
        .await
        .expect("2nd");
    let err = api
        .submit_component("agent:root", task_cfg("q2"))
        .await
        .expect_err("3rd over the with_quota(2) cap");
    assert!(matches!(err, SpawnError::ResourceLimit(_)));
}

// T07.e — over-quota submit is rejected AND not persisted (quota gate runs
// before the AC-05 registry write).
#[tokio::test]
async fn t07e_over_quota_not_persisted() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    let api = InMemoryComponentSubmitApi::new()
        .with_registry(Arc::clone(&reg))
        .with_quota(1);
    api.submit_component("agent:root", task_cfg("keep"))
        .await
        .expect("1st within quota");
    let err = api
        .submit_component("agent:root", task_cfg("dropped"))
        .await
        .expect_err("2nd over quota");
    assert!(matches!(err, SpawnError::ResourceLimit(_)));
    let rows = reg.list().await.expect("list");
    assert_eq!(rows.len(), 1, "over-quota submit must not persist");
    assert_eq!(rows[0].id.as_str(), "keep");
}

// T07.f — adversarial r14 W#2b regression: with_quota(0) must NOT brick
// all submission. The defensive `.max(1)` floor makes 0 an effective cap
// of 1 — the 1st submit is admitted, the 2nd rejected — NOT a total
// self-DoS where even the 1st submit is rejected.
#[tokio::test]
async fn t07f_with_quota_zero_floors_to_one_not_total_dos() {
    let api = InMemoryComponentSubmitApi::new().with_quota(0);
    api.submit_component("agent:root", task_cfg("z0"))
        .await
        .expect("with_quota(0) must still admit the 1st submit (floored to 1, not 0)");
    let err = api
        .submit_component("agent:root", task_cfg("z1"))
        .await
        .expect_err("2nd submit over the floored effective cap of 1");
    assert!(
        matches!(err, SpawnError::ResourceLimit(_)),
        "expected ResourceLimit on the 2nd submit, got {err:?}"
    );
}
