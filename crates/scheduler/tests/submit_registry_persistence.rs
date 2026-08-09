//! AC-05 (MODULE-014-AC-05 / REQ-049, T16) verification: `submit-component`
//! admission **write-through** persists to the SQLite `ComponentRegistry`.
//!
//! Scope: write-through only. `submit_component`'s happy path persists every
//! admitted component as a one-shot row (`interval_ms: None`); rejected
//! admission persists nothing. Verified by reading the registry DIRECTLY
//! (`reg.get`/`reg.list`) — NOT via the submit API's in-memory
//! `list_components` (the registry-backed read/quota/restart-recovery path
//! is the explicitly waived Slice-E full-lifecycle item; see MODULE-014
//! §3.7 / §3.8 (v),(w)).

use std::sync::Arc;

use advance_scheduler::{
    ComponentRegistry, ComponentSubmitApi, ComponentSubmitConfig, InMemoryComponentSubmitApi,
    SpawnError,
};
use advance_shared_types::capability::{CapRequest, CapabilityId};
use advance_shared_types::component::ComponentType;

fn cfg(id: &str, t: ComponentType) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: t,
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

// T16.a — happy path persists; row readable via reg.get with the submitter
// recorded and interval_ms == None (one-shot).
#[tokio::test]
async fn t16a_submit_persists_row_to_registry() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    let api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));

    let id = api
        .submit_component("agent:root", cfg("x", ComponentType::Task))
        .await
        .expect("happy path admitted");
    assert_eq!(id.as_str(), "x");

    let row = reg
        .get("x")
        .await
        .expect("reg.get ok")
        .expect("row present");
    assert_eq!(row.submitter, "agent:root");
    assert_eq!(
        row.interval_ms, None,
        "admitted component persists one-shot"
    );
}

// T16.b — persistence survives a "restart": drop api+registry, reopen the
// same SQLite file, the row is recovered.
#[tokio::test]
async fn t16b_persistence_survives_restart() {
    let td = tempfile::tempdir().unwrap();
    {
        let reg = Arc::new(
            ComponentRegistry::open_in(td.path(), "components.db")
                .await
                .expect("open_in"),
        );
        let api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));
        api.submit_component("agent:root", cfg("survivor", ComponentType::Task))
            .await
            .expect("admitted");
        // api + reg dropped at end of block → SQLite connection closed.
    }
    let reg2 = ComponentRegistry::open_in(td.path(), "components.db")
        .await
        .expect("reopen");
    let rows = reg2.list().await.expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id.as_str(), "survivor");
}

// T16.c — admission persistence is component-type agnostic: a cron-type
// submit ALSO persists (with interval_ms == None — recurring tick-tracking
// is the waived Slice-E full-lifecycle path, NOT asserted here).
#[tokio::test]
async fn t16c_cron_type_persists_type_agnostically() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    let api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));
    api.submit_component("agent:root", cfg("cron-x", ComponentType::Cron))
        .await
        .expect("cron admitted");
    let row = reg.get("cron-x").await.expect("ok").expect("present");
    assert_eq!(row.component_type, ComponentType::Cron);
    assert_eq!(row.interval_ms, None);
}

// T16.d — rejected admission persists NOTHING (daemon + lifecycle
// controller cap → CapabilityDenied before the registry write).
#[tokio::test]
async fn t16d_rejected_admission_persists_nothing() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    let api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));

    let mut bad = cfg("d", ComponentType::Daemon);
    bad.capabilities = vec![CapRequest {
        capability: CapabilityId::new("lifecycle.spawn-child"),
    }];
    let err = api
        .submit_component("agent:root", bad)
        .await
        .expect_err("daemon + lifecycle cap must be rejected");
    assert!(matches!(err, SpawnError::CapabilityDenied(_)));
    assert!(
        reg.list().await.expect("list").is_empty(),
        "rejected admission must not persist a registry row"
    );
}

// T16.e — back-compat: no registry wired → happy path still Ok (Slice-D
// in-memory-only behavior preserved).
#[tokio::test]
async fn t16e_no_registry_back_compat() {
    let api = InMemoryComponentSubmitApi::new();
    let id = api
        .submit_component("agent:root", cfg("nr", ComponentType::Task))
        .await
        .expect("no-registry happy path still admits");
    assert_eq!(id.as_str(), "nr");
}

// T16.f — dup id: 2nd submit rejected; exactly one registry row.
#[tokio::test]
async fn t16f_duplicate_id_rejected_single_row() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    let api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));
    api.submit_component("agent:root", cfg("dup", ComponentType::Task))
        .await
        .expect("first admit");
    let err = api
        .submit_component("agent:root", cfg("dup", ComponentType::Task))
        .await
        .expect_err("duplicate id must be rejected");
    assert!(matches!(err, SpawnError::AlreadyExists(_)));
    assert_eq!(reg.list().await.expect("list").len(), 1);
}
