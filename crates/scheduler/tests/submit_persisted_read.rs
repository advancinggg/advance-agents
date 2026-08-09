//! sched-triggers (trigger-chain product pre-build): registry-backed durable
//! read accessor `InMemoryComponentSubmitApi::list_components_persisted`.
//!
//! Future-witness targets:
//! - SYS-AC-108: an admitted component is persisted to the ComponentRegistry and
//!   queryable (here via the durable accessor, not the in-memory list).
//! - SYS-AC-109: the persisted component is durable independently of the
//!   submitter's in-memory metadata.
//!
//! This deliberately does NOT duplicate `submit_registry_persistence.rs`'s
//! close/reopen roundtrip — it asserts the NEW accessor surface + the
//! no-registry empty path.

use std::sync::Arc;

use advance_scheduler::{
    ComponentRegistry, ComponentSubmitApi, ComponentSubmitConfig, InMemoryComponentSubmitApi,
};
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

// SYS-AC-108 — admitted components are durably queryable via the accessor.
#[tokio::test]
async fn persisted_read_reflects_admitted_rows() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    let api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));

    api.submit_component("agent:root", cfg("cron-a", ComponentType::Cron))
        .await
        .expect("admit cron-a");
    api.submit_component("agent:root", cfg("task-b", ComponentType::Task))
        .await
        .expect("admit task-b");

    let mut rows = api
        .list_components_persisted()
        .await
        .expect("durable read ok");
    rows.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["cron-a", "task-b"]);
    assert!(rows.iter().all(|r| r.submitter == "agent:root"));
}

// SYS-AC-109 — durability is independent of the submitter: a fresh API instance
// (no in-memory admission state) reading the SAME registry still sees the rows,
// proving the component outlives the submitting api's in-memory metadata.
#[tokio::test]
async fn persisted_rows_outlive_submitter_in_memory_state() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    {
        let submitter_api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));
        submitter_api
            .submit_component("agent:ephemeral", cfg("survivor", ComponentType::Cron))
            .await
            .expect("admit survivor");
        // submitter_api dropped here — its in-memory admission map is gone.
    }

    // A brand-new reader sharing only the registry still sees the durable row.
    let reader_api = InMemoryComponentSubmitApi::new().with_registry(Arc::clone(&reg));
    let rows = reader_api
        .list_components_persisted()
        .await
        .expect("durable read ok");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id.as_str(), "survivor");
    // And the in-memory list of the fresh reader is empty (distinct surface).
    assert!(reader_api.list_components().await.is_empty());
}

// No registry configured → empty Ok (back-compat; nothing durable to read).
#[tokio::test]
async fn no_registry_returns_empty_ok() {
    let api = InMemoryComponentSubmitApi::new();
    let rows = api.list_components_persisted().await.expect("ok");
    assert!(rows.is_empty());
}
