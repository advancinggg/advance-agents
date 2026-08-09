//! AC-17 verification: agent creates cron/daemon via submit-component;
//! submitter recorded as metadata; admission API has no submitter→component
//! cascade rule (proves architectural "parent agent lifecycle decoupled"
//! property at the admission layer).

use advance_scheduler::{ComponentSubmitApi, ComponentSubmitConfig, InMemoryComponentSubmitApi};
use advance_shared_types::capability::{CapRequest, CapabilityId};
use advance_shared_types::component::ComponentType;

fn cap(id: &str) -> CapRequest {
    CapRequest {
        capability: CapabilityId::new(id),
    }
}

fn base_cfg(id: &str, t: ComponentType) -> ComponentSubmitConfig {
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

#[tokio::test]
async fn agent_submits_cron_recorded() {
    let api = InMemoryComponentSubmitApi::new();
    let cfg = base_cfg("cron-a", ComponentType::Cron);
    let id = api
        .submit_component("agent:root", cfg)
        .await
        .expect("agent submits cron must be Ok");
    assert_eq!(id.as_str(), "cron-a");
    assert_eq!(
        api.submitter_of("cron-a").await,
        Some("agent:root".to_owned())
    );
}

#[tokio::test]
async fn agent_submits_daemon_with_safe_cap() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("daemon-x", ComponentType::Daemon);
    cfg.capabilities = vec![cap("fs.read")];
    api.submit_component("agent:research", cfg)
        .await
        .expect("daemon + fs.read must be Ok");
    assert_eq!(
        api.submitter_of("daemon-x").await,
        Some("agent:research".to_owned())
    );
}

#[tokio::test]
async fn no_submitter_cascade_on_kill() {
    let api = InMemoryComponentSubmitApi::new();
    // Submit 3 components: cron-a + cron-b from agent:root, cron-c from agent:other.
    let _ = api
        .submit_component("agent:root", base_cfg("cron-a", ComponentType::Cron))
        .await
        .unwrap();
    let _ = api
        .submit_component("agent:root", base_cfg("cron-b", ComponentType::Cron))
        .await
        .unwrap();
    let _ = api
        .submit_component("agent:other", base_cfg("cron-c", ComponentType::Cron))
        .await
        .unwrap();

    // Kill cron-a. Verify cron-b and cron-c are NOT affected (no submitter cascade).
    api.kill_component("cron-a").await.unwrap();
    assert!(
        api.component_status("cron-a").await.is_err(),
        "cron-a must be gone"
    );
    api.component_status("cron-b")
        .await
        .expect("cron-b must still exist (no cascade)");
    api.component_status("cron-c")
        .await
        .expect("cron-c must still exist");

    // Submitter metadata is preserved.
    assert_eq!(
        api.submitter_of("cron-b").await,
        Some("agent:root".to_owned())
    );
    assert_eq!(
        api.submitter_of("cron-c").await,
        Some("agent:other".to_owned())
    );
}

#[tokio::test]
async fn kill_unknown_id_idempotent() {
    let api = InMemoryComponentSubmitApi::new();
    // Submitter id passed in as if it were a component id — kill_component
    // must be a no-op Ok (the admission API has no mapping from submitter
    // id to component id, so it cannot tell the difference).
    api.kill_component("ghost").await.unwrap();
    api.kill_component("agent:root").await.unwrap();
}
