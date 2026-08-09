//! AC-16 + AC-24 verification: submit-component admission rejects
//! - daemon + TriggerEvent trigger (anywhere in nested AnyOf, AC-16)
//! - daemon + lifecycle controller capability (AC-24)
//! and accepts the cross-type controls (cron + lifecycle cap; daemon + safe
//! cap; agent rejection wins over lifecycle-cap check).

use advance_scheduler::{
    ComponentSubmitApi, ComponentSubmitConfig, InMemoryComponentSubmitApi, SpawnError,
    TriggerConfig, TriggerSubscription, WebhookConfig,
};
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

// ─── AC-16 daemon-no-trigger-event admission ────────────────────────────

#[tokio::test]
async fn daemon_with_trigger_event_rejected() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d1", ComponentType::Daemon);
    cfg.trigger = Some(TriggerConfig::TriggerEvent(TriggerSubscription {
        event_type: "grant.issued".into(),
        filter: None,
        debounce_ms: None,
    }));
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(msg.contains("daemon"), "msg: {msg}");
            assert!(msg.contains("trigger-event"), "msg: {msg}");
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[tokio::test]
async fn daemon_with_schedule_trigger_accepted() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d2", ComponentType::Daemon);
    cfg.trigger = Some(TriggerConfig::Schedule("every-30s".into()));
    api.submit_component("agent:root", cfg)
        .await
        .expect("daemon + Schedule must be accepted");
}

#[tokio::test]
async fn daemon_with_filewatch_trigger_accepted() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d3", ComponentType::Daemon);
    cfg.trigger = Some(TriggerConfig::FileWatch("/tmp/*".into()));
    api.submit_component("agent:root", cfg)
        .await
        .expect("daemon + FileWatch must be accepted");
}

#[tokio::test]
async fn daemon_with_webhook_trigger_accepted() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d4", ComponentType::Daemon);
    cfg.trigger = Some(TriggerConfig::Webhook(WebhookConfig {
        path: "/hook".into(),
        secret: None,
    }));
    api.submit_component("agent:root", cfg)
        .await
        .expect("daemon + Webhook must be accepted");
}

#[tokio::test]
async fn daemon_with_anyof_no_trigger_event_accepted() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d5", ComponentType::Daemon);
    cfg.trigger = Some(TriggerConfig::AnyOf(vec![
        TriggerConfig::Schedule("every-1m".into()),
        TriggerConfig::Webhook(WebhookConfig {
            path: "/hook".into(),
            secret: None,
        }),
    ]));
    api.submit_component("agent:root", cfg)
        .await
        .expect("daemon + AnyOf without TriggerEvent must be accepted");
}

#[tokio::test]
async fn daemon_with_anyof_containing_trigger_event_rejected() {
    // Recursive walker should descend into AnyOf and reject.
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d6", ComponentType::Daemon);
    cfg.trigger = Some(TriggerConfig::AnyOf(vec![
        TriggerConfig::Schedule("every-1m".into()),
        TriggerConfig::TriggerEvent(TriggerSubscription {
            event_type: "grant.issued".into(),
            filter: None,
            debounce_ms: None,
        }),
    ]));
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)), "got {err:?}");
}

// ─── AC-24 daemon-no-lifecycle-controller-cap admission ─────────────────

#[tokio::test]
async fn daemon_with_spawn_child_rejected() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d7", ComponentType::Daemon);
    cfg.capabilities = vec![cap("lifecycle.spawn-child")];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::CapabilityDenied(msg) => {
            assert!(msg.contains("spawn-child"), "msg: {msg}");
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn daemon_with_spawn_sub_rejected() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d8", ComponentType::Daemon);
    cfg.capabilities = vec![cap("lifecycle.spawn-sub")];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    assert!(matches!(err, SpawnError::CapabilityDenied(_)));
}

#[tokio::test]
async fn daemon_with_submit_decomposition_rejected() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d9", ComponentType::Daemon);
    cfg.capabilities = vec![cap("lifecycle.submit-decomposition")];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    assert!(matches!(err, SpawnError::CapabilityDenied(_)));
}

#[tokio::test]
async fn daemon_with_fs_read_accepted() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("d10", ComponentType::Daemon);
    cfg.capabilities = vec![cap("fs.read")];
    api.submit_component("agent:root", cfg)
        .await
        .expect("daemon + non-controller cap must be accepted");
}

#[tokio::test]
async fn daemon_with_no_caps_accepted() {
    let api = InMemoryComponentSubmitApi::new();
    let cfg = base_cfg("d11", ComponentType::Daemon);
    api.submit_component("agent:root", cfg)
        .await
        .expect("daemon + [] caps must be accepted");
}

#[tokio::test]
async fn agent_with_any_cap_rejected() {
    // Rule 1 (agent-type rejection) runs BEFORE rule 2 (lifecycle-cap check).
    // An agent + lifecycle.spawn-child should produce the agent-rejection
    // error, NOT the cap-denied error.
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("a1", ComponentType::Agent);
    cfg.capabilities = vec![cap("lifecycle.spawn-child")];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(msg.contains("agent components"), "msg: {msg}");
        }
        other => panic!("expected InvalidConfig (agent rejection), got {other:?}"),
    }
}

#[tokio::test]
async fn cron_with_spawn_child_accepted() {
    // Only daemon is restricted at scheduler admission. Cron + lifecycle.spawn-child
    // is admission-accepted; downstream MODULE-013 SubsetValidator may reject.
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("c1", ComponentType::Cron);
    cfg.capabilities = vec![cap("lifecycle.spawn-child")];
    api.submit_component("agent:root", cfg)
        .await
        .expect("cron + lifecycle cap is admission-accepted (only daemon restricted)");
}
