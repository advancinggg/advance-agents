//! sched-residue: submit-admission gate coverage — Gate-1 trigger-event
//! whitelist (admission rule 4, ADR
//! `2026-06-10-trigger-whitelist-submit-admission-gate`) + the
//! `SubmitSubsetGate` port (admission rule 5).
//!
//! Future-witness targets: SYS-AC-104 (non-whitelisted trigger-event rejected
//! at submit admission, nothing persisted) and SYS-AC-110 (over-grant request
//! rejected by the SubsetValidator, no component registered). This slice
//! builds + crate-tests the product; the e2e witnesses (real harness +
//! real cap-grant adapter) are the future harvest slice's job (0 SYS-AC
//! flip here).

use std::sync::{Arc, Mutex};

use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::submit::SubmitSubsetGate;
use advance_scheduler::types::{
    ComponentSubmitConfig, SpawnError, TriggerConfig, TriggerSubscription,
};
use advance_scheduler::{ComponentSubmitApi, InMemoryComponentSubmitApi};
use advance_shared_types::agent_tree::Capability;
use advance_shared_types::capability::{CapRequest, CapabilityId};
use advance_shared_types::component::ComponentType;
use tempfile::TempDir;

fn base_cfg(id: &str, component_type: ComponentType) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type,
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

fn trigger_event(event_type: &str) -> TriggerConfig {
    TriggerConfig::TriggerEvent(TriggerSubscription {
        event_type: event_type.into(),
        filter: None,
        debounce_ms: None,
    })
}

/// Rule-5 test double: always rejects with SubsetViolation.
struct AlwaysFailGate;

impl SubmitSubsetGate for AlwaysFailGate {
    fn check(&self, _submitter: &str, _requested: &[Capability]) -> Result<(), SpawnError> {
        Err(SpawnError::SubsetViolation(
            "requested capabilities exceed submitter grant (test double)".into(),
        ))
    }
}

/// Rule-5 test double: records the (submitter, requested) calls and approves.
#[derive(Default)]
struct RecordingGate {
    calls: Mutex<Vec<(String, Vec<Capability>)>>,
}

impl SubmitSubsetGate for RecordingGate {
    fn check(&self, submitter: &str, requested: &[Capability]) -> Result<(), SpawnError> {
        self.calls
            .lock()
            .unwrap()
            .push((submitter.to_owned(), requested.to_vec()));
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Gate-1 whitelist (rule 4)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn g1_task_with_non_whitelisted_trigger_event_rejected() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("g1", ComponentType::Task);
    cfg.trigger = Some(trigger_event("fs.write"));
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(msg.contains("fs.write"), "must name the offender: {msg}");
            assert!(msg.contains("non-whitelisted"), "must say why: {msg}");
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[tokio::test]
async fn g2_non_daemon_nested_anyof_offending_leaf_fail_closed() {
    // cron component (rule 3 never runs for non-daemon types) with the
    // offender nested two AnyOf levels deep → still rejected (fail-closed:
    // one offending leaf rejects the whole config).
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("g2", ComponentType::Cron);
    cfg.trigger = Some(TriggerConfig::AnyOf(vec![
        TriggerConfig::Schedule("*/5 * * * *".into()),
        TriggerConfig::AnyOf(vec![trigger_event("fs.write")]),
    ]));
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(
                msg.contains("fs.write"),
                "must name the nested offender: {msg}"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[tokio::test]
async fn g3_whitelisted_trigger_trees_unaffected() {
    // Whitelisted TriggerEvent at top level (watcher type) and inside AnyOf
    // (task type) both still admit — the regression guard for AC-18-adjacent
    // behavior.
    let api = InMemoryComponentSubmitApi::new();

    let mut watcher_cfg = base_cfg("g3-w", ComponentType::Watcher);
    watcher_cfg.trigger = Some(trigger_event("grant.issued"));
    api.submit_component("agent:root", watcher_cfg)
        .await
        .expect("whitelisted trigger-event must admit");

    let mut task_cfg = base_cfg("g3-t", ComponentType::Task);
    task_cfg.trigger = Some(TriggerConfig::AnyOf(vec![
        TriggerConfig::Schedule("@hourly".into()),
        trigger_event("component.finished"),
        trigger_event("git.commit"),
    ]));
    api.submit_component("agent:root", task_cfg)
        .await
        .expect("whitelisted AnyOf tree must admit");
}

#[tokio::test]
async fn g4_depth_overflow_fail_closed() {
    // Hand-built (never passes serde) nesting depth 9 > MAX_TRIGGER_NESTING_DEPTH=8.
    let api = InMemoryComponentSubmitApi::new();
    let mut tree = trigger_event("grant.issued");
    for _ in 0..9 {
        tree = TriggerConfig::AnyOf(vec![tree]);
    }
    let mut cfg = base_cfg("g4", ComponentType::Task);
    cfg.trigger = Some(tree);
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(
                msg.contains("MAX_TRIGGER_NESTING_DEPTH"),
                "must be the depth-cap rejection: {msg}"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[tokio::test]
async fn g5_daemon_whitelisted_trigger_event_still_rule3_error() {
    // Order pin: rule 3 (daemon+TriggerEvent) precedes rule 4, so a daemon
    // with a WHITELISTED trigger-event still gets the daemon-specific error
    // (not a whitelist message).
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("g5", ComponentType::Daemon);
    cfg.trigger = Some(trigger_event("grant.issued"));
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(
                msg.contains("daemon"),
                "rule-3 daemon error expected: {msg}"
            );
            assert!(
                !msg.contains("non-whitelisted"),
                "must NOT be the rule-4 whitelist error: {msg}"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[tokio::test]
async fn g6_overlong_event_type_bounded_echo() {
    // 200 chars > MAX_EVENT_TYPE_LEN=128 → length-first rejection; the
    // offending string is NOT echoed wholesale into the error.
    let api = InMemoryComponentSubmitApi::new();
    let long = "x".repeat(200);
    let mut cfg = base_cfg("g6", ComponentType::Task);
    cfg.trigger = Some(trigger_event(&long));
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(
                msg.contains("MAX_EVENT_TYPE_LEN"),
                "must be the length rejection: {msg}"
            );
            assert!(
                !msg.contains(&long),
                "the 200-char event_type must not be echoed whole"
            );
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[tokio::test]
async fn g7_rejection_persists_nothing_and_consumes_no_quota() {
    // With a real registry wired and quota=1: a rejected submit leaves the
    // registry empty, the store empty, and the quota slot intact (a
    // subsequent valid submit by the same submitter succeeds).
    let dir = TempDir::new().expect("tempdir");
    let registry = Arc::new(
        ComponentRegistry::open_in(dir.path(), "components.db")
            .await
            .expect("registry open"),
    );
    let api = InMemoryComponentSubmitApi::new()
        .with_registry(Arc::clone(&registry))
        .with_quota(1);

    let mut bad = base_cfg("g7-bad", ComponentType::Task);
    bad.trigger = Some(trigger_event("fs.write"));
    let err = api.submit_component("agent:root", bad).await.unwrap_err();
    assert!(matches!(err, SpawnError::InvalidConfig(_)));

    assert!(
        registry.list().await.expect("registry list").is_empty(),
        "rejected submit must not persist a registry row"
    );
    assert!(
        api.list_components().await.is_empty(),
        "rejected submit must not insert a store row"
    );

    // Quota slot intact: with quota=1 the next valid submit still succeeds.
    let good = base_cfg("g7-good", ComponentType::Task);
    api.submit_component("agent:root", good)
        .await
        .expect("quota slot must not have been consumed by the rejection");
}

// ─────────────────────────────────────────────────────────────────────────
// SubmitSubsetGate (rule 5)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn s1_no_gate_injected_back_compat_admits() {
    let api = InMemoryComponentSubmitApi::new();
    let mut cfg = base_cfg("s1", ComponentType::Task);
    cfg.capabilities = vec![CapRequest {
        capability: CapabilityId::new("fs"),
    }];
    api.submit_component("agent:root", cfg)
        .await
        .expect("no gate wired -> pre-seam behavior admits");
}

#[tokio::test]
async fn s2_failing_gate_rejects_with_zero_side_effects() {
    let dir = TempDir::new().expect("tempdir");
    let registry = Arc::new(
        ComponentRegistry::open_in(dir.path(), "components.db")
            .await
            .expect("registry open"),
    );
    let api = InMemoryComponentSubmitApi::new()
        .with_registry(Arc::clone(&registry))
        .with_quota(1)
        .with_subset_gate(Arc::new(AlwaysFailGate));

    let mut cfg = base_cfg("s2", ComponentType::Task);
    cfg.capabilities = vec![CapRequest {
        capability: CapabilityId::new("http"),
    }];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    assert!(
        matches!(err, SpawnError::SubsetViolation(_)),
        "expected SubsetViolation, got {err:?}"
    );

    assert!(
        registry.list().await.expect("registry list").is_empty(),
        "subset rejection must not persist a registry row"
    );
    assert!(
        api.list_components().await.is_empty(),
        "subset rejection must not insert a store row"
    );
}

#[tokio::test]
async fn s2b_failing_gate_consumes_no_quota_slot() {
    // Separate API instance with quota=1: subset rejection then a valid
    // (capability-free) submit — the slot must still be available.
    let api = InMemoryComponentSubmitApi::new()
        .with_quota(1)
        .with_subset_gate(Arc::new(PassEmptyGate));

    let mut over = base_cfg("s2b-over", ComponentType::Task);
    over.capabilities = vec![CapRequest {
        capability: CapabilityId::new("http"),
    }];
    let err = api.submit_component("agent:root", over).await.unwrap_err();
    assert!(matches!(err, SpawnError::SubsetViolation(_)));

    let ok = base_cfg("s2b-ok", ComponentType::Task);
    api.submit_component("agent:root", ok)
        .await
        .expect("quota slot must survive a subset rejection");
}

/// Approves empty requests, rejects any non-empty request — a minimal
/// "submitter holds no grants" double for the quota-survival test.
struct PassEmptyGate;

impl SubmitSubsetGate for PassEmptyGate {
    fn check(&self, _submitter: &str, requested: &[Capability]) -> Result<(), SpawnError> {
        if requested.is_empty() {
            Ok(())
        } else {
            Err(SpawnError::SubsetViolation(
                "submitter holds no grants (test double)".into(),
            ))
        }
    }
}

#[tokio::test]
async fn s3_recording_gate_sees_submitter_and_null_params_projection() {
    let gate = Arc::new(RecordingGate::default());
    let api = InMemoryComponentSubmitApi::new().with_subset_gate(gate.clone());

    let mut cfg = base_cfg("s3", ComponentType::Cron);
    cfg.capabilities = vec![
        CapRequest {
            capability: CapabilityId::new("fs"),
        },
        CapRequest {
            capability: CapabilityId::new("llm"),
        },
    ];
    api.submit_component("agent:research", cfg)
        .await
        .expect("approving gate admits");

    let calls = gate.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (submitter, requested) = &calls[0];
    assert_eq!(submitter, "agent:research");
    assert_eq!(requested.len(), 2);
    assert_eq!(requested[0].id.as_str(), "fs");
    assert_eq!(requested[1].id.as_str(), "llm");
    for cap in requested {
        assert!(
            cap.params.as_value().is_null(),
            "CapRequest is id-only -> projection must be CapParams::empty() (Null)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Rule ordering pins
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn s4_whitelist_rule4_precedes_subset_rule5() {
    let api = InMemoryComponentSubmitApi::new().with_subset_gate(Arc::new(AlwaysFailGate));
    let mut cfg = base_cfg("s4", ComponentType::Task);
    cfg.trigger = Some(trigger_event("fs.write"));
    cfg.capabilities = vec![CapRequest {
        capability: CapabilityId::new("http"),
    }];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    assert!(
        matches!(err, SpawnError::InvalidConfig(_)),
        "rule 4 (whitelist InvalidConfig) must win over rule 5 (SubsetViolation), got {err:?}"
    );
}

#[tokio::test]
async fn s5_daemon_cap_rule2_precedes_subset_rule5() {
    let api = InMemoryComponentSubmitApi::new().with_subset_gate(Arc::new(AlwaysFailGate));
    let mut cfg = base_cfg("s5", ComponentType::Daemon);
    cfg.capabilities = vec![CapRequest {
        capability: CapabilityId::new("lifecycle.spawn-child"),
    }];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    assert!(
        matches!(err, SpawnError::CapabilityDenied(_)),
        "rule 2 (CapabilityDenied) must win over rule 5, got {err:?}"
    );
}

#[tokio::test]
async fn s6_agent_type_rule1_precedes_subset_rule5() {
    let api = InMemoryComponentSubmitApi::new().with_subset_gate(Arc::new(AlwaysFailGate));
    let mut cfg = base_cfg("s6", ComponentType::Agent);
    cfg.capabilities = vec![CapRequest {
        capability: CapabilityId::new("http"),
    }];
    let err = api.submit_component("agent:root", cfg).await.unwrap_err();
    match err {
        SpawnError::InvalidConfig(msg) => {
            assert!(
                msg.contains("agent components"),
                "rule 1 (agent-type rejection) must win over rule 5: {msg}"
            );
        }
        other => panic!("expected rule-1 InvalidConfig, got {other:?}"),
    }
}
