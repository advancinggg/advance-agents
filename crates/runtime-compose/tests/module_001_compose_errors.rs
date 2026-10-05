//! MODULE-001-AC-30 — `ComposeError` carries today's startup cases with today's texts,
//! witnessed on real failing compositions (not against copied strings), and each failure
//! leaves nothing behind: a missing runtime config (`ConfigNotFound`, after the lock it
//! took is released), a malformed one (`Bootstrap`), and a deployed driver that does not
//! load (`AgentLoop`, after part of the runtime started).
//!
//! The compositions of this binary run one at a time (`serial`): it checks process-wide
//! state.

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::{
    ComposeFailpoints, ComposeProbe, MemoryComposeLog, ProbeRecord,
};
use advance_runtime_compose::{compose, log_keys, ComposeError};
use t111::{alive_tasks, assert_composition_gone, assert_steps, serial, T111Home};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_config_not_found_releases_lock() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], false);
    let config = home.home.join(".advance/runtime-config.yaml");
    std::fs::remove_file(&config).expect("remove the runtime config");

    let error = compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new())
        .await
        .expect_err("no runtime config");
    match &error {
        ComposeError::ConfigNotFound { path } => assert_eq!(path, &config),
        other => panic!("expected ComposeError::ConfigNotFound, got {other:?}"),
    }
    let text = error.to_string();
    assert!(
        text.contains("runtime-config.yaml not found at") && text.contains("advance init"),
        "{text}"
    );
    assert!(
        !home.lock_path().exists(),
        "the runtime lock taken before the config was read is released"
    );
    assert!(!reserved_homes_for_test().contains(&home.home));
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_malformed_config_is_bootstrap_error() {
    let _serial = serial();
    let home = T111Home::new(&["fs"], false);
    std::fs::write(
        home.home.join(".advance/runtime-config.yaml"),
        "wasm: [this is not\n  valid: yaml\n",
    )
    .expect("write a malformed runtime config");

    let error = compose(home.options(Arc::new(MemoryComposeLog::new())), Vec::new())
        .await
        .expect_err("a malformed runtime config");
    assert!(matches!(error, ComposeError::Bootstrap(_)), "{error:?}");
    assert!(
        error.to_string().starts_with("bootstrap failed: "),
        "{error}"
    );
    assert!(!home.lock_path().exists(), "the runtime lock is released");
    assert!(!reserved_homes_for_test().contains(&home.home));
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_unloadable_driver_is_agent_loop_error_and_tears_down() {
    let _serial = serial();
    let home = T111Home::new(&["fs", "llm"], true);
    home.deploy_driver_bytes(b"not a wasm component");
    let baseline = alive_tasks();

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(log.clone()))
            .with_failpoints(ComposeFailpoints {
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        Vec::new(),
    )
    .await
    .expect_err("the deployed driver does not load");
    assert!(matches!(error, ComposeError::AgentLoop(_)), "{error:?}");
    let text = error.to_string();
    assert!(
        text.starts_with("deployed component ") && text.contains(" failed to load: "),
        "{text}"
    );
    assert_eq!(log.count(log_keys::READY), 1, "it failed after readiness");
    assert_eq!(log.count(log_keys::AGENT_LOOP_WIRED), 0);
    assert_eq!(log.count(log_keys::SHUTTING_DOWN), 0);

    let record = probe.record();
    assert_steps(
        &record,
        &[
            "ingress.client_api",
            "holds.selected_provider",
            "holds.event_bus",
            "holds.drop_graph",
            "guard",
        ],
    );
    assert!(
        !record.step_names().contains(&"loops.root"),
        "no root loop was started:\n{}",
        record.render_steps()
    );
    assert_composition_gone(baseline, &probe, &home.home).await;
}

/// The order witness itself: steps recorded out of the shutdown order (the EventBus stopped
/// before the git queue), a mandatory step that did not run, or mandatory steps that ran
/// in another order than listed each fail `assert_steps`; the shutdown order passes.
#[test]
fn module_001_ac30_assert_steps_rejects_another_order() {
    let record = |steps: &[&'static str]| ProbeRecord {
        teardown_steps: steps.iter().map(|step| (*step, 0)).collect(),
        ..ProbeRecord::default()
    };
    let in_order = ["holds.git_queue", "holds.event_bus", "guard"];
    assert_steps(&record(&in_order), &in_order);
    let rejected: [(&[&'static str], &[&str]); 3] = [
        (&["holds.event_bus", "holds.git_queue", "guard"], &in_order),
        (&["holds.git_queue", "guard"], &in_order),
        (&in_order, &["holds.event_bus", "holds.git_queue"]),
    ];
    for (steps, mandatory) in rejected {
        let rec = record(steps);
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_steps(&rec, mandatory)
        }))
        .is_err();
        assert!(failed, "{steps:?} with mandatory {mandatory:?} must fail");
    }
}
