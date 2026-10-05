//! MODULE-001-AC-30 — a capability wiring that fails part-way hands back what it started,
//! and the composition's teardown stops it: the failure right after the git commit queue
//! started (with the EventBus, the cap-grant sweeper and the CONTRACT-218 custody already
//! up) returns `ComposeError::Wiring` with the wiring's text, the queue's worker is joined
//! before its registration is released, nothing is left, and the home composes again.
//!
//! The only test of its binary: it checks process-wide state.

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_runtime_compose::test_support::{
    ComposeFailpoints, ComposeProbe, MemoryComposeLog, WIRING_FAILPOINT,
};
use advance_runtime_compose::{compose, log_keys, ComposeError};
use t111::{alive_tasks, assert_composition_gone, assert_steps, serial, T111Home};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_wiring_failure_after_git_queue_tears_down() {
    let _serial = serial();
    let home = T111Home::new(&["fs", "llm", "lifecycle"], true);
    let baseline = alive_tasks();

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(log.clone()))
            .with_failpoints(ComposeFailpoints {
                wiring_after_git_queue: true,
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        Vec::new(),
    )
    .await
    .expect_err("the wiring fails after the git commit queue started");
    let expected = format!("agent-tree config materialization failure: {WIRING_FAILPOINT}");
    match &error {
        ComposeError::Wiring(text) => assert_eq!(text, &expected),
        other => panic!("expected ComposeError::Wiring, got {other:?}"),
    }
    assert_eq!(error.to_string(), format!("wiring failed: {expected}"));
    assert_eq!(log.count(log_keys::READY), 0, "it failed before readiness");
    assert_eq!(log.count(log_keys::SHUTTING_DOWN), 0);

    let record = probe.record();
    assert!(
        record.git_queue.is_some() && record.event_bus.is_some(),
        "the queue and the EventBus had started"
    );
    assert_steps(
        &record,
        &[
            "holds.watchers",
            "holds.cap_grant_sweeper",
            "holds.git_queue",
            "holds.event_bus",
            "holds.drop_graph",
            "guard",
        ],
    );
    // The EventBus and the queue are dead, and the queue's registration and the custody
    // paths are released: the worker was joined before its entry went.
    assert_composition_gone(baseline, &probe, &home.home).await;

    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose(
        home.options(Arc::new(MemoryComposeLog::new()))
            .with_failpoints(ComposeFailpoints {
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        Vec::new(),
    )
    .await
    .expect("the home composes after the failed wiring");
    runtime.shutdown().await.expect("shutdown");
    assert_composition_gone(baseline, &probe, &home.home).await;
}
