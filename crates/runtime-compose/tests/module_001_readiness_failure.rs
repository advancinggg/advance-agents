//! MODULE-001-T111 (1) / MODULE-001-AC-30 — a readiness line that cannot be written stops
//! the composition: `compose` returns the typed `ComposeError::Readiness` (which
//! `advance start` prints and exits 1 on) after tearing down everything started before
//! the line — the Client API, the selected-provider writer, the git commit queue, the
//! EventBus — and the agent loop was never started.
//!
//! The only test of its binary: it checks process-wide state.

#[path = "support/t111.rs"]
mod t111;

use std::io;
use std::sync::Arc;

use advance_runtime_compose::test_support::{ComposeFailpoints, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, log_keys, ComposeError};
use t111::{alive_tasks, assert_composition_gone, assert_steps, serial, T111Home};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_readiness_failure_is_typed_and_tears_down() {
    let _serial = serial();
    let home = T111Home::new(&["fs", "llm"], true);
    let baseline = alive_tasks();

    let log = MemoryComposeLog::failing_ready(io::ErrorKind::BrokenPipe);
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
    .expect_err("the readiness line cannot be written");
    match &error {
        ComposeError::Readiness(io) => assert_eq!(io.kind(), io::ErrorKind::BrokenPipe),
        other => panic!("expected ComposeError::Readiness, got {other:?}"),
    }
    assert_eq!(
        error.to_string(),
        format!(
            "failed to flush readiness signal: {}",
            io::Error::from(io::ErrorKind::BrokenPipe)
        )
    );
    assert!(
        std::error::Error::source(&error).is_some(),
        "the io error is the source"
    );

    assert_eq!(log.count(log_keys::READY), 1, "the line was attempted once");
    assert_eq!(log.count(log_keys::AGENT_LOOP_WIRED), 0, "no agent loop");
    assert_eq!(
        log.count(log_keys::SHUTTING_DOWN),
        0,
        "a failed start prints nothing"
    );

    let record = probe.record();
    assert_steps(
        &record,
        &[
            "ingress.client_api",
            "holds.selected_provider",
            "holds.git_queue",
            "holds.event_bus",
            "holds.drop_graph",
            "guard",
        ],
    );
    assert!(
        !record.step_names().contains(&"loops.root"),
        "the root loop never started:\n{}",
        record.render_steps()
    );
    assert_composition_gone(baseline, &probe, &home.home).await;
}
