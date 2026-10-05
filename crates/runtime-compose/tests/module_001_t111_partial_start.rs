//! MODULE-001-T111 (7) / MODULE-001-AC-30 — a failure after part of the runtime started:
//! the `POST /msg` listener cannot bind once the Client API, the git commit queue and the
//! root agent loop are up. `compose` returns `ComposeError::Listener` with today's text,
//! after the same ordered teardown as a requested shutdown (but without its
//! `advance: shutting down` line), and nothing of the composition is left; the home then
//! composes again.
//!
//! The only test of its binary: it checks process-wide state.

#[path = "support/t111.rs"]
mod t111;

use std::io;
use std::sync::Arc;

use advance_runtime_compose::test_support::{
    ComposeFailpoints, ComposeProbe, MemoryComposeLog, POST_MSG_FAILPOINT,
};
use advance_runtime_compose::{compose, log_keys, ComposeError};
use t111::{alive_tasks, assert_composition_gone, assert_steps, serial, T111Home};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_t111_7_post_msg_bind_failure_tears_down() {
    let _serial = serial();
    let home = T111Home::new(&["fs", "llm", "lifecycle"], true);
    let baseline = alive_tasks();

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(log.clone()))
            .with_failpoints(ComposeFailpoints {
                post_msg_bind: Some(io::ErrorKind::AddrInUse),
                probe: Some(Arc::clone(&probe)),
                ..ComposeFailpoints::default()
            }),
        Vec::new(),
    )
    .await
    .expect_err("the POST /msg listener cannot bind");
    assert!(matches!(error, ComposeError::Listener(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!(
            "failed to bind POST /msg listener: {}",
            io::Error::new(io::ErrorKind::AddrInUse, POST_MSG_FAILPOINT)
        )
    );

    // It failed after the readiness line and the agent loop, before the listener line,
    // and the teardown of a failed start prints nothing.
    assert_eq!(log.count(log_keys::READY), 1);
    assert_eq!(log.count(log_keys::AGENT_LOOP_WIRED), 1);
    assert_eq!(log.count(log_keys::MSG_LISTENER), 0);
    assert_eq!(log.count(log_keys::SHUTTING_DOWN), 0);

    let record = probe.record();
    assert_steps(
        &record,
        &[
            "ingress.client_api",
            "loops.root",
            "holds.git_queue",
            "holds.event_bus",
            "guard",
        ],
    );
    assert!(
        !record.step_names().contains(&"ingress.post_msg"),
        "no POST /msg listener was bound, so none is stopped:\n{}",
        record.render_steps()
    );
    assert_composition_gone(baseline, &probe, &home.home).await;

    // Without the failpoint the same home composes and stops.
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
    .expect("the home composes after the failed start");
    assert!(
        probe.record().listener("post_msg").is_some(),
        "POST /msg is bound this time"
    );
    runtime.shutdown().await.expect("shutdown");
    assert_composition_gone(baseline, &probe, &home.home).await;
}
