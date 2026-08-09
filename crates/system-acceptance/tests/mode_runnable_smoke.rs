//! HF fast-follow smoke (2026-06-03): `drive_runnable()` (Tracks F/G).
//!
//! Drives a runnable component's `run(config)` in-process via a TEST `RunnableHook`
//! (the trait + RunResult are shipped; the production WASM runnable path is the
//! upstream `P-runnable` follow-up — see the crate README).

use std::sync::Arc;

use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::types::{ComponentConfig, RunResult, RunStatus};
use async_trait::async_trait;
use system_acceptance::SystemUnderTest;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// Test hook that completes, echoing the component id into the output.
struct OkHook;
#[async_trait]
impl RunnableHook for OkHook {
    async fn run_once(&self, cfg: ComponentConfig) -> Result<RunResult, HookError> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: Some(cfg.id.into_bytes()),
        })
    }
}

/// Test hook that reports a per-iteration failure.
struct FailHook;
#[async_trait]
impl RunnableHook for FailHook {
    async fn run_once(&self, _cfg: ComponentConfig) -> Result<RunResult, HookError> {
        Ok(RunResult {
            status: RunStatus::Failed("boom".into()),
            output: None,
        })
    }
}

#[tokio::test]
async fn drive_runnable_runs_a_test_hook() {
    let sut = SystemUnderTest::builder().build(CORE_BYTES).await;

    let res = sut
        .drive_runnable(Arc::new(OkHook), "cron:daily", None, None)
        .await
        .expect("run_once returns Ok");
    assert_eq!(res.status, RunStatus::Completed);
    assert_eq!(res.output.as_deref(), Some(b"cron:daily".as_slice()));

    let failed = sut
        .drive_runnable(Arc::new(FailHook), "cron:fail", None, None)
        .await
        .expect("run_once returns Ok(Failed)");
    assert_eq!(failed.status, RunStatus::Failed("boom".into()));
}
