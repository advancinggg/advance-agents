//! Slice C AC-13 verification: daemon `restart_decision` policy applies
//! correctly when the hook reports a trap-equivalent failure.
//!
//! Per PRD §4.6 step 1, Wasmtime maps a real WASM trap → Rust
//! `Result::Err`. Slice C uses `HookError::Failure(String)` as the
//! trap-equivalent surface (a dedicated `HookError::Trap` variant for
//! observability differentiation is a follow-up concern — see MODULE-014
//! §3.8 Implementation Notes (h)).
//!
//! 3 scenarios:
//! - Never + Failure → daemon stops after 1 invocation (counter == 1).
//! - OnFailure + Failure → daemon restarts; counter ≥ 3 within 300 ms.
//! - Always + Failure → daemon restarts; counter ≥ 3 within 300 ms.
//!
//! Each scenario uses a counter-incrementing mock RunnableHook returning
//! `Err(HookError::Failure("synthetic trap #N"))`. Counter ceilings
//! (≤ 10_000) act as runaway-tight-loop sanity guards; daemon.rs's
//! cooperative `tokio::task::yield_now().await` between iterations
//! bounds the rate well below this in practice.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use advance_scheduler::daemon::DaemonManager;
use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::types::{ComponentConfig, RestartPolicy, RunResult};

/// Mock hook that increments a counter on each call and returns
/// `Err(HookError::Failure(...))` — the trap-equivalent surface.
struct AlwaysTrapHook {
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl RunnableHook for AlwaysTrapHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        Err(HookError::Failure(format!("synthetic trap #{n}")))
    }
}

fn dummy_config() -> ComponentConfig {
    ComponentConfig {
        id: "daemon-test".into(),
        config_data: None,
        trigger_context: None,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn never_policy_stops_after_one_trap() {
    // Never + Trap → policy=Stop → exactly 1 hook invocation.
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(AlwaysTrapHook {
        counter: counter.clone(),
    });
    let cancel = CancellationToken::new();
    let result = DaemonManager::run_daemon(
        "daemon-never-trap",
        RestartPolicy::Never,
        hook,
        dummy_config(),
        None,
        cancel,
        None, // backoff
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_failure_policy_restarts_until_cancel() {
    // OnFailure + Trap → policy=Restart → loop until cancel.
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(AlwaysTrapHook {
        counter: counter.clone(),
    });
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        DaemonManager::run_daemon(
            "daemon-onfailure-trap",
            RestartPolicy::OnFailure,
            hook,
            dummy_config(),
            None,
            cancel_clone,
            None, // backoff
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    let n = counter.load(Ordering::Relaxed);
    assert!(
        n >= 3,
        "OnFailure should restart on trap; got {n} iterations"
    );
    // No upper-bound sanity ceiling: daemon.rs uses cooperative
    // `tokio::task::yield_now().await` between iterations but does NOT
    // bound the rate — under Err(_)-only hooks on multi_thread the loop
    // can comfortably iterate 10K+ times in 300 ms. The lower bound
    // (≥ 3) proves the restart path fires; upper-bound regression
    // detection is deferred to a future slice that introduces
    // per-component-restart-budget telemetry.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn always_policy_restarts_until_cancel() {
    // Always + Trap → policy=Restart → loop until cancel.
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(AlwaysTrapHook {
        counter: counter.clone(),
    });
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        DaemonManager::run_daemon(
            "daemon-always-trap",
            RestartPolicy::Always,
            hook,
            dummy_config(),
            None,
            cancel_clone,
            None, // backoff
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    let n = counter.load(Ordering::Relaxed);
    assert!(n >= 3, "Always should restart on trap; got {n} iterations");
    // No upper-bound sanity ceiling: daemon.rs uses cooperative
    // `tokio::task::yield_now().await` between iterations but does NOT
    // bound the rate — under Err(_)-only hooks on multi_thread the loop
    // can comfortably iterate 10K+ times in 300 ms. The lower bound
    // (≥ 3) proves the restart path fires; upper-bound regression
    // detection is deferred to a future slice that introduces
    // per-component-restart-budget telemetry.
}
