//! AC-03 (MODULE-014-AC-03 / REQ-023, T03) verification: a delayed task
//! waits N ms then runs.
//!
//! `TaskRunner::run_task` already honors `submit_cfg.delay` via
//! `tokio::time::sleep` (Slice B); Slice E adds this deterministic
//! virtual-clock (`start_paused`) verification. A real-time delay
//! regression test already exists in `driver_loops.rs`; this adds explicit
//! AC-03 attribution + determinism (no wall-clock race). All calls use the
//! full 5-arg `run_task(id, cfg, None /*trigger_context*/, hook,
//! None /*output_dir*/)` signature.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::task::TaskRunner;
use advance_scheduler::types::{ComponentConfig, ComponentSubmitConfig, RunResult, RunStatus};
use advance_shared_types::component::ComponentType;

struct FlagHook {
    fired: Arc<AtomicBool>,
}

#[async_trait]
impl RunnableHook for FlagHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        self.fired.store(true, Ordering::SeqCst);
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

fn task_cfg(id: &str, delay: Option<u64>) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

// T03.a — delay=5000ms: NOT fired before 5 s; fired after.
#[tokio::test(start_paused = true)]
async fn t03a_delay_5s_fires_after_5s() {
    let fired = Arc::new(AtomicBool::new(false));
    let hook: Arc<dyn RunnableHook> = Arc::new(FlagHook {
        fired: fired.clone(),
    });
    let cfg = task_cfg("t-delay", Some(5000));
    let jh =
        tokio::spawn(async move { TaskRunner::run_task("t-delay", cfg, None, hook, None).await });

    // Advance to just short of the delay — hook must NOT have fired.
    tokio::time::advance(Duration::from_millis(4999)).await;
    tokio::task::yield_now().await;
    assert!(
        !fired.load(Ordering::SeqCst),
        "hook fired before the 5 s delay elapsed"
    );

    // Advance past the delay — hook fires, run_task returns Completed.
    tokio::time::advance(Duration::from_millis(2)).await;
    let r = jh.await.expect("spawned task joined").expect("run_task Ok");
    assert!(matches!(r.status, RunStatus::Completed));
    assert!(
        fired.load(Ordering::SeqCst),
        "hook did not fire after the 5 s delay elapsed"
    );
}

// T03.b — delay=None fires immediately.
#[tokio::test(start_paused = true)]
async fn t03b_no_delay_fires_immediately() {
    let fired = Arc::new(AtomicBool::new(false));
    let hook: Arc<dyn RunnableHook> = Arc::new(FlagHook {
        fired: fired.clone(),
    });
    let r = TaskRunner::run_task("t-now", task_cfg("t-now", None), None, hook, None)
        .await
        .expect("run_task Ok");
    assert!(matches!(r.status, RunStatus::Completed));
    assert!(
        fired.load(Ordering::SeqCst),
        "no-delay task must fire immediately"
    );
}

// T03.c — delay=Some(0) fires immediately (zero-delay == no wait).
#[tokio::test(start_paused = true)]
async fn t03c_zero_delay_fires_immediately() {
    let fired = Arc::new(AtomicBool::new(false));
    let hook: Arc<dyn RunnableHook> = Arc::new(FlagHook {
        fired: fired.clone(),
    });
    let r = TaskRunner::run_task("t-zero", task_cfg("t-zero", Some(0)), None, hook, None)
        .await
        .expect("run_task Ok");
    assert!(matches!(r.status, RunStatus::Completed));
    assert!(
        fired.load(Ordering::SeqCst),
        "zero-delay task must fire immediately"
    );
}
