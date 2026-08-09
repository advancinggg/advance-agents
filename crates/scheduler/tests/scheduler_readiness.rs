//! Slice C AC-20 verification: `Scheduler::start_with_readiness(probe)`
//! returns `Err(RuntimeNotReady)` when the readiness probe reports false;
//! returns `Ok(())` when probe reports true.
//!
//! The HostRegistry-backed `RuntimeReadiness` adapter is in `waived_scope`
//! (formally declared in the Slice C plan). Slice C verifies the gate
//! orchestration via mock probes at the trait level — matches the
//! Slice B precedent for `RunBootstrap`-via-mock.

use std::sync::Arc;

use async_trait::async_trait;

use advance_scheduler::hook::RuntimeReadiness;
use advance_scheduler::scheduler::{Scheduler, SchedulerStartError};
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;

/// Mock probe that returns a configurable boolean.
struct MockReadiness {
    ready: bool,
}

#[async_trait]
impl RuntimeReadiness for MockReadiness {
    async fn is_ready(&self) -> bool {
        self.ready
    }
}

fn make_scheduler() -> Scheduler {
    let bus = Arc::new(TriggerBusDispatchImpl::new());
    Scheduler::new(bus)
}

#[tokio::test]
async fn readiness_false_fails_fast() {
    let sched = make_scheduler();
    let probe: Arc<dyn RuntimeReadiness> = Arc::new(MockReadiness { ready: false });
    let result = sched.start_with_readiness(probe).await;
    assert!(matches!(result, Err(SchedulerStartError::RuntimeNotReady)));
}

#[tokio::test]
async fn readiness_true_succeeds() {
    let sched = make_scheduler();
    let probe: Arc<dyn RuntimeReadiness> = Arc::new(MockReadiness { ready: true });
    let result = sched.start_with_readiness(probe).await;
    assert!(result.is_ok());
}
