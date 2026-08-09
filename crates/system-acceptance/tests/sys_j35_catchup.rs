//! SYS-J-35 restart catch-up journey witnesses (SYS-AC-112, 113, 114).
//!
//! Real product: the production `catch_up_components` (sequential, AC-08) and
//! `TaskRunner::run_expired_catchup` (semaphore-bounded, AC-10) over the durable SQLite
//! `ComponentRegistry` (MODULE-014). Driven through the harness `.with_triggers()` seam
//! (`sut.submit_registry()`). Mirrors `crates/scheduler/tests/{catchup_recovery,
//! concurrent_catchup_limit}.rs` at the system-acceptance witness layer.
//!
//! The injected `CatchupDispatcher` is the runnable-dispatch seam (the real
//! component-run is the P-runnable follow-up). The witnessed substance — fire-EXACTLY-once,
//! `expected_next_fire_at_ms` clear/advance, and the ≤3 concurrency bound — is all real
//! M014 over the real registry; the dispatcher is the dispatch boundary, not a stub of
//! the catch-up scheduling logic.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_scheduler::task::TaskRunner;
use advance_scheduler::{
    catch_up_components, CatchupDispatcher, ComponentRegistryRow, ComponentSubmitConfig, HookError,
};
use advance_shared_types::component::ComponentType;

use system_acceptance::SystemUnderTest;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// A fixed "now" comfortably above any seeded `expected_next_fire_at_ms`.
const NOW: i64 = 10_000_000;

/// Counts dispatches (the fire-exactly-once witness for 112/113).
#[derive(Default)]
struct CountingDispatcher {
    dispatched: AtomicUsize,
}

#[async_trait]
impl CatchupDispatcher for CountingDispatcher {
    async fn dispatch_catchup(&self, _row: &ComponentRegistryRow) -> Result<(), HookError> {
        self.dispatched.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Records peak concurrent in-flight dispatches (the ≤3 bound witness for 114). Holds a
/// 30 ms sleep so ≥4 overdue rows genuinely contend for the 3-permit semaphore (an
/// instant-return dispatcher would never exceed 1 — a vacuous pass).
#[derive(Default)]
struct MaxObservingDispatcher {
    in_flight: AtomicUsize,
    max_observed: AtomicUsize,
    dispatched: AtomicUsize,
}

#[async_trait]
impl CatchupDispatcher for MaxObservingDispatcher {
    async fn dispatch_catchup(&self, _row: &ComponentRegistryRow) -> Result<(), HookError> {
        let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_observed.fetch_max(cur, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(30)).await;
        self.dispatched.fetch_add(1, Ordering::SeqCst);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}

fn cfg(id: &str, t: ComponentType) -> ComponentSubmitConfig {
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

async fn triggers_sut() -> SystemUnderTest {
    SystemUnderTest::builder()
        .with_triggers()
        .build(J01_SKELETON)
        .await
}

// SYS-AC-112 — after restart, a missed one-shot task (past expected_next_fire_at_ms)
// fires exactly once and its expected_next_fire_at_ms is cleared; a second pass dispatches
// it zero times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_112_oneshot_catchup_fires_once_and_clears() {
    let sut = triggers_sut().await;
    let reg = sut.submit_registry();
    // One-shot: interval None. insert writes NULL expected_next → arm it overdue.
    reg.insert("agent:root", &cfg("os-112", ComponentType::Task), None)
        .await
        .expect("insert one-shot");
    reg.set_expected_next_fire("os-112", Some(NOW - 1_000))
        .await
        .expect("arm overdue");

    let d1 = Arc::new(CountingDispatcher::default());
    let o1 = catch_up_components(reg, NOW, d1.as_ref())
        .await
        .expect("first catch-up pass");
    assert_eq!(o1.len(), 1, "the missed one-shot was caught up");
    assert_eq!(
        d1.dispatched.load(Ordering::SeqCst),
        1,
        "fired exactly once"
    );

    let row = reg.get("os-112").await.expect("get").expect("present");
    assert_eq!(
        row.expected_next_fire_at_ms, None,
        "one-shot expected_next_fire cleared"
    );

    // Second pass at the same now → zero dispatches (idempotent).
    let d2 = Arc::new(CountingDispatcher::default());
    let o2 = catch_up_components(reg, NOW, d2.as_ref())
        .await
        .expect("second catch-up pass");
    assert!(o2.is_empty(), "the cleared one-shot is not caught up again");
    assert_eq!(
        d2.dispatched.load(Ordering::SeqCst),
        0,
        "second pass dispatches zero"
    );
}

// SYS-AC-113 — after restart, a missed recurring schedule fires exactly once and its
// expected_next_fire_at_ms advances to now + interval_ms (NOT back-filled per missed
// interval).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_113_recurring_catchup_fires_once_and_reschedules() {
    let sut = triggers_sut().await;
    let reg = sut.submit_registry();
    // Recurring: interval Some(5_000) (>= MIN_RECURRING_INTERVAL_MS). Arm it overdue.
    reg.insert(
        "agent:root",
        &cfg("rec-113", ComponentType::Cron),
        Some(5_000),
    )
    .await
    .expect("insert recurring");
    reg.set_expected_next_fire("rec-113", Some(NOW - 1_000))
        .await
        .expect("arm overdue");

    let d = Arc::new(CountingDispatcher::default());
    let o = catch_up_components(reg, NOW, d.as_ref())
        .await
        .expect("catch-up pass");
    assert_eq!(o.len(), 1, "the missed recurring schedule was caught up");
    assert_eq!(
        d.dispatched.load(Ordering::SeqCst),
        1,
        "fired exactly once (not once-per-missed-interval)"
    );

    let row = reg.get("rec-113").await.expect("get").expect("present");
    assert_eq!(
        row.expected_next_fire_at_ms,
        Some(NOW + 5_000),
        "recurring rescheduled to now + interval (single advance, not back-filled)"
    );
}

// SYS-AC-114 — concurrent expired-task catch-up dispatch is bounded by
// max_concurrent_catchup (default 3): no more than 3 catch-up runs execute simultaneously.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_114_concurrent_catchup_bounded_by_3() {
    let sut = triggers_sut().await;
    let reg = sut.submit_registry();
    // 10 overdue one-shot rows — far more than the cap, so the bound is genuinely stressed.
    for i in 0..10 {
        let id = format!("c{i}");
        reg.insert("agent:root", &cfg(&id, ComponentType::Task), None)
            .await
            .expect("insert");
        reg.set_expected_next_fire(&id, Some(NOW - 1_000))
            .await
            .expect("arm overdue");
    }

    let mock = Arc::new(MaxObservingDispatcher::default());
    // Use the DEFAULT entry point (binds DEFAULT_MAX_CONCURRENT_CATCHUP=3 from the
    // product, types.rs) rather than passing a literal 3 — so the witness covers the
    // criterion's "default 3", not just "the semaphore honors whatever cap I pass".
    let outcomes = TaskRunner::run_expired_catchup_default(Arc::clone(reg), NOW, mock.clone())
        .await
        .expect("run_expired_catchup_default");

    assert_eq!(outcomes.len(), 10, "all 10 overdue rows were caught up");
    assert_eq!(
        mock.dispatched.load(Ordering::SeqCst),
        10,
        "each overdue row dispatched once"
    );
    let peak = mock.max_observed.load(Ordering::SeqCst);
    assert!(
        peak <= 3,
        "concurrency bounded by max_concurrent_catchup=3; observed peak {peak}"
    );
    // Non-vacuous: 10 rows each held 30 ms across 4 workers genuinely contend up to the cap.
    assert!(
        peak >= 2,
        "the cap was actually stressed (peak >= 2); observed {peak}"
    );
}
