//! T-TICK — production scheduler tick-loop runner (Wave-7 Lane B, 2026-06-22).
//!
//! Verifies `run_scheduler_tick_loop` drives `Scheduler::dispatch_tick` (→ every
//! registered extension's `on_tick`) on a fixed interval and stops cleanly on a
//! `CancellationToken`, plus its defensive interval bounds. Uses `start_paused`
//! so the interval ticks fire on the virtual clock (deterministic, no wall-clock
//! waits, non-flaky).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use advance_scheduler::{
    run_scheduler_tick_loop, ComponentEvent, Scheduler, SchedulerExtension, SchedulerTick,
    TriggerBusDispatchImpl,
};
use tokio_util::sync::CancellationToken;

/// A minimal `SchedulerExtension` that counts the `on_tick` fan-out calls.
struct CountingExt {
    ticks: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl SchedulerExtension for CountingExt {
    fn name(&self) -> &str {
        "counting"
    }
    async fn on_tick(&self, _tick: SchedulerTick) {
        self.ticks.fetch_add(1, Ordering::SeqCst);
    }
    async fn on_component_event(&self, _event: ComponentEvent) {}
}

fn scheduler_with_counter() -> (Arc<Scheduler>, Arc<AtomicU64>) {
    let mut scheduler = Scheduler::new(Arc::new(TriggerBusDispatchImpl::new()));
    let ticks = Arc::new(AtomicU64::new(0));
    let ext = Arc::new(CountingExt {
        ticks: Arc::clone(&ticks),
    });
    scheduler.register_extension(ext as Arc<dyn SchedulerExtension>);
    (Arc::new(scheduler), ticks)
}

/// An extension whose `on_tick` ALWAYS panics — to prove a PERSISTENT panic stops
/// the loop after the consecutive-panic threshold (adversarial r10 W1).
struct PanickingExt {
    ticks: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl SchedulerExtension for PanickingExt {
    fn name(&self) -> &str {
        "panicking"
    }
    async fn on_tick(&self, _tick: SchedulerTick) {
        self.ticks.fetch_add(1, Ordering::SeqCst);
        panic!("boom — simulated extension on_tick panic");
    }
    async fn on_component_event(&self, _event: ComponentEvent) {}
}

/// An extension whose `on_tick` panics on the FIRST tick only, then succeeds — to
/// prove the loop SURVIVES a transient panic and resets its consecutive counter.
struct PanicOnceExt {
    ticks: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl SchedulerExtension for PanicOnceExt {
    fn name(&self) -> &str {
        "panic-once"
    }
    async fn on_tick(&self, _tick: SchedulerTick) {
        // fetch_add returns the PRIOR value; panic only on the very first tick.
        if self.ticks.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("boom — one-shot panic on the first tick");
        }
    }
    async fn on_component_event(&self, _event: ComponentEvent) {}
}

// T-TICK-1 — the loop drives on_tick on the interval, then `cancel` stops it
// cleanly (Ok return; no ticks after cancel).
#[tokio::test(start_paused = true)]
async fn tick_loop_drives_on_tick_until_cancelled() {
    let (scheduler, ticks) = scheduler_with_counter();
    let cancel = CancellationToken::new();

    let handle = tokio::spawn(run_scheduler_tick_loop(
        scheduler,
        Duration::from_millis(10),
        cancel.clone(),
    ));

    // Virtual clock auto-advances while the test task is parked: a 10 ms interval
    // over 55 ms fires ~5 ticks (first at +10 ms).
    tokio::time::sleep(Duration::from_millis(55)).await;
    let observed = ticks.load(Ordering::SeqCst);
    assert!(
        observed >= 4,
        "expected the tick loop to drive >=4 on_tick fan-outs in 55ms@10ms, got {observed}"
    );

    cancel.cancel();
    let res = handle.await.expect("tick-loop task joins");
    assert!(res.is_ok(), "cancelled tick loop returns Ok, got {res:?}");

    // No further ticks fire after the loop has exited.
    let after_cancel = ticks.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        ticks.load(Ordering::SeqCst),
        after_cancel,
        "no on_tick fan-out after the loop is cancelled"
    );
}

// T-TICK-2 — defensive interval bounds: Duration::ZERO and > 30 days are rejected
// (no loop started), returning Err to the caller.
#[tokio::test]
async fn tick_loop_rejects_zero_and_oversized_interval() {
    let (scheduler, ticks) = scheduler_with_counter();
    let cancel = CancellationToken::new();

    let zero =
        run_scheduler_tick_loop(Arc::clone(&scheduler), Duration::ZERO, cancel.clone()).await;
    assert!(zero.is_err(), "Duration::ZERO interval must be rejected");

    let oversized = run_scheduler_tick_loop(
        scheduler,
        Duration::from_secs(60 * 60 * 24 * 31), // 31 days > 30-day ceiling
        cancel,
    )
    .await;
    assert!(oversized.is_err(), "> 30-day interval must be rejected");

    // Neither rejected call dispatched a tick.
    assert_eq!(ticks.load(Ordering::SeqCst), 0);
}

// T-TICK-3 — a TRANSIENT panic (first tick) is isolated to its per-tick task; the
// loop SURVIVES, resets its consecutive-panic counter, keeps ticking, and returns Ok
// on cancel (audit r7 + adversarial r10 W1: a one-off panic must not kill the loop).
#[tokio::test(start_paused = true)]
async fn tick_loop_survives_a_transient_panic() {
    let mut scheduler = Scheduler::new(Arc::new(TriggerBusDispatchImpl::new()));
    let ticks = Arc::new(AtomicU64::new(0));
    let ext = Arc::new(PanicOnceExt {
        ticks: Arc::clone(&ticks),
    });
    scheduler.register_extension(ext as Arc<dyn SchedulerExtension>);
    let scheduler = Arc::new(scheduler);
    let cancel = CancellationToken::new();

    let handle = tokio::spawn(run_scheduler_tick_loop(
        scheduler,
        Duration::from_millis(10),
        cancel.clone(),
    ));

    // The first tick panics (isolated); subsequent ticks succeed. (tokio prints the
    // one panic to stderr — expected noise.)
    tokio::time::sleep(Duration::from_millis(55)).await;
    let observed = ticks.load(Ordering::SeqCst);
    assert!(
        observed >= 3,
        "the loop must survive the transient panic and keep dispatching, got {observed}"
    );

    cancel.cancel();
    let res = handle.await.expect("the loop task itself never panics");
    assert!(
        res.is_ok(),
        "the loop returns Ok after a transient panic, got {res:?}"
    );
}

// T-TICK-4 — a PERSISTENT panic (every tick) stops the loop with a loud Err after the
// consecutive-panic threshold, rather than re-panicking + flooding logs forever
// (adversarial r10 W1).
#[tokio::test(start_paused = true)]
async fn tick_loop_stops_after_consecutive_panics() {
    let mut scheduler = Scheduler::new(Arc::new(TriggerBusDispatchImpl::new()));
    let ticks = Arc::new(AtomicU64::new(0));
    let ext = Arc::new(PanickingExt {
        ticks: Arc::clone(&ticks),
    });
    scheduler.register_extension(ext as Arc<dyn SchedulerExtension>);
    let scheduler = Arc::new(scheduler);
    let cancel = CancellationToken::new();

    let handle = tokio::spawn(run_scheduler_tick_loop(
        scheduler,
        Duration::from_millis(10),
        cancel,
    ));

    // Every tick panics → the loop hits the consecutive-panic threshold and returns Err.
    let res = handle.await.expect("the loop task itself never panics");
    let Err(msg) = res else {
        panic!("expected the loop to stop with Err after consecutive panics, got {res:?}");
    };
    assert!(
        msg.contains("consecutive"),
        "loud disabling error, got: {msg}"
    );
    // It stopped promptly (a handful of ticks, not unbounded).
    let observed = ticks.load(Ordering::SeqCst);
    assert!(
        observed <= 8,
        "stopped promptly after the threshold, got {observed}"
    );
}
