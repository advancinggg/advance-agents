//! Production scheduler tick loop (Wave-7 Lane B, 2026-06-22).
//!
//! [`run_scheduler_tick_loop`] is the persistent interval driver that fans
//! [`Scheduler::dispatch_tick`] out to every registered [`crate::SchedulerExtension`]
//! on a fixed cadence. Before this, `Scheduler::register_extension` →
//! `dispatch_tick` → `on_tick` was test-only (no production caller existed — the
//! cli composition root noted "no production `dispatch_tick` loop exists yet"). The
//! cli daemon (`advance start`) registers the auto-mode extension on a `Scheduler`
//! and spawns this loop, so MODULE-015's `DefaultAutoLoopDriver::run_cadence_pass`
//! (degrade/halt detection) + the auto terminal-settle coordinator finally run on a
//! real production tick.
//!
//! It mirrors [`crate::cron::CronDriver::run_periodic`]: a real
//! `tokio::time::interval_at` loop with the same `Duration::ZERO` / 30-day-ceiling
//! defensive bounds and `CancellationToken`-driven clean exit. It is intentionally
//! minimal — the cadence/settle/notify policy all lives inside the registered
//! extensions' `on_tick`; this runner only supplies the wall-clock `now_ms` and the
//! fan-out.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::{interval_at, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::scheduler::Scheduler;
use crate::types::SchedulerTick;

/// Wall-clock milliseconds since the Unix epoch as a `u64` (matching
/// [`SchedulerTick::now_ms`]). A pre-epoch clock (`Err`) saturates to 0 rather
/// than panicking — `run_cadence_pass`'s time math is all saturating, so a 0
/// anchor is harmless (it never fabricates an elapsed-time breach).
fn now_unix_ms_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Aborts the wrapped task when dropped. Wraps the per-tick fan-out `JoinHandle`
/// so that if the loop task is itself aborted mid-tick (daemon teardown), dropping
/// the loop future aborts the in-flight `dispatch_tick` task rather than DETACHING
/// it (a bare `JoinHandle` drop detaches, leaking the in-flight notify egress until
/// process exit — adversarial r10 W2).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Drive [`Scheduler::dispatch_tick`] on a fixed `interval` until `cancel` fires.
///
/// Each fire computes a fresh wall-clock `now_ms` and dispatches a
/// [`SchedulerTick`] to every registered extension (sequential fan-out, in
/// registration order). The per-tick `dispatch_tick` is raced against `cancel`
/// (mirroring `CronDriver::run_periodic`) so a slow extension cannot extend
/// shutdown latency beyond the in-flight tick.
///
/// Defensive validation (mirrors `CronDriver::run_periodic`): `Duration::ZERO`
/// is rejected (`tokio::time::interval_at` panics on it) and an interval `> 30
/// days` is rejected (guards `Instant::now() + interval` from overflowing
/// Tokio's internal `Instant`). On a bad interval the loop never starts and the
/// error is returned to the caller (which logs it and degrades — a missing tick
/// loop simply leaves the auto path dormant, never crashes the daemon).
pub async fn run_scheduler_tick_loop(
    scheduler: Arc<Scheduler>,
    interval: Duration,
    cancel: CancellationToken,
) -> Result<(), String> {
    if interval.is_zero() {
        return Err("run_scheduler_tick_loop interval must be > Duration::ZERO".to_string());
    }
    const MAX_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24 * 30);
    if interval > MAX_INTERVAL {
        return Err(format!(
            "run_scheduler_tick_loop interval {interval:?} exceeds 30-day ceiling"
        ));
    }

    let mut ticker = interval_at(Instant::now() + interval, interval);
    // Delay (not Burst): a stalled tick must not fire a backlog of catch-up
    // ticks all at once — a single late tick is sufficient for cadence work.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Consecutive per-tick panics: a poisoned driver mutex makes `run_cadence_pass`
    // re-panic on EVERY tick (std `Mutex` poison is permanent), which would otherwise
    // spew one log line per `interval` forever while doing zero cadence/settle work.
    // Stop after a small threshold with a single loud error instead of an unbounded
    // log flood + futile re-tick (adversarial r10 W1). A single transient panic resets
    // the counter on the next successful tick, so the loop keeps surviving one-off panics.
    const MAX_CONSECUTIVE_TICK_PANICS: u32 = 5;
    let mut consecutive_panics: u32 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = ticker.tick() => {
                let tick = SchedulerTick::new(now_unix_ms_u64());
                // Isolate the per-tick fan-out in its OWN task so a PANIC in an
                // extension's `on_tick` (e.g. a poisoned driver mutex inside
                // `run_cadence_pass`, which `.expect()`s) is caught + logged and the
                // loop SURVIVES to the next tick — rather than unwinding this whole
                // loop task and silently stopping all cadence/settle work for the
                // daemon's lifetime (audit r7). The fan-out is wrapped in `AbortOnDrop`
                // so if THIS loop task is itself aborted mid-tick (daemon teardown), the
                // in-flight fan-out is ABORTED, never detached/orphaned (adversarial r10
                // W2). The fan-out is raced against cancel so shutdown latency stays
                // bounded by the in-flight tick (the auto settle's RunManager mutations
                // are synchronous, so an aborted/dropped dispatch future never half-settles).
                let sched = Arc::clone(&scheduler);
                let mut fanout =
                    AbortOnDrop(tokio::spawn(async move { sched.dispatch_tick(tick).await }));
                tokio::select! {
                    // On shutdown, returning drops `fanout` → AbortOnDrop aborts the
                    // in-flight dispatch task (no orphan).
                    _ = cancel.cancelled() => return Ok(()),
                    res = &mut fanout.0 => {
                        // A panic in an extension's on_tick surfaces as a JoinError here
                        // (tokio also prints it via the default hook).
                        if let Err(e) = res {
                            if e.is_panic() {
                                consecutive_panics += 1;
                                eprintln!(
                                    "advance: scheduler tick dispatch panicked ({e}); the tick \
                                     loop continues ({consecutive_panics}/{MAX_CONSECUTIVE_TICK_PANICS} \
                                     consecutive)"
                                );
                                if consecutive_panics >= MAX_CONSECUTIVE_TICK_PANICS {
                                    return Err(format!(
                                        "scheduler tick loop disabled after {consecutive_panics} \
                                         consecutive dispatch panics (likely a poisoned driver mutex \
                                         — auto cadence/settle is non-functional; restart required)"
                                    ));
                                }
                                continue;
                            }
                        }
                        // A clean tick (or a non-panic JoinError, unreachable here) resets the run.
                        consecutive_panics = 0;
                    }
                }
            }
        }
    }
}
