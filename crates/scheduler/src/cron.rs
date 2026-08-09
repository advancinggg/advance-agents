//! `CronDriver` (PRD §4.3) + real periodic tick loop.
//!
//! Slice A shipped:
//! - `CronDriver` skeleton struct (`new` constructor).
//! - `compute_jitter` real FNV-1a 64-bit deterministic hash.
//!
//! Slice B adds `run_periodic(id, interval, hook, config, cancel_token)`:
//! - Real `tokio::time::interval_at` loop with jitter as the initial offset.
//! - `Duration::ZERO` and `> 30-day` upper bound reject (defensive).
//! - Cancellation via `CancellationToken`.
//!
//! The cron-expression-string adapter (`*/5 * * * *` → `Duration`) is part
//! of the CronExpr-integration scaffolding declared in `waived_scope`
//! (`.dev-state/state.json`); `run_periodic` accepts a fixed `Duration`
//! interval here, which is sufficient to exercise the periodic-loop
//! control flow + jitter wiring covered by AC-12's adjacent ACs.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{interval_at, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use advance_shared_types::traits::EventBusEmit;

use crate::component_emit::{
    emit_component_error, emit_component_finished, emit_component_started,
};
use crate::hook::{HookError, RunnableHook};
use crate::output;
use crate::trigger_emit::emit_trigger_fired;
use crate::types::ComponentConfig;

/// Slice A `CronDriver` skeleton + Slice B real periodic loop.
#[derive(Default)]
pub struct CronDriver;

impl CronDriver {
    pub fn new() -> Self {
        Self
    }

    /// Real periodic tick loop. Slice B: takes a fixed `interval: Duration`
    /// rather than a `CronExpr` — the cron-expression-to-Duration
    /// adapter is part of the CronExpr-integration scaffolding
    /// declared in `waived_scope` (`.dev-state/state.json`).
    /// Applies `compute_jitter(id, "", interval_ms, 0.1)` as the initial
    /// offset so simultaneous component starts spread out.
    ///
    /// Cancellation: `cancel_token.cancelled()` returns immediately; loop
    /// exits cleanly.
    ///
    /// Defensive validation:
    /// - `Duration::ZERO` rejected (`tokio::time::interval_at` panics on it).
    /// - Interval `> 30 days` rejected to prevent `Instant::now() + jitter`
    ///   overflowing Tokio's internal Instant representation.
    /// Slice C: new `output_dir: Option<PathBuf>` parameter wires per-tick
    /// `result.bin` atomic write via `output::write_result_to_dir`. When
    /// None, no write happens. Caller is responsible for path-confinement
    /// (see MODULE-014 §3.8 Implementation Notes (c)).
    pub async fn run_periodic(
        id: &str,
        interval: Duration,
        hook: Arc<dyn RunnableHook>,
        config: ComponentConfig,
        output_dir: Option<PathBuf>,
        cancel_token: CancellationToken,
    ) -> Result<(), HookError> {
        // Preserved byte-compatibly: delegate to the emitter-aware variant with
        // no event sink (sched-triggers slice). Every existing caller/signature
        // is unchanged.
        Self::run_periodic_with_emitter(id, interval, hook, config, output_dir, None, cancel_token)
            .await
    }

    /// sched-triggers (trigger-chain product pre-build): the emitter-aware
    /// sibling of [`CronDriver::run_periodic`]. Identical tick loop, but emits a
    /// `trigger.fired` event (`trigger_type == "cron"`) on every tick — before
    /// invoking the hook — via the optional dependency-inverted
    /// [`EventBusEmit`] sink. `emitter == None` ⇒ behaves exactly like the
    /// pre-existing `run_periodic` (no-op emission).
    ///
    /// Note: `trigger.fired` is emitted at tick time, so the emitted count
    /// equals the number of ticks (fires), NOT the number of successful hook
    /// completions — a tick that fires then immediately cancels still recorded
    /// the fire (future-witness SYS-AC-099).
    pub async fn run_periodic_with_emitter(
        id: &str,
        interval: Duration,
        hook: Arc<dyn RunnableHook>,
        config: ComponentConfig,
        output_dir: Option<PathBuf>,
        emitter: Option<Arc<dyn EventBusEmit>>,
        cancel_token: CancellationToken,
    ) -> Result<(), HookError> {
        if interval.is_zero() {
            return Err(HookError::Failure(
                "CronDriver::run_periodic interval must be > Duration::ZERO".into(),
            ));
        }
        const MAX_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24 * 30);
        if interval > MAX_INTERVAL {
            return Err(HookError::Failure(format!(
                "CronDriver::run_periodic interval {:?} exceeds 30-day ceiling",
                interval
            )));
        }
        let interval_ms = interval.as_millis() as u64;
        // Slice B: schedule arg is `""` because we don't have cron-expression
        // strings yet. Disambiguation is via `id` alone — ComponentRegistry's
        // per-ID uniqueness invariant prevents collision.
        let jitter = compute_jitter(id, "", interval_ms, 0.1);
        let start = Instant::now() + jitter;
        let mut ticker = interval_at(start, interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => return Ok(()),
                _ = ticker.tick() => {
                    // sched-triggers: emit trigger.fired at the fire moment
                    // (before the hook runs). No-op when no emitter is wired.
                    emit_trigger_fired(emitter.as_ref(), id, "cron");
                    // sched-residue: component.started marks run begin. Like
                    // trigger.fired, it is emitted before the hook races the
                    // cancel token — a cancel-mid-hook therefore yields an
                    // orphan started (no finished/error), the documented
                    // accepted posture (component_emit.rs rustdoc).
                    emit_component_started(emitter.as_ref(), id, "cron");
                    let run_started_at = Instant::now();
                    // Audit Round-3 Diff-Warning-2 fix: race the hook
                    // against cancel-token like DaemonManager does. A
                    // long-running cron hook should not extend cancellation
                    // latency beyond the current hook's duration.
                    let result = tokio::select! {
                        _ = cancel_token.cancelled() => return Ok(()),
                        res = hook.run_once(config.clone()) => res,
                    };
                    match result {
                        Ok(run_result) => {
                            // sched-residue: finished reflects hook success
                            // (independent of the best-effort output write
                            // below); Ok(Failed-status) is finished with
                            // status=="failed", not component.error.
                            emit_component_finished(
                                emitter.as_ref(),
                                id,
                                "cron",
                                run_started_at.elapsed().as_millis() as u64,
                                &run_result.status,
                            );
                            // Slice C: per-tick result.bin atomic write.
                            // Errors logged but not propagated — the
                            // tick itself succeeded; output-write is a
                            // best-effort side channel. Visibility via
                            // eprintln per the Slice B/C diagnostic
                            // pattern (structured event emission is a
                            // follow-up concern).
                            if let Some(dir) = output_dir.as_deref() {
                                if let Err(e) = output::write_result_to_dir(dir, &run_result).await
                                {
                                    eprintln!(
                                        "CronDriver::run_periodic id={:?}: write_result_to_dir failed: {}",
                                        id, e
                                    );
                                }
                            }
                        }
                        Err(HookError::Cancelled) => return Ok(()),
                        Err(HookError::Failure(msg)) => {
                            // Slice B: surface non-cancel hook errors but
                            // keep the loop alive. Structured per-id
                            // restart-on-tick-failure policy is a
                            // follow-up slice's concern. sched-residue:
                            // the structured surface is component.error.
                            emit_component_error(emitter.as_ref(), id, "cron", &msg);
                        }
                    }
                }
            }
        }
    }
}

/// FNV-1a 64-bit deterministic hash. Non-cryptographic; chosen for
/// supply-chain reasons (no extra crate needed) and adequate diffusion
/// for cron-window-spreading purposes.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// Compute a deterministic anti-thundering-herd jitter offset.
///
/// - `id` and `schedule` together identify the cron component.
/// - `period_ms` is the cron period in milliseconds.
/// - `ratio` is the maximum jitter as a fraction of `period_ms`
///   (typical: 0.1, capped to the canonical 900 000 ms ceiling per
///   MODULE-014 §1.4.2 pseudocode).
///
/// **Defensive semantics**:
/// 1. `ratio.is_nan()` short-circuits to `Duration::ZERO` BEFORE the
///    `clamp()` chain (`f64::clamp(NaN, _, _)` returns NaN; then
///    `NaN.min(900_000.0)` returns 900_000 because NaN comparisons are
///    `false`, which would yield a misleadingly non-zero jitter from a
///    malformed ratio). The explicit guard treats NaN as "skip jitter
///    entirely".
/// 2. Negative ratios clamp to 0.0 → zero jitter.
/// 3. Ratios > 1.0 clamp to 1.0.
/// 4. The 900 000 ms (15-minute) ceiling matches §1.4.2 pseudocode.
///
/// Determinism: same `(id, schedule, period_ms, ratio)` inputs always
/// produce the same `Duration`.
pub fn compute_jitter(id: &str, schedule: &str, period_ms: u64, ratio: f64) -> Duration {
    if ratio.is_nan() {
        return Duration::ZERO;
    }
    let ratio = ratio.clamp(0.0, 1.0);
    let max_jitter_ms = ((period_ms as f64) * ratio).min(900_000.0) as u64;
    if max_jitter_ms == 0 {
        return Duration::ZERO;
    }
    let mut buf = id.as_bytes().to_vec();
    buf.push(0);
    buf.extend_from_slice(schedule.as_bytes());
    let h = fnv1a64(&buf);
    Duration::from_millis(h % max_jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn determinism_same_input_same_output() {
        let a = compute_jitter("cron-a", "*/5 * * * *", 300_000, 0.1);
        let b = compute_jitter("cron-a", "*/5 * * * *", 300_000, 0.1);
        assert_eq!(a, b);
    }

    #[test]
    fn differentiation_distinct_ids() {
        let mut seen = HashSet::new();
        for i in 0..100 {
            let id = format!("cron-{i}");
            seen.insert(compute_jitter(&id, "*/5 * * * *", 300_000, 0.1));
        }
        // FNV-1a over varying ids should produce overwhelmingly
        // distinct outputs. Threshold 95/100 leaves slack for
        // hash collisions while catching constant or near-constant
        // implementations.
        assert!(
            seen.len() >= 95,
            "expected >= 95 distinct jitter values, got {}",
            seen.len()
        );
    }

    #[test]
    fn bound_below_ceiling() {
        // ratio=1.0 + huge period — jitter is capped at 900_000 ms.
        for i in 0..1_000 {
            let id = format!("cron-{i}");
            let j = compute_jitter(&id, "* * * * *", u64::MAX / 2, 1.0);
            assert!(
                j < Duration::from_millis(900_000),
                "jitter {j:?} exceeds 15-min ceiling"
            );
        }
    }

    #[test]
    fn nan_ratio_returns_zero() {
        let j = compute_jitter("cron-x", "*/5 * * * *", 300_000, f64::NAN);
        assert_eq!(j, Duration::ZERO);
    }

    #[test]
    fn negative_ratio_clamps_to_zero() {
        let j = compute_jitter("cron-x", "*/5 * * * *", 300_000, -0.5);
        assert_eq!(j, Duration::ZERO);
    }

    #[test]
    fn ratio_above_one_clamps_to_one() {
        let j_one = compute_jitter("cron-x", "*/5 * * * *", 60_000, 1.0);
        let j_huge = compute_jitter("cron-x", "*/5 * * * *", 60_000, 5.0);
        assert_eq!(j_one, j_huge);
    }
}
