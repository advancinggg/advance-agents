//! `DaemonManager` (PRD §4.3) + real restart loop driven by `restart_decision`.
//!
//! Slice A shipped the pure `restart_decision` truth-table helper.
//! Slice B added `run_daemon(id, policy, hook, config, cancel_token)`:
//! - Iterates the hook in a loop.
//! - Maps `Result<RunResult, HookError>` → succeeded bool.
//! - Consults `restart_decision(policy, succeeded)` → Stop or Restart.
//! - Cancellation via `CancellationToken`.
//!
//! Slice D adds AC-21 daemon restart back-off via a new 7th arg
//! `backoff: Option<RestartBackoffConfig>`. `RestartBackoffConfig` is
//! scheduler-local and DISTINCT from PRD §9.5.1 `retry-config` (LLM/tool
//! retries owned by MODULE-009 / run-manager). The loop uses a 4-way
//! `match (decision, succeeded, backoff.as_ref())` branch table that gates
//! the exponential delay-ladder on `succeeded == false`. See MODULE-014
//! §3.8 notes (j) for the schema-distinction rationale.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use advance_shared_types::traits::EventBusEmit;

use crate::component_emit::{
    emit_component_error, emit_component_finished, emit_component_started,
};
use crate::cron::compute_jitter;
use crate::hook::{HookError, RunnableHook};
use crate::output;
use crate::types::{ComponentConfig, RestartPolicy, RetryConfig};

/// Scheduler-local restart back-off config. Used by `DaemonManager::run_daemon`
/// 7th arg. DISTINCT from PRD §9.5.1 `retry-config` (LLM/tool retry shape
/// owned by `crates/run-manager/src/retry.rs`). Daemon restart back-off and
/// LLM/tool retries address orthogonal concerns — see MODULE-014 §3.8 note
/// (j).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestartBackoffConfig {
    /// Maximum number of retries before giving up (and returning
    /// `Err(HookError::Failure("max retries exceeded"))`). Clamped at
    /// `MAX_RESTART_RETRIES`.
    pub max_retries: u32,
    /// Base delay between retries in milliseconds. The delay-ladder
    /// progresses as `min(base * 2^(attempt-1), max_delay_ms)`.
    pub base_delay_ms: u64,
    /// Hard ceiling on the per-attempt delay. Clamped at
    /// `MAX_RESTART_BACKOFF_DELAY_MS`.
    pub max_delay_ms: u64,
    /// Add deterministic jitter (FNV-1a via `compute_jitter`) on top of the
    /// computed delay to prevent thundering-herd retries across multiple
    /// daemon components with identical backoff configs.
    pub jitter: bool,
}

impl Default for RestartBackoffConfig {
    fn default() -> Self {
        Self {
            max_retries: 0,
            base_delay_ms: 0,
            max_delay_ms: 0,
            jitter: false,
        }
    }
}

/// Hard cap on `RestartBackoffConfig.max_delay_ms` — 1 hour. Distinct from
/// `MAX_TASK_DELAY_MS = 7 days` (one-shot delayed-task admission ceiling).
pub const MAX_RESTART_BACKOFF_DELAY_MS: u64 = 60 * 60 * 1000;

/// Hard cap on `RestartBackoffConfig.max_retries` — 1024.
pub const MAX_RESTART_RETRIES: u32 = 1024;

/// Parse-restart-backoff-config error.
#[derive(Debug, Error)]
pub enum ParseRestartBackoffError {
    #[error("serde error: {0}")]
    Serde(String),
    #[error("invalid field: {0}")]
    InvalidField(String),
}

/// Slice D helper: read a scheduler-local `RestartBackoffConfig` out of a
/// PRD §9.5.1 `RetryConfig` opaque JSON. Currently NOT exercised in Slice D
/// production paths (Slice D tests pass `RestartBackoffConfig` directly to
/// `run_daemon`); exported for future Slice E + downstream callers who want
/// to mirror an LLM-style retry config into daemon restart back-off.
///
/// The opaque `RetryConfig` newtype wraps `serde_json::Value`; this function
/// looks for the kebab-case top-level fields `max-retries`, `base-delay-ms`,
/// `max-delay-ms`, `jitter`. Behavior per field:
/// - Missing → defaults to 0 / false.
/// - Mistyped (non-integer where integer expected, non-bool where bool
///   expected, negative integer, out-of-u32 integer) → returns
///   `Err(ParseRestartBackoffError::InvalidField(msg))`.
/// - In-range u32/u64 numeric values that exceed `MAX_RESTART_RETRIES` /
///   `MAX_RESTART_BACKOFF_DELAY_MS` are CLAMPED to the cap (not rejected).
///   Rationale: defense-in-depth — admission cannot be denied for a
///   "too-large but well-typed" config; the clamp simply enforces the
///   ceiling.
pub fn parse_restart_backoff_config(
    retry: &RetryConfig,
) -> Result<RestartBackoffConfig, ParseRestartBackoffError> {
    let v = &retry.0;
    let obj = v.as_object().ok_or_else(|| {
        ParseRestartBackoffError::InvalidField("RetryConfig payload is not a JSON object".into())
    })?;

    let max_retries = read_u32(obj, "max-retries")?.min(MAX_RESTART_RETRIES);
    let base_delay_ms = read_u64(obj, "base-delay-ms")?;
    let max_delay_ms = read_u64(obj, "max-delay-ms")?.min(MAX_RESTART_BACKOFF_DELAY_MS);
    let jitter = read_bool(obj, "jitter")?;

    Ok(RestartBackoffConfig {
        max_retries,
        base_delay_ms,
        max_delay_ms,
        jitter,
    })
}

/// Strict bool reader: missing key → false; present-and-typed → value; present-and-mistyped → Err.
/// Round-2 audit-fix: `jitter` field was previously read with permissive
/// `as_bool().unwrap_or(false)` — strict now matches the numeric readers.
fn read_bool(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, ParseRestartBackoffError> {
    match obj.get(key) {
        None => Ok(false),
        Some(v) => v.as_bool().ok_or_else(|| {
            ParseRestartBackoffError::InvalidField(format!("field {key:?} is not a bool"))
        }),
    }
}

/// Strict u32 reader: missing key → 0; present-and-typed → value; present-and-mistyped or out-of-u32 → Err.
fn read_u32(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u32, ParseRestartBackoffError> {
    match obj.get(key) {
        None => Ok(0),
        Some(v) => match v.as_u64() {
            None => Err(ParseRestartBackoffError::InvalidField(format!(
                "field {key:?} is not a non-negative integer"
            ))),
            Some(n) => u32::try_from(n).map_err(|_| {
                ParseRestartBackoffError::InvalidField(format!(
                    "field {key:?} value {n} exceeds u32::MAX"
                ))
            }),
        },
    }
}

/// Strict u64 reader: missing key → 0; present-and-typed → value; present-and-mistyped → Err.
fn read_u64(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, ParseRestartBackoffError> {
    match obj.get(key) {
        None => Ok(0),
        Some(v) => v.as_u64().ok_or_else(|| {
            ParseRestartBackoffError::InvalidField(format!(
                "field {key:?} is not a non-negative integer"
            ))
        }),
    }
}

/// Slice A `DaemonManager` skeleton + Slice B real restart loop.
#[derive(Default)]
pub struct DaemonManager;

impl DaemonManager {
    pub fn new() -> Self {
        Self
    }

    /// Real restart loop driven by `restart_decision`. Each iteration:
    /// 1. Check cancel-token (early exit on pre-tick cancel).
    /// 2. Invoke hook (race against cancel via tokio::select!).
    /// 3. Map result to `succeeded: bool` (Ok → true; Err → false).
    /// 4. `restart_decision(policy, succeeded)` → Stop / Restart.
    /// 5. On Stop → return; on Restart → next iteration.
    ///
    /// Slice C added `output_dir: Option<PathBuf>` parameter wiring
    /// per-iteration `result.bin` atomic write.
    ///
    /// Slice D adds `backoff: Option<RestartBackoffConfig>` (7th arg) for
    /// AC-21 — when present, exponential delay between failed iterations
    /// (gated on `succeeded == false`); success path resets `attempt`
    /// counter and skips the sleep. When `backoff = None`, falls back to
    /// Slice C `tokio::task::yield_now` pattern.
    pub async fn run_daemon(
        id: &str,
        policy: RestartPolicy,
        hook: Arc<dyn RunnableHook>,
        config: ComponentConfig,
        output_dir: Option<PathBuf>,
        cancel_token: CancellationToken,
        backoff: Option<RestartBackoffConfig>,
    ) -> Result<(), HookError> {
        // Preserved byte-compatibly: delegate to the emitter-aware variant
        // with no event sink (sched-residue slice, the run_periodic /
        // run_periodic_with_emitter precedent). Every existing
        // caller/signature is unchanged.
        Self::run_daemon_with_emitter(
            id,
            policy,
            hook,
            config,
            output_dir,
            None,
            cancel_token,
            backoff,
        )
        .await
    }

    /// sched-residue: emitter-aware sibling of [`DaemonManager::run_daemon`].
    /// Identical restart loop, but emits `component.started` at the top of
    /// each restart iteration and `component.finished` / `component.error`
    /// at the success-discrimination point — one started per iteration
    /// (each iteration IS a run under the daemon restart model). `emitter ==
    /// None` ⇒ behaves exactly like the pre-existing `run_daemon`.
    ///
    /// Emission semantics (component_emit.rs rustdoc):
    /// - `Ok(run_result)` → `component.finished` with `status` from
    ///   `run_result.status` (`Ok(Failed)` is finished-with-status, matching
    ///   `restart_decision`'s `result.is_ok()` success notion).
    /// - `Err(HookError::Failure)` → `component.error`; the restart/backoff
    ///   machinery runs after it unchanged (a max-retries-exhausted return
    ///   needs no extra emission — that iteration's error already emitted).
    /// - `Err(HookError::Cancelled)` / cancel-mid-hook → nothing after the
    ///   iteration's started (orphan-started accepted posture).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_daemon_with_emitter(
        id: &str,
        policy: RestartPolicy,
        hook: Arc<dyn RunnableHook>,
        config: ComponentConfig,
        output_dir: Option<PathBuf>,
        emitter: Option<Arc<dyn EventBusEmit>>,
        cancel_token: CancellationToken,
        backoff: Option<RestartBackoffConfig>,
    ) -> Result<(), HookError> {
        let mut attempt: u32 = 1;
        loop {
            if cancel_token.is_cancelled() {
                return Ok(());
            }
            emit_component_started(emitter.as_ref(), id, "daemon");
            let run_started_at = Instant::now();
            // Race the hook against cancel so a long-running hook does not
            // block daemon shutdown.
            let result = tokio::select! {
                res = hook.run_once(config.clone()) => res,
                _ = cancel_token.cancelled() => return Ok(()),
            };
            // HookError::Cancelled short-circuits the restart loop regardless
            // of policy.
            if matches!(result, Err(HookError::Cancelled)) {
                return Ok(());
            }
            // sched-residue: single discrimination point — Cancelled already
            // short-circuited above, so result here is Ok or Err(Failure).
            // Emission happens BEFORE the best-effort output write (adversarial
            // r7 fix) so `duration_ms` measures the hook only and `finished`
            // is not delayed by disk latency — the same semantics as the
            // cron/watcher emit sites (cross-driver duration consistency).
            match &result {
                Ok(run_result) => emit_component_finished(
                    emitter.as_ref(),
                    id,
                    "daemon",
                    run_started_at.elapsed().as_millis() as u64,
                    &run_result.status,
                ),
                Err(HookError::Failure(msg)) => {
                    emit_component_error(emitter.as_ref(), id, "daemon", msg);
                }
                Err(HookError::Cancelled) => {
                    // Unreachable: short-circuited above. No emission.
                }
            }
            // Per-iteration result.bin atomic write on Ok (best-effort).
            if let Ok(ref run_result) = result {
                if let Some(dir) = output_dir.as_deref() {
                    if let Err(e) = output::write_result_to_dir(dir, run_result).await {
                        eprintln!(
                            "DaemonManager::run_daemon id={:?}: write_result_to_dir failed: {}",
                            id, e
                        );
                    }
                }
            }
            let succeeded = result.is_ok();
            let decision = restart_decision(policy, succeeded);

            // Slice D 4-way branch table — gates the delay-ladder on
            // succeeded==false only. See MODULE-014 §3.8 note (j).
            match (decision, succeeded, backoff.as_ref()) {
                // Policy says stop: exit cleanly.
                (RestartDecision::Stop, _, _) => return Ok(()),

                // Policy says restart on SUCCESS (e.g. Always + Ok). No error
                // path, no backoff — reset attempt counter; cooperative yield.
                (RestartDecision::Restart, true, _) => {
                    attempt = 1;
                    tokio::task::yield_now().await;
                    continue;
                }

                // Policy says restart on FAILURE without backoff config: Slice
                // C cooperative-yield path. attempt counter not used.
                (RestartDecision::Restart, false, None) => {
                    tokio::task::yield_now().await;
                    continue;
                }

                // Policy says restart on FAILURE with backoff config:
                // exponential delay ladder.
                (RestartDecision::Restart, false, Some(cfg)) => {
                    if attempt > cfg.max_retries {
                        return Err(HookError::Failure("max retries exceeded".into()));
                    }
                    // Compute delay: min(base * 2^(attempt-1), max_delay_ms).
                    // Clamp exponent at 20 so the saturating_mul cannot wrap u64.
                    // Audit Round-1 Warning-3 fix: jitter is applied BEFORE the
                    // max_delay_ms clamp so the final sleep can never exceed the
                    // documented cap.
                    let exp = (attempt.saturating_sub(1)).min(20);
                    let raw = cfg.base_delay_ms.saturating_mul(1u64 << exp);
                    let with_jitter = if cfg.jitter {
                        let j = compute_jitter(id, &attempt.to_string(), raw, 0.1);
                        raw.saturating_add(j.as_millis() as u64)
                    } else {
                        raw
                    };
                    let delay_ms = with_jitter.min(cfg.max_delay_ms);
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                        _ = cancel_token.cancelled() => return Ok(()),
                    }
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            }
        }
    }
}

/// Slice A restart-decision outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    Stop,
    Restart,
}

/// Pure restart-policy truth table per MODULE-014 §1.4.2b. The real
/// loop in Slice B wraps this — for now it's directly testable.
///
/// | policy     | succeeded | decision |
/// |------------|-----------|----------|
/// | Never      | true      | Stop     |
/// | Never      | false     | Stop     |
/// | OnFailure  | true      | Stop     |
/// | OnFailure  | false     | Restart  |
/// | Always     | true      | Restart  |
/// | Always     | false     | Restart  |
pub fn restart_decision(policy: RestartPolicy, succeeded: bool) -> RestartDecision {
    use RestartPolicy::*;
    match (policy, succeeded) {
        (Never, _) => RestartDecision::Stop,
        (OnFailure, true) => RestartDecision::Stop,
        (OnFailure, false) => RestartDecision::Restart,
        (Always, _) => RestartDecision::Restart,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_stops_on_success() {
        assert_eq!(
            restart_decision(RestartPolicy::Never, true),
            RestartDecision::Stop
        );
    }

    #[test]
    fn never_stops_on_failure() {
        assert_eq!(
            restart_decision(RestartPolicy::Never, false),
            RestartDecision::Stop
        );
    }

    #[test]
    fn on_failure_stops_on_success() {
        assert_eq!(
            restart_decision(RestartPolicy::OnFailure, true),
            RestartDecision::Stop
        );
    }

    #[test]
    fn on_failure_restarts_on_failure() {
        assert_eq!(
            restart_decision(RestartPolicy::OnFailure, false),
            RestartDecision::Restart
        );
    }

    #[test]
    fn always_restarts_on_success() {
        assert_eq!(
            restart_decision(RestartPolicy::Always, true),
            RestartDecision::Restart
        );
    }

    #[test]
    fn always_restarts_on_failure() {
        assert_eq!(
            restart_decision(RestartPolicy::Always, false),
            RestartDecision::Restart
        );
    }
}
