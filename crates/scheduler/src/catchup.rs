//! Restart catch-up logic — Slice D (AC-08).
//!
//! `catch_up_components(registry, now_ms, dispatcher)` iterates rows whose
//! `expected_next_fire_at_ms` is in the past and dispatches each ONCE.
//!
//! - One-shot rows (`interval_ms.is_none()`): after successful dispatch,
//!   `record_fire(id, now_ms, None)` clears `expected_next_fire_at_ms`.
//! - Recurring rows (`interval_ms.is_some()`): after successful dispatch,
//!   `record_fire(id, now_ms, Some(now_ms + interval_ms))` schedules the
//!   next tick.
//!
//! Per-row dispatch failures (HookError from the dispatcher) are captured
//! in `outcome.dispatched_ok = false` + `outcome.error_message`; the
//! registry row is LEFT UNCHANGED so a subsequent catch-up attempt retries.
//!
//! Per-row registry write failures (RegistryError from `record_fire` AFTER
//! successful dispatch) are captured in `outcome.registry_write_failed = true`
//! + `outcome.error_message`. The dispatch itself already fired, but the
//! state mutation failed — operator will see the failed bookkeeping.
//!
//! Iteration-stopping registry errors (e.g. SQL connection lost during
//! `list()`) surface as the function's outer `Err(RegistryError)`. There is
//! NO `CatchupError` enum: the outer error type is just `RegistryError`,
//! per round-3 contract simplification.

use async_trait::async_trait;

use crate::hook::HookError;
use crate::registry::{ComponentRegistry, ComponentRegistryRow, RegistryError};
use crate::types::ComponentId;

/// Per-row catch-up outcome. The `error_message` field is non-None when
/// either `dispatched_ok = false` (per-row dispatch err) or
/// `registry_write_failed = true` (per-row record_fire err after success).
#[derive(Clone, Debug)]
pub struct CatchupOutcome {
    pub id: ComponentId,
    pub kind: CatchupKind,
    pub dispatched_ok: bool,
    pub registry_write_failed: bool,
    pub error_message: Option<String>,
}

/// Classification of a caught-up row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatchupKind {
    /// `interval_ms.is_none()` — one-shot. Cleared after dispatch.
    OneShotMissed,
    /// `interval_ms.is_some()` — recurring. Rescheduled to next tick.
    RecurringMissed,
}

/// Per-row dispatcher trait. Implementors invoke the real driver entry for
/// the row's component type and return Ok / Err. The `#[async_trait]` keeps
/// the trait object-safe and matches the `RunnableHook` pattern in
/// `hook.rs`.
#[async_trait]
pub trait CatchupDispatcher: Send + Sync {
    async fn dispatch_catchup(&self, row: &ComponentRegistryRow) -> Result<(), HookError>;
}

/// Iterate registry rows whose `expected_next_fire_at_ms <= now_ms` and
/// dispatch each ONCE. Returns the per-row outcome vector; only
/// iteration-stopping registry errors surface as the outer Err.
pub async fn catch_up_components(
    registry: &ComponentRegistry,
    now_ms: i64,
    dispatcher: &dyn CatchupDispatcher,
) -> Result<Vec<CatchupOutcome>, RegistryError> {
    let all_rows = registry.list().await?;
    let mut outcomes = Vec::new();
    for row in all_rows {
        let missed = row
            .expected_next_fire_at_ms
            .map(|t| t <= now_ms)
            .unwrap_or(false);
        if !missed {
            continue;
        }
        let kind = match row.interval_ms {
            Some(_) => CatchupKind::RecurringMissed,
            None => CatchupKind::OneShotMissed,
        };
        let dispatch_result = dispatcher.dispatch_catchup(&row).await;
        let outcome = match dispatch_result {
            Ok(()) => {
                // Dispatch succeeded — attempt the registry write.
                // Audit Round-1 Warning-2 fix: use saturating_add so a row with
                // an attacker-chosen huge `interval_ms` cannot panic in debug
                // or wrap in release builds.
                let next_ts = row.interval_ms.map(|iv| now_ms.saturating_add(iv));
                let write_result = registry.record_fire(row.id.as_str(), now_ms, next_ts).await;
                match write_result {
                    Ok(()) => CatchupOutcome {
                        id: row.id.clone(),
                        kind,
                        dispatched_ok: true,
                        registry_write_failed: false,
                        error_message: None,
                    },
                    Err(e) => CatchupOutcome {
                        id: row.id.clone(),
                        kind,
                        dispatched_ok: true,
                        registry_write_failed: true,
                        error_message: Some(format!("record_fire failed: {e}")),
                    },
                }
            }
            Err(hook_err) => CatchupOutcome {
                id: row.id.clone(),
                kind,
                dispatched_ok: false,
                registry_write_failed: false,
                error_message: Some(format!("{hook_err}")),
            },
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ComponentRegistryRow;

    // Test the outcome shape construction (no DB needed).
    #[test]
    fn outcome_oneshot_success_shape() {
        // Just verify the struct compiles and fields match.
        let _ = CatchupOutcome {
            id: crate::types::ComponentId("x".to_owned()),
            kind: CatchupKind::OneShotMissed,
            dispatched_ok: true,
            registry_write_failed: false,
            error_message: None,
        };
    }

    #[test]
    fn outcome_recurring_dispatch_failed_shape() {
        let _ = CatchupOutcome {
            id: crate::types::ComponentId("y".to_owned()),
            kind: CatchupKind::RecurringMissed,
            dispatched_ok: false,
            registry_write_failed: false,
            error_message: Some("synthetic dispatch failure".to_owned()),
        };
    }

    // Object-safety regression-lock for CatchupDispatcher.
    fn _object_safe(_: Box<dyn CatchupDispatcher>) {}

    // Construct a dummy row to verify the row struct shape.
    fn _dummy_row() -> ComponentRegistryRow {
        ComponentRegistryRow {
            id: crate::types::ComponentId("test".to_owned()),
            component_type: advance_shared_types::component::ComponentType::Cron,
            submit_config: crate::types::ComponentSubmitConfig {
                sensitive_params: Vec::new(),
                id: "test".into(),
                component_type: advance_shared_types::component::ComponentType::Cron,
                binary: Vec::new(),
                capabilities: Vec::new(),
                output_dir: None,
                trigger: None,
                restart_policy: None,
                delay: None,
                initial_grants: None,
                preset: None,
                retry: None,
            },
            submitter: "agent:root".to_owned(),
            submitted_at_ms: 0,
            interval_ms: Some(5_000),
            expected_next_fire_at_ms: Some(0),
            last_fire_at_ms: None,
        }
    }
}
