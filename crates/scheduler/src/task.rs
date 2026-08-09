//! `TaskRunner` (PRD §4.3) + real one-shot delay + hook invocation.
//!
//! Slice A shipped the skeleton struct.
//! Slice B adds `run_task(id, submit_cfg, trigger_context, hook)`:
//! - Honors `submit_cfg.delay` via `tokio::time::sleep`.
//! - Invokes hook exactly once and returns its `RunResult`.
//! - Accepts `trigger_context: Option<TriggerContext>` for trigger-driven
//!   tasks (the watcher-spawned variant); standalone delayed tasks pass
//!   `None`.
//!
//! Slice E (m014-slice-e) AC-10 adds `run_expired_catchup{,_default}`:
//! bounded-concurrency expired-task catch-up over the SQLite
//! `ComponentRegistry`, reusing the public `CatchupDispatcher` trait. The
//! existing sequential `catchup::catch_up_components` (AC-08 helper) is left
//! untouched; this is a NEW, distinct owned-`Arc` entry (`JoinSet::spawn`
//! needs `'static + Send`). See MODULE-014 §3.8 (y).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::sleep;

use advance_shared_types::traits::EventBusEmit;

use crate::catchup::{CatchupDispatcher, CatchupKind, CatchupOutcome};
use crate::component_emit::{
    emit_component_error, emit_component_finished, emit_component_started,
};
use crate::hook::{HookError, RunnableHook};
use crate::output;
use crate::registry::{ComponentRegistry, RegistryError};
use crate::types::{
    ComponentConfig, ComponentSubmitConfig, RunResult, TriggerContext,
    DEFAULT_MAX_CONCURRENT_CATCHUP,
};

/// Slice A `TaskRunner` skeleton + Slice B real one-shot loop.
#[derive(Default)]
pub struct TaskRunner;

impl TaskRunner {
    pub fn new() -> Self {
        Self
    }

    /// One-shot task: honor `submit_cfg.delay` if `Some(ms)` via
    /// `tokio::time::sleep`; then invoke hook exactly once and return its
    /// result. No restart, no scheduling.
    ///
    /// `trigger_context` flows through into the `ComponentConfig` passed to
    /// the hook so trigger-driven tasks (spawned by WatcherDriver) can
    /// surface the originating event's context to the runnable.
    /// Slice C: new `output_dir: Option<PathBuf>` parameter wires
    /// post-run `result.bin` atomic write. Task is one-shot; the write
    /// happens once after the hook returns Ok.
    pub async fn run_task(
        id: &str,
        submit_cfg: ComponentSubmitConfig,
        trigger_context: Option<TriggerContext>,
        hook: Arc<dyn RunnableHook>,
        output_dir: Option<PathBuf>,
    ) -> Result<RunResult, HookError> {
        // Preserved byte-compatibly: delegate to the emitter-aware variant
        // with no event sink (sched-residue slice, the run_periodic /
        // run_periodic_with_emitter precedent).
        Self::run_task_with_emitter(id, submit_cfg, trigger_context, hook, output_dir, None).await
    }

    /// sched-residue: emitter-aware sibling of [`TaskRunner::run_task`].
    /// Identical one-shot semantics, but emits `component.started`
    /// immediately before the hook (AFTER the optional delay — started marks
    /// run begin, not submit+delay begin) and `component.finished` /
    /// `component.error` from the hook result before re-propagating it
    /// unchanged. `emitter == None` ⇒ behaves exactly like the pre-existing
    /// `run_task`.
    pub async fn run_task_with_emitter(
        id: &str,
        submit_cfg: ComponentSubmitConfig,
        trigger_context: Option<TriggerContext>,
        hook: Arc<dyn RunnableHook>,
        output_dir: Option<PathBuf>,
        emitter: Option<Arc<dyn EventBusEmit>>,
    ) -> Result<RunResult, HookError> {
        if let Some(delay_ms) = submit_cfg.delay {
            sleep(Duration::from_millis(delay_ms)).await;
        }
        let config = ComponentConfig {
            id: submit_cfg.id.clone(),
            config_data: None,
            trigger_context,
        };
        emit_component_started(emitter.as_ref(), id, "task");
        let run_started_at = Instant::now();
        // sched-residue: the former `hook.run_once(..).await?` is
        // restructured to bind-match-repropagate (behavior-identical) so
        // Err(Failure) emits component.error before re-returning.
        let result = hook.run_once(config).await;
        match &result {
            Ok(run_result) => emit_component_finished(
                emitter.as_ref(),
                id,
                "task",
                run_started_at.elapsed().as_millis() as u64,
                &run_result.status,
            ),
            Err(HookError::Failure(msg)) => {
                emit_component_error(emitter.as_ref(), id, "task", msg);
            }
            Err(HookError::Cancelled) => {
                // Cancellation is not failure: no emission (orphan-started
                // accepted posture, component_emit.rs rustdoc).
            }
        }
        let result = result?;
        // Slice C: result.bin atomic write. Errors logged but not
        // propagated (best-effort side channel).
        if let Some(dir) = output_dir.as_deref() {
            if let Err(e) = output::write_result_to_dir(dir, &result).await {
                eprintln!(
                    "TaskRunner::run_task id={:?}: write_result_to_dir failed: {}",
                    id, e
                );
            }
        }
        Ok(result)
    }

    /// AC-10: bounded-concurrency expired-task catch-up.
    ///
    /// Takes ONE `registry.list()` snapshot, filters rows whose
    /// `expected_next_fire_at_ms <= now_ms`, and dispatches each via the
    /// public `CatchupDispatcher` with at most `max_concurrent` in flight
    /// (a `tokio::sync::Semaphore` permit is acquired on the parent task
    /// BEFORE each `JoinSet::spawn`, so concurrency is bounded). Per-row
    /// outcome semantics are byte-identical to the sequential
    /// `catchup::catch_up_components` (AC-08): one-shot
    /// (`interval_ms.is_none()`) → `record_fire(.., None)` clears
    /// `expected_next_fire_at_ms`; recurring → `record_fire(..,
    /// Some(now_ms + interval))`.
    ///
    /// Owned `Arc` inputs: `JoinSet::spawn` requires `'static + Send`
    /// futures; `CatchupDispatcher::dispatch_catchup` borrows and
    /// `ComponentRegistry` is non-`Clone`, so the spawn-based design takes
    /// `Arc<ComponentRegistry>` / `Arc<dyn CatchupDispatcher>` (both
    /// `Send + Sync + 'static`). `catch_up_components` keeps its `&`-borrow
    /// signature and is left untouched.
    ///
    /// The spawned task body is **panic-free by construction**: `id`/`kind`
    /// are captured before any `.await`; every dispatch / `record_fire`
    /// error is mapped into a `CatchupOutcome` field (never `.unwrap()`).
    /// The only `.expect()` is on the parent-task `acquire_owned` and is
    /// infallible (the semaphore is never `close()`d). A `JoinError` is
    /// therefore reachable only if the externally-injected dispatcher
    /// impl itself panics. The join loop **drains the entire `JoinSet`
    /// to completion before re-raising** the first such panic (or
    /// returning a non-panic `JoinError`): re-raising mid-drain would
    /// drop `set` and abort sibling tasks that have already fired
    /// `dispatch_catchup` but not yet completed `record_fire`, leaving
    /// those rows armed and re-dispatched next pass. Draining first makes
    /// the **panic axis** on par with the sequential `catch_up_components`
    /// (a sibling `dispatch_catchup` panic no longer abandons other
    /// spawned rows' `record_fire`) while still preserving the non-
    /// swallowing behavior (the first panic is propagated via
    /// `resume_unwind` AFTER the drain). This parity is scoped to the
    /// panic axis ONLY: on the **parent-future-cancellation axis** (the
    /// caller drops the `run_expired_catchup` future), async Rust cannot
    /// `.await` the `JoinSet` from `drop`, so up to `max_concurrent`
    /// in-flight dispatches plus the un-spawned remainder are aborted —
    /// any sibling that fired `dispatch_catchup` but not `record_fire` is
    /// left armed and re-dispatched next pass. That at-least-once-on-
    /// cancel posture (wider than the sequential path's single in-flight
    /// dispatch ONLY because bounded concurrency is the AC-10 spec'd
    /// requirement) is NOT resolved here: its only correct fix is the
    /// per-row dispatch-claim flag / `expected_next_fire_at_ms` CAS,
    /// which needs out-of-boundary `registry.rs` schema changes and is
    /// the formally-declared `waived_scope[0]` Slice-E item — the same
    /// at-least-once posture the sequential `catch_up_components`
    /// inherits, NOT newly introduced. Single-invocation safe. See
    /// MODULE-014 §3.8 (y).
    pub async fn run_expired_catchup(
        registry: Arc<ComponentRegistry>,
        now_ms: i64,
        dispatcher: Arc<dyn CatchupDispatcher>,
        max_concurrent: usize,
    ) -> Result<Vec<CatchupOutcome>, RegistryError> {
        let all_rows = registry.list().await?;
        let sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
        let mut set: JoinSet<CatchupOutcome> = JoinSet::new();
        for row in all_rows {
            let overdue = row
                .expected_next_fire_at_ms
                .map(|t| t <= now_ms)
                .unwrap_or(false);
            if !overdue {
                continue;
            }
            let permit = Arc::clone(&sem)
                .acquire_owned()
                .await
                .expect("catch-up semaphore is never closed");
            let reg = Arc::clone(&registry);
            let disp = Arc::clone(&dispatcher);
            set.spawn(async move {
                let _permit = permit;
                let id = row.id.clone();
                let kind = if row.interval_ms.is_some() {
                    CatchupKind::RecurringMissed
                } else {
                    CatchupKind::OneShotMissed
                };
                match disp.dispatch_catchup(&row).await {
                    Ok(()) => {
                        let next_ts = row.interval_ms.map(|iv| now_ms.saturating_add(iv));
                        match reg.record_fire(row.id.as_str(), now_ms, next_ts).await {
                            Ok(()) => CatchupOutcome {
                                id,
                                kind,
                                dispatched_ok: true,
                                registry_write_failed: false,
                                error_message: None,
                            },
                            Err(e) => CatchupOutcome {
                                id,
                                kind,
                                dispatched_ok: true,
                                registry_write_failed: true,
                                error_message: Some(format!("record_fire failed: {e}")),
                            },
                        }
                    }
                    Err(he) => CatchupOutcome {
                        id,
                        kind,
                        dispatched_ok: false,
                        registry_write_failed: false,
                        error_message: Some(format!("{he}")),
                    },
                }
            });
        }
        // Drain the ENTIRE JoinSet before propagating any panic / non-
        // panic JoinError. Re-raising mid-loop would drop `set`, aborting
        // sibling tasks that may have already fired `dispatch_catchup`
        // but not yet completed `record_fire` — leaving those rows armed
        // and re-dispatched on the next pass (duplicate dispatch).
        // Draining first guarantees every spawned row's bookkeeping runs
        // to completion (genuine single-invocation parity with
        // `catch_up_components`); the first panic is re-raised AFTER the
        // drain so the non-swallowing behavior is preserved.
        let mut outcomes = Vec::new();
        let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;
        let mut first_join_err: Option<String> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(o) => outcomes.push(o),
                Err(je) if je.is_panic() => {
                    if first_panic.is_none() {
                        first_panic = Some(je.into_panic());
                    }
                }
                Err(je) => {
                    if first_join_err.is_none() {
                        first_join_err = Some(format!("catchup task join error: {je}"));
                    }
                }
            }
        }
        if let Some(p) = first_panic {
            std::panic::resume_unwind(p);
        }
        if let Some(e) = first_join_err {
            return Err(RegistryError::Io(e));
        }
        Ok(outcomes)
    }

    /// AC-10 default-consuming entry: binds the documented
    /// `scheduler.max_concurrent_catchup` default (`= 3`,
    /// `DEFAULT_MAX_CONCURRENT_CATCHUP`) so callers get the spec'd "default
    /// 3" behavior without passing the cap. This is the in-scope code path
    /// that makes AC-10's "default 3" an implemented behavior rather than a
    /// dangling constant (verified by `tests/concurrent_catchup_limit.rs`
    /// T08.b). The production scheduler-startup caller that would invoke
    /// this after registry recovery is the waived Slice-E
    /// full-driver→registry tick-tracking wiring (MODULE-014 §3.2/§3.5/§3.7).
    pub async fn run_expired_catchup_default(
        registry: Arc<ComponentRegistry>,
        now_ms: i64,
        dispatcher: Arc<dyn CatchupDispatcher>,
    ) -> Result<Vec<CatchupOutcome>, RegistryError> {
        Self::run_expired_catchup(registry, now_ms, dispatcher, DEFAULT_MAX_CONCURRENT_CATCHUP)
            .await
    }
}
