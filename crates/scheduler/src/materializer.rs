//! Registry→driver materializer — scheduler-internal half (S3 satellite).
//!
//! [`ComponentMaterializer`] turns an admitted [`ComponentRegistryRow`] into a
//! running driver: it builds a [`RunnableHook`] from the row's binary bytes via
//! the dependency-inverted [`RunnableHookFactory`] seam, then dispatches to the
//! matching driver entry (`CronDriver::run_periodic` / `WatcherDriver::
//! run_with_trigger_source` / `DaemonManager::run_daemon` / `TaskRunner::
//! run_task`). This closes the long-waived "post-readiness driver-entry
//! invocation" that `scheduler.rs`'s `driver_name` / `start_with_readiness`
//! rustdocs declared deferred since Slice B.
//!
//! **The data-driven link (anti-fake-green).** Every input — id, binary,
//! trigger, restart policy, retry, delay, output-dir — is EXTRACTED FROM the
//! row (`row.id` + `row.submit_config`), never minted from an id string. The
//! SYS-AC-109 fake-green (a driver bound to its admission only by an id string,
//! so deleting the submit still "passed") is structurally impossible here: the
//! factory receives `row.submit_config.binary` and the hook runs with a
//! `ComponentConfig.id` derived from `row.id`. The witness in
//! `tests/materializer.rs` regression-locks this with a binary-mutation
//! discriminator.
//!
//! **Trait-inversion preserved.** The only WASM-aware seam is
//! `RunnableHookFactory` (takes `&[u8]`, not a runtime `LoadedComponent`); the
//! materializer holds an `Arc<dyn RunnableHookFactory>` and never names a
//! runtime type. No `advance-runtime`/`wasmtime` compile-time edge is added
//! (MODULE-014 §2.2 posture intact).
//!
//! **Sibling of, not an impl of, `CatchupDispatcher`.** Catch-up
//! (`catchup.rs`) fires a *missed* row's hook exactly ONCE; the materializer
//! STARTS the persistent driver loop (cron/watcher/daemon run until cancel;
//! task runs once). The two are deliberately distinct: `dispatch_catchup` has
//! no cancel parameter and a "dispatch once" contract, semantically
//! incompatible with starting a long-running loop.
//!
//! **Spawnable per row.** `materialize` takes `self: Arc<Self>` + an owned
//! `row` so the returned future is `'static`: the mainline readiness loop can
//! `tokio::spawn(Arc::clone(&materializer).materialize(row, cancel))` one task
//! per registry row (that walk loop + the cli `RunnableHookFactory` impl are
//! the two mainline follow-ups recorded in MODULE-014 §3.6).

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use advance_shared_types::component::ComponentType;

use crate::cron::CronDriver;
use crate::daemon::{parse_restart_backoff_config, DaemonManager};
use crate::hook::{
    ComponentTypeBreakerGate, FileWatchSource, HookError, RunnableHookFactory, WebhookSource,
};
use crate::registry::{ComponentRegistryRow, MIN_RECURRING_INTERVAL_MS};
use crate::task::TaskRunner;
use crate::trigger_bus::TriggerBusDispatchImpl;
use crate::trigger_source::{parse_schedule_string, resolve_trigger, MAX_TRIGGER_NESTING_DEPTH};
use crate::types::{ComponentConfig, RestartPolicy, TriggerConfig, MAX_TASK_DELAY_MS};
use crate::watcher::WatcherDriver;

/// Upper ceiling for a watcher `Schedule`-trigger interval, mirroring
/// `CronDriver::run_periodic`'s 30-day reject (which exists to prevent
/// `Instant`-overflow panics in Tokio's timer). `ScheduleTriggerSource` itself
/// only rejects a zero duration, so the materializer enforces the ceiling at the
/// trust boundary.
const MAX_SCHEDULE_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Production "registry row → running driver" dispatcher. Holds the
/// dependency-inverted `RunnableHookFactory` plus the trigger-source seams the
/// watcher path needs (`resolve_trigger` requires the bus dispatcher + a
/// file-watch source + a webhook source).
pub struct ComponentMaterializer {
    factory: Arc<dyn RunnableHookFactory>,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_source: Arc<dyn FileWatchSource>,
    webhook_source: Arc<dyn WebhookSource>,
    /// Stage-F obs SLICE 3 — optional component-type circuit-breaker gate
    /// (SYS-AC-228). `None` (default) = allow all (unchanged behavior). Installed
    /// via [`Self::with_component_type_breaker_gate`]; the concrete
    /// `DefaultCircuitBreakerBus`-backed adapter is wired at the cli root.
    breaker_gate: Option<Arc<dyn ComponentTypeBreakerGate>>,
}

/// Validate a watcher trigger tree's SHAPE at the materializer trust boundary:
/// reject a degenerate empty `AnyOf` (adversarial round-18) and floor/ceiling
/// every `Schedule` leaf (adversarial round-10).
///
/// **Empty `AnyOf` (round-18)**: `AnyOf(vec![])` is admissible (admission +
/// serde only cap the UPPER `AnyOf` width, never the lower bound), but
/// `AnyOfTriggerSource::run` returns immediately for zero children → the watcher
/// drain loop sees `rx` closed and exits without ever firing the hook → an
/// "admitted-but-never-fires" silent no-op (the very class the system-acceptance
/// axis exists to prevent). It is STRUCTURALLY guaranteed never to fire (unlike a
/// legitimately-quiescent FileWatch/TriggerEvent awaiting an event), so the trust
/// boundary refuses it.
///
/// The Cron arm re-floors `row.interval_ms` and the Task arm re-caps `cfg.delay`,
/// but a watcher's `Schedule` interval comes from a trigger STRING that neither
/// admission (`submit.rs` never parses `Schedule` strings) nor
/// `parse_schedule_string` / `ScheduleTriggerSource` floors — they only reject a
/// zero duration. So a watcher row carrying `Schedule("every-1ms")` would drive a
/// sub-floor (~1000 fires/sec) hot tick loop, and a huge interval has no ceiling
/// (Tokio `Instant`-overflow risk). Re-assert `[MIN_RECURRING_INTERVAL_MS,
/// MAX_SCHEDULE_INTERVAL]` here for every `Schedule` leaf (recursing `AnyOf`),
/// consistent with the cron/task trust-boundary checks. `FileWatch` / `Webhook` /
/// `TriggerEvent` leaves carry no schedule interval (their firing is event-driven;
/// the `FileWatch`/`Webhook` production sources are waived).
///
/// Note: this floors only at the COMPONENT-materialization layer; the
/// `ScheduleTriggerSource` primitive (and its direct `resolve_trigger` callers /
/// unit tests) keep their finer-grained capability — a sub-100ms `Schedule` is a
/// valid low-level source, just not a valid materialized recurring component.
fn validate_watcher_trigger(trigger: &TriggerConfig, depth: usize) -> Result<(), HookError> {
    if depth > MAX_TRIGGER_NESTING_DEPTH {
        return Err(HookError::Failure(format!(
            "watcher trigger nesting depth {depth} exceeds \
             MAX_TRIGGER_NESTING_DEPTH ({MAX_TRIGGER_NESTING_DEPTH})"
        )));
    }
    match trigger {
        TriggerConfig::Schedule(s) => {
            let interval = parse_schedule_string(s)
                .map_err(|e| HookError::Failure(format!("watcher schedule {s:?}: {e:?}")))?;
            let floor = Duration::from_millis(MIN_RECURRING_INTERVAL_MS as u64);
            if interval < floor {
                return Err(HookError::Failure(format!(
                    "watcher schedule {s:?} interval {interval:?} is below the \
                     MIN_RECURRING_INTERVAL_MS floor ({MIN_RECURRING_INTERVAL_MS} ms); \
                     refusing to start a sub-floor tick loop"
                )));
            }
            if interval > MAX_SCHEDULE_INTERVAL {
                return Err(HookError::Failure(format!(
                    "watcher schedule {s:?} interval {interval:?} exceeds the 30-day ceiling"
                )));
            }
            Ok(())
        }
        TriggerConfig::AnyOf(children) => {
            if children.is_empty() {
                return Err(HookError::Failure(
                    "watcher trigger is an empty AnyOf — it is structurally \
                     guaranteed never to fire (admitted-but-never-fires); \
                     refusing to materialize a silent no-op component"
                        .to_owned(),
                ));
            }
            for child in children {
                validate_watcher_trigger(child, depth + 1)?;
            }
            Ok(())
        }
        TriggerConfig::FileWatch(_)
        | TriggerConfig::Webhook(_)
        | TriggerConfig::TriggerEvent(_) => Ok(()),
    }
}

/// Shape-confine a row's `output_dir` at the materializer trust boundary
/// (adversarial round-14). The drivers write `result.bin` into `output_dir` on
/// every tick/restart (`output::write_result_to_dir`), which rejects only a `..`
/// component and explicitly delegates absolute-path/symlink confinement to the
/// submit-component admission path — which does NOT validate `output_dir`. So a
/// row reaching `materialize` by any non-admission path (direct registry insert,
/// migration, corruption) could set `output_dir` to an absolute location and
/// drive repeated arbitrary-location file writes — a strictly more severe sink
/// than the sub-floor hot loop the timing re-checks defend.
///
/// This enforces the CONTEXT-FREE invariants the materializer can decide without
/// external state: reject empty, reject absolute, reject any `..` traversal
/// component. The remaining CONTEXT-DEPENDENT confinement — canonicalizing the
/// resolved (possibly symlinked) relative path under a trusted output root — is
/// the composition root's concern (it owns the root), recorded in MODULE-014
/// §3.6; the materializer has no trusted-root context to do it correctly.
fn validate_output_dir(output_dir: Option<&str>) -> Result<Option<PathBuf>, HookError> {
    let Some(dir) = output_dir else {
        return Ok(None);
    };
    if dir.is_empty() {
        return Err(HookError::Failure(
            "component output_dir is an empty string".to_owned(),
        ));
    }
    let path = Path::new(dir);
    if path.is_absolute() {
        return Err(HookError::Failure(format!(
            "component output_dir {dir:?} is absolute; only a relative, \
             traversal-free output_dir is accepted at the materializer trust \
             boundary (root-relative confinement is the composition root's concern)"
        )));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(HookError::Failure(format!(
            "component output_dir {dir:?} contains a '..' traversal component"
        )));
    }
    Ok(Some(PathBuf::from(dir)))
}

impl ComponentMaterializer {
    pub fn new(
        factory: Arc<dyn RunnableHookFactory>,
        dispatcher: Arc<TriggerBusDispatchImpl>,
        file_source: Arc<dyn FileWatchSource>,
        webhook_source: Arc<dyn WebhookSource>,
    ) -> Self {
        Self {
            factory,
            dispatcher,
            file_source,
            webhook_source,
            breaker_gate: None,
        }
    }

    /// Stage-F obs SLICE 3 — additive builder installing the component-type
    /// circuit-breaker gate (SYS-AC-228). Mirrors the codebase's `with_*`
    /// convention; `new()` is unchanged so every existing caller keeps the
    /// default `None` (allow-all) behavior.
    pub fn with_component_type_breaker_gate(
        mut self,
        gate: Arc<dyn ComponentTypeBreakerGate>,
    ) -> Self {
        self.breaker_gate = Some(gate);
        self
    }

    /// Turn one registry row into a running driver. Returns when the driver
    /// loop exits — on `cancel` for the looping drivers (Cron/Watcher/Daemon),
    /// or after the single run for Task. Errors map driver/factory/resolve
    /// failures to [`HookError`].
    ///
    /// `Agent` rows fail closed: agents are message-driven via
    /// `AgentLoopDriverImpl`, NOT a runnable-run leg, so this returns an
    /// explicit error rather than silently no-op'ing (admission already rejects
    /// `submit-component` of an Agent, but the materializer is defensive about
    /// any unexpected shape that reaches it).
    pub async fn materialize(
        self: Arc<Self>,
        row: ComponentRegistryRow,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        // Every field below is read FROM the row's submit_config (the
        // submitted bytes/trigger/policy), not minted from an id string.
        let cfg = &row.submit_config;
        // submit_config.output_dir is Option<String>; the driver entries take
        // Option<PathBuf>. Trust-boundary shape-confinement (adversarial
        // round-14): the drivers write `result.bin` into output_dir on every
        // tick/restart via `output::write_result_to_dir`, which only rejects a
        // `..` component and delegates absolute-path/symlink confinement to
        // admission — but admission never validates output_dir. So a row written
        // by any non-admission path could point output_dir at an absolute
        // location (e.g. /etc/cron.d) for repeated arbitrary-location writes.
        // Reject absolute / traversal / empty here, before any driver dispatch.
        let output_dir: Option<PathBuf> = validate_output_dir(cfg.output_dir.as_deref())?;

        // Stage-F obs SLICE 3 (SYS-AC-228) — consult the component-type breaker
        // gate at the dispatch path, BEFORE the type match (so an Open breaker
        // fails-closed THIS type's dispatch without building a hook, while other
        // component types proceed). `ComponentType` is `Copy`, so reading it here
        // then matching below has no move conflict. `None` gate = allow all.
        if let Some(gate) = &self.breaker_gate {
            if let Some(reason) = gate.is_open_component_type(row.component_type) {
                return Err(HookError::Failure(format!(
                    "component {:?} (type {:?}) dispatch blocked by component-type breaker: {}",
                    row.id.as_str(),
                    row.component_type,
                    reason
                )));
            }
        }

        match row.component_type {
            // Fail-closed BEFORE building a hook — no silent no-op, no wasted
            // factory call.
            ComponentType::Agent => Err(HookError::Failure(format!(
                "component {:?} is an Agent: agents are message-driven \
                 (AgentLoopDriverImpl), not a runnable-run leg; \
                 ComponentMaterializer cannot materialize them",
                row.id.as_str()
            ))),

            ComponentType::Cron => {
                // Interval from the already-resolved, admission-floored
                // `interval_ms` (>= MIN_RECURRING_INTERVAL_MS), NOT a re-parsed
                // trigger string — `parse_schedule_string` only accepts
                // `every-N{ms,s,m,h}` and would reject e.g. a 5-field cron.
                let interval_ms = row.interval_ms.ok_or_else(|| {
                    HookError::Failure(format!(
                        "cron component {:?} has no interval_ms; cannot start \
                         the periodic driver",
                        row.id.as_str()
                    ))
                })?;
                // Defensive trust-boundary re-floor (adversarial round-6 W2):
                // admission floors interval_ms at MIN_RECURRING_INTERVAL_MS, but
                // the materializer is the point that turns a PERSISTED row into a
                // live tick loop. A row written by any non-admission path (direct
                // registry insert, a migration/tool, DB corruption) could carry a
                // sub-floor (or non-positive) interval_ms; re-assert the floor
                // here so such a row cannot drive a high-frequency hot tick loop
                // (CPU + per-tick emit/result.bin amplification). Admitted rows are
                // already >= MIN_RECURRING_INTERVAL_MS, so this never rejects a
                // legitimately-admitted cron component.
                if interval_ms < MIN_RECURRING_INTERVAL_MS {
                    return Err(HookError::Failure(format!(
                        "cron component {:?} interval_ms {} is below the \
                         MIN_RECURRING_INTERVAL_MS floor ({}); refusing to start a \
                         sub-floor tick loop",
                        row.id.as_str(),
                        interval_ms,
                        MIN_RECURRING_INTERVAL_MS
                    )));
                }
                let interval = Duration::from_millis(interval_ms as u64);
                let hook = self
                    .factory
                    .build(&cfg.binary, row.id.as_str(), &cfg.capabilities)
                    .await?;
                let config = ComponentConfig {
                    id: row.id.as_str().to_owned(),
                    config_data: None,
                    trigger_context: None,
                };
                CronDriver::run_periodic(
                    row.id.as_str(),
                    interval,
                    hook,
                    config,
                    output_dir,
                    cancel,
                )
                .await
            }

            ComponentType::Watcher => {
                let trigger = cfg.trigger.clone().ok_or_else(|| {
                    HookError::Failure(format!(
                        "watcher component {:?} has no trigger config; cannot \
                         resolve a trigger source",
                        row.id.as_str()
                    ))
                })?;
                // Trust-boundary trigger-shape validation: reject a degenerate
                // empty AnyOf that would materialize to an admitted-but-never-fires
                // no-op (round-18), and re-floor/ceiling every Schedule-leaf
                // interval (round-10) — a watcher Schedule interval comes from a
                // trigger string that neither admission nor
                // resolve_trigger/ScheduleTriggerSource bounds.
                validate_watcher_trigger(&trigger, 0)?;
                // Resolve the trigger (cheap, fail-closed, depth-capped) BEFORE
                // the expensive factory.build — symmetric with the cron
                // check-before-build ordering, so a structurally-invalid trigger
                // is rejected without paying the binary-load cost (adversarial
                // round-8 Info-4).
                let source = resolve_trigger(
                    trigger,
                    Arc::clone(&self.dispatcher),
                    Arc::clone(&self.file_source),
                    Arc::clone(&self.webhook_source),
                )
                .map_err(|e| {
                    HookError::Failure(format!(
                        "watcher component {:?}: resolve_trigger failed: {e:?}",
                        row.id.as_str()
                    ))
                })?;
                let hook = self
                    .factory
                    .build(&cfg.binary, row.id.as_str(), &cfg.capabilities)
                    .await?;
                WatcherDriver::run_with_trigger_source(
                    row.id.as_str(),
                    source,
                    hook,
                    output_dir,
                    cancel,
                )
                .await
            }

            ComponentType::Daemon => {
                // restart_policy + retry FLOW THROUGH from submit_config; never
                // hardcoded. RestartPolicy is Copy. A daemon admitted without a
                // restart_policy defaults to Never (run-once-then-stop — the
                // conservative non-surprising default; admission permits a
                // policy-less daemon, so failing closed here would make a
                // legitimately-admitted component un-runnable).
                let policy = cfg.restart_policy.unwrap_or(RestartPolicy::Never);
                let backoff = cfg
                    .retry
                    .as_ref()
                    .map(parse_restart_backoff_config)
                    .transpose()
                    .map_err(|e| {
                        HookError::Failure(format!(
                            "daemon component {:?}: retry/backoff config: {e:?}",
                            row.id.as_str()
                        ))
                    })?;
                let hook = self
                    .factory
                    .build(&cfg.binary, row.id.as_str(), &cfg.capabilities)
                    .await?;
                let config = ComponentConfig {
                    id: row.id.as_str().to_owned(),
                    config_data: None,
                    trigger_context: None,
                };
                DaemonManager::run_daemon(
                    row.id.as_str(),
                    policy,
                    hook,
                    config,
                    output_dir,
                    cancel,
                    backoff,
                )
                .await
            }

            ComponentType::Task => {
                // Defensive trust-boundary re-cap (adversarial round-8 W1,
                // symmetric with the cron interval re-floor): admission caps
                // `delay` at MAX_TASK_DELAY_MS via the serde gate, but a row
                // reaching materialize by any non-serde/non-admission path could
                // carry an unbounded `delay`. Re-assert the cap here, BEFORE
                // building a hook. Admitted rows are already <= MAX_TASK_DELAY_MS,
                // so this never rejects a legitimately-admitted task. (The cap
                // bounds the fire-and-forget worst case; the cancel race below
                // makes a cancelled delayed task stop promptly regardless.)
                if let Some(delay_ms) = cfg.delay {
                    if delay_ms > MAX_TASK_DELAY_MS {
                        return Err(HookError::Failure(format!(
                            "task component {:?} delay {} ms exceeds \
                             MAX_TASK_DELAY_MS ({}); refusing to park a task \
                             beyond the cap",
                            row.id.as_str(),
                            delay_ms,
                            MAX_TASK_DELAY_MS
                        )));
                    }
                }
                // One-shot. `submit_cfg.delay` is honored inside run_task; the
                // ComponentConfig is built there from submit_cfg.id (== row.id
                // for an admitted row). No originating trigger context for a
                // directly-materialized task (trigger-driven tasks arrive via
                // the watcher path).
                let hook = self
                    .factory
                    .build(&cfg.binary, row.id.as_str(), &cfg.capabilities)
                    .await?;
                // Race run_task against `cancel` (adversarial round-18): run_task
                // has no cancel parameter, so its pre-hook delay sleep + hook run
                // are not interruptible on their own. Symmetric with the
                // cron/watcher/daemon arms (which all tokio::select! on cancel),
                // wrap it here so a cancelled delayed task stops promptly and drops
                // the hook Arc + the cfg/binary copy, instead of parking the
                // spawned task for the full (capped) delay after teardown.
                tokio::select! {
                    _ = cancel.cancelled() => Ok(()),
                    res = TaskRunner::run_task(
                        row.id.as_str(),
                        cfg.clone(),
                        None,
                        hook,
                        output_dir,
                    ) => res.map(|_run_result| ()),
                }
            }
        }
    }
}
