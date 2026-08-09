//! Readiness-gated registry-walk loop — the cli composition-root fn that turns
//! a live [`ComponentRegistry`] into running drivers (B3 satellite, 2026-06-15).
//!
//! [`run_readiness_gated_walk`] is the second cli half of MODULE-014 §3.6's
//! "two mainline follow-ups" (the first being
//! [`WasmRunnableHookFactory`](crate::runnable_hook_factory::WasmRunnableHookFactory)).
//! After `Scheduler::start_with_readiness`'s probe passes (AC-20 fail-fast), it
//! reads `registry.list()` and spawns one
//! [`ComponentMaterializer::materialize`](advance_scheduler::materializer::ComponentMaterializer::materialize)
//! task per **non-Agent** row, with **per-row error isolation**: each row gets
//! its own `tokio::spawn`ed task → its own [`JoinHandle`]; a row's returned
//! `Err` (e.g. a factory load failure on corrupt bytes) stays in that handle's
//! `Result` and never aborts the walk or its sibling rows. Agent rows are
//! filtered out (they are message-driven via `AgentLoopDriverImpl`, not a
//! runnable-run leg — `materialize` would fail-close them anyway).
//!
//! **Production composition (Legacy3 closure).** `advance start` calls
//! [`start_continuous_readiness_gated_walk_with_breaker_gate`] over a live
//! `ComponentRegistry::open_in(<ws>/.triggers, "components.db")`, installing the
//! component-type circuit-breaker gate over the runtime's shared
//! `CircuitBreakerBus` (see `crate::breaker_gate::DefaultComponentTypeBreakerGate`).
//! The reconciler materializes boot rows and polls for newly committed rows; each
//! component id is started at most once per daemon lifetime. The compatibility
//! one-shot helpers remain for narrow unit tests.
//!
//! **Gate scope.** The gate is the "block NEW dispatch" layer — consulted once per
//! row at `materialize`-time (SYS-AC-228's criterion: "new dispatch ... is blocked
//! while other types continue"). It does NOT stop an already-running
//! Cron/Watcher/Daemon driver loop (the "handle running instances" breaker layer is
//! a separate concern). A breaker opened after boot governs later reconciliation
//! dispatches while leaving already-running drivers unchanged.
//!
//! **Lifecycle foot-gun for the caller.** The returned `JoinHandle`s for
//! Cron/Watcher/Daemon rows wrap futures that run UNTIL CANCEL — **dropping a
//! handle does NOT abort the spawned task**. To stop the drivers the caller
//! must hold + cancel the single shared `cancel` token, which cancels ALL rows
//! at once (no per-row cancel; derive `cancel.child_token()` upstream if
//! per-row cancel is ever needed).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use advance_scheduler::hook::{
    FileWatchSource, HookError, RunnableHookFactory, RuntimeReadiness, WebhookSource,
};
use advance_scheduler::materializer::ComponentMaterializer;
use advance_scheduler::registry::{ComponentRegistry, RegistryError};
use advance_scheduler::scheduler::{Scheduler, SchedulerStartError};
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::types::ComponentId;
use advance_shared_types::component::ComponentType;

use crate::breaker_gate::DefaultComponentTypeBreakerGate;
use advance_runtime::circuit_breaker::CircuitBreakerBus;

/// Failure modes of [`run_readiness_gated_walk`] BEFORE any per-row work is
/// spawned. Hand-rolled `Display` + `Error` (no `thiserror` dep — mirrors the
/// in-tree `InstantiateError`/`BootstrapError` hand-rolled pattern). Per-row
/// failures are NOT here: they live inside each returned `JoinHandle`'s
/// `Result<(), HookError>`.
#[derive(Debug)]
pub enum WalkError {
    /// The readiness probe reported not-ready — the scheduler fail-fasts and
    /// NOTHING is spawned (AC-20).
    NotReady(SchedulerStartError),
    /// `registry.list()` failed — read error before any spawn.
    Registry(RegistryError),
}

/// Production continuous reconciler.  It owns every materialized driver and the registry poller;
/// shutdown first cancels the shared token, then waits for the supervisor to join the drivers.
pub struct ContinuousReadinessWalk {
    cancel: CancellationToken,
    supervisor: JoinHandle<()>,
}

impl ContinuousReadinessWalk {
    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.supervisor.await;
    }
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalkError::NotReady(e) => write!(f, "readiness gate failed: {e}"),
            WalkError::Registry(e) => write!(f, "registry list failed: {e}"),
        }
    }
}

impl std::error::Error for WalkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WalkError::NotReady(e) => Some(e),
            WalkError::Registry(e) => Some(e),
        }
    }
}

/// Run the readiness-gated registry walk. On a ready probe, returns one
/// `(ComponentId, JoinHandle<Result<(), HookError>>)` per spawned non-Agent
/// row; the caller owns join/await/forget (production `advance start` would
/// hold them for the process lifetime — see the module foot-gun note). On a
/// not-ready probe returns `Err(WalkError::NotReady)` having spawned nothing.
///
/// Args (the hand-off-pinned shape): the live `registry`, the readiness
/// `probe`, and the 4 materializer seams (`factory`, `dispatcher`,
/// `file_source`, `webhook_source`) the caller supplies, plus the shared
/// `cancel` token.
pub async fn run_readiness_gated_walk(
    registry: &ComponentRegistry,
    probe: Arc<dyn RuntimeReadiness>,
    factory: Arc<dyn RunnableHookFactory>,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_source: Arc<dyn FileWatchSource>,
    webhook_source: Arc<dyn WebhookSource>,
    cancel: CancellationToken,
) -> Result<Vec<(ComponentId, JoinHandle<Result<(), HookError>>)>, WalkError> {
    // Delegates with NO breaker gate (None) — behaviorally identical to the
    // original walk, so the existing callers (cli walk test + the SYS-AC-109
    // harness `sys_j34_runleg.rs`) are byte-unchanged.
    run_readiness_gated_walk_inner(
        registry,
        probe,
        factory,
        dispatcher,
        file_source,
        webhook_source,
        None,
        cancel,
    )
    .await
}

/// [Wave-13 Lane B / SYS-AC-228] Like [`run_readiness_gated_walk`] but installs
/// the production component-type circuit-breaker gate over `breaker_bus` (the
/// runtime's shared `CircuitBreakerBus`). Each spawned `materialize` consults the
/// gate at the dispatch path BEFORE its type-match, so an Open component-type
/// breaker fails-closed THAT type's dispatch while other types proceed (the
/// `advance start` production boot drives this variant). Additive over
/// [`run_readiness_gated_walk`] — the bare fn's signature is unchanged.
pub async fn run_readiness_gated_walk_with_breaker_gate(
    registry: &ComponentRegistry,
    probe: Arc<dyn RuntimeReadiness>,
    factory: Arc<dyn RunnableHookFactory>,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_source: Arc<dyn FileWatchSource>,
    webhook_source: Arc<dyn WebhookSource>,
    breaker_bus: Arc<dyn CircuitBreakerBus>,
    cancel: CancellationToken,
) -> Result<Vec<(ComponentId, JoinHandle<Result<(), HookError>>)>, WalkError> {
    run_readiness_gated_walk_inner(
        registry,
        probe,
        factory,
        dispatcher,
        file_source,
        webhook_source,
        Some(breaker_bus),
        cancel,
    )
    .await
}

/// Start the production registry reconciler.  Unlike the compatibility one-shot helpers above,
/// this discovers rows committed after boot, materializes each canonical component id exactly once
/// per daemon lifetime, and retains the drivers until shutdown.  Durable rows are rediscovered on
/// restart, so a process crash between admission and the next poll cannot strand a submission.
#[allow(clippy::too_many_arguments)]
pub async fn start_continuous_readiness_gated_walk_with_breaker_gate(
    registry: Arc<ComponentRegistry>,
    probe: Arc<dyn RuntimeReadiness>,
    factory: Arc<dyn RunnableHookFactory>,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_source: Arc<dyn FileWatchSource>,
    webhook_source: Arc<dyn WebhookSource>,
    breaker_bus: Arc<dyn CircuitBreakerBus>,
) -> Result<ContinuousReadinessWalk, WalkError> {
    Scheduler::new(Arc::clone(&dispatcher))
        .start_with_readiness(probe)
        .await
        .map_err(WalkError::NotReady)?;

    let initial = registry.list().await.map_err(WalkError::Registry)?;
    let materializer = Arc::new(
        ComponentMaterializer::new(factory, dispatcher, file_source, webhook_source)
            .with_component_type_breaker_gate(Arc::new(DefaultComponentTypeBreakerGate::new(
                breaker_bus,
            ))),
    );
    let cancel = CancellationToken::new();
    let supervisor_cancel = cancel.clone();
    let supervisor = tokio::spawn(async move {
        let mut seen = HashSet::new();
        let mut drivers: Vec<JoinHandle<Result<(), HookError>>> = Vec::new();
        enqueue_unseen(
            initial,
            &mut seen,
            &mut drivers,
            Arc::clone(&materializer),
            supervisor_cancel.clone(),
        );

        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = supervisor_cancel.cancelled() => break,
                _ = interval.tick() => {
                    match registry.list().await {
                        Ok(rows) => enqueue_unseen(
                            rows,
                            &mut seen,
                            &mut drivers,
                            Arc::clone(&materializer),
                            supervisor_cancel.clone(),
                        ),
                        Err(error) => eprintln!(
                            "advance: component registry reconciliation read failed: {}",
                            error.to_string().escape_debug()
                        ),
                    }
                }
            }
        }

        // All drivers share this token.  It is already cancelled; wait for their type-specific
        // cancellation branch so no runtime/injector borrow outlives the daemon host.
        for driver in drivers {
            let _ = driver.await;
        }
    });
    Ok(ContinuousReadinessWalk { cancel, supervisor })
}

fn enqueue_unseen(
    rows: Vec<advance_scheduler::registry::ComponentRegistryRow>,
    seen: &mut HashSet<String>,
    drivers: &mut Vec<JoinHandle<Result<(), HookError>>>,
    materializer: Arc<ComponentMaterializer>,
    cancel: CancellationToken,
) {
    for row in rows {
        if row.component_type == ComponentType::Agent {
            continue;
        }
        let id = row.id.as_str().to_owned();
        if !seen.insert(id) {
            continue;
        }
        drivers.push(tokio::spawn(
            Arc::clone(&materializer).materialize(row, cancel.clone()),
        ));
    }
}

/// Shared body for both public walk variants. `breaker_bus`: `Some` installs the
/// component-type gate via `ComponentMaterializer::with_component_type_breaker_gate`
/// (the cli `DefaultComponentTypeBreakerGate` adapter over the real bus); `None`
/// = allow all (the original behavior).
async fn run_readiness_gated_walk_inner(
    registry: &ComponentRegistry,
    probe: Arc<dyn RuntimeReadiness>,
    factory: Arc<dyn RunnableHookFactory>,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_source: Arc<dyn FileWatchSource>,
    webhook_source: Arc<dyn WebhookSource>,
    breaker_bus: Option<Arc<dyn CircuitBreakerBus>>,
    cancel: CancellationToken,
) -> Result<Vec<(ComponentId, JoinHandle<Result<(), HookError>>)>, WalkError> {
    // Readiness gate via the blessed AC-20 entrypoint (the prompt mandates
    // "after start_with_readiness returns Ok, read registry.list()"). The
    // throwaway Scheduler is cheap (4 driver structs + an empty vec, dropped)
    // and reuses the SAME dispatcher Arc the materializer needs — routing
    // readiness here keeps the gate semantics centralized in the scheduler so
    // any future hardening (the documented HostRegistry "scheduler.boot" probe)
    // is inherited without a cli change.
    Scheduler::new(Arc::clone(&dispatcher))
        .start_with_readiness(Arc::clone(&probe))
        .await
        .map_err(WalkError::NotReady)?;

    let rows = registry.list().await.map_err(WalkError::Registry)?;

    // Build the materializer; when a bus is supplied (the production boot path)
    // install the component-type breaker gate via the consuming builder BEFORE
    // wrapping in Arc. `None` = allow all (unchanged behavior for the bare walk).
    let materializer = ComponentMaterializer::new(factory, dispatcher, file_source, webhook_source);
    let materializer = match breaker_bus {
        Some(bus) => materializer
            .with_component_type_breaker_gate(Arc::new(DefaultComponentTypeBreakerGate::new(bus))),
        None => materializer,
    };
    let materializer = Arc::new(materializer);

    let mut handles = Vec::new();
    for row in rows {
        // Agents are message-driven, not a runnable-run leg — skip (do not
        // spawn a guaranteed-Err task).
        if row.component_type == ComponentType::Agent {
            continue;
        }
        let id = row.id.clone();
        // Per-row isolation: one spawned task per row. `materialize(self:
        // Arc<Self>, row, cancel)` owns its row + an Arc of self, so the future
        // is 'static. A failing/corrupt row's Err lands in THIS handle only.
        let handle = tokio::spawn(Arc::clone(&materializer).materialize(row, cancel.clone()));
        handles.push((id, handle));
    }
    Ok(handles)
}
