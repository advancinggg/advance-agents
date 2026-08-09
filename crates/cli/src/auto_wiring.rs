//! Stage-D cli composition root for the MODULE-015 auto-loop driver.
//!
//! The auto-loop crate keeps ZERO `advance-event-bus` / `advance-messaging` /
//! `advance-pack-manager` dependencies (crate-boundary discipline — MODULE-015
//! §3.8 note 10). The CONCRETE bindings for its abstract seams live here:
//!
//! - [`EventBusAutoIterationSink`] — `AutoIterationEventSink` → M019
//!   `EventBusEmit` (the 7 `auto.*` lifecycle events).
//! - [`EventBusNotifySink`] — `NotifySink` → M019 `EventBusEmit` (degrade/halt
//!   notification, event-agnostic). NOTE: SYS-AC-257 requires `channel.raw_sent`
//!   (cap-channel OUTBOUND egress); the real egress binding is a harvest
//!   install point — this cli adapter emits a best-effort observability event.
//! - [`PackEvaluatorResolver`] — `EvaluatorResolver` → MODULE-018
//!   `PackRegistry::resolve_pack_component` (CONTRACT-170; the 201 sub-slice).
//! - [`build_auto_loop_driver`] / [`build_auto_round_advancer`] /
//!   [`start_auto_session`] — construct the driver (real M003 checkpoint/rollback
//!   over the workspace git repo), the `RoundAdvancer` (driver-as-`AutoStateReader`),
//!   and the Auto-mode start path.
//!
//! **Satellite scope** (flips ZERO SYS-AC): the persistent scheduler tick-loop
//! that delivers `on_tick`, `Scheduler::register_extension`, the real m017-e
//! `SkillRollback`, the M008 `RunBudget` `RunBudgetSource`, and the Auto-mode
//! cli SUBCOMMAND that calls [`start_auto_session`] are harvest install points.
//! The driver built here holds the event/notify sinks but no `SkillRollback`
//! (discard fails-CLOSED) and no `RunBudgetSource` (budget falls back to the
//! fail-CLOSED safety-valve derivation).

use std::path::Path;
use std::sync::Arc;

use advance_git::{DefaultNamedCheckpoint, DefaultWorkspaceRollback};
use advance_pack_manager::registry::{PackComponentResolution, PackRegistry};
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_runtime::config::NotifyChannelConfig;
use advance_scheduler_auto_loop::{
    sanitize_for_audit, validate_constraint_surface, AutoError, AutoEventSinkError,
    AutoIterationEventPayload, AutoIterationEventSink, AutoLoopConfig, AutoLoopDriver,
    AutoLoopRoundAdvancer, AutoStateReader, DefaultAutoLoopDriver, DefaultIterationCheckpoint,
    DefaultIterationRollback, EvaluatorManifest, EvaluatorResolveError, EvaluatorResolver,
    EvaluatorSpec, IterationStatus, NotifySink, NotifySinkError, ResultsWriter,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RoundAdvancer, RunError};
use advance_shared_types::traits::{CostTrackerQuery, EventBusEmit};
use async_trait::async_trait;
use cap_channel::OutboundTransport;

/// `AutoIterationEventSink` → M019 `EventBusEmit`. Builds an observability
/// `Event` per payload (uncorrelated — the `Event::observability` posture, same
/// as cap-grant `authz.checked`) and fires it on the bus.
pub struct EventBusAutoIterationSink {
    bus: Arc<dyn EventBusEmit>,
}

impl EventBusAutoIterationSink {
    pub fn new(bus: Arc<dyn EventBusEmit>) -> Self {
        Self { bus }
    }
}

/// Adversarial-r10 W4: sanitize an optional `run_id` (control-char / ANSI /
/// bidi-override stripping) before it enters an `Event` payload that flows into
/// the operator-audit-log / WS / `Debug` sink class — matching the in-crate
/// `crash_reason`/`summary` posture. (`agent_id` is sanitized at the emit site.)
fn san_run(run_id: &Option<String>) -> Option<String> {
    run_id.as_ref().map(|r| sanitize_for_audit(r))
}

fn iteration_event_payload_json(p: &AutoIterationEventPayload) -> serde_json::Value {
    match p {
        AutoIterationEventPayload::Started {
            run_id, iteration, ..
        } => serde_json::json!({ "run_id": san_run(run_id), "iter": iteration }),
        AutoIterationEventPayload::Kept {
            run_id,
            iteration,
            metric,
            ..
        }
        | AutoIterationEventPayload::Discarded {
            run_id,
            iteration,
            metric,
            ..
        } => serde_json::json!({ "run_id": san_run(run_id), "iter": iteration, "metric": metric }),
        AutoIterationEventPayload::Crashed {
            run_id,
            iteration,
            reason,
            ..
        } => serde_json::json!({ "run_id": san_run(run_id), "iter": iteration, "reason": reason }),
        AutoIterationEventPayload::Completed {
            run_id,
            iteration,
            status,
            ..
        } => serde_json::json!({
            "run_id": san_run(run_id),
            "iter": iteration,
            "status": status_str(*status),
        }),
        AutoIterationEventPayload::Degraded { reason, .. } => {
            serde_json::json!({ "reason": reason.as_str() })
        }
        AutoIterationEventPayload::Halted { reason, .. } => {
            serde_json::json!({ "reason": reason.as_str() })
        }
        // `AutoIterationEventPayload` is `#[non_exhaustive]`; a future variant
        // emits an empty payload (the event_type + agent_id still carry on the
        // Event envelope) until this adapter is extended.
        _ => serde_json::json!({}),
    }
}

fn status_str(s: IterationStatus) -> &'static str {
    match s {
        IterationStatus::Keep => "keep",
        IterationStatus::Discard => "discard",
        IterationStatus::Crash => "crash",
    }
}

#[async_trait]
impl AutoIterationEventSink for EventBusAutoIterationSink {
    async fn emit(&self, payload: AutoIterationEventPayload) -> Result<(), AutoEventSinkError> {
        // Adversarial-r10 W4: sanitize agent_id at the emit site (it flows into
        // Event.agent_id → SQL/WS/Debug sink class) — same posture as run_id +
        // crash_reason/summary.
        let ev = Event::observability(
            payload.event_type(),
            sanitize_for_audit(payload.agent_id()),
            iteration_event_payload_json(&payload),
            None,
        );
        self.bus.emit(ev);
        Ok(())
    }
}

/// Event type for the cli-side degrade/halt notification observability emit.
/// (Distinct from SYS-AC-257's `channel.raw_sent`, which the harvest wires via
/// cap-channel egress.)
pub const AUTO_NOTIFY_EVENT: &str = "auto.notify";

/// `NotifySink` → M019 `EventBusEmit` (event-agnostic best-effort notify).
pub struct EventBusNotifySink {
    bus: Arc<dyn EventBusEmit>,
}

impl EventBusNotifySink {
    pub fn new(bus: Arc<dyn EventBusEmit>) -> Self {
        Self { bus }
    }
}

#[async_trait]
impl NotifySink for EventBusNotifySink {
    async fn notify(&self, agent_id: &str, message: &str) -> Result<(), NotifySinkError> {
        // Adversarial-r10 W4: sanitize agent_id (the degrade/halt message text is
        // loop-controlled, but agent_id flows into Event.agent_id).
        let ev = Event::observability(
            AUTO_NOTIFY_EVENT,
            sanitize_for_audit(agent_id),
            serde_json::json!({ "message": message }),
            None,
        );
        self.bus.emit(ev);
        Ok(())
    }
}

/// 201 sub-slice: `EvaluatorResolver` → MODULE-018 `PackRegistry::resolve_pack_component`
/// (CONTRACT-170). Translates a `PackComponentResolution` into the auto-loop-local
/// [`EvaluatorSpec`] and enforces the REQ-073 constraint surface. Keeps the
/// auto-loop crate free of any `advance-pack-manager` edge (the resolver trait is
/// auto-loop-local; this concrete impl lives at the cli composition root).
pub struct PackEvaluatorResolver {
    registry: Arc<dyn PackRegistry>,
}

impl PackEvaluatorResolver {
    pub fn new(registry: Arc<dyn PackRegistry>) -> Self {
        Self { registry }
    }
}

/// Translate a resolved Pack component into the auto-loop `EvaluatorManifest`,
/// deriving the structured constraint-surface fields the auto-loop validator
/// needs: `has_binary` (binary non-empty) + `trigger_present` (a non-null
/// top-level `trigger` key in the component.yaml). The auto-loop
/// `validate_constraint_surface` then enforces task-type / no-trigger / has-binary.
pub fn to_evaluator_manifest(res: &PackComponentResolution) -> EvaluatorManifest {
    let has_binary = !res.binary.is_empty();
    // Adversarial-r10 I7: bound the component.yaml parse. Pack content is
    // admin-approved (MODULE-018 trust model), but skip the unbounded
    // `serde_yml` parse for a pathologically large manifest to avoid a
    // parse-memory/CPU spike during evaluator resolution (matches the auto-loop
    // config path's MAX_FILTER_VALUE_BYTES posture). Over-cap → treat as no
    // trigger; the has_binary + component_type=="task" constraints still gate.
    const MAX_PACK_RAW_YAML_BYTES: usize = 64 * 1024;
    let trigger_present = if res.manifest.raw_yaml.len() > MAX_PACK_RAW_YAML_BYTES {
        false
    } else {
        serde_yml::from_str::<serde_json::Value>(&res.manifest.raw_yaml)
            .ok()
            .and_then(|v| v.get("trigger").map(|t| !t.is_null()))
            .unwrap_or(false)
    };
    EvaluatorManifest {
        component_type: res.manifest.component_type.clone(),
        has_binary,
        trigger_present,
        raw_yaml: res.manifest.raw_yaml.clone(),
    }
}

#[async_trait]
impl EvaluatorResolver for PackEvaluatorResolver {
    async fn resolve_evaluator(
        &self,
        fq_ref: &str,
    ) -> Result<EvaluatorSpec, EvaluatorResolveError> {
        let res = self
            .registry
            .resolve_pack_component(fq_ref)
            .map_err(|e| EvaluatorResolveError::NotFound(format!("{fq_ref}: {e}")))?;
        let manifest = to_evaluator_manifest(&res);
        validate_constraint_surface(&manifest)
            .map_err(EvaluatorResolveError::ConstraintViolated)?;
        Ok(EvaluatorSpec {
            binary: res.binary,
            capabilities: res.capabilities,
            output_dir: res.output_dir,
            manifest,
        })
    }
}

/// Build the production `DefaultAutoLoopDriver` rooted at `workspace`, wiring the
/// EventBus event + notify sinks. Returns `None` when `workspace` is not a git
/// repository (auto-mode needs per-iteration git checkpoints — degrade
/// gracefully, exactly as cap-fs `git_sync` / rollback-memory do on a non-repo
/// workspace).
///
/// The driver holds NO `SkillRollback` (discard fails-CLOSED until the m017-e
/// impl is wired) and NO `RunBudgetSource` (budget falls back to the fail-CLOSED
/// safety-valve derivation). The persistent scheduler tick-loop +
/// `register_extension` + the real M008/M017 bridges are harvest install points.
pub fn build_auto_loop_driver(
    workspace: &Path,
    event_bus: Arc<dyn EventBusEmit>,
) -> Option<Arc<DefaultAutoLoopDriver>> {
    let named = DefaultNamedCheckpoint::new(workspace.to_path_buf()).ok()?;
    let rollback = DefaultWorkspaceRollback::new(workspace.to_path_buf()).ok()?;
    // `new` only canonicalizes — it never opens the repo. Probe with
    // `verify_repo()` (one real repo open) so a NON-repo workspace degrades to
    // None instead of building a driver whose checkpoints would fail at runtime
    // (same posture as the cap-fs git_sync / rollback-memory wiring).
    rollback.verify_repo().ok()?;
    let driver = DefaultAutoLoopDriver::new(
        Arc::new(DefaultIterationCheckpoint::new(Arc::new(named))),
        Arc::new(DefaultIterationRollback::new(Arc::new(rollback))),
    )
    .with_iteration_event_sink(Arc::new(EventBusAutoIterationSink::new(event_bus.clone())))
    .with_notify_sink(Arc::new(EventBusNotifySink::new(event_bus)));
    Some(Arc::new(driver))
}

/// Wave-6 Lane C (2026-06-21) — install a [`NotifySink`] on a FRESHLY-built auto driver
/// via the doc-blessed `Arc::try_unwrap(..).with_notify_sink(..)` augment (the same
/// pattern cost-tracker / results-writer / skill-rollback use in the system-acceptance
/// harness). Returns `Err` if `driver`'s `Arc` is already SHARED (e.g. already cloned
/// into the `RoundAdvancer` via [`build_auto_round_advancer`]) — the augment-before-share
/// contract: install the notify sink BEFORE the driver is handed to the advancer.
pub fn install_notify_sink(
    driver: Arc<DefaultAutoLoopDriver>,
    sink: Arc<dyn NotifySink>,
) -> Result<Arc<DefaultAutoLoopDriver>, String> {
    let driver = Arc::try_unwrap(driver).map_err(|_| {
        "install_notify_sink: auto driver Arc is already shared; install the notify sink BEFORE \
         cloning the driver into the round-advancer (build_auto_round_advancer)"
            .to_string()
    })?;
    Ok(Arc::new(driver.with_notify_sink(sink)))
}

/// Wave-6 Lane C (2026-06-21) — the SYS-AC-257 production install point: build the auto
/// driver AND install the cap-channel notify sink sourced from a `channels.notify`
/// config block, REPLACING the `EventBusNotifySink` → `auto.notify` default (auto_wiring
/// line ~258) with the `CapChannelNotifySink` → `channel.raw_sent` egress. The augment
/// runs on the freshly-built UNIQUE `Arc` (so `Arc::try_unwrap` always succeeds) and the
/// returned `Arc` is still unique — the daemon-boot integration is a one-line swap of
/// [`build_auto_loop_driver`] for this fn at the wiring site, with NO advancer-clone
/// reorder.
///
/// The `channels.notify` config is validated FIRST (before the git-repo degrade check),
/// so an invalid notify config (unsupported adapter / empty url-template / empty
/// conversation_id) fails CLOSED at boot REGARDLESS of whether this workspace supports
/// auto mode — otherwise a malformed config would be silently ignored on a non-git
/// workspace (auto-mode degraded) and only surface later if the workspace became a git
/// repo (audit r6: silent-misconfig / fake-green; matches `channels_boot`'s loud-at-boot
/// posture). Returns `Err` on an invalid notify config; `Ok(None)` when the config is
/// VALID but `workspace` is not a git repository (degrades exactly like
/// [`build_auto_loop_driver`] — the validated sink is moot with no auto loop to notify).
/// `transport` is the wired `ChannelRuntime.transport`; `owner_agent_id` is the daemon's
/// serving messaging id (the egress ownership check matches it against the notify
/// subscription owner).
pub fn build_auto_loop_driver_with_channel_notify(
    workspace: &Path,
    event_bus: Arc<dyn EventBusEmit>,
    transport: Arc<dyn OutboundTransport>,
    owner_agent_id: &str,
    notify: &NotifyChannelConfig,
) -> Result<Option<Arc<DefaultAutoLoopDriver>>, String> {
    // Validate + build the notify sink FIRST (fail-closed on a malformed config,
    // independent of auto-mode availability — audit r6 Codex W).
    let sink =
        crate::channel_notify_sink::build_channel_notify_sink(transport, owner_agent_id, notify)?;
    let Some(driver) = build_auto_loop_driver(workspace, event_bus) else {
        // Non-repo: no auto driver (degrade). The config was valid; the sink is moot
        // (no auto loop to notify) → dropped here.
        return Ok(None);
    };
    let driver = install_notify_sink(driver, Arc::new(sink))?;
    Ok(Some(driver))
}

/// Build the CONTRACT-141 `RoundAdvancer` from the driver (coercing it to its
/// `AutoStateReader` impl). This is the `RunManager::with_round_advancer` arg.
pub fn build_auto_round_advancer(driver: Arc<DefaultAutoLoopDriver>) -> Arc<dyn RoundAdvancer> {
    let reader: Arc<dyn AutoStateReader> = driver;
    Arc::new(AutoLoopRoundAdvancer::new(reader))
}

/// Auto-mode start-path logic (PRD §4.7.2): validate + claim the per-agent
/// `AutoState` and register the `run_id → agent_id` mapping so
/// `RunManager::complete_round` routes the `auto:{agent-id}` Run to the auto
/// advancer. The caller mints the `auto:{agent-id}` Run via `RunManager` and
/// passes its `run_id`. (Wiring this to a `advance auto start` SUBCOMMAND is a
/// harvest install point.)
pub async fn start_auto_session(
    driver: &DefaultAutoLoopDriver,
    agent_id: &str,
    run_id: &str,
    config: AutoLoopConfig,
) -> Result<(), AutoError> {
    driver.start(agent_id, config).await?;
    driver.register_run(run_id, agent_id)?;
    Ok(())
}

/// Wave-22 (autoloop-integ) — install the REAL `CostTrackerQuery` + a
/// `ResultsWriter` on a FRESHLY-built auto driver via the doc-blessed
/// `Arc::try_unwrap` augment (the same augment-before-share pattern as
/// [`install_notify_sink`]). Production [`build_auto_loop_driver`] wires neither,
/// so without this the driver's `check_per_iteration_budget` can't read accrued
/// cost (`cost_tracker == None` → degrades to `Ok`) and `close_iteration`'s
/// crash arm writes NO `results.jsonl` crash row (`results_writer == None`).
/// Returns `Err` if the driver `Arc` is already SHARED (install BEFORE the
/// round-advancer clone — the augment-before-share contract).
pub fn install_auto_loop_integration(
    driver: Arc<DefaultAutoLoopDriver>,
    cost_tracker: Arc<dyn CostTrackerQuery>,
    workspace: &Path,
) -> Result<Arc<DefaultAutoLoopDriver>, String> {
    let driver = Arc::try_unwrap(driver).map_err(|_| {
        "install_auto_loop_integration: auto driver Arc is already shared; install the \
         cost-tracker + results-writer BEFORE cloning the driver into the round-advancer \
         (build_auto_round_advancer)"
            .to_string()
    })?;
    let driver = driver
        .with_cost_tracker(cost_tracker)
        .with_results_writer(Arc::new(ResultsWriter::new(workspace.to_path_buf())));
    Ok(Arc::new(driver))
}

/// Error from [`mint_auto_run`].
#[derive(Debug)]
pub enum AutoMintError {
    /// `RunManager::ensure_run` failed (invalid task_id / non-finite cost limit / …).
    Run(RunError),
    /// `driver.start` failed (invalid config / already-started / sessions at capacity).
    Start(AutoError),
    /// `driver.register_run` failed (run-mappings at capacity); the started
    /// session was rolled back via `driver.stop` (no live-state half-state).
    Register(AutoError),
}

impl std::fmt::Display for AutoMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoMintError::Run(e) => write!(f, "auto-mint ensure_run failed: {e:?}"),
            AutoMintError::Start(e) => write!(f, "auto-mint driver.start failed: {e}"),
            AutoMintError::Register(e) => {
                write!(
                    f,
                    "auto-mint register_run failed (session rolled back): {e}"
                )
            }
        }
    }
}

impl std::error::Error for AutoMintError {}

/// Wave-22 (autoloop-integ) — the real single-producer `auto:{agent-id}` Run
/// minter (AC-02 / REQ-069). Mints a MODULE-008 RunManager Run under the
/// `auto:{agent-id}` task_id (`ensure_run`, atomic under the RunManager
/// write-lock, `is_auto_mode` prefix) with an INDEPENDENT `RunConfig` budget,
/// then starts the driver session + registers the `run_id → agent_id` mapping so
/// `RunManager::complete_round` routes the auto Run to the auto advancer.
///
/// **Single-producer invariant (scoped to the current wired composition):** no
/// production `ensure_run` caller mints an `auto:`-prefixed task_id — the cli
/// session producer (`agent_loop.rs`) + the cap-lifecycle cascade both mint BARE
/// ids, and the WIT `AgentRunWitImpl` `auto:` path is not host-exported today —
/// so this minter is the sole `auto:` producer. `ensure_run` returns only a
/// `RunId` (no create-vs-reuse discriminator), so create-vs-reuse classification
/// is NOT attempted (a `fail_run` under a misclassification could kill another
/// owner's Run — never done here).
///
/// **Compensation.** Two post-`ensure_run` failure paths, both leaving an INERT
/// Run (no live tick-loop caller drives a Run with no driver session), reclaimed
/// by the next mint's `ensure_run` reuse-or-create (idempotent by `auto:{agent}`
/// task_id):
/// - `driver.start` FAILURE (invalid config / already-started / sessions at
///   capacity): no session was created, so there is nothing to stop; return a
///   loud `Err(Start)`. The Run is left inert.
/// - `driver.register_run` FAILURE after a SUCCESSFUL `start` (run-mappings at
///   capacity): `driver.start` mutated live `AutoState` that the tick cadence
///   runs over, so this is NOT inert — compensate DRIVER-side with
///   `driver.stop(agent_id)` (safe: the session it just started; `stop` on a
///   non-session agent is a harmless no-op), then return a loud `Err(Register)`.
/// Never a silent half-state; never a `fail_run` (see above).
pub async fn mint_auto_run(
    driver: &DefaultAutoLoopDriver,
    run_manager: &RunManager,
    agent_id: &str,
    config: AutoLoopConfig,
    run_config: RunConfig,
) -> Result<RunId, AutoMintError> {
    let task_id = driver.auto_namespace_task_id(agent_id);
    let run_id = run_manager
        .ensure_run(&task_id, agent_id, run_config)
        .map_err(AutoMintError::Run)?;
    driver
        .start(agent_id, config)
        .await
        .map_err(AutoMintError::Start)?;
    if let Err(e) = driver.register_run(run_id.as_ref(), agent_id) {
        // Post-start failure is NOT inert (live AutoState + tick cadence run over
        // it) — compensate driver-side, loud Err. Do NOT `fail_run` the Run.
        let _ = driver.stop(agent_id).await;
        return Err(AutoMintError::Register(e));
    }
    Ok(run_id)
}
