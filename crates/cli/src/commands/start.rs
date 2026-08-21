//! `advance start [--workspace <path>]` — Slice AE (2026-05-09); guest-component
//! autoload + agent-loop driver added in Slice BS-3 (2026-06-03, D12);
//! multi-turn serving loop added in Phase-2 Step-2 (2026-06-05).
//!
//! Brings up the runtime construction surface ([`advance_runtime::RuntimeHost`]),
//! then loads a deployed agent component if one is present at the conventional
//! path `<workspace>/.agent/behavior.component.wasm` and spawns the scheduler
//! agent-loop driver's `serve` SERVING LOOP ([`crate::agent_loop::build_agent_loop`]
//! → `AgentLoopDriverImpl::serve`) on a cancellable task — serving consecutive
//! `POST /msg` requests and carrying agent state across turns. Parks until
//! SIGINT / SIGTERM; releases the runtime lock on shutdown via `RuntimeLock::Drop`.
//!
//! The load is ONE-SHOT — the bytes are read exactly once at boot, there is no
//! file watcher, and changing the deployed binary requires a restart (MODULE-001
//! AC-13 clause (a): "restart is the mechanism"; this is NOT a mid-run hot swap).
//! Absent component → park (graceful, mirroring a missing `.agent/config.yaml`);
//! present-but-unparseable → fail boot loudly (a deployed-but-broken agent must
//! surface, not silently park). The gated SYS-AC witnesses (002/190) do NOT
//! depend on this path — the `system-acceptance` harness drives the turn
//! in-process via the same `build_agent_loop` factory. Full agent-template
//! materialization of a deployed binary into the workspace ships in MODULE-018/005.

use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use advance_runtime::config::ConfigError;
use advance_runtime::config::RuntimeConfigProvider;
use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::{BootstrapError, RuntimeHost, RuntimeHostBuilder};

// Slice BS-3 (2026-06-03) — CLI-composition-root agent-loop wiring (D12).
// WS-A (2026-06-04) — Message/MessageKind for the `POST /msg` inbound source.
use advance_messaging::{
    MailboxStore, Message, MessageKind, MsgError, OutboundActionSink, MAX_PAYLOAD_BYTES,
};
use advance_scheduler::hook::{
    MessageHandler, ProtectedTurnExecutionBoundary, TurnObserver, TurnPersistenceBoundary,
};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};

// Wave-13 Lane B (SYS-AC-228): drive the readiness-gated registry walk at boot,
// installing the component-type breaker gate over the runtime's shared bus.
use crate::runnable_hook_factory::WasmRunnableHookFactory;
use crate::runnable_walk::start_continuous_readiness_gated_walk_with_breaker_gate;
use advance_scheduler::hook::{
    FileWatchSource, HookError, RunnableHookFactory, RuntimeReadiness, WebhookSource,
};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::WebhookConfig;
use advance_shared_types::traits::{CallableInventoryReader, EventBusEmit};
use async_trait::async_trait;
// SAT-B (slice satB-postproc): the live components-backed PostProcessor is
// chained onto the driver via `AgentLoopDriverImpl::with_post_processor`.
use advance_shared_types::mailbox::AgentActionDispatcher;
use advance_shared_types::memory::PostProcessorHook;

// WS-A — in-process HTTP `POST /msg` inbound message source.
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::watch;

use crate::agent_loop::{
    build_agent_loop_with_action_limit, build_agent_loop_with_prebuilt_dispatcher,
    PublishingContextAssembler, RunManagerBootstrap, RunSession, SessionRunCell,
    WasmMessageHandler,
};
// Backbone Step 2 (2026-06-07): the cap-llm gateway type for the assembled-context
// seam (the gateway Arc comes from `WiringHandles.llm_gateway`).
use advance_shared_types::agent_tree::AgentTreeSnapshot;
use cap_llm::{resolve_provider_and_model, LlmGateway};
// Wave-12 Lane C: the decomposition reader trait (for the assembler port) + the
// concrete store type (the `WiringHandles.decomposition_store` handle).
use advance_context_engine::DecompositionReader;
use cap_lifecycle::DefaultDecompositionStore;
// Phase-3 kickoff (2026-06-06): thread the live RunManager + per-run budget caps
// into the agent loop so the session run_id producer + per-turn complete_round run.
use advance_run_manager::{RepetitionGuard, RunConfig, RunManager};
// Phase-2 Step-1 (reply delivery): POST /msg ↔ dispatch reply correlation.
use crate::reply::ReplyRegistry;
// Phase-2 Step-3: the composite daemon outbound sink (POST /msg registry +
// in-host channel egress) + the production channel bring-up (config → /hooks
// listener + host pump + egress chain + identity).
use crate::channel_egress::{ChannelEgress, DaemonOutboundSink};
use crate::channels_boot;
use crate::execution_turn_ingress::ExecutionTurnIngress;

#[derive(Clone)]
struct ProgressLoopWiring {
    ingress: Arc<ExecutionTurnIngress>,
    action_dispatcher: Arc<dyn AgentActionDispatcher>,
    execution_boundary: Arc<dyn ProtectedTurnExecutionBoundary>,
}

/// Canonical messaging id for the daemon's single agent. Distinct from the
/// cap-layer id (`"default-agent"`, used for cap-fs/grant/skills/llm via
/// `ComponentCtx`): messaging `is_safe_id` REQUIRES an `agent:`/`user:` prefix at
/// dispatch, while cap-grant + cap-lifecycle REJECT a colon (`[A-Za-z0-9_-]`).
/// The two grammars are incompatible (a documented cross-module product gap), so
/// the composition root maps between them — this id is used for the `MailboxStore`
/// key, `run_agent`/dispatch, the reply registry, and the `POST /msg` target.
/// `pub` so the integration tests witness the production id (false-green guard).
pub const DEFAULT_MSG_AGENT_ID: &str = "agent:default";

/// How long `POST /msg` waits for the turn's reply before returning 504. Bounds
/// the request hold time for an errored/hung turn (the happy + no-reply paths
/// resolve immediately via the oneshot / done watch).
const REPLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Wave-7 Lane B (2026-06-22): cadence of the production auto-mode scheduler tick
/// loop (`run_scheduler_tick_loop` → `dispatch_tick` → the `AutoTickExtension`'s
/// degrade/halt cadence pass + terminal settle). 1 s matches the second-grained
/// safety-valve wall-time / degrade-backoff knobs (sub-second adds no precision;
/// multi-second would delay degrade/halt detection). The pass is a cheap no-op
/// over zero live auto sessions (the production state today).
const AUTO_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Wave-13 Lane B (SYS-AC-228): hard bound on the boot-path registry setup. The
/// ops THIS block issues — `tokio::fs` symlink check + `create_dir_all` +
/// `canonicalize` — all offload to the blocking pool, so they do NOT occupy the
/// single-threaded boot executor and the timer keeps being driven (a bare
/// `std::fs` call would block the sole thread and defeat the bound — audit r4).
/// On a hung/stuck `.triggers` mount the offloaded `symlink_metadata`/
/// `canonicalize` of that path stall FIRST and the timeout fires before
/// `ComponentRegistry::open_in` is even reached. Caveat (adversarial r7): once
/// reached, `open_in` re-`canonicalize()`s + `is_dir()`s its root SYNCHRONOUSLY
/// on the caller thread (only its SQLite `Connection::open` is `spawn_blocking`)
/// — but on the SAME `.triggers` path our preceding bounded `canonicalize`
/// already resolved, so it adds no new unbounded wait in practice (barring an
/// extreme TOCTOU mount-swap between the two canonicalizes — a privileged/operator
/// scenario). On timeout the walk is SKIPPED (non-fatal, like an open error) so
/// the daemon still reaches the park. (Orphaned blocking ops are bounded to one
/// task each and reaped when the FS unblocks or the process exits.)
const BOOT_REGISTRY_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Wave-13 Lane B (SYS-AC-228) — boot-path readiness probe for
/// [`run_readiness_gated_walk_with_breaker_gate`]. Always-ready: at this boot
/// point `wire_capabilities` has already returned, so the runtime IS ready. The
/// real `HostRegistry`-backed `scheduler.boot` probe is a separate documented
/// (waived) wiring slice; this placeholder keeps the readiness leg honest for a
/// post-wiring boot without pulling that slice in.
struct BootReadyProbe;
#[async_trait]
impl RuntimeReadiness for BootReadyProbe {
    async fn is_ready(&self) -> bool {
        true
    }
}

/// Wave-13 Lane B (SYS-AC-228) — boot-path file-watch source placeholder. No
/// production `FileWatchSource` impl exists yet (a real notify-backed source is a
/// documented follow-up); a persisted FileWatch-triggered Watcher row therefore
/// parks here until cancel (inert) rather than watching files. Never invoked on a
/// fresh production workspace (empty registry).
struct BootNoopFileWatchSource;
#[async_trait]
impl FileWatchSource for BootNoopFileWatchSource {
    async fn run(
        &self,
        _glob: String,
        _tx: tokio::sync::mpsc::Sender<TriggerFireEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), HookError> {
        cancel.cancelled().await;
        Ok(())
    }
}

/// Wave-13 Lane B (SYS-AC-228) — boot-path webhook source placeholder. The
/// production `WebhookListener` (MODULE-014 §3.7) exists but is not bound here (it
/// needs a configured addr; binding a second listener at boot is out of this
/// slice's scope). Parks until cancel; never invoked on a fresh workspace.
struct BootNoopWebhookSource;
#[async_trait]
impl WebhookSource for BootNoopWebhookSource {
    async fn run(
        &self,
        _cfg: WebhookConfig,
        _tx: tokio::sync::mpsc::Sender<TriggerFireEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), HookError> {
        cancel.cancelled().await;
        Ok(())
    }
}

/// Render a `Path` for safe stderr emission. Adversarial R1 W4 fix: a path
/// sourced from user input (e.g. `--workspace`, `$ADVANCE_WORKSPACE`, or
/// pulled from a tampered config file) may carry ANSI escapes, terminal
/// control sequences, or newlines. `Path::display()` does NOT escape these;
/// `{:?}` formatting routes through Debug → `escape_debug` and DOES.
fn safe_path(p: &Path) -> String {
    format!("{p:?}")
}

/// Sync entry point invoked from `main.rs`. Builds a current-thread Tokio
/// runtime and drives `run_async`.
pub fn run(workspace: Option<PathBuf>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("advance start: failed to build tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(run_async(workspace))
}

async fn run_async(workspace: Option<PathBuf>) -> ExitCode {
    // 1. Install signal listeners FIRST. Tokio's `signal(SignalKind::*)` is
    //    synchronous (installs the kernel handler eagerly), so subsequent
    //    SIGINT/SIGTERM during lock-acquire or bootstrap is captured and
    //    pending — preventing a window where the kernel default handler kills
    //    the process before the lock can be released or bootstrap can clean up.
    //    (Audit R1 W1 fix.)
    #[cfg(unix)]
    let listeners = match install_unix_listeners() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("advance start: failed to install signal listeners: {e}");
            return ExitCode::from(1);
        }
    };

    // 2. Resolve workspace: --workspace → $ADVANCE_WORKSPACE → CWD.
    let workspace = match resolve_workspace(workspace) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("advance start: {msg}");
            return ExitCode::from(1);
        }
    };

    // 3. Workspace must exist as a directory. canonicalize() requires the path
    //    to exist; check first to produce a friendly error.
    if !workspace.is_dir() {
        eprintln!(
            "advance start: workspace does not exist or is not a directory: {}",
            safe_path(&workspace)
        );
        return ExitCode::from(1);
    }
    let workspace = match workspace.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "advance start: failed to canonicalize workspace {}: {e}",
                safe_path(&workspace)
            );
            return ExitCode::from(1);
        }
    };
    let config_path = workspace.join(".advance").join("runtime-config.yaml");

    // 4. Acquire the single-active-runtime lock. Drop releases it.
    //    Heartbeat default 30s per MODULE-001 §1.4.3; staleness threshold
    //    is the lock's own concern (2 min internally).
    let _lock = match RuntimeLock::acquire(&workspace, Duration::from_secs(30)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("advance start: failed to acquire runtime lock: {e}");
            return ExitCode::from(1);
        }
    };

    // 5. Construct the runtime host via the Slice AG production wiring
    //    path: RuntimeHostBuilder gives us the partial-construction surface
    //    (sqlite_index_handle, host_registry) BEFORE the CapabilityInjector
    //    is built, so wire_capabilities can construct cap-grant's real
    //    GrantCheckImpl + EventBus + cap-secrets host fns and inject them
    //    via builder.build(grant_check). Map missing-config to a friendly
    //    hint via the CliWiringError::Bootstrap → BootstrapError::Config
    //    → ConfigError::IoError(NotFound) variant chain (preserved
    //    verbatim from Slice AE).
    //
    // 5a. Partial-construct.
    let builder = match RuntimeHostBuilder::new(&config_path, &workspace).await {
        Ok(b) => b,
        Err(BootstrapError::Config(ConfigError::IoError { source, .. }))
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            eprintln!(
                "advance start: runtime-config.yaml not found at {}; run `advance init <workspace>` first",
                safe_path(&config_path)
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("advance start: bootstrap failed: {e}");
            return ExitCode::from(1);
        }
    };

    // 5b. Wire production cap-grant + cap-secrets + EventBus.
    // Plan-Eval R1 Warning 4 fix: let-binding ORDER hints at forward-compat
    // graceful-shutdown intent but is NOT load-bearing for Slice AG
    // correctness — Slice AG relies on process termination for cleanup
    // (Tokio runtime drops at process exit, cancelling all spawned tasks).
    // wiring_handles is declared AFTER _lock so a future graceful-shutdown
    // slice can rely on the drop order (handles before lock release). Its
    // `event_bus_dyn` is threaded into the agent loop (EventBusRejectionSink).
    //
    // Audit-R1 Claude-Diff-Warning 2 fix: dropped the NotFound branch arm
    // that was unreachable in practice — the friendly missing-config
    // diagnostic is owned exclusively by the RuntimeHostBuilder::new arm
    // above. `wire_capabilities` does not re-open `runtime-config.yaml`;
    // its only NotFound vector would be a TOCTOU between `is_file()` and
    // the cap-grant compile, which (a) is sub-microsecond and (b) Slice AG
    // resolves by passing pre-snapshotted YAML bytes to cap-grant via the
    // Step-2 fix in `wiring.rs`. Surface any wiring failure with the
    // generic diagnostic.
    let (host, wiring_handles) = match crate::wiring::wire_capabilities(builder, &workspace).await {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("advance start: wiring failed: {e}");
            return ExitCode::from(1);
        }
    };

    {
        let pid = std::process::id();
        let first = host
            .config()
            .llm_providers
            .first()
            .map(|p| p.id.clone())
            .unwrap_or_default();
        let _ = advance_along_home::write_selected_provider(&workspace, pid, &first);
        let mut rx = host.config_watcher().subscribe();
        let ws = workspace.clone();
        tokio::spawn(async move {
            while let Some(cfg) = rx.recv().await {
                let id = cfg
                    .llm_providers
                    .first()
                    .map(|p| p.id.clone())
                    .unwrap_or_default();
                let _ = advance_along_home::write_selected_provider(&ws, pid, &id);
            }
        });
    }

    println!(
        "advance: runtime ready (workspace={})",
        safe_path(&workspace)
    );
    if let Err(e) = std::io::stdout().flush() {
        eprintln!("advance start: failed to flush readiness signal: {e}");
        return ExitCode::from(1);
    }

    // 5c — Slice BS-3 (D12): one-shot load of a deployed agent component (if
    //      present) + spawn the agent-loop driver. Ok(None) → absent → park
    //      (graceful); Err → present-but-unparseable → fail boot loudly. This is
    //      a boot-time load, not a hot swap (AC-13 clause (a)). The gated SYS-AC
    //      witnesses run in the system-acceptance harness, not via this path.
    let progress_loop_wiring = wiring_handles
        .progress_lifecycle
        .as_ref()
        .map(|activation| ProgressLoopWiring {
            ingress: activation.execution_ingress.clone(),
            action_dispatcher: activation.action_dispatcher.clone(),
            execution_boundary: activation.execution_boundary.clone(),
        });
    // Tee slice T3, observer path (ii): install the reap handle BEFORE the root loop
    // is spawned. AUDIT round 6 found the previous placement (after
    // `try_spawn_agent_loop` returned) left a live window: the root serve task starts
    // inside that call, and its first turn can spawn a child. `on_child_spawned` reads
    // this `OnceLock` ONCE at loop construction, so a child born in that window was
    // baked with a reap-less observer for the process lifetime.
    if let (Some(mgr), Some(reaper)) = (
        wiring_handles.perchild_manager.as_ref(),
        wiring_handles.llm_stream_reaper.as_ref(),
    ) {
        mgr.set_llm_stream_reaper(reaper.clone());
    }
    let agent_loop = match try_spawn_agent_loop(
        &host,
        &workspace,
        wiring_handles.event_bus_dyn.clone(),
        wiring_handles.run_manager.clone(),
        wiring_handles.run_config.clone(),
        // Backbone Step 2: the cap-llm gateway (Some iff llm declared) for the
        // assembled-context seam.
        wiring_handles.llm_gateway.clone(),
        wiring_handles.llm_stream_reaper.clone(),
        // B1 backbone (2026-06-09): the SHARED registered memory store (Some iff
        // memory declared) for the real Tier-1b knowledge reader — same Arc the WIT
        // handlers use (no second open).
        wiring_handles.memory_store.clone(),
        // Wave-20 notify production closure: reuse the composition root's
        // messaging store so notify delivery and the serve loop share one mailbox.
        wiring_handles.messaging_store.clone(),
        wiring_handles.reply_registry.clone(),
        wiring_handles.channel_runtime.clone(),
        progress_loop_wiring,
        // Stage-C SAT-A: the populated agent-tree snapshot + the cap-memory root
        // (both capability-gated in wiring.rs) for the live `# Available Delegates`
        // + the L2/L3/L4 history readers.
        wiring_handles.agent_tree_snapshot.clone(),
        wiring_handles.memory_root.clone(),
        // skills-J26 reader satellite: the cap-skills provider root (Some iff
        // `skills` declared) for the live `# Available Skills` reader.
        wiring_handles.skills_root.clone(),
        // Wave-12 Lane C: the shared decomposition store (Some iff the shared tree
        // exists) for the live Tier-2 ⑭ "Active Task Decomposition" section.
        wiring_handles.decomposition_store.clone(),
        // SAT-B: the CONCRETE Arc<EventBus> (coerces to Arc<dyn EventBusEmit +
        // Send + Sync>) for the live components-backed PostProcessor's bus.
        wiring_handles.event_bus.clone(),
        // SAT-C (slice satC-l6): the live git commit queue (Some iff a git repo)
        // for the production L6 construction. Coerce the concrete
        // `Arc<DefaultGitCommitQueue>` to the `Arc<dyn GitCommitQueue>` trait
        // object via the closure-return coercion (`as` does not unsize an Arc).
        wiring_handles
            .git_queue
            .clone()
            .map(|q| -> Arc<dyn advance_git::GitCommitQueue> { q }),
        // Stage-C MAINLINE harvest pass-3: the REAL VLM extractor (Some iff llm declared).
        wiring_handles.vlm_extractor.clone(),
        // Wave-12 (SYS-AC-122): the tool-path repetition guard to late-bind.
        wiring_handles.repetition_guard.clone(),
        // MODULE-017-AC-22: skills turn persistence runtime, if skills+git are wired.
        wiring_handles.skill_turn_runtime.clone(),
        // W24 seam (f): the shared crash-cascade sink attached to the root loop.
        wiring_handles.crash_cascade_sink.clone(),
        wiring_handles.evidence_ids.clone(),
        wiring_handles.tool_registry.clone(),
        wiring_handles.tools_grant_reader.clone(),
        wiring_handles.web_grant.clone(),
    )
    .await
    {
        Ok(spawned) => spawned,
        Err(msg) => {
            eprintln!("advance start: {msg}");
            return ExitCode::from(1);
        }
    };

    // W24 boot leg (SYS-AC-282 / MODULE-001-AC-22): now that the root serve loop is
    // live and the per-child manager's runtime is bound, serve the BOOT-DECLARED
    // children the config-tree materializer (`materialize_config_tree`) created at
    // boot — the SAME per-child serve path a runtime spawn uses. Class-agnostic: it
    // serves whatever non-root nodes exist. `materialize_config_tree` used an
    // observer-less spawner, so these children were routable tree nodes with NO loops
    // until this walk; their loops are drained by the existing `perchild_manager`
    // shutdown drain at teardown.
    if let Some(mgr) = wiring_handles.perchild_manager.as_ref() {
        mgr.serve_existing_children();
    }

    // 5d — WS-A: when an agent loop is running, spawn the in-process HTTP
    //      `POST /msg` inbound message source over the SAME `MailboxStore` the
    //      loop reads, so an external POST wakes the parked serving loop
    //      (`serve`). No loop (no deployed component) → no listener (nothing
    //      to wake). Borrow `agent_loop` here (don't move it) so it stays owned
    //      for the shutdown abort below.
    //      Audit r1 Warning: when channels are configured they REPLACE the POST
    //      /msg shim — skip the POST listener so a channel turn can never cancel
    //      a pending POST reply slot (no POST↔channel mis-correlation).
    let msg_listener = if let Some(spawned) = agent_loop.as_ref() {
        if spawned.channels_active {
            println!("advance: channels configured — POST /msg shim disabled (replaced by /hooks)");
            None
        } else {
            match spawn_msg_listener(
                spawned.store.clone(),
                spawned.execution_ingress.clone(),
                spawned.agent_id.clone(),
                spawned.reply_registry.clone(),
                spawned.done.clone(),
                spawned.in_flight.clone(),
            )
            .await
            {
                Ok(handle) => Some(handle),
                Err(msg) => {
                    eprintln!("advance start: {msg}");
                    spawned.handle.abort(); // tear down the loop we already spawned
                    return ExitCode::from(1);
                }
            }
        }
    } else {
        None
    };

    // Wave-7 Lane B (183/185): wire the PRODUCTION auto tick caller. When a
    // git-repo auto driver exists, construct the AutoTickCoordinator (owns the
    // driver + the RunManager) + the AutoTickExtension, register ONLY the wrapper
    // (not the bare driver — that would double-run `run_cadence_pass` per tick) on a
    // Scheduler, and spawn `run_scheduler_tick_loop` so `dispatch_tick` drives the
    // extension's cadence/cancel/settle pass on AUTO_TICK_INTERVAL. The settle stays
    // product-driven (the tick calls the coordinator; the coordinator calls the
    // RunManager). DORMANT until the harvest's `advance auto start` boot calls
    // `AutoTickExtension::register_session` (the session registry is empty here, so
    // the cadence + settle passes are no-ops). `None` on a non-repo workspace → no
    // tick loop (graceful degrade, like the rest of the auto path).
    let auto_tick: Option<(
        tokio_util::sync::CancellationToken,
        tokio::task::JoinHandle<()>,
    )> = if let Some(driver) = wiring_handles.auto_loop_driver.clone() {
        let coordinator = Arc::new(crate::crash_coordinator::AutoTickCoordinator::new(
            driver.clone(),
            wiring_handles.run_manager.clone(),
        ));
        let extension: Arc<dyn advance_scheduler::SchedulerExtension> = Arc::new(
            crate::auto_tick_extension::AutoTickExtension::new(driver, coordinator),
        );
        let mut scheduler = advance_scheduler::Scheduler::new(Arc::new(
            advance_scheduler::TriggerBusDispatchImpl::new(),
        ));
        scheduler.register_extension(extension);
        let scheduler = Arc::new(scheduler);
        let cancel = tokio_util::sync::CancellationToken::new();
        let loop_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = advance_scheduler::run_scheduler_tick_loop(
                scheduler,
                AUTO_TICK_INTERVAL,
                loop_cancel,
            )
            .await
            {
                eprintln!("advance: auto tick loop did not start: {e}");
            }
        });
        println!(
            "advance: auto-mode scheduler tick loop running (interval={AUTO_TICK_INTERVAL:?})"
        );
        Some((cancel, handle))
    } else {
        None
    };

    // Drive the continuous readiness-gated registry reconciliation over a
    // live ComponentRegistry, installing the component-type breaker gate over the
    // SAME shared CircuitBreakerBus the runtime consults — making the gate WIRED +
    // reachable on a production dispatch path. Boot rows and later CONTRACT-217
    // submissions are materialized exactly once per daemon lifetime. Entirely
    // non-fatal — any failure/timeout logs + skips, never blocks the daemon.
    //
    // Gate scope (adversarial r7): this is the "block NEW dispatch" layer — the
    // gate is consulted once per newly discovered row at `materialize`-time (before the per-type
    // match), exactly matching SYS-AC-228's criterion ("new dispatch to components
    // of that type is blocked while other types continue"). It does NOT stop an
    // already-running Cron/Watcher/Daemon driver loop (that "handle running
    // instances" layer, REQ-111, is a separate breaker concern, not this slice).
    // A breaker opened after boot governs later submitted rows.
    let readiness_walk = {
        let triggers_root = workspace.join(".triggers");
        // ALL boot-path FS ops run INSIDE the single timeout and use `tokio::fs`
        // (each delegates to `spawn_blocking`, so they DON'T occupy the
        // single-threaded boot executor and the timeout can actually fire).
        // Ordered STRICTLY before `open_in` — which canonicalizes the root
        // FOLLOWING symlinks then creates the DB, so a post-open check is too late.
        let opened = tokio::time::timeout(BOOT_REGISTRY_OPEN_TIMEOUT, async {
            // (1) reject a pre-existing symlinked `.triggers` root (lstat, no follow).
            if let Ok(meta) = tokio::fs::symlink_metadata(&triggers_root).await {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "{} is a symlink (path-confinement)",
                        safe_path(&triggers_root)
                    ));
                }
            }
            // (2) create the dir, then (3) confine the canonical root under the
            // canonical workspace BEFORE opening the DB.
            tokio::fs::create_dir_all(&triggers_root)
                .await
                .map_err(|e| format!("create_dir_all .triggers: {e}"))?;
            let canon = tokio::fs::canonicalize(&triggers_root)
                .await
                .map_err(|e| format!("canonicalize .triggers: {e}"))?;
            if !canon.starts_with(&workspace) {
                return Err(format!(
                    "{} escapes workspace (path-confinement)",
                    safe_path(&canon)
                ));
            }
            ComponentRegistry::open_in(&triggers_root, "components.db")
                .await
                // `RegistryError` Display embeds raw `path.display()`; escape it
                // (matches the `safe_path` Debug/escape_debug discipline) so a
                // terminal-escape-laden `.triggers`-resolved name can't inject into
                // the operator's terminal via this skip-path message (adversarial r7).
                .map_err(|e| format!("open registry: {}", e.to_string().escape_debug()))
        })
        .await;

        match opened {
            Ok(Ok(registry)) => {
                let registry = Arc::new(registry);
                let factory: Arc<dyn RunnableHookFactory> = Arc::new(
                    WasmRunnableHookFactory::new(
                        host.component_runtime(),
                        host.capability_injector(),
                    )
                    .with_event_bus(Arc::clone(&wiring_handles.event_bus_dyn)),
                );
                let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
                let probe: Arc<dyn RuntimeReadiness> = Arc::new(BootReadyProbe);
                let file_source: Arc<dyn FileWatchSource> = Arc::new(BootNoopFileWatchSource);
                let webhook_source: Arc<dyn WebhookSource> = Arc::new(BootNoopWebhookSource);
                let breaker_bus = host.circuit_breaker_bus();
                match start_continuous_readiness_gated_walk_with_breaker_gate(
                    registry,
                    probe,
                    factory,
                    dispatcher,
                    file_source,
                    webhook_source,
                    breaker_bus,
                )
                .await
                {
                    Ok(walk) => {
                        println!("advance: continuous component reconciliation wired (component-type breaker gate active)");
                        Some(walk)
                    }
                    Err(e) => {
                        eprintln!("advance: readiness walk did not run: {e}");
                        None
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("advance: skipping readiness walk — {e}");
                None
            }
            Err(_elapsed) => {
                eprintln!(
                    "advance: skipping readiness walk — registry open timed out after {BOOT_REGISTRY_OPEN_TIMEOUT:?}"
                );
                None
            }
        }
    };

    // 6. Park until SIGINT / SIGTERM. Listeners were installed in step 1 (above
    //    lock-acquire) so any signal received during lock-acquire or bootstrap
    //    is captured and pending; the .recv() here just resolves immediately
    //    in that case.
    #[cfg(unix)]
    park_until_shutdown_unix(listeners).await;
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    // Cancel the inbound listener + the agent-loop task before dropping the host
    // so neither outlives the runtime it borrows capability handles from.
    if let Some(handle) = msg_listener {
        handle.abort();
    }
    if let Some(spawned) = agent_loop {
        spawned.handle.abort();
        for h in spawned.channel_handles {
            h.abort();
        }
    }
    // Wave-23 seam (d): abort any per-child serve loops the spawn observer started,
    // alongside the root loop, before `_host`/`_lock` drop.
    if let Some(mgr) = wiring_handles.perchild_manager.as_ref() {
        mgr.drain();
    }
    // Wave-7 Lane B: stop the auto tick loop. cancel() FIRST (graceful — the loop's
    // `select!` sees the token and returns Ok at the next await point), THEN abort()
    // (force, in case it is mid in-flight tick), before `_host`/`_lock` drop so the
    // loop never outlives the runtime whose handles the coordinator clones borrow.
    if let Some((cancel, handle)) = auto_tick {
        cancel.cancel();
        handle.abort();
    }
    // Stop the registry reconciler and every driver before dropping the runtime host.
    if let Some(walk) = readiness_walk {
        walk.shutdown().await;
    }
    println!("advance: shutting down");
    // _host and _lock drop here, releasing resources.
    ExitCode::SUCCESS
}

/// MODULE-001-AC-20 (024): discriminate a `wasm32` core module from an encoded WASM
/// Component by the binary header. Both share the `\0asm` magic (bytes 0..4); the low
/// byte of the version field (byte 4) is `0x01` for a core module and `0x0d` for a
/// component-model binary (cf. `build_agent::encode_core_to_component`'s own test). A
/// buffer too short to hold the 8-byte preamble, or not `\0asm`, is treated as "not a
/// core module" so `load_component` surfaces the real parse error rather than this
/// path mis-encoding it.
fn is_core_module(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[0..4] == b"\0asm" && bytes[4] == 0x01
}

/// MODULE-001-AC-20 (024): resolve the deploy driver bytes from the canonical
/// materialized name and return LOAD-READY Component bytes (path + bytes). Prefers
/// `<ws>/.agent/behavior.component.wasm` (the `build-agent` deploy output); else falls
/// back to `<ws>/.agent/behavior.wasm` (the SYS-AC-022 / §1.4.3-manifest name a
/// template materializes). A `wasm32` core module is encoded to a Component via
/// `build_agent::encode_core_to_component`; an already-encoded Component is returned
/// as-is. `Ok(None)` = neither artifact present (caller parks). `Err` = present but
/// unreadable / un-encodable. Pure (no `RuntimeHost`) so it is unit-testable.
pub(crate) fn resolve_driver_component_bytes(
    workspace: &Path,
) -> Result<Option<(PathBuf, Vec<u8>)>, String> {
    let component_path = workspace.join(".agent").join("behavior.component.wasm");
    let materialized_path = workspace.join(".agent").join("behavior.wasm");
    let (driver_path, raw) = match std::fs::read(&component_path) {
        Ok(b) => (component_path, b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::read(&materialized_path) {
                Ok(b) => (materialized_path, b),
                Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e2) => {
                    return Err(format!(
                        "deployed component {} is present but unreadable: {e2}",
                        safe_path(&materialized_path)
                    ))
                }
            }
        }
        Err(e) => {
            return Err(format!(
                "deployed component {} is present but unreadable: {e}",
                safe_path(&component_path)
            ))
        }
    };
    if is_core_module(&raw) {
        let encoded = build_agent::encode_core_to_component(&raw).map_err(|e| {
            format!(
                "deployed component {} is a core module that failed to encode: {e:?}",
                safe_path(&driver_path)
            )
        })?;
        Ok(Some((driver_path, encoded)))
    } else {
        Ok(Some((driver_path, raw)))
    }
}

/// Slice BS-3 (D12): load a deployed agent component ONE-SHOT (if present at the
/// conventional `<workspace>/.agent/behavior.component.wasm`) and spawn the scheduler
/// agent-loop driver on a cancellable task.
///
/// MODULE-001-AC-20 (024): the loader resolves the canonical materialized name —
/// it prefers `<ws>/.agent/behavior.component.wasm` (the `build-agent` deploy output)
/// and falls back to `<ws>/.agent/behavior.wasm` (the SYS-AC-022 / §1.4.3-manifest
/// name a template materializes via `apply_template`). `load_component` accepts a
/// PRE-ENCODED component only, so the loader discriminates an encoded Component
/// (component-model header, version byte `0x0d`) from a `wasm32` core module (`0x01`)
/// and encodes a core module via `build_agent::encode_core_to_component` ON THE FLY
/// before loading — so a template-materialized child has a loadable driver with no
/// extra build step. This is a ONE-SHOT boot encode+load (the bytes are read exactly
/// once at boot — MODULE-001 AC-13 clause (a)), NOT hot-reload.
///
/// Returns:
/// - `Ok(None)` — no component deployed → caller parks (graceful, mirrors a
///   missing `.agent/config.yaml`).
/// - `Ok(Some(handle))` — component loaded + driver spawned; `handle` is aborted
///   on shutdown.
/// - `Err(msg)` — a component IS present but could not be read/parsed → caller
///   fails boot loudly (a deployed-but-broken agent must surface, not silently
///   park).
///
/// This is NOT a hot-reload path: the bytes are read exactly once at boot, there
/// is no file watcher, and changing the deployed binary requires a restart
/// (MODULE-001 AC-13 clause (a) — "restart is the mechanism"). The spawned
/// `serve` loop (Phase-2 Step-2) instantiates the guest then blocks on the
/// mailbox `recv`; WS-A's in-process `POST /msg` listener (spawned by `run_async`
/// over the SAME store this returns) delivers a `Message` that wakes that `recv`
/// and drives one turn, then the loop parks on `recv` again for the next message.
/// The `system-acceptance` harness drives single turns via the same factory's
/// `run_agent`.
fn select_agent_loop_store(provided: Option<Arc<MailboxStore>>) -> Arc<MailboxStore> {
    provided.unwrap_or_else(|| {
        Arc::new(MailboxStore::new(
            NonZeroUsize::new(64).expect("mailbox capacity 64 is nonzero"),
        ))
    })
}

async fn try_spawn_agent_loop(
    host: &RuntimeHost,
    workspace: &Path,
    event_bus: Arc<dyn EventBusEmit>,
    run_manager: Arc<RunManager>,
    run_config: RunConfig,
    // Backbone Step 2 (2026-06-07): the cap-llm gateway (Some iff llm declared) —
    // used to build the `PublishingContextAssembler` seam that feeds the assembled
    // layered context to the guest's `generate`. `None` → MinimalContextAssembler.
    llm_gateway: Option<Arc<LlmGateway>>,
    // Tee slice T3 (ADR 2026-07-22 D5): turn-end reap handle. Composed into the
    // root turn-observer fan-out below so an abandoned live stream is settled at
    // turn end rather than waiting for the absolute deadline / TTL sweep.
    llm_stream_reaper: Option<Arc<cap_llm::AgentStreamReaper>>,
    // B1 backbone (2026-06-09): the SHARED registered `MemoryStore` (Some iff the
    // agent declared `memory`) — the real Tier-1b knowledge reader reads THIS store,
    // not a second `open()`.
    memory_store: Option<Arc<cap_memory::MemoryStore>>,
    // Wave-20 notify production closure: optional composition-root mailbox
    // store shared with notify/await wiring. `None` preserves the pre-existing
    // loop-local store behavior.
    messaging_store: Option<Arc<MailboxStore>>,
    // Composition-root singleton reply/channel graph. `progress_loop` is Some
    // only after the C215+C216 joint authority has been consumed.
    reply_registry: Arc<ReplyRegistry>,
    channel_rt: Option<Arc<channels_boot::ChannelRuntime>>,
    progress_loop: Option<ProgressLoopWiring>,
    // Stage-C SAT-A: the populated agent-tree snapshot (Some iff `fs` declared) —
    // replaces the hardcoded `EmptyAgentTree` so the assembler's `# Available
    // Delegates` reflects the real tree. And the cap-memory root dir (Some iff
    // `memory` declared) — the base for the L2/L3/L4 history file readers.
    agent_tree_snapshot: Option<Arc<dyn AgentTreeSnapshot>>,
    memory_root: Option<PathBuf>,
    // skills-J26 reader satellite (2026-06-20): the cap-skills provider root
    // (Some iff `skills` declared — single-sourced in wiring.rs) for the live
    // `# Available Skills` reader. None → StubSkillSummary (no section).
    skills_root: Option<PathBuf>,
    // Wave-12 Lane C: the shared `DefaultDecompositionStore` (Some iff the shared
    // tree exists — `declares_fs || declares_messaging`) the decomposition host-fns
    // record into. Wrapped in a `CapDecompositionReader` below for the Tier-2 ⑭
    // "Active Task Decomposition" section; `None` ⇒ `EmptyDecomposition` (no section).
    decomposition_store: Option<Arc<DefaultDecompositionStore>>,
    // SAT-B (slice satB-postproc): the CONCRETE event bus (Send + Sync), threaded
    // so the live `Components::wired(...)` gets the REAL L6/Seam-A bus. `run_async`
    // passes `wiring_handles.event_bus.clone()` (the `Arc<EventBus>` at
    // wiring.rs:158, which coerces to this trait object — an already-erased
    // `Arc<dyn EventBusEmit>` like the rejection-sink `event_bus` arg above does
    // NOT coerce up to `+ Send + Sync`, hence a distinct param).
    event_bus_ss: Arc<dyn EventBusEmit + Send + Sync>,
    // SAT-C (slice satC-l6): the live git commit queue (CONTRACT-020; `Some` iff
    // the workspace is a git repo). Threaded into `build_live_post_processor` to
    // attach the production L6 construction (in-process Step-9 dispatch + real
    // `GitQueueL6Committer`). `None` ⇒ no L6 handler (Step-9 emit-only).
    git_queue: Option<Arc<dyn advance_git::GitCommitQueue>>,
    // Stage-C MAINLINE harvest pass-3 (2026-06-19): the REAL VLM description extractor
    // (Some iff llm declared) — threaded into `build_live_post_processor` to install the
    // `VlmDescriptionIndexer` into the live post-processor Step-3.
    vlm_extractor: Option<Arc<dyn cap_llm::VlmExtractor>>,
    // Wave-12 (SYS-AC-122): the process-global tool-path `RepetitionGuard` (Some
    // iff `tools` declared) — late-bound below with THIS per-agent
    // `ContextAssembler` so a repeated tool-triplet's Tier-3 warning surfaces on
    // the next handle-message turn.
    repetition_guard: Option<Arc<RepetitionGuard>>,
    skill_turn_runtime: Option<Arc<cap_skills::SkillTurnRuntime>>,
    // W24 seam (f): the shared crash-cascade sink (Some iff messaging+tree wired),
    // attached to the ROOT loop (uniformity — child loops get it inside the manager).
    crash_cascade_sink: Option<Arc<dyn advance_scheduler::hook::CrashCascadeSink>>,
    evidence_ids: Arc<cap_tools::web::EvidenceIdStore>,
    tool_registry: Option<Arc<dyn cap_tools::ToolRegistry>>,
    tools_grant_reader: Option<Arc<dyn advance_shared_types::traits::ToolsGrantReader>>,
    web_grant: Option<Arc<dyn advance_shared_types::traits::GrantCheck>>,
) -> Result<Option<SpawnedAgentLoop>, String> {
    // MODULE-001-AC-20 (024): resolve the canonical materialized name + (if a core
    // module) encode it to a Component on the fly. `None` → no driver deployed → park.
    let (driver_path, bytes) = match resolve_driver_component_bytes(workspace)? {
        Some(pair) => pair,
        None => return Ok(None),
    };
    let runtime = host.component_runtime();
    let loaded = runtime.load_component(&bytes).map_err(|e| {
        format!(
            "deployed component {} failed to load: {e:?}",
            safe_path(&driver_path)
        )
    })?;
    let injector = host.capability_injector();
    // TWO agent ids — the two id grammars are incompatible (see DEFAULT_MSG_AGENT_ID):
    // - cap_agent_id (bare): cap-fs resolver-tree root + cap-grant grantee,
    //   resolved via ComponentCtx at host-fn time. MUST match wiring.rs
    //   DEFAULT_AGENT_ID ("default-agent") or the deployed agent's fs + grant
    //   resolution fails (lookup by exact id string). cap-grant/cap-lifecycle
    //   reject a colon, so this stays bare.
    let cap_agent_id = "default-agent".to_string();
    // - msg_agent_id (canonical, colon-prefixed): the MailboxStore key + the
    //   run_agent/dispatch id + the reply-registry key + the POST /msg target.
    //   messaging is_safe_id requires the prefix; the mailbox store does not
    //   validate key grammar, so deliver/recv stay consistent on it.
    let msg_agent_id = DEFAULT_MSG_AGENT_ID.to_string();
    // WS-A: source the guest's capability set from `.agent/config.yaml` (was a
    // hardcoded `vec![fs]`). The SAME `.agent/config.yaml` gates which host fns
    // `wiring::wire_capabilities` registered, so the requested caps and the
    // registered host fns line up exactly (via the shared `agent_config`
    // helper). No config (or none active) → empty set, consistent with wiring
    // registering no host fns in that case.
    let caps = crate::agent_config::active_capabilities(
        crate::agent_config::read_agent_yaml(workspace).as_deref(),
    );
    // Backbone Step 2 (adversarial r9 W2): snapshot the agent's DECLARED cap names
    // here, BEFORE `caps` is moved into `WasmMessageHandler::new`, so the
    // context-assembler host-fn probe can scope `# Available Tools` to this agent's
    // own capability set (not a process-wide allowlist).
    let declared_cap_names: Vec<String> = caps
        .iter()
        .map(|c| c.capability.as_str().to_string())
        .collect();
    // Phase-3 kickoff: one shared cell carries the session RunId from the
    // driver-side `RunManagerBootstrap` to the handler's `init`. Both use the
    // SAME bare `cap_agent_id`, so the bootstrap's run is exactly the run the
    // producer sets on `ComponentCtx`.
    let session_cell: SessionRunCell = Arc::new(std::sync::OnceLock::new());
    let handler: Arc<dyn MessageHandler> = Arc::new(
        WasmMessageHandler::new(
            runtime,
            loaded,
            injector,
            caps,
            cap_agent_id.clone(),
            "trace-boot".to_string(),
        )
        .with_run_session(RunSession {
            run_manager: run_manager.clone(),
            cell: session_cell.clone(),
        }),
    );
    // Hold the shared store at this scope and clone the Arc into the loop: the
    // SAME store is returned to `run_async`, which hands it to the `POST /msg`
    // listener. `Mailbox::deliver` (listener side) → `notify_one` wakes the
    // `recv` the loop is parked on.
    let store = select_agent_loop_store(messaging_store);
    // Reply registry and channel runtime were staged once in wire_capabilities.
    // No second HTTP security chain or SubscriptionManager is constructed here.
    // Audit r1 Warning: when channels are configured they REPLACE the POST /msg
    // shim (ADR: "/hooks replaces POST /msg") — `run_async` then does NOT spawn
    // the POST /msg listener, so a channel turn can never cancel a pending POST
    // reply slot (the agent-id-keyed POST↔channel mis-correlation is structurally
    // impossible when the two never share the serving loop).
    let channels_active = channel_rt.is_some();
    // The composite outbound sink: channel-sourced replies (origin present) go
    // in-host through OutboundTransport; POST /msg replies (origin None) fulfil
    // the reply registry.
    let outbound: Option<Arc<dyn OutboundActionSink>> =
        progress_loop.is_none().then(|| match &channel_rt {
            Some(cr) => Arc::new(
                DaemonOutboundSink::with_channel(
                    reply_registry.clone(),
                    ChannelEgress::new(cr.transport.clone(), cr.manager.clone()),
                )
                .with_evidence_ids(evidence_ids.clone()),
            ) as Arc<dyn OutboundActionSink>,
            None => Arc::new(
                DaemonOutboundSink::registry_only(reply_registry.clone())
                    .with_evidence_ids(evidence_ids.clone()),
            ) as Arc<dyn OutboundActionSink>,
        });
    // Phase-2 Step-2: single-in-flight guard, hoisted here (was created inside
    // `spawn_msg_listener`) and SHARED between the listener (which CASes it on
    // each POST) and the serving loop's `WatchTurnObserver` (which clears it at
    // each turn boundary). One owner clears it: the observer when a turn ran, or
    // the listener's deliver-error branch when a turn never started.
    let in_flight = Arc::new(AtomicBool::new(false));
    // Phase-2 Step-2: per-turn observer. At every `serve` turn boundary it (1)
    // `cancel`s the reply slot — a no-op if dispatch already fulfilled it
    // (happy / no-action turn), otherwise it drops the pending sender so a
    // no-reply turn (validator-reject / assemble-error / trap) resolves the
    // awaiting POST's rx to Err → 502 instead of hanging — and (2) clears the
    // in-flight guard so the next serial POST proceeds.
    // Tee slice T3: the root path is a FAN-OUT — the existing `WatchTurnObserver`
    // plus the turn-end reap observer. Order matters: the watch observer runs first
    // so it clears its in-flight guard promptly even when a reap has streams to
    // settle. Path (ii), the per-child serve loop, is composed separately in
    // `perchild_daemon.rs`; both must be wired or served child turns never reap.
    let watch_observer: Arc<dyn TurnObserver> = Arc::new(WatchTurnObserver {
        reply_registry: reply_registry.clone(),
        in_flight: in_flight.clone(),
    });
    let observer: Arc<dyn TurnObserver> = match llm_stream_reaper.clone() {
        Some(reaper) => Arc::new(crate::reap::CompositeTurnObserver::new(vec![
            watch_observer,
            // §5.2 item 5: the authoritative (serve-key, cap-id) pair is injected
            // verbatim from the SAME locals this function serves and grants with —
            // never re-derived from the serve id by string surgery.
            Arc::new(crate::reap::ReapTurnObserver::for_agent(
                reaper,
                msg_agent_id.clone(),
                cap_agent_id.clone(),
            )),
        ])),
        None => watch_observer,
    };
    // Phase-3 kickoff: replace the default `MinimalRunBootstrap` with the real
    // `RunManagerBootstrap` (production path) — it mints the session run + publishes
    // its RunId into `session_cell` (the SAME cell + bare `cap_agent_id` the handler
    // reads in `init`). The driver discards the returned String; the cell is the
    // hand-off.
    // Backbone Step 2: clone the bus for the context assembler's `context.assembled`
    // emit BEFORE `event_bus` is moved into `build_agent_loop` (rejection sink).
    let assembler_bus = event_bus.clone();
    // Stage-C SAT-A: resolve a CONCRETE model id (the default provider's
    // lex-first alias VALUE — `None` hint → gateway-default resolution) so
    // MODULE-010's `model_context_window` returns a real budget rather than the
    // fail-safe-small `SMALL_MODEL_WINDOW`. Any error (no providers / empty
    // aliases) → empty string (the documented small-window fallback). The
    // borrow of the `Arc<RuntimeConfig>` temporary lives for the call duration.
    let assembler_model = resolve_provider_and_model(&host.config().llm_providers, None)
        .map(|r| r.model)
        .unwrap_or_default();
    // MODULE-014-AC-25 (029): clone the EventBus emitter for the agent-loop trap path
    // BEFORE `event_bus` is moved into `build_agent_loop` (the rejection sink), so a
    // real guest trap surfaces a production `component.error` event. No RestartPolicy
    // is wired here (there is no production agent-loop restart-policy config source
    // yet) — the `Option<RestartPolicy>` default `None` preserves the continue-on-trap
    // behaviour; the policy is opt-in once a config field lands (MODULE-014 §2.7).
    let ce_emitter = event_bus.clone();
    // AC-17: apply the `security.action_validator.max_message_size` config SNAPSHOT
    // (read once at construction; the validator stays deterministic — CONTRACT-113).
    let action_max_message_size = host.config().security.action_validator.max_message_size;
    let mut driver = match progress_loop.as_ref() {
        Some(progress) => build_agent_loop_with_prebuilt_dispatcher(
            store.clone(),
            handler,
            progress.action_dispatcher.clone(),
        ),
        None => build_agent_loop_with_action_limit(
            store.clone(),
            handler,
            event_bus,
            outbound,
            action_max_message_size,
        ),
    }
    .with_turn_observer(observer)
    .with_model(assembler_model)
    .with_component_error_emitter(ce_emitter)
    .with_run_bootstrap(Arc::new(RunManagerBootstrap {
        run_manager,
        run_config,
        session_agent: cap_agent_id.clone(),
        cell: session_cell,
    }));
    if let Some(progress) = progress_loop.as_ref() {
        driver = driver.with_protected_turn_boundary(progress.execution_boundary.clone());
    }
    if let Some(runtime) = skill_turn_runtime {
        driver = driver.with_turn_persistence_boundary(Arc::new(SkillTurnBoundary { runtime }));
    }
    // W24 seam (f): attach the shared crash-cascade sink to the ROOT loop. Inert for
    // the root itself (no parent to notify), attached for uniformity with the child
    // loops per the seam-(f) "attach to BOTH root and child loops" clause.
    if let Some(sink) = crash_cascade_sink {
        driver = driver.with_crash_cascade(sink);
    }
    // SAT-B (slice satB-postproc, #1 hazard fix): install the live
    // components-backed PostProcessor — GATED on `memory_store` + `llm_gateway`
    // both present (else the trace-only `PostProcessor::new()` from
    // `build_agent_loop` is kept, which writes NO synthetic entries). Borrows
    // both Options via `.as_ref()` so the context-assembler block below — which
    // MOVES `llm_gateway` (the `if let Some(gateway)`) and `memory_store` — still
    // owns them. The bare `cap_agent_id` is the write-bucket key (colon/bare fix).
    driver = driver.with_post_processor(build_live_post_processor(
        memory_store.as_ref(),
        llm_gateway.as_ref(),
        workspace,
        event_bus_ss,
        &cap_agent_id,
        git_queue,
        vlm_extractor,
        agent_tree_snapshot.clone(),
    ));
    // Backbone Step 2: when llm is wired, install the REAL ContextAssemblerImpl
    // (via the PublishingContextAssembler seam) so the assembled layered context
    // (a) emits `context.assembled` per real turn and (b) feeds the guest's
    // `generate` (published into the gateway's per-agent store under the bare
    // cap_agent_id = ComponentCtx.agent_id). Production wires REAL event_bus +
    // host_fn_inventory (HostRegistry probe) + gateway + the REAL `agent_tree`
    // snapshot (SAT-A; the 5-spawn block records `Sub` nodes into it — 011); STILL
    // STUBS `callable_inventory` (empty, lands in a later slice). `None` gateway →
    // keep the default MinimalContextAssembler (no LLM, no seam).
    if let Some(gateway) = llm_gateway {
        // Backbone Step 2 (adversarial r9 W2): probe host fns ONLY under the caps
        // THIS agent declared in `.agent/config.yaml` (the same `caps` set injected
        // into the guest linker), NOT a process-wide allowlist — so the assembled
        // `# Available Tools` section never advertises host fns outside the agent's
        // own capability set. (Full dynamic L1 grant-filtering is the satellite
        // tools-inv slice / SYS-AC-012.)
        let declared_caps: Vec<&str> = declared_cap_names.iter().map(|s| s.as_str()).collect();
        // B1 backbone (2026-06-09, ADVERSARIAL-r7 fix): the real Tier-1b
        // KnowledgeMapReader reads the SHARED registered `MemoryStore` (the SAME
        // `Arc` the WIT handlers use, threaded via `WiringHandles.memory_store`),
        // NOT a second `MemoryStore::open()` — so there is no second active-set
        // hydration, no dual-handle corruption hazard, and no new `.agent/memory`
        // open surface. CAPABILITY GATE: `memory_store` is `Some` iff `.agent/
        // config.yaml` declared `memory` (gated once, in wiring.rs); a no-memory-cap
        // agent gets `None` → the all-stub path, so `.agent/memory` content can never
        // reach its prompt. cap-memory writes under the BARE cap id (`cap_agent_id`);
        // the assembler queries with the COLON routing id (`msg_agent_id`) — read the
        // bare write-bucket, key the reader under BOTH so the colon query hits
        // (MODULE-010 §3.6 B1 row). The Tier-1b projection is a build-time snapshot.
        // Stage-C SAT-A: the REAL populated agent-tree snapshot (or `EmptyAgentTree`
        // when no `fs` cap) replaces the hardcoded `EmptyAgentTree`. 011 (Wave-11
        // Lane B): the spawn host-fns now record `Sub` nodes into this SAME shared
        // tree (`wire_capabilities` 5-spawn block), so the tree is no longer
        // Root-only as it grows. Wave-12: the colon/bare keying is now BRIDGED —
        // `assemble()` matches delegates against the agent-id alias set passed below
        // (`&[cap_agent_id (bare), msg_agent_id (colon)]`), so a sub-agent recorded
        // under the bare cap-id surfaces for the colon-keyed assemble turn BY NAME.
        // (SYS-AC-011 stays DEFERRED only for the empty-caps WIT spawn cap-lift gap.)
        // `memory_root.as_deref()` activates the L2/L3/L4 history
        // readers (already memory-cap-gated in wiring).
        let agent_tree: Arc<dyn AgentTreeSnapshot> = match agent_tree_snapshot.clone() {
            Some(t) => t,
            None => Arc::new(crate::context_wiring::EmptyAgentTree),
        };
        // Wave-12 Lane C: wrap the shared decomposition store (Some iff the shared
        // tree exists) in a `CapDecompositionReader` with this agent's bare/colon
        // alias set (BARE-FIRST — the store rejects colon owner ids; this is the fix
        // for the colon/bare keying residual the 011 delegates section left open).
        // The SAME `[cap_agent_id, msg_agent_id]` slice the memory reader uses below.
        // `None` ⇒ `EmptyDecomposition` (no Tier-2 ⑭ section).
        let decomposition: Arc<dyn DecompositionReader> = match decomposition_store.clone() {
            Some(store) => Arc::new(crate::context_wiring::CapDecompositionReader::new(
                store,
                vec![cap_agent_id.clone(), msg_agent_id.clone()],
            )),
            None => Arc::new(crate::context_wiring::EmptyDecomposition),
        };
        let callable: Arc<dyn CallableInventoryReader> = if let Some(reg) = tool_registry.as_ref() {
            let listed = cap_tools::ToolRegistry::list(reg.as_ref()).await;
            let allow = tools_grant_reader
                .as_ref()
                .and_then(|r| r.tool_allowlist(&cap_agent_id));
            let entries = cap_tools::web::project_callable_tool_entries(
                listed,
                allow.as_deref(),
                web_grant.as_deref(),
                &cap_agent_id,
            );
            Arc::new(cap_tools::CallableInventory::new(entries, vec![]))
        } else {
            Arc::new(crate::context_wiring::EmptyCallableInventory)
        };
        let inner = crate::context_wiring::build_context_assembler_for_agent_with_decomposition(
            assembler_bus,
            callable,
            Arc::new(crate::context_wiring::FixedHostFnInventory::new(
                crate::context_wiring::host_fns_from_registry(
                    &*host.host_registry(),
                    &declared_caps,
                ),
            )),
            agent_tree,
            memory_store,
            &cap_agent_id,
            &[cap_agent_id.clone(), msg_agent_id.clone()],
            memory_root.as_deref(),
            // skills-J26 reader satellite: activates the real DiskSkillSummaryReader
            // (Some iff `skills` declared — already gated in wiring.rs).
            skills_root.as_deref(),
            decomposition,
        );
        // Wave-12 (SYS-AC-122): LATE-BIND THIS per-agent assembler into the
        // process-global tool-path RepetitionGuard (built at wire_capabilities
        // Step 7, before `inner` existed). The guard injects a repetition warning
        // via `inner.inject_tier3_warning(agent_id, …)`; the next handle-message
        // turn assembles via `publishing` → `inner.assemble(…)` — ONE shared
        // WarningQueue (the publishing wrapper delegates both to `inner`). Set
        // BEFORE `inner` moves into the wrapper. The bare-record / colon-drain
        // keying is bridged by the assembler's `query_aliases` `[cap_agent_id,
        // msg_agent_id]` (the `&[cap_agent_id.clone(), msg_agent_id.clone()]` arg
        // passed to `build_context_assembler_for_agent_with_skills` below).
        if let Some(guard) = &repetition_guard {
            guard.set_context_assembler(inner.clone());
        }
        let publishing = Arc::new(PublishingContextAssembler::new(
            inner,
            gateway,
            cap_agent_id.clone(),
        ));
        driver = driver.with_context_assembler(publishing);
    }
    // ComponentConfig.id carries the CAP id (the guest's self-identity for caps).
    let cfg = ComponentConfig {
        id: cap_agent_id.clone(),
        config_data: None,
        trigger_context: None,
    };
    let component_id = ComponentId::new("agent-default-inst".to_string())
        .map_err(|_| "internal: static component instance id is invalid".to_string())?;
    let instance = WasmInstance::new(component_id);
    println!("advance: agent loop wired (component loaded; serving inbound messages)");
    // `done` watch: the serving-loop task sends `true` only when the loop
    // TERMINATES (shutdown `handle.abort()` or a panic-unwind, via the drop-guard).
    // Under the infinite `serve` loop it no longer fires on per-turn completion;
    // `handle_msg` uses it to 503 any POST once the daemon is going away.
    let (done_tx, done_rx) = watch::channel(false);
    let run_agent_id = msg_agent_id.clone();
    let handle = tokio::spawn(async move {
        // Set done=true on loop termination AND on a panic-unwind (drop-guard),
        // so a waiting `POST /msg` never hangs to the timeout if the loop ends,
        // and post-shutdown POSTs get 503 regardless of how the loop ended.
        struct DoneOnDrop(watch::Sender<bool>);
        impl Drop for DoneOnDrop {
            fn drop(&mut self) {
                let _ = self.0.send(true);
            }
        }
        let _done_guard = DoneOnDrop(done_tx);
        // Phase-2 Step-2: `serve` (the multi-turn loop) replaces the single-turn
        // `run_agent`. Runs until the task is aborted at shutdown.
        driver.serve(&run_agent_id, cfg, instance).await;
    });
    let execution_ingress = progress_loop
        .as_ref()
        .map(|progress| progress.ingress.clone());
    // Phase-2 Step-3: when channels are configured, bind the shared `/hooks`
    // listener + spawn the host pump (poll_host_pump → Message → mailbox → serve).
    let mut channel_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(cr) = channel_rt {
        match channels_boot::spawn_hooks_listener(cr.supervisor.clone(), cr.listen_addr).await {
            Ok(h) => channel_handles.push(h),
            Err(msg) => {
                handle.abort();
                return Err(msg);
            }
        }
        channel_handles.push(match execution_ingress.as_ref() {
            Some(ingress) => channels_boot::spawn_protected_host_pump(
                cr.manager.clone(),
                cr.identity.clone(),
                cr.subs.clone(),
                ingress.clone(),
                msg_agent_id.clone(),
            ),
            None => channels_boot::spawn_host_pump(
                cr.manager.clone(),
                cr.identity.clone(),
                cr.subs.clone(),
                store.clone(),
                msg_agent_id.clone(),
            ),
        });
    }
    Ok(Some(SpawnedAgentLoop {
        handle,
        store,
        agent_id: msg_agent_id,
        reply_registry,
        done: done_rx,
        in_flight,
        execution_ingress,
        channel_handles,
        channels_active,
    }))
}

/// A spawned agent loop plus the shared `MailboxStore` it reads from and the
/// messaging agent id it runs under. `run_async` hands the store + reply registry
/// + done watch to the `POST /msg` listener so an inbound message wakes the parked
/// turn and its reply is correlated back, and aborts `handle` on shutdown.
struct SpawnedAgentLoop {
    handle: tokio::task::JoinHandle<()>,
    store: Arc<MailboxStore>,
    /// The MESSAGING id (`DEFAULT_MSG_AGENT_ID`) — the mailbox key + POST target.
    agent_id: String,
    /// Reply correlation registry shared with the dispatcher's `ReplyRouterSink`.
    reply_registry: Arc<ReplyRegistry>,
    /// `true` once the serving loop terminates (shutdown/abort/panic). Under the
    /// infinite `serve` loop this fires only on termination, never per-turn.
    done: watch::Receiver<bool>,
    /// Single-in-flight guard shared with the serving loop's `WatchTurnObserver`
    /// (which clears it at each turn boundary) and the `POST /msg` listener (which
    /// CASes it per POST). Phase-2 Step-2.
    in_flight: Arc<AtomicBool>,
    /// C216 external ingress. `Some` only when the joint graph is active.
    execution_ingress: Option<Arc<ExecutionTurnIngress>>,
    /// Phase-2 Step-3: the `/hooks` listener + host-pump task handles (when
    /// channels are configured). Aborted on shutdown alongside the loop.
    channel_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Phase-2 Step-3: true when channels are configured — the POST /msg shim
    /// listener is then NOT spawned (channels replace it).
    channels_active: bool,
}

#[cfg(feature = "test-support")]
pub struct TestServeLoop {
    inner: SpawnedAgentLoop,
}

#[cfg(feature = "test-support")]
impl TestServeLoop {
    pub fn store(&self) -> Arc<MailboxStore> {
        self.inner.store.clone()
    }

    pub fn agent_id(&self) -> &str {
        &self.inner.agent_id
    }
}

#[cfg(feature = "test-support")]
impl Drop for TestServeLoop {
    fn drop(&mut self) {
        self.inner.handle.abort();
        for handle in &self.inner.channel_handles {
            handle.abort();
        }
    }
}

#[cfg(feature = "test-support")]
pub async fn spawn_test_agent_loop(
    host: &RuntimeHost,
    workspace: &Path,
    handles: &crate::wiring::WiringHandles,
    messaging_store: Arc<MailboxStore>,
) -> Result<Option<TestServeLoop>, String> {
    let git_queue = handles
        .git_queue
        .clone()
        .map(|q| -> Arc<dyn advance_git::GitCommitQueue> { q });
    let progress_loop = handles
        .messaging_store
        .as_ref()
        .filter(|wired| Arc::ptr_eq(wired, &messaging_store))
        .and_then(|_| handles.progress_lifecycle.as_ref())
        .map(|activation| ProgressLoopWiring {
            ingress: activation.execution_ingress.clone(),
            action_dispatcher: activation.action_dispatcher.clone(),
            execution_boundary: activation.execution_boundary.clone(),
        });
    // AUDIT round 7: the test-support harness must arm observer path (ii) too.
    // Without this, `PerChildLoopManager::on_child_spawned` reads an empty `OnceLock`
    // and bakes every child with a reap-less observer — on the ONLY composition an
    // owed T120 witness can drive.
    if let (Some(mgr), Some(reaper)) = (
        handles.perchild_manager.as_ref(),
        handles.llm_stream_reaper.as_ref(),
    ) {
        mgr.set_llm_stream_reaper(reaper.clone());
    }
    try_spawn_agent_loop(
        host,
        workspace,
        handles.event_bus_dyn.clone(),
        handles.run_manager.clone(),
        handles.run_config.clone(),
        handles.llm_gateway.clone(),
        handles.llm_stream_reaper.clone(),
        handles.memory_store.clone(),
        Some(messaging_store),
        handles.reply_registry.clone(),
        handles.channel_runtime.clone(),
        progress_loop,
        handles.agent_tree_snapshot.clone(),
        handles.memory_root.clone(),
        handles.skills_root.clone(),
        handles.decomposition_store.clone(),
        handles.event_bus.clone(),
        git_queue,
        handles.vlm_extractor.clone(),
        handles.repetition_guard.clone(),
        handles.skill_turn_runtime.clone(),
        // W24 seam (f): the shared crash-cascade sink attached to the root loop.
        handles.crash_cascade_sink.clone(),
        handles.evidence_ids.clone(),
        handles.tool_registry.clone(),
        handles.tools_grant_reader.clone(),
        handles.web_grant.clone(),
    )
    .await
    .map(|spawned| spawned.map(|inner| TestServeLoop { inner }))
}

/// Phase-2 Step-2 per-turn observer wired into the serving loop. Fired at the END
/// of every `serve` iteration (success OR handled error/trap) to coordinate the
/// daemon's `POST /msg` correlation: it `cancel`s the reply slot (a no-op when
/// dispatch already fulfilled it; otherwise it drops the pending sender so a
/// no-reply turn resolves the awaiting POST's rx to `Err` → 502 with no timeout
/// hang) and clears the single-in-flight guard so the next serial POST proceeds.
struct WatchTurnObserver {
    reply_registry: Arc<ReplyRegistry>,
    in_flight: Arc<AtomicBool>,
}

impl TurnObserver for WatchTurnObserver {
    fn on_turn_complete(&self, agent_id: &str) {
        // Order: cancel the (possibly already-fulfilled) reply slot FIRST, then
        // release in_flight. `cancel` is a no-op if dispatch's `fulfill` already
        // removed the slot (the happy/no-action turn — the produced reply is
        // already queued on the receiver). A pending slot (error/reject/trap turn
        // that never reached dispatch) has its sender dropped → the POST's
        // `rx.await` resolves `Err` → 502. Releasing in_flight last means a POST
        // woken by the resolved rx sees in_flight already clear.
        self.reply_registry.cancel(agent_id);
        self.in_flight.store(false, Ordering::Release);
    }
}

struct SkillTurnBoundary {
    runtime: Arc<cap_skills::SkillTurnRuntime>,
}

#[async_trait]
impl TurnPersistenceBoundary for SkillTurnBoundary {
    async fn begin_turn(&self, _agent_id: &str, _msg: &Message) -> Result<String, HookError> {
        self.runtime
            .begin_turn()
            .await
            .map_err(|e| HookError::Failure(e.to_string()))
    }

    async fn finish_turn(&self, _agent_id: &str, lease_id: &str) -> Result<(), HookError> {
        self.runtime
            .finish_turn(lease_id)
            .await
            .map_err(|e| HookError::Failure(e.to_string()))
    }

    async fn abort_turn(&self, _agent_id: &str, lease_id: &str, _reason: &str) {
        self.runtime.abort_turn(lease_id).await;
    }
}

/// Inbound `POST /msg` JSON body: `{ "agent_id"?: string, "payload": string }`.
/// `agent_id` defaults to the running loop's agent id when omitted; `payload`
/// is delivered to the guest as `list<u8>` (its UTF-8 bytes).
#[derive(Deserialize)]
struct MsgRequest {
    #[serde(default)]
    agent_id: Option<String>,
    payload: String,
}

/// Shared state for the `POST /msg` handler. `Clone` (axum requirement) is cheap
/// — every field is an `Arc` or a cheap `watch::Receiver` clone.
#[derive(Clone)]
struct MsgListenerState {
    store: Arc<MailboxStore>,
    execution_ingress: Option<Arc<ExecutionTurnIngress>>,
    default_agent_id: Arc<String>,
    counter: Arc<AtomicU64>,
    /// Reply correlation registry (shared with the dispatcher's `ReplyRouterSink`).
    reply_registry: Arc<ReplyRegistry>,
    /// `true` once the serving loop terminates (shutdown/abort/panic → POSTs 503).
    done: watch::Receiver<bool>,
    /// Single-in-flight guard: `true` while a turn is in flight. Set by the POST
    /// handler's CAS; cleared by the serving loop's `WatchTurnObserver` at the
    /// turn boundary (or by the deliver-error branch if the turn never started).
    /// The agent-id-keyed registry holds one slot per agent, so a concurrent 2nd
    /// POST would collide; it is rejected (409) until the in-flight turn finishes.
    in_flight: Arc<AtomicBool>,
}

/// Spawn the in-process HTTP `POST /msg` listener over `store`. Binds
/// `127.0.0.1:0` (OS-assigned port) and prints the bound address so operators
/// and tests can discover it. Returns the serve task's `JoinHandle` (aborted on
/// shutdown). This is the e2e-spine inbound seam; a configurable bind addr and
/// the dispatcher-routed `/hooks/*` channel path are Phase-2 (MODULE-016).
async fn spawn_msg_listener(
    store: Arc<MailboxStore>,
    execution_ingress: Option<Arc<ExecutionTurnIngress>>,
    agent_id: String,
    reply_registry: Arc<ReplyRegistry>,
    done: watch::Receiver<bool>,
    in_flight: Arc<AtomicBool>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let state = MsgListenerState {
        store,
        execution_ingress,
        default_agent_id: Arc::new(agent_id),
        counter: Arc::new(AtomicU64::new(0)),
        reply_registry,
        done,
        // Phase-2 Step-2: SHARED with the serving loop's `WatchTurnObserver`
        // (which clears it at each turn boundary) — was created here per-listener.
        in_flight,
    };
    // Cap the inbound body at the mailbox payload bound (1 MiB) so a grossly
    // oversized POST is rejected by axum BEFORE it is buffered + JSON-parsed +
    // copied into a `Message` (the mailbox's own `MAX_PAYLOAD_BYTES` check would
    // otherwise only reject it last, after the full-body work). Adversarial-R8 W2.
    let app = Router::new()
        .route("/msg", post(handle_msg))
        .layer(DefaultBodyLimit::max(MAX_PAYLOAD_BYTES))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to bind POST /msg listener: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("failed to read POST /msg listener address: {e}"))?;
    println!("advance: msg listener on http://{addr}/msg");
    Ok(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("advance: msg listener stopped: {e}");
        }
    }))
}

/// Map a resolved reply to an HTTP outcome: a produced reply → `200` + raw bytes;
/// a turn that produced no action → `202` (accepted, no reply).
fn map_reply(reply: Option<Vec<u8>>) -> (StatusCode, Vec<u8>) {
    match reply {
        Some(bytes) => (StatusCode::OK, bytes),
        None => (StatusCode::ACCEPTED, Vec::new()),
    }
}

/// Decode `{agent_id?, payload}`, deliver it into the shared `MailboxStore` to
/// wake the parked serving loop (`serve`), then await the turn's reply and return
/// the model's answer in the HTTP body. Phase-2 Step-1 reply delivery (design B);
/// Phase-2 Step-2 turn coordination (the `WatchTurnObserver` clears in-flight +
/// resolves no-reply turns at each turn boundary, so serial POSTs are served).
///
/// Outcomes: `200` + reply bytes; `202` (turn reached dispatch with no action);
/// `404` (target is not the loaded loop's agent); `503` (the serving loop has
/// terminated / the daemon is shutting down); `409` (a turn is already in-flight —
/// single-in-flight enforced); `502` (the turn produced no reply, e.g. a
/// validator-reject / guest trap that never reached dispatch); `504` (no reply
/// within `REPLY_TIMEOUT`); `503`/`400` (delivery backpressure / bad payload).
/// The handler never panics.
async fn handle_msg(
    State(state): State<MsgListenerState>,
    Json(req): Json<MsgRequest>,
) -> (StatusCode, Vec<u8>) {
    let target = req
        .agent_id
        .unwrap_or_else(|| (*state.default_agent_id).clone());

    // Single-agent daemon: only the loaded loop's agent is serviceable. Reject a
    // mismatching target immediately rather than deliver to a mailbox no loop
    // reads (which would otherwise hang to the timeout).
    if target != *state.default_agent_id {
        return (StatusCode::NOT_FOUND, Vec::new());
    }
    // The serving loop has terminated (shutdown / abort / panic) — no future turn
    // will fulfil a reply. Fail fast instead of hanging.
    if *state.done.borrow() {
        return (StatusCode::SERVICE_UNAVAILABLE, Vec::new());
    }
    // Enforce single in-flight POST (the registry is agent-id-keyed). CAS the
    // guard; a concurrent second POST is rejected with 409.
    if state
        .in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return (StatusCode::CONFLICT, Vec::new());
    }

    let n = state.counter.fetch_add(1, Ordering::Relaxed);
    // Register the reply slot BEFORE delivering, so the dispatcher's outbound
    // sink (fired during the turn) finds it.
    let mut rx = state.reply_registry.register(&target);

    if let Err(e) = deliver_to_store(
        &state.store,
        state.execution_ingress.as_deref(),
        &target,
        format!("msg-http-{n}-{}", uuid::Uuid::new_v4().simple()),
        req.payload.into_bytes(),
    ) {
        // The turn never started → release the in-flight guard + drop the slot.
        state.reply_registry.cancel(&target);
        state.in_flight.store(false, Ordering::Release);
        return match e {
            DeliverError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
            DeliverError::BadPayload => (StatusCode::BAD_REQUEST, Vec::new()),
        };
    }

    // The turn is now in flight. Phase-2 Step-2: `in_flight` is cleared by the
    // serving loop's `WatchTurnObserver` at the turn boundary (NOT by this
    // handler on any exit) — so an overrunning (>120s) turn keeps `in_flight`
    // set and a 2nd POST stays 409 (no mis-correlation) until the observer fires.
    //
    // The observer also `cancel`s the reply slot at the turn boundary, so a
    // no-reply turn (validator-reject / assemble-error / trap, which never
    // reached dispatch) resolves `rx` to `Err` here — no wait for the timeout.
    // `biased` + rx-first: dispatch's `fulfill` (synchronous, inside the awaited
    // dispatch) runs strictly BEFORE the observer's `cancel`, so a produced reply
    // is always observed via the `rx` arm — never lost to the `done` arm.
    let mut done = state.done.clone();
    enum Outcome {
        Reply(Result<Option<Vec<u8>>, tokio::sync::oneshot::error::RecvError>),
        DaemonGone,
        Timeout,
    }
    let outcome = tokio::select! {
        biased;
        r = &mut rx => Outcome::Reply(r),
        _ = done.wait_for(|&d| d) => Outcome::DaemonGone,
        _ = tokio::time::sleep(REPLY_TIMEOUT) => Outcome::Timeout,
    };
    match outcome {
        // Produced reply → 200 (Some) / 202 (None: a turn that reached dispatch
        // with an empty action batch). The j01 skeleton's no-action turn lands here.
        Outcome::Reply(Ok(reply)) => map_reply(reply),
        // The observer cancelled a pending slot → this was a no-reply turn
        // (validator-reject / assemble-error / trap that never reached dispatch).
        Outcome::Reply(Err(_)) => (StatusCode::BAD_GATEWAY, Vec::new()),
        // The serving loop terminated (shutdown / abort / panic) while we waited.
        // Honor a reply that landed in the same instant; else the daemon is going
        // away → 503. Cancel any still-pending slot so no sender leaks.
        Outcome::DaemonGone => match rx.try_recv() {
            Ok(reply) => map_reply(reply),
            Err(_) => {
                state.reply_registry.cancel(&target);
                (StatusCode::SERVICE_UNAVAILABLE, Vec::new())
            }
        },
        Outcome::Timeout => {
            state.reply_registry.cancel(&target);
            (StatusCode::GATEWAY_TIMEOUT, Vec::new())
        }
    }
}

/// Outcome of a failed [`deliver_to_store`], mapped to an HTTP status by the
/// handler.
#[derive(Debug)]
enum DeliverError {
    /// Transient/retryable capacity problem — mailbox registry full
    /// (`get_or_create`) or this mailbox's queue full (`deliver` →
    /// `MailboxFull`). Maps to HTTP 503.
    Unavailable,
    /// `Mailbox::deliver` rejected the message on a payload/header bound check
    /// (`InvalidPayload`). Maps to HTTP 400 (client error).
    BadPayload,
}

/// Build a `User` [`Message`] from `payload` and deliver it DIRECTLY into the
/// shared store for `target` — `Mailbox::deliver` → `notify_one` wakes the
/// loop's parked `recv`. This bypasses `MailboxDispatcherImpl::deliver`'s
/// `validate_routing` (which expects `agent:`-prefixed ids + a tree reader);
/// fine for the single-agent spine — dispatcher-routed inbound + the
/// `msg.received` event are a Phase-2 channel-system concern (MODULE-016).
///
/// Factored out of the HTTP handler so the delivery core is unit-testable
/// without the axum/TCP layer.
fn deliver_to_store(
    store: &Arc<MailboxStore>,
    execution_ingress: Option<&ExecutionTurnIngress>,
    target: &str,
    msg_id: String,
    payload: Vec<u8>,
) -> Result<(), DeliverError> {
    let msg = Message {
        id: msg_id,
        kind: MessageKind::User,
        from: "user:http".to_string(),
        to: target.to_string(),
        payload,
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    };
    let delivery = match execution_ingress {
        Some(ingress) => ingress.publish(msg),
        None => store
            .get_or_create(target)
            .and_then(|mailbox| mailbox.deliver(msg)),
    };
    delivery.map_err(|e| match e {
        // A full mailbox queue is transient/retryable → 503, not a 400.
        MsgError::MailboxFull => DeliverError::Unavailable,
        // payload/header/metadata bound checks (and anything else) → 400.
        _ => DeliverError::BadPayload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_agent_loop_store_reuses_provided_store() {
        let provided = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
        let selected = select_agent_loop_store(Some(provided.clone()));
        assert!(Arc::ptr_eq(&selected, &provided));
    }

    // Test 9 (in-isolation): the listener's delivery core puts a Message into
    // the shared store under the target id, and a subsequent `poll` retrieves it
    // — the plumbing the daemon's loop reads, without the HTTP/guest layers.
    #[tokio::test]
    async fn deliver_to_store_then_poll_returns_message() {
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
        deliver_to_store(
            &store,
            None,
            "default-agent",
            "m1".to_string(),
            b"hello".to_vec(),
        )
        .unwrap_or_else(|_| panic!("deliver should succeed"));
        let mb = store.get_or_create("default-agent").unwrap();
        let got = mb.poll().expect("a message was delivered");
        assert_eq!(got.payload, b"hello");
        assert_eq!(got.to, "default-agent");
        assert_eq!(got.from, "user:http");
        assert_eq!(got.kind, MessageKind::User);
    }

    // The exact wake mechanism the daemon relies on: deliver into the shared
    // store, then a parked `recv` returns that message (notify_one wakes it).
    #[tokio::test]
    async fn deliver_to_store_wakes_a_recv() {
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
        deliver_to_store(
            &store,
            None,
            "default-agent",
            "m1".to_string(),
            b"wake".to_vec(),
        )
        .unwrap();
        let mb = store.get_or_create("default-agent").unwrap();
        // The message is already queued, so recv resolves immediately.
        let got = mb.recv().await;
        assert_eq!(got.payload, b"wake");
    }

    // Test 7: the POST /msg ↔ reply correlation plumbing handle_msg relies on,
    // axum-free. register a reply slot → deliver to the store → simulate the
    // dispatcher fulfilling the slot → the awaited receiver resolves with the
    // reply; the message is also queued for the loop to consume.
    #[tokio::test]
    async fn register_deliver_fulfill_roundtrips_reply() {
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
        let reg = Arc::new(ReplyRegistry::new());
        let target = DEFAULT_MSG_AGENT_ID;

        let rx = reg.register(target);
        deliver_to_store(&store, None, target, "m1".to_string(), b"prompt".to_vec())
            .expect("deliver should succeed");
        // The loop would recv + dispatch; simulate the ReplyRouterSink fulfilling.
        reg.fulfill(target, Some(b"the reply".to_vec()));
        assert_eq!(rx.await.unwrap(), Some(b"the reply".to_vec()));

        // And the inbound message is queued under the messaging id for the loop.
        let mb = store.get_or_create(target).unwrap();
        assert_eq!(mb.poll().expect("queued").payload, b"prompt");
    }

    // Test 7 (error path): a deliver failure cancels the pending slot so no
    // sender is leaked (the awaited receiver resolves to Err).
    #[tokio::test]
    async fn deliver_error_cancels_pending_slot() {
        let reg = Arc::new(ReplyRegistry::new());
        let target = DEFAULT_MSG_AGENT_ID;
        let rx = reg.register(target);
        // Simulate the handler's deliver-error branch.
        reg.cancel(target);
        // A subsequent fulfill is a no-op; the receiver sees a dropped sender.
        reg.fulfill(target, Some(b"late".to_vec()));
        assert!(rx.await.is_err());
    }

    // Phase-2 Step-2 (T3): a no-reply turn — the observer cancels the still-pending
    // reply slot (→ the awaiting POST's rx resolves Err → 502) AND clears in_flight
    // so the next serial POST proceeds.
    #[tokio::test]
    async fn turn_observer_cancels_pending_slot_and_clears_in_flight() {
        let reply_registry = Arc::new(ReplyRegistry::new());
        let in_flight = Arc::new(AtomicBool::new(true));
        let observer = WatchTurnObserver {
            reply_registry: reply_registry.clone(),
            in_flight: in_flight.clone(),
        };
        let target = DEFAULT_MSG_AGENT_ID;
        let rx = reply_registry.register(target); // turn produced no reply yet
        observer.on_turn_complete(target);
        assert!(
            !in_flight.load(Ordering::Acquire),
            "in_flight must be released"
        );
        assert!(
            rx.await.is_err(),
            "a pending slot must be cancelled (sender dropped) → POST resolves Err → 502",
        );
    }

    // Phase-2 Step-2 (T3): a happy turn — dispatch fulfilled the slot BEFORE the
    // observer fires, so the observer's cancel is a no-op and the delivered reply
    // survives; in_flight is still cleared.
    #[tokio::test]
    async fn turn_observer_is_noop_on_already_fulfilled_slot() {
        let reply_registry = Arc::new(ReplyRegistry::new());
        let in_flight = Arc::new(AtomicBool::new(true));
        let observer = WatchTurnObserver {
            reply_registry: reply_registry.clone(),
            in_flight: in_flight.clone(),
        };
        let target = DEFAULT_MSG_AGENT_ID;
        let rx = reply_registry.register(target);
        reply_registry.fulfill(target, Some(b"the reply".to_vec())); // dispatch fulfilled
        observer.on_turn_complete(target); // cancel is a no-op (slot already removed)
        assert_eq!(
            rx.await.unwrap(),
            Some(b"the reply".to_vec()),
            "the already-delivered reply must survive the observer's no-op cancel",
        );
        assert!(
            !in_flight.load(Ordering::Acquire),
            "in_flight must be released"
        );
    }
}

#[cfg(unix)]
struct UnixSignalListeners {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

#[cfg(unix)]
fn install_unix_listeners() -> std::io::Result<UnixSignalListeners> {
    use tokio::signal::unix::{signal, SignalKind};
    Ok(UnixSignalListeners {
        sigint: signal(SignalKind::interrupt())?,
        sigterm: signal(SignalKind::terminate())?,
    })
}

#[cfg(unix)]
async fn park_until_shutdown_unix(mut listeners: UnixSignalListeners) {
    tokio::select! {
        _ = listeners.sigint.recv() => {}
        _ = listeners.sigterm.recv() => {}
    }
}

fn resolve_workspace(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(ws) = std::env::var_os("ADVANCE_WORKSPACE") {
        if !ws.is_empty() {
            return Ok(PathBuf::from(ws));
        }
    }
    std::env::current_dir().map_err(|e| format!("cannot resolve CWD as workspace: {e}"))
}

/// SAT-B (slice satB-postproc — #1 hazard fix / AC-44/45/46): build the live
/// agent-turn `PostProcessor`. Returns the components-backed
/// `PostProcessor::with_components(...)` ONLY when BOTH `memory_store` and
/// `llm_gateway` are present; otherwise the trace-only `PostProcessor::new()`
/// (which writes NO synthetic entries — the synthetic-entry guard). The
/// extractor is the cli `LlmBatchExtractor` over CONTRACT-081; the durable
/// `RusqliteSqliteIndex` is wired if it opens, else a logged degrade to the
/// in-memory index (the turn pipeline never fails on index-open). All
/// store/index/file writes are keyed by the BARE `write_agent_id` (the
/// colon-msg-id vs bare-cap-id write-bucket fix).
fn build_live_post_processor(
    memory_store: Option<&Arc<cap_memory::MemoryStore>>,
    llm_gateway: Option<&Arc<LlmGateway>>,
    workspace: &Path,
    event_bus_ss: Arc<dyn EventBusEmit + Send + Sync>,
    write_agent_id: &str,
    // SAT-C (slice satC-l6): the live git commit queue (CONTRACT-020). `Some`
    // ⇒ attach the production L6 construction (in-process Step-9 dispatch + real
    // git committer). `None` (no git workspace) ⇒ no L6 handler → Step-9 emits
    // `memory.l6_consolidation_due` only (non-regressive, pre-SAT-C behaviour).
    git_queue: Option<Arc<dyn advance_git::GitCommitQueue>>,
    // Stage-C MAINLINE harvest pass-3 (2026-06-19): when `Some` (llm declared), install the
    // `VlmDescriptionIndexer` (Step-3 VLM/LLM description indexing) into the live
    // post-processor. `None` → Step-3 stays the pre-pass-3 trace-only no-op.
    vlm: Option<Arc<dyn cap_llm::VlmExtractor>>,
    // Wave-9 Lane B: the live MODULE-005 agent-tree snapshot (Some iff `fs` declared),
    // threaded into the production L6 `StalenessProbe`'s MODULE-002 path resolver
    // (`build_l6_stale_resolver`). `None` ⇒ `EmptyAgentTree` fallback (conservative Stale).
    agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
) -> Arc<dyn PostProcessorHook> {
    let (Some(store), Some(gateway)) = (memory_store, llm_gateway) else {
        // Trace-only path (AC-44 synthetic-entry guard): an LLM-absent or
        // memory-absent config never installs the components-backed processor,
        // so no `StubBatchExtractor` / synthetic entries reach the live turn.
        return Arc::new(cap_memory::PostProcessor::new());
    };
    // Coerce the concrete gateway to the trait object: clone to a concrete
    // `Arc<LlmGateway>` first (so `Arc::clone`'s T is inferred as the concrete
    // type), THEN let the next binding do the Arc<Concrete>→Arc<dyn> unsize
    // coercion (a direct arg position / target-typed `Arc::clone` cannot).
    let gw_concrete = Arc::clone(gateway);
    let gw: Arc<dyn cap_llm::LlmGatewayInternal + Send + Sync> = gw_concrete;
    let extractor: Arc<dyn cap_memory::BatchExtractor + Send + Sync> =
        Arc::new(crate::memory_extractor::LlmBatchExtractor::new(gw, None));
    let reconciler = cap_memory::Reconciler::from_concrete(
        Arc::new(cap_memory::InMemorySimilarityIndex::new()),
        cap_memory::DEFAULT_THRESHOLD,
    );
    let cooldown = Arc::new(cap_memory::FailureCooldown::new(
        cap_memory::DEFAULT_COOLDOWN_SECS,
    ));
    let clock = Arc::new(cap_memory::SystemClock);
    let mem_root = workspace.join(".agent").join("memory");
    let mut components = cap_memory::Components::wired(
        extractor,
        reconciler,
        Arc::clone(store),
        cooldown,
        clock,
        event_bus_ss,
    )
    .with_fs_root(mem_root.clone())
    .with_write_agent_id(write_agent_id);
    // Durable 254 (AC-46): swap in the on-disk rusqlite index; degrade to the
    // in-memory default (+ log) if `open` fails — never fail the turn pipeline.
    match cap_memory::RusqliteSqliteIndex::open(mem_root.join("index.sqlite")) {
        Ok(idx) => {
            components = components.with_sqlite_index(Arc::new(idx));
        }
        Err(e) => {
            eprintln!(
                "advance start: durable memory index open failed ({e}); using the in-memory index"
            );
        }
    }
    // Stage-C MAINLINE harvest pass-3 (2026-06-19): install the VLM/LLM description
    // indexer (Step-3) when a VLM extractor is present (llm declared). Done BEFORE the L6
    // attach (which consumes `git_queue`). Mirrors the system-acceptance harness install
    // (`build_harness_live_post_processor` + `.with_vlm_indexer()`), so the harness e2e
    // witnesses reflect this production path.
    if let Some(vlm) = vlm {
        // Concrete-clone-then-unsize: `VlmDescriptionIndexer::new` wants a BARE
        // `Arc<dyn LlmGatewayInternal>` (not `+ Send + Sync`), so bind from a fresh
        // concrete clone of `gateway` rather than reusing the `+ Send + Sync` `gw` at :1162.
        let gw_vlm_concrete = Arc::clone(gateway);
        let gw_vlm: Arc<dyn cap_llm::LlmGatewayInternal> = gw_vlm_concrete;
        components = components.with_description_indexer(Arc::new(
            crate::vlm_indexer::VlmDescriptionIndexer::new(gw_vlm, vlm, workspace.to_path_buf()),
        ));
    }
    // SAT-C (slice satC-l6): when a live git queue is present, attach the L6
    // production construction (shares the live store/lease/l6_emitter/clock Arcs
    // + a rooted cursor store; real GitQueueL6Committer; in-process Step-9
    // dispatch). Absent ⇒ no L6 handler (Step-9 emits consolidation_due only).
    if let Some(gq) = git_queue {
        // slice wave6-laneB: build the real LlmL6Classifier and INJECT it into
        // attach_l6 (the system-acceptance harness injects StubL6Classifier). `gw`
        // above was moved into the extractor, so coerce a fresh gateway handle for
        // the classifier via the same concrete-clone-then-let unsize idiom (:1240).
        let gw_l6_concrete = Arc::clone(gateway);
        let gw_l6: Arc<dyn cap_llm::LlmGatewayInternal + Send + Sync> = gw_l6_concrete;
        let l6_classifier: Arc<dyn cap_memory::l6::L6Classifier + Send + Sync> =
            Arc::new(crate::l6_classifier::LlmL6Classifier::new(gw_l6, None));
        // Wave-9 Lane B: ALWAYS wire the real `ResolverStalenessProbe` on the production
        // L6 path (not gated on `agent_tree.is_some()` — the FileRef producer is llm-gated,
        // not fs-gated). `build_l6_stale_resolver` falls back to `EmptyAgentTree` when no fs
        // tree is present (conservative Stale). The harness keeps the empty stub via the
        // byte-identical `attach_l6` shim.
        components = crate::l6_wiring::attach_l6_with_stale_resolver(
            components,
            l6_classifier,
            gq,
            workspace.to_path_buf(),
            mem_root.clone(),
            Some(crate::l6_wiring::build_l6_stale_resolver(
                workspace.to_path_buf(),
                agent_tree,
            )),
        );
    }
    Arc::new(cap_memory::PostProcessor::with_components(components))
}

#[cfg(test)]
mod satb_gate_tests {
    use super::*;
    use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};

    fn fixture_msg() -> Message {
        Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:t".into(),
            to: "agent:default".into(),
            payload: vec![],
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }
    fn fixture_result() -> ActionResult {
        ActionResult {
            new_state: vec![],
            actions: vec![],
        }
    }
    fn bus() -> Arc<dyn EventBusEmit + Send + Sync> {
        Arc::new(cap_memory::NoopEventBus)
    }

    /// T53 (AC-44 synthetic-entry guard): an LLM-absent (or memory-absent)
    /// config keeps the trace-only `PostProcessor::new()` — running it over a
    /// store writes ZERO entries (no `StubBatchExtractor` on the live turn).
    /// The (Some, Some) → `with_components` branch is exercised live + by the
    /// cap-memory `integration_postproc_writeback` T54-T60 suite (which builds
    /// `Components::wired` directly; constructing a real `LlmGateway` is out of a
    /// cli unit test's reach).
    #[tokio::test]
    async fn t53_gate_trace_only_writes_zero_entries_when_llm_or_memory_absent() {
        let store = Arc::new(cap_memory::MemoryStore::new());
        let ws = std::env::temp_dir(); // unused on the trace-only path

        // (memory present, llm absent) → trace-only, no writes.
        let pp = build_live_post_processor(
            Some(&store),
            None,
            &ws,
            bus(),
            "default-agent",
            None,
            None,
            None,
        );
        pp.run("default-agent", &fixture_msg(), &fixture_result())
            .await
            .expect("run Ok");
        assert!(
            store.list("default-agent").is_empty(),
            "an LLM-absent config must write NO synthetic memory entries"
        );

        // (both absent) → trace-only, no writes.
        let pp2 =
            build_live_post_processor(None, None, &ws, bus(), "default-agent", None, None, None);
        pp2.run("default-agent", &fixture_msg(), &fixture_result())
            .await
            .expect("run Ok");
        assert!(store.list("default-agent").is_empty());
    }
}

#[cfg(test)]
mod skill_turn_boundary_pin {
    //! 2026-07-03 (MODULE-017 §3.6 (ccc) closure follow-up): pins the production
    //! `SkillTurnBoundary` adapter — the exact object the serving-loop builder
    //! installs via `with_turn_persistence_boundary` — as REALLY driving the
    //! `SkillTurnRuntime` lease lifecycle (begin → on-disk lease + active;
    //! finish → settled; abort → dropped). The runtime-construction half of the
    //! chain (`wire_capabilities` → `WiringHandles.skill_turn_runtime`) is
    //! pinned by `cli/tests/context_skill_reader.rs`; the remaining unpinned
    //! hop is the one-line install inside the daemon-boot-only serving-loop
    //! builder — disclosed in MODULE-017 §3.6.
    use super::*;
    use advance_git::{CommitRequest, GitCommitQueue, GitError};
    use advance_shared_types::event::Event;
    use advance_shared_types::mailbox::{Message, MessageKind};
    use git2::Oid;
    use tokio::sync::oneshot;

    struct OkCommitQueue;
    impl GitCommitQueue for OkCommitQueue {
        fn submit(&self, _req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Ok(Oid::zero()));
            rx
        }
    }

    struct NullBus;
    impl EventBusEmit for NullBus {
        fn emit(&self, _event: Event) {}
    }

    fn msg() -> Message {
        Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:t".into(),
            to: "agent:default".into(),
            payload: vec![],
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }

    fn lease_json_count(root: &std::path::Path) -> usize {
        let dir = root.join(".agent").join("_skill_turn_leases");
        match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .path()
                        .extension()
                        .and_then(|x| x.to_str())
                        == Some("json")
                })
                .count(),
            Err(_) => 0,
        }
    }

    #[tokio::test]
    async fn boundary_drives_real_skill_turn_runtime_lease_lifecycle() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Arc::new(
            cap_skills::persistence::DiskSkillStorage::with_default_writer(
                dir.path().to_path_buf(),
            ),
        );
        let shared = Arc::new(tokio::sync::Mutex::new(
            cap_skills::SkillStore::with_storage(storage),
        ));
        let coordinator = Arc::new(cap_skills::SkillPersistenceCoordinator::with_shared_store(
            "default-agent".to_string(),
            dir.path().to_path_buf(),
            Arc::clone(&shared),
            Arc::new(OkCommitQueue) as Arc<dyn GitCommitQueue>,
            Arc::new(NullBus) as Arc<dyn EventBusEmit>,
        ));
        let flusher: Arc<dyn cap_skills::RuntimePrivateFlush> =
            Arc::new(cap_skills::StoreDraftFlush::new(Arc::clone(&shared)));
        let driver =
            cap_skills::SkillTurnPersistenceDriver::new(Arc::clone(&shared), coordinator, flusher);
        let runtime = Arc::new(cap_skills::SkillTurnRuntime::new(
            "default-agent",
            dir.path().to_path_buf(),
            shared,
            driver,
            Arc::new(NullBus) as Arc<dyn EventBusEmit>,
            Arc::new(cap_skills::NoopSkillHealthFlush),
            dir.path().join(".agent").join("memory"),
        ));
        let boundary = SkillTurnBoundary {
            runtime: Arc::clone(&runtime),
        };

        // begin drives the runtime: on-disk lease exists + runtime is active.
        let lease = boundary
            .begin_turn("default-agent", &msg())
            .await
            .expect("begin_turn through the production boundary");
        assert!(runtime.is_active_for("default-agent").await);
        assert_eq!(lease_json_count(dir.path()), 1);

        // finish settles it (empty turn → journal removed, runtime idle).
        boundary
            .finish_turn("default-agent", &lease)
            .await
            .expect("finish_turn through the production boundary");
        assert!(!runtime.is_active_for("default-agent").await);
        assert_eq!(lease_json_count(dir.path()), 0);

        // abort drops a fresh lease.
        let lease = boundary
            .begin_turn("default-agent", &msg())
            .await
            .expect("second begin_turn");
        boundary.abort_turn("default-agent", &lease, "test").await;
        assert!(!runtime.is_active_for("default-agent").await);
        assert_eq!(lease_json_count(dir.path()), 0);
    }
}

#[cfg(test)]
mod tests_024 {
    //! MODULE-001-AC-20 (024) — deploy-component loader resolution (T-024a/T-024b):
    //! the production loader resolves the canonical materialized name and encodes a
    //! core module to a Component on the fly so a template-materialized child loads.
    use super::{is_core_module, resolve_driver_component_bytes};
    use advance_runtime::config::WasmConfig;
    use advance_runtime::ComponentRuntime;
    use wit_component::ComponentEncoder;

    /// Real committed wit-bindgen guest CORE module (the runtime fixture).
    const MINIMAL_CORE: &[u8] =
        include_bytes!("../../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");

    fn encoded_component() -> Vec<u8> {
        ComponentEncoder::default()
            .validate(true)
            .module(MINIMAL_CORE)
            .expect("encoder accepts the guest core module")
            .encode()
            .expect("encode to a Component")
    }

    fn wasm_cfg() -> WasmConfig {
        WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled: false,
        }
    }

    #[test]
    fn t024_is_core_module_discriminates_header() {
        assert!(
            is_core_module(MINIMAL_CORE),
            "real core module → version byte 0x01"
        );
        assert!(
            !is_core_module(&encoded_component()),
            "encoded Component → version byte 0x0d"
        );
        assert!(!is_core_module(b"\0as"), "too short → not core");
        assert!(
            !is_core_module(b"not a wasm module at all"),
            "no \\0asm magic → not core"
        );
    }

    #[test]
    fn t024a_loads_materialized_behavior_wasm_component() {
        // A template materializes an ENCODED Component to .agent/behavior.wasm (no
        // .component.wasm). The loader resolves the fallback name + load_component OK.
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = dir.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("behavior.wasm"), encoded_component()).unwrap();

        let (path, bytes) = resolve_driver_component_bytes(dir.path())
            .expect("resolve ok")
            .expect("a driver is present");
        assert!(
            path.ends_with("behavior.wasm"),
            "resolved the materialized fallback name"
        );
        assert_eq!(bytes[4], 0x0d, "resolved bytes are an encoded Component");
        ComponentRuntime::new(&wasm_cfg())
            .expect("runtime")
            .load_component(&bytes)
            .expect("materialized behavior.wasm loads");
    }

    #[test]
    fn t024b_core_module_behavior_wasm_is_encoded_then_loads() {
        // A RAW core module at .agent/behavior.wasm is encoded on the fly + loads.
        let dir = tempfile::tempdir().expect("tempdir");
        let agent = dir.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("behavior.wasm"), MINIMAL_CORE).unwrap();

        let (_, bytes) = resolve_driver_component_bytes(dir.path())
            .expect("resolve ok")
            .expect("a driver is present");
        assert_eq!(
            bytes[4], 0x0d,
            "core module encoded to a Component (version 0x0d)"
        );
        assert_ne!(
            bytes.as_slice(),
            MINIMAL_CORE,
            "encoded output differs from the core input"
        );
        ComponentRuntime::new(&wasm_cfg())
            .expect("runtime")
            .load_component(&bytes)
            .expect("encoded core module loads");
    }

    #[test]
    fn t024_prefers_component_wasm_and_parks_when_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            resolve_driver_component_bytes(dir.path())
                .expect("ok")
                .is_none(),
            "absent both artifacts → park (None)"
        );
        let agent = dir.path().join(".agent");
        std::fs::create_dir_all(&agent).unwrap();
        // .component.wasm is PREFERRED over behavior.wasm: a valid Component in the
        // former, a would-fail-to-encode core-header stub in the latter; the resolver
        // must pick the Component and never route the stub through the encoder.
        std::fs::write(agent.join("behavior.component.wasm"), encoded_component()).unwrap();
        std::fs::write(agent.join("behavior.wasm"), b"\0asm\x01\0\0\0").unwrap();
        let (path, bytes) = resolve_driver_component_bytes(dir.path())
            .expect("resolve ok")
            .expect("a driver is present");
        assert!(
            path.ends_with("behavior.component.wasm"),
            "preferred the .component.wasm name"
        );
        assert_eq!(
            bytes[4], 0x0d,
            "returned the encoded Component, not the core stub"
        );
    }
}
