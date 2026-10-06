//! The composition's ordered teardown.
//!
//! [`Composition`] owns everything the daemon composition started and stops all of
//! it in one order, on a requested shutdown and after a startup failure alike:
//!
//! 1. **ingress** — the Client API, the `POST /msg` listener and the channel
//!    `/hooks` listener stop accepting and drain their requests, concurrently, each
//!    within its budget;
//! 2. **loops** — the root serve loop, the channel host pump, the per-child loops,
//!    the MCP client (stdio process groups), the auto tick loop and the readiness
//!    walk stop; then every live LLM stream is settled and the stream reaper stopped.
//!    A requested shutdown then prints `advance: shutting down`;
//! 3. **extension hooks** — each extension's shutdown hook, in reverse registration
//!    order, each bounded and isolated from the others' panics; then the composition
//!    lets go of the extensions;
//! 4. **holds**, in dependency order — the selected-provider writer, the config
//!    watcher and its WAL-mode observer, the packs poll, the cap-grant sweeper, the
//!    breaker subscriber, the ChatGPT sign-in (a renewal already started is awaited,
//!    never cut off), the git commit queue (closed and its worker joined while the
//!    EventBus still records its commits), the Client API provider slots and adapter
//!    threads, the EventBus; then the rest of the graph is dropped on the blocking
//!    pool (that drop joins the CONTRACT-218 custody threads and the epoch ticker);
//! 5. **the instance guard** — the runtime lock is released last.
//!
//! Each step runs only for the parts that exist, so a composition that failed
//! part-way stops exactly what it started. Nothing in the sequence fails: a bound
//! that elapses is reported on stderr and the sequence goes on (except the config
//! watcher's release of its OS watcher, which then finishes on its own thread, holding
//! nothing the rest of the sequence needs), and a startup-failure teardown prints
//! nothing else.

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_client_api::{ClientApi, ClientApiServer, ShutdownIngress};
use advance_runtime::config::RuntimeConfigWatcher;
use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::RuntimeHost;
use futures::FutureExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::api::{
    log_keys, BoxFuture, ClientApiEndpoint, ComposeExtension, InstanceGuardKind, RuntimePhase,
};
use crate::client_api_adapters::WorkerControl;
use crate::compose_log::LogHandle;
use crate::daemon::{ComposedGraph, Listener};
use crate::registry::HomeReservation;
use crate::runnable_walk::ContinuousReadinessWalk;
use crate::wiring::{HoldStoppers, WiringHandles};

/// Budget of the Client API's drain: its serve task, its upgraded WebSockets and its
/// in-flight dispatches share one deadline.
const CLIENT_API_DRAIN: Duration = Duration::from_secs(10);
/// Budget of the `POST /msg` and `/hooks` listeners' drains.
const LISTENER_DRAIN: Duration = Duration::from_secs(5);
/// Budget of one extension's shutdown hook; past it the hook is abandoned.
const EXTENSION_SHUTDOWN_BOUND: Duration = Duration::from_secs(5);
/// Budget of a thread join: the Client API adapter threads (one shared deadline; a thread
/// still running past it is reported), the config watcher's OS-watcher release (never
/// reported), the WAL-mode observer.
const THREAD_JOIN_BOUND: Duration = Duration::from_secs(2);
/// After this long, a ChatGPT token renewal still finishing is reported; the teardown
/// keeps waiting for it (a renewal may already have rotated the refresh token, which
/// must be persisted).
const SIGN_IN_REPORT_AFTER: Duration = Duration::from_secs(3);
/// How often the waits on threads poll.
const POLL: Duration = Duration::from_millis(10);

/// Why a composition is torn down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TeardownReason {
    /// A requested shutdown: prints `advance: shutting down` once the loops stopped.
    Requested,
    /// The composition failed to start: prints nothing.
    StartupFailed,
}

/// The teardown steps, in order. A step runs (and is recorded) only when its part
/// exists.
pub const TEARDOWN_ORDER: &[&str] = &[
    "ingress.client_api",
    "ingress.post_msg",
    "ingress.hooks",
    "loops.root",
    "loops.host_pump",
    "loops.perchild",
    "loops.mcp",
    "loops.auto_tick",
    "loops.readiness_walk",
    "loops.llm_stream_reaper",
    "extensions.hooks",
    "extensions.tasks",
    "holds.selected_provider",
    "holds.watchers",
    "holds.packs_poll",
    "holds.cap_grant_sweeper",
    "holds.breaker",
    "holds.chatgpt_sign_in",
    "holds.git_queue",
    "holds.client_api_slots",
    "holds.event_bus",
    "holds.extension_holds",
    "holds.drop_graph",
    "guard",
];

/// Where the teardown records the steps it ran: in test-support builds, the
/// composition's probe (each step with tokio's `num_alive_tasks` right after it).
#[derive(Default)]
pub(crate) struct StepLog {
    #[cfg(feature = "test-support")]
    probe: Option<Arc<crate::test_support::ComposeProbe>>,
}

impl StepLog {
    pub(crate) fn record(&self, step: &'static str) {
        debug_assert!(
            TEARDOWN_ORDER.contains(&step),
            "unknown teardown step {step}"
        );
        probe_record!(self.probe, |record| record
            .teardown_steps
            .push((step, alive_tasks())));
    }
}

/// The tasks alive on the current tokio runtime.
#[cfg(feature = "test-support")]
fn alive_tasks() -> usize {
    tokio::runtime::Handle::try_current()
        .map(|handle| handle.metrics().num_alive_tasks())
        .unwrap_or(0)
}

/// The instance guard a composition holds until the end of its teardown: the home's
/// process-local reservation and, under the pid-lock guard, the runtime lock.
pub(crate) struct GuardHold {
    reservation: HomeReservation,
    lock: Option<RuntimeLock>,
}

impl GuardHold {
    pub(crate) fn new(reservation: HomeReservation, lock: Option<RuntimeLock>) -> Self {
        Self { reservation, lock }
    }

    pub(crate) fn kind(&self) -> InstanceGuardKind {
        match self.lock {
            Some(_) => InstanceGuardKind::PidLockFile,
            None => InstanceGuardKind::ProcessLocal,
        }
    }

    /// Release the guard: the runtime lock's heartbeat is joined, then its file removed;
    /// then the home's reservation is released.
    pub(crate) async fn release(self) {
        let GuardHold { reservation, lock } = self;
        if let Some(lock) = lock {
            lock.release().await;
        }
        drop(reservation);
    }
}

/// What a composed runtime reports about itself (read through
/// [`ComposedRuntime`](crate::api::ComposedRuntime)). It holds the Client API only
/// weakly and the root loop's end-of-life signal, never a part of the graph.
pub(crate) struct RuntimeView {
    phase: Mutex<RuntimePhase>,
    root_agent_id: String,
    client_api: Option<ClientApiEndpoint>,
    /// `true` once the root serve loop has ended; `None` without a deployed driver.
    agent_loop_done: Option<watch::Receiver<bool>>,
    instance_guard: InstanceGuardKind,
}

impl RuntimeView {
    pub(crate) fn new(
        root_agent_id: String,
        client_api: Option<ClientApiEndpoint>,
        agent_loop_done: Option<watch::Receiver<bool>>,
        instance_guard: InstanceGuardKind,
    ) -> Self {
        Self {
            phase: Mutex::new(RuntimePhase::Running),
            root_agent_id,
            client_api,
            agent_loop_done,
            instance_guard,
        }
    }

    pub(crate) fn phase(&self) -> RuntimePhase {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_phase(&self, phase: RuntimePhase) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = phase;
    }

    pub(crate) fn root_agent_id(&self) -> &str {
        &self.root_agent_id
    }

    pub(crate) fn client_api(&self) -> Option<&ClientApiEndpoint> {
        self.client_api.as_ref()
    }

    /// Whether the root serve loop is still running.
    pub(crate) fn agent_loop_alive(&self) -> bool {
        self.agent_loop_done
            .as_ref()
            .is_some_and(|done| !*done.borrow())
    }

    pub(crate) fn instance_guard(&self) -> InstanceGuardKind {
        self.instance_guard
    }
}

/// The config watcher as the teardown stops it.
trait StopConfigWatcher: Send + Sync {
    /// Stop watching: everything at once but the release of the OS watcher, which the
    /// returned future waits for last.
    fn stop(&self) -> BoxFuture<'_, ()>;
}

impl StopConfigWatcher for RuntimeConfigWatcher {
    fn stop(&self) -> BoxFuture<'_, ()> {
        Box::pin(RuntimeConfigWatcher::stop(self))
    }
}

/// Everything a daemon composition started, and its one teardown.
pub(crate) struct Composition {
    log: LogHandle,
    steps: StepLog,
    /// The state a composed runtime reports (none for a composition that failed to start).
    view: Option<Arc<RuntimeView>>,
    // Step 1: ingress.
    client_api_server: Option<ClientApiServer>,
    msg_listener: Option<Listener>,
    hooks: Option<(CancellationToken, JoinHandle<()>)>,
    // Step 2: loops (the per-child manager and the stream reaper are in `stoppers`).
    root_loop: Option<JoinHandle<()>>,
    host_pump: Option<JoinHandle<()>>,
    auto_tick: Option<(CancellationToken, JoinHandle<()>)>,
    readiness_walk: Option<ContinuousReadinessWalk>,
    // Step 3: the extensions, in registration order, and the tasks started for them.
    extensions: Vec<Arc<dyn ComposeExtension>>,
    extension_tasks: TaskTracker,
    // Step 4: holds.
    selected_provider_task: Option<JoinHandle<()>>,
    config_watcher: Option<Arc<dyn StopConfigWatcher>>,
    wal_observer: Option<JoinHandle<()>>,
    stoppers: HoldStoppers,
    /// What the extensions hold that must outlive the graph's holds but not the
    /// composition.
    extension_holds: Vec<Box<dyn std::any::Any + Send + Sync>>,
    /// Everything else, dropped last (on the blocking pool).
    graph_rest: Option<(RuntimeHost, WiringHandles)>,
    // Step 5.
    guard: Option<GuardHold>,
}

impl Composition {
    /// A composed (or partly composed) graph: the stoppable items are taken out of
    /// the wiring handles, the rest is kept whole to be dropped last.
    pub(crate) fn from_graph(
        graph: ComposedGraph,
        config_watcher: Arc<RuntimeConfigWatcher>,
        wal_observer: Option<JoinHandle<()>>,
        guard: GuardHold,
        log: LogHandle,
    ) -> Self {
        let ComposedGraph {
            host,
            mut wiring_handles,
            selected_provider_task,
            agent_loop,
            msg_listener,
            auto_tick,
            readiness_walk,
        } = graph;
        let stoppers = HoldStoppers {
            event_bus: Some(Arc::clone(&wiring_handles.event_bus)),
            cap_grant_sweeper_handle: wiring_handles.cap_grant.sweeper_handle.take(),
            cap_grant_sweeper_arc: wiring_handles.cap_grant.sweeper.take(),
            perchild_manager: wiring_handles.perchild_manager.take(),
            git_queue: wiring_handles.git_queue.take(),
            chatgpt_sign_in: wiring_handles.chatgpt_sign_in.take(),
            packs_watcher: wiring_handles.packs_watcher.take(),
            breaker_subscriber: wiring_handles.breaker_subscriber.take(),
            llm_stream_reaper: wiring_handles.llm_stream_reaper.take(),
            adapter_workers: std::mem::take(&mut wiring_handles.adapter_workers),
            mcp: wiring_handles.mcp.take(),
        };
        let client_api_server = wiring_handles.client_api_server.take();
        let (root_loop, hooks, host_pump) = match agent_loop {
            Some(spawned) => (Some(spawned.handle), spawned.hooks, spawned.host_pump),
            None => (None, None, None),
        };
        Self {
            log,
            steps: StepLog::default(),
            view: None,
            client_api_server,
            msg_listener,
            hooks,
            root_loop,
            host_pump,
            auto_tick,
            readiness_walk,
            extensions: Vec::new(),
            extension_tasks: TaskTracker::new(),
            selected_provider_task,
            config_watcher: Some(config_watcher),
            wal_observer,
            stoppers,
            extension_holds: Vec::new(),
            graph_rest: Some((host, wiring_handles)),
            guard: Some(guard),
        }
    }

    /// What a failed capability wiring had started.
    pub(crate) fn from_stoppers(
        stoppers: HoldStoppers,
        config_watcher: Option<Arc<RuntimeConfigWatcher>>,
        wal_observer: Option<JoinHandle<()>>,
        guard: Option<GuardHold>,
        log: LogHandle,
    ) -> Self {
        Self {
            log,
            steps: StepLog::default(),
            view: None,
            client_api_server: None,
            msg_listener: None,
            hooks: None,
            root_loop: None,
            host_pump: None,
            auto_tick: None,
            readiness_walk: None,
            extensions: Vec::new(),
            extension_tasks: TaskTracker::new(),
            selected_provider_task: None,
            config_watcher: config_watcher.map(|watcher| watcher as Arc<dyn StopConfigWatcher>),
            wal_observer,
            stoppers,
            extension_holds: Vec::new(),
            graph_rest: None,
            guard,
        }
    }

    /// What a composition refused right after the runtime host builder was made: the
    /// config watcher, its WAL-mode observer and the instance guard.
    pub(crate) fn early(
        config_watcher: Arc<RuntimeConfigWatcher>,
        wal_observer: Option<JoinHandle<()>>,
        guard: GuardHold,
        log: LogHandle,
    ) -> Self {
        Self::from_stoppers(
            HoldStoppers::default(),
            Some(config_watcher),
            wal_observer,
            Some(guard),
            log,
        )
    }

    /// The extensions composed with the runtime (their shutdown hooks run in step 3).
    pub(crate) fn with_extensions(mut self, extensions: Vec<Arc<dyn ComposeExtension>>) -> Self {
        self.extensions = extensions;
        self
    }

    /// The view the composed runtime reports through; the teardown moves its phase.
    pub(crate) fn with_view(mut self, view: Arc<RuntimeView>) -> Self {
        self.view = Some(view);
        self
    }

    /// Record every teardown step into `probe`.
    #[cfg(feature = "test-support")]
    pub(crate) fn with_probe(
        mut self,
        probe: Option<Arc<crate::test_support::ComposeProbe>>,
    ) -> Self {
        self.steps.probe = probe;
        self
    }

    /// Stop everything, in order (see the module documentation).
    pub(crate) async fn teardown(mut self, reason: TeardownReason) {
        let log = self.log.clone();
        if let Some(view) = self.view.as_ref() {
            view.set_phase(RuntimePhase::ShuttingDown);
        }

        // ── Step 1: ingress, the three drains concurrently. ──────────────────────
        let client_api_server = self.client_api_server.take();
        let msg_listener = self.msg_listener.take();
        let hooks = self.hooks.take();
        let (client_api, msg_overran, hooks_overran) = tokio::join!(
            async {
                match client_api_server {
                    Some(server) => Some(server.shutdown_ingress(CLIENT_API_DRAIN).await),
                    None => None,
                }
            },
            async {
                match msg_listener {
                    Some(listener) => {
                        Some(drain_listener(listener.shutdown, listener.task, LISTENER_DRAIN).await)
                    }
                    None => None,
                }
            },
            async {
                match hooks {
                    Some((shutdown, task)) => {
                        Some(drain_listener(shutdown, task, LISTENER_DRAIN).await)
                    }
                    None => None,
                }
            },
        );
        let client_api = client_api.map(|ingress| {
            report_client_api_ingress(&ingress, &log);
            self.steps.record("ingress.client_api");
            ingress.api
        });
        if let Some(overran) = msg_overran {
            if overran {
                log.err(
                    log_keys::COMPOSE_MSG_LISTENER_DRAIN_OVERRUN,
                    format!(
                        "advance: WARN POST /msg requests still running after {}s; listener stopped",
                        LISTENER_DRAIN.as_secs()
                    ),
                );
            }
            self.steps.record("ingress.post_msg");
        }
        if let Some(overran) = hooks_overran {
            if overran {
                log.err(
                    log_keys::COMPOSE_HOOKS_DRAIN_OVERRUN,
                    format!(
                        "advance: WARN /hooks requests still running after {}s; listener stopped",
                        LISTENER_DRAIN.as_secs()
                    ),
                );
            }
            self.steps.record("ingress.hooks");
        }

        // ── Step 2: loops. ────────────────────────────────────────────────────────
        if let Some(task) = self.root_loop.take() {
            abort_and_join(task).await;
            self.steps.record("loops.root");
        }
        if let Some(task) = self.host_pump.take() {
            abort_and_join(task).await;
            self.steps.record("loops.host_pump");
        }
        if let Some(manager) = self.stoppers.perchild_manager.as_ref() {
            manager.shutdown().await;
            self.steps.record("loops.perchild");
        }
        if let Some(mcp) = self.stoppers.mcp.take() {
            // A stdio server leads its own process group and would otherwise outlive
            // this process. Drop of the last handle does the same; doing it here keeps
            // those groups from outliving the loops.
            mcp.shutdown();
            self.steps.record("loops.mcp");
        }
        if let Some((cancel, task)) = self.auto_tick.take() {
            cancel.cancel();
            abort_and_join(task).await;
            self.steps.record("loops.auto_tick");
        }
        if let Some(walk) = self.readiness_walk.take() {
            walk.shutdown().await;
            self.steps.record("loops.readiness_walk");
        }
        if let Some(reaper) = self.stoppers.llm_stream_reaper.as_ref() {
            // A turn the loops' stop cut short never reaches its own turn-end reap.
            // The settlement does I/O (the run budget's commits): off the runtime threads.
            let settling = Arc::clone(reaper);
            let _ = tokio::task::spawn_blocking(move || settling.reap_all()).await;
            reaper.stop().await;
            self.steps.record("loops.llm_stream_reaper");
        }
        if reason == TeardownReason::Requested {
            log.out(log_keys::SHUTTING_DOWN, "advance: shutting down");
        }

        // ── Step 3: extension hooks. ─────────────────────────────────────────────
        let extensions = std::mem::take(&mut self.extensions);
        if !extensions.is_empty() {
            run_extension_shutdown_hooks(&extensions, &log).await;
            self.steps.record("extensions.hooks");
        }
        if !self.extension_tasks.is_empty() {
            self.extension_tasks.close();
            self.extension_tasks.wait().await;
            self.steps.record("extensions.tasks");
        }
        // The composition lets go of its extensions here: nothing of theirs is dropped
        // after the holds or the instance guard.
        drop(extensions);

        // ── Step 4: holds, in dependency order. ───────────────────────────────────
        if let Some(task) = self.selected_provider_task.take() {
            abort_and_join(task).await;
            self.steps.record("holds.selected_provider");
        }
        if self.config_watcher.is_some() || self.wal_observer.is_some() {
            if let Some(watcher) = self.config_watcher.take() {
                // Everything but the OS watcher's release happens at once: no reload is
                // applied any more, the poll and bridge tasks are stopped and every
                // subscriber channel is closed. The release (on macOS it waits for the
                // FSEvents run loop, which can take seconds) gets a bound; past it the
                // release finishes on its own thread. It holds nothing the rest of the
                // sequence needs, so going on without it is not reported.
                let _ = tokio::time::timeout(THREAD_JOIN_BOUND, watcher.stop()).await;
            }
            if let Some(mut observer) = self.wal_observer.take() {
                // It ends once the watcher closed its subscriber channels.
                if tokio::time::timeout(THREAD_JOIN_BOUND, &mut observer)
                    .await
                    .is_err()
                {
                    abort_and_join(observer).await;
                }
            }
            self.steps.record("holds.watchers");
        }
        if let Some(task) = self.stoppers.packs_watcher.take() {
            abort_and_join(task).await;
            self.steps.record("holds.packs_poll");
        }
        let sweeper_arc = self.stoppers.cap_grant_sweeper_arc.take();
        let sweeper_task = self.stoppers.cap_grant_sweeper_handle.take();
        if sweeper_arc.is_some() || sweeper_task.is_some() {
            // The task holds only a `Weak` of the sweeper.
            drop(sweeper_arc);
            if let Some(task) = sweeper_task {
                abort_and_join(task).await;
            }
            self.steps.record("holds.cap_grant_sweeper");
        }
        if let Some(breaker) = self.stoppers.breaker_subscriber.take() {
            breaker.shutdown().await;
            self.steps.record("holds.breaker");
        }
        if let Some(sign_in) = self.stoppers.chatgpt_sign_in.as_ref() {
            close_sign_in(sign_in, &log).await;
            self.steps.record("holds.chatgpt_sign_in");
        }
        if let Some(queue) = self.stoppers.git_queue.as_ref() {
            // The worker commits what is queued, then exits; only then is the repo's
            // queue registration released.
            queue.close_and_join().await;
            self.steps.record("holds.git_queue");
        }
        let adapter_workers = std::mem::take(&mut self.stoppers.adapter_workers);
        if client_api.is_some() || !adapter_workers.is_empty() {
            if let Some(api) = client_api {
                clear_client_api(api);
            }
            close_adapter_workers(&adapter_workers, &log).await;
            self.steps.record("holds.client_api_slots");
        }
        if let Some(bus) = self.stoppers.event_bus.as_ref() {
            bus.shutdown_shared().await;
            self.steps.record("holds.event_bus");
        }
        let extension_holds = std::mem::take(&mut self.extension_holds);
        if !extension_holds.is_empty() {
            drop(extension_holds);
            self.steps.record("holds.extension_holds");
        }
        let rest = (self.graph_rest.take(), std::mem::take(&mut self.stoppers));
        if rest.0.is_some() || !rest.1.is_empty() {
            // The last references go here: the EventBus pipeline and its observation
            // projector (with the CONTRACT-218 custody, whose drop joins its threads),
            // the component runtime (whose drop joins the epoch ticker). Those joins end
            // promptly once signalled, but they block: off the runtime threads.
            let _ = tokio::task::spawn_blocking(move || drop(rest)).await;
            self.steps.record("holds.drop_graph");
        }

        // ── Step 5: the instance guard, last. ─────────────────────────────────────
        if let Some(guard) = self.guard.take() {
            guard.release().await;
            self.steps.record("guard");
        }
        if let Some(view) = self.view.as_ref() {
            view.set_phase(RuntimePhase::Stopped);
        }
    }
}

impl HoldStoppers {
    /// Whether nothing is held.
    fn is_empty(&self) -> bool {
        let HoldStoppers {
            event_bus,
            cap_grant_sweeper_handle,
            cap_grant_sweeper_arc,
            perchild_manager,
            git_queue,
            chatgpt_sign_in,
            packs_watcher,
            breaker_subscriber,
            llm_stream_reaper,
            adapter_workers,
            mcp,
        } = self;
        event_bus.is_none()
            && cap_grant_sweeper_handle.is_none()
            && cap_grant_sweeper_arc.is_none()
            && perchild_manager.is_none()
            && git_queue.is_none()
            && chatgpt_sign_in.is_none()
            && packs_watcher.is_none()
            && breaker_subscriber.is_none()
            && llm_stream_reaper.is_none()
            && adapter_workers.is_empty()
            && mcp.is_none()
    }

    /// Stop what a failed wiring had started (no ingress and no loop exist yet): the
    /// same steps, in the same order, as the composition's teardown.
    pub(crate) async fn teardown_standalone(self, log: &LogHandle) {
        Composition::from_stoppers(self, None, None, None, log.clone())
            .teardown(TeardownReason::StartupFailed)
            .await;
    }
}

/// Run every extension's shutdown hook, in reverse registration order. Each hook gets
/// [`EXTENSION_SHUTDOWN_BOUND`]; one that has not finished by then is abandoned (its
/// future dropped) and reported. A hook that panics, while its future is built or
/// polled, is reported; the remaining hooks still run.
async fn run_extension_shutdown_hooks(extensions: &[Arc<dyn ComposeExtension>], log: &LogHandle) {
    for extension in extensions.iter().rev() {
        let id = extension.id();
        // `Ok(true)`: the hook finished; `Ok(false)`: it panicked; `Err`: it overran.
        let finished = match std::panic::catch_unwind(AssertUnwindSafe(|| extension.shutdown())) {
            Ok(hook) => tokio::time::timeout(
                EXTENSION_SHUTDOWN_BOUND,
                AssertUnwindSafe(hook).catch_unwind(),
            )
            .await
            .map(|outcome| outcome.is_ok()),
            Err(_panic) => Ok(false),
        };
        match finished {
            Ok(true) => {}
            Ok(false) => log.err(
                log_keys::EXT_SHUTDOWN_PANICKED,
                format!("advance: WARN extension {id} shutdown hook panicked; continuing"),
            ),
            Err(_elapsed) => log.err(
                log_keys::EXT_SHUTDOWN_ABANDONED,
                format!(
                    "advance: WARN extension {id} shutdown hook did not finish within {}s; abandoned",
                    EXTENSION_SHUTDOWN_BOUND.as_secs()
                ),
            ),
        }
    }
}

/// Stop a listener gracefully: it stops accepting, and its in-flight requests get
/// `budget` to finish; past it the listener is aborted. Returns whether it overran.
async fn drain_listener(
    shutdown: CancellationToken,
    mut task: JoinHandle<()>,
    budget: Duration,
) -> bool {
    shutdown.cancel();
    match tokio::time::timeout(budget, &mut task).await {
        Ok(_) => false,
        Err(_) => {
            abort_and_join(task).await;
            true
        }
    }
}

/// Abort `task` and wait until it has ended.
async fn abort_and_join(task: JoinHandle<()>) {
    task.abort();
    let _ = task.await;
}

/// Report what the Client API's drain observed beyond a clean stop.
fn report_client_api_ingress(ingress: &ShutdownIngress, log: &LogHandle) {
    if ingress.serve_overran || !ingress.ws_joined || !ingress.drained {
        log.err(
            log_keys::COMPOSE_CLIENT_API_DRAIN_OVERRUN,
            format!(
                "advance: WARN client API requests still running after {}s; listener stopped",
                CLIENT_API_DRAIN.as_secs()
            ),
        );
    }
    if let Err(e) = &ingress.serve {
        log.err(
            log_keys::COMPOSE_CLIENT_API_SERVE_FAILED,
            format!("advance: WARN client API listener stopped: {e}"),
        );
    }
}

/// Empty every provider slot of the Client API (each family answers
/// `module_unavailable` from now on) and let go of it.
fn clear_client_api(api: Arc<ClientApi>) {
    api.clear_providers();
    drop(api);
}

/// Close the sign-in, then wait until its threads have exited and no renewal is
/// running. A renewal already started is never cut off: it finishes (or its request
/// times out) and persists what it rotated; a wait past [`SIGN_IN_REPORT_AFTER`] is
/// reported once.
async fn close_sign_in(sign_in: &advance_home::ChatGptSignIn, log: &LogHandle) {
    sign_in.close();
    let started = Instant::now();
    let mut reported = false;
    while !sign_in.threads_exited() {
        if !reported && started.elapsed() >= SIGN_IN_REPORT_AFTER {
            log.err(
                log_keys::COMPOSE_SIGN_IN_OVERRUN,
                format!(
                    "advance: WARN ChatGPT sign-in still finishing a token renewal after {}s; \
                     waiting for it",
                    SIGN_IN_REPORT_AFTER.as_secs()
                ),
            );
            reported = true;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Close every adapter worker's queue, then wait (polled, one shared deadline) until
/// each thread has exited; a thread still running at the deadline is reported and left
/// to finish on its own.
async fn close_adapter_workers(workers: &[Arc<dyn WorkerControl>], log: &LogHandle) {
    for worker in workers {
        worker.close();
    }
    let deadline = Instant::now() + THREAD_JOIN_BOUND;
    loop {
        let running: Vec<&Arc<dyn WorkerControl>> =
            workers.iter().filter(|worker| !worker.try_join()).collect();
        if running.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            for worker in running {
                report_thread_overrun(worker.name(), log);
            }
            return;
        }
        tokio::time::sleep(POLL).await;
    }
}

fn report_thread_overrun(name: &str, log: &LogHandle) {
    log.err(
        log_keys::COMPOSE_THREAD_JOIN_OVERRUN,
        format!(
            "advance: WARN {name} thread still running after {}s; detached",
            THREAD_JOIN_BOUND.as_secs()
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ComposeLog, ComposeLogLine, LogStream};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct Recording(Mutex<Vec<ComposeLogLine>>);

    impl ComposeLog for Recording {
        fn line(&self, line: &ComposeLogLine) {
            self.0.lock().unwrap().push(line.clone());
        }

        fn ready(&self, line: &ComposeLogLine) -> std::io::Result<()> {
            self.line(line);
            Ok(())
        }
    }

    impl Recording {
        fn keys(&self) -> Vec<&'static str> {
            self.0.lock().unwrap().iter().map(|l| l.key).collect()
        }
    }

    #[test]
    fn module_001_ac30_teardown_steps_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for step in TEARDOWN_ORDER {
            assert!(seen.insert(*step), "{step} is listed twice");
        }
        assert_eq!(TEARDOWN_ORDER.last(), Some(&"guard"), "the guard goes last");
    }

    /// The shutdown line is printed on a requested shutdown only; a startup failure's
    /// teardown prints nothing; and the instance guard is released (the lock file is gone).
    #[tokio::test]
    async fn module_001_ac30_teardown_prints_only_the_shutdown_line_and_releases_the_guard() {
        for (reason, expected) in [
            (TeardownReason::Requested, vec![log_keys::SHUTTING_DOWN]),
            (TeardownReason::StartupFailed, vec![]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let home = std::fs::canonicalize(dir.path()).unwrap();
            let lock = RuntimeLock::acquire(&home, Duration::from_secs(30))
                .await
                .expect("lock");
            let lock_path = lock.path().to_path_buf();
            assert!(lock_path.exists());
            let reservation = HomeReservation::acquire(home.clone()).expect("reserve");
            let guard = GuardHold::new(reservation, Some(lock));
            assert_eq!(guard.kind(), InstanceGuardKind::PidLockFile);
            let sink = Arc::new(Recording::default());
            Composition::from_stoppers(
                HoldStoppers::default(),
                None,
                None,
                Some(guard),
                LogHandle::new(sink.clone()),
            )
            .teardown(reason)
            .await;
            assert_eq!(sink.keys(), expected, "{reason:?}");
            assert!(!lock_path.exists(), "{reason:?}: the guard is released");
            assert!(
                !crate::registry::reserved_homes_for_test().contains(&home),
                "{reason:?}: the reservation is released with the guard"
            );
        }
    }

    /// A process-local guard is the reservation alone; the teardown moves a composed
    /// runtime's view through `ShuttingDown` to `Stopped`.
    #[tokio::test]
    async fn module_001_ac30_process_local_guard_and_view_phases() {
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        let guard = GuardHold::new(HomeReservation::acquire(home.clone()).unwrap(), None);
        assert_eq!(guard.kind(), InstanceGuardKind::ProcessLocal);
        let view = Arc::new(RuntimeView::new("root-id".into(), None, None, guard.kind()));
        assert_eq!(view.phase(), RuntimePhase::Running);
        assert!(!view.agent_loop_alive(), "no driver, no loop");
        Composition::from_stoppers(
            HoldStoppers::default(),
            None,
            None,
            Some(guard),
            LogHandle::null(),
        )
        .with_view(Arc::clone(&view))
        .teardown(TeardownReason::Requested)
        .await;
        assert_eq!(view.phase(), RuntimePhase::Stopped);
        assert!(!crate::registry::reserved_homes_for_test().contains(&home));
        assert!(
            !home.join(".runtime").exists(),
            "no lock file was ever written"
        );
    }

    struct Hook {
        id: &'static str,
        behaviour: HookBehaviour,
        ran: Arc<Mutex<Vec<&'static str>>>,
    }

    enum HookBehaviour {
        Finish,
        Hang(Duration),
        PanicWhilePolled,
        PanicWhileBuilt,
    }

    impl ComposeExtension for Hook {
        fn id(&self) -> &'static str {
            self.id
        }

        fn shutdown<'a>(&'a self) -> crate::api::BoxFuture<'a, ()> {
            self.ran.lock().unwrap().push(self.id);
            match self.behaviour {
                HookBehaviour::Finish => Box::pin(async {}),
                HookBehaviour::Hang(duration) => Box::pin(tokio::time::sleep(duration)),
                HookBehaviour::PanicWhilePolled => Box::pin(async { panic!("hook panicked") }),
                HookBehaviour::PanicWhileBuilt => panic!("hook panicked before its future"),
            }
        }
    }

    /// Hooks run in reverse registration order; a hook that hangs is abandoned at the
    /// bound, a hook that panics (building or polling its future) is reported, and the
    /// hooks after either still run.
    #[tokio::test(start_paused = true)]
    async fn module_001_ac30_extension_shutdown_hooks_reverse_bounded() {
        let ran = Arc::new(Mutex::new(Vec::new()));
        let hook = |id, behaviour| -> Arc<dyn ComposeExtension> {
            Arc::new(Hook {
                id,
                behaviour,
                ran: Arc::clone(&ran),
            })
        };
        let extensions = vec![
            hook("first", HookBehaviour::Finish),
            hook("panics-built", HookBehaviour::PanicWhileBuilt),
            hook("hangs", HookBehaviour::Hang(Duration::from_secs(10))),
            hook("panics-polled", HookBehaviour::PanicWhilePolled),
            hook("last", HookBehaviour::Finish),
        ];
        let sink = Arc::new(Recording::default());
        let started = Instant::now();
        run_extension_shutdown_hooks(&extensions, &LogHandle::new(sink.clone())).await;
        let waited = started.elapsed();
        assert!(
            waited >= EXTENSION_SHUTDOWN_BOUND && waited < EXTENSION_SHUTDOWN_BOUND + POLL,
            "only the hanging hook waits, and only for its bound: {waited:?}"
        );
        assert_eq!(
            *ran.lock().unwrap(),
            vec!["last", "panics-polled", "hangs", "panics-built", "first"]
        );
        let lines: Vec<(&'static str, String)> = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|line| {
                assert_eq!(line.stream, LogStream::Stderr);
                (line.key, line.text.clone())
            })
            .collect();
        assert_eq!(
            lines,
            vec![
                (
                    log_keys::EXT_SHUTDOWN_PANICKED,
                    "advance: WARN extension panics-polled shutdown hook panicked; continuing"
                        .to_owned()
                ),
                (
                    log_keys::EXT_SHUTDOWN_ABANDONED,
                    "advance: WARN extension hangs shutdown hook did not finish within 5s; abandoned"
                        .to_owned()
                ),
                (
                    log_keys::EXT_SHUTDOWN_PANICKED,
                    "advance: WARN extension panics-built shutdown hook panicked; continuing"
                        .to_owned()
                ),
            ]
        );
    }

    /// The teardown runs the hooks (and records the step) only when extensions exist.
    #[tokio::test]
    async fn module_001_ac30_teardown_runs_the_extension_hooks_in_step_3() {
        let ran = Arc::new(Mutex::new(Vec::new()));
        let extensions: Vec<Arc<dyn ComposeExtension>> = vec![
            Arc::new(Hook {
                id: "one",
                behaviour: HookBehaviour::Finish,
                ran: Arc::clone(&ran),
            }),
            Arc::new(Hook {
                id: "two",
                behaviour: HookBehaviour::Finish,
                ran: Arc::clone(&ran),
            }),
        ];
        let sink = Arc::new(Recording::default());
        Composition::from_stoppers(
            HoldStoppers::default(),
            None,
            None,
            None,
            LogHandle::new(sink.clone()),
        )
        .with_extensions(extensions)
        .teardown(TeardownReason::Requested)
        .await;
        assert_eq!(*ran.lock().unwrap(), vec!["two", "one"]);
        assert_eq!(sink.keys(), vec![log_keys::SHUTTING_DOWN]);
    }

    /// A config watcher whose OS-watcher release takes `release`: everything else its stop
    /// does happens at once.
    struct SlowRelease {
        stopped: AtomicBool,
        release: Duration,
    }

    impl StopConfigWatcher for SlowRelease {
        fn stop(&self) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                self.stopped.store(true, Ordering::SeqCst);
                tokio::time::sleep(self.release).await;
            })
        }
    }

    /// A release of the OS watcher that outlasts its bound (on macOS the FSEvents run loop
    /// can take seconds) is left to finish on its own thread without a word: a requested
    /// shutdown prints only `advance: shutting down`, a startup failure's teardown prints
    /// nothing, and neither waits past the bound.
    #[tokio::test(start_paused = true)]
    async fn module_001_ac30_slow_config_watcher_release_is_bounded_and_silent() {
        for (reason, expected) in [
            (TeardownReason::Requested, vec![log_keys::SHUTTING_DOWN]),
            (TeardownReason::StartupFailed, vec![]),
        ] {
            let watcher = Arc::new(SlowRelease {
                stopped: AtomicBool::new(false),
                release: Duration::from_secs(30),
            });
            let sink = Arc::new(Recording::default());
            let probe = Arc::new(crate::test_support::ComposeProbe::new());
            let mut composition = Composition::from_stoppers(
                HoldStoppers::default(),
                None,
                None,
                None,
                LogHandle::new(sink.clone()),
            )
            .with_probe(Some(Arc::clone(&probe)));
            composition.config_watcher = Some(watcher.clone() as Arc<dyn StopConfigWatcher>);
            let started = Instant::now();
            composition.teardown(reason).await;
            let waited = started.elapsed();
            assert!(
                watcher.stopped.load(Ordering::SeqCst),
                "{reason:?}: the watcher is stopped"
            );
            assert!(
                waited >= THREAD_JOIN_BOUND && waited < THREAD_JOIN_BOUND + POLL,
                "{reason:?}: the release gets its bound and no more: {waited:?}"
            );
            assert_eq!(sink.keys(), expected, "{reason:?}");
            assert_eq!(
                probe.record().step_names(),
                vec!["holds.watchers"],
                "{reason:?}"
            );
        }
    }

    /// An extension that records, when it is dropped, the teardown steps that had run by
    /// then and whether the runtime lock file still existed.
    struct DropWitness {
        probe: Arc<crate::test_support::ComposeProbe>,
        lock_path: std::path::PathBuf,
        seen: Arc<Mutex<Option<(Vec<&'static str>, bool)>>>,
    }

    impl ComposeExtension for DropWitness {
        fn id(&self) -> &'static str {
            "drop-witness"
        }

        fn shutdown<'a>(&'a self) -> crate::api::BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    impl Drop for DropWitness {
        fn drop(&mut self) {
            *self.seen.lock().unwrap() =
                Some((self.probe.record().step_names(), self.lock_path.exists()));
        }
    }

    /// The composition lets go of an extension right after the shutdown hooks: before
    /// any hold is released and while the instance guard is still held.
    #[tokio::test]
    async fn module_001_ac30_extensions_are_let_go_after_their_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        let lock = RuntimeLock::acquire(&home, Duration::from_secs(30))
            .await
            .expect("lock");
        let lock_path = lock.path().to_path_buf();
        let guard = GuardHold::new(
            HomeReservation::acquire(home.clone()).expect("reserve"),
            Some(lock),
        );
        let probe = Arc::new(crate::test_support::ComposeProbe::new());
        let seen = Arc::new(Mutex::new(None));
        let extension: Arc<dyn ComposeExtension> = Arc::new(DropWitness {
            probe: Arc::clone(&probe),
            lock_path: lock_path.clone(),
            seen: Arc::clone(&seen),
        });
        Composition::from_stoppers(
            HoldStoppers::default(),
            None,
            None,
            Some(guard),
            LogHandle::null(),
        )
        .with_extensions(vec![extension])
        .with_probe(Some(Arc::clone(&probe)))
        .teardown(TeardownReason::Requested)
        .await;
        let (steps, lock_held) = seen
            .lock()
            .unwrap()
            .take()
            .expect("the extension was dropped");
        assert_eq!(
            steps,
            vec!["extensions.hooks"],
            "dropped right after its hook"
        );
        assert!(lock_held, "dropped while the instance guard was still held");
        assert_eq!(
            probe.record().step_names(),
            vec!["extensions.hooks", "guard"]
        );
        assert!(!lock_path.exists(), "the guard is released after");
    }

    /// A listener whose requests never finish is aborted once its budget has elapsed.
    #[tokio::test(start_paused = true)]
    async fn module_001_ac30_listener_drain_is_bounded() {
        let shutdown = CancellationToken::new();
        let stuck = tokio::spawn(std::future::pending::<()>());
        let started = Instant::now();
        assert!(drain_listener(shutdown.clone(), stuck, LISTENER_DRAIN).await);
        assert!(shutdown.is_cancelled());
        let waited = started.elapsed();
        assert!(
            waited >= LISTENER_DRAIN && waited < LISTENER_DRAIN + POLL,
            "{waited:?}"
        );

        let token = CancellationToken::new();
        let graceful = tokio::spawn({
            let token = token.clone();
            async move { token.cancelled().await }
        });
        assert!(!drain_listener(token, graceful, LISTENER_DRAIN).await);
    }

    struct FakeWorker {
        name: &'static str,
        closed: AtomicBool,
        exits_on_close: bool,
    }

    impl WorkerControl for FakeWorker {
        fn name(&self) -> &'static str {
            self.name
        }

        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }

        fn try_join(&self) -> bool {
            self.exits_on_close && self.closed.load(Ordering::SeqCst)
        }
    }

    /// Every worker is closed; a thread that does not exit within the shared bound is
    /// reported by name and left detached, one that exits is not reported.
    #[tokio::test(start_paused = true)]
    async fn module_001_ac30_adapter_thread_join_is_bounded() {
        let exiting = Arc::new(FakeWorker {
            name: "advance-client-events",
            closed: AtomicBool::new(false),
            exits_on_close: true,
        });
        let stuck = Arc::new(FakeWorker {
            name: "advance-client-run-control",
            closed: AtomicBool::new(false),
            exits_on_close: false,
        });
        let workers: Vec<Arc<dyn WorkerControl>> = vec![exiting.clone(), stuck.clone()];
        let sink = Arc::new(Recording::default());
        let started = Instant::now();
        close_adapter_workers(&workers, &LogHandle::new(sink.clone())).await;
        assert!(started.elapsed() >= THREAD_JOIN_BOUND);
        assert!(exiting.closed.load(Ordering::SeqCst) && stuck.closed.load(Ordering::SeqCst));
        let lines = sink.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0].key, log_keys::COMPOSE_THREAD_JOIN_OVERRUN);
        assert_eq!(lines[0].stream, LogStream::Stderr);
        assert_eq!(
            lines[0].text,
            "advance: WARN advance-client-run-control thread still running after 2s; detached"
        );
    }
}
