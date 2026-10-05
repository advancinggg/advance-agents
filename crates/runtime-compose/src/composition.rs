//! The composition's ordered teardown.
//!
//! [`Composition`] owns everything the daemon composition started and stops all of
//! it in one order, on a requested shutdown and after a startup failure alike:
//!
//! 1. **ingress** — the Client API, the `POST /msg` listener and the channel
//!    `/hooks` listener stop accepting and drain their requests, concurrently, each
//!    within its budget;
//! 2. **loops** — the root serve loop, the channel host pump, the per-child loops,
//!    the auto tick loop and the readiness walk stop; then every live LLM stream is
//!    settled and the stream reaper stopped. A requested shutdown then prints
//!    `advance: shutting down`;
//! 3. **extension hooks** — none are composed yet;
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
//! that elapses is reported on stderr and the sequence goes on, and a startup-failure
//! teardown prints nothing else.

use std::sync::Arc;
use std::time::Duration;

use advance_client_api::{ClientApi, ClientApiServer, ShutdownIngress};
use advance_runtime::config::RuntimeConfigWatcher;
use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::RuntimeHost;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::api::log_keys;
use crate::client_api_adapters::WorkerControl;
use crate::compose_log::LogHandle;
use crate::daemon::{ComposedGraph, Listener};
use crate::runnable_walk::ContinuousReadinessWalk;
use crate::wiring::{HoldStoppers, WiringHandles};

/// Budget of the Client API's drain: its serve task, its upgraded WebSockets and its
/// in-flight dispatches share one deadline.
const CLIENT_API_DRAIN: Duration = Duration::from_secs(10);
/// Budget of the `POST /msg` and `/hooks` listeners' drains.
const LISTENER_DRAIN: Duration = Duration::from_secs(5);
/// Budget of a thread join: the Client API adapter threads (one shared deadline), the
/// config watcher's OS-watcher release, the WAL-mode observer.
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
pub(crate) const TEARDOWN_ORDER: &[&str] = &[
    "ingress.client_api",
    "ingress.post_msg",
    "ingress.hooks",
    "loops.root",
    "loops.host_pump",
    "loops.perchild",
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

/// Where the teardown records the steps it ran.
#[derive(Default)]
struct StepLog;

impl StepLog {
    fn record(&self, step: &'static str) {
        debug_assert!(
            TEARDOWN_ORDER.contains(&step),
            "unknown teardown step {step}"
        );
    }
}

/// The instance guard a composition holds until the end of its teardown.
pub(crate) struct GuardHold {
    lock: Option<RuntimeLock>,
}

impl GuardHold {
    pub(crate) fn new(lock: RuntimeLock) -> Self {
        Self { lock: Some(lock) }
    }

    /// Release the guard: the runtime lock's heartbeat is joined, then its file removed.
    pub(crate) async fn release(self) {
        if let Some(lock) = self.lock {
            lock.release().await;
        }
    }
}

/// Everything a daemon composition started, and its one teardown.
pub(crate) struct Composition {
    log: LogHandle,
    steps: StepLog,
    // Step 1: ingress.
    client_api_server: Option<ClientApiServer>,
    msg_listener: Option<Listener>,
    hooks: Option<(CancellationToken, JoinHandle<()>)>,
    // Step 2: loops (the per-child manager and the stream reaper are in `stoppers`).
    root_loop: Option<JoinHandle<()>>,
    host_pump: Option<JoinHandle<()>>,
    auto_tick: Option<(CancellationToken, JoinHandle<()>)>,
    readiness_walk: Option<ContinuousReadinessWalk>,
    // Step 4: holds.
    selected_provider_task: Option<JoinHandle<()>>,
    config_watcher: Option<Arc<RuntimeConfigWatcher>>,
    wal_observer: Option<JoinHandle<()>>,
    stoppers: HoldStoppers,
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
        };
        let client_api_server = wiring_handles.client_api_server.take();
        let (root_loop, hooks, host_pump) = match agent_loop {
            Some(spawned) => (Some(spawned.handle), spawned.hooks, spawned.host_pump),
            None => (None, None, None),
        };
        Self {
            log,
            steps: StepLog,
            client_api_server,
            msg_listener,
            hooks,
            root_loop,
            host_pump,
            auto_tick,
            readiness_walk,
            selected_provider_task,
            config_watcher: Some(config_watcher),
            wal_observer,
            stoppers,
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
            steps: StepLog,
            client_api_server: None,
            msg_listener: None,
            hooks: None,
            root_loop: None,
            host_pump: None,
            auto_tick: None,
            readiness_walk: None,
            selected_provider_task: None,
            config_watcher,
            wal_observer,
            stoppers,
            graph_rest: None,
            guard,
        }
    }

    /// Stop everything, in order (see the module documentation).
    pub(crate) async fn teardown(mut self, reason: TeardownReason) {
        let log = self.log.clone();

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

        // ── Step 3: extension hooks (none are composed yet). ─────────────────────

        // ── Step 4: holds, in dependency order. ───────────────────────────────────
        if let Some(task) = self.selected_provider_task.take() {
            abort_and_join(task).await;
            self.steps.record("holds.selected_provider");
        }
        if self.config_watcher.is_some() || self.wal_observer.is_some() {
            if let Some(watcher) = self.config_watcher.take() {
                // Everything but the OS watcher's release happens at once; that release
                // (on macOS a join of the FSEvents run loop) gets a bound, then finishes
                // on its own thread.
                if tokio::time::timeout(THREAD_JOIN_BOUND, watcher.stop())
                    .await
                    .is_err()
                {
                    report_thread_overrun("config watcher", &log);
                }
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
    }

    /// Stop what a failed wiring had started (no ingress and no loop exist yet): the
    /// same steps, in the same order, as the composition's teardown.
    pub(crate) async fn teardown_standalone(self, log: &LogHandle) {
        Composition::from_stoppers(self, None, None, None, log.clone())
            .teardown(TeardownReason::StartupFailed)
            .await;
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
    use std::sync::Mutex;

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
            let sink = Arc::new(Recording::default());
            Composition::from_stoppers(
                HoldStoppers::default(),
                None,
                None,
                Some(GuardHold::new(lock)),
                LogHandle::new(sink.clone()),
            )
            .teardown(reason)
            .await;
            assert_eq!(sink.keys(), expected, "{reason:?}");
            assert!(!lock_path.exists(), "{reason:?}: the guard is released");
        }
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
