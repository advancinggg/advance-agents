//! CONTRACT-243 attach source and in-process launcher (MODULE-001-AC-34).

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_client_api::Platform;
use advance_home::{
    AttachSession, AttachTarget, CancelToken, ConnectError, RuntimeAttachSource, RuntimeLauncher,
    RuntimeState, SelectedProvider,
};
use futures::FutureExt;
use tokio::runtime::{Handle, RuntimeFlavor};

use super::{
    log_keys, ClientApiEndpoint, ClientApiOptions, ComposeError, ComposeExtension, ComposeOptions,
    ComposedRuntime, LockFailure, RuntimeHealthView,
};
use crate::compose_log::LogHandle;
use crate::registry::{lookup, Lookup};

/// `ConnectError::LaunchFailed { reason }` values of the in-process launcher (kebab-case, like
/// `advance-bin-not-found` / `spawn-failed` / `timeout` / `process_forbidden` today).
pub mod launch_reasons {
    pub const HOME_UNAVAILABLE: &str = "home-unavailable";
    pub const NO_CLIENT_API: &str = "no-client-api";
    pub const CLIENT_API_UNAVAILABLE: &str = "client-api-unavailable";
    pub const TIMEOUT: &str = "timeout";
    pub const RUNTIME_UNAVAILABLE: &str = "runtime-unavailable";
    pub const COMPOSE_PANICKED: &str = "compose-panicked";
    pub const COMPOSE_CONFIG_NOT_FOUND: &str = "compose-config-not-found";
    pub const COMPOSE_LOCK: &str = "compose-lock";
    pub const COMPOSE_BOOTSTRAP: &str = "compose-bootstrap";
    pub const COMPOSE_WIRING: &str = "compose-wiring";
    pub const COMPOSE_AGENT_LOOP: &str = "compose-agent-loop";
    pub const COMPOSE_LISTENER: &str = "compose-listener";
    pub const COMPOSE_READINESS: &str = "compose-readiness";
    pub const COMPOSE_EXTENSION: &str = "compose-extension";
    pub const COMPOSE_UNSUPPORTED: &str = "compose-unsupported";
    pub const ALL: &[&str] = &[
        HOME_UNAVAILABLE,
        NO_CLIENT_API,
        CLIENT_API_UNAVAILABLE,
        TIMEOUT,
        RUNTIME_UNAVAILABLE,
        COMPOSE_PANICKED,
        COMPOSE_CONFIG_NOT_FOUND,
        COMPOSE_LOCK,
        COMPOSE_BOOTSTRAP,
        COMPOSE_WIRING,
        COMPOSE_AGENT_LOOP,
        COMPOSE_LISTENER,
        COMPOSE_READINESS,
        COMPOSE_EXTENSION,
        COMPOSE_UNSUPPORTED,
    ];
}

/// The process-local registry as a CONTRACT-243 attach source (MODULE-001-AC-34). It sees every
/// composition in this process (launched by `InProcessLauncher`, the bridge, or a direct `compose`),
/// never a lock or discovery file, and mints a native operator session per attach. Any in-process
/// code can therefore mint a session: extensions and hosts are trusted in-process code (ADR D2).
/// CONTRACT-243 is synchronous; call it from a thread that is not a worker of the composition's
/// Tokio runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessLocalAttachSource {
    _private: (),
}

impl ProcessLocalAttachSource {
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

enum Seen {
    /// No registry entry, or a relative / unresolvable path.
    Free,
    /// Reserved but not attachable now.
    Busy,
    /// Published and attachable (not yet probed).
    Attachable {
        endpoint: ClientApiEndpoint,
        platform: Platform,
    },
}

fn registry_key(home: &Path) -> Option<PathBuf> {
    if home.is_absolute() {
        fs::canonicalize(home).ok()
    } else {
        None
    }
}

fn launched_key(home: &Path) -> PathBuf {
    registry_key(home).unwrap_or_else(|| home.to_path_buf())
}

fn seen(home: &Path) -> Seen {
    match registry_key(home) {
        Some(key) => seen_of(lookup(&key)),
        None => Seen::Free,
    }
}

fn seen_of(lookup: Lookup) -> Seen {
    match lookup {
        Lookup::Free => Seen::Free,
        Lookup::Reserved(None) => Seen::Busy,
        Lookup::Reserved(Some(info)) => {
            if info.shutdown.is_triggered() {
                return Seen::Busy;
            }
            let Some(view) = info.view.upgrade() else {
                return Seen::Busy;
            };
            match view.client_api_endpoint() {
                Some(endpoint) if endpoint.api.strong_count() > 0 => Seen::Attachable {
                    endpoint,
                    platform: info.platform,
                },
                _ => Seen::Busy,
            }
        }
    }
}

fn state_of(seen: &Seen, accepts: impl Fn(&str) -> bool) -> RuntimeState {
    match seen {
        Seen::Free => RuntimeState::Idle,
        Seen::Busy => RuntimeState::Starting,
        Seen::Attachable { endpoint, .. } => {
            if accepts(&endpoint.base_url) {
                RuntimeState::Running
            } else {
                RuntimeState::Starting
            }
        }
    }
}

fn accepts(base: &str) -> bool {
    advance_home::discovery::client_api_accepts(base)
        || advance_home::discovery::client_api_accepts(base)
}

fn mint_for(endpoint: &ClientApiEndpoint, platform: Platform) -> Option<AttachSession> {
    let api = endpoint.api.upgrade()?;
    let info = api.mint_in_process_session(platform);
    Some(AttachSession::new(
        info.session_id,
        info.token,
        info.expires_at,
    ))
}

impl RuntimeAttachSource for ProcessLocalAttachSource {
    fn runtime_state(&self, home: &Path) -> RuntimeState {
        state_of(&seen(home), accepts)
    }

    fn live_pid(&self, home: &Path) -> Option<u32> {
        match seen(home) {
            Seen::Free => None,
            Seen::Busy | Seen::Attachable { .. } => Some(std::process::id()),
        }
    }

    fn selected_provider(&self, home: &Path) -> Option<SelectedProvider> {
        if !home.is_absolute() {
            return None;
        }
        advance_home::runtime_state::read_selected_provider(home)
    }

    fn attach(&self, home: &Path) -> Option<AttachTarget> {
        match seen(home) {
            Seen::Attachable { endpoint, platform } => {
                if accepts(&endpoint.base_url) {
                    let session = mint_for(&endpoint, platform)?;
                    Some(AttachTarget {
                        client_api_base: endpoint.base_url,
                        session: Some(session),
                    })
                } else {
                    None
                }
            }
            Seen::Free | Seen::Busy => None,
        }
    }

    fn claim_launch(&self, home: &Path) -> bool {
        match registry_key(home) {
            Some(key) => crate::registry::claim_launch(&key, Instant::now()),
            None => true,
        }
    }

    fn release_launch(&self, home: &Path) {
        if let Some(key) = registry_key(home) {
            crate::registry::release_launch(&key);
        }
    }
}

/// What [`InProcessLauncher`] composes for a home. The launcher sets `options.home` to the canonical home.
#[non_exhaustive]
pub struct LaunchPlan {
    pub options: ComposeOptions,
    pub extensions: Vec<Arc<dyn ComposeExtension>>,
}

impl LaunchPlan {
    pub fn new(options: ComposeOptions, extensions: Vec<Arc<dyn ComposeExtension>>) -> Self {
        Self {
            options,
            extensions,
        }
    }
}

type PlanFn = dyn Fn(&Path) -> LaunchPlan + Send + Sync;

struct LauncherInner {
    runtime: Handle,
    plan: Box<PlanFn>,
    launched: Mutex<HashMap<PathBuf, ComposedRuntime>>,
}

/// A CONTRACT-243 `RuntimeLauncher` that composes the runtime in the calling process, on `runtime`
/// (MODULE-001-AC-34). It also exposes stop and health.
///
/// Threads: `runtime` is a multi-thread Tokio runtime with at least two workers. CONTRACT-243 sleeps
/// and probes on the calling thread, so call `start_or_attach` (and `start` / `stop`) from a host
/// thread or `spawn_blocking`, never from a worker of `runtime`.
///
/// Ownership and drop order: the launcher owns the runtimes it launched. Dropping it triggers their
/// shutdown, which then runs on `runtime`. Stop every home (or drop the launcher and let those
/// shutdowns finish) before dropping `runtime`. If `runtime` goes first, each composition's ordered
/// shutdown is cut short: its registry entry is still released (RAII), but the drains and joins of
/// the shutdown sequence do not run.
pub struct InProcessLauncher {
    inner: Arc<LauncherInner>,
    start_bound: Duration,
    stop_bound: Duration,
}

impl InProcessLauncher {
    pub const DEFAULT_START_BOUND: Duration = Duration::from_secs(30);
    pub const DEFAULT_STOP_BOUND: Duration = Duration::from_secs(60);

    /// Refuses a current-thread runtime and a multi-thread runtime with fewer than two workers.
    pub fn new<F>(runtime: Handle, plan: F) -> Result<Self, InProcessLauncherError>
    where
        F: Fn(&Path) -> LaunchPlan + Send + Sync + 'static,
    {
        if runtime.runtime_flavor() == RuntimeFlavor::CurrentThread {
            return Err(InProcessLauncherError::CurrentThreadRuntime);
        }
        let workers = runtime.metrics().num_workers();
        if workers < 2 {
            return Err(InProcessLauncherError::TooFewWorkers { workers });
        }
        Ok(Self {
            inner: Arc::new(LauncherInner {
                runtime,
                plan: Box::new(plan),
                launched: Mutex::new(HashMap::new()),
            }),
            start_bound: Self::DEFAULT_START_BOUND,
            stop_bound: Self::DEFAULT_STOP_BOUND,
        })
    }

    pub fn with_start_bound(mut self, bound: Duration) -> Self {
        self.start_bound = bound;
        self
    }

    pub fn with_stop_bound(mut self, bound: Duration) -> Self {
        self.stop_bound = bound;
        self
    }

    /// Runs the ordered shutdown of the runtime this launcher launched for `home` (also one whose
    /// shutdown was triggered elsewhere) and waits for it. The home is released when this returns `Ok`.
    pub fn stop(&self, home: &Path) -> Result<(), InProcessStopError> {
        let key = launched_key(home);
        let rt = {
            let mut launched = self
                .inner
                .launched
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            launched.remove(&key)
        };
        let Some(rt) = rt else {
            return Err(InProcessStopError::NotLaunched);
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let _join = self.inner.runtime.spawn(async move {
            let outcome = AssertUnwindSafe(rt.shutdown()).catch_unwind().await;
            let _ = tx.send(outcome);
        });
        wait_stop(&rx, self.stop_bound)
    }

    /// Health of the runtime this launcher launched for `home`; a runtime whose shutdown was
    /// triggered reports `ShuttingDown`, then `Stopped`, until `stop` or the next launch removes it.
    pub fn health(&self, home: &Path) -> Option<RuntimeHealthView> {
        let launched = self
            .inner
            .launched
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        launched.get(&launched_key(home)).map(|rt| rt.health())
    }

    /// Test-support: trigger the shutdown of the runtime launched for `home` without removing it, as
    /// a shutdown that does not go through `stop` would. `true` if this call started the sequence.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn trigger_shutdown_for_test(&self, home: &Path) -> bool {
        let launched = self
            .inner
            .launched
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        launched
            .get(&launched_key(home))
            .map(|rt| rt.shutdown_handle().trigger())
            .unwrap_or(false)
    }
}

impl RuntimeLauncher for InProcessLauncher {
    fn start(&self, home: &Path, cancel: &CancelToken) -> Result<(), ConnectError> {
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        let key = registry_key(home).ok_or(ConnectError::LaunchFailed {
            reason: launch_reasons::HOME_UNAVAILABLE.into(),
        })?;
        let LaunchPlan {
            mut options,
            extensions,
        } = (self.inner.plan)(&key);
        options.home = key.clone();
        if matches!(options.client_api, ClientApiOptions::Off) {
            return Err(ConnectError::LaunchFailed {
                reason: launch_reasons::NO_CLIENT_API.into(),
            });
        }
        let log = LogHandle::new(options.log.clone());
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let inner = Arc::clone(&self.inner);
        let w = crate::daemon::safe_path(&key);
        let _join = self.inner.runtime.spawn(async move {
            let outcome = compose_one(inner, key, options, extensions, log, &w).await;
            let _ = tx.send(outcome);
        });
        wait_start(&rx, cancel, self.start_bound)
    }
}

fn wait_start(
    rx: &std::sync::mpsc::Receiver<Result<(), &'static str>>,
    cancel: &CancelToken,
    bound: Duration,
) -> Result<(), ConnectError> {
    let deadline = Instant::now() + bound;
    loop {
        if cancel.is_cancelled() {
            return Err(ConnectError::Cancelled);
        }
        match block_waiting(|| rx.recv_timeout(Duration::from_millis(20))) {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(reason)) => {
                return Err(ConnectError::LaunchFailed {
                    reason: reason.into(),
                })
            }
            Err(RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    return Err(ConnectError::LaunchFailed {
                        reason: launch_reasons::TIMEOUT.into(),
                    });
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(ConnectError::LaunchFailed {
                    reason: launch_reasons::RUNTIME_UNAVAILABLE.into(),
                })
            }
        }
    }
}

fn wait_stop(
    rx: &std::sync::mpsc::Receiver<std::thread::Result<Result<(), ComposeError>>>,
    bound: Duration,
) -> Result<(), InProcessStopError> {
    let deadline = Instant::now() + bound;
    loop {
        match block_waiting(|| rx.recv_timeout(Duration::from_millis(20))) {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(_)) => return Err(InProcessStopError::Panicked),
            Err(RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    return Err(InProcessStopError::TimedOut);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(InProcessStopError::RuntimeUnavailable)
            }
        }
    }
}

async fn compose_one(
    inner: Arc<LauncherInner>,
    key: PathBuf,
    options: ComposeOptions,
    extensions: Vec<Arc<dyn ComposeExtension>>,
    log: LogHandle,
    w: &str,
) -> Result<(), &'static str> {
    match AssertUnwindSafe(crate::compose::compose(options, extensions))
        .catch_unwind()
        .await
    {
        Ok(Ok(rt)) if rt.client_api().is_none() => {
            let _ = rt.shutdown().await;
            log.err(
                log_keys::ATTACH_LAUNCH_FAILED,
                format!(
                    "advance: in-process start failed (workspace={w}): the Client API listener is not bound"
                ),
            );
            Err(launch_reasons::CLIENT_API_UNAVAILABLE)
        }
        Ok(Ok(rt)) => insert_launched(&inner, key, rt, log, w).await,
        Ok(Err(ComposeError::Lock(LockFailure::HeldInProcess))) => Ok(()),
        Ok(Err(e)) => {
            log.err(
                log_keys::ATTACH_LAUNCH_FAILED,
                format!("advance: in-process start failed (workspace={w}): {e}"),
            );
            Err(reason(&e))
        }
        Err(_) => {
            log.err(
                log_keys::ATTACH_LAUNCH_FAILED,
                format!("advance: in-process start panicked (workspace={w})"),
            );
            Err(launch_reasons::COMPOSE_PANICKED)
        }
    }
}

async fn insert_launched(
    inner: &LauncherInner,
    key: PathBuf,
    rt: ComposedRuntime,
    log: LogHandle,
    w: &str,
) -> Result<(), &'static str> {
    enum Insert {
        Vacant,
        /// Stale (triggered) entry replaced; drop the old `ComposedRuntime` after
        /// the `launched` guard is released.
        Replaced(Option<ComposedRuntime>),
        Conflict(ComposedRuntime),
    }
    let insert = {
        let mut launched = inner.launched.lock().unwrap_or_else(|p| p.into_inner());
        match launched
            .get(&key)
            .map(|existing| existing.shutdown_handle().is_triggered())
        {
            None => {
                launched.insert(key, rt);
                Insert::Vacant
            }
            Some(true) => Insert::Replaced(launched.insert(key, rt)),
            Some(false) => Insert::Conflict(rt),
        }
    };
    match insert {
        Insert::Vacant => Ok(()),
        Insert::Replaced(old) => {
            drop(old);
            Ok(())
        }
        Insert::Conflict(rt) => {
            let _ = rt.shutdown().await;
            log.err(
                log_keys::ATTACH_LAUNCH_FAILED,
                format!(
                    "advance: in-process start failed (workspace={w}): the launcher already holds a running runtime for this home"
                ),
            );
            Err(launch_reasons::COMPOSE_LOCK)
        }
    }
}

fn reason(e: &ComposeError) -> &'static str {
    match e {
        ComposeError::ConfigNotFound { .. } => launch_reasons::COMPOSE_CONFIG_NOT_FOUND,
        ComposeError::Lock(_) => launch_reasons::COMPOSE_LOCK,
        ComposeError::Bootstrap(_) => launch_reasons::COMPOSE_BOOTSTRAP,
        ComposeError::Wiring(_) => launch_reasons::COMPOSE_WIRING,
        ComposeError::AgentLoop(_) => launch_reasons::COMPOSE_AGENT_LOOP,
        ComposeError::Listener(_) => launch_reasons::COMPOSE_LISTENER,
        ComposeError::Readiness(_) => launch_reasons::COMPOSE_READINESS,
        ComposeError::Registration { .. }
        | ComposeError::InferenceClaim { .. }
        | ComposeError::CapabilityCollision { .. }
        | ComposeError::HostFunction { .. }
        | ComposeError::Tool { .. }
        | ComposeError::Extension { .. } => launch_reasons::COMPOSE_EXTENSION,
        ComposeError::Unsupported(_) => launch_reasons::COMPOSE_UNSUPPORTED,
    }
}

fn block_waiting<R>(f: impl FnOnce() -> R) -> R {
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

impl Drop for InProcessLauncher {
    fn drop(&mut self) {
        let homes: Vec<PathBuf> = {
            let launched = self
                .inner
                .launched
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            launched.keys().cloned().collect()
        };
        for home in homes {
            let _ = self.stop(&home);
        }
    }
}

impl fmt::Debug for InProcessLauncher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self
            .inner
            .launched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        f.debug_struct("InProcessLauncher")
            .field("launched", &n)
            .field("start_bound", &self.start_bound)
            .field("stop_bound", &self.stop_bound)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InProcessLauncherError {
    CurrentThreadRuntime,
    TooFewWorkers { workers: usize },
}

impl fmt::Display for InProcessLauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentThreadRuntime => {
                f.write_str("the in-process launcher needs a multi-thread Tokio runtime")
            }
            Self::TooFewWorkers { workers } => write!(
                f,
                "the in-process launcher needs at least two Tokio workers (this runtime has {workers})"
            ),
        }
    }
}

impl std::error::Error for InProcessLauncherError {}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InProcessStopError {
    NotLaunched,
    TimedOut,
    Panicked,
    RuntimeUnavailable,
}

impl fmt::Display for InProcessStopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLaunched => f.write_str("no runtime launched here for this home"),
            Self::TimedOut => f.write_str("shutdown still running after the stop bound"),
            Self::Panicked => f.write_str("the shutdown sequence panicked"),
            Self::RuntimeUnavailable => f.write_str("the launcher's Tokio runtime is gone"),
        }
    }
}

impl std::error::Error for InProcessStopError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ShutdownHandle;
    use crate::registry::AttachInfo;
    use advance_client_api::{ClientApi, ClientApiConfig, ExtensionRouteGate, Scope};
    use std::net::SocketAddr;
    use std::sync::Weak;

    fn dummy_endpoint() -> ClientApiEndpoint {
        ClientApiEndpoint {
            base_url: "http://127.0.0.1:1".into(),
            socket_addr: "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
            api: Weak::new(),
        }
    }

    #[test]
    fn module_001_ac34_process_local_source_state_table() {
        assert_eq!(state_of(&Seen::Free, |_| true), RuntimeState::Idle);
        assert_eq!(state_of(&Seen::Busy, |_| true), RuntimeState::Starting);
        let attachable = Seen::Attachable {
            endpoint: dummy_endpoint(),
            platform: Platform::Ios,
        };
        assert_eq!(state_of(&attachable, |_| true), RuntimeState::Running);
        assert_eq!(state_of(&attachable, |_| false), RuntimeState::Starting);
        assert!(matches!(seen_of(Lookup::Free), Seen::Free));
        assert!(matches!(seen_of(Lookup::Reserved(None)), Seen::Busy));
        let gone = AttachInfo {
            view: Weak::new(),
            shutdown: ShutdownHandle::new(ExtensionRouteGate::new()),
            platform: Platform::Ios,
        };
        assert!(matches!(seen_of(Lookup::Reserved(Some(gone))), Seen::Busy));
    }

    #[test]
    fn module_001_ac34_process_local_source_mints_one_native_operator_session_per_attach() {
        let api = Arc::new(ClientApi::new(ClientApiConfig::default()));
        let ep = ClientApiEndpoint {
            base_url: "http://127.0.0.1:1".into(),
            socket_addr: "127.0.0.1:1".parse().unwrap(),
            api: Arc::downgrade(&api),
        };
        let a = mint_for(&ep, Platform::Ios).expect("first mint");
        let b = mint_for(&ep, Platform::Ios).expect("second mint");
        assert_ne!(a.session_id(), b.session_id());
        for session in [&a, &b] {
            let got = api
                .sessions()
                .get_valid(session.bearer_token(), 0)
                .expect("valid");
            assert_eq!(got.scopes, Scope::operator_default());
            assert!(got.csrf_token.is_none());
            assert_eq!(got.platform, Platform::Ios);
        }
        drop(api);
        assert!(mint_for(&ep, Platform::Ios).is_none());
    }

    #[test]
    fn module_001_ac34_process_local_source_without_a_registry_entry() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let source = ProcessLocalAttachSource::new();
        assert_eq!(source.runtime_state(home), RuntimeState::Idle);
        assert!(source.live_pid(home).is_none());
        assert!(source.attach(home).is_none());
        assert!(source.selected_provider(home).is_none());
        assert!(source.claim_launch(home));
        assert!(!source.claim_launch(home));
        source.release_launch(home);
        assert!(source.claim_launch(home));
        source.release_launch(home);
        let relative = Path::new("relative/home");
        assert_eq!(source.runtime_state(relative), RuntimeState::Idle);
        assert!(source.claim_launch(relative));
        assert!(!crate::registry::launch_claims_for_test()
            .iter()
            .any(|p| p == relative));
        let leftover: Vec<_> = fs::read_dir(home).unwrap().filter_map(|e| e.ok()).collect();
        assert!(
            leftover.is_empty(),
            "in-process source writes no files: {leftover:?}"
        );
    }
}
