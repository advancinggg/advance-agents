//! BridgeHandle = Arc<BridgeInner> with stop/detach Drop policy.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_client_api::ClientApi;
use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::RuntimeHost;
use advance_runtime_compose::{
    ClientApiCheck, ComposedRuntime, HostPlatform, InstanceGuardKind, RuntimePhase, WasmEngine,
    Zeroizing,
};
use tokio::process::Child;
use tokio::task::JoinHandle;
use zeroize::Zeroize;

use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::lock_status;
use crate::profile::{build_profile, build_profile_v2, uses_runtime_lock, ProfileV2};
use crate::registry;
use crate::runtime_rt;
use crate::types::{
    BridgeHealth, BridgeHealthV2, BridgeLifecycleInput, CompositionMode, CompositionProfile,
    HostBackend, LockExclusivity, PlatformLifecycleState, SuperviseReadiness,
    HEALTH_SCHEMA_VERSION, HEALTH_SCHEMA_VERSION_V2,
};

const STOP_GRACE: Duration = Duration::from_secs(5);
const SESSION_MIN_REMAINING_MS: u64 = 300_000;
const NO_CLIENT_API: &str = "no Client API on this handle";
const CLIENT_API_UNBOUND: &str =
    "the Client API listener is not bound (a foreground rebind failed or the runtime is stopping)";

pub(crate) enum ModeState {
    Embed {
        host: Option<RuntimeHost>,
        lock: Option<RuntimeLock>,
    },
    Supervise {
        child: Option<Child>,
        drain_tasks: Vec<JoinHandle<()>>,
        kill_on_drop: bool,
        readiness: SuperviseReadiness,
    },
    Composed(Arc<ComposedHandle>),
}

pub(crate) struct BridgeInner {
    pub workspace: PathBuf,
    pub config: BridgeConfig,
    pub lifecycle: Mutex<BridgeLifecycleInput>,
    pub mode: Mutex<ModeState>,
    pub stopped: AtomicBool,
    pub reserved: AtomicBool,
    pub v2: Option<V2Settings>,
}

/// Cloneable handle (Arc).
#[derive(Clone)]
pub struct BridgeHandle {
    pub(crate) inner: Arc<BridgeInner>,
}

impl std::fmt::Debug for BridgeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeHandle")
            .field("workspace", &self.inner.workspace)
            .field("stopped", &self.inner.stopped.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// v2 start settings stored on the handle.
#[derive(Clone)]
pub(crate) struct V2Settings {
    pub platform: HostPlatform,
    pub composition: CompositionProfile,
    pub client_api: bool,
    pub session_platform: advance_client_api::Platform,
}

struct ShellSession {
    #[allow(dead_code)]
    session_id: String,
    token: Zeroizing<String>,
    base: String,
}

pub(crate) struct ComposedHandle {
    runtime: Mutex<Option<Arc<ComposedRuntime>>>,
    session: Mutex<Option<ShellSession>>,
    settings: V2Settings,
}

impl ComposedHandle {
    pub(crate) fn new(runtime: ComposedRuntime, settings: V2Settings) -> Self {
        Self {
            runtime: Mutex::new(Some(Arc::new(runtime))),
            session: Mutex::new(None),
            settings,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_session_stand_in(settings: V2Settings) -> Self {
        Self {
            runtime: Mutex::new(None),
            session: Mutex::new(None),
            settings,
        }
    }

    fn runtime(&self) -> Option<Arc<ComposedRuntime>> {
        self.runtime.lock().ok().and_then(|g| g.clone())
    }

    fn take_runtime(&self) -> Option<Arc<ComposedRuntime>> {
        self.runtime.lock().ok().and_then(|mut g| g.take())
    }

    fn clear_session(&self) {
        if let Ok(mut g) = self.session.lock() {
            *g = None;
        }
    }

    pub(crate) async fn on_foreground(&self) {
        let Some(rt) = self.runtime() else {
            return;
        };
        if let Ok(ClientApiCheck::Moved { .. }) = rt.reverify_client_api().await {
            self.rotate_after_move(&rt);
        }
    }

    fn rotate_after_move(&self, rt: &ComposedRuntime) {
        let Some(ep) = rt.client_api() else {
            return;
        };
        let Some(api) = ep.api.upgrade() else {
            return;
        };
        self.rotate_after_move_on(&api, &ep.base_url);
    }

    pub(crate) fn rotate_after_move_on(&self, api: &ClientApi, base: &str) {
        let Ok(mut g) = self.session.lock() else {
            return;
        };
        let needs_mint = match g.as_ref() {
            None => true,
            Some(held) => held.base != base,
        };
        if !needs_mint {
            return;
        }
        api.sessions().revoke_all();
        *g = Some(mint_shell_session(
            api,
            self.settings.session_platform,
            base,
        ));
    }

    pub(crate) fn session_token(
        &self,
        api: &ClientApi,
        base: &str,
    ) -> Result<Zeroizing<String>, BridgeError> {
        let mut g = self
            .session
            .lock()
            .map_err(|_| BridgeError::Internal("session lock".into()))?;
        if let Some(held) = g.as_ref() {
            if held.base == base && api.session_valid_for(&held.token, SESSION_MIN_REMAINING_MS) {
                return Ok(held.token.clone());
            }
            if held.base != base {
                api.sessions().revoke_all();
            }
        }
        let minted = mint_shell_session(api, self.settings.session_platform, base);
        let token = minted.token.clone();
        *g = Some(minted);
        Ok(token)
    }

    #[cfg(test)]
    pub(crate) fn stored_base(&self) -> Option<String> {
        self.session
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.base.clone()))
    }
}

fn mint_shell_session(
    api: &ClientApi,
    platform: advance_client_api::Platform,
    base: &str,
) -> ShellSession {
    let mut info = api.mint_in_process_session(platform);
    let token = Zeroizing::new(info.token.clone());
    info.token.zeroize();
    ShellSession {
        session_id: info.session_id,
        token,
        base: base.to_owned(),
    }
}

fn no_client_api() -> BridgeError {
    BridgeError::Unsupported(NO_CLIENT_API.into())
}

fn client_api_unbound() -> BridgeError {
    BridgeError::Unsupported(CLIENT_API_UNBOUND.into())
}

impl BridgeHandle {
    pub(crate) fn new(inner: Arc<BridgeInner>) -> Self {
        Self { inner }
    }

    pub fn stop(self) -> Result<(), BridgeError> {
        stop_inner(&self.inner, /*force_reap*/ true)
    }

    /// The composition behind a v2 `full` handle; `None` for v1 and `host_only` handles and after
    /// `stop`. Holding it does not keep the runtime up: `stop` / drop of the handle shut it down.
    pub fn composed_runtime(&self) -> Option<Arc<ComposedRuntime>> {
        let mode = self.inner.mode.lock().ok()?;
        match &*mode {
            ModeState::Composed(c) => c.runtime(),
            _ => None,
        }
    }

    pub fn client_api_base(&self) -> Result<String, BridgeError> {
        let settings = self.inner.v2.as_ref().ok_or_else(no_client_api)?;
        if !settings.client_api {
            return Err(no_client_api());
        }
        let rt = self.composed_runtime().ok_or_else(client_api_unbound)?;
        rt.client_api()
            .map(|ep| ep.base_url)
            .ok_or_else(client_api_unbound)
    }

    pub fn client_api_session(&self) -> Result<Zeroizing<String>, BridgeError> {
        let settings = self.inner.v2.as_ref().ok_or_else(no_client_api)?;
        if !settings.client_api {
            return Err(no_client_api());
        }
        let composed = {
            let mode = self
                .inner
                .mode
                .lock()
                .map_err(|_| BridgeError::Internal("mode lock".into()))?;
            match &*mode {
                ModeState::Composed(c) => Arc::clone(c),
                _ => return Err(no_client_api()),
            }
        };
        let rt = composed.runtime().ok_or_else(client_api_unbound)?;
        let ep = rt.client_api().ok_or_else(client_api_unbound)?;
        let api = ep.api.upgrade().ok_or_else(client_api_unbound)?;
        composed.session_token(&api, &ep.base_url)
    }

    /// 14 `Unsupported` on a v1 handle ("health v2 is reported only for handles started through v2").
    pub fn health_v2(&self) -> Result<BridgeHealthV2, BridgeError> {
        let settings = self.inner.v2.clone().ok_or_else(|| {
            BridgeError::Unsupported(
                "health v2 is reported only for handles started through v2".into(),
            )
        })?;
        let lifecycle = self
            .inner
            .lifecycle
            .lock()
            .map_err(|_| BridgeError::Internal("lifecycle lock".into()))?
            .clone();
        let stopped = self.inner.stopped.load(Ordering::SeqCst);

        enum Snap {
            Full {
                runtime: Option<Arc<ComposedRuntime>>,
            },
            HostOnly {
                host_up: bool,
                backend: HostBackend,
                need_lock_hb: bool,
                lock_excl: LockExclusivity,
            },
        }

        let snap = {
            let mode = self
                .inner
                .mode
                .lock()
                .map_err(|_| BridgeError::Internal("mode lock".into()))?;
            match &*mode {
                ModeState::Composed(c) => Snap::Full {
                    runtime: c.runtime(),
                },
                ModeState::Embed { host, lock } => {
                    let host_up = host.is_some() && !stopped;
                    let backend = match host.as_ref() {
                        Some(h) => {
                            let report = h.component_runtime().engine_report();
                            if report.host.is_pulley && report.tool.is_pulley {
                                HostBackend::Pulley
                            } else {
                                HostBackend::Cranelift
                            }
                        }
                        None => HostBackend::Cranelift,
                    };
                    let need_lock_hb = lock.is_some() && uses_runtime_lock();
                    let lock_excl = if uses_runtime_lock() {
                        LockExclusivity::RuntimeLock
                    } else {
                        LockExclusivity::ProcessLocal
                    };
                    Snap::HostOnly {
                        host_up,
                        backend,
                        need_lock_hb,
                        lock_excl,
                    }
                }
                ModeState::Supervise { .. } => {
                    return Err(BridgeError::Internal(
                        "health v2 is not defined for supervise handles".into(),
                    ));
                }
            }
        };

        match snap {
            Snap::Full { runtime } => {
                let health = runtime.as_ref().map(|rt| rt.health());
                let runtime_up = !stopped
                    && health
                        .as_ref()
                        .is_some_and(|h| h.phase == RuntimePhase::Running);
                let agent_loop_up = health.as_ref().is_some_and(|h| h.agent_loop_up);
                let client_api_base = runtime
                    .as_ref()
                    .and_then(|rt| rt.client_api().map(|e| e.base_url));
                let backend = match health.as_ref() {
                    Some(h) if h.wasm_engine == WasmEngine::Pulley => HostBackend::Pulley,
                    _ => HostBackend::Cranelift,
                };
                let lock_exclusivity = match health.as_ref() {
                    Some(h) if h.instance_guard == InstanceGuardKind::PidLockFile => {
                        LockExclusivity::RuntimeLock
                    }
                    Some(_) => LockExclusivity::ProcessLocal,
                    None if settings.platform.is_mobile() => LockExclusivity::ProcessLocal,
                    None => LockExclusivity::RuntimeLock,
                };
                let last_heartbeat_ok =
                    if matches!(lock_exclusivity, LockExclusivity::RuntimeLock) && runtime_up {
                        lock_status::embed_lock_heartbeat_ok(&self.inner.workspace)
                    } else {
                        runtime_up
                    };
                let profile = build_profile_v2(ProfileV2 {
                    platform: settings.platform,
                    backend,
                    lifecycle: lifecycle.state,
                    runtime_up,
                    agent_loop_up,
                    composition: settings.composition,
                    battery_pct: lifecycle.battery_pct,
                    network_class: lifecycle.network_class.clone(),
                });
                Ok(BridgeHealthV2 {
                    schema_version: HEALTH_SCHEMA_VERSION_V2,
                    runtime_up,
                    profile,
                    last_heartbeat_ok,
                    composition_mode: CompositionMode::Embed,
                    lock_exclusivity,
                    supervise_readiness: None,
                    composition_profile: settings.composition,
                    agent_loop_up,
                    client_api_base,
                })
            }
            Snap::HostOnly {
                host_up,
                backend,
                need_lock_hb,
                lock_excl,
            } => {
                let last_heartbeat_ok = if need_lock_hb {
                    lock_status::embed_lock_heartbeat_ok(&self.inner.workspace)
                } else {
                    host_up
                };
                let profile = build_profile_v2(ProfileV2 {
                    platform: settings.platform,
                    backend,
                    lifecycle: lifecycle.state,
                    runtime_up: host_up,
                    agent_loop_up: false,
                    composition: settings.composition,
                    battery_pct: lifecycle.battery_pct,
                    network_class: lifecycle.network_class.clone(),
                });
                Ok(BridgeHealthV2 {
                    schema_version: HEALTH_SCHEMA_VERSION_V2,
                    runtime_up: host_up,
                    profile,
                    last_heartbeat_ok,
                    composition_mode: CompositionMode::Embed,
                    lock_exclusivity: lock_excl,
                    supervise_readiness: None,
                    composition_profile: settings.composition,
                    agent_loop_up: false,
                    client_api_base: None,
                })
            }
        }
    }

    pub fn health(&self) -> Result<BridgeHealth, BridgeError> {
        if self.is_v2() {
            let v2 = self.health_v2()?;
            return Ok(BridgeHealth {
                schema_version: HEALTH_SCHEMA_VERSION,
                runtime_up: v2.runtime_up,
                profile: v2.profile,
                last_heartbeat_ok: v2.last_heartbeat_ok,
                composition_mode: v2.composition_mode,
                lock_exclusivity: v2.lock_exclusivity,
                supervise_readiness: v2.supervise_readiness,
            });
        }
        let lifecycle = self
            .inner
            .lifecycle
            .lock()
            .map_err(|_| BridgeError::Internal("lifecycle lock".into()))?
            .clone();
        let (runtime_up, need_lock_hb, readiness, lock_excl) = {
            let mut mode = self
                .inner
                .mode
                .lock()
                .map_err(|_| BridgeError::Internal("mode lock".into()))?;
            match &mut *mode {
                ModeState::Embed { host, lock } => {
                    let up = host.is_some() && !self.inner.stopped.load(Ordering::SeqCst);
                    let need_hb = lock.is_some() && uses_runtime_lock();
                    let excl = if uses_runtime_lock() {
                        LockExclusivity::RuntimeLock
                    } else {
                        LockExclusivity::ProcessLocal
                    };
                    (up, need_hb, None, excl)
                }
                ModeState::Supervise {
                    child, readiness, ..
                } => {
                    let alive = if let Some(c) = child.as_mut() {
                        match c.try_wait() {
                            Ok(None) => true,
                            Ok(Some(_)) => false,
                            Err(_) => false,
                        }
                    } else {
                        false
                    };
                    let up = alive && !self.inner.stopped.load(Ordering::SeqCst);
                    (up, false, Some(*readiness), LockExclusivity::ProcessLocal)
                }
                ModeState::Composed(_) => {
                    return Err(BridgeError::Internal(
                        "composed handle missing v2 settings".into(),
                    ));
                }
            }
        };
        // Read the lock file *after* releasing mode so a FIFO/hang cannot wedge stop.
        let last_hb = if need_lock_hb {
            lock_status::embed_lock_heartbeat_ok(&self.inner.workspace)
        } else {
            runtime_up
        };
        let profile = build_profile(
            self.inner.config.platform,
            self.inner.config.engine_mode,
            lifecycle.state,
            runtime_up,
            lifecycle.battery_pct,
            lifecycle.network_class.clone(),
        );
        Ok(BridgeHealth {
            schema_version: HEALTH_SCHEMA_VERSION,
            runtime_up,
            profile,
            last_heartbeat_ok: last_hb,
            composition_mode: self.inner.config.composition_mode,
            lock_exclusivity: lock_excl,
            supervise_readiness: if matches!(
                self.inner.config.composition_mode,
                CompositionMode::Supervise
            ) {
                readiness
            } else {
                None
            },
        })
    }

    pub fn on_lifecycle(&self, input: BridgeLifecycleInput) -> Result<(), BridgeError> {
        if let Some(pct) = input.battery_pct {
            if pct > 100 {
                return Err(BridgeError::InvalidArg);
            }
        }
        let state = input.state;
        {
            let mut g = self
                .inner
                .lifecycle
                .lock()
                .map_err(|_| BridgeError::Internal("lifecycle lock".into()))?;
            *g = input;
        }
        if matches!(state, PlatformLifecycleState::Foreground) {
            if let Some(c) = self.composed_handle() {
                runtime_rt::block_on_global(async move { c.on_foreground().await });
            }
        }
        Ok(())
    }

    pub async fn on_lifecycle_async(&self, input: BridgeLifecycleInput) -> Result<(), BridgeError> {
        if let Some(pct) = input.battery_pct {
            if pct > 100 {
                return Err(BridgeError::InvalidArg);
            }
        }
        let state = input.state;
        {
            let mut g = self
                .inner
                .lifecycle
                .lock()
                .map_err(|_| BridgeError::Internal("lifecycle lock".into()))?;
            *g = input;
        }
        if matches!(state, PlatformLifecycleState::Foreground) {
            if let Some(c) = self.composed_handle() {
                c.on_foreground().await;
            }
        }
        Ok(())
    }

    pub(crate) fn is_v2(&self) -> bool {
        self.inner.v2.is_some()
    }

    fn composed_handle(&self) -> Option<Arc<ComposedHandle>> {
        let mode = self.inner.mode.lock().ok()?;
        match &*mode {
            ModeState::Composed(c) => Some(Arc::clone(c)),
            _ => None,
        }
    }

    pub(crate) async fn stop_async_inner(self) -> Result<(), BridgeError> {
        stop_inner_async(&self.inner, true).await
    }
}

impl Drop for BridgeInner {
    fn drop(&mut self) {
        // Last Arc dropped. Always drain leftover resources even if `stopped`
        // was set before teardown finished (panic / cancelled helper).
        let _ = self.stopped.swap(true, Ordering::SeqCst);
        let mut drains = Vec::new();
        let mut child = None;
        let mut composed = None;
        let force = {
            match self.mode.get_mut().unwrap_or_else(|e| e.into_inner()) {
                ModeState::Embed { host, lock } => {
                    *host = None;
                    *lock = None;
                    true
                }
                ModeState::Supervise {
                    child: c,
                    drain_tasks,
                    kill_on_drop: k,
                    ..
                } => {
                    drains = std::mem::take(drain_tasks);
                    child = c.take();
                    *k
                }
                ModeState::Composed(c) => {
                    c.clear_session();
                    composed = c.take_runtime();
                    true
                }
            }
        };
        for t in drains {
            t.abort();
        }
        if let Some(mut c) = child {
            if force {
                // Signal before the helper-thread wait so a spawn failure
                // cannot skip start_kill (SpawnGuard already does this).
                let _ = c.start_kill();
                runtime_rt::block_on_global_best_effort(async move {
                    let _ = tokio::time::timeout(STOP_GRACE, c.wait()).await;
                    let _ = c.start_kill();
                    let _ = tokio::time::timeout(STOP_GRACE, c.wait()).await;
                });
            } else {
                // Keep-available: do not kill; reap on GLOBAL_RT so the pid is not a zombie.
                drop(runtime_rt::global_rt().spawn(async move {
                    let _ = c.wait().await;
                }));
            }
        }
        if let Some(rt) = composed {
            runtime_rt::block_on_global_best_effort(async move {
                rt.shutdown_handle().trigger();
                rt.wait().await;
            });
        }
        // Plan T30: detach releases the process-local reservation.
        if self.reserved.swap(false, Ordering::SeqCst) {
            registry::release(&self.workspace);
        }
    }
}

fn stop_inner(inner: &Arc<BridgeInner>, force_reap: bool) -> Result<(), BridgeError> {
    if inner.stopped.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let inner_for_reset = Arc::clone(inner);
    let inner = Arc::clone(inner);
    let result = runtime_rt::block_on_global(async move { teardown(inner, force_reap).await });
    if result.is_err() {
        inner_for_reset.stopped.store(false, Ordering::SeqCst);
    }
    result
}

async fn stop_inner_async(inner: &Arc<BridgeInner>, force_reap: bool) -> Result<(), BridgeError> {
    if inner.stopped.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let inner_for_reset = Arc::clone(inner);
    let inner = Arc::clone(inner);
    let result = teardown(inner, force_reap).await;
    if result.is_err() {
        inner_for_reset.stopped.store(false, Ordering::SeqCst);
    }
    result
}

async fn teardown(inner: Arc<BridgeInner>, force_reap: bool) -> Result<(), BridgeError> {
    enum Pending {
        Embed,
        Reap(Child),
        Detach(Child),
        Composed(Option<Arc<ComposedRuntime>>),
        None,
    }
    let mut drains: Vec<JoinHandle<()>> = Vec::new();
    let pending = {
        let mut mode = inner
            .mode
            .lock()
            .map_err(|_| BridgeError::Internal("mode lock".into()))?;
        match &mut *mode {
            ModeState::Embed { host, lock } => {
                *host = None;
                *lock = None;
                Pending::Embed
            }
            ModeState::Supervise {
                child,
                drain_tasks,
                kill_on_drop,
                ..
            } => {
                drains = std::mem::take(drain_tasks);
                let c = child.take();
                if force_reap || *kill_on_drop {
                    c.map(Pending::Reap).unwrap_or(Pending::None)
                } else {
                    c.map(Pending::Detach).unwrap_or(Pending::None)
                }
            }
            ModeState::Composed(c) => {
                c.clear_session();
                Pending::Composed(c.take_runtime())
            }
        }
    };
    for t in drains {
        t.abort();
    }
    match pending {
        Pending::Reap(mut c) => {
            let _ = c.start_kill();
            let _ = tokio::time::timeout(STOP_GRACE, c.wait()).await;
            let _ = c.start_kill();
            let _ = tokio::time::timeout(STOP_GRACE, c.wait()).await;
        }
        Pending::Detach(mut c) => {
            // Keep-available detach: no kill; background wait reaps the pid.
            drop(tokio::spawn(async move {
                let _ = c.wait().await;
            }));
        }
        Pending::Composed(Some(rt)) => {
            rt.shutdown_handle().trigger();
            rt.wait().await;
        }
        Pending::Embed | Pending::None | Pending::Composed(None) => {}
    }
    // Always release: explicit stop reaps; detach is plan T30 (registry free).
    if inner.reserved.swap(false, Ordering::SeqCst) {
        registry::release(&inner.workspace);
    }
    Ok(())
}

/// Initial lifecycle default.
pub fn default_lifecycle() -> BridgeLifecycleInput {
    BridgeLifecycleInput {
        state: PlatformLifecycleState::Foreground,
        battery_pct: None,
        network_class: None,
    }
}
