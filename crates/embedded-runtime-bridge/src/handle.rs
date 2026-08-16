//! BridgeHandle = Arc<BridgeInner> with stop/detach Drop policy.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::RuntimeHost;
use tokio::process::Child;
use tokio::task::JoinHandle;

use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::lock_status;
use crate::profile::{build_profile, uses_runtime_lock};
use crate::registry;
use crate::runtime_rt;
use crate::types::{
    BridgeHealth, BridgeLifecycleInput, CompositionMode, LockExclusivity, PlatformLifecycleState,
    SuperviseReadiness, HEALTH_SCHEMA_VERSION,
};

const STOP_GRACE: Duration = Duration::from_secs(5);

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
}

pub(crate) struct BridgeInner {
    pub workspace: PathBuf,
    pub config: BridgeConfig,
    pub lifecycle: Mutex<BridgeLifecycleInput>,
    pub mode: Mutex<ModeState>,
    pub stopped: AtomicBool,
    pub reserved: AtomicBool,
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

impl BridgeHandle {
    pub(crate) fn new(inner: Arc<BridgeInner>) -> Self {
        Self { inner }
    }

    pub fn stop(self) -> Result<(), BridgeError> {
        stop_inner(&self.inner, /*force_reap*/ true)
    }

    pub fn health(&self) -> Result<BridgeHealth, BridgeError> {
        if self.inner.stopped.load(Ordering::SeqCst) {
            // Still valid until drop if stop was called but handle lives.
        }
        let lifecycle = self
            .inner
            .lifecycle
            .lock()
            .map_err(|_| BridgeError::Internal("lifecycle lock".into()))?
            .clone();
        let (runtime_up, last_hb, readiness, lock_excl) = {
            let mut mode = self
                .inner
                .mode
                .lock()
                .map_err(|_| BridgeError::Internal("mode lock".into()))?;
            match &mut *mode {
                ModeState::Embed { host, lock } => {
                    let up = host.is_some() && !self.inner.stopped.load(Ordering::SeqCst);
                    let hb = if lock.is_some() && uses_runtime_lock() {
                        lock_status::embed_lock_heartbeat_ok(&self.inner.workspace)
                    } else {
                        up
                    };
                    let excl = if uses_runtime_lock() {
                        LockExclusivity::RuntimeLock
                    } else {
                        LockExclusivity::ProcessLocal
                    };
                    (up, hb, None, excl)
                }
                ModeState::Supervise {
                    child,
                    readiness,
                    ..
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
                    (up, up, Some(*readiness), LockExclusivity::ProcessLocal)
                }
            }
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
        let mut g = self
            .inner
            .lifecycle
            .lock()
            .map_err(|_| BridgeError::Internal("lifecycle lock".into()))?;
        *g = input;
        Ok(())
    }
}

impl Drop for BridgeHandle {
    fn drop(&mut self) {
        // Only act when last Arc drops.
        if Arc::strong_count(&self.inner) > 1 {
            return;
        }
        let kill_on_drop = match &*self.inner.mode.lock().unwrap_or_else(|e| e.into_inner()) {
            ModeState::Embed { .. } => true,
            ModeState::Supervise { kill_on_drop, .. } => *kill_on_drop,
        };
        let _ = stop_inner(&self.inner, kill_on_drop);
    }
}

fn stop_inner(inner: &Arc<BridgeInner>, force_reap: bool) -> Result<(), BridgeError> {
    // Idempotent mark.
    let already = inner.stopped.swap(true, Ordering::SeqCst);
    if already && force_reap {
        // Already stopped; still Ok.
        return Ok(());
    }
    if already && !force_reap {
        return Ok(());
    }

    let inner = Arc::clone(inner);
    runtime_rt::block_on_global(async move {
        // Extract resources under the mutex, then await without holding the guard.
        enum Pending {
            Embed,
            Reap(Child),
            Detach(Child),
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
            Pending::Detach(_c) => {
                // Drop without kill (keep-available).
            }
            Pending::Embed | Pending::None => {}
        }
        if inner.reserved.swap(false, Ordering::SeqCst) {
            registry::release(&inner.workspace);
        }
        Ok(())
    })
}

/// Initial lifecycle default.
pub fn default_lifecycle() -> BridgeLifecycleInput {
    BridgeLifecycleInput {
        state: PlatformLifecycleState::Foreground,
        battery_pct: None,
        network_class: None,
    }
}
