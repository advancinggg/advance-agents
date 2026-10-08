//! A composed runtime, and how it is stopped.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::error::ComposeError;
use super::extension::{ExtensionHealth, ExtensionState};
use super::options::{ComposeProfile, ProcessPolicy, WasmEngine};
use crate::composition::RuntimeView;

/// A running composition. It owns nothing of the runtime itself: the runtime's parts
/// are owned by the composition's shutdown task, which stops them all in order once
/// a [`ShutdownHandle`] is triggered (or this value is dropped).
pub struct ComposedRuntime {
    view: Arc<RuntimeView>,
    shutdown: ShutdownHandle,
    done: watch::Receiver<bool>,
    supervisor: Option<JoinHandle<()>>,
}

impl ComposedRuntime {
    pub(crate) fn new(
        view: Arc<RuntimeView>,
        shutdown: ShutdownHandle,
        done: watch::Receiver<bool>,
        supervisor: JoinHandle<()>,
    ) -> Self {
        Self {
            view,
            shutdown,
            done,
            supervisor: Some(supervisor),
        }
    }

    /// The Client API this composition serves: `None` when none is bound, and from the
    /// moment the shutdown is triggered. It holds the API only weakly. After a rebind
    /// the endpoint follows the listener (`RuntimeView::client_api_endpoint`).
    pub fn client_api(&self) -> Option<ClientApiEndpoint> {
        if self.shutdown.is_triggered() {
            return None;
        }
        self.view.client_api_endpoint()
    }

    /// ADR 2026-10-03 D3: probe the Client API listener (a host calls this when its
    /// app returns to the foreground) and, when it does not answer, rebind the same
    /// `ClientApi`, previous port first. Bounded (about 2 s). Runs on the runtime
    /// that composed, whatever runtime polls this future; serialised with shutdown
    /// step 1.
    pub async fn reverify_client_api(&self) -> Result<ClientApiCheck, ClientApiRebindError> {
        let ing = self
            .view
            .client_ingress()
            .ok_or(ClientApiRebindError::NotComposed)?;
        if ing.admission() != crate::api::Admission::InProcessOnly {
            return Err(ClientApiRebindError::NotInProcessAdmission);
        }
        if self.shutdown.is_triggered() {
            return Err(ClientApiRebindError::ShuttingDown);
        }
        let join = ing
            .runtime()
            .spawn(std::sync::Arc::clone(ing).reverify_body());
        match join.await {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(ClientApiRebindError::ShuttingDown),
        }
    }

    /// Close the listener as if the OS had reclaimed its socket (the endpoint keeps
    /// naming the old base until the next re-verification). `None` without a listener
    /// or once shutdown step 1 ran.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub async fn sever_client_api_listener_for_test(&self) -> Option<SocketAddr> {
        let ing = self.view.client_ingress()?;
        ing.sever_for_test().await
    }

    /// The next probe reports "no answer" although the listener is up.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn fail_next_client_api_probe_for_test(&self) {
        if let Some(ing) = self.view.client_ingress() {
            ing.fail_next_probe();
        }
    }

    /// The next rebind fails both binds.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn fail_next_client_api_rebind_for_test(&self) {
        if let Some(ing) = self.view.client_ingress() {
            ing.fail_next_rebind();
        }
    }

    /// The next re-verification parks after its shutdown pre-check and before it
    /// takes the ingress lock (`reached` is notified, then it awaits `resume`).
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn pause_next_client_api_reverify_for_test(
        &self,
    ) -> Option<crate::test_support::ReverifyPause> {
        self.view.client_ingress().map(|ing| ing.arm_pause())
    }

    /// The root agent's immutable id.
    pub fn root_agent_id(&self) -> &str {
        self.view.root_agent_id()
    }

    pub fn health(&self) -> RuntimeHealthView {
        let phase = match self.view.phase() {
            RuntimePhase::Running if self.shutdown.is_triggered() => RuntimePhase::ShuttingDown,
            phase => phase,
        };
        let running = phase == RuntimePhase::Running;
        let extensions = self.view.extensions();
        let failed_extensions = extensions
            .iter()
            .filter(|health| matches!(health.state, ExtensionState::Failed(_)))
            .map(|health| health.id)
            .collect();
        RuntimeHealthView {
            phase,
            agent_loop_up: running && self.view.agent_loop_alive(),
            client_api_base: self.client_api().map(|endpoint| endpoint.base_url),
            instance_guard: self.view.instance_guard(),
            profile: self.view.profile(),
            processes: self.view.processes(),
            wasm_engine: self.view.wasm_engine(),
            extensions,
            failed_extensions,
        }
    }

    /// A handle that starts the shutdown; it can be cloned and kept anywhere.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown.clone()
    }

    /// Resolves once the shutdown sequence has completed.
    pub async fn wait(&self) {
        let mut done = self.done.clone();
        let _ = done.wait_for(|done| *done).await;
    }

    /// Start the shutdown (if it has not started) and wait until it has completed: no
    /// task of this composition is left afterwards. A panic of the shutdown task is
    /// resumed here.
    pub async fn shutdown(mut self) -> Result<(), ComposeError> {
        self.shutdown.trigger();
        if let Some(supervisor) = self.supervisor.take() {
            if let Err(error) = supervisor.await {
                if error.is_panic() {
                    std::panic::resume_unwind(error.into_panic());
                }
                // Cancelled: the runtime it ran on is shutting down.
            }
        }
        Ok(())
    }
}

/// Dropping the runtime starts its shutdown; the sequence still runs to its end on the
/// runtime the composition was made on. A host that composes the same home again must
/// first await [`ComposedRuntime::shutdown`] or [`ComposedRuntime::wait`].
impl Drop for ComposedRuntime {
    fn drop(&mut self) {
        self.shutdown.trigger();
    }
}

impl fmt::Debug for ComposedRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComposedRuntime")
            .field("root_agent_id", &self.view.root_agent_id())
            .field("phase", &self.view.phase())
            .field("shutdown", &self.shutdown)
            .finish_non_exhaustive()
    }
}

/// What [`ComposedRuntime::reverify_client_api`] found (ADR 2026-10-03 D3 foreground
/// re-verification).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientApiCheck {
    /// The listener answered its own probe; nothing changed.
    Healthy,
    /// The listener did not answer and was bound again on its previous port, on the
    /// same `ClientApi`: the base and every session are unchanged.
    Rebound { addr: SocketAddr },
    /// The previous port could not be bound again; the same `ClientApi` now listens
    /// on a new port. The base changed. The caller mints a new session and revokes
    /// the old ones (`api.sessions().revoke_all()`); the CONTRACT-210 bridge does
    /// this itself.
    Moved {
        previous: SocketAddr,
        current: SocketAddr,
    },
}

/// Why [`ComposedRuntime::reverify_client_api`] did not complete a check or rebind.
#[non_exhaustive]
#[derive(Debug)]
pub enum ClientApiRebindError {
    /// No Client API was composed (`ClientApiOptions::Off`, or a same-user bind that
    /// failed at boot).
    NotComposed,
    /// Re-verification is offered for `Admission::InProcessOnly` only: a same-user
    /// daemon's discovery file and console origin name its port, so its listener is
    /// never moved.
    NotInProcessAdmission,
    /// Shutdown has started (checked again after the ingress lock is taken).
    ShuttingDown,
    /// Neither the previous port nor a new one could be bound. The Client API stays
    /// unbound until a later `reverify_client_api` succeeds; `client_api()` answers
    /// `None` meanwhile.
    Bind {
        previous: SocketAddr,
        error: std::io::Error,
    },
}

impl fmt::Display for ClientApiRebindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotComposed => write!(f, "no Client API was composed"),
            Self::NotInProcessAdmission => write!(
                f,
                "the Client API listener is rebound only under in-process admission"
            ),
            Self::ShuttingDown => write!(f, "the runtime is shutting down"),
            Self::Bind { previous, error } => write!(
                f,
                "Client API listener could not be bound again (previous {previous}): {error}"
            ),
        }
    }
}

impl std::error::Error for ClientApiRebindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Where the composition's Client API listens.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ClientApiEndpoint {
    /// `http://127.0.0.1:<port>`.
    pub base_url: String,
    pub socket_addr: SocketAddr,
    /// The API itself, held weakly: it dies with the composition.
    pub api: Weak<advance_client_api::ClientApi>,
}

/// A snapshot of a composed runtime's state.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeHealthView {
    pub phase: RuntimePhase,
    /// The root agent's serve loop is running (always `false` once the shutdown started,
    /// and on a home without a deployed driver).
    pub agent_loop_up: bool,
    pub client_api_base: Option<String>,
    /// The instance guard in use.
    pub instance_guard: InstanceGuardKind,
    /// The composed profile (T113 (1) reads the row on the running composition).
    pub profile: ComposeProfile,
    /// The policy every spawn site of this composition received.
    pub processes: ProcessPolicy,
    /// The code both Wasmtime engines emit, read back from them: `Pulley` iff both target pulley64.
    pub wasm_engine: WasmEngine,
    /// Every composed extension, in registration order.
    pub extensions: Vec<ExtensionHealth>,
    /// Extensions whose start failed.
    pub failed_extensions: Vec<&'static str>,
}

/// Where a composed runtime is in its life.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimePhase {
    Running,
    ShuttingDown,
    Stopped,
}

/// Which instance guard a composition holds.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceGuardKind {
    PidLockFile,
    ProcessLocal,
}

/// Starts a composition's shutdown. Cloneable; triggering is idempotent. It holds only
/// a cancellation token, never the runtime.
#[derive(Clone)]
pub struct ShutdownHandle {
    shared: Arc<ShutdownShared>,
}

struct ShutdownShared {
    started: AtomicBool,
    token: CancellationToken,
    route_gate: advance_client_api::ExtensionRouteGate,
}

impl ShutdownHandle {
    pub(crate) fn new(route_gate: advance_client_api::ExtensionRouteGate) -> Self {
        Self {
            shared: Arc::new(ShutdownShared {
                started: AtomicBool::new(false),
                token: CancellationToken::new(),
                route_gate,
            }),
        }
    }

    /// Start the shutdown. `true` only for the call that started it.
    /// Closes the extension route gate first, then swaps the started flag and cancels the token.
    pub fn trigger(&self) -> bool {
        self.shared.route_gate.close();
        let first = !self.shared.started.swap(true, Ordering::AcqRel);
        self.shared.token.cancel();
        first
    }

    /// Whether the shutdown has been started.
    pub fn is_triggered(&self) -> bool {
        self.shared.started.load(Ordering::Acquire)
    }

    /// Cancelled once the shutdown is triggered.
    pub(crate) fn token(&self) -> CancellationToken {
        self.shared.token.clone()
    }
}

impl fmt::Debug for ShutdownHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShutdownHandle")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the first trigger, through any clone, starts the shutdown.
    #[test]
    fn module_001_ac30_shutdown_handle_trigger_is_idempotent_across_clones() {
        let first = ShutdownHandle::new(advance_client_api::ExtensionRouteGate::new());
        let second = first.clone();
        let token = first.token();
        assert!(!first.is_triggered() && !second.is_triggered());
        assert!(!token.is_cancelled());
        assert!(second.trigger());
        assert!(!first.trigger());
        assert!(!second.trigger());
        assert!(first.is_triggered() && second.is_triggered());
        assert!(token.is_cancelled());
        assert_eq!(format!("{first:?}"), "ShutdownHandle { triggered: true }");
    }
}
