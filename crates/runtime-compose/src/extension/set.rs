//! The composed set of extensions, their contexts, tasks and shutdown.

use std::collections::HashSet;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use advance_client_api::clock::{Clock, SystemClock};
use advance_runtime::config::RuntimeConfigWatcher;
use advance_shared_types::traits::{EventBusEmit, GrantCheck, LeakDetector};
use futures::FutureExt;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::api::{
    log_keys, ComposeCx, ComposeError, ComposeExtension, ComposeProfile, ConfigView,
    ExtensionEmitter, ExtensionFailure, ExtensionGrantCheck, ExtensionHealth, ExtensionPhase,
    ExtensionSecrets, ExtensionState, GatewayHandle, ProcessPolicy, RunView, StartedCx,
    TaskSpawner, ViewError,
};
use crate::compose_log::LogHandle;
use crate::composition::StepLog;
use crate::effective_capabilities::EffectiveCapabilities;
use crate::extension::capabilities::{check_names, check_total, Declaration};
use crate::extension::guard::{call_guarded, call_guarded_async, CallOutcome};
use crate::extension::ids::check_extension_id;

/// Budget of the extension-task join after cancellation.
pub const EXTENSION_TASKS_JOIN_BOUND: Duration = Duration::from_secs(5);

/// Shared revocation bit: every view answers ShutDown / Deny / None once set.
#[derive(Clone)]
pub(crate) struct Revocation(Arc<AtomicBool>);

impl Revocation {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn revoked() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    pub(crate) fn revoke(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub(crate) struct TaskShared {
    tracker: TaskTracker,
    cancel: CancellationToken,
    closed: Mutex<bool>,
    handle: Option<Handle>,
    log: LogHandle,
}

impl TaskShared {
    fn new(handle: Option<Handle>, log: LogHandle) -> Arc<Self> {
        Arc::new(Self {
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
            closed: Mutex::new(false),
            handle,
            log,
        })
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn dead() -> Arc<Self> {
        Arc::new(Self {
            tracker: TaskTracker::new(),
            cancel: CancellationToken::new(),
            closed: Mutex::new(true),
            handle: None,
            log: LogHandle::null(),
        })
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancel.child_token()
    }

    pub(crate) fn spawn_wrapped(
        &self,
        extension: &'static str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ViewError> {
        let closed = self.closed.lock().unwrap_or_else(PoisonError::into_inner);
        if *closed {
            return Err(ViewError::ShutDown);
        }
        let Some(handle) = self.handle.as_ref() else {
            return Err(ViewError::ShutDown);
        };
        let (cancel, log) = (self.cancel.clone(), self.log.clone());
        self.tracker.spawn_on(
            async move {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {}
                    r = AssertUnwindSafe(fut).catch_unwind() => {
                        if r.is_err() {
                            log.err(
                                log_keys::EXT_TASK_PANICKED,
                                format!(
                                    "advance: WARN extension {extension} task panicked; task ended"
                                ),
                            );
                        }
                    }
                }
            },
            handle,
        );
        drop(closed);
        Ok(())
    }
}

struct Entry {
    ext: Arc<dyn ComposeExtension>,
    id: &'static str,
    capabilities: &'static [&'static str],
    needs_secret_store: bool,
}

/// The composed set of extensions.
pub struct ExtensionSet {
    entries: Vec<Entry>,
    board: Arc<ExtensionBoard>,
    tasks: Arc<TaskShared>,
    revoked: Revocation,
    contexts: OnceLock<Vec<ComposeCx>>,
    clock: Arc<dyn Clock>,
    log: LogHandle,
    plan: ExtensionPlan,
    secret_need: bool,
    capabilities: EffectiveCapabilities,
    route_gate: advance_client_api::ExtensionRouteGate,
}

/// Home / profile / process policy captured at prepare.
pub struct ExtensionPlan {
    pub home: Arc<Path>,
    pub profile: ComposeProfile,
    pub processes: ProcessPolicy,
}

/// Weak handles `install_contexts` wires into each [`ComposeCx`].
pub struct CxParts {
    pub config: Weak<RuntimeConfigWatcher>,
    pub event_bus: Weak<dyn EventBusEmit>,
    pub run_manager: Weak<advance_run_manager::RunManager>,
    pub grant_check: Weak<dyn GrantCheck>,
    pub secret_store: Option<Weak<cap_secrets::SecretStore>>,
    pub leak_detector: Arc<dyn LeakDetector>,
}

/// What exists once the runtime is up, for `on_started`.
pub struct StartedParts {
    pub gateway: Option<Weak<cap_llm::LlmGateway>>,
    pub client_api_base: Option<String>,
    pub client_api_addr: Option<std::net::SocketAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretPlan {
    NotNeeded,
    ReuseOss,
    BuildForExtensions,
}

/// Owner decision for a declared secret need on a store-less home.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretNeedRule {
    FailCompose,
    NoView,
    BuildOnNeed,
}

pub const SECRET_NEED_RULE: SecretNeedRule = SecretNeedRule::BuildOnNeed;

/// Per-extension start state, registration order.
pub struct ExtensionBoard {
    states: Vec<(&'static str, Mutex<ExtensionState>)>,
}

impl ExtensionBoard {
    fn starting(ids: &[&'static str]) -> Arc<Self> {
        Arc::new(Self {
            states: ids
                .iter()
                .map(|id| (*id, Mutex::new(ExtensionState::Starting)))
                .collect(),
        })
    }

    pub fn snapshot(&self) -> Vec<ExtensionHealth> {
        self.states
            .iter()
            .map(|(id, state)| ExtensionHealth {
                id: *id,
                state: state.lock().unwrap_or_else(PoisonError::into_inner).clone(),
            })
            .collect()
    }

    pub(crate) fn set(&self, id: &str, s: ExtensionState) {
        if let Some((_, state)) = self.states.iter().find(|(entry, _)| *entry == id) {
            *state.lock().unwrap_or_else(PoisonError::into_inner) = s;
        }
    }
}

impl ExtensionSet {
    /// `WiringOptions::compat()` and `Composition::early()`: no entries,
    /// `LogHandle::null()`, handle `None`.
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            entries: Vec::new(),
            board: ExtensionBoard::starting(&[]),
            tasks: TaskShared::new(None, LogHandle::null()),
            revoked: Revocation::new(),
            contexts: OnceLock::new(),
            clock: Arc::new(SystemClock),
            log: LogHandle::null(),
            plan: ExtensionPlan {
                home: Arc::from(Path::new("")),
                profile: ComposeProfile::Daemon,
                processes: ProcessPolicy::Allow,
            },
            secret_need: false,
            capabilities: EffectiveCapabilities::default(),
            route_gate: advance_client_api::ExtensionRouteGate::new(),
        })
    }

    /// Compose's declaration step. No side effect besides calling the declaration methods.
    pub fn prepare(
        exts: Vec<Arc<dyn ComposeExtension>>,
        plan: ExtensionPlan,
        log: LogHandle,
    ) -> Result<Arc<Self>, ComposeError> {
        let handle = Handle::try_current().ok();
        let mut entries = Vec::with_capacity(exts.len());
        let mut declarations: Vec<Declaration> = Vec::with_capacity(exts.len());
        let mut seen = HashSet::new();
        let mut secret_need = false;
        for ext in exts {
            let id = match call_guarded(|| Ok(ext.id())) {
                CallOutcome::Ok(id) => id,
                CallOutcome::Failed(_) => unreachable!("id() is infallible"),
                CallOutcome::Panicked(message) => {
                    return Err(ComposeError::Extension {
                        extension: "<unknown>",
                        phase: ExtensionPhase::Capabilities,
                        failure: ExtensionFailure::Panicked(message),
                    });
                }
            };
            if let Err(reason) = check_extension_id(id) {
                return Err(ComposeError::Extension {
                    extension: id,
                    phase: ExtensionPhase::Capabilities,
                    failure: ExtensionFailure::Failed(format!(
                        "invalid extension id {id:?}: {reason}"
                    )),
                });
            }
            if !seen.insert(id) {
                return Err(ComposeError::Extension {
                    extension: id,
                    phase: ExtensionPhase::Capabilities,
                    failure: ExtensionFailure::Failed(format!(
                        "extension id {id:?} is used by an earlier extension"
                    )),
                });
            }
            let capabilities = match call_guarded(|| Ok(ext.capabilities())) {
                CallOutcome::Ok(capabilities) => capabilities,
                CallOutcome::Failed(_) => unreachable!("capabilities() is infallible"),
                CallOutcome::Panicked(message) => {
                    return Err(ComposeError::Extension {
                        extension: id,
                        phase: ExtensionPhase::Capabilities,
                        failure: ExtensionFailure::Panicked(message),
                    });
                }
            };
            check_names(&declarations, id, capabilities)?;
            let needs_secret_store = match call_guarded(|| Ok(ext.needs_secret_store())) {
                CallOutcome::Ok(need) => need,
                CallOutcome::Failed(_) => unreachable!("needs_secret_store() is infallible"),
                CallOutcome::Panicked(message) => {
                    return Err(ComposeError::Extension {
                        extension: id,
                        phase: ExtensionPhase::Capabilities,
                        failure: ExtensionFailure::Panicked(message),
                    });
                }
            };
            secret_need |= needs_secret_store;
            declarations.push((id, capabilities));
            entries.push(Entry {
                ext,
                id,
                capabilities,
                needs_secret_store,
            });
        }
        check_total(&declarations)?;
        let ids: Vec<&'static str> = entries.iter().map(|entry| entry.id).collect();
        let tasks = TaskShared::new(handle, log.clone());
        Ok(Arc::new(Self {
            entries,
            board: ExtensionBoard::starting(&ids),
            tasks,
            revoked: Revocation::new(),
            contexts: OnceLock::new(),
            clock: Arc::new(SystemClock),
            log,
            plan,
            secret_need,
            capabilities: EffectiveCapabilities::from_extension_entries(&declarations),
            route_gate: advance_client_api::ExtensionRouteGate::new(),
        }))
    }

    /// Known ∪ the composition's extension capabilities.
    pub fn effective_capabilities(&self) -> &EffectiveCapabilities {
        &self.capabilities
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.id).collect()
    }

    pub fn capabilities_of(&self, id: &str) -> &'static [&'static str] {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.capabilities)
            .unwrap_or(&[])
    }

    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    pub fn route_gate(&self) -> &advance_client_api::ExtensionRouteGate {
        &self.route_gate
    }

    pub fn secret_plan(&self, oss_store: bool) -> Result<SecretPlan, ComposeError> {
        secret_plan_with(
            SECRET_NEED_RULE,
            self.secret_need,
            oss_store,
            self.first_secret_needer(),
        )
    }

    fn first_secret_needer(&self) -> &'static str {
        self.entries
            .iter()
            .find(|entry| entry.needs_secret_store)
            .map(|entry| entry.id)
            .unwrap_or("")
    }

    pub fn install_contexts(&self, parts: CxParts) {
        if self.entries.is_empty() {
            return;
        }
        let contexts: Vec<ComposeCx> = self
            .entries
            .iter()
            .map(|entry| self.compose_cx(entry, &parts))
            .collect();
        if self.contexts.set(contexts).is_err() {
            debug_assert!(false, "install_contexts called twice");
        }
    }

    fn compose_cx(&self, entry: &Entry, parts: &CxParts) -> ComposeCx {
        let gate = self.revoked.clone();
        let clock = Arc::clone(&self.clock);
        let secrets = if entry.needs_secret_store {
            parts
                .secret_store
                .clone()
                .map(|store| ExtensionSecrets::new(entry.id, store, gate.clone()))
        } else {
            None
        };
        ComposeCx::new(
            entry.id,
            Arc::clone(&self.plan.home),
            self.plan.profile,
            self.plan.processes,
            clock.clone(),
            Arc::clone(&parts.leak_detector),
            ConfigView::new(parts.config.clone(), gate.clone()),
            TaskSpawner::new(entry.id, Arc::clone(&self.tasks)),
            ExtensionEmitter::new(entry.id, parts.event_bus.clone(), clock, gate.clone()),
            RunView::new(parts.run_manager.clone(), gate.clone()),
            ExtensionGrantCheck::new(entry.id, parts.grant_check.clone(), gate),
            secrets,
        )
    }

    pub fn iter_with_cx(
        &self,
    ) -> Result<
        impl Iterator<Item = (&'static str, &Arc<dyn ComposeExtension>, &ComposeCx)> + '_,
        ComposeError,
    > {
        debug_assert!(
            self.entries.is_empty() || self.contexts.get().is_some(),
            "extension contexts not installed"
        );
        self.try_iter_with_cx()
    }

    pub(crate) fn try_iter_with_cx(
        &self,
    ) -> Result<
        impl Iterator<Item = (&'static str, &Arc<dyn ComposeExtension>, &ComposeCx)> + '_,
        ComposeError,
    > {
        let empty: &[ComposeCx] = &[];
        let contexts = if self.entries.is_empty() {
            empty
        } else {
            self.contexts
                .get()
                .ok_or_else(|| ComposeError::Wiring("extension contexts not installed".into()))?
        };
        Ok(self
            .entries
            .iter()
            .zip(contexts.iter())
            .map(|(entry, cx)| (entry.id, &entry.ext, cx)))
    }

    pub fn spawn_on_started(&self, parts: StartedParts) {
        let Some(contexts) = self.contexts.get() else {
            debug_assert!(self.entries.is_empty());
            return;
        };
        for (entry, cx) in self.entries.iter().zip(contexts.iter()) {
            let started = StartedCx::new(
                cx.clone(),
                parts
                    .gateway
                    .clone()
                    .map(|gateway| GatewayHandle::new(gateway, self.revoked.clone())),
                parts.client_api_base.clone(),
                parts.client_api_addr,
            );
            let ext = Arc::clone(&entry.ext);
            let id = entry.id;
            let board = Arc::clone(&self.board);
            let log = self.log.clone();
            let fut = async move {
                match call_guarded_async(|| ext.on_started(&started)).await {
                    CallOutcome::Ok(()) => board.set(id, ExtensionState::Started),
                    CallOutcome::Failed(error) => {
                        let message = crate::extension::guard::sanitize_text(error.message());
                        log.err(
                            log_keys::EXT_ON_STARTED_FAILED,
                            format!("advance: WARN extension {id} on_started failed: {message}"),
                        );
                        board.set(
                            id,
                            ExtensionState::Failed(ExtensionFailure::Failed(message)),
                        );
                    }
                    CallOutcome::Panicked(message) => {
                        log.err(
                            log_keys::EXT_ON_STARTED_PANICKED,
                            format!(
                                "advance: WARN extension {id} on_started panicked; extension marked failed"
                            ),
                        );
                        board.set(
                            id,
                            ExtensionState::Failed(ExtensionFailure::Panicked(message)),
                        );
                    }
                }
            };
            let _ = self.tasks.spawn_wrapped(id, fut);
        }
    }

    pub fn board(&self) -> Arc<ExtensionBoard> {
        Arc::clone(&self.board)
    }

    pub(crate) async fn run_shutdown_hooks(&self, steps: &StepLog) {
        if self.entries.is_empty() {
            return;
        }
        for entry in self.entries.iter().rev() {
            let id = entry.id;
            let finished = match std::panic::catch_unwind(AssertUnwindSafe(|| entry.ext.shutdown()))
            {
                Ok(hook) => tokio::time::timeout(
                    crate::composition::EXTENSION_SHUTDOWN_BOUND,
                    AssertUnwindSafe(hook).catch_unwind(),
                )
                .await
                .map(|outcome| outcome.is_ok()),
                Err(_panic) => Ok(false),
            };
            match finished {
                Ok(true) => {}
                Ok(false) => self.log.err(
                    log_keys::EXT_SHUTDOWN_PANICKED,
                    format!("advance: WARN extension {id} shutdown hook panicked; continuing"),
                ),
                Err(_elapsed) => self.log.err(
                    log_keys::EXT_SHUTDOWN_ABANDONED,
                    format!(
                        "advance: WARN extension {id} shutdown hook did not finish within {}s; abandoned",
                        crate::composition::EXTENSION_SHUTDOWN_BOUND.as_secs()
                    ),
                ),
            }
        }
        steps.record("extensions.hooks");
    }

    pub(crate) async fn cancel_and_join_tasks(&self, steps: &StepLog) {
        let had = {
            let mut closed = self
                .tasks
                .closed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *closed = true;
            !self.tasks.tracker.is_empty()
        };
        self.tasks.tracker.close();
        self.tasks.cancel.cancel();
        if tokio::time::timeout(EXTENSION_TASKS_JOIN_BOUND, self.tasks.tracker.wait())
            .await
            .is_err()
        {
            let n = self.tasks.tracker.len();
            self.log.err(
                log_keys::EXT_TASKS_ABANDONED,
                format!(
                    "advance: WARN {n} extension task(s) still running 5s after cancellation; abandoned"
                ),
            );
        }
        if had {
            steps.record("extensions.tasks");
        }
    }

    pub fn revoke(&self) {
        self.revoked.revoke();
    }

    #[cfg(test)]
    fn spawn_unwrapped_for_test(&self, fut: impl Future<Output = ()> + Send + 'static) {
        let handle = self
            .tasks
            .handle
            .as_ref()
            .expect("prepare captured a runtime handle");
        self.tasks.tracker.spawn_on(fut, handle);
    }
}

pub(crate) fn secret_plan_with(
    rule: SecretNeedRule,
    need: bool,
    oss_store: bool,
    first: &'static str,
) -> Result<SecretPlan, ComposeError> {
    if !need {
        return Ok(SecretPlan::NotNeeded);
    }
    if oss_store {
        return Ok(SecretPlan::ReuseOss);
    }
    match rule {
        SecretNeedRule::BuildOnNeed => Ok(SecretPlan::BuildForExtensions),
        SecretNeedRule::NoView => Ok(SecretPlan::NotNeeded),
        SecretNeedRule::FailCompose => Err(ComposeError::Extension {
            extension: first,
            phase: ExtensionPhase::Capabilities,
            failure: ExtensionFailure::Failed(
                "needs a secret store, but the home declares neither `secrets` nor `llm`".into(),
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{BoxFuture, ComposeLogLine, EmitError, LogStream, SecretViewError};
    use crate::test_support::MemoryComposeLog;
    use advance_event_bus::{taxonomy, EventBus, EventBusConfig};
    use advance_shared_types::event::Event;
    use advance_shared_types::traits::{EventBusEmit, GrantCheck};
    use cap_secrets::{InMemorySecretStorage, SecretStore};
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex as StdMutex;
    use tokio::time::Instant;
    use zeroize::Zeroizing;

    struct Fake {
        id: &'static str,
        caps: &'static [&'static str],
        need: bool,
        panic_id: bool,
        panic_caps: bool,
        panic_need: bool,
        caps_calls: AtomicUsize,
    }

    impl Fake {
        fn new(id: &'static str) -> Self {
            Self {
                id,
                caps: &[],
                need: false,
                panic_id: false,
                panic_caps: false,
                panic_need: false,
                caps_calls: AtomicUsize::new(0),
            }
        }
    }

    impl ComposeExtension for Fake {
        fn id(&self) -> &'static str {
            if self.panic_id {
                panic!("id panic");
            }
            self.id
        }

        fn capabilities(&self) -> &'static [&'static str] {
            self.caps_calls.fetch_add(1, AtomicOrdering::SeqCst);
            if self.panic_caps {
                panic!("caps panic");
            }
            self.caps
        }

        fn needs_secret_store(&self) -> bool {
            if self.panic_need {
                panic!("need panic");
            }
            self.need
        }
    }

    fn plan() -> ExtensionPlan {
        ExtensionPlan {
            home: Arc::from(Path::new("/tmp")),
            profile: ComposeProfile::Daemon,
            processes: ProcessPolicy::Allow,
        }
    }

    fn dummy_parts() -> CxParts {
        struct NopEmit;
        impl EventBusEmit for NopEmit {
            fn emit(&self, _: Event) {}
        }
        struct NopGrant;
        impl GrantCheck for NopGrant {
            fn check(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &advance_shared_types::capability::CapParams,
            ) -> crate::api::GrantDecision {
                crate::api::GrantDecision::Deny("none".into())
            }
        }
        fn dangling<T: ?Sized>(strong: Arc<T>) -> Weak<T> {
            Arc::downgrade(&strong)
        }
        CxParts {
            config: Weak::new(),
            event_bus: dangling(Arc::new(NopEmit) as Arc<dyn EventBusEmit>),
            run_manager: Weak::new(),
            grant_check: dangling(Arc::new(NopGrant) as Arc<dyn GrantCheck>),
            secret_store: None,
            leak_detector: Arc::new(cap_http::DefaultLeakDetector::new()),
        }
    }

    #[test]
    fn module_001_ac31_prepare_order_and_error_mapping() {
        match ExtensionSet::prepare(
            vec![Arc::new(Fake {
                panic_id: true,
                ..Fake::new("fixture")
            })],
            plan(),
            LogHandle::null(),
        ) {
            Err(ComposeError::Extension {
                extension: "<unknown>",
                phase: ExtensionPhase::Capabilities,
                failure: ExtensionFailure::Panicked(ref message),
            }) if message.contains("id panic") => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        match ExtensionSet::prepare(
            vec![Arc::new(Fake::new("Fixture"))],
            plan(),
            LogHandle::null(),
        ) {
            Err(ComposeError::Extension {
                extension: "Fixture",
                phase: ExtensionPhase::Capabilities,
                failure: ExtensionFailure::Failed(ref message),
            }) if message.contains("invalid extension id") => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        let second_calls = Arc::new(Fake::new("fixture"));
        match ExtensionSet::prepare(
            vec![
                Arc::new(Fake::new("fixture")),
                Arc::clone(&second_calls) as _,
            ],
            plan(),
            LogHandle::null(),
        ) {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Capabilities,
                failure: ExtensionFailure::Failed(ref message),
            }) if message == "extension id \"fixture\" is used by an earlier extension" => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }
        assert_eq!(second_calls.caps_calls.load(AtomicOrdering::SeqCst), 0);

        let named = Arc::new(Fake {
            caps: &["fixture.x"],
            ..Fake::new("fixture")
        });
        let named_dup = Arc::new(Fake {
            caps: &["fixture.x"],
            ..Fake::new("fixture")
        });
        match ExtensionSet::prepare(
            vec![Arc::clone(&named) as _, Arc::clone(&named_dup) as _],
            plan(),
            LogHandle::null(),
        ) {
            Err(ComposeError::Extension {
                phase: ExtensionPhase::Capabilities,
                failure: ExtensionFailure::Failed(ref message),
                ..
            }) if message == "extension id \"fixture\" is used by an earlier extension" => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }
        assert_eq!(named_dup.caps_calls.load(AtomicOrdering::SeqCst), 0);

        match ExtensionSet::prepare(
            vec![Arc::new(Fake {
                panic_caps: true,
                ..Fake::new("fixture")
            })],
            plan(),
            LogHandle::null(),
        ) {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Capabilities,
                failure: ExtensionFailure::Panicked(ref message),
            }) if message.contains("caps panic") => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        match ExtensionSet::prepare(
            vec![Arc::new(Fake {
                panic_need: true,
                ..Fake::new("fixture")
            })],
            plan(),
            LogHandle::null(),
        ) {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::Capabilities,
                failure: ExtensionFailure::Panicked(ref message),
            }) if message.contains("need panic") => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        let accepted = Arc::new(Fake {
            caps: &["fixture.x"],
            ..Fake::new("fixture")
        });
        let set =
            ExtensionSet::prepare(vec![Arc::clone(&accepted) as _], plan(), LogHandle::null())
                .expect("prepare");
        assert_eq!(accepted.caps_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(set.capabilities_of("fixture"), &["fixture.x"]);
        let snap = set.board().snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, "fixture");
        assert!(matches!(snap[0].state, ExtensionState::Starting));
    }

    #[test]
    fn module_001_ac31_iter_with_cx_requires_installed_contexts() {
        let empty = ExtensionSet::empty();
        assert_eq!(empty.try_iter_with_cx().expect("empty").count(), 0);

        let set = ExtensionSet::prepare(
            vec![Arc::new(Fake::new("fixture")), Arc::new(Fake::new("other"))],
            plan(),
            LogHandle::null(),
        )
        .expect("prepare");
        match set.try_iter_with_cx() {
            Err(ComposeError::Wiring(message)) if message == "extension contexts not installed" => {
            }
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }
        set.install_contexts(dummy_parts());
        let items: Vec<_> = set.try_iter_with_cx().expect("installed").collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, "fixture");
        assert_eq!(items[0].2.extension_id(), "fixture");
        assert_eq!(items[1].0, "other");
        assert_eq!(items[1].2.extension_id(), "other");
        assert!(!std::ptr::eq(items[0].2, items[1].2));
        let via_iter: Vec<_> = set
            .iter_with_cx()
            .expect("iter")
            .map(|(id, _, _)| id)
            .collect();
        assert_eq!(via_iter, vec!["fixture", "other"]);
    }

    #[test]
    fn module_001_ac31_secret_plan_rule_arms() {
        for need in [false, true] {
            for oss in [false, true] {
                for rule in [
                    SecretNeedRule::BuildOnNeed,
                    SecretNeedRule::NoView,
                    SecretNeedRule::FailCompose,
                ] {
                    let result = secret_plan_with(rule, need, oss, "fixture");
                    if !need {
                        assert_eq!(result.unwrap(), SecretPlan::NotNeeded);
                    } else if oss {
                        assert_eq!(result.unwrap(), SecretPlan::ReuseOss);
                    } else {
                        match rule {
                            SecretNeedRule::BuildOnNeed => {
                                assert_eq!(result.unwrap(), SecretPlan::BuildForExtensions);
                            }
                            SecretNeedRule::NoView => {
                                assert_eq!(result.unwrap(), SecretPlan::NotNeeded);
                            }
                            SecretNeedRule::FailCompose => match result {
                                Err(ComposeError::Extension {
                                    extension: "fixture",
                                    phase: ExtensionPhase::Capabilities,
                                    failure: ExtensionFailure::Failed(ref message),
                                }) if message
                                    == "needs a secret store, but the home declares neither `secrets` nor `llm`" =>
                                    {}
                                other => panic!("{other:?}"),
                            },
                        }
                    }
                }
            }
        }
    }

    struct RecordingBus {
        events: StdMutex<Vec<Event>>,
    }

    impl EventBusEmit for RecordingBus {
        fn emit(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn module_001_ac31_emitter_validation_and_stamping() {
        let bus = Arc::new(RecordingBus {
            events: StdMutex::new(Vec::new()),
        });
        let clock = Arc::new(advance_client_api::clock::TestClock::new(1_700_000_000_000));
        let emitter = ExtensionEmitter::new(
            "fixture",
            Arc::downgrade(&(Arc::clone(&bus) as Arc<dyn EventBusEmit>)),
            clock,
            Revocation::new(),
        );
        let receipt = emitter
            .emit("ext.fixture.ping", json!({"n": 1}))
            .expect("emit");
        assert_eq!(receipt.source, "ext.fixture");
        let events = bus.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_id, "ext.fixture");
        assert_eq!(events[0].id, receipt.event_id);
        assert_eq!(events[0].timestamp, receipt.timestamp);
        assert_eq!(events[0].timestamp.timestamp_millis(), 1_700_000_000_000);
        assert!(events[0].run_id.is_none());
        assert!(events[0].task_id.is_none());
        drop(events);

        assert!(matches!(
            emitter.emit("run.completed", json!({})),
            Err(EmitError::ForeignType { .. })
        ));
        assert_eq!(
            EmitError::ForeignType {
                event_type: "run.completed".into()
            }
            .to_string(),
            "event type \"run.completed\" is outside this extension's namespace"
        );
        assert!(matches!(
            emitter.emit("ext.fixture.", json!({})),
            Err(EmitError::InvalidType {
                reason: "empty suffix",
                ..
            })
        ));
        assert!(matches!(
            emitter.emit("ext.fixture.Ping", json!({})),
            Err(EmitError::InvalidType {
                reason: "bad segment",
                ..
            })
        ));
        let too_big = json!("x".repeat(70 * 1024));
        match emitter.emit("ext.fixture.ping", too_big) {
            Err(EmitError::TooLarge {
                field: "payload", ..
            }) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(
            EmitError::TooLarge {
                field: "payload",
                actual: 10,
                limit: 5
            }
            .to_string(),
            "event field payload is 10 bytes; the limit is 5"
        );
        assert_eq!(
            EmitError::InvalidType {
                event_type: "ext.fixture.".into(),
                reason: "empty suffix"
            }
            .to_string(),
            "invalid event type \"ext.fixture.\": empty suffix"
        );
        assert_eq!(EmitError::ShutDown.to_string(), "composition stopped");
        assert_eq!(bus.events.lock().unwrap().len(), 1);
    }

    #[test]
    fn module_001_ac31_secret_view_name_rules() {
        let store = Arc::new(SecretStore::new(
            Zeroizing::new([7u8; 32]),
            Arc::new(InMemorySecretStorage::new()),
        ));
        let secrets = ExtensionSecrets::new("fixture", Arc::downgrade(&store), Revocation::new());
        secrets.store("ext/fixture/k", "v1").expect("store");
        assert!(secrets.exists("ext/fixture/k").expect("exists"));
        match secrets.store("ext/fixture-two/k", "x") {
            Err(SecretViewError::OutsideNamespace { name }) if name == "ext/fixture-two/k" => {}
            other => panic!("{other:?}"),
        }
        match secrets.store("ext/fixture/../k", "x") {
            Err(SecretViewError::InvalidName {
                reason: "dot segment",
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        match secrets.store("ext/fixture/", "x") {
            Err(SecretViewError::InvalidName {
                reason: "empty name",
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        let long = format!("ext/fixture/{}", "a".repeat(201));
        match secrets.store(&long, "x") {
            Err(SecretViewError::InvalidName {
                reason: "longer than 200 bytes",
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(secrets.names().expect("names"), vec!["ext/fixture/k"]);
        assert_eq!(
            SecretViewError::OutsideNamespace {
                name: "other".into()
            }
            .to_string(),
            "secret name \"other\" is outside this extension's namespace"
        );
        assert_eq!(
            SecretViewError::InvalidName {
                name: "ext/fixture/../k".into(),
                reason: "dot segment"
            }
            .to_string(),
            "invalid secret name \"ext/fixture/../k\": dot segment"
        );
        assert_eq!(SecretViewError::ShutDown.to_string(), "composition stopped");
        assert_eq!(
            SecretViewError::Store("boom".into()).to_string(),
            "secret store error: boom"
        );
    }

    #[test]
    fn module_001_ac31_t112_d1_ext_event_never_reaches_cost_ledger_or_trigger_bus() {
        fn under_namespace(event_type: &str, id: &str) -> bool {
            event_type.starts_with(&format!("ext.{id}."))
        }
        for event_type in taxonomy::TRIGGER_BUS_WHITELIST {
            assert!(
                !under_namespace(event_type, "fixture"),
                "{event_type} is in the extension namespace"
            );
        }
        assert!(!under_namespace(taxonomy::llm::RESPONSE, "fixture"));

        let bus = Arc::new(RecordingBus {
            events: StdMutex::new(Vec::new()),
        });
        let emitter = ExtensionEmitter::new(
            "fixture",
            Arc::downgrade(&(Arc::clone(&bus) as Arc<dyn EventBusEmit>)),
            Arc::new(SystemClock),
            Revocation::new(),
        );
        emitter
            .emit("ext.fixture.ping", json!({}))
            .expect("admitted");
        assert!(emitter.emit("llm.response", json!({})).is_err());
        assert!(emitter.emit("run.completed", json!({})).is_err());
        let events = bus.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "ext.fixture.ping");
        drop(events);

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("jsonl")).unwrap();
        let bus = Arc::new(
            EventBus::new_synchronous_for_tests(EventBusConfig::new(
                dir.path().join("jsonl"),
                dir.path().join("events.db"),
            ))
            .expect("sync bus"),
        );
        let mut direct =
            Event::observability("llm.response", "agent", json!({"input_tokens": 1}), None);
        direct.run_id = Some("run-1".into());
        EventBusEmit::emit(&*bus, direct);
        assert!(bus.cost_tracker_query().query_run("run-1").is_some());
        let emitter = ExtensionEmitter::new(
            "fixture",
            Arc::downgrade(&(Arc::clone(&bus) as Arc<dyn EventBusEmit>)),
            Arc::new(SystemClock),
            Revocation::new(),
        );
        assert!(matches!(
            emitter.emit("llm.response", json!({"input_tokens": 99})),
            Err(EmitError::ForeignType { .. })
        ));
        assert!(
            bus.cost_tracker_query().query_run("run-1").is_some(),
            "refused emit leaves the ledger unchanged"
        );
    }

    struct Hook {
        id: &'static str,
        behaviour: HookBehaviour,
        ran: Arc<StdMutex<Vec<&'static str>>>,
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

        fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
            self.ran.lock().unwrap().push(self.id);
            match self.behaviour {
                HookBehaviour::Finish => Box::pin(async {}),
                HookBehaviour::Hang(duration) => Box::pin(tokio::time::sleep(duration)),
                HookBehaviour::PanicWhilePolled => Box::pin(async { panic!("hook panicked") }),
                HookBehaviour::PanicWhileBuilt => panic!("hook panicked before its future"),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn module_001_ac30_extension_shutdown_hooks_reverse_bounded() {
        let ran = Arc::new(StdMutex::new(Vec::new()));
        let hook = |id, behaviour| -> Arc<dyn ComposeExtension> {
            Arc::new(Hook {
                id,
                behaviour,
                ran: Arc::clone(&ran),
            })
        };
        let sink = MemoryComposeLog::new();
        let set = ExtensionSet::prepare(
            vec![
                hook("first", HookBehaviour::Finish),
                hook("panics-built", HookBehaviour::PanicWhileBuilt),
                hook("hangs", HookBehaviour::Hang(Duration::from_secs(10))),
                hook("panics-polled", HookBehaviour::PanicWhilePolled),
                hook("last", HookBehaviour::Finish),
            ],
            plan(),
            LogHandle::new(Arc::new(sink.clone())),
        )
        .expect("prepare");
        let started = Instant::now();
        set.run_shutdown_hooks(&StepLog::default()).await;
        let waited = started.elapsed();
        let bound = crate::composition::EXTENSION_SHUTDOWN_BOUND;
        assert!(
            waited >= bound && waited < bound + Duration::from_millis(10),
            "only the hanging hook waits, and only for its bound: {waited:?}"
        );
        assert_eq!(
            *ran.lock().unwrap(),
            vec!["last", "panics-polled", "hangs", "panics-built", "first"]
        );
        let lines: Vec<(&'static str, String)> = sink
            .lines()
            .into_iter()
            .map(|ComposeLogLine { stream, key, text }| {
                assert_eq!(stream, LogStream::Stderr);
                (key, text)
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

    #[tokio::test(start_paused = true)]
    async fn module_001_ac31_task_spawner_closed_cancel_and_abandon() {
        let sink = MemoryComposeLog::new();
        let set = ExtensionSet::prepare(
            vec![Arc::new(Fake::new("fixture"))],
            plan(),
            LogHandle::new(Arc::new(sink.clone())),
        )
        .expect("prepare");
        set.install_contexts(dummy_parts());
        let cx = set
            .try_iter_with_cx()
            .expect("cx")
            .next()
            .expect("one")
            .2
            .clone();

        cx.tasks()
            .spawn(async { tokio::time::sleep(Duration::from_secs(60)).await })
            .expect("spawn");
        let started = Instant::now();
        set.cancel_and_join_tasks(&StepLog::default()).await;
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "cancelled task joins at once"
        );
        assert_eq!(cx.tasks().spawn(async {}), Err(ViewError::ShutDown));

        let set = ExtensionSet::prepare(
            vec![Arc::new(Fake::new("fixture"))],
            plan(),
            LogHandle::null(),
        )
        .expect("prepare");
        set.install_contexts(dummy_parts());
        set.cancel_and_join_tasks(&StepLog::default()).await;
        set.spawn_on_started(StartedParts {
            gateway: None,
            client_api_base: None,
            client_api_addr: None,
        });
        assert!(matches!(
            set.board().snapshot()[0].state,
            ExtensionState::Starting
        ));

        let set = ExtensionSet::prepare(
            vec![Arc::new(Fake::new("fixture"))],
            plan(),
            LogHandle::null(),
        )
        .expect("prepare");
        set.install_contexts(dummy_parts());
        let cx = set
            .try_iter_with_cx()
            .expect("cx")
            .next()
            .expect("one")
            .2
            .clone();
        let flag = Arc::new(AtomicBool::new(false));
        let spawner = cx.tasks().clone();
        let flag_thread = Arc::clone(&flag);
        std::thread::spawn(move || {
            spawner
                .spawn(async move {
                    flag_thread.store(true, AtomicOrdering::SeqCst);
                })
                .expect("spawn from thread");
        })
        .join()
        .expect("thread");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !flag.load(AtomicOrdering::SeqCst) && Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert!(
            flag.load(AtomicOrdering::SeqCst),
            "task from std thread ran"
        );

        let sink = MemoryComposeLog::new();
        let set = ExtensionSet::prepare(
            vec![Arc::new(Fake::new("fixture"))],
            plan(),
            LogHandle::new(Arc::new(sink.clone())),
        )
        .expect("prepare");
        set.spawn_unwrapped_for_test(async {
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let started = Instant::now();
        set.cancel_and_join_tasks(&StepLog::default()).await;
        let waited = started.elapsed();
        assert!(
            waited >= EXTENSION_TASKS_JOIN_BOUND
                && waited < EXTENSION_TASKS_JOIN_BOUND + Duration::from_millis(10),
            "unwrapped sleeper is abandoned at 5s: {waited:?}"
        );
        assert_eq!(sink.count(log_keys::EXT_TASKS_ABANDONED), 1);
        let text = sink.lines()[0].text.clone();
        assert!(text.contains("1 extension task(s) still running 5s after cancellation; abandoned"));
    }
}
