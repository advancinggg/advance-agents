//! Least-privilege contexts and views an extension receives.

use std::fmt;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::Path;
#[cfg(feature = "test-support")]
use std::path::PathBuf;
use std::sync::{Arc, Weak};

use advance_client_api::clock::Clock;
use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider, RuntimeConfigWatcher};
use advance_shared_types::capability::CapParams;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, GrantCheck, LeakDetector};
use advance_shared_types::{capability::GrantDecision, run::TaskRunStatus};
use chrono::{DateTime, Utc};
use secrecy::Secret;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::options::{ComposeProfile, ProcessPolicy};
use crate::extension::call;
use crate::extension::set::{Revocation, TaskShared};

/// Least-privilege context of ONE extension (ADR D2 (d)). Clone is cheap.
#[derive(Clone)]
pub struct ComposeCx {
    extension: &'static str,
    home: Arc<Path>,
    profile: ComposeProfile,
    processes: ProcessPolicy,
    clock: Arc<dyn Clock>,
    leak_detector: Arc<dyn LeakDetector>,
    config: ConfigView,
    tasks: TaskSpawner,
    emitter: ExtensionEmitter,
    runs: RunView,
    grants: ExtensionGrantCheck,
    secrets: Option<ExtensionSecrets>,
}

impl ComposeCx {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        extension: &'static str,
        home: Arc<Path>,
        profile: ComposeProfile,
        processes: ProcessPolicy,
        clock: Arc<dyn Clock>,
        leak_detector: Arc<dyn LeakDetector>,
        config: ConfigView,
        tasks: TaskSpawner,
        emitter: ExtensionEmitter,
        runs: RunView,
        grants: ExtensionGrantCheck,
        secrets: Option<ExtensionSecrets>,
    ) -> Self {
        Self {
            extension,
            home,
            profile,
            processes,
            clock,
            leak_detector,
            config,
            tasks,
            emitter,
            runs,
            grants,
            secrets,
        }
    }

    pub fn extension_id(&self) -> &'static str {
        self.extension
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn profile(&self) -> ComposeProfile {
        self.profile
    }

    pub fn processes(&self) -> ProcessPolicy {
        self.processes
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn leak_detector(&self) -> &Arc<dyn LeakDetector> {
        &self.leak_detector
    }

    pub fn config(&self) -> &ConfigView {
        &self.config
    }

    pub fn tasks(&self) -> &TaskSpawner {
        &self.tasks
    }

    pub fn emitter(&self) -> &ExtensionEmitter {
        &self.emitter
    }

    pub fn runs(&self) -> &RunView {
        &self.runs
    }

    pub fn grants(&self) -> &ExtensionGrantCheck {
        &self.grants
    }

    pub fn secrets(&self) -> Option<&ExtensionSecrets> {
        self.secrets.as_ref()
    }

    /// Test seam for sibling unit tests: every view is dead (answers ShutDown /
    /// Deny), the spawner refuses, profile Daemon, processes Allow.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn detached_for_test(extension: &'static str, home: PathBuf) -> Self {
        let gate = Revocation::revoked();
        let home: Arc<Path> = Arc::from(home.into_boxed_path());
        let clock: Arc<dyn Clock> = Arc::new(advance_client_api::clock::SystemClock);
        let leak_detector: Arc<dyn LeakDetector> = Arc::new(cap_http::DefaultLeakDetector::new());
        let tasks = TaskSpawner::new(extension, TaskShared::dead());
        struct DetachedEmit;
        impl EventBusEmit for DetachedEmit {
            fn emit(&self, _: Event) {}
        }
        struct DetachedGrant;
        impl GrantCheck for DetachedGrant {
            fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
                GrantDecision::Deny("composition stopped".into())
            }
        }
        fn dangling<T: ?Sized>(strong: Arc<T>) -> Weak<T> {
            Arc::downgrade(&strong)
        }
        Self::new(
            extension,
            Arc::clone(&home),
            ComposeProfile::Daemon,
            ProcessPolicy::Allow,
            clock.clone(),
            leak_detector,
            ConfigView::new(Weak::new(), gate.clone()),
            tasks,
            ExtensionEmitter::new(
                extension,
                dangling(Arc::new(DetachedEmit) as Arc<dyn EventBusEmit>),
                clock,
                gate.clone(),
            ),
            RunView::new(Weak::new(), gate.clone()),
            ExtensionGrantCheck::new(
                extension,
                dangling(Arc::new(DetachedGrant) as Arc<dyn GrantCheck>),
                gate.clone(),
            ),
            None,
        )
    }
}

impl fmt::Debug for ComposeCx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComposeCx")
            .field("extension", &self.extension)
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

/// [`ComposeCx`] + what exists once the runtime is up. Owned by the spawned
/// `on_started` task.
pub struct StartedCx {
    cx: ComposeCx,
    gateway: Option<GatewayHandle>,
    client_api_base: Option<String>,
    client_api_addr: Option<SocketAddr>,
}

impl StartedCx {
    pub(crate) fn new(
        cx: ComposeCx,
        gateway: Option<GatewayHandle>,
        client_api_base: Option<String>,
        client_api_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            cx,
            gateway,
            client_api_base,
            client_api_addr,
        }
    }

    pub fn cx(&self) -> &ComposeCx {
        &self.cx
    }

    pub fn gateway(&self) -> Option<&GatewayHandle> {
        self.gateway.as_ref()
    }

    pub fn client_api_base(&self) -> Option<&str> {
        self.client_api_base.as_deref()
    }

    pub fn client_api_addr(&self) -> Option<SocketAddr> {
        self.client_api_addr
    }
}

impl Deref for StartedCx {
    type Target = ComposeCx;

    fn deref(&self) -> &Self::Target {
        &self.cx
    }
}

/// The composition has been stopped.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewError {
    ShutDown,
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("composition stopped")
    }
}

impl std::error::Error for ViewError {}

/// Read-only live config.
#[derive(Clone)]
pub struct ConfigView {
    watcher: Weak<RuntimeConfigWatcher>,
    gate: Revocation,
}

impl ConfigView {
    pub(crate) fn new(watcher: Weak<RuntimeConfigWatcher>, gate: Revocation) -> Self {
        Self { watcher, gate }
    }

    /// A snapshot of the live config; it follows edits of `runtime-config.yaml`.
    pub fn current(&self) -> Result<Arc<RuntimeConfig>, ViewError> {
        if self.gate.is_revoked() {
            return Err(ViewError::ShutDown);
        }
        let watcher = self.watcher.upgrade().ok_or(ViewError::ShutDown)?;
        Ok(RuntimeConfigProvider::current(&*watcher))
    }
}

/// Tasks spawned here run on the composition's runtime, are cancelled (dropped at
/// their next await) and joined in shutdown step 3 after the hooks; a panic is
/// contained and logged. Cancellation is cooperative: a task that reaches no `.await`
/// within 5 s of the cancellation (CPU-bound or blocking work) keeps running,
/// abandoned, and the composition logs it under
/// [`EXT_TASKS_ABANDONED`](crate::api::log_keys::EXT_TASKS_ABANDONED). Run such work
/// with `tokio::task::spawn_blocking` and have it check
/// [`cancellation_token`](Self::cancellation_token).
#[derive(Clone)]
pub struct TaskSpawner {
    extension: &'static str,
    shared: Arc<TaskShared>,
}

impl TaskSpawner {
    pub(crate) fn new(extension: &'static str, shared: Arc<TaskShared>) -> Self {
        Self { extension, shared }
    }

    /// Callable from any thread (it spawns on the stored runtime handle).
    /// `Err(ShutDown)` once step 3 began.
    pub fn spawn<F>(&self, task: F) -> Result<(), ViewError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.shared.spawn_wrapped(self.extension, task)
    }

    /// Child token cancelled when step 3's task cancellation begins.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.shared.cancellation_token()
    }
}

/// The only EventBus access an extension gets.
#[derive(Clone)]
pub struct ExtensionEmitter {
    extension: &'static str,
    prefix: String,
    source: String,
    bus: Weak<dyn EventBusEmit>,
    clock: Arc<dyn Clock>,
    gate: Revocation,
}

impl ExtensionEmitter {
    pub(crate) fn new(
        extension: &'static str,
        bus: Weak<dyn EventBusEmit>,
        clock: Arc<dyn Clock>,
        gate: Revocation,
    ) -> Self {
        Self {
            extension,
            prefix: format!("ext.{extension}."),
            source: format!("ext.{extension}"),
            bus,
            clock,
            gate,
        }
    }

    pub fn namespace(&self) -> &str {
        &self.prefix
    }

    /// Accepts only `ext.<id>.<suffix>`; stamps id, time and source itself.
    pub fn emit(&self, event_type: &str, payload: Value) -> Result<EmitReceipt, EmitError> {
        if self.gate.is_revoked() {
            return Err(EmitError::ShutDown);
        }
        let bus = self.bus.upgrade().ok_or(EmitError::ShutDown)?;
        self.check_event_type(event_type)?;
        let timestamp = DateTime::<Utc>::from_timestamp_millis(self.clock.now_millis() as i64)
            .unwrap_or_else(Utc::now);
        let event_id = Uuid::new_v4().to_string();
        let event = Event {
            id: event_id.clone(),
            timestamp,
            agent_id: self.source.clone(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            event_type: event_type.to_owned(),
            payload,
            duration_ms: None,
        };
        if let Err(error) = advance_event_bus::validate_event_size(&event) {
            return Err(map_size_error(error, event_type));
        }
        bus.emit(event);
        Ok(EmitReceipt {
            event_id,
            timestamp,
            source: self.source.clone(),
        })
    }

    fn check_event_type(&self, event_type: &str) -> Result<(), EmitError> {
        if !event_type.starts_with(&self.prefix) {
            return Err(EmitError::ForeignType {
                event_type: event_type.to_owned(),
            });
        }
        if event_type.len() > 128 {
            return Err(EmitError::InvalidType {
                event_type: event_type.to_owned(),
                reason: "longer than 128 bytes",
            });
        }
        let suffix = &event_type[self.prefix.len()..];
        if suffix.is_empty() {
            return Err(EmitError::InvalidType {
                event_type: event_type.to_owned(),
                reason: "empty suffix",
            });
        }
        for segment in suffix.split('.') {
            if segment.is_empty() {
                return Err(EmitError::InvalidType {
                    event_type: event_type.to_owned(),
                    reason: "empty segment",
                });
            }
            if !segment
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            {
                return Err(EmitError::InvalidType {
                    event_type: event_type.to_owned(),
                    reason: "bad segment",
                });
            }
        }
        let _ = self.extension;
        Ok(())
    }
}

fn map_size_error(error: advance_event_bus::EventBusError, event_type: &str) -> EmitError {
    match error {
        advance_event_bus::EventBusError::OversizeEventField {
            field,
            actual,
            limit,
        } => EmitError::TooLarge {
            field,
            actual,
            limit,
        },
        advance_event_bus::EventBusError::Json(_) => EmitError::InvalidType {
            event_type: event_type.to_owned(),
            reason: "payload not serializable",
        },
        _ => EmitError::InvalidType {
            event_type: event_type.to_owned(),
            reason: "payload not serializable",
        },
    }
}

/// Receipt of an admitted `ext.<id>.*` event.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmitReceipt {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

/// Why an extension could not emit.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmitError {
    /// Not under this extension's `ext.<id>.` (e.g. `run.completed`, `llm.response`).
    ForeignType {
        event_type: String,
    },
    /// Under the namespace but malformed (empty suffix / bad segment / over 128
    /// bytes / payload not serializable).
    InvalidType {
        event_type: String,
        reason: &'static str,
    },
    /// A bound of `advance_event_bus::validate_event_size`.
    TooLarge {
        field: &'static str,
        actual: usize,
        limit: usize,
    },
    ShutDown,
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::ForeignType { event_type } => write!(
                f,
                "event type {event_type:?} is outside this extension's namespace"
            ),
            EmitError::InvalidType { event_type, reason } => {
                write!(f, "invalid event type {event_type:?}: {reason}")
            }
            EmitError::TooLarge {
                field,
                actual,
                limit,
            } => write!(
                f,
                "event field {field} is {actual} bytes; the limit is {limit}"
            ),
            EmitError::ShutDown => f.write_str("composition stopped"),
        }
    }
}

impl std::error::Error for EmitError {}

/// Read-only run view: no pause / cancel / resume / complete / fail.
///
/// ```
/// fn f(cx: &advance_runtime_compose::api::ComposeCx) {
///     let _ = cx.runs().runs();
/// }
/// ```
///
/// ```compile_fail
/// fn f(cx: &advance_runtime_compose::api::ComposeCx) {
///     let _ = cx.runs().pause("r");
/// }
/// ```
///
/// ```compile_fail
/// fn f(cx: &advance_runtime_compose::api::ComposeCx) {
///     let _ = cx.runs().cancel("r");
/// }
/// ```
#[derive(Clone)]
pub struct RunView {
    runs: Weak<advance_run_manager::RunManager>,
    gate: Revocation,
}

impl RunView {
    pub(crate) fn new(runs: Weak<advance_run_manager::RunManager>, gate: Revocation) -> Self {
        Self { runs, gate }
    }

    pub fn run(&self, run_id: &str) -> Result<Option<RunInfo>, ViewError> {
        Ok(self.runs()?.into_iter().find(|run| run.run_id == run_id))
    }

    pub fn runs(&self) -> Result<Vec<RunInfo>, ViewError> {
        if self.gate.is_revoked() {
            return Err(ViewError::ShutDown);
        }
        let manager = self.runs.upgrade().ok_or(ViewError::ShutDown)?;
        Ok(manager.list_runs().iter().map(run_info).collect())
    }
}

fn run_info(run: &advance_run_manager::Run) -> RunInfo {
    RunInfo {
        run_id: run.id.as_ref().to_owned(),
        task_id: run.task_id.clone(),
        controller_agent: run.controller_agent.clone(),
        status: run.status.clone(),
        iteration: run.iteration,
        token_used: run.budget.token_used,
        cost_usd: run.budget.cost_usd,
        created_at: run.created_at,
        updated_at: run.updated_at,
    }
}

/// A snapshot of one run, with no control methods.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct RunInfo {
    pub run_id: String,
    pub task_id: String,
    pub controller_agent: String,
    pub status: TaskRunStatus,
    pub iteration: u32,
    pub token_used: u64,
    pub cost_usd: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A grant check bound to the host call being served (ADR D2 (d)): it takes no
/// agent id.
///
/// ```
/// fn f(cx: &advance_runtime_compose::api::ComposeCx) {
///     let _ = cx
///         .grants()
///         .check("fs", &advance_runtime_compose::CapParams::empty());
/// }
/// ```
///
/// ```compile_fail
/// fn f(cx: &advance_runtime_compose::api::ComposeCx) {
///     let _ = cx.grants().check(
///         "agent-x",
///         "fs",
///         &advance_runtime_compose::CapParams::empty(),
///     );
/// }
/// ```
#[derive(Clone)]
pub struct ExtensionGrantCheck {
    extension: &'static str,
    grants: Weak<dyn GrantCheck>,
    gate: Revocation,
}

impl ExtensionGrantCheck {
    pub(crate) fn new(
        extension: &'static str,
        grants: Weak<dyn GrantCheck>,
        gate: Revocation,
    ) -> Self {
        Self {
            extension,
            grants,
            gate,
        }
    }

    /// Inside this extension's host-function or native-tool call:
    /// `GrantCheck::check(<the calling agent>, capability, <the called function>,
    /// params)`. Fail closed otherwise.
    pub fn check(&self, capability: &str, params: &CapParams) -> GrantDecision {
        if self.gate.is_revoked() || self.grants.upgrade().is_none() {
            return GrantDecision::Deny("composition stopped".into());
        }
        if capability.is_empty() || capability.len() > 256 || capability.contains(':') {
            return GrantDecision::Deny("invalid capability".into());
        }
        let Some(call) = call::current() else {
            return GrantDecision::Deny("no host call in progress".into());
        };
        if call.extension() != self.extension {
            return GrantDecision::Deny("host call belongs to another extension".into());
        }
        let Some(grants) = self.grants.upgrade() else {
            return GrantDecision::Deny("composition stopped".into());
        };
        grants.check(call.agent_id(), capability, call.function(), params)
    }
}

/// `SecretStore` view limited to `ext/<id>/…` names.
#[derive(Clone)]
pub struct ExtensionSecrets {
    prefix: String,
    store: Weak<cap_secrets::SecretStore>,
    gate: Revocation,
}

impl ExtensionSecrets {
    pub(crate) fn new(
        extension: &'static str,
        store: Weak<cap_secrets::SecretStore>,
        gate: Revocation,
    ) -> Self {
        Self {
            prefix: format!("ext/{extension}/"),
            store,
            gate,
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn store(&self, name: &str, value: &str) -> Result<(), SecretViewError> {
        let store = self.upgrade()?;
        let name = self.qualify(name)?;
        store
            .store(name, value)
            .map_err(|error| SecretViewError::Store(error.to_string()))
    }

    pub fn resolve(&self, name: &str) -> Result<Secret<String>, SecretViewError> {
        let store = self.upgrade()?;
        let name = self.qualify(name)?;
        store
            .resolve(name)
            .map_err(|error| SecretViewError::Store(error.to_string()))
    }

    pub fn exists(&self, name: &str) -> Result<bool, SecretViewError> {
        let store = self.upgrade()?;
        let name = self.qualify(name)?;
        store
            .exists(name)
            .map_err(|error| SecretViewError::Store(error.to_string()))
    }

    pub fn remove(&self, name: &str) -> Result<bool, SecretViewError> {
        let store = self.upgrade()?;
        let name = self.qualify(name)?;
        store
            .remove(name)
            .map_err(|error| SecretViewError::Store(error.to_string()))
    }

    /// Only names under the prefix.
    pub fn names(&self) -> Result<Vec<String>, SecretViewError> {
        let store = self.upgrade()?;
        Ok(store
            .names()
            .into_iter()
            .filter(|name| name.starts_with(&self.prefix))
            .collect())
    }

    fn upgrade(&self) -> Result<Arc<cap_secrets::SecretStore>, SecretViewError> {
        if self.gate.is_revoked() {
            return Err(SecretViewError::ShutDown);
        }
        self.store.upgrade().ok_or(SecretViewError::ShutDown)
    }

    fn qualify<'a>(&self, name: &'a str) -> Result<&'a str, SecretViewError> {
        if !name.starts_with(&self.prefix) {
            return Err(SecretViewError::OutsideNamespace {
                name: name.to_owned(),
            });
        }
        let rest = &name[self.prefix.len()..];
        if rest.is_empty() {
            return Err(SecretViewError::InvalidName {
                name: name.to_owned(),
                reason: "empty name",
            });
        }
        if rest.len() > 200 {
            return Err(SecretViewError::InvalidName {
                name: name.to_owned(),
                reason: "longer than 200 bytes",
            });
        }
        for segment in rest.split('/') {
            if segment.is_empty() {
                return Err(SecretViewError::InvalidName {
                    name: name.to_owned(),
                    reason: "empty segment",
                });
            }
            if segment == "." || segment == ".." {
                return Err(SecretViewError::InvalidName {
                    name: name.to_owned(),
                    reason: "dot segment",
                });
            }
            if !segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
            {
                return Err(SecretViewError::InvalidName {
                    name: name.to_owned(),
                    reason: "invalid character",
                });
            }
        }
        Ok(name)
    }
}

/// Why a secret view call failed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretViewError {
    OutsideNamespace { name: String },
    InvalidName { name: String, reason: &'static str },
    ShutDown,
    Store(String),
}

impl fmt::Display for SecretViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretViewError::OutsideNamespace { name } => {
                write!(
                    f,
                    "secret name {name:?} is outside this extension's namespace"
                )
            }
            SecretViewError::InvalidName { name, reason } => {
                write!(f, "invalid secret name {name:?}: {reason}")
            }
            SecretViewError::ShutDown => f.write_str("composition stopped"),
            SecretViewError::Store(message) => write!(f, "secret store error: {message}"),
        }
    }
}

impl std::error::Error for SecretViewError {}

/// The composed gateway (`StartedCx` only, `llm` homes only).
#[derive(Clone)]
pub struct GatewayHandle {
    gateway: Weak<cap_llm::LlmGateway>,
    gate: Revocation,
}

impl GatewayHandle {
    pub(crate) fn new(gateway: Weak<cap_llm::LlmGateway>, gate: Revocation) -> Self {
        Self { gateway, gate }
    }

    /// `None` once step 4 began or the gateway is gone. A strong Arc kept past a
    /// call delays the gateway's drop; drop it before your shutdown hook returns.
    pub fn upgrade(&self) -> Option<Arc<cap_llm::LlmGateway>> {
        if self.gate.is_revoked() {
            return None;
        }
        self.gateway.upgrade()
    }
}
