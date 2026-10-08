//! [`compose`]: compose the runtime of one home, and hand back a [`ComposedRuntime`]
//! that stops it.
//!
//! The order is the one `advance start` has always followed: the instance guard (the
//! process-local reservation, then the pid lock), the runtime host builder, the
//! capability wiring, the readiness line, the agent loop and its listeners, the tick
//! loop and the readiness walk. A failure after anything started stops what started,
//! in the shutdown's order, before the error is returned.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_runtime::config::{ConfigError, RuntimeConfig};
use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::{BootstrapError, RuntimeHostBuilder};
use tokio::sync::watch;

use crate::api::{
    Admission, ClientApiOptions, ComposeError, ComposeExtension, ComposeOptions, ComposeProfile,
    ComposedRuntime, HostPlatform, InstanceGuard, LockFailure, MasterKeyInput, PlatformRule,
    ProcessPolicy, RuntimeHealthView, ShutdownHandle, Unsupported, WasmEngine,
};
use crate::client_ingress::IngressFromGraph;
use crate::compose_log::LogHandle;
use crate::composition::{Composition, GuardHold, RuntimeView, TeardownReason};
use crate::daemon::{compose_graph, GraphFailure, GraphOptions, PartialGraph};
use crate::extension::{ExtensionPlan, ExtensionSet, StartedParts};
use crate::registry::{HomeReservation, ReserveError};
use crate::wiring::WiringOptions;

/// Compose the runtime `options` describe, with `extensions`.
///
/// On success the runtime is up: the readiness line has been emitted, and the
/// returned [`ComposedRuntime`] stops it ([`ComposedRuntime::shutdown`], a
/// [`ShutdownHandle`], or by being dropped). On failure nothing of the composition is
/// left: what had started was stopped first.
///
/// The future is `Send + 'static`, so it can be spawned on any runtime.
pub async fn compose(
    options: ComposeOptions,
    extensions: Vec<Arc<dyn ComposeExtension>>,
) -> Result<ComposedRuntime, ComposeError> {
    let plan = validate(&options)?;
    let ComposeOptions {
        instance,
        master_key,
        client_api,
        listeners,
        log,
        profile,
        processes,
        wasm_engine,
        hot_reload,
        #[cfg(feature = "test-support")]
        failpoints,
        ..
    } = options;
    let log = LogHandle::new(log);
    let exts = ExtensionSet::prepare(
        extensions,
        ExtensionPlan {
            home: Arc::from(plan.home.as_path()),
            profile,
            processes,
        },
        log.clone(),
    )?;

    // 1. The process-local reservation, before the cross-process lock: a second
    //    composition of the home in this process is refused here.
    let reservation = HomeReservation::acquire(plan.home.clone()).map_err(|error| {
        ComposeError::Lock(match error {
            ReserveError::AlreadyReserved => LockFailure::HeldInProcess,
            ReserveError::Poisoned => LockFailure::RegistryPoisoned,
        })
    })?;

    // 2. The pid lock (its heartbeat starts now). A failure releases the reservation.
    let lock = match instance {
        InstanceGuard::PidLockFile { heartbeat } => {
            match RuntimeLock::acquire_with_policy(&plan.home, heartbeat, processes).await {
                Ok(lock) => Some(lock),
                Err(error) => {
                    return Err(ComposeError::Lock(LockFailure::from_lock_error(&error)));
                }
            }
        }
        InstanceGuard::ProcessLocal => None,
    };
    let guard = GuardHold::new(reservation, lock);
    let instance_guard = guard.kind();

    // 3. The runtime host builder. A failure releases the guard (heartbeat joined, lock
    //    file removed) before it is reported.
    let config_path = config_path(&plan.home);
    let builder =
        match RuntimeHostBuilder::new_with_hot_reload(&config_path, &plan.home, hot_reload).await {
            Ok(builder) => builder.with_wasm_backend(wasm_backend(wasm_engine)),
            Err(BootstrapError::Config(ConfigError::IoError { source, .. }))
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                guard.release().await;
                return Err(ComposeError::ConfigNotFound { path: config_path });
            }
            Err(error) => {
                guard.release().await;
                return Err(ComposeError::Bootstrap(error.to_string()));
            }
        };
    #[cfg(feature = "test-support")]
    probe_record!(failpoints.probe, |record| {
        record.config_watching = Some(builder.config_watcher().is_watching());
    });
    // The config watcher and its WAL-mode observer are stopped by the teardown.
    let config_watcher = builder.config_watcher();
    let wal_observer = builder.take_wal_observer();
    if !listeners.channel_hooks && channels_need_hooks(&builder.config()) {
        let composition = Composition::early(config_watcher, wal_observer, guard, log);
        #[cfg(feature = "test-support")]
        let composition = composition.with_probe(failpoints.probe.clone());
        composition.teardown(TeardownReason::StartupFailed).await;
        return Err(ComposeError::Unsupported(Unsupported::ListenerRequired(
            "channel /hooks",
        )));
    }
    if !listeners.oauth_callback
        && builder
            .config()
            .llm_providers
            .iter()
            .any(|provider| provider.uses_chatgpt_sign_in())
    {
        let composition = Composition::early(config_watcher, wal_observer, guard, log);
        #[cfg(feature = "test-support")]
        let composition = composition.with_probe(failpoints.probe.clone());
        composition.teardown(TeardownReason::StartupFailed).await;
        return Err(ComposeError::Unsupported(Unsupported::ListenerRequired(
            "OAuth callback",
        )));
    }

    // 4. The graph: capability wiring, readiness, agent loop, listeners, tick loop,
    //    readiness walk.
    let opts = GraphOptions {
        log: log.clone(),
        listeners,
        wiring: WiringOptions {
            state_root: plan.state_root.clone(),
            master_key: match master_key {
                MasterKeyInput::Provided(key) => Some(key),
                MasterKeyInput::FromConfig => None,
            },
            event_bus_ws: listeners.event_bus_ws,
            client_api,
            log: log.clone(),
            extensions: Arc::clone(&exts),
            processes,
            hot_reload,
            oauth_callback: listeners.oauth_callback,
            #[cfg(feature = "test-support")]
            probe: failpoints.probe.clone(),
            #[cfg(feature = "test-support")]
            fail_after_git_queue: failpoints.wiring_after_git_queue,
            ..WiringOptions::compat()
        },
        hot_reload,
        #[cfg(feature = "test-support")]
        failpoints: failpoints.clone(),
    };
    let (admission, write_discovery) = match &client_api {
        ClientApiOptions::Loopback {
            admission,
            write_discovery,
            ..
        } => (*admission, *write_discovery),
        ClientApiOptions::Off => (Admission::SameUserLoopback, false),
    };
    let ingress = IngressFromGraph {
        admission,
        write_discovery,
        home: plan.home.clone(),
        #[cfg(feature = "test-support")]
        probe: failpoints.probe.clone(),
    };
    match compose_graph(builder, &plan.home, opts).await {
        Ok(graph) => {
            let wasm_engine = engine_of(&graph.host.component_runtime().engine_report());
            let started = StartedParts {
                gateway: graph
                    .wiring_handles
                    .llm_gateway
                    .as_ref()
                    .map(Arc::downgrade),
                client_api_base: graph
                    .client_api_endpoint()
                    .as_ref()
                    .map(|endpoint| endpoint.base_url.clone()),
                client_api_addr: graph
                    .client_api_endpoint()
                    .map(|endpoint| endpoint.socket_addr),
            };
            let root_agent_id = graph.wiring_handles.root_agent_id.clone();
            let agent_loop_done = graph.agent_loop_done();
            let composition =
                Composition::from_graph(graph, config_watcher, wal_observer, guard, log, ingress);
            let view = Arc::new(RuntimeView::new(
                root_agent_id,
                composition.client_ingress(),
                agent_loop_done,
                instance_guard,
                profile,
                processes,
                wasm_engine,
                exts.board(),
            ));
            let composition = composition
                .with_extensions(Arc::clone(&exts))
                .with_view(Arc::clone(&view));
            #[cfg(feature = "test-support")]
            let composition = composition.with_probe(failpoints.probe.clone());
            // Spawned before the supervisor exists: no trigger can close the tracker first.
            exts.spawn_on_started(started);
            // The one task that owns the composition: it runs the shutdown sequence once
            // the handle is triggered.
            let shutdown = ShutdownHandle::new(exts.route_gate().clone());
            let (done_tx, done_rx) = watch::channel(false);
            let triggered = shutdown.token();
            let supervisor = tokio::spawn(async move {
                triggered.cancelled().await;
                composition.teardown(TeardownReason::Requested).await;
                let _ = done_tx.send(true);
            });
            Ok(ComposedRuntime::new(view, shutdown, done_rx, supervisor))
        }
        Err(GraphFailure { error, partial }) => {
            let composition = match partial {
                PartialGraph::Graph(graph) => Composition::from_graph(
                    *graph,
                    config_watcher,
                    wal_observer,
                    guard,
                    log,
                    ingress,
                ),
                PartialGraph::Wiring(stoppers) => Composition::from_stoppers(
                    stoppers,
                    Some(config_watcher),
                    wal_observer,
                    Some(guard),
                    log,
                ),
            };
            let composition = composition.with_extensions(exts);
            #[cfg(feature = "test-support")]
            let composition = composition.with_probe(failpoints.probe.clone());
            composition.teardown(TeardownReason::StartupFailed).await;
            Err(error)
        }
    }
}

/// `<home>/.advance/runtime-config.yaml`: the one place the config path is derived.
pub(crate) fn config_path(home: &Path) -> PathBuf {
    home.join(".advance").join("runtime-config.yaml")
}

/// What [`validate`] established about the options.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The home, canonical.
    pub home: PathBuf,
    /// The state root, canonical and outside the home.
    pub state_root: Option<PathBuf>,
}

/// Host facts `validate` consults.
#[derive(Clone, Copy, Debug)]
struct HostFacts {
    compiled: Option<HostPlatform>,
    pulley_supported: bool,
}

impl HostFacts {
    fn current() -> Self {
        Self {
            compiled: HostPlatform::compiled(),
            pulley_supported: advance_runtime::component_loader::PULLEY_HOST_SUPPORTED,
        }
    }
}

/// Check every option value before anything starts. Reads the file system only to
/// canonicalize paths already known to be absolute (never the current directory).
pub(crate) fn validate(options: &ComposeOptions) -> Result<Plan, ComposeError> {
    validate_on(options, HostFacts::current())
}

/// Test seam, kept as a wrapper: `validate_on(o, HostFacts { compiled, ..HostFacts::current() })`.
#[cfg(test)]
fn validate_with_compiled(
    options: &ComposeOptions,
    compiled: Option<HostPlatform>,
) -> Result<Plan, ComposeError> {
    validate_on(
        options,
        HostFacts {
            compiled,
            ..HostFacts::current()
        },
    )
}

fn validate_on(options: &ComposeOptions, host: HostFacts) -> Result<Plan, ComposeError> {
    let refuse = |what: Unsupported| Err(ComposeError::Unsupported(what));

    let home = match canonical_directory(&options.home) {
        Some(home) if home == options.home => home,
        _ => return refuse(Unsupported::HomeNotCanonical(options.home.clone())),
    };

    compiled_target_rule(options, host.compiled).map_err(ComposeError::Unsupported)?;

    if let ComposeProfile::Embedded { platform } = options.profile {
        if let Err(rule) = row_allows(
            platform,
            options.instance,
            options.processes,
            options.wasm_engine,
        ) {
            return refuse(Unsupported::PlatformTable { platform, rule });
        }
        if platform.is_mobile() && options.state_root.is_none() {
            return refuse(Unsupported::StateRootRequired { platform });
        }
    }

    let state_root = match &options.state_root {
        None => None,
        Some(root) => Some(validate_state_root(root, &home)?),
    };

    if options.instance == InstanceGuard::ProcessLocal
        && matches!(
            options.client_api,
            ClientApiOptions::Loopback {
                write_discovery: true,
                ..
            }
        )
    {
        return refuse(Unsupported::DiscoveryRequiresPidLock);
    }

    if options.instance == InstanceGuard::ProcessLocal {
        let listeners = options.listeners;
        if listeners.post_msg {
            return refuse(Unsupported::ListenerUnderProcessLocal("POST /msg"));
        }
        if listeners.event_bus_ws {
            return refuse(Unsupported::ListenerUnderProcessLocal("EventBus WebSocket"));
        }
        if listeners.channel_hooks {
            return refuse(Unsupported::ListenerUnderProcessLocal("channel /hooks"));
        }
        if listeners.oauth_callback {
            return refuse(Unsupported::ListenerUnderProcessLocal("OAuth callback"));
        }
    }

    if matches!(options.profile, ComposeProfile::Embedded { .. }) {
        if let ClientApiOptions::Loopback {
            admission: Admission::SameUserLoopback,
            ..
        } = options.client_api
        {
            return refuse(Unsupported::EmbeddedAdmission);
        }
    }

    check_wasm_engine(options.wasm_engine, host.pulley_supported)
        .map_err(ComposeError::Unsupported)?;

    Ok(Plan { home, state_root })
}

/// A compiled iOS / Android binary composes only `Embedded { platform: that }`.
fn compiled_target_rule(
    options: &ComposeOptions,
    compiled: Option<HostPlatform>,
) -> Result<(), Unsupported> {
    let Some(compiled) = compiled else {
        return Ok(());
    };
    if !compiled.is_mobile() {
        return Ok(());
    }
    match options.profile {
        ComposeProfile::Embedded { platform } if platform == compiled => Ok(()),
        _ => Err(Unsupported::PlatformMismatch { compiled }),
    }
}

/// Allowed combinations of the ADR D3 platform table. First broken column wins:
/// instance, then processes, then engine.
fn row_allows(
    platform: HostPlatform,
    instance: InstanceGuard,
    processes: ProcessPolicy,
    engine: WasmEngine,
) -> Result<(), PlatformRule> {
    if platform.is_mobile() {
        if instance != InstanceGuard::ProcessLocal {
            return Err(PlatformRule::Instance);
        }
        if !processes.is_forbid() {
            return Err(PlatformRule::Processes);
        }
        if engine != WasmEngine::Pulley {
            return Err(PlatformRule::Engine);
        }
    } else if !matches!(instance, InstanceGuard::PidLockFile { .. }) {
        return Err(PlatformRule::Instance);
    }
    Ok(())
}

fn check_wasm_engine(engine: WasmEngine, pulley_supported: bool) -> Result<(), Unsupported> {
    match engine {
        WasmEngine::Native => Ok(()),
        WasmEngine::Pulley if pulley_supported => Ok(()),
        WasmEngine::Pulley => Err(Unsupported::WasmEngineUnavailable {
            engine: WasmEngine::Pulley,
            reason: "pulley64 needs a 64-bit little-endian host",
        }),
    }
}

fn wasm_backend(engine: WasmEngine) -> advance_runtime::WasmBackend {
    match engine {
        WasmEngine::Native => advance_runtime::WasmBackend::Native,
        WasmEngine::Pulley => advance_runtime::WasmBackend::Pulley,
    }
}

fn engine_of(report: &advance_runtime::EngineReport) -> WasmEngine {
    if report.host.is_pulley && report.tool.is_pulley {
        WasmEngine::Pulley
    } else {
        WasmEngine::Native
    }
}

/// `path` canonicalized, when it is an absolute path to an existing directory.
fn canonical_directory(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    std::fs::canonicalize(path)
        .ok()
        .filter(|canonical| canonical.is_dir())
}

/// The canonical state root: an absolute, existing directory outside the home.
fn validate_state_root(root: &Path, home: &Path) -> Result<PathBuf, ComposeError> {
    let refuse = |reason: &'static str| {
        Err(ComposeError::Unsupported(Unsupported::StateRoot {
            path: root.to_path_buf(),
            reason,
        }))
    };
    if !root.is_absolute() {
        return refuse("is not an absolute path");
    }
    let Some(canonical) = canonical_directory(root) else {
        return refuse("is not an existing directory");
    };
    if canonical.starts_with(home) {
        return refuse("lies inside the home");
    }
    Ok(canonical)
}

/// Whether the home's config makes the composition bind the channel `/hooks` listener
/// (a listen address and at least one channel).
fn channels_need_hooks(config: &RuntimeConfig) -> bool {
    config.channels.webhook_listen_addr.is_some() && !config.channels.channels.is_empty()
}

// Compile-time witnesses: `compose`'s future is `Send + 'static` (it can be spawned on
// any runtime), and the values a host keeps or moves between tasks are `Send + Sync`.
const _: () = {
    fn assert_send_static<F, Fut>(_: F)
    where
        F: Fn(ComposeOptions, Vec<Arc<dyn ComposeExtension>>) -> Fut,
        Fut: std::future::Future<Output = Result<ComposedRuntime, ComposeError>> + Send + 'static,
    {
    }
    #[allow(dead_code)]
    fn witness() {
        assert_send_static(compose);
    }
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    fn assert_send<T: Send + 'static>() {}
    #[allow(dead_code)]
    fn _object_safe(_: &dyn ComposeExtension) {}
    #[allow(dead_code)]
    fn witness_types() {
        assert_send_sync::<ComposedRuntime>();
        assert_send_sync::<ShutdownHandle>();
        assert_send_sync::<ComposeOptions>();
        assert_send_sync::<ComposeError>();
        assert_send::<RuntimeHealthView>();
        assert_send_sync::<crate::wiring::GatewayInference>();
    }
    #[allow(dead_code)]
    fn witness_ext_types() {
        assert_send_sync::<crate::api::ComposeCx>();
        assert_send_sync::<crate::api::StartedCx>();
        assert_send_sync::<crate::api::ExtensionEmitter>();
        assert_send_sync::<crate::api::RunView>();
        assert_send_sync::<crate::api::ExtensionGrantCheck>();
        assert_send_sync::<crate::api::ExtensionSecrets>();
        assert_send_sync::<crate::api::TaskSpawner>();
        assert_send_sync::<crate::api::ConfigView>();
        assert_send_sync::<crate::api::GatewayHandle>();
        assert_send_sync::<crate::api::ExtensionError>();
        assert_send_sync::<crate::api::ExtensionHealth>();
        assert_send_sync::<ExtensionSet>();
        assert_send_sync::<crate::extension::call::CallIdentity>();
        assert_send_sync::<crate::api::HostFunctionRegistrar>();
        assert_send_sync::<crate::extension::host_functions::ContainedHostFunction>();
        assert_send_sync::<crate::api::ToolRegistrar>();
        assert_send_sync::<crate::extension::tools::ContainedHostTool>();
        assert_send_sync::<crate::api::InferenceContribution>();
        assert_send_sync::<crate::inference::ExtensionHold>();
        assert_send_sync::<crate::inference::contained::ContainedInferencePort>();
        assert_send_sync::<crate::inference::contained::ContainedMeshDispatch>();
        assert_send::<crate::inference::contained::ContainedStream>();
        assert_send_sync::<crate::inference::ComposedClaimedPreflight>();
        assert_send_sync::<crate::inference::ClaimedPreflightStopper>();
        assert_send::<advance_client_api::ExtensionFamilies>();
        assert_send_sync::<advance_client_api::ExtensionRouteGate>();
        assert_send_sync::<crate::api::ClientApiCheck>();
        assert_send_sync::<crate::api::ClientApiRebindError>();
        fn _reverify_future_is_send(rt: &ComposedRuntime) {
            fn assert_send<T: Send>(_: T) {}
            assert_send(rt.reverify_client_api());
        }
    }
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ListenerOptions, NullComposeLog, Zeroizing};

    fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
        (dir, path)
    }

    fn daemon(home: &Path) -> ComposeOptions {
        ComposeOptions::daemon(home, Arc::new(NullComposeLog))
    }

    fn refused(options: &ComposeOptions) -> Unsupported {
        match validate(options) {
            Err(ComposeError::Unsupported(what)) => what,
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn module_001_ac30_config_path_is_under_the_home_advance_dir() {
        assert_eq!(
            config_path(Path::new("/w")),
            PathBuf::from("/w/.advance/runtime-config.yaml")
        );
    }

    #[test]
    fn module_001_ac30_validate_accepts_the_daemon_options_and_a_process_local_guard() {
        let (_home_dir, home) = canonical_tempdir();
        let (_root_dir, root) = canonical_tempdir();
        assert_eq!(
            validate(&daemon(&home)).unwrap(),
            Plan {
                home: home.clone(),
                state_root: None
            }
        );
        let options = daemon(&home)
            .with_instance(InstanceGuard::ProcessLocal)
            .with_client_api(ClientApiOptions::loopback(
                0,
                false,
                Admission::SameUserLoopback,
            ))
            .with_state_root(&root)
            .with_master_key(MasterKeyInput::Provided(Zeroizing::new([1; 32])))
            .with_listeners(ListenerOptions::none());
        assert_eq!(
            validate(&options).unwrap(),
            Plan {
                home: home.clone(),
                state_root: Some(root)
            }
        );
        let off = daemon(&home)
            .with_instance(InstanceGuard::ProcessLocal)
            .with_client_api(ClientApiOptions::Off)
            .with_listeners(ListenerOptions::none());
        assert!(validate(&off).is_ok());
        assert!(validate(&daemon(&home).with_processes(ProcessPolicy::Forbid)).is_ok());
        assert!(validate(&daemon(&home).with_hot_reload(false)).is_ok());
        assert!(validate(
            &daemon(&home).with_listeners(ListenerOptions::daemon().with_oauth_callback(false))
        )
        .is_ok());
        assert!(
            validate(&daemon(&home).with_client_api(ClientApiOptions::loopback(
                0,
                false,
                Admission::InProcessOnly,
            )))
            .is_ok()
        );
        assert!(validate(&daemon(&home).with_wasm_engine(WasmEngine::Pulley)).is_ok());
    }

    #[test]
    fn module_001_ac30_validate_refuses_a_home_that_is_not_an_absolute_canonical_directory() {
        let (_home_dir, home) = canonical_tempdir();
        std::fs::create_dir(home.join("sub")).unwrap();
        std::fs::write(home.join("file"), b"x").unwrap();
        let not_canonical = home.join("sub").join("..");
        let mut cases = vec![
            PathBuf::from("relative/home"),
            not_canonical,
            home.join("missing"),
            home.join("file"),
        ];
        #[cfg(unix)]
        {
            let link = home.join("link");
            std::os::unix::fs::symlink(home.join("sub"), &link).unwrap();
            cases.push(link);
        }
        for path in cases {
            assert_eq!(
                refused(&daemon(&path)),
                Unsupported::HomeNotCanonical(path.clone())
            );
        }
    }

    #[test]
    fn module_001_ac30_validate_refuses_an_unusable_state_root_and_discovery_without_the_pid_lock()
    {
        let (_home_dir, home) = canonical_tempdir();
        std::fs::create_dir(home.join("inside")).unwrap();
        let cases = [
            (PathBuf::from("relative/root"), "is not an absolute path"),
            (home.join("missing"), "is not an existing directory"),
            (home.clone(), "lies inside the home"),
            (home.join("inside"), "lies inside the home"),
        ];
        for (root, reason) in cases {
            assert_eq!(
                refused(&daemon(&home).with_state_root(&root)),
                Unsupported::StateRoot { path: root, reason }
            );
        }
        assert_eq!(
            refused(&daemon(&home).with_instance(InstanceGuard::ProcessLocal)),
            Unsupported::DiscoveryRequiresPidLock
        );
    }

    /// A refused option leaves nothing behind: no lock file, no reservation. A missing
    /// runtime config is reported after the guard was released.
    #[tokio::test]
    async fn module_001_ac30_compose_refusals_leave_no_guard_behind() {
        let (_home_dir, home) = canonical_tempdir();
        let error = compose(
            daemon(&home).with_instance(InstanceGuard::ProcessLocal),
            Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ComposeError::Unsupported(Unsupported::DiscoveryRequiresPidLock)
        ));
        assert!(!home.join(".runtime").exists(), "nothing was written");
        assert!(!crate::registry::reserved_homes_for_test().contains(&home));

        let error = compose(daemon(&home), Vec::new()).await.unwrap_err();
        assert!(
            matches!(&error, ComposeError::ConfigNotFound { path } if *path == config_path(&home)),
            "{error:?}"
        );
        assert!(
            !home.join(".runtime").join("runtime.lock").exists(),
            "the lock taken before the config was read is released"
        );
        assert!(!crate::registry::reserved_homes_for_test().contains(&home));
    }

    /// While a home is reserved in this process, a second composition is refused before
    /// any lock is tried.
    #[tokio::test]
    async fn module_001_ac30_compose_refuses_a_home_reserved_in_this_process() {
        let (_home_dir, home) = canonical_tempdir();
        let held = HomeReservation::acquire(home.clone()).unwrap();
        let error = compose(daemon(&home), Vec::new()).await.unwrap_err();
        assert!(
            matches!(error, ComposeError::Lock(LockFailure::HeldInProcess)),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "failed to acquire runtime lock: another runtime active (pid={})",
                std::process::id()
            )
        );
        assert!(!home.join(".runtime").exists(), "no lock was tried");
        drop(held);
    }

    #[test]
    fn module_001_ac32_pulley_needs_a_64_bit_little_endian_host() {
        let (_home_dir, home) = canonical_tempdir();
        assert!(matches!(
            check_wasm_engine(WasmEngine::Pulley, false),
            Err(Unsupported::WasmEngineUnavailable {
                engine: WasmEngine::Pulley,
                reason: "pulley64 needs a 64-bit little-endian host",
            })
        ));
        assert_eq!(
            ComposeError::Unsupported(Unsupported::WasmEngineUnavailable {
                engine: WasmEngine::Pulley,
                reason: "pulley64 needs a 64-bit little-endian host",
            })
            .to_string(),
            "unsupported: the Pulley wasm engine is not available on this host: pulley64 needs a 64-bit little-endian host"
        );
        assert!(check_wasm_engine(WasmEngine::Pulley, true).is_ok());
        assert!(check_wasm_engine(WasmEngine::Native, false).is_ok());

        let pulley = daemon(&home).with_wasm_engine(WasmEngine::Pulley);
        match validate_on(
            &pulley,
            HostFacts {
                compiled: None,
                pulley_supported: false,
            },
        ) {
            Err(ComposeError::Unsupported(Unsupported::WasmEngineUnavailable {
                engine: WasmEngine::Pulley,
                reason: "pulley64 needs a 64-bit little-endian host",
            })) => {}
            other => panic!("expected WasmEngineUnavailable, got {other:?}"),
        }
        assert!(validate_on(
            &pulley,
            HostFacts {
                compiled: None,
                pulley_supported: true,
            },
        )
        .is_ok());
    }

    #[test]
    fn module_001_ac32_wasm_engine_check_runs_after_the_platform_table_rows() {
        let (_home_dir, home) = canonical_tempdir();
        let (_root_dir, state_root) = canonical_tempdir();
        let log = Arc::new(NullComposeLog);

        let ios_native = ComposeOptions::embedded(
            &home,
            HostPlatform::Ios,
            Arc::clone(&log) as Arc<dyn crate::api::ComposeLog>,
        )
        .with_state_root(&state_root)
        .with_wasm_engine(WasmEngine::Native);
        match validate_on(
            &ios_native,
            HostFacts {
                compiled: None,
                pulley_supported: true,
            },
        ) {
            Err(ComposeError::Unsupported(Unsupported::PlatformTable {
                platform: HostPlatform::Ios,
                rule: PlatformRule::Engine,
            })) => {}
            other => panic!("expected PlatformTable Engine, got {other:?}"),
        }

        let ios_default = ComposeOptions::embedded(
            &home,
            HostPlatform::Ios,
            Arc::clone(&log) as Arc<dyn crate::api::ComposeLog>,
        )
        .with_state_root(&state_root);
        match validate_on(
            &ios_default,
            HostFacts {
                compiled: None,
                pulley_supported: false,
            },
        ) {
            Err(ComposeError::Unsupported(Unsupported::WasmEngineUnavailable {
                engine: WasmEngine::Pulley,
                ..
            })) => {}
            other => panic!("expected WasmEngineUnavailable, got {other:?}"),
        }

        let ios_no_root = ComposeOptions::embedded(
            &home,
            HostPlatform::Ios,
            log as Arc<dyn crate::api::ComposeLog>,
        );
        match validate_on(
            &ios_no_root,
            HostFacts {
                compiled: None,
                pulley_supported: false,
            },
        ) {
            Err(ComposeError::Unsupported(Unsupported::StateRootRequired {
                platform: HostPlatform::Ios,
            })) => {}
            other => panic!("expected StateRootRequired, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod module_001_ac32_platform_tests {
    use super::*;
    use crate::api::NullComposeLog;

    fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
        (dir, path)
    }

    #[test]
    fn module_001_ac32_platform_table_matrix() {
        let platforms = [
            HostPlatform::MacOs,
            HostPlatform::Ios,
            HostPlatform::Android,
            HostPlatform::Windows,
            HostPlatform::Linux,
        ];
        let instances = [InstanceGuard::ProcessLocal, InstanceGuard::pid_lock()];
        let processes = [ProcessPolicy::Allow, ProcessPolicy::Forbid];
        let engines = [WasmEngine::Native, WasmEngine::Pulley];
        for platform in platforms {
            for instance in instances {
                for process in processes {
                    for engine in engines {
                        let got = row_allows(platform, instance, process, engine);
                        let expected = expected_row(platform, instance, process, engine);
                        assert_eq!(
                            got, expected,
                            "{platform:?} instance={instance:?} processes={process:?} engine={engine:?}"
                        );
                        if let Err(rule) = got {
                            let text = Unsupported::PlatformTable { platform, rule }.to_string();
                            match rule {
                                PlatformRule::Instance if platform.is_mobile() => {
                                    assert_eq!(
                                        text,
                                        format!(
                                            "the {platform} embedded profile requires the process-local instance guard"
                                        )
                                    );
                                }
                                PlatformRule::Instance => {
                                    assert_eq!(
                                        text,
                                        format!(
                                            "the {platform} embedded profile requires the pid-lock instance guard"
                                        )
                                    );
                                }
                                PlatformRule::Processes => {
                                    assert_eq!(
                                        text,
                                        format!(
                                            "the {platform} embedded profile requires processes forbid"
                                        )
                                    );
                                }
                                PlatformRule::Engine => {
                                    assert_eq!(
                                        text,
                                        format!(
                                            "the {platform} embedded profile requires the pulley engine"
                                        )
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn expected_row(
        platform: HostPlatform,
        instance: InstanceGuard,
        processes: ProcessPolicy,
        engine: WasmEngine,
    ) -> Result<(), PlatformRule> {
        if platform.is_mobile() {
            if instance != InstanceGuard::ProcessLocal {
                return Err(PlatformRule::Instance);
            }
            if !processes.is_forbid() {
                return Err(PlatformRule::Processes);
            }
            if engine != WasmEngine::Pulley {
                return Err(PlatformRule::Engine);
            }
            Ok(())
        } else if matches!(instance, InstanceGuard::PidLockFile { .. }) {
            Ok(())
        } else {
            Err(PlatformRule::Instance)
        }
    }

    #[test]
    fn module_001_ac32_d3_compiled_mobile_target_composes_only_its_embedded_row() {
        let (_home_dir, home) = canonical_tempdir();
        let log = Arc::new(NullComposeLog);
        let daemon =
            ComposeOptions::daemon(&home, Arc::clone(&log) as Arc<dyn crate::api::ComposeLog>);
        let android = ComposeOptions::embedded(
            &home,
            HostPlatform::Android,
            Arc::clone(&log) as Arc<dyn crate::api::ComposeLog>,
        );
        let ios = ComposeOptions::embedded(
            &home,
            HostPlatform::Ios,
            log as Arc<dyn crate::api::ComposeLog>,
        );

        assert_eq!(
            compiled_target_rule(&daemon, Some(HostPlatform::Ios)),
            Err(Unsupported::PlatformMismatch {
                compiled: HostPlatform::Ios
            })
        );
        assert_eq!(
            compiled_target_rule(&android, Some(HostPlatform::Ios)),
            Err(Unsupported::PlatformMismatch {
                compiled: HostPlatform::Ios
            })
        );
        assert_eq!(compiled_target_rule(&ios, Some(HostPlatform::Ios)), Ok(()));
        assert_eq!(
            compiled_target_rule(&ios, Some(HostPlatform::Linux)),
            Ok(())
        );
        assert_eq!(
            compiled_target_rule(&daemon, Some(HostPlatform::Linux)),
            Ok(())
        );
        assert_eq!(compiled_target_rule(&ios, None), Ok(()));

        assert_eq!(
            match validate_with_compiled(&daemon, Some(HostPlatform::Ios)) {
                Err(ComposeError::Unsupported(what)) => what,
                other => panic!("expected PlatformMismatch, got {other:?}"),
            },
            Unsupported::PlatformMismatch {
                compiled: HostPlatform::Ios
            }
        );
        assert_eq!(
            Unsupported::PlatformMismatch {
                compiled: HostPlatform::Ios
            }
            .to_string(),
            "this build targets ios; only the ios embedded profile can compose here"
        );
    }
}
