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
    ComposedRuntime, InstanceGuard, LockFailure, MasterKeyInput, ProcessPolicy, RuntimeHealthView,
    ShutdownHandle, Unsupported, WasmEngine,
};
use crate::compose_log::LogHandle;
use crate::composition::{Composition, GuardHold, RuntimeView, TeardownReason};
use crate::daemon::{compose_graph, GraphFailure, GraphOptions, PartialGraph};
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
        #[cfg(feature = "test-support")]
        failpoints,
        ..
    } = options;
    let log = LogHandle::new(log);

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
            match RuntimeLock::acquire(&plan.home, heartbeat).await {
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
    let builder = match RuntimeHostBuilder::new(&config_path, &plan.home).await {
        Ok(builder) => builder,
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
            #[cfg(feature = "test-support")]
            probe: failpoints.probe.clone(),
            #[cfg(feature = "test-support")]
            fail_after_git_queue: failpoints.wiring_after_git_queue,
            ..WiringOptions::compat()
        },
        #[cfg(feature = "test-support")]
        failpoints: failpoints.clone(),
    };
    match compose_graph(builder, &plan.home, opts).await {
        Ok(graph) => {
            let view = Arc::new(RuntimeView::new(
                graph.wiring_handles.root_agent_id.clone(),
                graph.client_api_endpoint(),
                graph.agent_loop_done(),
                instance_guard,
            ));
            let composition =
                Composition::from_graph(graph, config_watcher, wal_observer, guard, log)
                    .with_extensions(extensions)
                    .with_view(Arc::clone(&view));
            #[cfg(feature = "test-support")]
            let composition = composition.with_probe(failpoints.probe.clone());
            // The one task that owns the composition: it runs the shutdown sequence once
            // the handle is triggered.
            let shutdown = ShutdownHandle::new();
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
                PartialGraph::Graph(graph) => {
                    Composition::from_graph(*graph, config_watcher, wal_observer, guard, log)
                }
                PartialGraph::Wiring(stoppers) => Composition::from_stoppers(
                    stoppers,
                    Some(config_watcher),
                    wal_observer,
                    Some(guard),
                    log,
                ),
            };
            let composition = composition.with_extensions(extensions);
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

/// Check every option value before anything starts. Reads the file system only to
/// canonicalize paths already known to be absolute (never the current directory).
pub(crate) fn validate(options: &ComposeOptions) -> Result<Plan, ComposeError> {
    let refuse = |what: Unsupported| Err(ComposeError::Unsupported(what));

    let home = match canonical_directory(&options.home) {
        Some(home) if home == options.home => home,
        _ => return refuse(Unsupported::HomeNotCanonical(options.home.clone())),
    };

    // Option values this build does not compose.
    if matches!(options.profile, ComposeProfile::Embedded { .. }) {
        return refuse(Unsupported::NotYetAvailable("ComposeProfile::Embedded"));
    }
    if options.processes == ProcessPolicy::Forbid {
        return refuse(Unsupported::NotYetAvailable("ProcessPolicy::Forbid"));
    }
    if options.wasm_engine == WasmEngine::Pulley {
        return refuse(Unsupported::NotYetAvailable("WasmEngine::Pulley"));
    }
    if !options.hot_reload {
        return refuse(Unsupported::NotYetAvailable("hot_reload: false"));
    }
    if !options.listeners.oauth_callback {
        return refuse(Unsupported::NotYetAvailable(
            "listeners.oauth_callback: false",
        ));
    }
    if let ClientApiOptions::Loopback {
        admission: Admission::InProcessOnly,
        ..
    } = options.client_api
    {
        return refuse(Unsupported::NotYetAvailable("Admission::InProcessOnly"));
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

    Ok(Plan { home, state_root })
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
    fn witness_types() {
        assert_send_sync::<ComposedRuntime>();
        assert_send_sync::<ShutdownHandle>();
        assert_send_sync::<ComposeOptions>();
        assert_send_sync::<ComposeError>();
        assert_send::<RuntimeHealthView>();
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
            .with_listeners(
                ListenerOptions::daemon()
                    .with_post_msg(false)
                    .with_event_bus_ws(false)
                    .with_channel_hooks(false),
            );
        assert_eq!(
            validate(&options).unwrap(),
            Plan {
                home: home.clone(),
                state_root: Some(root)
            }
        );
        let off = daemon(&home)
            .with_instance(InstanceGuard::ProcessLocal)
            .with_client_api(ClientApiOptions::Off);
        assert!(validate(&off).is_ok());
    }

    #[test]
    fn module_001_ac30_validate_refuses_each_value_this_build_does_not_compose() {
        let (_home_dir, home) = canonical_tempdir();
        let cases = [
            (
                daemon(&home).with_profile(ComposeProfile::Embedded {
                    platform: crate::api::HostPlatform::Ios,
                }),
                "ComposeProfile::Embedded",
            ),
            (
                daemon(&home).with_processes(ProcessPolicy::Forbid),
                "ProcessPolicy::Forbid",
            ),
            (
                daemon(&home).with_wasm_engine(WasmEngine::Pulley),
                "WasmEngine::Pulley",
            ),
            (daemon(&home).with_hot_reload(false), "hot_reload: false"),
            (
                daemon(&home).with_listeners(ListenerOptions::daemon().with_oauth_callback(false)),
                "listeners.oauth_callback: false",
            ),
            (
                daemon(&home).with_client_api(ClientApiOptions::loopback(
                    0,
                    true,
                    Admission::InProcessOnly,
                )),
                "Admission::InProcessOnly",
            ),
        ];
        for (options, what) in cases {
            assert_eq!(refused(&options), Unsupported::NotYetAvailable(what));
        }
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
        let error = compose(daemon(&home).with_hot_reload(false), Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ComposeError::Unsupported(Unsupported::NotYetAvailable("hot_reload: false"))
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
}
