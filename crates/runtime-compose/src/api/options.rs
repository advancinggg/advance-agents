//! What a composition is asked to compose.
//!
//! [`ComposeOptions::daemon`] is exactly what `advance start` composes. Every other
//! value either composes a narrower runtime (no Client API, no `POST /msg`
//! listener, no EventBus server, a process-local instance guard, platform state
//! under a given root, a master key supplied by the host) or is refused before
//! anything starts with [`ComposeError::Unsupported`](crate::api::ComposeError).

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub use zeroize::Zeroizing;

use super::compose_log::ComposeLog;

/// The options of one composition.
///
/// The fields are public, so a host can change one field of a preset
/// (`let mut o = ComposeOptions::daemon(home, log); o.listeners.post_msg = false;`) or
/// use the `with_*` builders.
#[non_exhaustive]
#[derive(Clone)]
pub struct ComposeOptions {
    /// The home (workspace) to compose: an absolute, canonical directory. The caller
    /// resolves it (flag, environment, current directory); the composition never does.
    pub home: PathBuf,
    pub profile: ComposeProfile,
    pub instance: InstanceGuard,
    /// Where platform state that must live outside the home is kept: the
    /// progress-lifecycle anchor under `<root>/contract216` and the CONTRACT-218
    /// platform directory under `<root>/contract218/<sha256(home)>`. `None` keeps the
    /// process `HOME` / `XDG_STATE_HOME` locations.
    pub state_root: Option<PathBuf>,
    pub master_key: MasterKeyInput,
    pub client_api: ClientApiOptions,
    pub listeners: ListenerOptions,
    pub processes: ProcessPolicy,
    pub wasm_engine: WasmEngine,
    /// Whether the runtime config and the installed packs are watched and applied live.
    pub hot_reload: bool,
    /// Where every line the composition emits goes.
    pub log: Arc<dyn ComposeLog>,
}

impl ComposeOptions {
    /// Exactly what `advance start` composes: the daemon profile, the pid lock with a
    /// 30-second heartbeat, platform state under the process `HOME`, the master key the
    /// runtime config selects, the loopback Client API on an OS-assigned port with its
    /// discovery file, every listener under its usual conditions, child processes
    /// allowed, the native engine, and hot reload on. Lines go to `log`; the library has
    /// no default sink that prints.
    pub fn daemon(home: impl Into<PathBuf>, log: Arc<dyn ComposeLog>) -> Self {
        Self {
            home: home.into(),
            profile: ComposeProfile::Daemon,
            instance: InstanceGuard::pid_lock(),
            state_root: None,
            master_key: MasterKeyInput::FromConfig,
            client_api: ClientApiOptions::daemon(),
            listeners: ListenerOptions::daemon(),
            processes: ProcessPolicy::Allow,
            wasm_engine: WasmEngine::Native,
            hot_reload: true,
            log,
        }
    }

    pub fn with_profile(mut self, profile: ComposeProfile) -> Self {
        self.profile = profile;
        self
    }

    pub fn with_instance(mut self, instance: InstanceGuard) -> Self {
        self.instance = instance;
        self
    }

    pub fn with_state_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.state_root = Some(root.into());
        self
    }

    pub fn with_master_key(mut self, key: MasterKeyInput) -> Self {
        self.master_key = key;
        self
    }

    pub fn with_client_api(mut self, client_api: ClientApiOptions) -> Self {
        self.client_api = client_api;
        self
    }

    pub fn with_listeners(mut self, listeners: ListenerOptions) -> Self {
        self.listeners = listeners;
        self
    }

    pub fn with_processes(mut self, processes: ProcessPolicy) -> Self {
        self.processes = processes;
        self
    }

    pub fn with_wasm_engine(mut self, engine: WasmEngine) -> Self {
        self.wasm_engine = engine;
        self
    }

    pub fn with_hot_reload(mut self, on: bool) -> Self {
        self.hot_reload = on;
        self
    }
}

impl fmt::Debug for ComposeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComposeOptions")
            .field("home", &self.home)
            .field("profile", &self.profile)
            .field("instance", &self.instance)
            .field("state_root", &self.state_root)
            .field("master_key", &self.master_key)
            .field("client_api", &self.client_api)
            .field("listeners", &self.listeners)
            .field("processes", &self.processes)
            .field("wasm_engine", &self.wasm_engine)
            .field("hot_reload", &self.hot_reload)
            .field("log", &format_args!("<ComposeLog>"))
            .finish_non_exhaustive()
    }
}

/// What kind of runtime is composed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeProfile {
    /// The desktop daemon `advance start` runs.
    Daemon,
    /// A runtime embedded in a host application on `platform`.
    Embedded { platform: HostPlatform },
}

/// The platform an embedded runtime runs on.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostPlatform {
    MacOs,
    Ios,
    Android,
    Windows,
    Linux,
}

/// How the composition makes sure it is the only runtime of its home.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceGuard {
    /// The cross-process pid lock `.runtime/runtime.lock`, refreshed every `heartbeat`,
    /// plus the process-local registry.
    PidLockFile { heartbeat: Duration },
    /// The process-local registry only: no lock file is written.
    ProcessLocal,
}

impl InstanceGuard {
    /// The pid lock `advance start` takes (a 30-second heartbeat).
    pub const fn pid_lock() -> Self {
        InstanceGuard::PidLockFile {
            heartbeat: Duration::from_secs(30),
        }
    }
}

/// Where the master key comes from.
#[derive(Clone)]
pub enum MasterKeyInput {
    /// The source the home's runtime config selects (`secrets:`), loaded as
    /// `advance start` loads it.
    FromConfig,
    /// A key the host holds. It is used as given whenever the composition needs a key:
    /// it is never loaded, migrated, minted or written anywhere.
    Provided(Zeroizing<[u8; 32]>),
}

impl fmt::Debug for MasterKeyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MasterKeyInput::FromConfig => f.write_str("FromConfig"),
            MasterKeyInput::Provided(_) => f.write_str("Provided(<redacted>)"),
        }
    }
}

/// Whether and how the Client API listens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientApiOptions {
    /// No Client API: nothing is bound and no discovery file is written.
    Off,
    /// A loopback listener on `port` (0 = OS-assigned). `write_discovery` writes
    /// `.runtime/client-api` once it is bound.
    #[non_exhaustive]
    Loopback {
        port: u16,
        write_discovery: bool,
        admission: Admission,
    },
}

impl ClientApiOptions {
    /// What `advance start` binds: an OS-assigned loopback port, the discovery file,
    /// same-user loopback admission.
    pub const fn daemon() -> Self {
        ClientApiOptions::Loopback {
            port: 0,
            write_discovery: true,
            admission: Admission::SameUserLoopback,
        }
    }

    pub const fn loopback(port: u16, write_discovery: bool, admission: Admission) -> Self {
        ClientApiOptions::Loopback {
            port,
            write_discovery,
            admission,
        }
    }
}

/// Who the Client API admits.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The loopback rule `advance start` applies.
    SameUserLoopback,
    /// Only sessions minted inside the host process.
    InProcessOnly,
}

/// The listeners besides the Client API. Each one that is on is bound under the
/// conditions `advance start` binds it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerOptions {
    /// The `POST /msg` listener (a deployed driver and no channels configured).
    pub post_msg: bool,
    /// The EventBus HTTP / WebSocket server (`/events`, `/query`).
    pub event_bus_ws: bool,
    /// The channel `/hooks` listener (channels configured and a deployed driver).
    pub channel_hooks: bool,
    /// The ChatGPT sign-in callback listener (one per sign-in attempt).
    pub oauth_callback: bool,
}

impl ListenerOptions {
    /// Every listener on, as `advance start` runs.
    pub const fn daemon() -> Self {
        Self {
            post_msg: true,
            event_bus_ws: true,
            channel_hooks: true,
            oauth_callback: true,
        }
    }

    /// Every listener off.
    pub const fn none() -> Self {
        Self {
            post_msg: false,
            event_bus_ws: false,
            channel_hooks: false,
            oauth_callback: false,
        }
    }

    pub fn with_post_msg(mut self, on: bool) -> Self {
        self.post_msg = on;
        self
    }

    pub fn with_event_bus_ws(mut self, on: bool) -> Self {
        self.event_bus_ws = on;
        self
    }

    pub fn with_channel_hooks(mut self, on: bool) -> Self {
        self.channel_hooks = on;
        self
    }

    pub fn with_oauth_callback(mut self, on: bool) -> Self {
        self.oauth_callback = on;
        self
    }
}

impl Default for ListenerOptions {
    fn default() -> Self {
        Self::daemon()
    }
}

/// Whether the runtime may start child processes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProcessPolicy {
    #[default]
    Allow,
    Forbid,
}

/// How WebAssembly components are executed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WasmEngine {
    /// Native code generation.
    #[default]
    Native,
    /// The portable interpreter.
    Pulley,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::NullComposeLog;

    #[test]
    fn module_001_ac30_daemon_options_are_what_advance_start_composes() {
        let options = ComposeOptions::daemon("/home", Arc::new(NullComposeLog));
        assert_eq!(options.home, PathBuf::from("/home"));
        assert_eq!(options.profile, ComposeProfile::Daemon);
        assert_eq!(
            options.instance,
            InstanceGuard::PidLockFile {
                heartbeat: Duration::from_secs(30)
            }
        );
        assert!(options.state_root.is_none());
        assert!(matches!(options.master_key, MasterKeyInput::FromConfig));
        assert_eq!(
            options.client_api,
            ClientApiOptions::loopback(0, true, Admission::SameUserLoopback)
        );
        assert_eq!(options.listeners, ListenerOptions::daemon());
        assert_eq!(options.listeners, ListenerOptions::default());
        assert_eq!(options.processes, ProcessPolicy::Allow);
        assert_eq!(options.wasm_engine, WasmEngine::Native);
        assert!(options.hot_reload);
    }

    #[test]
    fn module_001_ac30_builders_set_one_field_each() {
        let options = ComposeOptions::daemon("/home", Arc::new(NullComposeLog))
            .with_instance(InstanceGuard::ProcessLocal)
            .with_state_root("/state")
            .with_client_api(ClientApiOptions::Off)
            .with_listeners(ListenerOptions::none().with_event_bus_ws(true))
            .with_hot_reload(false);
        assert_eq!(options.instance, InstanceGuard::ProcessLocal);
        assert_eq!(options.state_root, Some(PathBuf::from("/state")));
        assert_eq!(options.client_api, ClientApiOptions::Off);
        assert_eq!(
            options.listeners,
            ListenerOptions {
                post_msg: false,
                event_bus_ws: true,
                channel_hooks: false,
                oauth_callback: false,
            }
        );
        assert!(!options.hot_reload);
        assert_eq!(options.processes, ProcessPolicy::default());
        assert_eq!(options.wasm_engine, WasmEngine::default());
    }

    /// A provided master key never reaches a `Debug` rendering.
    #[test]
    fn module_001_ac30_debug_redacts_a_provided_master_key() {
        let key = [0xa7u8; 32];
        let options = ComposeOptions::daemon("/home", Arc::new(NullComposeLog))
            .with_master_key(MasterKeyInput::Provided(Zeroizing::new(key)));
        let rendered = format!("{options:?} {:?}", options.master_key);
        assert!(rendered.contains("Provided(<redacted>)"), "{rendered}");
        assert!(rendered.contains("<ComposeLog>"), "{rendered}");
        for needle in [hex::encode(key), "167".to_owned(), "a7".to_owned()] {
            assert!(!rendered.contains(&needle), "{needle} in {rendered}");
        }
    }
}
