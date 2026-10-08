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
    /// Test-only failpoints and observers (all off by default).
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub failpoints: crate::test_support::ComposeFailpoints,
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
            #[cfg(feature = "test-support")]
            failpoints: crate::test_support::ComposeFailpoints::default(),
        }
    }

    /// The ADR D3 embedded profile for `platform`. The single definition of the
    /// embedded defaults: the CONTRACT-210 bridge builds every v2 `full`
    /// composition as `embedded(..)` followed by its options_json overrides
    /// (processes, engine, state_root, client_api port or `Off`, master key).
    ///
    /// | field        | iOS / Android                         | macOS / Windows / Linux                                   |
    /// |--------------|---------------------------------------|-----------------------------------------------------------|
    /// | profile      | `Embedded { platform }`               | `Embedded { platform }`                                   |
    /// | instance     | `ProcessLocal`                        | `InstanceGuard::pid_lock()` (30 s)                        |
    /// | processes    | `Forbid`                              | `Allow`                                                   |
    /// | wasm_engine  | `Pulley`                              | `Native`                                                  |
    /// | listeners    | `ListenerOptions::none()`             | `ListenerOptions::daemon().with_post_msg(false).with_event_bus_ws(false)` |
    /// | client_api   | `loopback(0, false, InProcessOnly)`   | `loopback(0, false, InProcessOnly)`                       |
    /// | hot_reload   | `true`                                | `true`                                                    |
    /// | state_root   | `None` (required: `compose` refuses `None` here) | `None` (optional)                              |
    /// | master_key   | `FromConfig`                          | `FromConfig`                                              |
    /// | log          | the caller's                          | the caller's                                              |
    pub fn embedded(
        home: impl Into<PathBuf>,
        platform: HostPlatform,
        log: Arc<dyn ComposeLog>,
    ) -> Self {
        let mobile = platform.is_mobile();
        Self {
            home: home.into(),
            profile: ComposeProfile::Embedded { platform },
            instance: if mobile {
                InstanceGuard::ProcessLocal
            } else {
                InstanceGuard::pid_lock()
            },
            state_root: None,
            master_key: MasterKeyInput::FromConfig,
            client_api: ClientApiOptions::loopback(0, false, Admission::InProcessOnly),
            listeners: if mobile {
                ListenerOptions::none()
            } else {
                ListenerOptions::daemon()
                    .with_post_msg(false)
                    .with_event_bus_ws(false)
            },
            processes: platform.default_processes(),
            wasm_engine: platform.default_engine(),
            hot_reload: true,
            log,
            #[cfg(feature = "test-support")]
            failpoints: crate::test_support::ComposeFailpoints::default(),
        }
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn with_failpoints(mut self, failpoints: crate::test_support::ComposeFailpoints) -> Self {
        self.failpoints = failpoints;
        self
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

impl HostPlatform {
    /// The table row this binary is compiled for; `None` outside the table (e.g. FreeBSD).
    pub const fn compiled() -> Option<HostPlatform> {
        if cfg!(target_os = "macos") {
            Some(HostPlatform::MacOs)
        } else if cfg!(target_os = "ios") {
            Some(HostPlatform::Ios)
        } else if cfg!(target_os = "android") {
            Some(HostPlatform::Android)
        } else if cfg!(target_os = "windows") {
            Some(HostPlatform::Windows)
        } else if cfg!(target_os = "linux") {
            Some(HostPlatform::Linux)
        } else {
            None
        }
    }

    /// `Ios | Android`.
    pub const fn is_mobile(self) -> bool {
        matches!(self, HostPlatform::Ios | HostPlatform::Android)
    }

    /// The options_json spelling: "mac" | "ios" | "android" | "windows" | "linux"
    /// (Display uses it).
    pub const fn as_str(self) -> &'static str {
        match self {
            HostPlatform::MacOs => "mac",
            HostPlatform::Ios => "ios",
            HostPlatform::Android => "android",
            HostPlatform::Windows => "windows",
            HostPlatform::Linux => "linux",
        }
    }

    /// `Forbid` on iOS / Android, else `Allow` (ADR D3 table / options_json defaults).
    pub const fn default_processes(self) -> ProcessPolicy {
        if self.is_mobile() {
            ProcessPolicy::Forbid
        } else {
            ProcessPolicy::Allow
        }
    }

    /// `Pulley` on iOS / Android, else `Native`.
    pub const fn default_engine(self) -> WasmEngine {
        if self.is_mobile() {
            WasmEngine::Pulley
        } else {
            WasmEngine::Native
        }
    }
}

impl fmt::Display for HostPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for HostPlatform {
    type Err = UnknownPlatform;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mac" => Ok(HostPlatform::MacOs),
            "ios" => Ok(HostPlatform::Ios),
            "android" => Ok(HostPlatform::Android),
            "windows" => Ok(HostPlatform::Windows),
            "linux" => Ok(HostPlatform::Linux),
            _ => Err(UnknownPlatform {
                input: s.to_owned(),
            }),
        }
    }
}

/// An options_json `platform` value outside the five spellings (the bridge maps it to 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownPlatform {
    input: String,
}

impl UnknownPlatform {
    pub fn input(&self) -> &str {
        &self.input
    }
}

/// `unknown platform "{input}" (expected mac, ios, android, windows or linux)`
impl fmt::Display for UnknownPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown platform \"{}\" (expected mac, ios, android, windows or linux)",
            self.input
        )
    }
}

impl std::error::Error for UnknownPlatform {}

/// Which column of the ADR D3 platform table an option broke.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformRule {
    Instance,
    Processes,
    Engine,
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
///
/// One type for every spawn site (runtime, capabilities, pack-manager, advance-home).
pub use advance_shared_types::process_policy::ProcessPolicy;

/// How WebAssembly components are executed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WasmEngine {
    /// Cranelift native code (today's engines).
    #[default]
    Native,
    /// Pulley bytecode on both engines (`pulley64`): no executable memory, no signal handler;
    /// each engine reserves the configured maximum memory (`max_memory_pages × 64 KiB`, at most
    /// 4 GiB). Needs a 64-bit little-endian host.
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

#[cfg(test)]
mod module_001_ac32_tests {
    use super::*;
    use crate::api::NullComposeLog;

    #[test]
    fn module_001_ac32_host_platform_spellings_and_compiled_row() {
        for (spelling, platform) in [
            ("mac", HostPlatform::MacOs),
            ("ios", HostPlatform::Ios),
            ("android", HostPlatform::Android),
            ("windows", HostPlatform::Windows),
            ("linux", HostPlatform::Linux),
        ] {
            assert_eq!(platform.as_str(), spelling);
            assert_eq!(platform.to_string(), spelling);
            assert_eq!(spelling.parse::<HostPlatform>().unwrap(), platform);
            assert_eq!(
                platform.is_mobile(),
                matches!(platform, HostPlatform::Ios | HostPlatform::Android)
            );
            if platform.is_mobile() {
                assert_eq!(platform.default_processes(), ProcessPolicy::Forbid);
                assert_eq!(platform.default_engine(), WasmEngine::Pulley);
            } else {
                assert_eq!(platform.default_processes(), ProcessPolicy::Allow);
                assert_eq!(platform.default_engine(), WasmEngine::Native);
            }
        }
        let unknown: UnknownPlatform = "Mac".parse::<HostPlatform>().unwrap_err();
        assert_eq!(unknown.input(), "Mac");
        assert_eq!(
            unknown.to_string(),
            "unknown platform \"Mac\" (expected mac, ios, android, windows or linux)"
        );
        #[cfg(target_os = "macos")]
        assert_eq!(HostPlatform::compiled(), Some(HostPlatform::MacOs));
        #[cfg(target_os = "ios")]
        assert_eq!(HostPlatform::compiled(), Some(HostPlatform::Ios));
        #[cfg(target_os = "android")]
        assert_eq!(HostPlatform::compiled(), Some(HostPlatform::Android));
        #[cfg(target_os = "windows")]
        assert_eq!(HostPlatform::compiled(), Some(HostPlatform::Windows));
        #[cfg(target_os = "linux")]
        assert_eq!(HostPlatform::compiled(), Some(HostPlatform::Linux));
    }

    #[test]
    fn module_001_ac32_embedded_constructor_matches_the_d3_table() {
        let log = Arc::new(NullComposeLog);
        for platform in [
            HostPlatform::MacOs,
            HostPlatform::Ios,
            HostPlatform::Android,
            HostPlatform::Windows,
            HostPlatform::Linux,
        ] {
            let options = ComposeOptions::embedded(
                "/home",
                platform,
                Arc::clone(&log) as Arc<dyn ComposeLog>,
            );
            assert_eq!(options.profile, ComposeProfile::Embedded { platform });
            assert_eq!(options.processes, platform.default_processes());
            assert_eq!(options.wasm_engine, platform.default_engine());
            assert!(options.hot_reload);
            assert!(options.state_root.is_none());
            assert!(matches!(options.master_key, MasterKeyInput::FromConfig));
            assert_eq!(
                options.client_api,
                ClientApiOptions::loopback(0, false, Admission::InProcessOnly)
            );
            if platform.is_mobile() {
                assert_eq!(options.instance, InstanceGuard::ProcessLocal);
                assert_eq!(options.listeners, ListenerOptions::none());
            } else {
                assert_eq!(options.instance, InstanceGuard::pid_lock());
                assert_eq!(
                    options.listeners,
                    ListenerOptions::daemon()
                        .with_post_msg(false)
                        .with_event_bus_ws(false)
                );
            }
        }
    }
}
