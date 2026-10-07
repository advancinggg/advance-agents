//! MODULE-001-AC-30 — the composition lives in `advance-runtime-compose`, and the
//! `advance-core` façade re-exports only its CONTRACT-244 API, as
//! `advance_core::runtime_compose`: no moved internal (the wiring, the daemon graph, the
//! process-local registry, the log handle) is reachable through the façade.
//!
//! Two checks:
//! - the API compiles through the façade (every allow-listed name is used below);
//! - a source scan: the façade line in `src/lib.rs` re-exports the library's `api` module
//!   and nothing else of it, and every non-blank, non-comment line of
//!   `crates/runtime-compose/src/api/mod.rs` is a private `mod <name>;` or a `pub use` of
//!   ONE allow-listed name (`pub use <path>::<Name>;`, one name per line, so the scan stays
//!   line-based whatever rustfmt does to long lines). Adding a name to the API means adding
//!   it to [`ALLOWED`] here.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use advance_core::runtime_compose::{
    compose, log_keys, Admission, BoxFuture, CapParams, CapabilityRefusal, ClientApiEndpoint,
    ClientApiOptions, ComponentFunc, ComposeCx, ComposeError, ComposeExtension, ComposeLog,
    ComposeLogLine, ComposeOptions, ComposeProfile, ComposedRuntime, ConfigView, EmitError,
    EmitReceipt, ExtensionEmitter, ExtensionError, ExtensionFailure, ExtensionGrantCheck,
    ExtensionHealth, ExtensionPhase, ExtensionSecrets, ExtensionState, GatewayHandle,
    GrantDecision, HostCallContext, HostCallError, HostFunctionDef, HostFunctionFailure,
    HostFunctionHandler, HostFunctionRefusal, HostFunctionRegistrar, HostPlatform, InstanceGuard,
    InstanceGuardKind, ListenerOptions, LockFailure, LogStream, MasterKeyInput, NullComposeLog,
    PanicAnswer, ProcessPolicy, RunInfo, RunView, RuntimeHealthView, RuntimePhase, SecretViewError,
    ShutdownHandle, StartedCx, TaskRunStatus, TaskSpawner, Unsupported, Val, ViewError, WasmEngine,
    Zeroizing,
};

/// The CONTRACT-244 API: every name `api/mod.rs` may re-export, and must.
const ALLOWED: &[&str] = &[
    "compose",
    "log_keys",
    "ComposeLog",
    "ComposeLogLine",
    "LogStream",
    "NullComposeLog",
    "ComposeError",
    "ExtensionFailure",
    "ExtensionPhase",
    "LockFailure",
    "Unsupported",
    "CapabilityRefusal",
    "ComponentFunc",
    "HostCallContext",
    "HostCallError",
    "HostFunctionDef",
    "HostFunctionFailure",
    "HostFunctionHandler",
    "HostFunctionRefusal",
    "HostFunctionRegistrar",
    "PanicAnswer",
    "Val",
    "BoxFuture",
    "ComposeExtension",
    "ExtensionError",
    "ExtensionHealth",
    "ExtensionState",
    "ComposeCx",
    "ConfigView",
    "EmitError",
    "EmitReceipt",
    "ExtensionEmitter",
    "ExtensionGrantCheck",
    "ExtensionSecrets",
    "GatewayHandle",
    "RunInfo",
    "RunView",
    "SecretViewError",
    "StartedCx",
    "TaskSpawner",
    "ViewError",
    "Admission",
    "ClientApiOptions",
    "ComposeOptions",
    "ComposeProfile",
    "HostPlatform",
    "InstanceGuard",
    "ListenerOptions",
    "MasterKeyInput",
    "ProcessPolicy",
    "WasmEngine",
    "Zeroizing",
    "ClientApiEndpoint",
    "ComposedRuntime",
    "InstanceGuardKind",
    "RuntimeHealthView",
    "RuntimePhase",
    "ShutdownHandle",
    "CapParams",
    "GrantDecision",
    "TaskRunStatus",
];

/// The one façade line.
const FACADE_LINE: &str = "pub use advance_runtime_compose::api as runtime_compose;";

struct Quiet;

impl ComposeExtension for Quiet {
    fn id(&self) -> &'static str {
        "quiet"
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// Every allow-listed name is reachable, and usable, through the façade.
#[allow(dead_code)]
fn uses_the_api_through_the_facade(home: std::path::PathBuf) {
    let log: Arc<dyn ComposeLog> = Arc::new(NullComposeLog);
    let options: ComposeOptions = ComposeOptions::daemon(home, log)
        .with_profile(ComposeProfile::Embedded {
            platform: HostPlatform::Linux,
        })
        .with_instance(InstanceGuard::pid_lock())
        .with_master_key(MasterKeyInput::Provided(Zeroizing::new([0; 32])))
        .with_client_api(ClientApiOptions::loopback(
            0,
            false,
            Admission::SameUserLoopback,
        ))
        .with_listeners(ListenerOptions::none())
        .with_processes(ProcessPolicy::Allow)
        .with_wasm_engine(WasmEngine::Native);
    let extensions: Vec<Arc<dyn ComposeExtension>> = vec![Arc::new(Quiet)];
    let _composing = compose(options, extensions);
    let _: fn(&ComposedRuntime) -> ShutdownHandle = ComposedRuntime::shutdown_handle;
    let _: fn(&ComposedRuntime) -> Option<ClientApiEndpoint> = ComposedRuntime::client_api;
    let _: fn(&ComposedRuntime) -> RuntimeHealthView = ComposedRuntime::health;
    let _: Option<RuntimePhase> = None;
    let _: Option<InstanceGuardKind> = None;
    let _: Option<ComposeLogLine> = None;
    let _: Option<LogStream> = None;
    let _: &[&str] = log_keys::ALL;
    let _: Option<ComposeError> = None;
    let _: Option<CapabilityRefusal> = None;
    let _: Option<HostFunctionRegistrar> = None;
    let _: Option<HostFunctionDef> = None;
    let _: Option<PanicAnswer> = None;
    let _: Option<HostFunctionFailure> = None;
    let _: Option<HostFunctionRefusal> = None;
    let _: Option<HostCallContext> = None;
    let _: Option<HostCallError> = None;
    let _: Option<Arc<dyn HostFunctionHandler>> = None;
    let _: Option<Val> = None;
    let _: Option<ComponentFunc> = None;
    let _: Option<LockFailure> = None;
    let _: Option<Unsupported> = None;
    let _: Option<ExtensionPhase> = None;
    let _: Option<ExtensionFailure> = None;
    let _: Option<ExtensionError> = None;
    let _: Option<ExtensionHealth> = None;
    let _: Option<ExtensionState> = None;
    let _: Option<ComposeCx> = None;
    let _: Option<StartedCx> = None;
    let _: Option<ConfigView> = None;
    let _: Option<TaskSpawner> = None;
    let _: Option<ExtensionEmitter> = None;
    let _: Option<EmitReceipt> = None;
    let _: Option<EmitError> = None;
    let _: Option<RunView> = None;
    let _: Option<RunInfo> = None;
    let _: Option<ExtensionGrantCheck> = None;
    let _: Option<ExtensionSecrets> = None;
    let _: Option<SecretViewError> = None;
    let _: Option<GatewayHandle> = None;
    let _: Option<ViewError> = None;
    let _: Option<CapParams> = None;
    let _: Option<GrantDecision> = None;
    let _: Option<TaskRunStatus> = None;
}

#[test]
fn module_001_ac30_facade_reexports_only_contract244_api() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR"));

    // The façade re-exports the library's `api` module, and nothing else of the library.
    let facade = std::fs::read_to_string(core.join("src/lib.rs")).expect("read the façade");
    let lines: Vec<&str> = facade
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("advance_runtime_compose"))
        .filter(|line| !line.starts_with("//"))
        .collect();
    assert_eq!(
        lines,
        vec![FACADE_LINE],
        "the façade names advance_runtime_compose exactly once, for its api module"
    );

    // The api module is private submodules plus one-name re-exports of the allow-list.
    let api_mod = core.join("../runtime-compose/src/api/mod.rs");
    let source = std::fs::read_to_string(&api_mod).expect("read api/mod.rs");
    let allowed: BTreeSet<&str> = ALLOWED.iter().copied().collect();
    assert_eq!(allowed.len(), ALLOWED.len(), "ALLOWED lists a name twice");
    let mut exported = BTreeSet::new();
    let mut strays = Vec::new();
    for (number, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if let Some(name) = line
            .strip_prefix("mod ")
            .and_then(|rest| rest.strip_suffix(';'))
        {
            if is_identifier(name) {
                continue;
            }
        }
        let reexported = line
            .strip_prefix("pub use ")
            .and_then(|rest| rest.strip_suffix(';'))
            .and_then(|path| path.rsplit_once("::"))
            .map(|(_, name)| name)
            .filter(|name| is_identifier(name));
        match reexported {
            Some(name) if allowed.contains(name) => {
                assert!(exported.insert(name), "{name} is re-exported twice");
            }
            _ => strays.push(format!("api/mod.rs:{}: {line}", number + 1)),
        }
    }
    assert!(
        strays.is_empty(),
        "every line of api/mod.rs is a private `mod x;` or `pub use path::Name;` of an \
         allow-listed name:\n{}",
        strays.join("\n")
    );
    let missing: Vec<&&str> = allowed
        .iter()
        .filter(|name| !exported.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "allow-listed names the API does not re-export: {missing:?}"
    );
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !text.starts_with(|c: char| c.is_ascii_digit())
}
