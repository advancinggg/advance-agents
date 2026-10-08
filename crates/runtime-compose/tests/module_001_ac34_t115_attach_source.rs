//! MODULE-001-T115 — in-process start, attach, stop and restart under ProcessLocal + Forbid.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use advance_home::{
    CancelToken, ConnectError, ConnectedRuntime, HostWorkspaceHome, PreflightFail, PreflightPort,
    RuntimeLauncher, RuntimeState, SecretBytes, SourceAdoptPort, WorkspaceHomeFirstOpen,
    WorkspaceHomeHandle,
};
use advance_runtime::config::LlmProviderConfig;
use advance_runtime_compose::test_support::fixture::{assert_gone_for_home, Http, HttpResponse};
use advance_runtime_compose::test_support::proc_self::child_pids;
use advance_runtime_compose::test_support::{
    launch_claims, reserved_homes, spawn_counter, ComposeProbe, MemoryComposeLog,
};
use advance_runtime_compose::{
    compose, launch_reasons, log_keys, Admission, ClientApiOptions, ComposeOptions, ComposeProfile,
    HostPlatform, InProcessLauncher, InProcessLauncherError, InProcessStopError, InstanceGuard,
    InstanceGuardKind, LaunchPlan, ListenerOptions, MasterKeyInput, NullComposeLog,
    ProcessLocalAttachSource, ProcessPolicy, RuntimePhase, WasmEngine,
};
use cap_secrets::read_workspace_master_key;
use serde_json::Value;
use walkdir::WalkDir;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

const START_BOUND: Duration = Duration::from_secs(120);
const WAIT_BOUND: Duration = Duration::from_secs(120);

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

struct NoPreflight;
impl PreflightPort for NoPreflight {
    fn preflight(
        &self,
        _home: &Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        _cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        panic!("preflight must not run")
    }
}

struct PassPreflight;
impl PreflightPort for PassPreflight {
    fn preflight(
        &self,
        _home: &Path,
        _provider: &LlmProviderConfig,
        _key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        if cancel.is_cancelled() {
            return Err(PreflightFail::Cancelled);
        }
        Ok(())
    }
}

struct Env {
    _home_dir: tempfile::TempDir,
    _state_dir: tempfile::TempDir,
    handle: WorkspaceHomeHandle,
    canonical: PathBuf,
    state_root: PathBuf,
    log: MemoryComposeLog,
    probes: Arc<Mutex<Vec<Arc<ComposeProbe>>>>,
    plan_calls: Arc<AtomicUsize>,
    s0: spawn_counter::SpawnCounts,
    rt: tokio::runtime::Runtime,
    launcher: Arc<InProcessLauncher>,
    h: HostWorkspaceHome,
}

fn make_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("multi-thread runtime")
}

fn ios_row(
    home: &Path,
    state_root: &Path,
    log: MemoryComposeLog,
    probe: Arc<ComposeProbe>,
) -> ComposeOptions {
    let key = read_workspace_master_key(home)
        .expect("read master.key")
        .expect("create minted master.key");
    let mut o = ComposeOptions::embedded(home.to_path_buf(), HostPlatform::Ios, Arc::new(log))
        .with_state_root(state_root.to_path_buf())
        .with_master_key(MasterKeyInput::Provided(key));
    o.failpoints.probe = Some(probe);
    o
}

/// Attach-semantics legs that do not assert Pulley / the iOS row.
fn semantic_row(
    home: &Path,
    state_root: &Path,
    log: MemoryComposeLog,
    probe: Arc<ComposeProbe>,
) -> ComposeOptions {
    let key = read_workspace_master_key(home)
        .expect("read master.key")
        .expect("create minted master.key");
    let mut o = ComposeOptions::daemon(home.to_path_buf(), Arc::new(log))
        .with_instance(InstanceGuard::ProcessLocal)
        .with_processes(ProcessPolicy::Forbid)
        .with_client_api(ClientApiOptions::loopback(
            0,
            false,
            Admission::InProcessOnly,
        ))
        .with_listeners(ListenerOptions::none())
        .with_wasm_engine(WasmEngine::Native)
        .with_state_root(state_root.to_path_buf())
        .with_master_key(MasterKeyInput::Provided(key));
    o.failpoints.probe = Some(probe);
    o
}

fn dummy_plan(_home: &Path) -> LaunchPlan {
    LaunchPlan::new(
        ComposeOptions::embedded(
            PathBuf::from("/tmp/ac34-dummy"),
            HostPlatform::Ios,
            Arc::new(NullComposeLog),
        ),
        vec![],
    )
}

fn open_env(
    preflight: Arc<dyn PreflightPort>,
    row: impl Fn(&Path, &Path, MemoryComposeLog, Arc<ComposeProbe>) -> ComposeOptions
        + Send
        + Sync
        + 'static,
) -> Env {
    open_env_on_plan(preflight, row, || {})
}

fn open_env_on_plan(
    preflight: Arc<dyn PreflightPort>,
    row: impl Fn(&Path, &Path, MemoryComposeLog, Arc<ComposeProbe>) -> ComposeOptions
        + Send
        + Sync
        + 'static,
    on_plan: impl Fn() + Send + Sync + 'static,
) -> Env {
    let home_dir = tempfile::tempdir().expect("home tempdir");
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let bootstrap = HostWorkspaceHome::production();
    let handle = bootstrap
        .create(home_dir.path(), "home")
        .expect("create home");
    let canonical = fs::canonicalize(handle.path()).expect("canonical home");
    let state_root = state_dir.path().to_path_buf();
    let log = MemoryComposeLog::new();
    let probes = Arc::new(Mutex::new(Vec::<Arc<ComposeProbe>>::new()));
    let plan_calls = Arc::new(AtomicUsize::new(0));
    let s0 = spawn_counter::snapshot();
    assert_no_live_children();

    let rt = make_rt();
    let plan_home = canonical.clone();
    let plan_state = state_root.clone();
    let plan_log = log.clone();
    let plan_probes = Arc::clone(&probes);
    let plan_calls_c = Arc::clone(&plan_calls);
    let launcher = Arc::new(
        InProcessLauncher::new(rt.handle().clone(), move |_key: &Path| {
            on_plan();
            plan_calls_c.fetch_add(1, Ordering::SeqCst);
            let probe = Arc::new(ComposeProbe::new());
            plan_probes.lock().expect("probes").push(Arc::clone(&probe));
            LaunchPlan::new(
                row(&plan_home, &plan_state, plan_log.clone(), probe),
                vec![],
            )
        })
        .expect("InProcessLauncher::new")
        .with_start_bound(START_BOUND)
        .with_stop_bound(START_BOUND),
    );
    let source = Arc::new(ProcessLocalAttachSource::new());
    let mut adopt = SourceAdoptPort::new(source.clone());
    adopt.timeout = WAIT_BOUND;
    let h = HostWorkspaceHome::with_ports_source_and_wait(
        preflight,
        launcher.clone(),
        Arc::new(adopt),
        source,
        WAIT_BOUND,
    );
    Env {
        _home_dir: home_dir,
        _state_dir: state_dir,
        handle,
        canonical,
        state_root,
        log,
        probes,
        plan_calls,
        s0,
        rt,
        launcher,
        h,
    }
}

fn c243_home(
    preflight: Arc<dyn PreflightPort>,
    launcher: Arc<InProcessLauncher>,
) -> HostWorkspaceHome {
    let source = Arc::new(ProcessLocalAttachSource::new());
    let mut adopt = SourceAdoptPort::new(source.clone());
    adopt.timeout = WAIT_BOUND;
    HostWorkspaceHome::with_ports_source_and_wait(
        preflight,
        launcher,
        Arc::new(adopt),
        source,
        WAIT_BOUND,
    )
}

fn probe_at(env: &Env, i: usize) -> Arc<ComposeProbe> {
    env.probes.lock().expect("probes")[i].clone()
}

fn addr_of(base: &str) -> SocketAddr {
    base.strip_prefix("http://")
        .unwrap_or(base)
        .trim_end_matches('/')
        .parse()
        .unwrap_or_else(|_| panic!("client_api_base is not http://host:port"))
}

fn error_code(body: &Value) -> &str {
    body.pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn http_get(
    rt: &tokio::runtime::Runtime,
    addr: SocketAddr,
    path: &str,
    session: Option<&str>,
) -> HttpResponse {
    let mut req = Http::get(addr, path);
    if let Some(token) = session {
        req = req.session(token.to_owned());
    }
    rt.block_on(req.send())
}

fn regular_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

fn lock_files(roots: &[&Path]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for root in roots {
        for path in regular_files(root) {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".lock"))
            {
                found.push(path);
            }
        }
    }
    found
}

fn assert_no_lock_or_discovery(home: &Path, state_root: &Path) {
    let runtime = home.join(".runtime");
    let runtime_lock = runtime.join("runtime.lock");
    let launch_lock = runtime.join("launch.lock");
    let client_api = runtime.join("client-api");
    let locks = lock_files(&[home, state_root]);
    let home_list = regular_files(home);
    let state_list = regular_files(state_root);
    assert!(
        !runtime_lock.exists() && !launch_lock.exists() && !client_api.exists() && locks.is_empty(),
        "daemon lock/discovery files present\n  runtime.lock exists={}\n  launch.lock exists={}\n  client-api exists={}\n  *.lock={locks:?}\n  home files={home_list:?}\n  state files={state_list:?}",
        runtime_lock.exists(),
        launch_lock.exists(),
        client_api.exists(),
    );
}

fn no_daemon_files(home: &Path, state_root: &Path) {
    assert_no_lock_or_discovery(home, state_root);
    let selected = home.join(".runtime").join("selected-provider");
    assert!(
        selected.is_file(),
        "selected-provider missing (D3 parity); home files={:?} state files={:?}",
        regular_files(home),
        regular_files(state_root)
    );
}

fn no_file_contains(roots: &[&Path], needle: &str) {
    for root in roots {
        for path in regular_files(root) {
            let bytes = fs::read(&path).unwrap_or_default();
            if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                panic!("session token found on disk in {}", path.display());
            }
        }
    }
}

fn no_log_contains(log: &MemoryComposeLog, needle: &str) {
    for line in log.lines() {
        if line.text.contains(needle) {
            panic!("compose log leaked a session token (key={})", line.key);
        }
    }
}

fn session_redacted(connected: &ConnectedRuntime) {
    let debug = format!("{connected:?}");
    assert!(
        debug.contains("<redacted>"),
        "ConnectedRuntime Debug should redact the bearer"
    );
    if let Some(session) = connected.session.as_ref() {
        if debug.contains(session.bearer_token()) {
            panic!("ConnectedRuntime Debug leaked the bearer token");
        }
    }
}

fn assert_no_live_children() {
    if let Some(pids) = child_pids() {
        assert!(pids.is_empty(), "live child pids: {pids:?}");
    }
}

fn assert_spawn_free(s0: &spawn_counter::SpawnCounts) {
    assert_eq!(
        spawn_counter::snapshot().since(s0).admitted_total(),
        0,
        "a spawn site admitted a child"
    );
    assert_no_live_children();
}

fn assert_home_released(canonical: &Path) {
    assert!(
        !reserved_homes().iter().any(|p| p == canonical),
        "home still reserved"
    );
    assert!(
        !launch_claims().iter().any(|p| p == canonical),
        "launch claim still held"
    );
}

fn providers_ok(rt: &tokio::runtime::Runtime, base: &str, token: &str) {
    let addr = addr_of(base);
    let with = http_get(rt, addr, "/client/providers", Some(token));
    assert_eq!(with.status, 200, "providers with session: {}", with.status);
    let without = http_get(rt, addr, "/client/providers", None);
    assert_eq!(without.status, 401, "providers without session");
    assert_eq!(error_code(&without.body), "unauthenticated");
}

fn launch_reason(err: ConnectError) -> String {
    match err {
        ConnectError::LaunchFailed { reason } => reason,
        other => panic!("expected LaunchFailed, got {other:?}"),
    }
}

#[test]
fn module_001_ac34_t115_in_process_start_attach_stop_restart() {
    let _guard = serial();
    let env = open_env(Arc::new(NoPreflight), ios_row);
    assert_eq!(env.h.runtime_state(&env.handle), RuntimeState::Idle);

    let c1 = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("first start_or_attach");
    assert_eq!(env.log.count(log_keys::READY), 1);
    let health = env
        .launcher
        .health(&env.canonical)
        .expect("health after start");
    assert_eq!(
        health.client_api_base.as_deref(),
        Some(c1.client_api_base.as_str())
    );
    assert!(
        c1.client_api_base.starts_with("http://127.0.0.1:"),
        "loopback base"
    );
    let s1 = c1.session.as_ref().expect("session on first attach");
    providers_ok(&env.rt, &c1.client_api_base, s1.bearer_token());
    assert!(!launch_claims().contains(&env.canonical));
    no_daemon_files(env.handle.path(), &env.state_root);
    session_redacted(&c1);
    no_file_contains(&[env.handle.path(), &env.state_root], s1.bearer_token());
    no_log_contains(&env.log, s1.bearer_token());
    assert_spawn_free(&env.s0);

    let c2 = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("second start_or_attach");
    assert_eq!(c2.client_api_base, c1.client_api_base);
    assert_eq!(env.log.count(log_keys::READY), 1);
    let s2 = c2.session.as_ref().expect("session on second attach");
    assert_ne!(s2.session_id(), s1.session_id());
    providers_ok(&env.rt, &c2.client_api_base, s2.bearer_token());
    no_daemon_files(env.handle.path(), &env.state_root);
    session_redacted(&c2);
    no_file_contains(&[env.handle.path(), &env.state_root], s1.bearer_token());
    no_file_contains(&[env.handle.path(), &env.state_root], s2.bearer_token());
    no_log_contains(&env.log, s1.bearer_token());
    no_log_contains(&env.log, s2.bearer_token());
    assert_eq!(env.h.runtime_state(&env.handle), RuntimeState::Running);
    assert_spawn_free(&env.s0);

    let health = env
        .launcher
        .health(&env.canonical)
        .expect("health while running");
    assert_eq!(health.phase, RuntimePhase::Running);
    assert!(health.agent_loop_up);
    assert_eq!(health.instance_guard, InstanceGuardKind::ProcessLocal);
    assert_eq!(
        health.client_api_base.as_deref(),
        Some(c1.client_api_base.as_str())
    );
    assert_eq!(
        health.profile,
        ComposeProfile::Embedded {
            platform: HostPlatform::Ios
        }
    );
    assert_eq!(health.processes, ProcessPolicy::Forbid);
    assert_eq!(health.wasm_engine, WasmEngine::Pulley);

    env.launcher.stop(&env.canonical).expect("stop");
    assert!(env.launcher.health(&env.canonical).is_none());
    assert_eq!(env.h.runtime_state(&env.handle), RuntimeState::Idle);
    assert_home_released(&env.canonical);
    env.rt.block_on(assert_gone_for_home(
        &probe_at(&env, 0),
        &env.canonical,
        None,
    ));
    no_file_contains(&[env.handle.path(), &env.state_root], s1.bearer_token());
    no_file_contains(&[env.handle.path(), &env.state_root], s2.bearer_token());
    assert_spawn_free(&env.s0);

    let c3 = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("restart start_or_attach");
    assert_eq!(env.log.count(log_keys::READY), 2);
    assert!(c3.session.is_some());
    assert_eq!(env.h.runtime_state(&env.handle), RuntimeState::Running);
    no_daemon_files(env.handle.path(), &env.state_root);
    env.launcher
        .stop(&env.canonical)
        .expect("stop after restart");
    env.rt.block_on(assert_gone_for_home(
        &probe_at(&env, 1),
        &env.canonical,
        None,
    ));
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_in_process_adopt_waits_through_the_source() {
    let _guard = serial();
    let env = open_env(Arc::new(PassPreflight), |home, state, log, probe| {
        ios_row(home, state, log, probe).with_hot_reload(true)
    });
    let c1 = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("start");
    let base = c1.client_api_base.clone();
    env.h
        .store_and_preflight(
            &env.handle,
            "openai",
            SecretBytes::new("sk-test-T115-adopt"),
            &CancelToken::new(),
        )
        .expect("store_and_preflight openai");
    let started = Instant::now();
    let c2 = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("adopt start_or_attach");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "adopt exceeded 10s"
    );
    let selected = advance_home::runtime_state::read_selected_provider(env.handle.path())
        .expect("selected-provider");
    assert_eq!(selected.provider_id, "openai");
    assert_eq!(env.log.count(log_keys::READY), 1);
    assert_eq!(c2.client_api_base, base);
    env.launcher.stop(&env.canonical).expect("stop");
    env.rt.block_on(assert_gone_for_home(
        &probe_at(&env, 0),
        &env.canonical,
        None,
    ));
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_in_process_start_on_a_held_home_is_ok_then_attaches() {
    let _guard = serial();
    let env = open_env(Arc::new(NoPreflight), ios_row);
    let probe = Arc::new(ComposeProbe::new());
    let composed = env
        .rt
        .block_on(compose(
            ios_row(
                &env.canonical,
                &env.state_root,
                env.log.clone(),
                Arc::clone(&probe),
            ),
            vec![],
        ))
        .expect("compose outside launcher");
    let started =
        RuntimeLauncher::start(env.launcher.as_ref(), &env.canonical, &CancelToken::new());
    assert!(started.is_ok(), "HeldInProcess maps to Ok: {started:?}");
    assert_eq!(env.plan_calls.load(Ordering::SeqCst), 1);
    assert_eq!(env.log.count(log_keys::READY), 1);
    assert_eq!(env.log.count(log_keys::ATTACH_LAUNCH_FAILED), 0);
    assert!(env.launcher.health(&env.canonical).is_none());
    assert!(!launch_claims().contains(&env.canonical));

    let c = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("attach to outside compose");
    let composed_base = composed.client_api().expect("composed Client API").base_url;
    assert_eq!(c.client_api_base, composed_base);
    assert!(c.session.is_some());
    assert_eq!(env.plan_calls.load(Ordering::SeqCst), 1);

    env.rt.block_on(composed.shutdown()).expect("shutdown");
    assert_eq!(env.h.runtime_state(&env.handle), RuntimeState::Idle);
    env.rt
        .block_on(assert_gone_for_home(&probe, &env.canonical, None));
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_concurrent_start_or_attach_composes_once() {
    let _guard = serial();
    let env = open_env(Arc::new(NoPreflight), semantic_row);
    let barrier = Arc::new(Barrier::new(2));
    let h_a = c243_home(Arc::new(NoPreflight), env.launcher.clone());
    let h_b = c243_home(Arc::new(NoPreflight), env.launcher.clone());
    let handle_a = env.handle.clone();
    let handle_b = env.handle.clone();
    let b_a = Arc::clone(&barrier);
    let b_b = Arc::clone(&barrier);
    let t_a = std::thread::spawn(move || {
        b_a.wait();
        h_a.start_or_attach(&handle_a, &CancelToken::new())
    });
    let t_b = env.rt.spawn_blocking(move || {
        b_b.wait();
        h_b.start_or_attach(&handle_b, &CancelToken::new())
    });
    let c_a = t_a.join().expect("host thread").expect("caller A");
    let c_b = env
        .rt
        .block_on(t_b)
        .expect("spawn_blocking")
        .expect("caller B");
    assert_eq!(c_a.client_api_base, c_b.client_api_base);
    let s_a = c_a.session.as_ref().expect("A session");
    let s_b = c_b.session.as_ref().expect("B session");
    assert_ne!(s_a.session_id(), s_b.session_id());
    assert_eq!(env.log.count(log_keys::READY), 1);
    env.launcher.stop(&env.canonical).expect("stop");
    env.rt.block_on(assert_gone_for_home(
        &probe_at(&env, 0),
        &env.canonical,
        None,
    ));
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_cancel_during_in_process_start_keeps_the_runtime_attachable() {
    let _guard = serial();
    let cancel = CancelToken::new();
    let cancel_plan = cancel.clone();
    let env = open_env_on_plan(Arc::new(NoPreflight), semantic_row, move || {
        cancel_plan.cancel()
    });
    let first = env.h.start_or_attach(&env.handle, &cancel);
    assert!(
        matches!(first, Err(ConnectError::Cancelled)),
        "expected Cancelled, got {first:?}"
    );
    assert!(!launch_claims().contains(&env.canonical));
    let deadline = Instant::now() + START_BOUND;
    loop {
        if env.h.runtime_state(&env.handle) == RuntimeState::Running {
            break;
        }
        if Instant::now() >= deadline {
            panic!("runtime was not attachable within the start bound after cancel");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let c = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("attach after cancel");
    assert_eq!(env.log.count(log_keys::READY), 1);
    assert!(c.session.is_some());
    env.launcher.stop(&env.canonical).expect("stop");
    env.rt.block_on(assert_gone_for_home(
        &probe_at(&env, 0),
        &env.canonical,
        None,
    ));
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_a_runtime_shut_down_outside_stop_is_replaced_or_stopped() {
    let _guard = serial();
    let env = open_env(Arc::new(NoPreflight), semantic_row);
    let c1 = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("compose #1");
    assert!(env.launcher.trigger_shutdown_for_test(&env.canonical));
    let health = env
        .launcher
        .health(&env.canonical)
        .expect("health after external trigger");
    assert_ne!(health.phase, RuntimePhase::Running);
    assert!(!health.agent_loop_up);

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if env.h.runtime_state(&env.handle) == RuntimeState::Idle {
            break;
        }
        if Instant::now() >= deadline {
            panic!("home did not become Idle within 15s after external shutdown");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let health = env
        .launcher
        .health(&env.canonical)
        .expect("stale entry still held");
    assert_eq!(health.phase, RuntimePhase::Stopped);

    let c2 = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect("compose #2 replaces stale");
    assert_eq!(env.log.count(log_keys::READY), 2);
    let health = env
        .launcher
        .health(&env.canonical)
        .expect("health after replace");
    assert_eq!(health.phase, RuntimePhase::Running);
    assert_eq!(
        health.client_api_base.as_deref(),
        Some(c2.client_api_base.as_str())
    );
    assert_eq!(env.log.count(log_keys::ATTACH_LAUNCH_FAILED), 0);
    let _ = c1;

    assert!(env.launcher.trigger_shutdown_for_test(&env.canonical));
    env.launcher
        .stop(&env.canonical)
        .expect("stop awaits triggered");
    assert!(env.launcher.health(&env.canonical).is_none());
    assert_eq!(env.h.runtime_state(&env.handle), RuntimeState::Idle);
    env.rt.block_on(assert_gone_for_home(
        &probe_at(&env, 1),
        &env.canonical,
        None,
    ));
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_in_process_compose_failure_is_launch_failed_and_releases_the_claim() {
    let _guard = serial();
    let env = open_env(Arc::new(NoPreflight), |home, state, log, probe| {
        ios_row(home, state, log, probe).with_client_api(ClientApiOptions::loopback(
            0,
            true,
            Admission::InProcessOnly,
        ))
    });
    let err = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect_err("compose must fail");
    assert_eq!(launch_reason(err), launch_reasons::COMPOSE_UNSUPPORTED);
    assert_home_released(&env.canonical);
    assert_eq!(env.h.runtime_state(&env.handle), RuntimeState::Idle);
    assert_eq!(env.log.count(log_keys::ATTACH_LAUNCH_FAILED), 1);
    let line = env
        .log
        .lines()
        .into_iter()
        .find(|l| l.key == log_keys::ATTACH_LAUNCH_FAILED)
        .expect("attach.launch_failed line");
    assert!(
        line.text.contains("unsupported:"),
        "failure line should carry unsupported:"
    );
    let rendered = format!("{:?}", env.canonical);
    assert!(
        line.text.contains(&rendered),
        "failure line should carry safe_path of the home"
    );
    assert_no_lock_or_discovery(env.handle.path(), &env.state_root);
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_in_process_launcher_refuses_a_plan_without_a_client_api() {
    let _guard = serial();
    let env = open_env(Arc::new(NoPreflight), |home, state, log, probe| {
        ios_row(home, state, log, probe).with_client_api(ClientApiOptions::Off)
    });
    let err = env
        .h
        .start_or_attach(&env.handle, &CancelToken::new())
        .expect_err("Off must fail");
    assert_eq!(launch_reason(err), launch_reasons::NO_CLIENT_API);
    assert_eq!(env.log.count(log_keys::READY), 0);
    assert_home_released(&env.canonical);
    assert_spawn_free(&env.s0);
}

#[test]
fn module_001_ac34_in_process_launcher_requires_a_multi_thread_runtime_with_two_workers() {
    let _guard = serial();
    let current = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread");
    let err = InProcessLauncher::new(current.handle().clone(), dummy_plan)
        .expect_err("current-thread refused");
    assert_eq!(err, InProcessLauncherError::CurrentThreadRuntime);
    assert_eq!(
        err.to_string(),
        "the in-process launcher needs a multi-thread Tokio runtime"
    );
    let _: &dyn std::error::Error = &err;
    drop(current);

    let one = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("one worker");
    let err = InProcessLauncher::new(one.handle().clone(), dummy_plan).expect_err("one worker");
    assert_eq!(err, InProcessLauncherError::TooFewWorkers { workers: 1 });
    assert_eq!(
        err.to_string(),
        "the in-process launcher needs at least two Tokio workers (this runtime has 1)"
    );
    let _: &dyn std::error::Error = &err;
    drop(one);

    let two = make_rt();
    InProcessLauncher::new(two.handle().clone(), dummy_plan).expect("two workers");
}

#[test]
fn module_001_ac34_stop_of_an_unlaunched_home_is_not_launched() {
    let _guard = serial();
    let rt = make_rt();
    let launcher = InProcessLauncher::new(rt.handle().clone(), dummy_plan).expect("launcher");
    let dir = tempfile::tempdir().expect("temp");
    let home = dir.path();
    assert_eq!(launcher.stop(home), Err(InProcessStopError::NotLaunched));
    assert!(launcher.health(home).is_none());
    assert_eq!(
        launcher.stop(Path::new("relative/home")),
        Err(InProcessStopError::NotLaunched)
    );
    assert_eq!(
        InProcessStopError::NotLaunched.to_string(),
        "no runtime launched here for this home"
    );
}
