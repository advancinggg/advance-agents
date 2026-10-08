//! MODULE-001-T113 — spawn-site CI gate and composing (1)(3)(4)(7) legs
//! (desktop / Forbid / ProcessLocal; iOS / Android rows).

#[path = "support/sockets.rs"]
mod sockets;
#[path = "support/spawn_gate.rs"]
mod spawn_gate;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime::runtime_lock::{inspect_lock, LockInspection, RuntimeLock};
use advance_runtime_compose::test_support::fixture::inference::provider_yaml;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, post_msg, CapDecl, FixtureDriver, FixtureHome,
    FixtureHomeSpec, Http, HttpResponse, FIXTURE_MASTER_KEY,
};
use advance_runtime_compose::test_support::proc_self::child_pids;
use advance_runtime_compose::test_support::{
    contract218_platform_key, reserved_homes, spawn_counter, ComposeProbe, MemoryComposeLog,
};
use advance_runtime_compose::{
    compose, Admission, ClientApiOptions, ComposeError, ComposeOptions, ComposeProfile,
    HostPlatform, InstanceGuard, InstanceGuardKind, ListenerOptions, LockFailure, MasterKeyInput,
    NullComposeLog, PlatformRule, ProcessPolicy, Unsupported, WasmEngine,
};
use advance_shared_types::process_policy::SpawnSite;
use serde_json::{json, Value};
use sockets::listening_sockets;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const ANCHOR_SUFFIX: &str = ".anchor";

const CHANNELS_BLOCK: &str = r#"channels:
  webhook-listen-addr: "127.0.0.1:0"
  channels:
    - name: progress-telegram
      adapter: telegram
      secret: inbound-test-secret
      route: progress
      url-template: "https://api.telegram.org/bot123/sendMessage"
      user-mappings:
        - channel-kind: telegram
          sender-id: "4242"
          user: "user:alice"
"#;

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn fixture_home(
    caps: &[&'static str],
    driver: FixtureDriver,
    providers: Option<String>,
) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver,
        git: false,
        providers_yaml: providers,
    })
    .expect("home")
}

fn error_code(body: &Value) -> &str {
    body.pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn assert_process_forbidden(resp: &HttpResponse) {
    assert_eq!(
        error_code(&resp.body),
        "module_unavailable",
        "{:?}",
        resp.body
    );
    let details = resp
        .body
        .pointer("/error/details")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(details, vec![json!("process_forbidden")], "{:?}", resp.body);
}

fn listing(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| {
            entry
                .expect("dirent")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn bytes_or_absent(path: &Path) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

fn restart_required_count(body: &Value) -> usize {
    body.get("warnings")
        .and_then(Value::as_array)
        .map(|warnings| {
            warnings
                .iter()
                .filter(|warning| {
                    warning.get("code").and_then(Value::as_str) == Some("restart_required")
                })
                .count()
        })
        .unwrap_or(0)
}

fn hex32(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

fn append_runtime_config(home: &FixtureHome, yaml: &str) {
    let path = home.home().join(".advance/runtime-config.yaml");
    let mut text = fs::read_to_string(&path).expect("runtime-config");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(yaml);
    fs::write(path, text).expect("append runtime-config");
}

fn set_master_key_env_name(home: &FixtureHome, name: &str) {
    let path = home.home().join(".advance/runtime-config.yaml");
    let text = fs::read_to_string(&path).expect("runtime-config");
    let replaced = text.replace(
        "env-var-name: ADV_FIXTURE_MASTER_KEY_UNUSED",
        &format!("env-var-name: {name}"),
    );
    assert_ne!(replaced, text, "secrets env-var-name not found:\n{text}");
    fs::write(path, replaced).expect("rewrite secrets env-var-name");
}

fn any_migrated(root: &Path) -> bool {
    fn walk(dir: &Path) -> bool {
        let Ok(entries) = fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".migrated"))
            {
                return true;
            }
            if path.is_dir() && walk(&path) {
                return true;
            }
        }
        false
    }
    walk(root)
}

fn selected_provider(home: &Path) -> String {
    fs::read_to_string(home.join(".runtime/selected-provider")).unwrap_or_default()
}

fn req_scratch_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|n| n.starts_with("advance-agent-cli-"))
        {
            continue;
        }
        let Ok(inner) = fs::read_dir(entry.path()) else {
            continue;
        };
        for child in inner.flatten() {
            let Ok(reqs) = fs::read_dir(child.path()) else {
                continue;
            };
            for req in reqs.flatten() {
                if req
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("req-"))
                {
                    out.push(req.path());
                }
            }
        }
    }
    out.sort();
    out
}

fn process_local_options(
    home: &FixtureHome,
    log: Arc<dyn advance_runtime_compose::ComposeLog>,
    probe: Arc<ComposeProbe>,
) -> ComposeOptions {
    home.options(log, probe)
        .with_instance(InstanceGuard::ProcessLocal)
        .with_listeners(ListenerOptions::none())
        .with_client_api(ClientApiOptions::loopback(
            0,
            false,
            Admission::SameUserLoopback,
        ))
}

fn refuse_unsupported(
    result: Result<advance_runtime_compose::ComposedRuntime, ComposeError>,
) -> Unsupported {
    match result {
        Err(ComposeError::Unsupported(what)) => what,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn module_001_ac32_t113_3_spawn_site_gate_lists_every_site_with_its_policy_check() {
    spawn_gate::assert_list();
}

#[test]
fn module_001_ac32_spawn_site_gate_self_test() {
    spawn_gate::self_test();
}

#[test]
fn module_001_ac32_t113_1_platform_table_row_defaults() {
    let log = Arc::new(NullComposeLog);
    for platform in [
        HostPlatform::MacOs,
        HostPlatform::Ios,
        HostPlatform::Android,
        HostPlatform::Windows,
        HostPlatform::Linux,
    ] {
        let options = ComposeOptions::embedded("/home", platform, Arc::clone(&log) as _);
        assert_eq!(options.profile, ComposeProfile::Embedded { platform });
        assert!(options.hot_reload);
        assert!(options.state_root.is_none());
        assert!(matches!(options.master_key, MasterKeyInput::FromConfig));
        assert_eq!(
            options.client_api,
            ClientApiOptions::loopback(0, false, Admission::InProcessOnly)
        );
        if platform.is_mobile() {
            assert_eq!(options.instance, InstanceGuard::ProcessLocal);
            assert_eq!(options.processes, ProcessPolicy::Forbid);
            assert_eq!(options.wasm_engine, WasmEngine::Pulley);
            assert_eq!(options.listeners, ListenerOptions::none());
        } else {
            assert_eq!(options.instance, InstanceGuard::pid_lock());
            assert_eq!(options.processes, ProcessPolicy::Allow);
            assert_eq!(options.wasm_engine, WasmEngine::Native);
            assert_eq!(
                options.listeners,
                ListenerOptions::daemon()
                    .with_post_msg(false)
                    .with_event_bus_ws(false)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_1_platform_table_desktop_rows_compose_with_their_defaults() {
    let _serial = SERIAL.lock().await;
    for platform in [
        HostPlatform::MacOs,
        HostPlatform::Windows,
        HostPlatform::Linux,
    ] {
        let home = fixture_home(&["fs"], FixtureDriver::None, None);
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let rt = compose(
            home.embedded_options(platform, Arc::new(log), Arc::clone(&probe))
                .with_client_api(ClientApiOptions::Off),
            Vec::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("{platform:?} composes: {e}"));
        let health = rt.health();
        assert_eq!(health.profile, ComposeProfile::Embedded { platform });
        assert_eq!(health.instance_guard, InstanceGuardKind::PidLockFile);
        assert_eq!(health.processes, ProcessPolicy::Allow);
        assert!(
            home.home().join(".runtime/runtime.lock").exists(),
            "runtime.lock while running"
        );
        rt.shutdown().await.expect("shutdown");
        assert!(!home.home().join(".runtime/runtime.lock").exists());
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_1_platform_table_mobile_rows_compose_with_their_defaults() {
    let _serial = SERIAL.lock().await;
    for platform in [HostPlatform::Ios, HostPlatform::Android] {
        let home = fixture_home(&["fs"], FixtureDriver::None, None);
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let rt = compose(
            home.embedded_options(platform, Arc::new(log), Arc::clone(&probe))
                .with_client_api(ClientApiOptions::Off),
            Vec::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("{platform:?} composes: {e}"));
        let health = rt.health();
        assert_eq!(health.profile, ComposeProfile::Embedded { platform });
        assert_eq!(health.instance_guard, InstanceGuardKind::ProcessLocal);
        assert_eq!(health.processes, ProcessPolicy::Forbid);
        assert_eq!(health.wasm_engine, WasmEngine::Pulley);
        assert!(
            !home.home().join(".runtime/runtime.lock").exists(),
            "{platform:?}: no runtime.lock"
        );
        rt.shutdown().await.expect("shutdown");
        assert!(!home.home().join(".runtime/runtime.lock").exists());
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_1_platform_table_refuses_forbidden_combinations() {
    let _serial = SERIAL.lock().await;
    let cases: Vec<(
        HostPlatform,
        PlatformRule,
        Box<dyn Fn(ComposeOptions) -> ComposeOptions>,
    )> = vec![
        (
            HostPlatform::Ios,
            PlatformRule::Engine,
            Box::new(|o| o.with_wasm_engine(WasmEngine::Native)),
        ),
        (
            HostPlatform::Ios,
            PlatformRule::Processes,
            Box::new(|o| o.with_processes(ProcessPolicy::Allow)),
        ),
        (
            HostPlatform::Ios,
            PlatformRule::Instance,
            Box::new(|o| o.with_instance(InstanceGuard::pid_lock())),
        ),
        (
            HostPlatform::Android,
            PlatformRule::Engine,
            Box::new(|o| o.with_wasm_engine(WasmEngine::Native)),
        ),
        (
            HostPlatform::Android,
            PlatformRule::Processes,
            Box::new(|o| o.with_processes(ProcessPolicy::Allow)),
        ),
        (
            HostPlatform::Android,
            PlatformRule::Instance,
            Box::new(|o| o.with_instance(InstanceGuard::pid_lock())),
        ),
        (
            HostPlatform::MacOs,
            PlatformRule::Instance,
            Box::new(|o| o.with_instance(InstanceGuard::ProcessLocal)),
        ),
        (
            HostPlatform::Windows,
            PlatformRule::Instance,
            Box::new(|o| o.with_instance(InstanceGuard::ProcessLocal)),
        ),
        (
            HostPlatform::Linux,
            PlatformRule::Instance,
            Box::new(|o| o.with_instance(InstanceGuard::ProcessLocal)),
        ),
    ];
    for (platform, rule, tweak) in cases {
        let home = fixture_home(&["fs"], FixtureDriver::None, None);
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let options = tweak(home.embedded_options(platform, Arc::new(log), Arc::clone(&probe)));
        let what = refuse_unsupported(compose(options, Vec::new()).await);
        let expected = Unsupported::PlatformTable { platform, rule };
        assert_eq!(what, expected, "{platform:?} {rule:?}");
        assert_eq!(what.to_string(), expected.to_string());
        assert!(
            !reserved_homes().iter().any(|p| p == home.home()),
            "home reserved after PlatformTable"
        );
        assert!(!home.home().join(".runtime/runtime.lock").exists());
        assert!(probe.record().listeners.is_empty());
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_3_local_sidecar_refused_under_forbid() {
    use advance_runtime_compose::test_support::fixture::inference::SidecarMarker;

    let _serial = SERIAL.lock().await;
    let marker = SidecarMarker::new().expect("marker");
    let side = provider_yaml::side(marker.command());
    let home = fixture_home(
        &["fs", "llm"],
        FixtureDriver::LlmNoErr,
        Some(provider_yaml::llm_providers_block(&[side.as_str()])),
    );
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let before = spawn_counter::snapshot();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_processes(ProcessPolicy::Forbid),
        Vec::new(),
    )
    .await
    .expect("compose under Forbid");
    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "llm:hi").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("llm-err:"), "{body}");
    // MODULE-009 §1.7 redacts the inner LocalTransport string on the WIT path;
    // the typed refusal is the spawn counter + the marker that never ran.
    assert!(body.contains("ProviderError(\"provider error\")"), "{body}");
    assert!(!marker.ran(), "sidecar ran under Forbid");
    let after = spawn_counter::snapshot();
    let delta = after.since(&before);
    assert_eq!(delta.admitted_total(), 0);
    assert_eq!(delta.refused(SpawnSite::LocalSidecar), 1);
    if let Some(pids) = child_pids() {
        assert_eq!(pids, Vec::<u32>::new());
    }
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_3_agent_cli_turn_refused_under_forbid() {
    use advance_runtime_compose::test_support::fixture::inference::SidecarMarker;

    let _serial = SERIAL.lock().await;
    let marker = SidecarMarker::new().expect("marker");
    let cli = provider_yaml::cli(marker.command());
    let home = fixture_home(
        &["fs", "llm"],
        FixtureDriver::LlmNoErr,
        Some(provider_yaml::llm_providers_block(&[cli.as_str()])),
    );
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let before = spawn_counter::snapshot();
    let scratch_before = req_scratch_dirs();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_processes(ProcessPolicy::Forbid),
        Vec::new(),
    )
    .await
    .expect("compose under Forbid");
    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    let (status, body) = post_msg(addr, "llm:hi").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("llm-err:"), "{body}");
    // MODULE-009 §1.7 redacts the inner agent-cli string on the WIT path;
    // the typed refusal is the spawn counter + the marker that never ran.
    assert!(body.contains("ProviderError(\"provider error\")"), "{body}");
    assert!(!marker.ran());
    let after = spawn_counter::snapshot();
    let delta = after.since(&before);
    assert_eq!(delta.admitted_total(), 0);
    assert!(
        delta.refused(SpawnSite::AgentCli) >= 1,
        "agent-cli refusals: {}",
        delta.refused(SpawnSite::AgentCli)
    );
    assert_eq!(req_scratch_dirs(), scratch_before, "no req-* dir");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_3_providers_family_agent_cli_probes_and_create_refused() {
    use advance_runtime_compose::test_support::fixture::inference::SidecarMarker;

    let _serial = SERIAL.lock().await;
    let marker = SidecarMarker::new().expect("marker");
    let cli = provider_yaml::cli(marker.command());
    let home = fixture_home(
        &["fs", "llm"],
        FixtureDriver::LlmNoErr,
        Some(provider_yaml::llm_providers_block(&[cli.as_str()])),
    );
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_processes(ProcessPolicy::Forbid),
        Vec::new(),
    )
    .await
    .expect("compose under Forbid");
    let ep = rt.client_api().expect("client api");
    let token = mint_session(&ep);
    let addr = ep.socket_addr;
    let config_path = home.home().join(".advance/runtime-config.yaml");
    let secrets_path = home.home().join(".advance/secrets.json");
    let config_before = fs::read(&config_path).expect("runtime-config");
    let secrets_before = bytes_or_absent(&secrets_path);
    let w0 = spawn_counter::snapshot();

    let preflight = Http::post(addr, "/client/providers/cli:preflight")
        .session(&token)
        .idempotency_key("t113-cli-preflight")
        .send()
        .await;
    assert_process_forbidden(&preflight);

    let usage = Http::get(addr, "/client/providers/cli/usage")
        .session(&token)
        .send()
        .await;
    assert_process_forbidden(&usage);

    let created = Http::post(addr, "/client/providers")
        .session(&token)
        .idempotency_key("t113-cli-create")
        .json(json!({
            "provider_id": "cli-b",
            "backend_class": "agent-cli",
            "agent_cli": {
                "vendor": "claude",
                "command": marker.command().display().to_string()
            },
            "model_aliases": { "default": "cli-model" },
            "cost": { "input_per_mtoken": 0.01, "output_per_mtoken": 0.01 },
            "rate_limit": { "requests_per_minute": 100, "tokens_per_minute": 100000 }
        }))
        .await;
    assert_process_forbidden(&created);

    assert_eq!(
        fs::read(&config_path).expect("runtime-config after"),
        config_before
    );
    assert_eq!(bytes_or_absent(&secrets_path), secrets_before);
    assert!(!marker.ran());
    let w1 = spawn_counter::snapshot();
    let delta = w1.since(&w0);
    assert_eq!(delta.refused(SpawnSite::AgentCli), 3);
    assert_eq!(delta.admitted_total(), 0);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_3_git_pack_source_refused_under_forbid() {
    let _serial = SERIAL.lock().await;
    let home = fixture_home(&["fs", "llm"], FixtureDriver::None, None);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_processes(ProcessPolicy::Forbid),
        Vec::new(),
    )
    .await
    .expect("compose under Forbid");
    let ep = rt.client_api().expect("client api");
    let token = mint_session(&ep);
    let packs = home.home().join(".advance/packs");
    let before_listing = listing(&packs);
    let before = spawn_counter::snapshot();
    let installed = Http::post(ep.socket_addr, "/client/packs:install")
        .session(&token)
        .idempotency_key("t113-git-pack")
        .json(json!({
            "source": "git+https://127.0.0.1:9/p.git",
            "accepted_capabilities": []
        }))
        .await;
    assert_process_forbidden(&installed);
    assert_eq!(listing(&packs), before_listing);
    let delta = spawn_counter::snapshot().since(&before);
    assert_eq!(delta.refused(SpawnSite::PackGitSource), 1);
    assert_eq!(delta.admitted_total(), 0);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_3_pid_lock_probe_in_process_judges_a_live_lock_live() {
    let _serial = SERIAL.lock().await;
    let home = fixture_home(&["fs"], FixtureDriver::None, None);
    let lock = RuntimeLock::acquire(home.home(), Duration::from_secs(30))
        .await
        .expect("acquire Allow");
    let s0 = spawn_counter::snapshot();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_processes(ProcessPolicy::Forbid)
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect_err("live lock refuses compose");
    match error {
        ComposeError::Lock(LockFailure::ActiveRuntime { pid }) => {
            assert_eq!(pid, std::process::id());
        }
        other => panic!("expected ActiveRuntime, got {other:?}"),
    }
    let s1 = spawn_counter::snapshot();
    let d1 = s1.since(&s0);
    assert_eq!(d1.admitted_total(), 0);
    assert_eq!(d1.refused(SpawnSite::PidLockProbe), 2);
    lock.release().await;

    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn true");
    let dead_pid = child.id();
    let status = child.wait().expect("reap true");
    assert!(status.success(), "{status:?}");
    let now = chrono::Utc::now().to_rfc3339();
    let yaml = format!(
        "pid: {dead_pid}\nplatform_uid: \"{}:{dead_pid}:unknown\"\nstarted_at: \"{now}\"\nheartbeat_at: \"{now}\"\nworkspace_root: \"{}\"\nversion: \"0.1.0\"",
        std::env::consts::OS,
        home.home().display()
    );
    fs::create_dir_all(home.home().join(".runtime")).expect("runtime dir");
    fs::write(home.home().join(".runtime/runtime.lock"), yaml).expect("stale lock");
    let s2 = spawn_counter::snapshot();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_processes(ProcessPolicy::Forbid)
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect("stale lock taken over");
    let s3 = spawn_counter::snapshot();
    let d3 = s3.since(&s2);
    assert_eq!(d3.admitted_total(), 0);
    assert_eq!(d3.refused(SpawnSite::PidLockProbe), 2);
    match inspect_lock(home.home()) {
        LockInspection::Live { pid } => assert_eq!(pid, std::process::id()),
        other => panic!("expected Live own pid, got {other:?}"),
    }
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

async fn assert_process_local_artefacts_and_sockets(
    home: FixtureHome,
    options: ComposeOptions,
    probe: Arc<ComposeProbe>,
    baseline: usize,
) {
    let home_progress = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".advance/platform-state/progress-lifecycle"));
    let home_before = home_progress.as_ref().map(|p| listing(p));
    let fallback = std::env::temp_dir()
        .join("advance-agents-contract218-platform")
        .join(contract218_platform_key(home.home()));
    assert!(
        !fallback.exists(),
        "C218 fallback present before compose: {}",
        fallback.display()
    );

    let rt = compose(options, Vec::new())
        .await
        .expect("ProcessLocal composition");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let rec = probe.record();
    assert!(!home.home().join(".runtime/runtime.lock").exists());
    assert!(!home.home().join(".runtime/launch.lock").exists());
    assert!(!home.home().join(".runtime/client-api").exists());
    assert_eq!(
        selected_provider(home.home()),
        format!("pid: {}\nprovider_id: \"\"\n", std::process::id())
    );
    let anchors = listing(&home.state_root().join("contract216"));
    assert!(
        anchors.iter().any(|name| name.ends_with(ANCHOR_SUFFIX)),
        "contract216 anchors: {anchors:?}"
    );
    let platform_dir = home
        .state_root()
        .join("contract218")
        .join(contract218_platform_key(home.home()));
    assert!(platform_dir.is_dir(), "missing {}", platform_dir.display());
    if let Some(socks) = listening_sockets() {
        assert_eq!(socks, vec![addr], "LISTEN sockets {socks:?}");
    }
    assert_eq!(rec.listeners, vec![("client_api", addr)]);
    assert_eq!(rec.master_key_from_config, Some(false));
    if let (Some(path), Some(before)) = (home_progress.as_ref(), home_before.as_ref()) {
        assert_eq!(&listing(path), before, "HOME progress-lifecycle changed");
    }
    assert!(
        !fallback.exists(),
        "C218 fallback written: {}",
        fallback.display()
    );

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_4_process_local_artefacts_and_sockets_daemon_profile() {
    let _serial = SERIAL.lock().await;
    let home = fixture_home(&["fs", "messaging", "lifecycle"], FixtureDriver::None, None);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let options = process_local_options(&home, Arc::new(log), Arc::clone(&probe));
    assert_process_local_artefacts_and_sockets(home, options, probe, baseline).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_4_process_local_artefacts_and_sockets_ios_row() {
    let _serial = SERIAL.lock().await;
    let home = fixture_home(&["fs", "messaging", "lifecycle"], FixtureDriver::None, None);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let options = home.embedded_options(HostPlatform::Ios, Arc::new(log), Arc::clone(&probe));
    assert_process_local_artefacts_and_sockets(home, options, probe, baseline).await;
}

async fn refuse_channels_or_oauth_under(
    make_options: impl Fn(
        &FixtureHome,
        Arc<dyn advance_runtime_compose::ComposeLog>,
        Arc<ComposeProbe>,
    ) -> ComposeOptions,
) {
    {
        let home = fixture_home(&["fs", "messaging"], FixtureDriver::None, None);
        append_runtime_config(&home, CHANNELS_BLOCK);
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let what = refuse_unsupported(
            compose(
                make_options(&home, Arc::new(log), Arc::clone(&probe)),
                Vec::new(),
            )
            .await,
        );
        assert_eq!(what, Unsupported::ListenerRequired("channel /hooks"));
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
    {
        let home = fixture_home(
            &["fs", "llm"],
            FixtureDriver::None,
            Some(provider_yaml::llm_providers_block(&[
                provider_yaml::CHATGPT_OAUTH,
            ])),
        );
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let what = refuse_unsupported(
            compose(
                make_options(&home, Arc::new(log), Arc::clone(&probe)),
                Vec::new(),
            )
            .await,
        );
        assert_eq!(what, Unsupported::ListenerRequired("OAuth callback"));
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_4_channels_or_oauth_sign_in_home_is_unsupported_under_process_local()
{
    let _serial = SERIAL.lock().await;
    refuse_channels_or_oauth_under(process_local_options).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_4_channels_or_oauth_sign_in_home_is_unsupported_under_process_local_ios_row(
) {
    let _serial = SERIAL.lock().await;
    refuse_channels_or_oauth_under(|home, log, probe| {
        home.embedded_options(HostPlatform::Ios, log, probe)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_4_state_root_required_and_outside_the_home() {
    let _serial = SERIAL.lock().await;
    for platform in [HostPlatform::Ios, HostPlatform::Android] {
        let home = fixture_home(&["fs"], FixtureDriver::None, None);
        let log = Arc::new(MemoryComposeLog::new());
        let probe = Arc::new(ComposeProbe::new());
        let none =
            ComposeOptions::embedded(home.home().to_path_buf(), platform, Arc::clone(&log) as _)
                .with_failpoints(advance_runtime_compose::test_support::ComposeFailpoints {
                    probe: Some(Arc::clone(&probe)),
                    ..Default::default()
                });
        let what = refuse_unsupported(compose(none, Vec::new()).await);
        assert_eq!(what, Unsupported::StateRootRequired { platform });
        assert_eq!(
            what.to_string(),
            format!("the {platform} embedded profile requires a state_root outside the home")
        );
        assert!(!reserved_homes().iter().any(|p| p == home.home()));

        let inside = home.home().join("sub");
        fs::create_dir_all(&inside).expect("sub dir");
        let inside = fs::canonicalize(&inside).expect("canonical sub");
        let with_inside = home
            .embedded_options(platform, Arc::clone(&log) as _, Arc::clone(&probe))
            .with_state_root(&inside);
        let what = refuse_unsupported(compose(with_inside, Vec::new()).await);
        match what {
            Unsupported::StateRoot { path, reason } => {
                assert_eq!(path, inside);
                assert_eq!(reason, "lies inside the home");
            }
            other => panic!("expected StateRoot inside home, got {other:?}"),
        }
        assert!(!reserved_homes().iter().any(|p| p == home.home()));
        assert!(probe.record().listeners.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_7_registry_refuses_a_second_profile_on_the_same_home() {
    let _serial = SERIAL.lock().await;
    let home = fixture_home(&["fs"], FixtureDriver::None, None);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("daemon compose");
    let platform = HostPlatform::compiled().unwrap_or(HostPlatform::Linux);
    let log2 = MemoryComposeLog::new();
    let probe2 = Arc::new(ComposeProbe::new());
    let error = compose(
        home.embedded_options(platform, Arc::new(log2), Arc::clone(&probe2))
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect_err("second profile");
    match error {
        ComposeError::Lock(LockFailure::HeldInProcess) => {}
        other => panic!("expected HeldInProcess, got {other:?}"),
    }
    rt.shutdown().await.expect("shutdown");
    let log3 = MemoryComposeLog::new();
    let probe3 = Arc::new(ComposeProbe::new());
    let baseline3 = alive_tasks();
    let embedded = compose(
        home.embedded_options(platform, Arc::new(log3), Arc::clone(&probe3))
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect("embedded after daemon shutdown");
    embedded.shutdown().await.expect("shutdown embedded");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    assert_gone_for_home(&probe3, home.home(), Some(baseline3)).await;
    assert!(!reserved_homes().iter().any(|p| p == home.home()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_t113_7_registry_refuses_a_second_profile_on_the_same_home_ios_row() {
    let _serial = SERIAL.lock().await;
    let home = fixture_home(&["fs"], FixtureDriver::None, None);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("daemon compose");
    let log2 = MemoryComposeLog::new();
    let probe2 = Arc::new(ComposeProbe::new());
    let error = compose(
        home.embedded_options(HostPlatform::Ios, Arc::new(log2), Arc::clone(&probe2))
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect_err("second profile");
    match error {
        ComposeError::Lock(LockFailure::HeldInProcess) => {}
        other => panic!("expected HeldInProcess, got {other:?}"),
    }
    rt.shutdown().await.expect("shutdown");
    let log3 = MemoryComposeLog::new();
    let probe3 = Arc::new(ComposeProbe::new());
    let baseline3 = alive_tasks();
    let embedded = compose(
        home.embedded_options(HostPlatform::Ios, Arc::new(log3), Arc::clone(&probe3))
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect("embedded after daemon shutdown");
    embedded.shutdown().await.expect("shutdown embedded");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    assert_gone_for_home(&probe3, home.home(), Some(baseline3)).await;
    assert!(!reserved_homes().iter().any(|p| p == home.home()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_listeners_refused_under_process_local() {
    let _serial = SERIAL.lock().await;
    let flags = [
        ("POST /msg", ListenerOptions::none().with_post_msg(true)),
        (
            "EventBus WebSocket",
            ListenerOptions::none().with_event_bus_ws(true),
        ),
        (
            "channel /hooks",
            ListenerOptions::none().with_channel_hooks(true),
        ),
        (
            "OAuth callback",
            ListenerOptions::none().with_oauth_callback(true),
        ),
    ];
    for (name, listeners) in flags {
        let home = fixture_home(&["fs"], FixtureDriver::None, None);
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let what = refuse_unsupported(
            compose(
                home.options(Arc::new(log), Arc::clone(&probe))
                    .with_instance(InstanceGuard::ProcessLocal)
                    .with_listeners(listeners)
                    .with_client_api(ClientApiOptions::loopback(
                        0,
                        false,
                        Admission::SameUserLoopback,
                    )),
                Vec::new(),
            )
            .await,
        );
        assert_eq!(what, Unsupported::ListenerUnderProcessLocal(name), "{name}");
        assert!(!reserved_homes().iter().any(|p| p == home.home()));
        assert!(probe.record().listeners.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_d3_hot_reload_off_no_watcher_no_pack_poll_and_admin_writes_answer_restart_required(
) {
    let _serial = SERIAL.lock().await;
    let providers =
        provider_yaml::llm_providers_block(&[provider_yaml::LOCAL_FREE, provider_yaml::CLOUD_A]);
    {
        let home = fixture_home(&["fs", "llm"], FixtureDriver::None, Some(providers.clone()));
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let rt = compose(
            home.options(Arc::new(log), Arc::clone(&probe))
                .with_hot_reload(false),
            Vec::new(),
        )
        .await
        .expect("hot_reload false");
        let rec = probe.record();
        assert_eq!(rec.config_watching, Some(false));
        assert_eq!(rec.packs_poll, Some(false));
        let ep = rt.client_api().expect("client api");
        let token = mint_session(&ep);
        let started = Instant::now();
        let created = Http::post(ep.socket_addr, "/client/providers")
            .session(&token)
            .idempotency_key("t113-cloud-b")
            .json(json!({
                "provider_id": "cloud-b",
                "backend_class": "cloud-http",
                "endpoint": "https://api.example.com",
                "model_aliases": { "m": "m" },
                "cost": { "input_per_mtoken": 1.0, "output_per_mtoken": 1.0 },
                "rate_limit": { "requests_per_minute": 10, "tokens_per_minute": 1000 }
            }))
            .await;
        assert!(created.body.get("data").is_some(), "{:?}", created.body);
        assert_eq!(
            restart_required_count(&created.body),
            1,
            "{:?}",
            created.body
        );
        assert!(
            created.body.pointer("/data/reload_pending").is_none()
                || created.body.pointer("/data/reload_pending") == Some(&Value::Null),
            "{:?}",
            created.body
        );
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{:?}",
            started.elapsed()
        );

        let selected = Http::post(ep.socket_addr, "/client/providers/cloud-b:select")
            .session(&token)
            .idempotency_key("t113-select-cloud-b")
            .send()
            .await;
        assert!(selected.body.get("data").is_some(), "{:?}", selected.body);
        assert_eq!(
            restart_required_count(&selected.body),
            1,
            "{:?}",
            selected.body
        );
        assert!(
            selected_provider(home.home()).contains("local-free"),
            "{}",
            selected_provider(home.home())
        );

        home.rewrite_providers(&provider_yaml::llm_providers_block(&[
            provider_yaml::CLOUD_A,
            provider_yaml::LOCAL_FREE,
        ]))
        .expect("reorder");
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            selected_provider(home.home()).contains("local-free"),
            "hot_reload off must not rewrite selected-provider: {}",
            selected_provider(home.home())
        );
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
    {
        let home = fixture_home(&["fs", "llm"], FixtureDriver::None, Some(providers));
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
            .await
            .expect("hot_reload true");
        home.rewrite_providers(&provider_yaml::llm_providers_block(&[
            provider_yaml::CLOUD_A,
            provider_yaml::LOCAL_FREE,
        ]))
        .expect("reorder control");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if selected_provider(home.home()).contains("cloud-a") {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "hot_reload true did not rewrite selected-provider: {}",
                    selected_provider(home.home())
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        rt.shutdown().await.expect("shutdown");
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_d3_master_key_provided_embedded_touches_no_key_source() {
    let _serial = SERIAL.lock().await;
    let platform = HostPlatform::compiled().unwrap_or(HostPlatform::Linux);
    let home = fixture_home(&["fs", "llm", "messaging"], FixtureDriver::None, None);
    set_master_key_env_name(&home, "ADVANCE_T113_KEY_NEVER_SET");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let options = home
        .embedded_options(platform, Arc::new(log), Arc::clone(&probe))
        .with_client_api(ClientApiOptions::Off);
    let rendered = format!("{options:?}");
    let hex = hex32(&FIXTURE_MASTER_KEY);
    assert!(
        !rendered.contains(&hex),
        "Debug leaked the provided key: {rendered}"
    );
    let rt = compose(options, Vec::new())
        .await
        .expect("Provided key composes");
    assert_eq!(probe.record().master_key_from_config, Some(false));
    assert!(!home.home().join(".advance/master.key").exists());
    assert!(!any_migrated(home.home()));
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;

    let control = fixture_home(&["fs", "llm", "messaging"], FixtureDriver::None, None);
    set_master_key_env_name(&control, "ADVANCE_T113_KEY_NEVER_SET");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let options =
        ComposeOptions::embedded(control.home().to_path_buf(), platform, Arc::new(log) as _)
            .with_state_root(control.state_root())
            .with_client_api(ClientApiOptions::Off)
            .with_failpoints(advance_runtime_compose::test_support::ComposeFailpoints {
                probe: Some(Arc::clone(&probe)),
                ..Default::default()
            });
    let error = compose(options, Vec::new())
        .await
        .expect_err("FromConfig with a missing env key");
    match error {
        ComposeError::Wiring(_) => {}
        other => panic!("expected Wiring, got {other:?}"),
    }
    assert_eq!(probe.record().master_key_from_config, Some(true));
    assert_gone_for_home(&probe, control.home(), Some(baseline)).await;
}
