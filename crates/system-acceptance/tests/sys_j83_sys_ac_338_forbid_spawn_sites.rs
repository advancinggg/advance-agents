//! SYS-AC-338: under `Forbid` a sidecar, `agent-cli`, MCP stdio or `git`
//! pack-source request answers a typed refusal and no child process exists.
//!
//! MCP stdio has no production compose path; that leg is port-level
//! `cap_mcp::McpClient`. Own binary because the spawn counter is process-global.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use advance_runtime_compose::compose;
use advance_runtime_compose::test_support::fixture::inference::{provider_yaml, SidecarMarker};
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, post_msg, CapDecl, FixtureDriver, FixtureExtension,
    FixtureHome, FixtureHomeSpec, Http, HttpResponse, FIXTURE_ID,
};
use advance_runtime_compose::test_support::proc_self::child_pids;
use advance_runtime_compose::test_support::{spawn_counter, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::ProcessPolicy;
use advance_shared_types::process_policy::SpawnSite;
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_mcp::{McpClient, McpServerEntry, McpServersConfig, McpTransportSpec};
use serde_json::{json, Value};

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn home(providers: Option<String>) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver: FixtureDriver::LlmNoErr,
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

struct NoOpDetector;
impl LeakDetector for NoOpDetector {
    fn scan(&self, _text: &str, _ctx: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_338_j83_forbid_spawn_sites_refuse_typed_no_child() {
    let s0 = spawn_counter::snapshot();
    let marker_s = SidecarMarker::new().expect("marker_s");
    let marker_c = SidecarMarker::new().expect("marker_c");
    let marker_m = SidecarMarker::new().expect("marker_m");

    let side = provider_yaml::side(marker_s.command());
    let cli = provider_yaml::cli(marker_c.command());
    let home_s = home(Some(provider_yaml::llm_providers_block(&[side.as_str()])));
    let home_c = home(Some(provider_yaml::llm_providers_block(&[cli.as_str()])));

    let log_s = MemoryComposeLog::new();
    let probe_s = Arc::new(ComposeProbe::new());
    let log_c = MemoryComposeLog::new();
    let probe_c = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt_s = compose(
        home_s
            .options(Arc::new(log_s), Arc::clone(&probe_s))
            .with_processes(ProcessPolicy::Forbid),
        vec![FixtureExtension::new(FIXTURE_ID).arc()],
    )
    .await
    .expect("compose S under Forbid");

    let rt_c = compose(
        home_c
            .options(Arc::new(log_c), Arc::clone(&probe_c))
            .with_processes(ProcessPolicy::Forbid),
        vec![FixtureExtension::new(FIXTURE_ID).arc()],
    )
    .await
    .expect("compose C under Forbid");

    let addr_s = probe_s
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound on S");
    let (status, body) = post_msg(addr_s, "llm:hi").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("llm-err:"), "{body}");
    // MODULE-009 §1.7 redacts the inner LocalTransport string on the WIT path;
    // the typed refusal is the spawn counter + the marker that never ran.
    assert!(body.contains("ProviderError(\"provider error\")"), "{body}");
    assert!(!marker_s.ran(), "sidecar ran under Forbid");

    let addr_c = probe_c
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound on C");
    let (status, body) = post_msg(addr_c, "llm:hi").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("llm-err:"), "{body}");
    // MODULE-009 §1.7 redacts the inner agent-cli string on the WIT path;
    // the typed refusal is the spawn counter + the marker that never ran.
    assert!(body.contains("ProviderError(\"provider error\")"), "{body}");
    assert!(!marker_c.ran(), "agent-cli ran under Forbid");

    let ep = rt_c.client_api().expect("client api");
    let token = mint_session(&ep);
    let addr = ep.socket_addr;
    let config_path = home_c.home().join(".advance/runtime-config.yaml");
    let secrets_path = home_c.home().join(".advance/secrets.json");
    let config_before = fs::read(&config_path).expect("runtime-config");
    let secrets_before = bytes_or_absent(&secrets_path);

    let preflight = Http::post(addr, "/client/providers/cli:preflight")
        .session(&token)
        .idempotency_key("forbid-cli-preflight")
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
        .idempotency_key("forbid-cli-create")
        .json(json!({
            "provider_id": "cli-b",
            "backend_class": "agent-cli",
            "agent_cli": {
                "vendor": "claude",
                "command": marker_c.command().display().to_string()
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

    let packs = home_c.home().join(".advance/packs");
    let before_listing = listing(&packs);
    let installed = Http::post(addr, "/client/packs:install")
        .session(&token)
        .idempotency_key("forbid-git-pack")
        .json(json!({
            "source": "git+https://127.0.0.1:9/p.git",
            "accepted_capabilities": []
        }))
        .await;
    assert_process_forbidden(&installed);
    assert_eq!(listing(&packs), before_listing);

    // Port-level MCP stdio leg: no production compose path reaches
    // StdioMcpTransport::spawn.
    let entry = McpServerEntry {
        server_id: "srv".into(),
        description: "test".into(),
        transport: McpTransportSpec::Stdio {
            command: marker_m.command().display().to_string(),
            args: vec![],
            env: BTreeMap::new(),
        },
        tool_patterns: None,
        tool_schemas: BTreeMap::new(),
    };
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(entry)
            .expect("stdio whitelist")
            .build(),
    );
    let err = McpClient::new(cfg, Arc::new(NoOpDetector), None)
        .with_process_policy(ProcessPolicy::Forbid)
        .list_tools("srv")
        .await
        .expect_err("mcp stdio forbid");
    assert!(err.to_string().contains("process_forbidden"), "{err}");
    assert!(!marker_m.ran(), "mcp stdio ran under Forbid");

    let delta = spawn_counter::snapshot().since(&s0);
    assert_eq!(delta.admitted_total(), 0);
    assert!(
        delta.refused(SpawnSite::LocalSidecar) >= 1,
        "LocalSidecar refusals: {}",
        delta.refused(SpawnSite::LocalSidecar)
    );
    assert!(
        delta.refused(SpawnSite::AgentCli) >= 1,
        "AgentCli refusals: {}",
        delta.refused(SpawnSite::AgentCli)
    );
    assert!(
        delta.refused(SpawnSite::PackGitSource) >= 1,
        "PackGitSource refusals: {}",
        delta.refused(SpawnSite::PackGitSource)
    );
    assert!(
        delta.refused(SpawnSite::McpStdio) >= 1,
        "McpStdio refusals: {}",
        delta.refused(SpawnSite::McpStdio)
    );
    assert!(!marker_s.ran() && !marker_c.ran() && !marker_m.ran());
    if let Some(pids) = child_pids() {
        assert_eq!(pids, Vec::<u32>::new());
    }

    rt_s.shutdown().await.expect("shutdown S");
    rt_c.shutdown().await.expect("shutdown C");
    assert_gone_for_home(&probe_s, home_s.home(), Some(baseline)).await;
    assert_gone_for_home(&probe_c, home_c.home(), Some(baseline)).await;
}
