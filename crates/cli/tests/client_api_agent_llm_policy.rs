//! Lane agent-llm-policy — the per-agent `llm:` policy over the PRODUCTION wiring.
//!
//! Drives the FULL boot path (`RuntimeHostBuilder::new` → `wire_capabilities`) over a temp
//! workspace declaring fs + llm (so the real cap-llm gateway is composed), then exercises the
//! daemon-composed `ClientApi` (`client_api_server.api()`, the same instance the loopback
//! transport serves) and the daemon's own gateway:
//!
//! - `:update {llm}` on the root writes the block into `.agent/config.yaml`, echoes it on the
//!   detail, and carries NO `restart_required`;
//! - an unknown `llm.provider` is `invalid_request` + details `["unknown_provider"]` and leaves
//!   the file untouched; `{}` clears the block;
//! - a child created with `llm` gets the block in ITS territory, and the production
//!   `WorkspaceAgentLlmPolicy` over the shared tree resolves both agents from disk;
//! - the composed gateway reports the policy source installed, and a pin (hand-edited into the
//!   file, bypassing the API's existence check) to a provider absent from the runtime config
//!   fails CLOSED on the next call — `ModelNotAvailable`, no network, no fallback.
//!
//! Witness boundary: the daemon's SSRF guard denies loopback egress, so a real
//! generate to a local mock endpoint cannot be driven through this wiring; routing to the pinned
//! provider and cost attribution are witnessed at the cap-llm level (`policy_tests.rs`).

use std::path::{Path, PathBuf};

use advance_cli::agent_config::parse_agent_llm_config;
use advance_cli::agent_llm_policy::WorkspaceAgentLlmPolicy;
use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_client_api::agents::WARNING_RESTART_REQUIRED;
use advance_client_api::{
    ClientAgentDetail, ClientApi, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    Platform, Principal, Scope, UNKNOWN_PROVIDER_DETAIL,
};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use cap_llm::{
    AgentLlmPolicySource, ChatMessage, ChatParams, ChatRole, LlmError, LlmGatewayInternal,
};
use serde_json::{json, Value};

const ROOT: &str = "default-agent";
const MASTER_KEY_ENV: &str = "ADV_AGENT_LLM_POLICY_MK";
const MASTER_KEY_HEX: &str = "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";

fn ensure_master_key() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var(MASTER_KEY_ENV, MASTER_KEY_HEX));
}

fn runtime_yaml() -> String {
    format!(
        r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt4o: gpt-4o-2024-08-06
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000
  - id: eu-mirror
    endpoint: https://eu.mirror.example
    api-key-secret: eu-mirror-api-key
    model-aliases:
      gpt4o: gpt-4o-eu
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: {MASTER_KEY_ENV}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    )
}

fn fresh_workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
    ensure_master_key();
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  llm: true\n",
    )
    .unwrap();
    (dir, workspace, config_path)
}

async fn boot(ws: &Path, cfg: &Path) -> (advance_runtime::bootstrap::RuntimeHost, WiringHandles) {
    let builder = RuntimeHostBuilder::new(cfg, ws).await.expect("builder");
    wire_capabilities(builder, ws).await.expect("wire")
}

fn mint(api: &ClientApi, token: &str) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

fn get(api: &ClientApi, path: &str) -> ClientEnvelope<Value> {
    api.handle(ClientRequest::get(path).with_session("tok"))
}

fn post(api: &ClientApi, path: &str, body: Value, key: &str) -> ClientEnvelope<Value> {
    api.handle(
        ClientRequest::post(path, body)
            .with_session("tok")
            .with_idempotency_key(key),
    )
}

fn detail(env: &ClientEnvelope<Value>) -> ClientAgentDetail {
    assert!(env.is_ok(), "expected ok, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("detail parses")
}

fn has_restart_warning(env: &ClientEnvelope<Value>) -> bool {
    env.warnings
        .iter()
        .any(|w| w.code == WARNING_RESTART_REQUIRED)
}

fn config_text(ws: &Path) -> String {
    std::fs::read_to_string(ws.join(".agent/config.yaml")).unwrap()
}

// ── LP-01: the block round-trips through the API and the production policy source ────────────
#[tokio::test(flavor = "multi_thread")]
async fn lp01_llm_block_over_production_wiring() {
    let (_g, ws, cfg) = fresh_workspace();
    let (_host, handles) = boot(&ws, &cfg).await;
    let api = handles
        .client_api_server
        .as_ref()
        .expect("EventBus up ⇒ Client API bound")
        .api();
    mint(&api, "tok");
    let gateway = handles
        .llm_gateway
        .clone()
        .expect("llm declared ⇒ gateway composed");
    assert!(
        gateway.has_agent_policy(),
        "wire_capabilities installs the WorkspaceAgentLlmPolicy on the production gateway"
    );

    // Before: no block on the root.
    let root = detail(&get(&api, &format!("/client/agents/{ROOT}")));
    assert!(root.config.llm.is_none());

    // Update: the block lands in the root document, echoes on the detail, no restart warning.
    let env = post(
        &api,
        &format!("/client/agents/{ROOT}:update"),
        json!({ "llm": { "provider": "eu-mirror", "model": "gpt4o", "constraint": "never-cloud" } }),
        "k-llm-root",
    );
    let d = detail(&env);
    let llm = d.config.llm.clone().expect("typed llm view");
    assert_eq!(llm.provider.as_deref(), Some("eu-mirror"));
    assert_eq!(llm.model.as_deref(), Some("gpt4o"));
    assert_eq!(llm.constraint.as_deref(), Some("never-cloud"));
    assert!(
        !has_restart_warning(&env),
        "an llm-only update applies at the next LLM call: {:?}",
        env.warnings
    );
    let text = config_text(&ws);
    assert!(text.contains("capabilities:"), "other keys kept: {text}");
    let decl = parse_agent_llm_config(Some(text.as_bytes()))
        .expect("the written block is valid")
        .expect("present");
    assert_eq!(decl.provider.as_deref(), Some("eu-mirror"));
    assert_eq!(decl.constraint.as_deref(), Some("never-cloud"));
    // The L0 capability gate still reads the same document.
    let caps = advance_cli::agent_config::active_capabilities(Some(text.as_bytes()));
    assert_eq!(caps.len(), 2, "fs + llm survive the rewrite");

    // The production policy source over the shared tree resolves the root from disk.
    let source = WorkspaceAgentLlmPolicy::new(
        handles.agent_tree.clone(),
        ROOT,
        ws.clone(),
        handles.event_bus_dyn.clone(),
    );
    let policy = source.policy_for(ROOT).expect("root policy");
    assert_eq!(policy.provider.as_deref(), Some("eu-mirror"));
    assert_eq!(policy.model.as_deref(), Some("gpt4o"));
    assert_eq!(
        policy.constraint,
        Some(cap_llm::UserHardConstraint::NeverCloud)
    );

    // Unknown provider: refused with the stable detail token; the file is untouched.
    let before = config_text(&ws);
    let env = post(
        &api,
        &format!("/client/agents/{ROOT}:update"),
        json!({ "llm": { "provider": "ghost" } }),
        "k-llm-ghost",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(
        env.error.as_ref().unwrap().details,
        vec![UNKNOWN_PROVIDER_DETAIL.to_string()]
    );
    assert_eq!(config_text(&ws), before, "a refused update writes nothing");

    // A child created WITH a block gets it in its own territory; the tree-backed source
    // resolves it by the bare tree id.
    let env = post(
        &api,
        "/client/agents",
        json!({
            "agent_id": "research",
            "template_ref": "explorer",
            "capabilities": ["fs"],
            "llm": { "provider": "openai", "model": "gpt4o" }
        }),
        "k-create-research",
    );
    let d = detail(&env);
    assert_eq!(d.config.llm.unwrap().provider.as_deref(), Some("openai"));
    let child_text = config_text(&ws.join("research"));
    assert!(child_text.contains("llm:"), "{child_text}");
    assert!(
        !config_text(&ws).contains("provider: openai"),
        "the child's block never lands in the root document"
    );
    let policy = source
        .policy_for("research")
        .expect("child policy via the tree");
    assert_eq!(policy.provider.as_deref(), Some("openai"));
    assert_eq!(policy.model.as_deref(), Some("gpt4o"));
    // A creation with an unknown provider never materializes the agent.
    let env = post(
        &api,
        "/client/agents",
        json!({ "agent_id": "ghostly", "template_ref": "explorer", "llm": { "provider": "ghost" } }),
        "k-create-ghostly",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidRequest));
    assert!(!ws.join("ghostly").exists());

    // `{}` clears the root block (mtime-tracked: the source sees it on the next call).
    let env = post(
        &api,
        &format!("/client/agents/{ROOT}:update"),
        json!({ "llm": {} }),
        "k-llm-clear",
    );
    assert!(detail(&env).config.llm.is_none());
    let cleared = config_text(&ws);
    assert!(
        !cleared.lines().any(|l| l.starts_with("llm:")),
        "no top-level llm key after clearing: {cleared}"
    );
    assert!(
        cleared.contains("capabilities:") && cleared.contains("agents:"),
        "the other keys survive the clear: {cleared}"
    );
    assert!(parse_agent_llm_config(Some(cleared.as_bytes()))
        .unwrap()
        .is_none());
    // Give coarse-mtime filesystems a distinct stamp before asserting the re-read.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(ws.join(".agent/config.yaml"))
        .unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
        .unwrap();
    assert!(source.policy_for(ROOT).is_none());
}

// ── LP-02: a pinned provider missing from the runtime config fails closed, in-process ─────────
#[tokio::test(flavor = "multi_thread")]
async fn lp02_pin_to_vanished_provider_fails_closed_without_leaving_the_process() {
    let (_g, ws, cfg) = fresh_workspace();
    let (_host, handles) = boot(&ws, &cfg).await;
    let gateway = handles.llm_gateway.clone().expect("gateway");
    // Bypass the API's existence check: hand-edit the file to pin an unknown provider.
    std::fs::write(
        ws.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  llm: true\nllm:\n  provider: vanished\n",
    )
    .unwrap();
    let err = gateway
        .chat(
            vec![ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            }],
            ChatParams::default(),
        )
        .await
        .expect_err("a pin to an unconfigured provider must fail closed");
    match err {
        LlmError::ModelNotAvailable(msg) => {
            assert_eq!(
                msg,
                "provider vanished not configured for agent default-agent"
            )
        }
        other => panic!("expected ModelNotAvailable, got {other:?}"),
    }
    // The refusal message is minted ONLY by the pre-placement policy step, so the request was
    // refused before any placement / dispatch could run (the "no llm.request" half of this
    // claim is pinned with a recording bus in cap-llm's `policy_tests.rs`).
}
