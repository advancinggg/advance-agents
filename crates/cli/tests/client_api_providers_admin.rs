//! CONTRACT-190 providers family — the PRODUCTION adapter over a real workspace home
//! (lane providers-family, `docs/llm-providers-policy-keychain.md` §1.5).
//!
//! Drives the FULL boot path (`RuntimeHostBuilder::new` → `wire_capabilities`) over a temp
//! workspace that declares `fs` + `llm` (so the daemon holds a LIVE `SecretStore`), then
//! exercises the daemon-composed `ClientApi` (`wiring_handles.client_api_server.api()`, the SAME
//! instance the loopback transport serves) through `handle()`: list / create / update / select /
//! delete / set-key / preflight / clear-key, asserting the REAL effects — the rewritten
//! `runtime-config.yaml` re-parsed by the runtime's strict `load_config`, the `.runtime/
//! selected-provider` adopt file, ciphertext in `.advance/secrets.json` that the daemon's own
//! store resolves, and the config watcher's applied reload (or the `reload_pending` advisory).
//!
//! Preflight is the ONE injected seam: a recording `PreflightPort` stands in for the network
//! generate path (the production adapter uses `GeneratePathPreflight`), mounted onto the booted
//! daemon's API with `install_provider_admin`.
//!
//! Fixture discipline: `master-key-source: env-var` with a test-unique env var name set ONCE
//! (`needs_key = true` because `llm` is declared), mirroring `s4_live_streaming_composition.rs`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use advance_cli::client_api_providers::{
    install_provider_admin, NoReferences, ProviderReferenceCheck, WiredProviderAdmin,
};
use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_client_api::envelope::{
    WARNING_PREFLIGHT_SKIPPED, WARNING_RELOAD_PENDING, WARNING_RESTART_REQUIRED,
};
use advance_client_api::provider_admin::{
    ClientProviderDeleteResult, ClientProviderKeyResult, ClientProviderList,
    ClientProviderPreflightResult, ClientProviderSummary,
};
use advance_client_api::{
    ClientApi, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession, Platform, Principal,
    Scope,
};
use advance_home::{CancelToken, PreflightFail, PreflightPort, SecretBytes};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::config::{load_config, LlmProviderConfig, RuntimeConfigProvider};
use secrecy::ExposeSecret;
use serde_json::{json, Value};

const MASTER_KEY_ENV: &str = "ADV_PROVIDERS_ADMIN_MK";
const MASTER_KEY_HEX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
const SECRET_KEY: &str = "sk-ant-LIVE-TEST-KEY-9f8e7d6c5b4a";
const OTHER_KEY: &str = "sk-ant-OTHER-KEY-00112233";

fn ensure_master_key_env() {
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
      gpt: gpt-4o
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
    ensure_master_key_env();
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

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes,
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

fn data<T: serde::de::DeserializeOwned>(env: &ClientEnvelope<Value>) -> T {
    assert!(env.is_ok(), "expected ok, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("payload parses")
}

fn has_warning(env: &ClientEnvelope<Value>, code: &str) -> bool {
    env.warnings.iter().any(|w| w.code == code)
}

fn entries(ws: &Path) -> Vec<LlmProviderConfig> {
    load_config(&ws.join(".advance/runtime-config.yaml"))
        .expect("runtime-config.yaml re-parses under the strict runtime loader")
        .llm_providers
}

fn ids(ws: &Path) -> Vec<String> {
    entries(ws).iter().map(|p| p.id.clone()).collect()
}

/// The ONE injected seam: records what the adapter asked it to verify, answers a scripted
/// verdict, and can stall until cancelled (the timeout leg).
struct ScriptedPreflight {
    calls: Mutex<Vec<(String, String)>>,
    verdict: Mutex<Result<(), PreflightFail>>,
    stall: Mutex<bool>,
}

impl ScriptedPreflight {
    fn passing() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            verdict: Mutex::new(Ok(())),
            stall: Mutex::new(false),
        })
    }
    fn set_verdict(&self, verdict: Result<(), PreflightFail>) {
        *self.verdict.lock().unwrap() = verdict;
    }
    fn set_stall(&self, stall: bool) {
        *self.stall.lock().unwrap() = stall;
    }
}

impl PreflightPort for ScriptedPreflight {
    fn preflight(
        &self,
        _home: &Path,
        provider: &LlmProviderConfig,
        key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        self.calls
            .lock()
            .unwrap()
            .push((provider.id.clone(), key.expose().to_string()));
        if *self.stall.lock().unwrap() {
            while !cancel.is_cancelled() {
                std::thread::sleep(Duration::from_millis(5));
            }
            return Err(PreflightFail::Cancelled);
        }
        self.verdict.lock().unwrap().clone()
    }
}

struct PinnedBy(Vec<String>);

impl ProviderReferenceCheck for PinnedBy {
    fn referenced_by(&self, provider_id: &str) -> Vec<String> {
        if self.0.iter().any(|p| p == provider_id) {
            vec!["research".to_string()]
        } else {
            Vec::new()
        }
    }
}

fn anthropic_body() -> Value {
    json!({
        "provider_id": "anthropic",
        "backend": "anthropic-messages",
        "endpoint": "https://api.anthropic.com",
        "model_aliases": { "sonnet": "claude-sonnet-4-5", "haiku": "claude-haiku-4-5" },
        "cost": { "input_per_mtoken": 3.0, "output_per_mtoken": 15.0, "cache_read_per_mtoken": 0.3 },
        "rate_limit": { "requests_per_minute": 500, "tokens_per_minute": 200000 },
        "retry_default": { "max_retries": 2, "base_delay_ms": 100, "max_delay_ms": 1000 }
    })
}

// ── PV-01: entry lifecycle over the daemon-composed API against the real YAML + watcher ───────
#[tokio::test(flavor = "multi_thread")]
async fn pv01_entry_lifecycle_over_production_wiring() {
    let (_g, ws, cfg) = fresh_workspace();
    let (host, handles) = boot(&ws, &cfg).await;
    let server = handles
        .client_api_server
        .as_ref()
        .expect("EventBus up ⇒ Client API bound");
    let api = server.api();
    let admin = handles
        .provider_admin
        .as_ref()
        .expect("providers adapter composed");
    assert!(admin.has_live_store(), "llm declared ⇒ live secret store");
    assert!(handles.secret_store.is_some());
    mint(&api, "tok", Scope::operator_default());

    // list: the seeded openai entry, selected, no key.
    let list: ClientProviderList = data(&get(&api, "/client/providers"));
    assert_eq!(list.providers.len(), 1);
    assert_eq!(list.providers[0].provider_id, "openai");
    assert!(list.providers[0].selected);
    assert_eq!(list.providers[0].key.secret_name, "openai-api-key");
    assert!(!list.providers[0].key.present);
    assert_eq!(list.providers[0].backend_class, "cloud-http");

    // create: appended (not selected); the document re-parses strictly with every field.
    let env = post(&api, "/client/providers", anthropic_body(), "k-create");
    let created: ClientProviderSummary = data(&env);
    assert_eq!(created.provider_id, "anthropic");
    assert!(!created.selected);
    assert_eq!(created.key.secret_name, "anthropic-api-key");
    assert_eq!(created.backend.as_deref(), Some("anthropic-messages"));
    assert_eq!(created.cost.cache_read_per_mtoken, Some(0.3));
    assert_eq!(created.retry_default.as_ref().unwrap().max_retries, 2);
    assert!(!has_warning(&env, WARNING_RESTART_REQUIRED));
    let on_disk = entries(&ws);
    assert_eq!(ids(&ws), vec!["openai", "anthropic"]);
    let a = &on_disk[1];
    assert_eq!(a.endpoint, "https://api.anthropic.com");
    assert_eq!(a.api_key_secret, "anthropic-api-key");
    assert_eq!(a.model_aliases["sonnet"], "claude-sonnet-4-5");
    assert_eq!(a.cost_per_mtoken_in, 3.0);
    assert_eq!(a.cost_per_mtoken_cache_read, Some(0.3));
    assert_eq!(a.rate_limit.as_ref().unwrap().requests_per_minute, 500);
    assert_eq!(a.retry_default.as_ref().unwrap().max_delay_ms, 1000);
    // Hot reload: either the watcher applied it within the adapter's wait, or the response
    // says so honestly. Record which leg fired.
    let reloaded = host.config_watcher().current().llm_providers.len() == 2;
    let pending = has_warning(&env, WARNING_RELOAD_PENDING);
    assert!(
        reloaded || pending,
        "a write is either observed by the watcher or flagged reload_pending"
    );
    eprintln!("PV-01 create: watcher_reloaded={reloaded} reload_pending_warning={pending}");

    // Duplicate id → already_exists, document untouched.
    let env = post(&api, "/client/providers", anthropic_body(), "k-dup");
    assert_eq!(env.error_code(), Some(ClientErrorCode::AlreadyExists));
    assert_eq!(ids(&ws), vec!["openai", "anthropic"]);

    // A create the RUNTIME rejects (cleartext http to a non-localhost host) → invalid_request,
    // and the document is untouched (tmp validated before rename).
    let mut cleartext = anthropic_body();
    cleartext["provider_id"] = json!("plain");
    cleartext["endpoint"] = json!("http://plain.example");
    let env = post(&api, "/client/providers", cleartext, "k-plain");
    assert_eq!(
        env.error_code(),
        Some(ClientErrorCode::InvalidRequest),
        "{env:?}"
    );
    assert_eq!(ids(&ws), vec!["openai", "anthropic"]);
    assert!(!ws.join(".advance/runtime-config.yaml.tmp").exists());

    // update: only the named field changes; untouched keys survive verbatim.
    let env = post(
        &api,
        "/client/providers/anthropic:update",
        json!({ "cost": { "input_per_mtoken": 2.0, "output_per_mtoken": 8.0 } }),
        "k-update",
    );
    let updated: ClientProviderSummary = data(&env);
    assert_eq!(updated.cost.input_per_mtoken, 2.0);
    assert_eq!(
        updated.cost.cache_read_per_mtoken, None,
        "replaced wholesale"
    );
    let a = entries(&ws)
        .into_iter()
        .find(|p| p.id == "anthropic")
        .unwrap();
    assert_eq!(a.cost_per_mtoken_out, 8.0);
    assert_eq!(
        a.endpoint, "https://api.anthropic.com",
        "untouched key survives"
    );
    assert_eq!(a.model_aliases.len(), 2, "untouched aliases survive");
    assert_eq!(a.rate_limit.as_ref().unwrap().tokens_per_minute, 200_000);
    assert_eq!(a.retry_default.as_ref().unwrap().max_retries, 2);
    assert_eq!(
        a.backend,
        Some(advance_runtime::config::ProviderBackend::AnthropicMessages)
    );

    // select: anthropic moves to index 0; the adopt file names it with THIS daemon's pid.
    let env = post(
        &api,
        "/client/providers/anthropic:select",
        Value::Null,
        "k-select",
    );
    let selected: ClientProviderSummary = data(&env);
    assert!(selected.selected);
    assert_eq!(ids(&ws), vec!["anthropic", "openai"]);
    let adopt = std::fs::read_to_string(ws.join(".runtime/selected-provider")).unwrap();
    assert!(adopt.contains("provider_id: \"anthropic\""), "{adopt}");
    assert!(
        adopt.contains(&format!("pid: {}", std::process::id())),
        "{adopt}"
    );
    let list: ClientProviderList = data(&get(&api, "/client/providers"));
    assert!(list.providers[0].selected && list.providers[0].provider_id == "anthropic");
    assert!(!list.providers[1].selected);

    // The watcher eventually holds the reordered document (poll up to 5 s — the adapter's own
    // 2 s wait may already have observed it).
    let mut observed = false;
    for _ in 0..50 {
        if host
            .config_watcher()
            .current()
            .llm_providers
            .first()
            .map(|p| p.id.as_str())
            == Some("anthropic")
        {
            observed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!("PV-01 select: watcher observed reorder within 5s = {observed}");

    // A sidecar-backed local entry: restart_required.
    let local = json!({
        "provider_id": "lm",
        "backend_class": "local",
        "model_aliases": { "tiny": "qwen2.5-0.5b" },
        "cost": { "input_per_mtoken": 0.01, "output_per_mtoken": 0.01 },
        "rate_limit": { "requests_per_minute": 100, "tokens_per_minute": 100000 },
        "sidecar": { "command": "/usr/bin/true", "args": ["--serve"] }
    });
    let env = post(&api, "/client/providers", local, "k-local");
    let lm: ClientProviderSummary = data(&env);
    assert!(lm.sidecar_present);
    assert_eq!(lm.backend_class, "local");
    assert!(has_warning(&env, WARNING_RESTART_REQUIRED));
    assert_eq!(ids(&ws), vec!["anthropic", "openai", "lm"]);

    // delete: openai goes; the head stays anthropic; keys are untouched by design.
    let env = post(
        &api,
        "/client/providers/openai:delete",
        Value::Null,
        "k-del-openai",
    );
    let deleted: ClientProviderDeleteResult = data(&env);
    assert_eq!(deleted.selected_provider_id.as_deref(), Some("anthropic"));
    assert_eq!(ids(&ws), vec!["anthropic", "lm"]);
    let env = post(&api, "/client/providers/lm:delete", Value::Null, "k-del-lm");
    assert!(env.is_ok(), "{env:?}");
    assert_eq!(ids(&ws), vec!["anthropic"]);
    // The last entry cannot be deleted.
    let env = post(
        &api,
        "/client/providers/anthropic:delete",
        Value::Null,
        "k-del-last",
    );
    assert_eq!(
        env.error_code(),
        Some(ClientErrorCode::InvalidState),
        "{env:?}"
    );
    assert_eq!(ids(&ws), vec!["anthropic"]);
    let env = post(
        &api,
        "/client/providers/openai:delete",
        Value::Null,
        "k-del-gone",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::NotFound));
}

// ── PV-02: key custody through the daemon's LIVE store with an injected preflight ────────────
#[tokio::test(flavor = "multi_thread")]
async fn pv02_key_custody_through_live_store() {
    let (_g, ws, cfg) = fresh_workspace();
    let (host, handles) = boot(&ws, &cfg).await;
    let api = handles.client_api_server.as_ref().unwrap().api();
    mint(&api, "tok", Scope::operator_default());
    let live_store = handles.secret_store.clone().expect("live store");

    // Mount an adapter whose ONLY difference from the wired one is the preflight seam.
    let preflight = ScriptedPreflight::passing();
    let adapter = Arc::new(
        WiredProviderAdmin::new(
            ws.clone(),
            host.config_watcher() as Arc<dyn RuntimeConfigProvider>,
            handles.secret_store.clone(),
            preflight.clone(),
            Arc::new(NoReferences),
        )
        .with_preflight_timeout(Duration::from_millis(300)),
    );
    install_provider_admin(&api, adapter);
    assert!(post(&api, "/client/providers", anthropic_body(), "k-create").is_ok());

    // set-key: the preflight saw the entry + key; the key lands ENCRYPTED in secrets.json and
    // the daemon's own store resolves it; no plaintext anywhere client-visible or on disk.
    let env = post(
        &api,
        "/client/providers/anthropic:set-key",
        json!({ "key": SECRET_KEY }),
        "k-set",
    );
    let result: ClientProviderKeyResult = data(&env);
    assert!(result.stored, "{env:?}");
    assert!(result.preflight.as_ref().unwrap().ok);
    assert_eq!(
        preflight.calls.lock().unwrap().as_slice(),
        &[("anthropic".to_string(), SECRET_KEY.to_string())]
    );
    assert!(!serde_json::to_string(&env).unwrap().contains(SECRET_KEY));
    let secrets_file = std::fs::read_to_string(ws.join(".advance/secrets.json")).unwrap();
    assert!(secrets_file.contains("anthropic-api-key"), "{secrets_file}");
    assert!(!secrets_file.contains(SECRET_KEY), "ciphertext only");
    assert_eq!(
        live_store
            .resolve("anthropic-api-key")
            .unwrap()
            .expose_secret(),
        SECRET_KEY,
        "the daemon's live store sees the key without a restart"
    );
    let one: ClientProviderSummary = data(&get(&api, "/client/providers/anthropic"));
    assert!(one.key.present);
    assert!(one.last_preflight.as_ref().unwrap().ok);
    assert!(!serde_json::to_string(&one).unwrap().contains(SECRET_KEY));

    // Replay: same key, same body → provider not re-entered (preflight call count unchanged).
    let replay = post(
        &api,
        "/client/providers/anthropic:set-key",
        json!({ "key": SECRET_KEY }),
        "k-set",
    );
    assert!(replay.is_ok());
    assert_eq!(preflight.calls.lock().unwrap().len(), 1);

    // A rejected preflight leaves the OLD key in place and answers stored=false as data.
    preflight.set_verdict(Err(PreflightFail::ProviderRejected {
        reason: "model-not-available".into(),
    }));
    let env = post(
        &api,
        "/client/providers/anthropic:set-key",
        json!({ "key": OTHER_KEY }),
        "k-set-bad",
    );
    let result: ClientProviderKeyResult = data(&env);
    assert!(!result.stored);
    assert_eq!(
        result.preflight.as_ref().unwrap().reason.as_deref(),
        Some("model-not-available")
    );
    assert_eq!(
        live_store
            .resolve("anthropic-api-key")
            .unwrap()
            .expose_secret(),
        SECRET_KEY
    );
    let secrets_file = std::fs::read_to_string(ws.join(".advance/secrets.json")).unwrap();
    assert!(!secrets_file.contains(OTHER_KEY));
    let one: ClientProviderSummary = data(&get(&api, "/client/providers/anthropic"));
    assert!(!one.last_preflight.as_ref().unwrap().ok, "verdict recorded");

    // A stalled preflight is cancelled at the deadline: reason `timeout`, old key intact.
    preflight.set_verdict(Ok(()));
    preflight.set_stall(true);
    let env = post(
        &api,
        "/client/providers/anthropic:set-key",
        json!({ "key": OTHER_KEY }),
        "k-set-slow",
    );
    let result: ClientProviderKeyResult = data(&env);
    assert!(!result.stored);
    assert_eq!(
        result.preflight.as_ref().unwrap().reason.as_deref(),
        Some("timeout")
    );
    assert_eq!(
        live_store
            .resolve("anthropic-api-key")
            .unwrap()
            .expose_secret(),
        SECRET_KEY
    );
    preflight.set_stall(false);

    // preflight re-checks the stored key (the port receives the STORED value, not a request).
    let calls_before = preflight.calls.lock().unwrap().len();
    let env = post(
        &api,
        "/client/providers/anthropic:preflight",
        Value::Null,
        "k-pf",
    );
    let verdict: ClientProviderPreflightResult = data(&env);
    assert!(verdict.ok);
    assert_eq!(
        preflight.calls.lock().unwrap()[calls_before],
        ("anthropic".to_string(), SECRET_KEY.to_string())
    );
    // openai has no key: a verdict, not an error.
    let env = post(
        &api,
        "/client/providers/openai:preflight",
        Value::Null,
        "k-pf-openai",
    );
    let verdict: ClientProviderPreflightResult = data(&env);
    assert!(!verdict.ok);
    assert_eq!(verdict.reason.as_deref(), Some("missing-key"));

    // clear-key: the daemon's store no longer resolves it; the file drops the name.
    let env = post(
        &api,
        "/client/providers/anthropic:clear-key",
        Value::Null,
        "k-clear",
    );
    let cleared: ClientProviderSummary = data(&env);
    assert!(!cleared.key.present);
    assert!(live_store.resolve("anthropic-api-key").is_err());
    let secrets_file = std::fs::read_to_string(ws.join(".advance/secrets.json")).unwrap();
    assert!(!secrets_file.contains("anthropic-api-key"));

    // A local-class entry stores without preflight (advisory attached), still through the
    // live store.
    let local = json!({
        "provider_id": "lm",
        "backend_class": "local",
        "model_aliases": { "tiny": "qwen2.5-0.5b" },
        "cost": { "input_per_mtoken": 0.01, "output_per_mtoken": 0.01 },
        "rate_limit": { "requests_per_minute": 100, "tokens_per_minute": 100000 }
    });
    assert!(post(&api, "/client/providers", local, "k-lm").is_ok());
    let calls_before = preflight.calls.lock().unwrap().len();
    let env = post(
        &api,
        "/client/providers/lm:set-key",
        json!({ "key": "local-token" }),
        "k-lm-key",
    );
    let result: ClientProviderKeyResult = data(&env);
    assert!(result.stored && result.preflight.is_none());
    assert!(has_warning(&env, WARNING_PREFLIGHT_SKIPPED));
    assert_eq!(preflight.calls.lock().unwrap().len(), calls_before);
    assert_eq!(
        live_store.resolve("lm-api-key").unwrap().expose_secret(),
        "local-token"
    );

    // Unknown provider → not_found before any preflight.
    let env = post(
        &api,
        "/client/providers/ghost:set-key",
        json!({ "key": "x" }),
        "k-ghost",
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::NotFound));
}

// ── PV-03: a referenced provider cannot be deleted (the cross-lane hook) ─────────────────────
#[tokio::test(flavor = "multi_thread")]
async fn pv03_referenced_provider_delete_is_refused() {
    let (_g, ws, cfg) = fresh_workspace();
    let (host, handles) = boot(&ws, &cfg).await;
    let api = handles.client_api_server.as_ref().unwrap().api();
    mint(&api, "tok", Scope::operator_default());
    let adapter = Arc::new(WiredProviderAdmin::new(
        ws.clone(),
        host.config_watcher() as Arc<dyn RuntimeConfigProvider>,
        handles.secret_store.clone(),
        ScriptedPreflight::passing(),
        Arc::new(PinnedBy(vec!["openai".into()])),
    ));
    install_provider_admin(&api, adapter);
    assert!(post(&api, "/client/providers", anthropic_body(), "k-create").is_ok());
    assert_eq!(ids(&ws), vec!["openai", "anthropic"]);

    let env = post(
        &api,
        "/client/providers/openai:delete",
        Value::Null,
        "k-del",
    );
    assert_eq!(
        env.error_code(),
        Some(ClientErrorCode::InvalidState),
        "{env:?}"
    );
    assert_eq!(ids(&ws), vec!["openai", "anthropic"], "document untouched");

    let env = post(
        &api,
        "/client/providers/anthropic:delete",
        Value::Null,
        "k-del-2",
    );
    assert!(env.is_ok(), "{env:?}");
    assert_eq!(ids(&ws), vec!["openai"]);
}

// ── PV-04: the PRODUCTION reference check — an agent's `llm.provider` pin blocks the delete ───
// (plan §4 step 2: the daemon composes `WorkspaceAgentLlmPolicy` as the `ProviderReferenceCheck`,
// walking the same root + tree the gateway's policy source reads; no injected double here).
#[tokio::test(flavor = "multi_thread")]
async fn pv04_agent_pin_blocks_delete_through_production_reference_check() {
    let (_g, ws, cfg) = fresh_workspace();
    let (_host, handles) = boot(&ws, &cfg).await;
    let api = handles
        .client_api_server
        .as_ref()
        .expect("EventBus up ⇒ Client API bound")
        .api();
    mint(&api, "tok", Scope::operator_default());

    // Two providers, so `last-provider` is not what refuses the delete.
    let created: ClientProviderSummary = data(&post(
        &api,
        "/client/providers",
        anthropic_body(),
        "k-pv04-create",
    ));
    assert_eq!(created.provider_id, "anthropic");
    assert_eq!(ids(&ws), vec!["openai", "anthropic"]);

    // Pin the root agent to `openai` through the agents family (Lane 2's surface).
    let env = post(
        &api,
        "/client/agents/default-agent:update",
        json!({ "llm": { "provider": "openai" } }),
        "k-pv04-pin",
    );
    assert!(env.is_ok(), "{env:?}");
    assert!(std::fs::read_to_string(ws.join(".agent/config.yaml"))
        .unwrap()
        .contains("provider: openai"));

    // The pinned provider cannot be deleted: invalid_state, document untouched.
    let env = post(
        &api,
        "/client/providers/openai:delete",
        Value::Null,
        "k-pv04-del-pinned",
    );
    assert_eq!(
        env.error_code(),
        Some(ClientErrorCode::InvalidState),
        "{env:?}"
    );
    assert_eq!(ids(&ws), vec!["openai", "anthropic"]);

    // The other provider is not pinned by anyone: its delete goes through.
    let env = post(
        &api,
        "/client/providers/anthropic:delete",
        Value::Null,
        "k-pv04-del-free",
    );
    let result: ClientProviderDeleteResult = data(&env);
    assert_eq!(result.provider_id, "anthropic");
    assert_eq!(result.selected_provider_id.as_deref(), Some("openai"));
    assert_eq!(ids(&ws), vec!["openai"]);

    // Clear the pin (`{}`), re-create the second provider, and the former pin target deletes.
    let env = post(
        &api,
        "/client/agents/default-agent:update",
        json!({ "llm": {} }),
        "k-pv04-unpin",
    );
    assert!(env.is_ok(), "{env:?}");
    let _: ClientProviderSummary = data(&post(
        &api,
        "/client/providers",
        anthropic_body(),
        "k-pv04-create-2",
    ));
    let env = post(
        &api,
        "/client/providers/openai:delete",
        Value::Null,
        "k-pv04-del-unpinned",
    );
    let result: ClientProviderDeleteResult = data(&env);
    assert_eq!(result.selected_provider_id.as_deref(), Some("anthropic"));
    assert_eq!(ids(&ws), vec!["anthropic"]);
}
