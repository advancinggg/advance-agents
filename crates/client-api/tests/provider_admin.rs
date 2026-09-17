//! CONTRACT-190 providers family — `/client/providers` list / create / get / update / delete /
//! set-key / clear-key / preflight / select over the REAL `ClientApi::handle()` pipeline
//! (admission, version, session, scope gate, idempotency reserve/replay, handler-side
//! validation, provider-error projection, warning attachment) against a recording in-memory
//! `ProviderAdminProvider`. The production adapter over the workspace's `runtime-config.yaml`
//! and the daemon's live secret store is `crates/cli/src/client_api_providers.rs`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::{EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS};
use advance_client_api::envelope::{
    WARNING_PREFLIGHT_SKIPPED, WARNING_RELOAD_PENDING, WARNING_RESTART_REQUIRED,
};
use advance_client_api::provider_admin::{
    ClientCreateProviderRequest, ClientProviderCost, ClientProviderDeleteResult, ClientProviderKey,
    ClientProviderKeyResult, ClientProviderList, ClientProviderPreflightResult,
    ClientProviderRateLimit, ClientProviderSummary, ClientUpdateProviderRequest,
    ProviderAdminOutcome, ProviderAdminWarning, MAX_KEY_BYTES,
};
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    Platform, Principal, ProviderAdminProvider, ProviderError, Scope,
};

const SECRET_KEY: &str = "sk-live-ULTRA-SECRET-0123456789";

// ── Recording in-memory provider ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Calls {
    list: AtomicUsize,
    get: AtomicUsize,
    create: AtomicUsize,
    update: AtomicUsize,
    delete: AtomicUsize,
    set_key: AtomicUsize,
    clear_key: AtomicUsize,
    preflight: AtomicUsize,
    select: AtomicUsize,
}

struct MemoryProviders {
    calls: Calls,
    entries: Mutex<Vec<ClientProviderSummary>>,
    keys: Mutex<BTreeMap<String, String>>,
    /// The verdict `set_key` / `preflight` report (`None` = pass).
    preflight_reason: Mutex<Option<String>>,
    fail: Option<ProviderError>,
}

fn summary(id: &str, selected: bool) -> ClientProviderSummary {
    ClientProviderSummary {
        provider_id: id.into(),
        backend_class: "cloud-http".into(),
        backend: None,
        endpoint: format!("https://api.{id}.example"),
        model_aliases: [("fast".to_string(), format!("{id}-fast"))]
            .into_iter()
            .collect(),
        embedding_model: None,
        auth_scheme: None,
        cost: ClientProviderCost {
            input_per_mtoken: 1.0,
            output_per_mtoken: 2.0,
            ..Default::default()
        },
        rate_limit: Some(ClientProviderRateLimit {
            requests_per_minute: 10,
            tokens_per_minute: 1000,
        }),
        retry_default: None,
        profile_id: None,
        device_id: None,
        sidecar_present: false,
        key: ClientProviderKey {
            secret_name: format!("{id}-api-key"),
            present: false,
        },
        selected,
        last_preflight: None,
    }
}

impl MemoryProviders {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            entries: Mutex::new(vec![summary("openai", true), summary("anthropic", false)]),
            keys: Mutex::new(BTreeMap::new()),
            preflight_reason: Mutex::new(None),
            fail: None,
        })
    }
    fn failing(err: ProviderError) -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            entries: Mutex::new(vec![]),
            keys: Mutex::new(BTreeMap::new()),
            preflight_reason: Mutex::new(None),
            fail: Some(err),
        })
    }
    fn gate(&self) -> Result<(), ProviderError> {
        match &self.fail {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    fn refresh(&self) {
        let keys = self.keys.lock().unwrap();
        let mut entries = self.entries.lock().unwrap();
        for (idx, e) in entries.iter_mut().enumerate() {
            e.selected = idx == 0;
            e.key.present = keys.contains_key(&e.key.secret_name);
        }
    }
    fn find(&self, id: &str) -> Result<ClientProviderSummary, ProviderError> {
        self.refresh();
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.provider_id == id)
            .cloned()
            .ok_or_else(|| ProviderError::NotFound(id.into()))
    }
}

impl ProviderAdminProvider for MemoryProviders {
    fn list_providers(&self) -> Result<Vec<ClientProviderSummary>, ProviderError> {
        self.calls.list.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        self.refresh();
        Ok(self.entries.lock().unwrap().clone())
    }
    fn get_provider(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        self.calls.get.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        self.find(provider_id)
    }
    fn create_provider(
        &self,
        request: &ClientCreateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        self.calls.create.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        if self.find(&request.provider_id).is_ok() {
            return Err(ProviderError::AlreadyExists(request.provider_id.clone()));
        }
        let mut s = summary(&request.provider_id, false);
        s.backend_class = request
            .backend_class
            .clone()
            .unwrap_or_else(|| "cloud-http".into());
        s.endpoint = request.endpoint.clone().unwrap_or_default();
        s.model_aliases = request.model_aliases.clone();
        s.sidecar_present = request.sidecar.is_some();
        self.entries.lock().unwrap().push(s.clone());
        let mut outcome = ProviderAdminOutcome::new(s.clone());
        if s.sidecar_present {
            outcome = outcome.with_warning(ProviderAdminWarning::RestartRequired);
        }
        Ok(outcome.with_warning(ProviderAdminWarning::ReloadPending))
    }
    fn update_provider(
        &self,
        provider_id: &str,
        request: &ClientUpdateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        self.calls.update.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let mut entries = self.entries.lock().unwrap();
        let e = entries
            .iter_mut()
            .find(|e| e.provider_id == provider_id)
            .ok_or_else(|| ProviderError::NotFound(provider_id.into()))?;
        if let Some(endpoint) = &request.endpoint {
            e.endpoint = endpoint.clone();
        }
        Ok(ProviderAdminOutcome::new(e.clone()))
    }
    fn delete_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderDeleteResult>, ProviderError> {
        self.calls.delete.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let mut entries = self.entries.lock().unwrap();
        let idx = entries
            .iter()
            .position(|e| e.provider_id == provider_id)
            .ok_or_else(|| ProviderError::NotFound(provider_id.into()))?;
        if entries.len() == 1 {
            return Err(ProviderError::InvalidState("last-provider".into()));
        }
        entries.remove(idx);
        Ok(ProviderAdminOutcome::new(ClientProviderDeleteResult {
            provider_id: provider_id.into(),
            selected_provider_id: entries.first().map(|e| e.provider_id.clone()),
        }))
    }
    fn set_key(
        &self,
        provider_id: &str,
        key: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderKeyResult>, ProviderError> {
        self.calls.set_key.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let entry = self.find(provider_id)?;
        if entry.backend_class != "cloud-http" {
            self.keys
                .lock()
                .unwrap()
                .insert(entry.key.secret_name, key.to_string());
            return Ok(ProviderAdminOutcome::new(ClientProviderKeyResult {
                stored: true,
                preflight: None,
            })
            .with_warning(ProviderAdminWarning::PreflightSkipped));
        }
        // ONE guard: locking the same std Mutex twice inside a single struct-literal
        // statement self-deadlocks (the first temporary guard lives to the end of the
        // statement) — this is what stalled pa05/pa06 for hours.
        let reason = self.preflight_reason.lock().unwrap().clone();
        let verdict = ClientProviderPreflightResult {
            ok: reason.is_none(),
            checked_at_ms: 1_700_000_000_000,
            reason,
        };
        if verdict.ok {
            self.keys
                .lock()
                .unwrap()
                .insert(entry.key.secret_name, key.to_string());
        }
        Ok(ProviderAdminOutcome::new(ClientProviderKeyResult {
            stored: verdict.ok,
            preflight: Some(verdict),
        }))
    }
    fn clear_key(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        self.calls.clear_key.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let entry = self.find(provider_id)?;
        self.keys.lock().unwrap().remove(&entry.key.secret_name);
        self.find(provider_id)
    }
    fn preflight(&self, provider_id: &str) -> Result<ClientProviderPreflightResult, ProviderError> {
        self.calls.preflight.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let entry = self.find(provider_id)?;
        if !self
            .keys
            .lock()
            .unwrap()
            .contains_key(&entry.key.secret_name)
        {
            return Ok(ClientProviderPreflightResult {
                ok: false,
                checked_at_ms: 1_700_000_000_001,
                reason: Some("missing-key".into()),
            });
        }
        Ok(ClientProviderPreflightResult {
            ok: true,
            checked_at_ms: 1_700_000_000_002,
            reason: None,
        })
    }
    fn select_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        self.calls.select.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let mut entries = self.entries.lock().unwrap();
        let idx = entries
            .iter()
            .position(|e| e.provider_id == provider_id)
            .ok_or_else(|| ProviderError::NotFound(provider_id.into()))?;
        let e = entries.remove(idx);
        entries.insert(0, e);
        drop(entries);
        Ok(ProviderAdminOutcome::new(self.find(provider_id)?))
    }
}

// ── Harness ──────────────────────────────────────────────────────────────────────────────────

fn api_with_config(
    provider: Arc<dyn ProviderAdminProvider>,
    config: ClientApiConfig,
) -> (ClientApi, RecordingSink) {
    let sink = RecordingSink::new();
    let api = ClientApi::with_parts(
        config,
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink.clone()),
    )
    .with_provider_admin(provider);
    (api, sink)
}

fn api_with(provider: Arc<dyn ProviderAdminProvider>) -> (ClientApi, RecordingSink) {
    api_with_config(provider, ClientApiConfig::default())
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

fn operator(api: &ClientApi) {
    mint(api, "tok", Scope::operator_default());
}

fn get(path: &str) -> ClientRequest {
    ClientRequest::get(path).with_session("tok")
}

fn post(path: &str, body: Value, key: &str) -> ClientRequest {
    ClientRequest::post(path, body)
        .with_session("tok")
        .with_idempotency_key(key)
}

fn code(env: &ClientEnvelope<Value>) -> Option<ClientErrorCode> {
    env.error_code()
}

fn data<T: serde::de::DeserializeOwned>(env: &ClientEnvelope<Value>) -> T {
    assert!(env.is_ok(), "expected ok envelope, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("payload parses")
}

fn has_warning(env: &ClientEnvelope<Value>, code: &str) -> bool {
    env.warnings.iter().any(|w| w.code == code)
}

fn create_body(id: &str) -> Value {
    json!({
        "provider_id": id,
        "endpoint": format!("https://api.{id}.example"),
        "model_aliases": { "fast": format!("{id}-fast") },
        "cost": { "input_per_mtoken": 1.0, "output_per_mtoken": 2.0 },
        "rate_limit": { "requests_per_minute": 10, "tokens_per_minute": 1000 }
    })
}

// ── PA-01: routes are always registered; an absent provider is module_unavailable ────────────
#[test]
fn pa01_absent_provider_is_module_unavailable_not_unknown_route() {
    let api = ClientApi::new(ClientApiConfig::default());
    operator(&api);
    for req in [
        get(routes::PATH_PROVIDERS),
        get("/client/providers/openai"),
        post(routes::PATH_PROVIDERS, create_body("x"), "k1"),
        post(
            "/client/providers/openai:update",
            json!({ "endpoint": "https://p.example" }),
            "k2",
        ),
        post("/client/providers/openai:delete", Value::Null, "k3"),
        post(
            "/client/providers/openai:set-key",
            json!({ "key": SECRET_KEY }),
            "k4",
        ),
        post("/client/providers/openai:clear-key", Value::Null, "k5"),
        post("/client/providers/openai:preflight", Value::Null, "k6"),
        post("/client/providers/openai:select", Value::Null, "k7"),
    ] {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{env:?}"
        );
    }
}

// ── PA-02: list + get project the provider's rows; ids are validated before the provider ─────
#[test]
fn pa02_list_and_get() {
    let provider = MemoryProviders::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let list: ClientProviderList = data(&api.handle(get(routes::PATH_PROVIDERS)));
    assert_eq!(list.providers.len(), 2);
    assert!(list.providers[0].selected);
    assert!(!list.providers[1].selected);
    assert_eq!(list.providers[0].key.secret_name, "openai-api-key");
    assert!(!list.providers[0].key.present);
    assert_eq!(provider.calls.list.load(Ordering::SeqCst), 1);

    let one: ClientProviderSummary = data(&api.handle(get("/client/providers/anthropic")));
    assert_eq!(one.provider_id, "anthropic");
    assert!(!one.selected);

    let env = api.handle(get("/client/providers/ghost"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));

    let gets = provider.calls.get.load(Ordering::SeqCst);
    for bad in ["/client/providers/bad%20id", "/client/providers/a.b"] {
        let env = api.handle(get(bad));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{bad}");
    }
    assert_eq!(provider.calls.get.load(Ordering::SeqCst), gets);
}

// ── PA-03: create runs the full mutation pipeline, replays idempotently, carries warnings ─────
#[test]
fn pa03_create_pipeline_replay_and_warnings() {
    let provider = MemoryProviders::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let env = api.handle(post(routes::PATH_PROVIDERS, create_body("mistral"), "k1"));
    let created: ClientProviderSummary = data(&env);
    assert_eq!(created.provider_id, "mistral");
    assert!(!created.selected);
    assert!(has_warning(&env, WARNING_RELOAD_PENDING));
    assert!(!has_warning(&env, WARNING_RESTART_REQUIRED));
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 1);

    // Same key + same body → replay, provider NOT re-entered.
    let replay = api.handle(post(routes::PATH_PROVIDERS, create_body("mistral"), "k1"));
    assert!(replay.is_ok());
    assert!(has_warning(&replay, "idempotent_replay"));
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 1);

    // Same key + different body → conflict.
    let env = api.handle(post(routes::PATH_PROVIDERS, create_body("other"), "k1"));
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyConflict));

    // Duplicate id → already_exists (projected from the provider).
    let env = api.handle(post(
        routes::PATH_PROVIDERS,
        create_body("mistral"),
        "k-dup",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::AlreadyExists));

    // A sidecar-backed local entry carries restart_required.
    let local = json!({
        "provider_id": "lm",
        "backend_class": "local",
        "model_aliases": { "tiny": "qwen-0.5b" },
        "cost": { "input_per_mtoken": 0.01, "output_per_mtoken": 0.01 },
        "rate_limit": { "requests_per_minute": 10, "tokens_per_minute": 1000 },
        "sidecar": { "command": "/usr/bin/true", "args": ["--serve"] }
    });
    let env = api.handle(post(routes::PATH_PROVIDERS, local, "k-local"));
    let lm: ClientProviderSummary = data(&env);
    assert!(lm.sidecar_present);
    assert!(has_warning(&env, WARNING_RESTART_REQUIRED));

    // Validation failures never reach the provider.
    let creates = provider.calls.create.load(Ordering::SeqCst);
    let mut no_aliases = create_body("v1");
    no_aliases["model_aliases"] = json!({});
    let mut no_endpoint = create_body("v2");
    no_endpoint.as_object_mut().unwrap().remove("endpoint");
    let mut bad_scheme = create_body("v3");
    bad_scheme["auth_scheme"] = json!("basic");
    let mut no_rate = create_body("v4");
    no_rate.as_object_mut().unwrap().remove("rate_limit");
    let mut extra = create_body("v5");
    extra["unknown"] = json!(1);
    let mut ctl = create_body("v6");
    ctl["endpoint"] = json!("https://x.example\n");
    for (bad, why) in [
        (create_body("bad id"), "bad id"),
        (no_aliases, "empty aliases"),
        (no_endpoint, "cloud-http without endpoint"),
        (bad_scheme, "bad auth scheme"),
        (no_rate, "missing rate limit"),
        (extra, "unknown field"),
        (ctl, "control char in endpoint"),
        (json!([]), "non-object body"),
    ] {
        let env = api.handle(post(routes::PATH_PROVIDERS, bad, &format!("k-{why}")));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{why}");
    }
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), creates);

    // A missing idempotency key is refused before the provider.
    let env = api
        .handle(ClientRequest::post(routes::PATH_PROVIDERS, create_body("v7")).with_session("tok"));
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyRequired));
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), creates);
}

// ── PA-04: update / delete / select ──────────────────────────────────────────────────────────
#[test]
fn pa04_update_delete_select() {
    let provider = MemoryProviders::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let env = api.handle(post(
        "/client/providers/anthropic:update",
        json!({ "endpoint": "https://proxy.example" }),
        "u1",
    ));
    let updated: ClientProviderSummary = data(&env);
    assert_eq!(updated.endpoint, "https://proxy.example");

    // Empty update / unknown field / bad enum → invalid_request before the provider.
    let updates = provider.calls.update.load(Ordering::SeqCst);
    for (bad, why) in [
        (json!({}), "empty"),
        (
            json!({ "provider_id": "x" }),
            "immutable id as unknown field",
        ),
        (json!({ "backend_class": "quantum" }), "bad class"),
        (json!({ "model_aliases": {} }), "empty aliases"),
    ] {
        let env = api.handle(post(
            "/client/providers/anthropic:update",
            bad,
            &format!("u-{why}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{why}");
    }
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), updates);

    let env = api.handle(post(
        "/client/providers/ghost:update",
        json!({ "endpoint": "https://p" }),
        "u9",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));

    // select moves anthropic to index 0.
    let env = api.handle(post(
        "/client/providers/anthropic:select",
        Value::Null,
        "s1",
    ));
    let selected: ClientProviderSummary = data(&env);
    assert!(selected.selected);
    let list: ClientProviderList = data(&api.handle(get(routes::PATH_PROVIDERS)));
    assert_eq!(list.providers[0].provider_id, "anthropic");
    assert!(!list.providers[1].selected);

    // delete openai → anthropic remains selected; deleting the last one is invalid_state.
    let env = api.handle(post("/client/providers/openai:delete", Value::Null, "d1"));
    let deleted: ClientProviderDeleteResult = data(&env);
    assert_eq!(deleted.provider_id, "openai");
    assert_eq!(deleted.selected_provider_id.as_deref(), Some("anthropic"));
    let env = api.handle(post(
        "/client/providers/anthropic:delete",
        Value::Null,
        "d2",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidState));
    let env = api.handle(post("/client/providers/openai:delete", Value::Null, "d3"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));
}

// ── PA-05: set-key / clear-key / preflight — key never echoed, verdict is data ────────────────
#[test]
fn pa05_key_lifecycle_never_echoes_the_key() {
    let provider = MemoryProviders::new();
    let (api, sink) = api_with(provider.clone());
    operator(&api);

    // A passing preflight stores the key; the response carries the verdict, never the key.
    let env = api.handle(post(
        "/client/providers/openai:set-key",
        json!({ "key": SECRET_KEY }),
        "sk1",
    ));
    let result: ClientProviderKeyResult = data(&env);
    assert!(result.stored);
    assert!(result.preflight.as_ref().unwrap().ok);
    assert!(!serde_json::to_string(&env).unwrap().contains(SECRET_KEY));
    let one: ClientProviderSummary = data(&api.handle(get("/client/providers/openai")));
    assert!(one.key.present);
    assert!(!serde_json::to_string(&one).unwrap().contains(SECRET_KEY));

    // Replay under the same key returns the same outcome without re-entering the provider.
    let replay = api.handle(post(
        "/client/providers/openai:set-key",
        json!({ "key": SECRET_KEY }),
        "sk1",
    ));
    assert!(replay.is_ok());
    assert!(has_warning(&replay, "idempotent_replay"));
    assert_eq!(provider.calls.set_key.load(Ordering::SeqCst), 1);
    assert!(!serde_json::to_string(&replay).unwrap().contains(SECRET_KEY));

    // Audit records carry route family + method only — never the body.
    let audit_dump = format!("{:?}", sink.events());
    assert!(
        !audit_dump.contains(SECRET_KEY),
        "audit must not carry key bytes"
    );

    // A failing preflight leaves the previous key untouched and answers stored=false as DATA.
    *provider.preflight_reason.lock().unwrap() = Some("model-not-available".into());
    let env = api.handle(post(
        "/client/providers/openai:set-key",
        json!({ "key": "sk-other-key" }),
        "sk2",
    ));
    let result: ClientProviderKeyResult = data(&env);
    assert!(!result.stored);
    assert_eq!(
        result.preflight.as_ref().unwrap().reason.as_deref(),
        Some("model-not-available")
    );
    assert_eq!(
        provider
            .keys
            .lock()
            .unwrap()
            .get("openai-api-key")
            .map(String::as_str),
        Some(SECRET_KEY),
        "old key survives a failed preflight"
    );
    *provider.preflight_reason.lock().unwrap() = None;

    // preflight re-checks a stored key; a missing key is a verdict, not an error.
    let env = api.handle(post(
        "/client/providers/openai:preflight",
        Value::Null,
        "pf1",
    ));
    let verdict: ClientProviderPreflightResult = data(&env);
    assert!(verdict.ok);
    let env = api.handle(post(
        "/client/providers/anthropic:preflight",
        Value::Null,
        "pf2",
    ));
    let verdict: ClientProviderPreflightResult = data(&env);
    assert!(!verdict.ok);
    assert_eq!(verdict.reason.as_deref(), Some("missing-key"));

    // clear-key drops it.
    let env = api.handle(post(
        "/client/providers/openai:clear-key",
        Value::Null,
        "ck1",
    ));
    let cleared: ClientProviderSummary = data(&env);
    assert!(!cleared.key.present);
    assert!(provider.keys.lock().unwrap().is_empty());

    // Key validation happens before the provider: empty / control chars / over the bound /
    // missing field / non-object body.
    let sets = provider.calls.set_key.load(Ordering::SeqCst);
    for (bad, why) in [
        (json!({ "key": "   " }), "blank"),
        (json!({ "key": "sk\n" }), "control char"),
        (
            json!({ "key": "k".repeat(MAX_KEY_BYTES + 1) }),
            "over bound",
        ),
        (json!({}), "missing key field"),
        (json!({ "key": "x", "extra": 1 }), "unknown field"),
        (json!("sk-raw"), "non-object body"),
    ] {
        let env = api.handle(post(
            "/client/providers/openai:set-key",
            bad,
            &format!("sk-{why}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{why}");
    }
    assert_eq!(provider.calls.set_key.load(Ordering::SeqCst), sets);

    // A non-cloud-http entry stores without preflight and says so.
    let local = json!({
        "provider_id": "lm",
        "backend_class": "local",
        "model_aliases": { "tiny": "qwen-0.5b" },
        "cost": { "input_per_mtoken": 0.01, "output_per_mtoken": 0.01 },
        "rate_limit": { "requests_per_minute": 10, "tokens_per_minute": 1000 }
    });
    assert!(api
        .handle(post(routes::PATH_PROVIDERS, local, "k-lm"))
        .is_ok());
    let env = api.handle(post(
        "/client/providers/lm:set-key",
        json!({ "key": "local-token" }),
        "sk-lm",
    ));
    let result: ClientProviderKeyResult = data(&env);
    assert!(result.stored);
    assert!(result.preflight.is_none());
    assert!(has_warning(&env, WARNING_PREFLIGHT_SKIPPED));
}

// ── PA-06: set-key is loopback-only (a remote peer past admission is still refused) ──────────
#[test]
fn pa06_set_key_refuses_non_loopback_peer() {
    let provider = MemoryProviders::new();
    let config = ClientApiConfig {
        remote_bind_enabled: true,
        ..ClientApiConfig::default()
    };
    let (api, _sink) = api_with_config(provider.clone(), config);
    operator(&api);

    let env = api.handle(
        post(
            "/client/providers/openai:set-key",
            json!({ "key": SECRET_KEY }),
            "rk1",
        )
        .with_loopback_peer(false),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{env:?}");
    assert_eq!(provider.calls.set_key.load(Ordering::SeqCst), 0);
    assert!(!serde_json::to_string(&env).unwrap().contains(SECRET_KEY));

    // Reads and non-key mutations from the same remote peer are fine.
    let env = api.handle(get(routes::PATH_PROVIDERS).with_loopback_peer(false));
    assert!(env.is_ok(), "{env:?}");
    let env = api.handle(
        post("/client/providers/anthropic:select", Value::Null, "rs1").with_loopback_peer(false),
    );
    assert!(env.is_ok(), "{env:?}");

    // The loopback peer is accepted.
    let env = api.handle(post(
        "/client/providers/openai:set-key",
        json!({ "key": SECRET_KEY }),
        "rk2",
    ));
    assert!(env.is_ok(), "{env:?}");
}

// ── PA-07: scope gate — reads need ReadInventory, mutations need ApproveGrants ────────────────
#[test]
fn pa07_scope_gate() {
    let provider = MemoryProviders::new();
    let (api, _sink) = api_with(provider.clone());
    mint(&api, "tok", vec![Scope::ReadInventory]);

    assert!(api.handle(get(routes::PATH_PROVIDERS)).is_ok());
    assert!(api.handle(get("/client/providers/openai")).is_ok());
    for req in [
        post(routes::PATH_PROVIDERS, create_body("x"), "k1"),
        post(
            "/client/providers/openai:update",
            json!({ "endpoint": "https://p.example" }),
            "k2",
        ),
        post("/client/providers/openai:delete", Value::Null, "k3"),
        post(
            "/client/providers/openai:set-key",
            json!({ "key": SECRET_KEY }),
            "k4",
        ),
        post("/client/providers/openai:clear-key", Value::Null, "k5"),
        post("/client/providers/openai:preflight", Value::Null, "k6"),
        post("/client/providers/openai:select", Value::Null, "k7"),
    ] {
        let env = api.handle(req);
        assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{env:?}");
    }
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.set_key.load(Ordering::SeqCst), 0);

    mint(&api, "ro", vec![Scope::ReadRuns, Scope::ControlRuns]);
    let env = api.handle(ClientRequest::get(routes::PATH_PROVIDERS).with_session("ro"));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));

    mint(&api, "admin", vec![Scope::ApproveGrants]);
    let env = api.handle(
        ClientRequest::post("/client/providers/anthropic:select", Value::Null)
            .with_session("admin")
            .with_idempotency_key("a1"),
    );
    assert!(env.is_ok(), "{env:?}");
}

// ── PA-08: every ProviderError variant projects to its fixed client code ─────────────────────
#[test]
fn pa08_provider_error_projection() {
    for (err, expected) in [
        (
            ProviderError::NotFound("x".into()),
            ClientErrorCode::NotFound,
        ),
        (
            ProviderError::AlreadyExists("x".into()),
            ClientErrorCode::AlreadyExists,
        ),
        (
            ProviderError::InvalidState("last".into()),
            ClientErrorCode::InvalidState,
        ),
        (
            ProviderError::InvalidRequest("load_config".into()),
            ClientErrorCode::InvalidRequest,
        ),
        (
            ProviderError::Forbidden("no".into()),
            ClientErrorCode::Forbidden,
        ),
        (
            ProviderError::Unavailable("io".into()),
            ClientErrorCode::ModuleUnavailable,
        ),
    ] {
        let (api, _sink) = api_with(MemoryProviders::failing(err.clone()));
        operator(&api);
        let env = api.handle(post(routes::PATH_PROVIDERS, create_body("p"), "k"));
        assert_eq!(code(&env), Some(expected.clone()), "{err:?} → {env:?}");
        let env = api.handle(get(routes::PATH_PROVIDERS));
        assert_eq!(code(&env), Some(expected), "{err:?} → {env:?}");
        // The provider's inner string never reaches the client.
        let text = serde_json::to_string(&env).unwrap();
        assert!(
            !text.contains("load_config") && !text.contains("last"),
            "{text}"
        );
    }
}

// ── PA-09: DTOs are inventoried in the CONTRACT-192 schema + compat gate ─────────────────────
#[test]
fn pa09_schema_components_inventoried() {
    let art = generate_schema_artifact();
    let components = art.schema["components"]
        .as_object()
        .expect("components object");
    for r in [
        "ClientProviderCost",
        "ClientProviderRateLimit",
        "ClientProviderRetry",
        "ClientProviderKey",
        "ClientProviderPreflightResult",
        "ClientProviderSummary",
        "ClientProviderList",
        "ClientProviderKeyResult",
        "ClientProviderDeleteResult",
    ] {
        assert!(components.contains_key(r), "{r} in schema");
        assert!(RESPONSE_COMPONENTS.contains(&r), "{r} inventoried");
    }
    for r in [
        "ClientProviderSidecar",
        "ClientCreateProviderRequest",
        "ClientUpdateProviderRequest",
        "ClientSetProviderKeyRequest",
    ] {
        assert!(components.contains_key(r), "{r} in schema");
        assert!(EXCLUDED_COMPONENTS.contains(&r), "{r} excluded");
    }
    let response: std::collections::BTreeSet<&str> = RESPONSE_COMPONENTS.iter().copied().collect();
    let excluded: std::collections::BTreeSet<&str> = EXCLUDED_COMPONENTS.iter().copied().collect();
    assert!(response.is_disjoint(&excluded));
    assert_eq!(response.len() + excluded.len(), components.len());
}
