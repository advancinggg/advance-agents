//! Secrets family — secrets mode read / switch (`/client/secrets/mode`,
//! `/client/secrets:set-mode`)
//!
//! Drives the REAL `ClientApi::handle()` pipeline (admission, version, session, scope gate,
//! idempotency reserve/replay, handler-side validation, provider-error projection) against a
//! recording in-memory `SecretsAdminProvider`. The production adapter over the home's
//! `runtime-config.yaml` is `crates/cli/src/client_api_secrets.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::{EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS};
use advance_client_api::envelope::WARNING_RESTART_REQUIRED;
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::secrets_admin::{ClientSecretsMode, ClientSetSecretsModeRequest};
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    NoopSink, Platform, Principal, ProviderError, Scope, SecretsAdminProvider,
};

// ── Recording in-memory provider ─────────────────────────────────────────────────────────────

struct MemorySecrets {
    mode_calls: AtomicUsize,
    set_calls: AtomicUsize,
    state: Mutex<ClientSecretsMode>,
    last_request: Mutex<Option<ClientSetSecretsModeRequest>>,
    fail: Option<ProviderError>,
}

fn file_mode() -> ClientSecretsMode {
    ClientSecretsMode {
        mode: "file".into(),
        master_key_source: "keychain".into(),
        synchronizable: true,
        namespace: "default".into(),
        access_group: None,
        platform_supported: true,
    }
}

impl MemorySecrets {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mode_calls: AtomicUsize::new(0),
            set_calls: AtomicUsize::new(0),
            state: Mutex::new(file_mode()),
            last_request: Mutex::new(None),
            fail: None,
        })
    }
    fn failing(err: ProviderError) -> Arc<Self> {
        Arc::new(Self {
            mode_calls: AtomicUsize::new(0),
            set_calls: AtomicUsize::new(0),
            state: Mutex::new(file_mode()),
            last_request: Mutex::new(None),
            fail: Some(err),
        })
    }
    fn gate(&self) -> Result<(), ProviderError> {
        match &self.fail {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

impl SecretsAdminProvider for MemorySecrets {
    fn mode(&self) -> Result<ClientSecretsMode, ProviderError> {
        self.mode_calls.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        Ok(self.state.lock().unwrap().clone())
    }
    fn set_mode(
        &self,
        request: &ClientSetSecretsModeRequest,
    ) -> Result<ClientSecretsMode, ProviderError> {
        self.set_calls.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        *self.last_request.lock().unwrap() = Some(request.clone());
        let mut state = self.state.lock().unwrap();
        state.mode = request.mode.clone();
        state.master_key_source = if request.mode == "file" {
            "keychain".into()
        } else {
            "keychain-sync".into()
        };
        if let Some(sync) = request.synchronizable {
            state.synchronizable = sync;
        }
        if let Some(ns) = &request.namespace {
            state.namespace = ns.clone();
        }
        Ok(state.clone())
    }
}

// ── Harness ──────────────────────────────────────────────────────────────────────────────────

fn api_with(provider: Arc<dyn SecretsAdminProvider>) -> ClientApi {
    ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(NoopSink),
    )
    .with_secrets_provider(provider)
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

// ── SA-01: routes are always registered; an absent provider is module_unavailable ────────────
#[test]
fn sa01_absent_provider_is_module_unavailable_not_unknown_route() {
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(NoopSink),
    );
    operator(&api);
    let env = api.handle(get(routes::PATH_SECRETS_MODE));
    assert_eq!(code(&env), Some(ClientErrorCode::ModuleUnavailable));
    let env = api.handle(post(
        routes::PATH_SECRETS_SET_MODE,
        json!({ "mode": "file" }),
        "k-sa01",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::ModuleUnavailable));
    // `family_of` keys an exact `:verb` route by its first segment (`secrets:set-mode`, like the
    // packs family's `packs:install`); both routes stay under the `secrets` prefix.
    assert!(routes::family_of(routes::PATH_SECRETS_SET_MODE).starts_with("secrets"));
    assert_eq!(routes::family_of(routes::PATH_SECRETS_MODE), "secrets");
}

// ── SA-02: read requires ReadInventory ───────────────────────────────────────────────────────
#[test]
fn sa02_mode_read_scope_gate() {
    let provider = MemorySecrets::new();
    let api = api_with(provider.clone());
    operator(&api);
    mint(&api, "tok-noscope", vec![]);
    mint(&api, "tok-read", vec![Scope::ReadInventory]);

    let env = api.handle(get(routes::PATH_SECRETS_MODE));
    let mode: ClientSecretsMode = data(&env);
    assert_eq!(mode, file_mode());
    assert_eq!(provider.mode_calls.load(Ordering::SeqCst), 1);

    let env = api.handle(ClientRequest::get(routes::PATH_SECRETS_MODE).with_session("tok-read"));
    assert!(env.is_ok());

    let env = api.handle(ClientRequest::get(routes::PATH_SECRETS_MODE).with_session("tok-noscope"));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
    let env = api.handle(ClientRequest::get(routes::PATH_SECRETS_MODE));
    assert_eq!(code(&env), Some(ClientErrorCode::Unauthenticated));
    // A read-only session cannot switch the mode.
    let env = api.handle(
        ClientRequest::post(routes::PATH_SECRETS_SET_MODE, json!({ "mode": "file" }))
            .with_session("tok-read")
            .with_idempotency_key("k-sa02"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
    assert_eq!(provider.set_calls.load(Ordering::SeqCst), 0);
}

// ── SA-03: handler-side validation never reaches the provider ────────────────────────────────
#[test]
fn sa03_set_mode_validation_before_provider() {
    let provider = MemorySecrets::new();
    let api = api_with(provider.clone());
    operator(&api);
    let cases: Vec<(&str, Value)> = vec![
        ("bad-mode", json!({ "mode": "keychain" })),
        ("empty-mode", json!({ "mode": "" })),
        (
            "file-with-sync",
            json!({ "mode": "file", "synchronizable": false }),
        ),
        ("file-with-ns", json!({ "mode": "file", "namespace": "x" })),
        (
            "bad-ns",
            json!({ "mode": "keychain-sync", "namespace": "not valid" }),
        ),
        (
            "long-ns",
            json!({ "mode": "keychain-sync", "namespace": "n".repeat(65) }),
        ),
        ("unknown-field", json!({ "mode": "file", "extra": 1 })),
        ("wrong-type", json!({ "mode": 3 })),
        ("array-body", json!([])),
        ("null-body", Value::Null),
    ];
    for (name, body) in cases {
        let env = api.handle(post(routes::PATH_SECRETS_SET_MODE, body, name));
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::InvalidRequest),
            "{name}: {:?}",
            env.error
        );
    }
    assert_eq!(provider.set_calls.load(Ordering::SeqCst), 0);
    // A mutation without an idempotency key is refused before the handler.
    let env = api.handle(
        ClientRequest::post(routes::PATH_SECRETS_SET_MODE, json!({ "mode": "file" }))
            .with_session("tok"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyRequired));
}

// ── SA-04: a switch carries restart_required and replays exactly once ────────────────────────
#[test]
fn sa04_set_mode_switch_warns_and_replays() {
    let provider = MemorySecrets::new();
    let api = api_with(provider.clone());
    operator(&api);
    let body = json!({ "mode": "keychain-sync", "namespace": "work", "synchronizable": false });
    let env = api.handle(post(routes::PATH_SECRETS_SET_MODE, body.clone(), "k-sa04"));
    let mode: ClientSecretsMode = data(&env);
    assert_eq!(mode.mode, "keychain-sync");
    assert_eq!(mode.master_key_source, "keychain-sync");
    assert_eq!(mode.namespace, "work");
    assert!(!mode.synchronizable);
    assert!(
        env.warnings
            .iter()
            .any(|w| w.code == WARNING_RESTART_REQUIRED),
        "{:?}",
        env.warnings
    );
    assert_eq!(provider.set_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.last_request.lock().unwrap().clone().unwrap(),
        ClientSetSecretsModeRequest {
            mode: "keychain-sync".into(),
            synchronizable: Some(false),
            namespace: Some("work".into()),
        }
    );

    // Same key + same body → the recorded outcome, no second provider call.
    let replay = api.handle(post(routes::PATH_SECRETS_SET_MODE, body, "k-sa04"));
    assert!(replay.is_ok());
    assert_eq!(replay.data, env.data);
    assert_eq!(provider.set_calls.load(Ordering::SeqCst), 1);

    // Same key + different body → conflict.
    let conflict = api.handle(post(
        routes::PATH_SECRETS_SET_MODE,
        json!({ "mode": "file" }),
        "k-sa04",
    ));
    assert_eq!(code(&conflict), Some(ClientErrorCode::IdempotencyConflict));

    // Back to file.
    let env = api.handle(post(
        routes::PATH_SECRETS_SET_MODE,
        json!({ "mode": "file" }),
        "k-sa04-back",
    ));
    let mode: ClientSecretsMode = data(&env);
    assert_eq!(mode.mode, "file");
    assert_eq!(provider.set_calls.load(Ordering::SeqCst), 2);
}

// ── SA-05: provider-error projection ─────────────────────────────────────────────────────────
#[test]
fn sa05_provider_error_projection() {
    let cases = vec![
        (
            ProviderError::PlatformUnsupported("keychain-sync".into()),
            ClientErrorCode::InvalidRequest,
            vec!["platform_unsupported".to_string()],
        ),
        (
            ProviderError::InvalidRequest("rejected".into()),
            ClientErrorCode::InvalidRequest,
            vec![],
        ),
        (
            ProviderError::Unavailable("config".into()),
            ClientErrorCode::ModuleUnavailable,
            vec![],
        ),
    ];
    for (err, expected, details) in cases {
        let api = api_with(MemorySecrets::failing(err.clone()));
        operator(&api);
        let env = api.handle(post(
            routes::PATH_SECRETS_SET_MODE,
            json!({ "mode": "keychain-sync" }),
            "k-sa05",
        ));
        assert_eq!(code(&env), Some(expected.clone()), "{err:?}");
        let e = env.error.clone().unwrap();
        assert_eq!(e.details, details, "{err:?}");
        // The projected message is the fixed client-safe text, never the inner string.
        assert!(!e.message.contains("rejected"));
        assert!(!e.message.contains("keychain-sync"));
        let env = api.handle(get(routes::PATH_SECRETS_MODE));
        assert_eq!(code(&env), Some(expected), "{err:?} on read");
    }
}

// ── SA-06: schema components + compat partition ──────────────────────────────────────────────
#[test]
fn sa06_dtos_are_schema_components_and_partitioned() {
    let art = generate_schema_artifact();
    let components = art.schema["components"].as_object().expect("components");
    assert!(components.contains_key("ClientSecretsMode"));
    assert!(components.contains_key("ClientSetSecretsModeRequest"));
    assert!(RESPONSE_COMPONENTS.contains(&"ClientSecretsMode"));
    assert!(EXCLUDED_COMPONENTS.contains(&"ClientSetSecretsModeRequest"));
    assert!(!RESPONSE_COMPONENTS.contains(&"ClientSetSecretsModeRequest"));
    // The response DTO round-trips through its schema-declared shape.
    let mode = file_mode();
    let value = serde_json::to_value(&mode).unwrap();
    assert_eq!(value["mode"], "file");
    assert!(
        value.get("access_group").is_none(),
        "absent optional is omitted"
    );
    let back: ClientSecretsMode = serde_json::from_value(value).unwrap();
    assert_eq!(back, mode);
}
