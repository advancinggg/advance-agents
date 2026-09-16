//! CONTRACT-190 packs family — installed packs / install / uninstall
//! (`/client/packs`, `/client/packs/{pack_id}`, `/client/packs:install`,
//! `/client/packs/{pack_id}:uninstall`).
//!
//! Drives the REAL `ClientApi::handle()` pipeline (admission, version, session, scope gate,
//! idempotency reserve/replay, handler-side validation, provider-error projection) against a
//! recording in-memory `PackAdminProvider`. The production adapter over the real pack registry +
//! installer is `crates/cli/src/client_api_packs.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::{EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS};
use advance_client_api::packs::{
    ClientPackDetail, ClientPackInstallRequest, ClientPackInstallResult, ClientPackList,
    ClientPackProvide, ClientPackSummary, ClientPackUninstallResult,
};
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    PackAdminProvider, Platform, Principal, ProviderError, Scope,
};

// ── Recording in-memory provider ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Calls {
    list: AtomicUsize,
    get: AtomicUsize,
    install: AtomicUsize,
    uninstall: AtomicUsize,
}

struct MemoryPacks {
    calls: Calls,
    installed: Mutex<Vec<ClientPackSummary>>,
    last_install: Mutex<Option<ClientPackInstallRequest>>,
    fail: Option<ProviderError>,
}

fn summary(name: &str, version: &str, required: &[&str]) -> ClientPackSummary {
    ClientPackSummary {
        name: name.into(),
        version: version.into(),
        trust_level: "untrusted".into(),
        signed_by: None,
        required_capabilities: required.iter().map(|s| s.to_string()).collect(),
    }
}

impl MemoryPacks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            installed: Mutex::new(vec![
                summary("foo", "1.0.0", &[]),
                summary("bar", "2.1.0", &["fs", "llm"]),
            ]),
            last_install: Mutex::new(None),
            fail: None,
        })
    }
    fn failing(err: ProviderError) -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            installed: Mutex::new(vec![]),
            last_install: Mutex::new(None),
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

impl PackAdminProvider for MemoryPacks {
    fn list_packs(&self) -> Result<Vec<ClientPackSummary>, ProviderError> {
        self.calls.list.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        Ok(self.installed.lock().unwrap().clone())
    }
    fn get_pack(&self, name: &str, version: &str) -> Result<ClientPackDetail, ProviderError> {
        self.calls.get.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let summary = self
            .installed
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.name == name && p.version == version)
            .cloned()
            .ok_or_else(|| ProviderError::NotFound(format!("{name}@{version}")))?;
        Ok(ClientPackDetail {
            summary,
            provides: vec![ClientPackProvide {
                kind: "agent-templates".into(),
                name: "researcher".into(),
            }],
        })
    }
    fn install_pack(
        &self,
        request: &ClientPackInstallRequest,
    ) -> Result<ClientPackInstallResult, ProviderError> {
        self.calls.install.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        *self.last_install.lock().unwrap() = Some(request.clone());
        self.installed
            .lock()
            .unwrap()
            .push(summary("new", "0.1.0", &[]));
        Ok(ClientPackInstallResult {
            name: "new".into(),
            version: "0.1.0".into(),
            install_path: "new@0.1.0".into(),
        })
    }
    fn uninstall_pack(
        &self,
        name: &str,
        version: &str,
    ) -> Result<ClientPackUninstallResult, ProviderError> {
        self.calls.uninstall.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let mut installed = self.installed.lock().unwrap();
        let before = installed.len();
        installed.retain(|p| !(p.name == name && p.version == version));
        if installed.len() == before {
            return Err(ProviderError::NotFound(format!("{name}@{version}")));
        }
        Ok(ClientPackUninstallResult {
            name: name.into(),
            version: version.into(),
        })
    }
}

// ── Harness ──────────────────────────────────────────────────────────────────────────────────

fn api_with(provider: Arc<dyn PackAdminProvider>) -> (ClientApi, RecordingSink) {
    let sink = RecordingSink::new();
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink.clone()),
    )
    .with_pack_provider(provider);
    (api, sink)
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

// ── PK-01: routes are always registered; an absent provider is module_unavailable ────────────
#[test]
fn pk01_absent_provider_is_module_unavailable_not_unknown_route() {
    let api = ClientApi::new(ClientApiConfig::default());
    operator(&api);
    for req in [
        get(routes::PATH_PACKS),
        get("/client/packs/foo@1.0.0"),
        post(
            routes::PATH_PACK_INSTALL,
            json!({ "source": "/tmp/p" }),
            "k1",
        ),
        post("/client/packs/foo@1.0.0:uninstall", Value::Null, "k2"),
    ] {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{env:?}"
        );
    }
}

// ── PK-02: list + detail project the provider's rows ─────────────────────────────────────────
#[test]
fn pk02_list_and_detail_project_installed_packs() {
    let provider = MemoryPacks::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let list: ClientPackList = data(&api.handle(get(routes::PATH_PACKS)));
    assert_eq!(list.packs.len(), 2);
    assert_eq!(list.packs[1].required_capabilities, vec!["fs", "llm"]);
    assert_eq!(provider.calls.list.load(Ordering::SeqCst), 1);

    let detail: ClientPackDetail = data(&api.handle(get("/client/packs/bar@2.1.0")));
    assert_eq!(detail.summary.name, "bar");
    assert_eq!(detail.provides[0].kind, "agent-templates");

    let env = api.handle(get("/client/packs/ghost@9.9.9"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));

    // Malformed ids are rejected BEFORE the provider is consulted.
    let calls = provider.calls.get.load(Ordering::SeqCst);
    for bad in ["/client/packs/no-version", "/client/packs/.hidden@1.0.0"] {
        let env = api.handle(get(bad));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{bad}");
    }
    assert_eq!(provider.calls.get.load(Ordering::SeqCst), calls);
}

// ── PK-03: install runs the full mutation pipeline and carries the accepted set ───────────────
#[test]
fn pk03_install_full_pipeline_carries_accepted_capabilities() {
    let provider = MemoryPacks::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let body = json!({ "source": "/tmp/new-pack", "accepted_capabilities": ["fs"] });
    let env = api.handle(post(routes::PATH_PACK_INSTALL, body.clone(), "k1"));
    let result: ClientPackInstallResult = data(&env);
    assert_eq!(result.name, "new");
    assert_eq!(provider.calls.install.load(Ordering::SeqCst), 1);
    let seen = provider.last_install.lock().unwrap().clone().unwrap();
    assert_eq!(seen.source, "/tmp/new-pack");
    assert_eq!(seen.accepted_capabilities, vec!["fs"]);

    // Same key → idempotent replay, the provider is NOT re-entered.
    let replay = api.handle(post(routes::PATH_PACK_INSTALL, body, "k1"));
    assert!(replay.is_ok());
    assert_eq!(provider.calls.install.load(Ordering::SeqCst), 1);
    assert!(replay
        .warnings
        .iter()
        .any(|w| w.code == "idempotent_replay"));

    // Validation failures never reach the provider.
    for (bad, why) in [
        (json!({ "source": "" }), "empty source"),
        (
            json!({ "source": "/tmp/p", "accepted_capabilities": ["a b"] }),
            "bad cap",
        ),
        (json!({ "source": "/tmp/p", "extra": 1 }), "unknown field"),
        (json!([]), "non-object body"),
    ] {
        let env = api.handle(post(routes::PATH_PACK_INSTALL, bad, &format!("k-{why}")));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{why}");
    }
    assert_eq!(provider.calls.install.load(Ordering::SeqCst), 1);

    // A missing idempotency key is refused before the provider.
    let env = api.handle(
        ClientRequest::post(routes::PATH_PACK_INSTALL, json!({ "source": "/tmp/p" }))
            .with_session("tok"),
    );
    assert!(!env.is_ok());
    assert_eq!(provider.calls.install.load(Ordering::SeqCst), 1);
}

// ── PK-04: uninstall + provider error projection ─────────────────────────────────────────────
#[test]
fn pk04_uninstall_and_error_projection() {
    let provider = MemoryPacks::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let env = api.handle(post("/client/packs/foo@1.0.0:uninstall", Value::Null, "u1"));
    let result: ClientPackUninstallResult = data(&env);
    assert_eq!(
        (result.name.as_str(), result.version.as_str()),
        ("foo", "1.0.0")
    );
    let list: ClientPackList = data(&api.handle(get(routes::PATH_PACKS)));
    assert_eq!(list.packs.len(), 1);

    let env = api.handle(post("/client/packs/foo@1.0.0:uninstall", Value::Null, "u2"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));

    for (err, expected) in [
        (
            ProviderError::AlreadyExists("x".into()),
            ClientErrorCode::AlreadyExists,
        ),
        (
            ProviderError::InvalidState("dependents".into()),
            ClientErrorCode::InvalidState,
        ),
        (
            ProviderError::Forbidden("not accepted".into()),
            ClientErrorCode::Forbidden,
        ),
        (
            ProviderError::Unavailable("fetch".into()),
            ClientErrorCode::ModuleUnavailable,
        ),
    ] {
        let (api, _sink) = api_with(MemoryPacks::failing(err));
        operator(&api);
        let env = api.handle(post(
            routes::PATH_PACK_INSTALL,
            json!({ "source": "/tmp/p" }),
            "k",
        ));
        assert_eq!(code(&env), Some(expected), "{env:?}");
    }
}

// ── PK-05: scope gate — reads need ReadInventory, mutations need ApproveGrants ────────────────
#[test]
fn pk05_scope_gate() {
    let provider = MemoryPacks::new();
    let (api, _sink) = api_with(provider.clone());
    mint(&api, "tok", vec![Scope::ReadInventory]);

    assert!(api.handle(get(routes::PATH_PACKS)).is_ok());
    let env = api.handle(post(
        routes::PATH_PACK_INSTALL,
        json!({ "source": "/tmp/p" }),
        "k",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{env:?}");
    assert_eq!(provider.calls.install.load(Ordering::SeqCst), 0);

    mint(&api, "ro", vec![Scope::ReadRuns]);
    let env = api.handle(ClientRequest::get(routes::PATH_PACKS).with_session("ro"));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
}

// ── PK-06: DTOs are inventoried in the CONTRACT-192 schema + compat gate ─────────────────────
#[test]
fn pk06_schema_components_inventoried() {
    let art = generate_schema_artifact();
    let components = art.schema["components"]
        .as_object()
        .expect("components object");
    for r in [
        "ClientPackSummary",
        "ClientPackProvide",
        "ClientPackDetail",
        "ClientPackList",
        "ClientPackInstallResult",
        "ClientPackUninstallResult",
    ] {
        assert!(components.contains_key(r), "{r} in schema");
        assert!(RESPONSE_COMPONENTS.contains(&r), "{r} inventoried");
    }
    assert!(components.contains_key("ClientPackInstallRequest"));
    assert!(EXCLUDED_COMPONENTS.contains(&"ClientPackInstallRequest"));
}
