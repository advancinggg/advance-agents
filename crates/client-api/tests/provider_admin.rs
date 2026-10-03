//! CONTRACT-190 providers family — `/client/providers` list / create / get / update / delete /
//! set-key / clear-key / preflight / select / sign-in over the REAL `ClientApi::handle()` pipeline
//! (admission, version, session, scope gate, idempotency reserve/replay, handler-side
//! validation, provider-error projection, warning attachment) against a recording in-memory
//! `ProviderAdminProvider`. The production adapter over the workspace's `runtime-config.yaml`
//! and the daemon's live secret store is `crates/cli/src/client_api_providers.rs`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    ClientProviderRateLimit, ClientProviderSignIn, ClientProviderSignInModel,
    ClientProviderSignInStart, ClientProviderSignOut, ClientProviderSummary, ClientProviderUsage,
    ClientProviderUsageWindow, ClientUpdateProviderRequest, ProviderAdminOutcome,
    ProviderAdminWarning, AUTH_SOURCES, CHATGPT_OAUTH_AUTH_SOURCE, MAX_KEY_BYTES, SIGN_IN_STATES,
};
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    Platform, Principal, ProviderAdminProvider, ProviderError, Scope, AUTH_SOURCE_MISMATCH_DETAIL,
};

const SECRET_KEY: &str = "sk-live-ULTRA-SECRET-0123456789";

/// What a sign-in hands the provider: the verifier it minted for the attempt, the code the
/// browser came back with, and the session the exchange returned. None of them may reach a
/// client.
const SIGN_IN_VERIFIER: &str = "pkce-verifier-ULTRA-SECRET-0123456789";
const SIGN_IN_AUTH_CODE: &str = "ac_ULTRA-SECRET-code-0123456789";
const SIGN_IN_ACCESS_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.access-ULTRA-SECRET.c2ln";
const SIGN_IN_REFRESH_TOKEN: &str = "rt_ULTRA-SECRET-refresh-0123456789";
const SIGN_IN_CUSTODY: [&str; 4] = [
    SIGN_IN_VERIFIER,
    SIGN_IN_AUTH_CODE,
    SIGN_IN_ACCESS_TOKEN,
    SIGN_IN_REFRESH_TOKEN,
];
/// The entry [`MemoryProviders::with_sign_in_entry`] seeds.
const PLAN: &str = "openai-plan";

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
    sign_in_start: AtomicUsize,
    sign_in_status: AtomicUsize,
    sign_in_cancel: AtomicUsize,
    sign_out: AtomicUsize,
}

/// Where one `chatgpt-oauth` entry's sign-in stands (absent = signed out).
enum SignInSlot {
    Pending {
        attempt: u64,
        verifier: String,
    },
    SignedIn {
        code: String,
        access_token: String,
        refresh_token: String,
    },
    Failed(&'static str),
}

struct MemoryProviders {
    calls: Calls,
    entries: Mutex<Vec<ClientProviderSummary>>,
    keys: Mutex<BTreeMap<String, String>>,
    /// The verdict `set_key` / `preflight` report (`None` = pass).
    preflight_reason: Mutex<Option<String>>,
    /// Provider id → sign-in slot. Holds token material; only `sign_in_of` projects it.
    sign_ins: Mutex<BTreeMap<String, SignInSlot>>,
    /// `sign_out` reports an unconfirmed revocation while set.
    revocation_offline: AtomicBool,
    fail: Option<ProviderError>,
}

/// The deadline the double gives attempt number `attempt`.
fn sign_in_deadline(attempt: u64) -> u64 {
    1_700_000_600_000 + attempt
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
        auth_source: None,
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
        agent_cli: None,
        key: ClientProviderKey {
            secret_name: format!("{id}-api-key"),
            present: false,
        },
        selected,
        last_preflight: None,
        last_usage: None,
        sign_in: None,
    }
}

/// A `chatgpt-oauth` entry as the provider projects it before any sign-in.
fn sign_in_summary(id: &str) -> ClientProviderSummary {
    ClientProviderSummary {
        backend: Some("openai-responses".into()),
        endpoint: "https://api.openai.com".into(),
        auth_source: Some(CHATGPT_OAUTH_AUTH_SOURCE.into()),
        key: ClientProviderKey {
            secret_name: format!("{id}-chatgpt-0a1b2c3d"),
            present: false,
        },
        ..summary(id, false)
    }
}

impl MemoryProviders {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            entries: Mutex::new(vec![summary("openai", true), summary("anthropic", false)]),
            keys: Mutex::new(BTreeMap::new()),
            preflight_reason: Mutex::new(None),
            sign_ins: Mutex::new(BTreeMap::new()),
            revocation_offline: AtomicBool::new(false),
            fail: None,
        })
    }
    /// `new()` plus one `chatgpt-oauth` entry ([`PLAN`]), signed out.
    fn with_sign_in_entry() -> Arc<Self> {
        let provider = Self::new();
        provider.entries.lock().unwrap().push(sign_in_summary(PLAN));
        provider
    }
    fn failing(err: ProviderError) -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            entries: Mutex::new(vec![]),
            keys: Mutex::new(BTreeMap::new()),
            preflight_reason: Mutex::new(None),
            sign_ins: Mutex::new(BTreeMap::new()),
            revocation_offline: AtomicBool::new(false),
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
            if e.auth_source.is_some() {
                e.sign_in = Some(self.sign_in_of(&e.provider_id));
            }
        }
    }
    /// The client-safe projection of one entry's sign-in slot: state, reason, account label,
    /// deadline and models — never the slot's token material.
    fn sign_in_of(&self, id: &str) -> ClientProviderSignIn {
        let checked_at_ms = 1_700_000_000_005;
        match self.sign_ins.lock().unwrap().get(id) {
            None => ClientProviderSignIn {
                state: "signed-out".into(),
                checked_at_ms,
                ..ClientProviderSignIn::default()
            },
            Some(SignInSlot::Pending { attempt, .. }) => ClientProviderSignIn {
                state: "pending".into(),
                checked_at_ms,
                expires_at_ms: Some(sign_in_deadline(*attempt)),
                ..ClientProviderSignIn::default()
            },
            Some(SignInSlot::SignedIn { .. }) => ClientProviderSignIn {
                state: "signed-in".into(),
                checked_at_ms,
                reason: None,
                account: Some("me@example.com".into()),
                plan_usage: Some(true),
                expires_at_ms: Some(1_700_003_600_000),
                models: vec![
                    ClientProviderSignInModel {
                        id: "gpt-5.2".into(),
                        display_name: Some("GPT-5.2".into()),
                    },
                    ClientProviderSignInModel {
                        id: "gpt-5.2-mini".into(),
                        display_name: None,
                    },
                ],
            },
            Some(SignInSlot::Failed(reason)) => ClientProviderSignIn {
                state: "failed".into(),
                checked_at_ms,
                reason: Some((*reason).into()),
                ..ClientProviderSignIn::default()
            },
        }
    }
    /// The entry behind a sign-in route, or the typed refusal for an entry that does not sign in.
    fn sign_in_entry(&self, id: &str) -> Result<ClientProviderSummary, ProviderError> {
        let entry = self.find(id)?;
        if entry.auth_source.as_deref() != Some(CHATGPT_OAUTH_AUTH_SOURCE) {
            return Err(ProviderError::AuthSourceMismatch(
                "sign-in-on-a-keyed-entry".into(),
            ));
        }
        Ok(entry)
    }
    /// What the browser coming back does to a pending attempt: the provider is handed the
    /// code and the session, keeps both, and stores the access token under the entry's secret
    /// name (the name the egress chain resolves).
    fn complete_sign_in(&self, id: &str, code: &str, access_token: &str, refresh_token: &str) {
        let entry = self.find(id).expect("entry exists");
        let previous = self.sign_ins.lock().unwrap().insert(
            id.to_string(),
            SignInSlot::SignedIn {
                code: code.to_string(),
                access_token: access_token.to_string(),
                refresh_token: refresh_token.to_string(),
            },
        );
        assert!(
            matches!(previous, Some(SignInSlot::Pending { .. })),
            "a sign-in completes a pending attempt"
        );
        self.keys
            .lock()
            .unwrap()
            .insert(entry.key.secret_name, access_token.to_string());
    }
    /// Every token-like value the double currently holds for `id`.
    fn held_material(&self, id: &str) -> Vec<String> {
        match self.sign_ins.lock().unwrap().get(id) {
            Some(SignInSlot::Pending { verifier, .. }) => vec![verifier.clone()],
            Some(SignInSlot::SignedIn {
                code,
                access_token,
                refresh_token,
            }) => vec![code.clone(), access_token.clone(), refresh_token.clone()],
            _ => vec![],
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
        if request.auth_source.as_deref() == Some(CHATGPT_OAUTH_AUTH_SOURCE) {
            s.auth_source = request.auth_source.clone();
            s.backend = Some("openai-responses".into());
            s.key.secret_name = format!("{}-chatgpt-0a1b2c3d", request.provider_id);
            s.sign_in = Some(self.sign_in_of(&request.provider_id));
        }
        if let Some(name) = &request.api_key_secret {
            s.key.secret_name = name.clone();
        }
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
        if entry.auth_source.is_some() {
            return Err(ProviderError::AuthSourceMismatch(
                "key-on-a-sign-in-entry".into(),
            ));
        }
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
        if entry.auth_source.is_some() {
            return Err(ProviderError::AuthSourceMismatch(
                "key-on-a-sign-in-entry".into(),
            ));
        }
        self.keys.lock().unwrap().remove(&entry.key.secret_name);
        self.find(provider_id)
    }
    fn usage(&self, provider_id: &str) -> Result<ClientProviderUsage, ProviderError> {
        self.gate()?;
        let entry = self.find(provider_id)?;
        if entry.backend_class != "agent-cli" {
            return Ok(ClientProviderUsage {
                ok: false,
                checked_at_ms: 1_700_000_000_003,
                reason: Some("unsupported-backend-class".into()),
                ..ClientProviderUsage::default()
            });
        }
        Ok(ClientProviderUsage {
            ok: true,
            checked_at_ms: 1_700_000_000_004,
            reason: None,
            plan: Some("max".into()),
            account: Some("me@example.com".into()),
            windows: vec![ClientProviderUsageWindow {
                kind: "session".into(),
                label: "Current session".into(),
                model: None,
                used_percent: 60.0,
                resets_at_ms: None,
                resets_label: Some("Sep 29 at 11pm (America/Los_Angeles)".into()),
                window_minutes: None,
            }],
        })
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
    fn sign_in_start(&self, provider_id: &str) -> Result<ClientProviderSignInStart, ProviderError> {
        let attempt = self.calls.sign_in_start.fetch_add(1, Ordering::SeqCst) as u64 + 1;
        self.gate()?;
        self.sign_in_entry(provider_id)?;
        // A new start replaces whatever attempt was pending. The verifier stays here; the URL
        // carries only what a browser address bar may show.
        self.sign_ins.lock().unwrap().insert(
            provider_id.to_string(),
            SignInSlot::Pending {
                attempt,
                verifier: SIGN_IN_VERIFIER.to_string(),
            },
        );
        Ok(ClientProviderSignInStart {
            authorize_url: format!(
                "https://auth.openai.com/api/accounts/authorize?response_type=code\
                 &client_id=dynamic_agent_client&state=state-{attempt}\
                 &code_challenge=challenge-{attempt}&code_challenge_method=S256"
            ),
            expires_at_ms: sign_in_deadline(attempt),
        })
    }
    fn sign_in_status(&self, provider_id: &str) -> Result<ClientProviderSignIn, ProviderError> {
        self.calls.sign_in_status.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        self.sign_in_entry(provider_id)?;
        Ok(self.sign_in_of(provider_id))
    }
    fn sign_in_cancel(&self, provider_id: &str) -> Result<ClientProviderSignIn, ProviderError> {
        self.calls.sign_in_cancel.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        self.sign_in_entry(provider_id)?;
        {
            // Only a pending attempt is abandoned; a session is not touched.
            let mut slots = self.sign_ins.lock().unwrap();
            if matches!(slots.get(provider_id), Some(SignInSlot::Pending { .. })) {
                slots.insert(provider_id.to_string(), SignInSlot::Failed("cancelled"));
            }
        }
        Ok(self.sign_in_of(provider_id))
    }
    fn sign_out(&self, provider_id: &str) -> Result<ClientProviderSignOut, ProviderError> {
        self.calls.sign_out.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let entry = self.sign_in_entry(provider_id)?;
        self.sign_ins.lock().unwrap().remove(provider_id);
        self.keys.lock().unwrap().remove(&entry.key.secret_name);
        Ok(ClientProviderSignOut {
            signed_out: true,
            revocation_confirmed: !self.revocation_offline.load(Ordering::SeqCst),
        })
    }
}

/// An adapter written before the sign-in routes existed: it implements only the required
/// methods and inherits the default sign-in bodies.
struct PredatesSignIn(Arc<MemoryProviders>);

impl ProviderAdminProvider for PredatesSignIn {
    fn list_providers(&self) -> Result<Vec<ClientProviderSummary>, ProviderError> {
        self.0.list_providers()
    }
    fn get_provider(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        self.0.get_provider(provider_id)
    }
    fn create_provider(
        &self,
        request: &ClientCreateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        self.0.create_provider(request)
    }
    fn update_provider(
        &self,
        provider_id: &str,
        request: &ClientUpdateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        self.0.update_provider(provider_id, request)
    }
    fn delete_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderDeleteResult>, ProviderError> {
        self.0.delete_provider(provider_id)
    }
    fn set_key(
        &self,
        provider_id: &str,
        key: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderKeyResult>, ProviderError> {
        self.0.set_key(provider_id, key)
    }
    fn clear_key(&self, provider_id: &str) -> Result<ClientProviderSummary, ProviderError> {
        self.0.clear_key(provider_id)
    }
    fn preflight(&self, provider_id: &str) -> Result<ClientProviderPreflightResult, ProviderError> {
        self.0.preflight(provider_id)
    }
    fn select_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        self.0.select_provider(provider_id)
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

/// The `details` tokens of an error envelope (empty for a success or a detail-free error).
fn details(env: &ClientEnvelope<Value>) -> Vec<String> {
    env.error
        .as_ref()
        .map(|e| e.details.clone())
        .unwrap_or_default()
}

/// The four sign-in routes for `id`: the three mutations carry `key`-prefixed idempotency keys.
fn sign_in_requests(id: &str, key: &str) -> [(&'static str, ClientRequest); 4] {
    [
        (
            "start",
            post(
                &format!("/client/providers/{id}:sign-in"),
                Value::Null,
                &format!("{key}-start"),
            ),
        ),
        ("status", get(&format!("/client/providers/{id}/sign-in"))),
        (
            "cancel",
            post(
                &format!("/client/providers/{id}:sign-in-cancel"),
                Value::Null,
                &format!("{key}-cancel"),
            ),
        ),
        (
            "sign-out",
            post(
                &format!("/client/providers/{id}:sign-out"),
                Value::Null,
                &format!("{key}-out"),
            ),
        ),
    ]
}

/// How often each sign-in method of the double was entered: start, status, cancel, sign-out.
fn sign_in_calls(provider: &MemoryProviders) -> [usize; 4] {
    [
        provider.calls.sign_in_start.load(Ordering::SeqCst),
        provider.calls.sign_in_status.load(Ordering::SeqCst),
        provider.calls.sign_in_cancel.load(Ordering::SeqCst),
        provider.calls.sign_out.load(Ordering::SeqCst),
    ]
}

/// A create body for a `chatgpt-oauth` entry with nothing but the required fields.
fn sign_in_create_body(id: &str) -> Value {
    let mut body = create_body(id);
    body["endpoint"] = json!("https://api.openai.com");
    body["auth_source"] = json!("chatgpt-oauth");
    body
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
        get("/client/providers/openai/usage"),
        post("/client/providers/openai:sign-in", Value::Null, "k8"),
        get("/client/providers/openai/sign-in"),
        post("/client/providers/openai:sign-in-cancel", Value::Null, "k9"),
        post("/client/providers/openai:sign-out", Value::Null, "k10"),
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
        post("/client/providers/openai:sign-in", Value::Null, "k8"),
        post("/client/providers/openai:sign-in-cancel", Value::Null, "k9"),
        post("/client/providers/openai:sign-out", Value::Null, "k10"),
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
        "ClientProviderSignInStart",
        "ClientProviderSignInModel",
        "ClientProviderSignIn",
        "ClientProviderSignOut",
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

    // The sign-in vocabularies are plain strings checked against tables: a component that
    // enumerated them would turn every later spelling into a closed-enum change.
    for (component, field) in [
        ("ClientProviderSignIn", "state"),
        ("ClientProviderSignIn", "reason"),
        ("ClientProviderSummary", "auth_source"),
        ("ClientCreateProviderRequest", "auth_source"),
    ] {
        let schema = &components[component]["properties"][field];
        assert!(schema.is_object(), "{component}.{field} in schema");
        let text = serde_json::to_string(schema).unwrap();
        assert!(
            !text.contains("\"enum\"") && !text.contains("\"const\""),
            "{component}.{field} must stay a free string: {text}"
        );
    }
    assert!(
        components["ClientUpdateProviderRequest"]["properties"]["auth_source"].is_null(),
        "the credential source is fixed at creation"
    );
}

// ── PA-11: GET …/usage — the vendor CLI's own allowance is a read; other classes answer a
//    fixed reason as DATA; an unknown id is not_found; a bad id never reaches the provider ──
#[test]
fn pa11_usage_read() {
    let provider = MemoryProviders::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let cloud: ClientProviderUsage = data(&api.handle(get("/client/providers/openai/usage")));
    assert!(!cloud.ok);
    assert_eq!(cloud.reason.as_deref(), Some("unsupported-backend-class"));
    assert!(cloud.windows.is_empty());

    let entry = ClientProviderSummary {
        provider_id: "claude-sub".into(),
        backend_class: "agent-cli".into(),
        ..summary("claude-sub", false)
    };
    provider.entries.lock().unwrap().push(entry);
    let usage: ClientProviderUsage = data(&api.handle(get("/client/providers/claude-sub/usage")));
    assert!(usage.ok);
    assert_eq!(usage.plan.as_deref(), Some("max"));
    assert_eq!(usage.account.as_deref(), Some("me@example.com"));
    assert_eq!(usage.windows.len(), 1);
    assert_eq!(usage.windows[0].kind, "session");
    assert_eq!(usage.windows[0].used_percent, 60.0);
    assert_eq!(
        usage.windows[0].resets_label.as_deref(),
        Some("Sep 29 at 11pm (America/Los_Angeles)")
    );

    let missing = api.handle(get("/client/providers/ghost/usage"));
    assert_eq!(
        code(&missing),
        Some(ClientErrorCode::NotFound),
        "{missing:?}"
    );
    let bad = api.handle(get("/client/providers/a.b/usage"));
    assert_eq!(code(&bad), Some(ClientErrorCode::InvalidRequest), "{bad:?}");
}

// ── PA-12: sign-in scope gate — the state is a ReadInventory read, start / cancel / sign-out
//    are ApproveGrants mutations; a session with neither reaches none of them ──────────────────
#[test]
fn pa12_sign_in_scope_gate() {
    let provider = MemoryProviders::with_sign_in_entry();
    let (api, _sink) = api_with(provider.clone());

    // ReadInventory alone: the state is readable, nothing can be changed.
    mint(&api, "tok", vec![Scope::ReadInventory]);
    for (what, req) in sign_in_requests(PLAN, "ro") {
        let env = api.handle(req);
        if what == "status" {
            let status: ClientProviderSignIn = data(&env);
            assert_eq!(status.state, "signed-out");
        } else {
            assert_eq!(
                code(&env),
                Some(ClientErrorCode::Forbidden),
                "{what}: {env:?}"
            );
        }
    }
    assert_eq!(sign_in_calls(&provider), [0, 1, 0, 0]);

    // ApproveGrants alone: the three mutations pass, the read does not.
    mint(&api, "admin", vec![Scope::ApproveGrants]);
    for (what, req) in sign_in_requests(PLAN, "admin") {
        let env = api.handle(req.with_session("admin"));
        if what == "status" {
            assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{env:?}");
        } else {
            assert!(env.is_ok(), "{what}: {env:?}");
        }
    }
    assert_eq!(sign_in_calls(&provider), [1, 1, 1, 1]);

    // Neither scope: all four are refused before the provider.
    mint(&api, "runs", vec![Scope::ReadRuns, Scope::ControlRuns]);
    for (what, req) in sign_in_requests(PLAN, "runs") {
        let env = api.handle(req.with_session("runs"));
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::Forbidden),
            "{what}: {env:?}"
        );
    }
    // No session at all.
    for (what, req) in [
        (
            "start",
            ClientRequest::post(format!("/client/providers/{PLAN}:sign-in"), Value::Null)
                .with_idempotency_key("anon-start"),
        ),
        (
            "status",
            ClientRequest::get(format!("/client/providers/{PLAN}/sign-in")),
        ),
        (
            "cancel",
            ClientRequest::post(
                format!("/client/providers/{PLAN}:sign-in-cancel"),
                Value::Null,
            )
            .with_idempotency_key("anon-cancel"),
        ),
        (
            "sign-out",
            ClientRequest::post(format!("/client/providers/{PLAN}:sign-out"), Value::Null)
                .with_idempotency_key("anon-out"),
        ),
    ] {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::Unauthenticated),
            "{what}: {env:?}"
        );
    }
    assert_eq!(sign_in_calls(&provider), [1, 1, 1, 1]);
}

// ── PA-13: the provider id is validated before the provider is consulted on every sign-in
//    route; an unknown id is the provider's not_found; the method is part of the route ────────
#[test]
fn pa13_sign_in_ids_validated_before_the_provider() {
    let provider = MemoryProviders::with_sign_in_entry();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let long = "x".repeat(65);
    for (i, bad) in ["bad%20id", "a.b", "a b", "é", long.as_str()]
        .into_iter()
        .enumerate()
    {
        for (what, req) in sign_in_requests(bad, &format!("bad{i}")) {
            let env = api.handle(req);
            assert_eq!(
                code(&env),
                Some(ClientErrorCode::InvalidRequest),
                "{what} {bad}: {env:?}"
            );
        }
    }
    assert_eq!(sign_in_calls(&provider), [0, 0, 0, 0]);

    // A refused id leaves its idempotency key free: nothing was committed under it.
    let env = api.handle(post("/client/providers/a.b:sign-in", Value::Null, "reuse"));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    let env = api.handle(post("/client/providers/a.b:sign-in", Value::Null, "reuse"));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert!(!has_warning(&env, "idempotent_replay"));

    // A well-formed id the provider does not know.
    for (what, req) in sign_in_requests("ghost", "ghost") {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::NotFound),
            "{what}: {env:?}"
        );
    }
    assert_eq!(sign_in_calls(&provider), [1, 1, 1, 1]);

    // The verbs are POST-only and the state is GET-only: the other method never reaches a
    // sign-in handler.
    for verb in ["sign-in", "sign-in-cancel", "sign-out"] {
        let env = api.handle(get(&format!("/client/providers/{PLAN}:{verb}")));
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::InvalidRequest),
            "GET :{verb} is the entry read with an invalid id: {env:?}"
        );
    }
    let env = api.handle(post(
        &format!("/client/providers/{PLAN}/sign-in"),
        Value::Null,
        "post-status",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::UnknownRoute), "{env:?}");
    assert_eq!(sign_in_calls(&provider), [1, 1, 1, 1]);

    // The mutations require an idempotency key like every other mutation of the family.
    for verb in ["sign-in", "sign-in-cancel", "sign-out"] {
        let env = api.handle(
            ClientRequest::post(format!("/client/providers/{PLAN}:{verb}"), Value::Null)
                .with_session("tok"),
        );
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::IdempotencyRequired),
            ":{verb}: {env:?}"
        );
    }
    assert_eq!(sign_in_calls(&provider), [1, 1, 1, 1]);
}

// ── PA-14: start answers the URL and the deadline and replays under the same key without
//    starting another attempt; the state is polled; cancel and sign-out answer data ───────────
#[test]
fn pa14_sign_in_start_replays_and_the_state_is_polled() {
    let provider = MemoryProviders::with_sign_in_entry();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);
    let start = format!("/client/providers/{PLAN}:sign-in");
    let status = format!("/client/providers/{PLAN}/sign-in");
    let cancel = format!("/client/providers/{PLAN}:sign-in-cancel");
    let sign_out = format!("/client/providers/{PLAN}:sign-out");

    let first_env = api.handle(post(&start, Value::Null, "si1"));
    let first: ClientProviderSignInStart = data(&first_env);
    assert!(
        first
            .authorize_url
            .starts_with("https://auth.openai.com/api/accounts/authorize?"),
        "{first:?}"
    );
    assert_eq!(first.expires_at_ms, sign_in_deadline(1));
    let mut fields: Vec<&str> = first_env
        .data
        .as_ref()
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["authorize_url", "expires_at_ms"],
        "the start response is the URL and the deadline, nothing else"
    );

    // Same key → the recorded pair, the provider is not re-entered, no second attempt.
    let replay_env = api.handle(post(&start, Value::Null, "si1"));
    let replay: ClientProviderSignInStart = data(&replay_env);
    assert_eq!(replay, first);
    assert!(has_warning(&replay_env, "idempotent_replay"));
    assert_eq!(replay_env.request_id, first_env.request_id);
    assert_eq!(provider.calls.sign_in_start.load(Ordering::SeqCst), 1);

    // The state a client polls while the browser is open.
    let pending: ClientProviderSignIn = data(&api.handle(get(&status)));
    assert_eq!(pending.state, "pending");
    assert_eq!(pending.expires_at_ms, Some(first.expires_at_ms));
    assert_eq!(pending.account, None);
    assert_eq!(pending.plan_usage, None);
    assert!(pending.models.is_empty());

    // A fresh key is a new attempt with its own URL and deadline; the old key keeps
    // answering the old (now superseded) pair.
    let second: ClientProviderSignInStart = data(&api.handle(post(&start, Value::Null, "si2")));
    assert_ne!(second.authorize_url, first.authorize_url);
    assert_eq!(second.expires_at_ms, sign_in_deadline(2));
    assert_eq!(provider.calls.sign_in_start.load(Ordering::SeqCst), 2);
    let stale: ClientProviderSignInStart = data(&api.handle(post(&start, Value::Null, "si1")));
    assert_eq!(stale, first);
    assert_eq!(provider.calls.sign_in_start.load(Ordering::SeqCst), 2);
    let pending: ClientProviderSignIn = data(&api.handle(get(&status)));
    assert_eq!(pending.expires_at_ms, Some(second.expires_at_ms));

    // The browser comes back: the state turns signed-in and the entry's summary carries it.
    provider.complete_sign_in(
        PLAN,
        SIGN_IN_AUTH_CODE,
        SIGN_IN_ACCESS_TOKEN,
        SIGN_IN_REFRESH_TOKEN,
    );
    let signed_in: ClientProviderSignIn = data(&api.handle(get(&status)));
    assert_eq!(signed_in.state, "signed-in");
    assert_eq!(signed_in.reason, None);
    assert_eq!(signed_in.account.as_deref(), Some("me@example.com"));
    assert_eq!(signed_in.plan_usage, Some(true));
    assert_eq!(signed_in.expires_at_ms, Some(1_700_003_600_000));
    assert_eq!(signed_in.models.len(), 2);
    assert_eq!(signed_in.models[0].id, "gpt-5.2");
    assert_eq!(signed_in.models[0].display_name.as_deref(), Some("GPT-5.2"));
    assert_eq!(signed_in.models[1].display_name, None);
    let one: ClientProviderSummary = data(&api.handle(get(&format!("/client/providers/{PLAN}"))));
    assert_eq!(one.auth_source.as_deref(), Some("chatgpt-oauth"));
    assert_eq!(one.sign_in.as_ref(), Some(&signed_in));
    assert!(one.key.present, "the session's credential is stored");

    // Cancel without a pending attempt changes nothing and answers the state.
    let env = api.handle(post(&cancel, Value::Null, "c1"));
    let after_cancel: ClientProviderSignIn = data(&env);
    assert_eq!(after_cancel, signed_in);

    // Sign-out answers data and replays without a second revocation.
    let env = api.handle(post(&sign_out, Value::Null, "so1"));
    let out: ClientProviderSignOut = data(&env);
    assert_eq!(
        out,
        ClientProviderSignOut {
            signed_out: true,
            revocation_confirmed: true
        }
    );
    let replay = api.handle(post(&sign_out, Value::Null, "so1"));
    assert_eq!(data::<ClientProviderSignOut>(&replay), out);
    assert!(has_warning(&replay, "idempotent_replay"));
    assert_eq!(provider.calls.sign_out.load(Ordering::SeqCst), 1);
    let signed_out: ClientProviderSignIn = data(&api.handle(get(&status)));
    assert_eq!(signed_out.state, "signed-out");
    let one: ClientProviderSummary = data(&api.handle(get(&format!("/client/providers/{PLAN}"))));
    assert!(!one.key.present);
    assert_eq!(one.sign_in.as_ref(), Some(&signed_out));

    // Cancelling a pending attempt ends it with a fixed reason, as data.
    let third: ClientProviderSignInStart = data(&api.handle(post(&start, Value::Null, "si3")));
    assert_eq!(third.expires_at_ms, sign_in_deadline(3));
    let cancelled: ClientProviderSignIn = data(&api.handle(post(&cancel, Value::Null, "c2")));
    assert_eq!(cancelled.state, "failed");
    assert_eq!(cancelled.reason.as_deref(), Some("cancelled"));
    assert_eq!(cancelled.expires_at_ms, None);

    // An unconfirmed revocation is a field of the result, not an error.
    provider.revocation_offline.store(true, Ordering::SeqCst);
    let out: ClientProviderSignOut = data(&api.handle(post(&sign_out, Value::Null, "so2")));
    assert!(out.signed_out);
    assert!(!out.revocation_confirmed);

    // Every state the double reported is one of the documented spellings.
    for state in [
        &pending.state,
        &signed_in.state,
        &signed_out.state,
        &cancelled.state,
    ] {
        assert!(SIGN_IN_STATES.contains(&state.as_str()), "{state}");
    }
    assert_eq!(SIGN_IN_STATES.len(), 4);
}

// ── PA-15: a route that does not apply to the entry's credential source is invalid_state with
//    the `auth_source_mismatch` detail token; an adapter without a sign-in is unavailable ──────
#[test]
fn pa15_wrong_source_is_invalid_state_with_the_detail_token() {
    let provider = MemoryProviders::with_sign_in_entry();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);
    assert_eq!(AUTH_SOURCE_MISMATCH_DETAIL, "auth_source_mismatch");

    // Sign-in routes on an API-key entry.
    for (what, req) in sign_in_requests("anthropic", "keyed") {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::InvalidState),
            "{what}: {env:?}"
        );
        assert_eq!(details(&env), [AUTH_SOURCE_MISMATCH_DETAIL], "{what}");
        let text = serde_json::to_string(&env).unwrap();
        assert!(!text.contains("sign-in-on-a-keyed-entry"), "{what}: {text}");
    }
    assert_eq!(sign_in_calls(&provider), [1, 1, 1, 1]);
    assert!(provider.sign_ins.lock().unwrap().is_empty());

    // Key routes on a sign-in entry.
    let env = api.handle(post(
        &format!("/client/providers/{PLAN}:set-key"),
        json!({ "key": SECRET_KEY }),
        "sk-plan",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidState), "{env:?}");
    assert_eq!(details(&env), [AUTH_SOURCE_MISMATCH_DETAIL]);
    let text = serde_json::to_string(&env).unwrap();
    assert!(!text.contains(SECRET_KEY) && !text.contains("key-on-a-sign-in-entry"));
    assert!(provider.keys.lock().unwrap().is_empty());
    let env = api.handle(post(
        &format!("/client/providers/{PLAN}:clear-key"),
        Value::Null,
        "ck-plan",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidState), "{env:?}");
    assert_eq!(details(&env), [AUTH_SOURCE_MISMATCH_DETAIL]);

    // The refusal is a committed outcome: the same key replays it without re-entering.
    let replay = api.handle(post(
        "/client/providers/anthropic:sign-in",
        Value::Null,
        "keyed-start",
    ));
    assert_eq!(code(&replay), Some(ClientErrorCode::InvalidState));
    assert_eq!(details(&replay), [AUTH_SOURCE_MISMATCH_DETAIL]);
    assert!(has_warning(&replay, "idempotent_replay"));
    assert_eq!(provider.calls.sign_in_start.load(Ordering::SeqCst), 1);

    // The token is what tells this refusal from an ordinary state refusal.
    let plain = ProviderError::InvalidState("last-provider".into()).into_client_error();
    assert_eq!(plain.code, ClientErrorCode::InvalidState);
    assert!(plain.details.is_empty());
    let typed = ProviderError::AuthSourceMismatch("inner".into()).into_client_error();
    assert_eq!(typed.code, plain.code);
    assert_eq!(typed.message, plain.message);
    assert_eq!(typed.details, [AUTH_SOURCE_MISMATCH_DETAIL]);

    // Every route projects the variant the same way.
    let (api, _sink) = api_with(MemoryProviders::failing(ProviderError::AuthSourceMismatch(
        "inner-reason".into(),
    )));
    operator(&api);
    for (what, req) in sign_in_requests(PLAN, "failing") {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::InvalidState),
            "{what}: {env:?}"
        );
        assert_eq!(details(&env), [AUTH_SOURCE_MISMATCH_DETAIL], "{what}");
        assert!(!serde_json::to_string(&env)
            .unwrap()
            .contains("inner-reason"));
    }

    // An adapter that predates the routes inherits the default bodies: unavailable, and the
    // rest of the family keeps working.
    let inner = MemoryProviders::with_sign_in_entry();
    let (api, _sink) = api_with(Arc::new(PredatesSignIn(inner.clone())));
    operator(&api);
    for (what, req) in sign_in_requests(PLAN, "legacy") {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{what}: {env:?}"
        );
        assert!(details(&env).is_empty(), "{what}");
    }
    assert_eq!(sign_in_calls(&inner), [0, 0, 0, 0]);
    assert!(api.handle(get(routes::PATH_PROVIDERS)).is_ok());
}

// ── PA-16: `auth_source` on create — the closed spellings, and what a `chatgpt-oauth` entry
//    may and may not name; the field does not exist on update ─────────────────────────────────
#[test]
fn pa16_create_auth_source_rules() {
    let provider = MemoryProviders::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);
    assert_eq!(AUTH_SOURCES, ["api-key", "chatgpt-oauth"]);

    // Accepted.
    let mut explicit_default = create_body("keyed");
    explicit_default["auth_source"] = json!("api-key");
    let mut spelled = sign_in_create_body("plan-spelled");
    spelled["backend_class"] = json!("cloud-http");
    spelled["backend"] = json!("openai-responses");
    spelled["auth_scheme"] = json!("bearer");
    let mut named = sign_in_create_body("plan-named");
    named["api_key_secret"] = json!("plan-named.session");
    for (body, why) in [
        (explicit_default, "explicit api-key"),
        (
            sign_in_create_body("plan-bare"),
            "chatgpt-oauth, nothing else named",
        ),
        (spelled, "chatgpt-oauth, every dependent field spelled"),
        (named, "chatgpt-oauth with its own secret name"),
    ] {
        let env = api.handle(post(routes::PATH_PROVIDERS, body, &format!("ok-{why}")));
        assert!(env.is_ok(), "{why}: {env:?}");
    }
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 4);

    // The summary names a non-default source and carries the sign-in state; an API-key entry
    // serializes neither field.
    let env = api.handle(get("/client/providers/plan-bare"));
    let plan: ClientProviderSummary = data(&env);
    assert_eq!(plan.auth_source.as_deref(), Some("chatgpt-oauth"));
    assert_eq!(plan.backend.as_deref(), Some("openai-responses"));
    assert_eq!(plan.sign_in.as_ref().unwrap().state, "signed-out");
    assert!(!plan.key.present);
    let named: ClientProviderSummary = data(&api.handle(get("/client/providers/plan-named")));
    assert_eq!(named.key.secret_name, "plan-named.session");
    let env = api.handle(get("/client/providers/keyed"));
    let keyed = env.data.as_ref().unwrap().as_object().unwrap();
    assert!(!keyed.contains_key("auth_source"), "{keyed:?}");
    assert!(!keyed.contains_key("sign_in"), "{keyed:?}");

    // Refused before the provider.
    let creates = provider.calls.create.load(Ordering::SeqCst);
    let with = |id: &str, field: &str, value: Value| {
        let mut body = sign_in_create_body(id);
        body[field] = value;
        body
    };
    let mut unknown = create_body("r0");
    unknown["auth_source"] = json!("oauth");
    let mut empty = create_body("r1");
    empty["auth_source"] = json!("");
    let mut cased = create_body("r2");
    cased["auth_source"] = json!("ChatGPT-OAuth");
    let mut not_a_string = create_body("r3");
    not_a_string["auth_source"] = json!({ "kind": "chatgpt-oauth" });
    let mut agent_cli = with("r6", "backend_class", json!("agent-cli"));
    agent_cli["agent_cli"] = json!({ "vendor": "codex", "command": "/opt/homebrew/bin/codex" });
    agent_cli.as_object_mut().unwrap().remove("endpoint");
    for (bad, why) in [
        (unknown, "unknown source"),
        (empty, "empty source"),
        (cased, "source spelling is exact"),
        (not_a_string, "source is a string"),
        (with("r4", "backend_class", json!("local")), "local class"),
        (
            with("r5", "backend_class", json!("mesh-remote")),
            "mesh-remote class",
        ),
        (agent_cli, "agent-cli class"),
        (
            with("r7", "backend", json!("openai-chat")),
            "chat-completions dialect",
        ),
        (
            with("r8", "backend", json!("anthropic-messages")),
            "anthropic dialect",
        ),
        (
            with("r9", "auth_scheme", json!("x-api-key")),
            "x-api-key scheme",
        ),
        (
            with("r10", "auth_scheme", json!("api-key")),
            "api-key scheme",
        ),
    ] {
        let env = api.handle(post(routes::PATH_PROVIDERS, bad, &format!("no-{why}")));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{why}");
    }
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), creates);

    // The dialect and scheme a sign-in entry may not name stay legal on an API-key entry.
    let mut other = create_body("keyed-chat");
    other["backend"] = json!("openai-chat");
    other["auth_scheme"] = json!("x-api-key");
    assert!(api
        .handle(post(routes::PATH_PROVIDERS, other, "ok-keyed-chat"))
        .is_ok());

    // The source of an entry is fixed at creation: update has no such field.
    let updates = provider.calls.update.load(Ordering::SeqCst);
    for (id, value) in [("keyed", "chatgpt-oauth"), ("plan-bare", "api-key")] {
        let env = api.handle(post(
            &format!("/client/providers/{id}:update"),
            json!({ "auth_source": value }),
            &format!("upd-{id}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{id}");
    }
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), updates);
}

// ── PA-17: a secret name reserved for a sign-in record is never accepted as an entry's
//    credential name, on create or on update, for either source ────────────────────────────────
#[test]
fn pa17_reserved_secret_name_refused() {
    let provider = MemoryProviders::with_sign_in_entry();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let mut keyed = create_body("k1");
    keyed["api_key_secret"] = json!("openai-api-key.chatgpt-oauth");
    let mut plan = sign_in_create_body("k2");
    plan["api_key_secret"] = json!("k2-chatgpt-0a1b2c3d.chatgpt-oauth");
    let mut bare = create_body("k3");
    bare["api_key_secret"] = json!(".chatgpt-oauth");
    for (bad, why) in [
        (keyed, "api-key entry"),
        (plan, "sign-in entry"),
        (bare, "suffix alone"),
    ] {
        let env = api.handle(post(routes::PATH_PROVIDERS, bad, &format!("rs-{why}")));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{why}");
    }
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 0);

    for id in ["openai", PLAN] {
        let env = api.handle(post(
            &format!("/client/providers/{id}:update"),
            json!({ "api_key_secret": "openai-api-key.chatgpt-oauth" }),
            &format!("rs-upd-{id}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{id}");
    }
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), 0);

    // Only the suffix position is reserved: the same words elsewhere in a name are fine.
    let mut inside = create_body("k4");
    inside["api_key_secret"] = json!("team.chatgpt-oauth.backup");
    let env = api.handle(post(routes::PATH_PROVIDERS, inside, "rs-inside"));
    let created: ClientProviderSummary = data(&env);
    assert_eq!(created.key.secret_name, "team.chatgpt-oauth.backup");
}

// ── PA-18: custody — the provider holds the verifier, the code and the session; no envelope
//    of the family, no replay and no audit record carries any of them ──────────────────────────
#[test]
fn pa18_sign_in_envelopes_carry_no_token() {
    let provider = MemoryProviders::with_sign_in_entry();
    let (api, sink) = api_with(provider.clone());
    operator(&api);
    let start = format!("/client/providers/{PLAN}:sign-in");
    let status = format!("/client/providers/{PLAN}/sign-in");
    let cancel = format!("/client/providers/{PLAN}:sign-in-cancel");
    let sign_out = format!("/client/providers/{PLAN}:sign-out");
    let entry = format!("/client/providers/{PLAN}");

    let mut seen: Vec<(String, ClientEnvelope<Value>)> = Vec::new();
    let mut send = |what: &str, req: ClientRequest| {
        let env = api.handle(req);
        seen.push((what.to_string(), env.clone()));
        env
    };

    // Pending: the provider holds the verifier.
    assert!(send("start", post(&start, Value::Null, "c-si1")).is_ok());
    assert_eq!(provider.held_material(PLAN), [SIGN_IN_VERIFIER]);
    assert!(send("start replay", post(&start, Value::Null, "c-si1")).is_ok());
    assert!(send("status pending", get(&status)).is_ok());
    assert!(send("entry pending", get(&entry)).is_ok());

    // Signed in: the provider holds the code and the session, and the access token sits under
    // the entry's secret name.
    provider.complete_sign_in(
        PLAN,
        SIGN_IN_AUTH_CODE,
        SIGN_IN_ACCESS_TOKEN,
        SIGN_IN_REFRESH_TOKEN,
    );
    assert_eq!(
        provider.held_material(PLAN),
        [
            SIGN_IN_AUTH_CODE,
            SIGN_IN_ACCESS_TOKEN,
            SIGN_IN_REFRESH_TOKEN
        ]
    );
    assert!(provider
        .keys
        .lock()
        .unwrap()
        .values()
        .any(|v| v == SIGN_IN_ACCESS_TOKEN));
    let env = send("status signed-in", get(&status));
    assert_eq!(data::<ClientProviderSignIn>(&env).state, "signed-in");
    let env = send("entry signed-in", get(&entry));
    assert!(data::<ClientProviderSummary>(&env).key.present);
    assert!(send("list signed-in", get(routes::PATH_PROVIDERS)).is_ok());
    assert!(send("cancel signed-in", post(&cancel, Value::Null, "c-c1")).is_ok());
    assert!(send(
        "preflight signed-in",
        post(&format!("{entry}:preflight"), Value::Null, "c-pf")
    )
    .is_ok());
    assert!(send(
        "select signed-in",
        post(&format!("{entry}:select"), Value::Null, "c-sel")
    )
    .is_ok());
    assert!(send(
        "update signed-in",
        post(
            &format!("{entry}:update"),
            json!({ "endpoint": "https://api.openai.com/" }),
            "c-upd"
        )
    )
    .is_ok());
    // Refusals while the session is held.
    assert!(send(
        "set-key refused",
        post(
            &format!("{entry}:set-key"),
            json!({ "key": SECRET_KEY }),
            "c-sk"
        )
    )
    .is_err());
    assert!(send(
        "clear-key refused",
        post(&format!("{entry}:clear-key"), Value::Null, "c-ck")
    )
    .is_err());
    for (what, req) in sign_in_requests("anthropic", "c-keyed") {
        assert!(send(&format!("wrong source {what}"), req).is_err());
    }
    assert!(send("sign-out", post(&sign_out, Value::Null, "c-so1")).is_ok());
    assert!(send("sign-out replay", post(&sign_out, Value::Null, "c-so1")).is_ok());
    assert!(send("status signed-out", get(&status)).is_ok());
    assert!(send("start again", post(&start, Value::Null, "c-si2")).is_ok());
    assert!(send("cancel pending", post(&cancel, Value::Null, "c-c2")).is_ok());

    // An adapter failure whose internal reason quotes token material: the projection drops
    // the reason on every sign-in route.
    for err in [
        ProviderError::Unavailable(format!("exchange of {SIGN_IN_AUTH_CODE} failed")),
        ProviderError::InvalidState(format!("verifier {SIGN_IN_VERIFIER} rejected")),
        ProviderError::AuthSourceMismatch(format!("bearer {SIGN_IN_ACCESS_TOKEN}")),
        ProviderError::NotFound(format!("no session for {SIGN_IN_REFRESH_TOKEN}")),
    ] {
        let (failing_api, failing_sink) = api_with(MemoryProviders::failing(err));
        operator(&failing_api);
        for (what, req) in sign_in_requests(PLAN, "c-fail") {
            let env = failing_api.handle(req);
            assert!(env.is_err(), "{what}: {env:?}");
            seen.push((format!("failing {what}"), env));
        }
        let audit = format!("{:?}", failing_sink.events());
        for secret in SIGN_IN_CUSTODY {
            assert!(!audit.contains(secret), "audit carries {secret}");
        }
    }

    // The check is not vacuous: the envelopes do carry what a client is meant to see.
    assert_eq!(seen.len(), 38);
    let all = seen
        .iter()
        .map(|(_, env)| serde_json::to_string(env).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "https://auth.openai.com/api/accounts/authorize?",
        "code_challenge=challenge-1",
        "me@example.com",
        "gpt-5.2-mini",
        "auth_source_mismatch",
        "\"signed-in\"",
    ] {
        assert!(
            all.contains(expected),
            "expected {expected} in the envelopes"
        );
    }

    for (what, env) in &seen {
        let wire = serde_json::to_string(env).unwrap();
        let debug = format!("{env:?}");
        for secret in SIGN_IN_CUSTODY {
            assert!(!wire.contains(secret), "{what}: wire carries {secret}");
            assert!(!debug.contains(secret), "{what}: Debug carries {secret}");
        }
        assert!(!wire.contains(SECRET_KEY), "{what}: wire carries the key");
    }
    let audit = format!("{:?}", sink.events());
    for secret in SIGN_IN_CUSTODY {
        assert!(!audit.contains(secret), "audit carries {secret}");
    }
    assert!(!audit.contains(SECRET_KEY));
}
