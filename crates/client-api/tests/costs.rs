//! CONTRACT-190 costs family — per-agent / per-provider LLM spend
//! (`/client/costs/agents`, `/client/costs/agents/{agent_id}`, `/client/costs/providers`,
//! `/client/costs/providers/{provider_id}`).
//!
//! Drives the REAL `ClientApi::handle()` pipeline (admission, version, session, scope gate,
//! handler-side validation, provider-error projection, audit family) against a recording
//! in-memory `CostProvider`. The production adapter over the durable event-bus ledger is
//! witnessed in `crates/cli/src/client_api_costs.rs` (unit) + `crates/event-bus/tests/cost_ledger.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::{EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS};
use advance_client_api::costs::{
    ClientAgentCostEntry, ClientAgentCostList, ClientAgentCostReport, ClientCostTotals,
    ClientProviderCostEntry, ClientProviderCostList, ClientProviderCostReport, ValidatedCostWindow,
};
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    CostProvider, Platform, Principal, ProviderError, Scope,
};

// ── Recording in-memory provider ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Calls {
    agent_totals: AtomicUsize,
    agent_report: AtomicUsize,
    provider_totals: AtomicUsize,
    provider_report: AtomicUsize,
}

struct MemoryCosts {
    calls: Calls,
    last_window: Mutex<Option<ValidatedCostWindow>>,
    last_id: Mutex<Option<String>>,
    fail: Option<ProviderError>,
    panic: bool,
}

impl MemoryCosts {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            last_window: Mutex::new(None),
            last_id: Mutex::new(None),
            fail: None,
            panic: false,
        })
    }
    fn failing(err: ProviderError) -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            last_window: Mutex::new(None),
            last_id: Mutex::new(None),
            fail: Some(err),
            panic: false,
        })
    }
    fn panicking() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            last_window: Mutex::new(None),
            last_id: Mutex::new(None),
            fail: None,
            panic: true,
        })
    }
    fn note(&self, window: &ValidatedCostWindow, id: Option<&str>) -> Result<(), ProviderError> {
        if self.panic {
            panic!("provider exploded");
        }
        *self.last_window.lock().unwrap() = Some(*window);
        *self.last_id.lock().unwrap() = id.map(str::to_string);
        match &self.fail {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
    fn totals(n: u64) -> ClientCostTotals {
        ClientCostTotals {
            tokens_in: n * 100,
            tokens_out: n * 10,
            cost_usd: n as f64 * 0.75,
            request_count: n as u32,
        }
    }
}

impl CostProvider for MemoryCosts {
    fn agent_totals(
        &self,
        window: &ValidatedCostWindow,
    ) -> Result<Vec<ClientAgentCostEntry>, ProviderError> {
        self.calls.agent_totals.fetch_add(1, Ordering::SeqCst);
        self.note(window, None)?;
        Ok(vec![
            ClientAgentCostEntry {
                agent_id: "research".into(),
                totals: Self::totals(4),
            },
            ClientAgentCostEntry {
                agent_id: "root".into(),
                totals: Self::totals(1),
            },
        ])
    }
    fn agent_report(
        &self,
        agent_id: &str,
        window: &ValidatedCostWindow,
    ) -> Result<ClientAgentCostReport, ProviderError> {
        self.calls.agent_report.fetch_add(1, Ordering::SeqCst);
        self.note(window, Some(agent_id))?;
        let known = agent_id == "research";
        Ok(ClientAgentCostReport {
            agent_id: agent_id.to_string(),
            totals: if known {
                Self::totals(4)
            } else {
                ClientCostTotals::default()
            },
            by_provider: if known {
                vec![
                    ClientProviderCostEntry {
                        provider_id: "anthropic".into(),
                        totals: Self::totals(3),
                    },
                    ClientProviderCostEntry {
                        provider_id: "unknown".into(),
                        totals: Self::totals(1),
                    },
                ]
            } else {
                vec![]
            },
            window: window.to_client(),
        })
    }
    fn provider_totals(
        &self,
        window: &ValidatedCostWindow,
    ) -> Result<Vec<ClientProviderCostEntry>, ProviderError> {
        self.calls.provider_totals.fetch_add(1, Ordering::SeqCst);
        self.note(window, None)?;
        Ok(vec![ClientProviderCostEntry {
            provider_id: "anthropic".into(),
            totals: Self::totals(5),
        }])
    }
    fn provider_report(
        &self,
        provider_id: &str,
        window: &ValidatedCostWindow,
    ) -> Result<ClientProviderCostReport, ProviderError> {
        self.calls.provider_report.fetch_add(1, Ordering::SeqCst);
        self.note(window, Some(provider_id))?;
        Ok(ClientProviderCostReport {
            provider_id: provider_id.to_string(),
            totals: Self::totals(5),
            by_agent: vec![ClientAgentCostEntry {
                agent_id: "research".into(),
                totals: Self::totals(5),
            }],
            window: window.to_client(),
        })
    }
}

// ── Rig ──────────────────────────────────────────────────────────────────────────────────────

fn api_with(provider: Arc<dyn CostProvider>) -> (ClientApi, RecordingSink) {
    let sink = RecordingSink::new();
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink.clone()),
    )
    .with_cost_provider(provider);
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

fn get_with_body(path: &str, body: Value) -> ClientRequest {
    let mut req = get(path);
    req.body = body;
    req
}

fn code(env: &ClientEnvelope<Value>) -> Option<ClientErrorCode> {
    env.error_code()
}

fn ok_data<T: serde::de::DeserializeOwned>(env: &ClientEnvelope<Value>) -> T {
    assert!(env.is_ok(), "expected ok envelope, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("response DTO parses")
}

const ALL_PATHS: [&str; 4] = [
    routes::PATH_COSTS_AGENTS,
    routes::PATH_COSTS_PROVIDERS,
    "/client/costs/agents/research",
    "/client/costs/providers/anthropic",
];

// ── CO-01: routes are always registered; an absent provider is module_unavailable ────────────
#[test]
fn co01_absent_provider_is_module_unavailable_not_unknown_route() {
    let api = ClientApi::new(ClientApiConfig::default());
    operator(&api);
    for path in ALL_PATHS {
        let env = api.handle(get(path));
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{path}"
        );
    }
    // Only GET is routed: POST to a costs path is unknown_route (no mutation family).
    let env = api.handle(
        ClientRequest::post(routes::PATH_COSTS_AGENTS, json!({}))
            .with_session("tok")
            .with_idempotency_key("k1"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::UnknownRoute));
}

// ── CO-02: session + ReadRuns scope gate, before any provider call ───────────────────────────
#[test]
fn co02_requires_session_and_read_runs_scope() {
    let provider = MemoryCosts::new();
    let (api, _sink) = api_with(provider.clone());
    for path in ALL_PATHS {
        let env = api.handle(ClientRequest::get(path));
        assert_eq!(code(&env), Some(ClientErrorCode::Unauthenticated), "{path}");
    }
    mint(&api, "tok", vec![Scope::ReadEvents, Scope::ControlRuns]);
    for path in ALL_PATHS {
        let env = api.handle(get(path));
        assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{path}");
    }
    assert_eq!(provider.calls.agent_totals.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.agent_report.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.provider_totals.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.provider_report.load(Ordering::SeqCst), 0);

    mint(&api, "tok", vec![Scope::ReadRuns]);
    for path in ALL_PATHS {
        let env = api.handle(get(path));
        assert!(env.is_ok(), "{path}: {:?}", env.error);
    }
}

// ── CO-03: list shapes + ordering passthrough + null body = unbounded window ─────────────────
#[test]
fn co03_lists_project_provider_rows_verbatim() {
    let provider = MemoryCosts::new();
    let (api, sink) = api_with(provider.clone());
    operator(&api);

    let agents: ClientAgentCostList = ok_data(&api.handle(get(routes::PATH_COSTS_AGENTS)));
    assert_eq!(agents.agents.len(), 2);
    assert_eq!(agents.agents[0].agent_id, "research");
    assert_eq!(agents.agents[0].totals.tokens_in, 400);
    assert_eq!(agents.agents[0].totals.request_count, 4);
    assert!((agents.agents[0].totals.cost_usd - 3.0).abs() < 1e-12);
    assert_eq!(agents.window.since, None);
    assert_eq!(agents.window.until, None);
    assert_eq!(
        *provider.last_window.lock().unwrap(),
        Some(ValidatedCostWindow::default())
    );

    let providers: ClientProviderCostList = ok_data(&api.handle(get(routes::PATH_COSTS_PROVIDERS)));
    assert_eq!(providers.providers.len(), 1);
    assert_eq!(providers.providers[0].provider_id, "anthropic");
    assert_eq!(providers.providers[0].totals.request_count, 5);

    // Audit family is `costs` for every route.
    let families: Vec<String> = sink.events().iter().map(|e| e.family.clone()).collect();
    assert!(families.iter().all(|f| f == "costs"), "{families:?}");
}

// ── CO-04: single reports carry the validated id + echo the normalized window ────────────────
#[test]
fn co04_reports_forward_id_and_window() {
    let provider = MemoryCosts::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let body = json!({ "since": "2026-09-01T00:00:00+02:00", "until": "2026-10-01T00:00:00Z" });
    let report: ClientAgentCostReport =
        ok_data(&api.handle(get_with_body("/client/costs/agents/research", body.clone())));
    assert_eq!(report.agent_id, "research");
    assert_eq!(report.totals.request_count, 4);
    assert_eq!(report.by_provider.len(), 2);
    assert_eq!(report.by_provider[1].provider_id, "unknown");
    assert_eq!(report.window.since.as_deref(), Some("2026-08-31T22:00:00Z"));
    assert_eq!(report.window.until.as_deref(), Some("2026-10-01T00:00:00Z"));
    assert_eq!(
        provider.last_id.lock().unwrap().as_deref(),
        Some("research")
    );
    let seen = provider.last_window.lock().unwrap().unwrap();
    assert_eq!(
        seen.since.unwrap().to_rfc3339(),
        "2026-08-31T22:00:00+00:00"
    );

    // Unknown agent: zero aggregate, NOT not_found (the ledger does not know the tree).
    let unknown: ClientAgentCostReport = ok_data(&api.handle(get("/client/costs/agents/nobody")));
    assert_eq!(unknown.totals, ClientCostTotals::default());
    assert!(unknown.by_provider.is_empty());

    let preport: ClientProviderCostReport = ok_data(&api.handle(get_with_body(
        "/client/costs/providers/openai-compatible",
        json!({ "since": "2026-09-01T00:00:00Z" }),
    )));
    assert_eq!(preport.provider_id, "openai-compatible");
    assert_eq!(preport.by_agent[0].agent_id, "research");
    assert_eq!(
        preport.window.since.as_deref(),
        Some("2026-09-01T00:00:00Z")
    );
    assert_eq!(preport.window.until, None);
    assert_eq!(
        provider.last_id.lock().unwrap().as_deref(),
        Some("openai-compatible")
    );
}

// ── CO-05: handler-side validation rejects before the provider is consulted ─────────────────
#[test]
fn co05_validation_precedes_provider() {
    let provider = MemoryCosts::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let bad_ids = [
        "/client/costs/agents/a%20b",
        "/client/costs/agents/agent:x",
        &format!("/client/costs/agents/{}", "x".repeat(65)),
        "/client/costs/providers/a%2Fb",
        "/client/costs/providers/p q",
        &format!("/client/costs/providers/{}", "p".repeat(65)),
    ];
    for path in bad_ids {
        let env = api.handle(get(path));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{path}");
    }
    let bad_bodies = [
        json!({ "since": "yesterday" }),
        json!({ "until": "2026-09-01" }),
        json!({ "since": "2026-10-01T00:00:00Z", "until": "2026-09-01T00:00:00Z" }),
        json!({ "since": "2026-09-01T00:00:00Z", "extra": true }),
        json!({ "since": 17 }),
        json!("2026-09-01T00:00:00Z"),
        json!([]),
    ];
    for body in bad_bodies {
        for path in ALL_PATHS {
            let env = api.handle(get_with_body(path, body.clone()));
            assert_eq!(
                code(&env),
                Some(ClientErrorCode::InvalidRequest),
                "{path} {body}"
            );
        }
    }
    assert_eq!(provider.calls.agent_totals.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.agent_report.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.provider_totals.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.provider_report.load(Ordering::SeqCst), 0);

    // Provider ids may carry `.`/`:`; agent ids may not.
    assert!(api
        .handle(get("/client/costs/providers/local.ollama:11434"))
        .is_ok());
    assert_eq!(
        code(&api.handle(get("/client/costs/agents/local.ollama"))),
        Some(ClientErrorCode::InvalidRequest)
    );
}

// ── CO-06: provider errors project to stable codes with fixed messages ──────────────────────
#[test]
fn co06_provider_errors_project_to_fixed_client_errors() {
    let (api, _sink) = api_with(MemoryCosts::failing(ProviderError::Unavailable(
        "sqlite pool exhausted /var/db/events.db".into(),
    )));
    operator(&api);
    for path in ALL_PATHS {
        let env = api.handle(get(path));
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{path}"
        );
        let msg = env.error.as_ref().unwrap().message.clone();
        assert!(!msg.contains("sqlite") && !msg.contains("/var"), "{msg}");
    }

    // A panicking provider never escapes the pipeline as a crash.
    let (api, _sink) = api_with(MemoryCosts::panicking());
    operator(&api);
    for path in ALL_PATHS {
        let env = api.handle(get(path));
        assert!(env.error.is_some(), "{path}");
        assert!(env.data.is_none(), "{path}");
        let msg = env.error.as_ref().unwrap().message.clone();
        assert!(!msg.contains("exploded"), "{msg}");
    }
}

// ── CO-07: every costs DTO is a CONTRACT-192 component and classified for the AC-14 gate ────
#[test]
fn co07_schema_components_registered_and_classified() {
    let artifact = generate_schema_artifact();
    let components = artifact.schema["components"]
        .as_object()
        .expect("components object");
    let response = [
        "ClientCostWindow",
        "ClientCostTotals",
        "ClientAgentCostEntry",
        "ClientProviderCostEntry",
        "ClientAgentCostReport",
        "ClientProviderCostReport",
        "ClientAgentCostList",
        "ClientProviderCostList",
    ];
    for r in response {
        assert!(components.contains_key(r), "{r} in schema");
        assert!(RESPONSE_COMPONENTS.contains(&r), "{r} inventoried");
    }
    assert!(components.contains_key("ClientCostQuery"));
    assert!(EXCLUDED_COMPONENTS.contains(&"ClientCostQuery"));
    // The request DTO is closed (deny_unknown_fields) so a typo'd bound can never silently
    // widen a window to "all history".
    assert_eq!(
        components["ClientCostQuery"]["additionalProperties"],
        json!(false)
    );
}
