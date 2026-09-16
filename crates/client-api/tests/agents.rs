//! CONTRACT-190 agents family — the operator-facing agent CRUD surface
//! (`/client/agents`, `/client/agents/{agent_id}`, `:update`, `:delete`, `/client/agent-templates`).
//!
//! These tests drive the REAL, unmodified `ClientApi::handle()` pipeline (admission, version,
//! session, scope gate, idempotency reserve/replay/conflict, CSRF, handler-side request validation,
//! provider-error projection, warnings, audit family) against a recording in-memory
//! `AgentAdminProvider`. The provider is a port fixture, not a claim about the real agent tree —
//! the production adapter over the real cap-lifecycle tree + filesystem is witnessed in
//! `crates/cli/tests/client_api_agents_admin.rs`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use advance_client_api::agents::{
    ClientAgentCapability, ClientAgentConfig, ClientAgentDeclaredChild, ClientAgentDeleteResult,
    ClientAgentDetail, ClientAgentLlm, ClientAgentSummary, ClientAgentTemplate,
    ClientCreateAgentRequest, ClientDeleteAgentRequest, ClientUpdateAgentRequest,
    MAX_AGENT_CONFIG_BYTES, MAX_DISPLAY_NAME_BYTES, MAX_REQUESTED_CAPABILITIES,
    MAX_WORKSPACE_PATH_DEPTH, WARNING_RESTART_REQUIRED,
};
use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::{
    response_field_inventory, EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS,
};
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    AgentAdminProvider, ClientApi, ClientApiConfig, ClientCapParam, ClientEnvelope,
    ClientErrorCode, ClientRequest, ClientSession, Platform, Principal, ProviderError, Scope,
    UNKNOWN_PROVIDER_DETAIL,
};

// ── Recording in-memory provider ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AgentRecord {
    summary: ClientAgentSummary,
    config_yaml: Option<String>,
    capabilities: Vec<String>,
    children: Vec<String>,
    llm: Option<ClientAgentLlm>,
}

#[derive(Default)]
struct Calls {
    list: AtomicUsize,
    get: AtomicUsize,
    create: AtomicUsize,
    update: AtomicUsize,
    delete: AtomicUsize,
    templates: AtomicUsize,
}

struct MemoryAgentAdmin {
    agents: Mutex<BTreeMap<String, AgentRecord>>,
    calls: Calls,
    /// The last create request the provider received (proves the validated DTO reaches it).
    last_create: Mutex<Option<ClientCreateAgentRequest>>,
    last_update: Mutex<Option<(String, ClientUpdateAgentRequest)>>,
    last_delete: Mutex<Option<(String, ClientDeleteAgentRequest)>>,
    panic_on_list: bool,
}

impl MemoryAgentAdmin {
    fn new() -> Arc<Self> {
        let mut agents = BTreeMap::new();
        agents.insert(
            "default-agent".to_string(),
            AgentRecord {
                summary: ClientAgentSummary {
                    agent_id: "default-agent".into(),
                    kind: "root".into(),
                    parent: None,
                    status: "active".into(),
                    workspace_path: ".".into(),
                    template_ref: None,
                    display_name: Some("Home".into()),
                },
                config_yaml: Some("capabilities:\n  fs: true\n  llm: true\n".into()),
                capabilities: vec!["fs".into(), "llm".into()],
                children: vec!["research".into()],
                llm: None,
            },
        );
        agents.insert(
            "research".to_string(),
            AgentRecord {
                summary: ClientAgentSummary {
                    agent_id: "research".into(),
                    kind: "child".into(),
                    parent: Some("default-agent".into()),
                    status: "active".into(),
                    workspace_path: "research".into(),
                    template_ref: Some("explorer".into()),
                    display_name: None,
                },
                config_yaml: None,
                capabilities: vec!["fs".into()],
                children: vec![],
                llm: Some(ClientAgentLlm {
                    provider: Some("local".into()),
                    model: Some("tiny".into()),
                    constraint: None,
                }),
            },
        );
        Arc::new(Self {
            agents: Mutex::new(agents),
            calls: Calls::default(),
            last_create: Mutex::new(None),
            last_update: Mutex::new(None),
            last_delete: Mutex::new(None),
            panic_on_list: false,
        })
    }

    fn panicking() -> Arc<Self> {
        Arc::new(Self {
            agents: Mutex::new(BTreeMap::new()),
            calls: Calls::default(),
            last_create: Mutex::new(None),
            last_update: Mutex::new(None),
            last_delete: Mutex::new(None),
            panic_on_list: true,
        })
    }

    fn detail(rec: &AgentRecord) -> ClientAgentDetail {
        ClientAgentDetail {
            agent: rec.summary.clone(),
            config: ClientAgentConfig {
                config_yaml: rec.config_yaml.clone(),
                capabilities: vec![ClientAgentCapability {
                    name: "fs".into(),
                    enabled: true,
                    auto_grant: true,
                    params: vec![ClientCapParam {
                        key: "paths".into(),
                        value: "[\"/\"]".into(),
                    }],
                }],
                declared_children: vec![ClientAgentDeclaredChild {
                    alias: "research".into(),
                    template: "explorer".into(),
                    target_path: "research".into(),
                    capabilities: vec!["fs".into()],
                    children: vec![],
                }],
                llm: rec.llm.clone(),
            },
            capabilities: rec.capabilities.clone(),
            children: rec.children.clone(),
            driver_present: rec.summary.kind == "root",
        }
    }
}

impl AgentAdminProvider for MemoryAgentAdmin {
    fn list_agents(&self) -> Result<Vec<ClientAgentSummary>, ProviderError> {
        self.calls.list.fetch_add(1, Ordering::SeqCst);
        if self.panic_on_list {
            panic!("provider exploded");
        }
        Ok(self
            .agents
            .lock()
            .unwrap()
            .values()
            .map(|r| r.summary.clone())
            .collect())
    }

    fn get_agent(&self, agent_id: &str) -> Result<ClientAgentDetail, ProviderError> {
        self.calls.get.fetch_add(1, Ordering::SeqCst);
        self.agents
            .lock()
            .unwrap()
            .get(agent_id)
            .map(Self::detail)
            .ok_or_else(|| ProviderError::NotFound("agent".into()))
    }

    fn create_agent(
        &self,
        request: &ClientCreateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        self.calls.create.fetch_add(1, Ordering::SeqCst);
        *self.last_create.lock().unwrap() = Some(request.clone());
        let mut agents = self.agents.lock().unwrap();
        if agents.contains_key(&request.agent_id) {
            return Err(ProviderError::AlreadyExists("agent".into()));
        }
        let parent = request
            .parent
            .clone()
            .unwrap_or_else(|| "default-agent".to_string());
        if !agents.contains_key(&parent) {
            return Err(ProviderError::NotFound("parent".into()));
        }
        if request.template_ref == "no-such-template" {
            return Err(ProviderError::InvalidRequest("template".into()));
        }
        if let Some(llm) = &request.llm {
            if llm.provider.as_deref() == Some("ghost") {
                return Err(ProviderError::UnknownProvider("ghost".into()));
            }
        }
        let rec = AgentRecord {
            summary: ClientAgentSummary {
                agent_id: request.agent_id.clone(),
                kind: "child".into(),
                parent: Some(parent.clone()),
                status: "active".into(),
                workspace_path: request
                    .workspace_path
                    .clone()
                    .unwrap_or_else(|| request.agent_id.clone()),
                template_ref: Some(request.template_ref.clone()),
                display_name: request.display_name.clone(),
            },
            config_yaml: request.config_yaml.clone(),
            capabilities: request.capabilities.clone(),
            children: vec![],
            llm: request.llm.clone().filter(|l| !l.is_empty()),
        };
        let detail = Self::detail(&rec);
        agents.insert(request.agent_id.clone(), rec);
        if let Some(p) = agents.get_mut(&parent) {
            p.children.push(request.agent_id.clone());
        }
        Ok(detail)
    }

    fn update_agent(
        &self,
        agent_id: &str,
        request: &ClientUpdateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        self.calls.update.fetch_add(1, Ordering::SeqCst);
        *self.last_update.lock().unwrap() = Some((agent_id.to_string(), request.clone()));
        let mut agents = self.agents.lock().unwrap();
        let rec = agents
            .get_mut(agent_id)
            .ok_or_else(|| ProviderError::NotFound("agent".into()))?;
        if request.config_yaml.as_deref() == Some("not: [valid") {
            return Err(ProviderError::InvalidRequest("yaml".into()));
        }
        if let Some(name) = &request.display_name {
            rec.summary.display_name = Some(name.clone());
        }
        if let Some(yaml) = &request.config_yaml {
            rec.config_yaml = Some(yaml.clone());
        }
        if let Some(caps) = &request.capabilities {
            if rec.summary.kind == "root" {
                return Err(ProviderError::InvalidRequest("root".into()));
            }
            if caps.iter().any(|c| c != "fs" && c != "llm") {
                return Err(ProviderError::InvalidRequest("subset".into()));
            }
            rec.capabilities = caps.clone();
        }
        if let Some(llm) = &request.llm {
            if llm.provider.as_deref() == Some("ghost") {
                return Err(ProviderError::UnknownProvider("ghost".into()));
            }
            rec.llm = if llm.is_empty() {
                None
            } else {
                Some(llm.clone())
            };
        }
        Ok(Self::detail(rec))
    }

    fn delete_agent(
        &self,
        agent_id: &str,
        request: &ClientDeleteAgentRequest,
    ) -> Result<ClientAgentDeleteResult, ProviderError> {
        self.calls.delete.fetch_add(1, Ordering::SeqCst);
        *self.last_delete.lock().unwrap() = Some((agent_id.to_string(), request.clone()));
        let mut agents = self.agents.lock().unwrap();
        let rec = agents
            .get(agent_id)
            .cloned()
            .ok_or_else(|| ProviderError::NotFound("agent".into()))?;
        if rec.summary.kind == "root" {
            return Err(ProviderError::InvalidRequest("root".into()));
        }
        agents.remove(agent_id);
        for other in agents.values_mut() {
            other.children.retain(|c| c != agent_id);
        }
        Ok(ClientAgentDeleteResult {
            agent_id: agent_id.to_string(),
            removed_agent_ids: vec![agent_id.to_string()],
            workspace_removed: request.remove_workspace,
        })
    }

    fn list_templates(&self) -> Result<Vec<ClientAgentTemplate>, ProviderError> {
        self.calls.templates.fetch_add(1, Ordering::SeqCst);
        Ok(vec![
            ClientAgentTemplate {
                template_ref: "explorer".into(),
                description: Some("Read-only exploration sub-agent".into()),
            },
            ClientAgentTemplate {
                template_ref: "planner".into(),
                description: None,
            },
        ])
    }
}

// ── Scaffolding ──────────────────────────────────────────────────────────────────────────────

fn api_with(provider: Arc<dyn AgentAdminProvider>) -> (ClientApi, RecordingSink) {
    let sink = RecordingSink::new();
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink.clone()),
    )
    .with_agent_provider(provider);
    (api, sink)
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>, csrf: Option<&str>) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: if csrf.is_some() {
                Platform::Web
            } else {
                Platform::Mac
            },
            scopes,
            csrf_token: csrf.map(str::to_string),
            expires_at: u64::MAX,
        },
        0,
    );
}

fn operator(api: &ClientApi) {
    mint(api, "tok", Scope::operator_default(), None);
}

fn create_body() -> Value {
    json!({
        "agent_id": "writer",
        "parent": "default-agent",
        "workspace_path": "teams/writer",
        "template_ref": "explorer",
        "capabilities": ["fs", "llm"],
        "display_name": "Writer"
    })
}

fn post(path: &str, body: Value, key: &str) -> ClientRequest {
    ClientRequest::post(path, body)
        .with_session("tok")
        .with_idempotency_key(key)
}

fn get(path: &str) -> ClientRequest {
    ClientRequest::get(path).with_session("tok")
}

fn code(env: &ClientEnvelope<Value>) -> Option<ClientErrorCode> {
    env.error_code()
}

fn detail(env: &ClientEnvelope<Value>) -> ClientAgentDetail {
    assert!(env.is_ok(), "expected ok envelope, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("ClientAgentDetail parses")
}

fn has_warning(env: &ClientEnvelope<Value>, warning: &str) -> bool {
    env.warnings.iter().any(|w| w.code == warning)
}

// ── AG-01: routes are always registered; an absent provider is module_unavailable ────────────
#[test]
fn ag01_absent_provider_is_module_unavailable_not_unknown_route() {
    let api = ClientApi::new(ClientApiConfig::default());
    operator(&api);
    let probes = vec![
        get(routes::PATH_AGENTS),
        get(routes::PATH_AGENT_TEMPLATES),
        get("/client/agents/research"),
        post(routes::PATH_AGENTS, create_body(), "k-create"),
        post(
            "/client/agents/research:update",
            json!({ "display_name": "R" }),
            "k-update",
        ),
        post("/client/agents/research:delete", Value::Null, "k-delete"),
    ];
    for req in probes {
        let path = req.path.clone();
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{path}: absent agents provider must be module_unavailable (never unknown_route)"
        );
    }
    // The family is genuinely routed: an unrelated path under it is still unknown_route.
    let env = api.handle(post(
        "/client/agents/research:frobnicate",
        Value::Null,
        "k-x",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::UnknownRoute));
    // Non-canonical path forms never match the templated family.
    let env = api.handle(get("//client/agents/research"));
    assert_eq!(code(&env), Some(ClientErrorCode::UnknownRoute));
}

// ── AG-02: list projects the provider summaries verbatim ─────────────────────────────────────
#[test]
fn ag02_list_agents_projects_summaries() {
    let provider = MemoryAgentAdmin::new();
    let (api, sink) = api_with(provider.clone());
    operator(&api);
    let env = api.handle(get(routes::PATH_AGENTS));
    assert!(env.is_ok(), "{:?}", env.error);
    let agents: Vec<ClientAgentSummary> =
        serde_json::from_value(env.data.clone().unwrap()["agents"].clone()).unwrap();
    assert_eq!(agents.len(), 2);
    let root = agents
        .iter()
        .find(|a| a.agent_id == "default-agent")
        .unwrap();
    assert_eq!(root.kind, "root");
    assert_eq!(root.workspace_path, ".");
    assert_eq!(root.display_name.as_deref(), Some("Home"));
    assert!(root.parent.is_none());
    let child = agents.iter().find(|a| a.agent_id == "research").unwrap();
    assert_eq!(child.parent.as_deref(), Some("default-agent"));
    assert_eq!(child.template_ref.as_deref(), Some("explorer"));
    // Optional fields are OMITTED (never null) on the wire.
    let raw = &env.data.as_ref().unwrap()["agents"];
    let child_raw = raw
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["agent_id"] == "research")
        .unwrap();
    assert!(child_raw.get("display_name").is_none());
    assert_eq!(provider.calls.list.load(Ordering::SeqCst), 1);
    // Audit family label is the resource family, never a secret.
    assert!(sink
        .events()
        .iter()
        .any(|e| e.kind == "client_api.response" && e.family == "agents"));
}

// ── AG-03: get returns the detail document; unknown id is not_found ──────────────────────────
#[test]
fn ag03_get_agent_detail_and_not_found() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    let env = api.handle(get("/client/agents/default-agent"));
    let d = detail(&env);
    assert_eq!(d.agent.agent_id, "default-agent");
    assert_eq!(d.children, vec!["research".to_string()]);
    assert!(d.driver_present);
    assert_eq!(
        d.config.config_yaml.as_deref(),
        Some("capabilities:\n  fs: true\n  llm: true\n")
    );
    assert_eq!(d.config.capabilities[0].name, "fs");
    assert!(d.config.capabilities[0].enabled && d.config.capabilities[0].auto_grant);
    assert_eq!(d.config.capabilities[0].params[0].key, "paths");
    assert_eq!(d.config.declared_children[0].alias, "research");
    assert_eq!(d.config.declared_children[0].target_path, "research");

    let env = api.handle(get("/client/agents/nope"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));
    assert_eq!(
        env.error.as_ref().unwrap().message,
        "resource not found",
        "provider reason strings never reach the client"
    );
    assert_eq!(provider.calls.get.load(Ordering::SeqCst), 2);
}

// ── AG-04: create runs the full mutation pipeline and reaches the provider ────────────────────
#[test]
fn ag04_create_agent_full_pipeline() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(routes::PATH_AGENTS, create_body(), "k-create"));
    let d = detail(&env);
    assert_eq!(d.agent.agent_id, "writer");
    assert_eq!(d.agent.kind, "child");
    assert_eq!(d.agent.parent.as_deref(), Some("default-agent"));
    assert_eq!(d.agent.workspace_path, "teams/writer");
    assert_eq!(d.agent.display_name.as_deref(), Some("Writer"));
    assert!(
        !has_warning(&env, WARNING_RESTART_REQUIRED),
        "no config document ⇒ no restart warning"
    );
    let received = provider.last_create.lock().unwrap().clone().unwrap();
    assert_eq!(
        received.capabilities,
        vec!["fs".to_string(), "llm".to_string()]
    );
    assert_eq!(received.template_ref, "explorer");
    assert_eq!(received.workspace_path.as_deref(), Some("teams/writer"));
    assert!(received.config_yaml.is_none());

    // A create carrying a config document is honest about when it applies.
    let mut body = create_body();
    body["agent_id"] = json!("editor");
    body["config_yaml"] = json!("capabilities:\n  fs: true\n");
    let env = api.handle(post(routes::PATH_AGENTS, body, "k-create-2"));
    let d = detail(&env);
    assert_eq!(d.agent.agent_id, "editor");
    assert!(has_warning(&env, WARNING_RESTART_REQUIRED));
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 2);

    // Both now appear in the list.
    let env = api.handle(get(routes::PATH_AGENTS));
    let ids: Vec<String> = env.data.unwrap()["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["agent_id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&"writer".to_string()) && ids.contains(&"editor".to_string()));
}

// ── AG-05: create is gated (idempotency key, ControlRuns scope, session) BEFORE the provider ──
#[test]
fn ag05_create_requires_idempotency_key_scope_and_session() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    mint(&api, "reader", vec![Scope::ReadRuns], None);

    let env =
        api.handle(ClientRequest::post(routes::PATH_AGENTS, create_body()).with_session("tok"));
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyRequired));

    let env = api.handle(
        ClientRequest::post(routes::PATH_AGENTS, create_body())
            .with_session("reader")
            .with_idempotency_key("k"),
    );
    assert_eq!(
        code(&env),
        Some(ClientErrorCode::Forbidden),
        "ReadRuns alone must not create agents"
    );

    let env = api
        .handle(ClientRequest::post(routes::PATH_AGENTS, create_body()).with_idempotency_key("k"));
    assert_eq!(code(&env), Some(ClientErrorCode::Unauthenticated));

    for (path, body) in [
        (
            "/client/agents/research:update",
            json!({"display_name": "x"}),
        ),
        ("/client/agents/research:delete", Value::Null),
    ] {
        let env = api.handle(
            ClientRequest::post(path, body)
                .with_session("reader")
                .with_idempotency_key("k2"),
        );
        assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{path}");
    }
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.delete.load(Ordering::SeqCst), 0);
}

// ── AG-06: idempotent replay never re-executes; a different body under one key conflicts ─────
#[test]
fn ag06_create_replay_is_idempotent_and_conflicts_on_different_body() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    let first = api.handle(post(routes::PATH_AGENTS, create_body(), "same-key"));
    assert!(first.is_ok(), "{:?}", first.error);
    let replay = api.handle(post(routes::PATH_AGENTS, create_body(), "same-key"));
    assert!(replay.is_ok());
    assert_eq!(replay.request_id, first.request_id);
    assert!(has_warning(&replay, "idempotent_replay"));
    assert_eq!(
        provider.calls.create.load(Ordering::SeqCst),
        1,
        "replay must not re-enter the provider"
    );
    let mut other = create_body();
    other["agent_id"] = json!("someone-else");
    let conflict = api.handle(post(routes::PATH_AGENTS, other, "same-key"));
    assert_eq!(code(&conflict), Some(ClientErrorCode::IdempotencyConflict));
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 1);
}

// ── AG-07: handler-side validation rejects bad input before any provider call ────────────────
#[test]
fn ag07_create_validation_rejects_bad_input_before_provider() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    let mut n = 0;
    let mut expect = |mutate: &dyn Fn(&mut Value), expected: ClientErrorCode, label: &str| {
        n += 1;
        let mut body = create_body();
        mutate(&mut body);
        let env = api.handle(post(routes::PATH_AGENTS, body, &format!("k-bad-{n}")));
        assert_eq!(code(&env), Some(expected), "{label}: {:?}", env.error);
    };
    let ir = ClientErrorCode::InvalidRequest;
    expect(&|b| b["agent_id"] = json!(""), ir.clone(), "empty id");
    expect(
        &|b| b["agent_id"] = json!("bad id"),
        ir.clone(),
        "space in id",
    );
    expect(
        &|b| b["agent_id"] = json!("a".repeat(65)),
        ir.clone(),
        "over-long id",
    );
    expect(
        &|b| b["agent_id"] = json!("../x"),
        ir.clone(),
        "traversal id",
    );
    expect(
        &|b| b["agent_id"] = json!("agent:x"),
        ir.clone(),
        "colon id",
    );
    expect(
        &|b| b["parent"] = json!("no way"),
        ir.clone(),
        "bad parent id",
    );
    expect(
        &|b| b["workspace_path"] = json!("../escape"),
        ir.clone(),
        "parent-dir path",
    );
    expect(
        &|b| b["workspace_path"] = json!("/abs"),
        ir.clone(),
        "absolute path",
    );
    expect(
        &|b| b["workspace_path"] = json!("a//b"),
        ir.clone(),
        "empty component",
    );
    expect(
        &|b| b["workspace_path"] = json!("a/./b"),
        ir.clone(),
        "cur-dir component",
    );
    expect(
        &|b| b["workspace_path"] = json!(".agent/x"),
        ir.clone(),
        "hidden component",
    );
    expect(
        &|b| b["workspace_path"] = json!("a\\b"),
        ir.clone(),
        "backslash",
    );
    expect(
        &|b| b["workspace_path"] = json!(""),
        ir.clone(),
        "empty path",
    );
    expect(
        &|b| b["workspace_path"] = json!(vec!["d"; MAX_WORKSPACE_PATH_DEPTH + 1].join("/")),
        ir.clone(),
        "over-deep path",
    );
    expect(
        &|b| b["template_ref"] = json!(""),
        ir.clone(),
        "empty template",
    );
    expect(
        &|b| b["template_ref"] = json!("../t"),
        ir.clone(),
        "traversal template",
    );
    expect(
        &|b| b["template_ref"] = json!("t t"),
        ir.clone(),
        "space in template",
    );
    expect(
        &|b| b["capabilities"] = json!(["fs", "fs"]),
        ir.clone(),
        "duplicate cap",
    );
    expect(
        &|b| b["capabilities"] = json!(["cap:x"]),
        ir.clone(),
        "bad cap charset",
    );
    expect(
        &|b| {
            b["capabilities"] = json!((0..=MAX_REQUESTED_CAPABILITIES)
                .map(|i| format!("c{i}"))
                .collect::<Vec<_>>())
        },
        ir.clone(),
        "too many caps",
    );
    expect(
        &|b| b["display_name"] = json!("   "),
        ir.clone(),
        "blank display name",
    );
    expect(
        &|b| b["display_name"] = json!("a\nb"),
        ir.clone(),
        "control char in name",
    );
    expect(
        &|b| b["display_name"] = json!("n".repeat(MAX_DISPLAY_NAME_BYTES + 1)),
        ir.clone(),
        "over-long display name",
    );
    expect(
        &|b| b["config_yaml"] = json!("a: b\0c"),
        ir.clone(),
        "NUL in config",
    );
    expect(
        &|b| b["config_yaml"] = json!("#".repeat(MAX_AGENT_CONFIG_BYTES + 1)),
        ClientErrorCode::RequestTooLarge,
        "oversize config",
    );
    expect(&|b| b["surprise"] = json!(1), ir.clone(), "unknown field");
    expect(&|b| b["agent_id"] = json!(42), ir.clone(), "wrong type");
    expect(
        &|b| {
            b.as_object_mut().unwrap().remove("template_ref");
        },
        ir.clone(),
        "missing template",
    );
    let env = api.handle(post(
        routes::PATH_AGENTS,
        json!("not an object"),
        "k-scalar",
    ));
    assert_eq!(code(&env), Some(ir.clone()));
    let env = api.handle(post(routes::PATH_AGENTS, Value::Null, "k-null"));
    assert_eq!(code(&env), Some(ir));
    assert_eq!(
        provider.calls.create.load(Ordering::SeqCst),
        0,
        "no invalid request may reach the provider"
    );
    // Validation failures release the reservation: the same key is usable afterwards.
    let env = api.handle(post(routes::PATH_AGENTS, create_body(), "k-bad-1"));
    assert!(env.is_ok(), "{:?}", env.error);
}

// ── AG-08: provider-side outcomes project to stable codes with fixed messages ─────────────────
#[test]
fn ag08_provider_errors_project_to_stable_codes() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    let mut body = create_body();
    body["agent_id"] = json!("research");
    let env = api.handle(post(routes::PATH_AGENTS, body, "k-dup"));
    assert_eq!(code(&env), Some(ClientErrorCode::AlreadyExists));
    assert_eq!(
        env.error.as_ref().unwrap().message,
        "resource already exists"
    );

    let mut body = create_body();
    body["parent"] = json!("ghost");
    let env = api.handle(post(routes::PATH_AGENTS, body, "k-ghost"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));

    let mut body = create_body();
    body["template_ref"] = json!("no-such-template");
    let env = api.handle(post(routes::PATH_AGENTS, body, "k-tpl"));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(env.error.as_ref().unwrap().message, "invalid request");

    // A provider rejection AFTER provider entry is recorded and replayed, never re-executed.
    let replay = api.handle(post(
        routes::PATH_AGENTS,
        {
            let mut b = create_body();
            b["agent_id"] = json!("research");
            b
        },
        "k-dup",
    ));
    assert_eq!(code(&replay), Some(ClientErrorCode::AlreadyExists));
    assert!(has_warning(&replay, "idempotent_replay"));
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 3);
}

// ── AG-09: update pipeline ───────────────────────────────────────────────────────────────────
#[test]
fn ag09_update_agent_pipeline() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);

    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "display_name": "Research Desk" }),
        "k-u1",
    ));
    let d = detail(&env);
    assert_eq!(d.agent.display_name.as_deref(), Some("Research Desk"));
    assert!(!has_warning(&env, WARNING_RESTART_REQUIRED));
    let (id, req) = provider.last_update.lock().unwrap().clone().unwrap();
    assert_eq!(id, "research");
    assert_eq!(req.display_name.as_deref(), Some("Research Desk"));

    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "config_yaml": "capabilities:\n  fs: true\n  memory: true\n" }),
        "k-u2",
    ));
    let d = detail(&env);
    assert_eq!(
        d.config.config_yaml.as_deref(),
        Some("capabilities:\n  fs: true\n  memory: true\n")
    );
    assert!(
        has_warning(&env, WARNING_RESTART_REQUIRED),
        "a config document change applies at the next daemon start"
    );

    let env = api.handle(post("/client/agents/research:update", json!({}), "k-u3"));
    assert_eq!(
        code(&env),
        Some(ClientErrorCode::InvalidRequest),
        "an empty update is rejected before the provider"
    );
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "display_name": "" }),
        "k-u4",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "config_yaml": "x".repeat(MAX_AGENT_CONFIG_BYTES + 1) }),
        "k-u5",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::RequestTooLarge));
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "config_yaml": "not: [valid" }),
        "k-u6",
    ));
    assert_eq!(
        code(&env),
        Some(ClientErrorCode::InvalidRequest),
        "provider-side document validation projects to invalid_request"
    );
    let env = api.handle(post(
        "/client/agents/ghost:update",
        json!({ "display_name": "x" }),
        "k-u7",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "display_name": "x", "bogus": true }),
        "k-u8",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), 4);
}

// ── AG-10: delete pipeline ───────────────────────────────────────────────────────────────────
#[test]
fn ag10_delete_agent_pipeline() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);

    let env = api.handle(post(
        "/client/agents/default-agent:delete",
        Value::Null,
        "k-d-root",
    ));
    assert_eq!(
        code(&env),
        Some(ClientErrorCode::InvalidRequest),
        "root deletion is rejected by the provider"
    );

    let env = api.handle(post("/client/agents/research:delete", Value::Null, "k-d1"));
    assert!(env.is_ok(), "{:?}", env.error);
    let result: ClientAgentDeleteResult = serde_json::from_value(env.data.unwrap()).unwrap();
    assert_eq!(result.agent_id, "research");
    assert_eq!(result.removed_agent_ids, vec!["research".to_string()]);
    assert!(
        !result.workspace_removed,
        "null body ⇒ remove_workspace=false"
    );
    let (_, req) = provider.last_delete.lock().unwrap().clone().unwrap();
    assert!(!req.remove_workspace);

    let env = api.handle(post("/client/agents/research:delete", Value::Null, "k-d2"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound), "already gone");

    // Re-create then delete with the workspace.
    let mut body = create_body();
    body["agent_id"] = json!("research");
    assert!(api
        .handle(post(routes::PATH_AGENTS, body, "k-recreate"))
        .is_ok());
    let env = api.handle(post(
        "/client/agents/research:delete",
        json!({ "remove_workspace": true }),
        "k-d3",
    ));
    let result: ClientAgentDeleteResult = serde_json::from_value(env.data.unwrap()).unwrap();
    assert!(result.workspace_removed);

    let env = api.handle(post(
        "/client/agents/research:delete",
        json!({ "remove_workspace": "yes" }),
        "k-d4",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    let env = api.handle(post(
        "/client/agents/research:delete",
        json!({ "nuke": true }),
        "k-d5",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(provider.calls.delete.load(Ordering::SeqCst), 4);
}

// ── AG-11: template listing ──────────────────────────────────────────────────────────────────
#[test]
fn ag11_templates_list() {
    let provider = MemoryAgentAdmin::new();
    let (api, sink) = api_with(provider.clone());
    operator(&api);
    mint(&api, "nope", vec![Scope::ReadMessages], None);
    let env = api.handle(get(routes::PATH_AGENT_TEMPLATES));
    assert!(env.is_ok(), "{:?}", env.error);
    let templates: Vec<ClientAgentTemplate> =
        serde_json::from_value(env.data.clone().unwrap()["templates"].clone()).unwrap();
    assert_eq!(templates.len(), 2);
    assert_eq!(templates[0].template_ref, "explorer");
    assert!(templates[0].description.is_some());
    assert!(env.data.unwrap()["templates"][1]
        .get("description")
        .is_none());
    let env = api.handle(ClientRequest::get(routes::PATH_AGENT_TEMPLATES).with_session("nope"));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
    assert_eq!(provider.calls.templates.load(Ordering::SeqCst), 1);
    assert!(sink
        .events()
        .iter()
        .any(|e| e.family == "agent-templates" && e.kind == "client_api.response"));
}

// ── AG-12: browser sessions need CSRF for every agent mutation ───────────────────────────────
#[test]
fn ag12_browser_mutation_requires_csrf() {
    let provider = MemoryAgentAdmin::new();
    let mut config = ClientApiConfig::default();
    config.allowed_origins = vec!["http://127.0.0.1:1".into()];
    let api = ClientApi::new(config).with_agent_provider(provider.clone());
    mint(&api, "web", Scope::operator_default(), Some("csrf-secret"));
    let origin = "http://127.0.0.1:1";

    let env = api.handle(
        ClientRequest::post(routes::PATH_AGENTS, create_body())
            .with_session("web")
            .with_origin(origin)
            .with_idempotency_key("k-csrf-1"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::CsrfRequired));
    let env = api.handle(
        ClientRequest::post(routes::PATH_AGENTS, create_body())
            .with_session("web")
            .with_origin(origin)
            .with_csrf("wrong")
            .with_idempotency_key("k-csrf-2"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::CsrfInvalid));
    let env = api.handle(
        ClientRequest::post(routes::PATH_AGENTS, create_body())
            .with_session("web")
            .with_origin(origin)
            .with_csrf("csrf-secret")
            .with_idempotency_key("k-csrf-3"),
    );
    assert!(env.is_ok(), "{:?}", env.error);
    // Reads over a browser origin need no CSRF.
    let env = api.handle(
        ClientRequest::get(routes::PATH_AGENTS)
            .with_session("web")
            .with_origin(origin),
    );
    assert!(env.is_ok());
    assert_eq!(provider.calls.create.load(Ordering::SeqCst), 1);
}

// ── AG-13: reads require ReadRuns ────────────────────────────────────────────────────────────
#[test]
fn ag13_reads_require_read_runs_scope() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    mint(&api, "ctl", vec![Scope::ControlRuns], None);
    for path in [
        routes::PATH_AGENTS,
        "/client/agents/research",
        routes::PATH_AGENT_TEMPLATES,
    ] {
        let env = api.handle(ClientRequest::get(path).with_session("ctl"));
        assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{path}");
    }
    assert_eq!(provider.calls.list.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.get.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.templates.load(Ordering::SeqCst), 0);
}

// ── AG-14: a path-bound agent id is validated before the provider sees it ────────────────────
#[test]
fn ag14_path_param_validation_never_reaches_provider() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    for path in [
        "/client/agents/..",
        "/client/agents/bad%20id",
        "/client/agents/agent:x",
    ] {
        let env = api.handle(get(path));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{path}");
    }
    let env = api.handle(post("/client/agents/..:delete", Value::Null, "k-p1"));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    let env = api.handle(post(
        "/client/agents/bad id:update",
        json!({ "display_name": "x" }),
        "k-p2",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(provider.calls.get.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.delete.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), 0);
}

// ── AG-15: a panicking provider degrades to module_unavailable ───────────────────────────────
#[test]
fn ag15_provider_panic_is_module_unavailable() {
    let (api, _) = api_with(MemoryAgentAdmin::panicking());
    operator(&api);
    let env = api.handle(get(routes::PATH_AGENTS));
    assert_eq!(code(&env), Some(ClientErrorCode::ModuleUnavailable));
}

// ── AG-16: contract surface — error codes, schema components, compat partition ───────────────
#[test]
fn ag16_contract_surface_registered() {
    for c in ["already_exists", "invalid_request"] {
        assert!(ClientErrorCode::known_codes().contains(&c), "{c}");
    }
    assert_eq!(ClientErrorCode::AlreadyExists.as_str(), "already_exists");
    assert_eq!(ClientErrorCode::InvalidRequest.as_str(), "invalid_request");
    let already = ProviderError::AlreadyExists("x".into()).into_client_error();
    assert_eq!(already.code, ClientErrorCode::AlreadyExists);
    assert_eq!(already.message, "resource already exists");
    let invalid = ProviderError::InvalidRequest("x".into()).into_client_error();
    assert_eq!(invalid.code, ClientErrorCode::InvalidRequest);
    assert_eq!(invalid.message, "invalid request");

    let art = generate_schema_artifact();
    let comps = art.schema["components"].as_object().unwrap();
    for dto in [
        "ClientAgentSummary",
        "ClientAgentCapability",
        "ClientAgentDeclaredChild",
        "ClientAgentConfig",
        "ClientAgentDetail",
        "ClientAgentDeleteResult",
        "ClientAgentTemplate",
        "ClientCreateAgentRequest",
        "ClientUpdateAgentRequest",
        "ClientDeleteAgentRequest",
        "ClientAgentLlm",
    ] {
        assert!(comps.contains_key(dto), "schema missing {dto}");
    }
    for r in [
        "ClientAgentSummary",
        "ClientAgentDetail",
        "ClientAgentDeleteResult",
        "ClientAgentTemplate",
        "ClientAgentLlm",
    ] {
        assert!(RESPONSE_COMPONENTS.contains(&r), "{r} inventoried");
    }
    for x in [
        "ClientCreateAgentRequest",
        "ClientUpdateAgentRequest",
        "ClientDeleteAgentRequest",
    ] {
        assert!(EXCLUDED_COMPONENTS.contains(&x), "{x} excluded");
    }
    let inventory = response_field_inventory(&art.schema).expect("partition holds");
    let summary = &inventory["ClientAgentSummary"];
    assert!(summary["agent_id"].required);
    assert!(!summary["display_name"].required);
    let deleted = &inventory["ClientAgentDeleteResult"];
    assert_eq!(deleted["removed_agent_ids"].type_token, "array<string>");
    let detail = &inventory["ClientAgentDetail"];
    assert!(detail["capabilities"].required);
    assert_eq!(detail["capabilities"].type_token, "array<string>");
    // The recursive declared-children DTO inventories without looping.
    assert!(inventory["ClientAgentConfig"]
        .keys()
        .any(|k| k.starts_with("declared_children")));
    // The request DTOs reject unknown fields (schema says so too).
    let create = &comps["ClientCreateAgentRequest"];
    assert_eq!(create["additionalProperties"], json!(false));
}

// ── AG-17: late install on a shared Arc flips absent → served ────────────────────────────────
#[test]
fn ag17_late_install_agent_provider() {
    let api = Arc::new(ClientApi::new(ClientApiConfig::default()));
    operator(&api);
    let env = api.handle(get(routes::PATH_AGENTS));
    assert_eq!(code(&env), Some(ClientErrorCode::ModuleUnavailable));
    api.install_agent_provider(MemoryAgentAdmin::new());
    let env = api.handle(get(routes::PATH_AGENTS));
    assert!(env.is_ok(), "{:?}", env.error);
}

// ── AG-18: DTO wire shape round-trips and never serializes absent optionals as null ─────────
#[test]
fn ag18_dto_wire_shape() {
    let req: ClientCreateAgentRequest = serde_json::from_value(json!({
        "agent_id": "a",
        "template_ref": "explorer"
    }))
    .unwrap();
    assert!(req.parent.is_none());
    assert!(req.capabilities.is_empty());
    let d = ClientDeleteAgentRequest::default();
    assert!(!d.remove_workspace);
    let u = ClientUpdateAgentRequest::default();
    assert!(u.display_name.is_none() && u.config_yaml.is_none() && u.capabilities.is_none());
    let summary = ClientAgentSummary {
        agent_id: "a".into(),
        kind: "child".into(),
        parent: None,
        status: "active".into(),
        workspace_path: "a".into(),
        template_ref: None,
        display_name: None,
    };
    let v = serde_json::to_value(&summary).unwrap();
    assert!(v.get("parent").is_none() && v.get("template_ref").is_none());
    let cfg = ClientAgentConfig {
        config_yaml: None,
        capabilities: vec![],
        declared_children: vec![],
        llm: None,
    };
    let v = serde_json::to_value(&cfg).unwrap();
    assert!(v.get("config_yaml").is_none());
    assert!(
        v.get("llm").is_none(),
        "an absent llm block is not serialized as null"
    );
    assert_eq!(v["capabilities"], json!([]));
}

// ── AG-19: persisted capabilities are readable and updatable (restart-applied) ────────────────
#[test]
fn ag19_capabilities_read_and_update() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);
    let d = detail(&api.handle(get("/client/agents/research")));
    assert_eq!(d.capabilities, vec!["fs".to_string()]);
    let root = detail(&api.handle(get("/client/agents/default-agent")));
    assert_eq!(root.capabilities, vec!["fs".to_string(), "llm".to_string()]);
    assert_eq!(
        root.config.declared_children[0].capabilities,
        vec!["fs".to_string()]
    );

    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "capabilities": ["fs", "llm"] }),
        "k-caps-1",
    ));
    let d = detail(&env);
    assert_eq!(d.capabilities, vec!["fs".to_string(), "llm".to_string()]);
    assert!(
        has_warning(&env, WARNING_RESTART_REQUIRED),
        "a persisted capability change applies at the next daemon start"
    );
    let (_, req) = provider.last_update.lock().unwrap().clone().unwrap();
    assert_eq!(
        req.capabilities,
        Some(vec!["fs".to_string(), "llm".to_string()])
    );

    // An empty list is a valid "no capabilities" update.
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "capabilities": [] }),
        "k-caps-2",
    ));
    assert!(detail(&env).capabilities.is_empty());

    // Handler-side validation: charset / duplicates / bound, before the provider.
    let before = provider.calls.update.load(Ordering::SeqCst);
    for (bad, label) in [
        (json!(["cap:x"]), "charset"),
        (json!(["fs", "fs"]), "duplicate"),
        (json!("fs"), "wrong type"),
        (
            json!((0..=MAX_REQUESTED_CAPABILITIES)
                .map(|i| format!("c{i}"))
                .collect::<Vec<_>>()),
            "too many",
        ),
    ] {
        let env = api.handle(post(
            "/client/agents/research:update",
            json!({ "capabilities": bad }),
            &format!("k-caps-bad-{label}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{label}");
    }
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), before);

    // Provider-side outcomes: root refuses, a superset of the parent is refused.
    let env = api.handle(post(
        "/client/agents/default-agent:update",
        json!({ "capabilities": ["fs"] }),
        "k-caps-root",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "capabilities": ["secrets"] }),
        "k-caps-superset",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
}

// ── AG-20 (lane agent-llm-policy): the typed llm block reads, updates, validates, projects ────
#[test]
fn ag20_llm_policy_read_update_and_validation() {
    let provider = MemoryAgentAdmin::new();
    let (api, _) = api_with(provider.clone());
    operator(&api);

    // Read: the block is projected on the detail; an absent block is absent (not null).
    let d = detail(&api.handle(get("/client/agents/research")));
    let llm = d.config.llm.clone().expect("research carries an llm block");
    assert_eq!(llm.provider.as_deref(), Some("local"));
    assert_eq!(llm.model.as_deref(), Some("tiny"));
    assert!(llm.constraint.is_none());
    let env = api.handle(get("/client/agents/default-agent"));
    assert!(env.data.as_ref().unwrap()["config"].get("llm").is_none());

    // Update: whole-block replacement reaches the provider; NO restart warning for llm alone.
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "llm": { "provider": "openai", "constraint": "never-cloud" } }),
        "k-llm-1",
    ));
    let d = detail(&env);
    let llm = d.config.llm.clone().unwrap();
    assert_eq!(llm.provider.as_deref(), Some("openai"));
    assert!(
        llm.model.is_none(),
        "whole-block replacement drops the old model"
    );
    assert_eq!(llm.constraint.as_deref(), Some("never-cloud"));
    assert!(
        !has_warning(&env, WARNING_RESTART_REQUIRED),
        "an llm-only update applies at the next LLM call"
    );
    let (id, req) = provider.last_update.lock().unwrap().clone().unwrap();
    assert_eq!(id, "research");
    assert_eq!(
        req.llm,
        Some(ClientAgentLlm {
            provider: Some("openai".into()),
            model: None,
            constraint: Some("never-cloud".into()),
        })
    );

    // llm + a config document still warns (the document part needs a restart).
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "config_yaml": "capabilities:\n  fs: true\n", "llm": { "model": "tiny" } }),
        "k-llm-2",
    ));
    assert!(env.is_ok());
    assert!(has_warning(&env, WARNING_RESTART_REQUIRED));

    // `{}` clears the block (a non-empty update).
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "llm": {} }),
        "k-llm-3",
    ));
    assert!(detail(&env).config.llm.is_none());

    // Root agent accepts an llm update too.
    let env = api.handle(post(
        "/client/agents/default-agent:update",
        json!({ "llm": { "model": "sonnet" } }),
        "k-llm-root",
    ));
    assert_eq!(
        detail(&env).config.llm.unwrap().model.as_deref(),
        Some("sonnet")
    );

    // Handler-side grammar: rejected BEFORE the provider.
    let before = provider.calls.update.load(Ordering::SeqCst);
    for (bad, label) in [
        (json!({ "provider": "agent:x" }), "provider charset"),
        (json!({ "provider": "" }), "provider empty"),
        (json!({ "model": "a b" }), "model whitespace"),
        (json!({ "model": "x".repeat(129) }), "model bound"),
        (json!({ "constraint": "gpu-only" }), "constraint grammar"),
        (json!({ "constraint": "device:" }), "device empty"),
        (json!({ "constraint": "device:a b" }), "device charset"),
        (json!({ "providr": "x" }), "unknown key"),
        (json!("local"), "wrong type"),
    ] {
        let env = api.handle(post(
            "/client/agents/research:update",
            json!({ "llm": bad }),
            &format!("k-llm-bad-{label}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{label}");
    }
    assert_eq!(provider.calls.update.load(Ordering::SeqCst), before);

    // Provider-side: an unknown provider id is invalid_request + the stable detail token.
    let env = api.handle(post(
        "/client/agents/research:update",
        json!({ "llm": { "provider": "ghost" } }),
        "k-llm-ghost",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(
        env.error.as_ref().unwrap().details,
        vec![UNKNOWN_PROVIDER_DETAIL.to_string()]
    );
    assert_eq!(UNKNOWN_PROVIDER_DETAIL, "unknown_provider");

    // Create carries the block through to the provider and back on the detail.
    let mut body = create_body();
    body["llm"] = json!({ "provider": "local", "model": "tiny" });
    let env = api.handle(post("/client/agents", body, "k-llm-create"));
    let d = detail(&env);
    assert_eq!(d.config.llm.unwrap().provider.as_deref(), Some("local"));
    let last = provider.last_create.lock().unwrap().clone().unwrap();
    assert_eq!(last.llm.unwrap().model.as_deref(), Some("tiny"));
    let mut body = create_body();
    body["agent_id"] = json!("ghostly");
    body["llm"] = json!({ "provider": "ghost" });
    let env = api.handle(post("/client/agents", body, "k-llm-create-ghost"));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(
        env.error.as_ref().unwrap().details,
        vec![UNKNOWN_PROVIDER_DETAIL.to_string()]
    );

    // Compat: the block is an inventoried response component with all-optional fields.
    let art = generate_schema_artifact();
    let inventory = response_field_inventory(&art.schema).expect("partition holds");
    let llm = &inventory["ClientAgentLlm"];
    assert!(!llm["provider"].required && !llm["model"].required && !llm["constraint"].required);
    assert!(inventory["ClientAgentConfig"]
        .keys()
        .any(|k| k.starts_with("llm")));
}
