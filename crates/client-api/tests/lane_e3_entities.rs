//! Lane E3 — CONTRACT-190 `schema` + `entities` families:
//! `/client/schema`, `/client/entities:query`, `/client/entities/{id}`, `:create`, `:patch`,
//! `:apply`, `:promote`, `:demote` over a recording in-memory `EntityProvider`, driving the REAL
//! `ClientApi::handle()` pipeline (admission, version, session, scope gate, idempotency
//! reserve/replay, handler-side validation, provider-error projection). The production adapter
//! over `DataStore` is `crates/cli/src/client_api_entities.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::RESPONSE_COMPONENTS;
use advance_client_api::entities::{
    ClientAspect, ClientEntityApplyRequest, ClientEntityCreateRequest, ClientEntityPage,
    ClientEntityPatchRequest, ClientEntityQueryRequest, ClientEntityRow, ClientEntityTarget,
    ClientSchema,
};
use advance_client_api::projection::{accepted_event_literals, leaf_names};
use advance_client_api::routes::{self, family_of};
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    EntityProvider, Platform, Principal, ProviderError, Scope,
};

// ── Recording in-memory provider ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Calls {
    describe: AtomicUsize,
    query: AtomicUsize,
    get: AtomicUsize,
    create: AtomicUsize,
    patch: AtomicUsize,
    apply: AtomicUsize,
}

struct MemoryEntities {
    calls: Calls,
    last_patch: Mutex<Option<(String, ClientEntityPatchRequest)>>,
    fail: Option<ProviderError>,
}

fn row(id: &str, status: &str) -> ClientEntityRow {
    ClientEntityRow {
        id: id.into(),
        agent_id: "alice".into(),
        path: "launch.md".into(),
        anchor: Some(id.into()),
        kind: "item".into(),
        r#type: "work-item".into(),
        title: Some("t".into()),
        aspects: vec!["agenda".into()],
        fields: json!({ "status": status }),
        updated_at: "2026-09-17T08:00:00Z".into(),
    }
}

impl MemoryEntities {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            last_patch: Mutex::new(None),
            fail: None,
        })
    }
    fn failing(err: ProviderError) -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            last_patch: Mutex::new(None),
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

impl EntityProvider for MemoryEntities {
    fn describe(&self) -> Result<ClientSchema, ProviderError> {
        self.calls.describe.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        Ok(ClientSchema {
            hash: "ab".repeat(32),
            aspects: vec![ClientAspect {
                name: "agenda".into(),
                key: vec!["status".into(), "starts".into()],
                fields: vec![],
                queries: vec![],
                views: vec![],
                operations: vec![],
            }],
        })
    }
    fn query(&self, req: &ClientEntityQueryRequest) -> Result<ClientEntityPage, ProviderError> {
        self.calls.query.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        assert_eq!(req.agent_id, "alice");
        Ok(ClientEntityPage {
            rows: vec![row("e-1", "todo"), row("e-2", "doing")],
            next_cursor: None,
        })
    }
    fn get(&self, agent_id: &str, entity_id: &str) -> Result<ClientEntityRow, ProviderError> {
        self.calls.get.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        assert_eq!(agent_id, "alice");
        match entity_id {
            "e-1" => Ok(row("e-1", "todo")),
            other => Err(ProviderError::NotFound(other.into())),
        }
    }
    fn create(&self, req: &ClientEntityCreateRequest) -> Result<ClientEntityRow, ProviderError> {
        self.calls.create.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        assert_eq!(req.parent, "launch.md");
        Ok(row("e-9", "todo"))
    }
    fn patch(
        &self,
        entity_id: &str,
        req: &ClientEntityPatchRequest,
    ) -> Result<ClientEntityRow, ProviderError> {
        self.calls.patch.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        *self.last_patch.lock().unwrap() = Some((entity_id.into(), req.clone()));
        Ok(row(entity_id, "done"))
    }
    fn apply(
        &self,
        entity_id: &str,
        req: &ClientEntityApplyRequest,
    ) -> Result<Vec<ClientEntityRow>, ProviderError> {
        self.calls.apply.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        assert_eq!(req.op, "detach_occurrence");
        Ok(vec![row(entity_id, "todo"), row("e-10", "todo")])
    }
    fn promote(
        &self,
        _agent_id: &str,
        entity_id: &str,
    ) -> Result<ClientEntityTarget, ProviderError> {
        self.gate()?;
        Ok(ClientEntityTarget {
            path: format!("{entity_id}.md"),
            anchor: None,
        })
    }
    fn demote(
        &self,
        _agent_id: &str,
        entity_id: &str,
    ) -> Result<ClientEntityTarget, ProviderError> {
        self.gate()?;
        Ok(ClientEntityTarget {
            path: "launch.md".into(),
            anchor: Some(entity_id.into()),
        })
    }
}

// ── Harness (same shape as tests/packs.rs) ───────────────────────────────────────────────────

fn api_with(provider: Arc<dyn EntityProvider>) -> (ClientApi, RecordingSink) {
    let sink = RecordingSink::new();
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink.clone()),
    )
    .with_entity_provider(provider);
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

// ── EN-01: routes registered; absent provider is module_unavailable ──────────────────────────
#[test]
fn en01_absent_provider_is_module_unavailable_not_unknown_route() {
    let api = ClientApi::new(ClientApiConfig::default());
    operator(&api);
    for req in [
        get(routes::PATH_SCHEMA),
        post(
            routes::PATH_ENTITIES_QUERY,
            json!({ "agent_id": "alice" }),
            "k0",
        ),
        get("/client/entities/alice/e-1"),
        post(
            routes::PATH_ENTITIES_CREATE,
            json!({ "agent_id": "alice", "parent": "launch.md", "record": {} }),
            "k1",
        ),
        post(
            "/client/entities/e-1:patch",
            json!({ "agent_id": "alice", "ops": [] }),
            "k2",
        ),
        post(
            "/client/entities/e-1:apply",
            json!({ "agent_id": "alice", "op": "x", "args": {} }),
            "k3",
        ),
        post(
            "/client/entities/e-1:promote",
            json!({ "agent_id": "alice" }),
            "k4",
        ),
        post(
            "/client/entities/e-1:demote",
            json!({ "agent_id": "alice" }),
            "k5",
        ),
    ] {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{env:?}"
        );
    }
    assert_eq!(family_of(routes::PATH_SCHEMA), "schema");
    assert_eq!(family_of(routes::PATH_ENTITIES_QUERY), "entities");
    assert_eq!(family_of("/client/entities/e-1:patch"), "entities");
}

// ── EN-02: schema and reads project the provider ─────────────────────────────────────────────
#[test]
fn en02_schema_query_and_get_project_rows() {
    let provider = MemoryEntities::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let schema: ClientSchema = data(&api.handle(get(routes::PATH_SCHEMA)));
    assert_eq!(schema.aspects[0].name, "agenda");
    assert_eq!(schema.hash.len(), 64);

    let page: ClientEntityPage = data(&api.handle(post(
        routes::PATH_ENTITIES_QUERY,
        json!({ "agent_id": "alice", "query": { "name": "open", "args": {} } }),
        "q1",
    )));
    assert_eq!(page.rows.len(), 2);
    assert_eq!(page.rows[1].fields["status"], json!("doing"));

    let one: ClientEntityRow = data(&api.handle(get("/client/entities/alice/e-1")));
    assert_eq!(one.id, "e-1");
    let env = api.handle(get("/client/entities/alice/e-404"));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));

    // Validation happens BEFORE the provider is consulted.
    let before = provider.calls.query.load(Ordering::SeqCst);
    for (why, body) in [
        ("agent_id required", json!({})),
        ("limit bound", json!({ "agent_id": "alice", "limit": 5000 })),
        ("bad agent id", json!({ "agent_id": "../x" })),
        ("unknown field", json!({ "agent_id": "alice", "nope": 1 })),
    ] {
        let env = api.handle(post(routes::PATH_ENTITIES_QUERY, body, "qv"));
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::InvalidRequest),
            "{why}: {env:?}"
        );
    }
    assert_eq!(provider.calls.query.load(Ordering::SeqCst), before);
    let calls = provider.calls.get.load(Ordering::SeqCst);
    let env = api.handle(get("/client/entities/.hidden/e-1"));
    assert_eq!(
        code(&env),
        Some(ClientErrorCode::InvalidRequest),
        "malformed agent id segment"
    );
    assert_eq!(provider.calls.get.load(Ordering::SeqCst), calls);
}

// ── EN-03: writes run the mutation pipeline, replay idempotently, need WriteEntities ─────────
#[test]
fn en03_writes_are_idempotent_mutations_behind_write_entities() {
    let provider = MemoryEntities::new();
    let (api, _sink) = api_with(provider.clone());
    operator(&api);

    let body = json!({ "agent_id": "alice", "ops": [{ "set": "status", "value": "done" }] });
    let first: ClientEntityRow =
        data(&api.handle(post("/client/entities/e-1:patch", body.clone(), "p1")));
    assert_eq!(first.fields["status"], json!("done"));
    let seen = provider.last_patch.lock().unwrap().clone().unwrap();
    assert_eq!(seen.0, "e-1");
    assert_eq!(seen.1.ops.len(), 1);

    // Same key + same body → replay, provider not called again; same key + other body → conflict.
    let replay: ClientEntityRow =
        data(&api.handle(post("/client/entities/e-1:patch", body.clone(), "p1")));
    assert_eq!(replay, first);
    assert_eq!(provider.calls.patch.load(Ordering::SeqCst), 1);
    let env = api.handle(post(
        "/client/entities/e-1:patch",
        json!({ "agent_id": "alice", "ops": [{ "unset": "due" }] }),
        "p1",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyConflict));

    let created: ClientEntityRow = data(&api.handle(post(
        routes::PATH_ENTITIES_CREATE,
        json!({ "agent_id": "alice", "parent": "launch.md", "record": { "type": "work-item", "title": "t", "status": "todo" } }),
        "c1",
    )));
    assert_eq!(created.id, "e-9");
    let applied: Vec<ClientEntityRow> = data(&api.handle(post(
        "/client/entities/e-1:apply",
        json!({ "agent_id": "alice", "op": "detach_occurrence", "args": { "at": "2026-10-05T02:00:00Z" } }),
        "a1",
    )));
    assert_eq!(applied.len(), 2);
    let promoted: ClientEntityTarget = data(&api.handle(post(
        "/client/entities/e-1:promote",
        json!({ "agent_id": "alice" }),
        "pr1",
    )));
    assert_eq!(promoted.path, "e-1.md");

    // Scope gate: a read-only session may query but not write.
    mint(&api, "ro", vec![Scope::ReadInventory]);
    let env = api.handle(ClientRequest::get(routes::PATH_SCHEMA).with_session("ro"));
    assert!(env.is_ok(), "{env:?}");
    let env = api.handle(
        ClientRequest::post("/client/entities/e-1:patch", body)
            .with_session("ro")
            .with_idempotency_key("p9"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
    assert!(Scope::operator_default().contains(&Scope::WriteEntities));
    // A write without an idempotency key is refused like every other mutation.
    let env = api.handle(
        ClientRequest::post(
            "/client/entities/e-1:demote",
            json!({ "agent_id": "alice" }),
        )
        .with_session("tok"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyRequired));
}

// ── EN-04: provider errors project per the CONTRACT-190 table ────────────────────────────────
#[test]
fn en04_provider_errors_project() {
    for (err, expected) in [
        (
            ProviderError::NotFound("e".into()),
            ClientErrorCode::NotFound,
        ),
        (
            ProviderError::InvalidState("done → doing".into()),
            ClientErrorCode::InvalidState,
        ),
        (
            ProviderError::Forbidden("territory".into()),
            ClientErrorCode::Forbidden,
        ),
        (
            ProviderError::Unavailable("op".into()),
            ClientErrorCode::ModuleUnavailable,
        ),
    ] {
        let (api, _sink) = api_with(MemoryEntities::failing(err));
        operator(&api);
        let env = api.handle(post(
            "/client/entities/e-1:patch",
            json!({ "agent_id": "alice", "ops": [] }),
            "x",
        ));
        assert_eq!(code(&env), Some(expected), "{env:?}");
    }
}

// ── EN-05: the change event is projected to clients with its leaves ──────────────────────────
#[test]
fn en05_entity_changed_is_projected_with_its_leaves() {
    assert!(accepted_event_literals().contains(&"data.entity_changed"));
    let leaves = leaf_names("data.entity_changed").expect("in the projection table");
    assert_eq!(leaves, vec!["entity_id", "path", "op", "kind"]);
}

// ── EN-06: the DTOs are schema components with compat coverage ───────────────────────────────
#[test]
fn en06_dtos_are_in_the_schema_inventory() {
    let artifact = generate_schema_artifact().schema_json();
    for name in [
        "ClientSchema",
        "ClientAspect",
        "ClientEntityRow",
        "ClientEntityPage",
        "ClientEntityTarget",
        "ClientEntityQueryRequest",
        "ClientEntityCreateRequest",
        "ClientEntityPatchRequest",
        "ClientEntityApplyRequest",
    ] {
        assert!(
            artifact.contains(name),
            "{name} missing from the schema artifact"
        );
    }
    for name in [
        "ClientSchema",
        "ClientEntityRow",
        "ClientEntityPage",
        "ClientEntityTarget",
    ] {
        assert!(
            RESPONSE_COMPONENTS.contains(&name),
            "{name} needs a compat baseline"
        );
    }
}
