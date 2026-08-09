//! MODULE-020-AC-12 (contract) — Web, Mac, iOS, Android, and Windows SDK fixtures pass the SAME
//! error, pagination, idempotency, and reconnect contract suite. (§3.3 MODULE-020-T12.)
//!
//! ONE shared implementation EXERCISES each of the four semantics against the REAL in-process
//! sync core (`ClientApi::handle()`), then asserts every observation against EVERY committed
//! per-platform surface fixture (`sdk-artifacts/conformance/fixtures/<target>/surface.json`)
//! and against the shared conformance vectors — so per-platform parity is EXERCISED parity, not
//! declaration-only containment:
//!
//!   - **errors**: real requests drive a representative set of declared error codes through the
//!     full pipeline (version gate, admission, CORS/CSRF, auth/session, scopes, idempotency
//!     gates, and a REAL MODULE-008 `RunManager` provider for `not_found`/`invalid_state`);
//!   - **pagination**: entities are created THROUGH the API (idempotency-keyed mutations), then
//!     the CONTRACT-190 base64url `{offset, last_id}` cursor is walked to exhaustion (order
//!     stability, no duplicates/gaps, terminal-cursor semantics);
//!   - **idempotency**: the same mutation is submitted twice with one key against the REAL
//!     `RunManager`; the replay returns the recorded outcome + the `idempotent_replay` warning
//!     and the provider runs exactly once;
//!   - **reconnect**: events are consumed from a REAL MODULE-019 `EventBus`, the client
//!     disconnects, and resumes via the declared `stream_id`/`last_event_id` fields (CONTRACT-191)
//!     with gap-free, exactly-once delivery.
//!
//! Harness disclosure (same accepted patterns as tests/envelope.rs, tests/runs.rs and
//! tests/events.rs — dev-dependency port fixtures driving REAL contract implementations, the
//! AC-05-precedent module-e2e floor): run mutations use the real `RunManager` behind the
//! `RunControlProvider` port; reconnect uses the real `EventBus` behind `ClientEventProvider`;
//! the paginated list family is a test-registered route pair (production list providers are
//! Wave-25 composition) whose handler is the REAL CONTRACT-190 pagination implementation
//! (`Cursor`/`clamp_limit`/`Page`) behind the REAL, unmodified `handle()` pipeline.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use advance_client_api::api::{ClientApi, HandlerSpec};
use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::SystemClock;
use advance_client_api::pagination::{clamp_limit, Cursor, Page};
use advance_client_api::request::Method;
use advance_client_api::runs::ClientAgentTreeNode;
use advance_client_api::runs::ClientRunMutation;
use advance_client_api::runs::ClientRunSummary;
use advance_client_api::schema::{manifest_path, shared_sdk_dir, vectors_path};
use advance_client_api::{
    AeadClientCursorCodec, ClientApiConfig, ClientCursorCodec, ClientEnvelope, ClientError,
    ClientErrorCode, ClientEventPage, ClientEventProvider, ClientRequest, ClientScalar,
    ClientSession, MemoryCursorKeyCustody, NormalizedEventFilter, OsCursorEntropy, Platform,
    Principal, ProviderError, RawEventRow, RunControlProvider, Scope, SystemCursorClock,
};

use advance_event_bus::{
    EventBus, EventBusConfig, EventFilter, ObservabilityReadApi, ReadApiError, ReadCursor,
};
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RunError, TaskRunStatus};
use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use cap_http::DefaultLeakDetector;
use chrono::Utc;

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Committed fixture + vector loading (the five platform surfaces under test)
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Load the COMMITTED per-platform surface fixtures (from disk, not the emitter) keyed by the
/// manifest's declared target list. The suite runs identically over every one of them.
fn committed_surfaces() -> Vec<(String, Value)> {
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest_path()).expect("manifest.json on disk"),
    )
    .expect("manifest parses");
    let targets: Vec<String> = manifest["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        targets,
        vec!["web", "mac", "ios", "android", "windows"],
        "the five platform targets of record"
    );
    targets
        .into_iter()
        .map(|t| {
            let p = shared_sdk_dir()
                .join("conformance/fixtures")
                .join(&t)
                .join("surface.json");
            let v: Value = serde_json::from_str(
                &std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}")),
            )
            .expect("surface parses");
            (t, v)
        })
        .collect()
}

/// The COMMITTED shared conformance vectors (from disk).
fn committed_vectors() -> Vec<Value> {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(vectors_path()).expect("vectors.json on disk"),
    )
    .expect("vectors parse");
    v["vectors"].as_array().expect("vectors array").clone()
}

fn surface_error_codes(surface: &Value) -> Vec<String> {
    surface["error_codes"]
        .as_array()
        .expect("error_codes")
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect()
}

fn surface_fields(surface: &Value, cursor: &str) -> Vec<String> {
    surface[cursor]["logical_fields"]
        .as_array()
        .expect("logical_fields")
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect()
}

/// Every observed envelope must satisfy the declared envelope invariant (data XOR error).
fn assert_envelope_invariant(env: &ClientEnvelope<Value>, scenario: &str) {
    assert!(
        env.is_ok() ^ env.is_err(),
        "{scenario}: envelope must satisfy data XOR error"
    );
    assert!(!env.request_id.is_empty(), "{scenario}: request_id present");
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// REAL RunManager provider adapter (same accepted harness as tests/runs.rs — AC-07 witness)
// ═══════════════════════════════════════════════════════════════════════════════════════════

#[derive(Default)]
struct MockEventBus {
    events: Mutex<Vec<Event>>,
}
impl MockEventBus {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn count(&self, run_id: &str, event_type: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type && e.run_id.as_deref() == Some(run_id))
            .count()
    }
    fn ids_for(&self, run_id: &str, event_type: &str) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type && e.run_id.as_deref() == Some(run_id))
            .map(|e| e.id.clone())
            .collect()
    }
}
impl EventBusEmit for MockEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct OkAwaitRef;
#[async_trait]
impl AwaitSessionRef for OkAwaitRef {
    fn exists(&self, _: &SessionId) -> bool {
        true
    }
    fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(&self, _sid: &SessionId, _reason: &str) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

fn status_label(s: &TaskRunStatus) -> &'static str {
    match s {
        TaskRunStatus::Active => "active",
        TaskRunStatus::Suspended => "suspended",
        TaskRunStatus::Paused => "paused",
        TaskRunStatus::Completed => "completed",
        TaskRunStatus::Failed(_) => "failed",
        TaskRunStatus::Cancelled(_) => "cancelled",
    }
}

fn map_run_err(e: RunError) -> ProviderError {
    match e {
        RunError::NotFound(_) => ProviderError::NotFound("run_not_found".into()),
        RunError::InvalidState(_) => ProviderError::InvalidState("invalid_run_state".into()),
        RunError::PermissionDenied(_) => ProviderError::InvalidState("run_op_not_permitted".into()),
        RunError::BudgetExceeded(_) => ProviderError::InvalidState("run_budget_exceeded".into()),
        RunError::AlreadyExists(_) => ProviderError::InvalidState("run_already_exists".into()),
    }
}

struct RunManagerRunControl {
    rt: Arc<tokio::runtime::Runtime>,
    mgr: Arc<RunManager>,
    bus: Arc<MockEventBus>,
}
impl RunManagerRunControl {
    fn rid(&self, run_id: &str) -> Result<RunId, ProviderError> {
        Ok(RunId::from_string_unchecked(run_id.to_string()))
    }
    fn result(&self, id: &RunId, run_id: &str, event_type: &str) -> ClientRunMutation {
        let status = self
            .mgr
            .run_status(id)
            .map(|w| status_label(&w.status).to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        ClientRunMutation {
            run_id: run_id.to_string(),
            status,
            emitted_event_ids: self.bus.ids_for(run_id, event_type),
        }
    }
}
impl RunControlProvider for RunManagerRunControl {
    fn list_runs(&self) -> Result<Vec<ClientRunSummary>, ProviderError> {
        Ok(Vec::new())
    }
    fn agent_tree(&self) -> Result<Vec<ClientAgentTreeNode>, ProviderError> {
        Ok(Vec::new())
    }
    fn pause(
        &self,
        run_id: &str,
        reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError> {
        let id = self.rid(run_id)?;
        self.rt
            .block_on(
                self.mgr
                    .pause_run(&id, reason.unwrap_or("paused").to_string()),
            )
            .map_err(map_run_err)?;
        Ok(self.result(&id, run_id, "run.paused"))
    }
    fn resume(
        &self,
        run_id: &str,
        _reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError> {
        let id = self.rid(run_id)?;
        self.mgr
            .resume_run(&id, "manual".to_string())
            .map_err(map_run_err)?;
        Ok(self.result(&id, run_id, "run.resumed"))
    }
    fn cancel(
        &self,
        run_id: &str,
        reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError> {
        let id = self.rid(run_id)?;
        self.rt
            .block_on(
                self.mgr
                    .cancel_run(&id, reason.unwrap_or("cancelled").to_string()),
            )
            .map_err(map_run_err)?;
        Ok(self.result(&id, run_id, "run.cancelled"))
    }
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>, csrf: Option<&str>, expires_at: u64) {
    let session = ClientSession {
        session_id: format!("sess-{token}"),
        principal: Principal {
            id: "operator".to_string(),
            os_user: "op".to_string(),
        },
        platform: Platform::Mac,
        scopes,
        csrf_token: csrf.map(|c| c.to_string()),
        expires_at,
    };
    api.sessions().insert(token.to_string(), session, 0);
}

struct RunFixture {
    api: ClientApi,
    mgr: Arc<RunManager>,
    bus: Arc<MockEventBus>,
}

fn run_fixture(config: ClientApiConfig) -> RunFixture {
    let bus = MockEventBus::new_arc();
    let mgr = Arc::new(
        RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
            .with_await_session_ref(Arc::new(OkAwaitRef)),
    );
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime"),
    );
    let adapter = RunManagerRunControl {
        rt,
        mgr: Arc::clone(&mgr),
        bus: Arc::clone(&bus),
    };
    let api = ClientApi::new(config).with_run_provider(Arc::new(adapter));
    mint(
        &api,
        "tok",
        vec![Scope::ReadRuns, Scope::ControlRuns],
        None,
        u64::MAX,
    );
    RunFixture { api, mgr, bus }
}

fn pause_req(run_id: &str, key: &str, reason: &str) -> ClientRequest {
    ClientRequest::post(
        format!("/client/runs/{run_id}:pause"),
        json!({ "reason": reason }),
    )
    .with_session("tok")
    .with_idempotency_key(key)
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Semantic 1 — ERROR: real requests produce the declared typed error codes
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Drive the real API through failure paths and return `(scenario, observed_code)` pairs.
fn exercise_error_semantics() -> Vec<(&'static str, String)> {
    let allowed_origin = "http://console.local".to_string();
    let cfg = ClientApiConfig {
        allowed_origins: vec![allowed_origin.clone()],
        ..ClientApiConfig::default()
    };
    let fx = run_fixture(cfg);
    // Sessions for the auth-family scenarios.
    mint(&fx.api, "tok-noscope", vec![], None, u64::MAX);
    mint(
        &fx.api,
        "tok-expired",
        vec![Scope::ReadRuns],
        None,
        1, // expired long ago vs SystemClock
    );
    mint(
        &fx.api,
        "tok-web",
        vec![Scope::ReadRuns, Scope::ControlRuns],
        Some("csrf-secret"),
        u64::MAX,
    );

    // Real runs for the provider-error scenarios.
    let run_ok = fx
        .mgr
        .ensure_run("task-err-ok", "operator", RunConfig::default())
        .unwrap();
    fx.mgr.suspend_run(&run_ok, "sid-conf").unwrap();
    let run_ok_id = run_ok.to_string();
    let run_done = fx
        .mgr
        .ensure_run("task-err-done", "operator", RunConfig::default())
        .unwrap();
    fx.mgr
        .with_status_for_test(&run_done, TaskRunStatus::Completed)
        .unwrap();
    let run_done_id = run_done.to_string();

    let mut observed: Vec<(&'static str, ClientEnvelope<Value>)> = Vec::new();

    // unsupported_api_version — version gate fails closed before any handler.
    let mut req = ClientRequest::get("/client/runs").with_session("tok");
    req.api_version = "1999-01-01".to_string();
    observed.push(("unsupported_api_version", fx.api.handle(req)));

    // unauthenticated — session-required route without a token.
    observed.push((
        "auth_missing_session",
        fx.api.handle(ClientRequest::get("/client/runs")),
    ));

    // session_expired — a real (but expired) session.
    observed.push((
        "auth_session_expired",
        fx.api
            .handle(ClientRequest::get("/client/runs").with_session("tok-expired")),
    ));

    // forbidden — authenticated but under-scoped.
    observed.push((
        "auth_underscoped",
        fx.api
            .handle(ClientRequest::get("/client/runs").with_session("tok-noscope")),
    ));

    // unknown_route.
    observed.push((
        "unknown_route",
        fx.api
            .handle(ClientRequest::get("/client/definitely-not-a-route").with_session("tok")),
    ));

    // request_too_large — body over the 1 MiB cap (validation bound).
    observed.push((
        "validation_body_too_large",
        fx.api.handle(
            ClientRequest::post(
                format!("/client/runs/{run_ok_id}:pause"),
                json!({ "reason": "x".repeat(2 * 1024 * 1024) }),
            )
            .with_session("tok")
            .with_idempotency_key("k-too-large"),
        ),
    ));

    // idempotency_required — mutation without a key.
    observed.push((
        "idempotency_missing_key",
        fx.api.handle(
            ClientRequest::post(format!("/client/runs/{run_ok_id}:pause"), json!({}))
                .with_session("tok"),
        ),
    ));

    // idempotency_conflict — same key, different request body (real committed first outcome).
    let first = fx.api.handle(pause_req(&run_ok_id, "conf-key", "first"));
    assert!(first.is_ok(), "conflict setup pause: {:?}", first.error);
    assert_envelope_invariant(&first, "conflict_setup");
    observed.push((
        "idempotency_conflict",
        fx.api.handle(pause_req(&run_ok_id, "conf-key", "second")),
    ));

    // not_found — REAL RunManager rejects an unknown run id.
    observed.push((
        "provider_not_found",
        fx.api.handle(pause_req("no-such-run", "k-nf", "witness")),
    ));

    // invalid_state — REAL RunManager rejects pausing a Completed run (validation failure).
    observed.push((
        "validation_invalid_transition",
        fx.api.handle(pause_req(&run_done_id, "k-inv", "witness")),
    ));

    // origin_not_allowed — browser Origin outside the exact-match allowlist.
    observed.push((
        "origin_not_allowed",
        fx.api.handle(
            ClientRequest::get("/client/runs")
                .with_session("tok")
                .with_origin("http://evil.example"),
        ),
    ));

    // csrf_required — allowed browser origin, mutation, no CSRF token bound/presented.
    observed.push((
        "csrf_required",
        fx.api.handle(
            ClientRequest::post(format!("/client/runs/{run_ok_id}:pause"), json!({}))
                .with_session("tok")
                .with_origin(allowed_origin.clone())
                .with_idempotency_key("k-csrf"),
        ),
    ));

    // csrf_invalid — session-bound CSRF token mismatch.
    observed.push((
        "csrf_invalid",
        fx.api.handle(
            ClientRequest::post(format!("/client/runs/{run_ok_id}:pause"), json!({}))
                .with_session("tok-web")
                .with_origin(allowed_origin)
                .with_csrf("wrong")
                .with_idempotency_key("k-csrf2"),
        ),
    ));

    // remote_bind_forbidden — non-loopback peer under the loopback-only default.
    observed.push((
        "remote_bind_forbidden",
        fx.api
            .handle(ClientRequest::get("/client/health").with_loopback_peer(false)),
    ));

    // projection_rejected — malformed history request rejected before any provider.
    observed.push((
        "validation_bad_history_request",
        fx.api.handle({
            let mut r = ClientRequest::get("/client/tasks/task-a/history").with_session("tok");
            r.body = json!(["not", "an", "object"]);
            r
        }),
    ));

    // module_unavailable — provider slot absent fails closed (separate bare core).
    let bare = ClientApi::new(ClientApiConfig::default());
    mint(
        &bare,
        "tok",
        vec![Scope::ReadRuns, Scope::ControlRuns],
        None,
        u64::MAX,
    );
    observed.push((
        "module_unavailable",
        bare.handle(pause_req("whatever", "k-mu", "witness")),
    ));

    observed
        .into_iter()
        .map(|(scenario, env)| {
            assert_envelope_invariant(&env, scenario);
            let err = env
                .error
                .as_ref()
                .unwrap_or_else(|| panic!("{scenario}: expected an error envelope"));
            assert_ne!(
                err.code,
                ClientErrorCode::Unknown,
                "{scenario}: server never produces the catch-all"
            );
            (scenario, err.code.as_str().to_string())
        })
        .collect()
}

#[test]
fn ac12_error_semantics_exercised_against_every_surface() {
    let observed = exercise_error_semantics();
    let observed_codes: BTreeSet<String> = observed.iter().map(|(_, c)| c.clone()).collect();

    // The demanded representative classes were all actually driven.
    for (scenario, code) in [
        ("unsupported_api_version", "unsupported_api_version"),
        ("auth_missing_session", "unauthenticated"),
        ("auth_session_expired", "session_expired"),
        ("auth_underscoped", "forbidden"),
        ("validation_invalid_transition", "invalid_state"),
        ("validation_bad_history_request", "projection_rejected"),
        ("idempotency_conflict", "idempotency_conflict"),
        ("provider_not_found", "not_found"),
        ("module_unavailable", "module_unavailable"),
    ] {
        assert!(
            observed.iter().any(|(s, c)| *s == scenario && c == code),
            "scenario {scenario} must observe {code}; got {observed:?}"
        );
    }

    let vectors = committed_vectors();
    let error_vectors: Vec<(&str, &str)> = vectors
        .iter()
        .filter(|v| v["kind"] == "error")
        .map(|v| {
            (
                v["name"].as_str().expect("vector name"),
                v["envelope"]["error"]["code"].as_str().expect("code"),
            )
        })
        .collect();
    assert!(
        error_vectors.len() >= 10,
        "the shared vectors carry a representative error set (got {})",
        error_vectors.len()
    );

    // The vectors' expected codes match OBSERVED reality (each declared code was actually
    // produced by the real API in this run).
    for (name, code) in &error_vectors {
        assert!(
            observed_codes.contains(*code),
            "vector {name} declares {code}, which the real API did not produce; observed {observed_codes:?}"
        );
    }

    // Every observed typed error is a member of EVERY platform surface's declared error_codes.
    let surfaces = committed_surfaces();
    assert_eq!(surfaces.len(), 5);
    for (target, surface) in &surfaces {
        let declared = surface_error_codes(surface);
        for (scenario, code) in &observed {
            assert!(
                declared.contains(code),
                "target {target}: observed {code} ({scenario}) missing from declared error_codes"
            );
        }
        for (name, code) in &error_vectors {
            assert!(
                declared.iter().any(|d| d == code),
                "target {target}: vector {name} code {code} missing from declared error_codes"
            );
        }
        assert!(
            surface["envelope_invariant"]
                .as_str()
                .expect("envelope_invariant")
                .contains("data XOR error"),
            "target {target}: declared envelope invariant"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Semantic 2 — PAGINATION: API-created entities walked to exhaustion via the declared cursor
// ═══════════════════════════════════════════════════════════════════════════════════════════

const ITEM_TOTAL: usize = 120;

/// Build a core with the REAL CONTRACT-190 pagination implementation served behind the REAL
/// pipeline: POST /client/sdk-items creates an entity (idempotency-keyed mutation); GET
/// /client/sdk-items pages with the canonical base64url `{offset, last_id}` `Cursor`.
fn pagination_fixture() -> (ClientApi, Arc<Mutex<Vec<(String, u64)>>>) {
    let items: Arc<Mutex<Vec<(String, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let mut api = ClientApi::new(ClientApiConfig::default());

    let create_items = Arc::clone(&items);
    api.register(
        Method::Post,
        "/client/sdk-items",
        HandlerSpec::mutation(true, move |ctx| {
            let n = ctx.body["n"].as_u64().ok_or_else(|| {
                ClientError::new(ClientErrorCode::InvalidState, "invalid item payload")
            })?;
            let mut g = create_items.lock().unwrap();
            let id = format!("item-{:04}", g.len());
            g.push((id.clone(), n));
            Ok(json!({ "id": id, "n": n }))
        }),
    );

    let list_items = Arc::clone(&items);
    api.register(
        Method::Get,
        "/client/sdk-items",
        HandlerSpec::read(true, move |ctx| {
            let invalid =
                || ClientError::new(ClientErrorCode::InvalidState, "invalid list request");
            let (cursor_tok, limit) = if ctx.body.is_null() {
                (None, None)
            } else {
                let obj = ctx.body.as_object().ok_or_else(invalid)?;
                if obj.keys().any(|k| k != "cursor" && k != "limit") {
                    return Err(invalid());
                }
                let c = match obj.get("cursor") {
                    None => None,
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(_) => return Err(invalid()),
                };
                let l = match obj.get("limit") {
                    None => None,
                    Some(v) => Some(v.as_u64().ok_or_else(invalid)? as usize),
                };
                (c, l)
            };
            let limit = clamp_limit(limit);
            let g = list_items.lock().unwrap();
            let offset = match cursor_tok {
                None => 0usize,
                Some(tok) => {
                    let cur = Cursor::decode(&tok).ok_or_else(|| {
                        ClientError::new(ClientErrorCode::InvalidState, "invalid pagination cursor")
                    })?;
                    let off = cur.offset as usize;
                    // The last_id leg must corroborate the offset (order/gap guard).
                    let anchored = off >= 1
                        && off <= g.len()
                        && cur.last_id.as_deref() == Some(g[off - 1].0.as_str());
                    if !anchored {
                        return Err(ClientError::new(
                            ClientErrorCode::InvalidState,
                            "stale pagination cursor",
                        ));
                    }
                    off
                }
            };
            let end = (offset + limit).min(g.len());
            let page_items: Vec<Value> = g[offset..end]
                .iter()
                .map(|(id, n)| json!({ "id": id, "n": n }))
                .collect();
            let next = if end < g.len() {
                Some(Cursor::new(end as u64, Some(g[end - 1].0.clone())).encode())
            } else {
                None
            };
            Ok(serde_json::to_value(Page::new(page_items, next)).expect("page serializes"))
        }),
    );

    (api, items)
}

struct PaginationObservation {
    /// Ordered item ids from one full walk.
    walk_ids: Vec<String>,
    /// Page sizes per walk step.
    page_sizes: Vec<usize>,
    /// Decoded logical-field key sets of every intermediate continuation cursor.
    cursor_key_sets: Vec<Vec<String>>,
    /// Terminal page omitted next_cursor entirely.
    terminal_cursor_absent: bool,
}

fn walk_pages(api: &ClientApi, token: &str) -> PaginationObservation {
    let mut walk_ids = Vec::new();
    let mut page_sizes = Vec::new();
    let mut cursor_key_sets = Vec::new();
    let mut cursor: Option<String> = None;
    let mut terminal_cursor_absent = false;
    for _step in 0..100 {
        let mut req = ClientRequest::get("/client/sdk-items").with_session(token);
        req.body = match &cursor {
            None => Value::Null,
            Some(c) => json!({ "cursor": c }),
        };
        let env = api.handle(req);
        assert_envelope_invariant(&env, "pagination_walk");
        assert!(env.is_ok(), "walk page: {:?}", env.error);
        let data = env.data.unwrap();
        let items = data["items"].as_array().expect("items");
        page_sizes.push(items.len());
        for it in items {
            walk_ids.push(it["id"].as_str().unwrap().to_string());
        }
        match data.get("next_cursor") {
            None => {
                terminal_cursor_absent = true;
                break;
            }
            Some(next) => {
                let tok = next
                    .as_str()
                    .expect("cursor is an opaque string")
                    .to_string();
                // Observe the declared logical fields inside the opaque token.
                let decoded = Cursor::decode(&tok).expect("continuation cursor decodes");
                let as_json = serde_json::to_value(&decoded).unwrap();
                let mut keys: Vec<String> = as_json.as_object().unwrap().keys().cloned().collect();
                keys.sort();
                cursor_key_sets.push(keys);
                cursor = Some(tok);
            }
        }
    }
    PaginationObservation {
        walk_ids,
        page_sizes,
        cursor_key_sets,
        terminal_cursor_absent,
    }
}

#[test]
fn ac12_pagination_exercised_against_every_surface() {
    let (api, items) = pagination_fixture();
    // Real session established THROUGH the API.
    let login = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "mac" }),
    ));
    assert!(login.is_ok(), "login: {:?}", login.error);
    let token = login.data.unwrap()["token"].as_str().unwrap().to_string();

    // Create enough entities THROUGH the API to force pagination (idempotency-keyed mutations).
    for i in 0..ITEM_TOTAL {
        let env = api.handle(
            ClientRequest::post("/client/sdk-items", json!({ "n": i }))
                .with_session(&token)
                .with_idempotency_key(format!("create-{i}")),
        );
        assert_envelope_invariant(&env, "item_create");
        assert!(env.is_ok(), "create {i}: {:?}", env.error);
    }
    // A replayed creation must NOT mint a duplicate entity.
    let replay = api.handle(
        ClientRequest::post("/client/sdk-items", json!({ "n": 7 }))
            .with_session(&token)
            .with_idempotency_key("create-7"),
    );
    assert!(replay.is_ok());
    assert!(replay
        .warnings
        .iter()
        .any(|w| w.code == "idempotent_replay"));
    assert_eq!(
        items.lock().unwrap().len(),
        ITEM_TOTAL,
        "no duplicate entity"
    );

    // Walk to exhaustion, twice (order stability).
    let obs = walk_pages(&api, &token);
    let again = walk_pages(&api, &token);
    assert_eq!(obs.walk_ids, again.walk_ids, "order-stable across walks");

    // No duplicates, no gaps: the walk is exactly the created sequence, in order.
    let expected: Vec<String> = (0..ITEM_TOTAL).map(|i| format!("item-{i:04}")).collect();
    assert_eq!(obs.walk_ids, expected, "exactly-once, ordered, gap-free");
    assert_eq!(obs.page_sizes, vec![50, 50, 20], "default limit pages");
    assert!(
        obs.terminal_cursor_absent,
        "terminal page omits next_cursor"
    );
    assert_eq!(obs.cursor_key_sets.len(), 2, "two continuation cursors");

    // A malformed cursor is rejected with a typed error (never a panic / wrong page).
    let mut bad = ClientRequest::get("/client/sdk-items").with_session(&token);
    bad.body = json!({ "cursor": "!!!not-base64!!!" });
    let bad_env = api.handle(bad);
    assert_eq!(bad_env.error_code(), Some(ClientErrorCode::InvalidState));

    // Assert the exercised cursor against EVERY platform surface fixture.
    let surfaces = committed_surfaces();
    for (target, surface) in &surfaces {
        assert_eq!(
            surface["pagination_cursor"]["type"], "base64url_position",
            "target {target}: declared pagination cursor type"
        );
        let mut declared = surface_fields(surface, "pagination_cursor");
        declared.sort();
        for keys in &obs.cursor_key_sets {
            assert!(
                keys.iter().all(|k| declared.contains(k)),
                "target {target}: observed cursor fields {keys:?} not all declared {declared:?}"
            );
        }
        // Both declared logical fields were exercised (offset + last_id present in the token).
        let union: BTreeSet<String> = obs.cursor_key_sets.iter().flatten().cloned().collect();
        let union: Vec<String> = union.into_iter().collect();
        assert_eq!(
            union, declared,
            "target {target}: the exercised cursor uses exactly the declared logical fields"
        );
        assert!(
            surface_error_codes(surface).contains(&"invalid_state".to_string()),
            "target {target}: the malformed-cursor rejection code is declared"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Semantic 3 — IDEMPOTENCY: one key, one execution, recorded outcome + declared warning
// ═══════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn ac12_idempotency_exercised_against_every_surface() {
    let fx = run_fixture(ClientApiConfig::default());
    let id = fx
        .mgr
        .ensure_run("task-idem", "operator", RunConfig::default())
        .unwrap();
    fx.mgr.suspend_run(&id, "sid-idem").unwrap();
    let run_id = id.to_string();

    // First submission executes the REAL provider mutation.
    let first = fx.api.handle(pause_req(&run_id, "idem-key", "witness"));
    assert_envelope_invariant(&first, "idempotency_first");
    assert!(first.is_ok(), "first pause: {:?}", first.error);
    assert_eq!(fx.bus.count(&run_id, "run.paused"), 1);

    // Replay with the SAME key: recorded outcome, no second execution, declared warning.
    let replay = fx.api.handle(pause_req(&run_id, "idem-key", "witness"));
    assert_envelope_invariant(&replay, "idempotency_replay");
    assert!(replay.is_ok());
    assert_eq!(
        replay.request_id, first.request_id,
        "replay echoes the ORIGINAL request_id (recorded outcome)"
    );
    assert_eq!(
        replay.data, first.data,
        "replay returns the recorded outcome byte-identically"
    );
    assert_eq!(
        fx.bus.count(&run_id, "run.paused"),
        1,
        "the provider ran exactly once"
    );
    let replay_warnings: Vec<String> = replay.warnings.iter().map(|w| w.code.clone()).collect();
    assert!(
        replay_warnings.iter().any(|c| c == "idempotent_replay"),
        "replay carries the declared idempotent_replay warning; got {replay_warnings:?}"
    );

    // Same key + different request is a conflict, not a replay.
    let conflict = fx.api.handle(pause_req(&run_id, "idem-key", "changed"));
    assert_eq!(
        conflict.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );
    assert_eq!(fx.bus.count(&run_id, "run.paused"), 1);

    // The shared vectors' replay warning matches observed reality.
    let vectors = committed_vectors();
    let vector_warning = vectors
        .iter()
        .find(|v| v["name"] == "data_with_warning")
        .expect("data_with_warning vector")["envelope"]["warnings"][0]["code"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        replay_warnings.contains(&vector_warning),
        "vector warning {vector_warning} was observed on the real replay"
    );

    // Assert against EVERY platform surface fixture.
    let surfaces = committed_surfaces();
    for (target, surface) in &surfaces {
        let declared_warnings: Vec<String> = surface["example_idempotency_warnings"]
            .as_array()
            .expect("example_idempotency_warnings")
            .iter()
            .map(|w| w.as_str().unwrap().to_string())
            .collect();
        for code in replay_warnings.iter().filter(|c| c.contains("idempotent")) {
            assert!(
                declared_warnings.contains(code),
                "target {target}: observed replay warning {code} not declared"
            );
        }
        assert!(
            declared_warnings.contains(&vector_warning),
            "target {target}: vector warning not declared"
        );
        let declared_codes = surface_error_codes(surface);
        for code in ["idempotency_conflict", "idempotency_required"] {
            assert!(
                declared_codes.contains(&code.to_string()),
                "target {target}: {code} declared"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Semantic 4 — RECONNECT: consume, disconnect, resume via declared fields, gap-free
// ═══════════════════════════════════════════════════════════════════════════════════════════

struct LiveBus {
    _rt_thread: std::thread::JoinHandle<()>,
    bus: Arc<EventBus>,
    read: Arc<dyn ObservabilityReadApi>,
}

impl LiveBus {
    fn start() -> Self {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let temp = Box::leak(Box::new(temp));
        let jsonl = temp.path().join("events");
        let db = temp.path().join("events.db");
        let mut cfg = EventBusConfig::new(jsonl, db);
        cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
        cfg.jsonl_retention_days = 30;

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("rt");
            rt.block_on(async move {
                let bus = EventBus::new(cfg).await.expect("bus");
                let bus = Arc::new(bus);
                let read = bus.read_api().expect("read_api");
                ready_tx.send((Arc::clone(&bus), read)).expect("ready send");
                // Park for the test-process lifetime.
                let _ = tokio::task::spawn_blocking(|| {
                    std::thread::park();
                })
                .await;
            });
        });
        let (bus, read) = ready_rx.recv().expect("bus ready");
        Self {
            _rt_thread: handle,
            bus,
            read,
        }
    }

    fn emit(&self, event: Event) {
        self.bus.emit(event);
    }

    fn wait_count(&self, min: usize, timeout: Duration) {
        let start = std::time::Instant::now();
        let read = Arc::clone(&self.read);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        while start.elapsed() < timeout {
            let n = rt.block_on(async {
                read.query(&EventFilter::default(), 10_000)
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            });
            if n >= min {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("wait_count: expected >= {min} within {timeout:?}");
    }
}

struct BusProvider {
    rt: tokio::runtime::Runtime,
    read: Arc<dyn ObservabilityReadApi>,
}

impl BusProvider {
    fn new(live: &LiveBus) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("provider rt");
        Self {
            rt,
            read: Arc::clone(&live.read),
        }
    }

    fn map_err(e: ReadApiError) -> ProviderError {
        match e {
            ReadApiError::CursorNotFound(_) => ProviderError::NotFound("cursor".into()),
            ReadApiError::BadFilter(_) => ProviderError::InvalidState("filter".into()),
            ReadApiError::Db(_) => ProviderError::Unavailable("db".into()),
        }
    }

    fn to_row(re: advance_event_bus::ReadEvent) -> RawEventRow {
        RawEventRow {
            raw_id: re.cursor.0,
            event_type: re.event.event_type.clone(),
            timestamp: re.event.timestamp,
            agent_id: re.event.agent_id.clone(),
            run_id: re.event.run_id.clone(),
            trace_id: re.event.trace_id.clone(),
            payload: re.event.payload.clone(),
        }
    }
}

impl ClientEventProvider for BusProvider {
    fn retention_days(&self) -> u32 {
        30
    }

    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
        let read = Arc::clone(&self.read);
        self.rt.block_on(async move {
            read.query(&EventFilter::default(), 1)
                .await
                .map(|rows| rows.into_iter().next().map(|r| r.cursor.0))
                .map_err(Self::map_err)
        })
    }

    fn query_history(
        &self,
        filter: &NormalizedEventFilter,
        limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        let ef = EventFilter {
            event_type_prefix: filter.event_type.clone(),
            agent_id: filter.agent_id.clone(),
            run_id: filter.run_id.clone(),
            trace_id: filter.trace_id.clone(),
            since: filter.since.clone(),
        };
        let read = Arc::clone(&self.read);
        self.rt.block_on(async move {
            read.query(&ef, limit)
                .await
                .map(|rows| rows.into_iter().map(Self::to_row).collect())
                .map_err(Self::map_err)
        })
    }

    fn drain_stream(
        &self,
        after_raw_id: Option<&str>,
        scan_ceiling: usize,
        idle_ms: u64,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        let read = Arc::clone(&self.read);
        let after = after_raw_id.map(|s| s.to_string());
        let idle = Duration::from_millis(idle_ms);
        self.rt.block_on(async move {
            let cursor = after.map(ReadCursor);
            let mut stream = read
                .resume(cursor, EventFilter::default())
                .await
                .map_err(Self::map_err)?;
            let mut out = Vec::new();
            while out.len() < scan_ceiling {
                match tokio::time::timeout(idle, stream.recv()).await {
                    Ok(Ok(Some(re))) => out.push(Self::to_row(re)),
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => return Err(Self::map_err(e)),
                    Err(_) => break, // idle end — success
                }
            }
            Ok(out)
        })
    }
}

fn events_api(live: &LiveBus) -> ClientApi {
    let custody = Arc::new(MemoryCursorKeyCustody::new_for_tests());
    let codec: Arc<dyn ClientCursorCodec> = Arc::new(AeadClientCursorCodec::new(
        custody,
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ));
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    ClientApi::with_parts(
        ClientApiConfig::default(),
        "tester",
        Arc::new(SystemClock),
        Arc::new(RecordingSink::new()),
    )
    .with_event_provider(Arc::new(BusProvider::new(live)))
    .with_leak_detector(detector)
    .with_cursor_codec(codec)
}

fn round_event(id: &str, iteration: u64) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "agent-a".into(),
        task_id: None,
        run_id: Some("run-1".into()),
        execution_id: None,
        trace_id: "00000000-0000-4000-8000-000000000001".into(),
        span_id: "span-1".into(),
        parent_span_id: None,
        event_type: "run.round_completed".into(),
        payload: json!({ "iteration": iteration }),
        duration_ms: None,
    }
}

fn poll_stream(api: &ClientApi, token: &str, body: Value) -> ClientEventPage {
    let mut req = ClientRequest::get("/client/events/stream").with_session(token);
    req.body = body;
    let env = api.handle(req);
    assert_envelope_invariant(&env, "reconnect_poll");
    assert!(env.is_ok(), "stream poll: {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("event page")
}

fn iterations_of(page: &ClientEventPage) -> Vec<u64> {
    page.events
        .iter()
        .map(|e| match e.data.get("iteration") {
            Some(ClientScalar::Unsigned(n)) => *n,
            other => panic!("iteration not projected as unsigned: {other:?}"),
        })
        .collect()
}

fn cursor_keys(page: &ClientEventPage) -> Vec<String> {
    let cur = page.cursor.as_ref().expect("cursor present");
    let as_json = serde_json::to_value(cur).unwrap();
    let mut keys: Vec<String> = as_json.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn ac12_reconnect_exercised_against_every_surface() {
    let live = LiveBus::start();
    let api = events_api(&live);
    let login = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "mac" }),
    ));
    assert!(login.is_ok(), "login: {:?}", login.error);
    let token = login.data.unwrap()["token"].as_str().unwrap().to_string();

    // Join (empty watermark), then produce batch A and CONSUME it.
    let join = poll_stream(&api, &token, Value::Null);
    assert!(join.events.is_empty());
    let c0 = join.cursor.clone().expect("watermark cursor");
    assert!(c0.last_event_id.is_some());

    for i in 0..5u64 {
        live.emit(round_event(&format!("a{i}"), i));
    }
    live.wait_count(5, Duration::from_secs(5));
    let page_a = poll_stream(
        &api,
        &token,
        json!({
            "stream_id": c0.stream_id,
            "last_event_id": c0.last_event_id,
            "limit": 32
        }),
    );
    let got_a = iterations_of(&page_a);
    assert_eq!(got_a, vec![0, 1, 2, 3, 4], "batch A consumed in order");
    let keys_a = cursor_keys(&page_a);
    let c1 = page_a.cursor.clone().unwrap();

    // DISCONNECT: the client goes away while batch B is produced.
    for i in 5..10u64 {
        live.emit(round_event(&format!("b{i}"), i));
    }
    live.wait_count(10, Duration::from_secs(5));

    // RESUME via the declared reconnect fields (stream_id + last_event_id).
    let reconnect_fields_used = vec!["last_event_id".to_string(), "stream_id".to_string()];
    let page_b = poll_stream(
        &api,
        &token,
        json!({
            "stream_id": c1.stream_id,
            "last_event_id": c1.last_event_id,
            "limit": 32
        }),
    );
    let got_b = iterations_of(&page_b);
    assert_eq!(
        got_b,
        vec![5, 6, 7, 8, 9],
        "resume is gap-free: exactly the missed batch, in order, no replays of batch A"
    );
    let keys_b = cursor_keys(&page_b);

    // Full sequence across the disconnect: exactly once each, ordered.
    let mut all = got_a.clone();
    all.extend(&got_b);
    assert_eq!(
        all,
        (0..10).collect::<Vec<u64>>(),
        "exactly-once across reconnect"
    );

    // A further poll from the final cursor delivers nothing new (no duplicates).
    let c2 = page_b.cursor.clone().unwrap();
    let page_idle = poll_stream(
        &api,
        &token,
        json!({
            "stream_id": c2.stream_id,
            "last_event_id": c2.last_event_id,
            "limit": 32
        }),
    );
    assert!(page_idle.events.is_empty(), "no duplicates after drain");

    // Assert the exercised reconnect cursor against EVERY platform surface fixture.
    let surfaces = committed_surfaces();
    assert_eq!(surfaces.len(), 5);
    for (target, surface) in &surfaces {
        assert_eq!(
            surface["reconnect_cursor"]["type"], "struct",
            "target {target}: declared reconnect cursor type"
        );
        let mut declared = surface_fields(surface, "reconnect_cursor");
        declared.sort();
        assert_eq!(
            reconnect_fields_used, declared,
            "target {target}: the resume request used exactly the declared reconnect fields"
        );
        for keys in [&keys_a, &keys_b] {
            assert_eq!(
                keys, &declared,
                "target {target}: observed reconnect cursor carries exactly the declared fields"
            );
        }
    }
}
