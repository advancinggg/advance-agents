//! MODULE-020-AC-07 witness (e2e cell — BUILT + HELD): run controls pause/resume/cancel + inspect
//! runs through the Client API; creation is NOT a direct M008 call.
//!
//! Drives `ClientApi::handle()` end-to-end against a REAL MODULE-008 `RunManager` (real state flips
//! asserted via run status + real `run.*` events on an injected `EventBusEmit` recorder). This is a
//! module-altitude in-process witness; the system-altitude e2e (SYS-AC-269, wired console) is
//! Wave-25, so the §3.4 ledger keeps AC-07 `untested` (build-and-hold, §3.6). No fake-green: every
//! assertion observes a REAL provider transition or a REAL emitted event.

use std::sync::{Arc, Mutex};

use advance_client_api::runs::ClientAgentTreeNode;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientErrorCode, ClientRequest, ClientRunMutation,
    ClientRunSummary, ClientSession, Platform, Principal, ProviderError, RunControlProvider, Scope,
};

use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::{RunError, TaskRunStatus};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

// ── Recorders / stubs (copied from run-manager's own test patterns) ──

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

// ── Real-provider adapter (production wiring is Wave-25 cli; the witness supplies it) ──

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
    // Fixed client-safe identifiers — the raw RunError reason string is NEVER forwarded to the
    // client (raw provider error never leaks; matches the messages/tools adapters' discipline).
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
        // Witness path: round-trip the exact ensure_run id via the __test-util unchecked ctor
        // (production Wave-25 adapter uses the validated RunId::from_string). Any id shape is
        // accepted here; an id not in the store surfaces as RunError::NotFound → not_found.
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
        Ok(self
            .mgr
            .list_runs()
            .into_iter()
            .map(|r| ClientRunSummary {
                run_id: r.id.to_string(),
                task_id: r.task_id.clone(),
                controller_agent: r.controller_agent.clone(),
                status: status_label(&r.status).to_string(),
                iteration: r.iteration,
                token_used: r.budget.token_used,
                token_limit: r.budget.token_limit,
                cost_usd: r.budget.cost_usd,
                cost_usd_limit: r.budget.cost_limit,
                created_at: r.created_at.to_rfc3339(),
                updated_at: r.updated_at.to_rfc3339(),
            })
            .collect())
    }
    fn agent_tree(&self) -> Result<Vec<ClientAgentTreeNode>, ProviderError> {
        // Flat agent view derived from live run controllers (CONTRACT-071 run-state read); a richer
        // MODULE-005 AgentTreeSnapshot projection is Wave-25 (§3.6 implementation-defined).
        Ok(self
            .mgr
            .list_runs()
            .into_iter()
            .map(|r| ClientAgentTreeNode {
                id: r.controller_agent.clone(),
                kind: "controller".to_string(),
                parent: None,
                status: status_label(&r.status).to_string(),
                template_ref: None,
            })
            .collect())
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
        // Resume is sync; the adapter passes a RESUME_REASONS-valid reason ("manual"), NOT the
        // client's arbitrary reason (which would be PermissionDenied).
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

// ── Scaffolding ──

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    let session = ClientSession {
        session_id: format!("sess-{token}"),
        principal: Principal {
            id: "operator".to_string(),
            os_user: "op".to_string(),
        },
        platform: Platform::Mac,
        scopes,
        csrf_token: None,
        expires_at: u64::MAX,
    };
    api.sessions().insert(token.to_string(), session, 0);
}

struct Fixture {
    api: ClientApi,
    mgr: Arc<RunManager>,
    bus: Arc<MockEventBus>,
}

fn fixture() -> Fixture {
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
    let api = ClientApi::new(ClientApiConfig::default()).with_run_provider(Arc::new(adapter));
    mint(&api, "tok", vec![Scope::ReadRuns, Scope::ControlRuns]);
    Fixture { api, mgr, bus }
}

fn mutate(
    api: &ClientApi,
    run_id: &str,
    action: &str,
    key: &str,
) -> advance_client_api::ClientEnvelope<serde_json::Value> {
    api.handle(
        ClientRequest::post(
            format!("/client/runs/{run_id}:{action}"),
            serde_json::json!({ "reason": "witness" }),
        )
        .with_session("tok")
        .with_idempotency_key(key),
    )
}

fn parse_mutation(
    env: &advance_client_api::ClientEnvelope<serde_json::Value>,
) -> ClientRunMutation {
    assert!(env.is_ok(), "expected ok, got {:?}", env.error);
    serde_json::from_value(env.data.clone().expect("data")).expect("ClientRunMutation")
}

// ── T07: pause → resume → cancel through handle(), asserting REAL RunManager state + run.* events ──

#[test]
fn t07_run_controls_flip_real_state_and_emit_events() {
    let fx = fixture();
    let id = fx
        .mgr
        .ensure_run("task-1", "operator", RunConfig::default())
        .unwrap();
    let run_id = id.to_string();

    // T07d (creation discriminator, part 1): the created run appears in GET /client/runs.
    let list_env = fx
        .api
        .handle(ClientRequest::get("/client/runs").with_session("tok"));
    assert!(list_env.is_ok());
    let runs: Vec<ClientRunSummary> =
        serde_json::from_value(list_env.data.unwrap()["runs"].clone()).unwrap();
    assert!(
        runs.iter().any(|r| r.run_id == run_id),
        "created run listed"
    );

    // agent-tree view rides AC-07 (derived from run controllers).
    let tree_env = fx
        .api
        .handle(ClientRequest::get("/client/runs/tree").with_session("tok"));
    let nodes: Vec<ClientAgentTreeNode> =
        serde_json::from_value(tree_env.data.unwrap()["nodes"].clone()).unwrap();
    assert!(nodes.iter().any(|n| n.id == "operator"));

    // T07a pause: Suspended → Paused (REAL flip + run.paused). suspend_run flips Active→Suspended
    // AND sets root_await, so pause_run's branch (a) closes the session and flips to Paused.
    fx.mgr.suspend_run(&id, "sid-a").unwrap();
    let m = parse_mutation(&mutate(&fx.api, &run_id, "pause", "k-pause"));
    assert_eq!(m.status, "paused");
    assert!(!m.emitted_event_ids.is_empty(), "run.paused id surfaced");
    assert!(
        matches!(
            fx.mgr.snapshot_status_for_test(&id),
            Some(TaskRunStatus::Paused)
        ),
        "REAL RunManager state flipped to Paused"
    );
    assert_eq!(
        fx.bus.count(&run_id, "run.paused"),
        1,
        "exactly one real run.paused"
    );

    // T07e idempotency: replaying the SAME key → NO second provider transition (exactly-once).
    let replay = mutate(&fx.api, &run_id, "pause", "k-pause");
    assert!(replay.is_ok());
    assert!(
        replay
            .warnings
            .iter()
            .any(|w| w.code == "idempotent_replay"),
        "replay carries the idempotent_replay warning"
    );
    assert_eq!(
        fx.bus.count(&run_id, "run.paused"),
        1,
        "replay did NOT drive a second pause_run"
    );

    // T07b resume: Paused → Active (REAL flip + run.resumed).
    let m = parse_mutation(&mutate(&fx.api, &run_id, "resume", "k-resume"));
    assert_eq!(m.status, "active");
    assert!(
        matches!(
            fx.mgr.snapshot_status_for_test(&id),
            Some(TaskRunStatus::Active)
        ),
        "REAL state flipped back to Active"
    );
    assert_eq!(fx.bus.count(&run_id, "run.resumed"), 1);

    // T07c cancel: from a Suspended precondition → Cancelled (REAL flip + run.cancelled).
    fx.mgr.suspend_run(&id, "sid-c").unwrap();
    let m = parse_mutation(&mutate(&fx.api, &run_id, "cancel", "k-cancel"));
    assert_eq!(m.status, "cancelled");
    assert!(
        matches!(
            fx.mgr.snapshot_status_for_test(&id),
            Some(TaskRunStatus::Cancelled(_))
        ),
        "REAL state flipped to Cancelled"
    );
    assert_eq!(fx.bus.count(&run_id, "run.cancelled"), 1);
}

#[test]
fn t07d_creation_is_not_a_client_op() {
    let fx = fixture();
    // POST /client/runs is not served — run creation flows via messaging/submit, not the client API.
    let env = fx.api.handle(
        ClientRequest::post("/client/runs", serde_json::json!({}))
            .with_session("tok")
            .with_idempotency_key("k"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::UnknownRoute));
}

#[test]
fn t07e_missing_idempotency_key_no_provider_call() {
    let fx = fixture();
    let id = fx
        .mgr
        .ensure_run("task-1", "operator", RunConfig::default())
        .unwrap();
    fx.mgr.suspend_run(&id, "sid").unwrap();
    let run_id = id.to_string();
    // A mutation with NO idempotency key → idempotency_required, and NO provider transition.
    let env = fx.api.handle(
        ClientRequest::post(
            format!("/client/runs/{run_id}:pause"),
            serde_json::json!({}),
        )
        .with_session("tok"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::IdempotencyRequired));
    assert_eq!(
        fx.bus.count(&run_id, "run.paused"),
        0,
        "no provider call on a keyless mutation"
    );
    assert!(matches!(
        fx.mgr.snapshot_status_for_test(&id),
        Some(TaskRunStatus::Suspended)
    ));
}

#[test]
fn t07f_error_projection_and_ordering() {
    // provider-absent → module_unavailable (no synthesized state).
    let bare = ClientApi::new(ClientApiConfig::default());
    mint(&bare, "tok", vec![Scope::ReadRuns, Scope::ControlRuns]);
    let env = bare.handle(
        ClientRequest::post("/client/runs/whatever:pause", serde_json::json!({}))
            .with_session("tok")
            .with_idempotency_key("k"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::ModuleUnavailable));

    let fx = fixture();
    // unknown run id → not_found (raw RunError::NotFound never leaks).
    let env = mutate(&fx.api, "no-such-run", "pause", "k1");
    assert_eq!(env.error_code(), Some(ClientErrorCode::NotFound));

    // unauth rejected BEFORE any provider call (no session).
    let env = fx.api.handle(
        ClientRequest::post("/client/runs/x:pause", serde_json::json!({}))
            .with_idempotency_key("k2"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::Unauthenticated));

    // invalid transition (pause a Completed run) → invalid_state.
    let id = fx
        .mgr
        .ensure_run("task-done", "operator", RunConfig::default())
        .unwrap();
    fx.mgr
        .with_status_for_test(&id, TaskRunStatus::Completed)
        .unwrap();
    let env = mutate(&fx.api, &id.to_string(), "pause", "k3");
    assert_eq!(env.error_code(), Some(ClientErrorCode::InvalidState));

    // under-scoped session → forbidden (has a session but not ControlRuns).
    mint(&fx.api, "tok-ro", vec![Scope::ReadRuns]);
    let env = fx.api.handle(
        ClientRequest::post("/client/runs/x:pause", serde_json::json!({}))
            .with_session("tok-ro")
            .with_idempotency_key("k4"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::Forbidden));
}

#[test]
fn t07_scope_enforced_before_idempotency_replay() {
    // A privileged (ControlRuns) session performs a pause, recording the outcome under an
    // idempotency key. The SAME principal but an under-scoped session replaying that key must be
    // denied `forbidden` BEFORE the idempotency replay lookup — it must NEVER receive the cached
    // privileged mutation outcome (the scope gate runs after auth, before the mutation gate).
    let fx = fixture();
    let id = fx
        .mgr
        .ensure_run("task-1", "operator", RunConfig::default())
        .unwrap();
    fx.mgr.suspend_run(&id, "sid").unwrap();
    let run_id = id.to_string();

    let ok = mutate(&fx.api, &run_id, "pause", "shared-key");
    assert!(ok.is_ok(), "privileged pause succeeds");
    assert_eq!(fx.bus.count(&run_id, "run.paused"), 1);

    mint(&fx.api, "tok-ro", vec![Scope::ReadRuns]); // same principal "operator", missing ControlRuns
    let replay = fx.api.handle(
        ClientRequest::post(
            format!("/client/runs/{run_id}:pause"),
            serde_json::json!({}),
        )
        .with_session("tok-ro")
        .with_idempotency_key("shared-key"),
    );
    assert_eq!(
        replay.error_code(),
        Some(ClientErrorCode::Forbidden),
        "under-scoped replay must be denied, not surface the cached mutation"
    );
    assert!(
        replay.data.is_none(),
        "no cached data surfaced to the under-scoped caller"
    );
}

#[test]
fn t07_noncanonical_path_does_not_route() {
    let fx = fixture();
    // A non-canonical path (double leading slash) must NOT match the templated route → unknown_route,
    // so it can never execute under a mismatched idempotency/audit family.
    let env = fx.api.handle(
        ClientRequest::post("//client/runs/x:pause", serde_json::json!({}))
            .with_session("tok")
            .with_idempotency_key("k"),
    );
    assert_eq!(env.error_code(), Some(ClientErrorCode::UnknownRoute));
}
