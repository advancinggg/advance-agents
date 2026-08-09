//! MODULE-013 AC-24 — production-composition witness for CONTRACT-123
//! `GrantApprovalIntake`.
//!
//! AI-11 (same-Arc pin): boot the REAL `wire_capabilities` composition root,
//! drive `request-capability` through the PRODUCTION-registered host handler, and
//! observe the parked request in `handles.grant_approval_intake.list_pending()` —
//! proving the registered chain's Channel port IS the exposed intake Arc. A
//! regression reverting the wired channel port to `default_channel_approval_port()`
//! would leave `list_pending()` empty (and the request Denied), failing the test.
//!
//! AI-12: the production builder functions `build_grant_approval_intake` +
//! `build_grant_resolver_chain` compose and close the operator approval loop.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_cli::wiring::{
    build_grant_approval_intake, build_grant_resolver_chain, wire_capabilities,
};
use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, RunBudget};
use cap_grant::data::{CapParam, ChainDecision, GrantRequest, GrantTtl};
use cap_grant::resolver::{ChannelApprovalPort, ResolverChain, ResolverContext};
use cap_grant::subset::{SubsetValidator, SubsetValidatorImpl};
use cap_grant::{GrantSqliteIndex, GrantStore, PresetRegistry};
use wasmtime::component::Val;

// ---- AI-11 — production composition (wire_capabilities) ----------------------

fn runtime_yaml() -> String {
    r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
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
  env-var-name: ADV_INTAKE_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

/// `.agent/config.yaml` declaring ONLY the `grant` capability (so `declares_grant`
/// is true and the intake is wired; no master key needed).
const GRANT_ONLY_CAPS: &str = "capabilities:\n  grant: true\n";

fn fresh_workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), GRANT_ONLY_CAPS).unwrap();
    (dir, workspace, config_path)
}

fn ctx() -> HostCallContext {
    HostCallContext {
        agent_id: "agent:test".to_string(),
        trace_id: "trace-intake".to_string(),
        turn_id: None,
        capability: "grant".to_string(),
        function: "advance:runtime/agent-grant@0.1.0::request-capability".to_string(),
        // MUST be None: production wires BudgetCheck with the live budget, which
        // fail-closes on an unknown Some(run_id) before the request reaches Channel.
        run_id: None,
        iteration: None,
    }
}

/// A `grant-request` WIT record for `fs` read-paths (no covering parent grant →
/// SubsetAutoApprove abstains → reaches the Channel intake).
fn fs_request_val() -> Val {
    Val::Record(vec![
        ("capability".into(), Val::String("fs".into())),
        (
            "params".into(),
            Val::Option(Some(Box::new(Val::List(vec![Val::Record(vec![
                ("key".into(), Val::String("read-paths".into())),
                ("value".into(), Val::String("/a".into())),
            ])])))),
        ),
        (
            "justification".into(),
            Val::Option(Some(Box::new(Val::String("intake wiring test".into())))),
        ),
    ])
}

/// Extract the `grant-decision` variant case from a `request-capability` result.
fn decision_case(out: Vec<Val>) -> String {
    assert_eq!(out.len(), 1, "one result value");
    match out.into_iter().next().unwrap() {
        Val::Result(Ok(Some(boxed))) => match *boxed {
            Val::Variant(case, _) => case,
            other => panic!("expected grant-decision variant, got {other:?}"),
        },
        other => panic!("expected Val::Result(Ok(Some)), got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ai_11_production_wiring_parks_in_exposed_intake_then_approves() {
    let (_dir, ws, cfg) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let intake = handles
        .grant_approval_intake
        .clone()
        .expect("production wire_capabilities constructed the grant approval intake");

    let handler = host
        .host_registry()
        .lookup("grant")
        .into_iter()
        .find(|s| s.name == "request-capability")
        .expect("production wire_capabilities registered request-capability")
        .handler;

    // First call → the PRODUCTION-registered chain parks the request pending.
    let d1 = decision_case(
        handler
            .call(ctx(), vec![fs_request_val()], 1)
            .await
            .expect("request-capability call ok"),
    );
    assert_eq!(d1, "pending", "no operator decision yet → pending");

    // SAME-ARC PIN: the parked request is visible via the exposed intake handle →
    // the registered chain's Channel port IS this intake (not the fail-closed
    // default). A revert to default_channel_approval_port() empties this list.
    let pending = intake.list_pending();
    assert_eq!(
        pending.len(),
        1,
        "the production-wired chain parked the request in the exposed intake"
    );
    assert_eq!(pending[0].caller, "agent:test");
    assert_eq!(pending[0].capability, "fs");
    let rid = pending[0].request_id.clone();

    // Operator approves through the exposed intake; the guest retry (same
    // production handler) observes the approval.
    intake.approve(&rid).expect("operator approve");
    let d2 = decision_case(
        handler
            .call(ctx(), vec![fs_request_val()], 1)
            .await
            .expect("retry call ok"),
    );
    assert_eq!(
        d2, "approved",
        "retry observes the operator's approval through the production wiring"
    );
    assert!(
        intake.list_pending().is_empty(),
        "single-use: the decision was consumed on retry"
    );
}

// ---- AI-12 — production builder functions compose + close the loop -----------

struct RecordingBus {
    events: Mutex<Vec<Event>>,
}
impl RecordingBus {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
        })
    }
}
impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct AllowBudget;
impl RunBudget for AllowBudget {
    fn check(&self, _run_id: &str, _tokens: u64, _cost: f64) -> BudgetDecision {
        BudgetDecision::Allow
    }
    fn commit(&self, _run_id: &str, _tokens: u64, _cost: f64) {}
}

fn make_store() -> (Arc<GrantStore>, Arc<RecordingBus>) {
    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
    let index = GrantSqliteIndex::new(handle);
    index.ensure_schema().expect("ensure_schema");
    let bus = RecordingBus::new();
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    (Arc::new(GrantStore::new(index, bus_dyn)), bus)
}

fn fs_request() -> GrantRequest {
    GrantRequest {
        caller: "agent:x".to_string(),
        capability: "fs".to_string(),
        params: Some(vec![CapParam {
            key: "read-paths".to_string(),
            value: "/a".to_string(),
        }]),
        ttl: GrantTtl::Once,
        justification: None,
    }
}

fn drive(
    chain: &ResolverChain,
    store: &GrantStore,
    bus: &Arc<dyn EventBusEmit>,
    req: GrantRequest,
) -> ChainDecision {
    let parents = store.list_by_grantee(&req.caller);
    let ctx = ResolverContext {
        parent_grants: &parents,
        run_id: None,
    };
    chain.evaluate(req, ctx, store, bus)
}

#[test]
fn ai_12_production_builders_compose_and_close_the_loop() {
    let (store, bus) = make_store();
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let presets = Arc::new(PresetRegistry::with_builtins());
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    // The EXACT production builder functions.
    let intake =
        build_grant_approval_intake(store.clone(), validator.clone(), presets, bus_dyn.clone());
    let chain = build_grant_resolver_chain(
        validator,
        Arc::new(AllowBudget),
        Some(intake.clone() as Arc<dyn ChannelApprovalPort>),
    );

    // request → pending → operator approve → retry → approved.
    assert_eq!(
        drive(&chain, &store, &bus_dyn, fs_request()),
        ChainDecision::Pending
    );
    let rid = intake.list_pending()[0].request_id.clone();
    intake.approve(&rid).expect("approve");
    let d = drive(&chain, &store, &bus_dyn, fs_request());
    assert!(
        matches!(d, ChainDecision::Approved(_)),
        "production builders close the approval loop, got {d:?}"
    );
}
