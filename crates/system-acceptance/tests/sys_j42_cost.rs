//! SYS-J-42 — the cost tracker subscribes to llm.response and exposes per-run
//! and per-iteration cost aggregates visible in the dashboard analytics view.
//! Chain: MODULE-009 → MODULE-019 → MODULE-008.
//!
//! Witnesses (harvest-obs slice, 2026-06-10): **SYS-AC-134 (qualified PASS,
//! user-gate decision 3), SYS-AC-135, SYS-AC-136** — test-local real wiring
//! (sys_budget_session_2turn precedent): real sync `EventBus` (its baked-in
//! CostTracker folds cost on emit), real `RunManager` (`ensure_run` emits the
//! real `run.created`), real `LlmGateway` over the h_loopback scripted backend
//! (the sole allowed double — the REAL OpenAI adapter parses its responses and
//! the gateway computes REAL cost_usd).
//!
//! **SYS-AC-134 fidelity disclosure (carried per plan + MODULE-019 §3.6 item
//! 27)**: the `runs` SQLite table has NO live-path writer — its only product
//! writer is `rebuild_sqlite_from_jsonl` (`fold_run` accumulates
//! `token_used`/`cost_usd` from `llm.response`), which has zero production
//! callers; a live daemon's `/query/runs` returns `null` until a rebuild runs.
//! This witness therefore drives emit → rebuild-fold → query — every component
//! is real product code and the fold IS the product's only runs-aggregation
//! implementation, but the live-incremental upsert is an open M019 product gap
//! (NOT claimed here). User-gate decision: qualified PASS with this disclosure.
//!
//! **SYS-AC-136 fidelity disclosure (per plan + MODULE-019 §3.6 item 28)**:
//! the distinct `iteration` values are stamped via `HostCallContext` because no
//! production caller on main populates a non-None iteration (M015 auto-mode /
//! M008 ComponentCtx producer wiring deferred); the consumer fold — cap-llm
//! `events.rs` writing `payload.iteration` + CostTracker keying by
//! `(run_id, iteration)` (CONTRACT-181) — is below the handler boundary and
//! fully real. The witness drives the production `AgentLlmGenerateHandler`
//! (the exact entry M015 will use; sys_j40_retry precedent).

#[path = "h_loopback/mod.rs"]
mod h_loopback;
use h_loopback::{boot, GatewayDeps, ScriptedResponse};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use advance_cli::wiring::run_config_from;
use advance_event_bus::query_api::{query_router, QueryState};
use advance_event_bus::rebuild_sqlite_from_jsonl;
use advance_event_bus::{EventBus, EventBusConfig};
use advance_run_manager::{RepetitionAction, RepetitionGuard, RunManager};
use advance_runtime::config::RunBudgetConfig;
use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::EventBusEmit;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use cap_llm::host_fn::AgentLlmGenerateHandler;
use cap_llm::{ChatMessage, ChatParams, ChatRole};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use tower::ServiceExt;
use wasmtime::component::Val;

const AGENT: &str = "obs-cost-agent";

fn user_msg() -> Vec<ChatMessage> {
    vec![ChatMessage {
        role: ChatRole::User,
        content: "hi".into(),
    }]
}

/// Real sync EventBus over a unique temp base; returns the bus + the base dir
/// (so tests can reach the JSONL dir for the rebuild fold).
fn real_bus(tag: &str) -> (Arc<EventBus>, std::path::PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("adv-obs-cost-{tag}-{nanos}"));
    std::fs::create_dir_all(&base).unwrap();
    let cfg = EventBusConfig::new(base.join("jsonl"), base.join("events.db"));
    (
        Arc::new(EventBus::new_synchronous_for_tests(cfg).expect("sync event bus")),
        base,
    )
}

fn deps(bus: Arc<dyn EventBusEmit>, rm: &RunManager) -> GatewayDeps {
    GatewayDeps {
        run_budget: Arc::new(rm.budget()),
        repetition_guard: Arc::new(RepetitionGuard::new(64, 100, RepetitionAction::WarnOnly)),
        event_bus: bus,
        default_agent_id: AGENT.into(),
    }
}

/// Oneshot GET against the production query router over `db_path`; returns the
/// parsed JSON body (panics on non-200).
async fn query_oneshot(db_path: &std::path::Path, uri: &str) -> serde_json::Value {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mgr = SqliteConnectionManager::file(db_path).with_flags(flags);
    let pool = Arc::new(r2d2::Pool::builder().max_size(2).build(mgr).unwrap());
    let router = query_router(QueryState { pool });
    let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65002".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "GET {uri} → 200, got {status}: {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).expect("JSON body")
}

/// Sum a top-level numeric payload field over all `llm.response` rows in the
/// live events table (ground truth the aggregates must reflect).
fn sum_llm_response_field(db_path: &std::path::Path, field: &str) -> f64 {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE event_type = 'llm.response'")
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    rows.iter()
        .map(|p| {
            serde_json::from_str::<serde_json::Value>(p)
                .ok()
                .and_then(|v| v.get(field).and_then(|f| f.as_f64()))
                .unwrap_or(0.0)
        })
        .sum()
}

/// SYS-AC-134 — after LLM calls emit llm.response with cost_usd, GET
/// /query/runs?run_id=<id> reflects the run's accumulated cost_usd/token_used
/// (via the production rebuild fold — see the module-header disclosure).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_134_query_runs_reflects_accumulated_cost_via_rebuild_fold() {
    let (bus, base) = real_bus("134");
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let rm = RunManager::new(bus_dyn.clone());
    let run_id = rm
        .ensure_run(
            "task-cost-134",
            AGENT,
            run_config_from(&RunBudgetConfig::default()),
        )
        .expect("ensure_run emits the real run.created");

    let harness = boot(
        vec![
            ScriptedResponse::ok_chat("turn-1", 100, 600),
            ScriptedResponse::ok_chat("turn-2", 50, 250),
        ],
        deps(bus_dyn.clone(), &rm),
    )
    .await;
    for _ in 0..2 {
        harness
            .gateway
            .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
            .await
            .expect("real gateway call over the loopback backend");
    }

    // Ground truth from the live events table (real gateway-computed cost).
    let live_db = base.join("events.db");
    let expected_cost = sum_llm_response_field(&live_db, "cost_usd");
    assert!(
        expected_cost > 0.0,
        "the real gateway computed a nonzero cost"
    );

    // Production fold: JSONL → fresh SQLite (the product's only runs writer).
    let rebuilt_db = base.join("rebuilt.db");
    let report = rebuild_sqlite_from_jsonl(&base.join("jsonl"), &rebuilt_db)
        .expect("rebuild fold over the real JSONL");
    assert!(
        report.events_replayed > 0,
        "rebuild replayed the emitted events"
    );

    // The production query surface reflects the accumulated run cost.
    let v = query_oneshot(&rebuilt_db, &format!("/runs?run_id={run_id}")).await;
    assert!(!v.is_null(), "runs row exists for {run_id} after the fold");
    assert_eq!(v["run_id"].as_str(), Some(run_id.to_string().as_str()));
    assert_eq!(
        v["task_id"], "task-cost-134",
        "task_id from the real run.created"
    );
    assert_eq!(
        v["token_used"].as_u64(),
        Some(100 + 600 + 50 + 250),
        "token_used == Σ(input+output) across both llm.response events"
    );
    let got_cost = v["cost_usd"].as_f64().expect("cost_usd present");
    assert!(
        (got_cost - expected_cost).abs() < 1e-9,
        "runs.cost_usd ({got_cost}) == Σ llm.response payload cost_usd ({expected_cost})"
    );
}

/// SYS-AC-135 — GET /query/dashboard/llm_analytics returns window aggregates
/// (cost_usd_total + tokens_in/out totals) over the real llm.response rows.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_135_llm_analytics_window_totals() {
    let (bus, base) = real_bus("135");
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let rm = RunManager::new(bus_dyn.clone());
    let run_id = rm
        .ensure_run(
            "task-cost-135",
            AGENT,
            run_config_from(&RunBudgetConfig::default()),
        )
        .expect("ensure_run");

    let harness = boot(
        vec![
            ScriptedResponse::ok_chat("turn-1", 100, 600),
            ScriptedResponse::ok_chat("turn-2", 50, 250),
        ],
        deps(bus_dyn.clone(), &rm),
    )
    .await;
    for _ in 0..2 {
        harness
            .gateway
            .chat_for_run(user_msg(), ChatParams::default(), run_id.to_string())
            .await
            .expect("real gateway call");
    }

    let live_db = base.join("events.db");
    let expected_cost = sum_llm_response_field(&live_db, "cost_usd");

    // The sync bus indexed the events inline; the dashboard reads them live.
    let v = query_oneshot(&live_db, "/dashboard/llm_analytics").await;
    assert_eq!(v["view"], "llm_analytics");
    assert_eq!(v["tokens_in_total"].as_u64(), Some(150), "Σ input_tokens");
    assert_eq!(v["tokens_out_total"].as_u64(), Some(850), "Σ output_tokens");
    assert_eq!(
        v["request_count"].as_u64(),
        Some(2),
        "two llm.response rows in window"
    );
    let got = v["cost_usd_total"].as_f64().expect("cost_usd_total");
    assert!(
        (got - expected_cost).abs() < 1e-9,
        "cost_usd_total ({got}) == Σ llm.response cost_usd ({expected_cost})"
    );
}

/// SYS-AC-136 — two iterations tagged with distinct payload.iteration produce
/// distinct per-iteration cost aggregates grouped by (run_id, iteration)
/// (CONTRACT-181 CostTrackerQuery — the journey's named product surface).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_136_distinct_iterations_distinct_aggregates() {
    let (bus, base) = real_bus("136");
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let rm = RunManager::new(bus_dyn.clone());
    let run_id = rm
        .ensure_run(
            "task-cost-136",
            AGENT,
            run_config_from(&RunBudgetConfig::default()),
        )
        .expect("ensure_run");
    let run = run_id.to_string();

    let harness = boot(
        vec![
            ScriptedResponse::ok_chat("iter-1", 10, 20),
            ScriptedResponse::ok_chat("iter-2", 30, 40),
        ],
        deps(bus_dyn.clone(), &rm),
    )
    .await;

    // Production host-fn entry (the path M015 auto-mode will drive), with the
    // iteration stamped through HostCallContext — see module-header disclosure.
    let handler = AgentLlmGenerateHandler {
        gateway: harness.gateway.clone(),
        turn_cost: None,
    };
    for iteration in [1u32, 2u32] {
        let ctx = HostCallContext {
            agent_id: AGENT.into(),
            trace_id: "trace-j42".into(),
            turn_id: None,
            capability: "llm".into(),
            function: "agent-llm::generate".into(),
            run_id: Some(run.clone()),
            iteration: Some(iteration),
        };
        handler
            .call(ctx, vec![Val::String("hi".into())], 1)
            .await
            .expect("generate host-fn dispatch ok");
    }

    // The real llm.response events carry the distinct payload.iteration tags.
    let conn = rusqlite::Connection::open_with_flags(
        base.join("events.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE event_type='llm.response' ORDER BY timestamp")
        .unwrap();
    let payloads: Vec<serde_json::Value> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .map(|p| serde_json::from_str(&p).unwrap())
        .collect();
    let mut iters: Vec<u64> = payloads
        .iter()
        .filter_map(|p| p.get("iteration").and_then(|i| i.as_u64()))
        .collect();
    iters.sort_unstable();
    assert_eq!(
        iters,
        vec![1, 2],
        "both llm.response rows carry distinct payload.iteration"
    );

    // CONTRACT-181: per-(run_id, iteration) aggregates are distinct + correct;
    // the per-run aggregate is their sum.
    let ct = bus.cost_tracker_query();
    let i1 = ct.query_iteration(&run, 1).expect("aggregate for (run, 1)");
    let i2 = ct.query_iteration(&run, 2).expect("aggregate for (run, 2)");
    assert_eq!(
        (i1.tokens_in, i1.tokens_out),
        (10, 20),
        "iteration-1 aggregate"
    );
    assert_eq!(
        (i2.tokens_in, i2.tokens_out),
        (30, 40),
        "iteration-2 aggregate"
    );
    assert_ne!(
        (i1.tokens_in, i1.tokens_out),
        (i2.tokens_in, i2.tokens_out),
        "distinct iterations produce distinct aggregates"
    );
    let total = ct.query_run(&run).expect("per-run aggregate");
    assert_eq!(
        (total.tokens_in, total.tokens_out, total.request_count),
        (40, 60, 2),
        "per-run aggregate is the sum over iterations"
    );
    assert!(
        (total.cost_usd - (i1.cost_usd + i2.cost_usd)).abs() < 1e-12,
        "per-run cost == Σ per-iteration cost"
    );
}
