//! HTTP `/query/*` API (Slice B AC-11).
//!
//! Mountable axum sub-router with 4 GET routes:
//! - `/query/traces?trace_id=...`
//! - `/query/runs?run_id=...`
//! - `/query/agents?agent_id=...`
//! - `/query/events?event_type=...&since=...&limit=...`
//!
//! All queries use rusqlite prepared statements (parameterized SQL) — Round-3 W7
//! protection against SQL injection (test T42 canary verification).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

const DEFAULT_LIMIT: u32 = 1000;
// Adversarial Round-1 W3 fix: cap MAX_LIMIT at 1000 (was 10_000). At 64 KiB
// per-event payload × 10_000 = 640 MiB worst-case allocation per request × 30
// burst tokens × N concurrent IPs amplifies into multi-GB transient memory
// pressure. Cap at 1000 events per request — clients needing more should
// page via since-cursor.
// Slice m019-readapi: widened to `pub(crate)` so `read_api::query` reuses the
// single 1000-row cap (single source of truth). No behavior change.
pub(crate) const MAX_LIMIT: u32 = 1000;

#[derive(Clone)]
pub struct QueryState {
    pub pool: Arc<Pool<SqliteConnectionManager>>,
}

#[derive(Debug, Serialize)]
pub struct EventRow {
    pub id: String,
    pub timestamp: String,
    pub agent_id: Option<String>,
    pub task_id: Option<String>,
    pub run_id: Option<String>,
    pub execution_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub event_type: String,
    pub payload: Option<String>,
    pub duration_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RunRow {
    pub run_id: String,
    pub task_id: String,
    pub controller_agent: Option<String>,
    pub status: Option<String>,
    pub token_used: Option<i64>,
    pub cost_usd: Option<f64>,
    pub last_resume_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentStatsRow {
    pub agent_id: String,
    pub active_tasks: Option<i64>,
    pub completed_tasks: Option<i64>,
    pub avg_turns_per_task: Option<f64>,
    pub avg_completion_time_hours: Option<f64>,
    pub memory_entries: Option<i64>,
    pub llm_tokens_24h: Option<i64>,
    pub error_count_24h: Option<i64>,
    pub last_active: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TraceQuery {
    pub trace_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RunQuery {
    pub run_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentQuery {
    pub agent_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub event_type: Option<String>,
    pub since: Option<String>,
    pub limit: Option<u32>,
}

pub fn query_router(state: QueryState) -> Router {
    use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

    // Round-1 AUDIT diff Critical 4 fix: tower_governor::GovernorLayer enforces
    // per-IP rate limit — 60 req/min per peer (1 req/sec sustained, with burst
    // up to 30). The `key_extractor` defaults to `PeerIpKeyExtractor` which
    // pulls from `ConnectInfo<SocketAddr>` set by the axum
    // `into_make_service_with_connect_info` adapter. Production callers MUST
    // use that adapter when binding the merged router; tests using
    // `Router::oneshot()` won't have ConnectInfo and will hit the layer's
    // fallback (allow-all). See ws_broadcaster.rs for the same pattern.
    //
    // 1 sec replenish + burst_size = 30 ≈ 60 req/min sustained (per
    // tower_governor README's quota math).
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(30)
            .finish()
            .expect("static governor config"),
    );
    Router::new()
        .route("/traces", get(handle_traces))
        .route("/runs", get(handle_runs))
        .route("/agents", get(handle_agents))
        .route("/events", get(handle_events))
        // Slice C: GET /query/sweeper_state returns retention sweeper status.
        // Read-only single-row table; inherits the loopback bind + tower_governor
        // rate limit from the parent router.
        .route("/sweeper_state", get(handle_sweeper_state))
        // Slice E (AC-15): parametric dashboard view route. 10 PRD §15.9 names
        // accepted; unknown view names return 404. Registered BEFORE the
        // GovernorLayer call so it inherits the per-IP rate limit + 127.0.0.1
        // bind defaults from the parent router. axum 0.8 uses `{capture}`
        // syntax (not v0.7's `:capture`).
        .route("/dashboard/{view}", get(handle_dashboard_view))
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .with_state(state)
}

#[derive(serde::Serialize)]
pub struct SweeperStateRow {
    pub last_sweep_at: Option<String>,
    pub files_removed_total: i64,
    pub bytes_freed_total: i64,
    pub sweep_count: i64,
}

async fn handle_sweeper_state(
    State(state): State<QueryState>,
) -> Result<Json<SweeperStateRow>, (StatusCode, String)> {
    let pool = state.pool.clone();
    let row = tokio::task::spawn_blocking(move || -> rusqlite::Result<SweeperStateRow> {
        let conn = pool.get().map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(e.to_string())))
        })?;
        let mut stmt = conn.prepare_cached(
            "SELECT last_sweep_at, files_removed_total, bytes_freed_total, sweep_count \
             FROM sweeper_state WHERE id = 1",
        )?;
        stmt.query_row([], |row| {
            Ok(SweeperStateRow {
                last_sweep_at: row.get(0)?,
                files_removed_total: row.get(1)?,
                bytes_freed_total: row.get(2)?,
                sweep_count: row.get(3)?,
            })
        })
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(row))
}

async fn handle_traces(
    State(state): State<QueryState>,
    Query(q): Query<TraceQuery>,
) -> Result<Json<Vec<EventRow>>, (StatusCode, String)> {
    let pool = state.pool.clone();
    let trace_id = q.trace_id;
    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<EventRow>, rusqlite::Error> {
        let conn = pool.get().map_err(map_pool_err)?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, timestamp, agent_id, task_id, run_id, execution_id, trace_id, span_id, \
             parent_span_id, event_type, payload, duration_ms FROM events \
             WHERE trace_id = ?1 ORDER BY timestamp",
        )?;
        let mapped = stmt.query_map([&trace_id], event_row_from_sql)?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(rows))
}

async fn handle_runs(
    State(state): State<QueryState>,
    Query(q): Query<RunQuery>,
) -> Result<Json<Option<RunRow>>, (StatusCode, String)> {
    let pool = state.pool.clone();
    let run_id = q.run_id;
    let row = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<RunRow>> {
        let conn = pool.get().map_err(map_pool_err)?;
        let mut stmt = conn.prepare_cached(
            "SELECT run_id, task_id, controller_agent, status, token_used, cost_usd, last_resume_reason \
             FROM runs WHERE run_id = ?1",
        )?;
        stmt.query_row([&run_id], run_row_from_sql).optional()
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(row))
}

async fn handle_agents(
    State(state): State<QueryState>,
    Query(q): Query<AgentQuery>,
) -> Result<Json<Option<AgentStatsRow>>, (StatusCode, String)> {
    let pool = state.pool.clone();
    let agent_id = q.agent_id;
    let row = tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<AgentStatsRow>> {
        let conn = pool.get().map_err(map_pool_err)?;
        let mut stmt = conn.prepare_cached(
            "SELECT agent_id, active_tasks, completed_tasks, avg_turns_per_task, \
             avg_completion_time_hours, memory_entries, llm_tokens_24h, error_count_24h, last_active \
             FROM agent_stats WHERE agent_id = ?1",
        )?;
        stmt.query_row([&agent_id], agent_stats_row_from_sql).optional()
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(row))
}

async fn handle_events(
    State(state): State<QueryState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<EventRow>>, (StatusCode, String)> {
    let pool = state.pool.clone();
    let event_type = q.event_type;
    // Round-2 AUDIT diff Warning 5 fix: validate `since` as ISO-8601 before
    // passing to SQL. The events.timestamp column stores ISO strings; a malformed
    // `since` value would silently bypass the lexicographic filter. Reject with
    // 400 Bad Request rather than returning unexpected results.
    let since = match q.since {
        Some(s) => match chrono::DateTime::parse_from_rfc3339(&s) {
            Ok(_) => Some(s),
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "invalid `since` parameter: expected ISO-8601 / RFC 3339 format".to_string(),
                ));
            }
        },
        None => None,
    };
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as i64;
    let rows = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<EventRow>> {
        let conn = pool.get().map_err(map_pool_err)?;
        // Build a parameterized SELECT covering both filters using SQL `COALESCE` /
        // bind-variable patterns so the SQL string itself is constant. NULL parameters
        // disable the corresponding filter clause.
        let mut stmt = conn.prepare_cached(
            "SELECT id, timestamp, agent_id, task_id, run_id, execution_id, trace_id, span_id, \
             parent_span_id, event_type, payload, duration_ms FROM events \
             WHERE (?1 IS NULL OR event_type = ?1) \
               AND (?2 IS NULL OR timestamp >= ?2) \
             ORDER BY timestamp DESC LIMIT ?3",
        )?;
        let mapped = stmt.query_map(
            rusqlite::params![event_type, since, limit],
            event_row_from_sql,
        )?;
        mapped.collect()
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(rows))
}

fn event_row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        agent_id: row.get(2)?,
        task_id: row.get(3)?,
        run_id: row.get(4)?,
        execution_id: row.get(5)?,
        trace_id: row.get(6)?,
        span_id: row.get(7)?,
        parent_span_id: row.get(8)?,
        event_type: row.get(9)?,
        payload: row.get(10)?,
        duration_ms: row.get(11)?,
    })
}

fn run_row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<RunRow> {
    Ok(RunRow {
        run_id: row.get(0)?,
        task_id: row.get(1)?,
        controller_agent: row.get(2)?,
        status: row.get(3)?,
        token_used: row.get(4)?,
        cost_usd: row.get(5)?,
        last_resume_reason: row.get(6)?,
    })
}

fn agent_stats_row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentStatsRow> {
    Ok(AgentStatsRow {
        agent_id: row.get(0)?,
        active_tasks: row.get(1)?,
        completed_tasks: row.get(2)?,
        avg_turns_per_task: row.get(3)?,
        avg_completion_time_hours: row.get(4)?,
        memory_entries: row.get(5)?,
        llm_tokens_24h: row.get(6)?,
        error_count_24h: row.get(7)?,
        last_active: row.get(8)?,
    })
}

fn map_pool_err(e: r2d2::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    )))
}

impl IntoResponse for crate::error::EventBusError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

// ─── Slice E (AC-15): Dashboard view dispatch ──────────────────────────────
//
// `GET /query/dashboard/:view` accepts 10 PRD §15.9 view names. Unknown view
// names return HTTP 404. Each view returns a JSON envelope shape:
//
//   { "view": <name>, "events": [<EventRow>...] }                  (for stream views)
//   { "view": "llm_analytics", "window_secs": N, ... rate fields } (for analytics)
//   { "view": "run_panel", ... run summary }                        (for panel views)
//
// All views are bounded by MAX_LIMIT=1000 and inherit the tower_governor
// per-IP rate limit + 127.0.0.1 bind defaults from the parent router.

/// The 10 PRD §15.9 dashboard view names. Closed enum; any other view
/// argument returns 404.
const DASHBOARD_VIEW_NAMES: &[&str] = &[
    "message_flow",
    "run_panel",
    "agent_panel",
    "task_timeline",
    "llm_analytics",
    "recall_quality",
    "topology",
    "trace",
    "security",
    "grant_panel",
];

#[derive(Debug, Serialize)]
struct DashboardEnvelope {
    view: String,
    events: Vec<EventRow>,
}

#[derive(Debug, Serialize)]
struct LlmAnalyticsResponse {
    view: &'static str,
    window_secs: u64,
    tokens_in_total: u64,
    tokens_out_total: u64,
    cost_usd_total: f64,
    request_count: u64,
    tokens_per_min: f64,
    cost_per_min: f64,
    requests_per_min: f64,
}

async fn handle_dashboard_view(
    Path(view): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<QueryState>,
) -> axum::response::Response {
    if !DASHBOARD_VIEW_NAMES.contains(&view.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            format!("unknown dashboard view: {view}"),
        )
            .into_response();
    }
    // Dispatch by view name. Each branch returns its own response shape.
    match view.as_str() {
        "message_flow" => dashboard_event_filter(
            state,
            "message_flow",
            "event_type LIKE 'msg.%' OR event_type LIKE 'mailbox.%' OR event_type LIKE 'channel.%'",
        )
        .await,
        "task_timeline" => dashboard_event_filter(
            state,
            "task_timeline",
            "event_type LIKE 'task.%' OR event_type = 'post.summary'",
        )
        .await,
        "recall_quality" => dashboard_event_filter(state, "recall_quality", "event_type LIKE 'recall.%'").await,
        "topology" => dashboard_event_filter(
            state,
            "topology",
            "event_type LIKE 'component.%' OR event_type = 'msg.routed'",
        )
        .await,
        "security" => dashboard_event_filter(state, "security", "event_type LIKE 'security.%'").await,
        "grant_panel" => dashboard_event_filter(
            state,
            "grant_panel",
            "event_type LIKE 'grant.%' OR event_type LIKE 'authz.%' OR event_type LIKE 'preset.%' OR event_type LIKE 'resolver.%'",
        )
        .await,
        "trace" => dashboard_trace(state, &params).await,
        "run_panel" => dashboard_run_panel(state, &params).await,
        "agent_panel" => dashboard_agent_panel(state, &params).await,
        "llm_analytics" => dashboard_llm_analytics(state, &params).await,
        _ => unreachable!("view name validated above"),
    }
}

/// Generic event-stream view: SELECT * FROM events WHERE <filter> ORDER BY timestamp DESC LIMIT 1000.
async fn dashboard_event_filter(
    state: QueryState,
    view: &'static str,
    where_clause: &'static str,
) -> axum::response::Response {
    let pool = state.pool.clone();
    let sql = format!(
        "SELECT id, timestamp, agent_id, task_id, run_id, execution_id, trace_id, \
                span_id, parent_span_id, event_type, payload, duration_ms \
         FROM events \
         WHERE {where_clause} \
         ORDER BY timestamp DESC \
         LIMIT {MAX_LIMIT}"
    );
    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<EventRow>, rusqlite::Error> {
        let conn = pool.get().map_err(map_pool_err)?;
        let mut stmt = conn.prepare(&sql)?;
        let iter = stmt.query_map([], event_row_from_sql)?;
        iter.collect()
    })
    .await;
    match rows {
        Ok(Ok(events)) => Json(DashboardEnvelope {
            view: view.to_string(),
            events,
        })
        .into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn dashboard_trace(
    state: QueryState,
    params: &HashMap<String, String>,
) -> axum::response::Response {
    let trace_id = match params.get("trace_id") {
        Some(t) => t.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "trace view requires ?trace_id= parameter".to_string(),
            )
                .into_response()
        }
    };
    let pool = state.pool.clone();
    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<EventRow>, rusqlite::Error> {
        let conn = pool.get().map_err(map_pool_err)?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, timestamp, agent_id, task_id, run_id, execution_id, trace_id, \
                    span_id, parent_span_id, event_type, payload, duration_ms \
             FROM events WHERE trace_id = ? ORDER BY timestamp",
        )?;
        let iter = stmt.query_map([trace_id], event_row_from_sql)?;
        iter.collect()
    })
    .await;
    match rows {
        Ok(Ok(events)) => Json(DashboardEnvelope {
            view: "trace".to_string(),
            events,
        })
        .into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn dashboard_run_panel(
    state: QueryState,
    params: &HashMap<String, String>,
) -> axum::response::Response {
    // If ?run_id=… is provided, return that run's row; otherwise return up to 100 recent runs.
    if let Some(run_id) = params.get("run_id").cloned() {
        let pool = state.pool.clone();
        let row = tokio::task::spawn_blocking(
            move || -> Result<Option<RunRow>, rusqlite::Error> {
                let conn = pool.get().map_err(map_pool_err)?;
                let mut stmt = conn.prepare_cached(
                    "SELECT run_id, task_id, controller_agent, status, token_used, cost_usd, last_resume_reason \
                     FROM runs WHERE run_id = ?",
                )?;
                stmt.query_row([run_id], run_row_from_sql).optional()
            },
        )
        .await;
        return match row {
            Ok(Ok(r)) => Json(r).into_response(),
            Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }
    let pool = state.pool.clone();
    let rows = tokio::task::spawn_blocking(move || -> Result<Vec<RunRow>, rusqlite::Error> {
        let conn = pool.get().map_err(map_pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT run_id, task_id, controller_agent, status, token_used, cost_usd, last_resume_reason \
             FROM runs ORDER BY run_id DESC LIMIT 100",
        )?;
        let iter = stmt.query_map([], run_row_from_sql)?;
        iter.collect()
    })
    .await;
    match rows {
        Ok(Ok(rs)) => Json(serde_json::json!({"view": "run_panel", "runs": rs})).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn dashboard_agent_panel(
    state: QueryState,
    params: &HashMap<String, String>,
) -> axum::response::Response {
    if let Some(agent_id) = params.get("agent_id").cloned() {
        let pool = state.pool.clone();
        let row = tokio::task::spawn_blocking(
            move || -> Result<Option<AgentStatsRow>, rusqlite::Error> {
                let conn = pool.get().map_err(map_pool_err)?;
                let mut stmt = conn.prepare_cached(
                    "SELECT agent_id, active_tasks, completed_tasks, avg_turns_per_task, \
                            avg_completion_time_hours, memory_entries, llm_tokens_24h, \
                            error_count_24h, last_active \
                     FROM agent_stats WHERE agent_id = ?",
                )?;
                stmt.query_row([agent_id], agent_stats_row_from_sql)
                    .optional()
            },
        )
        .await;
        return match row {
            Ok(Ok(r)) => Json(r).into_response(),
            Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }
    let pool = state.pool.clone();
    let rows =
        tokio::task::spawn_blocking(move || -> Result<Vec<AgentStatsRow>, rusqlite::Error> {
            let conn = pool.get().map_err(map_pool_err)?;
            let mut stmt = conn.prepare(
                "SELECT agent_id, active_tasks, completed_tasks, avg_turns_per_task, \
                    avg_completion_time_hours, memory_entries, llm_tokens_24h, \
                    error_count_24h, last_active \
             FROM agent_stats ORDER BY agent_id LIMIT 100",
            )?;
            let iter = stmt.query_map([], agent_stats_row_from_sql)?;
            iter.collect()
        })
        .await;
    match rows {
        Ok(Ok(rs)) => {
            Json(serde_json::json!({"view": "agent_panel", "agents": rs})).into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// AC-15 "cost rate" theme. Aggregates `llm.response` events over a configurable
/// time window (?window_secs=, default 3600 s = 1 hour) and computes rate-based
/// metrics: tokens/min, cost/min, requests/min. Reads TOP-LEVEL payload fields
/// (`input_tokens`, `output_tokens`, `cost_usd`) per the cap-llm payload-shape
/// fix (closes M019 §3.6 item 17).
/// Maximum `?window_secs=` value accepted by `dashboard_llm_analytics`. Bounds
/// `chrono::Duration::seconds(window_secs as i64)` away from i64 overflow +
/// from "give me everything since the Unix epoch" requests. 36 500 days = 100
/// years; matches the workspace's existing `MAX_RETENTION_DAYS` discipline
/// (lib.rs:81) for "absurd-but-finite" upper bounds. Slice E adversarial
/// finding R1 fix: prior code cast `window_secs as i64` directly, which on
/// inputs > i64::MAX produces a negative duration and either silently selects
/// zero rows (future cutoff) OR can panic in chrono internals on platform-
/// specific overflow paths.
const MAX_WINDOW_SECS: u64 = 36_500 * 86_400; // 100 years

async fn dashboard_llm_analytics(
    state: QueryState,
    params: &HashMap<String, String>,
) -> axum::response::Response {
    let window_secs_raw: u64 = params
        .get("window_secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);
    // Clamp to safe i64 range — guards against the audit Round 1 Critical 1
    // overflow path (window_secs as i64 negative when input > i64::MAX,
    // producing future cutoff or panic).
    let window_secs = window_secs_raw.min(MAX_WINDOW_SECS);
    let pool = state.pool.clone();
    let agg = tokio::task::spawn_blocking(
        move || -> Result<(u64, u64, f64, u64), rusqlite::Error> {
            let conn = pool.get().map_err(map_pool_err)?;
            let cutoff = chrono::Utc::now() - chrono::Duration::seconds(window_secs as i64);
            let cutoff_str = cutoff.to_rfc3339();
            // Read TOP-LEVEL payload fields per PRD §15.3.5 canonical shape
            // (post Slice E cap-llm payload-shape fix).
            let mut stmt = conn.prepare(
                "SELECT COALESCE(SUM(CAST(json_extract(payload, '$.input_tokens') AS INTEGER)), 0), \
                        COALESCE(SUM(CAST(json_extract(payload, '$.output_tokens') AS INTEGER)), 0), \
                        COALESCE(SUM(CAST(json_extract(payload, '$.cost_usd') AS REAL)), 0.0), \
                        COUNT(*) \
                 FROM events \
                 WHERE event_type = 'llm.response' AND timestamp >= ? LIMIT 1",
            )?;
            stmt.query_row([cutoff_str], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, f64>(2)?,
                    row.get::<_, i64>(3)? as u64,
                ))
            })
        },
    )
    .await;
    match agg {
        Ok(Ok((tokens_in_total, tokens_out_total, cost_usd_total, request_count))) => {
            // Rate computation: scale per-window total to per-minute rate.
            // window_secs cannot be 0 (params parse fails on `0`? No — 0 is valid
            // u64 parse. Guard explicitly to avoid divide-by-zero.)
            let window_min = (window_secs as f64) / 60.0;
            let (tokens_per_min, cost_per_min, requests_per_min) = if window_min > 0.0 {
                (
                    ((tokens_in_total + tokens_out_total) as f64) / window_min,
                    cost_usd_total / window_min,
                    (request_count as f64) / window_min,
                )
            } else {
                (0.0, 0.0, 0.0)
            };
            Json(LlmAnalyticsResponse {
                view: "llm_analytics",
                window_secs,
                tokens_in_total,
                tokens_out_total,
                cost_usd_total,
                request_count,
                tokens_per_min,
                cost_per_min,
                requests_per_min,
            })
            .into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
