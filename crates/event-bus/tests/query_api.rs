//! T-S-B AC-11 HTTP /query API integration tests via tower::ServiceExt::oneshot
//! (no TCP listener needed; in-process router invocation).

use std::path::Path;

use advance_event_bus::query_api::{query_router, QueryState};
use std::net::SocketAddr;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use tower::ServiceExt;

fn build_pool_with_schema(db_path: &Path) -> Pool<SqliteConnectionManager> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mgr = SqliteConnectionManager::file(db_path).with_flags(flags);
    let pool = Pool::builder().max_size(2).build(mgr).unwrap();
    let mut conn = pool.get().unwrap();
    // Apply schema by way of opening a real EventBus once and dropping it.
    drop(conn);
    let temp_jsonl = std::path::PathBuf::from("/tmp/query_api_test_jsonl_dummy");
    let _ = std::fs::create_dir_all(&temp_jsonl);
    let _bus = advance_event_bus::EventBus::new_synchronous_for_tests(
        advance_event_bus::EventBusConfig::new(temp_jsonl, db_path.to_path_buf()),
    )
    .expect("bus");
    drop(_bus);
    // Re-open the connection to seed.
    let pool = Pool::builder()
        .max_size(2)
        .build(SqliteConnectionManager::file(db_path).with_flags(flags))
        .unwrap();
    conn = pool.get().unwrap();
    conn.execute(
        "INSERT INTO events (id, timestamp, agent_id, trace_id, span_id, event_type, payload) \
         VALUES ('e1','2026-05-04T12:00:00.000Z','agent-A','tr-1','s-1','fs.write','{}')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO events (id, timestamp, agent_id, trace_id, span_id, event_type, payload) \
         VALUES ('e2','2026-05-04T12:00:01.000Z','agent-A','tr-1','s-2','fs.read','{}')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO runs (run_id, task_id, status) VALUES ('run-1','task-1','Active')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO agent_stats (agent_id, active_tasks, completed_tasks, llm_tokens_24h, error_count_24h, last_active) \
         VALUES ('agent-A', 1, 0, 100, 0, '2026-05-04T12:00:00.000Z')",
        [],
    )
    .unwrap();
    drop(conn);
    pool
}

/// MODULE-019-T38 — GET /query/traces?trace_id=tr-1 returns events.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t38_query_traces() {
    let temp = tempfile::TempDir::new().unwrap();
    let pool = std::sync::Arc::new(build_pool_with_schema(&temp.path().join("events.db")));
    let router = query_router(QueryState { pool });

    let mut request = Request::builder()
        .uri("/traces?trace_id=tr-1")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65000".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    if status != StatusCode::OK {
        panic!("status={} body={}", status, String::from_utf8_lossy(&body));
    }
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 2);
}

/// MODULE-019-T39 — GET /query/runs?run_id=run-1 returns the row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t39_query_runs() {
    let temp = tempfile::TempDir::new().unwrap();
    let pool = std::sync::Arc::new(build_pool_with_schema(&temp.path().join("events.db")));
    let router = query_router(QueryState { pool });

    let mut request = Request::builder()
        .uri("/runs?run_id=run-1")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65000".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["run_id"], "run-1");
    assert_eq!(v["task_id"], "task-1");
}

/// MODULE-019-T40 — GET /query/agents?agent_id=agent-A returns agent_stats.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t40_query_agents() {
    let temp = tempfile::TempDir::new().unwrap();
    let pool = std::sync::Arc::new(build_pool_with_schema(&temp.path().join("events.db")));
    let router = query_router(QueryState { pool });

    let mut request = Request::builder()
        .uri("/agents?agent_id=agent-A")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65000".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["agent_id"], "agent-A");
    assert_eq!(v["llm_tokens_24h"], 100);
}

/// MODULE-019-T41 — GET /query/events?event_type=fs.write returns filtered list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t41_query_events_filtered() {
    let temp = tempfile::TempDir::new().unwrap();
    let pool = std::sync::Arc::new(build_pool_with_schema(&temp.path().join("events.db")));
    let router = query_router(QueryState { pool });

    let mut request = Request::builder()
        .uri("/events?event_type=fs.write&limit=10")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65000".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["event_type"], "fs.write");
}

/// MODULE-019-T42 — SQL injection canary. Even a malicious event_type returns
/// only matching events; the canary table (created in setup) is NOT modified.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t42_query_events_sql_injection_canary() {
    let temp = tempfile::TempDir::new().unwrap();
    let db_path = temp.path().join("events.db");
    let pool = std::sync::Arc::new(build_pool_with_schema(&db_path));

    // Pre-seed canary table.
    {
        let conn = pool.get().unwrap();
        conn.execute("CREATE TABLE canary (n INTEGER)", []).unwrap();
        conn.execute("INSERT INTO canary VALUES (1)", []).unwrap();
    }

    let router = query_router(QueryState { pool: pool.clone() });

    // Attempt classic SQLi: comment-out + UNION SELECT.
    let mut request = Request::builder()
        .uri("/events?event_type=fs.write%27%20OR%201%3D1%3B%20DROP%20TABLE%20canary%3B%20--&limit=10")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65000".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Canary table must still exist with its row intact.
    let conn = pool.get().unwrap();
    let n: i64 = conn
        .query_row("SELECT n FROM canary", [], |r| r.get(0))
        .expect("canary table intact");
    assert_eq!(n, 1, "SQL injection should NOT modify canary row");
}
