//! Slice C — T54: single-axum-server multiplexes /events (WebSocket upgrade)
//! and /query/* (HTTP) on one port. Regression-locks the topology that lets
//! Slice B serve both surfaces from a single TcpListener (per MODULE-019 §2.10).

use std::time::Duration;

use advance_event_bus::{EventBus, EventBusConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t54_single_port_multiplexes_ws_and_query() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let mut cfg = EventBusConfig::new(jsonl_dir, db_path);
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    let bus = EventBus::new(cfg).await.expect("bus");

    let server_addr = bus.server_addr().expect("server_addr");

    // Concurrently: HTTP GET /query/agents and WS upgrade to /events.
    let http_task = tokio::spawn({
        let url = format!("http://{server_addr}/query/agents?agent_id=does-not-exist");
        async move { http_get(&url).await }
    });

    let ws_task = tokio::spawn({
        let url = format!("ws://{server_addr}/events");
        async move { ws_connect(&url).await }
    });

    let (http_result, ws_result) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(http_task, ws_task)
    })
    .await
    .expect("timed out");

    let http_status = http_result.unwrap();
    let ws_ok = ws_result.unwrap();

    // /query/agents returns 200 (with empty/null row for non-existent agent).
    assert_eq!(http_status, 200, "expected /query/agents to return 200");
    // WS upgrade succeeds.
    assert!(ws_ok, "expected WS upgrade to succeed");

    bus.shutdown().await;
}

/// Minimal raw-TCP HTTP/1.1 GET that returns the response status code.
async fn http_get(url: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let stripped = url.strip_prefix("http://").expect("http:// scheme");
    let (host_port, path) = match stripped.find('/') {
        Some(idx) => (&stripped[..idx], &stripped[idx..]),
        None => (stripped, "/"),
    };
    let mut stream = TcpStream::connect(host_port).await.expect("connect");
    let host_only = host_port.split(':').next().unwrap_or(host_port);
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_only}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    let header = String::from_utf8_lossy(&buf);
    let first = header.lines().next().unwrap_or("");
    // first looks like "HTTP/1.1 200 OK"
    first
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Connect to a WebSocket and confirm the handshake completes (we don't send
/// any data — just verify the upgrade).
async fn ws_connect(url: &str) -> bool {
    use tokio_tungstenite::connect_async;

    match connect_async(url).await {
        Ok((mut stream, _resp)) => {
            let _ = stream.close(None).await;
            true
        }
        Err(e) => {
            eprintln!("ws_connect failed: {e:?}");
            false
        }
    }
}
