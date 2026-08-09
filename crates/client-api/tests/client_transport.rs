//! Real-socket witness for the public HTTP/WebSocket adapter and embedded console.

use std::net::TcpListener as StdTcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer, ClientCursorCodec,
    ClientEnvelope, ClientEventPage, ClientEventProvider, ClientSession, MemoryCursorKeyCustody,
    NormalizedEventFilter, OsCursorEntropy, Platform, Principal, ProviderError, RawEventRow, Scope,
    SystemCursorClock, CLIENT_WS_PROTOCOL,
};
use advance_shared_types::security_validator::LeakDetector;
use cap_http::DefaultLeakDetector;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

#[derive(Default)]
struct QueueProvider {
    rows: Mutex<Vec<RawEventRow>>,
}

impl QueueProvider {
    fn push(&self, raw_id: &str) {
        self.rows.lock().unwrap().push(RawEventRow {
            raw_id: raw_id.into(),
            event_type: "run.created".into(),
            timestamp: Utc::now(),
            agent_id: "agent:console".into(),
            run_id: Some("run-console".into()),
            trace_id: "00000000-0000-4000-8000-000000000001".into(),
            payload: json!({}),
        });
    }
}

impl ClientEventProvider for QueueProvider {
    fn retention_days(&self) -> u32 {
        30
    }

    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .last()
            .map(|row| row.raw_id.clone()))
    }

    fn query_history(
        &self,
        _filter: &NormalizedEventFilter,
        limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }

    fn drain_stream(
        &self,
        after_raw_id: Option<&str>,
        scan_ceiling: usize,
        _idle_ms: u64,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        let rows = self.rows.lock().unwrap();
        let start = after_raw_id
            .and_then(|id| rows.iter().position(|row| row.raw_id == id))
            .map(|index| index + 1)
            .unwrap_or(0);
        Ok(rows
            .iter()
            .skip(start)
            .take(scan_ceiling)
            .cloned()
            .collect())
    }
}

fn free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn api(origin: &str, provider: Arc<QueueProvider>) -> Arc<ClientApi> {
    let mut config = ClientApiConfig::default();
    config.allowed_origins = vec![origin.into()];
    let codec: Arc<dyn ClientCursorCodec> = Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ));
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(config)
        .with_event_provider(provider)
        .with_leak_detector(detector)
        .with_cursor_codec(codec);
    api.sessions().insert(
        "transport-token".into(),
        ClientSession {
            session_id: "transport-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("transport-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
    Arc::new(api)
}

async fn read_static(port: u16) -> String {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn connect(
    port: u16,
    origin: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut request = format!("ws://127.0.0.1:{port}/client/events/stream")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.transport-token")
            .parse()
            .unwrap(),
    );
    request
        .headers_mut()
        .insert(ORIGIN, origin.parse().unwrap());
    let (socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .unwrap()
            .to_str()
            .unwrap(),
        CLIENT_WS_PROTOCOL
    );
    socket
}

async fn next_page(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> ClientEventPage {
    let message = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Text(text) => break text,
                Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                _ => {}
            }
        }
    })
    .await
    .expect("public WebSocket page");
    let envelope: ClientEnvelope<Value> = serde_json::from_str(&message).unwrap();
    assert!(envelope.is_ok(), "{:?}", envelope.error);
    serde_json::from_value(envelope.data.unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_console_transport_streams_and_resumes_without_backdoors() {
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let provider = Arc::new(QueueProvider::default());
    let server = ClientApiServer::bind(api(&origin, Arc::clone(&provider)), port)
        .await
        .unwrap();

    let static_response = read_static(port).await;
    assert!(static_response.starts_with("HTTP/1.1 200"));
    assert!(static_response
        .to_ascii_lowercase()
        .contains("content-security-policy:"));
    assert!(static_response.contains("Advance Console"));
    assert!(!static_response.contains("/query"));

    let mut socket = connect(port, &origin).await;
    let seed = next_page(&mut socket).await;
    let seed_cursor = seed.cursor.expect("empty-join cursor");
    assert!(seed.events.is_empty());

    provider.push("raw-1");
    let first = next_page(&mut socket).await;
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events[0].event_type, "run.created");
    let resume = first.cursor.expect("resume cursor");
    socket.close(None).await.unwrap();

    provider.push("raw-2");
    let mut reconnected = connect(port, &origin).await;
    let _fresh_seed = next_page(&mut reconnected).await;
    reconnected
        .send(Message::Text(
            serde_json::to_string(&json!({
                "stream_id": resume.stream_id,
                "last_event_id": resume.last_event_id,
            }))
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let resumed = next_page(&mut reconnected).await;
    assert_eq!(resumed.events.len(), 1);
    assert_ne!(resumed.events[0].event_id, first.events[0].event_id);

    // The first authenticated seed is not a raw id and cannot expose the provider's `raw-*` ids.
    let encoded_seed = serde_json::to_string(&seed_cursor).unwrap();
    assert!(!encoded_seed.contains("raw-1"));
    assert!(!encoded_seed.contains("raw-2"));

    reconnected.close(None).await.unwrap();
    server.shutdown().await.unwrap();
}
