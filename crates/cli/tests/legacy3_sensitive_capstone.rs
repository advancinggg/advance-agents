//! MODULE-012-T10 / Legacy M001–019 closure capstone.
//!
//! One production composition drives the real lifecycle@0.2.0 submit handler,
//! reopens the durable scheduler row, executes its exact WASM bytes, and proves
//! the guest sentinel is absent from JSONL, SQLite, EventBus WebSocket, public
//! task history, public pending approval, and the public Web Console WebSocket.

use std::sync::{Arc, Once};
use std::time::Duration;

use advance_cli::runnable_hook_factory::WasmRunnableHookFactory;
use advance_cli::wiring::wire_capabilities;
use advance_client_api::{API_VERSION, CLIENT_WS_PROTOCOL};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use advance_scheduler::hook::RunnableHookFactory;
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::types::ComponentConfig;
use cap_grant::{CapParam, ChannelApprovalPort, ChannelApprovalRequest, GrantTtl};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use wasmtime::component::Val;
use wit_component::ComponentEncoder;

const SENTINEL: &str = "legacy3-raw-secret-7f3a";
const MASTER_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MASTER_KEY_ENV: &str = "ADV_LEGACY3_CAPSTONE_MASTER_KEY";
const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-legacy3-sensitive.core.wasm");

fn install_master_key() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| std::env::set_var(MASTER_KEY_ENV, MASTER_KEY));
}

fn runtime_yaml() -> String {
    format!(
        r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: {MASTER_KEY_ENV}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    )
}

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("legacy guest core module")
        .encode()
        .expect("legacy guest component")
}

fn submit_value(binary: Vec<u8>) -> Val {
    Val::Record(vec![
        ("id".into(), Val::String("legacy3-sensitive".into())),
        ("component-type".into(), Val::Variant("task".into(), None)),
        (
            "binary".into(),
            Val::List(binary.into_iter().map(Val::U8).collect()),
        ),
        ("capabilities".into(), Val::List(Vec::new())),
        ("output-dir".into(), Val::Option(None)),
        ("trigger".into(), Val::Option(None)),
        ("restart-policy".into(), Val::Option(None)),
        ("delay".into(), Val::Option(None)),
        ("initial-grants".into(), Val::Option(None)),
        ("preset".into(), Val::Option(None)),
        ("retry".into(), Val::Option(None)),
        (
            "sensitive-params".into(),
            Val::List(
                ["api_key", "id", "event_type", "run_id"]
                    .into_iter()
                    .map(|name| Val::String(name.to_owned()))
                    .collect(),
            ),
        ),
    ])
}

fn assert_submit_ok(values: Vec<Val>) {
    assert_eq!(values.len(), 1);
    match &values[0] {
        Val::Result(Ok(Some(value))) => match value.as_ref() {
            Val::String(id) => assert_eq!(id, "legacy3-sensitive"),
            other => panic!("unexpected lifecycle submit result: {other:?}"),
        },
        other => panic!("lifecycle submit failed: {other:?}"),
    }
}

async fn http(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    origin: Option<&str>,
    token: Option<&str>,
    body: Option<&str>,
) -> String {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect Client API");
    let body = body.unwrap_or("");
    let origin = origin
        .map(|value| format!("Origin: {value}\r\n"))
        .unwrap_or_default();
    let authorization = token
        .map(|value| format!("Authorization: Bearer {value}\r\n"))
        .unwrap_or_default();
    let content = if body.is_empty() {
        String::new()
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nX-Advance-Api-Version: {API_VERSION}\r\n{origin}{authorization}{content}Connection: close\r\n\r\n{body}"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let response = String::from_utf8(bytes).expect("HTTP UTF-8");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response
        .split_once("\r\n\r\n")
        .expect("HTTP body")
        .1
        .to_owned()
}

async fn next_text<S>(socket: &mut S, surface: &str) -> String
where
    S: futures::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap_or_else(|_| panic!("{surface} WebSocket frame timeout"))
            .expect("WebSocket remains open")
            .expect("WebSocket frame")
        {
            Message::Text(text) => return text.to_string(),
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
            Message::Close(frame) => panic!("WebSocket closed early: {frame:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_guest_is_raw_only_at_execution_and_redacted_on_every_surface() {
    install_master_key();
    let directory = tempfile::tempdir().expect("workspace");
    let workspace = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let runtime_config = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&runtime_config, runtime_yaml()).unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  lifecycle: true\n  grant: true\n",
    )
    .unwrap();

    let builder = RuntimeHostBuilder::new(&runtime_config, &workspace)
        .await
        .expect("runtime builder");
    let (host, handles) = wire_capabilities(builder, &workspace)
        .await
        .expect("production composition");
    let lifecycle = host
        .host_registry()
        .lookup("lifecycle")
        .into_iter()
        .find(|spec| spec.name == "submit-component")
        .expect("lifecycle@0.2.0 submit handler");
    let submitted_bytes = component_bytes();
    let result = lifecycle
        .handler
        .call(
            HostCallContext {
                agent_id: "default-agent".to_owned(),
                trace_id: "legacy3-submit".to_owned(),
                turn_id: None,
                capability: "lifecycle".to_owned(),
                function: "advance:runtime/agent-lifecycle@0.2.0::submit-component".to_owned(),
                run_id: None,
                iteration: None,
            },
            vec![submit_value(submitted_bytes.clone())],
            1,
        )
        .await
        .expect("lifecycle dispatch");
    assert_submit_ok(result);

    let reopened = ComponentRegistry::open_in(&workspace.join(".triggers"), "components.db")
        .await
        .expect("reopen durable scheduler registry");
    let rows = reopened.list().await.expect("durable rows");
    let row = rows
        .iter()
        .find(|row| row.submit_config.id == "legacy3-sensitive")
        .expect("submitted row");
    assert_eq!(row.submit_config.binary, submitted_bytes);
    assert_eq!(
        row.submit_config.sensitive_params,
        ["api_key", "event_type", "id", "run_id"]
    );

    handles
        .grant_approval_intake
        .as_ref()
        .expect("real grant intake")
        .request_approval(ChannelApprovalRequest {
            request_id: "legacy3-pending".to_owned(),
            caller: "legacy3-sensitive".to_owned(),
            capability: "http".to_owned(),
            params: Some(vec![CapParam {
                key: "api_key".to_owned(),
                value: SENTINEL.to_owned(),
            }]),
            ttl: GrantTtl::Once,
            justification: Some("legacy capstone".to_owned()),
        })
        .expect("park production approval");

    let event_address = handles.event_bus.server_addr().expect("EventBus server");
    let (mut event_ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{event_address}/events"))
            .await
            .expect("EventBus WebSocket");

    let public_server = handles
        .client_api_server
        .as_ref()
        .expect("production public Client API");
    let public_address = public_server.local_addr();
    let origin = format!("http://{public_address}");
    let login = http(
        public_address,
        "POST",
        "/client/session/login",
        Some(&origin),
        None,
        Some(r#"{"platform":"web"}"#),
    )
    .await;
    let login: serde_json::Value = serde_json::from_str(&login).expect("login envelope");
    let token = login["data"]["token"]
        .as_str()
        .expect("session token")
        .to_owned();

    let mut request = format!("ws://{public_address}/client/events/stream")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("Origin", origin.parse().unwrap());
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
            .parse()
            .unwrap(),
    );
    let (mut public_ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("public dashboard WebSocket");
    let seed = next_text(&mut public_ws, "public seed").await;
    assert!(!seed.contains(SENTINEL), "public WS seed leaked: {seed}");

    let factory =
        WasmRunnableHookFactory::new(host.component_runtime(), host.capability_injector())
            .with_event_bus(Arc::clone(&handles.event_bus_dyn));
    let hook = factory
        .build(&row.submit_config.binary, "legacy3-sensitive", &[])
        .await
        .expect("build exact admitted guest bytes");
    let run = hook
        .run_once(ComponentConfig {
            id: "legacy3-sensitive".to_owned(),
            config_data: None,
            trigger_context: None,
        })
        .await
        .expect("real guest execution");
    let raw = String::from_utf8(run.output.expect("guest raw output")).unwrap();
    assert!(
        raw.contains(SENTINEL),
        "execution must retain the raw value"
    );

    let event_frame = next_text(&mut event_ws, "EventBus run.completed").await;
    assert!(event_frame.contains("[REDACTED]"), "{event_frame}");
    assert!(
        !event_frame.contains(SENTINEL),
        "EventBus WS leaked: {event_frame}"
    );

    // CONTRACT-190 streams from CONTRACT-185's durable cursor surface, while
    // the EventBus socket above is intentionally best-effort broadcast. Wait
    // for the SQLite commit before requiring the recoverable public stream.
    let mut durable_run_id = None;
    for _ in 0..100 {
        let query = handles
            .observability_read_api
            .as_ref()
            .unwrap()
            .query(&Default::default(), 20)
            .await
            .unwrap();
        if let Some(completed) = query
            .iter()
            .find(|event| event.event.event_type == "run.completed")
        {
            durable_run_id = completed.event.run_id.clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let durable_run_id = durable_run_id.expect("run.completed durable run id");

    let public_frame = loop {
        let frame = next_text(&mut public_ws, "public run.completed").await;
        assert!(!frame.contains(SENTINEL), "public WS leaked: {frame}");
        if frame.contains("run.completed") {
            break frame;
        }
    };
    assert!(public_frame.contains("legacy3-sensitive"));

    let pending = http(
        public_address,
        "GET",
        "/client/grants/pending",
        Some(&origin),
        Some(&token),
        None,
    )
    .await;
    let history = http(
        public_address,
        "GET",
        "/client/tasks/task%3Alegacy3-sensitive/history",
        Some(&origin),
        Some(&token),
        None,
    )
    .await;
    let run_history = http(
        public_address,
        "GET",
        &format!("/client/runs/{durable_run_id}/history"),
        Some(&origin),
        Some(&token),
        None,
    )
    .await;
    let console = http(public_address, "GET", "/app.js", None, None, None).await;
    for (name, value) in [
        ("pending approval", &pending),
        ("task history", &history),
        ("run history", &run_history),
        ("Web Console asset", &console),
    ] {
        assert!(!value.contains(SENTINEL), "{name} leaked: {value}");
    }
    assert!(pending.contains("[REDACTED]") && pending.contains("legacy3-pending"));
    assert!(history.contains("[REDACTED]") && history.contains("run.completed"));
    assert!(run_history.contains("[REDACTED]") && run_history.contains("run.completed"));
    assert!(console.contains("textContent"));
    assert!(!console.contains("/query"));

    let jsonl = std::fs::read_dir(workspace.join(".runtime/events/jsonl"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .collect::<String>();
    assert!(
        jsonl.contains("[REDACTED]"),
        "JSONL did not persist redaction"
    );
    assert!(!jsonl.contains(SENTINEL), "JSONL leaked: {jsonl}");

    let database = rusqlite::Connection::open(workspace.join(".runtime/events.db")).unwrap();
    let payload: String = database
        .query_row(
            "SELECT payload FROM events WHERE event_type='run.completed' ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("SQLite projected payload");
    assert!(payload.contains("[REDACTED]"));
    assert!(!payload.contains(SENTINEL), "SQLite leaked: {payload}");

    let _ = event_ws.send(Message::Close(None)).await;
    let _ = public_ws.send(Message::Close(None)).await;
}
