//! Shared helpers of the MODULE-001-T112 (b) inference witnesses.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::CLIENT_WS_PROTOCOL;
use advance_runtime_compose::test_support::fixture::inference::provider_yaml;
use advance_runtime_compose::test_support::fixture::{
    mint_session, post_msg, CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec, HttpResponse,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, ComposeError, ComposeExtension, ComposedRuntime};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

pub const POLL: Duration = Duration::from_millis(10);
pub const WAIT: Duration = Duration::from_secs(5);

/// The OSS-bound `local` entry of [`local_side_entry`].
pub const LOCAL_SIDE: &str = "local-side";

pub const CREATE_LOCAL_TWO: &str = r#"{"provider_id":"local-two","backend_class":"local","model_aliases":{"default":"m2"},"cost":{"input_per_mtoken":0.01,"output_per_mtoken":0.01},"rate_limit":{"requests_per_minute":100,"tokens_per_minute":100000}}"#;

pub type WsClient = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

pub fn home(caps: &'static [&'static str], providers: &[&str]) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver: FixtureDriver::LlmNoErr,
        git: false,
        providers_yaml: Some(provider_yaml::llm_providers_block(providers)),
    })
    .expect("home")
}

pub fn append_runtime_config(home: &FixtureHome, yaml: &str) {
    let path = home.home().join(".advance/runtime-config.yaml");
    let mut text = std::fs::read_to_string(&path).expect("runtime-config");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(yaml);
    std::fs::write(path, text).expect("append runtime-config");
}

pub async fn compose_with(
    home: &FixtureHome,
    exts: Vec<Arc<dyn ComposeExtension>>,
) -> (
    Result<ComposedRuntime, ComposeError>,
    MemoryComposeLog,
    Arc<ComposeProbe>,
    usize,
) {
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let result = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        exts,
    )
    .await;
    (result, log, probe, baseline)
}

pub fn msg_addr(probe: &ComposeProbe) -> SocketAddr {
    probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound")
}

pub fn api(rt: &ComposedRuntime) -> (SocketAddr, String) {
    let endpoint = rt.client_api().expect("client api");
    let token = mint_session(&endpoint);
    (endpoint.socket_addr, token)
}

pub async fn msg(probe: &ComposeProbe, payload: &str) -> (u16, String) {
    post_msg(msg_addr(probe), payload).await
}

pub fn all_events(home: &Path) -> Vec<Value> {
    let dir = home.join(".runtime/events/jsonl");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries {
        let path = entry.expect("jsonl entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read jsonl");
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("jsonl line in {}: {error}: {line}", path.display())
            }));
        }
    }
    out
}

pub fn events(home: &Path, ty: &str) -> Vec<Value> {
    all_events(home)
        .into_iter()
        .filter(|event| event.get("event_type").and_then(Value::as_str) == Some(ty))
        .collect()
}

pub async fn wait_events(
    home: &Path,
    ty: &str,
    pred: impl Fn(&Value) -> bool,
    n: usize,
    budget: Duration,
) -> Vec<Value> {
    let deadline = Instant::now() + budget;
    loop {
        let matched: Vec<Value> = events(home, ty).into_iter().filter(&pred).collect();
        if matched.len() >= n {
            return matched;
        }
        if Instant::now() >= deadline {
            panic!(
                "wait_events {ty} wanted {n} within {budget:?}, got {}: {matched:?}",
                matched.len()
            );
        }
        tokio::time::sleep(POLL).await;
    }
}

pub fn jsonl_contains(home: &Path, needle: &str) -> bool {
    let dir = home.join(".runtime/events/jsonl");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries {
        let path = entry.expect("jsonl entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read jsonl");
        if text.contains(needle) {
            return true;
        }
    }
    false
}

pub async fn deltas_ws(addr: SocketAddr, token: &str) -> WsClient {
    let mut request = format!("ws://{addr}/client/llm/deltas/stream")
        .into_client_request()
        .expect("WebSocket request");
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
            .parse()
            .expect("protocol header"),
    );
    request.headers_mut().insert(
        ORIGIN,
        format!("http://{addr}").parse().expect("origin header"),
    );
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the Client API");
    let (mut ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("WebSocket handshake");
    let seed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return text.to_string(),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = ws.send(Message::Pong(payload)).await;
                }
                other => panic!("unexpected frame before the seed: {other:?}"),
            }
        }
    })
    .await
    .expect("the seed frame arrives");
    let envelope: Value = serde_json::from_str(&seed).expect("seed json");
    assert_eq!(
        envelope.pointer("/data/subscribed"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    ws
}

pub fn restart_required_count(resp: &HttpResponse) -> usize {
    resp.body
        .get("warnings")
        .and_then(Value::as_array)
        .map(|warnings| {
            warnings
                .iter()
                .filter(|warning| {
                    warning.get("code").and_then(Value::as_str) == Some("restart_required")
                })
                .count()
        })
        .unwrap_or(0)
}

pub fn subsequence(haystack: &[&str], needle: &[&str]) -> bool {
    let mut rest = haystack;
    for wanted in needle {
        match rest.iter().position(|got| got == wanted) {
            Some(index) => rest = &rest[index + 1..],
            None => return false,
        }
    }
    true
}

pub fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

pub fn run_id(event: &Value) -> Option<&str> {
    event
        .get("run_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

pub fn provider_id(event: &Value) -> Option<&str> {
    event
        .pointer("/payload/provider_id")
        .and_then(Value::as_str)
}

pub fn provider(event: &Value) -> Option<&str> {
    event.pointer("/payload/provider").and_then(Value::as_str)
}

/// `local-side`: a `local` entry that OSS binds (it has a sidecar), priced as the fixture's
/// `local-stub` (2.0 / 4.0 USD per million input / output tokens) and served by `command`.
pub fn local_side_entry(command: &Path) -> String {
    let quoted = command.display().to_string().replace('\'', "''");
    format!(
        concat!(
            "  - id: local-side\n",
            "    backend-class: local\n",
            "    endpoint: \"\"\n",
            "    api-key-secret: local-side-key\n",
            "    model-aliases: {{ default: side-model }}\n",
            "    cost-per-mtoken-in: 2.0\n",
            "    cost-per-mtoken-out: 4.0\n",
            "    rate-limit: {{ requests-per-minute: 100, tokens-per-minute: 100000 }}\n",
            "    sidecar: {{ command: '{}' }}\n",
        ),
        quoted
    )
}

/// Pins the root agent's LLM calls to `provider`: the `llm:` block of the home's
/// `.agent/config.yaml`, which the gateway reads again at the agent's next call.
pub fn pin_root_provider(home: &FixtureHome, provider: &str) {
    let path = home.home().join(".agent/config.yaml");
    let text = std::fs::read_to_string(&path).expect("read the agent config");
    let kept = text.split("\nllm:\n").next().unwrap_or_default().trim_end();
    std::fs::write(&path, format!("{kept}\nllm:\n  provider: {provider}\n"))
        .expect("pin the root agent's provider");
}

/// The sidecar of an OSS-bound `local` entry, played by the test: an executable
/// `#!/bin/sh` script that prints `PORT=<n>` and stays alive (what OSS reads from the
/// entry's `sidecar.command` at boot), and an OpenAI-compatible
/// `POST /v1/chat/completions` responder on `127.0.0.1:<n>`, on its own thread, that
/// answers every chat with `reply` and the given usage.
#[cfg(unix)]
pub struct LoopbackSidecar {
    _dir: tempfile::TempDir,
    script: std::path::PathBuf,
    addr: SocketAddr,
    chats: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl LoopbackSidecar {
    pub fn start(reply: &str, prompt_tokens: u64, completion_tokens: u64) -> Self {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the sidecar's port");
        let addr = listener.local_addr().expect("the sidecar's address");
        let dir = tempfile::tempdir().expect("sidecar dir");
        let script = dir.path().join("sidecar.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho PORT={}\nexec /bin/sleep 300\n",
                addr.port()
            ),
        )
        .expect("write the sidecar script");
        let mut perms = std::fs::metadata(&script)
            .expect("sidecar script metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("make the sidecar script executable");
        let body = serde_json::json!({
            "choices": [{"message": {"content": reply}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
            "model": "side-model",
        })
        .to_string();
        let chats = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let chats = Arc::clone(&chats);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        answer_chat(stream, &body, &chats);
                    }
                }
            })
        };
        Self {
            _dir: dir,
            script,
            addr,
            chats,
            stop,
            thread: Some(thread),
        }
    }

    pub fn command(&self) -> &Path {
        &self.script
    }

    /// The chats answered so far.
    pub fn chats(&self) -> usize {
        self.chats.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(unix)]
impl Drop for LoopbackSidecar {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wakes the accept loop so it sees the flag.
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Reads one request (head and `Content-Length` body) and answers it: `body` for
/// `POST /v1/chat/completions` (counted in `chats`), 404 otherwise. A failed read or
/// write fails the caller's turn, which the test asserts on.
#[cfg(unix)]
fn answer_chat(
    mut stream: std::net::TcpStream,
    body: &str,
    chats: &std::sync::atomic::AtomicUsize,
) {
    use std::io::{Read, Write};

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&request[..head_end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while request.len() < head_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    let (status, payload) = if head.starts_with("POST /v1/chat/completions ") {
        chats.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ("200 OK", body)
    } else {
        ("404 Not Found", "{}")
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
}
