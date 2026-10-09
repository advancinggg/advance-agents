//! MODULE-001-T114 — poll_stream GET+WebSocket, refusals, shutdown, stall, containment, the
//! cursor carried from page to page and the extension's dispatch budget.

use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::CLIENT_WS_PROTOCOL;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, CapDecl, FamiliesControl, Feed, FeedCall, FixtureDriver,
    FixtureExtension, FixtureFamilies, FixtureHome, FixtureHomeSpec, Http, HttpResponse,
    FIXTURE_ID,
};
use advance_runtime_compose::test_support::{
    ComposeProbe, MemoryComposeLog, ProbeRecord, TEARDOWN_ORDER,
};
use advance_runtime_compose::{
    compose, log_keys, ClientFamilyRegistrar, ComposeCx, ComposeError, ComposeExtension,
    DuplicateOf, ExtensionError, FamilyBudget, HandlerSpec, Method, PathDefect, PollEmit,
    PollStreamSpec, RouteRefusalReason, Scope,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;

type WsClient = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn home() -> FixtureHome {
    home_with(&["fs"])
}

fn home_with(caps: &[&'static str]) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home")
}

fn names(rec: &ProbeRecord) -> Vec<&'static str> {
    rec.step_names()
}

fn subsequence(haystack: &[&str], needle: &[&str]) -> bool {
    let mut rest = haystack;
    for wanted in needle {
        match rest.iter().position(|got| got == wanted) {
            Some(index) => rest = &rest[index + 1..],
            None => return false,
        }
    }
    true
}

fn error_code(body: &Value) -> &str {
    body.pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn error_message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn median_ms(gaps: &[u128]) -> u128 {
    let mut sorted = gaps.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    assert!(n > 0, "no poll gaps");
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

async fn next_text(ws: &mut WsClient, budget: Duration) -> String {
    tokio::time::timeout(budget, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return text.to_string(),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = ws.send(Message::Pong(payload)).await;
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    })
    .await
    .expect("text frame")
}

async fn assert_ws_closed(ws: &mut WsClient, budget: Duration) {
    let closed = tokio::time::timeout(budget, async {
        loop {
            match ws.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "WebSocket still open after {budget:?}");
}

fn handshake_body(err: WsError) -> (u16, Value) {
    match err {
        WsError::Http(resp) => {
            let status = resp.status().as_u16();
            let body = resp
                .body()
                .as_ref()
                .and_then(|bytes| serde_json::from_slice(bytes).ok())
                .unwrap_or(Value::Null);
            (status, body)
        }
        other => panic!("expected HTTP handshake refusal, got {other:?}"),
    }
}

async fn try_ws(
    addr: SocketAddr,
    path: &str,
    token: Option<&str>,
    origin: Option<&str>,
) -> Result<WsClient, (u16, Value)> {
    let mut request = format!("ws://{addr}{path}")
        .into_client_request()
        .expect("WebSocket request");
    let protocol = match token {
        Some(token) => format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}"),
        None => CLIENT_WS_PROTOCOL.to_string(),
    };
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        protocol.parse().expect("protocol header"),
    );
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert(ORIGIN, origin.parse().expect("origin header"));
    }
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the Client API");
    match tokio_tungstenite::client_async(request, tcp).await {
        Ok((ws, response)) => {
            assert_eq!(response.status().as_u16(), 101, "{response:?}");
            Ok(ws)
        }
        Err(err) => Err(handshake_body(err)),
    }
}

async fn open_ws(
    addr: SocketAddr,
    path: &str,
    token: &str,
    origin: Option<&str>,
) -> (WsClient, Value) {
    let mut ws = try_ws(addr, path, Some(token), origin)
        .await
        .unwrap_or_else(|(status, body)| panic!("upgrade {path}: {status} {body}"));
    let text = next_text(&mut ws, Duration::from_secs(10)).await;
    let envelope: Value = serde_json::from_str(&text).expect("seed json");
    (ws, envelope)
}

fn feed_ext() -> (FixtureExtension, Arc<FamiliesControl>) {
    let families = FixtureFamilies::standard().with_feed();
    let control = families.control();
    (
        FixtureExtension::new(FIXTURE_ID).with_families(families),
        control,
    )
}

struct PollRefusal {
    path: &'static str,
    pre_get: bool,
}

impl ComposeExtension for PollRefusal {
    fn id(&self) -> &'static str {
        "fixture"
    }

    fn client_families(
        &self,
        _cx: &ComposeCx,
        reg: &mut ClientFamilyRegistrar<'_>,
    ) -> Result<(), ExtensionError> {
        let read =
            || HandlerSpec::read(true, |_| Ok(json!({}))).with_scopes(vec![Scope::ReadInventory]);
        if self.pre_get {
            reg.route(Method::Get, "/client/fixture/feed", read())?;
        }
        reg.poll_stream(
            self.path,
            PollStreamSpec::new(read(), "/cursor", PollEmit::NonEmptyArrayAt("/items")),
        )?;
        Ok(())
    }
}

async fn assert_registration_gone(
    home: &FixtureHome,
    log: &MemoryComposeLog,
    probe: &ComposeProbe,
    baseline: usize,
    error: &ComposeError,
    extension: &'static str,
    route: &str,
    reason: RouteRefusalReason,
) {
    match error {
        ComposeError::Registration {
            extension: got_ext,
            route: got_route,
            reason: got_reason,
        } if *got_ext == extension && *got_route == route && *got_reason == reason => {}
        other => panic!("{route}: {other:?}"),
    }
    let text = error.to_string();
    assert!(
        text.starts_with(&format!("extension {extension}: route {route} refused: ")),
        "{text}"
    );
    assert_eq!(log.count(log_keys::READY), 0, "{route}");
    let rec = probe.record();
    assert!(
        rec.listeners.iter().all(|(name, _)| *name != "client_api"),
        "{route}: {:?}",
        rec.listeners
    );
    let steps = names(&rec);
    assert!(
        subsequence(&TEARDOWN_ORDER, &steps),
        "{route}: {steps:?} vs {TEARDOWN_ORDER:?}"
    );
    for step in [
        "extensions.hooks",
        "holds.watchers",
        "holds.packs_poll",
        "holds.event_bus",
        "holds.drop_graph",
        "guard",
    ] {
        assert!(steps.contains(&step), "{route} missing {step}: {steps:?}");
    }
    for step in [
        "ingress.client_api",
        "loops.root",
        "holds.selected_provider",
        "holds.breaker",
    ] {
        assert!(!steps.contains(&step), "{route} has {step}: {steps:?}");
    }
    assert_gone_for_home(probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_t114_poll_stream() {
    let _serial = SERIAL.lock().await;
    let home = home_with(&["fs", "llm"]);
    let (ext, control) = feed_ext();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    let get = Http::get(addr, "/client/fixture/feed")
        .session(&token)
        .send()
        .await;
    assert_eq!(get.status, 200, "{:?}", get.body);
    assert_eq!(get.body["data"]["items"], json!([]));
    assert_eq!(get.body["data"]["cursor"], json!("c0"));

    let no_bearer = try_ws(addr, "/client/fixture/feed", None, Some(&origin))
        .await
        .expect_err("feed without bearer");
    let events_no_bearer = try_ws(addr, "/client/events/stream", None, Some(&origin))
        .await
        .expect_err("events without bearer");
    assert_eq!(no_bearer.0, 401, "{:?}", no_bearer.1);
    assert_eq!(error_code(&no_bearer.1), "unauthenticated");
    assert_eq!(
        (no_bearer.0, error_code(&no_bearer.1)),
        (events_no_bearer.0, error_code(&events_no_bearer.1)),
        "feed {:?} events {:?}",
        no_bearer.1,
        events_no_bearer.1
    );

    let evil = "http://evil.invalid";
    let bad_origin = try_ws(addr, "/client/fixture/feed", Some(&token), Some(evil))
        .await
        .expect_err("feed evil origin");
    let events_evil = try_ws(addr, "/client/events/stream", Some(&token), Some(evil))
        .await
        .expect_err("events evil origin");
    assert_eq!(bad_origin.0, 403, "{:?}", bad_origin.1);
    assert_eq!(error_code(&bad_origin.1), "origin_not_allowed");
    assert_eq!(
        (bad_origin.0, error_code(&bad_origin.1)),
        (events_evil.0, error_code(&events_evil.1)),
        "feed {:?} events {:?}",
        bad_origin.1,
        events_evil.1
    );

    {
        let (_events, events_seed) =
            open_ws(addr, "/client/events/stream", &token, Some(&origin)).await;
        assert!(
            events_seed.get("data").is_some_and(|data| !data.is_null()),
            "{events_seed}"
        );
    }
    {
        let (_deltas, delta_seed) =
            open_ws(addr, "/client/llm/deltas/stream", &token, Some(&origin)).await;
        assert_eq!(
            delta_seed.pointer("/data/subscribed"),
            Some(&Value::Bool(true)),
            "{delta_seed}"
        );
    }

    let polls_before = control.polls().len();
    let (mut feed, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    let seeded_at = Instant::now();
    assert!(seed.get("error").is_none_or(Value::is_null), "{seed}");
    assert_eq!(seed["data"]["items"], json!([]), "{seed}");
    assert_eq!(seed["data"]["cursor"], json!("c0"), "{seed}");

    let quiet_until = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < quiet_until {
        let left = quiet_until.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, feed.next()).await {
            Err(_) => break,
            Ok(Some(Ok(Message::Text(text)))) => panic!("frame while feed empty: {text}"),
            Ok(Some(Ok(Message::Ping(_)))) => panic!("ping during the empty-page window"),
            Ok(Some(Ok(_))) => {}
            Ok(None) | Ok(Some(Err(_))) => panic!("feed closed while empty"),
        }
    }

    let polls = control.polls();
    let window = &polls[polls_before..];
    assert!(
        window.len() >= 4,
        "polls after the seed stream: {}",
        window.len()
    );
    let gaps: Vec<u128> = window
        .windows(2)
        .map(|pair| pair[1].0.duration_since(pair[0].0).as_millis())
        .collect();
    let median = median_ms(&gaps);
    assert!(
        (200..=400).contains(&median),
        "median gap {median} ms, gaps {gaps:?}"
    );
    for gap in &gaps {
        assert!(
            (100..=1000).contains(gap),
            "gap {gap} ms outside [100, 1000], gaps {gaps:?}"
        );
    }
    for (_, body) in window.iter().skip(1) {
        assert_eq!(
            body.pointer("/cursor").and_then(Value::as_str),
            Some("c0"),
            "{body}"
        );
    }

    let item = json!({"id": 1});
    control.push_feed(item.clone());
    let page = next_text(&mut feed, Duration::from_secs(1)).await;
    let page: Value = serde_json::from_str(&page).expect("page json");
    assert_eq!(page["data"]["items"], json!([item]), "{page}");

    let ping_budget = Duration::from_secs(16).saturating_sub(seeded_at.elapsed());
    let saw_ping = tokio::time::timeout(ping_budget, async {
        loop {
            match feed.next().await {
                Some(Ok(Message::Ping(payload))) => {
                    let _ = feed.send(Message::Pong(payload)).await;
                    return true;
                }
                Some(Ok(Message::Text(text))) => panic!("extra poll frame: {text}"),
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) => {}
                other => panic!("feed ended before ping: {other:?}"),
            }
        }
    })
    .await
    .expect("Ping within 16 s of the seed");
    assert!(saw_ping);

    rt.shutdown().await.expect("shutdown");
    assert_ws_closed(&mut feed, Duration::from_secs(2)).await;
    let rec = probe.record();
    assert_eq!(
        rec.client_api_ws_joined,
        Some(true),
        "{:?}",
        rec.step_names()
    );
    assert!(
        names(&rec).contains(&"ingress.client_api"),
        "{:?}",
        names(&rec)
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_t114_poll_stream_refusals_fail_compose() {
    let _serial = SERIAL.lock().await;
    let home = home();
    let rows: [(&'static str, bool, &'static str, RouteRefusalReason); 3] = [
        (
            "/client/events/feed",
            false,
            "GET /client/events/feed",
            RouteRefusalReason::ReservedLabel {
                label: "events".into(),
            },
        ),
        (
            "/client/fixture//feed",
            false,
            "GET /client/fixture//feed",
            RouteRefusalReason::InvalidPath(PathDefect::EmptySegment { index: 1 }),
        ),
        (
            "/client/fixture/feed",
            true,
            "GET /client/fixture/feed",
            RouteRefusalReason::DuplicateRoute {
                shape: "/client/fixture/feed".into(),
                of: DuplicateOf::Extension("fixture"),
            },
        ),
    ];
    for (path, pre_get, route, reason) in rows {
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let error = compose(
            home.options(Arc::new(log.clone()), Arc::clone(&probe)),
            vec![Arc::new(PollRefusal { path, pre_get })],
        )
        .await
        .expect_err(route);
        assert_registration_gone(
            &home, &log, &probe, baseline, &error, "fixture", route, reason,
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_t114_shutdown_preempts_a_stalled_stream() {
    let _serial = SERIAL.lock().await;
    let home = home();
    let (ext, control) = feed_ext();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    let (seeded_tx, seeded_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let stall_thread = std::thread::spawn(move || {
        let mut request = format!("ws://{addr}/client/fixture/feed")
            .into_client_request()
            .expect("WebSocket request");
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
                .parse()
                .expect("protocol header"),
        );
        request
            .headers_mut()
            .insert(ORIGIN, origin.parse().expect("origin header"));
        let stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("seed timeout");
        let (mut socket, _) =
            tokio_tungstenite::tungstenite::client::client(request, stream).expect("upgrade");
        loop {
            match socket.read() {
                Ok(Message::Text(_)) => break,
                Ok(Message::Ping(payload)) => {
                    socket.send(Message::Pong(payload)).expect("pong");
                }
                other => panic!("unexpected frame before the seed: {other:?}"),
            }
        }
        socket
            .get_mut()
            .set_read_timeout(None)
            .expect("clear timeout");
        seeded_tx.send(()).expect("seeded");
        let _ = release_rx.recv();
        drop(socket);
    });
    seeded_rx.recv().expect("stalled client read the seed");

    const ITEM_BYTES: usize = 65_536;
    const BURST: usize = 16;
    const CAP: usize = 256 * 1024 * 1024;
    let payload = "x".repeat(ITEM_BYTES);
    let mut pushed = 0usize;
    let mut last_len = control.polls().len();
    let mut last_change = Instant::now();
    loop {
        for _ in 0..BURST {
            control.push_feed(json!(payload.clone()));
            pushed += ITEM_BYTES;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let n = control.polls().len();
        if n != last_len {
            last_len = n;
            last_change = Instant::now();
        }
        if last_change.elapsed() >= Duration::from_secs(1) {
            break;
        }
        assert!(
            pushed < CAP,
            "no send stall after {pushed} bytes, polls={n}"
        );
    }

    let t = Instant::now();
    rt.shutdown().await.expect("shutdown");
    assert!(
        t.elapsed() <= Duration::from_secs(3),
        "shutdown of a stalled poll stream took {:?}",
        t.elapsed()
    );
    let rec = probe.record();
    assert_eq!(
        rec.client_api_ws_joined,
        Some(true),
        "{:?}",
        rec.step_names()
    );
    assert!(
        names(&rec).contains(&"ingress.client_api"),
        "{:?}",
        names(&rec)
    );
    let _ = release_tx.send(());
    stall_thread.join().expect("stall client");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_poll_stream_handler_panic_is_contained() {
    let _serial = SERIAL.lock().await;
    let home = home();
    let (ext, control) = feed_ext();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    let (mut feed, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    assert_eq!(seed["data"]["cursor"], json!("c0"), "{seed}");
    control.panic_next_poll();
    let panicked = next_text(&mut feed, Duration::from_secs(2)).await;
    let envelope: Value = serde_json::from_str(&panicked).expect("error envelope");
    assert_eq!(error_code(&envelope), "module_unavailable", "{envelope}");
    assert_eq!(
        error_message(&envelope),
        "provider unavailable",
        "{envelope}"
    );
    assert_ws_closed(&mut feed, Duration::from_secs(2)).await;
    assert_eq!(log.count(log_keys::EXT_ROUTE_PANICKED), 1);
    let line = log
        .lines()
        .into_iter()
        .find(|line| line.key == log_keys::EXT_ROUTE_PANICKED)
        .expect("panic log");
    assert_eq!(
        line.text,
        "advance: WARN extension fixture route GET /client/fixture/feed panicked; answered module_unavailable"
    );
    for line in log.lines() {
        assert!(
            !line.text.contains("fixture feed panic"),
            "panic payload in log: {}",
            line.text
        );
    }

    let (mut again, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    assert_eq!(seed["data"]["items"], json!([]), "{seed}");
    let get = Http::get(addr, "/client/fixture/feed")
        .session(&token)
        .send()
        .await;
    assert_eq!(get.status, 200, "{:?}", get.body);
    let item = json!({"id": "after-panic"});
    control.push_feed(item.clone());
    let page = next_text(&mut again, Duration::from_secs(1)).await;
    let page: Value = serde_json::from_str(&page).expect("page json");
    assert_eq!(page["data"]["items"], json!([item]), "{page}");

    drop(again);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

/// How long a leg waits for the feed reads it needs (four poll intervals take one second).
const READS_WAIT: Duration = Duration::from_secs(10);

/// Every read of `feed` once at least `n` ran.
async fn wait_reads(control: &FamiliesControl, feed: Feed, n: usize) -> Vec<FeedCall> {
    let deadline = Instant::now() + READS_WAIT;
    loop {
        let reads = control.feed_calls(feed);
        if reads.len() >= n {
            return reads;
        }
        assert!(
            Instant::now() < deadline,
            "{feed:?}: {} reads, waited for {n}: {reads:?}",
            reads.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The reads after the one that answered the page `cursor` (the first read to answer it), once
/// at least two ran.
async fn reads_after_page(control: &FamiliesControl, feed: Feed, cursor: &str) -> Vec<FeedCall> {
    let deadline = Instant::now() + READS_WAIT;
    loop {
        let reads = control.feed_calls(feed);
        let page = reads
            .iter()
            .position(|read| read.cursor == cursor)
            .unwrap_or_else(|| panic!("{feed:?}: no read answered {cursor}: {reads:?}"));
        if reads.len() >= page + 3 {
            return reads[page + 1..].to_vec();
        }
        assert!(
            Instant::now() < deadline,
            "{feed:?}: fewer than two reads after the {cursor} page: {reads:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The reads of one stream, seed first: the seed read has no body, and every later read carries
/// at `pointer` the cursor the read before it answered.
fn assert_cursor_chain(reads: &[FeedCall], pointer: &str) {
    assert!(reads.len() >= 2, "{reads:?}");
    assert!(reads[0].body.is_null(), "seed read: {:?}", reads[0]);
    for pair in reads.windows(2) {
        assert_eq!(
            pair[1].body.pointer(pointer),
            Some(&json!(pair[0].cursor)),
            "{pointer} of {:?} after {:?}",
            pair[1],
            pair[0]
        );
    }
}

async fn next_page(ws: &mut WsClient) -> Value {
    let text = next_text(ws, Duration::from_secs(2)).await;
    serde_json::from_str(&text).expect("page json")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_t114_each_poll_carries_the_previous_page_cursor() {
    let _serial = SERIAL.lock().await;
    let home = home();
    let families = FixtureFamilies::standard().with_feed().with_nested_feed();
    let control = families.control();
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(families);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    // Cursor pointer `/cursor`; no client body, so each poll body is the cursor alone.
    let (mut flat, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    assert_eq!(seed["data"]["cursor"], json!("c0"), "{seed}");
    for (cursor, item) in [("c1", json!({"id": "a"})), ("c2", json!({"id": "b"}))] {
        control.push_feed(item.clone());
        let page = next_page(&mut flat).await;
        assert_eq!(page["data"]["items"], json!([item]), "{page}");
        assert_eq!(page["data"]["cursor"], json!(cursor), "{page}");
        for read in reads_after_page(&control, Feed::Flat, cursor).await {
            assert_eq!(read.body, json!({ "cursor": cursor }), "{read:?}");
        }
    }
    drop(flat);
    assert_cursor_chain(&control.feed_calls(Feed::Flat), "/cursor");

    // Cursor pointer `/page/cursor`: the adapter creates `page` in an empty body.
    let (mut nested, seed) =
        open_ws(addr, "/client/fixture/nested-feed", &token, Some(&origin)).await;
    assert_eq!(
        seed.pointer("/data/page/cursor"),
        Some(&json!("c0")),
        "{seed}"
    );
    assert_eq!(seed["data"]["items"], json!([]), "{seed}");
    let reads = wait_reads(&control, Feed::Nested, 3).await;
    for read in &reads[1..] {
        assert_eq!(read.body, json!({ "page": { "cursor": "c0" } }), "{read:?}");
    }

    // A body the client sends replaces the base body: its other fields stay in every poll and
    // the cursor goes into its own `page` object.
    let base = json!({ "filter": "fixture", "page": { "size": 2 } });
    nested
        .send(Message::Text(base.to_string().into()))
        .await
        .expect("send the base body");
    let deadline = Instant::now() + READS_WAIT;
    while !control
        .feed_calls(Feed::Nested)
        .iter()
        .any(|read| read.body.get("filter").is_some())
    {
        assert!(
            Instant::now() < deadline,
            "no poll carried the client body: {:?}",
            control.feed_calls(Feed::Nested)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for (cursor, item) in [("c1", json!({"id": "c"})), ("c2", json!({"id": "d"}))] {
        control.push_to(Feed::Nested, item.clone());
        let page = next_page(&mut nested).await;
        assert_eq!(page["data"]["items"], json!([item]), "{page}");
        assert_eq!(
            page.pointer("/data/page/cursor"),
            Some(&json!(cursor)),
            "{page}"
        );
        for read in reads_after_page(&control, Feed::Nested, cursor).await {
            assert_eq!(
                read.body,
                json!({ "filter": "fixture", "page": { "size": 2, "cursor": cursor } }),
                "{read:?}"
            );
        }
    }
    drop(nested);
    let reads = control.feed_calls(Feed::Nested);
    assert_cursor_chain(&reads, "/page/cursor");
    let first = reads
        .iter()
        .position(|read| read.body.get("filter").is_some())
        .expect("a poll with the client body");
    for read in &reads[1..first] {
        assert_eq!(read.body, json!({ "page": { "cursor": "c0" } }), "{read:?}");
    }
    for pair in reads[first - 1..].windows(2) {
        assert_eq!(
            pair[1].body,
            json!({ "filter": "fixture", "page": { "size": 2, "cursor": pair[0].cursor } }),
            "{:?} after {:?}",
            pair[1],
            pair[0]
        );
    }

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

/// Holds the extension's only dispatch permit with its slow route. A poll may hold the permit at
/// the moment the slow GET arrives; that GET is then refused at capacity and sent again.
async fn hold_extension_permit(
    addr: SocketAddr,
    token: &str,
    control: &FamiliesControl,
) -> tokio::task::JoinHandle<HttpResponse> {
    let deadline = Instant::now() + READS_WAIT;
    loop {
        let session = token.to_owned();
        let slow = tokio::spawn(async move {
            Http::get(addr, "/client/fixture/slow")
                .session(session)
                .send()
                .await
        });
        loop {
            if control.holding() == 1 {
                return slow;
            }
            if slow.is_finished() {
                let refused = slow.await.expect("slow route");
                assert_eq!(refused.status, 503, "{:?}", refused.body);
                assert_eq!(
                    error_message(&refused.body),
                    "server at dispatch capacity",
                    "{:?}",
                    refused.body
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the slow route never held the extension's permit"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// The seed and every poll take a permit of the extension's own dispatch pool, as its other
/// routes do: while that pool is saturated a new stream is refused like an extension route and an
/// open stream skips its polls (no read, no frame), and OSS routes keep answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_poll_stream_runs_under_the_extension_dispatch_budget() {
    let _serial = SERIAL.lock().await;
    let home = home_with(&["fs", "llm"]);
    let families = FixtureFamilies::standard()
        .with_feed()
        .with_budget(FamilyBudget::new(1, 4));
    let control = families.control();
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(families);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    let (mut feed, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    assert_eq!(seed["data"]["cursor"], json!("c0"), "{seed}");
    wait_reads(&control, Feed::Flat, 3).await;

    let slow = hold_extension_permit(addr, &token, &control).await;
    {
        let api = ep.api.upgrade().expect("client api alive");
        let stats = api.extension_budget_stats();
        assert_eq!(stats.len(), 1, "{stats:?}");
        assert_eq!(stats[0].dispatch_available, 0, "{stats:?}");
    }
    let reads = control.polls().len();
    let item = json!({"id": "after-the-hold"});
    control.push_feed(item.clone());
    let quiet_until = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < quiet_until {
        let left = quiet_until.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, feed.next()).await {
            Err(_) => break,
            Ok(Some(Ok(Message::Text(text)))) => {
                panic!("poll frame while the extension's pool is saturated: {text}")
            }
            Ok(Some(Ok(_))) => {}
            Ok(None) | Ok(Some(Err(_))) => panic!("feed closed while the pool is saturated"),
        }
    }
    assert_eq!(
        control.polls().len(),
        reads,
        "a poll read ran while the extension's pool was saturated"
    );

    let seed_refused = try_ws(addr, "/client/fixture/feed", Some(&token), Some(&origin))
        .await
        .expect_err("a seed while the extension's pool is saturated");
    let route = Http::get(addr, "/client/fixture/status")
        .session(&token)
        .send()
        .await;
    for (status, body) in [
        (seed_refused.0, &seed_refused.1),
        (route.status, &route.body),
    ] {
        assert_eq!(status, 503, "{body}");
        assert_eq!(error_code(body), "module_unavailable", "{body}");
        assert_eq!(error_message(body), "server at dispatch capacity", "{body}");
    }
    let health = Http::get(addr, "/client/health").send().await;
    assert_eq!(health.status, 200, "{:?}", health.body);
    let runs = Http::get(addr, "/client/runs").session(&token).send().await;
    assert_eq!(runs.status, 200, "{:?}", runs.body);
    assert!(
        runs.body.get("data").is_some_and(|data| !data.is_null()),
        "{:?}",
        runs.body
    );
    {
        let (_events, events_seed) =
            open_ws(addr, "/client/events/stream", &token, Some(&origin)).await;
        assert!(
            events_seed.get("data").is_some_and(|data| !data.is_null()),
            "{events_seed}"
        );
    }
    assert_eq!(
        control.polls().len(),
        reads,
        "a read ran while the extension's pool was saturated"
    );

    control.release_slow_route();
    let held = slow.await.expect("slow route");
    assert_eq!(held.status, 200, "{:?}", held.body);
    assert_eq!(held.body["data"], json!({"held": true}));
    let page = next_page(&mut feed).await;
    assert_eq!(page["data"]["items"], json!([item]), "{page}");
    assert_eq!(page["data"]["cursor"], json!("c1"), "{page}");

    drop(feed);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}
