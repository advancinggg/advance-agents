//! MODULE-001-AC-30 lower-crate witnesses for the Client API side of the ordered shutdown:
//! `ClientApiServer::shutdown_ingress` stops accepting, closes and joins the upgraded
//! WebSocket tasks (events and LLM deltas), drains the in-flight dispatches within one bounded
//! budget and always hands the `Arc<ClientApi>` back; `ClientApi::clear_providers` empties every
//! provider slot so the families answer `module_unavailable` and the providers are dropped.
//!
//! WebSocket clients are polled inline and HTTP clients run on std threads, so the tests spawn
//! no tokio task of their own and `num_alive_tasks` counts only the server.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_client_api::clock::SystemClock;
use advance_client_api::{
    AeadClientCursorCodec, AgentAdminProvider, BoundGrantApprovalPort, BoundGrantMutation,
    BoundHistoryPage, BoundHistoryReadPort, BoundMutationOutcome, ClientAgentCostEntry,
    ClientAgentCostReport, ClientAgentDeleteResult, ClientAgentDetail, ClientAgentSummary,
    ClientAgentTemplate, ClientAgentTreeNode, ClientApi, ClientApiConfig, ClientApiServer,
    ClientCreateAgentRequest, ClientCreateProviderRequest, ClientCursorCodec,
    ClientDeleteAgentRequest, ClientEntityApplyRequest, ClientEntityCreateRequest,
    ClientEntityPage, ClientEntityPatchRequest, ClientEntityQueryRequest, ClientEntityRow,
    ClientEntityTarget, ClientErrorCode, ClientEventProvider, ClientMessageAck,
    ClientMessageStatus, ClientPackApplyResult, ClientPackDetail, ClientPackInstallRequest,
    ClientPackInstallResult, ClientPackSummary, ClientPackUninstallResult, ClientProviderCostEntry,
    ClientProviderCostReport, ClientProviderDeleteResult, ClientProviderKeyResult,
    ClientProviderPreflightResult, ClientProviderSummary, ClientRequest, ClientRunMutation,
    ClientRunSummary, ClientSchema, ClientSecretsMode, ClientSession, ClientSetSecretsModeRequest,
    ClientToolInventory, ClientUpdateAgentRequest, ClientUpdateProviderRequest, CostProvider,
    DeltaHoldSplit, DeltaPumpExit, DeltaPumpExitObserver, EntityProvider, HandlerSpec, LlmDeltaHub,
    MemoryCursorKeyCustody, MessagingProvider, Method, NormalizedEventFilter, OsCursorEntropy,
    PackAdminProvider, Platform, Principal, ProviderAdminOutcome, ProviderAdminProvider,
    ProviderClientDoneReceipt, ProviderError, ProviderMutationRecovery, ProviderPrepareOutcome,
    RawEventRow, RunControlProvider, Scope, SecretsAdminProvider, SystemCursorClock, ToolsProvider,
    ValidatedCostWindow, API_VERSION, CLIENT_WS_PROTOCOL,
};
use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::sensitive_observation::{
    BoundObservationDocument, SensitiveObservationRedactor,
};
use advance_shared_types::test_support::observation_association_roles;
use cap_http::canonical_facade::decoded_hold_split;
use cap_http::DefaultLeakDetector;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

const TOKEN: &str = "shutdown-ingress-token";

type Sock =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// An event provider with no events; every call returns at once.
struct EmptyEvents;

impl ClientEventProvider for EmptyEvents {
    fn retention_days(&self) -> u32 {
        30
    }
    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
        Ok(None)
    }
    fn query_history(
        &self,
        _filter: &NormalizedEventFilter,
        _limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        Ok(Vec::new())
    }
    fn drain_stream(
        &self,
        _after: Option<&str>,
        _max: usize,
        _idle_ms: u64,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        Ok(Vec::new())
    }
}

fn codec() -> Arc<dyn ClientCursorCodec> {
    Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ))
}

fn delta_hub() -> Arc<LlmDeltaHub> {
    let hold_split: DeltaHoldSplit =
        Arc::new(|buf: &[u8], max: usize| decoded_hold_split(buf, max));
    Arc::new(LlmDeltaHub::new(
        Some(Arc::new(DefaultLeakDetector::new())),
        Some(hold_split),
        Arc::new(SystemClock),
        None,
    ))
}

fn install_session(api: &ClientApi) {
    api.sessions().insert(
        TOKEN.into(),
        ClientSession {
            session_id: "shutdown-ingress-session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: Some("shutdown-ingress-csrf".into()),
            expires_at: u64::MAX,
        },
        0,
    );
}

fn origin_of(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

fn config_for(addr: SocketAddr) -> ClientApiConfig {
    let mut config = ClientApiConfig::default();
    config.allowed_origins = vec![origin_of(addr)];
    config
}

async fn connect_ws(addr: SocketAddr, path: &str) -> Sock {
    let mut request = format!("ws://{addr}{path}").into_client_request().unwrap();
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{TOKEN}")
            .parse()
            .unwrap(),
    );
    request
        .headers_mut()
        .insert(ORIGIN, origin_of(addr).parse().unwrap());
    let (socket, _response) = tokio_tungstenite::connect_async(request)
        .await
        .unwrap_or_else(|e| panic!("ws connect {path}: {e:?}"));
    socket
}

/// The next text frame (answering nothing; the seed arrives first).
async fn next_text(socket: &mut Sock) -> String {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("frame within 5s")
            .expect("stream open")
            .expect("frame");
        match frame {
            Message::Text(text) => return text.to_string(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}

/// Reads until the server's `Close` frame or the end of the stream (2 s budget).
async fn expect_closed(socket: &mut Sock, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, socket.next()).await {
            Err(_) => panic!("{what}: no Close / end of stream within 2s"),
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return,
            Ok(Some(Ok(_))) => continue,
        }
    }
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

async fn wait_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Raw HTTP/1.1 GET on a std thread; returns the status code (0 when the connection ended
/// without a response).
fn http_get_thread(addr: SocketAddr, path: &'static str) -> std::thread::JoinHandle<u16> {
    std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nx-advance-api-version: {API_VERSION}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response)
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    })
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_client_api_shutdown_ingress_joins_ws_and_drains() {
    let baseline = alive_tasks();
    let exits: Arc<Mutex<Vec<DeltaPumpExit>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&exits);
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let server = ClientApiServer::bind_local_factory(0, move |addr| {
        let api = ClientApi::new(config_for(addr))
            .with_event_provider(Arc::new(EmptyEvents))
            .with_leak_detector(detector)
            .with_cursor_codec(codec())
            .with_llm_delta_hub(delta_hub())
            .with_delta_pump_observer(Arc::new(move |exit| sink.lock().unwrap().push(exit)));
        install_session(&api);
        Arc::new(api)
    })
    .await
    .expect("bind");
    let addr = server.local_addr();

    // One events stream and one LLM delta stream, each past its seed (the task is running).
    let mut events = connect_ws(addr, "/client/events/stream").await;
    let mut deltas = connect_ws(addr, "/client/llm/deltas/stream").await;
    let seed = next_text(&mut events).await;
    assert!(seed.contains("\"data\""), "events seed: {seed}");
    let seed = next_text(&mut deltas).await;
    assert!(seed.contains("\"data\""), "delta seed: {seed}");
    assert!(
        alive_tasks() >= baseline + 3,
        "serve task + two WebSocket tasks expected alive"
    );

    let started = Instant::now();
    let ingress = server.shutdown_ingress(Duration::from_secs(5)).await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "an idle server stops at once, took {:?}",
        started.elapsed()
    );
    assert!(ingress.serve.is_ok(), "serve result: {:?}", ingress.serve);
    assert!(!ingress.serve_overran, "the serve task finished in time");
    assert!(ingress.ws_joined, "both WebSocket tasks were joined");
    assert!(ingress.drained, "no dispatch was left in flight");

    expect_closed(&mut events, "events stream").await;
    expect_closed(&mut deltas, "delta stream").await;
    assert_eq!(
        exits.lock().unwrap().as_slice(),
        &[DeltaPumpExit::ServerShutdown],
        "the delta pump ended for the server shutdown"
    );
    assert_eq!(DeltaPumpExit::ServerShutdown.as_str(), "server_shutdown");

    // No task of the server is left, and nothing but the returned handle holds the API.
    assert!(
        wait_until(Duration::from_secs(2), || alive_tasks() == baseline).await,
        "tasks left: {} (baseline {baseline})",
        alive_tasks()
    );
    assert!(
        wait_until(Duration::from_secs(2), || Arc::strong_count(&ingress.api)
            == 1)
        .await,
        "other holders of the ClientApi remain: {}",
        Arc::strong_count(&ingress.api)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_client_api_drain_is_bounded() {
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let (e, r, f) = (
        Arc::clone(&entered),
        Arc::clone(&release),
        Arc::clone(&finished),
    );
    let server = ClientApiServer::bind_local_factory(0, move |addr| {
        let mut api = ClientApi::new(config_for(addr));
        api.register(
            Method::Get,
            "/client/t111-blocked",
            HandlerSpec::read(false, move |_ctx| {
                e.store(true, Ordering::SeqCst);
                while !r.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                f.store(true, Ordering::SeqCst);
                Ok(json!({"released": true}))
            }),
        );
        Arc::new(api)
    })
    .await
    .expect("bind");
    let addr = server.local_addr();

    let client = http_get_thread(addr, "/client/t111-blocked");
    assert!(
        wait_until(Duration::from_secs(5), || entered.load(Ordering::SeqCst)).await,
        "the request never reached its handler"
    );

    // The open connection keeps axum's graceful shutdown waiting: the budget bounds it.
    let started = Instant::now();
    let ingress = server.shutdown_ingress(Duration::from_millis(200)).await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(1),
        "shutdown_ingress overran its 200 ms budget: {took:?}"
    );
    assert!(ingress.serve_overran, "the serve task was aborted");
    assert!(ingress.serve.is_ok());
    assert!(ingress.ws_joined, "no WebSocket task existed");
    assert!(
        !ingress.drained,
        "the blocked dispatch still holds its permit"
    );
    assert!(
        Arc::strong_count(&ingress.api) >= 2,
        "the in-flight request still holds the API, and the API was handed back"
    );

    // Releasing the handler lets the request finish; then nothing else holds the API.
    release.store(true, Ordering::SeqCst);
    assert!(
        wait_until(Duration::from_secs(5), || finished.load(Ordering::SeqCst)).await,
        "the handler did not finish after release"
    );
    assert!(
        wait_until(Duration::from_secs(5), || Arc::strong_count(&ingress.api)
            == 1)
        .await,
        "holders of the ClientApi remain: {}",
        Arc::strong_count(&ingress.api)
    );
    let status = tokio::task::spawn_blocking(move || client.join().unwrap())
        .await
        .unwrap();
    assert!(
        status == 200 || status == 0,
        "the in-flight request completes or its connection ends, got {status}"
    );
}

fn events_request() -> ClientRequest {
    ClientRequest {
        api_version: API_VERSION.to_string(),
        method: Method::Get,
        path: "/client/events".into(),
        session_token: Some(TOKEN.into()),
        origin: None,
        csrf_token: None,
        idempotency_key: None,
        is_loopback_peer: true,
        body: Value::Null,
    }
}

/// A provider for every port the Client API has a slot for. Never called: it only shows that
/// `clear_providers` drops what each slot held.
struct Sentinel;

impl RunControlProvider for Sentinel {
    fn list_runs(&self) -> Result<Vec<ClientRunSummary>, ProviderError> {
        unreachable!()
    }
    fn agent_tree(&self) -> Result<Vec<ClientAgentTreeNode>, ProviderError> {
        unreachable!()
    }
    fn pause(&self, _: &str, _: Option<&str>) -> Result<ClientRunMutation, ProviderError> {
        unreachable!()
    }
    fn resume(&self, _: &str, _: Option<&str>) -> Result<ClientRunMutation, ProviderError> {
        unreachable!()
    }
    fn cancel(&self, _: &str, _: Option<&str>) -> Result<ClientRunMutation, ProviderError> {
        unreachable!()
    }
}

impl MessagingProvider for Sentinel {
    fn send(&self, _: &str, _: &[u8]) -> Result<ClientMessageAck, ProviderError> {
        unreachable!()
    }
    fn message_status(&self, _: &str) -> Result<ClientMessageStatus, ProviderError> {
        unreachable!()
    }
}

impl ToolsProvider for Sentinel {
    fn inventory(&self, _: &str) -> Result<ClientToolInventory, ProviderError> {
        unreachable!()
    }
}

impl AgentAdminProvider for Sentinel {
    fn list_agents(&self) -> Result<Vec<ClientAgentSummary>, ProviderError> {
        unreachable!()
    }
    fn get_agent(&self, _: &str) -> Result<ClientAgentDetail, ProviderError> {
        unreachable!()
    }
    fn create_agent(
        &self,
        _: &ClientCreateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        unreachable!()
    }
    fn update_agent(
        &self,
        _: &str,
        _: &ClientUpdateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        unreachable!()
    }
    fn delete_agent(
        &self,
        _: &str,
        _: &ClientDeleteAgentRequest,
    ) -> Result<ClientAgentDeleteResult, ProviderError> {
        unreachable!()
    }
    fn list_templates(&self) -> Result<Vec<ClientAgentTemplate>, ProviderError> {
        unreachable!()
    }
}

impl CostProvider for Sentinel {
    fn agent_totals(
        &self,
        _: &ValidatedCostWindow,
    ) -> Result<Vec<ClientAgentCostEntry>, ProviderError> {
        unreachable!()
    }
    fn agent_report(
        &self,
        _: &str,
        _: &ValidatedCostWindow,
    ) -> Result<ClientAgentCostReport, ProviderError> {
        unreachable!()
    }
    fn provider_totals(
        &self,
        _: &ValidatedCostWindow,
    ) -> Result<Vec<ClientProviderCostEntry>, ProviderError> {
        unreachable!()
    }
    fn provider_report(
        &self,
        _: &str,
        _: &ValidatedCostWindow,
    ) -> Result<ClientProviderCostReport, ProviderError> {
        unreachable!()
    }
}

impl PackAdminProvider for Sentinel {
    fn list_packs(&self) -> Result<Vec<ClientPackSummary>, ProviderError> {
        unreachable!()
    }
    fn get_pack(&self, _: &str, _: &str) -> Result<ClientPackDetail, ProviderError> {
        unreachable!()
    }
    fn install_pack(
        &self,
        _: &ClientPackInstallRequest,
    ) -> Result<ClientPackInstallResult, ProviderError> {
        unreachable!()
    }
    fn uninstall_pack(&self, _: &str, _: &str) -> Result<ClientPackUninstallResult, ProviderError> {
        unreachable!()
    }
    fn apply_pack_workflow(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<ClientPackApplyResult, ProviderError> {
        unreachable!()
    }
}

impl EntityProvider for Sentinel {
    fn describe(&self) -> Result<ClientSchema, ProviderError> {
        unreachable!()
    }
    fn query(&self, _: &ClientEntityQueryRequest) -> Result<ClientEntityPage, ProviderError> {
        unreachable!()
    }
    fn get(&self, _: &str, _: &str) -> Result<ClientEntityRow, ProviderError> {
        unreachable!()
    }
    fn create(&self, _: &ClientEntityCreateRequest) -> Result<ClientEntityRow, ProviderError> {
        unreachable!()
    }
    fn patch(
        &self,
        _: &str,
        _: &ClientEntityPatchRequest,
    ) -> Result<ClientEntityRow, ProviderError> {
        unreachable!()
    }
    fn apply(
        &self,
        _: &str,
        _: &ClientEntityApplyRequest,
    ) -> Result<Vec<ClientEntityRow>, ProviderError> {
        unreachable!()
    }
    fn promote(&self, _: &str, _: &str) -> Result<ClientEntityTarget, ProviderError> {
        unreachable!()
    }
    fn demote(&self, _: &str, _: &str) -> Result<ClientEntityTarget, ProviderError> {
        unreachable!()
    }
}

impl ProviderAdminProvider for Sentinel {
    fn list_providers(&self) -> Result<Vec<ClientProviderSummary>, ProviderError> {
        unreachable!()
    }
    fn get_provider(&self, _: &str) -> Result<ClientProviderSummary, ProviderError> {
        unreachable!()
    }
    fn create_provider(
        &self,
        _: &ClientCreateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        unreachable!()
    }
    fn update_provider(
        &self,
        _: &str,
        _: &ClientUpdateProviderRequest,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        unreachable!()
    }
    fn delete_provider(
        &self,
        _: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderDeleteResult>, ProviderError> {
        unreachable!()
    }
    fn set_key(
        &self,
        _: &str,
        _: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderKeyResult>, ProviderError> {
        unreachable!()
    }
    fn clear_key(&self, _: &str) -> Result<ClientProviderSummary, ProviderError> {
        unreachable!()
    }
    fn preflight(&self, _: &str) -> Result<ClientProviderPreflightResult, ProviderError> {
        unreachable!()
    }
    fn select_provider(
        &self,
        _: &str,
    ) -> Result<ProviderAdminOutcome<ClientProviderSummary>, ProviderError> {
        unreachable!()
    }
}

impl SecretsAdminProvider for Sentinel {
    fn mode(&self) -> Result<ClientSecretsMode, ProviderError> {
        unreachable!()
    }
    fn set_mode(
        &self,
        _: &ClientSetSecretsModeRequest,
    ) -> Result<ClientSecretsMode, ProviderError> {
        unreachable!()
    }
}

impl BoundGrantApprovalPort for Sentinel {
    fn list_pending_bound(&self) -> Result<Vec<BoundObservationDocument>, ProviderError> {
        unreachable!()
    }
    fn prepare_mutation_bound(
        &self,
        _: [u8; 32],
        _: [u8; 32],
        _: BoundGrantMutation,
    ) -> ProviderPrepareOutcome {
        unreachable!()
    }
    fn verify_recovery_ticket_bound(
        &self,
        _: [u8; 32],
        _: [u8; 32],
        _: u8,
        _: &ProviderMutationRecovery,
    ) -> Result<(), ProviderError> {
        unreachable!()
    }
    fn execute_prepared_bound(&self, _: &ProviderMutationRecovery) -> BoundMutationOutcome {
        unreachable!()
    }
    fn recover_mutation_bound(&self, _: &ProviderMutationRecovery) -> BoundMutationOutcome {
        unreachable!()
    }
    fn acknowledge_client_done_bound(
        &self,
        _: &ProviderClientDoneReceipt,
    ) -> Result<(), ProviderError> {
        unreachable!()
    }
}

impl BoundHistoryReadPort for Sentinel {
    fn task_history_bound(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        unreachable!()
    }
    fn run_history_bound(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        unreachable!()
    }
}

/// An observation redactor that is never called.
fn sentinel_redactor() -> SensitiveObservationRedactor {
    let roles = observation_association_roles([0x55; 32], [0x66; 16], Vec::new()).expect("roles");
    roles
        .provider
        .bind_once(roles.verifier, |_| unreachable!())
        .expect("redactor")
}

/// A probe that tells whether anything still holds `held`.
fn probe<T: ?Sized + 'static>(
    name: &'static str,
    held: &Arc<T>,
) -> (&'static str, Box<dyn Fn() -> bool>) {
    let weak = Arc::downgrade(held);
    (name, Box::new(move || weak.strong_count() > 0))
}

/// `clear_providers` empties every provider slot: each provider installed through its builder
/// (and held by nothing else) is dropped, and the families answer `module_unavailable`.
#[test]
fn module_001_ac30_client_api_clear_providers() {
    let (api, probes) = {
        let run = Arc::new(Sentinel);
        let messaging = Arc::new(Sentinel);
        let tools = Arc::new(Sentinel);
        let agent = Arc::new(Sentinel);
        let cost = Arc::new(Sentinel);
        let pack = Arc::new(Sentinel);
        let provider_admin = Arc::new(Sentinel);
        let secrets = Arc::new(Sentinel);
        let entity = Arc::new(Sentinel);
        let events: Arc<dyn ClientEventProvider> = Arc::new(EmptyEvents);
        let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
        let cursor = codec();
        let bound_grant = Arc::new(Sentinel);
        let bound_history = Arc::new(Sentinel);
        let redactor = Arc::new(sentinel_redactor());
        let hub = delta_hub();
        let observer: DeltaPumpExitObserver = Arc::new(|_| {});
        let probes = vec![
            probe("run", &run),
            probe("messaging", &messaging),
            probe("tools", &tools),
            probe("agent", &agent),
            probe("cost", &cost),
            probe("pack", &pack),
            probe("provider_admin", &provider_admin),
            probe("secrets", &secrets),
            probe("entity", &entity),
            probe("event", &events),
            probe("leak_detector", &detector),
            probe("cursor_codec", &cursor),
            probe("bound_grant", &bound_grant),
            probe("bound_history", &bound_history),
            probe("observation_redactor", &redactor),
            probe("llm_delta_hub", &hub),
            probe("delta_pump_observer", &observer),
        ];
        let api = ClientApi::new(ClientApiConfig::default())
            .with_run_provider(run)
            .with_messaging_provider(messaging)
            .with_tools_provider(tools)
            .with_agent_provider(agent)
            .with_cost_provider(cost)
            .with_pack_provider(pack)
            .with_provider_admin(provider_admin)
            .with_secrets_provider(secrets)
            .with_entity_provider(entity)
            .with_event_provider(events)
            .with_leak_detector(detector)
            .with_cursor_codec(cursor)
            .with_bound_grant_provider(bound_grant)
            .with_bound_history_provider(bound_history)
            .with_observation_redactor(redactor)
            .with_llm_delta_hub(hub)
            .with_delta_pump_observer(observer);
        (api, probes)
    };
    install_session(&api);
    let alive = |probes: &[(&'static str, Box<dyn Fn() -> bool>)]| -> Vec<&'static str> {
        probes
            .iter()
            .filter(|(_, alive)| alive())
            .map(|(name, _)| *name)
            .collect()
    };
    assert_eq!(
        alive(&probes).len(),
        probes.len(),
        "every provider is held by its slot before the clear"
    );

    let before = api.handle(events_request());
    assert!(before.is_ok(), "events family served before: {before:?}");

    api.clear_providers();

    let after = api.handle(events_request());
    let error = after.error.as_ref().expect("events family refused after");
    assert_eq!(error.code, ClientErrorCode::ModuleUnavailable);
    assert_eq!(
        alive(&probes),
        Vec::<&str>::new(),
        "slots still holding their provider after clear_providers"
    );

    // Idempotent; the sessions survive.
    api.clear_providers();
    assert!(api.sessions().get_valid(TOKEN, 0).is_ok());
}
