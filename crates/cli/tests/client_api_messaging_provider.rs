//! CLI-served MessagingProvider: deliver onto the serve-loop mailbox.
//! Wires AC-08 locally; does not flip MODULE-020-AC-08.

use std::sync::Arc;

use advance_cli::client_api_adapters::ServeLoopMessagingProvider;
use advance_cli::commands::start::spawn_test_agent_loop;
use advance_cli::reply::ReplyRegistry;
use advance_cli::wiring::wire_capabilities_with_home_for_test;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientMessageAck, ClientMessageStatus, ClientRequest,
    ClientSession, Platform, Principal, Scope,
};
use advance_messaging::{MailboxStore, DEFAULT_CAPACITY};
use advance_runtime::bootstrap::RuntimeHostBuilder;

const MINIMAL_RUNTIME_YAML: &str = "\
wasm:
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
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: \".runtime/index.db\"
  pool-size: 4
";

const TEST_MASTER_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

const J01_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    let session = ClientSession {
        session_id: format!("sess-{token}"),
        principal: Principal {
            id: "operator".to_string(),
            os_user: "op".to_string(),
        },
        platform: Platform::Mac,
        scopes,
        csrf_token: None,
        expires_at: u64::MAX,
    };
    api.sessions().insert(token.to_string(), session, 0);
}

fn send(
    api: &ClientApi,
    to: &str,
    payload: &str,
    key: &str,
) -> advance_client_api::ClientEnvelope<serde_json::Value> {
    api.handle(
        ClientRequest::post(
            "/client/messages",
            serde_json::json!({ "to": to, "payload": payload }),
        )
        .with_session("tok")
        .with_idempotency_key(key),
    )
}

fn get_status(api: &ClientApi, message_id: &str) -> ClientMessageStatus {
    let env = api
        .handle(ClientRequest::get(format!("/client/messages/{message_id}")).with_session("tok"));
    assert!(env.is_ok(), "status ok: {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).unwrap()
}

#[test]
fn msg01_send_delivers_user_payload() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let replies = Arc::new(ReplyRegistry::new());
    let api = ClientApi::new(ClientApiConfig::default()).with_messaging_provider(Arc::new(
        ServeLoopMessagingProvider::for_test(store.clone(), replies),
    ));
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);
    let env = send(&api, "agent:default", "hi", "k-send");
    assert!(env.is_ok(), "send ok: {:?}", env.error);
    let ack: ClientMessageAck = serde_json::from_value(env.data.clone().unwrap()).unwrap();
    assert_eq!(ack.to, "agent:default");
    assert_eq!(ack.delivery_state, "delivered");
    let got = store
        .get("agent:default")
        .expect("mailbox")
        .poll()
        .expect("user message");
    assert_eq!(got.payload, b"hi");
}

#[test]
fn msg02_status_replied_after_fulfill_without_register() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let replies = Arc::new(ReplyRegistry::new());
    let api = ClientApi::new(ClientApiConfig::default()).with_messaging_provider(Arc::new(
        ServeLoopMessagingProvider::for_test(store.clone(), replies.clone()),
    ));
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);
    let env = send(&api, "agent:default", "hi", "k-status");
    let ack: ClientMessageAck = serde_json::from_value(env.data.clone().unwrap()).unwrap();
    let st0 = get_status(&api, &ack.message_id);
    assert_eq!(st0.reply_state, "none");
    replies.fulfill("agent:default", Some(b"pong".to_vec()));
    let st1 = get_status(&api, &ack.message_id);
    assert_eq!(st1.reply_state, "replied");

    let mailbox = store.get("agent:default").expect("mailbox from first send");
    while mailbox
        .deliver(advance_messaging::Message {
            id: format!("fill-{}", mailbox.depth()),
            kind: advance_messaging::MessageKind::User,
            from: "user:client-api".into(),
            to: "agent:default".into(),
            payload: b"fill".to_vec(),
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        })
        .is_ok()
    {}
    let env_fail = send(&api, "agent:default", "again", "k-full");
    assert!(!env_fail.is_ok(), "full mailbox must fail send");
    let st2 = get_status(&api, &ack.message_id);
    assert_eq!(
        st2.reply_state, "replied",
        "failed send must not clear prior reply_state"
    );
}

#[test]
fn msg03_bare_api_is_module_unavailable() {
    let api = ClientApi::new(ClientApiConfig::default());
    mint(&api, "tok", vec![Scope::SendMessages]);
    let env = send(&api, "agent:default", "hi", "k-bare");
    assert!(!env.is_ok());
    let err = env.error.expect("error");
    assert_eq!(err.code.as_str(), "module_unavailable");
}

#[test]
fn msg04_unknown_to_is_not_found() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let replies = Arc::new(ReplyRegistry::new());
    let api = ClientApi::new(ClientApiConfig::default()).with_messaging_provider(Arc::new(
        ServeLoopMessagingProvider::for_test(store.clone(), replies),
    ));
    mint(&api, "tok", vec![Scope::SendMessages]);
    let env = send(&api, "default-agent", "hi", "k-wrong");
    assert!(!env.is_ok());
    let err = env.error.expect("error");
    assert_eq!(err.code.as_str(), "not_found");
    assert!(store.get("default-agent").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn msg05_composition_root_installs_provider_and_shares_store() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var("SECRETS_MASTER_KEY", TEST_MASTER_KEY_HEX));

    let dir = tempfile::tempdir().expect("tempdir");
    let home_dir = tempfile::tempdir().expect("home");
    let workspace = std::fs::canonicalize(dir.path()).expect("canon ws");
    let home = std::fs::canonicalize(home_dir.path()).expect("canon home");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    std::fs::write(
        workspace.join(".advance/runtime-config.yaml"),
        MINIMAL_RUNTIME_YAML,
    )
    .unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  llm: true\n",
    )
    .unwrap();
    std::fs::write(workspace.join(".agent/behavior.wasm"), J01_CORE).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");

    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("builder");
    let (host, handles) = wire_capabilities_with_home_for_test(builder, &workspace, &home)
        .await
        .expect("wire");
    let server = handles
        .client_api_server
        .as_ref()
        .expect("Client API bound");
    let api = server.api();
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);

    let serve = spawn_test_agent_loop(
        &host,
        &workspace,
        &handles,
        handles.client_ingress_store.clone(),
    )
    .await
    .expect("spawn")
    .expect("j01 driver starts a serve loop");
    assert!(
        Arc::ptr_eq(&serve.store(), &handles.client_ingress_store),
        "serve loop recvs the Client API ingress store"
    );

    let env = send(&api, "agent:default", "hi", "k-compose");
    assert!(env.is_ok(), "composition send: {:?}", env.error);
}

#[test]
fn msg06_status_stream_key_none_until_recorded() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let replies = Arc::new(ReplyRegistry::new());
    let api = ClientApi::new(ClientApiConfig::default()).with_messaging_provider(Arc::new(
        ServeLoopMessagingProvider::for_test(store.clone(), replies.clone()),
    ));
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);
    let env = send(&api, "agent:default", "hi", "k-stream-none");
    let ack: ClientMessageAck = serde_json::from_value(env.data.clone().unwrap()).unwrap();
    let st0 = get_status(&api, &ack.message_id);
    assert!(st0.stream_key.is_none());
    replies.record_stream_key("agent:default", "st_abc");
    let st1 = get_status(&api, &ack.message_id);
    assert_eq!(st1.stream_key.as_deref(), Some("st_abc"));
    let json = serde_json::to_value(&st0).unwrap();
    assert!(json.get("stream_key").is_none());
}

#[test]
fn msg09_two_sends_isolate_stream_key_per_message_id() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let replies = Arc::new(ReplyRegistry::new());
    let api = ClientApi::new(ClientApiConfig::default()).with_messaging_provider(Arc::new(
        ServeLoopMessagingProvider::for_test(store.clone(), replies.clone()),
    ));
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);
    let ack1: ClientMessageAck = serde_json::from_value(
        send(&api, "agent:default", "a", "k-iso-1")
            .data
            .clone()
            .unwrap(),
    )
    .unwrap();
    replies.record_stream_key("default-agent", "st_one");
    let ack2: ClientMessageAck = serde_json::from_value(
        send(&api, "agent:default", "b", "k-iso-2")
            .data
            .clone()
            .unwrap(),
    )
    .unwrap();
    replies.record_stream_key("default-agent", "st_two");
    assert_eq!(
        get_status(&api, &ack1.message_id).stream_key.as_deref(),
        Some("st_one")
    );
    assert_eq!(
        get_status(&api, &ack2.message_id).stream_key.as_deref(),
        Some("st_two")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn msg07_production_wrap_status_sees_begin_on_gateway_sink() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var("SECRETS_MASTER_KEY", TEST_MASTER_KEY_HEX));

    use advance_shared_types::traits::{LlmDeltaEvent, LlmDeltaFrame};

    let dir = tempfile::tempdir().expect("tempdir");
    let home_dir = tempfile::tempdir().expect("home");
    let workspace = std::fs::canonicalize(dir.path()).expect("canon ws");
    let home = std::fs::canonicalize(home_dir.path()).expect("canon home");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    std::fs::write(
        workspace.join(".advance/runtime-config.yaml"),
        MINIMAL_RUNTIME_YAML,
    )
    .unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  llm: true\n",
    )
    .unwrap();
    std::fs::write(workspace.join(".agent/behavior.wasm"), J01_CORE).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");

    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("builder");
    let (_host, handles) = wire_capabilities_with_home_for_test(builder, &workspace, &home)
        .await
        .expect("wire");
    let server = handles
        .client_api_server
        .as_ref()
        .expect("Client API bound");
    let api = server.api();
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);
    let env = send(&api, "agent:default", "hi", "k-prodwrap");
    let ack: ClientMessageAck = serde_json::from_value(env.data.clone().unwrap()).unwrap();

    let gw = handles.llm_gateway.as_ref().expect("llm: true ⇒ gateway");
    gw.delta_sink().publish(LlmDeltaEvent {
        agent_id: Arc::from("default-agent"),
        stream_key: Arc::from("st_prodwrap"),
        frame: LlmDeltaFrame::Begin {
            run_id: None,
            task_id: None,
        },
    });
    let st = get_status(&api, &ack.message_id);
    assert_eq!(st.stream_key.as_deref(), Some("st_prodwrap"));
}

#[tokio::test]
async fn msg08_generate_host_fn_status_key_and_hub_concat() {
    use std::net::IpAddr;
    use std::sync::{Arc as StdArc, RwLock};

    use advance_cli::reply::StreamKeyAnnouncer;
    use advance_client_api::clock::SystemClock;
    use advance_client_api::deltas::LlmDeltaHub;
    use advance_runtime::config::RuntimeConfigProvider;
    use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
    use advance_shared_types::capability::BudgetDecision;
    use advance_shared_types::security_validator::{
        HttpResponse, HttpSecurityChain, LeakDetector, SsrfGuard,
    };
    use advance_shared_types::traits::{
        EventBusEmit, LlmDeltaSink, RepetitionGuardCheck, RunBudget,
    };
    use cap_http::canonical_facade::decoded_hold_split;
    use cap_http::{
        DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, MockHttpExecutor,
        MockResolver,
    };
    use cap_llm::{register_agent_llm, LlmGateway};
    use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
    use wasmtime::component::Val;
    use zeroize::Zeroizing;

    const YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt4o: gpt-4o-2024-08-06
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
circuit-breakers: []
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
users: []
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

    struct Cfg(RwLock<StdArc<advance_runtime::config::RuntimeConfig>>);
    impl RuntimeConfigProvider for Cfg {
        fn current(&self) -> StdArc<advance_runtime::config::RuntimeConfig> {
            StdArc::clone(&self.0.read().unwrap())
        }
        fn subscribe(
            &self,
        ) -> tokio::sync::mpsc::Receiver<StdArc<advance_runtime::config::RuntimeConfig>> {
            tokio::sync::mpsc::channel(1).1
        }
        fn last_error(&self) -> Option<String> {
            None
        }
    }
    struct Allow;
    impl RunBudget for Allow {
        fn check(&self, _: &str, _: u64, _: f64) -> BudgetDecision {
            BudgetDecision::Allow
        }
        fn commit(&self, _: &str, _: u64, _: f64) {}
    }
    struct Bus;
    impl EventBusEmit for Bus {
        fn emit(&self, _: advance_shared_types::event::Event) {}
    }
    struct Rep;
    impl RepetitionGuardCheck for Rep {
        fn record_tool_call(
            &self,
            _: &str,
            _: advance_shared_types::repetition::ToolCallSignature,
        ) -> advance_shared_types::repetition::RepetitionDecision {
            advance_shared_types::repetition::RepetitionDecision::Pass
        }
        fn record_output(
            &self,
            _: &str,
            _: advance_shared_types::repetition::OutputHash,
        ) -> advance_shared_types::repetition::RepetitionDecision {
            advance_shared_types::repetition::RepetitionDecision::Pass
        }
    }
    struct AllowRl;
    impl cap_http::rate_limit::RateLimiter for AllowRl {
        fn check(&self, _: &str, _: &str) -> Result<(), u64> {
            Ok(())
        }
    }

    let storage: StdArc<dyn SecretStorage> = StdArc::new(InMemorySecretStorage::new());
    let secrets = SecretStore::new(Zeroizing::new([0xab_u8; 32]), storage);
    secrets
        .store("openai-api-key", "test-secret-value")
        .unwrap();
    let exec = MockHttpExecutor::new().with_response(
        "https://api.openai.com/v1/chat/completions",
        HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(&serde_json::json!({
                "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                "model": "gpt-4o-mini",
            }))
            .unwrap(),
        },
    );
    let leak: StdArc<dyn LeakDetector> = StdArc::new(DefaultLeakDetector::new());
    let ssrf: StdArc<dyn SsrfGuard> = StdArc::new(DefaultSsrfGuard::with_resolver(Box::new(
        MockResolver::new().with("api.openai.com", vec!["8.8.8.8".parse::<IpAddr>().unwrap()]),
    )));
    let chain: StdArc<dyn HttpSecurityChain> = StdArc::new(DefaultHttpSecurityChain::new(
        StdArc::new(secrets),
        leak.clone(),
        ssrf,
        StdArc::new(AllowRl),
        StdArc::new(exec),
    ));

    let hub = StdArc::new(LlmDeltaHub::new(
        Some(StdArc::new(DefaultLeakDetector::new()) as StdArc<dyn LeakDetector>),
        Some(StdArc::new(|buf: &[u8], max: usize| {
            decoded_hold_split(buf, max)
        })),
        StdArc::new(SystemClock),
        None,
    ));
    let replies = StdArc::new(ReplyRegistry::new());
    let sink: StdArc<dyn LlmDeltaSink> = StdArc::new(StreamKeyAnnouncer::new(
        StdArc::clone(&hub) as StdArc<dyn LlmDeltaSink>,
        StdArc::clone(&replies),
    ));
    let cfg = serde_yml::from_str(YAML).unwrap();
    let gw = StdArc::new(
        LlmGateway::new(
            StdArc::new(Cfg(RwLock::new(StdArc::new(cfg)))),
            chain,
            StdArc::new(Allow),
            StdArc::new(Bus) as StdArc<dyn EventBusEmit>,
            StdArc::new(Rep),
            "default-agent".into(),
        )
        .with_delta_sink(sink),
    );
    let registry = InMemoryHostRegistry::new();
    register_agent_llm(&registry, StdArc::clone(&gw));
    let generate_h = registry
        .lookup("llm")
        .into_iter()
        .find(|s| s.name == "generate")
        .expect("generate host fn")
        .handler
        .clone();

    let store = StdArc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let api = ClientApi::new(ClientApiConfig::default()).with_messaging_provider(StdArc::new(
        ServeLoopMessagingProvider::for_test(store, StdArc::clone(&replies)),
    ));
    mint(&api, "tok", vec![Scope::SendMessages, Scope::ReadMessages]);
    let env = send(&api, "agent:default", "hi", "k-c235");
    let ack: ClientMessageAck = serde_json::from_value(env.data.clone().unwrap()).unwrap();

    let ctx = HostCallContext {
        agent_id: "default-agent".into(),
        trace_id: "t-c235".into(),
        turn_id: None,
        capability: "llm".into(),
        function: "agent-llm::generate".into(),
        run_id: None,
        iteration: None,
    };
    let vals = generate_h
        .call(ctx, vec![Val::String("hello".into())], 1)
        .await
        .expect("host fn");
    assert!(
        matches!(&vals[0], Val::Result(Ok(_))),
        "generate ok: {:?}",
        vals[0]
    );

    let st = get_status(&api, &ack.message_id);
    let key = st.stream_key.expect("status stream_key");
    assert!(key.starts_with("st_"), "{key}");
    let page = hub.read_page(&key, 0);
    let concat: String = page.deltas.iter().map(|d| d.text.as_str()).collect();
    assert_eq!(concat, "hello");
}
