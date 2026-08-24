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
