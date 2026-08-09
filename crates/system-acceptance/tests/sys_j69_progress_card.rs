//! SYS-J-69 / MODULE-006-AC-08 — real repository WASM actions reach the
//! jointly activated C216/C215 production dispatcher and Telegram renderer.
//!
//! Two fresh protected turns instantiate the checked-in `guest-rust-send`
//! fixture independently.  Its unchanged payload-only Action ABI emits
//! ack→progress→result and ack→progress→error.  The production composition
//! root decodes and host-stamps each source, renders one mutable Telegram card,
//! and sends every attempt through the real DefaultHttpSecurityChain.  Only
//! deterministic DNS and the external Telegram peer are doubled.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_cli::agent_loop::{build_agent_loop_with_prebuilt_dispatcher, WasmMessageHandler};
use advance_cli::wiring::wire_capabilities_with_channel_security_for_test;
use advance_messaging::TurnMailboxDelivery;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::capability::{CapRequest, CapabilityId};
use advance_shared_types::mailbox::{Message, MessageKind, MessageOrigin};
use advance_shared_types::security_validator::{
    HttpRequest, HttpResponse, RedirectCheck, SsrfGuard,
};
use advance_shared_types::turn_attribution::{QueuedTurnSpec, TurnCompletionOwner};
use advance_shared_types::SessionId;
use async_trait::async_trait;
use cap_http::{DefaultSsrfGuard, ExecutorError, HttpExecutor, MockResolver};

const AGENT_COLON: &str = "agent:default";
const AGENT_BARE: &str = "default-agent";
const TEST_MASTER_KEY: &str = "4f0be08e7d1746246fe409f30f67df1826848f071d4608f41de29c5c082f9b31";
const CORE: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-send.core.wasm");

const RUNTIME_YAML: &str = r#"wasm:
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
  env-var-name: SYS_J69_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4

channels:
  webhook-listen-addr: "127.0.0.1:0"
  channels:
    - name: progress-telegram
      adapter: telegram
      secret: inbound-test-secret
      route: progress
      url-template: "https://api.telegram.org/bot123/sendMessage"
      user-mappings:
        - channel-kind: telegram
          sender-id: "4242"
          user: "user:alice"
"#;

const AGENT_YAML: &str = r#"capabilities:
  messaging: true
"#;

#[derive(Default)]
struct TelegramPeer {
    requests: Mutex<Vec<HttpRequest>>,
}

impl TelegramPeer {
    fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpExecutor for TelegramPeer {
    async fn execute(
        &self,
        request: &HttpRequest,
        _redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"ok":true,"result":{"message_id":77}}"#.to_vec(),
        })
    }
}

fn fresh_workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("workspace");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonical workspace");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let runtime_config = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&runtime_config, RUNTIME_YAML).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), AGENT_YAML).unwrap();
    (dir, workspace, runtime_config)
}

fn inbound_message(source_id: &str, subscription_id: &str) -> Message {
    let mut channel_metadata = HashMap::new();
    channel_metadata.insert("channel.adapter".into(), "telegram".into());
    channel_metadata.insert("channel.sender_id".into(), "4242".into());
    channel_metadata.insert(
        "channel.subscription_id".into(),
        subscription_id.to_string(),
    );
    channel_metadata.insert("channel.conversation_id".into(), "chat-42".into());
    channel_metadata.insert("channel.reply_address.chat_id".into(), "chat-42".into());
    Message {
        id: source_id.to_string(),
        kind: MessageKind::User,
        from: "user:alice".into(),
        to: AGENT_COLON.into(),
        payload: b"run progress witness".to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: Some(MessageOrigin {
            message_id: source_id.to_string(),
            original_channel: "telegram".into(),
            original_sender: "4242".into(),
            adapter_id: "telegram".into(),
            channel_metadata,
            received_at: advance_shared_types::chrono::Utc::now(),
            context: None,
        }),
    }
}

fn publish_turn(
    store: &Arc<advance_messaging::MailboxStore>,
    source_id: &str,
    subscription_id: &str,
) {
    store
        .publish_execution_turn(TurnMailboxDelivery {
            target: AGENT_COLON.into(),
            message: inbound_message(source_id, subscription_id),
            spec: QueuedTurnSpec {
                turn_id: source_id.to_string(),
                expected_agent: AGENT_COLON.into(),
                parent_agent: "user:alice".into(),
                session_id: SessionId(format!("exec_{source_id}")),
                slot: 0,
                completion_owner: TurnCompletionOwner::ExecutionBoundary,
                original_task_id: Some(format!("task-{source_id}")),
                original_run_id: Some(format!("run-{source_id}")),
                original_reply_to: Some("user:alice".into()),
            },
        })
        .expect("publish protected channel turn");
}

fn message_handler(
    host: &advance_runtime::bootstrap::RuntimeHost,
    trace_id: &str,
) -> Arc<dyn MessageHandler> {
    let component = build_agent::encode_core_to_component(CORE).expect("encode component");
    let loaded = host
        .component_runtime()
        .load_component(&component)
        .expect("load repository guest");
    Arc::new(WasmMessageHandler::new(
        host.component_runtime(),
        loaded,
        host.capability_injector(),
        vec![CapRequest {
            capability: CapabilityId::from("messaging"),
        }],
        AGENT_BARE.into(),
        trace_id.into(),
    ))
}

fn assert_request(request: &HttpRequest, suffix: &str, text: &str, edit: bool) {
    assert!(
        request.url.ends_with(suffix),
        "request URL: {}",
        request.url
    );
    let body: serde_json::Value = serde_json::from_slice(&request.body).expect("Telegram JSON");
    assert_eq!(body["chat_id"], "chat-42");
    assert_eq!(body["text"], text);
    if edit {
        assert_eq!(body["message_id"], 77);
    } else {
        assert!(body.get("message_id").is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn module_006_ac_08_real_wasm_both_terminal_branches_use_one_card_and_security_chain() {
    std::env::set_var("SYS_J69_MASTER_KEY", TEST_MASTER_KEY);
    let platform_home_guard = tempfile::tempdir().expect("platform home");
    let platform_home = std::fs::canonicalize(platform_home_guard.path()).expect("canonical home");
    std::env::set_var("HOME", &platform_home);

    let (_workspace_guard, workspace, config_path) = fresh_workspace();
    let peer = Arc::new(TelegramPeer::default());
    let mut resolver = MockResolver::new();
    resolver = resolver.with("api.telegram.org", vec!["8.8.8.8".parse().unwrap()]);
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let executor: Arc<dyn HttpExecutor> = peer.clone();
    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("runtime builder");
    let (host, handles) =
        wire_capabilities_with_channel_security_for_test(builder, &workspace, ssrf, executor)
            .await
            .expect("production composition");

    let channel = handles
        .channel_runtime
        .as_ref()
        .expect("configured Telegram runtime");
    assert_eq!(channel.subs.len(), 1);
    let subscription_id = channel.subs[0].sub_id.as_str().to_string();
    let store = handles
        .messaging_store
        .as_ref()
        .expect("protected mailbox store")
        .clone();
    let dispatcher = handles
        .action_dispatcher_for_test()
        .expect("joint action dispatcher");
    let boundary = handles
        .protected_turn_boundary_for_test()
        .expect("joint execution boundary");

    for (index, (branch, source_id)) in [
        ("progress-result", "progress-result-source"),
        ("progress-error", "progress-error-source"),
    ]
    .into_iter()
    .enumerate()
    {
        publish_turn(&store, source_id, &subscription_id);
        let driver = build_agent_loop_with_prebuilt_dispatcher(
            store.clone(),
            message_handler(&host, &format!("trace-progress-{index}")),
            dispatcher.clone(),
        )
        .with_protected_turn_boundary(boundary.clone());
        driver
            .serve_n_turns(
                AGENT_COLON,
                ComponentConfig {
                    id: format!("progress-branch-{index}"),
                    config_data: Some(branch.as_bytes().to_vec()),
                    trigger_context: None,
                },
                WasmInstance::new(ComponentId::new(format!("progress-instance-{index}")).unwrap()),
                1,
            )
            .await;
    }

    let requests = peer.requests();
    assert_eq!(requests.len(), 6, "three chain attempts per fresh source");
    assert_request(&requests[0], "/sendMessage", "Accepted", false);
    assert_request(&requests[1], "/editMessageText", "Working", true);
    assert_request(&requests[2], "/editMessageText", "Completed", true);
    assert_request(&requests[3], "/sendMessage", "Accepted", false);
    assert_request(&requests[4], "/editMessageText", "Working", true);
    assert_request(&requests[5], "/editMessageText", "Failed", true);
}
