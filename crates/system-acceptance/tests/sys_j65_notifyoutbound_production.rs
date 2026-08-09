//! SYS-J-65 — production CLI notify composition and NotifyOutbound leak scanning.
//!
//! The witness starts at `advance_cli::wiring::wire_capabilities`, launches the
//! production `start.rs` serve loop through the `advance-cli/test-support` helper
//! over the caller-owned shared `MailboxStore`, then drives a notify-importing
//! runnable through the production `WasmRunnableHookFactory` + `CronDriver`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use advance_cli::commands::start::{spawn_test_agent_loop, TestServeLoop};
use advance_cli::runnable_hook_factory::WasmRunnableHookFactory;
use advance_cli::wiring::{wire_capabilities, WiringHandles};
use advance_messaging::MailboxStore;
use advance_runtime::bootstrap::{RuntimeHost, RuntimeHostBuilder};
use advance_scheduler::cron::CronDriver;
use advance_scheduler::hook::{HookError, RunnableHook, RunnableHookFactory};
use advance_scheduler::types::{ComponentConfig, RunResult};
use advance_shared_types::capability::{CapRequest, CapabilityId};
use async_trait::async_trait;
use cap_grant::{Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use wit_component::ComponentEncoder;

const SKELETON_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const NOTIFY_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-notify.core.wasm");

const NOTIFY_PAYLOAD: [u8; 4] = [0x07, 0x1F, 0xAB, 0x01];
const STATE_NOTIFY_AGENT_OK: [u8; 4] = [0x07, 0x1F, 0x0A, 0x01];
const STATE_NOTIFY_AGENT_BLOCKED: [u8; 4] = [0x07, 0x1F, 0xB0, 0x01];
const STATE_NOTIFY_CHANNEL_BLOCKED: [u8; 4] = [0x07, 0x1F, 0xB0, 0x02];

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
    "30415263748596a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f";

fn ensure_test_master_key() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var("SECRETS_MASTER_KEY", TEST_MASTER_KEY_HEX));
}

struct ProdHarness {
    _serve_loop: TestServeLoop,
    host: RuntimeHost,
    _handles: WiringHandles,
    shared_store: Arc<MailboxStore>,
    workspace: PathBuf,
    _tmp: TempDir,
}

struct CancelAfterRunHook {
    inner: Arc<dyn RunnableHook>,
    cancel: CancellationToken,
}

#[async_trait]
impl RunnableHook for CancelAfterRunHook {
    async fn run_once(&self, config: ComponentConfig) -> Result<RunResult, HookError> {
        let result = self.inner.run_once(config).await;
        self.cancel.cancel();
        result
    }
}

fn component_bytes(core: &[u8]) -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(core)
        .expect("core module wraps")
        .encode()
        .expect("component encoded")
}

fn fresh_workspace() -> (TempDir, PathBuf, PathBuf) {
    ensure_test_master_key();
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    std::fs::write(
        workspace.join(".agent/config.yaml"),
        "capabilities:\n  fs: true\n  messaging: true\n",
    )
    .unwrap();
    std::fs::write(
        workspace.join(".agent/behavior.component.wasm"),
        component_bytes(SKELETON_CORE),
    )
    .unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, MINIMAL_RUNTIME_YAML).unwrap();
    (dir, workspace, config_path)
}

async fn setup_prod() -> ProdHarness {
    let (tmp, workspace, config_path) = fresh_workspace();
    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .expect("runtime host builder");
    let (host, handles) = wire_capabilities(builder, &workspace)
        .await
        .expect("production wire_capabilities");
    let shared_store = handles
        .messaging_store
        .clone()
        .expect("messaging:true yields a shared MailboxStore");
    let serve_loop = spawn_test_agent_loop(&host, &workspace, &handles, shared_store.clone())
        .await
        .expect("spawn production serve loop")
        .expect("deployed skeleton component starts a serve loop");
    let loop_store = serve_loop.store();
    assert!(
        Arc::ptr_eq(&loop_store, &shared_store),
        "serve loop must read the exact store that wire_capabilities gave notify"
    );
    assert_eq!(serve_loop.agent_id(), "agent:default");

    ProdHarness {
        _serve_loop: serve_loop,
        host,
        _handles: handles,
        shared_store,
        workspace,
        _tmp: tmp,
    }
}

fn mailbox_depth(store: &MailboxStore, agent: &str) -> usize {
    store.get(agent).map(|m| m.depth()).unwrap_or(0)
}

fn grant_messaging(h: &ProdHarness, component_id: &str) {
    h._handles
        .cap_grant
        .store
        .insert_dynamic(Grant {
            id: GrantId::new(format!("grant:{component_id}:messaging")),
            grantee: component_id.to_string(),
            capability: "messaging".to_string(),
            params: Vec::new(),
            ttl: GrantTtl::Lifecycle,
            issuer: GrantIssuer::Admin,
            provenance: GrantProvenance::Requested,
            status: GrantStatus::Active,
            created_at: chrono::Utc::now(),
            expires_at: None,
        })
        .expect("insert messaging grant for cron component");
}

async fn drive_notify_cron(h: &ProdHarness, id: &str, branch: &[u8]) -> Vec<u8> {
    grant_messaging(h, id);
    let factory =
        WasmRunnableHookFactory::new(h.host.component_runtime(), h.host.capability_injector());
    let caps = vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }];
    let hook = factory
        .build(&component_bytes(NOTIFY_CORE), id, &caps)
        .await
        .expect("production runnable hook builds");
    let outdir = tempfile::tempdir().expect("cron output dir");
    let out_path = outdir.path().to_path_buf();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let hook: Arc<dyn RunnableHook> = Arc::new(CancelAfterRunHook {
        inner: hook,
        cancel: cancel.clone(),
    });
    let id_owned = id.to_string();
    let cfg = ComponentConfig {
        id: id.to_string(),
        config_data: Some(branch.to_vec()),
        trigger_context: None,
    };
    let handle = tokio::spawn(async move {
        CronDriver::run_periodic_with_emitter(
            &id_owned,
            Duration::from_millis(10),
            hook,
            cfg,
            Some(out_path),
            None,
            cancel_clone,
        )
        .await
    });

    let result_path = outdir.path().join("result.bin");
    for _ in 0..2000 {
        if result_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    cancel.cancel();
    let _ = handle.await;
    std::fs::read(&result_path).unwrap_or_else(|e| {
        panic!(
            "cron {id} did not produce result.bin at {}: {e}",
            result_path.display()
        )
    })
}

async fn poll_file_eq(path: &Path, expected: &[u8]) -> bool {
    for _ in 0..1000 {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes == expected {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

async fn poll_file_absent(path: &Path) -> bool {
    for _ in 0..100 {
        if path.exists() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// SYS-AC-265 — a production scheduler/runnable guest calls notify-agent,
/// delivers into the shared mailbox store, wakes the production serve loop, and
/// the target skeleton's handle-message writes the notify payload to `j01.txt`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_265_notify_agent_reaches_production_serve_loop() {
    let h = setup_prod().await;
    assert_eq!(mailbox_depth(&h.shared_store, "agent:default"), 0);

    let out = drive_notify_cron(&h, "cron-265", b"notify-agent-default").await;
    assert_eq!(out, STATE_NOTIFY_AGENT_OK);
    assert!(
        poll_file_eq(&h.workspace.join("j01.txt"), &NOTIFY_PAYLOAD).await,
        "target serve loop should consume the notify message and write j01.txt"
    );
    assert_eq!(mailbox_depth(&h.shared_store, "agent:default"), 0);
}

/// SYS-AC-266 — the same production caller path sends a block-class secret via
/// notify-agent; the live NotifyOutbound detector blocks before mailbox delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_266_notify_agent_secret_blocked_before_delivery() {
    let h = setup_prod().await;
    let out = drive_notify_cron(&h, "cron-266", b"notify-agent-secret").await;
    assert_eq!(out, STATE_NOTIFY_AGENT_BLOCKED);
    assert_eq!(mailbox_depth(&h.shared_store, "agent:default"), 0);
    assert!(
        poll_file_absent(&h.workspace.join("j01.txt")).await,
        "blocked notify-agent secret must not wake the target serve loop"
    );
}

/// SYS-AC-267 — notify-channel secret payloads are blocked by the same live
/// NotifyOutbound detector before channel adapter resolution or delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_267_notify_channel_secret_blocked_before_resolution() {
    let h = setup_prod().await;
    let out = drive_notify_cron(&h, "cron-267", b"notify-channel-secret").await;
    assert_eq!(out, STATE_NOTIFY_CHANNEL_BLOCKED);
    assert_eq!(mailbox_depth(&h.shared_store, "agent:default"), 0);
    assert!(
        poll_file_absent(&h.workspace.join("j01.txt")).await,
        "blocked notify-channel secret must not reach any target mailbox"
    );
}
