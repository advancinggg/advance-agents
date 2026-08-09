//! SYS-J-55 — a scheduled non-agent component calls `notify-agent` and the payload
//! lands in the target agent's mailbox (`msg.received`) WITHOUT a hierarchy check,
//! waking its handle-message; over-capacity and unknown-target errors are surfaced
//! without delivery. Chain: MODULE-014 → MODULE-001 → MODULE-006 → MODULE-019.
//!
//! Witness surface: the caller is a real `CronDriver` tick invoking the production
//! `WasmRunnableHook` over a guest that imports `advance:runtime/notify@0.1.0`.
//! `ComponentCtx` keeps the cron component id for L1 gates, while the typed notify
//! path maps the host-fn sender to `system`; no test calls the notify host-fn
//! directly.

use std::time::Duration;

use advance_scheduler::cron::CronDriver;
use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::types::{ComponentConfig, RunResult};
use async_trait::async_trait;
use system_acceptance::{Cap, SystemUnderTest};
use tokio_util::sync::CancellationToken;

const NOTIFY_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-notify.core.wasm");
const TARGET: &str = "agent:harness";
const STATE_NOTIFY_AGENT_OK: [u8; 4] = [0x07, 0x1F, 0x0A, 0x01];
const STATE_NOTIFY_AGENT_FULL: [u8; 4] = [0x07, 0x1F, 0xF0, 0x01];

fn msg_received_count(sut: &SystemUnderTest) -> usize {
    sut.events()
        .iter()
        .filter(|e| e.event_type == "msg.received")
        .count()
}

fn mailbox_depth(sut: &SystemUnderTest, agent: &str) -> usize {
    sut.mailbox_store()
        .get(agent)
        .map(|m| m.depth())
        .unwrap_or(0)
}

struct CancelAfterRunHook {
    inner: std::sync::Arc<dyn RunnableHook>,
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

async fn drive_notify_cron(sut: &SystemUnderTest, id: &str, branch: &[u8]) -> Option<Vec<u8>> {
    let hook = sut.wasm_runnable_hook(id);
    let emitter = sut.event_emitter();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let hook: std::sync::Arc<dyn RunnableHook> = std::sync::Arc::new(CancelAfterRunHook {
        inner: hook,
        cancel: cancel.clone(),
    });
    let id_owned = id.to_string();
    let outdir = tempfile::tempdir().expect("cron output dir");
    let out_path = outdir.path().to_path_buf();
    let cfg = ComponentConfig {
        id: id.to_string(),
        config_data: Some(branch.to_vec()),
        trigger_context: None,
    };
    let handle = tokio::spawn(async move {
        // Tokio's first interval tick is immediate. Keep the following tick well
        // beyond one witness run so a slow/contended first invocation cannot
        // leave both cancellation and an overdue second tick ready at once.
        CronDriver::run_periodic_with_emitter(
            &id_owned,
            Duration::from_secs(60),
            hook,
            cfg,
            Some(out_path),
            Some(emitter),
            cancel_clone,
        )
        .await
    });

    for _ in 0..2000 {
        let terminal = sut.events().iter().any(|e| {
            (e.event_type == "component.finished" || e.event_type == "component.error")
                && e.payload.get("id").and_then(|v| v.as_str()) == Some(id)
        });
        if terminal {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    cancel.cancel();
    let _ = handle.await;
    let output = std::fs::read(outdir.path().join("result.bin")).ok();
    if output.is_none() {
        let errors: Vec<_> = sut
            .events()
            .into_iter()
            .filter(|e| {
                e.event_type == "component.error"
                    && e.payload.get("id").and_then(|v| v.as_str()) == Some(id)
            })
            .map(|e| e.payload)
            .collect();
        panic!("cron {id} produced no result.bin; component.error payloads={errors:?}");
    }
    output
}

/// SYS-AC-173 — a scheduled non-agent notify-agent to the target delivers into its
/// mailbox without a hierarchy check, emits exactly one `msg.received`
/// (`from=system`, `kind=system`), and a single handle-message turn consumes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_173_notify_delivers_without_hierarchy_check_and_wakes_handle_message() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .caps(&[Cap::Fs, Cap::Messaging])
        .build(NOTIFY_BYTES)
        .await;

    let out = drive_notify_cron(&sut, "cron-173", b"notify-agent-harness")
        .await
        .expect("cron notify output");
    assert_eq!(out, STATE_NOTIFY_AGENT_OK);

    let received: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "msg.received")
        .collect();
    assert_eq!(received.len(), 1, "exactly one msg.received");
    let ev = &received[0];
    assert_eq!(ev.agent_id, TARGET, "event.agent_id is the recipient");
    assert_eq!(ev.payload["from"].as_str(), Some("system"));
    assert_eq!(ev.payload["kind"].as_str(), Some("system"));
    assert_eq!(ev.payload["to"].as_str(), Some(TARGET));

    assert_eq!(mailbox_depth(&sut, TARGET), 1);
    sut.run_turn().await;
    assert_eq!(mailbox_depth(&sut, TARGET), 0);
}

/// SYS-AC-174 — with mailbox capacity 1, the first scheduled notify delivers and
/// the second returns the typed `mailbox-full` branch from the guest fixture while
/// delivering nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_174_over_capacity_returns_mailbox_full_and_delivers_nothing() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .caps(&[Cap::Fs, Cap::Messaging])
        .with_mailbox_cap(1)
        .build(NOTIFY_BYTES)
        .await;

    let first = drive_notify_cron(&sut, "cron-174a", b"notify-agent-harness")
        .await
        .expect("first notify output");
    assert_eq!(first, STATE_NOTIFY_AGENT_OK);
    assert_eq!(mailbox_depth(&sut, TARGET), 1);
    assert_eq!(msg_received_count(&sut), 1);

    let second = drive_notify_cron(&sut, "cron-174b", b"notify-agent-harness-full")
        .await
        .expect("mailbox-full sentinel output");
    assert_eq!(second, STATE_NOTIFY_AGENT_FULL);
    assert_eq!(mailbox_depth(&sut, TARGET), 1);
    assert_eq!(msg_received_count(&sut), 1);
}

/// SYS-AC-175 — a scheduled notify-agent carrying a message-context delivers a
/// `msg.received` whose task/run/execution ids match, and one turn consumes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_175_notify_carries_message_context_and_one_turn() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .caps(&[Cap::Fs, Cap::Messaging])
        .build(NOTIFY_BYTES)
        .await;

    let out = drive_notify_cron(&sut, "cron-175", b"notify-agent-harness-context")
        .await
        .expect("context notify output");
    assert_eq!(out, STATE_NOTIFY_AGENT_OK);

    let received: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "msg.received")
        .collect();
    assert_eq!(received.len(), 1, "exactly one msg.received");
    let ev = &received[0];
    assert_eq!(ev.task_id.as_deref(), Some("task-175"));
    assert_eq!(ev.run_id.as_deref(), Some("run-175"));
    assert_eq!(ev.execution_id.as_deref(), Some("exec-175"));

    assert_eq!(mailbox_depth(&sut, TARGET), 1);
    sut.run_turn().await;
    assert_eq!(mailbox_depth(&sut, TARGET), 0);
}

/// SYS-AC-244 — a scheduled notify-agent to a non-existent target returns the
/// fixture's typed `invalid-target("target_unknown")` sentinel and delivers
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_244_notify_to_unknown_target_returns_invalid_target_and_delivers_nothing() {
    let sut = SystemUnderTest::builder()
        .with_triggers()
        .caps(&[Cap::Fs, Cap::Messaging])
        .build(NOTIFY_BYTES)
        .await;

    let out = drive_notify_cron(&sut, "cron-244", b"notify-agent-unknown")
        .await
        .expect("unknown-target sentinel output");
    assert_eq!(out, STATE_NOTIFY_AGENT_OK);
    assert_eq!(msg_received_count(&sut), 0);
    assert_eq!(mailbox_depth(&sut, TARGET), 0);
}
