//! SLICE 2 — `CapChannelNotifySink` (the SYS-AC-257 product seam).
//!
//! PRODUCT-UNIT/INTEGRATION witnesses for the cli notify sink that routes the
//! auto-loop degrade/halt notification through cap-channel OUTBOUND egress so
//! `channel.raw_sent` fires. These flip **ZERO SYS-AC** — the SYS-AC-257 e2e
//! witness (`sys_j62_auto_degrade_halt.rs`, real outbound sub + real
//! `HttpSecurityChain` pass on a wired daemon) stays `#[ignore]`d until the harvest.
//! Here the security chain is an `OkChain` double — legitimate product-unit-testing
//! of the sink→transport→emit path (the egress emit semantics are MODULE-016-AC-12,
//! already `passed`).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_cli::channel_notify_sink::CapChannelNotifySink;
use advance_scheduler_auto_loop::config::{
    MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
};
use advance_scheduler_auto_loop::{
    AutoLoopDriver, AutoLoopError, DefaultAutoLoopDriver, IterationCheckpoint, IterationRollback,
    NotifySink, NotifySinkError,
};
use advance_shared_types::event::Event;
use advance_shared_types::outbound::OutboundTarget;
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
};
use advance_shared_types::traits::EventBusEmit;
use cap_channel::{
    AdapterType, ChannelConfig, Consumer, HttpEgress, HttpMethod, OutboundConfig,
    OutboundTransport, Subscription, SubscriptionId,
};

// ── doubles ──────────────────────────────────────────────────────────────────

/// A security chain that always passes (200) — the executor/network is out of scope
/// for the emit test (mirrors cap-channel's own `egress::tests::OkChain`).
struct OkChain;
#[async_trait]
impl HttpSecurityChain for OkChain {
    async fn execute(
        &self,
        _agent_id: &str,
        _req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{\"ok\":true}".to_vec(),
        })
    }
}

#[derive(Default)]
struct RecBus {
    events: Mutex<Vec<Event>>,
}
impl RecBus {
    fn count(&self, ty: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .count()
    }
    fn raw_sent_body_bytes(&self) -> Option<u64> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.event_type == "channel.raw_sent")
            .and_then(|e| e.payload["body_bytes"].as_u64())
    }
    fn raw_sent_adapter(&self) -> Option<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.event_type == "channel.raw_sent")
            .and_then(|e| e.payload["adapter"].as_str().map(str::to_string))
    }
}
impl EventBusEmit for RecBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct NoopCkpt;
#[async_trait]
impl IterationCheckpoint for NoopCkpt {
    async fn checkpoint_baseline(&self, _agent_id: &str) -> Result<(), AutoLoopError> {
        Ok(())
    }
    async fn checkpoint_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}
struct NoopRb;
#[async_trait]
impl IterationRollback for NoopRb {
    async fn rollback_iteration(&self, _agent_id: &str, _n: u32) -> Result<(), AutoLoopError> {
        Ok(())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn telegram_config(outbound: bool) -> ChannelConfig {
    ChannelConfig {
        adapter_type: AdapterType::Telegram,
        params: vec![],
        outbound: outbound.then(|| OutboundConfig {
            method: HttpMethod::Post,
            url_template: "https://api.telegram.org/bot123/sendMessage".to_string(),
            headers: vec![("Content-Type".into(), "application/json".into())],
        }),
    }
}

/// A standalone OUTBOUND notify subscription owned by `owner` (`HostPump`, no guest).
fn notify_sub(owner: &str, outbound: bool) -> Subscription {
    Subscription::new_with_consumer(
        SubscriptionId::new(),
        owner,
        telegram_config(outbound),
        Consumer::HostPump,
    )
}

fn notify_target() -> OutboundTarget {
    OutboundTarget::ChatReply {
        conversation_id: "98765".into(),
        reply_address: vec![("chat_id".into(), "98765".into())],
    }
}

fn egress(bus: Arc<RecBus>) -> Arc<dyn OutboundTransport> {
    Arc::new(HttpEgress::new(Arc::new(OkChain)).with_event_bus(bus))
}

fn primary_only_criteria() -> SuccessCriteria {
    SuccessCriteria {
        evaluator: None,
        objectives: vec![Objective {
            name: "val-bpb".to_string(),
            role: Role::Primary,
            metric_source: MetricSource::File {
                path: "m.json".to_string(),
                key: "v".to_string(),
            },
            predicate: Predicate {
                op: Op::Lt,
                threshold: None,
            },
        }],
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    }
}

// ── T-NS-1 — notify → channel.raw_sent ───────────────────────────────────────
#[tokio::test]
async fn notify_emits_channel_raw_sent() {
    let bus = Arc::new(RecBus::default());
    let sink = CapChannelNotifySink::new(
        egress(bus.clone()),
        "agent:owner",
        notify_sub("agent:owner", true),
        notify_target(),
    );

    sink.notify("root", "auto-loop halted: max_iterations")
        .await
        .expect("notify ok");

    assert_eq!(
        bus.count("channel.raw_sent"),
        1,
        "exactly one channel.raw_sent"
    );
    assert_eq!(bus.raw_sent_adapter().as_deref(), Some("telegram"));
    // body_bytes is the PRE-render guest data length: the formatted notify body.
    let body = format!("[{}] {}", "root", "auto-loop halted: max_iterations");
    assert_eq!(bus.raw_sent_body_bytes(), Some(body.len() as u64));
}

// ── T-NS-2 — notify failure → NotifySinkError, no emit ───────────────────────
#[tokio::test]
async fn notify_failure_surfaces_error_no_emit() {
    let bus = Arc::new(RecBus::default());
    // A subscription with NO outbound config → `send` returns InvalidConfig before
    // the chain — a realistic transport failure that the sink must map (not panic).
    let sink = CapChannelNotifySink::new(
        egress(bus.clone()),
        "agent:owner",
        notify_sub("agent:owner", false),
        notify_target(),
    );

    let err = sink
        .notify("root", "auto-loop degraded: 3 consecutive LLM errors")
        .await
        .expect_err("notify must surface the transport failure");
    assert!(matches!(err, NotifySinkError::NotifyFailed(_)));
    assert_eq!(bus.count("channel.raw_sent"), 0, "no emit on failure");
}

// ── T-NS-3 — driver degrade drives CapChannelNotifySink → channel.raw_sent ───
// Proves the sink is genuinely INSTALLED into the driver's degrade/halt path
// (`run_cadence_pass` → `notify_sink.notify`), not "built but unwired".
#[tokio::test]
async fn driver_degrade_drives_cap_channel_notify_to_raw_sent() {
    let bus = Arc::new(RecBus::default());
    let sink: Arc<dyn NotifySink> = Arc::new(CapChannelNotifySink::new(
        egress(bus.clone()),
        "agent:owner",
        notify_sub("agent:owner", true),
        notify_target(),
    ));
    let driver =
        DefaultAutoLoopDriver::new(Arc::new(NoopCkpt), Arc::new(NoopRb)).with_notify_sink(sink);
    driver
        .start("root", primary_only_criteria())
        .await
        .expect("start");

    // 3 consecutive LLM errors ≥ the default limit (3) → degrade on the next tick.
    driver.record_llm_error("root");
    driver.record_llm_error("root");
    driver.record_llm_error("root");
    driver.run_cadence_pass(1_000).await;

    assert_eq!(
        bus.count("channel.raw_sent"),
        1,
        "degrade notification egressed via cap-channel → channel.raw_sent"
    );
}
