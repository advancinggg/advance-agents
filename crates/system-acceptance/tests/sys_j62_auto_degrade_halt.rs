//! SYS-J-62 (auto loop degrades on no-progress / halts on safety-valve breach)
//! system-acceptance witnesses. Drives the REAL `run_cadence_pass` via the
//! production `on_tick` (`SchedulerExtension`) over the cli-built driver;
//! `auto.degraded` / `auto.halted` land on the REAL capturing EventBus.
//!
//! Flips: SYS-AC-256 / 258, and — Wave-8 Lane A — SYS-AC-257 (now PRODUCT-installed sink).
//!
//! SYS-AC-257 (Wave-8 Lane A, 2026-06-22): FLIPPED. The earlier defer (adversarial r6) was
//! that the witness SWAPPED the cap-channel sink via `.with_notify_sink` (a harness override),
//! so `channel.raw_sent` fired ONLY because the harness installed it — while the production
//! auto-wiring wired `EventBusNotifySink` → `auto.notify`. Wave-7 Lane B MERGED the production
//! config-sourcing install: `build_auto_loop_driver_with_channel_notify` (`auto_wiring.rs:303`)
//! installs `CapChannelNotifySink` (→ `channel.raw_sent`) REPLACING the `EventBusNotifySink`
//! (→ `auto.notify`) default from a `channels.notify` config, and `wire_capabilities`
//! (`wiring.rs:528`) calls it on the daemon-boot path. This witness now builds the driver via
//! THAT production fn (the `WireOpts.notify_channel` harness variant routes to it) and drives
//! the degrade through the PRODUCTION registered `AutoTickExtension::on_tick` — no harness sink
//! swap, no bare-driver tick. The `OkChain` doubles ONLY the network executor (outside the
//! SYS-J-62 chain, downstream of the `channel.raw_sent` emit — MODULE-016-AC-12).

mod stepd_auto_support;

use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;

use advance_runtime::config::{NotifyChannelConfig, NotifyReplyAddr};
use advance_scheduler::{SchedulerExtension, SchedulerTick};
use advance_scheduler_auto_loop::config::{Op, SafetyValve};
use advance_scheduler_auto_loop::{AutoLoopDriver, AutoStatus, IterationOutcome, IterationStatus};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
};
use advance_shared_types::traits::EventBusEmit;
use cap_channel::{HttpEgress, OutboundTransport};

use stepd_auto_support::{
    close_ctx, criteria_with_safety_valve, primary_criteria, AutoWired, WireOpts,
};

// ── 257 doubles: a RECORDING OkChain (captures the outbound body the product
//    built) + a RecBus (captures the redacted channel.raw_sent egress event) ──

#[derive(Default)]
struct RecordingOkChain {
    bodies: StdMutex<Vec<Vec<u8>>>,
}
#[async_trait]
impl HttpSecurityChain for RecordingOkChain {
    async fn execute(
        &self,
        _agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        // The product-built, rendered outbound request body reaches the chain here
        // (cap-channel egress.rs:180) — capture it; the network executor is out of
        // scope (a component outside the SYS-J-62 chain).
        self.bodies.lock().unwrap().push(req.body.clone());
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: b"{\"ok\":true}".to_vec(),
        })
    }
}

#[derive(Default)]
struct RecBus {
    events: StdMutex<Vec<Event>>,
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
}
impl EventBusEmit for RecBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

// SYS-AC-256: after N consecutive no-progress rounds the auto run transitions to
// Degraded, emits auto.degraded, and reduces its schedule frequency (observable
// reduced cadence). The no-progress count is accrued through REAL discard closes
// (NOT injected). Mirrors auto-loop ac24_no_progress_degrades_with_reduced_cadence.
#[tokio::test]
async fn sys_ac_256_no_progress_degrades_with_reduced_cadence() {
    let sv = SafetyValve {
        consecutive_no_progress_limit: Some(2),
        ..Default::default()
    };
    let w = AutoWired::build(WireOpts::default());
    w.driver
        .start("root", criteria_with_safety_valve(sv))
        .await
        .expect("start");

    // keep (baseline 0.5), then 2 non-improving discards → consecutive_no_progress=2.
    // Each iteration first checkpoints (real M003) so the discard arm's real
    // rollback_iteration has a checkpoint to restore.
    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("is1");
    let o0 = w
        .driver
        .close_iteration(close_ctx("root", 1, Some(0.5), false))
        .await
        .expect("c1");
    assert!(matches!(
        o0,
        IterationOutcome::Continue {
            status: IterationStatus::Keep,
            ..
        }
    ));
    for n in 2..=3u32 {
        w.driver
            .iteration_start("root", Some("run-root".to_string()), n)
            .await
            .expect("is");
        let o = w
            .driver
            .close_iteration(close_ctx("root", n, Some(0.9), false))
            .await
            .expect("discard close");
        assert!(matches!(
            o,
            IterationOutcome::Continue {
                status: IterationStatus::Discard,
                ..
            }
        ));
    }

    // Cadence tick → REAL run_cadence_pass → no-progress detector fires → Degraded.
    w.driver.on_tick(SchedulerTick::new(1000)).await;
    assert_eq!(w.driver.status("root").await, Some(AutoStatus::Degraded));
    assert_eq!(
        w.bus.event_count("auto.degraded"),
        1,
        "exactly one auto.degraded on the real bus"
    );
    let backoff = w
        .driver
        .degraded_backoff_until_ms("root")
        .expect("backoff window opened");
    assert!(
        backoff > 1000,
        "reduced-cadence backoff window opened: {backoff}"
    );
    assert_eq!(w.driver.cadence_skip("root"), Some(0));

    // A tick WITHIN the backoff window is SKIPPED (reduced cadence observable).
    w.driver.on_tick(SchedulerTick::new(2000)).await;
    assert_eq!(
        w.driver.cadence_skip("root"),
        Some(1),
        "a within-window tick is skipped → cadence_skip grows (reduced frequency)"
    );
    // Still exactly one degrade event (no duplicate from the skipped tick).
    assert_eq!(w.bus.event_count("auto.degraded"), 1);
}

// SYS-AC-258: a safety-valve breach (max_iterations) transitions the auto run to
// Halted (recoverable; DISTINCT from Completed and Cancelled) and emits
// auto.halted. Mirrors auto-loop safety_valve_halts_on_max_iterations.
#[tokio::test]
async fn sys_ac_258_safety_valve_breach_halts() {
    let sv = SafetyValve {
        max_iterations: Some(1),
        ..Default::default()
    };
    let w = AutoWired::build(WireOpts::default());
    w.driver
        .start("root", criteria_with_safety_valve(sv))
        .await
        .expect("start");

    // close iter-1 → AutoState.iteration = 1 (== max_iterations).
    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("is1");
    w.driver
        .close_iteration(close_ctx("root", 1, Some(0.5), false))
        .await
        .expect("c1");

    // Cadence tick → REAL safety-valve detector → Halted.
    w.driver.on_tick(SchedulerTick::new(1000)).await;
    let status = w.driver.status("root").await;
    assert_eq!(
        status,
        Some(AutoStatus::Halted),
        "max_iterations breach → Halted (distinct from Completed/Cancelled); got {status:?}"
    );
    assert_eq!(
        w.bus.event_count("auto.halted"),
        1,
        "exactly one auto.halted on the real bus"
    );
}

// SYS-AC-257 — FLIPPED (Wave-8 Lane A, PRODUCT-installed sink). On degrade a human-facing
// notification egresses via cap-channel (channel.raw_sent) carrying the degrade reason. The sink
// is installed by the PRODUCTION config-sourcing fn build_auto_loop_driver_with_channel_notify
// (CapChannelNotifySink REPLACING the EventBusNotifySink->auto.notify default), NOT a harness
// .with_notify_sink swap (the adversarial-r6 refutation). The degrade is driven through the
// PRODUCTION registered AutoTickExtension::on_tick (start.rs registers ONLY this extension).
#[tokio::test]
async fn sys_ac_257_degrade_notifies_via_channel_raw_sent() {
    // The cap-channel OUTBOUND egress (real HttpEgress + a recording OkChain for the network
    // executor only) over a RecBus that captures the redacted channel.raw_sent.
    let recbus = Arc::new(RecBus::default());
    let chain = Arc::new(RecordingOkChain::default());
    let egress: Arc<dyn OutboundTransport> =
        Arc::new(HttpEgress::new(chain.clone()).with_event_bus(recbus.clone()));

    // The `channels.notify` config the PRODUCTION build_channel_notify_sink sources the sink from
    // (telegram outbound; non-empty url-template + conversation-id — both fail-closed-guarded).
    let notify_cfg = NotifyChannelConfig {
        adapter: "telegram".to_string(),
        url_template: "https://api.telegram.org/bot123/sendMessage".to_string(),
        conversation_id: "98765".to_string(),
        reply_address: vec![NotifyReplyAddr {
            key: "chat_id".to_string(),
            value: "98765".to_string(),
        }],
    };

    // Build the driver via the PRODUCTION config-sourcing path → CapChannelNotifySink installed
    // (NOT a harness sink swap). owner "agent:owner" is the id build_channel_notify_sink binds the
    // notify subscription to + the egress send ownership-check key (so the send passes).
    let w = AutoWired::build(WireOpts {
        notify_channel: Some((egress, "agent:owner".to_string(), notify_cfg)),
        ..Default::default()
    });
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");

    // Drive a REAL degrade through the PRODUCTION registered extension: 3 consecutive LLM errors
    // ≥ the default limit (3); ext.on_tick → run_settle_pass → run_cadence_pass degrades + notifies
    // (no session registered → the settle/cancel passes are no-ops). This is the live-daemon caller
    // (start.rs:344 registers only the AutoTickExtension), matching the 183/185 tick path.
    w.driver.record_llm_error("root");
    w.driver.record_llm_error("root");
    w.driver.record_llm_error("root");
    let ext = w.auto_tick_extension();
    ext.on_tick(SchedulerTick::new(1_000)).await;

    // The product DECIDED the degrade (not the harness).
    assert_eq!(
        w.driver.status("root").await,
        Some(AutoStatus::Degraded),
        "the product degraded the loop after 3 consecutive LLM errors"
    );
    assert_eq!(
        w.bus.event_count("auto.degraded"),
        1,
        "exactly one auto.degraded (the product degrade decision)"
    );

    // (a) THE seam fired: the human-notify egressed via cap-channel → channel.raw_sent,
    // NOT the placeholder auto.notify (the PRODUCTION install REPLACED EventBusNotifySink).
    assert_eq!(
        recbus.count("channel.raw_sent"),
        1,
        "degrade notification egressed via cap-channel → channel.raw_sent"
    );
    assert_eq!(
        w.bus.event_count("auto.notify"),
        0,
        "the cap-channel sink replaced the EventBusNotifySink placeholder (no auto.notify)"
    );

    // (b) the channel.raw_sent event is REDACTED (adapter + body_bytes only); the
    // reason rides in the actual product-built outbound BODY captured at the chain.
    let bodies = chain.bodies.lock().unwrap();
    assert_eq!(
        bodies.len(),
        1,
        "exactly one outbound notify request reached the chain"
    );
    let body = String::from_utf8_lossy(&bodies[0]);
    assert!(
        body.contains("auto-loop degraded"),
        "the outbound notify body carries the product-computed degrade reason; got: {body}"
    );

    // (c) the redacted event records a non-zero body length (the egress fired).
    assert!(
        recbus.raw_sent_body_bytes().unwrap_or(0) > 0,
        "channel.raw_sent records the outbound body_bytes"
    );
}
