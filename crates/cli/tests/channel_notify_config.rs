//! SLICE 2 — `channels.notify` config-sourced `CapChannelNotifySink` install (257).
//!
//! PRODUCT witnesses for the cli notify-config sourcing + the PRODUCTION install path
//! (`build_channel_notify_sink` + `build_auto_loop_driver_with_channel_notify` /
//! `install_notify_sink`). These flip **ZERO SYS-AC** — the SYS-AC-257 e2e witness
//! (`sys_j62_auto_degrade_halt.rs`, real outbound sub + real `HttpSecurityChain` pass on
//! a wired daemon) stays `#[ignore]`d until the harvest. The key difference from the
//! existing `channel_notify_sink.rs` tests: here the sink is installed by the PRODUCTION
//! `build_auto_loop_driver_with_channel_notify` from a `NotifyChannelConfig` (NOT a
//! harness `.with_notify_sink` swap), so the degrade → `channel.raw_sent` path is
//! production-driven (the witness-floor for the 257 harvest). The security chain is an
//! `OkChain` double — legitimate product-unit-testing of the config → sink → emit path.

use std::path::Path;
use std::sync::{Arc, Mutex};

use advance_cli::auto_wiring::{build_auto_loop_driver_with_channel_notify, install_notify_sink};
use advance_cli::channel_notify_sink::build_channel_notify_sink;
use advance_runtime::config::{NotifyChannelConfig, NotifyReplyAddr};
use advance_scheduler_auto_loop::{
    AutoLoopDriver, AutoLoopError, DefaultAutoLoopDriver, IterationCheckpoint, IterationRollback,
    NoopNotifySink, NotifySink,
};
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use cap_channel::{HttpEgress, OutboundTransport};

// ── doubles ──────────────────────────────────────────────────────────────────

/// A security chain that always passes (200) — mirrors cap-channel's `egress::tests::OkChain`.
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

fn egress(bus: Arc<RecBus>) -> Arc<dyn OutboundTransport> {
    Arc::new(HttpEgress::new(Arc::new(OkChain)).with_event_bus(bus))
}

fn notify_cfg(adapter: &str) -> NotifyChannelConfig {
    NotifyChannelConfig {
        adapter: adapter.to_string(),
        url_template: "https://api.telegram.org/bot123/sendMessage".to_string(),
        conversation_id: "98765".to_string(),
        reply_address: vec![NotifyReplyAddr {
            key: "chat_id".to_string(),
            value: "98765".to_string(),
        }],
    }
}

/// Minimal primary-only success criteria (re-built locally; no per-iteration budget,
/// no safety valve → `run_cadence_pass` uses defaults).
fn primary_criteria() -> advance_scheduler_auto_loop::config::SuccessCriteria {
    use advance_scheduler_auto_loop::config::{
        MetricSource, Objective, Op, Predicate, Role, SuccessCriteria,
    };
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

fn init_repo(dir: &Path) {
    let repo = git2::Repository::init(dir).unwrap();
    let mut cfg = repo.config().unwrap();
    cfg.set_str("user.name", "t").unwrap();
    cfg.set_str("user.email", "t@example.com").unwrap();
    let sig = git2::Signature::now("t", "t@example.com").unwrap();
    let tree_id = repo.index().unwrap().write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
        .unwrap();
}

// ── T-NC-2a — config → sink → channel.raw_sent ───────────────────────────────
#[tokio::test]
async fn build_channel_notify_sink_from_config_emits_raw_sent() {
    let bus = Arc::new(RecBus::default());
    let sink =
        build_channel_notify_sink(egress(bus.clone()), "agent:owner", &notify_cfg("telegram"))
            .expect("telegram notify config builds a sink");

    sink.notify("root", "auto-loop halted: max_iterations")
        .await
        .expect("notify ok");

    assert_eq!(
        bus.count("channel.raw_sent"),
        1,
        "exactly one channel.raw_sent"
    );
    assert_eq!(bus.raw_sent_adapter().as_deref(), Some("telegram"));
}

// ── T-NC-2b — unsupported adapter rejected loudly ────────────────────────────
#[tokio::test]
async fn build_channel_notify_sink_rejects_non_telegram() {
    let bus = Arc::new(RecBus::default());
    // `CapChannelNotifySink` is not `Debug`, so destructure rather than `expect_err`.
    let Err(err) = build_channel_notify_sink(egress(bus), "agent:owner", &notify_cfg("slack"))
    else {
        panic!("non-telegram adapter must be rejected");
    };
    assert!(err.contains("not a supported"), "{err}");
}

// ── T-NC-2c — empty / whitespace / NUL conversation_id rejected (Wave-7 Lane B) ──
// An empty conversation_id would hit the Telegram renderer's raw-passthrough fallback
// and still egress (→ channel.raw_sent) to an UNDETERMINED target — a misdelivered
// notify that masquerades as a passing 257 witness. Reject loudly at build time.
#[tokio::test]
async fn build_channel_notify_sink_rejects_empty_conversation_id() {
    let bus = Arc::new(RecBus::default());

    let mut empty = notify_cfg("telegram");
    empty.conversation_id = String::new();
    let Err(err) = build_channel_notify_sink(egress(bus.clone()), "agent:owner", &empty) else {
        panic!("empty conversation_id must be rejected");
    };
    assert!(err.contains("conversation_id"), "{err}");

    let mut whitespace = notify_cfg("telegram");
    whitespace.conversation_id = "   ".to_string();
    assert!(
        build_channel_notify_sink(egress(bus.clone()), "agent:owner", &whitespace).is_err(),
        "whitespace-only conversation_id must be rejected"
    );

    let mut nul = notify_cfg("telegram");
    nul.conversation_id = "9\08".to_string();
    assert!(
        build_channel_notify_sink(egress(bus), "agent:owner", &nul).is_err(),
        "NUL in conversation_id must be rejected"
    );
}

// ── T-NC-3 — PRODUCTION install path: build_auto_loop_driver_with_channel_notify ─
// Proves the cap-channel notify sink is installed by PRODUCTION code (from config),
// REPLACING the EventBusNotifySink → auto.notify default: degrade egresses
// channel.raw_sent, NOT auto.notify. Same RecBus backs both the build event_bus AND
// the egress transport so both event classes are observable on one bus.
#[tokio::test]
async fn production_install_replaces_eventbus_notify_with_cap_channel() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let bus = Arc::new(RecBus::default());

    let driver = build_auto_loop_driver_with_channel_notify(
        tmp.path(),
        bus.clone() as Arc<dyn EventBusEmit>,
        egress(bus.clone()),
        "agent:owner",
        &notify_cfg("telegram"),
    )
    .expect("install ok")
    .expect("git workspace → Some(driver)");

    driver
        .start("root", primary_criteria())
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
        "degrade notify egressed via the config-installed cap-channel sink"
    );
    assert_eq!(
        bus.count("auto.notify"),
        0,
        "the EventBusNotifySink → auto.notify default was REPLACED (no auto.notify)"
    );
}

// ── T-NC-3b — non-git workspace degrades to Ok(None) ─────────────────────────
#[test]
fn build_with_channel_notify_none_on_non_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let bus = Arc::new(RecBus::default());
    let res = build_auto_loop_driver_with_channel_notify(
        tmp.path(),
        bus.clone() as Arc<dyn EventBusEmit>,
        egress(bus),
        "agent:owner",
        &notify_cfg("telegram"),
    )
    .expect("non-repo is Ok(None), not Err");
    assert!(
        res.is_none(),
        "non-git workspace → Ok(None) (degrade, like build_auto_loop_driver)"
    );
}

// ── T-NC-3c — invalid notify config fails CLOSED even on a non-git workspace ──
// Audit r6 (Codex W): a malformed channels.notify config must Err at boot REGARDLESS of
// whether auto mode is available — not be silently ignored on a non-repo (where the old
// git-check-first ordering returned Ok(None) before validating, a silent-misconfig).
#[test]
fn build_with_channel_notify_invalid_config_errs_even_on_non_repo() {
    let tmp = tempfile::tempdir().unwrap(); // NOT a git repo
    let bus = Arc::new(RecBus::default());
    let mut bad = notify_cfg("telegram");
    bad.conversation_id = String::new(); // invalid → must Err before the git degrade
    let Err(err) = build_auto_loop_driver_with_channel_notify(
        tmp.path(),
        bus.clone() as Arc<dyn EventBusEmit>,
        egress(bus),
        "agent:owner",
        &bad,
    ) else {
        panic!("invalid notify config must Err even on a non-git workspace, not Ok(None)");
    };
    assert!(err.contains("conversation_id"), "{err}");
}

// ── T-NC-4 — install_notify_sink errs on a SHARED Arc (augment-before-share) ──
#[test]
fn install_notify_sink_errs_on_shared_arc() {
    let driver = Arc::new(DefaultAutoLoopDriver::new(
        Arc::new(NoopCkpt),
        Arc::new(NoopRb),
    ));
    let _shared = Arc::clone(&driver); // refcount 2 → not unique
    let sink: Arc<dyn NotifySink> = Arc::new(NoopNotifySink);
    // `Arc<DefaultAutoLoopDriver>` is not `Debug`, so destructure rather than `expect_err`.
    let Err(err) = install_notify_sink(driver, sink) else {
        panic!("a shared driver Arc must reject the try_unwrap augment");
    };
    assert!(err.contains("already shared"), "{err}");
}
