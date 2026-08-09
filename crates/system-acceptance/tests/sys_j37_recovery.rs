//! SYS-J-37 — on startup the runtime scans Suspended runs with missing await
//! sessions, flips them active, and delivers `run.interrupted` to the controller.
//! Chain: MODULE-008 run-manager → MODULE-006 messaging → MODULE-019 observability.
//!
//! Witnessed test-local against the REAL `advance_run_manager` crash-recovery walk
//! (`recover_on_startup` / `recover_from_disk` / `cold_start_recovery`) with a real
//! `EventBusEmit` sink. The ONLY mock is `DeadSession` — a `AwaitSessionRef` whose
//! `exists()` returns false: this simulates the absent-M007 await session (the crash
//! precondition itself), analogous to the external-LLM loopback, not a chain mock.
//!
//! SYS-AC-121 (the controller agent receives a `Message::RunInterrupted` in its mailbox
//! and its handle-message runs after recovery) is WITNESSED below on the real wired SUT
//! (`sys_ac_121_*`). Wave-12 landed the bridge — `ControlMessage::RunInterrupted` +
//! `Message::run_interrupted` + the `RunInterruptSink` DI port / `MailboxRunInterruptSink`
//! + the `recover_on_startup` sink call — so the prior "no such variant / no bridge"
//! deferral is closed. The witness drives REAL `recover_on_startup` over the production
//! `MailboxRunInterruptSink` into the SUT's REAL shared `MailboxStore`, then a REAL
//! `run_turn` so the guest's handle-message runs on the product-delivered control message.

#[path = "h_loopback/mod.rs"]
mod h_loopback;
use h_loopback::CapturingBus;

use std::sync::Arc;

use advance_messaging::MailboxRunInterruptSink;
use advance_run_manager::{RunConfig, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::mailbox::{ControlMessage, MessageKind};
use advance_shared_types::run::TaskRunStatus;
use async_trait::async_trait;
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

const AGENT: &str = "agent:harness";

/// The committed reference guest: its `handle-message` reads `msg.payload` as the prompt
/// and dials `agent-llm/generate` — so a product-delivered `Message::RunInterrupted`
/// (payload = the `ControlMessage` JSON) surfaces verbatim in the loopback request body.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

/// The absent-M007 await session: a crashed/lost session that no longer exists.
/// `exists()==false` is the recovery walk's trigger; `walk_tree`/`close` are
/// required for object-safety but never exercised here.
struct DeadSession;

#[async_trait]
impl AwaitSessionRef for DeadSession {
    fn exists(&self, _session_id: &SessionId) -> bool {
        false
    }
    fn walk_tree(&self, _session_id: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(
        &self,
        _session_id: &SessionId,
        _reason: &str,
    ) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

/// SYS-AC-119: on startup with a Suspended run whose await session no longer exists,
/// the run's run-status returns active (flipped from suspended).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_119_suspended_run_flips_active_on_recovery() {
    let bus = Arc::new(CapturingBus::new());
    let rm = RunManager::new(bus);
    let run_id = rm
        .ensure_run("task-h-119", AGENT, RunConfig::default())
        .expect("ensure_run");
    // Active → Suspended with a root_await session id.
    rm.suspend_run(&run_id, "sess-119").expect("suspend_run");
    assert_eq!(
        rm.run_status(&run_id).expect("run_status").status,
        TaskRunStatus::Suspended,
        "precondition: run is Suspended"
    );

    let report = rm.recover_on_startup(Arc::new(DeadSession)).await;
    assert_eq!(report.suspended_scanned, 1);

    assert_eq!(
        rm.run_status(&run_id).expect("run_status").status,
        TaskRunStatus::Active,
        "recovery flipped Suspended → Active"
    );
}

/// SYS-AC-120: a `run.interrupted` event is emitted for each recovered run.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_120_recovery_emits_run_interrupted() {
    let bus = Arc::new(CapturingBus::new());
    let rm = RunManager::new(bus.clone());
    let run_id = rm
        .ensure_run("task-h-120", AGENT, RunConfig::default())
        .expect("ensure_run");
    rm.suspend_run(&run_id, "sess-120").expect("suspend_run");

    let report = rm.recover_on_startup(Arc::new(DeadSession)).await;
    assert_eq!(report.interrupted_emitted, 1, "one run recovered");

    let interrupted = bus.events_named("run.interrupted");
    assert_eq!(interrupted.len(), 1, "exactly one run.interrupted emitted");
    assert_eq!(
        interrupted[0].run_id.as_deref(),
        Some(run_id.to_string().as_str()),
        "the event references the recovered run"
    );
}

/// SYS-AC-226: a second runtime restart after recovery does NOT re-emit
/// `run.interrupted` — the Suspended→Active flip + cleared root_await are persisted
/// to disk BEFORE the first emit, so a re-scan recovers it zero further times.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_226_no_reemit_on_second_restart() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let state_dir = dir.path().to_path_buf();

    // ── Restart #1: manager A creates+suspends (persists Suspended), then recovers.
    let bus_a = Arc::new(CapturingBus::new());
    let a = Arc::new(RunManager::new(bus_a.clone()).with_state_dir(state_dir.clone()));
    let run_id = a
        .ensure_run("task-h-226", AGENT, RunConfig::default())
        .expect("ensure_run");
    a.suspend_run(&run_id, "sess-226").expect("suspend_run");

    let report_a = a
        .cold_start_recovery(Arc::new(DeadSession))
        .await
        .expect("cold_start_recovery A");
    // A's run is in its in-memory store, so recover_from_disk SKIPS it (disk_loaded==0);
    // the flip is the in-memory walk, which persists Active before emit.
    assert_eq!(
        report_a.disk_loaded, 0,
        "A's run was already in-memory (disk row skipped)"
    );
    assert_eq!(report_a.interrupted_emitted, 1, "A recovered the run once");
    assert_eq!(bus_a.count("run.interrupted"), 1);
    drop(a);

    // ── Restart #2: a FRESH manager B over the SAME state_dir.
    let bus_b = Arc::new(CapturingBus::new());
    let b = Arc::new(RunManager::new(bus_b.clone()).with_state_dir(state_dir.clone()));
    let report_b = b
        .cold_start_recovery(Arc::new(DeadSession))
        .await
        .expect("cold_start_recovery B");
    // B loads the now-Active row from disk; the recovery walk finds zero Suspended
    // candidates → no further run.interrupted.
    assert_eq!(report_b.disk_loaded, 1, "B loaded the persisted Active row");
    assert_eq!(
        report_b.suspended_scanned, 0,
        "no Suspended candidate on re-scan"
    );
    assert_eq!(
        report_b.interrupted_emitted, 0,
        "no re-emit on the second restart"
    );
    assert_eq!(bus_b.count("run.interrupted"), 0);
}

/// Build a real wired SUT (loopback LLM), wire the PRODUCTION `MailboxRunInterruptSink`
/// over the SUT's REAL shared `MailboxStore`, suspend a run via the PUBLIC `suspend_run`,
/// and drive REAL `recover_on_startup`. Returns the SUT + the product-synthesized run_id.
/// Delivery is product-driven (the recovery walk calls the sink); the ONLY doubles are the
/// loopback LLM + `DeadSession` (the crash precondition — mirroring passed 119/120/226).
///
/// WITNESS-FLOOR SCOPE (honest, explicit): this proves the SYS-AC-121 *criterion* — a
/// `Message::RunInterrupted` is delivered into the controller mailbox and handle-message runs
/// on it — on the SAME SYS-J-37 harness floor as the passed 119/120/226 (the harness
/// constructs the real `RunManager` + drives the real `recover_on_startup`; `advance start`
/// boot-driven recovery is not part of this journey's witness floor). Keying is consistent by
/// construction: `sut.agent_id()` is BOTH the run's `controller_agent` (the sink delivers to
/// it verbatim) AND the agent-loop recv id — closing the `run_interrupt_sink.rs` bare/colon
/// orphan-mailbox caveat for the witnessed path. The production `advance start` boot-install
/// of recover_on_startup+sink AND the production bare/colon controller-key reconciliation
/// remain a tracked product follow-up (MODULE-008 §3.6) — which is why REQ-048 stays
/// **Partial**, NOT Verified (see SYSTEM-ACCEPTANCE.md §3/§4).
async fn build_sut_and_recover() -> (SystemUnderTest, String) {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "recovered-turn-reply",
            5,
            7,
        )]))
        .build(HELLO_LLM_CORE)
        .await;
    let controller = sut.agent_id().to_string(); // "agent:harness" — the loop's recv key

    let bus = Arc::new(CapturingBus::new());
    let sink = Arc::new(MailboxRunInterruptSink::new(sut.mailbox_store()));
    let rm = RunManager::new(bus.clone()).with_run_interrupt_sink(sink);

    let run_id = rm
        .ensure_run("task-121", &controller, RunConfig::default())
        .expect("ensure_run");
    rm.suspend_run(&run_id, "sess-121").expect("suspend_run");
    assert_eq!(
        rm.run_status(&run_id).expect("run_status").status,
        TaskRunStatus::Suspended,
        "precondition: run is Suspended"
    );

    // PRODUCT recovery: flips Active + emits run.interrupted + delivers via the sink.
    let report = rm.recover_on_startup(Arc::new(DeadSession)).await;
    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(
        report.interrupted_emitted, 1,
        "recovery recovered + emitted + delivered"
    );
    assert_eq!(
        bus.count("run.interrupted"),
        1,
        "exactly one run.interrupted emitted"
    );
    (sut, run_id.to_string())
}

/// SYS-AC-121 (delivery): the product recovery path delivers exactly one
/// `Message::RunInterrupted` (kind=Control, from=system, to=controller) into the
/// controller's mailbox — decoded on the ACTUAL delivered message (no harness inject).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_121_recovery_delivers_run_interrupted_to_controller_mailbox() {
    let (sut, run_id) = build_sut_and_recover().await;
    let controller = sut.agent_id().to_string();

    let mb = sut
        .mailbox_store()
        .get(&controller)
        .expect("recovery+sink created the controller mailbox");
    assert_eq!(
        mb.depth(),
        1,
        "exactly one product-delivered message (no harness inject)"
    );

    // Decode the ACTUAL delivered message (non-circular — the recovery walk built it).
    let msg = mb.recv().await;
    assert_eq!(
        msg.kind,
        MessageKind::Control,
        "RunInterrupted is a Control message"
    );
    assert_eq!(
        msg.to, controller,
        "delivered to the controller's mailbox key"
    );
    assert_eq!(msg.from, "system", "host-originated control message");
    let decoded: ControlMessage =
        serde_json::from_slice(&msg.payload).expect("payload decodes as ControlMessage");
    match decoded {
        ControlMessage::RunInterrupted {
            run_id: rid,
            reason,
        } => {
            assert_eq!(rid, run_id, "the product-synthesized run_id is propagated");
            assert_eq!(reason, "crash-recovery");
        }
    }
}

/// SYS-AC-121 (handle-message runs): a REAL `run_turn` over the recovery-delivered store
/// pops the `Message::RunInterrupted` and runs the guest's handle-message ON it — the guest
/// reads `msg.payload` (the ControlMessage JSON) as the prompt → real cap-llm `generate` →
/// loopback. Anti-fake-green (adversarial-r10 hardened): handle-message running is proven by
/// exactly one recorded generate call (the guest is its sole caller); and to isolate the
/// guest's read from the assembler's side channel (the assembler also folds `msg.payload`
/// into its PREPENDED context), the assertion targets the FINAL message of the chat request —
/// the guest's own generate prompt — and requires IT to carry the product-synthesized run_id +
/// discriminant + reason. A guest that ignored `msg.payload` (e.g. sent the default prompt)
/// would fail this, so it genuinely proves handle-message ran on the RunInterrupted content.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_121_handle_message_runs_on_recovery_delivered_run_interrupted() {
    let (sut, run_id) = build_sut_and_recover().await;
    let controller = sut.agent_id().to_string();

    // Exactly one product-delivered message awaits the turn (no harness inject).
    assert_eq!(
        sut.mailbox_store()
            .get(&controller)
            .map(|m| m.depth())
            .unwrap_or(0),
        1,
        "one product-delivered message before the turn"
    );

    // Drive the REAL wired turn: run_agent pops the RunInterrupted → guest handle-message.
    sut.run_turn().await;

    assert_eq!(
        sut.mailbox_store()
            .get(&controller)
            .map(|m| m.depth())
            .unwrap_or(0),
        0,
        "the agent loop drained the RunInterrupted from the mailbox"
    );

    // The guest's handle-message is the SOLE caller of `agent-llm/generate`, so a recorded
    // chat request proves handle-message RAN; exactly one call (no extra/zero) confirms the
    // single recovery turn.
    assert_eq!(
        sut.llm_chat_request_count(),
        1,
        "the guest's handle-message dialed generate exactly once on the recovery turn"
    );
    let body = sut
        .llm_last_chat_request_body()
        .expect("the guest dialed generate on the recovery-delivered message");

    // Anti-side-channel (adversarial r10): the assembler also folds `msg.payload` into its
    // prepended context, so a raw `body.contains(run_id)` could be satisfied by the assembler
    // alone. Isolate the GUEST's contribution — the generate seam PREPENDS the assembled
    // context, so the guest's own prompt is the FINAL message. Assert THAT message carries the
    // RunInterrupted payload: this fails if the guest ignored `msg.payload` (e.g. sent the
    // default prompt), proving handle-message ran ON the RunInterrupted content, not merely
    // that the body mentions the run_id via the assembler's side channel.
    let body_json: serde_json::Value =
        serde_json::from_str(&body).expect("the recorded chat request body is JSON");
    let messages = body_json["messages"]
        .as_array()
        .expect("OpenAI chat request carries a messages array");
    let guest_prompt = messages
        .last()
        .and_then(|m| m["content"].as_str())
        .expect("the final (guest-prompt) message has string content");
    assert!(
        guest_prompt.contains("RunInterrupted")
            && guest_prompt.contains("crash-recovery")
            && guest_prompt.contains(&run_id),
        "the guest's generate prompt (final message) IS the RunInterrupted payload (run_id \
         {run_id} + discriminant + reason) — handle-message read msg.payload, not the \
         assembler side channel: guest_prompt = {guest_prompt}"
    );

    // Corroborating coarse check (the message content reached the LLM at all).
    assert!(
        body.contains(&run_id),
        "body carries the run_id {run_id}: {body}"
    );
}
