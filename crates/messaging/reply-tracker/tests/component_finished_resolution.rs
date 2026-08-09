//! MODULE-007-AC-19 witness (Wave-19 Lane 3 / slice m007-G) — ComponentFinished
//! await-slot resolution via the CONTRACT-184 `RunCompletionSink` push-sink.
//!
//! Faithful to MODULE-007 §2.3: on `run.completed` (driven by the production
//! `RunManager::complete_run` → `ComponentResolutionSink`), the matching
//! `ComponentFinished` slot is marked `reply-status::completed` **STATUS-ONLY
//! with an EMPTY payload** — the component output is NOT delivered through the
//! AwaitSession; the caller reads `output-dir/result.bin` directly (the
//! `caller_reads_result_bin_from_output_dir` leg). The witness drives the REAL
//! cross-module path (drive-prod-fn): a real `AwaitSessionManagerImpl` parks a
//! real `await-replies` `start()`, a real `RunManager.with_run_completion_sink`
//! fires the sink from `complete_run`, and the parked future resolves.
//!
//! **Test-role breakdown** — AC-19's criterion spans three legs:
//! spawn-from-template (covered separately by M005-AC-20), run.completed→sink
//! resolution, and caller `output-dir/result.bin` read. This file covers the latter
//! two legs only; it is NOT a production component-driver e2e witness.
//! - The M007 resolution leg is driven by 5 tests:
//!   `resolves_status_via_run_completed_sink` + `anti_fake_green_…` (the two real
//!   `complete_run`→sink integration drivers); `resolve_component_finished_direct`
//!   + `allof_mixed_…` (direct inherent-method drivers); `non_matching_…`
//!   (negative — no spurious resolution). Two additional tests cover Wave-24
//!   payload-integrity and colon-short-circuit hardening.
//! - `caller_reads_result_bin_from_output_dir` covers ONLY the caller/M002-layer
//!   read leg. It exercises NO M007 code by design (M007 is status-only; the read is
//!   the caller's job) and does not bridge the missing production driver.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::Mutex;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, ComponentAwaitRequest, ReplyResult,
    ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::traits::EventBusEmit;

use advance_reply_tracker::{
    AwaitSessionManager, AwaitSessionManagerImpl, ComponentResolutionSink, ManagerOptions,
};
use advance_run_manager::{RunConfig, RunManager};
use advance_scheduler::{write_result_to_dir, RunResult, RunStatus};

// ── Minimal no-op test doubles ──────────────────────────────────────────

/// No-op event bus (the resolution path emits nothing relevant here).
struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

/// Minimal dispatcher: records nothing, every `deliver` succeeds (the agent
/// slot in `allof_mixed` needs an Ok deliver; ComponentFinished slots never
/// dispatch).
#[derive(Default)]
struct OkDispatcher {
    delivered: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl MailboxDispatcher for OkDispatcher {
    async fn deliver(&self, target: &str, _msg: Message) -> Result<(), MsgError> {
        self.delivered.lock().await.push(target.to_string());
        Ok(())
    }
    async fn reply(
        &self,
        _from: &str,
        _to_message_id: &str,
        _payload: Vec<u8>,
    ) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _from: &str,
        _target: &str,
        _payload: Vec<u8>,
        _context: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

fn mk_manager() -> Arc<AwaitSessionManagerImpl> {
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(OkDispatcher::default());
    Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ))
}

/// Build a real `RunManager` wired with the production `ComponentResolutionSink`
/// over `manager` (the same integration seam now composed at the CLI root; this
/// local construction is not a production component-driver witness).
fn mk_run_manager(manager: &Arc<AwaitSessionManagerImpl>) -> RunManager {
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let sink = Arc::new(ComponentResolutionSink::new(Arc::clone(manager)));
    RunManager::new(bus).with_run_completion_sink(sink)
}

fn component_req(component_id: &str) -> AwaitRequest {
    AwaitRequest::ComponentFinished(ComponentAwaitRequest {
        component_id: component_id.to_string(),
        correlation_id: format!("corr-{component_id}"),
    })
}

fn agent_req(target: &str, correlation_id: &str) -> AwaitRequest {
    // correlation_id must be a safe opaque id (no colon) — distinct from the
    // colon-bearing agent `target`.
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![9],
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

fn allof() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: None,
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

/// Deterministically wait until `start()` has REGISTERED its session (the
/// `sessions.insert` happens immediately before the `rx.await` park), proving
/// the await is genuinely parked — a real signal, NOT a wall-clock sleep (so the
/// park-before-complete ordering is not timing-dependent / flake-prone). Mirrors
/// the established `send_ingress.rs::wait_for_session_count` helper.
async fn wait_until_parked(manager: &AwaitSessionManagerImpl, expected: usize) {
    for _ in 0..2000 {
        if manager.session_count_for_test().await == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "wait_until_parked: expected {expected} registered session(s), got {}",
        manager.session_count_for_test().await
    );
}

/// Let any spawned resolution task run to completion deterministically by
/// draining the cooperative scheduler. Used for NEGATIVE checks (proving a
/// non-matching completion resolved NOTHING) — corroborated by the direct
/// `resolve_component_finished_direct` no-match→None assertion.
async fn settle(iters: usize) {
    for _ in 0..iters {
        tokio::task::yield_now().await;
    }
}

// ── T-G1: full path — complete_run → sink → status-only resolution ──────

#[tokio::test(flavor = "current_thread")]
async fn resolves_status_via_run_completed_sink() {
    let manager = mk_manager();
    let rm = mk_run_manager(&manager);

    // Park a real await with a single ComponentFinished slot.
    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start("controller", vec![component_req("comp-1")], allof())
            .await
    });

    // Deterministically wait for the session to be registered (= parked).
    wait_until_parked(&manager, 1).await;
    assert!(
        !start_handle.is_finished(),
        "await must be parked before the run completes"
    );

    // Run the component (task_id == component_id) and complete it. complete_run
    // fires the CONTRACT-184 sink → resolve_component_finished → on_reply.
    let run_id = rm
        .ensure_run("comp-1", "comp-1", RunConfig::default())
        .expect("ensure_run");
    rm.complete_run(&run_id, "done".to_string())
        .expect("complete_run");

    let result = tokio::time::timeout(Duration::from_secs(5), start_handle)
        .await
        .expect("await resolved within 5s")
        .expect("start task did not panic")
        .expect("start returned Ok(AwaitResult)");

    assert_eq!(result.replies.len(), 1, "one slot");
    let r = &result.replies[0];
    assert_eq!(r.source, "component:comp-1", "source = component:{{id}}");
    assert_eq!(r.status, ReplyStatus::Completed, "marked completed");
    assert!(
        r.payload.is_empty(),
        "STATUS-ONLY per §2.3 — payload MUST be empty (caller reads result.bin), got {} bytes",
        r.payload.len()
    );
}

// ── T-G2: §2.3 caller-read leg — result.bin readable from output-dir ────

#[tokio::test(flavor = "current_thread")]
async fn caller_reads_result_bin_from_output_dir() {
    // The component's run writes its output to output-dir/result.bin via the
    // real production writer; the CALLER (here, the test acting as the parent
    // per §2.3 pt 3) reads it back — decoupled from M007's resolution.
    let dir = tempfile::tempdir().expect("tempdir");
    let result = RunResult {
        status: RunStatus::Completed,
        output: Some(b"SENTINEL-RESULT".to_vec()),
    };
    write_result_to_dir(dir.path(), &result)
        .await
        .expect("write_result_to_dir");

    let bytes = tokio::fs::read(dir.path().join("result.bin"))
        .await
        .expect("caller reads result.bin");
    assert_eq!(
        bytes, b"SENTINEL-RESULT",
        "caller reads the component's output bytes"
    );
}

// ── T-G3: anti-fake-green — genuinely parked, only the sink resolves it ──

#[tokio::test(flavor = "current_thread")]
async fn anti_fake_green_genuinely_parked_then_resolved() {
    let manager = mk_manager();
    let rm = mk_run_manager(&manager);

    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start("controller", vec![component_req("comp-x")], allof())
            .await
    });

    // Probe BEFORE completion: the session is registered (start() committed to
    // the park) AND the future is genuinely pending (not pre-resolved) — a
    // deterministic discriminator, not a wall-clock guess.
    wait_until_parked(&manager, 1).await;
    assert!(
        !start_handle.is_finished(),
        "discriminator: the await is genuinely PARKED before run.completed (not fake-green pre-resolution)"
    );

    let run_id = rm
        .ensure_run("comp-x", "comp-x", RunConfig::default())
        .expect("ensure_run");
    rm.complete_run(&run_id, "ok".to_string())
        .expect("complete_run");

    // Only now does it resolve — proving the sink path drove it.
    let result = tokio::time::timeout(Duration::from_secs(5), start_handle)
        .await
        .expect("resolved after the sink fired")
        .expect("no panic")
        .expect("Ok(AwaitResult)");
    assert_eq!(result.replies[0].source, "component:comp-x");
    assert_eq!(result.replies[0].status, ReplyStatus::Completed);
}

// ── T-G4: non-matching component_id resolves nothing (no leakage) ───────

#[tokio::test(flavor = "current_thread")]
async fn non_matching_component_id_no_resolution() {
    let manager = mk_manager();
    let rm = mk_run_manager(&manager);

    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start("controller", vec![component_req("comp-1")], allof())
            .await
    });
    wait_until_parked(&manager, 1).await;

    // A DIFFERENT component's run completes — must NOT resolve comp-1's slot.
    let run_id = rm
        .ensure_run("other-component", "other-component", RunConfig::default())
        .expect("ensure_run");
    rm.complete_run(&run_id, "done".to_string())
        .expect("complete_run");

    // Drain the scheduler so the spawned (non-matching) resolve runs to its
    // no-op; the slot must remain unresolved (corroborated by the direct
    // no-match→None assertion in resolve_component_finished_direct).
    settle(64).await;
    assert!(
        !start_handle.is_finished(),
        "a non-matching run must NOT resolve comp-1's slot (no cross-session leakage)"
    );
    assert_eq!(
        manager.session_count_for_test().await,
        1,
        "session still parked"
    );

    // Clean up: resolve it for real, then drain the task.
    let sid = manager
        .resolve_component_finished("comp-1", "done")
        .await
        .expect("now matches comp-1");
    assert!(!sid.0.is_empty());
    let result = tokio::time::timeout(Duration::from_secs(5), start_handle)
        .await
        .expect("resolved after the real match")
        .expect("no panic")
        .expect("Ok");
    assert_eq!(result.replies[0].source, "component:comp-1");
}

// ── T-G5: AllOf composes the component path with the agent on_reply path ─

#[tokio::test(flavor = "current_thread")]
async fn allof_mixed_agent_and_component_slot() {
    let manager = mk_manager();

    // AllOf: slot 0 = ComponentFinished, slot 1 = AgentRequest. Both must
    // resolve for is_complete().
    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start(
            "controller",
            vec![
                component_req("comp-1"),
                agent_req("agent:child", "corr-child"),
            ],
            allof(),
        )
        .await
    });
    wait_until_parked(&manager, 1).await;
    assert!(
        !start_handle.is_finished(),
        "parked until BOTH slots resolve"
    );

    // Resolve the component slot (slot 0) via the M007 resolver → returns the sid.
    let sid = manager
        .resolve_component_finished("comp-1", "done")
        .await
        .expect("component slot matched");

    // Still parked — the agent slot (slot 1) is pending (session NOT removed).
    settle(32).await;
    assert!(
        !start_handle.is_finished(),
        "AllOf: still parked after only the component slot resolved"
    );
    assert_eq!(
        manager.session_count_for_test().await,
        1,
        "session still open"
    );

    // Resolve the agent slot (slot 1) via the existing on_reply path.
    manager
        .on_reply(
            &sid,
            1,
            ReplyResult {
                slot: 1,
                source: "agent:child".to_string(),
                payload: vec![7, 7],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("agent on_reply");

    let result = tokio::time::timeout(Duration::from_secs(5), start_handle)
        .await
        .expect("resolved once both slots done")
        .expect("no panic")
        .expect("Ok");
    assert_eq!(result.replies.len(), 2);
    let comp = result
        .replies
        .iter()
        .find(|r| r.source == "component:comp-1")
        .expect("component reply");
    let agent = result
        .replies
        .iter()
        .find(|r| r.source == "agent:child")
        .expect("agent reply");
    assert!(
        comp.payload.is_empty(),
        "component slot status-only (empty payload)"
    );
    assert_eq!(
        agent.payload,
        vec![7, 7],
        "agent slot carries its reply payload"
    );
}

// ── T-G6: resolve_component_finished direct unit (match + no-match) ──────

#[tokio::test(flavor = "current_thread")]
async fn resolve_component_finished_direct() {
    let manager = mk_manager();

    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start("controller", vec![component_req("comp-1")], allof())
            .await
    });
    wait_until_parked(&manager, 1).await;

    // No-match → None (no open slot for "nope").
    assert!(
        manager
            .resolve_component_finished("nope", "done")
            .await
            .is_none(),
        "no matching open ComponentFinished slot → None"
    );
    assert!(!start_handle.is_finished(), "still parked after a no-match");

    // Match → Some(sid), slot resolved Completed/empty.
    let sid = manager
        .resolve_component_finished("comp-1", "done")
        .await
        .expect("matched comp-1");
    assert!(!sid.0.is_empty());

    let result = tokio::time::timeout(Duration::from_secs(5), start_handle)
        .await
        .expect("resolved")
        .expect("no panic")
        .expect("Ok");
    assert_eq!(result.replies[0].source, "component:comp-1");
    assert_eq!(result.replies[0].status, ReplyStatus::Completed);
    assert!(result.replies[0].payload.is_empty());
}

// ── T3 (Wave-24 req270-sink): on_reply INTEGRITY empty-payload guard ────
// §2.3 makes a ComponentFinished reply STATUS-ONLY (empty payload). A direct
// on_reply caller could forge `source == component:{id}` (passing the source-match)
// WITH a payload; the empty-payload guard must reject it. The legit resolver sends
// empty, so the happy path (T-G1/T-G6) is untouched.
#[tokio::test(flavor = "current_thread")]
async fn on_reply_rejects_nonempty_payload_for_component_slot() {
    let manager = mk_manager();

    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start("controller", vec![component_req("comp-1")], allof())
            .await
    });
    wait_until_parked(&manager, 1).await;

    let sid = manager.first_open_session_id_for_test().await;
    // Forge a ComponentFinished reply WITH a payload. `source == component:comp-1`
    // passes the source-match, so the REJECTION comes from the new empty-payload
    // guard (not the source check).
    let err = manager
        .on_reply(
            &sid,
            0,
            ReplyResult {
                slot: 0,
                source: "component:comp-1".to_string(),
                payload: vec![1, 2, 3],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect_err("non-empty payload for a ComponentFinished slot must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("status-only"),
        "rejection reason must name the status-only invariant, got: {msg}"
    );
    assert!(
        !start_handle.is_finished(),
        "the rejected reply must NOT resolve the slot"
    );

    // Clean up: resolve it for real (empty payload) so the spawned start task ends.
    let _ = manager.resolve_component_finished("comp-1", "done").await;
    let _ = tokio::time::timeout(Duration::from_secs(5), start_handle).await;
}

// ── T5 (Wave-24 req270-sink): colon short-circuit witnessed by the attempt counter ─
// `ComponentResolutionSink::on_run_completed` skips the spawn when `task_id` has a
// `:` (a component_id is colon-free, so a colon task_id can never join). The
// resolve-attempt counter distinguishes a short-circuited completion (0 entries)
// from a colon-free non-match that genuinely spawns + enters the resolver (1).
#[tokio::test(flavor = "current_thread")]
async fn colon_task_id_short_circuits_without_resolver_entry() {
    let manager = mk_manager();
    let rm = mk_run_manager(&manager);

    // Park a ComponentFinished await so there IS an open session to (not) scan.
    let mgr = Arc::clone(&manager);
    let start_handle = tokio::spawn(async move {
        mgr.start("controller", vec![component_req("comp-1")], allof())
            .await
    });
    wait_until_parked(&manager, 1).await;
    assert_eq!(
        manager.resolve_attempts_for_test(),
        0,
        "baseline: no attempts yet"
    );

    // (a) A colon-bearing task_id (mirrors auto-settle's `auto:{agent}`) fires the
    //     sink but MUST short-circuit before spawning the resolver.
    let colon_run = rm
        .ensure_run("auto:a", "auto:a", RunConfig::default())
        .expect("ensure_run colon");
    rm.complete_run(&colon_run, "done".to_string())
        .expect("complete_run colon");
    settle(64).await;
    assert_eq!(
        manager.resolve_attempts_for_test(),
        0,
        "a colon task_id must short-circuit in on_run_completed: no spawn, no resolver entry"
    );
    assert!(
        !start_handle.is_finished(),
        "a colon completion resolves nothing"
    );

    // (b) A colon-free NON-matching task_id spawns + ENTERS the resolver (scans, no
    //     match). Proves the counter distinguishes short-circuit from a real attempt.
    let free_run = rm
        .ensure_run("other-comp", "other-comp", RunConfig::default())
        .expect("ensure_run colon-free");
    rm.complete_run(&free_run, "done".to_string())
        .expect("complete_run colon-free");
    settle(64).await;
    assert_eq!(
        manager.resolve_attempts_for_test(),
        1,
        "a colon-free non-match must ENTER the resolver exactly once"
    );
    assert!(
        !start_handle.is_finished(),
        "a non-matching completion resolves nothing"
    );

    // Clean up.
    let _ = manager.resolve_component_finished("comp-1", "done").await;
    let _ = tokio::time::timeout(Duration::from_secs(5), start_handle).await;
}
