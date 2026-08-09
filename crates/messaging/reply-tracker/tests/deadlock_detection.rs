//! MODULE-007 AC-09 — deadlock detection (slice m007-B; direction flipped
//! to the adjudicated clause direction by dev-task-deadlock-flip, ADR
//! `2026-06-10-await-deadlock-direction-adjudication`: reject self-await +
//! await-ANCESTOR (upward), admit await-descendant (downward, SYS-J-05)).
//!
//! T08a: all-cycle (child `b` awaits its parent `a` — an upward await) →
//!       whole-call `Err(DeadlockDetected)`; 0 deliver.
//! T08a2 (T08i): the admit-direction mirror — parent `a` awaits its direct
//!       child `agent:b` (downward await, the SYS-J-05 delegation pattern)
//!       → ADMITTED: dispatched, resolves `Completed` (regression lock
//!       against re-inverting the direction).
//! T08f: some-but-not-all-cycle (caller `b`: upward `agent:a` cyclic;
//!       `agent:c`/`agent:d` unrelated roots) → cyclic slot recorded
//!       `ReplyStatus::Failed("deadlock:agent:a")`; non-cyclic slots dispatch
//!       (2 deliver); session proceeds.
//! T08b: independent subtree (no cyclic targets) → admission passes,
//!       resolves normally.
//! T08d: `agent_tree = None` (default) → gate skipped (slice-A behavior).
//! T08e: bare target absent from `parent_of` → NOT DeadlockDetected; dispatch
//!       → mock InvalidTarget → per-slot `Failed("invalid-target:agent:zzz")`
//!       (AC-07 preserved).
//! T08g: MALFORMED target (`"a"` — no `agent:` prefix, fails `is_safe_id`)
//!       equal to the bare caller name, WITH `agent_tree = Some` → the
//!       deadlock gate must NOT deadlock-evaluate it (no self-await
//!       `DeadlockDetected` escalation); it falls through to the per-slot
//!       dispatch invalid-target path → `Failed("invalid-target:a")`,
//!       `FailedDispatch` (AUDIT round W1/W2 regression lock — the frozen
//!       "malformed→AC-07 fall-through" rule with the deadlock gate ACTIVE).
//! T08h: all-cyclic-agents request PADDED with a non-agent `user:` target
//!       (`is_safe_id` accepts `user:<body>`/`system` but they are NOT
//!       deadlock-evaluable agents) → the non-agent slot must NOT be counted
//!       toward `agent_slot_count`; the genuinely all-cyclic request must
//!       still produce whole-call `Err(DeadlockDetected)` (Adversarial round
//!       W2 regression lock — the all-cycle admission-triage bypass).
//!
//! (T08c — the `forms_cycle` unit sub-cases — is the in-src
//! `#[cfg(test)] mod tests` in `src/deadlock.rs`.)

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::Mutex;

use advance_messaging::dispatcher::MailboxDispatcher;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionStatus,
    OrchestrationError, ReplyResult, ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::traits::EventBusEmit;

use advance_reply_tracker::{AwaitSessionManager, AwaitSessionManagerImpl, ManagerOptions};

// ── Wave-15 Lane A: RecordingEmitter for the deadlock_rejected emit test ──
#[derive(Default)]
struct RecordingEmitter {
    events: std::sync::Mutex<Vec<Event>>,
}
impl RecordingEmitter {
    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}
impl EventBusEmit for RecordingEmitter {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

// ── MockDispatcher (records deliver calls; injectable InvalidTarget) ────

#[derive(Default)]
struct MockDispatcher {
    calls: Arc<Mutex<Vec<String>>>,
    inject_invalid_target: Arc<Mutex<Vec<String>>>,
}

impl MockDispatcher {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    async fn calls(&self) -> Vec<String> {
        self.calls.lock().await.clone()
    }
}

#[async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, target: &str, _msg: Message) -> Result<(), MsgError> {
        self.calls.lock().await.push(target.to_string());
        let inject = self.inject_invalid_target.lock().await;
        if inject.iter().any(|t| t == target) {
            Err(MsgError::InvalidTarget(target.to_string()))
        } else {
            Ok(())
        }
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

// ── MockAgentTree (fixed AgentTreeSnapshotData, bare-AgentId keys) ──────

struct MockAgentTree {
    data: AgentTreeSnapshotData,
}

impl MockAgentTree {
    /// `parent_pairs`: (child-bare, Some(parent-bare) | None).
    fn new(node_ids: &[&str], parent_pairs: &[(&str, Option<&str>)]) -> Arc<Self> {
        let mut parent_of = HashMap::new();
        for (child, parent) in parent_pairs {
            parent_of.insert(
                AgentId(child.to_string()),
                parent.map(|p| AgentId(p.to_string())),
            );
        }
        let nodes = node_ids
            .iter()
            .map(|i| AgentNode {
                id: AgentId(i.to_string()),
                kind: AgentKind::Child,
                parent: None,
                workspace_path: PathBuf::from("/tmp"),
                capabilities: Vec::<Capability>::new(),
                template_ref: None,
                status: AgentStatus::Active,
            })
            .collect();
        Arc::new(Self {
            data: AgentTreeSnapshotData {
                nodes,
                parent_of,
                children_of: HashMap::new(),
                peer_slug_map: HashMap::new(),
                revision: 1,
            },
        })
    }
}

impl AgentTreeReader for MockAgentTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.data
            .parent_of
            .get(&AgentId(agent_id.to_string()))
            .and_then(|p| p.as_ref().map(|a| a.0.clone()))
    }
    fn children_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        self.data.nodes.iter().any(|n| n.id.0 == agent_id)
    }
    fn agent_kind(&self, _agent_id: &str) -> Option<AgentKind> {
        None
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        Vec::new()
    }
}

impl AgentTreeSnapshot for MockAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        self.data.clone()
    }
}

fn make_agent_req(target: &str, correlation_id: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: correlation_id.to_string(),
        context: None,
    })
}

fn opts(mode: AwaitMode) -> AwaitOptions {
    AwaitOptions {
        mode,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

// ── T08a all-cycle (upward await) → whole-call Err(DeadlockDetected) ───

#[tokio::test(flavor = "current_thread")]
async fn t08a_all_cycle_whole_call_deadlock_detected() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // parent_of[b] = Some(a); caller = "b"; target agent:a → walking up from
    // caller b reaches a == target → upward await → cycle (clause direction,
    // ADR 2026-06-10-await-deadlock-direction-adjudication).
    let tree = MockAgentTree::new(&["a", "b"], &[("b", Some("a")), ("a", None)]);
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let result = manager
        .start(
            "b",
            vec![make_agent_req("agent:a", "c1")],
            opts(AwaitMode::AllOf),
        )
        .await;
    assert!(
        matches!(result, Err(OrchestrationError::DeadlockDetected(_))),
        "all-cycle (child awaits parent) must be whole-call DeadlockDetected, got {result:?}"
    );
    assert_eq!(
        mock.calls().await.len(),
        0,
        "0 deliver calls on whole-call deadlock"
    );
}

// ── T08a2 (T08i) admit-direction mirror: parent awaits child → ADMITTED ─
//
// The SYS-J-05 delegation regression lock (the most important new invariant
// of the direction flip): caller `a` awaits its DIRECT CHILD `agent:b` over
// the SAME tree as t08a. Under the pre-flip (inverted) walk this exact
// topology was rejected as DeadlockDetected; under the adjudicated clause
// direction it MUST be admitted, dispatched, and resolve normally. If a
// future change re-inverts the walk, this test fails immediately.

#[tokio::test(flavor = "current_thread")]
async fn t08a2_parent_awaits_direct_child_admitted() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // Same tree as t08a: parent_of[b] = Some(a). Caller = "a" (the parent);
    // target agent:b (its child) — a downward await → NOT a cycle.
    let tree = MockAgentTree::new(&["a", "b"], &[("b", Some("a")), ("a", None)]);
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "a",
            vec![make_agent_req("agent:b", "c1")],
            opts(AwaitMode::AllOf),
        )
        .await
    });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }
    // Admitted: the child target was dispatched (NOT rejected at admission).
    assert_eq!(
        mock.calls().await,
        vec!["agent:b".to_string()],
        "parent→child (downward) await must be admitted and dispatched"
    );
    let session_id = manager.first_open_session_id_for_test().await;
    manager
        .on_reply(
            &session_id,
            0,
            ReplyResult {
                slot: 0,
                source: "agent:b".to_string(),
                payload: vec![],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply ok");
    let result = h
        .await
        .expect("spawn ok")
        .expect("start Ok — downward await admitted");
    assert_eq!(
        result.status,
        AwaitSessionStatus::Completed,
        "parent-awaits-child session must resolve Completed"
    );
}

// ── T08f some-but-not-all-cycle → per-slot Failed("deadlock:..") ───────

#[tokio::test(flavor = "current_thread")]
async fn t08f_mixed_single_cycle_per_slot_deadlock_others_dispatch() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // Caller "b" (child of a). agent:a cyclic (a is b's parent — upward
    // await); c, d independent (roots, unrelated to b's ancestry).
    let tree = MockAgentTree::new(
        &["a", "b", "c", "d"],
        &[("b", Some("a")), ("c", None), ("d", None), ("a", None)],
    );
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let requests = vec![
        make_agent_req("agent:a", "c1"),
        make_agent_req("agent:c", "c2"),
        make_agent_req("agent:d", "c3"),
    ];
    let mgr = manager.clone();
    let h = tokio::spawn(async move { mgr.start("b", requests, opts(AwaitMode::AllOf)).await });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }

    // Only the 2 non-cyclic targets are delivered.
    let calls = mock.calls().await;
    assert_eq!(
        calls.len(),
        2,
        "only agent:c + agent:d dispatched, got {calls:?}"
    );
    assert!(calls.contains(&"agent:c".to_string()));
    assert!(calls.contains(&"agent:d".to_string()));
    assert!(
        !calls.contains(&"agent:a".to_string()),
        "cyclic slot NOT dispatched"
    );

    // Session NOT whole-call-errored; it proceeds (slot 0 recorded as a
    // deadlock failure, slots 1+2 pending). Complete the remaining slots and
    // assert slot-0's recorded reason.
    let session_id = manager.first_open_session_id_for_test().await;
    for slot in 1..3u32 {
        manager
            .on_reply(
                &session_id,
                slot,
                ReplyResult {
                    slot,
                    source: format!("agent:{}", if slot == 1 { "c" } else { "d" }),
                    payload: vec![],
                    status: ReplyStatus::Completed,
                    received_at: Utc::now(),
                    task_id: None,
                },
            )
            .await
            .expect("on_reply ok");
    }
    let result = h.await.expect("spawn ok").expect("start Ok");
    let slot0 = result
        .replies
        .iter()
        .find(|r| r.slot == 0)
        .expect("slot 0 present");
    match &slot0.status {
        ReplyStatus::Failed(reason) => {
            assert_eq!(
                reason, "deadlock:agent:a",
                "slot-0 per-slot deadlock reason"
            );
        }
        other => panic!("slot 0 must be Failed(deadlock:..), got {other:?}"),
    }
}

// ── Wave-15 Lane A: some-but-not-all cycle emits orchestration.deadlock_rejected ──

/// SYS-AC-169 module-level emit witness: a 2-slot AllOf where slot 0 (`agent:a`,
/// the caller `b`'s parent = upward) is cyclic and slot 1 (`agent:c`, unrelated
/// root) is valid. With an injected `EventBusEmit`, the admission triage emits
/// exactly one `orchestration.deadlock_rejected` event — empty `trace_id`,
/// `requester=b`, `targets` naming the cyclic `agent:a`, `cycle=[b, a]` — even
/// though the overall call would resolve once slot 1 replies.
#[tokio::test(flavor = "current_thread")]
async fn t08f_emit_deadlock_rejected_event() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let tree = MockAgentTree::new(
        &["a", "b", "c"],
        &[("b", Some("a")), ("c", None), ("a", None)],
    );
    let emitter = Arc::new(RecordingEmitter::default());
    let dyn_emitter: Arc<dyn EventBusEmit> = emitter.clone();
    let options = ManagerOptions {
        agent_tree: Some(tree),
        event_emitter: Some(dyn_emitter),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let requests = vec![
        make_agent_req("agent:a", "c1"), // cyclic: a is b's parent (upward)
        make_agent_req("agent:c", "c2"), // valid: unrelated root
    ];
    let mgr = manager.clone();
    let h = tokio::spawn(async move { mgr.start("b", requests, opts(AwaitMode::AllOf)).await });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }

    let events = emitter.events();
    let dr: Vec<&Event> = events
        .iter()
        .filter(|e| e.event_type == "orchestration.deadlock_rejected")
        .collect();
    assert_eq!(
        dr.len(),
        1,
        "exactly one deadlock_rejected emitted at admission, got {events:?}"
    );
    let ev = dr[0];
    assert_eq!(ev.trace_id, "", "session-stable envelope ⇒ empty trace_id");
    assert_eq!(
        ev.agent_id, "b",
        "envelope agent_id = bare caller (requester)"
    );
    assert_eq!(ev.payload["requester"], serde_json::json!("b"));
    let targets = ev.payload["targets"].as_array().expect("targets array");
    assert!(
        targets.iter().any(|t| t == "agent:a"),
        "targets names the cyclic agent:a: {ev:?}"
    );
    let cycle = ev.payload["cycle"].as_array().expect("cycle array");
    assert_eq!(
        cycle.first().and_then(|v| v.as_str()),
        Some("b"),
        "cycle starts at the caller"
    );
    assert_eq!(
        cycle.last().and_then(|v| v.as_str()),
        Some("a"),
        "cycle ends at the cyclic ancestor target"
    );

    h.abort();
}

/// Discriminator: a no-cycle 2-slot AllOf (both targets unrelated roots, with
/// the deadlock gate ACTIVE) emits NO deadlock_rejected event — proving the
/// event is causally tied to the cyclic-slot rejection, not unconditional.
#[tokio::test(flavor = "current_thread")]
async fn t08f_no_cycle_emits_no_deadlock_rejected_event() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let tree = MockAgentTree::new(
        &["a", "b", "c", "d"],
        &[("b", Some("a")), ("c", None), ("d", None), ("a", None)],
    );
    let emitter = Arc::new(RecordingEmitter::default());
    let dyn_emitter: Arc<dyn EventBusEmit> = emitter.clone();
    let options = ManagerOptions {
        agent_tree: Some(tree),
        event_emitter: Some(dyn_emitter),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // Caller "b" awaits "agent:c" + "agent:d" — both unrelated roots (NOT
    // ancestors of b), so no cyclic slot → no deadlock_rejected.
    let requests = vec![
        make_agent_req("agent:c", "c1"),
        make_agent_req("agent:d", "c2"),
    ];
    let mgr = manager.clone();
    let h = tokio::spawn(async move { mgr.start("b", requests, opts(AwaitMode::AllOf)).await });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }

    let n = emitter
        .events()
        .iter()
        .filter(|e| e.event_type == "orchestration.deadlock_rejected")
        .count();
    assert_eq!(n, 0, "no cyclic slot ⇒ no deadlock_rejected event");
    h.abort();
}

// ── T08a3 (T08j) multi-slot ALL-upward (incl. multi-hop) → whole-call ──
//
// Closes two TEST-round-4 coverage gaps in one fixture: (1) the all-cycle
// admission branch (`deadlock_slots.len() == agent_slot_count`) was only
// exercised with agent_slot_count == 1; (2) a multi-hop upward await
// (target = grandparent) was only unit-locked (t08c_ii), never driven
// through the real manager gate. Caller `c` over chain c→b→a awaits BOTH
// `agent:a` (grandparent, 2 hops up) and `agent:b` (parent, 1 hop up) —
// every agent slot is upward-cyclic → whole-call DeadlockDetected, 0
// deliver.

#[tokio::test(flavor = "current_thread")]
async fn t08a3_multi_slot_all_upward_whole_call_deadlock() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let tree = MockAgentTree::new(
        &["a", "b", "c"],
        &[("c", Some("b")), ("b", Some("a")), ("a", None)],
    );
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let requests = vec![
        make_agent_req("agent:a", "c1"), // grandparent — 2-hop upward await
        make_agent_req("agent:b", "c2"), // parent — 1-hop upward await
    ];
    let result = manager.start("c", requests, opts(AwaitMode::AllOf)).await;
    assert!(
        matches!(result, Err(OrchestrationError::DeadlockDetected(_))),
        "2 agent slots, both upward-cyclic (multi-hop + direct) must be \
         whole-call DeadlockDetected, got {result:?}"
    );
    assert_eq!(
        mock.calls().await.len(),
        0,
        "0 deliver calls on whole-call deadlock"
    );
}

// ── T08a4 (T08k) well-formed self-await with tree active → whole-call ──
//
// Closes the TEST-round-4 gap: t08c_i unit-locks the self-await branch and
// t08g covers the MALFORMED-target shape (which falls through to AC-07
// before the branch), but no integration test drove a WELL-FORMED
// `agent:a` self-await (caller `a`, `a` present in the tree) through the
// manager gate to whole-call DeadlockDetected.

#[tokio::test(flavor = "current_thread")]
async fn t08a4_well_formed_self_await_whole_call_deadlock() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    let tree = MockAgentTree::new(&["a"], &[("a", None)]);
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let result = manager
        .start(
            "a",
            vec![make_agent_req("agent:a", "c1")],
            opts(AwaitMode::AllOf),
        )
        .await;
    assert!(
        matches!(result, Err(OrchestrationError::DeadlockDetected(_))),
        "well-formed self-await (caller a, target agent:a, tree active) \
         must be whole-call DeadlockDetected, got {result:?}"
    );
    assert_eq!(
        mock.calls().await.len(),
        0,
        "0 deliver calls on whole-call deadlock"
    );
}

// ── T08b independent subtree → admission passes, resolves ─────────────

#[tokio::test(flavor = "current_thread")]
async fn t08b_independent_subtree_admission_passes() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // agent:c is an independent subtree (root); caller "a" is unrelated.
    let tree = MockAgentTree::new(&["a", "c"], &[("c", None), ("a", None)]);
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "a",
            vec![make_agent_req("agent:c", "c1")],
            opts(AwaitMode::AllOf),
        )
        .await
    });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }
    assert_eq!(mock.calls().await, vec!["agent:c".to_string()]);
    let session_id = manager.first_open_session_id_for_test().await;
    manager
        .on_reply(
            &session_id,
            0,
            ReplyResult {
                slot: 0,
                source: "agent:c".to_string(),
                payload: vec![],
                status: ReplyStatus::Completed,
                received_at: Utc::now(),
                task_id: None,
            },
        )
        .await
        .expect("on_reply ok");
    let result = h.await.expect("spawn ok").expect("start Ok");
    assert_eq!(result.status, AwaitSessionStatus::Completed);
}

// ── T08d agent_tree = None → gate skipped (slice-A behavior) ──────────

#[tokio::test(flavor = "current_thread")]
async fn t08d_agent_tree_none_gate_skipped() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // Default options → agent_tree None. Even a "self-await"-looking target
    // is NOT deadlock-checked (no tree).
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let mgr = manager.clone();
    let h = tokio::spawn(async move {
        mgr.start(
            "a",
            vec![make_agent_req("agent:a", "c1")],
            opts(AwaitMode::AllOf),
        )
        .await
    });
    for _ in 0..6 {
        tokio::task::yield_now().await;
    }
    // Dispatched normally (no deadlock gate).
    assert_eq!(mock.calls().await, vec!["agent:a".to_string()]);
    let session_id = manager.first_open_session_id_for_test().await;
    let _ = manager.close(&session_id, "test-cleanup").await;
    let _ = h.await;
}

// ── T08e absent bare target → not deadlock; per-slot invalid-target ───

#[tokio::test(flavor = "current_thread")]
async fn t08e_absent_target_falls_through_to_invalid_target() {
    let mock = MockDispatcher::new();
    {
        // Mock returns InvalidTarget for agent:zzz.
        mock.inject_invalid_target
            .lock()
            .await
            .push("agent:zzz".to_string());
    }
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // parent_of has only {a}; agent:zzz bare "zzz" is absent → forms_cycle
    // false → NOT DeadlockDetected; dispatch → mock InvalidTarget.
    let tree = MockAgentTree::new(&["a"], &[("a", None)]);
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // Single-slot all-failed dispatch → Ok(FailedDispatch) per PRD §9.2.
    let result = manager
        .start(
            "a",
            vec![make_agent_req("agent:zzz", "c1")],
            opts(AwaitMode::AllOf),
        )
        .await
        .expect("absent target is NOT a whole-call deadlock; all-failed → Ok");
    assert_eq!(result.status, AwaitSessionStatus::FailedDispatch);
    assert_eq!(result.replies.len(), 1);
    match &result.replies[0].status {
        ReplyStatus::Failed(reason) => {
            assert_eq!(
                reason, "invalid-target:agent:zzz",
                "absent target → per-slot invalid-target (AC-07 preserved), NOT deadlock"
            );
        }
        other => panic!("expected Failed(invalid-target:..), got {other:?}"),
    }
}

// ── T08g malformed target == bare caller, agent_tree=Some → AC-07 ──────
//
// AUDIT round W1/W2 regression lock. Before the W1 fix the deadlock gate
// called `bare_agent_name` + `forms_cycle` on the raw target with NO
// `is_safe_id` pre-filter, so caller "a" + malformed target "a" (no
// `agent:` prefix) + `agent_tree = Some` hit `forms_cycle`'s self-await
// branch (`target_bare == caller_bare`) → all-cyclic → whole-call
// `Err(DeadlockDetected)`. The frozen rev-14 plan mandates
// "malformed→AC-07 fall-through": a malformed target must NOT be
// deadlock-evaluated; it falls through to the per-slot dispatch
// invalid-target path. This test returns `Err(DeadlockDetected)` (panics
// at `.expect`) without the manager.rs deadlock-gate `is_safe_id`
// pre-filter.
#[tokio::test(flavor = "current_thread")]
async fn t08g_malformed_target_eq_caller_with_tree_falls_through_to_ac07() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // Tree present and contains the bare caller name "a" — this is exactly
    // the W1 trigger: a populated agent_tree so the deadlock gate is ACTIVE.
    let tree = MockAgentTree::new(&["a"], &[("a", None)]);
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    // caller "a"; single slot target "a" — MALFORMED (no `agent:` prefix →
    // fails `is_safe_id`) AND equal to the bare caller name (the precise
    // self-await regression path).
    let result = manager
        .start("a", vec![make_agent_req("a", "c1")], opts(AwaitMode::AllOf))
        .await
        .expect(
            "malformed target == caller with agent_tree=Some must NOT be a \
             whole-call DeadlockDetected — it falls through to per-slot \
             invalid-target (frozen 'malformed→AC-07 fall-through')",
        );
    assert_eq!(
        result.status,
        AwaitSessionStatus::FailedDispatch,
        "single malformed slot → all-failed-dispatch fast path"
    );
    assert_eq!(result.replies.len(), 1);
    match &result.replies[0].status {
        ReplyStatus::Failed(reason) => {
            assert_eq!(
                reason, "invalid-target:a",
                "malformed target → per-slot invalid-target (AC-07 preserved), \
                 NOT a deadlock escalation"
            );
        }
        other => panic!("expected Failed(invalid-target:a), got {other:?}"),
    }
    // dispatch.rs pre-validates with `is_safe_id` and rejects the malformed
    // target before invoking `deliver`, so 0 deliver calls.
    assert_eq!(
        mock.calls().await.len(),
        0,
        "malformed target rejected pre-deliver → 0 deliver calls"
    );
}

// ── T08h all-cyclic-agents padded with a non-agent target → still ─────
//      whole-call DeadlockDetected (Adversarial W2 regression lock)
//
// `is_safe_id` accepts the non-agent MODULE-006 id kinds `user:<body>`
// and `system` (grammar: `system | agent:body | user:body`). Before the
// W2 fix the deadlock gate counted ANY `is_safe_id` target toward
// `agent_slot_count`, so a caller could pad an otherwise all-cyclic
// request with a `user:`/`system` slot (`bare_agent_name` leaves it
// unchanged; `forms_cycle` cannot match it → not in `deadlock_slots`),
// making `deadlock_slots.len() == agent_slot_count` fail and SUPPRESSING
// the whole-call `DeadlockDetected` (an all-cycle admission-triage
// bypass). With the fix only canonical `agent:` targets are
// deadlock-evaluable: the `user:` slot is skipped (not counted, falls
// through to per-slot dispatch), the lone real agent target is cyclic,
// so the request is still whole-call `Err(DeadlockDetected)`. Without
// the fix this returns `Ok(FailedDispatch)` and the assertion fails.
#[tokio::test(flavor = "current_thread")]
async fn t08h_non_agent_pad_does_not_suppress_whole_call_deadlock() {
    let mock = MockDispatcher::new();
    let dispatcher: Arc<dyn MailboxDispatcher> = mock.clone();
    // parent_of[b] = Some(a); caller "b"; target agent:a — walking up from
    // caller b reaches a == target → upward await → cycle. "user:alice" is
    // a valid is_safe_id id but NOT an agent (no `agent:` prefix) → must be
    // invisible to the deadlock gate.
    let tree = MockAgentTree::new(&["a", "b"], &[("b", Some("a")), ("a", None)]);
    let options = ManagerOptions {
        agent_tree: Some(tree),
        ..ManagerOptions::default()
    };
    let manager = Arc::new(AwaitSessionManagerImpl::new(dispatcher, options));

    let requests = vec![
        make_agent_req("agent:a", "c1"), // the only real agent target — cyclic
        make_agent_req("user:alice", "c2"), // non-agent pad (is_safe_id true)
    ];
    let result = manager.start("b", requests, opts(AwaitMode::AllOf)).await;
    assert!(
        matches!(result, Err(OrchestrationError::DeadlockDetected(_))),
        "all-cyclic-agents (only agent:a, and it is cyclic) padded with a \
         non-agent user: slot must STILL be whole-call DeadlockDetected — \
         the non-agent slot must not dilute agent_slot_count (W2); got \
         {result:?}"
    );
    assert_eq!(
        mock.calls().await.len(),
        0,
        "0 deliver calls on whole-call deadlock"
    );
}
