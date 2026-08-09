//! Stage-C SAT-A — the cli cap-memory-backed L2/L3/L4 history readers
//! (`CapMemoryHistoryReader`) + the history-aware assembler builder.
//!
//! T6  — the readers project seeded `turn-index.yaml` / `summary.yaml` fixtures.
//! T6b — security: path-traversal `task_id` rejected; embedded agent/task id
//!       mismatch rejected; no-memory-cap path wires no real readers.
//! T7  — `build_context_assembler_for_agent_with_history` wires the real readers
//!       only when memory + memory_root are present (folded into `assemble()`).

use std::sync::Arc;
use std::time::SystemTime;

use advance_cli::context_wiring::{
    build_context_assembler_for_agent_with_history, CapMemoryHistoryReader, EmptyAgentTree,
    EmptyCallableInventory, FixedHostFnInventory,
};
use advance_context_engine::{
    HostFnInventoryReader, L2DigestReader, L3EpochReader, L4TaskSummaryReader,
};
use advance_shared_types::agent_tree::{AgentState, AgentStatus, AgentTreeSnapshot};
use advance_shared_types::context::{AssemblyContext, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::{CallableInventoryReader, EventBusEmit};
use cap_memory::summary::{Summary, SummaryMeta};
use cap_memory::turn_index::{Importance, LogOffset, TurnEntry, TurnIndex, TurnIndexMeta};
use cap_memory::MemoryStore;

// ── fixture builders (serialize the canonical cap-memory serde forms) ──

fn turn_entry(agent_id: &str, task_id: &str, digest: &str) -> TurnEntry {
    TurnEntry {
        turn: 1,
        timestamp: "2026-06-16T00:00:00Z".into(),
        agent_id: agent_id.into(),
        task_id: task_id.into(),
        log_offset: LogOffset {
            start_line: 0,
            end_line: 0,
        },
        has_user_instruction: true,
        has_user_correction: false,
        has_tool_use: false,
        has_decision: false,
        importance: Importance::Normal,
        digest: digest.into(),
        collapsed_view: "collapsed view text".into(),
        git_commit: String::new(),
        git_diff_summary: String::new(),
        git_checkpoints: vec![],
        reference_count: 0,
        content_identifiers: vec![],
        read_file_versions: vec![],
        tokens_digest: 5,
        tokens_collapse_excerpt: 10,
        tokens_l0_processed: 20,
    }
}

fn write_turn_index(root: &std::path::Path, task_id: &str, entry: TurnEntry) {
    let index = TurnIndex {
        meta: TurnIndexMeta {
            last_epoch_turn: 0,
            last_epoch_at: "2026-06-16T00:00:00Z".into(),
        },
        turns: vec![entry],
        epochs: vec![],
    };
    let dir = root.join("tasks").join(task_id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("turn-index.yaml"),
        serde_yml::to_string(&index).unwrap(),
    )
    .unwrap();
}

fn summary(agent_id: &str, task_id: &str, brief: &str) -> Summary {
    Summary {
        meta: SummaryMeta {
            task_id: task_id.into(),
            agent_id: agent_id.into(),
            title: "t".into(),
            status: "active".into(),
            profile: "default".into(),
            turns_total: 1,
            last_updated: "2026-06-16T00:00:00Z".into(),
            last_turn_at: "2026-06-16T00:00:00Z".into(),
            last_brief_update: 0,
            last_decisions_update: 0,
            last_state_update: 0,
        },
        brief: brief.into(),
        key_decisions: vec![],
        findings: vec![],
        open_questions: vec![],
        current_state: String::new(),
        errors_and_corrections: vec![],
        workflow: String::new(),
    }
}

fn write_summary(root: &std::path::Path, task_id: &str, s: Summary) {
    let dir = root.join("tasks").join(task_id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("summary.yaml"), serde_yml::to_string(&s).unwrap()).unwrap();
}

// ── T6: readers project seeded fixtures ──
#[tokio::test]
async fn t6_readers_project_seeded_fixtures() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_turn_index(
        root,
        "task-1",
        turn_entry("agent:a", "task-1", "did the thing"),
    );
    write_summary(
        root,
        "task-1",
        summary("agent:a", "task-1", "the task brief"),
    );

    let reader = CapMemoryHistoryReader::new(root.to_path_buf(), vec!["agent:a".to_string()]);

    let digests = reader.read_digests("agent:a", "task-1").await.unwrap();
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].turn_id, 1);
    assert_eq!(digests[0].digest, "did the thing");

    let task = reader.read_task_summary("agent:a", "task-1").await.unwrap();
    let task = task.expect("summary.yaml projected to L4");
    assert_eq!(task.task_id, "task-1");
    assert_eq!(task.summary, "the task brief");

    // Absent task dir → empty / None (graceful).
    assert!(reader
        .read_digests("agent:a", "missing")
        .await
        .unwrap()
        .is_empty());
    assert!(reader
        .read_task_summary("agent:a", "missing")
        .await
        .unwrap()
        .is_none());
}

// ── T6b: security guards ──
#[tokio::test]
async fn t6b_path_traversal_and_id_mismatch_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // A turn-index whose embedded ids are for a DIFFERENT task/agent.
    write_turn_index(
        root,
        "task-1",
        turn_entry("agent:evil", "other-task", "leak"),
    );
    write_summary(
        root,
        "task-1",
        summary("agent:evil", "other-task", "secret brief"),
    );

    let reader = CapMemoryHistoryReader::new(root.to_path_buf(), vec!["agent:a".to_string()]);

    // Embedded id mismatch → records rejected (no cross-task/agent leak), even
    // though the file physically lives under tasks/task-1/.
    assert!(
        reader
            .read_digests("agent:a", "task-1")
            .await
            .unwrap()
            .is_empty(),
        "a turn whose embedded agent/task ids do not match is filtered out"
    );
    assert!(
        reader
            .read_task_summary("agent:a", "task-1")
            .await
            .unwrap()
            .is_none(),
        "a summary whose embedded ids do not match is rejected"
    );
    assert!(
        reader
            .read_epoch("agent:a", "task-1")
            .await
            .unwrap()
            .is_none(),
        "L3 is gated on the file genuinely belonging to the task (no matching turn → None)"
    );

    // Path-traversal task_id → refused (no read outside the memory root).
    for evil in ["../escape", "a/b", "..", "with/slash"] {
        assert!(
            reader
                .read_digests("agent:a", evil)
                .await
                .unwrap()
                .is_empty(),
            "unsafe task_id {evil:?} must be rejected (path-traversal guard)"
        );
        assert!(reader
            .read_task_summary("agent:a", evil)
            .await
            .unwrap()
            .is_none());
    }
}

// ── T7: builder wires real readers only when memory + root present ──

struct NoBus;
impl EventBusEmit for NoBus {
    fn emit(&self, _e: Event) {}
}

fn stub_ctx(task_id: &str) -> AssemblyContext {
    AssemblyContext {
        agent_id: "agent:a".into(),
        task_id: Some(task_id.into()),
        message: Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "agent:a".into(),
            to: "agent:a".into(),
            payload: Vec::new(),
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        },
        prompt: "the prompt".into(),
        model: "claude-3-5-sonnet-20241022".into(), // Wide budget → no overflow
        turn_buffer: Vec::<LlmMessage>::new(),
        prior_state: AgentState {
            agent_id: "agent:a".into(),
            status: AgentStatus::Active,
            current_task_id: Some(task_id.into()),
            current_run_id: None,
            iteration: 0,
            turn_counter: 0,
            last_handle_message_at: None,
        },
    }
}

fn ports() -> (
    Arc<dyn CallableInventoryReader>,
    Arc<dyn HostFnInventoryReader>,
    Arc<dyn AgentTreeSnapshot>,
) {
    (
        Arc::new(EmptyCallableInventory),
        Arc::new(FixedHostFnInventory::from_names(&[])),
        Arc::new(EmptyAgentTree),
    )
}

#[tokio::test]
async fn t7_history_builder_wires_real_readers_when_memory_root_present() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_summary(
        root,
        "task-1",
        summary("agent:a", "task-1", "wired task brief"),
    );

    let (callable, hostfn, tree) = ports();
    let store = Some(Arc::new(MemoryStore::new()));
    let aliases = vec!["agent:a".to_string()];

    // memory + memory_root present → real L4 reader → the summary folds in.
    let asm = build_context_assembler_for_agent_with_history(
        Arc::new(NoBus),
        callable.clone(),
        hostfn.clone(),
        tree.clone(),
        store.clone(),
        "agent:a",
        &aliases,
        Some(root),
    );
    let res = asm.assemble(stub_ctx("task-1")).await.unwrap();
    assert!(
        res.messages
            .iter()
            .any(|m| m.content.starts_with("# Task Summary")
                && m.content.contains("wired task brief")),
        "with memory_root, the real L4 reader folds the task summary into the prompt"
    );

    // memory present but memory_root = None → stub readers → no summary.
    let asm_no_root = build_context_assembler_for_agent_with_history(
        Arc::new(NoBus),
        callable,
        hostfn,
        tree,
        store,
        "agent:a",
        &aliases,
        None,
    );
    let res2 = asm_no_root.assemble(stub_ctx("task-1")).await.unwrap();
    assert!(
        !res2
            .messages
            .iter()
            .any(|m| m.content.starts_with("# Task Summary")),
        "without memory_root the history readers stay inert (no fold)"
    );
}
