//! Wave-12 Lane C (172 + 171) — production decomposition wiring witness (anti-fake-green).
//!
//! Guards the claim that `wire_capabilities` shares ONE `DefaultDecompositionStore`
//! between the decomposition host-fns and the context-assembler so the Tier-2 ⑭
//! "Active Task Decomposition" section reads LIVE decomposition state — NOT merely
//! that the helpers exist.
//!
//! - **T-172-01**: with `fs` declared, `lookup("lifecycle")` has submit-decomposition /
//!   update-subtask-status (idempotent=false) + get-decomposition (idempotent=true)
//!   registered under the canonical ns (the recording half).
//! - **T-172-02** (the 172 keystone): a real decomposition submitted into the SHARED
//!   `handles.decomposition_store` → the REAL assembler (built over a
//!   `CapDecompositionReader` on the SAME store) assembles a `# Active Task
//!   Decomposition` section listing the active task's subtasks. The live store the
//!   assembler reads, not a harness-seeded one.
//! - **T-172-03**: no fs/messaging cap ⇒ NO decomposition host-fns + `decomposition_store`
//!   is None ⇒ `EmptyDecomposition` ⇒ no section (the `agent_tree.is_some()` gate holds).
//! - **T-172-04** (keying — does BETTER than 011): after a real submit under the bare
//!   `default-agent`, assembling with the PRODUCTION colon msg-id `agent:default` STILL
//!   renders the section — the `CapDecompositionReader`'s bare-first alias set resolves
//!   the colon/bare residual the 011 delegates section left open.
//! - **T-172-05** (171 — emit is product-wired): driving the prod-registered
//!   `update-subtask-status` handler emits `task.subtask_updated{old→new}` on the bus AND
//!   mutates the persisted subtask status. (Build-lane regression guard for the emit/wiring half;
//!   the SYS-AC-171 system flip + its existing-id/status-readback WIT legs land in SYS-J-54's
//!   system-acceptance witnesses — Wave-17 Lane 4 widened the `get-decomposition` lowering + the
//!   existing-id lift.)
//! - **T-172-06** (non-orphaned filter): an orphaned (Completed-then-dropped) subtask is
//!   EXCLUDED from the section; a live non-orphaned subtask is INCLUDED.
//!
//! **ZERO ledger flips**: regression guards, not AC/SYS-AC witnesses. `"lifecycle"` is
//! NOT in `KNOWN_CAPABILITIES`, so no guest links the interface; these tests drive the
//! prod-registered handlers / shared store directly (the spawn_wiring_011.rs precedent).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_cli::context_wiring::{
    build_context_assembler_for_agent_with_decomposition, CapDecompositionReader, EmptyAgentTree,
    EmptyCallableInventory, EmptyDecomposition, FixedHostFnInventory,
};
use advance_cli::wiring::wire_capabilities;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentState, AgentStatus};
use advance_shared_types::context::{AssemblyContext, ContextAssembler, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::EventBusEmit;
use cap_lifecycle::{
    register_agent_decomposition, AgentTreeStore, DecompositionPlan, DecompositionStore,
    DecompositionStrategy, DefaultDecompositionStore, SubtaskSpec, SubtaskStatus,
};
use cap_memory::MemoryStore;
use wasmtime::component::Val;

const NS: &str = "advance:runtime/agent-lifecycle@0.2.0";
const CAP_AGENT: &str = "default-agent"; // bare cap id = the tree Root + decomposition owner
const MSG_AGENT: &str = "agent:default"; // colon msg id the production assembler keys on
const TASK: &str = "task-decomp-172";

struct NoBus;
impl EventBusEmit for NoBus {
    fn emit(&self, _e: Event) {}
}

/// Captures emitted events for the 171 emit assertion (the harness `CapturingBus`
/// pattern; this is in the witness, not in system-acceptance).
#[derive(Clone)]
struct CapturingBus(Arc<Mutex<Vec<Event>>>);
impl EventBusEmit for CapturingBus {
    fn emit(&self, e: Event) {
        self.0.lock().expect("poisoned").push(e);
    }
}

fn runtime_yaml() -> String {
    r#"wasm:
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
  env-var-name: ADV_DECOMP172_MK_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    .to_string()
}

fn fresh_workspace(caps_yaml: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = std::fs::canonicalize(dir.path()).expect("canonicalize");
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(workspace.join(".runtime/events/jsonl")).unwrap();
    std::fs::create_dir_all(workspace.join(".agent")).unwrap();
    let config_path = workspace.join(".advance/runtime-config.yaml");
    std::fs::write(&config_path, runtime_yaml()).unwrap();
    std::fs::write(workspace.join(".agent/config.yaml"), caps_yaml).unwrap();
    (dir, workspace, config_path)
}

/// An `AssemblyContext` for `agent_id` + `task_id`. Wide model budget ⇒ no truncation.
fn ctx_for(agent_id: &str, task_id: Option<&str>) -> AssemblyContext {
    AssemblyContext {
        agent_id: agent_id.into(),
        task_id: task_id.map(str::to_string),
        message: Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: agent_id.into(),
            to: agent_id.into(),
            payload: Vec::new(),
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        },
        prompt: "the prompt".into(),
        model: "claude-3-5-sonnet-20241022".into(),
        turn_buffer: Vec::<LlmMessage>::new(),
        prior_state: AgentState {
            agent_id: agent_id.into(),
            status: AgentStatus::Active,
            current_task_id: None,
            current_run_id: None,
            iteration: 0,
            turn_counter: 0,
            last_handle_message_at: None,
        },
    }
}

/// A `Decompose`-strategy plan with the given `(title, assignee)` subtasks (no deps,
/// fresh ids).
fn plan(goal: &str, subtasks: &[(&str, &str)]) -> DecompositionPlan {
    DecompositionPlan {
        goal: goal.into(),
        strategy: DecompositionStrategy::Decompose,
        subtasks: subtasks
            .iter()
            .map(|(title, assignee)| SubtaskSpec {
                existing_id: None,
                title: (*title).into(),
                assignee: (*assignee).into(),
                template_ref: None,
                prompt: String::new(),
                depends_on: Vec::new(),
            })
            .collect(),
    }
}

/// Build the REAL assembler over `decomposition` (+ an empty agent-tree) so the
/// assembled prompt's `# Active Task Decomposition` section reflects ONLY the
/// decomposition reader. `aliases` is the bare/colon alias set the reader resolves.
fn assembler_over(
    decomposition: Arc<dyn advance_context_engine::DecompositionReader>,
) -> Arc<dyn ContextAssembler> {
    build_context_assembler_for_agent_with_decomposition(
        Arc::new(NoBus),
        Arc::new(EmptyCallableInventory),
        Arc::new(FixedHostFnInventory::new(vec![])),
        Arc::new(EmptyAgentTree),
        None::<Arc<MemoryStore>>,
        CAP_AGENT,
        &[CAP_AGENT.to_string()],
        None, // memory_root
        None, // skills_agent_root
        decomposition,
    )
}

fn section_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|l| l.starts_with("- "))
        .map(str::to_string)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn t_172_01_decomposition_hostfns_registered_live() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let specs = host.host_registry().lookup("lifecycle");
    for (op, idempotent) in [
        ("submit-decomposition", false),
        ("update-subtask-status", false),
        ("get-decomposition", true),
    ] {
        let found = specs.iter().any(|s| {
            s.capability == "lifecycle"
                && s.namespace == NS
                && s.name == op
                && s.idempotent == idempotent
        });
        assert!(
            found,
            "fs declared ⇒ `{op}` host-fn (ns `{NS}`, idempotent={idempotent}) must be registered; got {specs:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t_172_02_assembler_lists_subtasks_from_shared_store() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // The SHARED store the wiring exposes (Some under fs/messaging).
    let store = handles
        .decomposition_store
        .clone()
        .expect("fs ⇒ decomposition_store is Some");
    store
        .submit(
            CAP_AGENT,
            TASK,
            plan(
                "ship feature",
                &[("design schema", "_self"), ("write tests", "_self")],
            ),
        )
        .expect("submit ok");

    // The REAL assembler, built over a CapDecompositionReader on the SAME store,
    // renders the active task's subtasks (the live store, not a harness-seeded one).
    let reader = Arc::new(CapDecompositionReader::new(
        store.clone(),
        vec![CAP_AGENT.to_string(), MSG_AGENT.to_string()],
    ));
    let assembler = assembler_over(reader);
    let result = assembler
        .assemble(ctx_for(CAP_AGENT, Some(TASK)))
        .await
        .expect("assemble");
    let section = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Active Task Decomposition"))
        .expect("assembled prompt has a # Active Task Decomposition section");
    assert!(
        section.content.contains("design schema"),
        "section must list subtask 'design schema': {}",
        section.content
    );
    assert!(
        section.content.contains("write tests"),
        "section must list subtask 'write tests': {}",
        section.content
    );
    assert_eq!(
        section_lines(&section.content).len(),
        2,
        "exactly two subtask lines: {}",
        section.content
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_172_03_no_tree_cap_no_store_no_section() {
    // Neither fs nor messaging ⇒ the shared tree (and the decomposition store) is None.
    let (_g, ws, cfg) = fresh_workspace("capabilities: {}\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    assert!(
        handles.decomposition_store.is_none(),
        "no fs/messaging ⇒ decomposition_store must be None"
    );
    let specs = host.host_registry().lookup("lifecycle");
    assert!(
        !specs.iter().any(|s| s.name == "submit-decomposition"),
        "no shared tree ⇒ decomposition host-fns must NOT be registered; got {specs:?}"
    );

    // EmptyDecomposition ⇒ no section (byte-identical empty-state).
    let assembler = assembler_over(Arc::new(EmptyDecomposition));
    let result = assembler
        .assemble(ctx_for(CAP_AGENT, Some(TASK)))
        .await
        .expect("assemble");
    assert!(
        !result
            .messages
            .iter()
            .any(|m| m.content.starts_with("# Active Task Decomposition")),
        "no decomposition store ⇒ no # Active Task Decomposition section"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_172_04_colon_msg_id_still_renders_via_alias() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws).await.expect("wire");
    let store = handles.decomposition_store.clone().expect("Some");
    store
        .submit(CAP_AGENT, TASK, plan("g", &[("only subtask", "_self")]))
        .expect("submit ok");

    // Assemble with the PRODUCTION colon msg-id. The reader's bare-first alias set
    // resolves the owner (bare `default-agent`) even though the assembler passes the
    // colon id — fixing the colon/bare residual 011's delegates section left open.
    let reader = Arc::new(CapDecompositionReader::new(
        store.clone(),
        vec![CAP_AGENT.to_string(), MSG_AGENT.to_string()],
    ));
    let assembler = assembler_over(reader);
    let result = assembler
        .assemble(ctx_for(MSG_AGENT, Some(TASK)))
        .await
        .expect("assemble");
    let section = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Active Task Decomposition"))
        .expect("colon msg-id STILL renders the section (alias resolved)");
    assert!(
        section.content.contains("only subtask"),
        "alias-resolved section must list the subtask: {}",
        section.content
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_172_05_update_subtask_status_emits_and_mutates() {
    // Standalone register over a real store + a CapturingBus (the same
    // `register_agent_decomposition` wire_capabilities uses) → drive the prod-registered
    // `update-subtask-status` handler → assert the emit + the persisted mutation.
    let dir = tempfile::tempdir().expect("tempdir");
    let ws = std::fs::canonicalize(dir.path()).expect("canon");
    std::fs::create_dir_all(ws.join(".agent")).unwrap();
    let tree = AgentTreeStore::new(ws.clone()).expect("tree");
    tree.insert_root(AgentNode {
        id: AgentId(CAP_AGENT.to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: ws.clone(),
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .expect("insert root");
    let store = Arc::new(DefaultDecompositionStore::new(tree));

    // Create the task + one subtask via the store; capture its minted id.
    let receipt = store
        .submit(CAP_AGENT, TASK, plan("g", &[("the subtask", "_self")]))
        .expect("submit ok");
    let subtask_id = receipt
        .subtask_ids
        .iter()
        .find(|m| m.title == "the subtask")
        .map(|m| m.subtask_id.clone())
        .expect("subtask id minted");

    let events = Arc::new(Mutex::new(Vec::<Event>::new()));
    let reg = InMemoryHostRegistry::new();
    register_agent_decomposition(&reg, store.clone(), Arc::new(CapturingBus(events.clone())));

    // Drive the PROD-REGISTERED update-subtask-status handler (Val::String params;
    // status lifts from a plain string per `lift_subtask_status`).
    let spec = reg
        .lookup("lifecycle")
        .into_iter()
        .find(|s| s.name == "update-subtask-status")
        .expect("update-subtask-status registered");
    let ctx = HostCallContext {
        agent_id: CAP_AGENT.to_string(),
        trace_id: "tr-172".to_string(),
        turn_id: None,
        capability: "lifecycle".to_string(),
        function: "advance:runtime/agent-lifecycle::update-subtask-status".to_string(),
        run_id: None,
        iteration: None,
    };
    let params = vec![
        Val::String(TASK.to_string()),
        Val::String(subtask_id.clone()),
        Val::String("in-progress".to_string()),
        Val::Option(None),
    ];
    spec.handler
        .call(ctx, params, 1)
        .await
        .expect("update-subtask-status call ok");

    // The emit is product-wired (task.subtask_updated{pending→in-progress}).
    let captured = events.lock().expect("poisoned");
    let evt = captured
        .iter()
        .find(|e| e.event_type == "task.subtask_updated")
        .expect("update-subtask-status must emit task.subtask_updated on the bus");
    let payload = evt.payload.to_string();
    assert!(
        payload.contains("pending") && payload.contains("in-progress"),
        "emit payload must carry old→new status (pending→in-progress): {payload}"
    );

    // The persisted state mutated (read back via the store Rust API — this is the
    // build-lane wiring guard; the WIT get-decomposition read-back is witnessed in
    // SYS-J-54's system-acceptance tests).
    let state = store
        .get(CAP_AGENT, TASK)
        .expect("get ok")
        .expect("task present");
    let st = state
        .subtasks
        .iter()
        .find(|s| s.subtask_id == subtask_id)
        .expect("subtask present");
    assert_eq!(
        st.status,
        SubtaskStatus::InProgress,
        "the subtask status must be mutated to InProgress"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_172_06_orphaned_subtasks_excluded_from_section() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (_host, handles) = wire_capabilities(builder, &ws).await.expect("wire");
    let store = handles.decomposition_store.clone().expect("Some");

    // Submit [alpha, beta]; complete alpha; re-submit [beta] (omitting alpha) so the
    // Completed-then-dropped alpha is retained orphaned (decomposition.rs orphan rule).
    let r1 = store
        .submit(
            CAP_AGENT,
            TASK,
            plan("g", &[("alpha-task", "_self"), ("beta-task", "_self")]),
        )
        .expect("submit 1");
    let alpha_id = r1
        .subtask_ids
        .iter()
        .find(|m| m.title == "alpha-task")
        .map(|m| m.subtask_id.clone())
        .expect("alpha id");
    store
        .update_subtask_status(CAP_AGENT, TASK, &alpha_id, SubtaskStatus::Completed, None)
        .expect("complete alpha");
    store
        .submit(CAP_AGENT, TASK, plan("g", &[("beta-task", "_self")]))
        .expect("submit 2 (drops alpha)");

    // Precondition: the persisted state holds BOTH an orphaned + a non-orphaned subtask.
    let state = store.get(CAP_AGENT, TASK).expect("get").expect("present");
    assert!(
        state.subtasks.iter().any(|s| s.orphaned),
        "alpha (Completed-then-dropped) must be retained orphaned: {:?}",
        state.subtasks
    );
    assert!(
        state.subtasks.iter().any(|s| !s.orphaned),
        "beta must be a live non-orphaned subtask: {:?}",
        state.subtasks
    );

    // The section lists ONLY the non-orphaned subtask.
    let reader = Arc::new(CapDecompositionReader::new(
        store.clone(),
        vec![CAP_AGENT.to_string(), MSG_AGENT.to_string()],
    ));
    let assembler = assembler_over(reader);
    let result = assembler
        .assemble(ctx_for(CAP_AGENT, Some(TASK)))
        .await
        .expect("assemble");
    let section = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Active Task Decomposition"))
        .expect("section present");
    assert!(
        section.content.contains("beta-task"),
        "non-orphaned beta-task must be listed: {}",
        section.content
    );
    assert!(
        !section.content.contains("alpha-task"),
        "orphaned alpha-task must be EXCLUDED: {}",
        section.content
    );
}
