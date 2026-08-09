//! 011 (Wave-11 Lane B) — production spawn host-fn wiring witness (anti-fake-green).
//!
//! Guards the claim that `wire_capabilities` actually registers the cap-lifecycle
//! spawn host-fns (`register_agent_spawn`) over the SAME shared `AgentTreeStore`
//! the context-assembler snapshots — so a sub-agent spawn records a `Sub` node the
//! `# Available Delegates` section reads — NOT merely that the helper exists.
//!
//! - **T-011-01**: with `fs` declared, `lookup("lifecycle")` has spawn-child /
//!   spawn-sub / spawn-agent-from-template registered (idempotent=false, canonical ns).
//! - **T-011-02** (the witness): drive the PROD-REGISTERED `spawn-sub` handler with a
//!   bare `default-agent` caller → the SHARED `agent_tree_snapshot` now has a `Sub`
//!   under `default-agent` → `format_available_delegates_section` lists it → the REAL
//!   assembler (built over the SAME snapshot) assembles a `# Available Delegates`
//!   message listing the sub. Same store the assembler reads, not a harness tree.
//! - **T-011-03**: no fs/messaging cap ⇒ NO lifecycle host-fns + `agent_tree_snapshot`
//!   is None (the gate holds — no tree, no spawn registration).
//! - **T-011-04** (keying-residual lock): after a real spawn under bare `default-agent`,
//!   querying the section with the PRODUCTION colon msg-id `agent:default` lists NOTHING
//!   — a genuine parent-key MISS (documents waived_scope #2; the SYS-J-04 harvest that
//!   fixes the assembler keying flips this).
//! - **T-011-05**: a messaging-ONLY agent registers the spawn host-fns over the
//!   dispatcher tree even though `agent_tree_snapshot` is None (the `agent_tree.is_some()`
//!   gate; dormant-over-dispatcher-tree, harmless).
//! - **T-011-06**: `spawn-agent-from-template` (kind=sub, builtin `explorer`) is
//!   OPERATIONAL (records a `Sub`), not a guaranteed `invalid-config` — proves the
//!   `with_template_resolver(.., BuiltinTemplateRegistry)` wiring.
//!
//! **ZERO ledger flips**: regression guards, not AC/SYS-AC witnesses. `"lifecycle"` is
//! NOT in `KNOWN_CAPABILITIES`, so no guest links the interface; these tests drive the
//! prod-registered handler directly (the messaging_wiring_b2.rs precedent).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use advance_cli::context_wiring::{
    build_context_assembler_for_agent_with_skills, EmptyCallableInventory, FixedHostFnInventory,
};
use advance_cli::wiring::wire_capabilities;
use advance_context_engine::format_available_delegates_section;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentState, AgentStatus, AgentTreeSnapshot,
};
use advance_shared_types::context::{AssemblyContext, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::EventBusEmit;
use cap_memory::MemoryStore;
use wasmtime::component::Val;

const NS: &str = "advance:runtime/agent-lifecycle@0.2.0";
const CAP_AGENT: &str = "default-agent"; // the bare cap id = the tree Root + spawn caller
const MSG_AGENT: &str = "agent:default"; // the colon msg id the production assembler keys on
const TEST_MASTER_KEY_HEX: &str =
    "2031425364758697a8b9cadbecfd0e1f2031425364758697a8b9cadbecfd0e1f";

fn ensure_test_master_key() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var("ADV_SPAWN011_MK_UNUSED", TEST_MASTER_KEY_HEX));
}

struct NoBus;
impl EventBusEmit for NoBus {
    fn emit(&self, _e: Event) {}
}

/// Minimal `runtime-config.yaml`. Messaging now derives the joint
/// CONTRACT-216/215 journal key, so the fixture installs one process-local,
/// constant test key before wiring.
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
  env-var-name: ADV_SPAWN011_MK_UNUSED

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
    ensure_test_master_key();
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

/// A `HostCallContext` for a registered lifecycle op, caller = bare `default-agent`.
fn spawn_ctx(op: &str) -> HostCallContext {
    HostCallContext {
        agent_id: CAP_AGENT.to_string(),
        trace_id: "tr-011".to_string(),
        turn_id: None,
        capability: "lifecycle".to_string(),
        function: format!("advance:runtime/agent-lifecycle::{op}"),
        run_id: None,
        iteration: None,
    }
}

/// Extract the agent-id string from a `Val::Result(Ok(Some(String)))` (the WIT
/// spawn ok-arm). Panics with the actual shape on any error/other variant.
fn ok_spawn_id(v: &Val) -> String {
    match v {
        Val::Result(Ok(Some(b))) => match b.as_ref() {
            Val::String(s) => s.clone(),
            other => panic!("expected Val::String spawn id, got {other:?}"),
        },
        other => panic!("expected Result::Ok(Some(String)) from spawn, got {other:?}"),
    }
}

/// `AssemblyContext` for `agent_id` (overrides the message + prior_state ids to match
/// so nothing keys on a stray id). Wide model budget → no truncation.
fn ctx_for(agent_id: &str) -> AssemblyContext {
    AssemblyContext {
        agent_id: agent_id.into(),
        task_id: None,
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

/// Drive the prod-registered `op` handler and return its single `Val`.
async fn call_lifecycle(
    host: &advance_runtime::bootstrap::RuntimeHost,
    op: &str,
    params: Vec<Val>,
) -> Val {
    let spec = host
        .host_registry()
        .lookup("lifecycle")
        .into_iter()
        .find(|s| s.name == op)
        .unwrap_or_else(|| panic!("{op} registered"));
    let out = spec
        .handler
        .call(spawn_ctx(op), params, 1)
        .await
        .unwrap_or_else(|e| panic!("{op} call: {e:?}"));
    assert_eq!(out.len(), 1, "{op} returns exactly one Val");
    out.into_iter().next().unwrap()
}

/// Count `# Available Delegates` lines (`- name — caps`) for `agent_id`.
fn delegate_lines(snap: &dyn AgentTreeSnapshot, agent_id: &str) -> usize {
    format_available_delegates_section(snap, agent_id)
        .lines()
        .filter(|l| l.starts_with("- "))
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn t_011_01_spawn_hostfns_registered_live() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, _handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let specs = host.host_registry().lookup("lifecycle");
    for op in ["spawn-child", "spawn-sub", "spawn-agent-from-template"] {
        let found = specs.iter().any(|s| {
            s.capability == "lifecycle" && s.namespace == NS && s.name == op && !s.idempotent
        });
        assert!(
            found,
            "fs declared ⇒ `{op}` host-fn (ns `{NS}`, idempotent=false) must be registered; got {specs:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn t_011_02_spawn_sub_records_into_shared_tree_and_assembler_lists_it() {
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // Drive the PROD-REGISTERED spawn-sub handler (caller = bare default-agent = Root).
    // Empty params ⇒ template_ref = None (no resolver needed).
    let sub_id = ok_spawn_id(&call_lifecycle(&host, "spawn-sub", vec![]).await);

    // The SAME store the assembler snapshots now contains the Sub under default-agent.
    let snap = handles
        .agent_tree_snapshot
        .clone()
        .expect("fs ⇒ agent_tree_snapshot is Some");
    let data = snap.snapshot();
    let recorded = data.nodes.iter().any(|n| {
        n.id.0 == sub_id
            && n.kind == AgentKind::Sub
            && n.parent.as_ref() == Some(&AgentId(CAP_AGENT.to_string()))
    });
    assert!(
        recorded,
        "spawn-sub must record a Sub node parented at `{CAP_AGENT}` into the shared tree; nodes={:?}",
        data.nodes.iter().map(|n| (&n.id.0, &n.kind, &n.parent)).collect::<Vec<_>>()
    );

    // The delegates section (reading the SAME snapshot) lists the sub.
    let section = format_available_delegates_section(snap.as_ref(), CAP_AGENT);
    assert!(
        section.contains(&format!("- {sub_id}")),
        "the # Available Delegates section must list the spawned sub `{sub_id}`: {section}"
    );
    assert_eq!(
        delegate_lines(snap.as_ref(), CAP_AGENT),
        1,
        "exactly one delegate (the spawned sub)"
    );

    // The REAL assembler, built over the SAME shared snapshot, assembles a
    // # Available Delegates message listing the sub (the full assemble turn).
    let assembler = build_context_assembler_for_agent_with_skills(
        Arc::new(NoBus),
        Arc::new(EmptyCallableInventory),
        Arc::new(FixedHostFnInventory::new(vec![])),
        snap.clone(),
        None::<Arc<MemoryStore>>,
        CAP_AGENT,
        &[CAP_AGENT.to_string()],
        None, // memory_root
        None, // skills_agent_root
    );
    let result = assembler
        .assemble(ctx_for(CAP_AGENT))
        .await
        .expect("assemble");
    let delegates_msg = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Delegates"))
        .expect("assembled prompt has a # Available Delegates section");
    assert!(
        delegates_msg.content.contains(&format!("- {sub_id}")),
        "the assembled # Available Delegates section lists the product-spawned sub `{sub_id}`: {}",
        delegates_msg.content
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_011_03_no_tree_no_spawn_registration() {
    // Neither fs nor messaging ⇒ no shared tree ⇒ no spawn registration + no snapshot.
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  memory: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");
    assert!(
        host.host_registry().lookup("lifecycle").is_empty(),
        "no fs/messaging cap ⇒ NO lifecycle host-fns registered (the agent_tree.is_some() gate)"
    );
    assert!(
        handles.agent_tree_snapshot.is_none(),
        "no fs cap ⇒ agent_tree_snapshot is None"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_011_04_colon_msg_id_misses_keying_residual_lock() {
    // Documents waived_scope #2: spawns record under the BARE cap-id `default-agent`,
    // but production assembles with the COLON msg-id `agent:default` → the delegates
    // lookup MISSES. `agent:default` passes is_valid_agent_id (colons allowed), so the
    // empty result is a genuine parent-key miss, NOT a guard rejection.
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    let sub_id = ok_spawn_id(&call_lifecycle(&host, "spawn-sub", vec![]).await);
    let snap = handles
        .agent_tree_snapshot
        .clone()
        .expect("fs ⇒ snapshot Some");

    // Bare cap-id lists the sub (sanity — the mechanism works when keyed consistently).
    assert_eq!(
        delegate_lines(snap.as_ref(), CAP_AGENT),
        1,
        "bare `{CAP_AGENT}` lists the sub `{sub_id}`"
    );
    // Colon msg-id misses — the documented production keying residual.
    assert_eq!(
        delegate_lines(snap.as_ref(), MSG_AGENT),
        0,
        "the production colon msg-id `{MSG_AGENT}` MISSES the bare-keyed sub (waived keying residual)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_011_05_messaging_only_registers_over_dispatcher_tree() {
    // messaging-only: the tree exists (for the dispatcher) but agent_tree_snapshot is
    // None (snapshot is fs-only). The agent_tree.is_some() gate still registers spawn
    // over the dispatcher tree — dormant, harmless.
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  messaging: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws)
        .await
        .expect("messaging-only wire must succeed");
    assert!(
        !host.host_registry().lookup("lifecycle").is_empty(),
        "messaging-only ⇒ spawn host-fns registered over the dispatcher tree"
    );
    assert!(
        handles.agent_tree_snapshot.is_none(),
        "messaging-only ⇒ agent_tree_snapshot is None (snapshot is fs-only)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn t_011_06_spawn_from_template_is_operational() {
    // spawn-agent-from-template (kind=sub, builtin `explorer`) must RECORD a Sub, not
    // fail invalid-config — proving the with_template_resolver(.., BuiltinTemplateRegistry)
    // wiring (a resolver-less DefaultSpawner::new would always fail here).
    let (_g, ws, cfg) = fresh_workspace("capabilities:\n  fs: true\n");
    let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
    let (host, handles) = wire_capabilities(builder, &ws).await.expect("wire");

    // params: [agent-kind=sub, template-ref=explorer] (a BuiltinTemplateRegistry builtin).
    let v = call_lifecycle(
        &host,
        "spawn-agent-from-template",
        vec![Val::String("sub".into()), Val::String("explorer".into())],
    )
    .await;
    let sub_id = ok_spawn_id(&v); // panics (with the variant) if it returned invalid-config

    let snap = handles
        .agent_tree_snapshot
        .clone()
        .expect("fs ⇒ snapshot Some");
    let data = snap.snapshot();
    let recorded = data.nodes.iter().any(|n| {
        n.id.0 == sub_id
            && n.kind == AgentKind::Sub
            && n.parent.as_ref() == Some(&AgentId(CAP_AGENT.to_string()))
    });
    assert!(
        recorded,
        "spawn-agent-from-template kind=sub must record a Sub under `{CAP_AGENT}`; nodes={:?}",
        data.nodes
            .iter()
            .map(|n| (&n.id.0, &n.kind))
            .collect::<Vec<_>>()
    );
}
