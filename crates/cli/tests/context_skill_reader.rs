//! skills-J26 reader satellite (2026-06-20) — the production `DiskSkillSummaryReader`
//! wired into the context assembler + threaded through `wire_capabilities`.
//!
//! RDR-4 — `build_context_assembler_for_agent_with_skills(.., skills_agent_root=Some)`
//!         folds the on-disk skill's L0 summary into the assembled prompt's
//!         `# Available Skills` section (the anti-fake-green witness: the port
//!         actually reaches the prompt). `None` → no section (byte-identical to
//!         `_with_history`).
//! RDR-6 — the REAL production composition root `wire_capabilities` sets
//!         `WiringHandles.skills_root` to `<ws>/.agent` iff `.agent/config.yaml`
//!         declares `skills` (None otherwise) — locking the wiring.rs config→handle
//!         threading leg the builder-level RDR-1/RDR-4 bypass.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use advance_cli::context_wiring::{
    build_context_assembler_for_agent_with_skills, EmptyAgentTree, EmptyCallableInventory,
    FixedHostFnInventory,
};
use advance_cli::wiring::wire_capabilities;
use advance_context_engine::HostFnInventoryReader;
use advance_git::bootstrap_repo_at;
use advance_runtime::bootstrap::RuntimeHostBuilder;
use advance_shared_types::agent_tree::{AgentState, AgentStatus, AgentTreeSnapshot};
use advance_shared_types::context::{AssemblyContext, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::{CallableInventoryReader, EventBusEmit};
use cap_memory::MemoryStore;
use cap_skills::persistence::{DiskSkillStorage, SkillBlob, SkillStorage};
use cap_skills::{Provenance, TrustLevel};

// ── shared fixture builders (mirror context_history_readers.rs) ──

struct NoBus;
impl EventBusEmit for NoBus {
    fn emit(&self, _e: Event) {}
}

fn stub_ctx() -> AssemblyContext {
    AssemblyContext {
        agent_id: "agent:a".into(),
        task_id: None,
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
        model: "claude-3-5-sonnet-20241022".into(), // wide budget → no truncation
        turn_buffer: Vec::<LlmMessage>::new(),
        prior_state: AgentState {
            agent_id: "agent:a".into(),
            status: AgentStatus::Active,
            current_task_id: None,
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

/// Materialize an active skill at the cap-skills provider root (`<ws>/.agent`),
/// so the reader (rooted at the same value) reads exactly what was written.
async fn write_skill(skills_agent_root: &std::path::Path, id: &str, version: u32, content: &str) {
    let storage = DiskSkillStorage::with_default_writer(skills_agent_root.to_path_buf());
    storage
        .write_active(&SkillBlob {
            skill_id: id.to_string(),
            version,
            content: content.to_string(),
            tags: vec![],
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        })
        .await
        .expect("write_active");
}

// ── RDR-4: the reader's entries reach the assembled prompt ──

#[tokio::test]
async fn rdr4_skills_root_some_folds_available_skills_into_prompt() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    let root = workspace.join(".agent");
    write_skill(
        &root,
        "greeter",
        1,
        "---\nname: greeter\n---\n# Greeter\n\nGreets the user warmly by name.\n",
    )
    .await;

    let (callable, hostfn, tree) = ports();
    let aliases = vec!["agent:a".to_string()];

    // skills_agent_root = Some(root) → real DiskSkillSummaryReader → section appears.
    let asm = build_context_assembler_for_agent_with_skills(
        Arc::new(NoBus),
        callable.clone(),
        hostfn.clone(),
        tree.clone(),
        None::<Arc<MemoryStore>>, // skills are independent of the memory cap
        "agent:a",
        &aliases,
        None,        // memory_root
        Some(&root), // skills_agent_root
    );
    let res = asm.assemble(stub_ctx()).await.unwrap();
    let skills_msg = res
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Skills"))
        .expect("with skills_root=Some, the # Available Skills section reaches the prompt");
    assert!(
        skills_msg.content.contains("greeter"),
        "the section lists the skill name: {}",
        skills_msg.content
    );
    assert!(
        skills_msg
            .content
            .contains("Greets the user warmly by name."),
        "the section carries the extracted L0 summary: {}",
        skills_msg.content
    );

    // skills_agent_root = None → StubSkillSummary → NO section (byte-identical to
    // build_context_assembler_for_agent_with_history).
    let asm_none = build_context_assembler_for_agent_with_skills(
        Arc::new(NoBus),
        callable,
        hostfn,
        tree,
        None::<Arc<MemoryStore>>,
        "agent:a",
        &aliases,
        None,
        None, // skills_agent_root = None
    );
    let res2 = asm_none.assemble(stub_ctx()).await.unwrap();
    assert!(
        !res2
            .messages
            .iter()
            .any(|m| m.content.starts_with("# Available Skills")),
        "without skills_root the section is omitted (omit-when-empty)"
    );
}

// ── RDR-6: wire_capabilities sets WiringHandles.skills_root from declares_skills ──

/// Minimal `runtime-config.yaml` (mirrors wiring_memory_persist.rs). Declaring only
/// `skills` leaves `needs_key = false`, so `load_real_master_key` is never called —
/// no env var / master key required, no test-global env mutation, no parallel race.
fn runtime_yaml() -> String {
    r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_SKILLTEST_MK_UNUSED

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

#[tokio::test(flavor = "multi_thread")]
async fn rdr6_wire_capabilities_sets_skills_root_iff_skills_declared() {
    // Positive: declares `skills` → skills_root == Some(<ws>/.agent).
    {
        let (_g, ws, cfg) = fresh_workspace("capabilities:\n  skills: true\n");
        let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
        let (host, handles) = wire_capabilities(builder, &ws)
            .await
            .expect("wire (skills)");
        assert_eq!(
            handles.skills_root,
            Some(ws.join(".agent")),
            "declares_skills → WiringHandles.skills_root = <ws>/.agent (the cap-skills provider root)"
        );
        drop(host);
        drop(handles);
    }

    // Git-backed positive: declares `skills` inside a bootstrapped repo → the
    // production AC-22 turn runtime is wired into `WiringHandles`.
    {
        let (_g, ws, cfg) = fresh_workspace("capabilities:\n  skills: true\n");
        bootstrap_repo_at(&ws).expect("bootstrap git repo");
        let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
        let (host, handles) = wire_capabilities(builder, &ws)
            .await
            .expect("wire (skills + git)");
        assert!(
            handles.skill_turn_runtime.is_some(),
            "declares_skills + git queue → AC-22 SkillTurnRuntime is production-wired"
        );
        drop(host);
        drop(handles);
    }

    // Negative: declares `memory` only (NO skills) → skills_root == None → the
    // assembler's StubSkillSummary → no `# Available Skills` for that agent.
    {
        let (_g, ws, cfg) = fresh_workspace("capabilities:\n  memory: true\n");
        let builder = RuntimeHostBuilder::new(&cfg, &ws).await.expect("builder");
        let (host, handles) = wire_capabilities(builder, &ws)
            .await
            .expect("wire (no skills)");
        assert_eq!(
            handles.skills_root, None,
            "no skills cap → WiringHandles.skills_root = None (reader stubbed)"
        );
        drop(host);
        drop(handles);
    }
}
