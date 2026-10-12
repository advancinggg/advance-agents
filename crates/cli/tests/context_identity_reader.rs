//! Identity satellite — production `DiskAgentIdentityReader` reaches the
//! assembled prompt's Tier-1a `# Agent Identity` section.
//!
//! IDR-4 — `build_context_assembler_for_agent_with_pack_skills(.., identity_agent_root=Some)`
//!         folds the on-disk AGENTS.md body into `# Agent Identity`.
//!         `None` → no section (byte-identical to `_with_decomposition`).

use std::sync::Arc;
use std::time::SystemTime;

use advance_cli::context_wiring::{
    build_context_assembler_for_agent_with_pack_skills, EmptyAgentTree, EmptyCallableInventory,
    EmptyDecomposition, FixedHostFnInventory,
};
use advance_context_engine::HostFnInventoryReader;
use advance_shared_types::agent_tree::{AgentState, AgentStatus, AgentTreeSnapshot};
use advance_shared_types::context::{AssemblyContext, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::{CallableInventoryReader, EventBusEmit};
use cap_memory::MemoryStore;

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
        model: "claude-3-5-sonnet-20241022".into(),
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

#[tokio::test]
async fn idr4_identity_root_some_folds_agent_identity_into_prompt() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    let root = workspace.join(".agent");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("AGENTS.md"),
        "# Researcher\n\nYou are a research agent that cites sources.\n\n## Guidelines\n\nAlways cite sources.\n",
    )
    .unwrap();

    let (callable, hostfn, tree) = ports();
    let aliases = vec!["agent:a".to_string()];

    let asm = build_context_assembler_for_agent_with_pack_skills(
        Arc::new(NoBus),
        callable.clone(),
        hostfn.clone(),
        tree.clone(),
        None::<Arc<MemoryStore>>,
        "agent:a",
        &aliases,
        None,
        None,
        Arc::new(EmptyDecomposition),
        None,
        Some(&root),
    );
    let res = asm.assemble(stub_ctx()).await.unwrap();
    let identity = res
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Agent Identity"))
        .expect("with identity_root=Some, # Agent Identity reaches the prompt");
    assert!(
        identity
            .content
            .contains("You are a research agent that cites sources."),
        "Tier 1a carries the identity prose: {}",
        identity.content
    );
    assert!(
        identity.content.contains("Always cite sources."),
        "Tier 1a carries later AGENTS.md sections, not just the first paragraph: {}",
        identity.content
    );
    assert!(
        identity.content.contains('\n'),
        "Tier 1a keeps Markdown line structure: {}",
        identity.content
    );
    assert!(
        res.tier_token_counts.tier1a > 0,
        "tier1a token count must be non-zero when identity is present"
    );

    let asm_none = build_context_assembler_for_agent_with_pack_skills(
        Arc::new(NoBus),
        callable,
        hostfn,
        tree,
        None::<Arc<MemoryStore>>,
        "agent:a",
        &aliases,
        None,
        None,
        Arc::new(EmptyDecomposition),
        None,
        None,
    );
    let res2 = asm_none.assemble(stub_ctx()).await.unwrap();
    assert!(
        !res2
            .messages
            .iter()
            .any(|m| m.content.starts_with("# Agent Identity")),
        "without identity_root the section is omitted"
    );
    assert_eq!(res2.tier_token_counts.tier1a, 0);
}
