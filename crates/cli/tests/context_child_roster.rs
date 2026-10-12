//! Child roster satellite — production assembler tree + identity ports fold
//! direct Child info into Tier 1b `# Available Children`.
//!
//! CR-1 — a populated tree lists this agent's direct Child (status,
//!         workspace, template, capabilities, AGENTS.md). Grandchildren
//!         and Subs are excluded. Terminated / Failed stay visible.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use advance_cli::context_wiring::{
    build_context_assembler_for_agent_with_pack_skills, EmptyCallableInventory, EmptyDecomposition,
    FixedHostFnInventory,
};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentState, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{CapParams, CapabilityId};
use advance_shared_types::context::{AssemblyContext, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::EventBusEmit;
use cap_memory::MemoryStore;

struct NoBus;
impl EventBusEmit for NoBus {
    fn emit(&self, _e: Event) {}
}

fn cap(id: &str) -> Capability {
    Capability {
        id: CapabilityId::new(id),
        params: CapParams(serde_json::Value::Null),
    }
}

fn node(
    id: &str,
    kind: AgentKind,
    parent: &str,
    caps: Vec<Capability>,
    status: AgentStatus,
    workspace_path: PathBuf,
    template_ref: Option<String>,
) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: Some(AgentId(parent.into())),
        workspace_path,
        capabilities: caps,
        template_ref,
        status,
    }
}

struct RosterTree {
    nodes: Vec<AgentNode>,
}

impl AgentTreeReader for RosterTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .and_then(|n| n.parent.as_ref().map(|p| p.0.clone()))
    }
    fn children_of(&self, agent_id: &str) -> Vec<String> {
        let key = AgentId(agent_id.to_string());
        self.nodes
            .iter()
            .filter(|n| n.parent.as_ref() == Some(&key))
            .map(|n| n.id.0.clone())
            .collect()
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == agent_id)
    }
    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, agent_id: &str) -> Vec<Capability> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.capabilities.clone())
            .unwrap_or_default()
    }
}

impl AgentTreeSnapshot for RosterTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            handles: Default::default(),
            nodes: self.nodes.clone(),
            parent_of: std::collections::HashMap::new(),
            children_of: std::collections::HashMap::new(),
            peer_slug_map: std::collections::HashMap::new(),
            revision: 0,
        }
    }
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

#[tokio::test]
async fn cr1_direct_children_reach_assembled_prompt() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    let parent_root = workspace.join(".agent");
    std::fs::create_dir_all(&parent_root).unwrap();

    let researcher_ws = workspace.join("children").join("researcher");
    let researcher_agent = researcher_ws.join(".agent");
    std::fs::create_dir_all(&researcher_agent).unwrap();
    std::fs::write(
        researcher_agent.join("AGENTS.md"),
        "# Researcher\n\nCite sources.\n\n## Later\n\nKeep this.\n",
    )
    .unwrap();

    let grand_ws = workspace.join("children").join("grand");
    let grand_agent = grand_ws.join(".agent");
    std::fs::create_dir_all(&grand_agent).unwrap();
    std::fs::write(
        grand_agent.join("AGENTS.md"),
        "# Grandchild must not appear\n",
    )
    .unwrap();

    let failed_ws = workspace.join("children").join("broken");
    std::fs::create_dir_all(failed_ws.join(".agent")).unwrap();

    let tree: Arc<dyn AgentTreeSnapshot> = Arc::new(RosterTree {
        nodes: vec![
            node(
                "researcher",
                AgentKind::Child,
                "a",
                vec![cap("fs.read")],
                AgentStatus::Active,
                researcher_ws.clone(),
                Some("pack/research".into()),
            ),
            node(
                "grand",
                AgentKind::Child,
                "researcher",
                vec![cap("llm.generate")],
                AgentStatus::Active,
                grand_ws,
                Some("pack/grand".into()),
            ),
            node(
                "broken",
                AgentKind::Child,
                "a",
                vec![cap("http.fetch")],
                AgentStatus::Failed,
                failed_ws,
                None,
            ),
            node(
                "temp",
                AgentKind::Sub,
                "a",
                vec![cap("web.search")],
                AgentStatus::Active,
                workspace.join(".sub").join("temp"),
                None,
            ),
        ],
    });
    let aliases = vec!["a".to_string(), "agent:a".to_string()];
    let asm = build_context_assembler_for_agent_with_pack_skills(
        Arc::new(NoBus),
        Arc::new(EmptyCallableInventory),
        Arc::new(FixedHostFnInventory::from_names(&[])),
        tree,
        None::<Arc<MemoryStore>>,
        "agent:a",
        &aliases,
        None,
        None,
        Arc::new(EmptyDecomposition),
        None,
        Some(&parent_root),
    );
    let res = asm.assemble(stub_ctx()).await.unwrap();
    let roster = res
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Children"))
        .expect("direct Child info reaches the prompt");
    assert!(
        roster.content.contains("## researcher"),
        "roster lists the direct Child: {}",
        roster.content
    );
    assert!(
        roster.content.contains("- status: active"),
        "active status is visible: {}",
        roster.content
    );
    assert!(
        roster.content.contains("- template: pack/research"),
        "template_ref is loaded: {}",
        roster.content
    );
    assert!(
        roster
            .content
            .contains(&format!("- workspace: {}", researcher_ws.display())),
        "workspace is loaded: {}",
        roster.content
    );
    assert!(
        roster.content.contains("Cite sources.") && roster.content.contains("Keep this."),
        "child AGENTS.md is loaded: {}",
        roster.content
    );
    assert!(
        roster.content.contains("## broken") && roster.content.contains("- status: failed"),
        "failed Child stays visible so the parent can see it hung: {}",
        roster.content
    );
    assert!(
        !roster.content.contains("grand") && !roster.content.contains("Grandchild must not appear"),
        "grandchild must stay out: {}",
        roster.content
    );
    assert!(
        !roster.content.contains("## temp"),
        "Sub must stay out of the Child roster: {}",
        roster.content
    );
    assert!(
        res.messages
            .iter()
            .any(|m| m.content.contains("- temp — web.search")),
        "Sub still appears under Available Delegates"
    );
}
