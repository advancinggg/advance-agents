//! Child roster satellite — production assembler tree port folds direct
//! Child basic info into Tier 1b `# Available Children`.
//!
//! CR-1 — a populated tree lists only this agent's direct Child (id + caps).
//!         Grandchildren and Subs are excluded. Empty tree omits the section.

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

fn node(id: &str, kind: AgentKind, parent: &str, caps: Vec<Capability>) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: Some(AgentId(parent.into())),
        workspace_path: PathBuf::from("/ws"),
        capabilities: caps,
        template_ref: None,
        status: AgentStatus::Active,
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
    let tree: Arc<dyn AgentTreeSnapshot> = Arc::new(RosterTree {
        nodes: vec![
            node("researcher", AgentKind::Child, "a", vec![cap("fs.read")]),
            node(
                "grand",
                AgentKind::Child,
                "researcher",
                vec![cap("llm.generate")],
            ),
            node("temp", AgentKind::Sub, "a", vec![cap("web.search")]),
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
        None,
    );
    let res = asm.assemble(stub_ctx()).await.unwrap();
    let roster = res
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Children"))
        .expect("direct Child basic info reaches the prompt");
    assert!(
        roster.content.contains("- researcher — fs.read"),
        "roster lists the direct Child: {}",
        roster.content
    );
    assert!(
        !roster.content.contains("grand"),
        "grandchild must stay out: {}",
        roster.content
    );
    assert!(
        !roster.content.contains("temp"),
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
