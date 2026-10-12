//! Tier 1b ⑥ — direct Child roster (`# Available Children`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use advance_context_engine::{
    format_available_children_section, format_available_children_section_with_aliases,
    AgentIdentityReader,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use advance_shared_types::capability::{CapParams, CapabilityId};
use advance_shared_types::context::ContextAssembler;
use async_trait::async_trait;

#[path = "common/mod.rs"]
mod common;
use common::*;

fn cap(id: &str) -> Capability {
    Capability {
        id: CapabilityId::new(id),
        params: CapParams(serde_json::Value::Null),
    }
}

fn node(id: &str, kind: AgentKind, parent: &str, caps: Vec<Capability>) -> AgentNode {
    node_full(
        id,
        kind,
        parent,
        caps,
        AgentStatus::Active,
        PathBuf::from(format!("/ws/{id}")),
        None,
    )
}

fn node_full(
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

struct MapIdentity(HashMap<PathBuf, String>);

#[async_trait]
impl AgentIdentityReader for MapIdentity {
    async fn agents_md_summary(&self, _agent_id: &str) -> Option<String> {
        None
    }
    async fn agents_md_for_workspace(&self, workspace: &Path) -> Option<String> {
        self.0.get(workspace).cloned()
    }
}

async fn roster(tree: &FixtureTree, agent_id: &str) -> Option<String> {
    format_available_children_section(tree, &NullAgentIdentity, agent_id).await
}

#[tokio::test]
async fn lists_direct_children_only() {
    let tree = FixtureTree {
        nodes: vec![
            node("child-1", AgentKind::Child, "root", vec![cap("fs.read")]),
            node("child-2", AgentKind::Child, "root", vec![cap("db.query")]),
            node(
                "grand",
                AgentKind::Child,
                "child-1",
                vec![cap("llm.generate")],
            ),
            node("sub-a", AgentKind::Sub, "root", vec![cap("web.search")]),
        ],
    };

    let section = roster(&tree, "root").await.expect("roster");
    assert!(section.starts_with("# Available Children"));
    assert!(section.contains("## child-1"));
    assert!(section.contains("- capabilities: fs.read"));
    assert!(section.contains("## child-2"));
    assert!(section.contains("- workspace: /ws/child-1"));
    assert!(section.contains("- workspace: /ws/child-2"));
    assert!(!section.contains("grand"), "grandchild must be excluded");
    assert!(
        !section.contains("/ws/grand"),
        "grandchild workspace omitted"
    );
    assert!(!section.contains("sub-a"), "Sub stays in delegates");
    assert_eq!(section.matches("## ").count(), 2);
}

#[tokio::test]
async fn empty_tree_omits_section() {
    let tree = FixtureTree { nodes: vec![] };
    assert_eq!(roster(&tree, "root").await, None);
}

#[tokio::test]
async fn only_sub_under_parent_omits_section() {
    let tree = FixtureTree {
        nodes: vec![node("sub-a", AgentKind::Sub, "root", vec![cap("fs.read")])],
    };
    assert_eq!(roster(&tree, "root").await, None);
}

#[tokio::test]
async fn terminated_and_failed_children_stay_visible() {
    let tree = FixtureTree {
        nodes: vec![
            node_full(
                "alive",
                AgentKind::Child,
                "root",
                vec![cap("fs.read")],
                AgentStatus::Active,
                PathBuf::from("/ws/alive"),
                None,
            ),
            node_full(
                "paused",
                AgentKind::Child,
                "root",
                vec![cap("fs.write")],
                AgentStatus::Paused,
                PathBuf::from("/ws/paused"),
                None,
            ),
            node_full(
                "dead",
                AgentKind::Child,
                "root",
                vec![cap("llm.generate")],
                AgentStatus::Terminated,
                PathBuf::from("/ws/dead"),
                None,
            ),
            node_full(
                "boom",
                AgentKind::Child,
                "root",
                vec![cap("web.search")],
                AgentStatus::Failed,
                PathBuf::from("/ws/boom"),
                None,
            ),
        ],
    };
    let section = roster(&tree, "root").await.expect("roster");
    assert!(section.contains("## dead"));
    assert!(section.contains("- status: terminated"));
    assert!(section.contains("## boom"));
    assert!(section.contains("- status: failed"));
    assert!(section.contains("- status: paused"));
    assert!(section.contains("- status: active"));
}

#[tokio::test]
async fn includes_workspace_template_and_agents_md() {
    let child_ws = PathBuf::from("/ws/researcher");
    let tree = FixtureTree {
        nodes: vec![
            node_full(
                "researcher",
                AgentKind::Child,
                "root",
                vec![cap("web.search")],
                AgentStatus::Active,
                child_ws.clone(),
                Some("pack/research".into()),
            ),
            node_full(
                "grand",
                AgentKind::Child,
                "researcher",
                vec![cap("llm.generate")],
                AgentStatus::Active,
                PathBuf::from("/ws/grand"),
                Some("pack/grand".into()),
            ),
        ],
    };
    let identity = MapIdentity(HashMap::from([
        (
            child_ws,
            "# Researcher\n\nCite sources.\n\n## Later\n\nKeep this.".into(),
        ),
        (
            PathBuf::from("/ws/grand"),
            "# Grandchild must not appear".into(),
        ),
    ]));
    let section = format_available_children_section(&tree, &identity, "root")
        .await
        .expect("roster");
    assert!(section.contains("- workspace: /ws/researcher"));
    assert!(section.contains("- template: pack/research"));
    assert!(section.contains("# Researcher"));
    assert!(section.contains("Cite sources."));
    assert!(section.contains("Keep this."));
    assert!(
        !section.contains("Grandchild must not appear"),
        "grandchild AGENTS.md must stay out"
    );
    assert!(!section.contains("pack/grand"));
}

#[tokio::test]
async fn invalid_agent_id_yields_none() {
    let tree = FixtureTree {
        nodes: vec![node(
            "child-1",
            AgentKind::Child,
            "root",
            vec![cap("fs.read")],
        )],
    };
    for bad in &["../etc/passwd", "id with spaces", ""] {
        assert_eq!(
            roster(&tree, bad).await,
            None,
            "invalid agent_id must omit: {bad:?}"
        );
    }
}

#[tokio::test]
async fn sanitizes_child_id_caps_workspace_and_template() {
    let tree = FixtureTree {
        nodes: vec![node_full(
            "ch\u{200B}ild",
            AgentKind::Child,
            "root",
            vec![cap("ev\u{202E}il")],
            AgentStatus::Active,
            PathBuf::from("/ws/ev\u{202E}il"),
            Some("tmpl\u{200B}".into()),
        )],
    };
    let section = roster(&tree, "root").await.expect("roster");
    assert!(!section.contains('\u{200B}'));
    assert!(!section.contains('\u{202E}'));
}

#[tokio::test]
async fn alias_aware_matches_child_under_bare_parent_id() {
    let tree = FixtureTree {
        nodes: vec![node(
            "researcher",
            AgentKind::Child,
            "root",
            vec![cap("web.search")],
        )],
    };

    assert_eq!(
        roster(&tree, "agent:root").await,
        None,
        "colon-keyed single-id misses the bare-keyed Child"
    );

    let aliases = vec!["root".to_string(), "agent:root".to_string()];
    let aliased = format_available_children_section_with_aliases(
        &tree,
        &NullAgentIdentity,
        "agent:root",
        &aliases,
    )
    .await
    .expect("hit");
    assert!(aliased.contains("## researcher"));
    assert!(aliased.contains("- capabilities: web.search"));

    assert_eq!(
        format_available_children_section_with_aliases(
            &tree,
            &NullAgentIdentity,
            "agent:root",
            &[]
        )
        .await,
        roster(&tree, "agent:root").await,
        "empty aliases == single-id behaviour"
    );
}

#[tokio::test]
async fn assemble_folds_direct_children_and_keeps_delegates_parallel() {
    let tree = FixtureTree {
        nodes: vec![
            node(
                "child-1",
                AgentKind::Child,
                "agent-default",
                vec![cap("fs.read")],
            ),
            node(
                "grand",
                AgentKind::Child,
                "child-1",
                vec![cap("llm.generate")],
            ),
            node(
                "sub-a",
                AgentKind::Sub,
                "agent-default",
                vec![cap("web.search")],
            ),
        ],
    };
    let asm = build_assembler_with_tree(std::sync::Arc::new(tree));
    let result = asm.assemble(stub_ctx()).await.expect("assemble ok");

    let children = result
        .messages
        .iter()
        .filter(|m| m.content.starts_with("# Available Children"))
        .count();
    let delegates = result
        .messages
        .iter()
        .filter(|m| m.content.starts_with("# Available Delegates"))
        .count();
    assert_eq!(children, 1);
    assert_eq!(delegates, 1);

    let roster_msg = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Children"))
        .expect("roster message");
    assert!(roster_msg.content.contains("## child-1"));
    assert!(roster_msg.content.contains("- capabilities: fs.read"));
    assert!(!roster_msg.content.contains("grand"));
    assert!(!roster_msg.content.contains("sub-a"));
    assert!(result.tier_token_counts.tier1b > 0);
}

#[tokio::test]
async fn assemble_omits_children_section_when_tree_empty() {
    let asm = build_assembler_with_empty_inventories();
    let result = asm.assemble(stub_ctx()).await.expect("assemble ok");
    assert!(
        !result
            .messages
            .iter()
            .any(|m| m.content.starts_with("# Available Children")),
        "empty tree must keep assemble output free of the roster header"
    );
}
