//! Tier 1b ⑥ — direct Child roster (`# Available Children`).

use std::path::PathBuf;

use advance_context_engine::{
    format_available_children_section, format_available_children_section_with_aliases,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use advance_shared_types::capability::{CapParams, CapabilityId};
use advance_shared_types::context::ContextAssembler;

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
    node_with_status(id, kind, parent, caps, AgentStatus::Active)
}

fn node_with_status(
    id: &str,
    kind: AgentKind,
    parent: &str,
    caps: Vec<Capability>,
    status: AgentStatus,
) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: Some(AgentId(parent.into())),
        workspace_path: PathBuf::from("/ws"),
        capabilities: caps,
        template_ref: None,
        status,
    }
}

#[test]
fn lists_direct_children_only() {
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

    let section = format_available_children_section(&tree, "root").expect("roster");
    assert!(section.starts_with("# Available Children"));
    assert!(section.contains("- child-1 — fs.read"));
    assert!(section.contains("- child-2 — db.query"));
    assert!(!section.contains("grand"), "grandchild must be excluded");
    assert!(!section.contains("sub-a"), "Sub stays in delegates");
    assert_eq!(section.lines().filter(|l| l.starts_with("- ")).count(), 2);
}

#[test]
fn empty_tree_omits_section() {
    let tree = FixtureTree { nodes: vec![] };
    assert_eq!(format_available_children_section(&tree, "root"), None);
}

#[test]
fn only_sub_under_parent_omits_section() {
    let tree = FixtureTree {
        nodes: vec![node("sub-a", AgentKind::Sub, "root", vec![cap("fs.read")])],
    };
    assert_eq!(format_available_children_section(&tree, "root"), None);
}

#[test]
fn terminated_and_failed_children_are_omitted() {
    let tree = FixtureTree {
        nodes: vec![
            node_with_status(
                "alive",
                AgentKind::Child,
                "root",
                vec![cap("fs.read")],
                AgentStatus::Active,
            ),
            node_with_status(
                "paused",
                AgentKind::Child,
                "root",
                vec![cap("fs.write")],
                AgentStatus::Paused,
            ),
            node_with_status(
                "dead",
                AgentKind::Child,
                "root",
                vec![cap("llm.generate")],
                AgentStatus::Terminated,
            ),
            node_with_status(
                "boom",
                AgentKind::Child,
                "root",
                vec![cap("web.search")],
                AgentStatus::Failed,
            ),
        ],
    };
    let section = format_available_children_section(&tree, "root").expect("roster");
    assert!(section.contains("- alive — "));
    assert!(section.contains("- paused — "));
    assert!(!section.contains("dead"));
    assert!(!section.contains("boom"));
}

#[test]
fn invalid_agent_id_yields_none() {
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
            format_available_children_section(&tree, bad),
            None,
            "invalid agent_id must omit: {bad:?}"
        );
    }
}

#[test]
fn sanitizes_child_id_and_caps() {
    let tree = FixtureTree {
        nodes: vec![node(
            "ch\u{200B}ild",
            AgentKind::Child,
            "root",
            vec![cap("ev\u{202E}il")],
        )],
    };
    let section = format_available_children_section(&tree, "root").expect("roster");
    assert!(!section.contains('\u{200B}'));
    assert!(!section.contains('\u{202E}'));
}

#[test]
fn alias_aware_matches_child_under_bare_parent_id() {
    let tree = FixtureTree {
        nodes: vec![node(
            "researcher",
            AgentKind::Child,
            "root",
            vec![cap("web.search")],
        )],
    };

    assert_eq!(
        format_available_children_section(&tree, "agent:root"),
        None,
        "colon-keyed single-id misses the bare-keyed Child"
    );

    let aliases = vec!["root".to_string(), "agent:root".to_string()];
    let aliased =
        format_available_children_section_with_aliases(&tree, "agent:root", &aliases).expect("hit");
    assert!(aliased.contains("- researcher — web.search"));

    assert_eq!(
        format_available_children_section_with_aliases(&tree, "agent:root", &[]),
        format_available_children_section(&tree, "agent:root"),
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

    let roster = result
        .messages
        .iter()
        .find(|m| m.content.starts_with("# Available Children"))
        .expect("roster message");
    assert!(roster.content.contains("- child-1 — fs.read"));
    assert!(!roster.content.contains("grand"));
    assert!(!roster.content.contains("sub-a"));
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
