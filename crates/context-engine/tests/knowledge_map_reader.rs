//! Crate tests for the dep-light `KnowledgeMapReader` real implementation
//! (`knowledge_map_reader::ProjectingKnowledgeMap`). Proves real projected
//! content directly AND that it reaches the assembled Tier-1b section through
//! the existing `build_tier1b` render path (the crate-level analogue of what
//! B1's SYS-AC-008 witnesses e2e), with untrusted bodies sanitized at render.

use std::collections::HashMap;

use advance_context_engine::{
    build_tier1b, KnowledgeMapReader, KnowledgeRecord, ProjectingKnowledgeMap,
    KNOWLEDGE_MAP_MAX_TOKENS,
};

fn reader_with(agent: &str, records: Vec<KnowledgeRecord>) -> ProjectingKnowledgeMap {
    let mut m = HashMap::new();
    m.insert(agent.to_string(), records);
    ProjectingKnowledgeMap::new(m)
}

#[tokio::test]
async fn projects_records_into_topics_and_syntheses() {
    let reader = reader_with(
        "a",
        vec![
            KnowledgeRecord::Topic {
                name: "auth".into(),
                body: "uses magic links".into(),
            },
            KnowledgeRecord::Synthesis {
                task_id: "task-1".into(),
                body: "did the thing".into(),
            },
            KnowledgeRecord::Topic {
                name: "db".into(),
                body: "postgres".into(),
            },
        ],
    );
    let km = reader.read_knowledge_map("a").await.unwrap();
    assert_eq!(km.topics.len(), 2);
    // Order preserved within each kind.
    assert_eq!(km.topics[0].name, "auth");
    assert_eq!(km.topics[0].body, "uses magic links");
    assert_eq!(km.topics[1].name, "db");
    assert_eq!(km.task_syntheses.len(), 1);
    assert_eq!(km.task_syntheses[0].task_id, "task-1");
    assert_eq!(km.task_syntheses[0].body, "did the thing");
}

#[tokio::test]
async fn unknown_agent_is_none() {
    let reader = reader_with(
        "a",
        vec![KnowledgeRecord::Topic {
            name: "x".into(),
            body: "y".into(),
        }],
    );
    assert!(reader.read_knowledge_map("other").await.is_none());
}

#[tokio::test]
async fn agent_with_no_records_is_none() {
    let reader = reader_with("a", vec![]);
    assert!(reader.read_knowledge_map("a").await.is_none());
}

#[tokio::test]
async fn tier1b_renders_real_knowledge_content() {
    let reader = reader_with(
        "agent-1",
        vec![
            KnowledgeRecord::Topic {
                name: "auth-flow".into(),
                body: "magic links primary".into(),
            },
            KnowledgeRecord::Synthesis {
                task_id: "task-7".into(),
                body: "shipped the login".into(),
            },
        ],
    );
    let msgs = build_tier1b(&reader, "agent-1", KNOWLEDGE_MAP_MAX_TOKENS).await;
    let joined: String = msgs
        .iter()
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    // The REAL projected topic/synthesis content reaches the assembled Tier-1b
    // section (vs the stub `None` → empty section).
    assert!(
        joined.contains("auth-flow"),
        "expected real topic name in tier1b: {joined}"
    );
    assert!(
        joined.contains("magic links primary"),
        "expected real topic body"
    );
    assert!(joined.contains("task-7"), "expected real synthesis task id");
    assert!(
        joined.contains("shipped the login"),
        "expected real synthesis body"
    );
}

#[tokio::test]
async fn untrusted_body_is_sanitized_at_render() {
    // A topic body carrying a BiDi RLO override mark (U+202E) — untrusted,
    // agent-authored. The reader returns it raw; the render path
    // (build_knowledge_map_section) sanitizes it. Assert the raw override mark
    // does NOT survive into the assembled section.
    let reader = reader_with(
        "agent-1",
        vec![KnowledgeRecord::Topic {
            name: "t".into(),
            body: "before\u{202E}after".into(),
        }],
    );
    let msgs = build_tier1b(&reader, "agent-1", KNOWLEDGE_MAP_MAX_TOKENS).await;
    let joined: String = msgs
        .iter()
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!joined.is_empty(), "topic should render a section");
    assert!(
        !joined.contains('\u{202E}'),
        "BiDi RLO override must be sanitized at render, not pass through verbatim"
    );
}
