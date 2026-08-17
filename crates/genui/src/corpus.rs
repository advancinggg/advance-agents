use serde_json::json;

use crate::document::{A2uiVersion, ComponentNode, DocumentId, GenUiDocument};

fn node(component: &str, props: serde_json::Value) -> ComponentNode {
    ComponentNode {
        component: component.into(),
        props,
        children: vec![],
    }
}

fn node_with_children(
    component: &str,
    props: serde_json::Value,
    children: Vec<ComponentNode>,
) -> ComponentNode {
    ComponentNode {
        component: component.into(),
        props,
        children,
    }
}

fn doc(root: Vec<ComponentNode>) -> GenUiDocument {
    GenUiDocument {
        protocol_version: A2uiVersion::V0_9_1,
        document_id: DocumentId("test-doc-001".into()),
        root,
    }
}

pub fn corpus_valid_documents() -> Vec<GenUiDocument> {
    vec![
        doc(vec![node("Text", json!({"content": "Hello, world!"}))]),
        doc(vec![node(
            "Heading",
            json!({"content": "Dashboard", "level": 2}),
        )]),
        doc(vec![node(
            "Button",
            json!({"label": "Refresh", "action": {"name": "refresh_data"}}),
        )]),
        doc(vec![node(
            "EntityCard",
            json!({"entity_id": "agent-1", "title": "My Agent"}),
        )]),
        doc(vec![node(
            "DataTable",
            json!({
                "title": "Runs",
                "columns": [
                    {"key": "id", "label": "ID"},
                    {"key": "status", "label": "Status", "format": "badge"}
                ],
                "data": [
                    {"id": "run-1", "status": "completed"},
                    {"id": "run-2", "status": "failed"}
                ]
            }),
        )]),
        doc(vec![node(
            "Callout",
            json!({"message": "Operation successful", "variant": "success"}),
        )]),
        doc(vec![node(
            "Stat",
            json!({"label": "Total Runs", "value": 42}),
        )]),
        doc(vec![node_with_children(
            "StatGroup",
            json!({"columns": 3}),
            vec![
                node("Stat", json!({"label": "Active", "value": 5})),
                node("Stat", json!({"label": "Queued", "value": 3})),
                node("Stat", json!({"label": "Failed", "value": 1})),
            ],
        )]),
        doc(vec![node_with_children(
            "Section",
            json!({"title": "Overview"}),
            vec![
                node("Text", json!({"content": "Welcome to the dashboard."})),
                node(
                    "Callout",
                    json!({"message": "All systems operational", "variant": "info"}),
                ),
            ],
        )]),
        doc(vec![node(
            "TreeView",
            json!({
                "nodes": [
                    {"id": "root", "label": "Workspace", "parent_id": null},
                    {"id": "child1", "label": "Project A", "parent_id": "root"},
                    {"id": "child2", "label": "Project B", "parent_id": "root"}
                ]
            }),
        )]),
        doc(vec![node_with_children(
            "Row",
            json!({"gap": "md"}),
            vec![
                node("Text", json!({"content": "Left"})),
                node("Text", json!({"content": "Right"})),
            ],
        )]),
    ]
}

pub fn corpus_invalid_documents() -> Vec<(GenUiDocument, &'static str)> {
    vec![
        (
            doc(vec![node("NonExistentWidget", json!({}))]),
            "unknown component",
        ),
        (
            doc(vec![node("Text", json!({"content": 42}))]),
            "wrong prop type",
        ),
        (doc(vec![node("Text", json!({}))]), "missing required prop"),
        (
            doc(vec![node(
                "Text",
                json!({"content": "<script>alert('xss')</script>"}),
            )]),
            "script injection in props",
        ),
        (
            doc(vec![node(
                "Text",
                json!({"content": "javascript:alert(1)"}),
            )]),
            "javascript: URI injection",
        ),
        (
            doc(vec![node(
                "Text",
                json!({"content": "<img src=x onerror=alert(1)>"}),
            )]),
            "event handler injection",
        ),
        (
            doc(vec![node(
                "Text",
                json!({"content": "data:text/html,<script>alert(1)</script>"}),
            )]),
            "data:text/html injection",
        ),
        (
            doc(vec![node_with_children(
                "Text",
                json!({"content": "no children allowed"}),
                vec![node("Text", json!({"content": "child"}))],
            )]),
            "children on non-container",
        ),
        (build_deep_document(10), "too deep nesting"),
    ]
}

fn build_deep_document(depth: usize) -> GenUiDocument {
    let mut current = node("Text", json!({"content": "leaf"}));
    for _ in 0..depth {
        current = node_with_children("Section", json!({"title": "level"}), vec![current]);
    }
    doc(vec![current])
}

pub fn corpus_degradation_vectors() -> Vec<(GenUiDocument, &'static str)> {
    vec![
        (
            doc(vec![node("Text", json!({"content": "Hello"}))]),
            "Hello\n",
        ),
        (
            doc(vec![node(
                "Heading",
                json!({"content": "Title", "level": 2}),
            )]),
            "## Title\n",
        ),
        (
            doc(vec![node(
                "Callout",
                json!({"message": "Warning!", "variant": "warning"}),
            )]),
            "[warning] Warning!\n",
        ),
        (
            doc(vec![node("Stat", json!({"label": "Count", "value": 7}))]),
            "Count: 7\n",
        ),
        (
            doc(vec![node(
                "Button",
                json!({"label": "Click Me", "action": {"name": "refresh_data"}}),
            )]),
            "[Click Me]\n",
        ),
        (
            doc(vec![node(
                "EntityCard",
                json!({"entity_id": "a1", "title": "Agent Alpha"}),
            )]),
            "[Entity: Agent Alpha]\n",
        ),
    ]
}
