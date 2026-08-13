use crate::catalog::ComponentCatalog;
use crate::document::{ComponentNode, GenUiDocument, MAX_DOCUMENT_DEPTH};

const MAX_OUTPUT_BYTES: usize = 4096;
const TRUNCATION_SUFFIX: &str = "...(truncated)";

pub fn degrade_to_text(doc: &GenUiDocument, catalog: &dyn ComponentCatalog) -> String {
    let mut out = String::new();
    for node in &doc.root {
        degrade_node(&mut out, node, catalog, 1);
    }
    if out.len() > MAX_OUTPUT_BYTES {
        let target = MAX_OUTPUT_BYTES - TRUNCATION_SUFFIX.len();
        let safe = out
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= target)
            .last()
            .unwrap_or(0);
        out.truncate(safe);
        out.push_str(TRUNCATION_SUFFIX);
    }
    out
}

fn degrade_node(
    out: &mut String,
    node: &ComponentNode,
    catalog: &dyn ComponentCatalog,
    depth: usize,
) {
    if depth > MAX_DOCUMENT_DEPTH {
        return;
    }

    let name = node.component.as_str();
    match name {
        "Text" => {
            if let Some(content) = node.props.get("content").and_then(|v| v.as_str()) {
                out.push_str(content);
                out.push('\n');
            }
        }
        "Heading" => {
            if let Some(content) = node.props.get("content").and_then(|v| v.as_str()) {
                let level = node
                    .props
                    .get("level")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(2) as usize;
                for _ in 0..level.min(4) {
                    out.push('#');
                }
                out.push(' ');
                out.push_str(content);
                out.push('\n');
            }
        }
        "Button" => {
            if let Some(label) = node.props.get("label").and_then(|v| v.as_str()) {
                out.push_str(&format!("[{label}]\n"));
            }
        }
        "EntityCard" => {
            let title = node
                .props
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("untitled");
            out.push_str(&format!("[Entity: {title}]\n"));
        }
        "DataTable" => {
            if let Some(title) = node.props.get("title").and_then(|v| v.as_str()) {
                out.push_str(&format!("Table: {title}\n"));
            }
            if let Some(columns) = node.props.get("columns").and_then(|v| v.as_array()) {
                let headers: Vec<&str> = columns
                    .iter()
                    .filter_map(|c| c.get("label").and_then(|l| l.as_str()))
                    .collect();
                out.push_str(&headers.join(" | "));
                out.push('\n');
            }
            if let Some(data) = node.props.get("data").and_then(|v| v.as_array()) {
                let cols = node
                    .props
                    .get("columns")
                    .and_then(|v| v.as_array())
                    .map(|c| {
                        c.iter()
                            .filter_map(|col| col.get("key").and_then(|k| k.as_str()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                for row in data.iter().take(10) {
                    let vals: Vec<String> = cols
                        .iter()
                        .map(|k| {
                            row.get(*k)
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .unwrap_or_default()
                        })
                        .collect();
                    out.push_str(&vals.join(" | "));
                    out.push('\n');
                }
            }
        }
        "TreeView" => {
            if let Some(nodes) = node.props.get("nodes").and_then(|v| v.as_array()) {
                for tree_node in nodes.iter().take(20) {
                    if let Some(label) = tree_node.get("label").and_then(|v| v.as_str()) {
                        out.push_str(&format!("- {label}\n"));
                    }
                }
            }
        }
        "Callout" => {
            let variant = node
                .props
                .get("variant")
                .and_then(|v| v.as_str())
                .unwrap_or("info");
            if let Some(message) = node.props.get("message").and_then(|v| v.as_str()) {
                out.push_str(&format!("[{variant}] {message}\n"));
            }
        }
        "Stat" => {
            let label = node
                .props
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let value = node
                .props
                .get("value")
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            out.push_str(&format!("{label}: {value}\n"));
        }
        "Section" | "Row" | "Column" | "StatGroup" => {
            if let Some(title) = node.props.get("title").and_then(|v| v.as_str()) {
                out.push_str(&format!("{title}\n"));
            }
            for child in &node.children {
                degrade_node(out, child, catalog, depth + 1);
            }
        }
        _ => {
            if catalog.lookup(name).is_some() {
                out.push_str(&format!("[{name}]\n"));
            } else {
                out.push_str(&format!("[unsupported: {name}]\n"));
            }
            for child in &node.children {
                degrade_node(out, child, catalog, depth + 1);
            }
        }
    }
}
