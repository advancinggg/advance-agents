use std::collections::HashMap;

use jsonschema::JSONSchema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::document::{validate_depth, ComponentNode, GenUiDocument};
use crate::error::GenUiError;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CatalogEntry {
    pub name: String,
    pub props_schema: serde_json::Value,
    pub allows_children: bool,
    pub selectable: bool,
    pub description: String,
    #[serde(default)]
    pub degradation_fallback: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ActionEntry {
    pub name: String,
    pub params_schema: serde_json::Value,
    #[serde(default)]
    pub confirm: Option<ConfirmMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConfirmMetadata {
    pub title: String,
    pub message: String,
    #[serde(default)]
    pub variant: ConfirmVariant,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmVariant {
    #[default]
    Default,
    Danger,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ActionRef {
    pub name: String,
    #[serde(default = "default_empty_object")]
    pub params: serde_json::Value,
    #[serde(default)]
    pub confirm: Option<ConfirmMetadata>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ValidationOutcome {
    Valid,
    Degraded { fallback: String },
    Rejected { code: String, reason: String },
}

fn default_empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

pub trait ComponentCatalog: Send + Sync {
    fn validate_document(&self, doc: &GenUiDocument) -> Result<(), GenUiError>;
    fn validate_node(&self, node: &ComponentNode) -> ValidationOutcome;
    fn validate_action(&self, action: &ActionRef) -> Result<(), GenUiError>;
    fn agent_vocabulary(&self) -> String;
    fn lookup(&self, name: &str) -> Option<&CatalogEntry>;
}

struct CompiledEntry {
    entry: CatalogEntry,
    validator: JSONSchema,
}

struct CompiledAction {
    entry: ActionEntry,
    validator: JSONSchema,
}

pub struct DefaultCatalog {
    components: HashMap<String, CompiledEntry>,
    actions: HashMap<String, CompiledAction>,
}

impl DefaultCatalog {
    pub fn new(
        entries: Vec<CatalogEntry>,
        action_entries: Vec<ActionEntry>,
    ) -> Self {
        let components = entries
            .into_iter()
            .map(|e| {
                let validator = JSONSchema::compile(&e.props_schema)
                    .expect("catalog prop schema must be valid JSON Schema");
                let name = e.name.clone();
                (name, CompiledEntry { entry: e, validator })
            })
            .collect();
        let actions = action_entries
            .into_iter()
            .map(|a| {
                let validator = JSONSchema::compile(&a.params_schema)
                    .expect("action param schema must be valid JSON Schema");
                let name = a.name.clone();
                (name, CompiledAction { entry: a, validator })
            })
            .collect();
        Self { components, actions }
    }

    pub fn component_entries(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.components.values().map(|c| &c.entry)
    }

    pub fn action_entries(&self) -> impl Iterator<Item = &ActionEntry> {
        self.actions.values().map(|a| &a.entry)
    }
}

const INJECTION_PATTERNS: &[&str] = &[
    "<script",
    "<svg",
    "<iframe",
    "<embed",
    "<object",
    "<form",
    "<base",
    "javascript:",
    "vbscript:",
    "data:text/html",
    "data:text/javascript",
    "data:application/",
    "data:image/svg+xml",
];

fn has_event_handler_attr(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i] == b'o' && bytes[i + 1] == b'n' && bytes[i + 2].is_ascii_alphabetic() {
            let in_tag_context = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'<');
            if !in_tag_context {
                continue;
            }
            if let Some(eq_pos) = s[i + 2..].find('=') {
                let between = &s[i + 2..i + 2 + eq_pos];
                if between.len() <= 20 && between.chars().all(|c| c.is_ascii_alphabetic()) {
                    return true;
                }
            }
        }
    }
    false
}

fn contains_injection(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            INJECTION_PATTERNS.iter().any(|p| lower.contains(p)) || has_event_handler_attr(&lower)
        }
        serde_json::Value::Array(arr) => arr.iter().any(contains_injection),
        serde_json::Value::Object(obj) => obj.values().any(contains_injection),
        _ => false,
    }
}

impl ComponentCatalog for DefaultCatalog {
    fn validate_document(&self, doc: &GenUiDocument) -> Result<(), GenUiError> {
        for node in &doc.root {
            self.validate_tree(node)?;
        }
        Ok(())
    }

    fn validate_node(&self, node: &ComponentNode) -> ValidationOutcome {
        let Some(compiled) = self.components.get(&node.component) else {
            return ValidationOutcome::Rejected {
                code: "invalid_component".into(),
                reason: format!("unknown component: {}", node.component),
            };
        };

        if !compiled.entry.allows_children && !node.children.is_empty() {
            return ValidationOutcome::Rejected {
                code: "invalid_props".into(),
                reason: format!("{} does not allow children", node.component),
            };
        }

        if let Err(errors) = compiled.validator.validate(&node.props) {
            let reason: String = errors
                .take(3)
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return ValidationOutcome::Rejected {
                code: "invalid_props".into(),
                reason,
            };
        }

        if contains_injection(&node.props) {
            return ValidationOutcome::Rejected {
                code: "invalid_props".into(),
                reason: "props contain injection pattern".into(),
            };
        }

        if let Some(ref fallback) = compiled.entry.degradation_fallback {
            ValidationOutcome::Degraded {
                fallback: fallback.clone(),
            }
        } else {
            ValidationOutcome::Valid
        }
    }

    fn validate_action(&self, action: &ActionRef) -> Result<(), GenUiError> {
        let Some(compiled) = self.actions.get(&action.name) else {
            return Err(GenUiError::InvalidAction {
                name: action.name.clone(),
                reason: "action not in catalog".into(),
            });
        };

        if let Err(errors) = compiled.validator.validate(&action.params) {
            let reason: String = errors
                .take(3)
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(GenUiError::InvalidAction {
                name: action.name.clone(),
                reason,
            });
        }

        if action.confirm.is_none() && compiled.entry.confirm.is_some() {
            return Err(GenUiError::InvalidAction {
                name: action.name.clone(),
                reason: "action requires confirmation metadata".into(),
            });
        }

        Ok(())
    }

    fn agent_vocabulary(&self) -> String {
        let mut lines = vec!["# Available GenUI Components\n".to_string()];
        let mut sorted: Vec<_> = self.components.values().collect();
        sorted.sort_by_key(|c| &c.entry.name);
        for compiled in &sorted {
            let e = &compiled.entry;
            lines.push(format!("## {}", e.name));
            lines.push(e.description.clone());
            if e.allows_children {
                lines.push("- Accepts children".into());
            }
            if e.selectable {
                lines.push("- Selectable".into());
            }
            lines.push(String::new());
        }

        lines.push("# Available Actions\n".to_string());
        let mut sorted_actions: Vec<_> = self.actions.values().collect();
        sorted_actions.sort_by_key(|a| &a.entry.name);
        for compiled in &sorted_actions {
            let a = &compiled.entry;
            lines.push(format!("- `{}`", a.name));
            if a.confirm.is_some() {
                lines.push("  (requires confirmation)".into());
            }
        }

        lines.join("\n")
    }

    fn lookup(&self, name: &str) -> Option<&CatalogEntry> {
        self.components.get(name).map(|c| &c.entry)
    }
}

impl DefaultCatalog {
    fn validate_tree(&self, node: &ComponentNode) -> Result<(), GenUiError> {
        match self.validate_node(node) {
            ValidationOutcome::Valid | ValidationOutcome::Degraded { .. } => {}
            ValidationOutcome::Rejected { code, reason } => {
                if code == "invalid_component" {
                    return Err(GenUiError::InvalidComponent {
                        name: node.component.clone(),
                    });
                }
                return Err(GenUiError::InvalidProps {
                    component: node.component.clone(),
                    reason,
                });
            }
        }
        if node.component == "Button" {
            if let Some(action_val) = node.props.get("action") {
                let action_ref: ActionRef = serde_json::from_value(action_val.clone())
                    .map_err(|e| GenUiError::InvalidProps {
                        component: "Button".into(),
                        reason: format!("malformed action: {e}"),
                    })?;
                self.validate_action(&action_ref)?;
            }
        }
        for child in &node.children {
            self.validate_tree(child)?;
        }
        Ok(())
    }
}

pub struct GenUiGate {
    enabled: bool,
    max_document_bytes: usize,
    catalog: DefaultCatalog,
}

impl GenUiGate {
    pub fn new(enabled: bool, max_document_bytes: usize, catalog: DefaultCatalog) -> Self {
        Self {
            enabled,
            max_document_bytes,
            catalog,
        }
    }

    pub fn admit(&self, doc: &GenUiDocument) -> Result<(), GenUiError> {
        if !self.enabled {
            return Err(GenUiError::Denied);
        }
        if !matches!(doc.protocol_version, crate::document::A2uiVersion::V0_9_1) {
            return Err(GenUiError::InvalidProps {
                component: "document".into(),
                reason: format!(
                    "unsupported protocol version: {:?}",
                    doc.protocol_version
                ),
            });
        }
        doc.validate_size(self.max_document_bytes)?;
        validate_depth(&doc.root, 1)?;
        self.catalog.validate_document(doc)
    }

    pub fn catalog(&self) -> &DefaultCatalog {
        &self.catalog
    }
}
