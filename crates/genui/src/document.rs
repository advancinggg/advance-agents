use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::GenUiError;

pub const MAX_DOCUMENT_BYTES: usize = 262_144;
pub const MAX_DOCUMENT_DEPTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum A2uiVersion {
    #[serde(rename = "0.9.1")]
    V0_9_1,
    #[serde(untagged)]
    Unknown(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct DocumentId(pub String);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GenUiDocument {
    pub protocol_version: A2uiVersion,
    pub document_id: DocumentId,
    pub root: Vec<ComponentNode>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComponentNode {
    pub component: String,
    pub props: serde_json::Value,
    #[serde(default)]
    pub children: Vec<ComponentNode>,
}

impl GenUiDocument {
    pub fn validate_size(&self, max_bytes: usize) -> Result<(), GenUiError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| GenUiError::InvalidProps {
                component: "document".into(),
                reason: e.to_string(),
            })?
            .len();
        if bytes > max_bytes {
            return Err(GenUiError::DocumentTooLarge { bytes, max: max_bytes });
        }
        Ok(())
    }
}

pub fn validate_depth(nodes: &[ComponentNode], current_depth: usize) -> Result<(), GenUiError> {
    if current_depth > MAX_DOCUMENT_DEPTH {
        return Err(GenUiError::DocumentTooDeep {
            depth: current_depth,
            max: MAX_DOCUMENT_DEPTH,
        });
    }
    for node in nodes {
        if !node.children.is_empty() {
            validate_depth(&node.children, current_depth + 1)?;
        }
    }
    Ok(())
}
