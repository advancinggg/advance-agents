use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum GenUiError {
    Denied,
    InvalidComponent { name: String },
    InvalidProps { component: String, reason: String },
    DocumentTooLarge { bytes: usize, max: usize },
    DocumentTooDeep { depth: usize, max: usize },
    InvalidAction { name: String, reason: String },
    SurfaceUnavailable { surface: String },
    BridgeViolation,
}

impl fmt::Display for GenUiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied => write!(f, "genui capability denied"),
            Self::InvalidComponent { name } => write!(f, "unknown component: {name}"),
            Self::InvalidProps { component, reason } => {
                write!(f, "invalid props on {component}: {reason}")
            }
            Self::DocumentTooLarge { bytes, max } => {
                write!(f, "document too large: {bytes} bytes (max {max})")
            }
            Self::DocumentTooDeep { depth, max } => {
                write!(f, "document too deep: depth {depth} (max {max})")
            }
            Self::InvalidAction { name, reason } => {
                write!(f, "invalid action {name}: {reason}")
            }
            Self::SurfaceUnavailable { surface } => {
                write!(f, "surface unavailable: {surface}")
            }
            Self::BridgeViolation => write!(f, "MCP Apps bridge policy violation"),
        }
    }
}

impl std::error::Error for GenUiError {}
