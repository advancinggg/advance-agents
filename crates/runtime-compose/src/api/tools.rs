//! Native tools an extension registers onto the composition.

use std::fmt;
use std::sync::Arc;

use cap_tools::LazyToolRegistry;

pub use async_trait::async_trait;
pub use cap_tools::{HostTool, MethodInfo, ToolDescription, ToolError};

use super::compose_log::ComposeLog;
use super::extension::ExtensionError;

/// Exists only when the home declares `tools`. Opaque; constructed only by the
/// composer.
pub struct ToolRegistrar {
    pub(crate) extension: &'static str,
    pub(crate) tools: Arc<LazyToolRegistry>,
    pub(crate) refusals: Vec<ToolRefusal>,
    pub(crate) registered: usize,
    pub(crate) log: Arc<dyn ComposeLog>,
}

impl ToolRegistrar {
    pub fn extension_id(&self) -> &'static str {
        self.extension
    }
}

/// Why [`ToolRegistrar::register`] refused a tool.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRefusal {
    /// `data`, any `skill::` id, or a web-family id.
    Reserved { id: String },
    /// Already registered (OSS, pack or another extension).
    Duplicate { id: String },
    /// Empty / longer than 128 bytes / whitespace or control; or a refusal of
    /// `register_host` itself (oversize describe, duplicate method).
    Invalid { id: String, reason: String },
    /// `describe()` panicked (called once, under catch_unwind, at registration).
    DescribePanicked { id: String },
}

impl fmt::Display for ToolRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolRefusal::Reserved { id } => write!(f, "tool {id:?}: reserved for OSS"),
            ToolRefusal::Duplicate { id } => write!(f, "tool {id:?}: already registered"),
            ToolRefusal::Invalid { id, reason } => write!(f, "tool {id:?}: {reason}"),
            ToolRefusal::DescribePanicked { id } => {
                write!(f, "tool {id:?}: describe() panicked")
            }
        }
    }
}

impl std::error::Error for ToolRefusal {}

impl From<ToolRefusal> for ExtensionError {
    fn from(refusal: ToolRefusal) -> Self {
        ExtensionError::new(refusal.to_string())
    }
}
