//! Shared extension machinery (not part of the CONTRACT-244 façade).

pub mod call;
pub mod capabilities;
pub mod guard;
pub mod host_functions;
pub mod ids;
pub mod set;

pub use set::{
    CxParts, ExtensionBoard, ExtensionPlan, ExtensionSet, SecretNeedRule, SecretPlan, StartedParts,
    SECRET_NEED_RULE,
};
