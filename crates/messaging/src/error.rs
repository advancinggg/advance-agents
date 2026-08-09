//! Slice A error surface — re-export of canonical shared-types errors.
//!
//! The slice-A `messaging` crate uses the canonical Rust error types from
//! `advance_shared_types::mailbox` directly. A standalone wrapper is
//! reserved for slice B+ if internal-only error variants emerge.

pub use advance_shared_types::mailbox::{DispatchError, MsgError};
pub use advance_shared_types::security_validator::SecurityError;
