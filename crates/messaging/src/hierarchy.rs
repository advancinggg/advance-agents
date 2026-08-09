//! Adjacent-level routing validation (MODULE-006 §1.3.3 + §3.5).
//!
//! `validate_routing` consumes `AgentTreeReader` (CONTRACT-040 from
//! MODULE-005) and enforces the allowed-route whitelist:
//! - `user:*` senders may message any existing agent (one-way bypass).
//! - Agent-to-agent: only parent↔child OR sibling↔sibling.
//! - All other paths reject with `MsgError::InvalidTarget`.
//!
//! Slice A defense-in-depth additions vs MODULE-006 §1.3.3 reference impl:
//! - `from == to` self-send is rejected (the reference doesn't address this).
//! - The `agent_exists(to)` check applies to `user:` senders too
//!   (the reference omits this for the user path; slice A tightens).
//!
//! # Identifier validation boundary
//!
//! Per shared-types `AgentTreeReader` invariant 3, `agent_id` charset
//! validation is the WIT host_fn layer's responsibility (a future slice).
//! Slice A's call sites are programmatic (tests + future host_fn) where
//! ids are already safe; the function does NOT validate `from` / `to`
//! beyond the routing rules.
//!
//! # PII discipline
//!
//! Per shared-types `MsgError` rustdoc, reason strings are short
//! invariant identifiers — no agent ids, no user content embedded in
//! the `String` payload.

use advance_shared_types::agent_tree::AgentTreeReader;
use advance_shared_types::mailbox::MsgError;

use crate::id_validation::is_safe_id;

const USER_PREFIX: &str = "user:";

pub fn validate_routing(tree: &dyn AgentTreeReader, from: &str, to: &str) -> Result<(), MsgError> {
    // Adversarial-R11 defense-in-depth: reject control-char / null /
    // Unicode confusables / empty-user-prefix before any tree lookup.
    if !is_safe_id(from) || !is_safe_id(to) {
        return Err(MsgError::InvalidTarget("invalid_id".into()));
    }
    if from == to {
        return Err(MsgError::InvalidTarget("self_send_forbidden".into()));
    }
    if !tree.agent_exists(to) {
        return Err(MsgError::InvalidTarget("unknown_target".into()));
    }
    if from.starts_with(USER_PREFIX) {
        return Ok(());
    }
    let from_parent = tree.parent_of(from);
    let to_parent = tree.parent_of(to);
    // child → parent
    if from_parent.as_deref() == Some(to) {
        return Ok(());
    }
    // parent → child
    if to_parent.as_deref() == Some(from) {
        return Ok(());
    }
    // sibling → sibling (both have a parent, and parents match)
    if from_parent.is_some() && from_parent == to_parent {
        return Ok(());
    }
    Err(MsgError::InvalidTarget("no_adjacency".into()))
}
