//! MODULE-005 agent-tree-lifecycle canonical dependency-inversion surface.
//!
//! Canonical source: `docs/modules/MODULE-005-agent-tree-lifecycle.md` §2.3
//! (AgentTreeReader + AgentTreeSnapshot + AgentKind + AgentTreeSnapshotData +
//! AgentNode + AgentStatus + AgentState + Capability) and §2.3 head amendment
//! for `AgentId` newtype (landed by /dev Slice AC v2).
//!
//! Verbatim hoist — if the owner module's declaration changes, run
//! `/spec MODULE-005` and re-hoist via a follow-on /dev slice.
//!
//! # Security posture
//!
//! This module ships only trait + data-type declarations; all runtime
//! enforcement is the downstream implementer's responsibility. Deserialization
//! boundaries (JSON → `AgentId` / `AgentNode` / `AgentTreeSnapshotData`)
//! accept untrusted input by default — callers at the deserialize site MUST:
//!
//! - Validate `AgentId.0` against `^[A-Za-z0-9_-]{1,64}$` before using as a
//!   HashMap key to prevent unicode-confusable spoofing, cross-agent
//!   collision, and unbounded key insertion DoS. The `pub String` tuple field
//!   is intentional for v2 narrow scope; typed helper constructors
//!   (`TryFrom<&str>`, `AgentId::new`) are deferred to MODULE-005
//!   concrete-impl.
//! - Reject `AgentNode.workspace_path` values containing `..`, absolute
//!   symlink targets outside the workspace root, or non-canonical components
//!   BEFORE persisting. The derived `Deserialize` impl will happily
//!   reconstruct `workspace_path: "../../etc/passwd"` from attacker-crafted
//!   JSON; path-traversal defense is downstream.
//! - Bound `AgentTreeSnapshotData.nodes.len()` (recommended ≤ 1024) and
//!   map-field sizes at the consumer edge — serde does not enforce these.
//! - `Capability.params: CapParams(serde_json::Value)` is transparent and
//!   unbounded by type. Callers deserializing `Capability` from untrusted
//!   JSON MUST cap both tree depth (recommended ≤ 16 levels) and total
//!   byte size (recommended ≤ 4 KiB per CapParams) BEFORE handing the
//!   materialized value to `GrantCheck::check`. `serde_json`'s default
//!   128-level recursion limit still permits multi-megabyte `Value` trees;
//!   a hostile manifest supplying `{"a":{"a":{"a":...}}}` nested thousands
//!   of elements deep will pass type checking and exhaust memory in the
//!   L1 authorization gate. CapParams itself is a Slice I type
//!   (see [`crate::capability::CapParams`]); this invariant is restated
//!   here because `Capability` is the first consumer surface that a
//!   Slice AC v2 downstream implementer encounters.

use crate::capability::{CapParams, CapabilityId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// Agent identifier. Canonical declaration: MODULE-005 §2.3 head (landed by
/// /dev Slice AC v2). Newtype-over-String matching Slice I `CapabilityId`
/// precedent for HashMap-key usage; wire format is `#[serde(transparent)]`
/// bare string. Backing string format (UUID v4 / ULID / opaque) is a
/// MODULE-005 concrete-impl choice — v2 only ships the narrow derive set.
///
/// # Implementer Invariants
///
/// 1. **Bounded length**: producers MUST enforce an upper bound (recommended
///    ≤ 64 bytes per AgentId; same guideline as `RunBudget::check` agent_id
///    validation) before persisting.
/// 2. **Charset**: validate against `^[A-Za-z0-9_-]{1,64}$` before using as a
///    HashMap key to prevent cross-agent collision, unicode-confusable
///    spoofing, or log-injection.
/// 3. **Public field**: the tuple-field `.0` is public to minimize v2
///    ergonomic surface. Helper impls (`new`, `as_str`, `Display`,
///    `AsRef<str>`, `Borrow<str>`, `From<&str>`, `From<String>`) are deferred
///    to MODULE-005 concrete-impl slice — matches the narrow scope decision
///    documented in /dev Slice AC v2 plan §3.14.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

/// Agent role in the hierarchy. Canonical source: MODULE-005 §2.3:383-387.
///
/// - `Root` — workspace-level, the sole top-level agent per §1.2.
/// - `Child` — spawned by a parent via `spawn-child`, has its own workspace subdir.
/// - `Sub` — ephemeral delegate spawned via `spawn-sub`, lifetime tied to parent turn.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentKind {
    Root,
    Child,
    Sub,
}

/// Agent runtime status. Canonical source: MODULE-005 §2.3:418-427.
/// Four variants, no payloads.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentStatus {
    /// Agent is registered and eligible to run its agent-loop.
    Active,
    /// Agent is paused (manually or by pause-run cascade); mailbox still receives.
    Paused,
    /// Agent terminated cleanly by parent `terminate-child`.
    Terminated,
    /// Agent terminated due to unrecoverable error / cascade failure.
    Failed,
}

/// Runtime projection of a per-agent granted capability. Canonical source:
/// MODULE-005 §2.3:456-459. Narrow read-only view over MODULE-013's full
/// Grant record (which adds provenance, issuer, TTL, delegation chain,
/// revocation metadata not needed by tree consumers).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    pub id: CapabilityId,
    pub params: CapParams,
}

/// Transient per-agent runtime snapshot passed to MODULE-010 context assembly
/// (`AssemblyContext.prior_state`). Canonical source: MODULE-005 §2.3:420-430.
/// Kept small so every pre-turn `assemble()` call can clone cheaply.
/// Consumers MUST treat as read-only; mutation goes through MODULE-005's
/// own tree writes.
///
/// **Implementer Invariants**: bounded `current_task_id` / `current_run_id`
/// lengths (recommended ≤ 64 bytes each); `iteration` / `turn_counter` use
/// `saturating_add` semantics to prevent overflow in long-lived agents.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentState {
    pub agent_id: String,
    pub status: AgentStatus,
    pub current_task_id: Option<String>,
    pub current_run_id: Option<String>,
    /// Iteration count within the current run (0 before first turn).
    pub iteration: u32,
    /// Monotonic turn counter across the agent's lifetime.
    pub turn_counter: u64,
    pub last_handle_message_at: Option<SystemTime>,
}

/// Agent tree node — the in-memory representation of a single agent within
/// the `AgentTree` rooted at the workspace. Canonical declaration: MODULE-005
/// §2.3 (moved from §2.5 Data Models to §2.3 Interface block by /dev Slice AC
/// v2 because `AgentNode` is part of the `AgentTreeSnapshotData.nodes:
/// Vec<AgentNode>` contract surface).
///
/// **Implementer Invariants**: `workspace_path` MUST be validated against
/// path-traversal (canonicalize + reject ancestor escape) before persisting;
/// `capabilities` length MUST be bounded (recommended ≤ 64 per agent).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNode {
    pub id: AgentId,
    pub kind: AgentKind,
    pub parent: Option<AgentId>,
    pub workspace_path: PathBuf,
    pub capabilities: Vec<Capability>,
    pub template_ref: Option<String>,
    pub status: AgentStatus,
}

/// Read-only snapshot of the full agent tree. Canonical source: MODULE-005
/// §2.3:403-414. Consumers receive this via
/// [`AgentTreeSnapshot::snapshot`]; the HashMaps enable O(1) lookups during
/// pre-turn assembly, territory-rule checks, and Delegate inventory
/// rendering.
///
/// **Implementer Invariants**: `nodes` / `parent_of` / `children_of` /
/// `peer_slug_map` MUST be consistent (every `AgentId` key in `parent_of`
/// appears in `nodes`; `children_of[p]` contains exactly the ids with
/// `parent_of[_] == Some(p)`). `revision` monotonically increments on every
/// tree mutation — consumers use it for cache invalidation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTreeSnapshotData {
    pub nodes: Vec<AgentNode>,
    pub parent_of: std::collections::HashMap<AgentId, Option<AgentId>>,
    pub children_of: std::collections::HashMap<AgentId, Vec<AgentId>>,
    pub peer_slug_map:
        std::collections::HashMap<AgentId, std::collections::HashMap<String, AgentId>>,
    /// Monotonic revision number; increments on every tree mutation.
    pub revision: u64,
}

/// CONTRACT-040 — read-only agent tree navigation. Canonical source:
/// MODULE-005 §2.3:364-371. Consumed by MODULE-002 (territory hierarchy),
/// MODULE-006 (adjacent-level messaging whitelist), MODULE-007 (ancestry),
/// MODULE-008 (descendant run cascade), MODULE-010 (Delegate inventory),
/// MODULE-011 (memory scoping), MODULE-014 (agent-loop dispatch),
/// MODULE-015 (auto-namespace).
///
/// # Implementer Invariants
///
/// 1. **Non-blocking**: all methods are sync and must return promptly; no I/O.
/// 2. **Consistent snapshot**: successive calls within a single logical turn
///    MUST reflect the same tree state (per-turn read-snapshot semantics).
/// 3. **Identifier validation**: `agent_id: &str` is untyped; implementers
///    MUST whitelist-validate before using as HashMap key.
/// 4. **Bounded output**: `children_of` / `siblings_of` return bounded
///    `Vec<String>` (recommended ≤ 256 per agent).
pub trait AgentTreeReader: Send + Sync {
    fn parent_of(&self, agent_id: &str) -> Option<String>;
    fn children_of(&self, agent_id: &str) -> Vec<String>;
    fn siblings_of(&self, agent_id: &str) -> Vec<String>;
    fn agent_exists(&self, agent_id: &str) -> bool;
    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind>;
    fn capabilities(&self, agent_id: &str) -> Vec<Capability>;
}

/// CONTRACT-040 — full tree snapshot extension. Canonical source: MODULE-005
/// §2.3:373-375. Supertrait over [`AgentTreeReader`]; adds the
/// O(1)-HashMap-keyed snapshot that consumers need for bulk territory
/// queries and cache invalidation via `revision`.
///
/// # Implementer Invariants (in addition to AgentTreeReader's)
///
/// 1. **Snapshot atomicity**: the returned [`AgentTreeSnapshotData`] MUST be
///    consistent as of a single logical instant — no partial mutation
///    between `parent_of` / `children_of` / `peer_slug_map` population.
/// 2. **Bounded output**: `nodes.len()` is implementation-capped
///    (recommended ≤ 1024 agents per workspace).
pub trait AgentTreeSnapshot: AgentTreeReader {
    fn snapshot(&self) -> AgentTreeSnapshotData;
}
