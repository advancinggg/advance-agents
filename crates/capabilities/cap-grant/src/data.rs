//! Grant data model (MODULE-013 §1.4.1).
//!
//! Slice A defines a local `pub type ComponentId = String;` alias matching the
//! spec literal name (`shared-types::component` only exports `ComponentType` enum,
//! no `ComponentId` type). Future shared-types widening to a typed newtype is
//! non-breaking for cap-grant downstream code.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;

/// Slice-A-local alias matching the spec literal name (MODULE-013 §1.4.1,
/// PRD §A.18). Future shared-types widening to a typed newtype is
/// non-breaking for cap-grant downstream code.
pub type ComponentId = String;

/// Newtype over `String` — the canonical Grant identifier. Implements
/// `Borrow<str>` so `HashMap<GrantId, Grant>::get(&str)` works without
/// allocation.
///
/// For static-config grants Slice A uses deterministic ids of the form
/// `static:{grantee}:{capability}` (cold-start stability — see
/// `compile.rs::compile_from_path`). Dynamic grants (slice B+) will use
/// UUID v4.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GrantId(pub String);

impl GrantId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for GrantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for GrantId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<&str> for GrantId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for GrantId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantTtl {
    Once,
    Lifecycle,
    Persistent,
    Duration(u64),
    Until(DateTime<Utc>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantIssuer {
    Config,
    Parent(ComponentId),
    Resolver(String),
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantProvenance {
    StaticConfig,
    Delegated(GrantId),
    Requested,
    Preset(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantStatus {
    Active,
    Consumed,
    Expired,
    Revoked,
}

impl GrantStatus {
    /// Wire-format string used by the SQLite `grant_index.status` column
    /// and by `grant.expired.original_ttl` event payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapParam {
    pub key: String,
    pub value: String,
}

/// Canonical Grant record (MODULE-013 §1.4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: GrantId,
    pub grantee: ComponentId,
    pub capability: String,
    pub params: Vec<CapParam>,
    pub ttl: GrantTtl,
    pub issuer: GrantIssuer,
    pub provenance: GrantProvenance,
    pub status: GrantStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Slice B types (MODULE-013 §1.4.2 ResolverChain + §1.4.4 Presets + narrow op)
// ============================================================================

/// A capability + params + ttl tuple representing the *content* of a grant
/// before it is materialized as a [`Grant`] record. Used as the parameter
/// type for [`SubsetValidator::validate`] (subset.rs) and as the payload of
/// [`ResolverOutcome::Approve`] (resolver.rs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantDraft {
    pub capability: String,
    pub params: Vec<CapParam>,
    pub ttl: GrantTtl,
}

/// A request for a new grant flowing into [`ResolverChain::evaluate`]. The
/// WIT-level `grant-request` (spec §2.3) carries only `capability`, `params`,
/// `justification`; the runtime-internal `GrantRequest` adds `caller` (the
/// agent making the request) and `ttl` (the requested TTL) — these are
/// supplied by the WIT translation layer (Slice D) or directly by Slice-B
/// test fixtures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub caller: ComponentId,
    pub capability: String,
    /// `None` = "request whole capability" (matches WIT
    /// `option<list<cap-param>>` per spec §2.3).
    pub params: Option<Vec<CapParam>>,
    pub ttl: GrantTtl,
    pub justification: Option<String>,
}

/// 3-state output of a single [`Resolver::resolve`] call (MODULE-013 §1.4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolverOutcome {
    Approve(GrantDraft),
    Deny(String),
    Pending,
    Abstain,
}

/// 3-state output of [`ResolverChain::evaluate`] (MODULE-013 §1.4.2).
///
/// Distinct from `shared-types::capability::GrantDecision` (the 2-state
/// `Allow`/`Deny` invocation-gate type for CONTRACT-121). This enum is the
/// resolver-chain decision; the WIT layer (Slice D) translates it to the
/// 3-variant `grant-decision` WIT type (`approved` / `denied` / `pending`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainDecision {
    Approved(GrantId),
    Denied(String),
    Pending,
}
