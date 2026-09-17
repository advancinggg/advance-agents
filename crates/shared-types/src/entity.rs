//! Entity model port.
//!
//! Structured data lives ONLY in frontmatter (a file's own block, its inline `items[]`, or a
//! directory's `index.md`); SQLite is a derived projection rebuilt from the files. This module
//! is the dependency-inversion seam between the crates that produce rows (cap-fs projects a
//! normalized frontmatter document into [`EntityRow`]s), the crate that stores them
//! (`advance-database` implements [`EntityIndex`] over the workspace index DB) and the crate
//! that operates on them (`cap-data`). No SQL / rusqlite type leaks through here.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The host tool id every agent reaches the entity model through (`tool-invoke("data", …)`).
pub const DATA_TOOL_ID: &str = "data";

/// The L1 grant family the `data` tool checks (`GrantCheck::check(agent, "data", method, params)`).
/// Grants carry one param, `mode`, a csv of `read` / `write`.
pub const DATA_GRANT_CAPABILITY: &str = "data";

/// Hard cap on `EntityQuery::limit`; a larger limit is an error, never clamped silently.
pub const MAX_ENTITY_QUERY_LIMIT: usize = 1000;

/// Default `EntityQuery::limit`.
pub const DEFAULT_ENTITY_QUERY_LIMIT: usize = 100;

/// Prefix of every host-assigned entity id (`"e-"` + 26-char Crockford-base32 ULID).
pub const ENTITY_ID_PREFIX: &str = "e-";

/// Stable entity identity: host-assigned, survives moves / promotion / demotion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityId(pub String);

impl EntityId {
    /// `true` iff the id has the `e-` + 26-character ULID shape the host mints.
    pub fn is_well_formed(&self) -> bool {
        let Some(rest) = self.0.strip_prefix(ENTITY_ID_PREFIX) else {
            return false;
        };
        rest.len() == 26
            && rest.bytes().all(|b| {
                b.is_ascii_digit()
                    || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
            })
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which storage tier a row comes from (plan §1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityKind {
    /// A file with its own frontmatter (T1).
    File,
    /// An inline record in a parent file's `items[]` (T0).
    Item,
    /// A directory whose `index.md` frontmatter is the entity (T2).
    Dir,
}

/// One projected entity (a file, an inline item or a directory) as stored in the index.
///
/// The promoted columns (`status`, `due_at`, `starts_at`, `ends_at`, `priority`, `title`) are
/// copies of well-known fields so the index can filter and order on them; `fields` carries every
/// record field (effective values, i.e. after `inherit`) except `items`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityRow {
    pub id: EntityId,
    pub agent_id: String,
    /// Workspace-relative path of the file that holds the record (an inline item = its parent
    /// file's path; a directory entity = the directory path).
    pub path: String,
    /// `Some(id)` for an inline item (its position inside `path`'s `items[]`), `None` otherwise.
    pub anchor: Option<EntityId>,
    /// The inline item's parent file entity / a file's directory entity, when known.
    pub parent: Option<EntityId>,
    pub kind: EntityKind,
    pub r#type: String,
    pub title: Option<String>,
    /// Aspects the record has (a record has an aspect iff any of the aspect's key fields is
    /// present), sorted.
    pub aspects: Vec<String>,
    pub status: Option<String>,
    pub due_at: Option<DateTime<Utc>>,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub priority: Option<i64>,
    pub fields: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// One sort key of an [`EntityQuery`]; `field` is a record field name (`due`, `starts`,
/// `priority`, `title`, `status`, `updated_at` …). Null values always sort last.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderKey {
    pub field: String,
    pub ascending: bool,
}

/// An index query. Every filter is optional and filters are ANDed. Time windows are half-open
/// `[start, end)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityQuery {
    pub agent_id: String,
    #[serde(default)]
    pub parent: Option<EntityId>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub aspect: Option<String>,
    /// `status IN (…)`.
    #[serde(default)]
    pub status: Option<Vec<String>>,
    #[serde(default)]
    pub due_between: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Matched against the expanded occurrence table (repeat-aware).
    #[serde(default)]
    pub occurs_between: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// `due_between` OR `occurs_between` on the same window.
    #[serde(default)]
    pub any_between: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Empty = `updated_at` descending.
    #[serde(default)]
    pub order: Vec<OrderKey>,
    /// ≤ [`MAX_ENTITY_QUERY_LIMIT`].
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    DEFAULT_ENTITY_QUERY_LIMIT
}

impl EntityQuery {
    /// An empty query for `agent` with the default limit.
    pub fn for_agent(agent: &str) -> Self {
        Self {
            agent_id: agent.to_string(),
            parent: None,
            r#type: None,
            aspect: None,
            status: None,
            due_between: None,
            occurs_between: None,
            any_between: None,
            order: Vec::new(),
            limit: DEFAULT_ENTITY_QUERY_LIMIT,
        }
    }
}

/// Index failure, projected to a safe string (no SQL / driver types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityIndexError {
    /// A query parameter violates a bound (`limit` > max, unknown order field, …).
    InvalidQuery(String),
    /// Storage failure.
    Storage(String),
}

impl std::fmt::Display for EntityIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQuery(m) => write!(f, "invalid entity query: {m}"),
            Self::Storage(m) => write!(f, "entity index storage: {m}"),
        }
    }
}

impl std::error::Error for EntityIndexError {}

/// The derived projection of the entity model (plan §2.1 / §2.2).
#[async_trait]
pub trait EntityIndex: Send + Sync {
    /// Replace every row of `path` (the file row + its inline items) with `rows` and recompute
    /// the path's occurrences (`repeat` expansion, 366-day horizon).
    async fn replace_path(
        &self,
        agent_id: &str,
        path: &str,
        rows: Vec<EntityRow>,
    ) -> Result<(), EntityIndexError>;
    async fn delete_path(&self, agent_id: &str, path: &str) -> Result<(), EntityIndexError>;
    async fn get(
        &self,
        agent_id: &str,
        id: &EntityId,
    ) -> Result<Option<EntityRow>, EntityIndexError>;
    async fn query(&self, q: &EntityQuery) -> Result<Vec<EntityRow>, EntityIndexError>;
    /// Drop every row of `agent_id` (before a rebuild).
    async fn truncate(&self, agent_id: &str) -> Result<(), EntityIndexError>;
}

/// Projects one file's bytes into its entity rows. Implemented by cap-fs over the live
/// meta-schema; consumed by `advance-database`'s rebuild scanner (which cannot depend on
/// cap-fs) and by cap-data. `Ok(vec![])` = the file has no frontmatter / no records.
pub trait EntityProjector: Send + Sync {
    fn project(
        &self,
        agent_id: &str,
        path: &str,
        bytes: &[u8],
        updated_at: DateTime<Utc>,
    ) -> Result<Vec<EntityRow>, String>;
}

/// Convenience: the record's declared fields as a map (used by projections and tests).
pub fn fields_map(row: &EntityRow) -> BTreeMap<String, serde_json::Value> {
    match &row.fields {
        serde_json::Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_id_shape() {
        assert!(EntityId("e-01J9K3ZQ7A0000000000000000".into()).is_well_formed());
        assert!(!EntityId("e-01J9K3ZQ7A".into()).is_well_formed());
        assert!(!EntityId("01J9K3ZQ7A0000000000000000".into()).is_well_formed());
        assert!(!EntityId("e-01J9K3ZQ7A000000000000000I".into()).is_well_formed());
    }

    #[test]
    fn query_defaults() {
        let q = EntityQuery::for_agent("alice");
        assert_eq!(q.limit, DEFAULT_ENTITY_QUERY_LIMIT);
        assert!(q.order.is_empty());
        let round: EntityQuery =
            serde_json::from_value(serde_json::json!({ "agent_id": "alice" })).unwrap();
        assert_eq!(round, q);
    }
}
