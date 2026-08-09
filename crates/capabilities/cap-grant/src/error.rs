//! Error type + crate-internal `Result` alias for `cap-grant` (MODULE-013 Slice A).

use crate::data::GrantId;

/// Errors raised by every fallible cap-grant entry point.
///
/// Slice A variants:
/// - `NotFound` — grant id missing OR not in `Active` state (the two cases
///   are indistinguishable from the caller's standpoint and collapse into
///   one variant per spec §2.8 `grant-error::not-found`).
/// - `InvalidConfig` — YAML schema mismatch, capability/grantee charset
///   violation, oversized YAML.
/// - `Db` — SQLite errors propagated from `advance-database`.
/// - `Yaml` — `serde_yml` parse errors.
///
/// Slice B additions:
/// - `SubsetViolation` — runtime SubsetValidator failure (parameter does
///   not satisfy the parent grant's subset rule per MODULE-013 §1.4.3 /
///   PRD §5.7.4). Maps to spec §2.8 `grant-error::subset-violation`.
///   Returned by `SubsetValidator::validate` AND by the inline URL
///   pattern structural-separator gate (`<prefix>/*` form required;
///   free-form `*` would permit domain-prefix collision).
/// - `PresetNotFound` — preset name lookup failure (registry has no
///   matching built-in or custom-YAML preset). Maps to spec §2.8
///   `grant-error::preset-not-found`.
///
/// Slice C additions:
/// - `PermissionDenied` — caller-grantee mismatch on `narrow` / `apply_preset` /
///   `delegate_grant`. Maps to spec §2.8 `grant-error::permission-denied`.
///   Migrated narrow's + apply_preset's auth-mismatch from `SubsetViolation` →
///   `PermissionDenied` to align with the WIT spec's distinct error variant.
#[derive(Debug)]
pub enum CapGrantError {
    NotFound(GrantId),
    InvalidConfig(String),
    SubsetViolation(String),
    PresetNotFound(String),
    PermissionDenied(String),
    Db(advance_database::DbError),
    Yaml(serde_yml::Error),
}

impl std::fmt::Display for CapGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "grant not found: {id}"),
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::SubsetViolation(msg) => write!(f, "subset violation: {msg}"),
            Self::PresetNotFound(name) => write!(f, "preset not found: {name}"),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            Self::Db(e) => write!(f, "db error: {e}"),
            Self::Yaml(e) => write!(f, "yaml error: {e}"),
        }
    }
}

impl std::error::Error for CapGrantError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotFound(_)
            | Self::InvalidConfig(_)
            | Self::SubsetViolation(_)
            | Self::PresetNotFound(_)
            | Self::PermissionDenied(_) => None,
            Self::Db(e) => Some(e),
            Self::Yaml(e) => Some(e),
        }
    }
}

impl From<advance_database::DbError> for CapGrantError {
    fn from(e: advance_database::DbError) -> Self {
        Self::Db(e)
    }
}

impl From<serde_yml::Error> for CapGrantError {
    fn from(e: serde_yml::Error) -> Self {
        Self::Yaml(e)
    }
}

impl From<rusqlite::Error> for CapGrantError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(advance_database::DbError::Sqlite(e))
    }
}

/// Crate-internal `Result` alias used by every store / cascade / sqlite
/// method signature. The `register_cap_grant` public entry point uses the
/// explicit `std::result::Result<_, CapGrantError>` form to keep the error
/// type visible at the public API boundary.
pub type Result<T> = std::result::Result<T, CapGrantError>;
