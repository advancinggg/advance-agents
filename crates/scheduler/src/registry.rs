//! `ComponentRegistry` — Slice D SQLite-backed persistence (AC-07).
//!
//! Schema:
//! ```sql
//! CREATE TABLE IF NOT EXISTS components (
//!   seq INTEGER PRIMARY KEY AUTOINCREMENT,
//!   id TEXT NOT NULL UNIQUE,
//!   component_type TEXT NOT NULL,
//!   submit_config_json TEXT NOT NULL,
//!   submitter TEXT NOT NULL,
//!   submitted_at_ms INTEGER NOT NULL,
//!   interval_ms INTEGER,
//!   expected_next_fire_at_ms INTEGER,
//!   last_fire_at_ms INTEGER
//! );
//! ```
//!
//! `seq INTEGER PRIMARY KEY AUTOINCREMENT` gives stable monotonic insertion
//! ordering even across same-millisecond inserts; `id` becomes a UNIQUE
//! column with its own index. `list()` uses `ORDER BY seq ASC`.
//!
//! Path-confinement on `open_in(trusted_root, db_filename)`:
//! 1. Grammar gate on `db_filename`: `^[a-zA-Z0-9._-]+$`, reject leading-dot,
//!    reject `.` / `..` / empty.
//! 2. Canonicalize `trusted_root`; final_path = `canonical_trusted_root.join(db_filename)`;
//!    sanity-check `final_path.starts_with(canonical_trusted_root)`.
//! 3. `symlink_metadata(&final_path)` — if the path EXISTS and is a symlink,
//!    reject. Catches the static "attacker pre-planted symlink leaf" case.
//!
//! Residual TOCTOU between symlink_metadata and Connection::open is
//! documented in MODULE-014 §3.8 note (k); cross-platform openat2 hardening
//! is deferred to a follow-up slice.
//!
//! All rusqlite calls run inside `tokio::task::spawn_blocking` because the
//! rusqlite API is synchronous; this avoids blocking the Tokio runtime.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use advance_shared_types::component::ComponentType;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::observation_anchor::{RegistryAnchorTuple, VerifiedEmptyRegistryGenesis};
use crate::trigger_source::MAX_TRIGGER_NESTING_DEPTH;
use crate::types::{ComponentId, ComponentSubmitConfig, SpawnError, TriggerConfig};

/// Minimum recurring interval — adversarial-round-1 Critical-1 floor.
/// Defends against `interval_ms <= 0` creating a hot-loop in `catch_up_components`:
/// `now_ms.saturating_add(0)` keeps `expected_next_fire_at_ms <= now_ms` after every
/// dispatch, so the next catch-up pass re-fires immediately. The 100ms floor is the
/// same magnitude as the cron-driver tick budget; sub-100ms recurring components are
/// not a supported use case at this layer.
pub const MIN_RECURRING_INTERVAL_MS: i64 = 100;

/// Maximum submitter-id length stored in the registry — adversarial-round-2 Warning fix.
/// `ComponentId::new` caps `id` at `MAX_COMPONENT_ID_LEN` (256); reusing the same cap on
/// `submitter` prevents a direct registry caller from amplifying per-row storage with a
/// multi-MB submitter string.
pub const MAX_SUBMITTER_LEN: usize = 256;

/// Exact target DDL for the registry-owned component projection.  The same
/// literal is used both to install the table and to construct the independent
/// reference `sqlite_master` allowlist, so whitespace or constraint drift
/// cannot silently become the new accepted schema.
const OBSERVATION_COMPONENT_SCHEMA_SQL: &str = "DROP INDEX IF EXISTS idx_components_next_fire;
     DROP INDEX IF EXISTS idx_components_id;
     DROP TABLE components;
     CREATE TABLE components (
        seq INTEGER PRIMARY KEY AUTOINCREMENT CHECK (seq > 0),
        id TEXT NOT NULL UNIQUE CHECK (
            length(CAST(id AS BLOB)) BETWEEN 1 AND 256
        ),
        component_type TEXT NOT NULL CHECK (
            component_type IN ('cron','watcher','daemon','task')
        ),
        submit_config_json TEXT NOT NULL CHECK (json_valid(submit_config_json)),
        submitter TEXT NOT NULL,
        submitted_at_ms INTEGER NOT NULL CHECK (submitted_at_ms >= 0),
        interval_ms INTEGER CHECK (interval_ms IS NULL OR interval_ms > 0),
        expected_next_fire_at_ms INTEGER CHECK (
            expected_next_fire_at_ms IS NULL OR expected_next_fire_at_ms >= 0
        ),
        last_fire_at_ms INTEGER CHECK (
            last_fire_at_ms IS NULL OR last_fire_at_ms >= 0
        ),
        sensitive_params BLOB NOT NULL CHECK (
            typeof(sensitive_params)='blob' AND
            length(sensitive_params) BETWEEN 4 AND 8452
        ),
        identity_incarnation INTEGER NOT NULL CHECK (identity_incarnation > 0),
        declaration_digest BLOB NOT NULL CHECK (
            typeof(declaration_digest)='blob' AND length(declaration_digest)=32
        ),
        lifecycle_state TEXT NOT NULL CHECK (
            lifecycle_state IN ('live','terminating','tombstoned')
        ),
        catalog_visible INTEGER NOT NULL CHECK (catalog_visible IN (0,1)),
        operation_id TEXT CHECK (
            operation_id IS NULL OR
            length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 256
        ),
        tombstoned_at_ms INTEGER CHECK (
            tombstoned_at_ms IS NULL OR tombstoned_at_ms >= 0
        ),
        retain_until_ms INTEGER CHECK (
            retain_until_ms IS NULL OR retain_until_ms >= 0
        ),
        CHECK (lifecycle_state='live' OR catalog_visible=0),
        CHECK (
            (lifecycle_state='live' AND tombstoned_at_ms IS NULL AND
             retain_until_ms IS NULL)
            OR
            (lifecycle_state='terminating' AND operation_id IS NOT NULL AND
             tombstoned_at_ms IS NULL AND retain_until_ms IS NOT NULL)
            OR
            (lifecycle_state='tombstoned' AND operation_id IS NOT NULL AND
             tombstoned_at_ms IS NOT NULL AND retain_until_ms >= tombstoned_at_ms)
        ),
        FOREIGN KEY(operation_id)
            REFERENCES observation_identity_operations(operation_id)
            ON DELETE RESTRICT
     ) STRICT;
     CREATE INDEX idx_components_next_fire ON components(expected_next_fire_at_ms);
     CREATE INDEX idx_components_id ON components(id);";

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: Option<String>,
}

const OBSERVATION_SCHEMA_FINGERPRINT_DOMAIN: &[u8] =
    b"advance.contract218.sqlite-master-schema.v1\0";
// Independent KAT over the canonical encoding documented in MODULE-014.  A
// deliberate DDL change must update the ratified literal rather than silently
// teaching the verifier that the installer is always correct.
const OBSERVATION_SCHEMA_FINGERPRINT: [u8; 32] = [
    0x73, 0x14, 0x5f, 0xc0, 0xd5, 0x0d, 0xbd, 0x1b, 0x2b, 0x73, 0x75, 0x62, 0x95, 0xce, 0x85, 0x78,
    0xe5, 0xa5, 0x28, 0x40, 0x33, 0x59, 0xe6, 0x1a, 0x5b, 0x5d, 0xca, 0xf9, 0x19, 0x0a, 0x73, 0xd0,
];

/// SQLite-backed component registry. Cloned via `Arc` semantics is unnecessary
/// since the struct holds its connection inside an `Arc<Mutex<Connection>>`;
/// callers wrap `ComponentRegistry` in `Arc` if they need shared ownership.
pub struct ComponentRegistry {
    pub(crate) conn: Arc<Mutex<Connection>>,
    db_path: PathBuf,
    /// One lock orders every CONTRACT-218 provider mutation over this exact
    /// connection.  The external anchor transition is driven while this lock
    /// is held; there is no second provider-side write lane.
    pub(crate) observation_mutation_lock: Arc<Mutex<()>>,
    observation_provider_claimed: Arc<AtomicBool>,
}

/// A row stored in the registry. `interval_ms` is `Some(N)` for recurring
/// components (cron / daemon / recurring watcher) and `None` for one-shots
/// (task / non-recurring trigger). `expected_next_fire_at_ms` is `None` when
/// no fire is currently scheduled; `last_fire_at_ms` is `None` until the
/// first fire is recorded.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComponentRegistryRow {
    pub id: ComponentId,
    pub component_type: ComponentType,
    pub submit_config: ComponentSubmitConfig,
    pub submitter: String,
    pub submitted_at_ms: i64,
    pub interval_ms: Option<i64>,
    pub expected_next_fire_at_ms: Option<i64>,
    pub last_fire_at_ms: Option<i64>,
}

/// Registry-layer errors. Per-row dispatch errors (HookError) from
/// `catch_up_components` live in `CatchupOutcome` fields, NOT here.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("io error: {0}")]
    Io(String),
    #[error("sql error: {0}")]
    Sql(String),
    #[error("serde error: {0}")]
    Serde(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("path confinement violation: {0}")]
    PathConfinement(String),
    #[error("invalid filename: {0}")]
    InvalidFilename(String),
    #[error("invalid observation-identity state: {0}")]
    ObservationState(String),
    #[error("observation-identity recovery required: {0}")]
    ObservationRecoveryRequired(String),
    #[error("observation-identity capacity exceeded: {0}")]
    ObservationCapacityExceeded(String),
}

impl From<rusqlite::Error> for RegistryError {
    fn from(e: rusqlite::Error) -> Self {
        RegistryError::Sql(e.to_string())
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(e: serde_json::Error) -> Self {
        RegistryError::Serde(e.to_string())
    }
}

impl ComponentRegistry {
    /// Open or create a SQLite-backed registry. See module docstring for
    /// path-confinement defense layers.
    pub async fn open_in(trusted_root: &Path, db_filename: &str) -> Result<Self, RegistryError> {
        // Layer 1: grammar gate on db_filename.
        validate_db_filename(db_filename)?;

        // Layer 2: canonicalize trusted_root + sanity-check.
        let canonical_root = trusted_root
            .canonicalize()
            .map_err(|e| RegistryError::Io(format!("canonicalize trusted_root: {e}")))?;
        if !canonical_root.is_dir() {
            return Err(RegistryError::PathConfinement(format!(
                "trusted_root {} is not a directory",
                canonical_root.display()
            )));
        }
        let final_path: PathBuf = canonical_root.join(db_filename);
        if !final_path.starts_with(&canonical_root) {
            return Err(RegistryError::PathConfinement(format!(
                "joined path {} escapes trusted_root {}",
                final_path.display(),
                canonical_root.display()
            )));
        }

        // Layer 3: symlink-leaf reject (only if the path EXISTS).
        if let Ok(meta) = tokio::fs::symlink_metadata(&final_path).await {
            if meta.file_type().is_symlink() {
                return Err(RegistryError::PathConfinement(format!(
                    "registry leaf {} is a symlink; rejected",
                    final_path.display()
                )));
            }
        }

        // Open the SQLite connection (sync API) on a blocking thread.
        let db_path = final_path.clone();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, RegistryError> {
            let mut c = Connection::open(&final_path)?;
            c.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;",
            )?;
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS components (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    component_type TEXT NOT NULL,
                    submit_config_json TEXT NOT NULL,
                    submitter TEXT NOT NULL,
                    submitted_at_ms INTEGER NOT NULL,
                    interval_ms INTEGER,
                    expected_next_fire_at_ms INTEGER,
                    last_fire_at_ms INTEGER,
                    sensitive_params BLOB CHECK (
                        sensitive_params IS NULL OR
                        (typeof(sensitive_params)='blob' AND
                         length(sensitive_params) BETWEEN 4 AND 8452)
                    ),
                    identity_incarnation INTEGER CHECK (
                        identity_incarnation IS NULL OR identity_incarnation > 0
                    ),
                    declaration_digest BLOB CHECK (
                        declaration_digest IS NULL OR
                        (typeof(declaration_digest)='blob' AND length(declaration_digest)=32)
                    ),
                    lifecycle_state TEXT NOT NULL DEFAULT 'live' CHECK (
                        lifecycle_state IN ('live','terminating','tombstoned')
                    ),
                    catalog_visible INTEGER NOT NULL DEFAULT 1 CHECK (
                        catalog_visible IN (0,1)
                    ),
                    operation_id TEXT,
                    tombstoned_at_ms INTEGER,
                    retain_until_ms INTEGER,
                    CHECK (lifecycle_state='live' OR catalog_visible=0)
                );
                CREATE INDEX IF NOT EXISTS idx_components_next_fire
                    ON components(expected_next_fire_at_ms);
                CREATE INDEX IF NOT EXISTS idx_components_id
                    ON components(id);",
            )?;
            // Preserve an exact nonempty nine-column legacy preimage until
            // the authenticated stopped migration has hashed it.  Creating
            // target foundation tables here would mutate the file inventory
            // before the migration block can be checked.
            if !has_nonempty_exact_legacy_component_schema(&c)? {
                create_observation_foundation_schema(&mut c)?;
                let anchored: i64 = c.query_row(
                    "SELECT COUNT(*) FROM observation_identity_ledger WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )?;
                if anchored != 0 {
                    verify_observation_schema_fingerprint(&c)?;
                }
            }
            verify_connection_pragmas(&c)?;
            Ok(c)
        })
        .await
        .map_err(|e| RegistryError::Io(format!("spawn_blocking join: {e}")))??;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path,
            observation_mutation_lock: Arc::new(Mutex::new(())),
            observation_provider_claimed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Canonical database path for composition-owned external anchoring and
    /// operational diagnostics. This grants no connection or mutation access.
    pub fn database_path(&self) -> &Path {
        &self.db_path
    }

    /// Issue the move-only greenfield witness only after the caller has taken
    /// this registry's mutation lock and the exact connected database has
    /// passed a complete emptiness scan.
    pub(crate) fn issue_verified_empty_genesis(
        &self,
        conn: &Connection,
        genesis: RegistryAnchorTuple,
    ) -> Result<VerifiedEmptyRegistryGenesis, RegistryError> {
        let connected_path: String = conn.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )?;
        let connected_path = PathBuf::from(connected_path)
            .canonicalize()
            .map_err(|error| {
                RegistryError::Io(format!("canonicalize connected registry: {error}"))
            })?;
        let expected_path = self
            .db_path
            .canonicalize()
            .map_err(|error| RegistryError::Io(format!("canonicalize registry path: {error}")))?;
        if connected_path != expected_path {
            return Err(RegistryError::ObservationRecoveryRequired(
                "genesis scan was not run over the claimed registry database".to_owned(),
            ));
        }

        for table in [
            "components",
            "observation_identity_operations",
            "observation_identities",
            "observation_identity_authority",
            "observation_identity_operation_members",
            "observation_previsible_activations",
            "observation_termination_finalizations",
            "observation_carrier_migrations",
            "observation_carrier_migration_rows",
            "observation_persisted_keyring_entries",
            "observation_retained_carrier_metadata",
            "observation_identity_ledger",
        ] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            let count: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
            if count != 0 {
                return Err(RegistryError::ObservationRecoveryRequired(
                    "greenfield witness requires an empty component/identity registry".to_owned(),
                ));
            }
        }
        let previsible_capacity: (i64, i64, i64) = conn.query_row(
            "SELECT row_count,actual_encoded_bytes,future_reserved_bytes
             FROM observation_previsible_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let finalize_capacity: (i64, i64, i64) = conn.query_row(
            "SELECT row_count,actual_encoded_bytes,future_reserved_bytes
             FROM observation_termination_finalize_capacity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if previsible_capacity != (0, 0, 0) || finalize_capacity != (0, 0, 0) {
            return Err(RegistryError::ObservationRecoveryRequired(
                "greenfield witness encountered nonzero capacity accounting".to_owned(),
            ));
        }
        let workspace_root = expected_path.parent().ok_or_else(|| {
            RegistryError::ObservationRecoveryRequired(
                "registry database has no canonical workspace parent".to_owned(),
            )
        })?;
        VerifiedEmptyRegistryGenesis::from_verified_empty_registry(
            genesis,
            workspace_root,
            &expected_path,
        )
        .map_err(|error| RegistryError::ObservationRecoveryRequired(error.to_string()))
    }

    /// Claim the one C218 provider/view allowed for this registry object.
    pub(crate) fn claim_observation_provider(&self) -> Result<(), RegistryError> {
        self.observation_provider_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| {
                RegistryError::ObservationState(
                    "a CONTRACT-218 provider is already attached to this registry".to_owned(),
                )
            })
    }

    pub(crate) fn release_observation_provider(&self) {
        self.observation_provider_claimed
            .store(false, Ordering::Release);
    }

    /// Insert a new component row. Maps `id` UNIQUE-constraint violations to
    /// `AlreadyExists`; other SQL errors propagate as `Sql(msg)`.
    ///
    /// **Webhook secret redaction (Slice D audit-Round-1 Critical fix)**: per
    /// `types.rs:646-655`, `WebhookConfig.secret` is documented as MUST be
    /// encrypted before any persistence path. Slice D's registry layer does
    /// not encrypt — instead, the insert path redacts secrets to `None`
    /// before serialization. Callers who need to recover the secret should
    /// keep it in a separate vault-backed reference. Defense applies
    /// recursively to nested `AnyOf` trees.
    pub async fn insert(
        &self,
        submitter: &str,
        cfg: &ComponentSubmitConfig,
        interval_ms: Option<i64>,
    ) -> Result<(), RegistryError> {
        if self.observation_provider_claimed.load(Ordering::Acquire) {
            return Err(RegistryError::ObservationState(
                "component insertion must use the anchored CONTRACT-218 provider while attached"
                    .to_owned(),
            ));
        }
        // Adversarial-round-2 Warning fix: cap submitter length to prevent
        // memory amplification via multi-MB submitter strings.
        if submitter.len() > MAX_SUBMITTER_LEN {
            return Err(RegistryError::InvalidFilename(format!(
                "submitter length {} exceeds MAX_SUBMITTER_LEN {MAX_SUBMITTER_LEN}",
                submitter.len()
            )));
        }
        // Adversarial-round-1 Critical-1 fix: validate interval_ms floor.
        // interval_ms <= 0 would create a hot-loop in catch_up_components
        // (record_fire computes next_ts = now_ms + 0 = now_ms; next catch-up
        // pass re-fires immediately).
        if let Some(iv) = interval_ms {
            if iv < MIN_RECURRING_INTERVAL_MS {
                return Err(RegistryError::InvalidFilename(format!(
                    "interval_ms {iv} below MIN_RECURRING_INTERVAL_MS {MIN_RECURRING_INTERVAL_MS}"
                )));
            }
        }
        let id = cfg.id.clone();
        let component_type = component_type_to_str(&cfg.component_type);
        // Adversarial-round-1 Critical-2 fix: redaction walker is now
        // depth-capped via MAX_TRIGGER_NESTING_DEPTH=8. Attacker-controlled
        // deeply-nested AnyOf trees that bypass submit-component admission
        // (any direct registry caller) cannot stack-overflow this thread.
        let mut cfg_for_storage = cfg.clone();
        redact_webhook_secrets_in_trigger(&mut cfg_for_storage.trigger, 0)?;
        let submit_config_json = serde_json::to_string(&cfg_for_storage)?;
        let submitter = submitter.to_owned();
        let submitted_at_ms = crate::types::now_unix_ms();

        let conn = Arc::clone(&self.conn);
        let mutation_lock = Arc::clone(&self.observation_mutation_lock);
        let provider_claimed = Arc::clone(&self.observation_provider_claimed);
        let id_for_err = id.clone();
        tokio::task::spawn_blocking(move || -> Result<(), RegistryError> {
            let _mutation_guard = mutation_lock.blocking_lock();
            let conn = conn.blocking_lock();
            reject_unanchored_security_write(&conn, provider_claimed.load(Ordering::Acquire))?;
            let result = conn.execute(
                "INSERT OR ABORT INTO components
                    (id, component_type, submit_config_json, submitter,
                     submitted_at_ms, interval_ms, expected_next_fire_at_ms,
                     last_fire_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL)",
                params![
                    id,
                    component_type,
                    submit_config_json,
                    submitter,
                    submitted_at_ms,
                    interval_ms
                ],
            );
            match result {
                Ok(_) => Ok(()),
                Err(rusqlite::Error::SqliteFailure(ffi_err, _msg))
                    if matches!(ffi_err.code, rusqlite::ErrorCode::ConstraintViolation) =>
                {
                    // id UNIQUE constraint violation → AlreadyExists.
                    Err(RegistryError::AlreadyExists(id_for_err))
                }
                Err(e) => Err(e.into()),
            }
        })
        .await
        .map_err(|e| RegistryError::Io(format!("spawn_blocking join: {e}")))?
    }

    /// Fetch a row by id. Returns `Ok(None)` if not found (NOT an error).
    pub async fn get(&self, id: &str) -> Result<Option<ComponentRegistryRow>, RegistryError> {
        let id = id.to_owned();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(
            move || -> Result<Option<ComponentRegistryRow>, RegistryError> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT id, component_type, submit_config_json, submitter,
                        submitted_at_ms, interval_ms, expected_next_fire_at_ms,
                        last_fire_at_ms
                 FROM components
                 WHERE id = ?1 AND lifecycle_state='live' AND catalog_visible=1",
                )?;
                let mut rows = stmt.query(params![id])?;
                match rows.next()? {
                    Some(row) => Ok(Some(row_to_registry_row(row)?)),
                    None => Ok(None),
                }
            },
        )
        .await
        .map_err(|e| RegistryError::Io(format!("spawn_blocking join: {e}")))?
    }

    /// List all rows in stable insertion order (`ORDER BY seq ASC`).
    pub async fn list(&self) -> Result<Vec<ComponentRegistryRow>, RegistryError> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(
            move || -> Result<Vec<ComponentRegistryRow>, RegistryError> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT id, component_type, submit_config_json, submitter,
                        submitted_at_ms, interval_ms, expected_next_fire_at_ms,
                        last_fire_at_ms
                 FROM components
                 WHERE lifecycle_state='live' AND catalog_visible=1
                 ORDER BY seq ASC",
                )?;
                let mut rows = stmt.query([])?;
                let mut out = Vec::new();
                while let Some(row) = rows.next()? {
                    out.push(row_to_registry_row(row)?);
                }
                Ok(out)
            },
        )
        .await
        .map_err(|e| RegistryError::Io(format!("spawn_blocking join: {e}")))?
    }

    /// Wave-20 (MODULE-012-AC-10 source): snapshot every component's
    /// `sensitive_params`, keyed by component id (which the scheduler emitters
    /// stamp as `Event.agent_id`). Only components declaring a NON-EMPTY list are
    /// included. Consumed by the cli `RegistrySensitiveParamsSource` boot snapshot
    /// feeding the MODULE-019 EventBus redaction seam. **DORMANT in production**:
    /// the WIT `submit-component` path does not carry `sensitive_params`, so the
    /// snapshot is empty unless set out-of-band.
    pub async fn sensitive_params_snapshot(
        &self,
    ) -> Result<std::collections::HashMap<String, Vec<String>>, RegistryError> {
        let rows = self.list().await?;
        let mut out = std::collections::HashMap::new();
        for row in rows {
            if !row.submit_config.sensitive_params.is_empty() {
                out.insert(
                    row.id.as_str().to_string(),
                    row.submit_config.sensitive_params.clone(),
                );
            }
        }
        Ok(out)
    }

    /// Delete a row by id. Idempotent: missing id returns Ok (no error).
    pub async fn delete(&self, id: &str) -> Result<(), RegistryError> {
        if self.observation_provider_claimed.load(Ordering::Acquire) {
            return Err(RegistryError::ObservationState(
                "component deletion must use the anchored CONTRACT-218 provider while attached"
                    .to_owned(),
            ));
        }
        let id = id.to_owned();
        let conn = Arc::clone(&self.conn);
        let mutation_lock = Arc::clone(&self.observation_mutation_lock);
        let provider_claimed = Arc::clone(&self.observation_provider_claimed);
        tokio::task::spawn_blocking(move || -> Result<(), RegistryError> {
            let _mutation_guard = mutation_lock.blocking_lock();
            let conn = conn.blocking_lock();
            reject_unanchored_security_write(&conn, provider_claimed.load(Ordering::Acquire))?;
            conn.execute("DELETE FROM components WHERE id = ?1", params![id])?;
            Ok(())
        })
        .await
        .map_err(|e| RegistryError::Io(format!("spawn_blocking join: {e}")))?
    }

    /// Update `expected_next_fire_at_ms` for a component. `None` clears the
    /// schedule (i.e. one-shot completed or recurring paused).
    pub async fn set_expected_next_fire(
        &self,
        id: &str,
        ts_ms: Option<i64>,
    ) -> Result<(), RegistryError> {
        let id = id.to_owned();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<(), RegistryError> {
            let conn = conn.blocking_lock();
            let n = conn.execute(
                "UPDATE components SET expected_next_fire_at_ms = ?1
                 WHERE id = ?2 AND lifecycle_state='live' AND catalog_visible=1",
                params![ts_ms, id],
            )?;
            if n == 0 {
                // Adversarial-round-1 Warning-4: do NOT echo full attacker-controlled
                // id back in the error message. Use a fixed string so the error
                // cannot serve as an existence oracle for guess-attacks across the id space.
                return Err(RegistryError::NotFound(
                    "<id not found in registry>".to_owned(),
                ));
            }
            Ok(())
        })
        .await
        .map_err(|e| RegistryError::Io(format!("spawn_blocking join: {e}")))?
    }

    /// Record a fire event: updates `last_fire_at_ms` to `fire_ts_ms` and
    /// `expected_next_fire_at_ms` to `next_ts_ms` (`None` clears the next-fire
    /// schedule).
    pub async fn record_fire(
        &self,
        id: &str,
        fire_ts_ms: i64,
        next_ts_ms: Option<i64>,
    ) -> Result<(), RegistryError> {
        let id = id.to_owned();
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || -> Result<(), RegistryError> {
            let conn = conn.blocking_lock();
            let n = conn.execute(
                "UPDATE components SET last_fire_at_ms = ?1, expected_next_fire_at_ms = ?2
                 WHERE id = ?3 AND lifecycle_state='live' AND catalog_visible=1",
                params![fire_ts_ms, next_ts_ms, id],
            )?;
            if n == 0 {
                return Err(RegistryError::NotFound(
                    "<id not found in registry>".to_owned(),
                ));
            }
            Ok(())
        })
        .await
        .map_err(|e| RegistryError::Io(format!("spawn_blocking join: {e}")))?
    }
}

fn verify_connection_pragmas(conn: &Connection) -> Result<(), RegistryError> {
    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 || foreign_keys != 1 {
        return Err(RegistryError::ObservationRecoveryRequired(format!(
            "required SQLite pragmas not active (journal_mode={journal_mode}, synchronous={synchronous}, foreign_keys={foreign_keys})"
        )));
    }
    Ok(())
}

/// Replace the empty legacy Slice-D component table with the exact strict
/// CONTRACT-218 target shape.  Nonempty legacy input is deliberately not
/// copied or guessed here; it requires the authenticated migration workflow.
pub(crate) fn activate_observation_component_schema(
    conn: &Connection,
) -> Result<(), RegistryError> {
    activate_observation_component_schema_inner(conn, false)
}

/// Rebuild a nonempty legacy table only after the scheduler migration owner
/// has independently decoded and authenticated every source row.
pub(crate) fn migrate_legacy_component_schema(conn: &Connection) -> Result<(), RegistryError> {
    activate_observation_component_schema_inner(conn, true)
}

fn activate_observation_component_schema_inner(
    conn: &Connection,
    authenticated_nonempty_migration: bool,
) -> Result<(), RegistryError> {
    let mut stmt = conn.prepare("PRAGMA table_info(components)")?;
    let mut rows = stmt.query([])?;
    let mut sensitive_not_null = false;
    let mut incarnation_not_null = false;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        let not_null: i64 = row.get(3)?;
        if name == "sensitive_params" {
            sensitive_not_null = not_null == 1;
        } else if name == "identity_incarnation" {
            incarnation_not_null = not_null == 1;
        }
    }
    drop(rows);
    drop(stmt);
    if sensitive_not_null && incarnation_not_null {
        return verify_observation_schema_fingerprint(conn);
    }
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM components", [], |row| row.get(0))?;
    if count != 0 && !authenticated_nonempty_migration {
        return Err(RegistryError::ObservationRecoveryRequired(
            "nonempty legacy component registry requires authenticated migration".to_owned(),
        ));
    }
    conn.execute_batch(OBSERVATION_COMPONENT_SCHEMA_SQL)?;
    verify_observation_schema_fingerprint(conn)
}

/// Install the durable CONTRACT-218 provider foundation in the existing
/// ComponentRegistry database.  The external selector/bundle is intentionally
/// not represented here; it is owned by MODULE-001 and injected through
/// `RegistryAnchorTransaction`.
pub(crate) fn create_observation_foundation_schema(conn: &Connection) -> Result<(), RegistryError> {
    conn.execute_batch(include_str!("observation_schema.sql"))?;
    Ok(())
}

/// Verify the exact persistent SQLite object graph used by the anchored
/// observation registry.  Row roots alone cannot authenticate CHECK/FK/STRICT
/// clauses, indexes, or triggers: an offline-added trigger could otherwise
/// turn the next legitimate anchored write into an authenticated rogue row.
///
/// The allowlist is generated once from an independent in-memory database
/// using the same immutable target DDL.  We compare every `sqlite_master`
/// object, including auto-indexes and `sqlite_sequence`; therefore missing,
/// weakened, reordered/rebuilt, or additional tables/indexes/triggers fail
/// before catalog visibility or mutation.
pub(crate) fn verify_observation_schema_fingerprint(
    conn: &Connection,
) -> Result<(), RegistryError> {
    static EXPECTED: OnceLock<Result<Vec<CanonicalSchemaObject>, String>> = OnceLock::new();
    let expected = EXPECTED.get_or_init(|| {
        let reference = Connection::open_in_memory().map_err(|error| error.to_string())?;
        reference
            .execute_batch("CREATE TABLE components (seq INTEGER);")
            .map_err(|error| error.to_string())?;
        create_observation_foundation_schema(&reference).map_err(|error| error.to_string())?;
        reference
            .execute_batch(OBSERVATION_COMPONENT_SCHEMA_SQL)
            .map_err(|error| error.to_string())?;
        let objects =
            read_canonical_schema_objects(&reference).map_err(|error| error.to_string())?;
        let fingerprint = canonical_schema_fingerprint(&objects)?;
        if fingerprint != OBSERVATION_SCHEMA_FINGERPRINT {
            return Err(format!(
                "canonical observation DDL differs from pinned fingerprint: {fingerprint:?}"
            ));
        }
        Ok(objects)
    });
    let expected = expected.as_ref().map_err(|error| {
        RegistryError::ObservationRecoveryRequired(format!(
            "canonical observation schema reference failed: {error}"
        ))
    })?;
    let observed = read_canonical_schema_objects(conn)?;
    if observed != *expected {
        let first_difference = observed
            .iter()
            .zip(expected.iter())
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| observed.len().min(expected.len()));
        return Err(RegistryError::ObservationRecoveryRequired(format!(
            "observation sqlite_master fingerprint mismatch at object {first_difference} (observed {}, expected {})",
            observed.len(),
            expected.len()
        )));
    }
    Ok(())
}

fn canonical_schema_fingerprint(objects: &[CanonicalSchemaObject]) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(OBSERVATION_SCHEMA_FINGERPRINT_DOMAIN);
    let count = u32::try_from(objects.len())
        .map_err(|_| "sqlite_master object count exceeds u32".to_owned())?;
    hasher.update(count.to_be_bytes());
    for object in objects {
        hash_schema_field(&mut hasher, object.object_type.as_bytes())?;
        hash_schema_field(&mut hasher, object.name.as_bytes())?;
        hash_schema_field(&mut hasher, object.table_name.as_bytes())?;
        match object.sql.as_deref() {
            None => hasher.update([0]),
            Some(sql) => {
                hasher.update([1]);
                hash_schema_field(&mut hasher, sql.as_bytes())?;
            }
        }
    }
    Ok(hasher.finalize().into())
}

fn hash_schema_field(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), String> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| "sqlite_master field exceeds u32".to_owned())?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn read_canonical_schema_objects(
    conn: &Connection,
) -> Result<Vec<CanonicalSchemaObject>, RegistryError> {
    let mut statement = conn.prepare(
        "SELECT type,name,tbl_name,sql
         FROM sqlite_master
         ORDER BY type COLLATE BINARY,name COLLATE BINARY,tbl_name COLLATE BINARY",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok(CanonicalSchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(RegistryError::from)?;
    Ok(objects)
}

fn has_nonempty_exact_legacy_component_schema(conn: &Connection) -> Result<bool, RegistryError> {
    const COLUMNS: [(&str, &str, i64, i64); 9] = [
        ("seq", "INTEGER", 0, 1),
        ("id", "TEXT", 1, 0),
        ("component_type", "TEXT", 1, 0),
        ("submit_config_json", "TEXT", 1, 0),
        ("submitter", "TEXT", 1, 0),
        ("submitted_at_ms", "INTEGER", 1, 0),
        ("interval_ms", "INTEGER", 0, 0),
        ("expected_next_fire_at_ms", "INTEGER", 0, 0),
        ("last_fire_at_ms", "INTEGER", 0, 0),
    ];
    let mut stmt = conn.prepare("PRAGMA table_info(components)")?;
    let observed = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let exact = observed.len() == COLUMNS.len()
        && observed
            .iter()
            .zip(COLUMNS)
            .all(|((name, kind, not_null, primary_key), expected)| {
                (name.as_str(), kind.as_str(), *not_null, *primary_key) == expected
            });
    if !exact {
        return Ok(false);
    }
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM components", [], |row| row.get(0))?;
    Ok(count > 0)
}

fn reject_unanchored_security_write(
    conn: &Connection,
    provider_claimed: bool,
) -> Result<(), RegistryError> {
    let anchored: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM observation_identity_ledger WHERE singleton=1
         )",
        [],
        |row| row.get(0),
    )?;
    if provider_claimed || anchored != 0 {
        return Err(RegistryError::ObservationState(
            "component identity mutation must use the anchored CONTRACT-218 provider".to_owned(),
        ));
    }
    Ok(())
}

/// Force the SQLite durability boundary required before the external selector
/// may move from current to next.
pub(crate) fn checkpoint_and_sync_registry(
    conn: &Connection,
    db_path: &Path,
) -> Result<(), RegistryError> {
    let (busy, _log_frames, _checkpointed): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if busy != 0 {
        return Err(RegistryError::ObservationRecoveryRequired(
            "WAL checkpoint reported busy frames".to_owned(),
        ));
    }

    std::fs::OpenOptions::new()
        .read(true)
        .open(db_path)
        .and_then(|f| f.sync_all())
        .map_err(|e| RegistryError::Io(format!("sync registry database: {e}")))?;

    let mut wal_name = db_path.as_os_str().to_os_string();
    wal_name.push("-wal");
    let wal_path = PathBuf::from(wal_name);
    if wal_path.exists() {
        std::fs::OpenOptions::new()
            .read(true)
            .open(&wal_path)
            .and_then(|f| f.sync_all())
            .map_err(|e| RegistryError::Io(format!("sync registry WAL: {e}")))?;
    }
    if let Some(parent) = db_path.parent() {
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| RegistryError::Io(format!("sync registry directory: {e}")))?;
    }
    Ok(())
}

/// Recursively zero out `WebhookConfig.secret` fields in a trigger tree.
/// Used by `insert` to defend `WebhookConfig.secret` plaintext-at-rest in
/// the SQLite store (Slice D audit-Round-1 Critical fix). The encryption
/// hardening is a follow-up slice's concern per `types.rs:611-621`.
///
/// Adversarial-round-1 Critical-2 fix: depth-capped at `MAX_TRIGGER_NESTING_DEPTH`
/// (= 8). Direct registry callers that bypass submit-component admission cannot
/// stack-overflow this thread via a deeply-nested AnyOf tree.
pub(crate) fn redact_webhook_secrets_in_trigger(
    t: &mut Option<TriggerConfig>,
    depth: usize,
) -> Result<(), RegistryError> {
    if let Some(ref mut trigger) = t {
        redact_webhook_secrets(trigger, depth)?;
    }
    Ok(())
}

fn redact_webhook_secrets(t: &mut TriggerConfig, depth: usize) -> Result<(), RegistryError> {
    if depth > MAX_TRIGGER_NESTING_DEPTH {
        return Err(RegistryError::InvalidFilename(format!(
            "TriggerConfig nesting depth {depth} exceeds \
             MAX_TRIGGER_NESTING_DEPTH {MAX_TRIGGER_NESTING_DEPTH} during persist"
        )));
    }
    match t {
        TriggerConfig::Webhook(cfg) => {
            cfg.secret = None;
        }
        TriggerConfig::AnyOf(children) => {
            for c in children {
                redact_webhook_secrets(c, depth + 1)?;
            }
        }
        TriggerConfig::Schedule(_)
        | TriggerConfig::FileWatch(_)
        | TriggerConfig::TriggerEvent(_) => {}
    }
    Ok(())
}

/// Grammar gate for `db_filename`: ASCII alphanumeric + `.` + `_` + `-`, no
/// leading dot, not `.` / `..` / empty.
fn validate_db_filename(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() {
        return Err(RegistryError::InvalidFilename(
            "db_filename must not be empty".to_owned(),
        ));
    }
    if name == "." || name == ".." {
        return Err(RegistryError::InvalidFilename(format!(
            "db_filename {name:?} is reserved"
        )));
    }
    if name.starts_with('.') {
        return Err(RegistryError::InvalidFilename(format!(
            "db_filename {name:?} must not start with '.'"
        )));
    }
    for c in name.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-';
        if !ok {
            return Err(RegistryError::InvalidFilename(format!(
                "db_filename {name:?} contains invalid character {c:?}"
            )));
        }
    }
    Ok(())
}

/// Convert a SQLite row to a `ComponentRegistryRow`.
fn row_to_registry_row(row: &rusqlite::Row<'_>) -> Result<ComponentRegistryRow, RegistryError> {
    let id_str: String = row.get(0)?;
    let component_type_str: String = row.get(1)?;
    let submit_config_json: String = row.get(2)?;
    let submitter: String = row.get(3)?;
    let submitted_at_ms: i64 = row.get(4)?;
    let interval_ms: Option<i64> = row.get(5)?;
    let expected_next_fire_at_ms: Option<i64> = row.get(6)?;
    let last_fire_at_ms: Option<i64> = row.get(7)?;

    let id = ComponentId::new(id_str)
        .map_err(|e: SpawnError| RegistryError::Sql(format!("id parse: {e:?}")))?;
    let component_type = str_to_component_type(&component_type_str)?;
    let submit_config: ComponentSubmitConfig = serde_json::from_str(&submit_config_json)?;
    Ok(ComponentRegistryRow {
        id,
        component_type,
        submit_config,
        submitter,
        submitted_at_ms,
        interval_ms,
        expected_next_fire_at_ms,
        last_fire_at_ms,
    })
}

fn component_type_to_str(t: &ComponentType) -> &'static str {
    match t {
        ComponentType::Agent => "agent",
        ComponentType::Cron => "cron",
        ComponentType::Watcher => "watcher",
        ComponentType::Daemon => "daemon",
        ComponentType::Task => "task",
    }
}

fn str_to_component_type(s: &str) -> Result<ComponentType, RegistryError> {
    match s {
        "agent" => Ok(ComponentType::Agent),
        "cron" => Ok(ComponentType::Cron),
        "watcher" => Ok(ComponentType::Watcher),
        "daemon" => Ok(ComponentType::Daemon),
        "task" => Ok(ComponentType::Task),
        other => Err(RegistryError::Sql(format!(
            "unknown component_type {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize, Eq, PartialEq)]
    struct TestOwnedSchemaObject {
        #[serde(rename = "type")]
        object_type: String,
        name: String,
        tbl_name: String,
        sql: Option<String>,
    }

    fn test_owned_schema_objects() -> Vec<TestOwnedSchemaObject> {
        serde_json::from_str(include_str!(
            "../tests/fixtures/observation_sqlite_master_v1.json"
        ))
        .expect("ratified test-owned sqlite_master fixture remains valid JSON")
    }

    fn append_test_owned_schema_field(preimage: &mut Vec<u8>, field: &[u8]) {
        let len = u32::try_from(field.len()).expect("test-owned schema field fits u32");
        preimage.extend_from_slice(&len.to_be_bytes());
        preimage.extend_from_slice(field);
    }

    fn encode_test_owned_schema_preimage(objects: &[TestOwnedSchemaObject]) -> Vec<u8> {
        let mut preimage = b"advance.contract218.sqlite-master-schema.v1\0".to_vec();
        let count = u32::try_from(objects.len()).expect("test-owned object count fits u32");
        preimage.extend_from_slice(&count.to_be_bytes());
        for object in objects {
            append_test_owned_schema_field(&mut preimage, object.object_type.as_bytes());
            append_test_owned_schema_field(&mut preimage, object.name.as_bytes());
            append_test_owned_schema_field(&mut preimage, object.tbl_name.as_bytes());
            match object.sql.as_deref() {
                None => preimage.push(0),
                Some(sql) => {
                    preimage.push(1);
                    append_test_owned_schema_field(&mut preimage, sql.as_bytes());
                }
            }
        }
        preimage
    }

    fn exact_observation_schema() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE components (seq INTEGER);",
            )
            .unwrap();
        create_observation_foundation_schema(&connection).unwrap();
        connection
            .execute_batch(OBSERVATION_COMPONENT_SCHEMA_SQL)
            .unwrap();
        verify_observation_schema_fingerprint(&connection).unwrap();
        connection
    }

    #[test]
    fn validate_db_filename_accepts_simple() {
        assert!(validate_db_filename("components.db").is_ok());
        assert!(validate_db_filename("a_1-2.db").is_ok());
    }

    #[test]
    fn validate_db_filename_rejects_dot_dot() {
        assert!(validate_db_filename("..").is_err());
        assert!(validate_db_filename(".").is_err());
        assert!(validate_db_filename("").is_err());
    }

    #[test]
    fn validate_db_filename_rejects_leading_dot() {
        assert!(validate_db_filename(".hidden").is_err());
    }

    #[test]
    fn validate_db_filename_rejects_separators() {
        assert!(validate_db_filename("../escape.db").is_err());
        assert!(validate_db_filename("sub/foo.db").is_err());
    }

    #[test]
    fn exact_sqlite_master_allowlist_accepts_only_the_target_schema() {
        let connection = exact_observation_schema();
        assert!(verify_observation_schema_fingerprint(&connection).is_ok());
    }

    #[test]
    fn canonical_sqlite_master_fingerprint_matches_pinned_digest() {
        // This KAT owns both the complete ordered sqlite_master tuple fixture
        // and its expected digest.  It intentionally calls none of the
        // production installer, reader, encoder, verifier, or constants.
        const TEST_OWNED_DIGEST: [u8; 32] = [
            0x73, 0x14, 0x5f, 0xc0, 0xd5, 0x0d, 0xbd, 0x1b, 0x2b, 0x73, 0x75, 0x62, 0x95, 0xce,
            0x85, 0x78, 0xe5, 0xa5, 0x28, 0x40, 0x33, 0x59, 0xe6, 0x1a, 0x5b, 0x5d, 0xca, 0xf9,
            0x19, 0x0a, 0x73, 0xd0,
        ];
        let objects = test_owned_schema_objects();
        assert_eq!(objects.len(), 34);
        let observed: [u8; 32] = Sha256::digest(encode_test_owned_schema_preimage(&objects)).into();
        assert_eq!(observed, TEST_OWNED_DIGEST);
    }

    #[test]
    fn production_sqlite_master_matches_test_owned_literal_objects() {
        let connection = exact_observation_schema();
        let mut statement = connection
            .prepare(
                "SELECT type,name,tbl_name,sql
                   FROM sqlite_master
                  ORDER BY type COLLATE BINARY,name COLLATE BINARY,tbl_name COLLATE BINARY",
            )
            .unwrap();
        let observed = statement
            .query_map([], |row| {
                Ok(TestOwnedSchemaObject {
                    object_type: row.get(0)?,
                    name: row.get(1)?,
                    tbl_name: row.get(2)?,
                    sql: row.get(3)?,
                })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(observed, test_owned_schema_objects());
    }

    #[test]
    fn extra_trigger_and_rogue_identity_injector_reject_before_use() {
        let connection = exact_observation_schema();
        connection
            .execute_batch(
                "CREATE TRIGGER rogue_identity_after_operation
                 AFTER INSERT ON observation_identity_operations
                 BEGIN
                   INSERT OR IGNORE INTO observation_identity_authority
                     (id,class,last_incarnation,last_declaration_digest)
                   VALUES ('rogue','agent',1,zeroblob(32));
                 END;",
            )
            .unwrap();
        assert!(matches!(
            verify_observation_schema_fingerprint(&connection),
            Err(RegistryError::ObservationRecoveryRequired(_))
        ));
    }

    #[test]
    fn altered_or_extra_index_rejects_with_identical_rows() {
        let connection = exact_observation_schema();
        connection
            .execute_batch(
                "DROP INDEX idx_components_next_fire;
                 CREATE INDEX idx_components_next_fire ON components(last_fire_at_ms);
                 CREATE INDEX unexpected_identity_phase
                   ON observation_identities(lifecycle_state);",
            )
            .unwrap();
        assert!(matches!(
            verify_observation_schema_fingerprint(&connection),
            Err(RegistryError::ObservationRecoveryRequired(_))
        ));
    }

    #[test]
    fn weakened_check_foreign_key_or_strict_ddl_rejects() {
        for removed in [
            " CHECK (seq > 0)",
            " FOREIGN KEY(operation_id)\n            REFERENCES observation_identity_operations(operation_id)\n            ON DELETE RESTRICT",
            " STRICT",
        ] {
            let connection = exact_observation_schema();
            let sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='components'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let weakened = sql.replacen(removed, "", 1);
            assert_ne!(weakened, sql, "test DDL fragment was not present: {removed:?}");
            connection
                .execute_batch("PRAGMA writable_schema=ON;")
                .unwrap();
            connection
                .execute(
                    "UPDATE sqlite_master SET sql=?1 WHERE type='table' AND name='components'",
                    params![weakened],
                )
                .unwrap();
            connection
                .execute_batch("PRAGMA writable_schema=OFF;")
                .unwrap();
            assert!(matches!(
                verify_observation_schema_fingerprint(&connection),
                Err(RegistryError::ObservationRecoveryRequired(_))
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn offline_schema_trigger_tamper_rejects_before_registry_open() {
        let temporary = tempfile::tempdir().unwrap();
        let registry = ComponentRegistry::open_in(temporary.path(), "components.db")
            .await
            .unwrap();
        {
            let connection = registry.conn.lock().await;
            activate_observation_component_schema(&connection).unwrap();
            connection
                .execute(
                    "INSERT INTO observation_identity_ledger
                       (singleton,registry_instance_id,committed_sequence,
                        committed_head_digest,committed_state_root,committed_keyring_root,
                        committed_role_allocation_root,migration_digest)
                     VALUES (1,?1,0,?2,?2,?2,?2,?2)",
                    params![[1_u8; 16].as_slice(), [2_u8; 32].as_slice()],
                )
                .unwrap();
        }
        let database_path = registry.database_path().to_path_buf();
        drop(registry);

        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER offline_rogue_identity
                 AFTER INSERT ON observation_identity_operations
                 BEGIN
                   INSERT OR IGNORE INTO observation_identity_authority
                     (id,class,last_incarnation,last_declaration_digest)
                   VALUES ('offline-rogue','agent',1,zeroblob(32));
                 END;",
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            ComponentRegistry::open_in(temporary.path(), "components.db").await,
            Err(RegistryError::ObservationRecoveryRequired(_))
        ));
    }
}
