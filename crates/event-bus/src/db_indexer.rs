//! Synchronous SQLite events-table indexer (Slice A).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OpenFlags};

use crate::error::EventBusError;
use crate::event_io::{insert_event, Event};
use crate::schema;

/// Round-1 adversarial W6 fix: r2d2 default connection_timeout is 30s; under
/// pool exhaustion an emit() call would block 30s before failing. 5s gives
/// callers fast feedback and increments dropped_count promptly.
const POOL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

const INSERT_EVENT_SQL: &str = "INSERT INTO events (id, timestamp, agent_id, task_id, run_id, \
    execution_id, trace_id, span_id, parent_span_id, event_type, payload, duration_ms) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

/// Connection pragmas applied on every borrowed connection.
///
/// **Round-6 W3 — `SQLITE_OPEN_NO_MUTEX` rationale**: `NO_MUTEX` is the
/// "single-threaded mutex" mode. Correct because r2d2 enforces the invariant that
/// each pool slot's `Connection` is borrowed exclusively by one thread at a time
/// (the borrowing thread holds it until drop returns it to the pool). Inside a
/// single connection's lifetime, all SQLite calls are made from the same thread;
/// SQLite's internal serialization mutex is unnecessary. `EventBusEmit::emit` is
/// `Send + Sync`, so multiple threads can call `emit()` concurrently — but each
/// call goes through `pool.get()?` which returns a distinct connection.
///
/// **Future hazard**: any code path that holds a connection and shares it across
/// tasks via `Arc<Connection>` violates the per-connection single-thread invariant
/// and MUST NOT be added without re-validating these flags. Slice B's bounded-channel
/// architecture preserves the invariant (a single background flusher pulls a
/// connection, processes a batch, returns it).
#[derive(Debug)]
pub(crate) struct PragmaCustomizer;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for PragmaCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; \
             PRAGMA synchronous = NORMAL; \
             PRAGMA busy_timeout = 5000;",
        )?;
        Ok(())
    }
}

/// Synchronous SQLite indexer. Owns its own r2d2 pool; does NOT consume
/// `SqliteIndexHandle` from MODULE-004. See plan §"Schema isolation" for rationale.
pub(crate) struct EventDbIndexer {
    pool: Arc<Pool<SqliteConnectionManager>>,
}

impl EventDbIndexer {
    pub(crate) fn new(db_path: &Path) -> Result<Self, EventBusError> {
        // Strip URI flag: caller-supplied path inputs cannot be reinterpreted as
        // SQLite URI strings (matches M004 handle.rs:91-95).
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let manager = SqliteConnectionManager::file(db_path).with_flags(flags);
        let pool = Pool::builder()
            .max_size(4)
            .connection_timeout(POOL_CONNECTION_TIMEOUT)
            .connection_customizer(Box::new(PragmaCustomizer))
            .build(manager)
            .map_err(EventBusError::from)?;

        // Run migrations once at construction time.
        let mut conn = pool.get()?;
        schema::apply(&mut conn)?;
        drop(conn);

        // Round-1 adversarial W8 fix + round-2 W3 fix: chmod the SQLite file
        // AND its WAL/SHM sidecars to 0o600 on Unix. SQLite creates the main
        // file at construction; under WAL mode the `-wal` and `-shm` sidecars
        // appear at the FIRST write transaction. Slice A's pool migration
        // (`schema::apply` above) executes a write transaction during
        // construction, so by this point all three files typically exist on
        // disk. Best-effort: any missing file is silently skipped (chmod ENOENT
        // is tolerated — running the loop again on a future construction would
        // re-apply if needed; runtime emit() calls do NOT chmod-on-write).
        //
        // Round-2 W3 acknowledged caveat: between SQLite's first creat() and
        // this chmod, a concurrent reader on the same host with directory
        // traversal access can open the file world-readable. The hardening
        // recommendation (umask(0o077) before pool construction OR creating a
        // 0o700 parent dir for events.db, mirroring jsonl_dir's 0o700 mode) is
        // deferred — Slice A relies on the process-internal trust boundary
        // inherited from M004 handle.rs:18-26.
        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::fs::PermissionsExt;

            let mut wal_path = OsString::from(db_path.as_os_str());
            wal_path.push("-wal");
            let mut shm_path = OsString::from(db_path.as_os_str());
            shm_path.push("-shm");

            for variant in [
                db_path.to_path_buf(),
                std::path::PathBuf::from(wal_path),
                std::path::PathBuf::from(shm_path),
            ] {
                if let Ok(meta) = std::fs::metadata(&variant) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&variant, perms);
                }
            }
        }

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub(crate) fn index(&self, event: &Event) -> Result<(), EventBusError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached(INSERT_EVENT_SQL)?;
        insert_event(&mut stmt, event)?;
        Ok(())
    }

    /// Slice B: construct an EventDbIndexer from an existing pool. Used by the
    /// production `EventBus::new` constructor so the same pool serves both the
    /// db_indexer actor and the stats_aggregator + query_api routes.
    pub(crate) fn from_pool(pool: Arc<Pool<SqliteConnectionManager>>) -> Self {
        Self { pool }
    }
}
