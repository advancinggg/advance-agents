//! Durable, non-payload CONTRACT-218 carrier sidecar for EventBus history.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

const MAX_EVENT_ID_BYTES: usize = 256;
const MAX_CARRIER_BYTES: usize = 1_024;

#[derive(Debug)]
pub struct ObservationCarrierStore {
    path: PathBuf,
}

impl ObservationCarrierStore {
    pub fn open(workspace: &Path) -> Result<Self, String> {
        let workspace = fs::canonicalize(workspace)
            .map_err(|error| format!("canonicalize carrier workspace: {error}"))?;
        let runtime = workspace.join(".runtime");
        fs::create_dir_all(&runtime)
            .map_err(|error| format!("create carrier directory: {error}"))?;
        let runtime = fs::canonicalize(&runtime)
            .map_err(|error| format!("canonicalize carrier directory: {error}"))?;
        if !runtime.starts_with(&workspace) {
            return Err("carrier directory escapes the workspace".to_owned());
        }
        let path = runtime.join("observation-carriers.db");
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err("carrier database leaf is a symlink".to_owned());
        }
        let store = Self { path };
        let connection = store.connection()?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS observation_carriers (
                    event_id TEXT PRIMARY KEY NOT NULL,
                    carrier BLOB NOT NULL,
                    CHECK(length(event_id) BETWEEN 1 AND 256),
                    CHECK(typeof(carrier)='blob' AND length(carrier) BETWEEN 1 AND 1024)
                 ) WITHOUT ROWID;",
            )
            .map_err(|error| format!("initialize carrier schema: {error}"))?;
        Ok(store)
    }

    pub fn put(&self, event_id: &str, carrier: &[u8]) -> Result<(), String> {
        validate(event_id, carrier)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("begin carrier transaction: {error}"))?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT carrier FROM observation_carriers WHERE event_id=?1",
                [event_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| format!("read existing carrier: {error}"))?;
        match existing {
            Some(existing) if existing != carrier => {
                return Err("event id is already bound to a different carrier".to_owned())
            }
            Some(_) => {}
            None => {
                transaction
                    .execute(
                        "INSERT INTO observation_carriers(event_id,carrier) VALUES(?1,?2)",
                        params![event_id, carrier],
                    )
                    .map_err(|error| format!("insert observation carrier: {error}"))?;
            }
        }
        transaction
            .commit()
            .map_err(|error| format!("commit observation carrier: {error}"))
    }

    pub fn get(&self, event_id: &str) -> Result<Option<Vec<u8>>, String> {
        if event_id.is_empty() || event_id.len() > MAX_EVENT_ID_BYTES {
            return Err("invalid carrier event id".to_owned());
        }
        let value = self
            .connection()?
            .query_row(
                "SELECT carrier FROM observation_carriers WHERE event_id=?1",
                [event_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| format!("read observation carrier: {error}"))?;
        if let Some(carrier) = value.as_deref() {
            validate(event_id, carrier)?;
        }
        Ok(value)
    }

    fn connection(&self) -> Result<Connection, String> {
        let connection = Connection::open(&self.path)
            .map_err(|error| format!("open observation carrier database: {error}"))?;
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .map_err(|error| format!("configure observation carrier database: {error}"))?;
        Ok(connection)
    }
}

fn validate(event_id: &str, carrier: &[u8]) -> Result<(), String> {
    if event_id.is_empty()
        || event_id.len() > MAX_EVENT_ID_BYTES
        || carrier.is_empty()
        || carrier.len() > MAX_CARRIER_BYTES
    {
        return Err("invalid observation carrier bounds".to_owned());
    }
    Ok(())
}
