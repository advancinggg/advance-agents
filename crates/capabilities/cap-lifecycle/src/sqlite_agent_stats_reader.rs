//! Slice C — production `AgentStatsReader` over CONTRACT-030
//! `SqliteIndexHandle` (MODULE-005 AC-17, REQ-318).
//!
//! The `agent_stats` table is **owned by MODULE-019** (observability); it
//! lives in the same SQLite file but outside CONTRACT-030's index tables.
//! cap-lifecycle is a strictly read-only consumer.
//!
//! Actual `agent_stats` schema (M019-owned, `event-bus/src/schema.rs` — every
//! value column is NULLABLE; documented here for cross-check per MODULE-005
//! §3.8; corrected 2026-06-10 — this doc previously claimed `NOT NULL`
//! columns, which neither the schema nor the live writers honor):
//! ```sql
//! CREATE TABLE agent_stats (
//!   agent_id                  TEXT PRIMARY KEY,
//!   active_tasks              INTEGER,
//!   completed_tasks           INTEGER,
//!   avg_turns_per_task        REAL,     -- always NULL today (no aggregation yet)
//!   avg_completion_time_hours REAL,     -- always NULL today (no aggregation yet)
//!   memory_entries            INTEGER,  -- always NULL today (no aggregation yet)
//!   llm_tokens_24h            INTEGER,
//!   error_count_24h           INTEGER,
//!   last_active               TEXT      -- ISO 8601
//! );
//! ```
//! NULL discrimination (adversarial r12): the schema permits NULL everywhere,
//! but the live writers differ per column, and the reader mirrors that:
//! - `avg_turns_per_task` / `avg_completion_time_hours` / `memory_entries` —
//!   BY-DESIGN NULL (both writers bind literal NULL; no aggregation exists
//!   yet) → projected to semantic zeros (`0.0` / `0`), matching the M019
//!   query side (`AgentStatsRow`).
//! - `active_tasks` / `completed_tasks` / `llm_tokens_24h` /
//!   `error_count_24h` — ALWAYS written as concrete integers by both writers
//!   → a NULL here is an anomaly (foreign writer / torn write / corruption)
//!   and is SURFACED as `IoFailure`, never normalized to a plausible 0.
//! - `last_active` — legitimately nullable (the aggregator binds it via
//!   `Option`) → NULL projects to `""`; but an over-long value (> 64 bytes;
//!   ISO 8601 is ≤ ~35) is an anomaly in this foreign-owned column and is
//!   rejected (`IoFailure`) rather than reflected unbounded across the WIT
//!   boundary into guests.

use std::sync::Arc;

use advance_database::SqliteIndexHandle;

use crate::error::LifecycleError;
use crate::stats::{AgentStats, AgentStatsReader};

/// Saturating `i64 → u32`. The M019-owned `agent_stats` columns are SQLite
/// signed `INTEGER`; a corrupt/negative writer value clamps to 0 and an
/// over-`u32::MAX` value saturates rather than silently wrapping (stats are
/// advisory observability — the least-misleading non-panicking conversion).
fn sat_u32(v: i64) -> u32 {
    v.clamp(0, u32::MAX as i64) as u32
}

/// Saturating `i64 → u64` (negative clamps to 0).
fn sat_u64(v: i64) -> u64 {
    if v < 0 {
        0
    } else {
        v as u64
    }
}

/// Egress bound for the foreign-owned `last_active` TEXT column (ISO 8601 is
/// ≤ ~35 bytes; 64 is generous headroom). Values beyond this are anomalous and
/// must not be reflected unbounded across the WIT boundary (adversarial r12).
const MAX_LAST_ACTIVE_BYTES: usize = 64;

/// Lift an always-written counter column; NULL = anomaly → error (never a
/// plausible-looking 0). See module doc "NULL discrimination".
fn counter(v: Option<i64>, col: &str, agent_id: &str) -> Result<i64, LifecycleError> {
    v.ok_or_else(|| {
        LifecycleError::IoFailure(format!(
            "corrupt agent_stats row for {agent_id}: NULL {col} (always written by both live writers)"
        ))
    })
}

#[derive(Clone)]
pub struct SqliteAgentStatsReader {
    handle: Arc<dyn SqliteIndexHandle>,
}

impl SqliteAgentStatsReader {
    pub fn new(handle: Arc<dyn SqliteIndexHandle>) -> Self {
        Self { handle }
    }
}

impl AgentStatsReader for SqliteAgentStatsReader {
    fn read_stats(&self, agent_id: &str) -> Result<AgentStats, LifecycleError> {
        let conn = self
            .handle
            .get_conn()
            .map_err(|e| LifecycleError::IoFailure(format!("get_conn: {e}")))?;
        let row = conn.query_row(
            "SELECT active_tasks, completed_tasks, avg_turns_per_task, \
             avg_completion_time_hours, memory_entries, llm_tokens_24h, \
             error_count_24h, last_active \
             FROM agent_stats WHERE agent_id = ?1",
            [agent_id],
            |r| {
                // Lift everything as Option first (every column is NULLABLE in
                // the M019 schema — never InvalidColumnType on a real-writer
                // row); the per-column NULL discrimination happens below,
                // outside the rusqlite closure (see module doc).
                Ok((
                    r.get::<_, Option<i64>>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, Option<f64>>(2)?,
                    r.get::<_, Option<f64>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            },
        );
        match row {
            Ok((active, completed, avg_turns, avg_hours, mem, llm, errs, last)) => {
                // last_active: legitimately nullable → "", but bounded —
                // never reflect an oversized foreign value into guests.
                let last_active = last.unwrap_or_default();
                if last_active.len() > MAX_LAST_ACTIVE_BYTES {
                    return Err(LifecycleError::IoFailure(format!(
                        "corrupt agent_stats row for {agent_id}: last_active is {} bytes \
                         (cap {MAX_LAST_ACTIVE_BYTES})",
                        last_active.len()
                    )));
                }
                Ok(AgentStats {
                    // Always-written counters: NULL = anomaly, surfaced.
                    active_tasks: sat_u32(counter(active, "active_tasks", agent_id)?),
                    completed_tasks: sat_u32(counter(completed, "completed_tasks", agent_id)?),
                    // By-design-NULL columns (no aggregation yet): zeros.
                    avg_turns_per_task: avg_turns.unwrap_or(0.0) as f32,
                    avg_completion_time_hours: avg_hours.unwrap_or(0.0) as f32,
                    memory_entries: sat_u32(mem.unwrap_or(0)),
                    llm_tokens_24h: sat_u64(counter(llm, "llm_tokens_24h", agent_id)?),
                    error_count_24h: sat_u32(counter(errs, "error_count_24h", agent_id)?),
                    last_active,
                })
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(LifecycleError::NotFound(format!(
                "no agent_stats row for {agent_id}"
            ))),
            Err(e) => Err(LifecycleError::IoFailure(format!("agent_stats query: {e}"))),
        }
    }
}
