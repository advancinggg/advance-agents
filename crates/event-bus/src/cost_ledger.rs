//! Durable cost attribution over the persisted `events` table (lane
//! cost-attribution, 2026-09-16) — the MODULE-019 implementation of
//! `CostLedgerQuery`.
//!
//! The in-memory `CostTracker` answers per-run budget questions and is lost on
//! restart (cost-tracker invariant 7). Operators and the Client API need the
//! HISTORICAL answer — "what has agent X spent, what did we pay provider Y" —
//! which only the durable `llm.response` rows can give. This module folds those
//! rows with SQL `json_extract` over the canonical top-level payload shape
//! (`input_tokens` / `output_tokens` / `cost_usd` / `provider`).
//!
//! Attribution rule (see `CostLedgerQuery` invariant 2): the row's `agent_id`
//! column is the paying agent (no roll-up to the parent — a caller that wants a
//! subtree total sums the children it knows from the tree); the provider key is
//! `payload.provider`, `"unknown"` for rows written before cap-llm carried it.
//!
//! Clamping mirrors `CostTracker::observe`: negative or non-numeric `cost_usd`
//! contributes `0.0`; token counts likewise (`CAST` of garbage is 0, `MAX(0, …)`
//! drops negatives).
//!
//! Windows are half-open `[since, until)` at second granularity, compared
//! lexically against the stored `%FT%T%.fZ` timestamps: `since` is floored and
//! `until` is ceiled to a whole second, so the comparison string never carries a
//! fractional part and the stored `…SS.fffZ` sorts consistently against it.
//! Second-granularity bounds can only include MORE rows, never fewer.

use std::sync::Arc;

use advance_shared_types::cost::{AttributedCost, CostLedgerError, CostWindow, RunCost};
use advance_shared_types::traits::{CostLedgerQuery, MAX_ATTRIBUTION_ROWS};
use chrono::{DateTime, Timelike, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::Value as SqlValue;

/// Provider key used for `llm.response` rows without a `payload.provider`.
pub const UNKNOWN_PROVIDER: &str = "unknown";

/// SQL fragment: the provider attribution key of a row.
/// `CAST … AS TEXT` so a non-string `provider` value (a corrupted or adversarial
/// payload carrying a number / object) is still a stable text bucket instead of
/// a column-type read error.
const PROVIDER_KEY_SQL: &str =
    "CAST(COALESCE(json_extract(payload, '$.provider'), 'unknown') AS TEXT)";

/// SQL fragment: the four clamped aggregates, in `RunCost` field order.
const AGG_SQL: &str =
    "COALESCE(SUM(MAX(0, CAST(json_extract(payload, '$.input_tokens') AS INTEGER))), 0), \
     COALESCE(SUM(MAX(0, CAST(json_extract(payload, '$.output_tokens') AS INTEGER))), 0), \
     COALESCE(SUM(MAX(0.0, CAST(json_extract(payload, '$.cost_usd') AS REAL))), 0.0), \
     COUNT(*)";

/// Production `CostLedgerQuery` over the bus's SQLite pool. Holds a CLONE of the
/// pool (never an `Arc<EventBus>`), like `EventBusReadApi`, so wiring's
/// `Arc::try_unwrap(bus_concrete)` invariant is preserved.
pub struct SqliteCostLedger {
    pool: Arc<Pool<SqliteConnectionManager>>,
}

impl SqliteCostLedger {
    pub(crate) fn new(pool: Arc<Pool<SqliteConnectionManager>>) -> Self {
        Self { pool }
    }

    /// Floor to the whole second and render in the stored timestamp shape
    /// (without a fractional part, see module docs).
    fn floor_second(ts: DateTime<Utc>) -> String {
        ts.with_nanosecond(0)
            .unwrap_or(ts)
            .format("%FT%TZ")
            .to_string()
    }

    /// Ceil to the whole second (a bound with any sub-second part rounds UP).
    fn ceil_second(ts: DateTime<Utc>) -> String {
        let floored = ts.with_nanosecond(0).unwrap_or(ts);
        let bumped = if ts.nanosecond() > 0 {
            floored
                .checked_add_signed(chrono::Duration::seconds(1))
                .unwrap_or(floored)
        } else {
            floored
        };
        bumped.format("%FT%TZ").to_string()
    }

    /// Build the `WHERE` tail + parameters for a window plus optional exact
    /// column/provider filters. Every value is bound, never interpolated.
    fn build_where(
        window: &CostWindow,
        agent_id: Option<&str>,
        provider_id: Option<&str>,
    ) -> (String, Vec<SqlValue>) {
        let mut clauses = vec!["event_type = 'llm.response'".to_string()];
        let mut params: Vec<SqlValue> = Vec::new();
        if let Some(since) = window.since {
            clauses.push("timestamp >= ?".into());
            params.push(SqlValue::Text(Self::floor_second(since)));
        }
        if let Some(until) = window.until {
            clauses.push("timestamp < ?".into());
            params.push(SqlValue::Text(Self::ceil_second(until)));
        }
        if let Some(agent) = agent_id {
            clauses.push("agent_id = ?".into());
            params.push(SqlValue::Text(agent.to_string()));
        }
        if let Some(provider) = provider_id {
            clauses.push(format!("{PROVIDER_KEY_SQL} = ?"));
            params.push(SqlValue::Text(provider.to_string()));
        }
        (clauses.join(" AND "), params)
    }

    fn map_row(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<RunCost> {
        let tokens_in: i64 = row.get(offset)?;
        let tokens_out: i64 = row.get(offset + 1)?;
        let cost_usd: f64 = row.get(offset + 2)?;
        let request_count: i64 = row.get(offset + 3)?;
        Ok(RunCost {
            tokens_in: tokens_in.max(0) as u64,
            tokens_out: tokens_out.max(0) as u64,
            cost_usd: if cost_usd.is_finite() && cost_usd >= 0.0 {
                cost_usd
            } else {
                0.0
            },
            request_count: request_count.clamp(0, u32::MAX as i64) as u32,
        })
    }

    fn total(
        &self,
        window: &CostWindow,
        agent_id: Option<&str>,
        provider_id: Option<&str>,
    ) -> Result<RunCost, CostLedgerError> {
        let (where_sql, params) = Self::build_where(window, agent_id, provider_id);
        let sql = format!("SELECT {AGG_SQL} FROM events WHERE {where_sql}");
        let conn = self
            .pool
            .get()
            .map_err(|e| CostLedgerError::Query(e.to_string()))?;
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| CostLedgerError::Query(e.to_string()))?;
        stmt.query_row(rusqlite::params_from_iter(params.iter()), |row| {
            Self::map_row(row, 0)
        })
        .map_err(|e| CostLedgerError::Query(e.to_string()))
    }

    /// Group by `key_sql` (a column name or the provider-key expression) with
    /// optional exact filters. Empty agent ids are excluded from per-agent
    /// groupings (CONTRACT-216 detached work never manufactures an agent bucket).
    fn grouped(
        &self,
        key_sql: &str,
        window: &CostWindow,
        agent_id: Option<&str>,
        provider_id: Option<&str>,
    ) -> Result<Vec<AttributedCost>, CostLedgerError> {
        let (mut where_sql, params) = Self::build_where(window, agent_id, provider_id);
        if key_sql == "agent_id" {
            where_sql.push_str(" AND agent_id IS NOT NULL AND agent_id <> ''");
        }
        let sql = format!(
            "SELECT {key_sql} AS k, {AGG_SQL} FROM events WHERE {where_sql} \
             GROUP BY k ORDER BY 4 DESC, k ASC LIMIT {MAX_ATTRIBUTION_ROWS}"
        );
        let conn = self
            .pool
            .get()
            .map_err(|e| CostLedgerError::Query(e.to_string()))?;
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| CostLedgerError::Query(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                let id: String = row.get(0)?;
                let cost = Self::map_row(row, 1)?;
                Ok(AttributedCost { id, cost })
            })
            .map_err(|e| CostLedgerError::Query(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| CostLedgerError::Query(e.to_string()))?);
        }
        Ok(out)
    }
}

impl CostLedgerQuery for SqliteCostLedger {
    fn agent_totals(&self, window: &CostWindow) -> Result<Vec<AttributedCost>, CostLedgerError> {
        self.grouped("agent_id", window, None, None)
    }

    fn agent_total(&self, agent_id: &str, window: &CostWindow) -> Result<RunCost, CostLedgerError> {
        if agent_id.is_empty() {
            return Ok(RunCost::default());
        }
        self.total(window, Some(agent_id), None)
    }

    fn agent_by_provider(
        &self,
        agent_id: &str,
        window: &CostWindow,
    ) -> Result<Vec<AttributedCost>, CostLedgerError> {
        if agent_id.is_empty() {
            return Ok(Vec::new());
        }
        self.grouped(PROVIDER_KEY_SQL, window, Some(agent_id), None)
    }

    fn provider_totals(&self, window: &CostWindow) -> Result<Vec<AttributedCost>, CostLedgerError> {
        self.grouped(PROVIDER_KEY_SQL, window, None, None)
    }

    fn provider_total(
        &self,
        provider_id: &str,
        window: &CostWindow,
    ) -> Result<RunCost, CostLedgerError> {
        if provider_id.is_empty() {
            return Ok(RunCost::default());
        }
        self.total(window, None, Some(provider_id))
    }

    fn provider_by_agent(
        &self,
        provider_id: &str,
        window: &CostWindow,
    ) -> Result<Vec<AttributedCost>, CostLedgerError> {
        if provider_id.is_empty() {
            return Ok(Vec::new());
        }
        self.grouped("agent_id", window, None, Some(provider_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_and_ceil_second_render_without_fraction() {
        let ts = DateTime::parse_from_rfc3339("2026-09-16T10:00:00.250Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(SqliteCostLedger::floor_second(ts), "2026-09-16T10:00:00Z");
        assert_eq!(SqliteCostLedger::ceil_second(ts), "2026-09-16T10:00:01Z");
        let whole = DateTime::parse_from_rfc3339("2026-09-16T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(SqliteCostLedger::ceil_second(whole), "2026-09-16T10:00:00Z");
    }

    #[test]
    fn where_clause_binds_every_value() {
        let w = CostWindow {
            since: Some(Utc::now()),
            until: Some(Utc::now()),
        };
        let (sql, params) = SqliteCostLedger::build_where(&w, Some("a"), Some("p"));
        assert_eq!(sql.matches('?').count(), 4);
        assert_eq!(params.len(), 4);
        assert!(!sql.contains("'a'") && !sql.contains("'p'"));
    }
}
