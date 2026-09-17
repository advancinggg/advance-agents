//! `SqliteEntityIndex` — the entity-model projection over the workspace index DB.
//!
//! Tables (schema v2): `entity_index` (one row per file / inline item / directory entity with
//! the promoted columns), `entity_aspect` (one row per aspect the entity has) and
//! `entity_occurrence` (the expanded occurrences of every entity with `starts`: a single
//! occurrence for a plain event, up to [`MAX_OCCURRENCES_PER_ENTITY`] within
//! [`OCCURRENCE_HORIZON_DAYS`] for a repeating one, minus its `exdates`).
//!
//! Timestamps are stored as canonical UTC text (`2026-09-20T00:00:00Z`) so lexicographic
//! comparison is chronological. Every operation runs as one `Immediate` transaction on the
//! blocking pool. Physically this is the same file as the rest of the index
//! (`database.db-path`); boot truncates and rebuilds it like every other table.

use std::sync::Arc;

use advance_shared_types::entity::{
    EntityId, EntityIndex, EntityIndexError, EntityKind, EntityQuery, EntityRow, OrderKey,
    MAX_ENTITY_QUERY_LIMIT,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};

use crate::handle::SqliteIndexHandle;

/// Occurrence expansion horizon after an entity's `starts`.
pub const OCCURRENCE_HORIZON_DAYS: i64 = 366;
/// Occurrence cap per entity; beyond it `fields.__truncated = true`.
pub const MAX_OCCURRENCES_PER_ENTITY: usize = 1024;

/// The production [`EntityIndex`].
#[derive(Clone)]
pub struct SqliteEntityIndex {
    handle: Arc<dyn SqliteIndexHandle>,
}

impl SqliteEntityIndex {
    pub fn new(handle: Arc<dyn SqliteIndexHandle>) -> Self {
        Self { handle }
    }

    async fn blocking<T, F>(&self, f: F) -> Result<T, EntityIndexError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, EntityIndexError> + Send + 'static,
    {
        let handle = Arc::clone(&self.handle);
        tokio::task::spawn_blocking(move || {
            let mut conn = handle
                .get_conn()
                .map_err(|e| EntityIndexError::Storage(e.to_string()))?;
            f(&mut conn)
        })
        .await
        .map_err(|e| EntityIndexError::Storage(format!("spawn_blocking: {e}")))?
    }
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn storage(e: rusqlite::Error) -> EntityIndexError {
    EntityIndexError::Storage(e.to_string())
}

fn kind_text(k: EntityKind) -> &'static str {
    match k {
        EntityKind::File => "file",
        EntityKind::Item => "item",
        EntityKind::Dir => "dir",
    }
}

fn kind_from(s: &str) -> EntityKind {
    match s {
        "item" => EntityKind::Item,
        "dir" => EntityKind::Dir,
        _ => EntityKind::File,
    }
}

/// Normalize a workspace path for storage: no leading slash.
pub fn normalize_entity_path(path: &str) -> &str {
    path.trim_start_matches('/')
}

// ── occurrence expansion ────────────────────────────────────────────────────────────────────

/// `(occurrences, truncated)` for one row. A row without `starts` has none; a plain event has
/// one; a repeating event is expanded through its RRULE minus `exdates`.
pub fn expand_occurrences(row: &EntityRow) -> (Vec<(DateTime<Utc>, Option<DateTime<Utc>>)>, bool) {
    let Some(starts) = row.starts_at else {
        return (Vec::new(), false);
    };
    let length = row.ends_at.map(|e| e - starts);
    let repeat = row
        .fields
        .get("repeat")
        .and_then(|v| v.as_str())
        .map(str::trim);
    let Some(rule) = repeat.filter(|r| !r.is_empty()) else {
        return (vec![(starts, row.ends_at)], false);
    };
    let exdates: Vec<DateTime<Utc>> = row
        .fields
        .get("exdates")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter_map(parse_ts_lenient)
                .collect()
        })
        .unwrap_or_default();
    let ical_ts = |t: DateTime<Utc>| t.format("%Y%m%dT%H%M%SZ").to_string();
    let mut text = format!("DTSTART:{}\nRRULE:{}\n", ical_ts(starts), rule);
    for ex in &exdates {
        text.push_str(&format!("EXDATE:{}\n", ical_ts(*ex)));
    }
    let set: rrule::RRuleSet = match text.parse() {
        Ok(s) => s,
        // An unparsable rule is indexed as a single occurrence so the entity stays findable.
        Err(_) => return (vec![(starts, row.ends_at)], false),
    };
    let horizon = starts + Duration::days(OCCURRENCE_HORIZON_DAYS);
    let result = set
        .after(starts.with_timezone(&rrule::Tz::UTC))
        .before(horizon.with_timezone(&rrule::Tz::UTC))
        .all(MAX_OCCURRENCES_PER_ENTITY as u16);
    let dates: Vec<(DateTime<Utc>, Option<DateTime<Utc>>)> = result
        .dates
        .into_iter()
        .map(|d| {
            let s = d.with_timezone(&Utc);
            (s, length.map(|l| s + l))
        })
        .collect();
    (dates, result.limited)
}

fn parse_ts_lenient(s: &str) -> Option<DateTime<Utc>> {
    if let Some(t) = parse_ts(s) {
        return Some(t);
    }
    chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|n| n.and_utc())
}

// ── SQL ─────────────────────────────────────────────────────────────────────────────────────

const SELECT_ROW: &str =
    "SELECT entity_id, agent_id, path, anchor, parent, kind, type, title, status, \
    due_at, starts_at, ends_at, priority, fields_json, updated_at, rowid FROM entity_index";

fn row_from_sql(r: &rusqlite::Row<'_>) -> rusqlite::Result<(EntityRow, i64)> {
    let fields: String = r.get(13)?;
    let updated: String = r.get(14)?;
    let opt_ts = |i: usize| -> rusqlite::Result<Option<DateTime<Utc>>> {
        let v: Option<String> = r.get(i)?;
        Ok(v.as_deref().and_then(parse_ts))
    };
    Ok((
        EntityRow {
            id: EntityId(r.get(0)?),
            agent_id: r.get(1)?,
            path: r.get(2)?,
            anchor: r.get::<_, Option<String>>(3)?.map(EntityId),
            parent: r.get::<_, Option<String>>(4)?.map(EntityId),
            kind: kind_from(&r.get::<_, String>(5)?),
            r#type: r.get(6)?,
            title: r.get(7)?,
            aspects: Vec::new(),
            status: r.get(8)?,
            due_at: opt_ts(9)?,
            starts_at: opt_ts(10)?,
            ends_at: opt_ts(11)?,
            priority: r.get(12)?,
            fields: serde_json::from_str(&fields).unwrap_or(serde_json::Value::Null),
            updated_at: parse_ts(&updated).unwrap_or_else(Utc::now),
        },
        r.get(15)?,
    ))
}

fn load_aspects(conn: &Connection, rowid: i64) -> rusqlite::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT aspect FROM entity_aspect WHERE entity_rowid = ?1 ORDER BY aspect")?;
    let rows = stmt.query_map(params![rowid], |r| r.get::<_, String>(0))?;
    rows.collect()
}

fn delete_path_tx(
    tx: &rusqlite::Transaction<'_>,
    agent_id: &str,
    path: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM entity_aspect WHERE entity_rowid IN (SELECT rowid FROM entity_index WHERE agent_id = ?1 AND path = ?2)",
        params![agent_id, path],
    )?;
    tx.execute(
        "DELETE FROM entity_occurrence WHERE entity_rowid IN (SELECT rowid FROM entity_index WHERE agent_id = ?1 AND path = ?2)",
        params![agent_id, path],
    )?;
    tx.execute(
        "DELETE FROM entity_index WHERE agent_id = ?1 AND path = ?2",
        params![agent_id, path],
    )?;
    Ok(())
}

/// Map an order-key field name to its column.
fn order_column(field: &str) -> Option<&'static str> {
    Some(match field {
        "due" | "due_at" => "due_at",
        "starts" | "starts_at" => "starts_at",
        "ends" | "ends_at" => "ends_at",
        "priority" => "priority",
        "title" => "title",
        "status" => "status",
        "type" => "type",
        "path" => "path",
        "updated_at" => "updated_at",
        _ => return None,
    })
}

fn order_sql(order: &[OrderKey]) -> Result<String, EntityIndexError> {
    if order.is_empty() {
        return Ok("updated_at DESC, rowid ASC".to_string());
    }
    let mut parts = Vec::with_capacity(order.len() + 1);
    for k in order {
        let col = order_column(&k.field).ok_or_else(|| {
            EntityIndexError::InvalidQuery(format!("unknown order field {:?}", k.field))
        })?;
        parts.push(format!(
            "({col} IS NULL) ASC, {col} {}",
            if k.ascending { "ASC" } else { "DESC" }
        ));
    }
    parts.push("rowid ASC".to_string());
    Ok(parts.join(", "))
}

#[async_trait]
impl EntityIndex for SqliteEntityIndex {
    async fn replace_path(
        &self,
        agent_id: &str,
        path: &str,
        rows: Vec<EntityRow>,
    ) -> Result<(), EntityIndexError> {
        let agent_id = agent_id.to_string();
        let path = normalize_entity_path(path).to_string();
        self.blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            delete_path_tx(&tx, &agent_id, &path).map_err(storage)?;
            for row in rows {
                let (occurrences, truncated) = expand_occurrences(&row);
                let mut fields = row.fields.clone();
                if truncated {
                    if let serde_json::Value::Object(m) = &mut fields {
                        m.insert("__truncated".into(), serde_json::Value::Bool(true));
                    }
                }
                let fields_json = serde_json::to_string(&fields).unwrap_or_else(|_| "{}".into());
                // A stale row for the same id under another path (a moved / promoted file
                // whose old path was not deleted first) is replaced: ids are unique per agent.
                tx.execute(
                    "DELETE FROM entity_aspect WHERE entity_rowid IN (SELECT rowid FROM entity_index WHERE agent_id = ?1 AND entity_id = ?2)",
                    params![agent_id, row.id.0],
                ).map_err(storage)?;
                tx.execute(
                    "DELETE FROM entity_occurrence WHERE entity_rowid IN (SELECT rowid FROM entity_index WHERE agent_id = ?1 AND entity_id = ?2)",
                    params![agent_id, row.id.0],
                ).map_err(storage)?;
                tx.execute(
                    "DELETE FROM entity_index WHERE agent_id = ?1 AND entity_id = ?2",
                    params![agent_id, row.id.0],
                )
                .map_err(storage)?;
                tx.execute(
                    "INSERT INTO entity_index(agent_id, entity_id, path, anchor, parent, kind, type, title, status, \
                     due_at, starts_at, ends_at, priority, fields_json, updated_at) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                    params![
                        agent_id,
                        row.id.0,
                        path,
                        row.anchor.as_ref().map(|a| a.0.clone()),
                        row.parent.as_ref().map(|p| p.0.clone()),
                        kind_text(row.kind),
                        row.r#type,
                        row.title,
                        row.status,
                        row.due_at.map(ts),
                        row.starts_at.map(ts),
                        row.ends_at.map(ts),
                        row.priority,
                        fields_json,
                        ts(row.updated_at),
                    ],
                )
                .map_err(storage)?;
                let rowid = tx.last_insert_rowid();
                for aspect in &row.aspects {
                    tx.execute(
                        "INSERT INTO entity_aspect(entity_rowid, agent_id, aspect) VALUES (?1, ?2, ?3)",
                        params![rowid, agent_id, aspect],
                    )
                    .map_err(storage)?;
                }
                for (s, e) in occurrences {
                    tx.execute(
                        "INSERT INTO entity_occurrence(entity_rowid, agent_id, starts_at, ends_at) VALUES (?1, ?2, ?3, ?4)",
                        params![rowid, agent_id, ts(s), e.map(ts)],
                    )
                    .map_err(storage)?;
                }
            }
            tx.commit().map_err(storage)
        })
        .await
    }

    async fn delete_path(&self, agent_id: &str, path: &str) -> Result<(), EntityIndexError> {
        let agent_id = agent_id.to_string();
        let path = normalize_entity_path(path).to_string();
        self.blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            delete_path_tx(&tx, &agent_id, &path).map_err(storage)?;
            tx.commit().map_err(storage)
        })
        .await
    }

    async fn get(
        &self,
        agent_id: &str,
        id: &EntityId,
    ) -> Result<Option<EntityRow>, EntityIndexError> {
        let agent_id = agent_id.to_string();
        let id = id.0.clone();
        self.blocking(move |conn| {
            let sql = format!("{SELECT_ROW} WHERE agent_id = ?1 AND entity_id = ?2");
            let found = conn
                .query_row(&sql, params![agent_id, id], row_from_sql)
                .optional()
                .map_err(storage)?;
            match found {
                None => Ok(None),
                Some((mut row, rowid)) => {
                    row.aspects = load_aspects(conn, rowid).map_err(storage)?;
                    Ok(Some(row))
                }
            }
        })
        .await
    }

    async fn query(&self, q: &EntityQuery) -> Result<Vec<EntityRow>, EntityIndexError> {
        if q.limit == 0 || q.limit > MAX_ENTITY_QUERY_LIMIT {
            return Err(EntityIndexError::InvalidQuery(format!(
                "limit must be 1..={MAX_ENTITY_QUERY_LIMIT}, got {}",
                q.limit
            )));
        }
        let order = order_sql(&q.order)?;
        let q = q.clone();
        self.blocking(move |conn| {
            let mut sql = format!("{SELECT_ROW} WHERE agent_id = ?");
            let mut args: Vec<rusqlite::types::Value> = vec![q.agent_id.clone().into()];
            if let Some(p) = &q.parent {
                sql.push_str(" AND parent = ?");
                args.push(p.0.clone().into());
            }
            if let Some(t) = &q.r#type {
                sql.push_str(" AND type = ?");
                args.push(t.clone().into());
            }
            if let Some(a) = &q.aspect {
                sql.push_str(" AND EXISTS (SELECT 1 FROM entity_aspect ea WHERE ea.entity_rowid = entity_index.rowid AND ea.aspect = ?)");
                args.push(a.clone().into());
            }
            if let Some(statuses) = &q.status {
                if statuses.is_empty() {
                    sql.push_str(" AND 0");
                } else {
                    let marks = vec!["?"; statuses.len()].join(",");
                    sql.push_str(&format!(" AND status IN ({marks})"));
                    for s in statuses {
                        args.push(s.clone().into());
                    }
                }
            }
            if let Some((a, b)) = q.due_between {
                sql.push_str(" AND due_at >= ? AND due_at < ?");
                args.push(ts(a).into());
                args.push(ts(b).into());
            }
            if let Some((a, b)) = q.occurs_between {
                sql.push_str(" AND EXISTS (SELECT 1 FROM entity_occurrence eo WHERE eo.entity_rowid = entity_index.rowid AND eo.starts_at >= ? AND eo.starts_at < ?)");
                args.push(ts(a).into());
                args.push(ts(b).into());
            }
            if let Some((a, b)) = q.any_between {
                sql.push_str(" AND ((due_at >= ? AND due_at < ?) OR EXISTS (SELECT 1 FROM entity_occurrence eo WHERE eo.entity_rowid = entity_index.rowid AND eo.starts_at >= ? AND eo.starts_at < ?))");
                args.push(ts(a).into());
                args.push(ts(b).into());
                args.push(ts(a).into());
                args.push(ts(b).into());
            }
            sql.push_str(&format!(" ORDER BY {order} LIMIT ?"));
            args.push((q.limit as i64).into());
            let mut stmt = conn.prepare(&sql).map_err(storage)?;
            let mapped = stmt
                .query_map(params_from_iter(args.iter()), row_from_sql)
                .map_err(storage)?;
            let mut out = Vec::new();
            for r in mapped {
                let (mut row, rowid) = r.map_err(storage)?;
                row.aspects = load_aspects(conn, rowid).map_err(storage)?;
                out.push(row);
            }
            Ok(out)
        })
        .await
    }

    async fn truncate(&self, agent_id: &str) -> Result<(), EntityIndexError> {
        let agent_id = agent_id.to_string();
        self.blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            tx.execute(
                "DELETE FROM entity_aspect WHERE agent_id = ?1",
                params![agent_id],
            )
            .map_err(storage)?;
            tx.execute(
                "DELETE FROM entity_occurrence WHERE agent_id = ?1",
                params![agent_id],
            )
            .map_err(storage)?;
            tx.execute(
                "DELETE FROM entity_index WHERE agent_id = ?1",
                params![agent_id],
            )
            .map_err(storage)?;
            tx.commit().map_err(storage)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(starts: &str, ends: Option<&str>, repeat: Option<&str>, exdates: &[&str]) -> EntityRow {
        let mut fields = serde_json::Map::new();
        if let Some(r) = repeat {
            fields.insert("repeat".into(), serde_json::Value::String(r.into()));
        }
        if !exdates.is_empty() {
            fields.insert(
                "exdates".into(),
                serde_json::Value::Array(
                    exdates
                        .iter()
                        .map(|e| serde_json::Value::String((*e).into()))
                        .collect(),
                ),
            );
        }
        EntityRow {
            id: EntityId("e-1".into()),
            agent_id: "a".into(),
            path: "x.md".into(),
            anchor: None,
            parent: None,
            kind: EntityKind::File,
            r#type: "meeting".into(),
            title: None,
            aspects: vec![],
            status: None,
            due_at: None,
            starts_at: parse_ts(starts),
            ends_at: ends.and_then(parse_ts),
            priority: None,
            fields: serde_json::Value::Object(fields),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn plain_event_is_one_occurrence() {
        let (occ, trunc) = expand_occurrences(&row(
            "2026-09-21T02:00:00Z",
            Some("2026-09-21T03:00:00Z"),
            None,
            &[],
        ));
        assert_eq!(occ.len(), 1);
        assert!(!trunc);
        assert_eq!(occ[0].1, parse_ts("2026-09-21T03:00:00Z"));
    }

    #[test]
    fn weekly_expands_minus_exdates_within_horizon() {
        let (occ, trunc) = expand_occurrences(&row(
            "2026-09-21T02:00:00Z",
            Some("2026-09-21T03:00:00Z"),
            Some("FREQ=WEEKLY;BYDAY=MO"),
            &["2026-10-05T02:00:00Z"],
        ));
        assert!(!trunc);
        assert!(occ.len() >= 50 && occ.len() <= 53, "{}", occ.len());
        assert!(occ
            .iter()
            .all(|(s, _)| *s != parse_ts("2026-10-05T02:00:00Z").unwrap()));
        assert!(occ
            .iter()
            .any(|(s, _)| *s == parse_ts("2026-10-12T02:00:00Z").unwrap()));
        assert_eq!(
            occ[0].1,
            parse_ts("2026-09-21T03:00:00Z"),
            "duration carried over"
        );
    }

    #[test]
    fn minutely_is_capped() {
        let (occ, trunc) = expand_occurrences(&row(
            "2026-09-21T00:00:00Z",
            None,
            Some("FREQ=MINUTELY"),
            &[],
        ));
        assert_eq!(occ.len(), MAX_OCCURRENCES_PER_ENTITY);
        assert!(trunc);
    }

    #[test]
    fn bad_rule_falls_back_to_single_occurrence() {
        let (occ, trunc) = expand_occurrences(&row(
            "2026-09-21T00:00:00Z",
            None,
            Some("FREQ=SOMETIMES"),
            &[],
        ));
        assert_eq!(occ.len(), 1);
        assert!(!trunc);
    }

    #[test]
    fn order_sql_rejects_unknown_fields() {
        assert!(order_sql(&[OrderKey {
            field: "nope".into(),
            ascending: true
        }])
        .is_err());
        assert_eq!(order_sql(&[]).unwrap(), "updated_at DESC, rowid ASC");
    }
}
