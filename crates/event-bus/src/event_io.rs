//! `Event` re-export + JSONL serialization + SQL parameter binding helpers.

pub use advance_shared_types::event::Event;

use rusqlite::{params, Statement};

use crate::error::EventBusError;

/// Serialize an `Event` to one JSONL line (`serde_json::to_string + '\n'`).
pub(crate) fn event_to_jsonl_line(event: &Event) -> Result<String, EventBusError> {
    let mut line = serde_json::to_string(event)?;
    line.push('\n');
    Ok(line)
}

/// Bind an `Event` to a prepared INSERT statement and execute it.
///
/// The statement must have 12 placeholders in the column order defined by
/// `schema::CREATE_EVENTS_SQL`.
///
/// **Timestamp format alignment** (round-1 audit Diff W2 fix): the SQLite `timestamp`
/// column is written using chrono's default serde format `%FT%T%.fZ` so the JSONL
/// line and the SQL row contain byte-identical timestamp strings (modulo
/// chrono's `%.f` "variable-width nanos" rule, which is identical on both sides
/// because both go through the same chrono Serialize / format pipeline). Downstream
/// tooling that joins or de-duplicates events by raw timestamp string across
/// sinks will see equal strings.
pub(crate) fn insert_event(
    stmt: &mut Statement<'_>,
    event: &Event,
) -> Result<usize, EventBusError> {
    let timestamp = event.timestamp.format("%FT%T%.fZ").to_string();
    let payload = serde_json::to_string(&event.payload)?;
    let rows = stmt.execute(params![
        event.id,
        timestamp,
        event.agent_id,
        event.task_id,
        event.run_id,
        event.execution_id,
        event.trace_id,
        event.span_id,
        event.parent_span_id,
        event.event_type,
        payload,
        event.duration_ms,
    ])?;
    Ok(rows)
}
