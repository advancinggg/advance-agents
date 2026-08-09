//! JSONL → SQLite rebuild path (Slice B AC-09).
//!
//! Algorithm spelled out in plan §"AC-09 rebuild algorithm spell-out": iterate
//! `<jsonl_dir>/*.jsonl` in date order, replay events into the events table, derive
//! traces / runs / agent_stats aggregations.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Adversarial Round-1 W6 fix: per-line size cap for JSONL parsing during
/// rebuild. A crafted file with no `\n` would otherwise let `BufReader::lines`
/// grow its internal `String` until OOM. Cap at 1 MiB which covers any
/// legitimate event (payload ≤ 64 KiB; full JSON envelope < 100 KiB) with 10×
/// headroom for over-redacted lines. Lines exceeding the cap are skipped and
/// counted in `RebuildReport.lines_skipped`.
const MAX_REBUILD_LINE_BYTES: u64 = 1024 * 1024;

use advance_shared_types::event::Event;
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};

use crate::error::EventBusError;
use crate::schema;

#[derive(Debug, Default)]
pub struct RebuildReport {
    pub events_replayed: u64,
    pub lines_skipped: u64,
    pub traces_built: u64,
    pub runs_built: u64,
    pub agent_stats_built: u64,
}

#[derive(Debug, Default)]
struct TraceAccum {
    start_at: Option<DateTime<Utc>>,
    end_at: Option<DateTime<Utc>>,
    total_events: i64,
    has_error: bool,
}

#[derive(Debug, Default)]
struct RunAccum {
    task_id: String,
    controller_agent: Option<String>,
    status: Option<String>,
    token_used: i64,
    cost_usd: f64,
    last_resume_reason: Option<String>,
}

#[derive(Debug, Default)]
struct AgentStatsAccum {
    active_tasks: i64,
    completed_tasks: i64,
    llm_tokens_24h: i64,
    error_count_24h: i64,
    last_active: Option<DateTime<Utc>>,
}

/// Rebuild the events.db SQLite contents from JSONL files in `jsonl_dir`.
///
/// The destination DB is OPENED OR CREATED by this function; if it already
/// exists it is opened in-place and `apply` migrations bring it to v2 if
/// necessary. The function does NOT delete existing rows — callers should pass
/// an empty / fresh `db_path` for a clean rebuild.
pub fn rebuild_sqlite_from_jsonl(
    jsonl_dir: &Path,
    db_path: &Path,
) -> Result<RebuildReport, EventBusError> {
    let mut report = RebuildReport::default();

    // Open / create the destination DB and migrate to v2.
    let mut conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;
    schema::apply(&mut conn)?;

    let files = list_jsonl_files(jsonl_dir)?;

    let mut traces: HashMap<String, TraceAccum> = HashMap::new();
    let mut runs: HashMap<String, RunAccum> = HashMap::new();
    let mut agent_stats: HashMap<String, AgentStatsAccum> = HashMap::new();

    let tx = conn.transaction()?;
    {
        let mut insert_event = tx.prepare_cached(
            "INSERT OR REPLACE INTO events (id, timestamp, agent_id, task_id, run_id, execution_id, \
             trace_id, span_id, parent_span_id, event_type, payload, duration_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;

        for file in &files {
            let f = match fs::File::open(file) {
                Ok(f) => f,
                Err(_) => continue,
            };
            // Adversarial Round-1 W6 fix: wrap in `take(MAX)` per line via a
            // bounded line-reader pattern. We use a fresh BufReader per file
            // and read line-by-line with manual length tracking so a malicious
            // unbounded line is truncated.
            let reader = BufReader::new(f);
            for line in BoundedLines::new(reader, MAX_REBUILD_LINE_BYTES) {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => {
                        report.lines_skipped += 1;
                        continue;
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                let event: Event = match serde_json::from_str(&line) {
                    Ok(e) => e,
                    Err(_) => {
                        report.lines_skipped += 1;
                        continue;
                    }
                };

                let timestamp_str = event.timestamp.format("%FT%T%.fZ").to_string();
                let payload_str =
                    serde_json::to_string(&event.payload).unwrap_or_else(|_| "null".into());
                insert_event.execute(rusqlite::params![
                    event.id,
                    timestamp_str,
                    event.agent_id,
                    event.task_id,
                    event.run_id,
                    event.execution_id,
                    event.trace_id,
                    event.span_id,
                    event.parent_span_id,
                    event.event_type,
                    payload_str,
                    event.duration_ms.map(|v| v as i64),
                ])?;
                report.events_replayed += 1;

                fold_trace(&mut traces, &event);
                fold_run(&mut runs, &event);
                fold_agent_stats(&mut agent_stats, &event);
            }
        }

        // Flush traces.
        let mut upsert_trace = tx.prepare_cached(
            "INSERT OR REPLACE INTO traces (trace_id, start_at, end_at, total_events, has_error) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for (trace_id, accum) in &traces {
            upsert_trace.execute(rusqlite::params![
                trace_id,
                accum
                    .start_at
                    .map(|t| t.format("%FT%T%.fZ").to_string())
                    .unwrap_or_default(),
                accum.end_at.map(|t| t.format("%FT%T%.fZ").to_string()),
                accum.total_events,
                accum.has_error as i64,
            ])?;
            report.traces_built += 1;
        }

        // Flush runs.
        let mut upsert_run = tx.prepare_cached(
            "INSERT OR REPLACE INTO runs (run_id, task_id, controller_agent, status, token_used, cost_usd, last_resume_reason) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for (run_id, accum) in &runs {
            upsert_run.execute(rusqlite::params![
                run_id,
                accum.task_id,
                accum.controller_agent,
                accum.status,
                accum.token_used,
                accum.cost_usd,
                accum.last_resume_reason,
            ])?;
            report.runs_built += 1;
        }

        // Flush agent_stats.
        let mut upsert_agent = tx.prepare_cached(
            "INSERT OR REPLACE INTO agent_stats (agent_id, active_tasks, completed_tasks, avg_turns_per_task, \
             avg_completion_time_hours, memory_entries, llm_tokens_24h, error_count_24h, last_active) \
             VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, ?6)",
        )?;
        for (agent_id, accum) in &agent_stats {
            upsert_agent.execute(rusqlite::params![
                agent_id,
                accum.active_tasks,
                accum.completed_tasks,
                accum.llm_tokens_24h,
                accum.error_count_24h,
                accum.last_active.map(|t| t.format("%FT%T%.fZ").to_string()),
            ])?;
            report.agent_stats_built += 1;
        }
    }
    tx.commit()?;

    Ok(report)
}

/// Bounded line iterator: like `BufReader::lines()` but each line is capped
/// at `max_bytes`. Lines exceeding the cap return `Err` and the underlying
/// reader skips past the next `\n` before resuming.
struct BoundedLines<R: BufRead> {
    reader: R,
    max_bytes: u64,
}

impl<R: BufRead> BoundedLines<R> {
    fn new(reader: R, max_bytes: u64) -> Self {
        Self { reader, max_bytes }
    }
}

impl<R: BufRead> Iterator for BoundedLines<R> {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = String::new();
        let mut total: u64 = 0;
        loop {
            // Decide consumed/found-newline/oob in a SCOPED borrow so we can
            // call consume() afterwards without overlapping the `fill_buf` borrow.
            enum Step {
                Eof,
                NewlineAt(usize, String),
                AccumulateAndAdvance(usize, String),
                // Declared step vocabulary: these two outcomes are currently handled
                // inline at their decision sites instead of round-tripping through
                // Step, so no constructor remains. Kept for the exhaustive match.
                #[allow(dead_code)]
                BudgetExhausted,
                Utf8Err(usize),
                #[allow(dead_code)]
                IoErr(std::io::Error),
            }
            let step = {
                let chunk = match self.reader.fill_buf() {
                    Ok(c) => c,
                    Err(e) => return Some(Err(e)),
                };
                if chunk.is_empty() {
                    Step::Eof
                } else {
                    let remaining = self.max_bytes.saturating_sub(total);
                    let take = (chunk.len() as u64).min(remaining) as usize;
                    let scan = &chunk[..take];
                    match scan.iter().position(|b| *b == b'\n') {
                        Some(idx) => {
                            let consumed = idx + 1;
                            match std::str::from_utf8(&scan[..consumed]) {
                                Ok(s) => Step::NewlineAt(consumed, s.to_string()),
                                Err(_) => Step::Utf8Err(consumed),
                            }
                        }
                        None => match std::str::from_utf8(scan) {
                            Ok(s) => Step::AccumulateAndAdvance(take, s.to_string()),
                            Err(_) => Step::Utf8Err(take),
                        },
                    }
                }
            };
            // chunk borrow released. Now safe to consume / read_until.
            match step {
                Step::Eof => return if buf.is_empty() { None } else { Some(Ok(buf)) },
                Step::NewlineAt(consumed, s) => {
                    self.reader.consume(consumed);
                    buf.push_str(&s);
                    return Some(Ok(buf));
                }
                Step::Utf8Err(consumed) => {
                    self.reader.consume(consumed);
                    return Some(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "rebuild: invalid utf-8 in JSONL line",
                    )));
                }
                Step::AccumulateAndAdvance(take, s) => {
                    self.reader.consume(take);
                    buf.push_str(&s);
                    total += take as u64;
                    if total >= self.max_bytes {
                        let mut skip = Vec::new();
                        let _ = self.reader.read_until(b'\n', &mut skip);
                        return Some(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "rebuild: line exceeded MAX_REBUILD_LINE_BYTES",
                        )));
                    }
                }
                Step::BudgetExhausted => {
                    return Some(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "rebuild: line exceeded MAX_REBUILD_LINE_BYTES",
                    )));
                }
                Step::IoErr(e) => return Some(Err(e)),
            }
        }
    }
}

fn list_jsonl_files(dir: &Path) -> Result<Vec<PathBuf>, EventBusError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "jsonl" {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn fold_trace(traces: &mut HashMap<String, TraceAccum>, event: &Event) {
    let trace_id = event.trace_id.clone();
    let entry = traces.entry(trace_id).or_default();
    // Round-1 AUDIT diff Warning 9 fix: use min(prev, new) for start_at instead
    // of "first-seen wins". JSONL files are read in date-filename order, but
    // events within a file may not be timestamp-sorted (e.g., late-arriving
    // out-of-order writes). start_at must reflect the EARLIEST event timestamp.
    entry.start_at = Some(match entry.start_at {
        Some(prev) if prev < event.timestamp => prev,
        _ => event.timestamp,
    });
    entry.end_at = Some(match entry.end_at {
        Some(prev) if prev > event.timestamp => prev,
        _ => event.timestamp,
    });
    entry.total_events += 1;
    if event.event_type.ends_with(".error") {
        entry.has_error = true;
    }
}

fn fold_run(runs: &mut HashMap<String, RunAccum>, event: &Event) {
    let Some(run_id) = event.run_id.clone() else {
        return;
    };
    let entry = runs.entry(run_id).or_default();
    match event.event_type.as_str() {
        "run.created" => {
            if let Some(task_id) = event.payload.get("task_id").and_then(|v| v.as_str()) {
                entry.task_id = task_id.to_string();
            }
            entry.controller_agent = event
                .payload
                .get("controller_agent")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            entry.status = Some("Active".into());
        }
        "run.completed" => {
            entry.status = Some("Completed".into());
            entry.last_resume_reason = event
                .payload
                .get("last_resume_reason")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
        "run.suspended" => entry.status = Some("Suspended".into()),
        "run.paused" => entry.status = Some("Paused".into()),
        "run.cancelled" => entry.status = Some("Cancelled".into()),
        "run.resumed" => entry.status = Some("Active".into()),
        "llm.response" => {
            let input = event
                .payload
                .get("input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let output = event
                .payload
                .get("output_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            entry.token_used = entry
                .token_used
                .saturating_add(input.saturating_add(output) as i64);
            let cost = event
                .payload
                .get("cost_usd")
                .and_then(|v| v.as_f64())
                .filter(|v| v.is_finite() && *v >= 0.0)
                .unwrap_or(0.0);
            entry.cost_usd += cost;
        }
        _ => {}
    }
}

fn fold_agent_stats(agent_stats: &mut HashMap<String, AgentStatsAccum>, event: &Event) {
    if event.agent_id.is_empty() {
        return;
    }
    let entry = agent_stats.entry(event.agent_id.clone()).or_default();
    match event.event_type.as_str() {
        "task.created" => entry.active_tasks = entry.active_tasks.saturating_add(1),
        "task.completed" => {
            entry.active_tasks = entry.active_tasks.saturating_sub(1);
            entry.completed_tasks = entry.completed_tasks.saturating_add(1);
        }
        "llm.response" => {
            let input = event
                .payload
                .get("input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let output = event
                .payload
                .get("output_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            entry.llm_tokens_24h = entry
                .llm_tokens_24h
                .saturating_add(input.saturating_add(output) as i64);
        }
        t if t.ends_with(".error") => {
            entry.error_count_24h = entry.error_count_24h.saturating_add(1);
        }
        _ => {}
    }
    entry.last_active = Some(event.timestamp);
}
