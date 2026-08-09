//! Per-agent rolling-24h stats accumulator + 1s tick task (Slice B AC-16).
//!
//! Implementation strategy:
//! - Actor pattern: receives `Event` clones via `mpsc::Receiver<Event>`.
//! - In-memory state: `LruCache<String, AgentStatsAccum>` capped at 1000 agents
//!   (Round-2 W6 / Round-3 W4 fix). Oldest-agent eviction on insert overflow.
//! - 1s tick (`tokio::time::interval`) flushes `agent_stats` UPSERTs in a single
//!   transaction (Round-3 W4 fix: minimizes SQLite writer-mutex contention).
//! - Rolling 24h window: per-agent `VecDeque<(DateTime<Utc>, EventKind)>`; on tick,
//!   pop entries older than 24h and decrement counters.
//!
//! Test injection: `Clock` trait via `Box<dyn Clock>` lets tests fast-forward.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use advance_shared_types::event::Event;
use chrono::{DateTime, Duration, Utc};
use lru::LruCache;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::clock::Clock;
use crate::error::EventBusError;

const DEFAULT_MAX_TRACKED_AGENTS: usize = 1000;
const ROLLING_WINDOW_HOURS: i64 = 24;

#[derive(Debug, Clone)]
pub(crate) enum EventKind {
    LlmResponse { tokens: u64 },
    TaskCreated,
    TaskCompleted,
    Error,
    Other,
}

impl EventKind {
    fn from_event(event: &Event) -> Self {
        match event.event_type.as_str() {
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
                EventKind::LlmResponse {
                    tokens: input.saturating_add(output),
                }
            }
            "task.created" => EventKind::TaskCreated,
            "task.completed" => EventKind::TaskCompleted,
            t if t.ends_with(".error") => EventKind::Error,
            _ => EventKind::Other,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct AgentStatsAccum {
    pub active_tasks: i64,
    pub completed_tasks: i64,
    pub llm_tokens_24h: i64,
    pub error_count_24h: i64,
    pub last_active: Option<DateTime<Utc>>,
    /// Rolling window of (timestamp, kind) entries for 24h trim.
    pub window: VecDeque<(DateTime<Utc>, EventKind)>,
}

impl AgentStatsAccum {
    fn record(&mut self, ts: DateTime<Utc>, kind: EventKind) {
        match &kind {
            EventKind::LlmResponse { tokens } => {
                self.llm_tokens_24h = self.llm_tokens_24h.saturating_add(*tokens as i64);
            }
            EventKind::TaskCreated => {
                self.active_tasks = self.active_tasks.saturating_add(1);
            }
            EventKind::TaskCompleted => {
                self.active_tasks = self.active_tasks.saturating_sub(1);
                self.completed_tasks = self.completed_tasks.saturating_add(1);
            }
            EventKind::Error => {
                self.error_count_24h = self.error_count_24h.saturating_add(1);
            }
            EventKind::Other => {}
        }
        self.last_active = Some(ts);
        self.window.push_back((ts, kind));
    }

    /// Drop entries older than `now - 24h` and reverse their counter contribution.
    fn trim(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::hours(ROLLING_WINDOW_HOURS);
        while let Some((ts, _)) = self.window.front() {
            if *ts >= cutoff {
                break;
            }
            let (_, kind) = self.window.pop_front().expect("front exists");
            match kind {
                EventKind::LlmResponse { tokens } => {
                    self.llm_tokens_24h = self.llm_tokens_24h.saturating_sub(tokens as i64);
                }
                EventKind::Error => {
                    self.error_count_24h = self.error_count_24h.saturating_sub(1);
                }
                EventKind::TaskCreated | EventKind::TaskCompleted | EventKind::Other => {
                    // active_tasks / completed_tasks are NOT reversed on trim — they
                    // represent absolute counts, not 24h-window counts.
                }
            }
        }
    }
}

const UPSERT_AGENT_STATS_SQL: &str = "INSERT INTO agent_stats (agent_id, active_tasks, completed_tasks, avg_turns_per_task, avg_completion_time_hours, memory_entries, llm_tokens_24h, error_count_24h, last_active) \
    VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, ?6) \
    ON CONFLICT(agent_id) DO UPDATE SET \
        active_tasks = excluded.active_tasks, \
        completed_tasks = excluded.completed_tasks, \
        llm_tokens_24h = excluded.llm_tokens_24h, \
        error_count_24h = excluded.error_count_24h, \
        last_active = excluded.last_active";

/// Spawn the stats aggregator background task.
///
/// Returns the receive-side `mpsc::Sender<Arc<Event>>` for the EventBus to enqueue
/// events. The task lives until `cancel_token` is triggered.
pub(crate) fn spawn(
    pool: Arc<Pool<SqliteConnectionManager>>,
    clock: Arc<dyn Clock>,
    cancel_token: CancellationToken,
    max_agents: Option<usize>,
) -> (mpsc::Sender<Arc<Event>>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Arc<Event>>(10_000);
    let cap = max_agents.unwrap_or(DEFAULT_MAX_TRACKED_AGENTS);
    let cap_nonzero =
        NonZeroUsize::new(cap.max(1)).expect("max_tracked_agents fallback to 1 must be non-zero");

    let handle = tokio::spawn(async move {
        let mut cache: LruCache<String, AgentStatsAccum> = LruCache::new(cap_nonzero);
        let mut tick = tokio::time::interval(StdDuration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the first immediate tick.
        tick.tick().await;

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    // Slice C plan Round 5 Codex W3 fix: drain rx BEFORE flushing
                    // so events buffered at cancel time enter the cache before the
                    // final UPSERT (otherwise the flush misses them and counters
                    // diverge from JSONL truth).
                    while let Ok(event) = rx.try_recv() {
                        if event.agent_id.is_empty() {
                            continue;
                        }
                        let kind = EventKind::from_event(&event);
                        let key = event.agent_id.clone();
                        let entry = if cache.contains(&key) {
                            cache.get_mut(&key).expect("contains check above")
                        } else {
                            let seeded = read_persisted_agent_stats(&pool, &key)
                                .unwrap_or_default();
                            cache.put(key.clone(), seeded);
                            cache.get_mut(&key).expect("just inserted")
                        };
                        entry.record(event.timestamp, kind);
                    }
                    let _ = flush_all(&pool, &mut cache, clock.now());
                    return;
                }
                _ = tick.tick() => {
                    let _ = flush_all(&pool, &mut cache, clock.now());
                }
                maybe = rx.recv() => {
                    match maybe {
                        Some(event) => {
                            if event.agent_id.is_empty() {
                                continue;
                            }
                            let kind = EventKind::from_event(&event);
                            let key = event.agent_id.clone();
                            // Adversarial Round-1 W4 fix: when an agent re-enters
                            // the cache after eviction, do NOT clobber prior
                            // persisted agent_stats with zeros. Read the current
                            // SQLite row first (if any) and seed the accumulator
                            // with the prior counters; this preserves
                            // active_tasks / completed_tasks / llm_tokens_24h /
                            // error_count_24h across an attacker-induced LRU
                            // eviction. Best-effort read — DB errors leave the
                            // accumulator at default(), which mirrors prior
                            // Slice B behavior.
                            let entry = if cache.contains(&key) {
                                cache.get_mut(&key).expect("contains check above")
                            } else {
                                let seeded = read_persisted_agent_stats(&pool, &key)
                                    .unwrap_or_default();
                                cache.put(key.clone(), seeded);
                                cache.get_mut(&key).expect("just inserted")
                            };
                            entry.record(event.timestamp, kind);
                        }
                        None => {
                            // Sender side dropped; drain final state and exit.
                            let _ = flush_all(&pool, &mut cache, clock.now());
                            return;
                        }
                    }
                }
            }
        }
    });

    (tx, handle)
}

/// Adversarial Round-1 W4 fix: read prior persisted counters when re-seeding
/// an evicted agent's accumulator. Prevents LRU-eviction-clobber attack where
/// flooding 1000+ synthetic agent_ids resets legitimate agents' counters to
/// zero on the next UPSERT tick.
///
/// Adversarial Round-2 W2 fix: the rolling-24h window cannot be exactly
/// reconstructed from persisted aggregates (the persisted row has TOTALS, not
/// per-event timestamps). To prevent the previously-eviction-stuck counters
/// from monotonically inflating forever, this re-seeder ZEROES the
/// `llm_tokens_24h` and `error_count_24h` rolling counters on re-seed. Only
/// `active_tasks`, `completed_tasks`, and `last_active` are preserved — those
/// are absolute counts, not 24h-windowed counts. The trade-off: across an LRU
/// eviction the rolling counters lose their pre-eviction contribution rather
/// than retain it forever undecayed. Fresh post-seed events accumulate
/// normally and decay normally at the 24h boundary. This is more honest than
/// the alternative (eternal monotonic inflation).
fn read_persisted_agent_stats(
    pool: &Arc<Pool<SqliteConnectionManager>>,
    agent_id: &str,
) -> Option<AgentStatsAccum> {
    let conn = pool.get().ok()?;
    let mut stmt = conn
        .prepare_cached(
            "SELECT active_tasks, completed_tasks, last_active \
             FROM agent_stats WHERE agent_id = ?1",
        )
        .ok()?;
    stmt.query_row([agent_id], |row| {
        let active: Option<i64> = row.get(0)?;
        let completed: Option<i64> = row.get(1)?;
        let last_active_str: Option<String> = row.get(2)?;
        let last_active = last_active_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        });
        Ok(AgentStatsAccum {
            active_tasks: active.unwrap_or(0),
            completed_tasks: completed.unwrap_or(0),
            // Rolling-24h counters reset to 0 on re-seed (see rustdoc above).
            llm_tokens_24h: 0,
            error_count_24h: 0,
            last_active,
            window: VecDeque::new(),
        })
    })
    .ok()
}

fn flush_all(
    pool: &Arc<Pool<SqliteConnectionManager>>,
    cache: &mut LruCache<String, AgentStatsAccum>,
    now: DateTime<Utc>,
) -> Result<(), EventBusError> {
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(UPSERT_AGENT_STATS_SQL)?;
        for (agent_id, accum) in cache.iter_mut() {
            accum.trim(now);
            stmt.execute(rusqlite::params![
                agent_id,
                accum.active_tasks,
                accum.completed_tasks,
                accum.llm_tokens_24h,
                accum.error_count_24h,
                accum.last_active.map(|t| t.format("%FT%T%.fZ").to_string()),
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}
