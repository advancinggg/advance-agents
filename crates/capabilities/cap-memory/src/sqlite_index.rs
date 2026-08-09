//! Cap-memory-internal SQLite-index seam (slice F, AC-19/24/27/31).
//!
//! `InMemorySqliteIndex` ships a `Mutex<HashMap>`-backed stub for tests (3
//! tables — turn / task / memory — keyed for multi-tenant scoping). Production
//! `rusqlite` + `sqlite-vec` adapter delegating to MODULE-004 CONTRACT-030
//! `SqliteIndexHandle` is deferred to a future M004 wiring slice — see
//! MODULE-011 §3.6 row "Production rusqlite + sqlite-vec adapter for
//! `SqliteIndex` seam".
//!
//! NOT promoted to `crates/shared-types`, NOT registered in
//! ARCHITECTURE.md §6.1 — same posture as slice B/C/D internal seams (per
//! MODULE-011 §2.7 explicit guidance).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;

/// Per-table global row cap for [`InMemorySqliteIndex`] (slice
/// `dev-task-mem-retention`). Bounds each of the 3 tables so a caller looping
/// `sync_turn_index` with monotonic `turn`s (or `sync_task_index` with distinct
/// `task_id`s) cannot grow a table without bound (memory-exhaustion DoS). On an
/// insert of a NEW key when the table is at capacity, the OLDEST-INSERTED row is
/// evicted first (FIFO — O(1), deterministic; see [`BoundedTable`]). Overwrites
/// of an existing key never evict. Defense-in-depth: there is still no production
/// caller of the 4 seam methods.
pub const MAX_INDEX_ROWS_PER_TABLE: usize = 100_000;

/// A `HashMap` bounded to a row cap with O(1), deterministic **FIFO** eviction:
/// a `VecDeque` records insertion order so the oldest-inserted key is evicted in
/// O(1) (no per-insert scan, no tie-break ambiguity). Overwriting an existing key
/// is O(1) and does not change eviction order or evict anything.
struct BoundedTable<K, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K, V> Default for BoundedTable<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<K: Clone + Eq + Hash, V> BoundedTable<K, V> {
    /// Insert or overwrite `key`→`row`. On a NEW key at `cap`, evict the
    /// oldest-inserted key(s) first (FIFO) to make room. Overwrites never evict.
    fn upsert(&mut self, key: K, row: V, cap: usize) {
        if self.map.contains_key(&key) {
            self.map.insert(key, row); // overwrite; insertion order unchanged
            return;
        }
        // Evict oldest-inserted until there is room for the new key. The `while`
        // (not `if`) is robust to a `cap` reduced between sessions. `pop_front`
        // keys are always present in `map` (added/removed in lockstep below).
        while self.map.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.map.remove(&old);
                }
                None => break,
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, row);
    }

    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key)
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        self.map.values()
    }
}

/// Row in the per-agent turn_index (AC-19 + AC-31).
///
/// `embedding` is a Vec<f32> from [`crate::embedder::Embedder::embed`]
/// (slice F stub = 8 dim; production = whatever the configured model produces).
/// `reference_count` mirrors `TurnEntry.reference_count` at sync time;
/// [`SqliteIndex`] callers use [`InMemorySqliteIndex::get_turn`] +
/// [`InMemorySqliteIndex::upsert_turn`] to bump it without recomputing the
/// embedding (AC-31 invariant — see `Components::bump_turn_reference`).
#[derive(Clone, Debug, PartialEq)]
pub struct TurnIndexRow {
    pub agent_id: String,
    pub task_id: String,
    pub turn: u32,
    pub digest: String,
    pub embedding: Vec<f32>,
    pub reference_count: u32,
    pub updated_at: String,
}

/// Row in the task_index (AC-27).
///
/// `brief_snapshot` is the verbatim `summary.brief` text stored alongside the
/// embedding — the slice-F string-equality brief-change gate (deterministic
/// substitute for semantic similarity; see MODULE-011 §3.8 note 12) compares
/// the current `summary.brief` against this field to decide whether to
/// recompute `brief_embedding`.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskIndexRow {
    pub task_id: String,
    pub agent_id: String,
    pub last_turn_at: String,
    pub turns_total: u32,
    pub updated_at: String,
    pub brief_snapshot: String,
    pub brief_embedding: Option<Vec<f32>>,
}

/// Row in the per-agent memory_index (AC-24).
///
/// `epistemic_status` is the lowercase string form of
/// [`crate::knowledge::MemoryStatus`] returned by
/// [`crate::knowledge::MemoryStatus::as_str`] — one of `"active"` /
/// `"contested"` / `"orphaned"` / `"superseded"` / `"forgotten"`.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryIndexRow {
    pub agent_id: String,
    pub memory_id: String,
    pub epistemic_status: String,
    pub updated_at: String,
}

/// Cap-memory-internal SQLite-index seam. Production adapter (rusqlite +
/// sqlite-vec via MODULE-004 CONTRACT-030) deferred per MODULE-011 §3.6.
pub trait SqliteIndex: Send + Sync {
    fn upsert_turn(&self, row: TurnIndexRow);
    fn upsert_task(&self, row: TaskIndexRow);
    fn upsert_memory(&self, row: MemoryIndexRow);

    fn get_turn(&self, agent_id: &str, task_id: &str, turn: u32) -> Option<TurnIndexRow>;
    fn get_task(&self, task_id: &str) -> Option<TaskIndexRow>;
    fn get_memory(&self, agent_id: &str, memory_id: &str) -> Option<MemoryIndexRow>;

    fn list_turns_for_agent(&self, agent_id: &str) -> Vec<TurnIndexRow>;
    fn list_tasks_for_agent(&self, agent_id: &str) -> Vec<TaskIndexRow>;
    fn list_memory_for_agent(&self, agent_id: &str) -> Vec<MemoryIndexRow>;
}

/// `Mutex<BoundedTable>`-backed in-memory `SqliteIndex` stub (each table capped at
/// [`MAX_INDEX_ROWS_PER_TABLE`] with FIFO eviction).
///
/// Multi-tenant keying matches a future rusqlite adapter's WHERE clauses:
/// - turn rows keyed `(agent_id, task_id, turn)`
/// - task rows keyed `task_id` (tasks span agents in PRD §11.3.3 but slice F's
///   single-agent test cases pass a row with a populated `agent_id` field for
///   filtering via [`list_tasks_for_agent`])
/// - memory rows keyed `(agent_id, memory_id)`
#[derive(Default)]
pub struct InMemorySqliteIndex {
    turn: Mutex<BoundedTable<(String, String, u32), TurnIndexRow>>,
    task: Mutex<BoundedTable<String, TaskIndexRow>>,
    memory: Mutex<BoundedTable<(String, String), MemoryIndexRow>>,
}

impl SqliteIndex for InMemorySqliteIndex {
    fn upsert_turn(&self, row: TurnIndexRow) {
        let key = (row.agent_id.clone(), row.task_id.clone(), row.turn);
        self.turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upsert(key, row, MAX_INDEX_ROWS_PER_TABLE);
    }

    fn upsert_task(&self, row: TaskIndexRow) {
        let key = row.task_id.clone();
        self.task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upsert(key, row, MAX_INDEX_ROWS_PER_TABLE);
    }

    fn upsert_memory(&self, row: MemoryIndexRow) {
        let key = (row.agent_id.clone(), row.memory_id.clone());
        self.memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upsert(key, row, MAX_INDEX_ROWS_PER_TABLE);
    }

    fn get_turn(&self, agent_id: &str, task_id: &str, turn: u32) -> Option<TurnIndexRow> {
        let guard = self
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .get(&(agent_id.to_owned(), task_id.to_owned(), turn))
            .cloned()
    }

    fn get_task(&self, task_id: &str) -> Option<TaskIndexRow> {
        let guard = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(task_id).cloned()
    }

    fn get_memory(&self, agent_id: &str, memory_id: &str) -> Option<MemoryIndexRow> {
        let guard = self
            .memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .get(&(agent_id.to_owned(), memory_id.to_owned()))
            .cloned()
    }

    fn list_turns_for_agent(&self, agent_id: &str) -> Vec<TurnIndexRow> {
        let guard = self
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .values()
            .filter(|r| r.agent_id == agent_id)
            .cloned()
            .collect()
    }

    fn list_tasks_for_agent(&self, agent_id: &str) -> Vec<TaskIndexRow> {
        let guard = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .values()
            .filter(|r| r.agent_id == agent_id)
            .cloned()
            .collect()
    }

    fn list_memory_for_agent(&self, agent_id: &str) -> Vec<MemoryIndexRow> {
        let guard = self
            .memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .values()
            .filter(|r| r.agent_id == agent_id)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(agent: &str, task: &str, t: u32) -> TurnIndexRow {
        TurnIndexRow {
            agent_id: agent.into(),
            task_id: task.into(),
            turn: t,
            digest: format!("d-{t}"),
            embedding: vec![0.1; 8],
            reference_count: 0,
            updated_at: "2026-05-22T00:00:00Z".into(),
        }
    }

    fn task(task_id: &str, agent: &str) -> TaskIndexRow {
        TaskIndexRow {
            task_id: task_id.into(),
            agent_id: agent.into(),
            last_turn_at: "2026-05-22T00:00:00Z".into(),
            turns_total: 1,
            updated_at: "2026-05-22T00:00:00Z".into(),
            brief_snapshot: "init".into(),
            brief_embedding: None,
        }
    }

    fn memory(agent: &str, id: &str, status: &str) -> MemoryIndexRow {
        MemoryIndexRow {
            agent_id: agent.into(),
            memory_id: id.into(),
            epistemic_status: status.into(),
            updated_at: "2026-05-22T00:00:00Z".into(),
        }
    }

    #[test]
    fn upsert_then_get_turn_round_trip() {
        let ix = InMemorySqliteIndex::default();
        let r = turn("agent:r", "task-001", 7);
        ix.upsert_turn(r.clone());
        assert_eq!(ix.get_turn("agent:r", "task-001", 7), Some(r));
    }

    #[test]
    fn upsert_turn_overwrites_same_key() {
        let ix = InMemorySqliteIndex::default();
        ix.upsert_turn(turn("agent:r", "task-001", 1));
        let mut r2 = turn("agent:r", "task-001", 1);
        r2.reference_count = 3;
        r2.updated_at = "2026-05-23T00:00:00Z".into();
        ix.upsert_turn(r2.clone());
        assert_eq!(ix.get_turn("agent:r", "task-001", 1), Some(r2));
    }

    #[test]
    fn get_turn_missing_returns_none() {
        let ix = InMemorySqliteIndex::default();
        assert_eq!(ix.get_turn("agent:r", "task-001", 99), None);
    }

    #[test]
    fn upsert_then_get_task_round_trip() {
        let ix = InMemorySqliteIndex::default();
        let r = task("task-001", "agent:r");
        ix.upsert_task(r.clone());
        assert_eq!(ix.get_task("task-001"), Some(r));
    }

    #[test]
    fn upsert_then_get_memory_round_trip() {
        let ix = InMemorySqliteIndex::default();
        let r = memory("agent:r", "mem-001", "active");
        ix.upsert_memory(r.clone());
        assert_eq!(ix.get_memory("agent:r", "mem-001"), Some(r));
    }

    #[test]
    fn list_turns_filters_by_agent() {
        let ix = InMemorySqliteIndex::default();
        ix.upsert_turn(turn("agent:r", "task-001", 1));
        ix.upsert_turn(turn("agent:r", "task-001", 2));
        ix.upsert_turn(turn("agent:s", "task-002", 1));
        let r_rows = ix.list_turns_for_agent("agent:r");
        let s_rows = ix.list_turns_for_agent("agent:s");
        assert_eq!(r_rows.len(), 2);
        assert_eq!(s_rows.len(), 1);
    }

    #[test]
    fn list_tasks_filters_by_agent() {
        let ix = InMemorySqliteIndex::default();
        ix.upsert_task(task("task-001", "agent:r"));
        ix.upsert_task(task("task-002", "agent:s"));
        assert_eq!(ix.list_tasks_for_agent("agent:r").len(), 1);
        assert_eq!(ix.list_tasks_for_agent("agent:s").len(), 1);
        assert_eq!(ix.list_tasks_for_agent("agent:absent").len(), 0);
    }

    #[test]
    fn list_memory_filters_by_agent() {
        let ix = InMemorySqliteIndex::default();
        ix.upsert_memory(memory("agent:r", "m1", "active"));
        ix.upsert_memory(memory("agent:r", "m2", "contested"));
        ix.upsert_memory(memory("agent:s", "m3", "active"));
        assert_eq!(ix.list_memory_for_agent("agent:r").len(), 2);
        assert_eq!(ix.list_memory_for_agent("agent:s").len(), 1);
    }

    #[test]
    fn turn_keys_disambiguate_agent_and_task() {
        let ix = InMemorySqliteIndex::default();
        ix.upsert_turn(turn("agent:r", "task-001", 1));
        ix.upsert_turn(turn("agent:r", "task-002", 1));
        ix.upsert_turn(turn("agent:s", "task-001", 1));
        assert!(ix.get_turn("agent:r", "task-001", 1).is_some());
        assert!(ix.get_turn("agent:r", "task-002", 1).is_some());
        assert!(ix.get_turn("agent:s", "task-001", 1).is_some());
        assert_eq!(ix.list_turns_for_agent("agent:r").len(), 2);
        assert_eq!(ix.list_turns_for_agent("agent:s").len(), 1);
    }

    fn mrow(id: &str, ts: &str) -> MemoryIndexRow {
        MemoryIndexRow {
            agent_id: "a".into(),
            memory_id: id.into(),
            epistemic_status: "active".into(),
            updated_at: ts.into(),
        }
    }

    #[test]
    fn bounded_table_fifo_evicts_oldest_inserted() {
        let mut t: BoundedTable<String, MemoryIndexRow> = BoundedTable::default();
        // Fill to cap=3 (insertion order m1, m2, m3).
        t.upsert("m1".into(), mrow("m1", "t1"), 3);
        t.upsert("m2".into(), mrow("m2", "t2"), 3);
        t.upsert("m3".into(), mrow("m3", "t3"), 3);
        // A NEW key at cap evicts the OLDEST-INSERTED (m1) — deterministic, O(1).
        t.upsert("m4".into(), mrow("m4", "t4"), 3);
        assert!(
            t.get(&"m1".to_string()).is_none(),
            "oldest-inserted m1 evicted"
        );
        assert!(t.get(&"m4".to_string()).is_some(), "newest m4 present");
        assert_eq!(t.values().count(), 3, "table stays at cap");
        // Overwriting an EXISTING key never evicts and does not change order.
        t.upsert("m2".into(), mrow("m2", "t2b"), 3);
        assert_eq!(t.values().count(), 3, "overwrite does not grow or evict");
        assert_eq!(
            t.get(&"m2".to_string()).unwrap().updated_at,
            "t2b",
            "overwrite applied"
        );
        // Next NEW key evicts m2 (the next-oldest by insertion, NOT m3) —
        // overwrite did not refresh its FIFO position.
        t.upsert("m5".into(), mrow("m5", "t5"), 3);
        assert!(
            t.get(&"m2".to_string()).is_none(),
            "m2 (next oldest-inserted) evicted"
        );
        assert!(t.get(&"m3".to_string()).is_some(), "m3 retained");
    }

    #[test]
    fn index_row_cap_under_cap_never_evicts() {
        // Sanity through the real seam path: under-cap upserts never drop rows.
        let ix = InMemorySqliteIndex::default();
        ix.upsert_memory(mrow("x1", "2026-01-01T00:00:00Z"));
        ix.upsert_memory(mrow("x2", "2026-01-02T00:00:00Z"));
        assert_eq!(ix.list_memory_for_agent("a").len(), 2);
        // Overwrite is a no-growth update.
        ix.upsert_memory(mrow("x1", "2026-01-03T00:00:00Z"));
        assert_eq!(ix.list_memory_for_agent("a").len(), 2);
    }
}
