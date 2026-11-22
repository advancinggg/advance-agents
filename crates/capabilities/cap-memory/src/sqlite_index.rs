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

/// How many of an agent's most recently updated turn rows a recall read looks
/// at. The same number bounds the upkeep of stored vectors
/// ([`SqliteIndex::list_turns_not_of_model`]): a row no reader reaches is not
/// worth an embedding request.
pub const RECENT_TURN_WINDOW: usize = 4096;

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

    /// The row under `key`, to change in place (insertion order unchanged).
    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(key)
    }

    fn values(&self) -> impl Iterator<Item = &V> {
        self.map.values()
    }

    /// Drop every row `keep` refuses.
    fn retain(&mut self, mut keep: impl FnMut(&V) -> bool) {
        self.map.retain(|_, row| keep(row));
        let map = &self.map;
        self.order.retain(|key| map.contains_key(key));
    }
}

/// The order an agent's turn rows are read in — by a recall read and by the upkeep of
/// stored vectors alike: most recently updated first, ties in time broken by task and
/// then turn (the key, so unique per agent).
fn recent_turns_first(a: &TurnIndexRow, b: &TurnIndexRow) -> std::cmp::Ordering {
    b.updated_at
        .cmp(&a.updated_at)
        .then_with(|| a.task_id.cmp(&b.task_id))
        .then_with(|| a.turn.cmp(&b.turn))
}

/// [`recent_turns_first`] for an agent's task rows (keyed by task).
fn recent_tasks_first(a: &TaskIndexRow, b: &TaskIndexRow) -> std::cmp::Ordering {
    b.updated_at
        .cmp(&a.updated_at)
        .then_with(|| a.task_id.cmp(&b.task_id))
}

/// The index could not be read or written (a pool timeout, a busy or damaged file, an
/// I/O error). What a caller asked for is unknown — never "there is nothing".
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("memory index unavailable: {0}")]
pub struct IndexUnavailable(pub String);

/// Row in the per-agent turn_index (AC-19 + AC-31).
///
/// `embedding` is a Vec<f32> from [`crate::embedder::Embedder::embed`]
/// (slice F stub = 8 dim; production = whatever the configured model produces).
/// `reference_count` mirrors `TurnEntry.reference_count` at sync time;
/// [`SqliteIndex`] callers use [`InMemorySqliteIndex::get_turn`] +
/// [`InMemorySqliteIndex::upsert_turn`] to bump it without recomputing the
/// embedding (AC-31 invariant — see `Components::bump_turn_reference`).
///
/// `embedding_model` binds the vector to the model that produced it
/// ([`crate::embedder::Embedder::embed_recorded`]). A reader compares a row only
/// with a query vector of the SAME model. `None` — the producing model is not
/// known (the stub sketch, a row written before the column existed) or there is
/// no vector (`embedding` empty: nothing could embed when the row was written).
#[derive(Clone, Debug, PartialEq)]
pub struct TurnIndexRow {
    pub agent_id: String,
    pub task_id: String,
    pub turn: u32,
    pub digest: String,
    pub embedding: Vec<f32>,
    pub embedding_model: Option<String>,
    pub reference_count: u32,
    pub updated_at: String,
}

/// Row in the task_index (AC-27): ONE agent's view of a task, keyed
/// `(agent_id, task_id)`.
///
/// A task id can be shared by several agents (it is set by whoever sends the
/// message), and a home's agents share one index. The brief is read from the
/// agent's own `summary.yaml`, embedded on the agent's own provider and read back
/// by that agent alone — so each agent has its own row, and one agent's turn never
/// rewrites another's brief, vector or model.
///
/// `brief_snapshot` is the verbatim `summary.brief` text stored alongside the
/// embedding — the slice-F string-equality brief-change gate (deterministic
/// substitute for semantic similarity; see MODULE-011 §3.8 note 12) compares
/// the current `summary.brief` against this field to decide whether to
/// recompute `brief_embedding`. `brief_embedding_model` binds that vector to
/// the model that produced it (same contract as
/// [`TurnIndexRow::embedding_model`]); a model change re-embeds the brief.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskIndexRow {
    pub task_id: String,
    pub agent_id: String,
    pub last_turn_at: String,
    pub turns_total: u32,
    pub updated_at: String,
    pub brief_snapshot: String,
    pub brief_embedding: Option<Vec<f32>>,
    pub brief_embedding_model: Option<String>,
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
    /// `agent_id`'s own row for `task_id` (see [`TaskIndexRow`]).
    fn get_task(&self, agent_id: &str, task_id: &str) -> Option<TaskIndexRow>;
    fn get_memory(&self, agent_id: &str, memory_id: &str) -> Option<MemoryIndexRow>;

    fn list_turns_for_agent(&self, agent_id: &str) -> Vec<TurnIndexRow>;
    fn list_tasks_for_agent(&self, agent_id: &str) -> Vec<TaskIndexRow>;
    fn list_memory_for_agent(&self, agent_id: &str) -> Vec<MemoryIndexRow>;

    /// How many turn rows `agent_id` has: [`Self::list_turns_for_agent`]'s length. An
    /// index that keeps its rows outside memory counts them without reading them.
    fn count_turns_for_agent(&self, agent_id: &str) -> usize {
        self.list_turns_for_agent(agent_id).len()
    }
    /// How many task rows `agent_id` has, as [`Self::count_turns_for_agent`].
    fn count_tasks_for_agent(&self, agent_id: &str) -> usize {
        self.list_tasks_for_agent(agent_id).len()
    }

    /// `agent_id`'s `window` latest turn rows of `task_id` (the highest turn numbers), latest
    /// first: what a search of one task's turns reads (PRD §11.3.5 "WHERE task_id = 当前
    /// task"). Empty when the index cannot be read, as [`Self::list_turns_for_agent`]. An
    /// index that keeps its rows outside memory reads no more of them than the window.
    fn list_turns_for_task(
        &self,
        agent_id: &str,
        task_id: &str,
        window: usize,
    ) -> Vec<TurnIndexRow> {
        let mut rows = self.list_turns_for_agent(agent_id);
        rows.retain(|row| row.task_id == task_id);
        rows.sort_by(|a, b| b.turn.cmp(&a.turn));
        rows.truncate(window);
        rows
    }

    /// `agent_id`'s `window` most recently updated turn rows, most recent first, ties
    /// in time broken by task and then turn: the rows a recall read looks at
    /// ([`RECENT_TURN_WINDOW`]) — the same window, row for row, that
    /// [`Self::list_turns_not_of_model`] keeps embedded. An index that keeps its rows
    /// outside memory reads no more of them than the window. Empty when the index
    /// cannot be read, as [`Self::list_turns_for_agent`].
    fn list_recent_turns(&self, agent_id: &str, window: usize) -> Vec<TurnIndexRow> {
        let mut rows = self.list_turns_for_agent(agent_id);
        rows.sort_by(recent_turns_first);
        rows.truncate(window);
        rows
    }

    /// Among `agent_id`'s `window` most recently updated turn rows: up to `limit`
    /// rows that have a digest and whose vector is NOT of `model` — another
    /// model's, one of no recorded model, or none at all — most recent first.
    /// These are the rows a query of `model` cannot be compared with until they
    /// are embedded again ([`Self::set_turn_embedding`]). Rows older than the
    /// window are never listed: a reader does not look that far back
    /// ([`RECENT_TURN_WINDOW`]). A digest made of whitespace alone (`str::trim`
    /// leaves nothing) is no text, in every implementation.
    ///
    /// `Err`: the index could not be read. That is not an empty list — the caller
    /// must not conclude that nothing is left to embed.
    fn list_turns_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        window: usize,
        limit: usize,
    ) -> Result<Vec<TurnIndexRow>, IndexUnavailable> {
        let mut rows = self.list_recent_turns(agent_id, window);
        rows.retain(|row| {
            !row.digest.trim().is_empty() && row.embedding_model.as_deref() != Some(model)
        });
        rows.truncate(limit);
        Ok(rows)
    }

    /// Give an existing turn row a vector of `model`, provided its digest is still
    /// `digest` (the text the vector was computed from). Every other column —
    /// `reference_count` and `updated_at` included — stays as it is. `Ok(false)`:
    /// no such row, or its digest changed in the meantime. `Err`: the index could
    /// not be written, which says nothing about the row.
    fn set_turn_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
        digest: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        match self.get_turn(agent_id, task_id, turn) {
            Some(mut row) if row.digest == digest => {
                row.embedding = embedding.to_vec();
                row.embedding_model = Some(model.to_owned());
                self.upsert_turn(row);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Up to `limit` of `agent_id`'s task rows whose brief has a text and whose
    /// vector is NOT of `model` — another model's, one of no recorded model, or
    /// none at all — most recently written first. These are the tasks a query of
    /// `model` cannot be compared with until their brief is embedded again
    /// ([`Self::set_task_brief_embedding`]). There is no window here: a reader that
    /// compares task briefs may compare any task of the agent. (The readers of today
    /// leave out the agent's default partition `_agent-{id}`; its brief is listed all
    /// the same, at the cost of one request after a model change, so that whether it
    /// is compared stays for task routing to decide.) `Err`: as for
    /// [`Self::list_turns_not_of_model`].
    fn list_tasks_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        limit: usize,
    ) -> Result<Vec<TaskIndexRow>, IndexUnavailable> {
        let mut rows = self.list_tasks_for_agent(agent_id);
        rows.retain(|row| {
            !row.brief_snapshot.trim().is_empty()
                && row.brief_embedding_model.as_deref() != Some(model)
        });
        rows.sort_by(recent_tasks_first);
        rows.truncate(limit);
        Ok(rows)
    }

    /// Give `agent_id`'s row for `task_id` a brief vector of `model`, provided its
    /// brief is still `brief` (the text the vector was computed from). Every other
    /// column stays as it is. `Ok(false)`: no such row, or its brief changed in the
    /// meantime. `Err`: as for [`Self::set_turn_embedding`].
    fn set_task_brief_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        brief: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        match self.get_task(agent_id, task_id) {
            Some(mut row) if row.brief_snapshot == brief => {
                row.brief_embedding = Some(embedding.to_vec());
                row.brief_embedding_model = Some(model.to_owned());
                self.upsert_task(row);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Drop every row of `agent_id` — turns, tasks and memory rows: the agent is gone.
    /// The rows are derived from files in the agent's own territory, which goes with
    /// it; left behind, they would be read back — and embedded again on its provider —
    /// by whichever agent is created under the same id next. Rows of other agents are
    /// not touched. Deliberately not a provided method: an index that keeps rows must
    /// say how it forgets them.
    fn forget_agent(&self, agent_id: &str) -> Result<(), IndexUnavailable>;
}

/// `Mutex<BoundedTable>`-backed in-memory `SqliteIndex` stub (each table capped at
/// [`MAX_INDEX_ROWS_PER_TABLE`] with FIFO eviction).
///
/// Multi-tenant keying matches the rusqlite adapter's:
/// - turn rows keyed `(agent_id, task_id, turn)`
/// - task rows keyed `(agent_id, task_id)` (see [`TaskIndexRow`])
/// - memory rows keyed `(agent_id, memory_id)`
#[derive(Default)]
pub struct InMemorySqliteIndex {
    turn: Mutex<BoundedTable<(String, String, u32), TurnIndexRow>>,
    task: Mutex<BoundedTable<(String, String), TaskIndexRow>>,
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
        let key = (row.agent_id.clone(), row.task_id.clone());
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

    fn get_task(&self, agent_id: &str, task_id: &str) -> Option<TaskIndexRow> {
        let guard = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .get(&(agent_id.to_owned(), task_id.to_owned()))
            .cloned()
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

    // The listings and setters below read and write under one lock, and copy only the
    // rows they return: the index this one stands in for answers each in one statement.

    fn count_turns_for_agent(&self, agent_id: &str) -> usize {
        let guard = self
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.values().filter(|r| r.agent_id == agent_id).count()
    }

    fn count_tasks_for_agent(&self, agent_id: &str) -> usize {
        let guard = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.values().filter(|r| r.agent_id == agent_id).count()
    }

    fn list_recent_turns(&self, agent_id: &str, window: usize) -> Vec<TurnIndexRow> {
        let guard = self
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rows: Vec<&TurnIndexRow> =
            guard.values().filter(|r| r.agent_id == agent_id).collect();
        rows.sort_by(|a, b| recent_turns_first(a, b));
        rows.into_iter().take(window).cloned().collect()
    }

    fn list_turns_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        window: usize,
        limit: usize,
    ) -> Result<Vec<TurnIndexRow>, IndexUnavailable> {
        let guard = self
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rows: Vec<&TurnIndexRow> =
            guard.values().filter(|r| r.agent_id == agent_id).collect();
        rows.sort_by(|a, b| recent_turns_first(a, b));
        Ok(rows
            .into_iter()
            .take(window)
            .filter(|row| {
                !row.digest.trim().is_empty() && row.embedding_model.as_deref() != Some(model)
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn set_turn_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
        digest: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        let mut guard = self
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.get_mut(&(agent_id.to_owned(), task_id.to_owned(), turn)) {
            Some(row) if row.digest == digest => {
                row.embedding = embedding.to_vec();
                row.embedding_model = Some(model.to_owned());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn list_tasks_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        limit: usize,
    ) -> Result<Vec<TaskIndexRow>, IndexUnavailable> {
        let guard = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rows: Vec<&TaskIndexRow> = guard
            .values()
            .filter(|row| {
                row.agent_id == agent_id
                    && !row.brief_snapshot.trim().is_empty()
                    && row.brief_embedding_model.as_deref() != Some(model)
            })
            .collect();
        rows.sort_by(|a, b| recent_tasks_first(a, b));
        Ok(rows.into_iter().take(limit).cloned().collect())
    }

    fn set_task_brief_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        brief: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        let mut guard = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.get_mut(&(agent_id.to_owned(), task_id.to_owned())) {
            Some(row) if row.brief_snapshot == brief => {
                row.brief_embedding = Some(embedding.to_vec());
                row.brief_embedding_model = Some(model.to_owned());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn forget_agent(&self, agent_id: &str) -> Result<(), IndexUnavailable> {
        self.turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|row| row.agent_id != agent_id);
        self.task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|row| row.agent_id != agent_id);
        self.memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|row| row.agent_id != agent_id);
        Ok(())
    }
}

/// What every [`SqliteIndex`] must do, whichever way it stores its rows: run
/// against the in-memory index below and against the durable one in
/// `sqlite_index_rusqlite`.
#[cfg(test)]
pub(crate) mod conformance {
    use super::*;

    fn turn(number: u32, model: Option<&str>, at: &str) -> TurnIndexRow {
        TurnIndexRow {
            agent_id: "agent:r".into(),
            task_id: "task-001".into(),
            turn: number,
            digest: format!("d-{number}"),
            embedding: vec![0.1; 8],
            embedding_model: model.map(str::to_string),
            reference_count: 0,
            updated_at: at.into(),
        }
    }

    /// Two agents working under one task id each keep their own row: neither
    /// write replaces the other's brief, vector or ownership.
    pub(crate) fn keeps_task_rows_per_agent(ix: &dyn SqliteIndex) {
        let row = |agent: &str, brief: &str, vector: Option<Vec<f32>>, model: Option<&str>| {
            TaskIndexRow {
                task_id: "shared".into(),
                agent_id: agent.into(),
                last_turn_at: "2026-05-22T00:00:00Z".into(),
                turns_total: 1,
                updated_at: "2026-05-22T00:00:00Z".into(),
                brief_snapshot: brief.into(),
                brief_embedding: vector,
                brief_embedding_model: model.map(str::to_string),
            }
        };
        let parent = row(
            "agent:r",
            "the parent's brief",
            Some(vec![1.0, 0.0]),
            Some("embed-a"),
        );
        let child = row("agent:s", "the child's brief", None, None);
        ix.upsert_task(parent.clone());
        ix.upsert_task(child.clone());
        assert_eq!(ix.get_task("agent:r", "shared"), Some(parent.clone()));
        assert_eq!(ix.get_task("agent:s", "shared"), Some(child.clone()));
        assert_eq!(ix.get_task("agent:t", "shared"), None);
        assert_eq!(ix.list_tasks_for_agent("agent:r"), vec![parent.clone()]);
        assert_eq!(ix.list_tasks_for_agent("agent:s"), vec![child.clone()]);

        // An update of one agent's row leaves the other's as it was.
        let mut child_later = child;
        child_later.brief_snapshot = "the child moved on".into();
        child_later.brief_embedding = Some(vec![0.0, 1.0]);
        child_later.brief_embedding_model = Some("embed-b".into());
        child_later.turns_total = 2;
        ix.upsert_task(child_later.clone());
        assert_eq!(ix.get_task("agent:r", "shared"), Some(parent));
        assert_eq!(ix.get_task("agent:s", "shared"), Some(child_later));
    }

    /// `list_turns_not_of_model`: rows of another model, of no recorded model and
    /// without a vector are listed, most recent first; rows of the model, rows of
    /// another agent, rows without a digest and rows older than the window are
    /// not.
    pub(crate) fn lists_what_a_query_cannot_use(ix: &dyn SqliteIndex) {
        ix.upsert_turn(turn(1, Some("embed-a"), "2026-05-22T00:00:01Z"));
        ix.upsert_turn(turn(2, Some("embed-b"), "2026-05-22T00:00:02Z"));
        ix.upsert_turn(turn(3, None, "2026-05-22T00:00:03Z"));
        let mut no_vector = turn(4, None, "2026-05-22T00:00:04Z");
        no_vector.embedding = Vec::new();
        ix.upsert_turn(no_vector);
        let mut no_digest = turn(5, None, "2026-05-22T00:00:05Z");
        no_digest.digest = String::new();
        ix.upsert_turn(no_digest);
        let mut blank_digest = turn(6, None, "2026-05-22T00:00:06Z");
        blank_digest.digest = " \t\r\n".into();
        ix.upsert_turn(blank_digest);
        let mut other_agent = turn(7, None, "2026-05-22T00:00:07Z");
        other_agent.agent_id = "agent:s".into();
        ix.upsert_turn(other_agent);
        // The oldest row: whitespace that is not ASCII (an ideographic space, a
        // no-break space) is no text either.
        let mut wide_blank = turn(0, None, "2026-05-22T00:00:00Z");
        wide_blank.digest = "\u{3000}\u{a0}".into();
        ix.upsert_turn(wide_blank);

        let turns = |model: &str, window: usize, limit: usize| -> Vec<u32> {
            ix.list_turns_not_of_model("agent:r", model, window, limit)
                .unwrap()
                .iter()
                .map(|r| r.turn)
                .collect()
        };
        assert_eq!(turns("embed-a", 100, 10), vec![4, 3, 2]);
        assert_eq!(turns("embed-b", 100, 10), vec![4, 3, 1]);
        assert_eq!(turns("embed-a", 100, 2), vec![4, 3], "newest first");
        assert_eq!(turns("embed-a", 100, 0), Vec::<u32>::new());
        // The window counts the agent's most recent rows whatever their model or
        // digest: turns 6, 5 and 4 are its newest three, and only 4 has a text.
        assert_eq!(turns("embed-a", 3, 10), vec![4]);
        assert_eq!(turns("embed-a", 4, 10), vec![4, 3]);
        assert_eq!(turns("embed-a", 0, 10), Vec::<u32>::new());
        // A listed row carries the text its vector is computed from.
        let listed = ix
            .list_turns_not_of_model("agent:r", "embed-a", 100, 1)
            .unwrap();
        assert_eq!(listed[0].digest, "d-4");
        assert_eq!(listed[0].task_id, "task-001");
        assert_eq!(
            turns("embed-a", 100, 10).len(),
            3,
            "listing changes nothing"
        );
    }

    /// `list_recent_turns`: the agent's newest rows, newest first, ties in time by task
    /// then turn, cut at the window — of every model, with a digest or not, and none of
    /// another agent's. Row for row the window `list_turns_not_of_model` keeps embedded.
    pub(crate) fn lists_the_recent_turns_in_reading_order(ix: &dyn SqliteIndex) {
        let rows = [
            ("task-b", 1, Some("embed-a"), "2026-05-22T00:00:03Z"),
            ("task-a", 2, None, "2026-05-22T00:00:02Z"),
            ("task-a", 1, Some("embed-b"), "2026-05-22T00:00:02Z"),
            ("task-c", 7, None, "2026-05-22T00:00:04Z"),
            ("task-a", 3, Some("embed-a"), "2026-05-22T00:00:01Z"),
        ];
        for (task, number, model, at) in rows {
            let mut row = turn(number, model, at);
            row.task_id = task.into();
            ix.upsert_turn(row);
        }
        let mut blank = turn(9, None, "2026-05-22T00:00:00Z");
        blank.digest = " ".into();
        ix.upsert_turn(blank);
        let mut elsewhere = turn(1, None, "2026-05-22T00:00:09Z");
        elsewhere.agent_id = "agent:s".into();
        ix.upsert_turn(elsewhere);
        // Counted without being read: every row of the agent, and none of another's.
        assert_eq!(ix.count_turns_for_agent("agent:r"), 6);
        assert_eq!(ix.count_turns_for_agent("agent:s"), 1);
        assert_eq!(ix.count_turns_for_agent("agent:none"), 0);

        let recent = |window: usize| -> Vec<(String, u32)> {
            ix.list_recent_turns("agent:r", window)
                .into_iter()
                .map(|r| (r.task_id, r.turn))
                .collect()
        };
        let in_order: Vec<(String, u32)> = [
            ("task-c", 7),
            ("task-b", 1),
            ("task-a", 1),
            ("task-a", 2),
            ("task-a", 3),
            ("task-001", 9),
        ]
        .into_iter()
        .map(|(task, number)| (task.to_string(), number))
        .collect();
        assert_eq!(recent(100), in_order);
        assert_eq!(recent(3), in_order[..3].to_vec());
        assert_eq!(recent(0), Vec::<(String, u32)>::new());
        // A listed row is the row as stored.
        let newest = ix.list_recent_turns("agent:r", 1);
        assert_eq!(newest, vec![ix.get_turn("agent:r", "task-c", 7).unwrap()]);
        // The window the upkeep of vectors keeps: of the same rows, those with a text
        // that a query of a model none of them has cannot use — all of them.
        for window in 0..=7 {
            let kept: Vec<(String, u32)> = ix
                .list_turns_not_of_model("agent:r", "embed-z", window, 100)
                .unwrap()
                .into_iter()
                .map(|r| (r.task_id, r.turn))
                .collect();
            let with_text: Vec<(String, u32)> = recent(window)
                .into_iter()
                .filter(|(task, _)| task != "task-001")
                .collect();
            assert_eq!(kept, with_text, "window {window}");
        }
    }

    /// Rows written in one instant are told apart by task and then turn, so the
    /// window holds the same rows whichever way they are stored — the rows a
    /// reader of that window takes.
    pub(crate) fn breaks_a_tie_in_time_by_task_then_turn(ix: &dyn SqliteIndex) {
        let at = "2026-05-22T00:00:01Z";
        // Written in an order that is neither the key's nor the listing's.
        for (task, number) in [("task-b", 1), ("task-a", 2), ("task-c", 1), ("task-a", 1)] {
            let mut row = turn(number, None, at);
            row.task_id = task.into();
            ix.upsert_turn(row);
        }
        let listed = |window: usize, limit: usize| -> Vec<(String, u32)> {
            ix.list_turns_not_of_model("agent:r", "embed-a", window, limit)
                .unwrap()
                .into_iter()
                .map(|r| (r.task_id, r.turn))
                .collect()
        };
        let in_order: Vec<(String, u32)> =
            [("task-a", 1), ("task-a", 2), ("task-b", 1), ("task-c", 1)]
                .into_iter()
                .map(|(task, number)| (task.to_string(), number))
                .collect();
        assert_eq!(listed(100, 10), in_order);
        // The window and the limit cut after the same rows.
        assert_eq!(listed(2, 10), in_order[..2].to_vec());
        assert_eq!(listed(100, 3), in_order[..3].to_vec());
        // And the reader of the window reads them in that order, cut at the same rows.
        let read = |window: usize| -> Vec<(String, u32)> {
            ix.list_recent_turns("agent:r", window)
                .into_iter()
                .map(|r| (r.task_id, r.turn))
                .collect()
        };
        assert_eq!(read(100), in_order);
        assert_eq!(read(3), in_order[..3].to_vec());
        // A row of the model takes its place in the window, and none in the listing.
        let mut of_the_model = turn(1, Some("embed-a"), at);
        of_the_model.task_id = "task-a".into();
        ix.upsert_turn(of_the_model);
        assert_eq!(listed(2, 10), in_order[1..2].to_vec());
    }

    /// `set_turn_embedding` changes the vector and its model only, and only
    /// while the digest is the one the vector was computed from.
    pub(crate) fn sets_the_vector_alone(ix: &dyn SqliteIndex) {
        let mut before = turn(1, None, "2026-05-22T00:00:01Z");
        before.reference_count = 7;
        ix.upsert_turn(before.clone());

        assert!(ix
            .set_turn_embedding("agent:r", "task-001", 1, "d-1", &[0.5, 0.25], "embed-a")
            .unwrap());
        let after = ix.get_turn("agent:r", "task-001", 1).unwrap();
        assert_eq!(after.embedding, vec![0.5, 0.25]);
        assert_eq!(after.embedding_model.as_deref(), Some("embed-a"));
        assert_eq!(
            (after.digest, after.reference_count, after.updated_at),
            (before.digest, before.reference_count, before.updated_at)
        );

        // A digest that changed in the meantime, or a row that is not there.
        assert!(!ix
            .set_turn_embedding("agent:r", "task-001", 1, "other", &[9.0], "embed-b")
            .unwrap());
        assert!(!ix
            .set_turn_embedding("agent:r", "task-001", 2, "d-2", &[9.0], "embed-b")
            .unwrap());
        assert!(!ix
            .set_turn_embedding("agent:s", "task-001", 1, "d-1", &[9.0], "embed-b")
            .unwrap());
        let unchanged = ix.get_turn("agent:r", "task-001", 1).unwrap();
        assert_eq!(unchanged.embedding, vec![0.5, 0.25]);
        assert_eq!(unchanged.embedding_model.as_deref(), Some("embed-a"));
        assert_eq!(ix.list_turns_for_agent("agent:r").len(), 1, "no row added");
    }

    fn task(id: &str, brief: &str, model: Option<&str>, at: &str) -> TaskIndexRow {
        TaskIndexRow {
            task_id: id.into(),
            agent_id: "agent:r".into(),
            last_turn_at: "2026-05-22T00:00:00Z".into(),
            turns_total: 3,
            updated_at: at.into(),
            brief_snapshot: brief.into(),
            brief_embedding: Some(vec![0.1; 8]),
            brief_embedding_model: model.map(str::to_string),
        }
    }

    /// `list_tasks_not_of_model`: tasks whose brief vector is of another model, of
    /// no recorded model or missing are listed, most recently written first;
    /// tasks of the model, of another agent or without a brief are not.
    pub(crate) fn lists_the_tasks_a_query_cannot_use(ix: &dyn SqliteIndex) {
        ix.upsert_task(task(
            "t-a",
            "brief a",
            Some("embed-a"),
            "2026-05-22T00:00:01Z",
        ));
        ix.upsert_task(task(
            "t-b",
            "brief b",
            Some("embed-b"),
            "2026-05-22T00:00:02Z",
        ));
        ix.upsert_task(task("t-none", "brief c", None, "2026-05-22T00:00:03Z"));
        let mut no_vector = task("t-bare", "brief d", None, "2026-05-22T00:00:04Z");
        no_vector.brief_embedding = None;
        ix.upsert_task(no_vector);
        ix.upsert_task(task("t-empty", "", None, "2026-05-22T00:00:05Z"));
        ix.upsert_task(task("t-blank", " \t\r\n", None, "2026-05-22T00:00:06Z"));
        ix.upsert_task(task(
            "t-wide",
            "\u{3000}\u{a0}",
            None,
            "2026-05-22T00:00:07Z",
        ));
        let mut other_agent = task("t-other", "brief e", None, "2026-05-22T00:00:08Z");
        other_agent.agent_id = "agent:s".into();
        ix.upsert_task(other_agent);
        // Two rows written at the same moment are listed in task-id order.
        ix.upsert_task(task("t-same-2", "brief g", None, "2026-05-22T00:00:09Z"));
        ix.upsert_task(task("t-same-1", "brief f", None, "2026-05-22T00:00:09Z"));
        // Counted without being read: every row of the agent, and none of another's.
        assert_eq!(ix.count_tasks_for_agent("agent:r"), 9);
        assert_eq!(ix.count_tasks_for_agent("agent:s"), 1);
        assert_eq!(ix.count_tasks_for_agent("agent:none"), 0);

        let tasks = |model: &str, limit: usize| -> Vec<String> {
            ix.list_tasks_not_of_model("agent:r", model, limit)
                .unwrap()
                .into_iter()
                .map(|r| r.task_id)
                .collect()
        };
        assert_eq!(
            tasks("embed-a", 10),
            ["t-same-1", "t-same-2", "t-bare", "t-none", "t-b"]
        );
        assert_eq!(
            tasks("embed-b", 10),
            ["t-same-1", "t-same-2", "t-bare", "t-none", "t-a"]
        );
        assert_eq!(tasks("embed-a", 3), ["t-same-1", "t-same-2", "t-bare"]);
        assert_eq!(tasks("embed-a", 0), Vec::<String>::new());
        // A listed row carries the text its vector is computed from.
        let listed = ix.list_tasks_not_of_model("agent:r", "embed-a", 3).unwrap();
        assert_eq!(listed[2].brief_snapshot, "brief d");
        assert_eq!(tasks("embed-a", 10).len(), 5, "listing changes nothing");
    }

    /// Rows without a text do not use up the limit — the listing goes on until it
    /// has `limit` rows that can be embedded — but they do count in the window.
    pub(crate) fn rows_without_a_text_do_not_use_up_the_limit(ix: &dyn SqliteIndex) {
        for number in 0..20_u32 {
            let at = format!("2026-05-22T00:00:{number:02}Z");
            // The ten most recent rows of each table have no text.
            let blank = number >= 10;
            let mut row = turn(number, None, &at);
            if blank {
                row.digest = "\u{3000} \t".into();
            }
            ix.upsert_turn(row);
            let brief = if blank {
                "\u{a0}\n".to_string()
            } else {
                format!("brief {number}")
            };
            ix.upsert_task(task(&format!("task-{number:02}"), &brief, None, &at));
        }
        let turns = |window: usize, limit: usize| -> Vec<u32> {
            ix.list_turns_not_of_model("agent:r", "embed-a", window, limit)
                .unwrap()
                .iter()
                .map(|row| row.turn)
                .collect()
        };
        assert_eq!(turns(100, 3), [9, 8, 7]);
        // The 12 most recent turn rows are the ten without a text, 9 and 8.
        assert_eq!(turns(12, 5), [9, 8]);
        let tasks: Vec<String> = ix
            .list_tasks_not_of_model("agent:r", "embed-a", 3)
            .unwrap()
            .into_iter()
            .map(|row| row.task_id)
            .collect();
        assert_eq!(tasks, ["task-09", "task-08", "task-07"]);
    }

    /// A text is blank to the index exactly when `str::trim` leaves nothing of
    /// it: for every character Unicode calls whitespace, and for the invisible
    /// characters it does not.
    pub(crate) fn agrees_with_str_trim_on_what_is_blank(ix: &dyn SqliteIndex) {
        let whitespace = (0..=u32::from(char::MAX))
            .filter_map(char::from_u32)
            .filter(|c| c.is_whitespace());
        // Invisible, yet not whitespace: a zero-width space, a word joiner, a
        // byte-order mark, a Mongolian vowel separator, a unit separator.
        let invisible = ['\u{200b}', '\u{2060}', '\u{feff}', '\u{180e}', '\u{1f}'];
        let texts: Vec<String> = whitespace
            .chain(invisible)
            .map(String::from)
            .chain([
                "\u{3000}x\u{3000}".to_string(),
                "\u{85}\u{2028}".to_string(),
            ])
            .collect();
        let mut turns_with_a_text = Vec::new();
        let mut tasks_with_a_text = Vec::new();
        for (number, text) in texts.iter().enumerate() {
            let number = number as u32;
            let at = format!("2026-05-22T00:{:02}:{:02}Z", number / 60, number % 60);
            let mut row = turn(number, None, &at);
            row.digest = text.clone();
            ix.upsert_turn(row);
            let task_id = format!("task-{number:03}");
            ix.upsert_task(task(&task_id, text, None, &at));
            if !text.trim().is_empty() {
                turns_with_a_text.push(number);
                tasks_with_a_text.push(task_id);
            }
        }
        // Both kinds are there, or this would show nothing.
        assert!(!turns_with_a_text.is_empty());
        assert!(turns_with_a_text.len() + 20 < texts.len());
        // Listed most recent first.
        turns_with_a_text.reverse();
        tasks_with_a_text.reverse();

        let turns: Vec<u32> = ix
            .list_turns_not_of_model("agent:r", "embed-a", 1000, 1000)
            .unwrap()
            .iter()
            .map(|row| row.turn)
            .collect();
        assert_eq!(turns, turns_with_a_text);
        let tasks: Vec<String> = ix
            .list_tasks_not_of_model("agent:r", "embed-a", 1000)
            .unwrap()
            .into_iter()
            .map(|row| row.task_id)
            .collect();
        assert_eq!(tasks, tasks_with_a_text);
    }

    /// `set_task_brief_embedding` changes the brief's vector and its model only,
    /// and only while the brief is the one the vector was computed from.
    pub(crate) fn sets_the_brief_vector_alone(ix: &dyn SqliteIndex) {
        let before = task("t-a", "the brief", None, "2026-05-22T00:00:01Z");
        ix.upsert_task(before.clone());
        let mut of_another = before.clone();
        of_another.agent_id = "agent:s".into();
        ix.upsert_task(of_another.clone());

        assert!(ix
            .set_task_brief_embedding("agent:r", "t-a", "the brief", &[0.5, 0.25], "embed-a")
            .unwrap());
        let after = ix.get_task("agent:r", "t-a").unwrap();
        assert_eq!(after.brief_embedding, Some(vec![0.5, 0.25]));
        assert_eq!(after.brief_embedding_model.as_deref(), Some("embed-a"));
        assert_eq!(
            TaskIndexRow {
                brief_embedding: before.brief_embedding.clone(),
                brief_embedding_model: None,
                ..after.clone()
            },
            before,
            "every other column is as it was"
        );
        assert_eq!(
            ix.get_task("agent:s", "t-a"),
            Some(of_another),
            "another agent's row under the same task id is not touched"
        );

        // A brief that changed in the meantime, or a row that is not there.
        assert!(!ix
            .set_task_brief_embedding("agent:r", "t-a", "other", &[9.0], "embed-b")
            .unwrap());
        assert!(!ix
            .set_task_brief_embedding("agent:r", "t-z", "the brief", &[9.0], "embed-b")
            .unwrap());
        assert!(!ix
            .set_task_brief_embedding("agent:t", "t-a", "the brief", &[9.0], "embed-b")
            .unwrap());
        assert_eq!(ix.get_task("agent:r", "t-a"), Some(after));
        assert_eq!(ix.list_tasks_for_agent("agent:r").len(), 1, "no row added");
    }

    /// `forget_agent` drops every row of the agent — turns, tasks, memory rows — and
    /// no row of another agent, one under the same task id included.
    pub(crate) fn forgets_one_agent_and_no_other(ix: &dyn SqliteIndex) {
        let at = "2026-05-22T00:00:01Z";
        for agent in ["agent:r", "agent:s"] {
            for number in 1..=3 {
                ix.upsert_turn(TurnIndexRow {
                    agent_id: agent.into(),
                    ..turn(number, Some("embed-a"), at)
                });
            }
            ix.upsert_task(TaskIndexRow {
                agent_id: agent.into(),
                ..task("t-a", "the brief", None, at)
            });
            ix.upsert_memory(MemoryIndexRow {
                agent_id: agent.into(),
                memory_id: "m-1".into(),
                epistemic_status: "active".into(),
                updated_at: at.into(),
            });
        }

        ix.forget_agent("agent:r").unwrap();

        assert!(ix.list_turns_for_agent("agent:r").is_empty());
        assert!(ix.list_tasks_for_agent("agent:r").is_empty());
        assert!(ix.list_memory_for_agent("agent:r").is_empty());
        assert_eq!(ix.get_task("agent:r", "t-a"), None);
        assert_eq!(ix.get_turn("agent:r", "task-001", 1), None);
        assert!(ix
            .list_tasks_not_of_model("agent:r", "embed-b", 10)
            .unwrap()
            .is_empty());
        assert!(ix
            .list_turns_not_of_model("agent:r", "embed-b", 10, 10)
            .unwrap()
            .is_empty());
        assert_eq!(ix.list_turns_for_agent("agent:s").len(), 3);
        assert_eq!(ix.list_tasks_for_agent("agent:s").len(), 1);
        assert_eq!(ix.list_memory_for_agent("agent:s").len(), 1);

        // Forgetting an agent that has no rows changes nothing, and an agent created
        // under the id later writes like any other.
        ix.forget_agent("agent:r").unwrap();
        ix.forget_agent("agent:nobody").unwrap();
        ix.upsert_turn(TurnIndexRow {
            agent_id: "agent:r".into(),
            ..turn(1, None, at)
        });
        assert_eq!(ix.list_turns_for_agent("agent:r").len(), 1);
        assert_eq!(ix.list_turns_for_agent("agent:s").len(), 3);
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
            embedding_model: None,
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
            brief_embedding_model: None,
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
        assert_eq!(ix.get_task("agent:r", "task-001"), Some(r));
        assert_eq!(ix.get_task("agent:s", "task-001"), None);
    }

    #[test]
    fn task_rows_are_kept_per_agent() {
        conformance::keeps_task_rows_per_agent(&InMemorySqliteIndex::default());
    }

    #[test]
    fn list_turns_not_of_model_lists_what_a_query_cannot_use() {
        conformance::lists_what_a_query_cannot_use(&InMemorySqliteIndex::default());
    }

    #[test]
    fn turns_of_one_instant_are_ordered_by_task_then_turn() {
        conformance::breaks_a_tie_in_time_by_task_then_turn(&InMemorySqliteIndex::default());
    }

    #[test]
    fn the_recent_turns_are_listed_in_reading_order() {
        conformance::lists_the_recent_turns_in_reading_order(&InMemorySqliteIndex::default());
    }

    #[test]
    fn set_turn_embedding_touches_the_vector_alone() {
        conformance::sets_the_vector_alone(&InMemorySqliteIndex::default());
    }

    #[test]
    fn list_tasks_not_of_model_lists_the_tasks_a_query_cannot_use() {
        conformance::lists_the_tasks_a_query_cannot_use(&InMemorySqliteIndex::default());
    }

    #[test]
    fn set_task_brief_embedding_touches_the_brief_vector_alone() {
        conformance::sets_the_brief_vector_alone(&InMemorySqliteIndex::default());
    }

    #[test]
    fn forget_agent_drops_one_agents_rows_and_no_others() {
        conformance::forgets_one_agent_and_no_other(&InMemorySqliteIndex::default());
    }

    /// Rows dropped by `forget_agent` free their place under the row cap, and the
    /// oldest-first eviction goes on over the rows that are left.
    #[test]
    fn forgotten_rows_leave_the_bounded_table_consistent() {
        let mut table: BoundedTable<u32, &str> = BoundedTable::default();
        for key in 0..4 {
            table.upsert(key, if key % 2 == 0 { "gone" } else { "kept" }, 4);
        }
        table.retain(|row| *row != "gone");
        assert_eq!(table.map.len(), 2);
        assert_eq!(table.order, VecDeque::from(vec![1, 3]));
        // Two more fit without eviction; a third evicts the oldest row left.
        table.upsert(10, "kept", 4);
        table.upsert(11, "kept", 4);
        assert_eq!(table.map.len(), 4);
        table.upsert(12, "kept", 4);
        assert_eq!(table.map.len(), 4);
        assert!(table.get(&1).is_none(), "the oldest row left is evicted");
        assert!(table.get(&3).is_some());
    }

    #[test]
    fn rows_without_a_text_do_not_use_up_the_limit() {
        conformance::rows_without_a_text_do_not_use_up_the_limit(&InMemorySqliteIndex::default());
    }

    #[test]
    fn a_text_is_blank_exactly_when_str_trim_leaves_nothing() {
        conformance::agrees_with_str_trim_on_what_is_blank(&InMemorySqliteIndex::default());
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
