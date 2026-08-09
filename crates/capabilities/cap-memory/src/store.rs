//! `MemoryStore` — the source of truth for memory entries: a per-agent
//! `Vec<MemoryEntry>` behind a `Mutex`, exposed via owned-`Arc` construction.
//! Two backends share one behaviour:
//! - [`MemoryStore::new`] / [`MemoryStore::with_limit`] — in-memory only.
//! - [`MemoryStore::open`] — PERSISTENT: hydrates per-agent buckets from
//!   `<dir>/<agent-slug>/knowledge.jsonl` and persists every mutation
//!   (`insert` atomic-appends; mutations atomic-rewrite; see `persistence.rs`).
//!
//! Both backends are **retention-bounded** (slice `dev-task-mem-retention`): all
//! ACTIVE entries are retained (active capacity is the `max_active_per_agent`
//! gate), while the INACTIVE (forgotten/superseded) tail is compacted to a bounded
//! window on every rewrite — see [`MemoryStore::open`]'s rustdoc and MODULE-011
//! §2.7 "Retention & compaction". A per-entry write cap ([`MAX_ENTRY_BYTES`])
//! keeps every persisted line below the boot read cap.
//!
//! The WIT host handlers (`wit_impl.rs`) and the post-processor's Step 5
//! (`post_processor.rs`) both consume the SAME `Arc<MemoryStore>` instance
//! (wired via `Components::register_agent_memory`) so reads via WIT see the
//! writes Step 5 made.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use advance_shared_types::memory::PostProcessorError;

use crate::knowledge::{MemoryEntry, MemoryStatus, MemoryType};
use crate::persistence::{
    KnowledgeJsonlStore, PersistError, DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT,
    DEFAULT_MAX_INACTIVE_PER_AGENT,
};
use crate::reconcile::MemoryAction;

pub type MemoryId = String;

/// Which L6 mutation a journal entry records (slice C — AC-34 in-process
/// rollback stand-in).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L6JournalField {
    ClusterId,
    ConsolidatedPrefInsert,
}

/// One reversible L6 mutation. `write_cluster_id` ALWAYS appends one of these
/// (no dedup — see MODULE-011 §3.8 note 2); `rollback_l6` reverse-replays
/// entries with `l6_commit_ts > before`, converging to the genuine pre-L6
/// value for duplicate `ClusterId` records on the same entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L6JournalEntry {
    pub entry_id: String,
    pub field: L6JournalField,
    /// Prior `cluster_id` (None for `ConsolidatedPrefInsert`).
    pub old: Option<String>,
    pub l6_commit_ts: SystemTime,
}

/// 30-day window for `KnowledgeHealthSnapshot.zero_access_30d`.
const THIRTY_DAYS: Duration = Duration::from_secs(30 * 24 * 3600);

/// `MemoryStore::forget` error surface — distinguished from
/// [`PostProcessorError`] so WIT handlers can map "not-found" to
/// `memory-error::not-found` without fragile string parsing.
#[derive(Clone, Debug)]
pub enum ForgetError {
    NotFound(String),
    Invalid(String),
}

impl From<ForgetError> for PostProcessorError {
    fn from(e: ForgetError) -> Self {
        match e {
            ForgetError::NotFound(s) => PostProcessorError::Invalid(s),
            ForgetError::Invalid(s) => PostProcessorError::Invalid(s),
        }
    }
}

/// Per-agent max active entries — bounds growth in slice B's in-memory mode.
/// Production CAP-equivalent will live in MODULE-011 §2.10
/// `memory.max_active_per_agent` once that knob is wired.
pub const DEFAULT_MAX_ACTIVE_PER_AGENT: usize = 10_000;

/// Per-entry serialized-line write cap (8 MiB) — slice `dev-task-mem-retention`.
/// Every entry written to `knowledge.jsonl` (via `insert` / `apply_action` /
/// `write_cluster_id`) is rejected if its serialized JSON line exceeds this.
/// Set BELOW the boot read cap (`persistence::MAX_LINE_BYTES` = 16 MiB), so NO
/// store-written line can ever trip the read cap (a committed over-cap line is
/// then unambiguously external corruption). 8 MiB admits every legitimate entry
/// (WIT `remember` caps content at 1 MiB; L6 syntheses are far smaller).
pub const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;

pub struct MemoryStore {
    inner: Mutex<HashMap<String, Vec<MemoryEntry>>>,
    /// Per-agent L6-mutation journal (slice C — `rollback_l6`).
    journal: Mutex<HashMap<String, Vec<L6JournalEntry>>>,
    /// Per-agent per-entry last-access timestamp (slice C — feeds
    /// `zero_access_30d` in the health snapshot's single O(N) pass).
    access: Mutex<HashMap<String, HashMap<String, SystemTime>>>,
    max_active_per_agent: usize,
    /// Inactive-tail retention window (slice `dev-task-mem-retention`). The
    /// forgotten/superseded tail is compacted to at most this many entries AND
    /// `max_inactive_bytes_per_agent` bytes on every rewrite; active entries are
    /// never counted toward, nor dropped by, this cap. Independent of
    /// `max_active_per_agent`. Defaults to `DEFAULT_MAX_INACTIVE_PER_AGENT`.
    max_inactive_per_agent: usize,
    /// Inactive-tail byte budget (exact serialized-line bytes incl. `\n`).
    max_inactive_bytes_per_agent: usize,
    /// On-disk `knowledge.jsonl` backend (slice m011-memory-persist, AC-40).
    /// `None` for [`MemoryStore::new`] / [`MemoryStore::with_limit`] /
    /// [`Default`] — those keep the byte-identical in-memory behaviour. `Some`
    /// for [`MemoryStore::open`]: `insert` atomic-appends, mutations atomic-
    /// rewrite, and a persist failure rolls back the in-memory mutation
    /// (cache==disk invariant scoped to `inner` vs knowledge.jsonl; the
    /// `journal` and `access` maps are in-process only and NOT persisted).
    /// See MODULE-011 §3.8 note 15.
    persistence: Option<Arc<KnowledgeJsonlStore>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            journal: Mutex::new(HashMap::new()),
            access: Mutex::new(HashMap::new()),
            max_active_per_agent: DEFAULT_MAX_ACTIVE_PER_AGENT,
            max_inactive_per_agent: DEFAULT_MAX_INACTIVE_PER_AGENT,
            max_inactive_bytes_per_agent: DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT,
            persistence: None,
        }
    }

    pub fn with_limit(max_active_per_agent: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            journal: Mutex::new(HashMap::new()),
            access: Mutex::new(HashMap::new()),
            max_active_per_agent,
            max_inactive_per_agent: DEFAULT_MAX_INACTIVE_PER_AGENT,
            max_inactive_bytes_per_agent: DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT,
            persistence: None,
        }
    }

    /// Test-only IN-MEMORY (persistence `None`) constructor with explicit
    /// inactive-retention caps, so compaction-at-the-cap can be exercised without
    /// inserting `DEFAULT_MAX_INACTIVE_PER_AGENT` (4096) entries. The PERSISTENT
    /// path (`open`) always uses the module-level default consts — matching the
    /// hydration window in `persistence::open` — so this never introduces a
    /// store-vs-hydration cap mismatch.
    #[doc(hidden)]
    pub fn with_inactive_caps(
        max_active_per_agent: usize,
        max_inactive_per_agent: usize,
        max_inactive_bytes_per_agent: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            journal: Mutex::new(HashMap::new()),
            access: Mutex::new(HashMap::new()),
            max_active_per_agent,
            max_inactive_per_agent,
            max_inactive_bytes_per_agent,
            persistence: None,
        }
    }

    /// Open a PERSISTENT store rooted at `dir` (slice m011-memory-persist,
    /// AC-40). Hydrates the in-memory per-agent buckets from each
    /// `<dir>/<agent-slug>/knowledge.jsonl`, then persists every subsequent
    /// mutation. `insert`/`recall`/`recall_at` signatures are unchanged — so
    /// the main-line agent-loop wiring (③) swaps `new()` → `open()` with zero
    /// backend work. A corrupt on-disk line fails loud here (never silently
    /// dropped). The `journal` + `access` maps start empty (in-process only).
    ///
    /// # Retention-bounded semantics (slice `dev-task-mem-retention`)
    /// This store is **retention-bounded** (the same contract for `new()` and
    /// `open()`):
    /// 1. **The inactive tail is bounded; active entries are retained.** `forget`
    ///    / `apply_action::Supersede` flip `is_active=false` but keep the entry —
    ///    until the inactive (forgotten/superseded) tail exceeds the retention
    ///    window (`max_inactive_per_agent` entries / `max_inactive_bytes_per_agent`
    ///    bytes), at which point the OLDEST inactive entries are compacted away on
    ///    the next rewrite (and during boot hydration). So `get` / `list` return a
    ///    forgotten/superseded entry only within the recent-inactive window; beyond
    ///    it, `get(forgotten_id)` returns `None`. `recall` / `recall_at` are
    ///    unaffected (always `is_active`-filtered). This bounds the production
    ///    `remember`→`forget` DoS that previously grew the file without bound.
    /// 2. **`max_active_per_agent` gates new ACTIVE inserts; active entries are
    ///    never dropped by retention.** Hydration loads every on-disk active entry
    ///    plus the bounded inactive tail (`persistence::open` applies the same
    ///    inactive window during the streaming read). If a file was externally
    ///    enlarged or the active cap reduced between sessions, the existing active
    ///    entries are kept and new active inserts stay blocked until the active
    ///    count drops — the safe, lossless degradation.
    pub fn open(
        dir: impl Into<PathBuf>,
        max_active_per_agent: usize,
    ) -> Result<Self, PersistError> {
        let (jsonl, buckets) = KnowledgeJsonlStore::open(dir)?;
        Ok(Self {
            inner: Mutex::new(buckets),
            journal: Mutex::new(HashMap::new()),
            access: Mutex::new(HashMap::new()),
            max_active_per_agent,
            max_inactive_per_agent: DEFAULT_MAX_INACTIVE_PER_AGENT,
            max_inactive_bytes_per_agent: DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT,
            persistence: Some(Arc::new(jsonl)),
        })
    }

    /// Serialized line of `entry`, rejecting it (`Invalid`) if longer than
    /// [`MAX_ENTRY_BYTES`]. Called on every path that writes/grows a persisted
    /// line so that NO store-written line can exceed the boot read cap
    /// (`persistence::MAX_LINE_BYTES`). Returns the serialized line so the insert
    /// hot path can reuse it (single-serialize).
    fn check_entry_size(entry: &MemoryEntry) -> Result<String, PostProcessorError> {
        let line = serde_json::to_string(entry).map_err(|e| {
            PostProcessorError::Invalid(format!("serialize entry {}: {e}", entry.id))
        })?;
        if line.len() > MAX_ENTRY_BYTES {
            return Err(PostProcessorError::Invalid(format!(
                "entry {} serialized size {} exceeds MAX_ENTRY_BYTES ({})",
                entry.id,
                line.len(),
                MAX_ENTRY_BYTES
            )));
        }
        Ok(line)
    }

    /// Drop the OLDEST inactive entries (lowest index = earliest inserted) from
    /// `bucket` + its lockstep serialized `lines` until the inactive tail fits the
    /// retention window (`max_inactive` entries AND `max_inactive_bytes` of exact
    /// serialized-line bytes incl. the trailing `\n`). **Active entries are never
    /// counted toward, nor dropped by, the cap.** Order-preserving, O(N).
    fn compact_inactive(
        bucket: &mut Vec<MemoryEntry>,
        lines: &mut Vec<String>,
        max_inactive: usize,
        max_inactive_bytes: usize,
    ) {
        debug_assert_eq!(
            bucket.len(),
            lines.len(),
            "bucket/lines must be in lockstep"
        );
        // Single pass: count inactive entries + sum their exact serialized bytes.
        let mut inactive_count = 0usize;
        let mut inactive_bytes = 0usize;
        for (e, l) in bucket.iter().zip(lines.iter()) {
            if !e.is_active {
                inactive_count += 1;
                inactive_bytes += l.len() + 1;
            }
        }
        if inactive_count <= max_inactive && inactive_bytes <= max_inactive_bytes {
            return; // common path: the inactive tail is already within both bounds
        }
        // Mark the OLDEST inactive entries (front-first) for drop until both bounds
        // hold; active entries are never marked. Then rebuild bucket+lines in ONE
        // index-synchronized pass (no shared-counter index-drift risk).
        let mut drop = vec![false; bucket.len()];
        let mut i = 0usize;
        while (inactive_count > max_inactive || inactive_bytes > max_inactive_bytes)
            && i < bucket.len()
        {
            if !bucket[i].is_active {
                drop[i] = true;
                inactive_count -= 1;
                inactive_bytes -= lines[i].len() + 1;
            }
            i += 1;
        }
        // Rebuild bucket+lines together from ONE zipped drain so they can never
        // desynchronize (no shared mutable counter across two closures).
        let mut new_bucket = Vec::with_capacity(bucket.len());
        let mut new_lines = Vec::with_capacity(lines.len());
        for (drop_it, (entry, line)) in drop.iter().zip(bucket.drain(..).zip(lines.drain(..))) {
            if !drop_it {
                new_bucket.push(entry);
                new_lines.push(line);
            }
        }
        *bucket = new_bucket;
        *lines = new_lines;
    }

    /// Compact the agent's inactive tail then persist via a full rewrite (called
    /// under the held `inner` guard — never re-locks `inner`). Single-serialize:
    /// serializes the live bucket once into `lines`, compacts bucket+lines in
    /// lockstep ([`compact_inactive`]), then writes the pre-serialized `lines`.
    /// Compaction runs in BOTH backends (uniform retention contract); the disk
    /// write happens only when persistence is `Some`. On a disk-write (or
    /// serialize) failure, restore the bucket to `pre` (undoing both the mutation
    /// AND the compaction) so cache==disk, and return the raw [`PersistError`].
    fn persist_or_restore(
        &self,
        guard: &mut MutexGuard<'_, HashMap<String, Vec<MemoryEntry>>>,
        agent_id: &str,
        pre: Vec<MemoryEntry>,
    ) -> Result<(), PersistError> {
        // Serialize the current bucket once + compact its inactive tail in-place.
        let lines_result: Result<Vec<String>, PersistError> = {
            if let Some(bucket) = guard.get_mut(agent_id) {
                let mut lines: Vec<String> = Vec::with_capacity(bucket.len());
                let mut ser_err: Option<PersistError> = None;
                for e in bucket.iter() {
                    match serde_json::to_string(e) {
                        Ok(s) => lines.push(s),
                        Err(err) => {
                            ser_err =
                                Some(PersistError::Io(format!("serialize entry {}: {err}", e.id)));
                            break;
                        }
                    }
                }
                match ser_err {
                    Some(e) => Err(e),
                    None => {
                        Self::compact_inactive(
                            bucket,
                            &mut lines,
                            self.max_inactive_per_agent,
                            self.max_inactive_bytes_per_agent,
                        );
                        Ok(lines)
                    }
                }
            } else {
                // No bucket for this agent → nothing to write (an empty file).
                Ok(Vec::new())
            }
        };
        let restore = |guard: &mut MutexGuard<'_, HashMap<String, Vec<MemoryEntry>>>| {
            if pre.is_empty() {
                guard.remove(agent_id);
            } else {
                guard.insert(agent_id.to_string(), pre.clone());
            }
        };
        let lines = match lines_result {
            Ok(l) => l,
            Err(e) => {
                restore(guard);
                return Err(e);
            }
        };
        let Some(p) = &self.persistence else {
            return Ok(()); // in-memory: compaction already applied to the bucket
        };
        match p.rewrite_lines(agent_id, &lines) {
            Ok(()) => Ok(()),
            Err(e) => {
                restore(guard);
                Err(e)
            }
        }
    }

    /// Snapshot the agent's current bucket (under the held guard) for the
    /// pre-mutation restore point. Empty vec when the agent has no bucket.
    fn snapshot(
        guard: &MutexGuard<'_, HashMap<String, Vec<MemoryEntry>>>,
        agent_id: &str,
    ) -> Vec<MemoryEntry> {
        guard.get(agent_id).cloned().unwrap_or_default()
    }

    pub fn insert(
        &self,
        agent_id: &str,
        entry: MemoryEntry,
    ) -> Result<MemoryId, PostProcessorError> {
        entry
            .validate_invariants()
            .map_err(|e| PostProcessorError::Invalid(e.to_string()))?;
        // Single-serialize: the per-entry write cap check yields the serialized
        // line, reused by the append fast-path below (no double serialization).
        let line = Self::check_entry_size(&entry)?;
        // Reconcile path: if this agent's on-disk file is still bloated because a
        // best-effort migration rewrite failed at boot, this insert does a FULL
        // compacting rewrite (not an append) to re-bound the disk — so a
        // `remember`-only agent still re-establishes the on-disk bound (adversarial
        // round W2). `false` for the in-memory (None) backend.
        let reconcile = self
            .persistence
            .as_ref()
            .is_some_and(|p| p.needs_rewrite(agent_id));
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pre = if reconcile {
            Self::snapshot(&guard, agent_id)
        } else {
            Vec::new()
        };
        let bucket = guard.entry(agent_id.to_string()).or_default();
        let active_count = bucket.iter().filter(|e| e.is_active).count();
        if entry.is_active && active_count >= self.max_active_per_agent {
            return Err(PostProcessorError::LimitExceeded);
        }
        let id = entry.id.clone();
        bucket.push(entry);
        // NOTE: the common insert path uses the append fast-path (one O(1) disk
        // write per insert) — only forget/supersede grow the inactive tail and
        // those rewrite (compact). The reconcile path (rare) instead does a full
        // compacting rewrite. On a disk-write failure, restore so cache==disk.
        // No-op when persistence is None.
        if let Some(p) = &self.persistence {
            if reconcile {
                // `bucket` (a &mut borrow of `guard`) is unused past this point, so
                // NLL releases it before `persist_or_restore` re-borrows `guard`.
                self.persist_or_restore(&mut guard, agent_id, pre)
                    .map_err(|e| {
                        PostProcessorError::Invalid(format!(
                            "persist (reconcile rewrite) failed, rolled back insert: {e}"
                        ))
                    })?;
                p.clear_pending(agent_id);
            } else if let Err(e) = p.append_line(agent_id, &line) {
                bucket.pop();
                return Err(PostProcessorError::Invalid(format!(
                    "persist (append) failed, rolled back insert: {e}"
                )));
            }
        }
        Ok(id)
    }

    pub fn get(&self, agent_id: &str, id: &str) -> Option<MemoryEntry> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(agent_id)?.iter().find(|e| e.id == id).cloned()
    }

    pub fn list(&self, agent_id: &str) -> Vec<MemoryEntry> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(agent_id).cloned().unwrap_or_default()
    }

    /// Slice B's `recall`: simple substring + tag match on active entries.
    /// `is_active=false` entries (Forgotten / Superseded) are excluded —
    /// per the §3.3 T01 expected-behavior contract. No embeddings yet
    /// (AC-19 deferred).
    pub fn recall(&self, agent_id: &str, query: &str, limit: u32) -> Vec<MemoryEntry> {
        let q = query.to_lowercase();
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let take = if limit == 0 {
            usize::MAX
        } else {
            limit as usize
        };
        guard
            .get(agent_id)
            .map(|bucket| {
                bucket
                    .iter()
                    .filter(|e| e.is_active)
                    .filter(|e| matches(&q, e))
                    .take(take)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Slice B's `recall-at`: `created_at <= timestamp` (lexicographic on
    /// RFC3339-ish strings — the slice A schema uses ISO-8601 strings for
    /// `created_at`, which sort lexicographically). Real wall-clock-aware
    /// rollback against committed history is deferred (AC-18 + recall-at
    /// full semantics, requires git wiring).
    pub fn recall_at(
        &self,
        agent_id: &str,
        query: &str,
        timestamp: &str,
        limit: u32,
    ) -> Vec<MemoryEntry> {
        let q = query.to_lowercase();
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let take = if limit == 0 {
            usize::MAX
        } else {
            limit as usize
        };
        guard
            .get(agent_id)
            .map(|bucket| {
                bucket
                    .iter()
                    .filter(|e| e.is_active)
                    .filter(|e| e.created_at.as_str() <= timestamp)
                    .filter(|e| matches(&q, e))
                    .take(take)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Forget result distinguished from generic store errors so WIT handlers
    /// can map the "not-found" case to the WIT `memory-error::not-found`
    /// variant without fragile Debug-string matching (round-10 audit fix —
    /// previously the ForgetHandler classified by `format!("{:?}")` substring
    /// match on PostProcessorError::Invalid contents, which would silently
    /// regress on any rewording of the underlying error strings).
    pub fn forget(&self, agent_id: &str, id: &str) -> Result<(), ForgetError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Pre-mutation snapshot for the persist-failure rollback (AC-40).
        let pre = Self::snapshot(&guard, agent_id);
        let changed = {
            let bucket = guard
                .get_mut(agent_id)
                .ok_or_else(|| ForgetError::NotFound(format!("agent_id {} unknown", agent_id)))?;
            let entry = bucket
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| ForgetError::NotFound(format!("entry id {} not found", id)))?;
            // W3 (CW1): if the entry is already Forgotten, this is a no-op — do
            // NOT rewrite the file (no redundant fsync on an idempotent retry).
            let already_forgotten = entry.status == MemoryStatus::Forgotten && !entry.is_active;
            entry.status = MemoryStatus::Forgotten;
            entry.is_active = false;
            // Forgotten entries MUST have superseded_by=None per invariant rule 4
            // ("non-superseded entries must have superseded_by=None").
            entry.superseded_by = None;
            entry.supersession_reason = None;
            entry
                .validate_invariants()
                .map_err(|e| ForgetError::Invalid(e.to_string()))?;
            !already_forgotten
        };
        // Persist the mutated bucket (full rewrite) ONLY when the entry actually
        // changed; roll back in-memory on a disk-write failure so cache==disk.
        if changed {
            self.persist_or_restore(&mut guard, agent_id, pre)
                .map_err(|e| {
                    ForgetError::Invalid(format!("persist failed, rolled back forget: {e}"))
                })?;
        }
        Ok(())
    }

    /// Slice B in-process rollback: drop entries with `created_at > timestamp`.
    /// Full AC-18 git-backed rollback is deferred.
    ///
    /// Slice D: returns the exact count of entries dropped, computed **inside
    /// the same `inner` lock** immediately before `retain` so the count is
    /// atomic with the drop (no read-modify-read race) and exact (not an
    /// `is_active` proxy). Powers `memory.rollback.entries_deactivated`
    /// (PRD §15.3.12; MODULE-011 §3.8 note 7). `Ok(0)` when the agent has no
    /// bucket.
    pub fn rollback(&self, agent_id: &str, timestamp: &str) -> Result<usize, PostProcessorError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pre = Self::snapshot(&guard, agent_id);
        let dropped = if let Some(bucket) = guard.get_mut(agent_id) {
            let d = bucket
                .iter()
                .filter(|e| e.created_at.as_str() > timestamp)
                .count();
            bucket.retain(|e| e.created_at.as_str() <= timestamp);
            d
        } else {
            0
        };
        // Persist only when the drop actually changed the bucket (W3: no-op
        // branches do not persist); roll back in-memory on a disk failure.
        if dropped > 0 {
            self.persist_or_restore(&mut guard, agent_id, pre)
                .map_err(|e| {
                    PostProcessorError::Invalid(format!(
                        "persist failed, rolled back rollback: {e}"
                    ))
                })?;
        }
        Ok(dropped)
    }

    /// Apply a `MemoryAction` produced by the `Reconciler`. Dispatched by the
    /// post-processor's Step 5.
    pub fn apply_action(
        &self,
        agent_id: &str,
        action: MemoryAction,
    ) -> Result<(), PostProcessorError> {
        match action {
            MemoryAction::Insert(entry) => {
                // Round-13 adversarial-fix #12: cross-agent identity defense —
                // refuse to write an entry whose own agent_id field disagrees
                // with the caller's agent_id parameter. The MemoryEntry's
                // agent_id field is otherwise just a witness, but with future
                // wiring it becomes a referent for cross-agent isolation
                // (find_similar already filters on entry.agent_id ==
                // agent_id). Failing here makes the invariant enforced rather
                // than by-comment.
                if entry.agent_id != agent_id {
                    return Err(PostProcessorError::Invalid(format!(
                        "agent_id mismatch: caller={} entry.agent_id={}",
                        agent_id, entry.agent_id
                    )));
                }
                let _ = self.insert(agent_id, entry)?;
                Ok(())
            }
            MemoryAction::Supersede {
                old_id,
                mut new_entry,
                reason,
            } => {
                // Round-13 adversarial-fix #12: cross-agent identity defense
                // (same as the Insert branch above).
                if new_entry.agent_id != agent_id {
                    return Err(PostProcessorError::Invalid(format!(
                        "agent_id mismatch on supersede: caller={} new_entry.agent_id={}",
                        agent_id, new_entry.agent_id
                    )));
                }
                // Normalize the new (active) row.
                new_entry.status = MemoryStatus::Active;
                new_entry.is_active = true;
                new_entry.superseded_by = None;
                new_entry.supersession_reason = None;
                new_entry
                    .validate_invariants()
                    .map_err(|e| PostProcessorError::Invalid(e.to_string()))?;
                // Per-entry write cap (slice dev-task-mem-retention): the new
                // active entry must fit MAX_ENTRY_BYTES so its persisted line can
                // never trip the boot read cap.
                let _ = Self::check_entry_size(&new_entry)?;
                let new_id = new_entry.id.clone();

                let mut guard = self
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Pre-mutation snapshot for the two-entry persist-failure unwind
                // (restores both the old-side mutation AND drops the pushed new
                // entry). (AC-40, W4.)
                let pre = Self::snapshot(&guard, agent_id);
                let bucket = guard.entry(agent_id.to_string()).or_default();

                // Phase 1: validate WITHOUT mutating. (a) old_id must exist
                // before any mutation lands — round-9 Diff Evaluator atomicity
                // fix #1: otherwise we leave an orphan new entry on failure.
                // (b) compute the candidate end-state for the old entry and
                // validate its invariants BEFORE applying — round-9 fix #2:
                // otherwise partial-mutation can leak on validate_invariants
                // failure. (c) active-count limit must account for Supersede's
                // net-zero delta (old → inactive AND new → active = +1 - 1) —
                // round-9 fix #3: pure-Insert is +1 (already checked in
                // `insert()`); Supersede is net-zero IF old is currently
                // active, else +1. Compute the net delta explicitly.
                let old_idx = bucket.iter().position(|e| e.id == old_id).ok_or_else(|| {
                    PostProcessorError::Invalid(format!("supersede old_id {} not found", old_id))
                })?;
                let old_currently_active = bucket[old_idx].is_active;
                let net_active_delta: isize = if old_currently_active { 0 } else { 1 };
                let active_count = bucket.iter().filter(|e| e.is_active).count() as isize;
                if active_count + net_active_delta > self.max_active_per_agent as isize {
                    return Err(PostProcessorError::LimitExceeded);
                }
                // Build the candidate OLD-side post-state in a local clone
                // and validate it. Only if validate passes do we commit both
                // mutations atomically (single-lock, no `await` in between).
                let mut candidate_old = bucket[old_idx].clone();
                candidate_old.status = MemoryStatus::Superseded;
                candidate_old.is_active = false;
                candidate_old.supersession_reason = Some(reason);
                candidate_old.superseded_by = Some(new_id);
                candidate_old
                    .validate_invariants()
                    .map_err(|e| PostProcessorError::Invalid(e.to_string()))?;
                // Per-entry write cap: the old entry GAINS superseded_by + reason,
                // so its serialized line grows — re-check it can still be persisted
                // (closes the Codex round-2 C1 rewrite-path gap).
                let _ = Self::check_entry_size(&candidate_old)?;

                // Phase 2: commit. Both mutations land while still holding the
                // guard, so external observers see either both-applied or
                // neither.
                //
                // Round-13 adversarial-fix #11: pre-reserve capacity for the
                // `push` BEFORE the in-place assignment so a Vec-realloc OOM
                // panic happens during `reserve` (no mutations applied yet)
                // rather than between the two commit statements (leaving a
                // Superseded predecessor pointing at a missing replacement).
                // Rust's default panic-on-OOM is `abort`, so panic-safety here
                // is defense-in-depth for hosts running with custom allocators
                // that fail-soft on OOM.
                bucket.reserve(1);
                bucket[old_idx] = candidate_old;
                bucket.push(new_entry);
                // Persist both mutations atomically (full rewrite); on a disk
                // failure persist_or_restore restores `pre` (the two-entry
                // unwind). (AC-40, W4.)
                self.persist_or_restore(&mut guard, agent_id, pre)
                    .map_err(|e| {
                        PostProcessorError::Invalid(format!(
                            "persist failed, rolled back supersede: {e}"
                        ))
                    })?;
                Ok(())
            }
            MemoryAction::Skip => Ok(()),
        }
    }

    // ───────────────────────── Slice C — L6 mutators ─────────────────────────

    /// L6 Step 5b cluster_id writeback (AC-34). Cross-agent identity defense:
    /// the entry's own `agent_id` must match the caller's `agent_id`. ALWAYS
    /// appends one `L6JournalEntry` capturing the cluster_id as it is right
    /// before this write (NO dedup — pre-L6-value restoration is the emergent
    /// result of `rollback_l6`'s reverse replay; see §3.8 note 2).
    pub fn write_cluster_id(
        &self,
        agent_id: &str,
        entry_id: &str,
        cluster_id: &str,
        l6_commit_ts: SystemTime,
    ) -> Result<(), PostProcessorError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Pre-mutation snapshot for the persist-failure rollback (AC-40). The
        // entry-not-found / agent-mismatch guards below return BEFORE any
        // mutation, so `pre` is only consumed on the mutate path.
        let pre = Self::snapshot(&guard, agent_id);
        let prev = {
            let bucket = guard.get_mut(agent_id).ok_or_else(|| {
                PostProcessorError::Invalid(format!("agent_id {agent_id} unknown"))
            })?;
            let entry = bucket
                .iter_mut()
                .find(|e| e.id == entry_id)
                .ok_or_else(|| {
                    PostProcessorError::Invalid(format!(
                        "write_cluster_id: entry {entry_id} not found"
                    ))
                })?;
            if entry.agent_id != agent_id {
                return Err(PostProcessorError::Invalid(format!(
                    "agent_id mismatch on write_cluster_id: caller={} entry.agent_id={}",
                    agent_id, entry.agent_id
                )));
            }
            let prev = entry.cluster_id.clone();
            entry.cluster_id = Some(cluster_id.to_string());
            // Per-entry write cap: cluster_id is an arbitrary-length field, so the
            // mutated entry could now exceed MAX_ENTRY_BYTES. If so, restore the
            // prior cluster_id and reject WITHOUT persisting (closes the Codex
            // round-2 C1 rewrite-path gap). guard drops on return.
            if let Err(e) = Self::check_entry_size(entry) {
                entry.cluster_id = prev;
                return Err(e);
            }
            prev
        };
        // Persist the mutated bucket; roll back inner on a disk failure and do
        // NOT journal (cache==disk; the journal stays consistent with disk).
        self.persist_or_restore(&mut guard, agent_id, pre)
            .map_err(|e| {
                PostProcessorError::Invalid(format!(
                    "persist failed, rolled back write_cluster_id: {e}"
                ))
            })?;
        drop(guard);
        // Journal ONLY after a successful persist.
        self.journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(agent_id.to_string())
            .or_default()
            .push(L6JournalEntry {
                entry_id: entry_id.to_string(),
                field: L6JournalField::ClusterId,
                old: prev,
                l6_commit_ts,
            });
        Ok(())
    }

    /// L6 Step 3/5b consolidated-preference append (AC-32). Validates
    /// `entry_type == UserPreference` and sources empty-or-task-turn-only,
    /// inserts, and journals a `ConsolidatedPrefInsert` so `rollback_l6` can
    /// drop it. Retry-idempotency: if an active entry with the SAME
    /// `l6_batch:{id}` tag already exists, skip (returns its id).
    pub fn append_consolidated_preference(
        &self,
        agent_id: &str,
        entry: MemoryEntry,
        l6_commit_ts: SystemTime,
    ) -> Result<MemoryId, PostProcessorError> {
        if entry.entry_type != MemoryType::UserPreference {
            return Err(PostProcessorError::Invalid(
                "consolidated_preference must be type=user-preference".into(),
            ));
        }
        if entry.agent_id != agent_id {
            return Err(PostProcessorError::Invalid(format!(
                "agent_id mismatch on append_consolidated_preference: caller={} entry.agent_id={}",
                agent_id, entry.agent_id
            )));
        }
        let only_task_turn = entry
            .sources
            .iter()
            .all(|s| matches!(s, crate::knowledge::MemorySource::TaskTurn { .. }));
        if !only_task_turn {
            return Err(PostProcessorError::Invalid(
                "consolidated_preference sources must be empty or task-turn only".into(),
            ));
        }
        let batch_tag = entry
            .tags
            .iter()
            .find(|t| t.starts_with("l6_batch:"))
            .cloned();
        // Retry-idempotency: skip a re-append carrying an l6_batch tag that an
        // active entry already has.
        if let Some(tag) = &batch_tag {
            let guard = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(bucket) = guard.get(agent_id) {
                if let Some(existing) = bucket
                    .iter()
                    .find(|e| e.is_active && e.tags.iter().any(|t| t == tag))
                {
                    return Ok(existing.id.clone());
                }
            }
        }
        let id = self.insert(agent_id, entry)?;
        self.journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(agent_id.to_string())
            .or_default()
            .push(L6JournalEntry {
                entry_id: id.clone(),
                field: L6JournalField::ConsolidatedPrefInsert,
                old: None,
                l6_commit_ts,
            });
        Ok(id)
    }

    /// AC-34 `GROUP BY cluster_id`. Active entries grouped by `cluster_id`;
    /// entries with `cluster_id=None` are grouped under the empty key `""`
    /// (callers filter that bucket out for cluster enumeration).
    pub fn group_by_cluster(&self, agent_id: &str) -> HashMap<String, Vec<MemoryEntry>> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out: HashMap<String, Vec<MemoryEntry>> = HashMap::new();
        if let Some(bucket) = guard.get(agent_id) {
            for e in bucket.iter().filter(|e| e.is_active) {
                let key = e.cluster_id.clone().unwrap_or_default();
                out.entry(key).or_default().push(e.clone());
            }
        }
        out
    }

    fn set_status(
        &self,
        agent_id: &str,
        entry_id: &str,
        status: MemoryStatus,
    ) -> Result<(), PostProcessorError> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Pre-mutation snapshot for the persist-failure rollback (AC-40).
        let pre = Self::snapshot(&guard, agent_id);
        let changed = {
            let bucket = guard.get_mut(agent_id).ok_or_else(|| {
                PostProcessorError::Invalid(format!("agent_id {agent_id} unknown"))
            })?;
            let entry = bucket
                .iter_mut()
                .find(|e| e.id == entry_id)
                .ok_or_else(|| {
                    PostProcessorError::Invalid(format!("set_status: entry {entry_id} not found"))
                })?;
            if entry.agent_id != agent_id {
                return Err(PostProcessorError::Invalid(format!(
                    "agent_id mismatch on set_status: caller={} entry.agent_id={}",
                    agent_id, entry.agent_id
                )));
            }
            // W3 (CW1): skip the rewrite when the row is already in the exact
            // target state (no redundant fsync on an idempotent re-mark).
            let already = entry.status == status
                && entry.is_active
                && entry.superseded_by.is_none()
                && entry.supersession_reason.is_none();
            // Contested/Orphaned keep is_active=true per §1.3.2 invariants.
            entry.status = status;
            entry.is_active = true;
            entry.superseded_by = None;
            entry.supersession_reason = None;
            entry
                .validate_invariants()
                .map_err(|e| PostProcessorError::Invalid(e.to_string()))?;
            !already
        };
        if changed {
            self.persist_or_restore(&mut guard, agent_id, pre)
                .map_err(|e| {
                    PostProcessorError::Invalid(format!(
                        "persist failed, rolled back set_status: {e}"
                    ))
                })?;
        }
        Ok(())
    }

    pub fn mark_contested(&self, agent_id: &str, entry_id: &str) -> Result<(), PostProcessorError> {
        self.set_status(agent_id, entry_id, MemoryStatus::Contested)
    }

    pub fn mark_orphaned(&self, agent_id: &str, entry_id: &str) -> Result<(), PostProcessorError> {
        self.set_status(agent_id, entry_id, MemoryStatus::Orphaned)
    }

    /// Record a last-access timestamp for `zero_access_30d`.
    pub fn record_access(&self, agent_id: &str, entry_id: &str, now: SystemTime) {
        self.access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(agent_id.to_string())
            .or_default()
            .insert(entry_id.to_string(), now);
    }

    /// True iff the entry has NO recorded access OR its last access is older
    /// than 30 days before `now`. Folded into the health-snapshot O(N) pass.
    pub fn is_zero_access_30d(&self, agent_id: &str, entry_id: &str, now: SystemTime) -> bool {
        let guard = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.get(agent_id).and_then(|m| m.get(entry_id)) {
            None => true,
            Some(&last) => match now.duration_since(last) {
                Ok(elapsed) => elapsed >= THIRTY_DAYS,
                // Clock regression — treat as recently accessed (do not
                // spuriously count toward zero_access).
                Err(_) => false,
            },
        }
    }

    /// AC-34 clause (iii) in-process stand-in. Reverse-replays journal entries
    /// with `l6_commit_ts > before`: `ClusterId` → restore recorded `old`;
    /// `ConsolidatedPrefInsert` → remove the inserted entry. Replayed records
    /// are pruned. The pre-existing `created_at`-based `rollback` is untouched.
    pub fn rollback_l6(
        &self,
        agent_id: &str,
        before: SystemTime,
    ) -> Result<(), PostProcessorError> {
        // Compute the replay set WITHOUT pruning yet — the journal prune is
        // deferred until AFTER a successful persist, so a disk-write failure
        // leaves the journal + inner consistent (AC-40 reorder vs the prior
        // prune-then-mutate order). (`to_replay` = records with `ts > before`,
        // replayed in REVERSE.)
        let to_replay: Vec<L6JournalEntry> = {
            let jguard = self
                .journal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(records) = jguard.get(agent_id) else {
                return Ok(());
            };
            records
                .iter()
                .filter(|r| r.l6_commit_ts > before)
                .cloned()
                .collect()
        };
        // W3: nothing to replay → no inner change → no persist + no prune
        // (pruning `ts <= before` would be a no-op here anyway).
        if to_replay.is_empty() {
            return Ok(());
        }

        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pre = Self::snapshot(&guard, agent_id);
        if let Some(bucket) = guard.get_mut(agent_id) {
            for rec in to_replay.into_iter().rev() {
                match rec.field {
                    L6JournalField::ClusterId => {
                        if let Some(e) = bucket.iter_mut().find(|e| e.id == rec.entry_id) {
                            e.cluster_id = rec.old.clone();
                        }
                    }
                    L6JournalField::ConsolidatedPrefInsert => {
                        bucket.retain(|e| e.id != rec.entry_id);
                    }
                }
            }
        }
        // Persist the reverted bucket; on a disk failure restore inner and
        // leave the journal intact (do NOT prune).
        self.persist_or_restore(&mut guard, agent_id, pre)
            .map_err(|e| {
                PostProcessorError::Invalid(format!("persist failed, rolled back rollback_l6: {e}"))
            })?;
        drop(guard);
        // Prune the replayed journal records ONLY after a successful persist.
        if let Some(records) = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(agent_id)
        {
            records.retain(|r| r.l6_commit_ts <= before);
        }
        Ok(())
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let summary = self
            .inner
            .lock()
            .map(|g| {
                g.iter()
                    .map(|(k, v)| (k.clone(), v.len()))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        f.debug_struct("MemoryStore")
            .field("max_active_per_agent", &self.max_active_per_agent)
            .field("per_agent_count", &summary)
            .finish()
    }
}

fn matches(needle_lower: &str, entry: &MemoryEntry) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if entry.content.to_lowercase().contains(needle_lower) {
        return true;
    }
    entry
        .tags
        .iter()
        .any(|t| t.to_lowercase().contains(needle_lower))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryEntry, MemoryStatus, MemoryType, SupersessionReason};

    fn fact(id: &str, agent: &str, content: &str, created_at: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.into(),
            agent_id: agent.into(),
            entry_type: MemoryType::Fact,
            content: content.into(),
            tags: vec![],
            created_at: created_at.into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        }
    }

    #[test]
    fn insert_then_recall_round_trip() {
        let store = MemoryStore::new();
        let id = store
            .insert(
                "agent",
                fact("f1", "agent", "Rust is fast", "2026-01-01T00:00:00Z"),
            )
            .expect("insert ok");
        assert_eq!(id, "f1");
        let hits = store.recall("agent", "rust", 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "f1");
    }

    #[test]
    fn forget_excludes_from_recall() {
        let store = MemoryStore::new();
        store
            .insert(
                "agent",
                fact("f1", "agent", "hello world", "2026-01-01T00:00:00Z"),
            )
            .expect("insert ok");
        store.forget("agent", "f1").expect("forget ok");
        let hits = store.recall("agent", "hello", 10);
        assert!(hits.is_empty(), "forgotten entries excluded from recall");
        let direct = store.get("agent", "f1").expect("entry still present");
        assert!(!direct.is_active);
        assert_eq!(direct.status, MemoryStatus::Forgotten);
        assert!(direct.superseded_by.is_none());
    }

    #[test]
    fn recall_at_filters_by_created_at() {
        let store = MemoryStore::new();
        store
            .insert(
                "agent",
                fact("f1", "agent", "early", "2026-01-01T00:00:00Z"),
            )
            .expect("insert early");
        store
            .insert("agent", fact("f2", "agent", "late", "2026-06-01T00:00:00Z"))
            .expect("insert late");
        let hits = store.recall_at("agent", "", "2026-03-01T00:00:00Z", 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "f1");
    }

    #[test]
    fn rollback_drops_entries_after_timestamp() {
        let store = MemoryStore::new();
        store
            .insert(
                "agent",
                fact("f1", "agent", "early", "2026-01-01T00:00:00Z"),
            )
            .expect("insert early");
        store
            .insert("agent", fact("f2", "agent", "late", "2026-06-01T00:00:00Z"))
            .expect("insert late");
        let dropped = store
            .rollback("agent", "2026-03-01T00:00:00Z")
            .expect("rollback ok");
        // Slice D: exact atomic dropped-count (powers
        // memory.rollback.entries_deactivated).
        assert_eq!(dropped, 1, "exactly f2 (created_at > ts) dropped");
        let all = store.list("agent");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "f1");
        // Idempotent re-run drops nothing.
        assert_eq!(
            store
                .rollback("agent", "2026-03-01T00:00:00Z")
                .expect("rollback ok"),
            0
        );
        // Absent agent bucket → Ok(0).
        assert_eq!(
            store
                .rollback("no-such-agent", "2026-03-01T00:00:00Z")
                .expect("ok"),
            0
        );
    }

    #[test]
    fn apply_action_supersede_mutates_old_and_inserts_new() {
        let store = MemoryStore::new();
        store
            .insert(
                "agent",
                fact("f1", "agent", "Rust is fast", "2026-01-01T00:00:00Z"),
            )
            .expect("insert old");
        let new = fact(
            "f2",
            "agent",
            "Rust is fast and safe",
            "2026-02-01T00:00:00Z",
        );
        store
            .apply_action(
                "agent",
                MemoryAction::Supersede {
                    old_id: "f1".into(),
                    new_entry: new,
                    reason: SupersessionReason::Refinement,
                },
            )
            .expect("apply_action ok");
        let old = store.get("agent", "f1").expect("old still present");
        assert!(!old.is_active);
        assert_eq!(old.status, MemoryStatus::Superseded);
        assert_eq!(
            old.supersession_reason,
            Some(SupersessionReason::Refinement)
        );
        assert_eq!(old.superseded_by, Some("f2".into()));
        let new = store.get("agent", "f2").expect("new inserted");
        assert!(new.is_active);
        assert_eq!(new.status, MemoryStatus::Active);
        assert!(new.superseded_by.is_none());
    }

    #[test]
    fn insert_limit_exceeded() {
        let store = MemoryStore::with_limit(2);
        store
            .insert("agent", fact("f1", "agent", "a", "t1"))
            .expect("first ok");
        store
            .insert("agent", fact("f2", "agent", "b", "t2"))
            .expect("second ok");
        let r = store.insert("agent", fact("f3", "agent", "c", "t3"));
        assert!(matches!(r, Err(PostProcessorError::LimitExceeded)));
    }

    #[test]
    fn apply_action_insert_dispatches() {
        let store = MemoryStore::new();
        store
            .apply_action(
                "agent",
                MemoryAction::Insert(fact("f1", "agent", "hello", "t1")),
            )
            .expect("apply Insert ok");
        assert_eq!(store.list("agent").len(), 1);
    }

    #[test]
    fn apply_action_skip_is_noop() {
        let store = MemoryStore::new();
        store
            .apply_action("agent", MemoryAction::Skip)
            .expect("apply Skip ok");
        assert!(store.list("agent").is_empty());
    }

    #[test]
    fn apply_action_supersede_atomic_on_missing_old_id() {
        // Round-9 audit fix: failing Supersede with a non-existent old_id
        // must NOT leave the new entry orphaned in the store.
        let store = MemoryStore::new();
        let new = fact("f-new", "agent", "x", "t1");
        let r = store.apply_action(
            "agent",
            MemoryAction::Supersede {
                old_id: "does-not-exist".into(),
                new_entry: new,
                reason: SupersessionReason::Refinement,
            },
        );
        assert!(matches!(r, Err(PostProcessorError::Invalid(_))));
        assert!(
            store.list("agent").is_empty(),
            "new entry must NOT be inserted when old_id is missing"
        );
    }

    #[test]
    fn apply_action_supersede_net_zero_at_active_limit() {
        // Round-9 audit fix: at active_count == max, a Supersede (net-zero
        // delta on active count) MUST succeed; only a pure Insert hits
        // LimitExceeded at max.
        let store = MemoryStore::with_limit(2);
        store
            .insert("agent", fact("f1", "agent", "a", "t1"))
            .unwrap();
        store
            .insert("agent", fact("f2", "agent", "b", "t2"))
            .unwrap();
        // active_count == 2 == max. Insert would fail; Supersede should pass.
        let new = fact("f3", "agent", "c", "t3");
        let r = store.apply_action(
            "agent",
            MemoryAction::Supersede {
                old_id: "f1".into(),
                new_entry: new,
                reason: SupersessionReason::Refinement,
            },
        );
        assert!(
            r.is_ok(),
            "Supersede at max must succeed (net delta = 0); got {:?}",
            r
        );
        // Now there are 3 entries total but still 2 active (f2 + f3).
        let bucket = store.list("agent");
        assert_eq!(bucket.len(), 3);
        let active = bucket.iter().filter(|e| e.is_active).count();
        assert_eq!(
            active, 2,
            "active count stays at 2 after net-zero supersede"
        );
    }

    // ──────────────── retention / compaction (dev-task-mem-retention) ────────────────

    /// The production `remember`→`forget` DoS is bounded: the inactive tail never
    /// exceeds the retention window even after many cycles.
    #[test]
    fn forget_loop_is_bounded() {
        // Small entry cap, huge byte cap → the entry cap binds.
        let store = MemoryStore::with_inactive_caps(10_000, 8, 1 << 30);
        for i in 0..50 {
            let id = format!("f{i}");
            store
                .insert("a", fact(&id, "a", "x", &format!("t{i:04}")))
                .unwrap();
            store.forget("a", &id).unwrap();
        }
        let all = store.list("a");
        let inactive = all.iter().filter(|e| !e.is_active).count();
        assert!(inactive <= 8, "inactive tail bounded to 8, got {inactive}");
        assert!(all.len() <= 8, "total bounded (0 active after the loop)");
    }

    /// Compaction drops the OLDEST inactive entries (earliest inserted) and keeps
    /// ALL active entries, preserving order.
    #[test]
    fn compaction_drops_oldest_inactive_keeps_active() {
        let store = MemoryStore::with_inactive_caps(10_000, 3, 1 << 30);
        store.insert("a", fact("act1", "a", "x", "t01")).unwrap();
        for i in 0..6 {
            let id = format!("g{i}");
            store
                .insert("a", fact(&id, "a", "x", &format!("t1{i}")))
                .unwrap();
            store.forget("a", &id).unwrap();
        }
        store.insert("a", fact("act2", "a", "x", "t99")).unwrap();
        let all = store.list("a");
        let active: Vec<_> = all
            .iter()
            .filter(|e| e.is_active)
            .map(|e| e.id.clone())
            .collect();
        let inactive: Vec<_> = all
            .iter()
            .filter(|e| !e.is_active)
            .map(|e| e.id.clone())
            .collect();
        assert_eq!(active, vec!["act1", "act2"], "all active retained");
        assert_eq!(
            inactive,
            vec!["g3", "g4", "g5"],
            "oldest inactive g0..g2 dropped"
        );
    }

    /// The byte cap binds the inactive tail by EXACT serialized-line bytes (can
    /// bind before the entry cap when entries are large).
    #[test]
    fn byte_cap_bounds_inactive_retention() {
        let big = "x".repeat(10_000);
        // Large entry cap, small byte cap → the byte cap binds.
        let store = MemoryStore::with_inactive_caps(10_000, 10_000, 25_000);
        for i in 0..6 {
            let id = format!("b{i}");
            store
                .insert("a", fact(&id, "a", &big, &format!("t{i}")))
                .unwrap();
            store.forget("a", &id).unwrap();
        }
        let all = store.list("a");
        let inactive_bytes: usize = all
            .iter()
            .filter(|e| !e.is_active)
            .map(|e| serde_json::to_string(e).unwrap().len() + 1)
            .sum();
        assert!(
            inactive_bytes <= 25_000,
            "inactive bytes bounded, got {inactive_bytes}"
        );
        let inactive = all.iter().filter(|e| !e.is_active).count();
        assert!(
            (1..6).contains(&inactive),
            "byte cap binds before the (large) entry cap: {inactive}"
        );
    }

    /// Active entries are NEVER counted toward, nor dropped by, the inactive cap —
    /// even with a tiny inactive window and many active entries (rd3 Critical).
    #[test]
    fn many_active_entries_never_dropped_by_retention() {
        let store = MemoryStore::with_inactive_caps(10_000, 1, 100);
        for i in 0..20 {
            store
                .insert("a", fact(&format!("a{i}"), "a", "x", &format!("t{i:02}")))
                .unwrap();
        }
        // A forget triggers compaction (rewrite path); active entries survive.
        store.insert("a", fact("victim", "a", "x", "t99")).unwrap();
        store.forget("a", "victim").unwrap();
        let all = store.list("a");
        assert_eq!(
            all.iter().filter(|e| e.is_active).count(),
            20,
            "all 20 active retained despite a tiny inactive cap"
        );
        assert!(
            all.iter().filter(|e| !e.is_active).count() <= 1,
            "inactive bounded to 1"
        );
    }

    /// A new() (in-memory, no persistence) store is ALSO retention-bounded — the
    /// contract is uniform across backends (Claude-rd2-W2).
    #[test]
    fn inmemory_new_store_is_retention_bounded() {
        let store = MemoryStore::with_inactive_caps(10_000, 5, 1 << 30);
        for i in 0..30 {
            let id = format!("f{i}");
            store
                .insert("a", fact(&id, "a", "x", &format!("t{i:02}")))
                .unwrap();
            store.forget("a", &id).unwrap();
        }
        assert!(store.list("a").iter().filter(|e| !e.is_active).count() <= 5);
    }

    /// An entry whose serialized line exceeds `MAX_ENTRY_BYTES` is rejected by
    /// `insert` (nothing persisted); an entry just under passes.
    #[test]
    fn entry_over_max_entry_bytes_rejected() {
        let store = MemoryStore::new();
        let huge = "x".repeat(MAX_ENTRY_BYTES + 100);
        let r = store.insert("a", fact("h", "a", &huge, "t"));
        assert!(
            matches!(r, Err(PostProcessorError::Invalid(_))),
            "oversize rejected: {r:?}"
        );
        assert!(store.list("a").is_empty(), "nothing persisted on reject");
        assert!(store
            .insert("a", fact("ok", "a", &"x".repeat(1024), "t"))
            .is_ok());
    }

    /// Supersede re-checks the OLD entry's size AFTER it gains `superseded_by` —
    /// a candidate_old that would exceed the cap is rejected atomically (C1 fix).
    #[test]
    fn supersede_candidate_old_over_cap_rejected() {
        let store = MemoryStore::new();
        // old fits comfortably; candidate_old (old + a 4000-char superseded_by id)
        // crosses the cap.
        let near = "x".repeat(MAX_ENTRY_BYTES - 2000);
        store.insert("a", fact("old", "a", &near, "t1")).unwrap();
        let huge_id = "n".repeat(4000);
        let new = fact(&huge_id, "a", "small", "t2");
        let r = store.apply_action(
            "a",
            MemoryAction::Supersede {
                old_id: "old".into(),
                new_entry: new,
                reason: SupersessionReason::Refinement,
            },
        );
        assert!(
            matches!(r, Err(PostProcessorError::Invalid(_))),
            "candidate_old over cap rejected: {r:?}"
        );
        // Atomic: old unchanged (active), new not inserted.
        let old = store.get("a", "old").unwrap();
        assert!(
            old.is_active && old.status == MemoryStatus::Active,
            "old unchanged"
        );
        assert!(old.superseded_by.is_none(), "old not superseded");
        assert!(store.get("a", &huge_id).is_none(), "new entry not inserted");
    }

    /// `write_cluster_id` re-checks size after setting the arbitrary-length
    /// `cluster_id`; on overflow it restores the prior cluster_id and rejects.
    #[test]
    fn write_cluster_id_over_cap_rejected() {
        let store = MemoryStore::new();
        let near = "x".repeat(MAX_ENTRY_BYTES - 2000);
        store.insert("a", fact("e", "a", &near, "t1")).unwrap();
        let huge_cluster = "c".repeat(4000);
        let r = store.write_cluster_id("a", "e", &huge_cluster, SystemTime::UNIX_EPOCH);
        assert!(
            matches!(r, Err(PostProcessorError::Invalid(_))),
            "cluster_id over cap rejected: {r:?}"
        );
        assert!(
            store.get("a", "e").unwrap().cluster_id.is_none(),
            "prior cluster_id restored"
        );
    }
}
