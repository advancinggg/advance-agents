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

use std::collections::{HashMap, HashSet};
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

/// The tag by which an entry handed over to another agent names the agent that wrote it
/// ([`MemoryStore::hand_over`]): `from-agent:<agent id>`. The store's own: [`MemoryStore::insert`]
/// and a supersede refuse an entry with a tag that reads as one once spelt plainly (in any ASCII
/// case, in styled or full-width letters, past invisible code points, with a look-alike colon or
/// hyphen), so no agent can name another as the origin of what it writes, and the post-processor
/// drops such a tag from the entries a model extracts before it writes them. The store reads
/// it exactly ([`handed_over_from`]); an entry written before v0.1.57 with such a tag of its
/// guest's keeps it, and reads as handed over.
pub const FROM_AGENT_TAG_PREFIX: &str = "from-agent:";

/// The agent `entry` was handed over from — the agent that wrote it — when it was handed over
/// ([`FROM_AGENT_TAG_PREFIX`]).
pub fn handed_over_from(entry: &MemoryEntry) -> Option<&str> {
    entry
        .tags
        .iter()
        .find_map(|t| t.strip_prefix(FROM_AGENT_TAG_PREFIX))
}

/// Whether `tag` reads as a [`FROM_AGENT_TAG_PREFIX`] tag once spelt plainly ([`plain`]): in
/// any ASCII case; in full-width forms or mathematical alphanumeric letters (styled forms of
/// the plain ones); past the default-ignorable — invisible — code points; with one of the
/// colons listed for its colon; and with a run of the dashes, hyphens, underscores and blanks
/// listed for its hyphen (White_Space, and the braille pattern blank) — those at the start and
/// those before the colon skipped. Letters of other scripts, accented letters, other styled
/// forms (circled, small capitals, …) and other signs that only look like a blank or a dash
/// (box drawing, CJK letters, …) are not chased: the store reads the prefix exactly
/// ([`handed_over_from`]), so such a tag is one of the writer's own, which names no agent to
/// the store.
pub(crate) fn reads_as_handed_over(tag: &str) -> bool {
    let prefix = FROM_AGENT_TAG_PREFIX;
    let mut folded = String::with_capacity(prefix.len() + 4);
    for c in tag.chars() {
        let c = match plain(c) {
            Plain::Invisible => continue,
            Plain::Separator => {
                // Skipped at the start; a run reads as one hyphen.
                if !folded.is_empty() && !folded.ends_with('-') {
                    folded.push('-');
                }
                continue;
            }
            Plain::Colon => {
                // The separators before a colon are dropped.
                while folded.ends_with('-') {
                    folded.pop();
                }
                ':'
            }
            Plain::Char(c) => c,
        };
        folded.push(c);
        // Only separators at its end are ever dropped, so what is folded so far stays as it
        // is once it ends in something else.
        if folded.len() >= prefix.len() {
            break;
        }
    }
    folded.starts_with(prefix)
}

/// What a character of a tag is once spelt plainly ([`reads_as_handed_over`]).
enum Plain {
    /// A default-ignorable code point: a reader does not see it.
    Invisible,
    /// A dash, hyphen, minus, underscore or blank of those listed.
    Separator,
    /// A colon of those listed.
    Colon,
    /// Anything else, an ASCII letter in lower case.
    Char(char),
}

/// `c` spelt plainly: a full-width form, or a mathematical alphanumeric letter — or one of the
/// letterlike symbols that stand in that block for a letter of the prefix —, as its ASCII
/// character; then classed ([`Plain`]).
fn plain(c: char) -> Plain {
    let c = match c {
        // The full-width forms of ASCII letters and signs (U+FF01..=U+FF5E).
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
        // The mathematical alphanumeric letters: thirteen styles of A–Z then a–z.
        '\u{1D400}'..='\u{1D6A3}' => {
            let k = (c as u32 - 0x1D400) % 52;
            char::from_u32(if k < 26 {
                'A' as u32 + k
            } else {
                'a' as u32 + k - 26
            })
            .unwrap_or(c)
        }
        // The letterlike symbols that stand in that block for letters of the prefix.
        '\u{2130}' => 'E',
        '\u{2131}' => 'F',
        '\u{2133}' => 'M',
        '\u{2115}' => 'N',
        '\u{211B}'..='\u{211D}' => 'R',
        '\u{210A}' => 'g',
        '\u{212F}' => 'e',
        '\u{2134}' => 'o',
        c => c,
    };
    match c {
        c if is_default_ignorable(c) => Plain::Invisible,
        ':' | '\u{02D0}' | '\u{02F8}' | '\u{0589}' | '\u{05C3}' | '\u{0703}' | '\u{0704}'
        | '\u{0903}' | '\u{0A83}' | '\u{16EC}' | '\u{1803}' | '\u{1809}' | '\u{205A}'
        | '\u{2236}' | '\u{A4FD}' | '\u{A789}' | '\u{FE13}' | '\u{FE30}' | '\u{FE55}' => {
            Plain::Colon
        }
        '-'
        | '_'
        | '\u{02CD}'
        | '\u{02D7}'
        | '\u{06D4}'
        | '\u{1806}'
        | '\u{2010}'..='\u{2015}'
        | '\u{2017}'
        | '\u{2043}'
        | '\u{2212}'
        | '\u{2796}'
        // The braille pattern blank: shown as a blank, though not White_Space.
        | '\u{2800}'
        | '\u{2E17}'
        | '\u{2E1A}'
        | '\u{2E3A}'
        | '\u{2E3B}'
        | '\u{FE4D}'..='\u{FE4F}'
        | '\u{FE58}'
        | '\u{FE63}' => Plain::Separator,
        c if c.is_whitespace() => Plain::Separator,
        c => Plain::Char(c.to_ascii_lowercase()),
    }
}

/// Unicode's `Default_Ignorable_Code_Point` (DerivedCoreProperties): the code points a
/// reader does not see.
fn is_default_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// How many active entries of its own `bucket` holds — those handed over to its agent
/// ([`handed_over_from`]) not counted: what `max_active_per_agent` is checked against when
/// an entry is added (an insert, a supersede of an inactive entry).
fn own_active(bucket: &[MemoryEntry]) -> usize {
    bucket
        .iter()
        .filter(|e| e.is_active && handed_over_from(e).is_none())
        .count()
}

/// The active entries an agent holds ([`MemoryStore::active_count`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActiveCount {
    /// Those without the provenance tag ([`handed_over_from`]) — what the cap on active
    /// entries bounds: the entries it wrote itself, and any handed over to it without the tag
    /// (one too large to carry it). An entry written before v0.1.57 with the tag of its
    /// guest's counts as handed over.
    pub own: usize,
    /// Those handed over to it ([`MemoryStore::hand_over`]), which the cap does not count.
    pub handed_over: usize,
}

/// What a hand-over moved ([`MemoryStore::hand_over`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandedOver {
    /// The ids of the entries moved: the agent that handed them over holds none of them now,
    /// and its heir holds every one.
    pub ids: Vec<MemoryId>,
    /// How many of them the heir did not hold already.
    pub gained: usize,
    /// How many of them are active.
    pub active: usize,
}

pub struct MemoryStore {
    inner: Mutex<HashMap<String, Vec<MemoryEntry>>>,
    /// Per-agent L6-mutation journal (slice C — `rollback_l6`).
    journal: Mutex<HashMap<String, Vec<L6JournalEntry>>>,
    /// Per-agent per-entry last-access timestamp (slice C — feeds
    /// `zero_access_30d` in the health snapshot's single O(N) pass).
    access: Mutex<HashMap<String, HashMap<String, SystemTime>>>,
    /// The cap on an agent's active entries of its own ([`own_active`]: those handed over
    /// to it not counted): an insert, and a supersede of an inactive entry, are refused once
    /// they reach it (MODULE-011 §3.6).
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
    /// 2. **`max_active_per_agent` gates new ACTIVE inserts — counting the agent's
    ///    own active entries, not those handed over to it ([`Self::hand_over`]); active
    ///    entries are never dropped by retention.** Hydration loads every on-disk active entry
    ///    plus the bounded inactive tail (`persistence::open` applies the same
    ///    inactive window during the streaming read). If a file was externally
    ///    enlarged or the active cap reduced between sessions, the existing active
    ///    entries are kept and new active inserts stay blocked until the agent's own
    ///    active count drops below the cap — the safe, lossless degradation.
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

    /// Refuse an entry with a tag that reads as a [`FROM_AGENT_TAG_PREFIX`] tag
    /// ([`reads_as_handed_over`]): only [`Self::hand_over`] sets one, so a guest's `remember`
    /// cannot name another agent as the origin of what it writes — nor keep a hand-over from
    /// naming the agent that wrote it.
    fn refuse_reserved_tags(entry: &MemoryEntry) -> Result<(), PostProcessorError> {
        match entry.tags.iter().find(|t| reads_as_handed_over(t)) {
            Some(tag) => Err(PostProcessorError::Invalid(format!(
                "entry {}: the tag {tag:?} is reserved: a tag that reads as \
                 `{FROM_AGENT_TAG_PREFIX}…` names the agent an entry was handed over from",
                entry.id
            ))),
            None => Ok(()),
        }
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
        Self::refuse_reserved_tags(&entry)?;
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
        // The cap bounds the active entries an agent wrote itself: those handed over to it
        // ([`Self::hand_over`]) are not counted.
        if entry.is_active && own_active(bucket) >= self.max_active_per_agent {
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

    /// Hand every entry `from` holds over to `to`: the knowledge of a terminated agent,
    /// kept as history and taken over by the agent that outlives it (owner decision
    /// 2026-11-17; MODULE-011 §3.6). Each entry — active or not — moves into `to`'s bucket
    /// under `to`'s id and keeps its status, task and sources, so `to` recalls an active one
    /// as it recalls its own. It is tagged [`FROM_AGENT_TAG_PREFIX`]`<from>`, unless a tag of
    /// that kind names the agent that wrote it already (it was handed over before), and its
    /// L6 cluster id is cleared: it names a cluster of `from`'s, and `to`'s consolidation
    /// clusters the entry anew. `from` is left with none.
    ///
    /// An entry `to` holds already, by id, is not added again, so a hand-over run again
    /// finishes one that failed part-way. `to`'s file is written first — when it cannot be,
    /// nothing changes —, then `from`'s is emptied — when it cannot be, or the process ends
    /// between the two writes, both hold the entries (none is lost) until a hand-over runs
    /// again; the store runs none by itself. Each write rewrites the whole file, under the
    /// store's lock.
    ///
    /// The cap on active entries bounds those an agent writes itself ([`Self::active_count`]):
    /// the entries handed over do not count against `to`'s, so `to` writes on as before, and
    /// its active entries grow by the active ones it takes over — the root's by those of every
    /// agent terminated below it. The inactive ones join `to`'s inactive tail under its
    /// retention, compacted on this rewrite as on every one: past the window the earliest
    /// inserted go, whoever wrote them, and the entries handed over count as inserted now,
    /// after `to`'s own. An entry too large to carry the tag — within a few bytes of
    /// [`MAX_ENTRY_BYTES`] — moves without it, and counts as `to`'s own. The entries' access
    /// times go with them; `from`'s L6 journal is dropped, since what it would roll back is
    /// no longer `from`'s. Returns what moved.
    pub fn hand_over(&self, from: &str, to: &str) -> Result<HandedOver, PostProcessorError> {
        self.move_entries(from, to, None)
    }

    /// Hand over to `to`, on the terms of [`Self::hand_over`], only those of `from`'s entries
    /// whose id is among `ids` — the entries a hand-over to `from` has just moved, when `from`
    /// turns out to be terminated too and they go on to the next heir —; `from` keeps the
    /// rest, its own among them, for its own terminate to hand over. An id `from` does not
    /// hold is passed over. Of `from`'s L6 journal, the records of the entries moved are
    /// dropped.
    pub fn hand_over_some(
        &self,
        from: &str,
        to: &str,
        ids: &[MemoryId],
    ) -> Result<HandedOver, PostProcessorError> {
        let only: HashSet<&str> = ids.iter().map(String::as_str).collect();
        self.move_entries(from, to, Some(&only))
    }

    /// [`Self::hand_over`] (`only` = `None`) and [`Self::hand_over_some`].
    fn move_entries(
        &self,
        from: &str,
        to: &str,
        only: Option<&HashSet<&str>>,
    ) -> Result<HandedOver, PostProcessorError> {
        if from == to {
            return Err(PostProcessorError::Invalid(format!(
                "hand_over: agent {from} cannot hand its entries over to itself"
            )));
        }
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let held_by_from = Self::snapshot(&guard, from);
        let moving: Vec<&MemoryEntry> = held_by_from
            .iter()
            .filter(|e| only.is_none_or(|only| only.contains(e.id.as_str())))
            .collect();
        if moving.is_empty() {
            return Ok(HandedOver::default());
        }
        let pre_to = Self::snapshot(&guard, to);
        let held_by_to: HashSet<String> = pre_to.iter().map(|e| e.id.clone()).collect();
        let tag = format!("{FROM_AGENT_TAG_PREFIX}{from}");
        let taken: Vec<MemoryEntry> = moving
            .iter()
            .filter(|e| !held_by_to.contains(&e.id))
            .map(|e| {
                let mut entry = (*e).clone();
                entry.agent_id = to.to_string();
                entry.cluster_id = None;
                if handed_over_from(&entry).is_none() {
                    entry.tags.push(tag.clone());
                    // An entry at the size cap moves untagged rather than not at all.
                    if Self::check_entry_size(&entry).is_err() {
                        entry.tags.pop();
                    }
                }
                entry
            })
            .collect();
        let moved = HandedOver {
            ids: moving.iter().map(|e| e.id.clone()).collect(),
            gained: taken.len(),
            active: moving.iter().filter(|e| e.is_active).count(),
        };
        if moved.gained > 0 {
            guard.entry(to.to_string()).or_default().extend(taken);
            self.persist_or_restore(&mut guard, to, pre_to)
                .map_err(|e| {
                    PostProcessorError::Invalid(format!(
                        "persist failed, nothing of {from} handed over to {to}: {e}"
                    ))
                })?;
        }
        let emptied = match only {
            None => true,
            Some(only) => {
                let bucket = guard.entry(from.to_string()).or_default();
                bucket.retain(|e| !only.contains(e.id.as_str()));
                bucket.is_empty()
            }
        };
        if emptied {
            guard.remove(from);
        }
        self.persist_or_restore(&mut guard, from, held_by_from)
            .map_err(|e| {
                PostProcessorError::Invalid(format!(
                    "persist failed, the entries of {from} are handed over to {to} and \
                     still held by {from} too: {e}"
                ))
            })?;
        drop(guard);
        if let Some(p) = &self.persistence {
            if moved.gained > 0 {
                p.clear_pending(to);
            }
            p.clear_pending(from);
        }
        {
            let mut access = self
                .access
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(times) = access.get_mut(from) {
                let taken: Vec<(String, SystemTime)> = moved
                    .ids
                    .iter()
                    .filter_map(|id| times.remove_entry(id))
                    .collect();
                if emptied || times.is_empty() {
                    access.remove(from);
                }
                if !taken.is_empty() {
                    let into = access.entry(to.to_string()).or_default();
                    for (id, at) in taken {
                        into.entry(id).or_insert(at);
                    }
                }
            }
        }
        {
            let mut journal = self
                .journal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if emptied {
                journal.remove(from);
            } else if let Some(records) = journal.get_mut(from) {
                let moved_ids: HashSet<&str> = moved.ids.iter().map(String::as_str).collect();
                records.retain(|r| !moved_ids.contains(r.entry_id.as_str()));
            }
        }
        Ok(moved)
    }

    /// The active entries `agent_id` holds: its own, which the cap on active entries bounds,
    /// and those handed over to it ([`Self::hand_over`]).
    pub fn active_count(&self, agent_id: &str) -> ActiveCount {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut count = ActiveCount::default();
        for entry in guard.get(agent_id).into_iter().flatten() {
            if !entry.is_active {
                continue;
            }
            if handed_over_from(entry).is_some() {
                count.handed_over += 1;
            } else {
                count.own += 1;
            }
        }
        count
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
                Self::refuse_reserved_tags(&new_entry)?;
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
                // failure. (c) the active-entry cap: a pure Insert is checked in
                // `insert()`; a Supersede adds no active entry when the old one is
                // active (old → inactive, new → active), and one otherwise — below.
                let old_idx = bucket.iter().position(|e| e.id == old_id).ok_or_else(|| {
                    PostProcessorError::Invalid(format!("supersede old_id {} not found", old_id))
                })?;
                // A supersede of an active entry leaves the number of active entries as it
                // was, and is never refused for the cap — nor by an agent past it (one whose
                // cap was lowered since, one that superseded entries handed over to it: each
                // new entry is its own, so its own entries pass the cap by those). One of an
                // inactive entry adds an active entry of the agent's own, and is refused as an
                // insert is.
                let old_currently_active = bucket[old_idx].is_active;
                if !old_currently_active && own_active(bucket) >= self.max_active_per_agent {
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

    fn ids(entries: &[MemoryEntry]) -> Vec<String> {
        entries.iter().map(|e| e.id.clone()).collect()
    }

    /// Plant a directory where `agent`'s file is written through (its `.tmp`): every
    /// rewrite of that file fails until it is removed. Returns its path.
    fn block_rewrites_of(root: &std::path::Path, agent: &str) -> std::path::PathBuf {
        let tmp = root.join(crate::persistence::slug(agent)).join(format!(
            "{}.tmp",
            crate::persistence::KNOWLEDGE_JSONL_FILENAME
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        tmp
    }

    /// A terminated agent's knowledge is taken over by its heir (owner decision 2026-11-17):
    /// every entry, active or not, under the heir's id, tagged with the agent that held it,
    /// unclustered, with its access time — on disk as in memory — and the agent is left with
    /// none.
    #[test]
    fn hand_over_moves_every_entry_to_the_heir_and_leaves_the_agent_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        store
            .insert(
                "root",
                fact("r1", "root", "the root's own", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        let mut known = fact("k1", "kid", "kid knows rust", "2026-01-02T00:00:00Z");
        known.tags = vec!["lang".into()];
        known.cluster_id = Some("cl-rust".into());
        store.insert("kid", known).unwrap();
        store
            .insert(
                "kid",
                fact("k2", "kid", "kid forgot this", "2026-01-03T00:00:00Z"),
            )
            .unwrap();
        store.forget("kid", "k2").unwrap();
        let seen = SystemTime::now();
        store.record_access("kid", "k1", seen);

        assert_eq!(store.hand_over("kid", "root").unwrap().gained, 2);

        let check = |store: &MemoryStore| {
            assert!(store.list("kid").is_empty(), "the agent holds none");
            assert_eq!(ids(&store.list("root")), ["r1", "k1", "k2"]);
            let k1 = store.get("root", "k1").unwrap();
            assert_eq!(k1.agent_id, "root");
            assert_eq!(k1.tags, ["lang", "from-agent:kid"]);
            assert_eq!(k1.cluster_id, None);
            assert!(k1.is_active);
            let k2 = store.get("root", "k2").unwrap();
            assert_eq!((k2.is_active, k2.status), (false, MemoryStatus::Forgotten));
            assert_eq!(k2.tags, ["from-agent:kid"]);
            assert_eq!(ids(&store.recall("root", "rust", 10)), ["k1"]);
        };
        check(&store);
        assert!(!store.is_zero_access_30d("root", "k1", seen));
        drop(store);
        check(&MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    }

    /// An entry handed over before keeps naming the agent that wrote it: a grandchild's,
    /// which its parent held when the parent was terminated in turn.
    #[test]
    fn hand_over_keeps_naming_the_agent_that_wrote_an_entry() {
        let store = MemoryStore::new();
        store
            .insert(
                "gc",
                fact("g1", "gc", "the grandchild's", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store
            .insert(
                "kid",
                fact("k1", "kid", "the child's", "2026-01-02T00:00:00Z"),
            )
            .unwrap();
        assert_eq!(store.hand_over("gc", "kid").unwrap().gained, 1);
        assert_eq!(store.hand_over("kid", "root").unwrap().gained, 2);
        assert_eq!(store.get("root", "g1").unwrap().tags, ["from-agent:gc"]);
        assert_eq!(store.get("root", "k1").unwrap().tags, ["from-agent:kid"]);
        assert!(store.list("gc").is_empty());
        assert!(store.list("kid").is_empty());
    }

    /// Run again, a hand-over adds nothing: an entry the heir holds already, by id — as it
    /// does after a hand-over that could not empty the agent — is not added twice.
    #[test]
    fn hand_over_run_again_adds_nothing() {
        let store = MemoryStore::new();
        store
            .insert("kid", fact("k1", "kid", "once", "2026-01-01T00:00:00Z"))
            .unwrap();
        assert_eq!(store.hand_over("kid", "root").unwrap().gained, 1);
        assert_eq!(store.hand_over("kid", "root").unwrap().gained, 0);
        // The agent holds the entry again, as one whose file could not be emptied does.
        store
            .insert("kid", fact("k1", "kid", "once", "2026-01-01T00:00:00Z"))
            .unwrap();
        assert_eq!(store.hand_over("kid", "root").unwrap().gained, 0);
        assert!(store.list("kid").is_empty());
        assert_eq!(ids(&store.list("root")), ["k1"]);
        assert_eq!(store.get("root", "k1").unwrap().tags, ["from-agent:kid"]);
    }

    /// A hand-over whose heir's file cannot be written changes nothing, in memory or on
    /// disk.
    #[test]
    fn hand_over_that_cannot_write_the_heir_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        store
            .insert(
                "root",
                fact("r1", "root", "the root's own", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store
            .insert(
                "kid",
                fact("k1", "kid", "the child's", "2026-01-02T00:00:00Z"),
            )
            .unwrap();
        block_rewrites_of(dir.path(), "root");
        assert!(store.hand_over("kid", "root").is_err());
        let check = |store: &MemoryStore| {
            assert_eq!(ids(&store.list("kid")), ["k1"]);
            assert_eq!(ids(&store.list("root")), ["r1"]);
            assert_eq!(store.get("kid", "k1").unwrap().agent_id, "kid");
        };
        check(&store);
        drop(store);
        check(&MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    }

    /// A hand-over that cannot empty the agent's file leaves the entries with the heir and
    /// with the agent too — in memory as on disk —, and a rerun finishes it.
    #[test]
    fn hand_over_that_cannot_empty_the_agent_is_finished_by_a_rerun() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        store
            .insert(
                "kid",
                fact("k1", "kid", "the child's", "2026-01-02T00:00:00Z"),
            )
            .unwrap();
        let blocked = block_rewrites_of(dir.path(), "kid");
        assert!(store.hand_over("kid", "root").is_err());
        let both = |store: &MemoryStore| {
            assert_eq!(ids(&store.list("kid")), ["k1"]);
            assert_eq!(ids(&store.list("root")), ["k1"]);
        };
        both(&store);
        both(&MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
        std::fs::remove_dir(&blocked).unwrap();
        assert_eq!(store.hand_over("kid", "root").unwrap().gained, 0);
        let done = |store: &MemoryStore| {
            assert!(store.list("kid").is_empty());
            assert_eq!(ids(&store.list("root")), ["k1"]);
            assert_eq!(store.get("root", "k1").unwrap().tags, ["from-agent:kid"]);
        };
        done(&store);
        drop(store);
        done(&MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    }

    /// An agent with no entries hands nothing over and writes nothing; and an agent cannot be
    /// its own heir.
    #[test]
    fn hand_over_of_nothing_or_to_itself() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        assert_eq!(store.hand_over("nobody", "root").unwrap().gained, 0);
        assert!(!dir.path().join(crate::persistence::slug("nobody")).exists());
        assert!(!dir.path().join(crate::persistence::slug("root")).exists());
        store
            .insert("kid", fact("k1", "kid", "mine", "2026-01-01T00:00:00Z"))
            .unwrap();
        assert!(store.hand_over("kid", "kid").is_err());
        assert_eq!(ids(&store.list("kid")), ["k1"]);
    }

    /// The provenance tag is the store's own: an entry written with one is refused, so no
    /// agent names another as the origin of what it remembers.
    #[test]
    fn insert_refuses_an_entry_that_names_an_agent_it_came_from() {
        let store = MemoryStore::new();
        let mut forged = fact("f1", "kid", "mine", "2026-01-01T00:00:00Z");
        forged.tags.push(format!("{FROM_AGENT_TAG_PREFIX}root"));
        assert!(matches!(
            store.insert("kid", forged),
            Err(PostProcessorError::Invalid(_))
        ));
        assert!(store.list("kid").is_empty());
        let mut near = fact("f2", "kid", "mine", "2026-01-01T00:00:00Z");
        near.tags.push("from-agents".to_string());
        assert!(
            store.insert("kid", near).is_ok(),
            "only the prefix is reserved"
        );
    }

    /// Nor does a superseding entry carry one.
    #[test]
    fn supersede_refuses_an_entry_that_names_an_agent_it_came_from() {
        let store = MemoryStore::new();
        store
            .insert("kid", fact("f1", "kid", "old", "2026-01-01T00:00:00Z"))
            .unwrap();
        let mut forged = fact("f2", "kid", "new", "2026-02-01T00:00:00Z");
        forged.tags.push(format!("{FROM_AGENT_TAG_PREFIX}root"));
        let applied = store.apply_action(
            "kid",
            MemoryAction::Supersede {
                old_id: "f1".into(),
                new_entry: forged,
                reason: SupersessionReason::Refinement,
            },
        );
        assert!(matches!(applied, Err(PostProcessorError::Invalid(_))));
        assert_eq!(ids(&store.list("kid")), ["f1"]);
        assert!(store.get("kid", "f1").unwrap().is_active, "nothing changes");
    }

    /// A tag that reads as a provenance tag once spelt plainly is refused too: in another
    /// case; past blanks or invisible code points; full-width or in mathematical letters;
    /// with a listed colon; with a run of dashes, underscores or blanks for its hyphen, or
    /// blanks before its colon. A tag that only begins alike is not, nor one in letters of
    /// another script or accented ones, which the store does not chase.
    #[test]
    fn insert_refuses_a_tag_that_reads_as_naming_the_agent_it_came_from() {
        let store = MemoryStore::new();
        let forged = [
            "From-Agent:root",
            " from-agent:root",
            "from-agent\u{FF1A}root",
            "\u{200B}from-agent:root",
            "from_agent:root",
            "from agent:root",
            "from\u{2010}agent:root",
            "\u{FF46}\u{FF52}\u{FF4F}\u{FF4D}\u{FF0D}\u{FF41}\u{FF47}\u{FF45}\u{FF4E}\u{FF54}\u{FF1A}root",
            "from - agent:root",
            "from-agent :root",
            "from  agent:root",
            "- from-agent:root",
            "from-agent\u{2066}:root",
            "f\u{FE0F}rom-agent:root",
            "\u{E0020}from-agent:root",
            "from\u{3164}-agent:root",
            "from-agent\u{A4FD}root",
            "from\u{2017}agent:root",
            "\u{1D41F}\u{1D42B}\u{1D428}\u{1D426}-\u{1D41A}\u{1D420}\u{1D41E}\u{1D427}\u{1D42D}:root",
            "\u{2131}rom-ag\u{212F}nt:root",
        ];
        for (i, tag) in forged.into_iter().enumerate() {
            let mut entry = fact(&format!("f{i}"), "kid", "mine", "2026-01-01T00:00:00Z");
            entry.tags.push(tag.to_string());
            assert!(
                matches!(
                    store.insert("kid", entry),
                    Err(PostProcessorError::Invalid(_))
                ),
                "{tag:?}"
            );
        }
        assert!(store.list("kid").is_empty());
        let fine = [
            "from-agents",
            "from agent reports",
            "agent:root",
            "fromagent:root",
            "from-agentx:root",
            "fr\u{0301}om-agent:root",
            "fr\u{043E}m-agent:root",
        ];
        for (i, tag) in fine.into_iter().enumerate() {
            let mut entry = fact(&format!("n{i}"), "kid", "mine", "2026-01-01T00:00:00Z");
            entry.tags.push(tag.to_string());
            assert!(store.insert("kid", entry).is_ok(), "{tag:?}");
        }
    }

    /// One forged tag for each look-alike the fold lists ([`plain`], [`is_default_ignorable`]):
    /// every invisible range at both ends, every colon, every dash, hyphen, underscore and blank
    /// (every range at both ends, and White_Space), every letterlike symbol in place of the
    /// letter it stands for, and the prefix in every style of the mathematical alphanumeric
    /// letters and in full-width forms — each reads as the prefix; and what only starts like it
    /// does not.
    #[test]
    fn every_listed_look_alike_reads_as_the_prefix() {
        fn ch(u: u32) -> char {
            char::from_u32(u).unwrap()
        }
        fn ends(ranges: &[(u32, u32)]) -> Vec<char> {
            ranges
                .iter()
                .flat_map(|&(lo, hi)| [ch(lo), ch(hi)])
                .collect()
        }
        let mut forged: Vec<String> = Vec::new();
        // Default_Ignorable_Code_Point, range by range.
        for c in ends(&[
            (0x00AD, 0x00AD),
            (0x034F, 0x034F),
            (0x061C, 0x061C),
            (0x115F, 0x1160),
            (0x17B4, 0x17B5),
            (0x180B, 0x180F),
            (0x200B, 0x200F),
            (0x202A, 0x202E),
            (0x2060, 0x206F),
            (0x3164, 0x3164),
            (0xFE00, 0xFE0F),
            (0xFEFF, 0xFEFF),
            (0xFFA0, 0xFFA0),
            (0xFFF0, 0xFFF8),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0000, 0xE0FFF),
        ]) {
            forged.push(format!("{c}from-agent:root"));
            forged.push(format!("fr{c}om-agent{c}:root"));
        }
        // The colons, the full-width one among them.
        for c in [
            ':', '\u{02D0}', '\u{02F8}', '\u{0589}', '\u{05C3}', '\u{0703}', '\u{0704}',
            '\u{0903}', '\u{0A83}', '\u{16EC}', '\u{1803}', '\u{1809}', '\u{205A}', '\u{2236}',
            '\u{A4FD}', '\u{A789}', '\u{FE13}', '\u{FE30}', '\u{FE55}', '\u{FF1A}',
        ] {
            forged.push(format!("from-agent{c}root"));
            forged.push(format!("from-agent -{c}root"));
        }
        // The dashes, hyphens, underscores and blanks: those listed (the full-width ones
        // among them), and White_Space.
        let mut separators = vec![
            '-', '_', '\u{02CD}', '\u{02D7}', '\u{06D4}', '\u{1806}', '\u{2017}', '\u{2043}',
            '\u{2212}', '\u{2796}', '\u{2800}', '\u{2E17}', '\u{2E1A}', '\u{2E3A}', '\u{2E3B}',
            '\u{FE58}', '\u{FE63}', '\u{FF0D}', '\u{FF3F}',
        ];
        separators.extend(ends(&[(0x2010, 0x2015), (0xFE4D, 0xFE4F)]));
        separators.extend([
            ' ', '\t', '\u{00A0}', '\u{1680}', '\u{2000}', '\u{200A}', '\u{2028}', '\u{2029}',
            '\u{202F}', '\u{205F}', '\u{3000}',
        ]);
        for c in separators {
            forged.push(format!("from{c}agent:root"));
            forged.push(format!("{c}from{c}{c}agent{c}:root"));
        }
        // The letterlike symbols, each in place of the letter it stands for.
        for (c, letter) in [
            ('\u{2130}', 'e'),
            ('\u{2131}', 'f'),
            ('\u{2133}', 'm'),
            ('\u{2115}', 'n'),
            ('\u{211B}', 'r'),
            ('\u{211C}', 'r'),
            ('\u{211D}', 'r'),
            ('\u{210A}', 'g'),
            ('\u{212F}', 'e'),
            ('\u{2134}', 'o'),
        ] {
            let word = "from-agent";
            let at = word.find(letter).unwrap();
            forged.push(format!("{}{c}{}:root", &word[..at], &word[at + 1..]));
        }
        // The prefix in each of the thirteen styles, in upper and in lower case.
        for style in 0..13u32 {
            for case in [0u32, 26] {
                let styled: String = "from-agent"
                    .chars()
                    .map(|c| match c {
                        '-' => '-',
                        c => ch(0x1D400 + 52 * style + case + (c as u32 - 'a' as u32)),
                    })
                    .collect();
                forged.push(format!("{styled}:root"));
            }
        }
        // In full-width forms.
        let full: String = "from-agent:"
            .chars()
            .map(|c| ch(c as u32 + 0xFEE0))
            .collect();
        forged.push(format!("{full}root"));
        for tag in &forged {
            assert!(reads_as_handed_over(tag), "{tag:?}");
        }
        for tag in [
            "from\u{2800}agents:root",
            "\u{2800}fromagent:root",
            "from-agent\u{2800}root",
            "from-agent\u{2134}root",
            "from\u{2500}agent:root",
        ] {
            assert!(!reads_as_handed_over(tag), "{tag:?}");
        }
    }

    /// The cap on active entries bounds those an agent writes itself: an heir taken past its
    /// cap writes on, up to its cap of its own; a supersede of an active entry — its own or
    /// one handed over — is never refused for the cap; one of an inactive entry is, as an
    /// insert is.
    #[test]
    fn hand_over_does_not_count_against_the_heirs_cap() {
        let store = MemoryStore::with_limit(2);
        store
            .insert(
                "root",
                fact("r1", "root", "the root's own", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store
            .insert(
                "kid",
                fact("k1", "kid", "the child's first", "2026-01-02T00:00:00Z"),
            )
            .unwrap();
        store
            .insert(
                "kid",
                fact("k2", "kid", "the child's second", "2026-01-03T00:00:00Z"),
            )
            .unwrap();
        let moved = store.hand_over("kid", "root").unwrap();
        assert_eq!((moved.ids.len(), moved.gained, moved.active), (2, 2, 2));
        assert_eq!(
            store.active_count("root"),
            ActiveCount {
                own: 1,
                handed_over: 2
            }
        );

        store
            .insert(
                "root",
                fact("r2", "root", "one more", "2026-01-04T00:00:00Z"),
            )
            .expect("the root writes on");
        assert!(matches!(
            store.insert(
                "root",
                fact("r3", "root", "past its cap", "2026-01-05T00:00:00Z")
            ),
            Err(PostProcessorError::LimitExceeded)
        ));
        let supersede = |old: &str, new: &str| {
            store.apply_action(
                "root",
                MemoryAction::Supersede {
                    old_id: old.into(),
                    new_entry: fact(new, "root", "refined", "2026-01-06T00:00:00Z"),
                    reason: SupersessionReason::Refinement,
                },
            )
        };
        supersede("k1", "r4").expect("an entry handed over is refined");
        supersede("r1", "r5").expect("an entry of its own is refined, past its cap");
        assert_eq!(
            store.active_count("root"),
            ActiveCount {
                own: 3,
                handed_over: 1
            }
        );
        store.forget("root", "r2").unwrap();
        assert!(matches!(
            supersede("r2", "r6"),
            Err(PostProcessorError::LimitExceeded)
        ));
    }

    /// A hand-over of some entries moves only those it names that the agent holds — on disk
    /// as in memory, with their access times — and leaves the agent the rest.
    #[test]
    fn hand_over_some_moves_only_the_entries_named() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        store
            .insert(
                "gc",
                fact("g1", "gc", "the grandchild's", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store
            .insert(
                "kid",
                fact("k1", "kid", "the child's own", "2026-01-02T00:00:00Z"),
            )
            .unwrap();
        assert_eq!(store.hand_over("gc", "kid").unwrap().ids, ["g1"]);
        let seen = SystemTime::now();
        store.record_access("kid", "g1", seen);
        store.record_access("kid", "k1", seen);

        let moved = store
            .hand_over_some("kid", "root", &["g1".to_string(), "absent".to_string()])
            .unwrap();
        assert_eq!(
            moved,
            HandedOver {
                ids: vec!["g1".to_string()],
                gained: 1,
                active: 1
            }
        );
        let check = |store: &MemoryStore| {
            assert_eq!(ids(&store.list("kid")), ["k1"]);
            assert_eq!(ids(&store.list("root")), ["g1"]);
            assert_eq!(store.get("root", "g1").unwrap().tags, ["from-agent:gc"]);
        };
        check(&store);
        assert!(!store.is_zero_access_30d("root", "g1", seen));
        assert!(!store.is_zero_access_30d("kid", "k1", seen));
        drop(store);
        check(&MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    }
}
