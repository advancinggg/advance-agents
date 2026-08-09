//! Skill-candidate state machine (AC-21, REQ-279) — cap-memory PRODUCER half.
//!
//! MODULE-011 §1.4.6 step 5c / §3.3 T21. This is the cap-memory side of the
//! skill-promotion bridge: an L6 consolidation PRODUCES a skill candidate into
//! `.agent/memory/_skill_candidates.jsonl` (runtime-private, not Git — §2.5).
//! Each lifecycle transition is an APPEND-ONLY JSONL event:
//!
//! - `generated` — a candidate is proposed (carries its `candidate_id` +
//!   `name` + `description`); after this it is `pending`.
//! - `resolved`  — terminal accept (the `generated` line is retained).
//! - `dismissed` — terminal dismiss.
//!
//! `candidate_id` is the lowercase-hex sha256 of the candidate's canonical key
//! (`name \n description`), so the same candidate content always yields the
//! same id (deterministic + process-stable — the AC-21 "sha256 candidate_id"
//! clause; SYS-AC-186).
//!
//! **Producer/consumer split:** the MODULE-017 `list-skill-candidates` /
//! `resolve-skill-candidate` WIT host-fns are the CONSUMER half
//! (MODULE-017-AC-21 — clean split, NOT a duplicate seam); they are WIRED to
//! this same on-disk store in cap-skills (slice wave6-laneB). The L6 Step-5a
//! runtime FLUSH of this file from inside `L6Runnable::handle` + the Step-5c
//! `skill.candidate_generated` emission are now LANDED (slice wave6-laneB; see
//! MODULE-011 §3.7 + §3.8 note 21). Because the reader (`read_events` /
//! `list_pending`) is now reachable from the guest-facing consumer host-fns, it
//! is DoS-bounded by `MAX_CANDIDATE_FILE_BYTES` (fail-closed `TooLarge`).
//!
//! The store is file-backed so the append-only invariant is directly testable
//! (each transition strictly grows the line count; state is reconstructed by
//! folding events, never by rewriting — T21-f). It mirrors the
//! `persistence::KnowledgeJsonlStore` append posture (`O_APPEND` + per-line
//! JSON): an append-only EVENT log. The ONE exception (slice wave6-laneB,
//! adversarial r1) is COMPACTION — when the log exceeds `MAX_CANDIDATE_EVENTS`,
//! `append_generated` atomically REWRITES it to the still-pending set (capped at
//! `MAX_PENDING_CANDIDATES`, dropping the oldest pending) so the now-guest-reachable
//! read cannot be DoS'd past `MAX_CANDIDATE_FILE_BYTES`; the folded pending state
//! is preserved (a compacted-away resolved candidate reads as NotFound rather than
//! AlreadyResolved — both surface as a consumer error, so no observable change).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Process-global per-candidate-file WRITE lock (slice wave6-laneB adversarial r3).
/// The L6 PRODUCER (cap-memory) and the cap-skills CONSUMER both mutate a candidate
/// file through `SkillCandidateStore`, IN THE SAME PROCESS but via independently
/// constructed instances — so a per-instance lock would not serialize them, and the
/// cap-skills provider `Mutex` only serializes consumer-vs-consumer. This registry
/// returns ONE `Mutex` per file path, so `append_generated` (incl. its compaction
/// rewrite) and `resolve` are mutually exclusive on a given file, eliminating the
/// compaction-rename-vs-concurrent-terminal-append data-loss race. Read-only
/// `list_pending`/`read_events` need no lock — `atomic_write`'s rename makes the
/// reader see either the old or the compacted file, never a torn one.
fn candidate_file_lock(path: &Path) -> Arc<Mutex<()>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let mut map = REGISTRY
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(
        map.entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

/// The canonical `_skill_candidates.jsonl` filename (runtime-private, not Git;
/// §2.5). Rooted under the agent's `.agent/memory/` by the cli `attach_l6` L6
/// flush (slice wave6-laneB); the store here is constructed against an explicit path.
pub const SKILL_CANDIDATES_FILENAME: &str = "_skill_candidates.jsonl";

/// Max bytes for a candidate `name` (adversarial-round W1 — bound the
/// producer input so an LLM-influenced name cannot drive unbounded JSONL
/// growth / per-line allocation). Mirrors the `wit_impl.rs` WIT-boundary cap
/// posture for guest-derived strings.
pub const MAX_CANDIDATE_NAME_BYTES: usize = 256;

/// Max bytes for a candidate `description` (adversarial-round W1).
pub const MAX_CANDIDATE_DESCRIPTION_BYTES: usize = 4096;

/// Max bytes for a candidate `candidate_id` (slice wave6-laneB adversarial r4).
/// `SkillCandidate::new` derives a 64-char lowercase-hex sha256, but the struct
/// field is PUBLIC, so a non-canonical caller could construct a candidate with an
/// arbitrarily large id. Bounding it (128 = 2× the sha256 hex) keeps the serialized
/// line size bounded so the compaction byte-bound (`should_compact_invariants`)
/// holds for ANY caller of `append_generated`, not just the L6 producer.
pub const MAX_CANDIDATE_ID_BYTES: usize = 128;

/// DoS bound on the total `_skill_candidates.jsonl` size (slice wave6-laneB).
/// The fold (`read_events` / `list_pending`) is now GUEST-REACHABLE via the
/// MODULE-017 `list/resolve-skill-candidate` host-fns, so a pathologically large
/// log (file corruption, or many years of L6 runs each appending up to the
/// `skill_health` array) is fail-closed rather than folded into unbounded memory.
/// 32 MiB ≈ >100k field-capped candidates (each ≤ ~256 name + ~4096 description +
/// JSON framing); a real deployment never approaches it (L6 is a rare cold path).
pub const MAX_CANDIDATE_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// Compaction trigger (slice wave6-laneB adversarial r1): when the append-only log
/// reaches this many events, `append_generated` first COMPACTS it (rewrite to the
/// pending set only) before appending. Without this a compromised/prompt-injected
/// LLM producing fresh candidates across many L6 runs would grow the log toward
/// `MAX_CANDIDATE_FILE_BYTES`, which would then fail-CLOSE the guest-reachable
/// consumer read. ~10k events ≈ a few MB — far under the byte cap.
pub const MAX_CANDIDATE_EVENTS: usize = 10_000;

/// Retention cap on PENDING candidates (slice wave6-laneB adversarial r1).
/// Compaction keeps the MOST-RECENT `MAX_PENDING_CANDIDATES` pending (drops the
/// oldest), so an unbounded stream of never-resolved candidates cannot grow the
/// file without bound. Mirrors the mem-retention slice's "drop oldest, keep newest"
/// inactive-cap posture. Generous: a real agent has a few dozen live candidates.
/// Sized so that even the JSON-ESCAPED worst-case line (control chars expand ~6×;
/// see `should_compact_invariants`) keeps the compacted file under the byte trigger
/// for ANY caller of the public `append_generated`, not just the bounded L6 producer.
pub const MAX_PENDING_CANDIDATES: usize = 512;

/// Retention cap on TERMINAL TOMBSTONES (slice wave6-laneB adversarial r5, W-15-2).
/// Compaction drops the heavy `Generated` line of a resolved/dismissed candidate but
/// KEEPS an id-only terminal tombstone, because `append_generated`'s dedup suppresses
/// any id already present in the log — dropping the terminal pair entirely would let a
/// later L6 run REGENERATE (resurrect) an already-dismissed/accepted candidate,
/// breaking dismiss/accept FINALITY. The tombstones are themselves bounded (drop
/// oldest beyond this cap), so finality is permanent for the most-recent N terminal
/// candidates while the file stays storage-bounded. A tombstone line is tiny (id only,
/// no name/description), so this cap can be generous without threatening the byte
/// budget (proved by `should_compact_invariants`).
pub const MAX_TERMINAL_TOMBSTONES: usize = 4096;

/// BYTE trigger for compaction (slice wave6-laneB adversarial r2). Compaction must
/// run BEFORE `read_events` would fail-close at `MAX_CANDIDATE_FILE_BYTES` — and an
/// event-COUNT trigger alone does not guarantee that, because `MAX_CANDIDATE_EVENTS`
/// worst-case lines (≈ name 256 + description 4096 + framing) exceed the byte cap.
/// 24 MiB is (a) below the 32 MiB read cap with room for one more max-size append,
/// and (b) above the max compacted size (`MAX_PENDING_CANDIDATES` × max-line ≈ 18 MiB),
/// so the log can NEVER reach the read cap (proved by `should_compact_invariants`).
pub const COMPACTION_TRIGGER_BYTES: u64 = 24 * 1024 * 1024;

/// A proposed skill candidate (the PRODUCER payload of a `generated` event).
///
/// Field shape mirrors `cap_skills::lifecycle::SkillCandidate`
/// (`candidate_id` / `name` / `description`) so the MODULE-017 consumer host-fns
/// (wired to this store in slice wave6-laneB) project these rows without an
/// impedance mismatch — cap-skills consumes the `candidate_id` VERBATIM (it has no
/// `sha2` dep), keeping the id algorithm single-sourced here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillCandidate {
    pub candidate_id: String,
    pub name: String,
    pub description: String,
}

impl SkillCandidate {
    /// Construct a candidate, DERIVING `candidate_id` as the lowercase-hex
    /// sha256 of the canonical key. Deterministic: the same `(name,
    /// description)` always yields the same id, across process runs (AC-21).
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        let name = name.into();
        let description = description.into();
        let candidate_id = compute_candidate_id(&name, &description);
        Self {
            candidate_id,
            name,
            description,
        }
    }
}

/// Lowercase-hex sha256 of the canonical candidate key built from `name` +
/// `description`. Exposed so callers (and tests) can predict the id without
/// constructing a `SkillCandidate`.
///
/// **Injective key (adversarial-round W3):** each field is LENGTH-PREFIXED
/// (`u64` little-endian byte count) before its bytes, so the `(name,
/// description) → key` mapping is bijective — an embedded newline/separator in
/// `name` can NO LONGER re-segment into a different `(name, description)` pair
/// with the same hash. Because `candidate_id` is the SOLE identity/idempotency
/// key of the state machine (a collision would let one candidate shadow or
/// suppress another via `append_generated` dedup / `resolve`), the
/// length-prefix closes that collision-spoofing surface — not merely a
/// content digest.
pub fn compute_candidate_id(name: &str, description: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update((name.len() as u64).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.update((description.len() as u64).to_le_bytes());
    hasher.update(description.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Terminal resolution of a pending candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Accept,
    Dismiss,
}

/// One append-only line in `_skill_candidates.jsonl`. Tagged on `event` so the
/// JSONL is self-describing and forward-readable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum SkillCandidateEvent {
    /// A candidate was produced (PRODUCER row) — pending after this.
    Generated {
        candidate_id: String,
        name: String,
        description: String,
    },
    /// Terminal accept.
    Resolved { candidate_id: String },
    /// Terminal dismiss.
    Dismissed { candidate_id: String },
}

impl SkillCandidateEvent {
    fn candidate_id(&self) -> &str {
        match self {
            SkillCandidateEvent::Generated { candidate_id, .. }
            | SkillCandidateEvent::Resolved { candidate_id }
            | SkillCandidateEvent::Dismissed { candidate_id } => candidate_id,
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self,
            SkillCandidateEvent::Resolved { .. } | SkillCandidateEvent::Dismissed { .. }
        )
    }
}

/// Errors from the skill-candidate store.
#[derive(Debug, thiserror::Error)]
pub enum SkillCandidateError {
    #[error("skill candidate not found: {0}")]
    NotFound(String),
    /// `name` or `description` exceeds its byte cap (adversarial-round W1 —
    /// reject rather than truncate, since truncation would silently change the
    /// `candidate_id`).
    #[error("skill candidate field too large: {0}")]
    TooLarge(String),
    /// A terminal event already exists for this candidate — the append-only
    /// state machine forbids a second terminal transition (double-resolve
    /// guard; the producer row + first terminal line are retained).
    #[error("skill candidate already resolved: {0}")]
    AlreadyResolved(String),
    #[error("skill candidate store io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("skill candidate store serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// File-backed append-only `_skill_candidates.jsonl` event store.
///
/// Writes are append-only (`O_APPEND`, one JSON object per line); reads fold
/// the whole log into the current state. There is NO rewrite path — terminal
/// transitions are appended, the `generated` rows are never mutated (the
/// AC-21 append-only invariant).
#[derive(Clone, Debug)]
pub struct SkillCandidateStore {
    path: PathBuf,
}

impl SkillCandidateStore {
    /// Open (or lazily create on first append) a store at `path`. The file is
    /// not created until the first `append_generated` so an unused store
    /// leaves no residue.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Open a store at `<dir>/_skill_candidates.jsonl`.
    pub fn in_dir(dir: impl AsRef<Path>) -> Self {
        Self::new(dir.as_ref().join(SKILL_CANDIDATES_FILENAME))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a `generated` event for `candidate`. Idempotent on
    /// `candidate_id`: a re-`generated` for an already-known candidate is a
    /// no-op (returns `Ok(false)`) so an L6 retry with the same `l6_batch_id`
    /// does not double-write. Returns `Ok(true)` when a new line was appended.
    pub fn append_generated(
        &self,
        candidate: &SkillCandidate,
    ) -> Result<bool, SkillCandidateError> {
        // Bound the producer input (adversarial-round W1): reject an oversize
        // name/description so an LLM-influenced candidate cannot drive
        // unbounded JSONL growth / per-line allocation. Reject (not truncate) —
        // truncation would silently change the candidate_id.
        if candidate.name.len() > MAX_CANDIDATE_NAME_BYTES {
            return Err(SkillCandidateError::TooLarge(format!(
                "name {} > {} bytes",
                candidate.name.len(),
                MAX_CANDIDATE_NAME_BYTES
            )));
        }
        if candidate.description.len() > MAX_CANDIDATE_DESCRIPTION_BYTES {
            return Err(SkillCandidateError::TooLarge(format!(
                "description {} > {} bytes",
                candidate.description.len(),
                MAX_CANDIDATE_DESCRIPTION_BYTES
            )));
        }
        // Bound the PUBLIC `candidate_id` field too (adversarial r4): `new` derives a
        // 64-hex sha256, but a struct-literal caller could pass an arbitrary id and
        // blow the serialized-line bound. Rejecting keeps the byte-bound sound.
        if candidate.candidate_id.len() > MAX_CANDIDATE_ID_BYTES {
            return Err(SkillCandidateError::TooLarge(format!(
                "candidate_id {} > {} bytes",
                candidate.candidate_id.len(),
                MAX_CANDIDATE_ID_BYTES
            )));
        }
        // Fold once to decide idempotency. (The producer path is off the hot
        // per-turn loop — L6 cold path — so a fold per append is acceptable;
        // the append-only file is small — bounded by the field caps above +
        // L6 cadence, NOT attacker-controlled per-line size.)
        // Serialize all writes to this file across the producer + consumer (same
        // process; adversarial r3): held for the whole read→(compact)→append, so a
        // compaction rewrite cannot lose a concurrent terminal append.
        let lock = candidate_file_lock(&self.path);
        let _guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Read the file BYTE size BEFORE `read_events` (adversarial r2): an
        // event-COUNT trigger alone is insufficient because the byte cap can fire
        // first for large-line candidates, and `read_events` fail-closes at the
        // byte cap — so compaction (which folds via `read_events`) must be able to
        // run while the log is still readable. `symlink_metadata` (no follow)
        // matches read_events; a missing/non-regular leaf → 0 (read_events handles it).
        let file_len = std::fs::symlink_metadata(&self.path)
            .ok()
            .filter(|m| m.file_type().is_file())
            .map(|m| m.len())
            .unwrap_or(0);
        let events = self.read_events()?;
        if events
            .iter()
            .any(|e| e.candidate_id() == candidate.candidate_id)
        {
            return Ok(false);
        }
        // Bound the append-only history (adversarial r1/r2): when the log is
        // approaching the byte cap OR the event count is high, compact to the
        // pending set (drop resolved/dismissed pairs + the oldest pending beyond
        // `MAX_PENDING_CANDIDATES`) BEFORE appending — so a compromised LLM
        // producing fresh candidates across many L6 runs cannot grow the
        // (guest-reachable) log toward `MAX_CANDIDATE_FILE_BYTES` (which would
        // fail-close the consumer read). Reuses the fold we just did.
        if Self::should_compact(file_len, events.len()) {
            self.compact_to_pending(&events)?;
        }
        self.append(&SkillCandidateEvent::Generated {
            candidate_id: candidate.candidate_id.clone(),
            name: candidate.name.clone(),
            description: candidate.description.clone(),
        })?;
        Ok(true)
    }

    /// Append a terminal `resolved`/`dismissed` event for `candidate_id`.
    ///
    /// - Unknown id (no `generated` line) ⇒ `Err(NotFound)`, NOTHING written.
    /// - Already-terminal id ⇒ `Err(AlreadyResolved)`, NOTHING written
    ///   (double-resolve guard; append-only invariant preserved).
    pub fn resolve(
        &self,
        candidate_id: &str,
        resolution: Resolution,
    ) -> Result<(), SkillCandidateError> {
        // Serialize with the producer's append/compaction on this file (same
        // process; adversarial r3) so a concurrent compaction rewrite cannot lose
        // this terminal append.
        let lock = candidate_file_lock(&self.path);
        let _guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events = self.read_events()?;
        let mut seen_generated = false;
        let mut seen_terminal = false;
        for e in &events {
            if e.candidate_id() == candidate_id {
                if matches!(e, SkillCandidateEvent::Generated { .. }) {
                    seen_generated = true;
                }
                if e.is_terminal() {
                    seen_terminal = true;
                }
            }
        }
        if !seen_generated {
            return Err(SkillCandidateError::NotFound(candidate_id.to_string()));
        }
        if seen_terminal {
            return Err(SkillCandidateError::AlreadyResolved(
                candidate_id.to_string(),
            ));
        }
        let event = match resolution {
            Resolution::Accept => SkillCandidateEvent::Resolved {
                candidate_id: candidate_id.to_string(),
            },
            Resolution::Dismiss => SkillCandidateEvent::Dismissed {
                candidate_id: candidate_id.to_string(),
            },
        };
        self.append(&event)
    }

    /// Fold the event log → the candidates that are still `pending` (have a
    /// `generated` event and NO terminal event), in first-seen (generation)
    /// order.
    pub fn list_pending(&self) -> Result<Vec<SkillCandidate>, SkillCandidateError> {
        Ok(Self::fold_pending(&self.read_events()?))
    }

    /// Fold an event slice → the still-`pending` candidates (a `generated` event,
    /// no terminal), in first-seen (generation) order. Shared by `list_pending`
    /// and compaction.
    fn fold_pending(events: &[SkillCandidateEvent]) -> Vec<SkillCandidate> {
        // Preserve generation order; drop any id that ever hit a terminal.
        let mut order: Vec<String> = Vec::new();
        let mut pending: std::collections::HashMap<String, SkillCandidate> =
            std::collections::HashMap::new();
        for e in events {
            match e {
                SkillCandidateEvent::Generated {
                    candidate_id,
                    name,
                    description,
                } => {
                    if !pending.contains_key(candidate_id) {
                        order.push(candidate_id.clone());
                    }
                    pending.insert(
                        candidate_id.clone(),
                        SkillCandidate {
                            candidate_id: candidate_id.clone(),
                            name: name.clone(),
                            description: description.clone(),
                        },
                    );
                }
                SkillCandidateEvent::Resolved { candidate_id }
                | SkillCandidateEvent::Dismissed { candidate_id } => {
                    pending.remove(candidate_id);
                }
            }
        }
        order
            .into_iter()
            .filter_map(|id| pending.remove(&id))
            .collect()
    }

    /// Compaction trigger decision (pure; unit-testable without a giant file).
    /// Compact when the log is approaching the byte cap (so `read_events` can still
    /// fold it before fail-closing at `MAX_CANDIDATE_FILE_BYTES`) OR the event count
    /// is high. The byte trigger is the load-bearing one — see
    /// `COMPACTION_TRIGGER_BYTES` + `should_compact_invariants`.
    fn should_compact(file_len: u64, event_count: usize) -> bool {
        file_len >= COMPACTION_TRIGGER_BYTES || event_count >= MAX_CANDIDATE_EVENTS
    }

    /// Compact the append-only log to the still-pending candidates' `Generated`
    /// events (slice wave6-laneB adversarial r1): drop resolved/dismissed pairs
    /// AND, when there are more than `MAX_PENDING_CANDIDATES`, the OLDEST pending —
    /// bounding the file so the unbounded append history cannot DoS the
    /// guest-reachable read past `MAX_CANDIDATE_FILE_BYTES`. Atomic (temp + rename
    /// via `persistence::atomic_write`), so a concurrent reader sees either the
    /// full old log or the compacted one, never a torn file; the folded pending
    /// set is preserved (list/resolve behave identically).
    fn compact_to_pending(
        &self,
        events: &[SkillCandidateEvent],
    ) -> Result<(), SkillCandidateError> {
        let mut pending = Self::fold_pending(events);
        if pending.len() > MAX_PENDING_CANDIDATES {
            let drop = pending.len() - MAX_PENDING_CANDIDATES;
            pending.drain(0..drop); // drop the oldest (front = earliest generated)
        }
        // Keep an id-only TERMINAL TOMBSTONE for each resolved/dismissed candidate
        // (adversarial r5, W-15-2): `append_generated`'s dedup suppresses any id
        // already in the log, so dropping the terminal pair entirely would let a later
        // L6 run resurrect an already-dismissed/accepted candidate. The tombstone keeps
        // the id (suppressing regeneration) WITHOUT the heavy Generated description, and
        // is itself bounded (drop oldest) so the file stays storage-bounded.
        let mut tombstones = Self::fold_terminal_tombstones(events);
        if tombstones.len() > MAX_TERMINAL_TOMBSTONES {
            let drop = tombstones.len() - MAX_TERMINAL_TOMBSTONES;
            tombstones.drain(0..drop); // drop the oldest terminal (front = earliest)
        }
        let mut out = String::new();
        for c in &pending {
            let ev = SkillCandidateEvent::Generated {
                candidate_id: c.candidate_id.clone(),
                name: c.name.clone(),
                description: c.description.clone(),
            };
            out.push_str(&serde_json::to_string(&ev)?);
            out.push('\n');
        }
        for ev in &tombstones {
            out.push_str(&serde_json::to_string(ev)?);
            out.push('\n');
        }
        crate::persistence::atomic_write(&self.path, out.as_bytes()).map_err(|e| {
            SkillCandidateError::Io(std::io::Error::other(format!(
                "skill candidate compaction: {e:?}"
            )))
        })
    }

    /// Fold an event slice → the id-only TERMINAL TOMBSTONE for every candidate that
    /// reached a terminal (resolved/dismissed) state, in first-terminal order, deduped
    /// (the double-resolve guard means an id has at most one terminal). Reconstructed
    /// (not cloned) as an id-only event so compaction can retain finality cheaply.
    /// Shared by `compact_to_pending`; a tombstone never enters `fold_pending` (it has
    /// no `Generated` event) so it is invisible to `list_pending`.
    fn fold_terminal_tombstones(events: &[SkillCandidateEvent]) -> Vec<SkillCandidateEvent> {
        let mut order: Vec<String> = Vec::new();
        // id → was-resolved (true = Resolved, false = Dismissed).
        let mut kind: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
        for e in events {
            let (id, resolved) = match e {
                SkillCandidateEvent::Resolved { candidate_id } => (candidate_id, true),
                SkillCandidateEvent::Dismissed { candidate_id } => (candidate_id, false),
                SkillCandidateEvent::Generated { .. } => continue,
            };
            if !kind.contains_key(id) {
                order.push(id.clone());
            }
            kind.insert(id.clone(), resolved);
        }
        order
            .into_iter()
            .map(|id| {
                if kind[&id] {
                    SkillCandidateEvent::Resolved { candidate_id: id }
                } else {
                    SkillCandidateEvent::Dismissed { candidate_id: id }
                }
            })
            .collect()
    }

    /// Total appended event lines (T21-f append-only line-growth witness).
    pub fn event_count(&self) -> Result<usize, SkillCandidateError> {
        Ok(self.read_events()?.len())
    }

    /// Read + parse every JSONL line into events (fold input). A missing file
    /// is an empty log. Fails loud on a malformed line (never silently drops).
    pub fn read_events(&self) -> Result<Vec<SkillCandidateEvent>, SkillCandidateError> {
        // DoS + FIFO-hang bound (slice wave6-laneB): the fold is now reachable from
        // the guest-facing `list/resolve-skill-candidate` host-fns. `symlink_metadata`
        // (does NOT follow a symlink) lets us, BEFORE `File::open`,
        //   (1) reject a NON-REGULAR leaf — symlink / FIFO / socket / device / dir —
        //       because `File::open` on a FIFO blocks the (spawn_blocking) thread
        //       forever; and
        //   (2) reject a pathologically large log FAIL-CLOSED rather than folding it
        //       into unbounded memory.
        // A missing file → Err(NotFound) → falls through to the empty-log handling
        // below. (`.agent/memory` is an owner-only 0700 tree the guest cannot write
        // into, so a post-stat leaf-swap is not guest-reachable — the residual TOCTOU
        // is the same accepted posture as `runnable.rs::reject_symlinked_dir`.)
        match std::fs::symlink_metadata(&self.path) {
            Ok(md) if !md.file_type().is_file() => {
                return Err(SkillCandidateError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "candidate log is not a regular file: {}",
                        self.path.display()
                    ),
                )));
            }
            Ok(md) if md.len() > MAX_CANDIDATE_FILE_BYTES => {
                return Err(SkillCandidateError::TooLarge(format!(
                    "candidate log {} bytes exceeds {MAX_CANDIDATE_FILE_BYTES} cap",
                    md.len()
                )));
            }
            _ => {}
        }
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: SkillCandidateEvent = serde_json::from_str(&line)?;
            events.push(event);
        }
        Ok(events)
    }

    /// Append one event as a single JSON line (`O_APPEND`).
    fn append(&self, event: &SkillCandidateEvent) -> Result<(), SkillCandidateError> {
        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store() -> (tempfile::TempDir, SkillCandidateStore) {
        let dir = tempdir().expect("tempdir");
        let store = SkillCandidateStore::in_dir(dir.path());
        (dir, store)
    }

    // T21-a: candidate_id is the lowercase-hex sha256 of the canonical key —
    // deterministic + process-stable.
    #[test]
    fn candidate_id_is_deterministic_sha256() {
        let a = SkillCandidate::new("summarize-pr", "Summarize a pull request diff");
        let b = SkillCandidate::new("summarize-pr", "Summarize a pull request diff");
        assert_eq!(a.candidate_id, b.candidate_id, "same input ⇒ same id");
        // lowercase-hex sha256 == 64 hex chars.
        assert_eq!(a.candidate_id.len(), 64);
        assert!(a.candidate_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(a.candidate_id.chars().all(|c| !c.is_ascii_uppercase()));
        // Different content ⇒ different id.
        let c = SkillCandidate::new("summarize-pr", "Different description");
        assert_ne!(a.candidate_id, c.candidate_id);
        // Pinned vector (stability across runs): length-prefixed sha256 of
        // (name="x", description="y").
        assert_eq!(compute_candidate_id("x", "y"), {
            let mut h = Sha256::new();
            h.update((1u64).to_le_bytes());
            h.update(b"x");
            h.update((1u64).to_le_bytes());
            h.update(b"y");
            let d = h.finalize();
            d.iter().map(|b| format!("{b:02x}")).collect::<String>()
        });
    }

    // T21-a/W3: the length-prefixed key is INJECTIVE — an embedded newline in
    // `name` can no longer re-segment into a different (name, description) pair
    // with the same id. With the old `name \n description` key,
    // ("a\nb","c") and ("a","b\nc") both hashed `a\nb\nc` → collision.
    #[test]
    fn candidate_id_no_newline_separator_collision() {
        assert_ne!(
            compute_candidate_id("a\nb", "c"),
            compute_candidate_id("a", "b\nc"),
            "length-prefix must make the (name, description) key injective"
        );
        // Empty-field disambiguation also holds.
        assert_ne!(
            compute_candidate_id("ab", ""),
            compute_candidate_id("a", "b")
        );
    }

    // W1: oversize name/description is rejected (not silently truncated, which
    // would change the candidate_id) and nothing is written.
    #[test]
    fn append_generated_rejects_oversize_fields() {
        let (_d, store) = store();
        let big_name = "x".repeat(MAX_CANDIDATE_NAME_BYTES + 1);
        let cand = SkillCandidate::new(big_name, "desc");
        let err = store.append_generated(&cand).unwrap_err();
        assert!(matches!(err, SkillCandidateError::TooLarge(_)));
        assert_eq!(
            store.event_count().unwrap(),
            0,
            "no line written on TooLarge"
        );

        let big_desc = "y".repeat(MAX_CANDIDATE_DESCRIPTION_BYTES + 1);
        let cand2 = SkillCandidate::new("ok-name", big_desc);
        assert!(matches!(
            store.append_generated(&cand2).unwrap_err(),
            SkillCandidateError::TooLarge(_)
        ));
        assert_eq!(store.event_count().unwrap(), 0);

        // At the cap boundary it is accepted.
        let ok = SkillCandidate::new("z".repeat(MAX_CANDIDATE_NAME_BYTES), "d");
        assert!(store.append_generated(&ok).unwrap());

        // W1 (adversarial r4): an oversize `candidate_id` is rejected too — the
        // struct field is public, so a non-canonical caller could bypass `new`'s
        // bounded sha256 and blow the serialized-line bound.
        let big_id = SkillCandidate {
            candidate_id: "a".repeat(MAX_CANDIDATE_ID_BYTES + 1),
            name: "ok-name".into(),
            description: "d".into(),
        };
        assert!(matches!(
            store.append_generated(&big_id).unwrap_err(),
            SkillCandidateError::TooLarge(_)
        ));
    }

    // T21-b: append_generated ⇒ list_pending returns it as pending.
    #[test]
    fn generated_then_pending() {
        let (_d, store) = store();
        let cand = SkillCandidate::new("skill-a", "desc a");
        assert!(store.append_generated(&cand).expect("append"));
        let pending = store.list_pending().expect("list");
        assert_eq!(pending, vec![cand.clone()]);
        assert_eq!(store.event_count().unwrap(), 1);
        // Idempotent re-generate ⇒ no second line.
        assert!(!store.append_generated(&cand).expect("re-append"));
        assert_eq!(store.event_count().unwrap(), 1);
    }

    // T21-c: resolve(Accept) appends a terminal `resolved` line (generated
    // retained) and drops the candidate from pending.
    #[test]
    fn resolve_accept_appends_terminal_and_drops_pending() {
        let (_d, store) = store();
        let cand = SkillCandidate::new("skill-b", "desc b");
        store.append_generated(&cand).unwrap();
        store
            .resolve(&cand.candidate_id, Resolution::Accept)
            .unwrap();
        assert!(store.list_pending().unwrap().is_empty());
        // Append-only: BOTH the generated AND the resolved line are retained.
        assert_eq!(store.event_count().unwrap(), 2);
        let events = store.read_events().unwrap();
        assert!(matches!(events[0], SkillCandidateEvent::Generated { .. }));
        assert!(matches!(events[1], SkillCandidateEvent::Resolved { .. }));
    }

    // T21-d: resolve(Dismiss) appends `dismissed`; not pending.
    #[test]
    fn resolve_dismiss_appends_terminal_and_drops_pending() {
        let (_d, store) = store();
        let cand = SkillCandidate::new("skill-c", "desc c");
        store.append_generated(&cand).unwrap();
        store
            .resolve(&cand.candidate_id, Resolution::Dismiss)
            .unwrap();
        assert!(store.list_pending().unwrap().is_empty());
        let events = store.read_events().unwrap();
        assert!(matches!(events[1], SkillCandidateEvent::Dismissed { .. }));
    }

    // T21-e: unknown id ⇒ NotFound + NOTHING written; double-resolve ⇒
    // AlreadyResolved + NOTHING written.
    #[test]
    fn resolve_unknown_and_double_resolve_are_guarded() {
        let (_d, store) = store();
        // Unknown id, empty log.
        let err = store.resolve("deadbeef", Resolution::Accept).unwrap_err();
        assert!(matches!(err, SkillCandidateError::NotFound(_)));
        assert_eq!(
            store.event_count().unwrap(),
            0,
            "no line written on NotFound"
        );

        let cand = SkillCandidate::new("skill-d", "desc d");
        store.append_generated(&cand).unwrap();
        store
            .resolve(&cand.candidate_id, Resolution::Accept)
            .unwrap();
        let count_after_first = store.event_count().unwrap();
        // Second terminal transition rejected; append-only invariant holds.
        let err = store
            .resolve(&cand.candidate_id, Resolution::Dismiss)
            .unwrap_err();
        assert!(matches!(err, SkillCandidateError::AlreadyResolved(_)));
        assert_eq!(
            store.event_count().unwrap(),
            count_after_first,
            "no line written on AlreadyResolved"
        );
    }

    // T21-f: the JSONL strictly grows; state is reconstructed purely by folding
    // events (a fresh store over the same path reads identical state).
    #[test]
    fn append_only_line_growth_and_fold_reconstruction() {
        let (_d, store) = store();
        let c1 = SkillCandidate::new("s1", "d1");
        let c2 = SkillCandidate::new("s2", "d2");
        store.append_generated(&c1).unwrap();
        assert_eq!(store.event_count().unwrap(), 1);
        store.append_generated(&c2).unwrap();
        assert_eq!(store.event_count().unwrap(), 2);
        store.resolve(&c1.candidate_id, Resolution::Accept).unwrap();
        assert_eq!(store.event_count().unwrap(), 3);
        // Generation order preserved; c1 resolved ⇒ only c2 pending.
        assert_eq!(store.list_pending().unwrap(), vec![c2.clone()]);
        // Fold reconstruction: a brand-new store over the same path agrees.
        let reopened = SkillCandidateStore::new(store.path());
        assert_eq!(reopened.list_pending().unwrap(), vec![c2]);
        assert_eq!(reopened.event_count().unwrap(), 3);
    }

    // slice wave6-laneB: `read_events` rejects a NON-REGULAR leaf (dir / symlink /
    // FIFO) BEFORE `File::open` — the guard that prevents a FIFO at the
    // (now guest-reachable) candidate path from blocking `open()` forever. A
    // directory + a symlink exercise the same `!is_file()` branch (a FIFO is the
    // same class; no `mkfifo` dep needed) and the call returns Err quickly (never hangs).
    #[cfg(unix)]
    #[test]
    fn read_events_rejects_non_regular_leaf() {
        let dir = tempdir().unwrap();
        // A directory at the candidate path → non-regular leaf → rejected.
        let as_dir = dir.path().join("candidates_dir");
        std::fs::create_dir(&as_dir).unwrap();
        assert!(matches!(
            SkillCandidateStore::new(&as_dir).read_events(),
            Err(SkillCandidateError::Io(_))
        ));
        // A symlink leaf (symlink_metadata does NOT follow it) → rejected.
        let target = dir.path().join("real.jsonl");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            SkillCandidateStore::new(&link).read_events(),
            Err(SkillCandidateError::Io(_))
        ));
        // A real regular file still reads cleanly (the guard only rejects non-regular).
        let cand = SkillCandidate::new("s", "d");
        let store = SkillCandidateStore::new(dir.path().join("ok.jsonl"));
        store.append_generated(&cand).unwrap();
        assert_eq!(store.read_events().unwrap().len(), 1);
    }

    // slice wave6-laneB adversarial r1/r5: compaction drops the heavy `Generated`
    // line of a resolved/dismissed candidate (bounding the append-only history) while
    // preserving the pending set AND an id-only TERMINAL TOMBSTONE that keeps
    // dismiss/accept FINALITY (regeneration stays suppressed) — W-15-2.
    #[test]
    fn compact_drops_resolved_generated_keeps_tombstone_and_pending() {
        let (_d, store) = store();
        let c1 = SkillCandidate::new("s1", "d1");
        let c2 = SkillCandidate::new("s2", "d2");
        let c3 = SkillCandidate::new("s3", "d3");
        store.append_generated(&c1).unwrap();
        store.append_generated(&c2).unwrap();
        store.append_generated(&c3).unwrap();
        store.resolve(&c1.candidate_id, Resolution::Accept).unwrap();
        assert_eq!(store.event_count().unwrap(), 4); // 3 generated + 1 resolved

        let events = store.read_events().unwrap();
        store.compact_to_pending(&events).unwrap();
        // c1's heavy Generated line is dropped but its id-only terminal tombstone is
        // RETAINED: c2/c3 Generated + c1 tombstone = 3 events.
        assert_eq!(store.event_count().unwrap(), 3);
        let names: Vec<String> = store
            .list_pending()
            .unwrap()
            .iter()
            .map(|c| c.name.clone())
            .collect();
        // The tombstone is invisible to list_pending (no Generated → never pending).
        assert_eq!(names, vec!["s2".to_string(), "s3".to_string()]);
        // The compacted candidate is no longer resolvable (no Generated → NotFound),
        // same as before — both NotFound and the prior AlreadyResolved are a consumer
        // not-found, so no observable regression.
        assert!(matches!(
            store.resolve(&c1.candidate_id, Resolution::Dismiss),
            Err(SkillCandidateError::NotFound(_))
        ));
        // FINALITY (W-15-2): re-generating the SAME candidate id after compaction is
        // still SUPPRESSED by the retained tombstone — a dismissed/accepted candidate
        // does NOT resurrect, and the pending set is unchanged.
        assert!(
            !store.append_generated(&c1).unwrap(),
            "the terminal tombstone must keep regeneration suppressed (no resurrection)"
        );
        assert_eq!(
            store.list_pending().unwrap().len(),
            2,
            "no resurrection into pending"
        );
        // A genuinely NEW candidate still appends from the compacted base.
        let c4 = SkillCandidate::new("s4", "d4");
        assert!(store.append_generated(&c4).unwrap());
    }

    // slice wave6-laneB adversarial r5 (W-15-2): the terminal tombstones are
    // themselves bounded (drop oldest beyond MAX_TERMINAL_TOMBSTONES), so finality is
    // permanent for the most-recent N terminal candidates and the file stays bounded —
    // the very oldest terminal id becomes regenerable again after eviction.
    #[test]
    fn compact_bounds_terminal_tombstones_dropping_oldest() {
        let (_d, store) = store();
        let n = MAX_TERMINAL_TOMBSTONES + 3;
        // Synthesize > cap distinct resolved (Generated+Resolved) pairs in memory.
        let ids: Vec<String> = (0..n)
            .map(|i| SkillCandidate::new(format!("s{i}"), "d").candidate_id)
            .collect();
        let mut events: Vec<SkillCandidateEvent> = Vec::with_capacity(2 * n);
        for (i, id) in ids.iter().enumerate() {
            events.push(SkillCandidateEvent::Generated {
                candidate_id: id.clone(),
                name: format!("s{i}"),
                description: "d".to_string(),
            });
            events.push(SkillCandidateEvent::Resolved {
                candidate_id: id.clone(),
            });
        }
        store.compact_to_pending(&events).unwrap();
        // Only the newest MAX_TERMINAL_TOMBSTONES tombstones survive (all events are
        // terminal, so the compacted file is exactly the tombstone block).
        assert_eq!(store.event_count().unwrap(), MAX_TERMINAL_TOMBSTONES);
        // The oldest terminal id was evicted → its tombstone is gone → it can be
        // regenerated again (finality is bounded, not infinite).
        let oldest = SkillCandidate {
            candidate_id: ids[0].clone(),
            name: "s0".to_string(),
            description: "d".to_string(),
        };
        assert!(
            store.append_generated(&oldest).unwrap(),
            "the evicted-oldest terminal id is regenerable (its tombstone was dropped)"
        );
        // A still-retained (newest) terminal id stays suppressed.
        let newest = SkillCandidate {
            candidate_id: ids[n - 1].clone(),
            name: format!("s{}", n - 1),
            description: "d".to_string(),
        };
        assert!(
            !store.append_generated(&newest).unwrap(),
            "a retained terminal id is still suppressed"
        );
    }

    // slice wave6-laneB adversarial r1: compaction caps the PENDING set to
    // MAX_PENDING_CANDIDATES, dropping the OLDEST — so an unbounded stream of
    // never-resolved candidates cannot grow the file without bound.
    #[test]
    fn compact_caps_pending_dropping_oldest() {
        let (_d, store) = store();
        let n = MAX_PENDING_CANDIDATES + 5;
        // Synthesize > cap distinct pending Generated events (no per-append I/O).
        let events: Vec<SkillCandidateEvent> = (0..n)
            .map(|i| {
                let c = SkillCandidate::new(format!("s{i}"), "d");
                SkillCandidateEvent::Generated {
                    candidate_id: c.candidate_id,
                    name: c.name,
                    description: c.description,
                }
            })
            .collect();
        store.compact_to_pending(&events).unwrap();
        let pending = store.list_pending().unwrap();
        assert_eq!(
            pending.len(),
            MAX_PENDING_CANDIDATES,
            "capped to the retention max"
        );
        // The newest is retained; the oldest (s0) was dropped.
        assert!(pending.iter().any(|c| c.name == format!("s{}", n - 1)));
        assert!(!pending.iter().any(|c| c.name == "s0"));
    }

    // slice wave6-laneB adversarial r2: the compaction trigger consts PROVE the log
    // can never reach the read cap (so read_events/compaction never fail-close on a
    // store this code manages). Closes the "byte cap out-races the event trigger" gap.
    #[test]
    fn should_compact_invariants() {
        // SERIALIZED worst-case bytes for ONE `Generated` JSONL line. The field
        // caps are on RAW bytes, but the file stores the JSON-ESCAPED form, where a
        // control byte (0x00–0x1f) expands to `\u00XX` (6×). So the worst case is
        // 6 × (candidate_id + name + description) + the fixed JSON keys/framing/newline.
        // (Real producer lines — a short ASCII fixed template — are an order of
        // magnitude smaller.) ALL THREE bounded fields are included (adversarial r4).
        const MAX_LINE: u64 = 6
            * (MAX_CANDIDATE_ID_BYTES + MAX_CANDIDATE_NAME_BYTES + MAX_CANDIDATE_DESCRIPTION_BYTES)
                as u64
            + 512;
        // (a) The file can reach at most COMPACTION_TRIGGER_BYTES + one max-size line
        //     before the byte trigger fires on the next append — and that stays under
        //     the read cap, so `read_events` (and thus compaction) never fail-closes.
        assert!(
            COMPACTION_TRIGGER_BYTES + MAX_LINE <= MAX_CANDIDATE_FILE_BYTES,
            "trigger {COMPACTION_TRIGGER_BYTES} + line {MAX_LINE} must stay <= read cap {MAX_CANDIDATE_FILE_BYTES}"
        );
        // A retained TERMINAL TOMBSTONE is an id-only Resolved/Dismissed JSONL line:
        // 6× id (worst-case JSON escape) + the fixed {"type":"…","candidate_id":""}
        // framing + newline. No name/description (those live only on Generated lines).
        const TOMBSTONE_MAX_LINE: u64 = 6 * MAX_CANDIDATE_ID_BYTES as u64 + 128;
        // (b) The MAX compacted file (pending cap × max line + tombstone cap × tombstone
        //     line) is below the byte trigger, so compaction actually shrinks the file
        //     (no immediate re-fire) even with the W-15-2 finality tombstones retained.
        let max_compacted = MAX_PENDING_CANDIDATES as u64 * MAX_LINE
            + MAX_TERMINAL_TOMBSTONES as u64 * TOMBSTONE_MAX_LINE;
        assert!(
            max_compacted < COMPACTION_TRIGGER_BYTES,
            "max compacted {max_compacted} must be < trigger {COMPACTION_TRIGGER_BYTES}"
        );
        // (c) The MAX compacted EVENT COUNT (pending + tombstones) is below the count
        //     trigger too, so a count-triggered compaction also shrinks below threshold
        //     (no immediate re-fire loop).
        assert!(
            MAX_PENDING_CANDIDATES + MAX_TERMINAL_TOMBSTONES < MAX_CANDIDATE_EVENTS,
            "max compacted events {} must be < count trigger {MAX_CANDIDATE_EVENTS}",
            MAX_PENDING_CANDIDATES + MAX_TERMINAL_TOMBSTONES
        );
        // should_compact fires on either trigger and not below both.
        assert!(SkillCandidateStore::should_compact(
            COMPACTION_TRIGGER_BYTES,
            0
        ));
        assert!(SkillCandidateStore::should_compact(0, MAX_CANDIDATE_EVENTS));
        assert!(!SkillCandidateStore::should_compact(0, 0));
        assert!(!SkillCandidateStore::should_compact(
            COMPACTION_TRIGGER_BYTES - 1,
            MAX_CANDIDATE_EVENTS - 1
        ));
    }
}
