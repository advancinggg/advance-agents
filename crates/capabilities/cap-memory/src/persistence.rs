//! `KnowledgeJsonlStore` — on-disk per-agent `knowledge.jsonl` persistence for
//! [`crate::store::MemoryStore`] (slice m011-memory-persist, AC-40).
//!
//! This is the cap-memory half of the §3.6 "Persistent `knowledge.jsonl` on-disk
//! write" deferral: the store-level durability backend behind the existing
//! `MemoryStore` seam, with `insert`/`recall`/`recall_at` signatures unchanged.
//!
//! ## Layout
//! Per-agent file at `<root>/<agent-slug>/knowledge.jsonl`, one
//! [`MemoryEntry`] JSON object per line. The dir name is a filesystem-safe
//! slug of the agent id (non-`[A-Za-z0-9._-]` chars → `_`) plus an FNV-1a-32
//! suffix so two distinct ids that sanitize to the same prefix do not collide;
//! the slug is NOT reversed on load — entries are bucketed by their own
//! `entry.agent_id` field (the true id), so the slug only needs to be unique.
//!
//! ## Write model (snapshot-as-jsonl with append fast-path)
//! - [`append`](KnowledgeJsonlStore::append) / [`append_line`](KnowledgeJsonlStore::append_line):
//!   the hot path — open `O_APPEND` (mode `0600`), write one `serde_json` line,
//!   `fsync`. O(1). Used for a pure insert of a new entry. `append_line` takes a
//!   pre-serialized line so the store can serialize exactly once (size-check +
//!   write share the same string).
//! - [`rewrite`](KnowledgeJsonlStore::rewrite) / [`rewrite_lines`](KnowledgeJsonlStore::rewrite_lines):
//!   atomic temp+`fsync`+`rename` of the whole per-agent file (mirrors
//!   `cap-secrets::file_storage::atomic_write`). Used when an existing entry
//!   mutates (forget / supersede / status / cluster / rollback). `rewrite_lines`
//!   takes pre-serialized lines (single-serialize from the store's compaction).
//!
//! ## Retention-bounded streaming hydration (slice `dev-task-mem-retention`)
//! [`open`](KnowledgeJsonlStore::open) reads each per-agent file as a **bounded
//! line stream** (a `BufReader` + [`read_line_capped`], peak per-line RAM ≤
//! [`MAX_LINE_BYTES`]) instead of loading the whole file into a `String`. While
//! hydrating it enforces an **inactive-specific retention window**: all `is_active`
//! entries are kept (in file order), but the inactive (forgotten/superseded) tail
//! is bounded to [`DEFAULT_MAX_INACTIVE_PER_AGENT`] entries AND
//! [`DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT`] bytes — the oldest inactive entries are
//! dropped first. The two seq-tagged streams are merged back by sequence so the
//! returned bucket preserves exact file order. A line that fails to parse is a loud
//! error UNLESS it is a torn (unterminated) final line, mirroring
//! `FileSecretStorage::open`. A torn file is healed (mandatory rewrite, fail-loud on
//! failure); a file that was only compacted-on-hydration is rewritten best-effort
//! (a transient rewrite failure leaves the disk file larger but the in-memory set
//! bounded — hydration is a deterministic function of the file, so a fresh reopen
//! reproduces the in-memory set; the next mutation's rewrite reconciles the size).
//!
//! ## Out of scope (deferred)
//! Production `.agent/memory/` root binding incl. nested `archive/{sub_id}/`
//! (a recursive scan the ③-wiring slice must add — see MODULE-011 §3.6), and
//! git-tracked rollback HISTORY (the L6 journal + `_knowledge_cursor.yaml` stay
//! in-process). Single-process posture: no cross-process file lock (matches the
//! `FileSecretStorage` single-runtime posture).

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, Write as _};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::knowledge::MemoryEntry;

/// Per-agent file name under the agent slug dir.
pub const KNOWLEDGE_JSONL_FILENAME: &str = "knowledge.jsonl";

/// The reserved second-level directory under a memory root that holds archived
/// sub-agent memory at `<root>/archive/<sub_id>/knowledge.jsonl` (M011-AC-29).
/// `KnowledgeJsonlStore::open` recurses exactly one extra level into this dir
/// (and ONLY this dir); every other second-level dir keeps the single-level
/// layout. A real agent slug is never literally `archive` — `slug()` appends an
/// FNV-1a suffix — so the name is unambiguous. The archive subdir name is the
/// (filesystem-safe, charset-validated) sub agent id written verbatim by
/// `cap-lifecycle`'s `FsMemoryArchiver`; buckets still key on each entry's own
/// `agent_id`, so the dir name is cosmetic.
pub const ARCHIVE_DIR_NAME: &str = "archive";

/// Per-line read cap for [`KnowledgeJsonlStore::open`] (16 MiB). Bounds peak
/// per-line RAM during the streaming hydration. It is set ABOVE the store's
/// per-entry write cap (`store::MAX_ENTRY_BYTES` = 8 MiB), so NO line written by
/// cap-memory can ever trip it — a committed line longer than this is external
/// tampering/corruption and fails loud (`PersistError::Corrupt`). A torn append
/// is always shorter than a full entry, so it never trips the cap either.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Inactive-tail entry retention window (slice `dev-task-mem-retention`). The
/// forgotten/superseded tail kept per agent is bounded to this many entries;
/// active entries are NOT counted toward, nor bounded by, this cap. Independent
/// of `store::DEFAULT_MAX_ACTIVE_PER_AGENT`. Used by both the store's compaction
/// (`store::MemoryStore`) and this module's hydration so the two paths drop the
/// same inactive set (the determinism precondition for cache==disk).
pub const DEFAULT_MAX_INACTIVE_PER_AGENT: usize = 4096;

/// Inactive-tail byte retention window (32 MiB). The forgotten/superseded tail
/// kept per agent is bounded to this many bytes (exact serialized-line length,
/// including the trailing `\n`); active entries are never dropped to satisfy it.
pub const DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT: usize = 32 * 1024 * 1024;

/// Error surface for on-disk persistence. `Corrupt` is reserved for an
/// unparseable line on `open` (fail-loud); `Io` covers every fs/serialize
/// failure on a write path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistError {
    Io(String),
    Corrupt(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistError::Io(s) => write!(f, "knowledge.jsonl io error: {s}"),
            PersistError::Corrupt(s) => write!(f, "knowledge.jsonl corrupt: {s}"),
        }
    }
}

impl std::error::Error for PersistError {}

/// On-disk per-agent `knowledge.jsonl` backend rooted at a directory.
#[derive(Debug)]
pub struct KnowledgeJsonlStore {
    root: PathBuf,
    /// Agents whose on-disk file was compacted DURING hydration but whose
    /// best-effort migration rewrite then FAILED (e.g. a transient disk fault) —
    /// so the on-disk file is still larger than the bounded in-memory set. The
    /// store reconciles such a file by doing a full rewrite on the agent's next
    /// mutation (see `MemoryStore::insert`), re-establishing the on-disk bound
    /// without forcing a fail-loud boot. `Mutex` (not the more natural set of an
    /// immutable construction value) so `MemoryStore::insert` can clear an entry
    /// after a successful reconcile.
    pending_rewrite: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl KnowledgeJsonlStore {
    /// `true` iff `agent_id`'s on-disk file is pending a reconcile rewrite (its
    /// best-effort migration rewrite failed at open). Consumed by
    /// `MemoryStore::insert` to upgrade the next append into a full rewrite.
    pub fn needs_rewrite(&self, agent_id: &str) -> bool {
        self.pending_rewrite
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(agent_id)
    }

    /// Clear `agent_id`'s pending-rewrite flag after a successful reconcile.
    pub fn clear_pending(&self, agent_id: &str) {
        self.pending_rewrite
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(agent_id);
    }

    /// Open (creating `root` if absent) and load every per-agent
    /// `knowledge.jsonl` under it into per-agent buckets keyed by the entries'
    /// own `agent_id`. Fails loud on an unparseable line.
    pub fn open(
        root: impl Into<PathBuf>,
    ) -> Result<(Self, HashMap<String, Vec<MemoryEntry>>), PersistError> {
        let root = root.into();
        fs::create_dir_all(&root)
            .map_err(|e| PersistError::Io(format!("create root {}: {e}", root.display())))?;
        let mut buckets: HashMap<String, Vec<MemoryEntry>> = HashMap::new();
        let mut pending_rewrite: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        let read_dir = fs::read_dir(&root)
            .map_err(|e| PersistError::Io(format!("read_dir {}: {e}", root.display())))?;
        // Collect candidate per-agent knowledge.jsonl files: level-1 agent-slug
        // dirs (the long-standing single-level layout) PLUS the level-2 archived
        // sub-agent layout `<root>/archive/<sub_id>/knowledge.jsonl` (M011-AC-29).
        // Only the literal `archive/` dir is recursed one extra level; every other
        // second-level dir keeps the single-level contract.
        let mut files: Vec<PathBuf> = Vec::new();
        for dirent in read_dir {
            let dirent =
                dirent.map_err(|e| PersistError::Io(format!("dir entry under root: {e}")))?;
            let path = dirent.path();
            // AW-Info2 hardening: use symlink_metadata (does NOT follow links) so
            // a planted directory symlink under the root is skipped — otherwise
            // the torn-file HEAL below would write THROUGH it to a target outside
            // the root. (Defense-in-depth atop the owner-only 0700 root trust
            // boundary; the deferred ③ wiring binds the real `.agent/memory/`
            // root.) The per-agent knowledge.jsonl is likewise required to be a
            // regular file, not a symlink.
            match fs::symlink_metadata(&path) {
                Ok(md) if md.is_dir() => {}
                _ => continue, // symlink, file, or unreadable → not a real agent dir
            }
            if path.file_name().and_then(|s| s.to_str()) == Some(ARCHIVE_DIR_NAME) {
                // Level-2 archived sub-agent memory (M011-AC-29): recurse exactly
                // one extra level into `archive/<sub_id>/knowledge.jsonl`. Same
                // symlink hardening as level-1 (skip symlinked dirs/files so the
                // torn-file HEAL never writes THROUGH a planted link).
                let archive_rd = match fs::read_dir(&path) {
                    Ok(rd) => rd,
                    Err(_) => continue, // unreadable archive dir → skip (non-fatal)
                };
                for sub in archive_rd {
                    let sub =
                        sub.map_err(|e| PersistError::Io(format!("dir entry under archive: {e}")))?;
                    let sub_path = sub.path();
                    match fs::symlink_metadata(&sub_path) {
                        Ok(md) if md.is_dir() => {}
                        _ => continue, // symlink/file/unreadable → not a real sub_id dir
                    }
                    let sub_file = sub_path.join(KNOWLEDGE_JSONL_FILENAME);
                    match fs::symlink_metadata(&sub_file) {
                        Ok(md) if md.is_file() => {}
                        _ => continue,
                    }
                    files.push(sub_file);
                }
                continue;
            }
            let file = path.join(KNOWLEDGE_JSONL_FILENAME);
            match fs::symlink_metadata(&file) {
                Ok(md) if md.is_file() => {}
                _ => continue, // absent, symlink, or non-regular → skip
            }
            files.push(file);
        }
        for file in files {
            // Streaming, retention-bounded hydration (slice dev-task-mem-retention).
            // Read the file line-by-line (bounded peak RAM ≤ MAX_LINE_BYTES per
            // line, vs the prior whole-file `read_to_string`). Keep ALL active
            // entries; bound the inactive (forgotten/superseded) tail to the
            // retention window by dropping the OLDEST inactive first. Both streams
            // are seq-tagged and merged back so the bucket preserves file order.
            let f = fs::File::open(&file)
                .map_err(|e| PersistError::Io(format!("open read {}: {e}", file.display())))?;
            let mut reader = std::io::BufReader::new(f);
            let mut line_buf: Vec<u8> = Vec::new();
            let mut seq: u64 = 0;
            let mut active: VecDeque<(u64, MemoryEntry)> = VecDeque::new();
            // (seq, entry, on-disk byte cost incl. trailing newline)
            let mut inactive: VecDeque<(u64, MemoryEntry, usize)> = VecDeque::new();
            let mut inactive_bytes: usize = 0;
            let mut compacted = false; // dropped inactive during hydration
            let mut torn = false; // unterminated unparseable final line (crash residue)
            let mut line_no: usize = 0;

            loop {
                // read_line_capped returns Some(had_newline) for a line, None at
                // clean EOF, Err on a line exceeding MAX_LINE_BYTES. `had_newline`
                // is false ONLY for an unterminated FINAL line (the torn-append
                // signature) — replicating the prior last-line/no-newline logic
                // without buffering the whole file.
                let had_newline = match read_line_capped(&mut reader, &mut line_buf, MAX_LINE_BYTES)
                {
                    Ok(None) => break, // clean EOF
                    Ok(Some(nl)) => nl,
                    Err(e) => {
                        return Err(PersistError::Corrupt(format!(
                            "{}:{}: {e}",
                            file.display(),
                            line_no + 1
                        )))
                    }
                };
                line_no += 1;
                // Strip the trailing '\n' (if present) for parsing; keep the raw
                // byte length (+1 for the newline the rewrite re-adds) as the
                // on-disk byte cost used for the inactive byte budget.
                let raw = if had_newline {
                    &line_buf[..line_buf.len().saturating_sub(1)]
                } else {
                    &line_buf[..]
                };
                // Decode as UTF-8. A non-UTF-8 line that is the unterminated final
                // line is torn crash residue (tolerate + heal); a committed
                // (newline-terminated) non-UTF-8 line is corruption (fail loud).
                let line = match std::str::from_utf8(raw) {
                    Ok(s) => s,
                    Err(_) => {
                        if !had_newline {
                            torn = true;
                            continue;
                        }
                        return Err(PersistError::Corrupt(format!(
                            "{}:{}: invalid utf-8",
                            file.display(),
                            line_no
                        )));
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<MemoryEntry>(line) {
                    Ok(entry) => {
                        // AW2: reject a tampered/partially-mutated-but-valid-JSON
                        // line whose state violates the MemoryEntry status↔active
                        // invariants (fail loud, never silently drop).
                        entry.validate_invariants().map_err(|e| {
                            PersistError::Corrupt(format!(
                                "{}:{}: invariant violation: {e}",
                                file.display(),
                                line_no
                            ))
                        })?;
                        if entry.is_active {
                            active.push_back((seq, entry));
                        } else {
                            // CANONICAL serialized byte cost (not the raw on-disk
                            // line length): the store's `compact_inactive` measures
                            // the byte budget the same way (re-serialized length), so
                            // hydration and compaction drop the SAME inactive set even
                            // for a non-canonical on-disk file (CRLF / pretty-printed
                            // / externally-written) — keeping `memory == hydrate(disk)`
                            // byte-exact and avoiding redundant boot-rewrite churn.
                            let line_bytes = serde_json::to_string(&entry)
                                .map(|s| s.len() + 1)
                                .unwrap_or(raw.len() + 1);
                            inactive_bytes += line_bytes;
                            inactive.push_back((seq, entry, line_bytes));
                        }
                        seq += 1;
                        // Bound the inactive tail (entries AND bytes); drop oldest
                        // inactive (front). Active entries are never touched.
                        while inactive.len() > DEFAULT_MAX_INACTIVE_PER_AGENT
                            || inactive_bytes > DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT
                        {
                            match inactive.pop_front() {
                                Some((_, _, dropped)) => {
                                    inactive_bytes -= dropped;
                                    compacted = true;
                                }
                                None => break,
                            }
                        }
                    }
                    Err(e) => {
                        // CW4: an unterminated unparseable FINAL line is torn crash
                        // residue (tolerate + heal). A committed (newline-terminated)
                        // unparseable line is genuine corruption → fail loud.
                        if !had_newline {
                            torn = true;
                            continue;
                        }
                        return Err(PersistError::Corrupt(format!(
                            "{}:{}: {e}",
                            file.display(),
                            line_no
                        )));
                    }
                }
            }

            // Merge the two seq-ordered streams back into exact file order.
            let mut file_entries: Vec<MemoryEntry> =
                Vec::with_capacity(active.len() + inactive.len());
            let mut ai = active.into_iter().peekable();
            let mut ii = inactive.into_iter().peekable();
            loop {
                let take_active = match (ai.peek(), ii.peek()) {
                    (Some((sa, _)), Some((si, _, _))) => sa < si,
                    (Some(_), None) => true,
                    (None, Some(_)) => false,
                    (None, None) => break,
                };
                if take_active {
                    file_entries.push(ai.next().expect("peeked active").1);
                } else {
                    file_entries.push(ii.next().expect("peeked inactive").1);
                }
            }

            // Rewrite-on-open policy:
            //  - torn  → MANDATORY heal (drop the torn residue durably). A torn
            //    file left un-healed would let a later `append` commit corruption
            //    on the NEXT restart, so propagate Err on heal failure (fail-loud,
            //    UNCHANGED from the prior behavior).
            //  - compacted-only → BEST-EFFORT migration rewrite. On failure, keep
            //    the RAM-bounded buckets and continue boot (no new boot-availability
            //    regression vs the prior "bloated-but-valid file opens fine"); the
            //    disk stays larger and self-corrects on the next mutation/boot.
            //    Safe because hydration is deterministic and the inactive window is
            //    sized on inactive entries only, so `memory == hydrate(disk)` holds.
            //    To bound the on-disk size even if the agent only ever appends
            //    (`remember`-only, which never triggers a rewrite), the agent is
            //    flagged `pending_rewrite` so its NEXT insert upgrades to a full
            //    reconcile rewrite (closes the adversarial-round "remember-only never
            //    re-bounds the disk after a failed best-effort rewrite" gap).
            if torn {
                rewrite_file_atomic(&file, &file_entries)?;
            } else if compacted && rewrite_file_atomic(&file, &file_entries).is_err() {
                for e in &file_entries {
                    pending_rewrite.insert(e.agent_id.clone());
                }
            }
            for entry in file_entries {
                buckets
                    .entry(entry.agent_id.clone())
                    .or_default()
                    .push(entry);
            }
        }
        Ok((
            Self {
                root,
                pending_rewrite: std::sync::Mutex::new(pending_rewrite),
            },
            buckets,
        ))
    }

    fn agent_dir(&self, agent_id: &str) -> PathBuf {
        self.root.join(slug(agent_id))
    }

    fn agent_file(&self, agent_id: &str) -> PathBuf {
        self.agent_dir(agent_id).join(KNOWLEDGE_JSONL_FILENAME)
    }

    /// Ensure the per-agent dir exists (mode `0700` on unix — owner-only,
    /// matching the `.advance/` trust-boundary posture).
    fn ensure_agent_dir(&self, agent_id: &str) -> Result<PathBuf, PersistError> {
        let dir = self.agent_dir(agent_id);
        // Hardening (satB-postproc adversarial r15 / Codex W1): refuse a planted
        // symlinked agent dir on the WRITE path. `open`-time hydration already
        // skips symlinked dirs, but `create_dir_all` would otherwise FOLLOW a
        // symlink-to-outside and write knowledge.jsonl outside the memory root.
        // Non-guest-reachable (0700 tree); defense-in-depth + write/read parity.
        if let Ok(md) = fs::symlink_metadata(&dir) {
            if md.file_type().is_symlink() {
                return Err(PersistError::Io(format!(
                    "refusing symlinked agent dir {}",
                    dir.display()
                )));
            }
        }
        fs::create_dir_all(&dir)
            .map_err(|e| PersistError::Io(format!("create agent dir {}: {e}", dir.display())))?;
        #[cfg(unix)]
        {
            // Re-assert 0700 (create_dir_all honours umask, which may be looser).
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| PersistError::Io(format!("chmod agent dir {}: {e}", dir.display())))?;
        }
        Ok(dir)
    }

    /// Atomic append of one entry's JSON line to the agent's `knowledge.jsonl`
    /// (the insert hot path). Creates the file mode `0600` on first write,
    /// `fsync`s after the write.
    pub fn append(&self, agent_id: &str, entry: &MemoryEntry) -> Result<(), PersistError> {
        let line = serde_json::to_string(entry)
            .map_err(|e| PersistError::Io(format!("serialize entry {}: {e}", entry.id)))?;
        self.append_line(agent_id, &line)
    }

    /// Atomic append of a PRE-SERIALIZED JSON line (without the trailing newline,
    /// which this adds) to the agent's `knowledge.jsonl`. Lets the store serialize
    /// each entry exactly once (the per-entry size check + this write share the
    /// same string). Same durability + partial-write-rollback semantics as
    /// [`append`](KnowledgeJsonlStore::append).
    pub fn append_line(&self, agent_id: &str, json_line: &str) -> Result<(), PersistError> {
        let dir = self.ensure_agent_dir(agent_id)?;
        let file = self.agent_file(agent_id);
        let newly_created = !file.exists();
        let mut line = String::with_capacity(json_line.len() + 1);
        line.push_str(json_line);
        line.push('\n');

        let mut opts = fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(&file)
            .map_err(|e| PersistError::Io(format!("open append {}: {e}", file.display())))?;
        // AW3: capture the pre-append length so a PARTIAL write (e.g. ENOSPC/EIO
        // mid-line, where the process does NOT crash) can be rolled back. With
        // O_APPEND the write lands at EOF == original_len, so on any
        // write/fsync error we `set_len(original_len)` to drop the torn tail.
        // Without this, the torn bytes would survive in-process and a LATER
        // successful append would write after them, committing a corrupt line
        // that bricks the store on the next restart. (The crash-mid-append
        // analogue — where we can't truncate — is caught by the open-time heal.)
        let original_len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if let Err(e) = f.write_all(line.as_bytes()).and_then(|()| f.sync_all()) {
            // Best-effort truncate of the partial tail; a shrink frees space so
            // it succeeds even under ENOSPC. Then surface the original error.
            let _ = f.set_len(original_len);
            let _ = f.sync_all();
            return Err(PersistError::Io(format!(
                "append write/fsync {} (rolled back partial tail): {e}",
                file.display()
            )));
        }
        // CW2: durably link a newly-created knowledge.jsonl into its directory.
        if newly_created {
            fsync_dir(&dir);
        }
        Ok(())
    }

    /// Atomic full rewrite of the agent's `knowledge.jsonl` from `entries`
    /// (one JSON line each) — temp file (mode `0600`) → `fsync` → `rename` over
    /// the target. Used when an existing entry mutates. An empty `entries` set
    /// writes an empty (0-byte) file (the agent currently has no entries).
    pub fn rewrite(&self, agent_id: &str, entries: &[MemoryEntry]) -> Result<(), PersistError> {
        self.ensure_agent_dir(agent_id)?;
        rewrite_file_atomic(&self.agent_file(agent_id), entries)
    }

    /// Atomic full rewrite from PRE-SERIALIZED JSON lines (one per line, newlines
    /// added here). Lets the store's compaction serialize each entry exactly once
    /// (the byte accounting + this write share the same lines). An empty slice
    /// writes an empty (0-byte) file.
    pub fn rewrite_lines(&self, agent_id: &str, lines: &[String]) -> Result<(), PersistError> {
        self.ensure_agent_dir(agent_id)?;
        atomic_write(&self.agent_file(agent_id), &join_lines(lines))
    }
}

/// Read one line (up to and including the terminating `\n`) from `r` into `buf`
/// (cleared first), capped at `max` bytes. Returns `Ok(Some(true))` for a
/// newline-terminated line, `Ok(Some(false))` for an UNTERMINATED final line at
/// EOF (the torn-append signature), `Ok(None)` at clean EOF (nothing left), or
/// `Err(Corrupt)` if the line exceeds `max` bytes before a `\n` (a committed line
/// that long is external corruption — no cap-memory write produces one). Bounds
/// peak per-line RAM to `max` regardless of file size.
fn read_line_capped<R: BufRead>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> Result<Option<bool>, PersistError> {
    buf.clear();
    loop {
        let available = r
            .fill_buf()
            .map_err(|e| PersistError::Io(format!("read: {e}")))?;
        if available.is_empty() {
            // EOF: if we have accumulated bytes, this is an unterminated final
            // line; otherwise nothing left to read.
            return Ok(if buf.is_empty() { None } else { Some(false) });
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let want = pos + 1; // include the newline
            if buf.len() + want > max {
                return Err(PersistError::Corrupt(format!("line exceeds {max} bytes")));
            }
            buf.extend_from_slice(&available[..want]);
            r.consume(want);
            return Ok(Some(true));
        }
        // No newline in this chunk: take it all (capped) and continue.
        if buf.len() + available.len() > max {
            return Err(PersistError::Corrupt(format!("line exceeds {max} bytes")));
        }
        let n = available.len();
        buf.extend_from_slice(available);
        r.consume(n);
    }
}

/// Build the on-disk byte buffer from pre-serialized lines (one `\n`-terminated
/// line each). An empty slice yields an empty buffer (0-byte file).
fn join_lines(lines: &[String]) -> Vec<u8> {
    let cap = lines.iter().map(|l| l.len() + 1).sum();
    let mut buf = Vec::with_capacity(cap);
    for l in lines {
        buf.extend_from_slice(l.as_bytes());
        buf.push(b'\n');
    }
    buf
}

/// Serialize `entries` (one JSON line each) and atomically write them to
/// `file` (temp+fsync+rename+dir-fsync). Shared by [`KnowledgeJsonlStore::rewrite`]
/// and the torn-file heal path in [`KnowledgeJsonlStore::open`]. An empty
/// `entries` set writes an empty (0-byte) file.
fn rewrite_file_atomic(file: &Path, entries: &[MemoryEntry]) -> Result<(), PersistError> {
    let mut buf = String::new();
    for e in entries {
        let s = serde_json::to_string(e)
            .map_err(|err| PersistError::Io(format!("serialize entry {}: {err}", e.id)))?;
        buf.push_str(&s);
        buf.push('\n');
    }
    atomic_write(file, buf.as_bytes())
}

/// Filesystem-safe per-agent dir slug: keep `[A-Za-z0-9._-]`, replace the rest
/// with `_`, and append a `-<8 hex>` FNV-1a-32 suffix of the RAW id so two
/// distinct ids that sanitize identically (e.g. `agent:foo` vs `agent_foo`) get
/// distinct dirs. FNV-1a is a fixed, byte-stable algorithm (the slug must be
/// reproducible across builds/restarts so the same id always maps to the same
/// dir).
///
/// `pub(crate)` since rollback-memory: `L6CursorStore::with_root` derives the
/// SAME per-agent dir for `_knowledge_cursor.yaml` (cursor file sits beside
/// the agent's `knowledge.jsonl` — one layout, one slug).
pub(crate) fn slug(agent_id: &str) -> String {
    let mut s: String = agent_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // FNV-1a 32-bit.
    let mut hash: u32 = 0x811c_9dc5;
    for b in agent_id.as_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let _ = write!(s, "-{hash:08x}");
    s
}

/// Write `bytes` to `path` atomically: sibling temp file (mode `0600`),
/// `fsync`, then `rename` over the target. The target inherits the temp's
/// `0600` mode. Mirrors `cap-secrets::file_storage::atomic_write`.
///
/// `pub(crate)` (SAT-B / slice satB-postproc): reused by `post_processor.rs`
/// Step 7 to atomically write `summary.yaml` / `turn-index.yaml`. No public
/// API change (crate-internal). Creates the parent dir if absent.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), PersistError> {
    let parent = path
        .parent()
        .ok_or_else(|| PersistError::Io("knowledge.jsonl path has no parent dir".to_string()))?;
    fs::create_dir_all(parent)
        .map_err(|e| PersistError::Io(format!("create dir {}: {e}", parent.display())))?;

    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);

    {
        // SAT-B audit r6 (symlink write-escape fix): remove any pre-existing temp
        // (including a maliciously pre-planted `<file>.tmp` SYMLINK) then create it
        // with O_CREAT|O_EXCL (`create_new`), which refuses to follow/clobber a
        // symlink — so a tampered task dir cannot redirect the write outside the
        // `confined_task_dir` root via a `<file>.tmp` symlink. If an attacker races
        // a symlink in after the remove, `create_new` fails (no follow). Safe for
        // existing callers: a stale crash-residue temp is simply recreated fresh,
        // and `mode(0o600)` applies on the (always-fresh) create.
        let _ = fs::remove_file(&tmp);
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(&tmp)
            .map_err(|e| PersistError::Io(format!("open temp {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| PersistError::Io(format!("write temp {}: {e}", tmp.display())))?;
        f.sync_all()
            .map_err(|e| PersistError::Io(format!("fsync temp {}: {e}", tmp.display())))?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        PersistError::Io(format!("rename temp into {}: {e}", path.display()))
    })?;
    // CW2: durably link the rename into the parent directory so a power-loss
    // immediately after `rename` cannot revert to the old inode. Best-effort
    // (the data `fsync` above is the primary guarantee).
    fsync_dir(parent);
    Ok(())
}

/// Best-effort directory `fsync` — durably commits a file create / `rename`
/// into the directory entry. Errors are ignored (the per-file `sync_all` is the
/// primary durability guarantee; this hardens the directory-entry link). No-op
/// on non-unix (opening a directory as a `File` is not portable).
#[cfg(unix)]
fn fsync_dir(dir: &Path) {
    if let Ok(f) = fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryStatus, MemoryType};

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
    fn append_then_reopen_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            assert!(buckets.is_empty());
            store
                .append(
                    "agent:a",
                    &fact("f1", "agent:a", "hello", "2026-01-01T00:00:00Z"),
                )
                .unwrap();
            store
                .append(
                    "agent:a",
                    &fact("f2", "agent:a", "world", "2026-02-01T00:00:00Z"),
                )
                .unwrap();
        }
        let (_store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        let bucket = buckets.get("agent:a").expect("agent:a hydrated");
        assert_eq!(bucket.len(), 2);
        assert_eq!(bucket[0].id, "f1");
        assert_eq!(bucket[1].id, "f2");
    }

    #[test]
    fn rewrite_replaces_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        store
            .append("agent:a", &fact("f1", "agent:a", "a", "t1"))
            .unwrap();
        // Rewrite to a single different entry.
        store
            .rewrite("agent:a", &[fact("f2", "agent:a", "b", "t2")])
            .unwrap();
        let (_store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        let bucket = buckets.get("agent:a").unwrap();
        assert_eq!(bucket.len(), 1);
        assert_eq!(bucket[0].id, "f2");
    }

    #[test]
    fn per_agent_isolation_and_slug_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        // Two ids that sanitize to the same prefix must NOT collide.
        store
            .append("agent:foo", &fact("a", "agent:foo", "x", "t"))
            .unwrap();
        store
            .append("agent_foo", &fact("b", "agent_foo", "y", "t"))
            .unwrap();
        assert_ne!(slug("agent:foo"), slug("agent_foo"));
        let (_store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        assert_eq!(buckets.get("agent:foo").unwrap().len(), 1);
        assert_eq!(buckets.get("agent_foo").unwrap().len(), 1);
        assert_eq!(buckets.get("agent:foo").unwrap()[0].id, "a");
        assert_eq!(buckets.get("agent_foo").unwrap()[0].id, "b");
    }

    #[test]
    fn archive_subtree_is_scanned_at_level_2() {
        // M011-AC-29: `<root>/archive/<sub_id>/knowledge.jsonl` is hydrated
        // (level-2), in ADDITION to the single-level `<root>/<agent-slug>/`
        // layout — and a NON-archive second-level dir is NOT recursed.
        let dir = tempfile::tempdir().unwrap();
        // Level-1: a normal agent bucket via the public append path.
        {
            let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            store
                .append("agent:a", &fact("l1", "agent:a", "live", "t1"))
                .unwrap();
        }
        // Level-2: an archived sub-agent's knowledge.jsonl under archive/<sub_id>/.
        let archive_sub = dir.path().join(ARCHIVE_DIR_NAME).join("sub-1");
        fs::create_dir_all(&archive_sub).unwrap();
        let arch_line = serde_json::to_string(&fact("arch", "sub-1", "archived", "t2")).unwrap();
        fs::write(
            archive_sub.join(KNOWLEDGE_JSONL_FILENAME),
            format!("{arch_line}\n"),
        )
        .unwrap();
        // A NON-archive second-level dir (under an agent slug dir) must NOT be
        // recursed — the single-level contract is preserved for everything but
        // the reserved `archive/` dir.
        let nested = dir.path().join(slug("agent:a")).join("nested");
        fs::create_dir_all(&nested).unwrap();
        let ghost_line = serde_json::to_string(&fact("ghost", "ghost", "no", "t3")).unwrap();
        fs::write(
            nested.join(KNOWLEDGE_JSONL_FILENAME),
            format!("{ghost_line}\n"),
        )
        .unwrap();

        let (_store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        // Level-1 still loaded.
        assert_eq!(buckets.get("agent:a").unwrap().len(), 1);
        assert_eq!(buckets.get("agent:a").unwrap()[0].id, "l1");
        // Level-2 archive loaded, bucketed by the entry's own agent_id (sub-1).
        assert_eq!(buckets.get("sub-1").unwrap().len(), 1);
        assert_eq!(buckets.get("sub-1").unwrap()[0].id, "arch");
        // The non-archive nested dir was NOT recursed (no "ghost" bucket).
        assert!(buckets.get("ghost").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn archive_skips_a_symlinked_sub_id_dir() {
        // Symlink hardening parity: a planted symlink at archive/<sub_id> is
        // skipped (mirrors the level-1 symlinked-agent-dir skip).
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        // A real target dir OUTSIDE the archive subtree, holding a knowledge.jsonl.
        let target = tempfile::tempdir().unwrap();
        let line = serde_json::to_string(&fact("leak", "evil", "x", "t")).unwrap();
        fs::write(
            target.path().join(KNOWLEDGE_JSONL_FILENAME),
            format!("{line}\n"),
        )
        .unwrap();
        let archive = dir.path().join(ARCHIVE_DIR_NAME);
        fs::create_dir_all(&archive).unwrap();
        symlink(target.path(), archive.join("evil")).unwrap();

        let (_store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        assert!(
            buckets.get("evil").is_none(),
            "symlinked archive sub dir must be skipped"
        );
    }

    #[test]
    fn torn_final_append_line_is_tolerated_on_open() {
        // CW4: a crash mid-append can leave a torn FINAL line (no trailing
        // newline). `open` must skip it (self-heal), not brick the agent.
        let dir = tempfile::tempdir().unwrap();
        let good;
        {
            let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            store
                .append("agent:a", &fact("f1", "agent:a", "committed", "t"))
                .unwrap();
            good = store.agent_file("agent:a");
            // Simulate a torn append: a partial JSON line with NO trailing newline.
            let mut f = fs::OpenOptions::new().append(true).open(&good).unwrap();
            f.write_all(b"{\"id\":\"f2\",\"agent_id\":\"agent:a\",\"ty")
                .unwrap();
        }
        // open() tolerates the torn last line and keeps the committed entry.
        let (_store, buckets) =
            KnowledgeJsonlStore::open(dir.path()).expect("torn last line tolerated");
        let bucket = buckets.get("agent:a").expect("agent:a present");
        assert_eq!(bucket.len(), 1, "only the committed f1 survives");
        assert_eq!(bucket[0].id, "f1");
    }

    #[test]
    fn torn_line_is_healed_so_next_append_survives_restart() {
        // AW1: open() must HEAL a torn file, not just tolerate it — otherwise a
        // subsequent append writes after the torn bytes, committing corruption
        // that bricks the store on the following restart.
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            store
                .append("agent:a", &fact("f1", "agent:a", "committed", "t"))
                .unwrap();
            // Torn append: partial JSON line, no trailing newline.
            let file = store.agent_file("agent:a");
            let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
            f.write_all(b"{\"id\":\"f2\",\"agent_id\":\"age").unwrap();
        }
        // Restart 1: open heals the torn file (drops the torn residue).
        {
            let (store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            assert_eq!(buckets.get("agent:a").unwrap().len(), 1);
            // Append a real entry AFTER the heal — must land on a clean file.
            store
                .append("agent:a", &fact("f3", "agent:a", "after heal", "t"))
                .unwrap();
        }
        // Restart 2: WITHOUT the heal this would be a committed corrupt line and
        // open would fail loud. With the heal, both f1 and f3 load cleanly.
        let (_store, buckets) =
            KnowledgeJsonlStore::open(dir.path()).expect("clean reopen after heal");
        let ids: Vec<&str> = buckets
            .get("agent:a")
            .unwrap()
            .iter()
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["f1", "f3"],
            "torn residue healed; f3 appended cleanly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_does_not_heal_through_a_symlinked_agent_dir() {
        // AW-Info2: the torn-file heal WRITES, so a planted directory symlink
        // under the root must be skipped (symlink_metadata), not followed —
        // otherwise the heal would rewrite a file outside the root.
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // A TORN knowledge.jsonl in the outside dir (would trigger a heal-write
        // if followed).
        let outside_file = outside.path().join(KNOWLEDGE_JSONL_FILENAME);
        fs::write(&outside_file, b"{\"id\":\"x\",torn-no-newline").unwrap();
        let before = fs::read(&outside_file).unwrap();
        // Symlink the outside dir under the root.
        symlink(outside.path(), dir.path().join("evil")).unwrap();

        // open must skip the symlink → NOT heal/rewrite the outside file.
        let (_store, _buckets) = KnowledgeJsonlStore::open(dir.path()).expect("open ok");
        let after = fs::read(&outside_file).unwrap();
        assert_eq!(
            before, after,
            "open must not write through a symlinked agent dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn append_refuses_symlinked_agent_dir() {
        // Codex W1 (satB-postproc adversarial r15): the WRITE path
        // (ensure_agent_dir/append) must refuse a planted directory symlink —
        // open-time hydration already skips one, but `create_dir_all` would
        // otherwise FOLLOW it and write knowledge.jsonl outside the root.
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        let agent = "agent:evil";
        symlink(outside.path(), dir.path().join(slug(agent))).unwrap();

        let err = store.append(agent, &fact("k1", agent, "x", "2026-01-01T00:00:00Z"));
        assert!(
            err.is_err(),
            "append through a symlinked agent dir must be refused"
        );
        assert!(
            !outside.path().join(KNOWLEDGE_JSONL_FILENAME).exists(),
            "must NOT write knowledge.jsonl through the symlink"
        );
    }

    #[test]
    fn invariant_violating_line_fails_loud_on_open() {
        // AW2: a valid-JSON line whose state violates the MemoryEntry invariants
        // (is_active=true + status=Superseded + superseded_by=Some) must fail
        // loud on hydration, not hydrate silently.
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        store
            .append("agent:a", &fact("f1", "agent:a", "ok", "t"))
            .unwrap();
        // Craft an illegal-but-valid-JSON entry and append it (newline-terminated).
        let mut bad = fact("bad", "agent:a", "tampered", "t");
        bad.status = MemoryStatus::Superseded; // is_active=true contradicts Superseded
        bad.superseded_by = Some("zzz".into());
        let file = store.agent_file("agent:a");
        let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
        f.write_all(serde_json::to_string(&bad).unwrap().as_bytes())
            .unwrap();
        f.write_all(b"\n").unwrap();

        assert!(
            matches!(
                KnowledgeJsonlStore::open(dir.path()),
                Err(PersistError::Corrupt(_))
            ),
            "an invariant-violating hydrated line must fail loud"
        );
    }

    #[test]
    fn corrupt_committed_line_still_fails_loud() {
        // A corrupt line that IS newline-terminated (committed) must still fail
        // loud — only a torn UN-terminated last line is tolerated (CW4).
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            store
                .append("agent:a", &fact("f1", "agent:a", "ok", "t"))
                .unwrap();
            let file = store.agent_file("agent:a");
            let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
            // Corrupt line WITH a trailing newline + a valid line after it →
            // the corrupt line is committed (not the torn last line).
            f.write_all(b"{ corrupt committed\n").unwrap();
            f.write_all(
                serde_json::to_string(&fact("f3", "agent:a", "after", "t"))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
            f.write_all(b"\n").unwrap();
        }
        assert!(
            matches!(
                KnowledgeJsonlStore::open(dir.path()),
                Err(PersistError::Corrupt(_))
            ),
            "a committed corrupt line must fail loud"
        );
    }

    #[test]
    fn corrupt_line_fails_loud_on_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            store
                .append("agent:a", &fact("f1", "agent:a", "ok", "t"))
                .unwrap();
            // Append a corrupt (non-JSON) line directly to the agent file.
            let file = store.agent_file("agent:a");
            let mut f = fs::OpenOptions::new().append(true).open(&file).unwrap();
            f.write_all(b"{ this is not valid json\n").unwrap();
        }
        let err = KnowledgeJsonlStore::open(dir.path()).unwrap_err();
        assert!(matches!(err, PersistError::Corrupt(_)), "got {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_is_0600_and_leaves_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        store
            .rewrite("agent:a", &[fact("f1", "agent:a", "x", "t")])
            .unwrap();
        let file = store.agent_file("agent:a");
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "knowledge.jsonl must be 0600, got {mode:o}");
        let mut tmp_os = file.as_os_str().to_owned();
        tmp_os.push(".tmp");
        assert!(!PathBuf::from(tmp_os).exists(), "no .tmp residue");
    }

    #[cfg(unix)]
    #[test]
    fn append_creates_0600_file() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        store
            .append("agent:a", &fact("f1", "agent:a", "x", "t"))
            .unwrap();
        let file = store.agent_file("agent:a");
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "appended knowledge.jsonl must be 0600, got {mode:o}"
        );
    }

    #[test]
    fn empty_rewrite_yields_empty_bucket_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        store
            .append("agent:a", &fact("f1", "agent:a", "x", "t"))
            .unwrap();
        store.rewrite("agent:a", &[]).unwrap();
        let (_store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        // An empty file → no lines → the agent has no entries (bucket absent).
        assert!(buckets.get("agent:a").map(|b| b.is_empty()).unwrap_or(true));
    }

    // ──────────── streaming bounded read (dev-task-mem-retention) ────────────

    #[test]
    fn bounded_read_round_trips_in_order() {
        // The streaming reader hydrates a multi-line file identically to the
        // prior whole-file read — order preserved, all (sub-cap) entries present.
        let dir = tempfile::tempdir().unwrap();
        {
            let (store, _) = KnowledgeJsonlStore::open(dir.path()).unwrap();
            for i in 0..20 {
                store
                    .append(
                        "agent:a",
                        &fact(&format!("e{i}"), "agent:a", "v", &format!("t{i:02}")),
                    )
                    .unwrap();
            }
        }
        let (_store, buckets) = KnowledgeJsonlStore::open(dir.path()).unwrap();
        let bucket = buckets.get("agent:a").expect("hydrated");
        assert_eq!(bucket.len(), 20);
        for (i, e) in bucket.iter().enumerate() {
            assert_eq!(e.id, format!("e{i}"), "exact file order preserved");
        }
    }

    #[test]
    fn oversize_committed_line_fails_loud() {
        // A committed (newline-terminated) line longer than MAX_LINE_BYTES is
        // external corruption (no cap-memory write produces one) → fail loud.
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("evil-agent");
        fs::create_dir_all(&agent_dir).unwrap();
        let file = agent_dir.join(KNOWLEDGE_JSONL_FILENAME);
        let mut f = fs::File::create(&file).unwrap();
        // > MAX_LINE_BYTES of bytes, newline-terminated (committed).
        let chunk = vec![b'x'; 1024 * 1024];
        for _ in 0..(MAX_LINE_BYTES / chunk.len() + 2) {
            f.write_all(&chunk).unwrap();
        }
        f.write_all(b"\n").unwrap();
        drop(f);
        assert!(
            matches!(
                KnowledgeJsonlStore::open(dir.path()),
                Err(PersistError::Corrupt(_))
            ),
            "an oversize committed line must fail loud"
        );
    }
}
