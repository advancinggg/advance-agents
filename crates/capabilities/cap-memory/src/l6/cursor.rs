//! L6 Step 5a — `_knowledge_cursor.yaml` runtime-private cursor store.
//! MODULE-011 §1.3.6 step 5a / §2.5. Slice C held it in-memory only; the
//! rollback-memory slice (2026-06-12) adds OPT-IN on-disk persistence
//! ([`L6CursorStore::with_root`]) — every `flush` / `reset_to_epoch` writes
//! `<root>/<agent-slug>/_knowledge_cursor.yaml` (beside the agent's
//! `knowledge.jsonl`, same `persistence::slug` layout) and `reset` removes
//! it, closing the SYS-AC-063 "no file written / no read path" gap. Writes
//! are best-effort (an I/O failure logs via `eprintln!` and keeps the
//! in-memory state authoritative — the cursor is runtime-private
//! observability state, not a correctness dependency; mirrors the
//! `write_result_to_dir` fail-soft posture). The default `new()` stays
//! in-memory-only, byte-identical for every existing caller. The `L6Cursor`
//! type itself is the shared-types CONTRACT-102 supporting type.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use advance_shared_types::memory::L6Cursor;

/// Filename of the per-agent on-disk cursor (MODULE-011 §2.5 — non-Git-tracked).
pub const KNOWLEDGE_CURSOR_FILENAME: &str = "_knowledge_cursor.yaml";

#[derive(Default)]
pub struct L6CursorStore {
    inner: Mutex<HashMap<String, L6Cursor>>,
    /// rollback-memory slice: optional persistence root. `None` (default) →
    /// in-memory-only (pre-slice behavior).
    root: Option<PathBuf>,
}

impl L6CursorStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            root: None,
        }
    }

    /// rollback-memory slice: persist cursors under `root` (the same
    /// directory the [`crate::store::MemoryStore`] is rooted at — the cursor
    /// file lands beside the agent's `knowledge.jsonl` via the shared
    /// `persistence::slug` layout).
    pub fn with_root(root: PathBuf) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            root: Some(root),
        }
    }

    /// The on-disk path this store writes for `agent_id` (`None` when the
    /// store is in-memory-only). Public so witnesses/integrators can read
    /// the file back without re-deriving the slug.
    pub fn cursor_file_path(&self, agent_id: &str) -> Option<PathBuf> {
        self.root.as_ref().map(|r| {
            r.join(crate::persistence::slug(agent_id))
                .join(KNOWLEDGE_CURSOR_FILENAME)
        })
    }

    /// Best-effort on-disk write (no-op when in-memory-only). Two-field
    /// hand-rolled YAML — `last_completed_at` as epoch seconds (UNIX_EPOCH
    /// → 0, the AC-18 "epoch/0/0" initial shape).
    fn write_file(&self, agent_id: &str, cursor: &L6Cursor) {
        let Some(path) = self.cursor_file_path(agent_id) else {
            return;
        };
        let secs = cursor
            .last_completed_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let id_line = match &cursor.last_knowledge_id {
            Some(id) => format!("last_knowledge_id: {id}\n"),
            None => "last_knowledge_id: null\n".to_string(),
        };
        let body = format!("{id_line}last_completed_at_epoch_secs: {secs}\n");
        let res = path
            .parent()
            .map(std::fs::create_dir_all)
            .transpose()
            .and_then(|_| std::fs::write(&path, body.as_bytes()).map(Some));
        if let Err(e) = res {
            eprintln!(
                "cap-memory: best-effort {KNOWLEDGE_CURSOR_FILENAME} write failed for {}: {e}",
                path.display()
            );
        }
    }

    /// Step 5a flush — overwrite the agent's cursor watermark.
    pub fn flush(&self, agent_id: &str, cursor: L6Cursor) {
        self.write_file(agent_id, &cursor);
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(agent_id.to_string(), cursor);
    }

    pub fn read(&self, agent_id: &str) -> Option<L6Cursor> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(agent_id)
            .cloned()
    }

    /// rollback-memory resets `_knowledge_cursor.yaml` (it is NOT
    /// git-tracked; reset to initial rather than checked out — MODULE-011
    /// §1.4 AC-18 wording; slice C in-memory reset).
    ///
    /// **Drop-tracking semantics**: REMOVES the per-agent slot. After
    /// `reset(agent_id)`, `read(agent_id)` returns `None`. Distinct from
    /// [`Self::reset_to_epoch`] (slice G, m011-slice-g) which materializes the
    /// literal initial-state value.
    pub fn reset(&self, agent_id: &str) {
        if let Some(path) = self.cursor_file_path(agent_id) {
            // Drop semantics extend to the file: absent slot ⇒ absent file.
            let _ = std::fs::remove_file(path);
        }
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(agent_id);
    }

    /// AC-18 cap-memory-half closure (slice G, m011-slice-g): reset the
    /// agent's cursor to the **literal initial state** per AC-18 §1.4 wording
    /// ("reset to initial state (epoch/0/0)"):
    ///
    /// ```text
    /// L6Cursor {
    ///     last_knowledge_id: None,
    ///     last_completed_at: SystemTime::UNIX_EPOCH,
    /// }
    /// ```
    ///
    /// After `reset_to_epoch(agent_id)`, `read(agent_id)` returns
    /// `Some(L6Cursor { last_knowledge_id: None, last_completed_at: UNIX_EPOCH })`
    /// — distinguishing a *materialized* initial state from an *absent* slot
    /// (see [`Self::reset`] for the latter semantics).
    ///
    /// Wired into the WIT `rollback-memory` host-fn success path by
    /// [`crate::wit_impl::RollbackMemoryHandler`]; verified by
    /// `tests/integration_slice_g.rs::T18_B_cursor_reset_on_rollback` +
    /// the inline `reset_to_epoch_materializes_initial` test below.
    pub fn reset_to_epoch(&self, agent_id: &str) {
        let initial = L6Cursor {
            last_knowledge_id: None,
            last_completed_at: SystemTime::UNIX_EPOCH,
        };
        // rollback-memory: the initial state is MATERIALIZED on disk too
        // (the SYS-AC-063 observable — the file shows epoch/0/0, NOT a
        // history checkout; the cursor is never in ROLLBACK_GIT_PATHS).
        self.write_file(agent_id, &initial);
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(agent_id.to_string(), initial);
    }
}

impl std::fmt::Debug for L6CursorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.inner.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("L6CursorStore")
            .field("tracked_agents", &n)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn cursor(id: &str) -> L6Cursor {
        L6Cursor {
            last_knowledge_id: Some(id.into()),
            last_completed_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn flush_read_reset() {
        let cs = L6CursorStore::new();
        assert!(cs.read("a").is_none());
        cs.flush("a", cursor("k-10"));
        assert_eq!(
            cs.read("a").unwrap().last_knowledge_id.as_deref(),
            Some("k-10")
        );
        cs.flush("a", cursor("k-20"));
        assert_eq!(
            cs.read("a").unwrap().last_knowledge_id.as_deref(),
            Some("k-20")
        );
        cs.reset("a");
        assert!(cs.read("a").is_none());
    }

    /// AC-18 cap-memory-half closure (slice G): `reset_to_epoch` materializes
    /// the literal initial state per AC-18 §1.4 ("reset to initial state
    /// (epoch/0/0)"). Contrast with `reset` which REMOVES the slot.
    #[test]
    fn reset_to_epoch_materializes_initial() {
        let cs = L6CursorStore::new();
        // Seed a non-initial cursor watermark.
        cs.flush("a", cursor("k-100"));
        assert_eq!(
            cs.read("a").unwrap().last_knowledge_id.as_deref(),
            Some("k-100")
        );

        // reset_to_epoch: read back literal initial-state Some(_).
        cs.reset_to_epoch("a");
        let cur = cs
            .read("a")
            .expect("reset_to_epoch must materialize Some(initial)");
        assert_eq!(cur.last_knowledge_id, None);
        assert_eq!(cur.last_completed_at, SystemTime::UNIX_EPOCH);

        // Contrast: reset() REMOVES the slot (Option<L6Cursor> goes to None).
        cs.flush("b", cursor("k-200"));
        cs.reset("b");
        assert!(cs.read("b").is_none(), "reset (drop semantics) yields None");

        // reset_to_epoch on a never-flushed agent: still materializes initial.
        cs.reset_to_epoch("c");
        let cur_c = cs
            .read("c")
            .expect("reset_to_epoch on absent agent creates initial");
        assert_eq!(cur_c.last_knowledge_id, None);
        assert_eq!(cur_c.last_completed_at, SystemTime::UNIX_EPOCH);
    }
}
