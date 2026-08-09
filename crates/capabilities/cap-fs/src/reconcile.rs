//! `WorkspaceReconciler` — slice C startup reconciliation (AC-13, REQ-131).
//!
//! Walks the workspace, repairs `.meta.yaml` drift (missing files / extra
//! entries / empty required fields), and invokes MODULE-004 CONTRACT-033
//! `IndexRebuild::rebuild_full` to rebuild SQLite from the reconciled
//! filesystem. Emits a single `FsEvent::ReconcileCompleted` event summarising
//! the run; per-directory `MetaUpdated` events are NOT emitted during
//! reconciliation (would flood the EventBus and race the bulk SQL truncate
//! in `rebuild_full`).
//!
//! ## Concurrency model — STARTUP ONLY
//!
//! `WorkspaceReconciler::reconcile()` is designed to run AT BOOT, before any
//! agent begins servicing fs.read / fs.write / fs.delete / fs.list / fs.scan
//! requests. Per PRD §1.4.6 + MODULE-002 §1.4.6 the reconciler is the
//! drift-recovery checkpoint that runs once per process startup.
//!
//! The implementation does NOT serialise its `load + read_dir` snapshots
//! against the meta_maintainer lock at the per-directory level: each
//! `reconcile_dir` reads the on-disk meta + directory listing OUTSIDE the
//! lock, then takes the lock to apply edits. If `reconcile()` were invoked
//! CONCURRENTLY with live fs.write / fs.delete traffic, an interleaving
//! could cause the reconciler to operate on a stale `entries_on_disk`
//! snapshot and stomp the live write's `.meta.yaml` mutation. This is
//! acceptable because:
//!
//! 1. The runtime invokes reconcile() exactly once at boot, before agents
//!    are scheduled (matches the §1.4.6 "Startup Reconciliation Flow"
//!    contract).
//! 2. The bulk SQL `IndexRebuild::rebuild_full()` step (CONTRACT-033)
//!    that follows the walk would in any case truncate-and-reinsert the
//!    `*_index` tables — incoming concurrent writes during the rebuild
//!    window are the documented degraded mode covered by
//!    `runtime.degraded.sqlite_rebuild_failed` semantics.
//! 3. Adding per-dir lock-held load+list would cap the meta_maintainer
//!    lock under the entire walk, serialising 10K+ `read_dir` syscalls
//!    against any future request. Slice C's pin: simpler is fine for
//!    startup; a future "online reconcile" slice may revisit the lock
//!    discipline if reconcile() becomes a runtime drift-repair surface.
//!
//! Callers that wish to run reconcile() during normal operation (e.g. a
//! future repl-style admin command) MUST quiesce fs traffic externally
//! before invoking; this module does not enforce the precondition.
//!
//! ## Hidden-name parity with MODULE-004
//!
//! `is_reconciler_skipped_name` is the unified predicate used by both the
//! walkdir-level filter AND the per-directory `entries_on_disk` filter. The
//! skip-set matches MODULE-004 `crates/database/src/rebuild.rs:357`
//! `is_hidden_dir` (`.git`, `.runtime`, `.advance`, `.sub`, `.agent`) plus
//! cap-fs `crates/capabilities/cap-fs/src/resolver.rs::is_workspace_hidden_name`
//! (`.meta.yaml`, `*.sqlite`, `*.sqlite-wal`, `*.sqlite-shm`,
//! `*.sqlite-journal`). Reconciler and rebuild MUST agree on which names are
//! out-of-scope so the triple-consistency invariant holds across both paths.
//!
//! **Asymmetry with the per-call resolver hidden-name filter** (Adversarial
//! Round 1 W2): `is_reconciler_skipped_name` is case-SENSITIVE and intentionally
//! includes `.runtime` / `.sub` / `.agent` (which the resolver's per-call
//! `is_workspace_hidden_name` does NOT include) AND OMITS the
//! `eq_ignore_ascii_case` check the resolver applies for its own subset.
//! That asymmetry is BY DESIGN: the goal of slice C's reconciler is parity
//! with M004's BULK rebuild scanner (which is also case-sensitive and uses
//! the same M004 hidden-dir set), NOT parity with the resolver's per-call
//! visibility filter. Concrete consequence: a hostile workspace whose root
//! contains a directory named with non-canonical case (e.g. `.GIT/` on Linux,
//! preserved case-sensitive) will be walked + indexed identically by both
//! M004 rebuild and cap-fs reconcile (both skip only the literal `.git`).
//! That's correct — divergence between cap-fs incremental writes and
//! M004 bulk rebuild is the defect; resolver visibility is a separate
//! per-call concern handled at the agent-fs WIT surface, not here.
//!
//! Rationale for skipping `.agent/`: M005 spawn-child / spawn-sub and M013
//! grant-manager own `.agent/`'s internal lifecycle including its own
//! `.meta.yaml`. PRD §6.2's example showing `.meta.yaml` inside
//! `.agent/skills/` describes M013/M017 lifecycle-managed skill territories;
//! slice C's reconciliation deliberately defers to those owners.
//!
//! ## Empty-body description policy
//!
//! When adding a new entry for an on-disk file, reconciler passes `b""` to
//! `MetaMaintainer::add_entry_for_write` for `name`/`slug`/`description`. The
//! schema's `content-extract` rule produces the `[pending] {filename}`
//! description fallback. The reconciler does NOT read file bodies for those
//! fields. The ONE deliberate, bounded exception (ADR 2026-06-29 Decision 1,
//! MODULE-002 §1.4.6) is the entity `type` backfill: for a type-absent Markdown
//! entry it does a LAZY + HARDENED bounded frontmatter head-read
//! ([`crate::meta_schema::read_frontmatter_type_bounded`]) to classify it —
//! steady-state reconciles (all entries typed) still read zero file bytes, and
//! the §1.6 "<5s for 10K files" SLA is re-validated under the head-read.
//! PRD §6.6.6's "text files re-extracted, non-text re-queued for VLM" intent
//! is preserved as a future-work milestone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::traits::EventBusEmit;
use walkdir::WalkDir;

use crate::error::{sanitize_io_error, FsError};
use crate::events::{
    emit_fs_event, emit_runtime_degraded, emit_runtime_index_rebuild, FsEvent, RebuildReportSummary,
};
use crate::meta_maintainer::{EntryMetaValues, MetaFile, MetaMaintainer};
use crate::meta_schema::{
    entity_type, is_markdown_name, read_frontmatter_type_bounded, MetaSchemaLoader,
};

/// Resolve + apply the entity `type` for one reconcile entry (ADR 2026-06-29
/// Decision 1). Returns `true` if it wrote a new value (so the caller can arm
/// its `changed` write-gate + `fields_repaired` counter).
///
/// - `is_new` entry (just added this pass): SET `type` from the is_dir-aware
///   resolver, OVERRIDING `add_entry_for_write`'s FILE placeholder (which used
///   `is_dir=false` + an empty body, so a new subdir would be wrongly `asset`
///   and a frontmatter `.md` wrongly `document`).
/// - EXISTING entry with an empty `type`: backfill via the resolver.
/// - EXISTING entry with a non-empty `type`: PRESERVE (user override kept).
///
/// The `.md` frontmatter head-read is LAZY (only performed when the type will be
/// written — i.e. `is_new` or empty — AND the entry is Markdown) and HARDENED
/// (`read_frontmatter_type_bounded`: `O_NOFOLLOW|O_NONBLOCK` + fstat regular-file,
/// so a `.md`-named FIFO/device/symlink can never block `open()`).
fn backfill_entry_type(
    dir: &Path,
    name: &str,
    is_dir: bool,
    entry: &mut EntryMetaValues,
    is_new: bool,
) -> bool {
    if !is_new && !entry.r#type.is_empty() {
        return false; // preserve existing non-empty type (user override)
    }
    let md_frontmatter = if !is_dir && is_markdown_name(name) {
        read_frontmatter_type_bounded(&dir.join(name))
    } else {
        None
    };
    let target = entity_type(name, is_dir, md_frontmatter.as_deref());
    if entry.r#type != target {
        entry.r#type = target;
        true
    } else {
        false
    }
}

/// Cap on `ReconcileReport.errors` length. Mirrors MODULE-004's
/// `MAX_REBUILD_ERRORS = 1024` (`crates/database/src/rebuild.rs:45`). Errors
/// past the cap are summarised in a trailing `"… N more errors truncated"`
/// sentinel so operators can see the original error stream length without
/// unbounded heap growth.
pub const MAX_RECONCILE_ERRORS: usize = 1024;

/// Per-error message length cap. Same rationale as M004's
/// `MAX_ERROR_MSG_BYTES = 512` (`crates/database/src/rebuild.rs:52`) — bound
/// hostile workspace error amplification.
pub const MAX_RECONCILE_ERROR_MSG_BYTES: usize = 512;

/// Cap on the number of directories the reconciler walks in one
/// `reconcile()` invocation. Adversarial-round-1 W1: a hostile workspace
/// with millions of directories would otherwise produce an unbounded
/// `Vec<PathBuf>` from `collect_dirs` (~50-200 B per entry plus walkdir's
/// internal stack), bloating peak boot memory before per-dir reconciliation
/// even begins. 16384 is far above realistic workspace sizes (the §1.6
/// SLA target is "<5s for 10K files"; even 10K dirs is well within budget),
/// while bounding worst-case peak memory at ~3 MiB. Excess dirs are
/// recorded as a single error and skipped — reconcile still completes for
/// the directories within budget; operators can split the workspace or
/// raise the cap if legitimate.
pub const MAX_RECONCILE_DIRS: usize = 16384;

/// Result of a single `WorkspaceReconciler::reconcile()` invocation.
#[derive(Clone, Debug, Default)]
pub struct ReconcileReport {
    pub dirs_scanned: u64,
    pub meta_yaml_created: u64,
    pub entries_added: u64,
    pub entries_removed: u64,
    pub fields_repaired: u64,
    /// `Some` iff `index_rebuild.is_some()` AND `rebuild_full().await` succeeded.
    /// On rebuild error, this stays `None` and the error is pushed to `errors`.
    pub rebuild_report: Option<advance_database::RebuildReport>,
    /// Bounded at [`MAX_RECONCILE_ERRORS`] with sentinel pattern.
    pub errors: Vec<String>,
}

impl ReconcileReport {
    fn push_error(&mut self, msg: String) {
        let msg = cap_msg(msg);
        if self.errors.len() < MAX_RECONCILE_ERRORS - 1 {
            self.errors.push(msg);
            return;
        }
        if self.errors.len() == MAX_RECONCILE_ERRORS - 1 {
            self.errors.push("… 1 more errors truncated".to_string());
            return;
        }
        let last = self.errors.last_mut().expect("non-empty");
        let parsed: u64 = last
            .strip_prefix("… ")
            .and_then(|s| s.strip_suffix(" more errors truncated"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        *last = format!("… {} more errors truncated", parsed + 1);
    }
}

/// Truncate `s` to fit within `MAX_RECONCILE_ERROR_MSG_BYTES`, appending the
/// suffix `"…(truncated)"` (14 bytes) when truncation occurs. We round the
/// truncation point down to the nearest UTF-8 character boundary to avoid
/// producing invalid UTF-8 mid-codepoint.
fn cap_msg(mut s: String) -> String {
    const SUFFIX: &str = "…(truncated)";
    const SUFFIX_LEN: usize = SUFFIX.len(); // 14 bytes (3 + 11)
    if s.len() > MAX_RECONCILE_ERROR_MSG_BYTES {
        let mut at = MAX_RECONCILE_ERROR_MSG_BYTES.saturating_sub(SUFFIX_LEN);
        while at > 0 && !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
        s.push_str(SUFFIX);
    }
    s
}

/// Unified hidden-name predicate (slice C). Used by:
/// - the walkdir-level `filter_entry` for descent pruning
/// - the per-directory `entries_on_disk` filter for `read_dir` listing
///
/// Matches both M004 `rebuild.rs::is_hidden_dir` AND cap-fs
/// `resolver.rs::is_workspace_hidden_name` semantics so reconciler and bulk
/// rebuild agree on out-of-scope names.
///
/// Skip-set: `{".git", ".runtime", ".advance", ".sub", ".agent", ".meta.yaml"}`
/// PLUS suffix matchers `*.sqlite`, `*.sqlite-wal`, `*.sqlite-shm`,
/// `*.sqlite-journal`.
pub fn is_reconciler_skipped_name(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".runtime" | ".advance" | ".sub" | ".agent" | ".meta.yaml"
    ) || name.ends_with(".sqlite")
        || name.ends_with(".sqlite-wal")
        || name.ends_with(".sqlite-shm")
        || name.ends_with(".sqlite-journal")
}

/// Workspace reconciler — walks the workspace and repairs `.meta.yaml` drift.
pub struct WorkspaceReconciler {
    workspace_root: PathBuf,
    #[allow(dead_code)]
    schema: Arc<MetaSchemaLoader>,
    maintainer: Arc<MetaMaintainer>,
    index_rebuild: Option<Arc<dyn advance_database::IndexRebuild>>,
    emitter: Arc<dyn EventBusEmit>,
}

impl WorkspaceReconciler {
    pub fn new(
        workspace_root: PathBuf,
        schema: Arc<MetaSchemaLoader>,
        maintainer: Arc<MetaMaintainer>,
        index_rebuild: Option<Arc<dyn advance_database::IndexRebuild>>,
        emitter: Arc<dyn EventBusEmit>,
    ) -> Self {
        Self {
            workspace_root,
            schema,
            maintainer,
            index_rebuild,
            emitter,
        }
    }

    /// Walk the workspace, repair `.meta.yaml` drift, invoke
    /// `IndexRebuild::rebuild_full` (when configured), emit
    /// `FsEvent::ReconcileCompleted`. Returns the aggregate report; per-dir
    /// IO errors are logged + skipped, walk continues.
    pub async fn reconcile(
        &self,
        agent_id: &str,
        trace_id: &str,
    ) -> Result<ReconcileReport, FsError> {
        let mut report = ReconcileReport::default();

        // Step 1+2: walk + per-dir reconciliation. collect_dirs() records
        // any walkdir-level traversal errors into report.errors before
        // returning the list of dirs that DID open successfully — matches
        // §1.4.6 "log + skip" semantics rather than silently dropping
        // permission/IO failures during descent.
        let dirs = self.collect_dirs(&mut report);
        for dir in dirs {
            report.dirs_scanned += 1;
            if let Err(e) = self.reconcile_dir(&dir, &mut report).await {
                report.push_error(format!("reconcile {}: {e:?}", dir.display()));
                continue;
            }
        }

        // Step 3: bulk SQL rebuild.
        //
        // Adversarial-round-1 W5 ordering note: when `rebuild_full()`
        // fails we emit `runtime.degraded.sqlite_rebuild_failed` here AND
        // proceed to emit the aggregate `FsEvent::ReconcileCompleted`
        // below (with `errors_count > 0` and
        // `rebuild_report_summary = None`). Subscribers therefore see the
        // failure surfaced TWICE on the same trace_id — once via the
        // typed `runtime.degraded.*` channel and once via the
        // ReconcileCompleted aggregate — and MUST be idempotent on the
        // failure across the two events. The dual-emission pattern is
        // intentional: the typed degraded event is the operator-actionable
        // signal; the aggregate ReconcileCompleted is the "reconcile
        // run completed (even if rebuild failed)" lifecycle marker.
        if let Some(rebuild) = &self.index_rebuild {
            match rebuild.rebuild_full().await {
                Ok(rb) => report.rebuild_report = Some(rb),
                Err(e) => {
                    emit_runtime_degraded(
                        &*self.emitter,
                        agent_id,
                        trace_id,
                        "sqlite_rebuild_failed",
                        serde_json::json!({"error": format!("{e:?}")}),
                    );
                    report.push_error(format!("rebuild_full: {e:?}"));
                }
            }
        }

        // Step 4: emit aggregate event.
        let rebuild_report_summary = report
            .rebuild_report
            .as_ref()
            .map(|r| RebuildReportSummary {
                meta_rows: r.meta_rows,
                content_rows: r.content_rows,
                memory_rows: r.memory_rows,
                task_rows: r.task_rows,
                turn_rows: r.turn_rows,
                embed_calls: r.embed_calls,
                elapsed_ms: r.elapsed_ms,
                errors_count: r.errors.len() as u64,
            });
        emit_fs_event(
            &*self.emitter,
            agent_id,
            trace_id,
            FsEvent::ReconcileCompleted {
                dirs_scanned: report.dirs_scanned,
                meta_yaml_created: report.meta_yaml_created,
                entries_added: report.entries_added,
                entries_removed: report.entries_removed,
                fields_repaired: report.fields_repaired,
                rebuild_report_summary,
                errors_count: report.errors.len() as u64,
            },
        );

        // Stage-B (2026-06-15): additive `runtime.index_rebuild` observability signal.
        // Emitted ONLY on the successful-rebuild branch (rebuild_report Some) — surfaces
        // the SQLite index-rebuild volume (files + dirs) as a distinct `runtime.*` event
        // for boot/reconcile, alongside the ReconcileCompleted aggregate above. The
        // rebuild-failure branch already surfaced `runtime.degraded.sqlite_rebuild_failed`
        // (and rebuild_report stays None), so no index_rebuild event fires there.
        // SYS-AC-147. `total_files` = M004 rebuild `content_rows`; `total_dirs` =
        // the reconcile pass's `dirs_scanned`.
        if let Some(rb) = report.rebuild_report.as_ref() {
            emit_runtime_index_rebuild(
                &*self.emitter,
                agent_id,
                trace_id,
                rb.content_rows,
                report.dirs_scanned,
            );
        }

        Ok(report)
    }

    fn collect_dirs(&self, report: &mut ReconcileReport) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut over_cap = 0u64;
        let mut iter = WalkDir::new(&self.workspace_root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_str().unwrap_or("");
                !is_reconciler_skipped_name(name)
            });
        while let Some(entry) = iter.next() {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    // Record walkdir-level descent errors to honor §1.4.6
                    // "log + skip" semantics. The walk continues with the
                    // next entry. e.path() may be None when the error
                    // occurred at the root; format defensively.
                    let path_str = e
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<root>".into());
                    report.push_error(format!("walkdir {path_str}: {e}"));
                    continue;
                }
            };
            if entry.file_type().is_dir() {
                if out.len() >= MAX_RECONCILE_DIRS {
                    over_cap += 1;
                    // Adversarial-round-2 W1 closure: prune descent into
                    // this directory's subtree once the dir cap is hit.
                    // Without this, walkdir would still iterate every
                    // subdir + file under the over-cap directory, paying
                    // full traversal cost even though no entry will be
                    // pushed. `skip_current_dir` short-circuits the
                    // descent.
                    iter.skip_current_dir();
                    continue;
                }
                out.push(entry.path().to_path_buf());
            }
        }
        if over_cap > 0 {
            // Bound worst-case peak memory by capping the workspace walk
            // at MAX_RECONCILE_DIRS. Excess dirs surface as a single
            // aggregate error so operators can see the cap was hit
            // without flooding the errors channel.
            report.push_error(format!(
                "walk skipped {over_cap} dirs past MAX_RECONCILE_DIRS={MAX_RECONCILE_DIRS}"
            ));
        }
        out
    }

    async fn reconcile_dir(&self, dir: &Path, report: &mut ReconcileReport) -> Result<(), FsError> {
        let meta_pre = self.maintainer.load(dir).await?;
        let entries_on_disk = self.list_entries(dir)?;

        match meta_pre {
            None => {
                self.reconcile_missing_meta(dir, &entries_on_disk, report)
                    .await
            }
            Some(existing) => {
                self.reconcile_existing_meta(dir, existing, &entries_on_disk, report)
                    .await
            }
        }
    }

    /// List non-skipped, non-symlink on-disk entries as `name → is_dir`. The
    /// `is_dir` flag (already available from the `file_type()` stat done here for
    /// symlink filtering) drives the entity-`type` backfill (directory →
    /// `collection`); carrying it avoids a second stat per entry.
    fn list_entries(&self, dir: &Path) -> Result<BTreeMap<String, bool>, FsError> {
        let mut out = BTreeMap::new();
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => return Err(FsError::IoError(sanitize_io_error(&e))),
        };
        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue, // per-entry IO error → skip
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_reconciler_skipped_name(&name) {
                continue;
            }
            // No ASCII filter — reconciler indexes valid Unicode filenames
            // (matches M004 rebuild scanner's read_to_string policy).
            // No `.agent/_*` filter — walk-level skip already prunes `.agent`.
            // Skip symlinks per slice B's FsListHandler discipline.
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            out.insert(name, file_type.is_dir());
        }
        Ok(out)
    }

    async fn reconcile_missing_meta(
        &self,
        dir: &Path,
        entries_on_disk: &BTreeMap<String, bool>,
        report: &mut ReconcileReport,
    ) -> Result<(), FsError> {
        // ensure_dir_meta creates `_scope` block but does not pre-populate child
        // entries — we add them via add_entry_for_write below.
        self.maintainer.ensure_dir_meta(dir, None).await?;
        report.meta_yaml_created += 1;

        if entries_on_disk.is_empty() {
            return Ok(());
        }

        // Re-load the just-created meta and merge in the on-disk entries.
        let _guard = self.maintainer.acquire().await;
        let existing = self.maintainer.load(dir).await?.unwrap_or_default();
        let mut current = existing;
        for name in entries_on_disk.keys() {
            // Adversarial-round-1 fix (C1): pass `current` by move to
            // avoid an O(N²) `MetaFile.clone()` on every iteration. With
            // millions of on-disk files in a single directory, the prior
            // `Some(current.clone())` quadratic clone storm could OOM the
            // runtime at boot before the per-write `MAX_META_YAML_BYTES`
            // cap fires (the cap is checked in `MetaMaintainer::write`,
            // AFTER the loop has materialised every clone).
            let entries_before = current.entries.len();
            let (next, _changed) = self
                .maintainer
                .add_entry_for_write(Some(current), name, b"")?;
            current = next;
            if current.entries.len() > entries_before {
                report.entries_added += 1;
            }
        }
        // Entity `type` backfill (ADR 2026-06-29 Decision 1): every entry here is
        // NEW, so override the FILE placeholder from `add_entry_for_write` with
        // the is_dir-aware resolver (a subdir → `collection`, a frontmatter `.md`
        // → its declared value). This path writes unconditionally, so no
        // `changed` flag is needed.
        for (name, is_dir) in entries_on_disk {
            if let Some(entry) = current.entries.get_mut(name) {
                if backfill_entry_type(dir, name, *is_dir, entry, true) {
                    report.fields_repaired += 1;
                }
            }
        }
        self.maintainer.write(dir, &current).await?;
        Ok(())
    }

    async fn reconcile_existing_meta(
        &self,
        dir: &Path,
        existing: MetaFile,
        entries_on_disk: &BTreeMap<String, bool>,
        report: &mut ReconcileReport,
    ) -> Result<(), FsError> {
        let _guard = self.maintainer.acquire().await;
        let mut current = existing;
        let mut changed = false;

        // Remove meta entries that no longer exist on disk.
        let to_remove: Vec<String> = current
            .entries
            .keys()
            .filter(|k| !entries_on_disk.contains_key(k.as_str()))
            .cloned()
            .collect();
        for name in to_remove {
            current.entries.remove(&name);
            report.entries_removed += 1;
            changed = true;
        }

        // Add entries on disk that aren't in meta; track which we added this
        // pass so the type backfill treats them as NEW (override the FILE
        // placeholder) while pre-existing entries only backfill-if-empty.
        let mut added_this_pass: BTreeSet<String> = BTreeSet::new();
        for name in entries_on_disk.keys() {
            if current.entries.contains_key(name) {
                continue;
            }
            // Adversarial-round-1 fix (C1): pass `current` by move (no clone)
            // to keep the per-iteration cost O(1). The previous
            // `Some(current.clone())` was Σi = O(N²) on a workspace with
            // many missing entries.
            let entries_before = current.entries.len();
            let (next, _added) = self
                .maintainer
                .add_entry_for_write(Some(current), name, b"")?;
            current = next;
            if current.entries.len() > entries_before {
                report.entries_added += 1;
                changed = true;
                added_this_pass.insert(name.clone());
            }
        }

        // Repair empty required name/slug/description + backfill entity `type`
        // on every remaining entry. `type` MUST arm `changed` when it writes
        // (else the `if changed` write-gate below skips persisting a type-only
        // backfill on a well-formed pre-type workspace — the migration would be
        // silently recomputed + discarded every reconcile).
        let entry_names: Vec<String> = current.entries.keys().cloned().collect();
        for name in entry_names {
            let is_dir = entries_on_disk.get(&name).copied().unwrap_or(false);
            let is_new = added_this_pass.contains(&name);
            let entry = match current.entries.get_mut(&name) {
                Some(e) => e,
                None => continue,
            };
            let repaired = self.maintainer.repair_entry_required_fields(entry, &name);
            if !repaired.is_empty() {
                report.fields_repaired += repaired.len() as u64;
                changed = true;
            }
            if backfill_entry_type(dir, &name, is_dir, entry, is_new) {
                report.fields_repaired += 1;
                changed = true;
            }
        }

        if changed {
            self.maintainer.write(dir, &current).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_set_includes_m004_dirs() {
        for name in [".git", ".runtime", ".advance", ".sub", ".agent"] {
            assert!(
                is_reconciler_skipped_name(name),
                "missing M004-parity skip: {name}"
            );
        }
    }

    #[test]
    fn skip_set_includes_meta_yaml_and_sqlite_suffixes() {
        assert!(is_reconciler_skipped_name(".meta.yaml"));
        assert!(is_reconciler_skipped_name("index.sqlite"));
        assert!(is_reconciler_skipped_name("index.sqlite-wal"));
        assert!(is_reconciler_skipped_name("index.sqlite-shm"));
        assert!(is_reconciler_skipped_name("index.sqlite-journal"));
    }

    #[test]
    fn skip_set_excludes_normal_names() {
        for name in [
            "notes.md",
            "research",
            ".gitignore",
            ".agent-templates",
            "中文.md",
            "image.png",
        ] {
            assert!(
                !is_reconciler_skipped_name(name),
                "false-positive skip: {name}"
            );
        }
    }

    #[test]
    fn report_push_error_caps_at_max() {
        let mut report = ReconcileReport::default();
        for i in 0..(MAX_RECONCILE_ERRORS + 5) {
            report.push_error(format!("error {i}"));
        }
        assert_eq!(report.errors.len(), MAX_RECONCILE_ERRORS);
        let last = report.errors.last().unwrap();
        assert!(last.contains("more errors truncated"));
    }

    #[test]
    fn cap_msg_truncates_long_strings() {
        let s = "x".repeat(MAX_RECONCILE_ERROR_MSG_BYTES * 2);
        let capped = cap_msg(s);
        assert!(capped.len() <= MAX_RECONCILE_ERROR_MSG_BYTES);
        assert!(capped.ends_with("…(truncated)"));
    }
}
