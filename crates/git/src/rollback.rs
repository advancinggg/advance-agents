//! CONTRACT-021 `WorkspaceRollback` — path-level rollback primitive.
//!
//! Implements MODULE-003 §1.4.2 + §2.3 byte-for-byte. Two modes:
//! - **FullDirectory** (§7.2): walks the target commit's tree under the
//!   agent's root, filters out `.agent/**`, child territories (per PRD §6.2
//!   `.agent/` single-signal rule), and hidden runtime paths, then checks
//!   out each surviving entry. Matches AC-05 / AC-15.
//! - **PathScoped** (§7.2): validates each caller-supplied path against the
//!   four rejection rules (`..` traversal, hidden runtime, child-territory
//!   overlap, `.agent/` outside memory-rollback) BEFORE expansion, then
//!   checks out each surviving path. Matches AC-06 / AC-16.
//!
//! `rollback_to_checkpoint` is the thin wrapper per §1.4.2 line 230-231:
//! parses the tag message, decides the mode, delegates via
//! `rollback(agent_id, RollbackTarget::Checkpoint(label), mode)`. Invalid
//! tag messages surface as `RollbackError::Checkpoint(CheckpointError::
//! InvalidState)` per §1.4.3 line 411-413.
//!
//! `memory_rollback_paths` returns the Git-tracked memory-file set per
//! PRD §11.6: `.agent/{agent_id}/memory/knowledge.jsonl`,
//! `.agent/{agent_id}/memory/_knowledge_map.yaml`, and every
//! `.agent/{agent_id}/memory/syntheses/**/*.md` (recursive). Excludes
//! `_knowledge_cursor.yaml` (non-Git-tracked).
//!
//! # Concurrency
//!
//! Async methods wrap their critical section in `tokio::task::spawn_blocking`
//! so the synchronous libgit2 work doesn't stall the async runtime. Inside
//! the blocking closure the per-repo-path `crate::coord::git_repo_lock`
//! mutex is acquired via `std::sync::Mutex::lock()` — `tokio::sync::Mutex`
//! cannot be used because the blocking-pool thread retains a tokio runtime
//! handle. `memory_rollback_paths` is synchronous and acquires the lock
//! directly at method entry.

use crate::coord::git_repo_lock;
use crate::error::{DeniedReason, RollbackError};
use crate::repo::open_repo_internal;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use chrono::Utc;
use git2::{build::CheckoutBuilder, ObjectType, Oid, Repository};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Defensive cap on `affected_paths` entries in the emitted `git.rollback`
/// event payload (Slice E). MODULE-003's path-expansion is bounded by
/// Slice C+D's `MAX_FULL_DIRECTORY_PATHS = 100_000`, which at ~60
/// bytes/path JSON would produce ~6 MB payloads — well over MODULE-019's
/// recommended per-event 64 KiB cap
/// (`advance_shared_types::event::Event` rustdoc invariant 2). Capping
/// here provides defense-in-depth; truncation is silent (the payload
/// keeps exactly the five PRD §15.3.17 fields — no new keys). Consumers
/// needing the authoritative full set fall back to `.meta.updated` per
/// PRD "reconciliation 走 meta.updated" design. Variable path lengths
/// mean a count cap alone doesn't strictly guarantee `< 64 KiB` —
/// MODULE-019's own size enforcement remains the canonical upstream
/// check.
pub(crate) const MAX_EVENT_AFFECTED_PATHS: usize = 1000;

/// Private no-op EventBus used by `DefaultWorkspaceRollback::new` to
/// preserve the Slice B call-site surface (all 21 legacy `::new`
/// sites — 17 in `tests/rollback.rs` + 4 in
/// `tests/rollback_checkpoint_integration.rs` — keep working without
/// edits). Zero-sized; auto-satisfies `Send + Sync`.
struct NoopEventBus;

impl EventBusEmit for NoopEventBus {
    fn emit(&self, _event: Event) {}
}

/// Construct the `git.rollback` Event payload per PRD §15.3.17 and
/// dispatch it through the injected `EventBusEmit` bus. Called only
/// from the async outer scope of `rollback` / `rollback_to_checkpoint`
/// (AFTER the `spawn_blocking` closure has returned and the coord
/// mutex has been released), and only when `do_rollback` returned
/// `Ok(paths)` with `!paths.is_empty()` — see the method bodies.
///
/// Silent truncation: if `affected_paths.len() > MAX_EVENT_AFFECTED_PATHS`,
/// the payload only contains the first N entries. No flag is added to
/// the payload (PRD §15.3.17 specifies exactly five fields:
/// `agent_id`, `target_ref`, `target_kind`, `affected_paths`,
/// `initiator`). Consumers requiring the authoritative full set use
/// the `.meta.updated` side channel per PRD's own design note.
fn emit_rollback_event(
    bus: &dyn EventBusEmit,
    agent_id: &str,
    target_ref: &str,
    target_kind: &'static str,
    affected_paths: &[PathBuf],
) {
    let affected: Vec<String> = affected_paths
        .iter()
        .take(MAX_EVENT_AFFECTED_PATHS)
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let payload = serde_json::json!({
        "agent_id": agent_id,
        "target_ref": target_ref,
        "target_kind": target_kind,
        "affected_paths": affected,
        "initiator": agent_id,
    });
    bus.emit(Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: String::new(),
        span_id: String::new(),
        parent_span_id: None,
        event_type: "git.rollback".to_string(),
        payload,
        duration_ms: None,
    });
}

/// Root-agent sentinel. Per PRD §6.2, the root agent's `.agent/` lives at
/// `<workdir>/.agent/`. If the caller-supplied `agent_id` matches the root
/// agent's config, the `agent_root` is the workspace root itself.
///
/// Slice B accepts the conventional `"root"` sentinel plus any agent_id
/// whose `<workdir>/.agent/config.yaml` agent_id field matches. In absence
/// of a root config.yaml (test fixtures), the sentinel `"root"` falls back
/// to `<workdir>` directly.
const ROOT_AGENT_SENTINEL: &str = "root";

/// Target of a rollback operation. Public API carries opaque strings — no
/// `git2::Oid` crosses the crate boundary per §1.1.
#[derive(Debug, Clone)]
pub enum RollbackTarget {
    /// 40-char lowercase hex SHA-1. Parsed to `git2::Oid` at the crate
    /// boundary via `Oid::from_str` and immediately peeled to a commit.
    Commit(String),
    /// Label within the current agent's checkpoint namespace. The impl
    /// resolves the label → annotated tag → commit Oid inside the critical
    /// section.
    Checkpoint(String),
}

#[derive(Debug, Clone)]
pub enum RollbackMode {
    /// Walk the target commit's tree and check out every entry inside the
    /// agent's writable domain.
    FullDirectory,
    /// Caller-supplied paths (relative to agent root). Each path is
    /// validated before checkout.
    PathScoped(Vec<PathBuf>),
}

/// CONTRACT-021 trait — async shape matches MODULE-003 §2.3 lines 546-573.
#[async_trait]
pub trait WorkspaceRollback: Send + Sync {
    async fn rollback(
        &self,
        agent_id: &str,
        target: RollbackTarget,
        mode: RollbackMode,
    ) -> Result<Vec<PathBuf>, RollbackError>;

    async fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
    ) -> Result<Vec<PathBuf>, RollbackError>;

    fn memory_rollback_paths(&self, agent_id: &str) -> Result<Vec<PathBuf>, RollbackError>;
}

/// Default impl — holds canonical repo path for coord mutex keying and
/// the injected `EventBusEmit` consumer for `git.rollback` event
/// emission (Slice E). Legacy `::new` uses the private `NoopEventBus`
/// to preserve call-site surface.
pub struct DefaultWorkspaceRollback {
    canonical_repo: PathBuf,
    event_bus: Arc<dyn EventBusEmit>,
}

/// Maximum directory-walk depth for both `resolve_agent_root` BFS and
/// `detect_child_territories` DFS. Matches PRD §6.2 hierarchy depth
/// conventions (single-digit layers) and bounds adversarial resource
/// consumption when an agent creates a deeply-nested tree.
const MAX_WALK_DEPTH: u32 = 8;

/// Defensive cap on `memory_rollback_paths` result size. PRD §11.6 does
/// not pin an upper bound, but an adversarial synthesis dir with
/// 10M+ files would starve the caller. 10k files is ~20× the realistic
/// corpus for the intended L6 consolidation workflow.
const MAX_MEMORY_PATHS: usize = 10_000;

/// Defensive cap on `expand_full_domain` result size. A target commit tree
/// with 10M+ blobs would OOM the caller; 100k is >>realistic per-agent
/// working set size. Adversarial R2 W6 fix.
const MAX_FULL_DIRECTORY_PATHS: usize = 100_000;

/// Defensive cap on total directory entries visited by FS walks. Bounds
/// both `resolve_agent_root` BFS and `detect_child_territories` DFS against
/// a workspace with millions of siblings at one depth level. Adversarial
/// R2 W5 fix — complements `MAX_WALK_DEPTH` which bounds depth but not
/// breadth.
const MAX_WALK_ENTRIES: usize = 100_000;

/// Resolve `agent_id → agent_root_abs` by scanning `<workdir>/**/.agent/config.yaml`
/// for a matching `agent_id` field, falling back to the root-sentinel
/// convention. Called inside every rollback op under the coord mutex per
/// §3.8 caveat #2; re-validates each call.
///
/// Returns `(absolute_root_path, root_relative_path_string_or_empty)`. The
/// root-relative string is used to prefix-filter full-directory expansion.
fn resolve_agent_root(workdir: &Path, agent_id: &str) -> Result<(PathBuf, String), RollbackError> {
    // Short-circuit: root sentinel + no root config.yaml → workdir.
    // Symlink-safe at BOTH the directory (`.agent/`) AND file
    // (`.agent/config.yaml`) level — `symlink_metadata` on an intermediate
    // symlinked `.agent/` directory returns symlink type; `.is_dir()`
    // returns false, so we fall through without following the link.
    // Adversarial R2 W3 fix: previous version only checked the file level,
    // allowing a planted `workdir/.agent -> /tmp/attack` to redirect the
    // subsequent config.yaml stat+read to an attacker-chosen location.
    let root_agent_dir = workdir.join(".agent");
    let root_agent_md = std::fs::symlink_metadata(&root_agent_dir);
    let root_agent_is_real_dir = root_agent_md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
    let root_cfg = root_agent_dir.join("config.yaml");
    if root_agent_is_real_dir
        && matches!(std::fs::symlink_metadata(&root_cfg), Ok(m) if m.is_file())
    {
        if let Ok(id) = read_config_agent_id_safe(&root_cfg) {
            if id == agent_id {
                return Ok((workdir.to_path_buf(), String::new()));
            }
        }
    } else if agent_id == ROOT_AGENT_SENTINEL {
        return Ok((workdir.to_path_buf(), String::new()));
    }

    // BFS for nested `.agent/config.yaml` (depth-capped; Slice B workspaces
    // are shallow per PRD §6.2). Skip `.agent/` at every level — that is
    // either the workspace's own private area OR a child's territory
    // (handled separately); descending into either would mis-resolve the
    // agent root. Adversarial I1 fix.
    let mut stack: Vec<(PathBuf, u32)> = vec![(workdir.to_path_buf(), 0)];
    let mut visited: usize = 0;
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_WALK_DEPTH {
            continue;
        }
        if visited >= MAX_WALK_ENTRIES {
            // Adversarial R2 W5 fix: fanout cap. Return NotFound rather than
            // pressing on with a partially-scanned stack that might miss the
            // target agent_id for deep/wide workspaces. Fail closed.
            return Err(RollbackError::NotFound {
                what: format!("agent_id={agent_id} (walk cap exceeded)"),
            });
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited >= MAX_WALK_ENTRIES {
                // Fail closed — parity with the top-of-loop cap. A bare `break`
                // would only exit the inner loop and could drain the stack empty
                // → terminal NotFound; make the cap explicit instead (adversarial
                // R16 W4 parity).
                return Err(RollbackError::NotFound {
                    what: format!("agent_id={agent_id} (walk cap exceeded)"),
                });
            }
            let p = entry.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Skip hidden-runtime roots AND `.agent/` at every descent level
            // (the agent's config.yaml sits at `<agent_root>/.agent/config.yaml`,
            // never at `<agent_root>/.agent/<nested>/.agent/config.yaml`).
            if name == ".git"
                || name == ".runtime"
                || name == ".advance"
                || name == ".sub"
                || name == ".agent"
            {
                continue;
            }
            let md = match std::fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_dir() {
                continue;
            }
            // Check for `.agent/config.yaml` on this descendant. Both the
            // directory AND the file must be real (not symlinks) —
            // `symlink_metadata` returns metadata of the link itself.
            let cfg = p.join(".agent").join("config.yaml");
            let agent_md = std::fs::symlink_metadata(p.join(".agent"));
            let cfg_md = std::fs::symlink_metadata(&cfg);
            let agent_is_real_dir = agent_md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let cfg_is_real_file = cfg_md.as_ref().map(|m| m.is_file()).unwrap_or(false);
            if agent_is_real_dir && cfg_is_real_file {
                if let Ok(id) = read_config_agent_id_safe(&cfg) {
                    if id == agent_id {
                        let rel = p
                            .strip_prefix(workdir)
                            .map(|r| r.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        return Ok((p, rel));
                    }
                }
                // Skip subtree (it's another agent's territory — don't descend
                // to look for a match inside a child's private area).
                continue;
            }
            stack.push((p, depth + 1));
        }
    }
    Err(RollbackError::NotFound {
        what: format!("agent_id={agent_id}"),
    })
}

/// Symlink-safe YAML-parsed reader of `agent_id` from a config.yaml.
/// Rejects: symlinked config.yaml (R1 C1 fix), duplicate `agent_id:` keys
/// (R2 W2 fix — first-match-wins line scans allowed a prepend-attack where
/// an attacker with config write access could alias one agent to another's
/// id by writing `agent_id: alice\nagent_id: research`), non-object YAML,
/// and non-string or empty `agent_id` values.
fn read_config_agent_id_safe(cfg_path: &Path) -> Result<String, std::io::Error> {
    // Double-check: symlink_metadata must report a non-symlink file. The
    // caller already stat'd cfg_path but the check here is defense-in-depth
    // against a TOCTOU window between the caller's stat and this read.
    let md = std::fs::symlink_metadata(cfg_path)?;
    if md.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to read through symlinked config.yaml: {}",
                cfg_path.display()
            ),
        ));
    }
    let content = std::fs::read_to_string(cfg_path)?;
    // Pre-scan for duplicate `agent_id` keys — serde_yml silently takes the
    // last value on duplicates, which is an attack path (agent_id override
    // prepend). Reject any config with more than one `agent_id` key,
    // including flow-mapping syntax on one line (adversarial R3 W1 fix).
    //
    // Two safeguards:
    // (a) Reject any YAML flow-mapping brace `{` OR flow-sequence bracket
    //     `[` at the top level — the config.yaml schema per PRD §6.2 is a
    //     flat block mapping, flow syntax is NEVER legitimate.
    // (b) Count literal `agent_id` occurrences (token-bounded) in the raw
    //     text AND cap at 1. Quoted-string occurrences inside values are
    //     unlikely and would be overzealously rejected — acceptable for
    //     defense-in-depth.
    // Reject YAML feature-rich syntax that can smuggle duplicate/overridden
    // `agent_id` values past the token-count check (adversarial R4 Critical
    // fix):
    //   `{`, `[`  — flow mapping / sequence
    //   `&`       — anchor declaration
    //   `*`       — alias reference (`agent_id: *a` resolves at parse time)
    //   `<<`      — merge key (`<<: *a` injects anchored fields)
    //   `!`       — explicit tag (`!!str`, `!tag` can alter parse semantics)
    // Our schema (PRD §6.2) is a flat block mapping of scalar string values.
    // None of these tokens are legitimate in that subset. A strict-subset
    // whitelist is more robust than enumerating new YAML attack variants.
    // `|` / `>` block-scalar indicators (R5 fix) — `agent_id: |\n  foo` or
    // `agent_id: >\n  foo` parse to multi-line / slash-containing values
    // that break identity shape assumptions.
    const FORBIDDEN_TOKENS: &[&str] = &["{", "[", "&", "*", "<<", "!", "|", ">"];
    for token in FORBIDDEN_TOKENS {
        if content.contains(token) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config.yaml contains forbidden YAML token `{token}` \
                     (must be flat block mapping with scalar string values): {}",
                    cfg_path.display()
                ),
            ));
        }
    }
    let agent_id_token_count = content
        .match_indices("agent_id")
        .filter(|(i, _)| {
            // Must be at start of input OR preceded by a non-word char
            // (avoids substring hits inside e.g. "my_agent_id").
            let before_ok = *i == 0
                || !content.as_bytes()[*i - 1].is_ascii_alphanumeric()
                    && content.as_bytes()[*i - 1] != b'_';
            // Must be followed by `:` after optional whitespace.
            let after = &content[*i + "agent_id".len()..];
            let after_ok = after.trim_start().starts_with(':');
            before_ok && after_ok
        })
        .count();
    if agent_id_token_count > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "duplicate `agent_id` key in {} (count={agent_id_token_count})",
                cfg_path.display()
            ),
        ));
    }
    // Parse the whole document via serde_yml. Accepting any document shape
    // that contains a top-level `agent_id: <string>` mapping.
    let value: serde_yml::Value = serde_yml::from_str(&content).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("yaml parse error in {}: {e}", cfg_path.display()),
        )
    })?;
    let mapping = value.as_mapping().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("config.yaml root is not a mapping: {}", cfg_path.display()),
        )
    })?;
    let id_val = mapping
        .get(serde_yml::Value::String("agent_id".to_string()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("no agent_id field in {}", cfg_path.display()),
            )
        })?;
    let id = id_val.as_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("agent_id is not a string in {}", cfg_path.display()),
        )
    })?;
    if id.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("agent_id is empty in {}", cfg_path.display()),
        ));
    }
    // Shape validation on the parsed value (R5 W2 fix): even with
    // FORBIDDEN_TOKENS rejecting YAML feature-rich syntax, a quoted-escape
    // value like `"a\nb"` could still produce a string containing control
    // chars, `/`, `..`, or NUL. Reject any id that isn't a flat ASCII-safe
    // Git-ref-compatible identifier. Tighter than `validate_ref_component`
    // (which is applied at API boundary): here we sanity-check the
    // attacker-controlled config file before it influences any resolution.
    if id.len() > 128 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "agent_id length exceeds 128 bytes in {}",
                cfg_path.display()
            ),
        ));
    }
    for c in id.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.';
        // Defense in depth — mirror validate_ref_component's NUL/control
        // rejection AND block `/`, `..`, whitespace anywhere in the value.
        if !ok {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "agent_id contains forbidden character `{c}` in {}",
                    cfg_path.display()
                ),
            ));
        }
    }
    if id.contains("..") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("agent_id contains `..` in {}", cfg_path.display()),
        ));
    }
    Ok(id.to_string())
}

impl DefaultWorkspaceRollback {
    /// Legacy constructor — installs a private `NoopEventBus`. Preserves
    /// the Slice B surface so all existing `::new` call sites keep
    /// working unchanged.
    pub fn new(repo_path: PathBuf) -> Result<Self, RollbackError> {
        Self::with_event_bus(repo_path, Arc::new(NoopEventBus))
    }

    /// Slice E additive constructor — accepts an injected
    /// `Arc<dyn EventBusEmit>` consumer. On successful `rollback` /
    /// `rollback_to_checkpoint` with non-empty `affected_paths`, a
    /// `git.rollback` event (CONTRACT-180) is emitted per PRD
    /// §15.3.17 payload schema. See `emit_rollback_event` for payload
    /// construction and `MAX_EVENT_AFFECTED_PATHS` for the defensive
    /// entry cap.
    pub fn with_event_bus(
        repo_path: PathBuf,
        event_bus: Arc<dyn EventBusEmit>,
    ) -> Result<Self, RollbackError> {
        let canonical_repo = std::fs::canonicalize(&repo_path).map_err(|e| {
            RollbackError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot canonicalize repo path for rollback impl: {} ({e})",
                    repo_path.display()
                ),
            ))
        })?;
        Ok(Self {
            canonical_repo,
            event_bus,
        })
    }

    /// Adversarial-round F2 fix (2026-06-13): one-shot repo probe for
    /// composition roots. `with_event_bus` only canonicalizes the path —
    /// it never opens the repo — so a wiring site that wants the
    /// open-probe-and-degrade posture (the `DefaultGitCommitQueue::spawn`
    /// precedent: non-repo workspace → feature disabled, NOT
    /// per-call mutate-then-error) must call this once at wiring time.
    pub fn verify_repo(&self) -> Result<(), RollbackError> {
        let coord = git_repo_lock(&self.canonical_repo);
        let _guard = coord
            .lock()
            .expect("git coord mutex poisoned in verify_repo");
        open_repo_internal(&self.canonical_repo)?;
        Ok(())
    }

    /// rollback-memory slice (2026-06-12) — the MODULE-011 AC-18 git half,
    /// timestamp-addressed: restore the agent's Git-tracked memory files
    /// **excluding `knowledge.jsonl`** (the `MemoryStore` owns that file's
    /// rollback in-process — restoring it here would split-brain the live
    /// store cache and be clobbered by the store's next persist) to their
    /// state at the latest commit whose commit time is **at or before**
    /// `timestamp_rfc3339`.
    ///
    /// Timestamp→commit resolution (the adjudicated design): a TIME-sorted
    /// revwalk from HEAD picks the first commit with
    /// `commit.time().seconds() <= ts`. The commit need not have TOUCHED a
    /// memory file — its tree IS the repository state at that wall-clock
    /// time, which is what "restore to that state" means. NOTE the two-clock
    /// caveat (recorded in MODULE-011 §3.8): knowledge `created_at` stamps
    /// and git commit times are different clocks; callers sequencing
    /// writes-then-commits within the same second get second-granularity
    /// semantics, no better.
    ///
    /// Path enumeration runs against the TARGET commit's tree (not HEAD —
    /// files deleted after the timestamp are restored, the stronger
    /// semantics): `_knowledge_map.yaml` if present + every
    /// `syntheses/*.md` blob (capped at [`MAX_MEMORY_PATHS`]), as
    /// agent-relative paths. The actual checkout delegates to
    /// [`WorkspaceRollback::rollback`] `PathScoped` — every validator
    /// (child-territory exclusion, the `.agent/memory/**` exception) and the
    /// `git.rollback` event emission apply unchanged. Enumerated-then-restored
    /// is two lock acquisitions (the enumeration guard drops before
    /// `rollback` re-locks) — the same §3.8 re-validate-per-call posture as
    /// every other entry point.
    ///
    /// Returns the restored workspace-relative paths. No commit at/before
    /// the timestamp, or no memory files in the target tree, are both
    /// `Ok(vec![])` no-ops (nothing existed to restore), not errors.
    pub async fn rollback_memory_files_at(
        &self,
        agent_id: &str,
        timestamp_rfc3339: &str,
    ) -> Result<Vec<PathBuf>, RollbackError> {
        let ts_epoch = chrono::DateTime::parse_from_rfc3339(timestamp_rfc3339)
            .map_err(|e| RollbackError::NotFound {
                what: format!(
                    "rollback-memory timestamp {timestamp_rfc3339:?} is not RFC3339: {e}"
                ),
            })?
            .timestamp();

        // Phase 1 (under the coord mutex): resolve target commit + enumerate
        // its memory-file set. The guard DROPS before phase 2's rollback()
        // re-acquires it (self-deadlock otherwise — std Mutex is not
        // reentrant).
        let (target_sha, paths) = {
            let coord = git_repo_lock(&self.canonical_repo);
            let _guard = coord
                .lock()
                .expect("git coord mutex poisoned in rollback_memory_files_at");
            crate::checkpoint::validate_ref_component(agent_id, "agent_id")
                .map_err(RollbackError::Checkpoint)?;
            let repo = open_repo_internal(&self.canonical_repo)?;
            let (_agent_root_abs, agent_root_rel) =
                resolve_agent_root(&self.canonical_repo, agent_id)?;
            let memory_prefix = if agent_root_rel.is_empty() {
                ".agent/memory".to_string()
            } else {
                format!("{agent_root_rel}/.agent/memory")
            };

            // TIME-sorted revwalk from HEAD → first commit at/before ts.
            let mut walk = repo.revwalk()?;
            if walk.push_head().is_err() {
                // Unborn HEAD (empty repo) → nothing existed at any time.
                return Ok(Vec::new());
            }
            walk.set_sorting(git2::Sort::TIME)?;
            let mut target: Option<git2::Commit> = None;
            for (i, oid) in walk.flatten().enumerate() {
                // Defensive bound — mirrors MAX_WALK_ENTRIES (breadth cap).
                // Adversarial-round F4 fix (2026-06-13): exhaustion is an
                // ERROR, not the no-op arm — a state-restoring operation
                // must never present a bound-capped scan as "nothing to
                // restore" (the :250-260 resolve_agent_root precedent).
                if i >= MAX_WALK_ENTRIES {
                    return Err(RollbackError::NotFound {
                        what: format!(
                            "rollback-memory revwalk cap exceeded \
                             (MAX_WALK_ENTRIES={MAX_WALK_ENTRIES}) before reaching \
                             a commit at-or-before the timestamp"
                        ),
                    });
                }
                let commit = repo.find_commit(oid)?;
                if commit.time().seconds() <= ts_epoch {
                    target = Some(commit);
                    break;
                }
            }
            let Some(commit) = target else {
                return Ok(Vec::new()); // repo younger than the timestamp
            };
            let sha = commit.id().to_string();
            let tree = commit.tree()?;

            // Agent-relative result set (rollback's validator rebases to
            // root-relative). knowledge.jsonl is DELIBERATELY absent.
            let agent_rel_prefix = ".agent/memory";
            let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
            let map_path = format!("{memory_prefix}/_knowledge_map.yaml");
            if tree.get_path(Path::new(&map_path)).is_ok() {
                paths.insert(PathBuf::from(format!(
                    "{agent_rel_prefix}/_knowledge_map.yaml"
                )));
            }
            let syntheses_prefix = format!("{memory_prefix}/syntheses");
            // Adversarial-round F4 fix (2026-06-13): a cap-aborted
            // enumeration must NOT silently restore a lexicographic prefix
            // of the syntheses set as if it were complete — fail closed.
            let mut enumeration_capped = false;
            if let Ok(subtree_entry) = tree.get_path(Path::new(&syntheses_prefix)) {
                if let Ok(obj) = subtree_entry.to_object(&repo) {
                    if let Ok(subtree) = obj.peel_to_tree() {
                        let _ = subtree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
                            if paths.len() >= MAX_MEMORY_PATHS {
                                enumeration_capped = true;
                                return git2::TreeWalkResult::Abort as i32;
                            }
                            if entry.kind() == Some(ObjectType::Blob) {
                                let name = entry.name().unwrap_or("");
                                if name.ends_with(".md") {
                                    paths.insert(PathBuf::from(format!(
                                        "{agent_rel_prefix}/syntheses/{root}{name}"
                                    )));
                                }
                            }
                            git2::TreeWalkResult::Ok as i32
                        });
                    }
                }
            }
            if enumeration_capped {
                return Err(RollbackError::NotFound {
                    what: format!(
                        "rollback-memory syntheses enumeration cap exceeded \
                         (MAX_MEMORY_PATHS={MAX_MEMORY_PATHS}) — refusing a \
                         partial restore"
                    ),
                });
            }
            (sha, paths.into_iter().collect::<Vec<_>>())
        };

        if paths.is_empty() {
            return Ok(Vec::new()); // nothing existed at that state — no-op
        }
        self.rollback(
            agent_id,
            RollbackTarget::Commit(target_sha),
            RollbackMode::PathScoped(paths),
        )
        .await
    }
}

#[async_trait]
impl WorkspaceRollback for DefaultWorkspaceRollback {
    async fn rollback(
        &self,
        agent_id: &str,
        target: RollbackTarget,
        mode: RollbackMode,
    ) -> Result<Vec<PathBuf>, RollbackError> {
        // Slice E adversarial fix R2: when target is Checkpoint(label),
        // validate the label at the public boundary so the same
        // bidi/control/format-char filter that `rollback_to_checkpoint`
        // applies also guards this alternate entry point. Without this,
        // a caller with a RollbackTarget::Checkpoint(adversarial_label)
        // could bypass the label validator and reach the emit site with
        // attacker-controlled target_ref. Commit targets pass through
        // libgit2's Oid::from_str parser inside do_rollback; malformed
        // hex already yields InvalidTarget before any emit — no
        // additional validation needed for that arm.
        if let RollbackTarget::Checkpoint(label) = &target {
            crate::checkpoint::validate_ref_component(label, "label")
                .map_err(RollbackError::Checkpoint)?;
        }

        // Capture emit-side slots BEFORE moving `target` into the blocking
        // closure. `RollbackTarget` is `Clone`-able but we only need the
        // target_ref string + static kind literal — extracting them
        // up-front keeps the post-await emit block independent of the
        // closure's lifetime.
        let (target_ref_for_event, target_kind_for_event) = match &target {
            RollbackTarget::Commit(hex) => (hex.clone(), "version"),
            RollbackTarget::Checkpoint(label) => (label.clone(), "checkpoint"),
        };
        let agent_id_for_event = agent_id.to_string();
        let event_bus = Arc::clone(&self.event_bus);

        let canonical = self.canonical_repo.clone();
        let agent_id_in_closure = agent_id_for_event.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<PathBuf>, RollbackError> {
            let coord = git_repo_lock(&canonical);
            let _guard = coord.lock().expect("git coord mutex poisoned in rollback");
            let repo = open_repo_internal(&canonical)?;
            do_rollback(&repo, &canonical, &agent_id_in_closure, target, mode)
            // `_guard` dropped here — coord mutex released when the
            // closure returns. The emit below runs outside the lock.
        })
        .await
        .map_err(|e| {
            RollbackError::Io(std::io::Error::other(format!(
                "rollback worker join error: {e}"
            )))
        })?;

        // Emit `git.rollback` only on successful rollback with non-empty
        // affected_paths. The restructured early-return inside `do_rollback`
        // (`if checkout_paths.is_empty() && removal_paths.is_empty() { return
        // Ok(vec![]) }`) represents a vacuous rollback (neither a revert nor a
        // removal — no workdir change), so we skip the emit. A FullDirectory
        // rollback that ONLY removes post-target files returns a non-empty set
        // and DOES emit. See §3.8 "git.rollback event emission" for the full
        // rationale.
        if let Ok(ref paths) = result {
            if !paths.is_empty() {
                emit_rollback_event(
                    event_bus.as_ref(),
                    &agent_id_for_event,
                    &target_ref_for_event,
                    target_kind_for_event,
                    paths,
                );
            }
        }
        result
    }

    async fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
    ) -> Result<Vec<PathBuf>, RollbackError> {
        // Hold the coord mutex across tag probe AND the full rollback to
        // close the TOCTOU window surfaced in R1 audit. A single
        // spawn_blocking closure owns the lock from mode resolution through
        // checkout, so a concurrent delete/create cannot race between the
        // two steps. Matches §1.4.2 line 230-231's spec call pattern
        // semantically while preserving atomicity.
        //
        // Slice E: the emit runs OUTSIDE this critical section — see the
        // post-await block after spawn_blocking returns. target_kind is
        // fixed at "checkpoint"; target_ref is the label. Validate
        // agent_id + label up-front so a malformed label never flows into
        // the emit payload even in the rare case where a matching ref
        // exists in the ODB (defense-in-depth — libgit2's ref grammar
        // accepts unicode control chars + bidi overrides that could
        // otherwise reach JSONL/SQLite consumers via payload.target_ref).
        // Adversarial round 17 fix.
        crate::checkpoint::validate_ref_component(agent_id, "agent_id")
            .map_err(RollbackError::Checkpoint)?;
        crate::checkpoint::validate_ref_component(label, "label")
            .map_err(RollbackError::Checkpoint)?;

        let agent_id_for_event = agent_id.to_string();
        let label_for_event = label.to_string();
        let event_bus = Arc::clone(&self.event_bus);

        let canonical = self.canonical_repo.clone();
        let agent_id_in_closure = agent_id_for_event.clone();
        let label_in_closure = label_for_event.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<PathBuf>, RollbackError> {
            let coord = git_repo_lock(&canonical);
            let _guard = coord
                .lock()
                .expect("git coord mutex poisoned in rollback_to_checkpoint");
            let repo = open_repo_internal(&canonical)?;
            let (valid, paths) =
                resolve_checkpoint(&repo, &agent_id_in_closure, &label_in_closure)?;
            if !valid {
                return Err(RollbackError::Checkpoint(
                    crate::error::CheckpointError::InvalidState {
                        label: label_in_closure.clone(),
                        reason: "corrupt tag message schema".to_string(),
                    },
                ));
            }
            let mode = match paths {
                None => RollbackMode::FullDirectory,
                Some(v) if v.is_empty() => RollbackMode::FullDirectory,
                Some(v) => RollbackMode::PathScoped(v),
            };
            do_rollback(
                &repo,
                &canonical,
                &agent_id_in_closure,
                RollbackTarget::Checkpoint(label_in_closure),
                mode,
            )
        })
        .await
        .map_err(|e| {
            RollbackError::Io(std::io::Error::other(format!(
                "rollback_to_checkpoint worker join error: {e}"
            )))
        })?;

        // Emit `git.rollback` only on success with non-empty paths.
        // target_kind is fixed at "checkpoint"; target_ref is the label.
        if let Ok(ref paths) = result {
            if !paths.is_empty() {
                emit_rollback_event(
                    event_bus.as_ref(),
                    &agent_id_for_event,
                    &label_for_event,
                    "checkpoint",
                    paths,
                );
            }
        }
        result
    }

    fn memory_rollback_paths(&self, agent_id: &str) -> Result<Vec<PathBuf>, RollbackError> {
        let coord = git_repo_lock(&self.canonical_repo);
        let _guard = coord
            .lock()
            .expect("git coord mutex poisoned in memory_rollback_paths");
        // Validate agent_id (re-uses checkpoint validator so the set of
        // accepted agent_ids is consistent across all entry points).
        crate::checkpoint::validate_ref_component(agent_id, "agent_id")
            .map_err(RollbackError::Checkpoint)?;
        let repo = open_repo_internal(&self.canonical_repo)?;
        // Resolve agent_root so the emitted paths are relative to the
        // workspace root AND contain the caller agent's territory prefix.
        // Adversarial R2 C2 fix: PRD §11 places memory at
        // `<agent_root>/.agent/memory/...`, NOT `.agent/{agent_id}/memory/...`.
        // For the root agent, agent_root_rel is empty → prefix = `.agent/memory`.
        // For a child at `research/`, prefix = `research/.agent/memory`.
        let (_agent_root_abs, agent_root_rel) = resolve_agent_root(&self.canonical_repo, agent_id)?;
        let memory_prefix = if agent_root_rel.is_empty() {
            ".agent/memory".to_string()
        } else {
            format!("{agent_root_rel}/.agent/memory")
        };
        let head_tree = repo
            .head()
            .ok()
            .and_then(|h| h.peel_to_commit().ok())
            .and_then(|c| c.tree().ok());
        // Agent-relative prefix that callers feed back into rollback(PathScoped).
        // rollback's validator rebases agent-relative → root-relative internally.
        let agent_rel_prefix = ".agent/memory".to_string();
        let syntheses_prefix = format!("{memory_prefix}/syntheses");
        let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
        // Mandatory entries — returned even if absent from HEAD tree
        // (caller passes the set to rollback(PathScoped) which surfaces
        // `NotFound` if any target path is missing from the target commit).
        // Paths are AGENT-RELATIVE: rollback's validator rebases to
        // root-relative via agent_prefix, yielding e.g. `.agent/memory/foo`
        // for root agent and `research/.agent/memory/foo` for research.
        paths.insert(PathBuf::from(format!("{agent_rel_prefix}/knowledge.jsonl")));
        paths.insert(PathBuf::from(format!(
            "{agent_rel_prefix}/_knowledge_map.yaml"
        )));
        // Prefix-pruned walk of the syntheses subtree only — bounded by the
        // subtree size, not the whole repo. Resolves the O(total tree)
        // complaint surfaced in R1 audit. `tree.get_path` returns the tree
        // entry for the subtree; we then descend that subtree.
        if let Some(tree) = head_tree {
            if let Ok(subtree_entry) = tree.get_path(Path::new(&syntheses_prefix)) {
                if let Ok(obj) = subtree_entry.to_object(&repo) {
                    if let Ok(subtree) = obj.peel_to_tree() {
                        let _ = subtree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
                            // Adversarial W2 fix: cap result set to prevent
                            // a malicious agent from starving callers via
                            // a synthesis dir with millions of tiny `.md`
                            // files. PRD §11.6 does not pin an upper bound;
                            // 10k is >20× the realistic L6 corpus size.
                            if paths.len() >= MAX_MEMORY_PATHS {
                                return git2::TreeWalkResult::Abort as i32;
                            }
                            if entry.kind() == Some(ObjectType::Blob) {
                                let name = entry.name().unwrap_or("");
                                if name.ends_with(".md") {
                                    // `root` is subtree-relative; rebase with
                                    // the AGENT-relative syntheses prefix so
                                    // callers get agent-relative paths.
                                    let agent_rel_syntheses =
                                        format!("{agent_rel_prefix}/syntheses");
                                    let full = format!("{agent_rel_syntheses}/{root}{name}");
                                    paths.insert(PathBuf::from(full));
                                }
                            }
                            git2::TreeWalkResult::Ok as i32
                        });
                    }
                }
            }
        }
        Ok(paths.into_iter().collect())
    }
}

/// Internal: resolve a `checkpoint/{agent_id}/{label}` annotated tag to its
/// target commit Oid and parsed paths. Returns `(valid, paths)` with
/// `valid=false` when the tag message schema is violated (rollback rejects
/// invalid checkpoints fail-closed per AC-10).
fn resolve_checkpoint(
    repo: &Repository,
    agent_id: &str,
    label: &str,
) -> Result<(bool, Option<Vec<PathBuf>>), RollbackError> {
    let tag_name = format!("checkpoint/{agent_id}/{label}");
    let full_ref = format!("refs/tags/{tag_name}");
    let r = match repo.find_reference(&full_ref) {
        Ok(r) => r,
        Err(e) if e.code() == git2::ErrorCode::NotFound => {
            return Err(RollbackError::NotFound {
                what: format!("checkpoint {tag_name}"),
            });
        }
        Err(e) => return Err(RollbackError::from(e)),
    };
    // Annotated tag expected; lightweight tag (peel_to_tag fails) is
    // treated as legacy empty-message → (valid=true, None).
    match r.peel_to_tag() {
        Ok(tag) => {
            let (valid, paths) =
                crate::checkpoint::parse_tag_message(tag.message_bytes().unwrap_or(&[]));
            Ok((valid, paths))
        }
        Err(_) => Ok((true, None)),
    }
}

/// Internal rollback driver — runs inside the blocking closure after the
/// coord mutex has been acquired.
fn do_rollback(
    repo: &Repository,
    canonical_repo: &Path,
    agent_id: &str,
    target: RollbackTarget,
    mode: RollbackMode,
) -> Result<Vec<PathBuf>, RollbackError> {
    // Validate agent_id up front.
    crate::checkpoint::validate_ref_component(agent_id, "agent_id")
        .map_err(RollbackError::Checkpoint)?;

    // Resolve target → commit Oid.
    let target_oid = match target {
        RollbackTarget::Commit(hex) => {
            Oid::from_str(&hex).map_err(|_| RollbackError::InvalidTarget {
                target: hex,
                reason: "malformed commit hex".to_string(),
            })?
        }
        RollbackTarget::Checkpoint(ref label) => {
            let tag_name = format!("checkpoint/{agent_id}/{label}");
            let full_ref = format!("refs/tags/{tag_name}");
            let r = match repo.find_reference(&full_ref) {
                Ok(r) => r,
                Err(e) if e.code() == git2::ErrorCode::NotFound => {
                    return Err(RollbackError::NotFound {
                        what: format!("checkpoint {tag_name}"),
                    });
                }
                Err(e) => return Err(RollbackError::from(e)),
            };
            // Annotated: .target() points at the tag object; peel to commit.
            // Lightweight: .target() points directly at the commit.
            match r.peel_to_commit() {
                Ok(c) => c.id(),
                Err(e) => return Err(RollbackError::from(e)),
            }
        }
    };
    let target_commit = repo.find_commit(target_oid)?;
    let target_tree = target_commit.tree()?;

    // Resolve agent_id → agent_root (absolute path + root-relative string).
    // Prefer the caller-supplied canonical_repo for FS walks: `repo.workdir()`
    // can return an un-canonicalized path (macOS `/var` vs `/private/var`
    // asymmetry), which would desync from the coord-mutex key AND cause
    // `strip_prefix` mismatches when rebasing child-territory paths.
    // Adversarial W4/W5 fix.
    let workdir = canonical_repo;
    let (agent_root_abs, agent_root_rel) = resolve_agent_root(workdir, agent_id)?;

    // Compute current child-territory set for the agent (not the whole repo).
    let child_territories = detect_child_territories(&agent_root_abs)?;
    // Rebase child-territory paths to root-relative so they compare against
    // root-relative tree-walk paths in `expand_full_domain`.
    let child_territories_rel: Vec<PathBuf> = child_territories
        .iter()
        .map(|t| {
            if agent_root_rel.is_empty() {
                t.clone()
            } else {
                PathBuf::from(format!("{agent_root_rel}/{}", t.to_string_lossy()))
            }
        })
        .collect();

    // Expand path list according to mode. PathScoped paths are interpreted
    // relative to agent_root (rebased to root-relative for the checkout).
    //
    // `checkout_paths` = the writable-domain blobs in the TARGET tree to restore.
    // `removal_paths`  = FullDirectory-only: Git-tracked writable-domain files
    //   present in HEAD but ABSENT from the target tree (files added/committed
    //   after the target) → removed so the on-disk domain re-computes to match
    //   the target revision (PRD §7.2). PathScoped has NO removal set (it must
    //   touch only its caller-named paths). Both expansions reuse the SAME
    //   exclusions (.agent/, grandchild, hidden-runtime, .git, .meta.yaml,
    //   sqlite), and `expand_full_domain` walks a Git TREE (blobs only) — so
    //   untracked files (incl. an uncommitted `.gitignore`) are structurally
    //   unreachable and never removed.
    //
    // Case-folding policy: on a case-insensitive filesystem (repo
    // `core.ignorecase = true`, the libgit2-detected default on macOS/APFS and
    // Windows) a force-checkout resolves a case-variant path into the real
    // lowercase directory, so the exclusion string tests must compare
    // case-insensitively or `.AGENT/x` / `GC/x` would slip past the
    // `.agent`/territory guards and overwrite the private subtree or a live
    // grandchild (adversarial R17 C2). On a case-SENSITIVE FS we must NOT fold —
    // `worker/DATA` and `worker/data` are genuinely distinct and folding would
    // over-reject. Read the repo's own config so the policy tracks the real FS.
    // Fail SAFE on an unreadable/absent config: default to folding. Over-folding
    // can only over-reject a legitimate case-distinct path (a functional denial,
    // never a confinement breach), whereas under-folding would reopen the R17 C2
    // case-variant bypass. libgit2 writes `core.ignorecase` at init from a real
    // FS probe, so this default is reached only on config corruption (R18).
    let ignorecase = repo
        .config()
        .and_then(|c| c.get_bool("core.ignorecase"))
        .unwrap_or(true);
    let (checkout_paths, removal_paths): (Vec<PathBuf>, Vec<PathBuf>) = match mode {
        RollbackMode::FullDirectory => {
            let checkout_paths = expand_full_domain(
                &target_tree,
                &agent_root_rel,
                &child_territories_rel,
                ignorecase,
            )?;
            let removal_paths = match head_tree_for_removal(repo)? {
                Some(head_tree) => {
                    let head_domain = expand_full_domain(
                        &head_tree,
                        &agent_root_rel,
                        &child_territories_rel,
                        ignorecase,
                    )?;
                    // Case-fold the set membership when the FS is case-insensitive
                    // (R18): otherwise a case-only rename between HEAD and target
                    // (`File.md` vs `file.md`) classifies the HEAD path as a
                    // post-target ADDITION → the removal leg deletes the file the
                    // checkout just restored (same inode on a case-insensitive
                    // FS) = data loss. Exact compare on a case-sensitive FS.
                    let key = |p: &Path| -> String {
                        if ignorecase {
                            p.to_string_lossy().to_lowercase()
                        } else {
                            p.to_string_lossy().to_string()
                        }
                    };
                    let target_set: std::collections::HashSet<String> =
                        checkout_paths.iter().map(|p| key(p)).collect();
                    head_domain
                        .into_iter()
                        // Files in HEAD but not in the target tree = added after target.
                        .filter(|p| !target_set.contains(&key(p)))
                        // `.gitignore` is repo infrastructure — never removed even
                        // if it was committed after the target.
                        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some(".gitignore"))
                        .collect()
                }
                // Unborn HEAD → nothing tracked → nothing to remove.
                None => Vec::new(),
            };
            (checkout_paths, removal_paths)
        }
        RollbackMode::PathScoped(inputs) => {
            let checkout_paths = validate_and_check_path_scoped(
                inputs,
                agent_id,
                &agent_root_rel,
                &child_territories_rel,
                workdir,
                &target_tree,
                ignorecase,
            )?;
            (checkout_paths, Vec::new())
        }
    };

    if checkout_paths.is_empty() && removal_paths.is_empty() {
        return Ok(Vec::new());
    }

    // Check out each path from the target commit FIRST. `CheckoutBuilder::path`
    // restricts the checkout to the declared paths only — other workdir entries
    // are untouched. FORCE so tracked content is overwritten per §7.2
    // "git checkout <commit> -- <paths>" semantics. Checking out BEFORE the
    // removal lets libgit2's force strategy resolve file↔directory shape changes
    // in BOTH directions (a HEAD file whose target is a directory prefix, or a
    // HEAD directory whose target is a file): force removes the conflicting
    // workdir entry and re-materializes the target shape. The removal pass then
    // only needs to clear post-target ADDITIONS that the checkout did not touch.
    //
    // GUARD: an empty `CheckoutBuilder` with `.force()` adds NO path
    // restriction → `checkout_tree(target_tree, force)` would force-checkout the
    // ENTIRE target tree to the workdir root. Only build/run the checkout when
    // there is something to restore (the empty-target / removal-only case skips
    // it entirely).
    if !checkout_paths.is_empty() {
        // Pre-clear file↔directory shape conflicts. Some libgit2/Linux combos
        // fail force-checkout with `Exists: directory exists` when HEAD has a
        // FILE at a path prefix of a TARGET directory (or the reverse). Remove
        // the conflicting workdir entry before checkout so materialization can
        // proceed; the subsequent force-checkout restores the target shape.
        let workdir = repo.workdir().ok_or_else(|| RollbackError::NotFound {
            what: "repository workdir".into(),
        })?;
        clear_workdir_shape_conflicts(workdir, &checkout_paths)?;

        let mut builder = CheckoutBuilder::new();
        builder.force();
        // CRITICAL (Slice B adversarial R16 C1): `CheckoutBuilder::path` feeds
        // libgit2 a PATHSPEC, not an exact path — by default `*`/`?`/`[..]` are
        // glob metacharacters. A validated literal like `worker/*` (a file
        // actually named `*`, or a blob name carrying a glob char) would then
        // wildmatch-expand at checkout and reach siblings the per-path exclusion
        // never saw — empirically including the excluded `.agent/**` subtree.
        // `disable_pathspec_match(true)` sets GIT_CHECKOUT_DISABLE_PATHSPEC_MATCH
        // so every entry is treated as an exact path, eliminating the glob
        // expansion on BOTH the PathScoped and FullDirectory checkout legs.
        builder.disable_pathspec_match(true);
        for p in &checkout_paths {
            builder.path(p);
        }
        repo.checkout_tree(target_tree.as_object(), Some(&mut builder))?;
    }

    // Remove files added after the target (FullDirectory only; `removal_paths`
    // is empty for PathScoped). Worktree-only delete — HEAD/index are NOT moved;
    // the MODULE-002 reconciler + MODULE-004 index rebuild re-sync disk→index so
    // recall/list reflect the reverted on-disk state (SYS-AC-160).
    let mut removed: Vec<PathBuf> = Vec::with_capacity(removal_paths.len());
    for p in &removal_paths {
        // Refuse any path bearing a `..` component. A normal Git tree cannot
        // produce one (git/libgit2 validate entry names), but a hand-crafted
        // adversarial tree could — and a `..` that stays within the workdir
        // would otherwise escape the agent's writable SUBdomain (e.g.
        // `worker/../root-owned.md` resolves to a repo-root file). Mirrors the
        // PathScoped validator's traversal rejection. FAIL-CLOSED (skip).
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }
        let abs = workdir.join(p);
        let Some(par) = abs.parent() else {
            continue;
        };
        // Containment: the removal path's PARENT must be (a) SYMLINK-FREE — its
        // `canonicalize` must equal the lexical join, so ANY intermediate symlink
        // (even one pointing to another in-domain location like the agent's own
        // `.agent/` or a grandchild territory) makes them differ and is refused —
        // and (b) within the AGENT ROOT (`agent_root_abs`, not merely the
        // workdir). Together with the `..` rejection this confines the delete to
        // the agent's real, non-symlinked writable subtree, so a post-commit
        // symlink swap cannot redirect the delete into an excluded subdomain or
        // outside the agent. Mirrors the `resolve_agent_root` / `detect_child_territories`
        // symlink posture. (For the root agent `agent_root_abs == workdir`;
        // `workdir` is the canonical repo path.)
        match std::fs::canonicalize(par) {
            Ok(canon) => {
                if !(canon == par && canon.starts_with(&agent_root_abs)) {
                    continue; // symlink / out-of-agent-root → FAIL-CLOSED skip
                }
            }
            // The parent (or an ancestor) is GONE or was converted to a file by
            // the forced checkout — e.g. a dir→file shape change where this HEAD
            // addition lived UNDER a path the target makes a file (`worker/a/b/c.md`
            // when the target makes `worker/a` a file). The removal path can no
            // longer exist; the checkout already removed it → count as affected,
            // nothing to delete.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::NotADirectory =>
            {
                removed.push(p.clone());
                continue;
            }
            // Any other canonicalize error (e.g. permission) → FAIL-CLOSED skip.
            Err(_) => continue,
        }
        // If the forced checkout materialized a DIRECTORY at this path (a
        // file↔directory shape change where the HEAD blob's target counterpart
        // is a directory prefix), the file we would remove is already gone —
        // skip it. Use `symlink_metadata` rather than relying on
        // `remove_file`'s error kind, which differs across platforms (Linux
        // EISDIR vs macOS EPERM for `unlink` on a directory).
        match std::fs::symlink_metadata(&abs) {
            // A directory now lives here: the forced checkout converted this
            // HEAD file into a directory (file→dir shape change). The HEAD file
            // WAS removed (by the checkout), so count it as affected, but do NOT
            // `remove_file` the directory.
            Ok(m) if m.file_type().is_dir() => {
                removed.push(p.clone());
                continue;
            }
            Ok(_) => {}
            // Already gone — the file is absent (`NotFound`) or an ANCESTOR was
            // converted to a file by the checkout (`NotADirectory` / ENOTDIR — a
            // dir→file shape change where the HEAD added file lived under a path
            // the target makes a file). Either way the removal path can no longer
            // exist; count as removed, nothing left to delete.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::NotADirectory =>
            {
                removed.push(p.clone());
                continue;
            }
            Err(e) => return Err(RollbackError::Io(e)),
        }
        match std::fs::remove_file(&abs) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(RollbackError::Io(e)),
        }
        prune_empty_parents(
            workdir,
            p,
            &agent_root_rel,
            &child_territories_rel,
            ignorecase,
        );
        removed.push(p.clone());
    }

    // affected_paths = reverted ∪ actually-removed (the `git.rollback` event +
    // the downstream reconcilers observe both legs; a fail-closed-skipped path
    // was not touched, so it is excluded).
    let mut affected = checkout_paths;
    affected.extend(removed);
    Ok(affected)
}

/// Read the current HEAD commit's tree, or `None` when HEAD is unborn / the
/// commit / tree cannot be resolved. Used by FullDirectory rollback to compute
/// the `HEAD ∖ target` "added after the target" removal set. Mirrors the
/// `.ok()`-chained, fail-soft posture of `rollback_memory_files_at`.
/// Read the current HEAD commit's tree for the FullDirectory removal diff.
/// `Ok(None)` ONLY for an unborn HEAD (a fresh repo with no commits → nothing
/// tracked → no removal). A genuine resolution failure (corrupt/unresolvable
/// HEAD, peel, or tree) propagates as `Err` rather than silently disabling the
/// removal — so a broken repo fails closed instead of leaving post-target
/// additions behind unnoticed.
fn head_tree_for_removal(repo: &Repository) -> Result<Option<git2::Tree<'_>>, RollbackError> {
    match repo.head() {
        Ok(h) => {
            let commit = h.peel_to_commit()?;
            let tree = commit.tree()?;
            Ok(Some(tree))
        }
        Err(e) if e.code() == git2::ErrorCode::UnbornBranch => Ok(None),
        Err(e) => Err(RollbackError::from(e)),
    }
}

/// After removing a file at `removed_rel` (root-relative), prune now-empty
/// parent directories, ascending ONLY while the directory is empty AND strictly
/// inside the agent's writable domain AND not excluded
/// (`is_excluded_from_writable_domain`). Never deletes the agent root, an
/// excluded dir (`.agent/`, grandchild, hidden-runtime), or anything at/above
/// the agent root. Best-effort: any read/remove error or non-empty dir stops
/// the ascent.
/// Remove workdir entries that block libgit2 from materializing a target path
/// because of a file↔directory type conflict at a path prefix or leaf.
fn clear_workdir_shape_conflicts(
    workdir: &Path,
    checkout_paths: &[PathBuf],
) -> Result<(), RollbackError> {
    for p in checkout_paths {
        // Prefixes of a longer path must be directories. If a prefix is currently a
        // file (HEAD file → TARGET directory under it), remove the file.
        let mut prefix = PathBuf::new();
        let comps: Vec<_> = p.components().collect();
        for (idx, comp) in comps.iter().enumerate() {
            prefix.push(comp.as_os_str());
            if idx + 1 == comps.len() {
                break;
            }
            let abs = workdir.join(&prefix);
            match std::fs::symlink_metadata(&abs) {
                Ok(meta) if meta.file_type().is_file() || meta.file_type().is_symlink() => {
                    std::fs::remove_file(&abs).map_err(RollbackError::Io)?;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(RollbackError::Io(e)),
            }
        }
        // Leaf: if TARGET restores a blob (no longer checkout path is a strict
        // child of `p`) but workdir has a directory there, remove the directory.
        let has_child = checkout_paths
            .iter()
            .any(|other| other.starts_with(p) && other.as_path() != p.as_path());
        if !has_child {
            let abs = workdir.join(p);
            match std::fs::symlink_metadata(&abs) {
                Ok(meta) if meta.file_type().is_dir() => {
                    std::fs::remove_dir_all(&abs).map_err(RollbackError::Io)?;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(RollbackError::Io(e)),
            }
        }
    }
    Ok(())
}

fn prune_empty_parents(
    workdir: &Path,
    removed_rel: &Path,
    agent_root_rel: &str,
    child_territories: &[PathBuf],
    ignorecase: bool,
) {
    let agent_prefix = if agent_root_rel.is_empty() {
        String::new()
    } else {
        format!("{agent_root_rel}/")
    };
    let mut cur = removed_rel.parent();
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() {
            break;
        }
        let dir_str = dir.to_string_lossy();
        // Stay strictly inside the writable domain: stop at the agent root or
        // anything not under the agent prefix.
        if dir_str == agent_root_rel {
            break;
        }
        if !agent_prefix.is_empty() && !dir_str.starts_with(&agent_prefix) {
            break;
        }
        // Never prune an excluded directory (.agent/, grandchild, hidden-runtime).
        if is_excluded_from_writable_domain(
            &format!("{dir_str}/"),
            &agent_prefix,
            child_territories,
            ignorecase,
        ) {
            break;
        }
        let abs = workdir.join(dir);
        // Refuse to traverse/remove a symlinked component (consistent with the
        // module's symlink posture — `resolve_agent_root`/`detect_child_territories`
        // use `symlink_metadata`); only operate on a REAL directory.
        match std::fs::symlink_metadata(&abs) {
            Ok(m) if m.file_type().is_dir() => {}
            _ => break,
        }
        match std::fs::read_dir(&abs) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    break; // not empty → stop ascending
                }
            }
            Err(_) => break,
        }
        if std::fs::remove_dir(&abs).is_err() {
            break;
        }
        cur = dir.parent();
    }
}

/// FullDirectory expansion: walk `target_tree`, collect every blob path under
/// `agent_root_rel` (root-relative prefix, empty for root agent), exclude
/// `agent_root/.agent/**`, hidden runtime paths, and any path under a current
/// child territory. Matches PRD §7.2 + AC-05 + AC-15.
fn expand_full_domain(
    target_tree: &git2::Tree,
    agent_root_rel: &str,
    child_territories: &[PathBuf],
    ignorecase: bool,
) -> Result<Vec<PathBuf>, RollbackError> {
    let mut out: Vec<PathBuf> = Vec::new();
    let agent_prefix = if agent_root_rel.is_empty() {
        String::new()
    } else {
        format!("{agent_root_rel}/")
    };
    let mut visited: usize = 0;
    target_tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        // Bound total tree entries VISITED (not just blobs collected) against
        // an adversarial tree padded with millions of EXCLUDED entries (e.g.
        // under `.agent/**`) that never increment `out` and so would otherwise
        // dodge the MAX_FULL_DIRECTORY_PATHS abort below. Mirrors the
        // MAX_WALK_ENTRIES breadth cap on the FS walks. Adversarial R15 W5.
        visited += 1;
        if visited >= MAX_WALK_ENTRIES {
            return git2::TreeWalkResult::Abort as i32;
        }
        // Adversarial R2 W6 fix: bound full-directory output against an
        // adversarial target commit with millions of blobs.
        if out.len() >= MAX_FULL_DIRECTORY_PATHS {
            return git2::TreeWalkResult::Abort as i32;
        }
        if entry.kind() == Some(ObjectType::Blob) {
            // Skip non-UTF-8 blob names. `entry.name()` is `None` for a
            // non-UTF-8 name; collapsing it to `""` (the old `unwrap_or("")`)
            // would yield a directory-PREFIX path (`worker/`) that then enters
            // the checkout/removal set and force-acts on a whole subtree
            // (adversarial R16 C2). The writable domain is UTF-8-only (cap-fs
            // paths are WIT `string`), so a non-UTF-8 entry is foreign — leave
            // it untouched rather than over-reaching.
            let Some(name) = entry.name() else {
                return git2::TreeWalkResult::Ok as i32;
            };
            let full = format!("{root}{name}");
            // Restrict to agent's subtree for non-root agents.
            if !agent_prefix.is_empty() && !full.starts_with(&agent_prefix) {
                return git2::TreeWalkResult::Ok as i32;
            }
            if is_excluded_from_writable_domain(&full, &agent_prefix, child_territories, ignorecase)
            {
                return git2::TreeWalkResult::Ok as i32;
            }
            out.push(PathBuf::from(full));
        }
        git2::TreeWalkResult::Ok as i32
    })?;
    Ok(out)
}

/// Expand a PathScoped DIRECTORY input (`dir_rel`, root-relative, no trailing
/// slash) to its constituent writable target-tree blobs, RE-APPLYING the
/// per-blob writable-domain exclusions. A directory path reaches this when a
/// directory-scoped checkpoint tag (stored with a trailing slash by
/// `normalize_paths`) is rolled back. `disable_pathspec_match(true)` makes the
/// checkout treat each `path` as exact, so a directory entry would otherwise
/// force-check-out the whole subtree recursively, bypassing every per-blob
/// exclusion (.agent / .meta.yaml / sqlite / nested territory) that the
/// validator only evaluated against the directory path itself (R17 C1).
/// Expanding here restores the directory's writable contents WHILE keeping the
/// per-blob exclusions — directory-scoped rollback works (R18 regression fix)
/// without the recursive bypass. Prefix matching folds case under `ignorecase`.
fn expand_pathscoped_subtree(
    target_tree: &git2::Tree,
    dir_rel: &str,
    agent_prefix: &str,
    child_territories: &[PathBuf],
    ignorecase: bool,
) -> Result<Vec<PathBuf>, RollbackError> {
    let fold = |s: &str| -> String {
        if ignorecase {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let prefix_f = fold(&format!("{dir_rel}/"));
    let mut out: Vec<PathBuf> = Vec::new();
    let mut visited: usize = 0;
    target_tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        visited += 1;
        if visited >= MAX_WALK_ENTRIES || out.len() >= MAX_FULL_DIRECTORY_PATHS {
            return git2::TreeWalkResult::Abort as i32;
        }
        if entry.kind() == Some(ObjectType::Blob) {
            // Skip non-UTF-8 names (parity with `expand_full_domain`).
            if let Some(name) = entry.name() {
                let full = format!("{root}{name}");
                if fold(&full).starts_with(&prefix_f)
                    && !is_excluded_from_writable_domain(
                        &full,
                        agent_prefix,
                        child_territories,
                        ignorecase,
                    )
                {
                    out.push(PathBuf::from(full));
                }
            }
        }
        git2::TreeWalkResult::Ok as i32
    })?;
    Ok(out)
}

/// Whether a path is excluded from the writable domain per PRD §7.2.
/// `agent_prefix` is the root-relative agent root with trailing `/`, or
/// empty for the root agent.
fn is_excluded_from_writable_domain(
    path: &str,
    agent_prefix: &str,
    child_territories: &[PathBuf],
    ignorecase: bool,
) -> bool {
    // Case-folding policy (adversarial R17 C2): on a case-insensitive FS a
    // checkout of a case-variant path resolves into the real lowercase
    // directory, so the string tests below compare a folded path. On a
    // case-sensitive FS `fold` is the identity (distinct paths stay distinct).
    let fold = |s: &str| -> String {
        if ignorecase {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let path_f = fold(path);
    // ANY `.agent` path component anywhere — not only the caller's own. A nested
    // `.agent` belonging to a child/grandchild (INCLUDING a former one present
    // in the target tree but no longer a detected on-disk territory) is
    // agent-private and must never be checked out/removed by a workspace
    // rollback (PRD §7.2). Mirrors the PathScoped per-component `.agent`
    // rejection, closing the FullDirectory/PathScoped parity gap (adversarial
    // R17 W3) and subsuming the agent's-own `.agent/` case.
    for seg in path_f.split('/') {
        if seg == ".agent" {
            return true;
        }
    }
    // Hidden runtime top-level paths at the workspace root (only meaningful
    // when agent_prefix is empty — these live at the repo root). Exclude both
    // the subtree (`.runtime/...`) AND the exact root path (`.runtime`), so a
    // target tree holding a FILE at that exact path is never checked out over
    // the hidden-runtime directory.
    if agent_prefix.is_empty() {
        for banned in &[".runtime", ".advance", ".sub"] {
            if path_f == *banned || path_f.starts_with(&format!("{banned}/")) {
                return true;
            }
        }
    }
    // `.meta.yaml` (anywhere in tree — each dir has one).
    if path_f == ".meta.yaml" || path_f.ends_with("/.meta.yaml") {
        return true;
    }
    // SQLite files (though `.gitignore` already excludes them; defense in depth).
    for ext in &[".sqlite", ".sqlite-wal", ".sqlite-shm"] {
        if path_f.ends_with(ext) {
            return true;
        }
    }
    // `.git` — should never appear in a tree entry (libgit2 filters it), but
    // defense in depth. ALWAYS case-insensitive (matches the commit-queue
    // boundary), independent of the FS `ignorecase`.
    let path_lc = path.to_ascii_lowercase();
    if path_lc.starts_with(".git/") || path_lc == ".git" {
        return true;
    }
    // Child territory — exclude any path that OVERLAPS a detected child-territory
    // directory in ANY of the three exhaustive ways (a path either IS the
    // territory, is UNDER it, CONTAINS it as an ancestor, or is disjoint):
    //   (1) the exact territory root  (`worker/gc`),
    //   (2) the subtree under it      (`worker/gc/**`),
    //   (3) an ANCESTOR path of it    (`worker/data`, when `worker/data/gc` is the
    //       territory) — a target blob at an ancestor would force-checkout over
    //       the live territory directory and recursively destroy it.
    // A detected grandchild territory is entirely off-limits to the parent's
    // rollback (SYS-AC-159), on BOTH the checkout (target-tree) and removal
    // (HEAD-tree) walks. Disjoint sibling files under a shared ancestor (e.g.
    // `worker/data/sibling.md`) are NOT excluded — only paths that overlap the
    // territory itself.
    for t in child_territories {
        let s = t.to_string_lossy();
        let root = fold(s.trim_end_matches('/'));
        if path_f == root
            || path_f.starts_with(&format!("{root}/"))
            || root.starts_with(&format!("{path_f}/"))
        {
            return true;
        }
    }
    false
}

/// PathScoped validation: rejection matrix for each input, then verify
/// presence in either current workspace or target tree. Paths are
/// interpreted relative to `agent_root_rel` (root-relative prefix; empty for
/// root agent). The memory-rollback exception permits `.agent/{agent_id}/memory/**`
/// paths ONLY when the path's embedded agent segment matches the caller's
/// `agent_id` parameter — cross-agent memory overwrites are rejected.
fn validate_and_check_path_scoped(
    inputs: Vec<PathBuf>,
    _agent_id: &str,
    agent_root_rel: &str,
    child_territories: &[PathBuf],
    workdir: &Path,
    target_tree: &git2::Tree,
    ignorecase: bool,
) -> Result<Vec<PathBuf>, RollbackError> {
    let agent_prefix = if agent_root_rel.is_empty() {
        String::new()
    } else {
        format!("{agent_root_rel}/")
    };
    // Case-folding policy (adversarial R17 C2) — see `is_excluded_from_writable_domain`.
    let fold = |s: &str| -> String {
        if ignorecase {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let mut out: Vec<PathBuf> = Vec::with_capacity(inputs.len());
    for p in inputs {
        let raw = p.to_string_lossy();
        // Encoding.
        if raw.contains(char::REPLACEMENT_CHARACTER) {
            return Err(RollbackError::PermissionDenied {
                path: p,
                reason: DeniedReason::Encoding,
            });
        }
        if raw.chars().any(|c| c == '\0' || c.is_control()) {
            return Err(RollbackError::PermissionDenied {
                path: p,
                reason: DeniedReason::Encoding,
            });
        }
        let stripped = raw.strip_prefix("./").unwrap_or(&raw).to_string();
        // Absolute / backslash.
        if Path::new(&stripped).is_absolute() || stripped.contains('\\') {
            return Err(RollbackError::PermissionDenied {
                path: p,
                reason: DeniedReason::NotWritableDomain,
            });
        }
        // ParentDir rejection + canonical normalization in a single pass.
        // `Path::components()` collapses interior `.` (CurDir) and empty
        // (`//`) segments but does NOT rewrite the source string — so without
        // this rebuild `stripped` keeps the literal `data/./gc/x` while the
        // STRING-based child-territory and memory-prefix checks below test the
        // raw form. Adversarial R15 C1: `data/./gc/x` (or `data//gc/x`) then
        // slipped past the `worker/data/gc` overlap guard yet resolved through
        // libgit2 checkout to the grandchild file. Rebuilding from the
        // surviving Normal segments yields a canonical string so every
        // downstream string test is sound; ParentDir is rejected here.
        let mut canonical = String::new();
        for c in Path::new(&stripped).components() {
            match c {
                Component::ParentDir => {
                    return Err(RollbackError::PermissionDenied {
                        path: p,
                        reason: DeniedReason::ParentDirTraversal,
                    });
                }
                Component::Normal(seg) => {
                    if !canonical.is_empty() {
                        canonical.push('/');
                    }
                    canonical.push_str(&seg.to_string_lossy());
                }
                // CurDir collapsed; RootDir/Prefix are unreachable (the
                // absolute/backslash check above already rejected them).
                _ => {}
            }
        }
        if canonical.is_empty() {
            // The path normalized to nothing (e.g. `.` or `./`): there is no
            // concrete in-domain target to check out. Reject rather than
            // silently rolling back the whole agent root.
            return Err(RollbackError::PermissionDenied {
                path: p,
                reason: DeniedReason::NotWritableDomain,
            });
        }
        let stripped = canonical;
        // Rebase caller-supplied agent-relative path → root-relative.
        let rel_to_root = if agent_prefix.is_empty() {
            stripped.clone()
        } else {
            format!("{agent_prefix}{stripped}")
        };
        // Memory-rollback exception per PRD §11.6: accept the caller's own
        // memory subtree `<agent_root_rel>/.agent/memory/**`. For root agent,
        // prefix simplifies to `.agent/memory/`. All other `.agent` segments
        // (bare `.agent`, `<someone_else>/.agent/`, `<caller>/.agent/` but
        // not `/memory/`) are rejected below. Adversarial R2 C2 fix: PRD §11
        // places memory at `<agent_root>/.agent/memory/`, NOT at
        // `.agent/{agent_id}/memory/` — reject any pattern of the old
        // (incorrect) shape.
        let memory_root_prefix = if agent_root_rel.is_empty() {
            ".agent/memory/".to_string()
        } else {
            format!("{agent_root_rel}/.agent/memory/")
        };
        if fold(&rel_to_root).starts_with(&fold(&memory_root_prefix)) {
            // Memory path — existence check and push. No further hidden-
            // runtime or child-territory checks: the caller's own memory
            // subtree is always accepted.
            let in_workdir = !workdir.as_os_str().is_empty()
                && std::fs::symlink_metadata(workdir.join(&rel_to_root)).is_ok();
            let in_target = target_tree.get_path(Path::new(&rel_to_root)).is_ok();
            if !in_workdir && !in_target {
                return Err(RollbackError::NotFound {
                    what: rel_to_root.clone(),
                });
            }
            out.push(PathBuf::from(rel_to_root));
            continue;
        }
        // Any `.agent` component anywhere → reject. Catches: bare `.agent`
        // (adversarial R2 C1 fix), `.agent/config.yaml`,
        // `<someone_else>/.agent/memory/**` (cross-agent memory overwrite
        // surfaced in R1 audit), and `.agent/<non-memory>/**`.
        for c in Path::new(&rel_to_root).components() {
            if matches!(c, Component::Normal(n) if fold(&n.to_string_lossy()) == ".agent") {
                return Err(RollbackError::PermissionDenied {
                    path: p,
                    reason: DeniedReason::DotAgentOutsideMemoryRollback,
                });
            }
        }
        // Hidden runtime per-component check on the rooted form.
        for c in Path::new(&rel_to_root).components() {
            if let Component::Normal(name) = c {
                let n = name.to_string_lossy();
                let nl = n.to_lowercase();
                if nl == ".git"
                    || nl == ".meta.yaml"
                    || nl == ".runtime"
                    || nl == ".advance"
                    || nl == ".sub"
                    || nl.ends_with(".sqlite")
                    || nl.ends_with(".sqlite-wal")
                    || nl.ends_with(".sqlite-shm")
                {
                    return Err(RollbackError::PermissionDenied {
                        path: p,
                        reason: DeniedReason::HiddenRuntimePath,
                    });
                }
            }
        }
        // Child-territory overlap — child_territories are root-relative. Reject
        // EXHAUSTIVELY over overlap (the same IS / UNDER / ANCESTOR predicate as
        // `is_excluded_from_writable_domain`): a PathScoped path that IS a
        // territory root, is UNDER it, OR is an ANCESTOR of it (a force-checkout
        // of an ancestor file would recursively destroy the live grandchild
        // directory). The ANCESTOR arm was previously missing here while the
        // FullDirectory path had it — closing the asymmetry.
        let rel_f = fold(&rel_to_root);
        for t in child_territories {
            let s = t.to_string_lossy();
            let root = fold(s.trim_end_matches('/'));
            if rel_f == root
                || rel_f.starts_with(&format!("{root}/"))
                || root.starts_with(&format!("{rel_f}/"))
            {
                return Err(RollbackError::PermissionDenied {
                    path: p,
                    reason: DeniedReason::ChildTerritoryOverlap,
                });
            }
        }
        // Existence: path must exist in either the current workspace or the
        // target commit tree — otherwise there is nothing to check out.
        // Adversarial W3 fix: symlink-safe existence check (see earlier comment).
        let in_workdir = !workdir.as_os_str().is_empty()
            && std::fs::symlink_metadata(workdir.join(&rel_to_root)).is_ok();
        let target_entry = target_tree.get_path(Path::new(&rel_to_root)).ok();
        if !in_workdir && target_entry.is_none() {
            return Err(RollbackError::NotFound {
                what: rel_to_root.clone(),
            });
        }
        // A PathScoped path that resolves to a TREE (directory) in the target
        // must NOT be pushed verbatim: with `disable_pathspec_match` the checkout
        // treats it as an exact directory and force-checks-out the ENTIRE subtree
        // recursively, bypassing every per-blob exclusion above (.agent /
        // .meta.yaml / sqlite / nested territory) that was evaluated only against
        // the directory path itself (adversarial R17 C1; empirically a
        // PathScoped(["data"]) restored data/inner/.agent/config.yaml +
        // data/secret.sqlite). EXPAND the directory to its writable blobs with
        // the per-blob exclusions re-applied — this keeps directory-scoped
        // checkpoint rollback working (R18 regression fix) without the recursive
        // bypass. (A workdir-only path absent from the target is a checkout
        // no-op — nothing to expand.)
        if let Some(entry) = &target_entry {
            if entry.kind() != Some(ObjectType::Blob) {
                out.extend(expand_pathscoped_subtree(
                    target_tree,
                    &rel_to_root,
                    &agent_prefix,
                    child_territories,
                    ignorecase,
                )?);
                continue;
            }
        }
        out.push(PathBuf::from(rel_to_root));
    }
    Ok(out)
}

/// Detect child territories in the current workspace via the PRD §6.2
/// single-signal rule: a directory is a child's territory iff it contains
/// a `.agent/` subdirectory. Symlink-safe via `symlink_metadata` + `is_dir()`
/// on the raw metadata (rejects symlinked `.agent/` markers — Slice A R1/R2
/// adversarial-pattern precedent).
///
/// Walk is depth-first from `workdir`, excluding `workdir/.agent/` itself
/// (otherwise we'd flag the workspace root as its own child). When a
/// `.agent/` marker is found on descendant D, record D and SKIP D's subtree
/// (grandchildren are the child's problem).
fn detect_child_territories(workdir: &Path) -> Result<Vec<PathBuf>, RollbackError> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<(PathBuf, u32)> = Vec::new();
    let mut visited: usize = 0;
    stack.push((workdir.to_path_buf(), 0));
    while let Some((dir, depth)) = stack.pop() {
        // Bound walk depth + breadth against adversarially deep/wide trees
        // (adversarial R1 W1 + R2 W5 fixes).
        if depth > MAX_WALK_DEPTH {
            continue;
        }
        if visited >= MAX_WALK_ENTRIES {
            // Fail closed — partial child-territory list could mis-classify
            // paths and enable cross-agent writes.
            return Err(RollbackError::Io(std::io::Error::other(
                "child-territory walk cap exceeded",
            )));
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited >= MAX_WALK_ENTRIES {
                // Fail closed — parity with the top-of-loop cap above. A bare
                // `break` only exits the inner loop; if this is the last stacked
                // directory the `while let` then drains empty and falls through
                // to `Ok(out)`, returning a PARTIAL child-territory list
                // (adversarial R16 W4). A missed territory would not be excluded
                // → cross-agent checkout/removal. A capped scan must never be
                // presented as a complete one.
                return Err(RollbackError::Io(std::io::Error::other(
                    "child-territory walk cap exceeded",
                )));
            }
            let path = entry.path();
            // Skip `.git` / `.agent` / `.runtime` / `.advance` / `.sub`
            // at the root level — those aren't child territories.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == ".git" || name == ".runtime" || name == ".advance" || name == ".sub" {
                continue;
            }
            // Skip the workdir's own .agent/ (we're walking workdir as
            // "root agent"; its .agent/ is its own private subtree, not a
            // child territory).
            if dir == workdir && name == ".agent" {
                continue;
            }
            // We only care about real directories, not symlinks, for the
            // purposes of child-territory detection.
            let md = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_dir() {
                continue;
            }
            // Check for `.agent/` marker. Use symlink_metadata so a symlinked
            // marker is not recognized (prevents adversarial subdir from
            // faking child-territory status via symlink).
            let marker = path.join(".agent");
            let marker_is_real_dir = std::fs::symlink_metadata(&marker)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            if marker_is_real_dir {
                // Record relative-to-workdir path.
                if let Ok(rel) = path.strip_prefix(workdir) {
                    out.push(rel.to_path_buf());
                }
                // Skip subtree (grandchildren are the child's responsibility).
                continue;
            }
            // Not a child territory — recurse with depth increment.
            stack.push((path, depth + 1));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_excluded_rejects_root_dotagent() {
        // Root agent (empty prefix) — `.agent/` is the root agent's own private area.
        assert!(is_excluded_from_writable_domain(
            ".agent/memory/knowledge.jsonl",
            "",
            &[],
            false
        ));
    }

    #[test]
    fn is_excluded_rejects_child_own_dotagent() {
        // Child agent at `research/` — its `.agent/` is `research/.agent/`.
        assert!(is_excluded_from_writable_domain(
            "research/.agent/config.yaml",
            "research/",
            &[],
            false
        ));
    }

    #[test]
    fn is_excluded_rejects_any_nested_dotagent() {
        // R17 W3: ANY `.agent` component is excluded — including a nested
        // non-own one that is NOT a currently-detected child territory.
        assert!(is_excluded_from_writable_domain(
            "worker/oldchild/.agent/config.yaml",
            "worker/",
            &[],
            false
        ));
    }

    #[test]
    fn is_excluded_rejects_meta_yaml() {
        assert!(is_excluded_from_writable_domain(
            ".meta.yaml",
            "",
            &[],
            false
        ));
        assert!(is_excluded_from_writable_domain(
            "data/.meta.yaml",
            "",
            &[],
            false
        ));
    }

    #[test]
    fn is_excluded_rejects_sqlite() {
        assert!(is_excluded_from_writable_domain(
            "index.sqlite",
            "",
            &[],
            false
        ));
        assert!(is_excluded_from_writable_domain(
            "foo.sqlite-wal",
            "",
            &[],
            false
        ));
    }

    #[test]
    fn is_excluded_rejects_child_territory() {
        let territories = vec![PathBuf::from("research")];
        assert!(is_excluded_from_writable_domain(
            "research/data.md",
            "",
            &territories,
            false
        ));
        assert!(!is_excluded_from_writable_domain(
            "writer/data.md",
            "",
            &territories,
            false
        ));
    }

    #[test]
    fn is_excluded_case_insensitive_git() {
        // Case-insensitive filesystems: `.Git/` must be rejected for parity
        // with commit_queue's `.eq_ignore_ascii_case(".git")` check.
        assert!(is_excluded_from_writable_domain(
            ".Git/config",
            "",
            &[],
            false
        ));
    }

    #[test]
    fn is_excluded_ignorecase_folds_dotagent_and_territory() {
        // R17 C2: with `ignorecase=true`, a case-variant of `.agent` or a child
        // territory IS excluded (the checkout would resolve into the lowercase
        // dir on a case-insensitive FS). With `ignorecase=false` it is NOT
        // (distinct paths on a case-sensitive FS — no over-rejection).
        let terr = vec![PathBuf::from("worker/gc")];
        assert!(is_excluded_from_writable_domain(
            "worker/.AGENT/secret.md",
            "worker/",
            &[],
            true
        ));
        assert!(is_excluded_from_writable_domain(
            "worker/GC/secret.md",
            "worker/",
            &terr,
            true
        ));
        assert!(!is_excluded_from_writable_domain(
            "worker/.AGENT/secret.md",
            "worker/",
            &[],
            false
        ));
        assert!(!is_excluded_from_writable_domain(
            "worker/GC/secret.md",
            "worker/",
            &terr,
            false
        ));
    }

    #[test]
    fn is_excluded_accepts_normal_path() {
        assert!(!is_excluded_from_writable_domain(
            "data/report.md",
            "",
            &[],
            false
        ));
    }

    #[test]
    fn read_config_extracts_agent_id() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "agent_id: my-agent\nother: value\n").unwrap();
        let id = read_config_agent_id_safe(&f).unwrap();
        assert_eq!(id, "my-agent");
    }

    #[test]
    fn read_config_strips_quotes() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "agent_id: \"quoted-id\"\n").unwrap();
        let id = read_config_agent_id_safe(&f).unwrap();
        assert_eq!(id, "quoted-id");
    }

    #[test]
    fn read_config_rejects_yaml_alias_anchor() {
        // Adversarial R4 Critical regression: `&anchor` + `*alias` syntax
        // would previously let an attacker redirect `agent_id` to the
        // anchor's value without triggering the duplicate-key pre-scan.
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "_x: &a research\nagent_id: *a\n").unwrap();
        let err = read_config_agent_id_safe(&f).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_config_rejects_flow_mapping() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "{agent_id: alice, agent_id: research}\n").unwrap();
        let err = read_config_agent_id_safe(&f).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_config_rejects_duplicate_block_key() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "agent_id: alice\nagent_id: research\n").unwrap();
        let err = read_config_agent_id_safe(&f).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_config_rejects_merge_key() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "agent_id: alice\n<<: other\n").unwrap();
        let err = read_config_agent_id_safe(&f).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_config_rejects_block_scalar_pipe() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "agent_id: |\n  research\n").unwrap();
        let err = read_config_agent_id_safe(&f).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_config_rejects_quoted_newline_in_value() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        // YAML double-quoted strings support C-style escapes, so `\n` becomes a literal newline.
        std::fs::write(&f, "agent_id: \"alice\\nresearch\"\n").unwrap();
        let err = read_config_agent_id_safe(&f).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_config_rejects_slash_in_value() {
        let td = tempfile::TempDir::new().unwrap();
        let f = td.path().join("config.yaml");
        std::fs::write(&f, "agent_id: alice/research\n").unwrap();
        let err = read_config_agent_id_safe(&f).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
