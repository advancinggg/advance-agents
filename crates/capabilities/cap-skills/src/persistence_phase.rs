//! AutoLoopDriver micro-lane persistence-phase coordinator (Slice H,
//! PRD §12.6.4 + §15.3.16B foundation).
//!
//! NARROW SCOPE — rollback-skill + delete-skill called from `runtime:auto-loop`
//! context. Activate-skill (turn lane) NOT handled here. NOT wired into
//! existing host_fn handlers. NOT exercised by AutoLoopDriver (future slice).
//! This is foundation library API for a future MODULE-014+MODULE-015 bridge
//! slice that closes AC-21 + AC-22 jointly.

use advance_git::{CommitRequest, CommitType, GitCommitQueue};
use advance_shared_types::event::Event;
use advance_shared_types::skills::{Provenance, TrustLevel};
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::SkillError;
use crate::lifecycle::SkillStore;
use crate::persistence::DiskSkillStorage;

/// Per-call provenance for the persistence-phase orchestrator.
///
/// - `AutoLoop` — the Slice-H micro lane (`runtime:auto-loop` initiator,
///   `CommitType::Micro`); used by the future MODULE-014 auto-loop bridge.
/// - `Agent { id }` — Wave-10 Lane C turn lane: an agent-initiated skill op
///   (`agent:{id}` initiator, `CommitType::Turn`). Per MODULE-017-AC-22, agent
///   skill changes commit as `turn`; `micro` stays reserved for `runtime:auto-loop`.
#[derive(Debug, Clone)]
pub enum Initiator {
    AutoLoop,
    Agent { id: String },
}

/// Wave-18 Lane 2 — record-side hook for the AutoLoop micro lane.
///
/// When an agent activates a skill DURING an auto iteration, the pre-activation
/// version must be recorded so a later iteration discard can restore it
/// (MODULE-017-AC-06). cap-skills must NOT depend on `scheduler/auto-loop`, so
/// the coordinator calls this dependency-inverted port; the cli production impl
/// (`DriverPreActivationObserver`) forwards to
/// `DefaultAutoLoopDriver::record_skill_pre_activation`, which is session-gated
/// (a no-op when no auto session is live for `agent_id`). Synchronous — the
/// driver method is a sync, non-blocking map insert. Default-`None` on the
/// coordinator keeps the agent turn lane byte-identical.
pub trait SkillPreActivationObserver: Send + Sync {
    /// Called BEFORE an activate mutation with the skill's CURRENT active
    /// version (`None` ⇒ the skill is absent / freshly created this activate).
    fn observe_pre_activation(&self, agent_id: &str, skill_id: &str, prev_version: Option<u32>);
}

impl Initiator {
    pub fn commit_type(&self) -> CommitType {
        match self {
            Initiator::AutoLoop => CommitType::Micro,
            Initiator::Agent { .. } => CommitType::Turn,
        }
    }

    /// Initiator audit string written into the commit-message prefix. Returns an
    /// owned `String` (Wave-10: the `Agent` arm is dynamic — `"agent:{id}"`);
    /// `CommitRequest::new` takes `impl Into<String>`, so a `String` is accepted.
    pub fn initiator_string(&self) -> String {
        match self {
            Initiator::AutoLoop => "runtime:auto-loop".to_string(),
            Initiator::Agent { id } => format!("agent:{id}"),
        }
    }
}

/// Per-agent persistence-phase coordinator. ONE coordinator binds to ONE
/// `agent_id` + ONE `agent_root`. The internal `SkillStore` is constructed
/// from a `DiskSkillStorage::with_default_writer(canonical_root)` (no caller-
/// injectable storage decoupling). PRD §12.6.5 single-flight invariant applies
/// — see M017 §3.6 (yy).
pub struct SkillPersistenceCoordinator {
    agent_id: String,
    agent_root: PathBuf,
    /// Wave-10 Lane C: `Arc<tokio::sync::Mutex<SkillStore>>` (was a bare
    /// `SkillStore`). `with_shared_store` lets the coordinator hold the SAME
    /// store the `SingleAgentSkillStoreProvider` resolves, so all eight skills
    /// host-fns serialize on ONE mutex. Each `*_with_persistence` method holds
    /// the guard across read→mutate→submit→commit-await→emit (commit-bytes
    /// correctness); the guard is bound once (the mutex is non-reentrant).
    skill_store: Arc<tokio::sync::Mutex<SkillStore>>,
    commit_queue: Arc<dyn GitCommitQueue>,
    event_bus: Arc<dyn EventBusEmit>,
    /// Wave-18 Lane 2 (additive, default `None`): record-side hook fired BEFORE
    /// an activate mutation so the AutoLoop driver can snapshot the
    /// pre-activation version (MODULE-017-AC-06). `None` ⇒ byte-identical turn
    /// lane (the agent activate/rollback emitters, SH-* tests, SYS-AC-076/077).
    pre_activation_observer: Option<Arc<dyn SkillPreActivationObserver>>,
}

impl SkillPersistenceCoordinator {
    /// Foundation constructor (Slice H). Canonicalizes `agent_root` (or falls
    /// back to raw path if canonicalize fails — symmetric with
    /// `DiskSkillStorage::with_default_writer`'s internal fallback) so the
    /// coordinator and its internal storage hold the same effective root. Owns
    /// its own `SkillStore` (wrapped in a fresh mutex) — used by the AutoLoop
    /// foundation + its tests. Production turn-lane wiring uses
    /// `with_shared_store` instead (to share the provider's store).
    pub fn new(
        agent_id: String,
        agent_root: PathBuf,
        commit_queue: Arc<dyn GitCommitQueue>,
        event_bus: Arc<dyn EventBusEmit>,
    ) -> Self {
        let canonical_root = std::fs::canonicalize(&agent_root).unwrap_or(agent_root);
        let storage = Arc::new(DiskSkillStorage::with_default_writer(
            canonical_root.clone(),
        ));
        let skill_store = SkillStore::with_storage(storage);
        Self {
            agent_id,
            agent_root: canonical_root,
            skill_store: Arc::new(tokio::sync::Mutex::new(skill_store)),
            commit_queue,
            event_bus,
            pre_activation_observer: None,
        }
    }

    /// Wave-10 Lane C production constructor. Binds to a CALLER-supplied
    /// `Arc<tokio::sync::Mutex<SkillStore>>` — typically the exact store the
    /// `SingleAgentSkillStoreProvider` resolves (`provider.get(agent_id).await`)
    /// — so the coordinator-routed activate/rollback and the six provider-routed
    /// handlers serialize on the SAME mutex (no two-stores-over-one-root
    /// divergence). `agent_root` MUST equal the root the shared store's
    /// `DiskSkillStorage` was constructed with, so the coordinator's
    /// `affected_paths` (`agent_root/.agent/skills/...`) match the store's
    /// on-disk writes. Canonicalized symmetrically with `new`.
    pub fn with_shared_store(
        agent_id: String,
        agent_root: PathBuf,
        skill_store: Arc<tokio::sync::Mutex<SkillStore>>,
        commit_queue: Arc<dyn GitCommitQueue>,
        event_bus: Arc<dyn EventBusEmit>,
    ) -> Self {
        let canonical_root = std::fs::canonicalize(&agent_root).unwrap_or(agent_root);
        Self {
            agent_id,
            agent_root: canonical_root,
            skill_store,
            commit_queue,
            event_bus,
            pre_activation_observer: None,
        }
    }

    /// Wave-18 Lane 2 additive builder: attach the record-side observer. Chained
    /// before `Arc::new` in the cli `wire_capabilities` skills arm (the observer
    /// wraps the in-scope `auto_loop_driver`); left `None` everywhere else, so
    /// the turn lane is byte-identical. First-write-wins is not relevant — only
    /// the cli composition calls it, exactly once.
    pub fn with_pre_activation_observer(
        mut self,
        observer: Arc<dyn SkillPreActivationObserver>,
    ) -> Self {
        self.pre_activation_observer = Some(observer);
        self
    }

    /// The agent this coordinator is bound to. Used by the host-fn isolation
    /// guard: a coordinator-routed call whose `ctx.agent_id` differs is rejected
    /// with `SkillNotFound` (mirrors `SingleAgentSkillStoreProvider::get`).
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub(crate) fn agent_root(&self) -> &std::path::Path {
        &self.agent_root
    }

    /// Rollback `skill_id` to `version` and durably commit + emit per PRD
    /// §12.6.4 steps 2 + 3. Storage-flush is delegated to
    /// `SkillStore::rollback`; the coordinator does NOT implement the PRD's
    /// Step 1 (overlay → disk flush of runtime-private files like `_drafts/`
    /// or `_skill_candidates.jsonl`), which remains deferred to the future
    /// MODULE-014 integrated-loop slice (see M017 §3.6 (uu)).
    pub async fn rollback_skill_with_persistence(
        &self,
        _initiator: Initiator,
        skill_id: &str,
        version: u32,
        reason: &str,
    ) -> Result<RolledBack, SkillError> {
        // Wave-10 Lane C: bind the shared-store guard ONCE and hold it across
        // read → mutate → submit → commit-await → emit (the mutex is
        // non-reentrant — never re-lock inside this method). This serializes the
        // whole op against every OTHER SkillStore op (all share this mutex), so
        // the git worker stages the bytes this op wrote without a concurrent
        // SkillStore op overwriting them mid-stage. NOTE (R9 adversarial Info):
        // this does NOT serialize against a cap-fs co-writer to the same hidden
        // `.agent/skills/...` path (cap-fs does not hold this mutex) — that
        // cross-capability window is pre-existing + bounded only by the queue's
        // own per-repo coord mutex (see M017 §3.6 (aaa)).
        let guard = self.skill_store.lock().await;
        let prior = guard.get(skill_id).await?;
        let prior_version = prior.version;
        let skill_name = prior.name.clone();

        // Storage flush via SkillStore (NOT the PRD §12.6.4 Step 1 overlay-to-
        // disk flush, which remains deferred — see M017 §3.6 (uu)). Not atomic
        // across write_version + write_active (see M017 §3.6 (vv)); on inner
        // failure, partial state may persist.
        guard.rollback(skill_id, version).await?;

        // Step 2 — build affected_paths + submit commit.
        let affected_paths = vec![
            self.agent_root
                .join(".agent")
                .join("skills")
                .join(skill_id)
                .join("SKILL.md"),
            self.agent_root
                .join(".agent")
                .join("skills")
                .join(skill_id)
                .join(".meta.yaml"),
            self.agent_root
                .join(".agent")
                .join("_skill_versions")
                .join(skill_id)
                .join(format!("v{}.md", prior_version)),
        ];
        let req = CommitRequest::new(
            self.agent_id.clone(),
            format!("rollback {} v{}", skill_id, version),
            affected_paths,
            _initiator.commit_type(),
            _initiator.initiator_string(),
        );
        let rx = self.commit_queue.submit(req);
        let oid_result = rx
            .await
            .map_err(|_| SkillError::InvalidTransition("commit worker closed".to_string()))?;
        let oid = oid_result.map_err(|e| {
            // R2 ADVERSARIAL fix: fixed safe-class string — do NOT format
            // the GitError into the SkillError payload (its Display impl
            // includes verbatim paths for PathOutsideWorkdir / Io variants).
            // The rich GitError is logged host-side via eprintln; only the
            // safe-class string crosses back to the bridge caller. Mirrors
            // cap-tools SB-22 redaction discipline (cf. M017 §2.9 line 988).
            eprintln!(
                "cap-skills SkillPersistenceCoordinator: git commit failed: {}",
                e
            );
            SkillError::InvalidTransition("git commit failed".to_string())
        })?;
        let commit_sha = oid.to_string();

        // Step 3 — emit AFTER commit success. PRD §15.3.16B payload schema.
        let new_version = prior_version.checked_add(1).ok_or_else(|| {
            SkillError::InvalidTransition(format!("version overflow: prior={}", prior_version))
        })?;
        // R1 AUDIT Warning #3 — clamp caller-supplied `reason` to bound the
        // event payload growth (PRD §15.3.16B doesn't specify a cap, but
        // existing lifecycle.rs MAX_REASON_LEN=1024 is the in-tree precedent).
        let bounded_reason: String = reason.chars().take(MAX_REASON_LEN_CHARS).collect();
        let payload = json!({
            "agent_id": self.agent_id,
            "skill_id": skill_id,
            "skill_name": skill_name,
            "from_version": prior_version,
            "to_version": new_version,
            "reason": bounded_reason,
        });
        self.event_bus.emit(Event {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: self.agent_id.clone(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            event_type: "skill.rolled_back".to_string(),
            payload,
            duration_ms: None,
        });
        Ok(RolledBack {
            commit_sha,
            new_version,
        })
    }

    /// Delete `skill_id` and durably commit + emit. Performs an inline
    /// trust-gate (matching `lifecycle::delete_allowed` semantics —
    /// AgentCreated+Untrusted only) AFTER the `skill_store.get(skill_id)`
    /// read (which reads SKILL.md + .meta.yaml via DiskSkillStorage) but
    /// BEFORE the recursive `enumerate_skill_dir_recursive` sidecar walk.
    /// For Trusted / Imported+Untrusted skills, returns `TrustViolation`
    /// before recursive enumeration runs (matches cap-skills `persistence.rs`
    /// precedent where the storage-layer trust gate runs inside
    /// `SkillStore::delete` after similar initial reads).
    pub async fn delete_skill_with_persistence(
        &self,
        _initiator: Initiator,
        skill_id: &str,
        reason: &str,
    ) -> Result<Deleted, SkillError> {
        // Wave-10 Lane C: hold the shared-store guard across the whole op (see
        // rollback_skill_with_persistence). The enumerate walk below is plain
        // filesystem I/O (not a SkillStore call), so holding the guard across it
        // is safe and keeps the affected_paths snapshot consistent with delete.
        let guard = self.skill_store.lock().await;
        let prior = guard.get(skill_id).await?;
        let prior_version = prior.version;
        let skill_name = prior.name.clone();

        let delete_allowed = matches!(
            (&prior.provenance, &prior.trust_level),
            (Provenance::AgentCreated, TrustLevel::Untrusted)
        );
        if !delete_allowed {
            return Err(SkillError::TrustViolation(skill_id.to_string()));
        }

        let skill_dir = self.agent_root.join(".agent").join("skills").join(skill_id);
        let mut affected_paths = enumerate_skill_dir_recursive(&skill_dir)
            .await
            .map_err(|e| {
                SkillError::InvalidTransition(format!(
                    "failed to enumerate skill dir for delete commit: {}",
                    e
                ))
            })?;
        affected_paths.push(
            self.agent_root
                .join(".agent")
                .join("_skill_versions")
                .join(skill_id)
                .join(format!("v{}.md", prior_version)),
        );

        guard.delete(skill_id).await?;

        let req = CommitRequest::new(
            self.agent_id.clone(),
            format!("delete {}", skill_id),
            affected_paths,
            _initiator.commit_type(),
            _initiator.initiator_string(),
        );
        let rx = self.commit_queue.submit(req);
        let oid_result = rx
            .await
            .map_err(|_| SkillError::InvalidTransition("commit worker closed".to_string()))?;
        let oid = oid_result.map_err(|e| {
            // R2 ADVERSARIAL fix: fixed safe-class string — do NOT format
            // the GitError into the SkillError payload (its Display impl
            // includes verbatim paths for PathOutsideWorkdir / Io variants).
            // The rich GitError is logged host-side via eprintln; only the
            // safe-class string crosses back to the bridge caller. Mirrors
            // cap-tools SB-22 redaction discipline (cf. M017 §2.9 line 988).
            eprintln!(
                "cap-skills SkillPersistenceCoordinator: git commit failed: {}",
                e
            );
            SkillError::InvalidTransition("git commit failed".to_string())
        })?;
        let commit_sha = oid.to_string();

        let bounded_reason: String = reason.chars().take(MAX_REASON_LEN_CHARS).collect();
        let payload = json!({
            "agent_id": self.agent_id,
            "skill_id": skill_id,
            "skill_name": skill_name,
            "reason": bounded_reason,
        });
        self.event_bus.emit(Event {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: self.agent_id.clone(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            event_type: "skill.deleted".to_string(),
            payload,
            duration_ms: None,
        });
        Ok(Deleted { commit_sha })
    }

    /// Wave-10 Lane C (076) — activate `draft_id`, then durably commit + emit
    /// `skill.activated`. Mirrors `rollback_skill_with_persistence`: the shared
    /// store guard is held across activate → read-back → commit → emit so the
    /// turn commit captures the activated SKILL.md + .meta.yaml bytes and the
    /// event names the committed version. Per MODULE-017-AC-22 the commit is
    /// `commit_type: turn` (supply `Initiator::Agent { id }`); the event fires
    /// only AFTER commit success. On store-error (e.g. `DraftNotFound` on a
    /// re-activate of a consumed draft) or commit-error, returns Err and emits
    /// NOTHING — idempotent at the agent boundary (matches the event-less
    /// host-fn's `idempotent: false` semantics).
    pub async fn activate_skill_with_persistence(
        &self,
        _initiator: Initiator,
        draft_id: &str,
        reason: &str,
    ) -> Result<Activated, SkillError> {
        // Hold the shared-store guard ONCE across the whole op (non-reentrant —
        // never re-lock here). See rollback_skill_with_persistence.
        let guard = self.skill_store.lock().await;
        // Peek the prior active (if any) BEFORE activate. On the existing-active
        // path `SkillStore::activate` ARCHIVES the prior at
        // `_skill_versions/{id}/v{prior.version}.md` (a NEW file written by THIS
        // activate), so it must be staged too. Fresh / resurrection paths have no
        // prior active (`get` → `SkillNotFound` → `None`) and activate writes no
        // archive → nothing extra to stage. (R9 ADVERSARIAL fix: the prior R5
        // comment wrongly claimed the archive was "committed by the op that
        // created it" — the archive comes into existence at THIS activate.)
        let prior_version: Option<u32> = guard.get(draft_id).await.ok().map(|s| s.version);
        // Wave-18 Lane 2 (MODULE-017-AC-06): record the pre-activation version to
        // the AutoLoop driver BEFORE the mutation, so an iteration discard can
        // restore it. `draft_id == skill_id` (name-keyed `SkillStore::activate`).
        // Default-`None` ⇒ turn lane unchanged. The driver gates on session
        // existence, so this is a no-op outside an auto iteration.
        if let Some(observer) = &self.pre_activation_observer {
            observer.observe_pre_activation(&self.agent_id, draft_id, prior_version);
        }
        // Mutate: consume the draft → install the active skill.
        let skill_id = guard.activate(draft_id).await?;
        // Read back the just-installed active to obtain the version (activate
        // returns only the skill-id) — still under the guard.
        let active = guard.get(&skill_id).await?;
        let version = active.version;
        let skill_name = active.name.clone();
        let provenance = active.provenance.clone();
        let trust_level = active.trust_level.clone();

        // affected_paths = SKILL.md + .meta.yaml (both always written by
        // write_active; .meta.yaml records the version) + the prior-version
        // archive `v{prior}.md` IFF activate archived a prior (existing-active
        // path). All staged paths are guaranteed on disk (just written), so the
        // commit never references a missing path.
        let skill_dir = self
            .agent_root
            .join(".agent")
            .join("skills")
            .join(&skill_id);
        let mut affected_paths = vec![skill_dir.join("SKILL.md"), skill_dir.join(".meta.yaml")];
        if let Some(pv) = prior_version {
            affected_paths.push(
                self.agent_root
                    .join(".agent")
                    .join("_skill_versions")
                    .join(&skill_id)
                    .join(format!("v{pv}.md")),
            );
        }

        let req = CommitRequest::new(
            self.agent_id.clone(),
            format!("activate {} v{}", skill_id, version),
            affected_paths,
            _initiator.commit_type(),
            _initiator.initiator_string(),
        );
        let rx = self.commit_queue.submit(req);
        let oid_result = rx
            .await
            .map_err(|_| SkillError::InvalidTransition("commit worker closed".to_string()))?;
        let oid = oid_result.map_err(|e| {
            // SB-22 redaction: fixed safe-class string; rich GitError host-side
            // only (its Display embeds verbatim paths for some variants).
            eprintln!(
                "cap-skills SkillPersistenceCoordinator: git commit failed: {}",
                e
            );
            SkillError::InvalidTransition("git commit failed".to_string())
        })?;
        let commit_sha = oid.to_string();

        // Emit AFTER commit success (PRD §15.3.16B). `activation_source` /
        // `warnings` are NOT populated (activate returns neither) — M017 §3.6 (aaa).
        let bounded_reason: String = reason.chars().take(MAX_REASON_LEN_CHARS).collect();
        let payload = json!({
            "agent_id": self.agent_id,
            "skill_id": skill_id,
            "skill_name": skill_name,
            "version": version,
            "provenance": provenance,
            "trust_level": trust_level,
            "reason": bounded_reason,
        });
        self.event_bus.emit(Event {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: self.agent_id.clone(),
            task_id: None,
            run_id: None,
            execution_id: None,
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            event_type: "skill.activated".to_string(),
            payload,
            duration_ms: None,
        });
        Ok(Activated {
            skill_id,
            version,
            commit_sha,
        })
    }
}

/// Return shape for `rollback_skill_with_persistence`.
#[derive(Debug, Clone)]
pub struct RolledBack {
    pub commit_sha: String,
    pub new_version: u32,
}

/// Return shape for `delete_skill_with_persistence`.
#[derive(Debug, Clone)]
pub struct Deleted {
    pub commit_sha: String,
}

/// Return shape for `activate_skill_with_persistence` (Wave-10 Lane C).
#[derive(Debug, Clone)]
pub struct Activated {
    pub skill_id: String,
    pub version: u32,
    pub commit_sha: String,
}

/// Cap on entries visited by `enumerate_skill_dir_recursive`. Aligned with
/// SkillBundle's 32-templates + 32-source-scripts + SKILL.md + .meta.yaml +
/// tool.wasm + tool.capabilities.json caps (~68 expected) with 4× headroom.
const MAX_ENUMERATE_ENTRIES: usize = 256;

/// Cap on caller-supplied `reason` codepoints in event payloads. The
/// in-tree `lifecycle.rs` precedent caps by BYTES (`MAX_REASON_LEN = 1024`
/// truncated via `is_char_boundary`); this slice caps by CHARS for
/// simpler `chars().take()` semantics. Worst case for 4-byte UTF-8
/// (emoji / some CJK) is ~4 KiB — well within MODULE-019's 64 KiB
/// per-event recommendation. R1 AUDIT Warning #3 fix.
const MAX_REASON_LEN_CHARS: usize = 1024;

/// Recursive directory enumeration that returns regular files AND symlink
/// leaves (symlink targets are NOT followed — defense-in-depth). On root-not-
/// found returns `Ok(empty)` so a delete of an already-missing skill_dir
/// doesn't fail enumeration. The `visited` counter increments for EVERY
/// `read_dir` entry (directories + leaves), so empty-subdirectory expansion
/// cannot bypass `MAX_ENUMERATE_ENTRIES`.
async fn enumerate_skill_dir_recursive(root: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    // R1 AUDIT Codex Diff Warning fix: reject symlinked ROOT (not just
    // symlinked children). Without this, an adversarial `.agent/skills/{id}`
    // symlink would cause read_dir to traverse outside the agent workspace.
    // NotFound on the root is OK (delete-of-already-missing skill).
    match tokio::fs::symlink_metadata(root).await {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "refusing to enumerate symlinked skill_dir root",
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    }
    let mut out = Vec::new();
    let mut visited = 0_usize;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        match tokio::fs::read_dir(&dir).await {
            Ok(mut entries) => {
                while let Some(entry) = entries.next_entry().await? {
                    visited += 1;
                    if visited > MAX_ENUMERATE_ENTRIES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "skill_dir visited entry count exceeds MAX_ENUMERATE_ENTRIES ({})",
                                MAX_ENUMERATE_ENTRIES
                            ),
                        ));
                    }
                    let meta = entry.file_type().await?;
                    let p = entry.path();
                    if meta.is_dir() {
                        stack.push(p);
                    } else {
                        // Regular file or symlink leaf — both captured for the
                        // commit's affected_paths (symlink targets never followed).
                        out.push(p);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // skill_dir already gone (delete of already-missing skill)
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────
// Inline tests — SH-01..SH-07 + SH-10..SH-13 use crate-private fields of
// SkillPersistenceCoordinator (test-only injection via direct struct literal
// — Rust visibility allows child `mod tests` to construct parent's struct
// literally with private fields). SH-11..SH-13 exercise
// `enumerate_skill_dir_recursive` directly (cap fires on overrun, root
// NotFound returns empty, root symlink rejected on cfg(unix)).
// SH-08/SH-09 (real-advance-git integration) live in
// tests/persistence_phase.rs.
// ──────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{DraftBlob, SkillBlob, SkillStorage};
    use advance_git::GitError;
    use async_trait::async_trait;
    use git2::Oid;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use tempfile::tempdir;
    use tokio::sync::oneshot;
    use tokio::sync::Notify;

    type Seq = Arc<Mutex<Vec<&'static str>>>;

    struct MockCommitQueue {
        next_result: Mutex<VecDeque<Result<Oid, GitError>>>,
        calls: Mutex<Vec<RecordedCommit>>,
        seq: Seq,
    }

    #[derive(Clone)]
    struct RecordedCommit {
        agent_id: String,
        commit_type: CommitType,
        initiator: String,
        message: String,
        affected_paths: Vec<PathBuf>,
    }

    impl GitCommitQueue for MockCommitQueue {
        fn submit(&self, req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>> {
            self.seq.lock().unwrap().push("commit.submit");
            self.calls.lock().unwrap().push(RecordedCommit {
                agent_id: req.agent_id.clone(),
                commit_type: req.commit_type,
                initiator: req.initiator.clone(),
                message: req.message.clone(),
                affected_paths: req.affected_paths.clone(),
            });
            let (tx, rx) = oneshot::channel();
            let result = self
                .next_result
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(Oid::zero()));
            let _ = tx.send(result); // EAGER SEND inside submit — no deadlock
            rx
        }
    }

    struct RecordingEmitter {
        events: Mutex<Vec<Event>>,
        seq: Seq,
    }

    impl EventBusEmit for RecordingEmitter {
        fn emit(&self, event: Event) {
            self.seq.lock().unwrap().push("event.emit");
            self.events.lock().unwrap().push(event);
        }
    }

    /// Wraps DiskSkillStorage and appends sequence labels on each write/delete
    /// so tests can verify ordering. Delegates the 11 non-default
    /// SkillStorage methods explicitly; the 3 sidecar methods inherit
    /// trait-default no-op impls — see M017 §3.6 (zz).
    struct OrderRecordingStorage {
        inner: DiskSkillStorage,
        seq: Seq,
    }

    #[async_trait]
    impl SkillStorage for OrderRecordingStorage {
        async fn read_draft(&self, name: &str) -> Result<Option<DraftBlob>, SkillError> {
            self.inner.read_draft(name).await
        }
        async fn write_draft(&self, blob: &DraftBlob) -> Result<(), SkillError> {
            self.seq.lock().unwrap().push("storage.write_draft");
            self.inner.write_draft(blob).await
        }
        async fn delete_draft(&self, name: &str) -> Result<(), SkillError> {
            self.seq.lock().unwrap().push("storage.delete_draft");
            self.inner.delete_draft(name).await
        }
        async fn list_drafts(&self) -> Result<Vec<DraftBlob>, SkillError> {
            self.inner.list_drafts().await
        }
        async fn read_active(&self, skill_id: &str) -> Result<Option<SkillBlob>, SkillError> {
            self.inner.read_active(skill_id).await
        }
        async fn write_active(&self, blob: &SkillBlob) -> Result<(), SkillError> {
            self.seq.lock().unwrap().push("storage.write_active");
            self.inner.write_active(blob).await
        }
        async fn delete_active(&self, skill_id: &str) -> Result<(), SkillError> {
            self.seq.lock().unwrap().push("storage.delete_active");
            self.inner.delete_active(skill_id).await
        }
        async fn list_active(&self) -> Result<Vec<SkillBlob>, SkillError> {
            self.inner.list_active().await
        }
        async fn read_version(
            &self,
            skill_id: &str,
            version: u32,
        ) -> Result<Option<String>, SkillError> {
            self.inner.read_version(skill_id, version).await
        }
        async fn write_version(
            &self,
            skill_id: &str,
            version: u32,
            content: &str,
        ) -> Result<(), SkillError> {
            self.seq.lock().unwrap().push("storage.write_version");
            self.inner.write_version(skill_id, version, content).await
        }
        async fn list_versions(&self, skill_id: &str) -> Result<Vec<u32>, SkillError> {
            self.inner.list_versions(skill_id).await
        }
        // Sidecar methods inherit trait-default no-op impls (§3.6 (zz))
    }

    fn coordinator_with_store(
        agent_id: String,
        agent_root: PathBuf,
        skill_store: SkillStore,
        commit_queue: Arc<dyn GitCommitQueue>,
        event_bus: Arc<dyn EventBusEmit>,
    ) -> SkillPersistenceCoordinator {
        // Wave-10 Lane C: the coordinator field is now
        // `Arc<tokio::sync::Mutex<SkillStore>>`; this helper KEEPS its
        // `skill_store: SkillStore` parameter and wraps internally, so all
        // SH-01..SH-13 call sites stay source-unchanged. Tests that retain an
        // unwrapped `store` alias (e.g. SH-03) still observe state because
        // `SkillStore::clone` shares the inner `Arc<dyn SkillStorage>`.
        SkillPersistenceCoordinator {
            agent_id,
            agent_root,
            skill_store: Arc::new(tokio::sync::Mutex::new(skill_store)),
            commit_queue,
            event_bus,
            pre_activation_observer: None,
        }
    }

    fn valid_skill_content() -> String {
        "---\nname: web-search\ndescription: a test skill\n---\n# Body\n".to_string()
    }

    async fn seed_active_skill(
        store: &SkillStore,
        name: &str,
        version: u32,
        provenance: Provenance,
        trust_level: TrustLevel,
    ) {
        let blob = SkillBlob {
            skill_id: name.to_string(),
            version,
            content: valid_skill_content(),
            tags: vec![],
            provenance,
            trust_level,
        };
        // SkillStore::with_storage doesn't expose its storage Arc; we use the
        // public store-level helpers when seeding. For trust-level overrides
        // we shouldn't propose_draft+activate (that always yields
        // AgentCreated+Untrusted). Instead we go through the storage backing
        // directly via a fresh SkillStore::with_storage of the same Arc — but
        // SkillStore does not expose the inner Arc<dyn SkillStorage>. The
        // tests below construct the wrapped storage outside and pass it both
        // to seed and to the coordinator (via coordinator_with_store).
        let _ = store;
        let _ = blob;
        // Body left intentionally empty — actual seeding is done by callers
        // using the storage Arc directly (see sh_01_setup helper).
    }

    /// Sets up a v1 prior skill via direct storage write (so it is visible to
    /// `coordinator.skill_store.get()`). Resets the shared seq Vec AFTER
    /// seeding so the coordinator's call is the only thing recorded.
    async fn setup_prior_skill_v1(
        seq: Seq,
        agent_root: &std::path::Path,
    ) -> (Arc<OrderRecordingStorage>, SkillStore) {
        let inner = DiskSkillStorage::with_default_writer(agent_root.to_path_buf());
        let wrap = Arc::new(OrderRecordingStorage {
            inner,
            seq: seq.clone(),
        });
        let blob = SkillBlob {
            skill_id: "web-search".into(),
            version: 1,
            content: valid_skill_content(),
            tags: vec![],
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        };
        wrap.write_active(&blob).await.unwrap();
        seq.lock().unwrap().clear();
        let storage_arc: Arc<dyn SkillStorage> = wrap.clone();
        let store = SkillStore::with_storage(storage_arc);
        (wrap, store)
    }

    fn make_event_bus(seq: Seq) -> Arc<RecordingEmitter> {
        Arc::new(RecordingEmitter {
            events: Mutex::new(Vec::new()),
            seq,
        })
    }

    fn make_queue(seq: Seq, results: Vec<Result<Oid, GitError>>) -> Arc<MockCommitQueue> {
        Arc::new(MockCommitQueue {
            next_result: Mutex::new(VecDeque::from(results)),
            calls: Mutex::new(Vec::new()),
            seq,
        })
    }

    // ── SH-01 — happy-path rollback (ordering + payload) ──
    #[tokio::test]
    async fn sh_01_rollback_happy_path_ordering() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let (_wrap, store) = setup_prior_skill_v1(seq.clone(), dir.path()).await;
        let oid = Oid::from_bytes(&[0u8; 20]).unwrap();
        let queue = make_queue(seq.clone(), vec![Ok(oid)]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        );

        let result = coordinator
            .rollback_skill_with_persistence(Initiator::AutoLoop, "web-search", 1, "iter discard")
            .await
            .unwrap();

        let seq_vec: Vec<&'static str> = seq.lock().unwrap().clone();
        assert_eq!(
            seq_vec,
            vec![
                "storage.write_version",
                "storage.write_active",
                "commit.submit",
                "event.emit"
            ]
        );

        let calls = queue.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let c = &calls[0];
        assert_eq!(c.agent_id, "root");
        assert_eq!(c.commit_type, CommitType::Micro);
        assert_eq!(c.initiator, "runtime:auto-loop");
        assert!(c.message.contains("rollback web-search v1"));
        assert_eq!(c.affected_paths.len(), 3);

        let events = emitter.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, "skill.rolled_back");
        assert_eq!(e.agent_id, "root");
        assert_eq!(e.payload["agent_id"], "root");
        assert_eq!(e.payload["skill_id"], "web-search");
        assert_eq!(e.payload["skill_name"], "web-search");
        assert_eq!(e.payload["from_version"], 1);
        assert_eq!(e.payload["to_version"], 2);
        assert_eq!(e.payload["reason"], "iter discard");

        assert_eq!(result.new_version, 2);
        assert_eq!(result.commit_sha, "0".repeat(40));
    }

    // ── SH-02 — happy-path delete with sidecar enumeration ──
    #[tokio::test]
    async fn sh_02_delete_happy_path_with_sidecar() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let (_wrap, store) = setup_prior_skill_v1(seq.clone(), dir.path()).await;

        // Pre-write a tool.wasm sidecar so enumerate finds it.
        let skill_dir = dir.path().join(".agent").join("skills").join("web-search");
        tokio::fs::create_dir_all(&skill_dir).await.unwrap();
        tokio::fs::write(skill_dir.join("tool.wasm"), [0xAA, 0xBB, 0xCC])
            .await
            .unwrap();

        let oid = Oid::from_bytes(&[1u8; 20]).unwrap();
        let queue = make_queue(seq.clone(), vec![Ok(oid)]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        );

        coordinator
            .delete_skill_with_persistence(Initiator::AutoLoop, "web-search", "iter discard")
            .await
            .unwrap();

        let seq_vec: Vec<&'static str> = seq.lock().unwrap().clone();
        // Expected: write_version (archive) → delete_active (remove_dir_all)
        // → commit.submit → event.emit
        assert_eq!(
            seq_vec,
            vec![
                "storage.write_version",
                "storage.delete_active",
                "commit.submit",
                "event.emit"
            ]
        );

        let calls = queue.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let c = &calls[0];
        assert_eq!(c.commit_type, CommitType::Micro);
        assert_eq!(c.initiator, "runtime:auto-loop");
        assert!(c.message.contains("delete web-search"));
        // SKILL.md + .meta.yaml + tool.wasm + version archive >= 4
        assert!(c.affected_paths.len() >= 4);

        let events = emitter.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, "skill.deleted");
        assert_eq!(e.payload["skill_id"], "web-search");
        assert_eq!(e.payload["reason"], "iter discard");
    }

    // ── SH-03 — commit failure: storage mutated, event NOT emitted ──
    #[tokio::test]
    async fn sh_03_rollback_commit_failure_no_event() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let (_wrap, store) = setup_prior_skill_v1(seq.clone(), dir.path()).await;
        let queue = make_queue(
            seq.clone(),
            vec![Err(GitError::Libgit2 {
                code: "-1".to_string(),
                message: "test-failure".to_string(),
            })],
        );
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store.clone(),
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        );

        let err = coordinator
            .rollback_skill_with_persistence(Initiator::AutoLoop, "web-search", 1, "discard")
            .await
            .unwrap_err();

        match err {
            SkillError::InvalidTransition(msg) => {
                assert!(msg.contains("git commit failed"), "msg was: {msg}");
            }
            other => panic!("expected InvalidTransition, got {:?}", other),
        }

        // Commit was attempted
        assert_eq!(queue.calls.lock().unwrap().len(), 1);
        // Event was NOT emitted
        assert!(emitter.events.lock().unwrap().is_empty());
        // Storage was mutated (skill is now at version 2)
        let s = store.get("web-search").await.unwrap();
        assert_eq!(s.version, 2);
    }

    // ── SH-04 — prior not found: SkillNotFound, no commit/event ──
    #[tokio::test]
    async fn sh_04_rollback_skill_not_found() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let inner = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let wrap = Arc::new(OrderRecordingStorage {
            inner,
            seq: seq.clone(),
        });
        let storage_arc: Arc<dyn SkillStorage> = wrap.clone();
        let store = SkillStore::with_storage(storage_arc);
        let queue = make_queue(seq.clone(), vec![]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        );

        let err = coordinator
            .rollback_skill_with_persistence(Initiator::AutoLoop, "missing", 1, "discard")
            .await
            .unwrap_err();
        match err {
            SkillError::SkillNotFound(_) => {}
            other => panic!("expected SkillNotFound, got {:?}", other),
        }
        assert!(queue.calls.lock().unwrap().is_empty());
        assert!(emitter.events.lock().unwrap().is_empty());
    }

    // ── SH-05 — rollback affected_paths shape ──
    #[tokio::test]
    async fn sh_05_rollback_affected_paths_shape() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let (_wrap, store) = setup_prior_skill_v1(seq.clone(), dir.path()).await;
        let queue = make_queue(seq.clone(), vec![Ok(Oid::from_bytes(&[0u8; 20]).unwrap())]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter as Arc<dyn EventBusEmit>,
        );
        coordinator
            .rollback_skill_with_persistence(Initiator::AutoLoop, "web-search", 1, "x")
            .await
            .unwrap();

        let calls = queue.calls.lock().unwrap();
        let paths = &calls[0].affected_paths;
        assert_eq!(paths.len(), 3);
        let names: Vec<String> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "SKILL.md"));
        assert!(names.iter().any(|n| n == ".meta.yaml"));
        assert!(names.iter().any(|n| n == "v1.md"));
    }

    // ── SH-06 — delete-without-sidecars affected_paths shape ──
    #[tokio::test]
    async fn sh_06_delete_affected_paths_no_sidecars() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let (_wrap, store) = setup_prior_skill_v1(seq.clone(), dir.path()).await;
        let queue = make_queue(seq.clone(), vec![Ok(Oid::from_bytes(&[0u8; 20]).unwrap())]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter as Arc<dyn EventBusEmit>,
        );
        coordinator
            .delete_skill_with_persistence(Initiator::AutoLoop, "web-search", "x")
            .await
            .unwrap();

        let calls = queue.calls.lock().unwrap();
        let paths: std::collections::HashSet<String> = calls[0]
            .affected_paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        // SKILL.md + .meta.yaml from enumeration + v1.md archive from coordinator
        assert!(paths.contains("SKILL.md"));
        assert!(paths.contains(".meta.yaml"));
        assert!(paths.contains("v1.md"));
    }

    // ── SH-07 — delete WITH sidecars: sidecars in affected_paths ──
    #[tokio::test]
    async fn sh_07_delete_with_sidecars() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let (_wrap, store) = setup_prior_skill_v1(seq.clone(), dir.path()).await;

        let skill_dir = dir.path().join(".agent").join("skills").join("web-search");
        tokio::fs::create_dir_all(skill_dir.join("templates"))
            .await
            .unwrap();
        tokio::fs::write(skill_dir.join("tool.wasm"), [0xAA, 0xBB, 0xCC])
            .await
            .unwrap();
        tokio::fs::write(
            skill_dir.join("templates").join("intro.md"),
            "intro content".as_bytes(),
        )
        .await
        .unwrap();

        let queue = make_queue(seq.clone(), vec![Ok(Oid::from_bytes(&[0u8; 20]).unwrap())]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter as Arc<dyn EventBusEmit>,
        );
        coordinator
            .delete_skill_with_persistence(Initiator::AutoLoop, "web-search", "x")
            .await
            .unwrap();

        let calls = queue.calls.lock().unwrap();
        let names: std::collections::HashSet<String> = calls[0]
            .affected_paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains("SKILL.md"));
        assert!(names.contains(".meta.yaml"));
        assert!(names.contains("tool.wasm"));
        assert!(names.contains("intro.md"));
        assert!(names.contains("v1.md"));
    }

    // ── SH-10 — trust-violation rejection (behavior only) ──
    #[tokio::test]
    async fn sh_10_delete_trusted_skill_rejected() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let inner = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let wrap = Arc::new(OrderRecordingStorage {
            inner,
            seq: seq.clone(),
        });
        // Seed a Trusted skill directly (bypasses propose_draft+activate which
        // always produces AgentCreated+Untrusted).
        let blob = SkillBlob {
            skill_id: "trusted-skill".into(),
            version: 1,
            content: valid_skill_content(),
            tags: vec![],
            provenance: Provenance::Imported,
            trust_level: TrustLevel::Trusted,
        };
        wrap.write_active(&blob).await.unwrap();
        seq.lock().unwrap().clear();
        let storage_arc: Arc<dyn SkillStorage> = wrap.clone();
        let store = SkillStore::with_storage(storage_arc);
        let queue = make_queue(seq.clone(), vec![]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        );

        let err = coordinator
            .delete_skill_with_persistence(Initiator::AutoLoop, "trusted-skill", "x")
            .await
            .unwrap_err();
        match err {
            SkillError::TrustViolation(_) => {}
            other => panic!("expected TrustViolation, got {:?}", other),
        }

        assert!(queue.calls.lock().unwrap().is_empty());
        assert!(emitter.events.lock().unwrap().is_empty());
    }

    // Silence dead_code lint on the unused setup helper kept for future
    // expansion.
    #[allow(dead_code)]
    async fn _seed_helper_kept() {
        let _ = seed_active_skill;
    }

    // ── SH-11 — MAX_ENUMERATE_ENTRIES cap fires on overrun ──
    #[tokio::test]
    async fn sh_11_enumerate_cap_fires_on_overrun() {
        let dir = tempdir().unwrap();
        // Create the skill_dir + 300 files to exceed MAX_ENUMERATE_ENTRIES=256.
        let skill_dir = dir.path().join(".agent").join("skills").join("toobig");
        tokio::fs::create_dir_all(&skill_dir).await.unwrap();
        for i in 0..300 {
            tokio::fs::write(skill_dir.join(format!("file_{i}.md")), b"x")
                .await
                .unwrap();
        }
        let err = enumerate_skill_dir_recursive(&skill_dir).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains("MAX_ENUMERATE_ENTRIES"),
            "expected cap error, got: {msg}"
        );
    }

    // ── SH-12 — root NotFound returns Ok(empty) (delete-of-already-missing) ──
    #[tokio::test]
    async fn sh_12_enumerate_root_not_found_returns_empty() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does").join("not").join("exist");
        let out = enumerate_skill_dir_recursive(&missing).await.unwrap();
        assert!(out.is_empty());
    }

    // ── SH-13 — symlinked root is rejected (R1 AUDIT Codex Diff fix) ──
    #[cfg(unix)]
    #[tokio::test]
    async fn sh_13_enumerate_root_symlink_rejected() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real_skill");
        let link_dir = dir.path().join("link_skill");
        tokio::fs::create_dir_all(&real_dir).await.unwrap();
        tokio::fs::write(real_dir.join("SKILL.md"), b"# real\n")
            .await
            .unwrap();
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let err = enumerate_skill_dir_recursive(&link_dir).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains("symlinked"),
            "expected symlink reject, got: {msg}"
        );
    }

    // ──────────────────────────────────────────────────────────────────
    // Wave-10 Lane C — agent turn-lane activate emitter (076) + initiator
    // turn-typing + commit-failure fail-closed + lock-across-commit.
    // ──────────────────────────────────────────────────────────────────

    fn valid_named_content(name: &str) -> String {
        format!("---\nname: {name}\ndescription: a test skill\n---\n# Body\n")
    }

    /// Seed a single fresh draft via the wrapped (seq-recording) storage, then
    /// reset the seq so only the coordinator's calls are recorded. Returns a
    /// `SkillStore` over the SAME storage Arc (sees the seeded draft on disk).
    async fn setup_pending_draft(seq: Seq, agent_root: &std::path::Path, name: &str) -> SkillStore {
        let inner = DiskSkillStorage::with_default_writer(agent_root.to_path_buf());
        let wrap = Arc::new(OrderRecordingStorage {
            inner,
            seq: seq.clone(),
        });
        let storage_arc: Arc<dyn SkillStorage> = wrap.clone();
        SkillStore::with_storage(storage_arc.clone())
            .propose_draft(name.to_string(), valid_named_content(name), vec![])
            .await
            .unwrap();
        seq.lock().unwrap().clear();
        SkillStore::with_storage(storage_arc)
    }

    // ── SH-14 — activate happy path: ordering + Turn commit + skill.activated ──
    #[tokio::test]
    async fn sh_14_activate_with_persistence_happy_path() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        let store = setup_pending_draft(seq.clone(), dir.path(), "web-search").await;
        let oid = Oid::from_bytes(&[0u8; 20]).unwrap();
        let queue = make_queue(seq.clone(), vec![Ok(oid)]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        );

        let result = coordinator
            .activate_skill_with_persistence(
                Initiator::Agent { id: "alice".into() },
                "web-search",
                "promote",
            )
            .await
            .unwrap();

        // Fresh activate: write_active → delete_draft → commit → emit.
        let seq_vec: Vec<&'static str> = seq.lock().unwrap().clone();
        assert_eq!(
            seq_vec,
            vec![
                "storage.write_active",
                "storage.delete_draft",
                "commit.submit",
                "event.emit"
            ]
        );

        let calls = queue.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let c = &calls[0];
        assert_eq!(c.commit_type, CommitType::Turn, "agent op commits as turn");
        assert_eq!(c.initiator, "agent:alice");
        assert!(
            c.message.contains("activate web-search v1"),
            "msg: {}",
            c.message
        );
        assert_eq!(c.affected_paths.len(), 2, "SKILL.md + .meta.yaml");

        let events = emitter.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.event_type, "skill.activated");
        assert_eq!(e.agent_id, "root");
        assert_eq!(e.payload["skill_id"], "web-search");
        assert_eq!(e.payload["skill_name"], "web-search");
        assert_eq!(e.payload["version"], 1);
        assert_eq!(e.payload["reason"], "promote");

        assert_eq!(result.skill_id, "web-search");
        assert_eq!(result.version, 1);
        assert_eq!(result.commit_sha, "0".repeat(40));
    }

    // ── SH-15 — Initiator turn-typing (Agent=Turn/agent:{id}; AutoLoop unchanged) ──
    #[test]
    fn sh_15_initiator_agent_turn_typing() {
        let agent = Initiator::Agent { id: "alice".into() };
        assert_eq!(agent.commit_type(), CommitType::Turn);
        assert_eq!(agent.initiator_string(), "agent:alice");

        let auto = Initiator::AutoLoop;
        assert_eq!(auto.commit_type(), CommitType::Micro);
        assert_eq!(auto.initiator_string(), "runtime:auto-loop");
    }

    // ── SH-16 — activate commit failure: storage mutated, event NOT emitted ──
    #[tokio::test]
    async fn sh_16_activate_commit_failure_no_event() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        // Independent storage handle to verify post-fail state.
        let inner = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let wrap = Arc::new(OrderRecordingStorage {
            inner,
            seq: seq.clone(),
        });
        let storage_arc: Arc<dyn SkillStorage> = wrap.clone();
        SkillStore::with_storage(storage_arc.clone())
            .propose_draft(
                "web-search".into(),
                valid_named_content("web-search"),
                vec![],
            )
            .await
            .unwrap();
        seq.lock().unwrap().clear();

        let store = SkillStore::with_storage(storage_arc.clone());
        let queue = make_queue(
            seq.clone(),
            vec![Err(GitError::Libgit2 {
                code: "-1".to_string(),
                message: "test-failure".to_string(),
            })],
        );
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        );

        let err = coordinator
            .activate_skill_with_persistence(
                Initiator::Agent { id: "alice".into() },
                "web-search",
                "x",
            )
            .await
            .unwrap_err();
        match err {
            SkillError::InvalidTransition(msg) => {
                assert!(msg.contains("git commit failed"), "msg was: {msg}");
            }
            other => panic!("expected InvalidTransition, got {:?}", other),
        }

        assert_eq!(queue.calls.lock().unwrap().len(), 1, "commit attempted");
        assert!(
            emitter.events.lock().unwrap().is_empty(),
            "no event on commit fail"
        );
        // Storage WAS mutated (active installed at v1) before the commit failed.
        let check = SkillStore::with_storage(storage_arc);
        assert_eq!(check.get("web-search").await.unwrap().version, 1);
    }

    /// Non-eager commit queue for SH-17: stores the `tx` in a slot (does NOT
    /// reply inside `submit`), and signals `submitted` once. The test releases
    /// the commit by sending on the stored `tx`.
    struct PendingCommitQueue {
        tx_slot: Mutex<Option<oneshot::Sender<Result<Oid, GitError>>>>,
        submitted: Notify,
    }

    impl GitCommitQueue for PendingCommitQueue {
        fn submit(&self, _req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>> {
            let (tx, rx) = oneshot::channel();
            *self.tx_slot.lock().unwrap() = Some(tx);
            self.submitted.notify_one();
            rx
        }
    }

    // ── SH-17 — the shared-store guard is held across the pending commit ──
    #[tokio::test]
    async fn sh_17_lock_held_across_pending_commit() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        // Build the SHARED store explicitly so the test keeps a handle to the
        // exact Arc<Mutex<..>> the coordinator holds.
        let inner = DiskSkillStorage::with_default_writer(dir.path().to_path_buf());
        let wrap = Arc::new(OrderRecordingStorage {
            inner,
            seq: seq.clone(),
        });
        let storage_arc: Arc<dyn SkillStorage> = wrap.clone();
        SkillStore::with_storage(storage_arc.clone())
            .propose_draft(
                "web-search".into(),
                valid_named_content("web-search"),
                vec![],
            )
            .await
            .unwrap();
        let shared = Arc::new(tokio::sync::Mutex::new(SkillStore::with_storage(
            storage_arc,
        )));

        let queue = Arc::new(PendingCommitQueue {
            tx_slot: Mutex::new(None),
            submitted: Notify::new(),
        });
        let emitter = make_event_bus(seq.clone());
        let coordinator = Arc::new(SkillPersistenceCoordinator::with_shared_store(
            "root".into(),
            dir.path().to_path_buf(),
            shared.clone(),
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter.clone() as Arc<dyn EventBusEmit>,
        ));

        // task1: activate — blocks on rx.await while holding the shared guard.
        let task1 = {
            let c = coordinator.clone();
            tokio::spawn(async move {
                c.activate_skill_with_persistence(
                    Initiator::Agent { id: "alice".into() },
                    "web-search",
                    "x",
                )
                .await
            })
        };

        // Wait until the coordinator has submitted the (never-replied) commit;
        // by construction the guard is held from before submit through emit.
        queue.submitted.notified().await;
        assert!(
            shared.try_lock().is_err(),
            "shared store guard must be held across the pending commit"
        );

        // Release the commit → task1 emits + drops the guard.
        let tx = queue.tx_slot.lock().unwrap().take().unwrap();
        tx.send(Ok(Oid::from_bytes(&[0u8; 20]).unwrap())).unwrap();
        let result = task1.await.unwrap().unwrap();
        assert_eq!(result.version, 1);
        assert_eq!(
            emitter.events.lock().unwrap().len(),
            1,
            "event emitted after commit"
        );
        assert!(
            shared.try_lock().is_ok(),
            "guard released after the op completes"
        );
    }

    // ── SH-19 — existing-active activate stages the freshly-archived prior version ──
    // R9 ADVERSARIAL fix: on the existing-active path activate writes a NEW
    // `_skill_versions/{id}/v{prior}.md` archive; it MUST be in the turn commit's
    // affected_paths (else on-disk vs git-tree divergence).
    #[tokio::test]
    async fn sh_19_activate_existing_active_stages_version_archive() {
        let dir = tempdir().unwrap();
        let seq: Seq = Arc::new(Mutex::new(Vec::new()));
        // Seed an active v1 (AgentCreated+Untrusted) directly.
        let (_wrap, store) = setup_prior_skill_v1(seq.clone(), dir.path()).await;
        // Propose a v2 draft for the SAME name → activate takes the existing-active path.
        store
            .propose_draft("web-search".into(), valid_skill_content(), vec![])
            .await
            .unwrap();
        let oid = Oid::from_bytes(&[0u8; 20]).unwrap();
        let queue = make_queue(seq.clone(), vec![Ok(oid)]);
        let emitter = make_event_bus(seq.clone());
        let coordinator = coordinator_with_store(
            "root".into(),
            dir.path().to_path_buf(),
            store,
            queue.clone() as Arc<dyn GitCommitQueue>,
            emitter as Arc<dyn EventBusEmit>,
        );

        let result = coordinator
            .activate_skill_with_persistence(
                Initiator::Agent { id: "alice".into() },
                "web-search",
                "",
            )
            .await
            .unwrap();
        assert_eq!(result.version, 2, "existing-active activate bumps to v2");

        let calls = queue.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let names: std::collections::HashSet<String> = calls[0]
            .affected_paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains("SKILL.md"));
        assert!(names.contains(".meta.yaml"));
        assert!(
            names.contains("v1.md"),
            "the freshly-archived prior version v1.md must be staged: {names:?}"
        );
        assert_eq!(
            calls[0].affected_paths.len(),
            3,
            "SKILL.md + .meta.yaml + v1.md"
        );
    }
}
