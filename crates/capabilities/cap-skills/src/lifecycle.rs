//! Storage-backed `SkillStore` state machine — MODULE-017 Slice C.
//!
//! Refactored from Slice A's in-memory `HashMap` model to an `async +
//! Arc<dyn SkillStorage>` design. All write transitions persist through
//! `cap-skills/persistence.rs`; the SkillStore itself is stateless.
//!
//! ## Methods (consumed by `cap-skills/src/host_fn.rs`)
//!
//! - `propose_draft(name, content, tags) -> draft_id` — name-keyed; fallible
//!   on `ContentTooLarge` (Slice C flip — was silent truncation in Slice A).
//! - `propose_patch(skill_id, content, reason) -> draft_id` — 4-cell trust
//!   gate; inherits patched skill's name + tags.
//! - `update_draft(draft_id, content) -> ()` — fallible on `ContentTooLarge`.
//! - `activate(draft_id) -> skill_id` — runs all 6 §1.3.2 security_scan
//!   checks; 3-path version dispatch (fresh / existing-active / resurrection).
//! - `rollback(skill_id, version) -> ()` — 4-cell trust gate.
//! - `delete(skill_id) -> ()` — 4-cell trust gate; tombstone via storage
//!   absence + retained version history.
//! - `list_skill_candidates() -> Vec<SkillCandidate>` — fires the opportunistic
//!   sweep, then (slice wave6-laneB) folds the cap-memory PRODUCER
//!   `_skill_candidates.jsonl` (rooted at `candidate_dir`) into the pending
//!   candidates; returns `[]` when `candidate_dir` is unset (the Slice-C stub).
//! - `resolve_skill_candidate(id, action) -> CandidateResult` — (slice
//!   wave6-laneB) appends the terminal `resolved`/`dismissed` event to that same
//!   store (accept also proposes a draft → real draft-id; dismiss → empty);
//!   `Err(SkillNotFound)` for an unknown id or an unset `candidate_dir`. The
//!   cap-memory store folds run via `spawn_blocking` (off the async executor).
//! - `elevate_trust(skill_id) -> ()` — admin method (NOT a host_fn);
//!   flips `Untrusted → Trusted` on the active skill.
//!
//! ## 4-cell trust matrix (PRD §5024-5028)
//!
//! | Provenance   | TrustLevel | patch | delete | rollback |
//! |--------------|------------|-------|--------|----------|
//! | AgentCreated | Untrusted  | Ok    | Ok     | Ok       |
//! | AgentCreated | Trusted    | Block | Block  | Block    |
//! | Imported     | Untrusted  | Ok    | Block  | Block    |
//! | Imported     | Trusted    | Block | Block  | Block    |
//!
//! ## 24h opportunistic sweep (PRD §12.6.3)
//!
//! Sweep fires at three entry-points: `propose_draft`, `activate`,
//! `list_skill_candidates`. Drafts older than 24h are deleted. Also exposed
//! as `startup_cleanup()` for explicit one-shot use.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Duration, Utc};

use advance_shared_types::skills::{Provenance, TrustLevel};

use crate::error::SkillError;
use crate::persistence::{DraftBlob, InMemorySkillStorage, SkillBlob, SkillStorage};
use crate::security_scan;

// ─────────────────────────────────────────────────────────────────────
// Size caps (Slice C: content is fallible; rest stay silent-truncated)
// ─────────────────────────────────────────────────────────────────────

/// Maximum length of a skill name (bytes); silent-truncated at propose.
/// The stricter ≤ 64-char regex applies at activate via `security_scan`.
const MAX_NAME_LEN: usize = 256;
/// Maximum length of content (bytes). **Slice C flip: explicit
/// `ContentTooLarge` rejection** (was: Slice A silent truncation).
const MAX_CONTENT_LEN: usize = 50_000;

/// Upper bound on a guest-supplied `resolve-skill-candidate` id (defense-in-depth;
/// mirrors the cap-memory producer's `MAX_CANDIDATE_ID_BYTES` append cap). A
/// canonical id is a 64-hex sha256, so anything longer can never match a capped
/// pending candidate — we reject it as not-found WITHOUT folding the event log.
const MAX_CANDIDATE_ID_LEN: usize = 128;
/// Maximum length of a single tag (bytes); silent-truncated.
const MAX_TAG_LEN: usize = 128;
/// Maximum number of tags per skill; silent-truncated.
const MAX_TAGS: usize = 32;
/// Maximum length of a `propose_patch` reason (bytes); silent-truncated.
const MAX_REASON_LEN: usize = 1024;

/// Draft TTL for the opportunistic sweep (PRD §12.6.3).
fn draft_ttl() -> Duration {
    Duration::hours(24)
}

/// UTF-8-aware byte truncation.
fn truncate_string(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s
}

fn truncate_tags(tags: Vec<String>) -> Vec<String> {
    tags.into_iter()
        .take(MAX_TAGS)
        .map(|t| truncate_string(t, MAX_TAG_LEN))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────
// 4-cell trust matrix (PRD §5024-5028)
// ─────────────────────────────────────────────────────────────────────

/// `propose_patch` permission: Trusted always blocked; Untrusted allowed
/// regardless of provenance (per PRD §5028: Imported+Untrusted CAN be
/// patched; the patched draft becomes a new AgentCreated chain on activate).
fn patch_allowed(_p: &Provenance, t: &TrustLevel) -> bool {
    !matches!(t, TrustLevel::Trusted)
}

/// `delete` permission: AgentCreated+Untrusted only.
fn delete_allowed(p: &Provenance, t: &TrustLevel) -> bool {
    matches!((p, t), (Provenance::AgentCreated, TrustLevel::Untrusted))
}

/// `rollback` permission: same as delete (AgentCreated+Untrusted only).
fn rollback_allowed(p: &Provenance, t: &TrustLevel) -> bool {
    delete_allowed(p, t)
}

// ─────────────────────────────────────────────────────────────────────
// Public records (Rust-side shape; WIT-side projection lives in host_fn)
// ─────────────────────────────────────────────────────────────────────

/// A pending change-set proposed by an agent.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct Draft {
    /// Slice C: `draft_id == name` (name-keyed).
    pub draft_id: String,
    pub name: String,
    pub content: String,
    pub tags: Vec<String>,
    /// `Some(skill_id)` for patch drafts; `None` for fresh drafts.
    pub parent: Option<String>,
    /// `Some(reason)` for patch drafts; `None` for fresh drafts.
    pub reason: Option<String>,
}

/// An activated, versioned skill.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct Skill {
    pub skill_id: String,
    pub name: String,
    pub version: u32,
    pub content: String,
    pub tags: Vec<String>,
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
}

/// A pending skill candidate surfaced by `list_skill_candidates`. Field shape
/// mirrors the cap-memory PRODUCER `cap_memory::SkillCandidate`
/// (`{candidate_id, name, description}`); the consumer maps the producer rows
/// 1:1 (slice wave6-laneB, leg 3). The `candidate_id` is the cap-memory
/// length-prefixed-sha256 — consumed VERBATIM, never recomputed here.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct SkillCandidate {
    pub candidate_id: String,
    pub name: String,
    pub description: String,
}

/// Action on `resolve_skill_candidate` (WIT `candidate-action`). slice wave6-laneB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateAction {
    Accept,
    Dismiss,
}

/// Result of `resolve_skill_candidate` (WIT `candidate-result`). On `Accept` the
/// `draft_id` is a REAL proposed draft; on `Dismiss` it is empty. slice wave6-laneB.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct CandidateResult {
    pub candidate_id: String,
    pub draft_id: String,
}

impl From<DraftBlob> for Draft {
    fn from(b: DraftBlob) -> Self {
        Self {
            draft_id: b.name.clone(),
            name: b.name,
            content: b.content,
            tags: b.tags,
            parent: b.parent,
            reason: b.reason,
        }
    }
}

impl From<SkillBlob> for Skill {
    fn from(b: SkillBlob) -> Self {
        Self {
            skill_id: b.skill_id.clone(),
            name: b.skill_id,
            version: b.version,
            content: b.content,
            tags: b.tags,
            provenance: b.provenance,
            trust_level: b.trust_level,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// SkillStore
// ─────────────────────────────────────────────────────────────────────

/// Wave-20 — a snapshot of a skill's LIVE state (the agent-visible active skill
/// + its draft, if any) captured by [`SkillStore::snapshot_live`] for the
/// turn-end driver's commit-failure compensation (MODULE-017-AC-22 leg (c),
/// §3.6 (ccc)). The append-only `_skill_versions/` archive and delete-only
/// sidecars are intentionally NOT part of the snapshot.
#[derive(Clone, Debug)]
pub struct LiveSnapshot {
    pub skill_id: String,
    pub active: Option<SkillBlob>,
    pub draft: Option<DraftBlob>,
}

/// Storage-backed `SkillStore` (Slice C).
///
/// Stateless wrapper over `Arc<dyn SkillStorage>`. All writes go through the
/// storage backend; the SkillStore is `Clone + Send + Sync` (cheap to share
/// across host_fn handlers).
#[derive(Clone)]
pub struct SkillStore {
    storage: Arc<dyn SkillStorage>,
    /// slice wave6-laneB (leg 3): directory holding the cap-memory PRODUCER
    /// `_skill_candidates.jsonl` (`<ws>/.agent/memory`). `Some` wires
    /// `list/resolve_skill_candidate` to the real store; `None` (the default)
    /// preserves the Slice-C stub (`list`→`[]`, `resolve`→`Err(not-found)`) so
    /// existing tests stay green.
    candidate_dir: Option<PathBuf>,
}

impl Default for SkillStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SkillStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillStore").finish_non_exhaustive()
    }
}

impl SkillStore {
    /// Construct with default in-memory backing.
    pub fn new() -> Self {
        Self {
            storage: Arc::new(InMemorySkillStorage::new()),
            candidate_dir: None,
        }
    }

    /// Construct with the given storage backing.
    pub fn with_storage(storage: Arc<dyn SkillStorage>) -> Self {
        Self {
            storage,
            candidate_dir: None,
        }
    }

    /// slice wave6-laneB (leg 3): point `list/resolve_skill_candidate` at the
    /// cap-memory PRODUCER `_skill_candidates.jsonl` under `dir`
    /// (`<ws>/.agent/memory`). Consuming builder. Absent ⇒ the Slice-C stub.
    pub fn with_candidate_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.candidate_dir = Some(dir.into());
        self
    }

    // ─── Wave-20: live-state snapshot / restore (turn-end driver leg-c) ────
    //
    // Used by `SkillTurnPersistenceDriver::commit_op_with_compensation`
    // (MODULE-017-AC-22 leg (c) / §3.6 (ccc)) to roll back the agent-visible
    // in-memory state after a git-commit failure. Reachable from the shared
    // `Arc<tokio::sync::Mutex<SkillStore>>` the driver holds (they use the
    // private `self.storage`); cap-skills-internal — no contract change.

    /// Snapshot the LIVE `{active, draft}` state for `skill_id`. The draft is
    /// name-keyed, so `draft_id == skill_id` on the activate/rollback paths.
    /// Deliberately does NOT capture the append-only `_skill_versions/` archive
    /// (durable history, not "in-memory state") nor delete-only sidecars.
    pub async fn snapshot_live(&self, skill_id: &str) -> Result<LiveSnapshot, SkillError> {
        // Defense-in-depth name validation before any storage path join — same
        // gate the other read/write accessors apply (get/get_draft/propose_draft).
        // These methods are `pub`, so a caller must not be able to reach a
        // DiskSkillStorage path join with a traversal-shaped id.
        security_scan::validate_skill_name(skill_id)?;
        let active = self.storage.read_active(skill_id).await?;
        let draft = self.storage.read_draft(skill_id).await?;
        Ok(LiveSnapshot {
            skill_id: skill_id.to_string(),
            active,
            draft,
        })
    }

    /// Restore the LIVE state to a prior [`SkillStore::snapshot_live`]: make the
    /// agent-visible `{active, draft}` match the snapshot. A `None` active is
    /// restored by `delete_active` (un-leaking a fresh-activate's
    /// spuriously-installed skill when its commit failed); a `None` draft by
    /// `delete_draft`. Both storage backings map delete-of-already-absent to
    /// `Ok`, so a `None`→`None` no-op restore is harmless.
    ///
    /// SCOPE + non-atomicity (adversarial-r1 W2/W3): this restores ONLY the live
    /// `{active, draft}` — it does NOT roll back the append-only `_skill_versions/`
    /// archive a coordinator `activate`/`rollback` wrote before its commit failed,
    /// so `list_history` may show that archived version alongside the restored
    /// active (a harmless append-only duplicate, idempotently overwritten when the
    /// op is retried). The two writes are NOT a transaction; a mid-restore storage
    /// fault can leave the live state torn (draft restored, active not — draft is
    /// written first to bound the loss). Callers treat an `Err` as "live state may
    /// be partial — reconcile / retry" (the driver re-enqueues the op).
    ///
    /// SECURITY (adversarial-r4 Info 5): this is an INTERNAL compensation
    /// primitive — it overwrites/deletes the live `{active, draft}` BY KEY with NO
    /// §5.7 trust-matrix check (the W1 key-bind only prevents cross-writing a
    /// blob to a mismatched key; it does not gate WHICH key is targeted). It is
    /// `pub` (re-exported via `SkillStore`, so any in-process `cap-skills`
    /// consumer can call it — it is NOT `pub(crate)`), but it is NOT a WIT
    /// host-fn (not guest-reachable) and adds no authority beyond the existing
    /// `SkillStorage` write/delete primitives. A host caller MUST already hold
    /// authority over `snap.skill_id`; do not expose it to untrusted callers.
    pub async fn restore_live(&self, snap: &LiveSnapshot) -> Result<(), SkillError> {
        // Validate the snapshot key reaching a storage path join (the snapshot
        // may be hand-constructed by a `pub` caller, not only produced by
        // `snapshot_live`). Same gate as the other accessors.
        security_scan::validate_skill_name(&snap.skill_id)?;
        // BIND the blobs to the snapshot key (adversarial-r1 W1): a
        // hand-constructed `LiveSnapshot` must not cross-write the active/draft
        // of a DIFFERENT skill than `snap.skill_id`. The blobs `snapshot_live`
        // produces always satisfy this (read for the same id). This also makes
        // the per-blob name validated (== the validated `snap.skill_id`).
        if let Some(blob) = &snap.active {
            if blob.skill_id != snap.skill_id {
                return Err(SkillError::InvalidTransition(
                    "restore_live: active.skill_id does not match the snapshot key".into(),
                ));
            }
        }
        if let Some(blob) = &snap.draft {
            if blob.name != snap.skill_id {
                return Err(SkillError::InvalidTransition(
                    "restore_live: draft.name does not match the snapshot key".into(),
                ));
            }
        }
        // Restore is TWO storage writes — NOT a filesystem transaction. Restore
        // the DRAFT first so a mid-restore storage fault on the second write
        // does not lose the agent's draft (adversarial-r1: prioritize not
        // destroying recoverable draft state; the active half then carries the
        // coordinator's mutation, which the next-turn retry overwrites). Does
        // NOT touch the append-only `_skill_versions/` archive — see the method
        // contract above + §3.6 (ccc).
        //
        // COMPENSATION (2026-07-03, §3.6 (ccc) flip-blocker (B) closure): each
        // half retries ONCE on a transient fault, and a still-failing restore
        // surfaces Err into the turn-runtime's durable-lease track — the lease
        // journal stays on disk, the next begin_turn reconcile replays it
        // precondition-gated, and a mismatch (torn half) PARKS the lease with
        // an error file rather than silently running against torn state. So a
        // crash/fault in this window is never silent and never wedges: either
        // the replay repairs it or the quarantined lease carries the evidence.
        match &snap.draft {
            Some(blob) => {
                if let Err(first) = self.storage.write_draft(blob).await {
                    eprintln!("cap-skills restore_live draft write failed once, retrying: {first}");
                    self.storage.write_draft(blob).await?;
                }
            }
            None => {
                if let Err(first) = self.storage.delete_draft(&snap.skill_id).await {
                    eprintln!(
                        "cap-skills restore_live draft delete failed once, retrying: {first}"
                    );
                    self.storage.delete_draft(&snap.skill_id).await?;
                }
            }
        }
        match &snap.active {
            Some(blob) => {
                if let Err(first) = self.storage.write_active(blob).await {
                    eprintln!(
                        "cap-skills restore_live active write failed once, retrying: {first}"
                    );
                    self.storage.write_active(blob).await?;
                }
            }
            None => {
                if let Err(first) = self.storage.delete_active(&snap.skill_id).await {
                    eprintln!(
                        "cap-skills restore_live active delete failed once, retrying: {first}"
                    );
                    self.storage.delete_active(&snap.skill_id).await?;
                }
            }
        }
        Ok(())
    }

    /// Wave-20 — flush a runtime-private draft blob to disk (the turn-end
    /// driver's leg-(b) Step-1 overlay→disk flush). Unlike `propose_draft` this
    /// is a verbatim persist of an already-staged blob (preserves
    /// `parent`/`reason`/`created_at`, no content re-scan/sweep) — but it DOES
    /// re-apply `propose_draft`'s SIZE bounds (name/content/tags/reason/parent)
    /// so it can never be a metadata-size bypass.
    pub async fn flush_draft(&self, blob: &DraftBlob) -> Result<(), SkillError> {
        // Defense-in-depth: validate the draft name before the storage path join.
        security_scan::validate_skill_name(&blob.name)?;
        // Enforce the SAME content cap `propose_draft` applies (adversarial-r1
        // W4: `flush_draft` must not become a `MAX_CONTENT_LEN` bypass).
        if blob.content.len() > MAX_CONTENT_LEN {
            return Err(SkillError::ContentTooLarge(blob.content.len()));
        }
        // Cap the metadata too (adversarial-r4 W3: `MAX_OVERLAY` bounds the
        // overlay COUNT, not per-blob bytes; `propose_draft` truncates tags +
        // forces parent/reason to `None`, so a hand-staged blob is the only way
        // these grow). Reject rather than truncate — a flushed draft must be a
        // faithful, bounded persist.
        if blob.tags.len() > MAX_TAGS || blob.tags.iter().any(|t| t.len() > MAX_TAG_LEN) {
            return Err(SkillError::InvalidTransition(
                "flush_draft: draft tags exceed MAX_TAGS / MAX_TAG_LEN".into(),
            ));
        }
        if let Some(reason) = &blob.reason {
            if reason.len() > MAX_REASON_LEN {
                return Err(SkillError::InvalidTransition(
                    "flush_draft: draft reason exceeds MAX_REASON_LEN".into(),
                ));
            }
        }
        // `parent` is a skill-id reference → the same name gate (bounds shape + length).
        if let Some(parent) = &blob.parent {
            security_scan::validate_skill_name(parent)?;
        }
        self.storage.write_draft(blob).await
    }

    // ─── 24h opportunistic sweep (PRD §12.6.3) ────────────────────

    async fn sweep(&self) -> Result<(), SkillError> {
        let now = Utc::now();
        let drafts = self.storage.list_drafts().await?;
        for draft in drafts {
            // Adversarial round 1 fix: clock-skew defense. A draft whose
            // `created_at` is in the future (corrupt meta yaml, or a
            // clock that jumped backward after the draft was written)
            // would compute a NEGATIVE `signed_duration_since` and be
            // permanently un-sweepable. Clamp future timestamps to `now`
            // so the sweep treats them as fresh (TTL = 0). The next
            // sweep pass picks them up after they age past the TTL.
            let effective = draft.created_at.min(now);
            if now.signed_duration_since(effective) > draft_ttl() {
                self.storage.delete_draft(&draft.name).await?;
            }
        }
        Ok(())
    }

    /// Public startup sweep — one-shot equivalent of the opportunistic
    /// sweep, invoked on storage init by the host wiring layer.
    pub async fn startup_cleanup(&self) -> Result<(), SkillError> {
        self.sweep().await
    }

    // ─── Drafts ───────────────────────────────────────────────────

    /// `propose-skill-draft(name, content, tags) -> draft-id`.
    ///
    /// Slice C: name-keyed (second call with same name UPDATES existing).
    /// Fallible: returns `ContentTooLarge` when content exceeds 50 KB;
    /// returns `InvalidName` if `name` doesn't match the §1.3.2 regex.
    /// Fires the opportunistic sweep at entry.
    ///
    /// **Audit round 3 fix**: name validation runs BEFORE the storage
    /// write. The pre-fix flow only validated at `activate` (via
    /// `security_scan::scan`), allowing path-traversal names like
    /// `"../../etc/foo"` to be persisted under `_skill_drafts/` before
    /// activate caught them. The pre-write gate closes that surface.
    pub async fn propose_draft(
        &self,
        name: String,
        content: String,
        tags: Vec<String>,
    ) -> Result<String, SkillError> {
        self.sweep().await?;
        // Pre-write name gate (audit round 3 — closes the path-traversal
        // surface where propose_draft could persist `../../foo` before
        // the activate-time security_scan caught it).
        security_scan::validate_skill_name(&name)?;
        if content.len() > MAX_CONTENT_LEN {
            return Err(SkillError::ContentTooLarge(content.len()));
        }
        let name = truncate_string(name, MAX_NAME_LEN);
        let blob = DraftBlob {
            name: name.clone(),
            content,
            tags: truncate_tags(tags),
            parent: None,
            reason: None,
            created_at: Utc::now(),
        };
        self.storage.write_draft(&blob).await?;
        Ok(name)
    }

    /// `propose-skill-patch(skill-id, content, reason) -> draft-id`.
    ///
    /// Trust-gated per the 4-cell matrix (Trusted blocked). Inherits patched
    /// skill's name + tags; creates / overwrites a name-keyed draft.
    pub async fn propose_patch(
        &self,
        skill_id: &str,
        content: String,
        reason: String,
    ) -> Result<String, SkillError> {
        // Audit round 3 fix: validate agent-supplied skill_id before any
        // storage path interpolation.
        security_scan::validate_skill_name(skill_id)?;
        if content.len() > MAX_CONTENT_LEN {
            return Err(SkillError::ContentTooLarge(content.len()));
        }
        let active = self
            .storage
            .read_active(skill_id)
            .await?
            .ok_or_else(|| SkillError::SkillNotFound(skill_id.to_string()))?;
        if !patch_allowed(&active.provenance, &active.trust_level) {
            return Err(SkillError::TrustViolation(skill_id.to_string()));
        }
        let name = active.skill_id.clone();
        let blob = DraftBlob {
            name: name.clone(),
            content,
            tags: active.tags.clone(),
            parent: Some(skill_id.to_string()),
            reason: Some(truncate_string(reason, MAX_REASON_LEN)),
            created_at: Utc::now(),
        };
        self.storage.write_draft(&blob).await?;
        Ok(name)
    }

    /// `update-skill-draft(draft-id, content) -> ()`.
    ///
    /// **Audit round 3 fix**: name validation on `draft_id` (which IS the
    /// name in Slice C's name-keyed scheme) before storage read. Closes
    /// the same path-traversal surface as `propose_draft` — without this,
    /// an attacker who somehow planted a draft at `../../foo/` could
    /// overwrite it via `update_draft("../../foo", new_content)`.
    pub async fn update_draft(&self, draft_id: &str, content: String) -> Result<(), SkillError> {
        security_scan::validate_skill_name(draft_id)?;
        if content.len() > MAX_CONTENT_LEN {
            return Err(SkillError::ContentTooLarge(content.len()));
        }
        let mut blob = self
            .storage
            .read_draft(draft_id)
            .await?
            .ok_or_else(|| SkillError::DraftNotFound(draft_id.to_string()))?;
        blob.content = content;
        self.storage.write_draft(&blob).await
    }

    // ─── Activate / rollback / delete ─────────────────────────────

    /// `activate-skill(draft-id) -> skill-id`.
    ///
    /// 3-path dispatch keyed by `Draft.name`:
    /// 1. Fresh-skill — no chain exists: install at v=1.
    /// 2. Existing-Active — replaces current; archives prior at v=prior+1.
    /// 3. Resurrection — no Active, versions exist: install at max+1.
    ///
    /// Pre-mutation steps:
    /// - Opportunistic sweep.
    /// - All 6 §1.3.2 security_scan checks on draft content (name +
    ///   conflict-exclusion against `list_active`).
    /// - **Trust gate** (audit round 1 fix): if an existing-Active prior is
    ///   `Trusted`, return `TrustViolation` *before* mutating storage.
    ///   Closes the bypass where `propose_draft + activate` could overwrite
    ///   a `Trusted` skill that `propose_patch` would have rejected.
    ///   Resurrection path inherits the prior chain's trust level (carried
    ///   on the last `versions` SkillBlob); the legacy versions stored as
    ///   plain content strings have no metadata, so the resurrection path
    ///   falls through to the default `Untrusted` chain — Slice C accepted
    ///   trade-off documented in §3.6.
    /// - u32 overflow check.
    pub async fn activate(&self, draft_id: &str) -> Result<String, SkillError> {
        // Audit round 3 fix: validate agent-supplied draft_id before
        // any storage read. Slice C's name-keyed scheme means draft_id is
        // a path component.
        security_scan::validate_skill_name(draft_id)?;
        self.sweep().await?;

        // Peek draft.
        let draft = self
            .storage
            .read_draft(draft_id)
            .await?
            .ok_or_else(|| SkillError::DraftNotFound(draft_id.to_string()))?;
        let name = draft.name.clone();
        let skill_id = name.clone();

        // Trust gate FIRST (adversarial round 1 fix — was previously after
        // security_scan, creating a content-validation oracle on Trusted
        // skill names where an attacker could probe §1.3.2 check failures
        // for any locked name before the trust gate fired). Now the gate
        // is the first thing checked against the prior — Trusted skills
        // return TrustViolation without revealing anything about the
        // candidate content.
        let prior = self.storage.read_active(&skill_id).await?;
        if let Some(ref p) = prior {
            if !patch_allowed(&p.provenance, &p.trust_level) {
                return Err(SkillError::TrustViolation(skill_id.clone()));
            }
        }

        // Security scan — pass active names EXCEPT `name` (replacing the
        // same name is not a conflict for activate).
        let active_blobs = self.storage.list_active().await?;
        let existing_names: Vec<&str> = active_blobs
            .iter()
            .filter(|b| b.skill_id != name)
            .map(|b| b.skill_id.as_str())
            .collect();
        security_scan::scan(&name, &draft.content, &existing_names)?;

        let versions = self.storage.list_versions(&skill_id).await?;
        let next_version = if let Some(ref p) = prior {
            // Existing-Active path.
            p.version.checked_add(1).ok_or_else(|| {
                SkillError::InvalidTransition(format!(
                    "version overflow on activate: skill={skill_id} prior={}",
                    p.version
                ))
            })?
        } else if let Some(max_v) = versions.iter().copied().max() {
            // Resurrection path.
            max_v.checked_add(1).ok_or_else(|| {
                SkillError::InvalidTransition(format!(
                    "version overflow on resurrect: skill={skill_id} last={max_v}"
                ))
            })?
        } else {
            // Fresh-skill path.
            1
        };

        // All checks passed — mutate.

        // Archive prior into versions before overwriting active.
        if let Some(p) = prior {
            self.storage
                .write_version(&skill_id, p.version, &p.content)
                .await?;
        }

        // Post-activate result is unconditionally `(AgentCreated,
        // Untrusted)`. Justification:
        // - Trusted prior is blocked above (TrustViolation), so we never
        //   reach this code path with Trusted prior.
        // - Imported+Untrusted prior + activate-of-agent-patch produces
        //   an AgentCreated chain per PRD §5028 ("the patched draft
        //   becomes a new AgentCreated chain on activate").
        // - Fresh / resurrection paths produce a new AgentCreated chain.
        let new_active = SkillBlob {
            skill_id: skill_id.clone(),
            version: next_version,
            content: draft.content,
            tags: draft.tags,
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        };
        self.storage.write_active(&new_active).await?;
        self.storage.delete_draft(&skill_id).await?;
        Ok(skill_id)
    }

    /// `rollback-skill(skill-id, version) -> ()`. Trust-gated.
    ///
    /// Appends a NEW active at `prior.version + 1` carrying the requested
    /// version's content (history-append, NOT in-place). Tombstoned skills
    /// are rollback-unreachable: returns `SkillNotFound`. Provenance +
    /// trust_level are preserved from the prior active.
    pub async fn rollback(&self, skill_id: &str, version: u32) -> Result<(), SkillError> {
        security_scan::validate_skill_name(skill_id)?;
        let prior = self
            .storage
            .read_active(skill_id)
            .await?
            .ok_or_else(|| SkillError::SkillNotFound(skill_id.to_string()))?;
        if !rollback_allowed(&prior.provenance, &prior.trust_level) {
            return Err(SkillError::TrustViolation(skill_id.to_string()));
        }

        // Locate target version's content.
        let source_content = if prior.version == version {
            // Rollback-to-current: copy current content under a bumped version.
            prior.content.clone()
        } else {
            self.storage
                .read_version(skill_id, version)
                .await?
                .ok_or_else(|| SkillError::VersionNotFound {
                    skill_id: skill_id.to_string(),
                    version,
                })?
        };

        let next_version = prior.version.checked_add(1).ok_or_else(|| {
            SkillError::InvalidTransition(format!(
                "version overflow on rollback: skill={skill_id} prior={}",
                prior.version
            ))
        })?;

        // Archive prior into versions before overwriting active.
        self.storage
            .write_version(skill_id, prior.version, &prior.content)
            .await?;

        let new_active = SkillBlob {
            skill_id: skill_id.to_string(),
            version: next_version,
            content: source_content,
            tags: prior.tags,
            provenance: prior.provenance,
            trust_level: prior.trust_level,
        };
        self.storage.write_active(&new_active).await
    }

    /// `delete-skill(skill-id) -> ()`. Trust-gated.
    ///
    /// Archives the prior active into versions (so `list_history` continues
    /// to return it) and clears the active record. Resurrection via
    /// `propose_draft + activate` continues the version chain.
    pub async fn delete(&self, skill_id: &str) -> Result<(), SkillError> {
        security_scan::validate_skill_name(skill_id)?;
        let prior = self
            .storage
            .read_active(skill_id)
            .await?
            .ok_or_else(|| SkillError::SkillNotFound(skill_id.to_string()))?;
        if !delete_allowed(&prior.provenance, &prior.trust_level) {
            return Err(SkillError::TrustViolation(skill_id.to_string()));
        }
        self.storage
            .write_version(skill_id, prior.version, &prior.content)
            .await?;
        self.storage.delete_active(skill_id).await
    }

    // ─── Read accessors ───────────────────────────────────────────

    pub async fn list_drafts(&self) -> Result<Vec<Draft>, SkillError> {
        let blobs = self.storage.list_drafts().await?;
        Ok(blobs.into_iter().map(Draft::from).collect())
    }

    /// Adversarial round 1 fix: read accessors validate the name argument
    /// the same as mutating methods — defense in depth. Without this gate,
    /// a future caller that exposes `get_draft` outside the validated
    /// host_fn boundary could trigger `read_draft("../../etc/foo")` which
    /// builds a host path with a traversal component.
    pub async fn get_draft(&self, draft_id: &str) -> Result<Option<Draft>, SkillError> {
        security_scan::validate_skill_name(draft_id)?;
        Ok(self.storage.read_draft(draft_id).await?.map(Draft::from))
    }

    /// Get the current Active Skill. Returns `SkillNotFound` if the skill
    /// has been deleted or never activated.
    ///
    /// Adversarial round 1 fix: name validation before storage read.
    pub async fn get(&self, skill_id: &str) -> Result<Skill, SkillError> {
        security_scan::validate_skill_name(skill_id)?;
        let blob = self
            .storage
            .read_active(skill_id)
            .await?
            .ok_or_else(|| SkillError::SkillNotFound(skill_id.to_string()))?;
        Ok(Skill::from(blob))
    }

    /// Return the full version history for a skill: all archived versions
    /// (sorted ascending) plus the current Active at the end if any.
    ///
    /// Slice C semantics:
    /// - Active path: archived versions get the active's provenance +
    ///   trust_level + tags (constant across the chain).
    /// - Tombstoned path (active absent, versions present): archived
    ///   versions use default provenance/trust/tags (metadata lost on
    ///   delete-without-tombstone-record — Slice C accepted trade-off).
    pub async fn list_history(&self, skill_id: &str) -> Result<Vec<Skill>, SkillError> {
        security_scan::validate_skill_name(skill_id)?;
        let mut versions = self.storage.list_versions(skill_id).await?;
        versions.sort_unstable();
        let active = self.storage.read_active(skill_id).await?;
        if versions.is_empty() && active.is_none() {
            return Err(SkillError::SkillNotFound(skill_id.to_string()));
        }
        let (proto_tags, proto_p, proto_t) = active
            .as_ref()
            .map(|a| (a.tags.clone(), a.provenance.clone(), a.trust_level.clone()))
            .unwrap_or_else(|| (Vec::new(), Provenance::AgentCreated, TrustLevel::Untrusted));
        let mut out = Vec::new();
        for v in versions {
            let content = self
                .storage
                .read_version(skill_id, v)
                .await?
                .unwrap_or_default();
            out.push(Skill {
                skill_id: skill_id.to_string(),
                name: skill_id.to_string(),
                version: v,
                content,
                tags: proto_tags.clone(),
                provenance: proto_p.clone(),
                trust_level: proto_t.clone(),
            });
        }
        if let Some(a) = active {
            out.push(Skill::from(a));
        }
        Ok(out)
    }

    /// `list-skill-candidates() -> Vec<SkillCandidate>` (slice wave6-laneB).
    ///
    /// Fires the opportunistic sweep (PRD §12.6.3 entry-point 3), then folds the
    /// cap-memory PRODUCER `_skill_candidates.jsonl` (rooted at `candidate_dir`)
    /// into the still-`pending` candidates, mapped 1:1 from
    /// `cap_memory::SkillCandidate` (id consumed verbatim). When `candidate_dir`
    /// is unset, returns `[]` (the Slice-C stub — for tests/configs without a
    /// wired memory root).
    pub async fn list_skill_candidates(&self) -> Result<Vec<SkillCandidate>, SkillError> {
        self.sweep().await?;
        let Some(dir) = &self.candidate_dir else {
            return Ok(Vec::new());
        };
        // Run the synchronous cap-memory store fold OFF the async executor so a
        // large log / slow disk cannot block the runtime on this guest-reachable
        // host-fn (the cap-memory store is std::fs; the rest of cap-skills is
        // async tokio::fs). The fold itself is DoS-bounded inside `read_events`
        // (`MAX_CANDIDATE_FILE_BYTES`).
        let dir = dir.clone();
        let pending = tokio::task::spawn_blocking(move || {
            cap_memory::SkillCandidateStore::in_dir(&dir).list_pending()
        })
        .await
        .map_err(|e| SkillError::InvalidTransition(format!("skill candidate store task: {e}")))?
        .map_err(|e| SkillError::InvalidTransition(format!("skill candidate store read: {e}")))?;
        Ok(pending
            .into_iter()
            .map(|c| SkillCandidate {
                candidate_id: c.candidate_id,
                name: c.name,
                description: c.description,
            })
            .collect())
    }

    /// `resolve-skill-candidate(candidate-id, action) -> candidate-result`
    /// (slice wave6-laneB). Appends a terminal `resolved`/`dismissed` event to the
    /// cap-memory PRODUCER store (append-only; the `generated` row is retained; the
    /// store guards unknown-id + double-resolve) so a subsequent
    /// `list_skill_candidates` no longer returns the candidate as pending. On
    /// `Accept`, a real skill draft is proposed from the candidate's (name,
    /// description) — the WIT `candidate-result.draft-id` is that new draft-id; on
    /// `Dismiss` the draft-id is empty. An unknown / already-resolved id, or an
    /// unset `candidate_dir`, returns `SkillNotFound` (WIT `not-found`).
    pub async fn resolve_skill_candidate(
        &self,
        candidate_id: &str,
        action: CandidateAction,
    ) -> Result<CandidateResult, SkillError> {
        let Some(dir) = &self.candidate_dir else {
            return Err(SkillError::SkillNotFound("candidate not found".to_string()));
        };
        // Bound the guest-supplied id up front (adversarial r4, W-C): an over-long
        // id cannot match a capped pending candidate, so it is not-found by
        // construction — reject it here without folding the (DoS-bounded) log.
        if candidate_id.len() > MAX_CANDIDATE_ID_LEN {
            return Err(SkillError::SkillNotFound("candidate not found".to_string()));
        }
        let dir = dir.clone();
        // Only a PENDING candidate is resolvable; `list_pending` excludes
        // already-terminal ids, so an unknown OR already-resolved id is "not found".
        // Run the synchronous fold OFF the async executor (guest-reachable host-fn;
        // DoS-bounded inside `read_events`).
        let pending = {
            let dir = dir.clone();
            tokio::task::spawn_blocking(move || {
                cap_memory::SkillCandidateStore::in_dir(&dir).list_pending()
            })
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("skill candidate store task: {e}")))?
            .map_err(|e| {
                SkillError::InvalidTransition(format!("skill candidate store read: {e}"))
            })?
        };
        let Some(cand) = pending.into_iter().find(|c| c.candidate_id == candidate_id) else {
            return Err(SkillError::SkillNotFound("candidate not found".to_string()));
        };
        // Reorder (adversarial r4): VALIDATE the name → append the terminal event
        // (locked) → propose the draft. (1) An invalid name fails up front, leaving
        // the candidate PENDING with no terminal/draft. (2) The locked terminal
        // append happens BEFORE any draft is created, so a concurrent producer
        // compaction that drops this candidate fails the resolve (NotFound) WITHOUT
        // leaking a draft. The cap-memory `resolve` re-checks pending UNDER the
        // candidate-file lock, so it is the authoritative guard.
        if action == CandidateAction::Accept {
            // Reject an invalid candidate name up front so `propose_draft` cannot
            // fail on the name AFTER the terminal event is already appended.
            security_scan::validate_skill_name(&cand.name)?;
        }

        let resolution = match action {
            CandidateAction::Accept => cap_memory::Resolution::Accept,
            CandidateAction::Dismiss => cap_memory::Resolution::Dismiss,
        };
        let cid = candidate_id.to_string();
        {
            let dir = dir.clone();
            let cid = cid.clone();
            tokio::task::spawn_blocking(move || {
                cap_memory::SkillCandidateStore::in_dir(&dir).resolve(&cid, resolution)
            })
            .await
            .map_err(|e| SkillError::InvalidTransition(format!("skill candidate store task: {e}")))?
            // The unlocked pre-list (above) can go stale before this LOCKED resolve:
            // a concurrent producer compaction can drop the candidate (or another
            // resolver can terminalize it) in the window between. cap-memory then
            // returns NotFound/AlreadyResolved — the SAME logical outcome as the
            // pre-list miss and double-resolve, so project it as `not-found`
            // (WIT `not-found`), NOT a misleading `internal` (adversarial r4, W-B).
            // A genuine store fault (I/O, oversize) stays `InvalidTransition`.
            .map_err(|e| match e {
                cap_memory::SkillCandidateError::NotFound(_)
                | cap_memory::SkillCandidateError::AlreadyResolved(_) => {
                    SkillError::SkillNotFound("candidate not found".to_string())
                }
                other => SkillError::InvalidTransition(format!("skill candidate resolve: {other}")),
            })?;
        }

        // Accept → propose the ACTIVATABLE SKILL.md SCAFFOLD now that the candidate
        // is terminally resolved (PRD §12.6.7 "accept → draft scaffold"), NOT the raw
        // description — `activate-skill` requires §1.3.2 YAML frontmatter. The
        // (pre-validated) `name` is regex-safe in the frontmatter; the `description`
        // is a fixed safe scalar; the candidate's proposal text goes in the markdown
        // BODY (escaping-safe; still scanned by activate). Dismiss → empty draft-id.
        //
        // Ordering note (adversarial r4 W-A / r6 W-16-1): the terminal append is
        // DELIBERATELY committed before this draft proposal. The two stores (candidate
        // log + draft store) are separate append-only logs with no shared transaction,
        // so SOME swap-point is unavoidable; this order fails CLOSED — a hard
        // draft-write I/O fault after the terminal append loses the candidate but
        // leaves NO orphan draft and CANNOT resurrect it.
        //
        // Why NOT the reverse (draft-first + compensating delete)? `propose_draft` is
        // NAME-KEYED UPSERT (the draft-id IS the skill name; a second propose with the
        // same name OVERWRITES). So a draft-first order whose terminal append then loses
        // the W2 compaction race would have to `delete_draft(name)` to avoid an orphan —
        // but that would DESTROY a user's pre-existing same-named draft (overwritten by
        // the upsert, unrecoverable). Terminal-first is therefore the least-bad design,
        // not a shortcut.
        //
        // Residual (r6 W-16-1, accepted Info): on a hard draft-write fault the accepted
        // candidate is consumed and — since r5's finality tombstone is retained — stays
        // SUPPRESSED from regeneration until the tombstone is evicted (after
        // MAX_TERMINAL_TOMBSTONES newer terminals). Recoverable by manually creating the
        // skill or by that eviction; not attacker-reachable (`name` is regex-checked and
        // content ≤ ~4.5 KiB ≪ MAX_CONTENT_LEN, so the ONLY residual `propose_draft`
        // failure is a raw disk/sweep I/O fault, never guest/LLM-controlled).
        let draft_id = match action {
            CandidateAction::Accept => {
                let content = format!(
                    "---\nname: {name}\ndescription: L6-proposed skill candidate\n---\n\n\
                     # {name}\n\n{desc}\n\n\
                     <!-- Auto-scaffolded from an L6 skill candidate; edit, then activate. -->\n",
                    name = cand.name,
                    desc = cand.description,
                );
                self.propose_draft(cand.name.clone(), content, Vec::new())
                    .await?
            }
            CandidateAction::Dismiss => String::new(),
        };
        Ok(CandidateResult {
            candidate_id: cid,
            draft_id,
        })
    }

    // ─── Admin (NOT a host_fn) ────────────────────────────────────

    /// Admin: flip an active skill's trust level from `Untrusted` →
    /// `Trusted`. Idempotent: re-elevating a `Trusted` skill is a no-op.
    ///
    /// NOT exposed via `register_agent_skills`. Callers must hold admin
    /// authority out-of-band. See SC-19 for the registry-lookup absence test.
    pub async fn elevate_trust(&self, skill_id: &str) -> Result<(), SkillError> {
        security_scan::validate_skill_name(skill_id)?;
        let mut active = self
            .storage
            .read_active(skill_id)
            .await?
            .ok_or_else(|| SkillError::SkillNotFound(skill_id.to_string()))?;
        active.trust_level = TrustLevel::Trusted;
        self.storage.write_active(&active).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::InMemorySkillStorage;

    fn valid_content(name: &str) -> String {
        format!("---\nname: {name}\ndescription: x\n---\n# {name}\n")
    }

    // ─────────────────────────────────────────────────────────────
    // Slice A regression — 18 SA tests adapted to #[tokio::test]
    // ─────────────────────────────────────────────────────────────

    /// SA-01: propose_draft fresh path.
    #[tokio::test]
    async fn sa_01_propose_draft_fresh() {
        let store = SkillStore::new();
        let id = store
            .propose_draft("foo".into(), valid_content("foo"), vec!["x".into()])
            .await
            .unwrap();
        assert_eq!(id, "foo", "Slice C: draft_id == name");
        let drafts = store.list_drafts().await.unwrap();
        assert_eq!(drafts.len(), 1);
        let d = &drafts[0];
        assert_eq!(d.name, "foo");
        assert_eq!(d.tags, vec!["x".to_string()]);
        assert_eq!(d.parent, None);
        assert_eq!(d.reason, None);
    }

    /// SA-02 (Slice C update): same name yields SAME draft_id (name-keyed).
    #[tokio::test]
    async fn sa_02_propose_draft_twice_same_name_same_id() {
        let store = SkillStore::new();
        let id1 = store
            .propose_draft("foo".into(), valid_content("foo"), vec![])
            .await
            .unwrap();
        let id2 = store
            .propose_draft("foo".into(), valid_content("foo2"), vec![])
            .await
            .unwrap();
        assert_eq!(id1, id2, "Slice C: name-keyed; second call updates");
        assert_eq!(id1, "foo");
        let drafts = store.list_drafts().await.unwrap();
        assert_eq!(drafts.len(), 1, "single draft per name");
        assert!(drafts[0].content.contains("foo2"));
    }

    /// SA-03: update_draft happy path + DraftNotFound.
    #[tokio::test]
    async fn sa_03_update_draft() {
        let store = SkillStore::new();
        let id = store
            .propose_draft("foo".into(), valid_content("foo"), vec![])
            .await
            .unwrap();
        store.update_draft(&id, "updated".into()).await.unwrap();
        assert_eq!(
            store.get_draft(&id).await.unwrap().unwrap().content,
            "updated"
        );
        let err = store
            .update_draft("nonexistent", "x".into())
            .await
            .unwrap_err();
        assert_eq!(err, SkillError::DraftNotFound("nonexistent".to_string()));
    }

    /// SA-04: activate v1 + activate v2; history grows; skill_id == name.
    #[tokio::test]
    async fn sa_04_activate_versioning() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("bar".into(), valid_content("bar"), vec![])
            .await
            .unwrap();
        let sid = store.activate(&d1).await.unwrap();
        assert_eq!(sid, "bar");
        assert_eq!(store.get("bar").await.unwrap().version, 1);

        let d2 = store
            .propose_draft("bar".into(), valid_content("bar"), vec![])
            .await
            .unwrap();
        let sid2 = store.activate(&d2).await.unwrap();
        assert_eq!(sid2, "bar");
        assert_eq!(store.get("bar").await.unwrap().version, 2);

        let history = store.list_history("bar").await.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].version, 1);
        assert_eq!(history[1].version, 2);
    }

    /// SA-05: rollback restores content + bumps version.
    #[tokio::test]
    async fn sa_05_rollback_restores_content_bumps_version() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("rb".into(), valid_content("rb-v1"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        let d2 = store
            .propose_draft("rb".into(), valid_content("rb-v2"), vec![])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();

        store.rollback("rb", 1).await.unwrap();
        let cur = store.get("rb").await.unwrap();
        assert_eq!(cur.version, 3);
        assert!(cur.content.contains("rb-v1"));
    }

    /// SA-06: rollback to non-existent version → VersionNotFound.
    #[tokio::test]
    async fn sa_06_rollback_version_not_found() {
        let store = SkillStore::new();
        let d = store
            .propose_draft("vk".into(), valid_content("vk"), vec![])
            .await
            .unwrap();
        store.activate(&d).await.unwrap();

        let err = store.rollback("vk", 99).await.unwrap_err();
        assert_eq!(
            err,
            SkillError::VersionNotFound {
                skill_id: "vk".to_string(),
                version: 99
            }
        );
    }

    /// SA-07: delete tombstone semantics.
    #[tokio::test]
    async fn sa_07_delete_tombstone() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("dl".into(), valid_content("dl-v1"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        let d2 = store
            .propose_draft("dl".into(), valid_content("dl-v2"), vec![])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();

        store.delete("dl").await.unwrap();

        // get returns SkillNotFound.
        assert_eq!(
            store.get("dl").await.unwrap_err(),
            SkillError::SkillNotFound("dl".to_string())
        );
        // list_history still returns archived versions.
        let history = store.list_history("dl").await.unwrap();
        assert_eq!(history.len(), 2);
        let versions: Vec<u32> = history.iter().map(|s| s.version).collect();
        assert_eq!(versions, vec![1, 2]);
    }

    /// SA-08: activate non-existent draft → DraftNotFound.
    #[tokio::test]
    async fn sa_08_activate_unknown_draft() {
        let store = SkillStore::new();
        let err = store.activate("unknown-draft").await.unwrap_err();
        assert_eq!(err, SkillError::DraftNotFound("unknown-draft".to_string()));
    }

    /// SA-09: propose_patch parent + reason + tag inheritance + version bump.
    #[tokio::test]
    async fn sa_09_propose_patch() {
        let store = SkillStore::new();
        let bar_tags = vec!["initial".to_string(), "marker".to_string()];
        let d_init = store
            .propose_draft("bar".into(), valid_content("bar-v1"), bar_tags.clone())
            .await
            .unwrap();
        store.activate(&d_init).await.unwrap();

        let patch_id = store
            .propose_patch("bar", valid_content("bar-patched"), "fix typo".into())
            .await
            .unwrap();
        assert_eq!(patch_id, "bar", "Slice C: patch draft_id == name");
        let patch_draft = store.get_draft(&patch_id).await.unwrap().unwrap();
        assert_eq!(patch_draft.name, "bar");
        assert_eq!(patch_draft.parent, Some("bar".to_string()));
        assert_eq!(patch_draft.reason, Some("fix typo".to_string()));
        assert_eq!(patch_draft.tags, bar_tags);

        // Activate the patch — bumps bar's version.
        let sid = store.activate(&patch_id).await.unwrap();
        assert_eq!(sid, "bar");
        assert_eq!(store.get("bar").await.unwrap().version, 2);

        // Negative path.
        let err = store
            .propose_patch("unknown-skill", "x".into(), "y".into())
            .await
            .unwrap_err();
        assert_eq!(err, SkillError::SkillNotFound("unknown-skill".to_string()));
    }

    /// SA-19: resurrection chain-continuation.
    #[tokio::test]
    async fn sa_19_resurrection_continues_chain() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("baz".into(), valid_content("baz-v1"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        let d2 = store
            .propose_draft("baz".into(), valid_content("baz-v2"), vec![])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();

        store.delete("baz").await.unwrap();

        // Resurrection: new active should be v3.
        let d3 = store
            .propose_draft("baz".into(), valid_content("baz-v3"), vec![])
            .await
            .unwrap();
        store.activate(&d3).await.unwrap();
        assert_eq!(store.get("baz").await.unwrap().version, 3);

        let history = store.list_history("baz").await.unwrap();
        let versions: Vec<u32> = history.iter().map(|s| s.version).collect();
        assert_eq!(versions, vec![1, 2, 3], "strictly-ascending");
    }

    /// SA-20: rollback on tombstoned skill → SkillNotFound.
    #[tokio::test]
    async fn sa_20_rollback_on_tombstoned_skill() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("qux".into(), valid_content("qux-v1"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        let d2 = store
            .propose_draft("qux".into(), valid_content("qux-v2"), vec![])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();

        store.delete("qux").await.unwrap();

        let err = store.rollback("qux", 1).await.unwrap_err();
        assert_eq!(err, SkillError::SkillNotFound("qux".to_string()));
    }

    /// SA-21: edge cases — draft consumption + double-activate +
    /// update_draft after activate.
    #[tokio::test]
    async fn sa_21_activate_edge_cases() {
        let store = SkillStore::new();
        let d = store
            .propose_draft("ec".into(), valid_content("ec"), vec![])
            .await
            .unwrap();
        store.activate(&d).await.unwrap();

        assert!(
            store.get_draft(&d).await.unwrap().is_none(),
            "activated draft should be consumed"
        );
        assert!(
            store.list_drafts().await.unwrap().is_empty(),
            "list_drafts excludes activated drafts"
        );

        let err1 = store.activate(&d).await.unwrap_err();
        assert_eq!(err1, SkillError::DraftNotFound(d.clone()));

        let err2 = store.update_draft(&d, "x".into()).await.unwrap_err();
        assert_eq!(err2, SkillError::DraftNotFound(d));
    }

    /// SA-22: rollback to current version no-op success + version bump.
    #[tokio::test]
    async fn sa_22_rollback_to_current_version_no_op_bump() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("zog".into(), valid_content("zog-v1"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        let d2 = store
            .propose_draft("zog".into(), valid_content("zog-v2"), vec![])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();

        store.rollback("zog", 2).await.unwrap();
        let cur = store.get("zog").await.unwrap();
        assert_eq!(cur.version, 3, "rollback-to-current bumps version");
        assert!(cur.content.contains("zog-v2"));
    }

    /// SA-23: storage list_drafts always reflects stored drafts (the
    /// Slice A MAX_DRAFTS in-memory cap is gone; storage is the bound).
    /// Sanity check: a few drafts written, all visible.
    #[tokio::test]
    async fn sa_23_storage_drafts_visible() {
        let store = SkillStore::new();
        for i in 0..5 {
            store
                .propose_draft(format!("n{i}"), valid_content(&format!("n{i}")), vec![])
                .await
                .unwrap();
        }
        assert_eq!(store.list_drafts().await.unwrap().len(), 5);
    }

    /// SA-24: u32 version overflow on activate → InvalidTransition. The
    /// peek-then-mutate ordering preserves draft + active on error.
    #[tokio::test]
    async fn sa_24_u32_overflow_returns_invalid_transition() {
        let storage = Arc::new(InMemorySkillStorage::new());
        // Plant an active at u32::MAX directly.
        storage
            .write_active(&SkillBlob {
                skill_id: "ovf".to_string(),
                version: u32::MAX,
                content: valid_content("ovf"),
                tags: vec!["max-tag".to_string()],
                provenance: Provenance::AgentCreated,
                trust_level: TrustLevel::Untrusted,
            })
            .await
            .unwrap();
        let store = SkillStore::with_storage(storage.clone());

        let d = store
            .propose_draft("ovf".into(), valid_content("ovf-next"), vec![])
            .await
            .unwrap();
        let err = store.activate(&d).await.unwrap_err();
        match err {
            SkillError::InvalidTransition(ref msg) => {
                assert!(
                    msg.contains("version overflow"),
                    "expected overflow message, got: {msg}"
                );
            }
            other => panic!("expected InvalidTransition, got: {other:?}"),
        }

        // Active preserved + draft preserved.
        let surviving = store.get("ovf").await.unwrap();
        assert_eq!(surviving.version, u32::MAX);
        assert!(
            store.get_draft(&d).await.unwrap().is_some(),
            "draft preserved on activate error"
        );
    }

    /// SA-27 (Slice C update): explicit `ContentTooLarge` rejection
    /// (was: Slice A silent truncation).
    #[tokio::test]
    async fn sa_27_propose_draft_rejects_oversized_content() {
        let store = SkillStore::new();
        let oversized = "x".repeat(MAX_CONTENT_LEN + 100);
        let err = store
            .propose_draft("n".into(), oversized.clone(), vec![])
            .await
            .unwrap_err();
        match err {
            SkillError::ContentTooLarge(n) => {
                assert_eq!(n, oversized.len(), "payload carries observed byte count");
            }
            other => panic!("expected ContentTooLarge, got: {other:?}"),
        }
        // Tags + name still silent-truncate (Slice C kept Slice A behavior
        // for non-content fields).
        let oversized_tag = "c".repeat(MAX_TAG_LEN + 50);
        let id = store
            .propose_draft("n2".into(), valid_content("n2"), vec![oversized_tag])
            .await
            .unwrap();
        let d = store.get_draft(&id).await.unwrap().unwrap();
        assert_eq!(d.tags[0].len(), MAX_TAG_LEN);
    }

    /// SA-26 (Slice C adaptation): storage backend handles many actives.
    /// Slice A's MAX_ACTIVE_SKILLS in-memory cap is gone (disk-backed).
    #[tokio::test]
    async fn sa_26_storage_handles_many_actives() {
        let store = SkillStore::new();
        for i in 0..10 {
            let name = format!("a{i}");
            let d = store
                .propose_draft(name.clone(), valid_content(&name), vec![])
                .await
                .unwrap();
            store.activate(&d).await.unwrap();
        }
        // All 10 reachable.
        for i in 0..10 {
            assert!(store.get(&format!("a{i}")).await.is_ok());
        }
    }

    // ─────────────────────────────────────────────────────────────
    // SC-09..SC-19: Trust matrix (4-cell + admin elevate)
    // ─────────────────────────────────────────────────────────────

    /// Seed an Imported skill directly via storage (test helper —
    /// `propose_draft + activate` always produces `AgentCreated`).
    async fn seed_active(
        storage: &Arc<InMemorySkillStorage>,
        skill_id: &str,
        provenance: Provenance,
        trust_level: TrustLevel,
    ) {
        storage
            .write_active(&SkillBlob {
                skill_id: skill_id.to_string(),
                version: 1,
                content: valid_content(skill_id),
                tags: vec![],
                provenance,
                trust_level,
            })
            .await
            .unwrap();
    }

    /// SC-09: AgentCreated + Untrusted → propose_patch OK.
    #[tokio::test]
    async fn sc_09_agent_untrusted_patch_ok() {
        let store = SkillStore::new();
        let d = store
            .propose_draft("sk".into(), valid_content("sk"), vec![])
            .await
            .unwrap();
        store.activate(&d).await.unwrap(); // AgentCreated + Untrusted
        let r = store
            .propose_patch("sk", valid_content("sk-patched"), "r".into())
            .await;
        assert!(r.is_ok(), "patch on AgentCreated+Untrusted should succeed");
    }

    /// SC-10: AgentCreated + Untrusted → delete OK.
    #[tokio::test]
    async fn sc_10_agent_untrusted_delete_ok() {
        let store = SkillStore::new();
        let d = store
            .propose_draft("sk".into(), valid_content("sk"), vec![])
            .await
            .unwrap();
        store.activate(&d).await.unwrap();
        assert!(store.delete("sk").await.is_ok());
    }

    /// SC-11: AgentCreated + Untrusted → rollback OK.
    #[tokio::test]
    async fn sc_11_agent_untrusted_rollback_ok() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("sk".into(), valid_content("sk-v1"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        let d2 = store
            .propose_draft("sk".into(), valid_content("sk-v2"), vec![])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();
        assert!(store.rollback("sk", 1).await.is_ok());
    }

    /// SC-12: Imported + Untrusted → propose_patch OK.
    #[tokio::test]
    async fn sc_12_imported_untrusted_patch_ok() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_active(&storage, "sk", Provenance::Imported, TrustLevel::Untrusted).await;
        let store = SkillStore::with_storage(storage);
        let r = store
            .propose_patch("sk", valid_content("sk-patched"), "r".into())
            .await;
        assert!(
            r.is_ok(),
            "Imported+Untrusted patch is allowed per PRD §5028"
        );
    }

    /// SC-13: Imported + Untrusted → delete TrustViolation.
    #[tokio::test]
    async fn sc_13_imported_untrusted_delete_blocked() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_active(&storage, "sk", Provenance::Imported, TrustLevel::Untrusted).await;
        let store = SkillStore::with_storage(storage);
        let err = store.delete("sk").await.unwrap_err();
        assert!(matches!(err, SkillError::TrustViolation(_)));
    }

    /// SC-14: Imported + Untrusted → rollback TrustViolation.
    #[tokio::test]
    async fn sc_14_imported_untrusted_rollback_blocked() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_active(&storage, "sk", Provenance::Imported, TrustLevel::Untrusted).await;
        let store = SkillStore::with_storage(storage);
        let err = store.rollback("sk", 1).await.unwrap_err();
        assert!(matches!(err, SkillError::TrustViolation(_)));
    }

    /// SC-15: * + Trusted → propose_patch TrustViolation.
    #[tokio::test]
    async fn sc_15_trusted_patch_blocked() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_active(
            &storage,
            "sk",
            Provenance::AgentCreated,
            TrustLevel::Trusted,
        )
        .await;
        let store = SkillStore::with_storage(storage);
        let err = store
            .propose_patch("sk", valid_content("sk-patched"), "r".into())
            .await
            .unwrap_err();
        assert!(matches!(err, SkillError::TrustViolation(_)));
    }

    /// SC-16: * + Trusted → delete TrustViolation.
    #[tokio::test]
    async fn sc_16_trusted_delete_blocked() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_active(&storage, "sk", Provenance::Imported, TrustLevel::Trusted).await;
        let store = SkillStore::with_storage(storage);
        let err = store.delete("sk").await.unwrap_err();
        assert!(matches!(err, SkillError::TrustViolation(_)));
    }

    /// SC-17: * + Trusted → rollback TrustViolation.
    #[tokio::test]
    async fn sc_17_trusted_rollback_blocked() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_active(
            &storage,
            "sk",
            Provenance::AgentCreated,
            TrustLevel::Trusted,
        )
        .await;
        let store = SkillStore::with_storage(storage);
        let err = store.rollback("sk", 1).await.unwrap_err();
        assert!(matches!(err, SkillError::TrustViolation(_)));
    }

    /// Audit round 3 fix: propose_draft REJECTS path-traversal names with
    /// InvalidName BEFORE any storage write — closes the surface where
    /// `propose_draft("../../etc/foo", ...)` could persist outside the
    /// agent root.
    #[tokio::test]
    async fn audit_round_3_propose_draft_rejects_path_traversal_names() {
        let store = SkillStore::new();
        let bad_names = [
            "../../etc/passwd",
            "/etc/foo",
            "..",
            ".hidden",
            "with/slash",
            "with\\backslash",
            "with\0null",
            "UPPERCASE",
            "with space",
        ];
        for bad in bad_names {
            let err = store
                .propose_draft(bad.into(), valid_content("x"), vec![])
                .await
                .unwrap_err();
            assert!(
                matches!(err, SkillError::InvalidName(_)),
                "name {bad:?} should be rejected with InvalidName, got: {err:?}"
            );
        }
        // No draft persisted on rejection.
        assert!(store.list_drafts().await.unwrap().is_empty());
    }

    /// Audit round 3 fix: update_draft / propose_patch / activate / rollback
    /// / delete / elevate_trust all validate the agent-supplied
    /// name/draft_id BEFORE any storage interpolation.
    #[tokio::test]
    async fn audit_round_3_all_public_methods_validate_names() {
        let store = SkillStore::new();
        let bad = "../escape";

        // update_draft
        let err = store.update_draft(bad, "x".into()).await.unwrap_err();
        assert!(matches!(err, SkillError::InvalidName(_)));

        // propose_patch
        let err = store
            .propose_patch(bad, "x".into(), "y".into())
            .await
            .unwrap_err();
        assert!(matches!(err, SkillError::InvalidName(_)));

        // activate
        let err = store.activate(bad).await.unwrap_err();
        assert!(matches!(err, SkillError::InvalidName(_)));

        // rollback
        let err = store.rollback(bad, 1).await.unwrap_err();
        assert!(matches!(err, SkillError::InvalidName(_)));

        // delete
        let err = store.delete(bad).await.unwrap_err();
        assert!(matches!(err, SkillError::InvalidName(_)));

        // elevate_trust
        let err = store.elevate_trust(bad).await.unwrap_err();
        assert!(matches!(err, SkillError::InvalidName(_)));
    }

    /// SC-18b (audit round 1 fix): elevate Untrusted → Trusted, then
    /// `propose_draft + activate` is BLOCKED (Trusted bypass closed).
    #[tokio::test]
    async fn sc_18b_elevate_then_activate_blocks_trusted_bypass() {
        let store = SkillStore::new();
        let d = store
            .propose_draft("sk".into(), valid_content("sk"), vec![])
            .await
            .unwrap();
        store.activate(&d).await.unwrap();
        store.elevate_trust("sk").await.unwrap();

        // Attempt the Trusted-bypass: agent re-proposes a draft for the
        // same name, then activates. Pre-fix: silently overwrites the
        // Trusted skill. Post-fix: TrustViolation at activate.
        let d2 = store
            .propose_draft("sk".into(), valid_content("malicious"), vec![])
            .await
            .unwrap();
        let err = store.activate(&d2).await.unwrap_err();
        assert!(
            matches!(err, SkillError::TrustViolation(_)),
            "activate must block when prior is Trusted, got: {err:?}"
        );
        // The Trusted skill content is preserved.
        let s = store.get("sk").await.unwrap();
        assert!(s.content.contains("name: sk"), "Trusted content untouched");
        assert!(matches!(s.trust_level, TrustLevel::Trusted));
    }

    /// SC-18: elevate Untrusted → Trusted, then propose_patch blocks.
    #[tokio::test]
    async fn sc_18_elevate_then_patch_blocks() {
        let store = SkillStore::new();
        let d = store
            .propose_draft("sk".into(), valid_content("sk"), vec![])
            .await
            .unwrap();
        store.activate(&d).await.unwrap(); // AgentCreated + Untrusted

        // First patch succeeds.
        assert!(store
            .propose_patch("sk", valid_content("sk-v2"), "r".into())
            .await
            .is_ok());

        // Admin elevates trust.
        store.elevate_trust("sk").await.unwrap();
        let s = store.get("sk").await.unwrap();
        assert!(matches!(s.trust_level, TrustLevel::Trusted));

        // Second patch blocked.
        let err = store
            .propose_patch("sk", valid_content("sk-v3"), "r".into())
            .await
            .unwrap_err();
        assert!(matches!(err, SkillError::TrustViolation(_)));
    }

    // SC-19: elevate_trust is NOT a host_fn — verified in host_fn.rs tests
    // (see SC-19 in host_fn::tests).

    // ─────────────────────────────────────────────────────────────
    // SC-01..SC-08: lifecycle integration (in-memory; disk variants
    // live in tests/lifecycle_disk.rs)
    // ─────────────────────────────────────────────────────────────

    /// SC-01-mem: propose → activate → rollback → delete happy path.
    #[tokio::test]
    async fn sc_01_happy_path_in_memory() {
        let store = SkillStore::new();
        let d = store
            .propose_draft("hp".into(), valid_content("hp-v1"), vec!["t".into()])
            .await
            .unwrap();
        store.activate(&d).await.unwrap();
        assert_eq!(store.get("hp").await.unwrap().version, 1);

        let d2 = store
            .propose_draft("hp".into(), valid_content("hp-v2"), vec!["t".into()])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();
        assert_eq!(store.get("hp").await.unwrap().version, 2);

        store.rollback("hp", 1).await.unwrap();
        assert_eq!(store.get("hp").await.unwrap().version, 3);

        store.delete("hp").await.unwrap();
        assert!(matches!(
            store.get("hp").await.unwrap_err(),
            SkillError::SkillNotFound(_)
        ));
    }

    /// SC-06: activate v1 → patch+activate v2 → rollback to v1 → active = v1 content.
    #[tokio::test]
    async fn sc_06_rollback_after_patch() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("foo".into(), valid_content("foo-v1"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();

        let d2 = store
            .propose_patch("foo", valid_content("foo-v2"), "patch".into())
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();
        assert_eq!(store.get("foo").await.unwrap().version, 2);

        store.rollback("foo", 1).await.unwrap();
        let cur = store.get("foo").await.unwrap();
        assert_eq!(cur.version, 3);
        assert!(cur.content.contains("foo-v1"));
    }

    /// SC-07: name-keyed update — second propose_draft overwrites SKILL.md.
    #[tokio::test]
    async fn sc_07_name_keyed_update() {
        let store = SkillStore::new();
        let id1 = store
            .propose_draft("foo".into(), valid_content("foo-c1"), vec![])
            .await
            .unwrap();
        let id2 = store
            .propose_draft("foo".into(), valid_content("foo-c2"), vec![])
            .await
            .unwrap();
        assert_eq!(id1, id2);
        let d = store.get_draft(&id2).await.unwrap().unwrap();
        assert!(d.content.contains("foo-c2"));
    }

    // ─────────────────────────────────────────────────────────────
    // SC-05a/b/c: 24h sweep at 3 entry-points
    // ─────────────────────────────────────────────────────────────

    /// Seed a backdated draft (created 25h ago) directly via storage.
    async fn seed_backdated_draft(storage: &Arc<InMemorySkillStorage>, name: &str) {
        let stale = Utc::now() - Duration::hours(25);
        storage
            .write_draft(&DraftBlob {
                name: name.to_string(),
                content: valid_content(name),
                tags: vec![],
                parent: None,
                reason: None,
                created_at: stale,
            })
            .await
            .unwrap();
    }

    /// SC-05a: propose_draft fires sweep → old drafts removed.
    #[tokio::test]
    async fn sc_05a_sweep_on_propose_draft() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_backdated_draft(&storage, "stale").await;
        let store = SkillStore::with_storage(storage.clone());
        assert_eq!(store.list_drafts().await.unwrap().len(), 1);

        // Fire sweep via propose_draft.
        store
            .propose_draft("fresh".into(), valid_content("fresh"), vec![])
            .await
            .unwrap();
        // Stale draft swept; only "fresh" remains.
        let drafts = store.list_drafts().await.unwrap();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].name, "fresh");
    }

    /// SC-05b: activate fires sweep → old drafts removed.
    #[tokio::test]
    async fn sc_05b_sweep_on_activate() {
        let storage = Arc::new(InMemorySkillStorage::new());
        // Plant a fresh draft to activate + a stale one to sweep.
        storage
            .write_draft(&DraftBlob {
                name: "fresh".into(),
                content: valid_content("fresh"),
                tags: vec![],
                parent: None,
                reason: None,
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        seed_backdated_draft(&storage, "stale").await;
        let store = SkillStore::with_storage(storage.clone());

        store.activate("fresh").await.unwrap();
        // Stale draft swept; activated draft consumed.
        let drafts = store.list_drafts().await.unwrap();
        assert!(
            drafts.is_empty(),
            "both drafts gone (one swept, one activated)"
        );
    }

    /// SC-05c: list_skill_candidates fires sweep → old drafts removed.
    #[tokio::test]
    async fn sc_05c_sweep_on_list_candidates() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_backdated_draft(&storage, "stale").await;
        let store = SkillStore::with_storage(storage.clone());
        assert_eq!(store.list_drafts().await.unwrap().len(), 1);

        let candidates = store.list_skill_candidates().await.unwrap();
        assert!(
            candidates.is_empty(),
            "Slice C: candidates list is empty stub"
        );
        // Sweep took effect.
        assert!(store.list_drafts().await.unwrap().is_empty());
    }

    /// SC-04 (boundary): 23h-old draft preserved.
    #[tokio::test]
    async fn sc_04_boundary_23h_preserved() {
        let storage = Arc::new(InMemorySkillStorage::new());
        let nearly_stale = Utc::now() - Duration::hours(23);
        storage
            .write_draft(&DraftBlob {
                name: "n".into(),
                content: valid_content("n"),
                tags: vec![],
                parent: None,
                reason: None,
                created_at: nearly_stale,
            })
            .await
            .unwrap();
        let store = SkillStore::with_storage(storage.clone());
        store.startup_cleanup().await.unwrap();
        assert_eq!(store.list_drafts().await.unwrap().len(), 1);
    }

    /// SC-03: startup_cleanup removes 25h-old draft.
    #[tokio::test]
    async fn sc_03_startup_cleanup_removes_stale() {
        let storage = Arc::new(InMemorySkillStorage::new());
        seed_backdated_draft(&storage, "stale").await;
        let store = SkillStore::with_storage(storage.clone());
        assert_eq!(store.list_drafts().await.unwrap().len(), 1);
        store.startup_cleanup().await.unwrap();
        assert!(store.list_drafts().await.unwrap().is_empty());
    }

    // ─────────────────────────────────────────────────────────────
    // Security scan wired into activate
    // ─────────────────────────────────────────────────────────────

    /// activate runs the 6 §1.3.2 checks. Invalid frontmatter blocks
    /// activate even though propose_draft accepted the content.
    #[tokio::test]
    async fn activate_runs_security_scan_invalid_frontmatter() {
        let store = SkillStore::new();
        // propose_draft accepts arbitrary content (size only); scan happens at activate.
        let d = store
            .propose_draft("bad".into(), "no frontmatter here".into(), vec![])
            .await
            .unwrap();
        let err = store.activate(&d).await.unwrap_err();
        assert!(matches!(err, SkillError::InvalidFrontmatter(_)));
    }

    /// activate's scan excludes the patched skill_id from name-conflict
    /// check so existing-Active patch path doesn't trigger NameConflict.
    #[tokio::test]
    async fn activate_existing_active_no_self_name_conflict() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("dup".into(), valid_content("dup"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        // Second activate with same name (existing-Active path) should NOT
        // trigger NameConflict.
        let d2 = store
            .propose_draft("dup".into(), valid_content("dup-v2"), vec![])
            .await
            .unwrap();
        let r = store.activate(&d2).await;
        assert!(
            r.is_ok(),
            "same-name activate should not self-conflict: {r:?}"
        );
        assert_eq!(store.get("dup").await.unwrap().version, 2);
    }

    /// Resurrection chain preserves AgentCreated provenance (new activate
    /// after delete is a fresh AgentCreated chain — patch matrix tests this).
    #[tokio::test]
    async fn resurrect_yields_agent_created() {
        let store = SkillStore::new();
        let d1 = store
            .propose_draft("rs".into(), valid_content("rs"), vec![])
            .await
            .unwrap();
        store.activate(&d1).await.unwrap();
        store.delete("rs").await.unwrap();
        let d2 = store
            .propose_draft("rs".into(), valid_content("rs"), vec![])
            .await
            .unwrap();
        store.activate(&d2).await.unwrap();
        let s = store.get("rs").await.unwrap();
        assert!(matches!(s.provenance, Provenance::AgentCreated));
        assert!(matches!(s.trust_level, TrustLevel::Untrusted));
    }
}
