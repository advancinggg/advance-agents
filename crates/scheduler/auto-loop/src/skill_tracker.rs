//! SkillPreState tracking primitives for the per-iteration discard/rollback
//! protocol (PRD §12.6.5 / MODULE-015 §1.4 AC-18 + AC-21 SkillPreState row).
//!
//! Crate-boundary note (m015-slice-c): [`SkillTracker`] is a STANDALONE struct,
//! NOT a field on [`crate::state::AutoState`]. The slice brief constrains
//! `src/` edits to `{skill_tracker, round_advancer, checkpoint, rollback,
//! results}.rs` only, so the tracker lives alongside `AutoState` (held by
//! callers, e.g., the future integrated §4.7.7 loop slice). The integrated
//! slice may move the tracker inside `AutoState` once `state.rs` becomes
//! editable.
//!
//! The future MODULE-017 cap-skills slice (m017-e) will ship a production
//! [`SkillRollback`] impl bound to the host-fn ABI; this slice ships only the
//! trait surface + [`NoopSkillRollback`] default impl. The
//! `RecordingSkillRollback` test double lives in `tests/common/mod.rs` (NOT
//! in `src/`) so the production public API stays minimal.
//!
//! # CONTRACT-164 boundary (read-only) vs `SkillRollback` (write)
//!
//! [`advance_shared_types::skills::SkillStateReader`] is READ-ONLY by
//! contract (only `active_skills` / `skill_version` / `provenance` /
//! `trust_level`). The write-side `rollback_skill(agent_id, skill_id,
//! version)` / `delete_skill(agent_id, skill_id)` surface lives here, local
//! to MODULE-015, until m017-e ships a cap-skills production impl with
//! matching signatures.
//!
//! # Lifecycle
//!
//! 1. **Pre-activation** (before `cap-skills::activate-skill(skill_id)`):
//!    caller reads `current_version` via [`advance_shared_types::skills::SkillStateReader::skill_version`]
//!    (None if skill absent) and calls [`SkillTracker::record_pre_activation`].
//!    First-insert-wins — re-activating the same skill within the same
//!    iteration does NOT overwrite the recorded pre-state (PRD §12.6.5).
//! 2. **Iteration KEEP**: caller invokes [`SkillTracker::clear`]; no
//!    `SkillRollback` calls.
//! 3. **Iteration DISCARD**: caller invokes
//!    [`SkillTracker::apply_discard`] passing a [`SkillRollback`] impl. The
//!    tracker iterates entries in deterministic sort order (by `skill_id`
//!    string compare) and dispatches per-variant:
//!    - [`SkillPreState::Absent`] → [`SkillRollback::delete_skill`]
//!    - [`SkillPreState::Version`]`(n)` → [`SkillRollback::rollback_skill(_, _, n)`]

use std::collections::HashMap;

use async_trait::async_trait;

/// Defensive cap on number of distinct skill_ids tracked per iteration
/// (adversarial Round-1 W1 fix). A hostile/buggy WASM caller racing
/// `cap-skills::activate-skill` with synthesized skill_ids could otherwise
/// grow the tracker unbounded. PRD §12.6.5 doesn't pin an upper bound,
/// but real iterations rarely activate more than a handful of skills —
/// 256 is >>realistic per-iteration activation count.
pub const MAX_TRACKED_SKILLS: usize = 256;

/// Defensive cap on `skill_id` length (adversarial Round-1 W1 fix).
/// CONTRACT-164 `SkillStateReader` docstring recommends `skill_id` ≤ 128
/// bytes; we accept up to 256 here for defense-in-depth with a 2× margin.
/// Longer IDs are rejected by `record_pre_activation` (silently dropped —
/// the caller's responsibility to pre-validate).
pub const MAX_SKILL_ID_BYTES: usize = 256;

/// Per PRD §12.6.5: state of a skill BEFORE first activation in the current
/// iteration. Iteration DISCARD restores the skill to this state.
///
/// First-insert-wins per iteration (see [`SkillTracker::record_pre_activation`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkillPreState {
    /// Skill did not exist before this iteration → delete on discard.
    Absent,
    /// Skill existed at version `N` → rollback to `N` on discard.
    Version(u32),
}

/// Local error type for the skill-tracker subsystem.
///
/// Intentionally NOT folded into [`crate::error::AutoLoopError`] because
/// `error.rs` is outside the slice-C allowlist (per task brief). The future
/// integrated-loop slice may wrap this into `AutoLoopError::SkillRollback`
/// when `error.rs` becomes editable.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SkillTrackerError {
    /// Underlying [`SkillRollback`] impl returned an error.
    #[error("skill rollback failed: {0}")]
    Rollback(String),
}

/// Write-side companion to CONTRACT-164
/// [`advance_shared_types::skills::SkillStateReader`].
///
/// Lives LOCAL to auto-loop until MODULE-017 m017-e ships cap-skills's
/// equivalent. Signature pinned to MODULE-017 host-fn shapes:
/// `rollback-skill(skill: skill-id, version: u32)` /
/// `delete-skill(skill: skill-id)` with an explicit `agent_id` parameter
/// added at the M015 boundary (the host-fn shape carries agent_id
/// implicitly per WASM context).
///
/// **Implementer Invariants**:
/// 1. **Idempotent on success**: calling `rollback_skill(a, s, v)` on a
///    skill already at version `v` is a no-op.
/// 2. **Errors are operational**: returned [`SkillTrackerError::Rollback`]
///    reasons SHOULD be short invariant identifiers, no PII, no agent-private
///    state (downstream consumers may log).
#[async_trait]
pub trait SkillRollback: Send + Sync {
    /// Restore `skill_id` to `target_version` for `agent_id`.
    async fn rollback_skill(
        &self,
        agent_id: &str,
        skill_id: &str,
        target_version: u32,
    ) -> Result<(), SkillTrackerError>;

    /// Delete `skill_id` for `agent_id` (no-op if absent).
    async fn delete_skill(&self, agent_id: &str, skill_id: &str) -> Result<(), SkillTrackerError>;
}

/// No-op default [`SkillRollback`] impl. Returns `Ok(())` for both methods.
///
/// **DO NOT use in production discard paths.** This impl silently
/// succeeds without performing any restoration — wiring it under the
/// `apply_discard` execution path would fail-open on AC-18/AC-21: a
/// discarded iteration's skill mutations would permanently leak past
/// the iteration boundary. The default exists for two narrow purposes:
/// (a) unit tests that exercise tracker-side bookkeeping (e.g.,
/// `apply_discard` drains entries even with a no-op write side); (b)
/// development scaffolding before MODULE-017 m017-e ships the
/// cap-skills production impl bound to the host-fn ABI. Production
/// deploys MUST replace this with the m017-e impl before the
/// integrated §4.7.7 loop slice goes live.
pub struct NoopSkillRollback;

#[async_trait]
impl SkillRollback for NoopSkillRollback {
    async fn rollback_skill(
        &self,
        _agent_id: &str,
        _skill_id: &str,
        _target_version: u32,
    ) -> Result<(), SkillTrackerError> {
        Ok(())
    }

    async fn delete_skill(
        &self,
        _agent_id: &str,
        _skill_id: &str,
    ) -> Result<(), SkillTrackerError> {
        Ok(())
    }
}

/// Per-iteration SkillPreState tracker (PRD §12.6.5).
///
/// Held STANDALONE alongside `AutoState` (crate-boundary constraint — see
/// module docs). One instance per `(agent_id, iteration)` tuple; callers
/// reset via [`SkillTracker::clear`] on iteration KEEP or drop the instance
/// on iteration end.
#[derive(Default, Debug)]
pub struct SkillTracker {
    /// HashMap keyed by `skill_id` → recorded pre-iteration state.
    states: HashMap<String, SkillPreState>,
}

impl SkillTracker {
    /// Construct a fresh tracker with an empty HashMap.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the pre-activation state for `skill_id`. First-insert-wins
    /// per PRD §12.6.5: re-activating the same skill within the same
    /// iteration does NOT overwrite the recorded pre-state.
    ///
    /// `current_version`:
    /// - `None` → the skill did not exist before activation → records
    ///   [`SkillPreState::Absent`] (DISCARD will delete).
    /// - `Some(n)` → the skill existed at version `n` → records
    ///   [`SkillPreState::Version(n)`] (DISCARD will rollback to `n`).
    ///
    /// Callers read `current_version` via
    /// [`advance_shared_types::skills::SkillStateReader::skill_version`]
    /// before invoking `cap-skills::activate-skill`.
    ///
    /// **Defensive caps** (adversarial Round-1 W1 fix): the call is
    /// silently dropped if `skill_id` exceeds [`MAX_SKILL_ID_BYTES`] OR
    /// the tracker already holds [`MAX_TRACKED_SKILLS`] entries (only for
    /// NEW entries — existing entries are still subject to first-insert-
    /// wins). The drop is intentionally silent: production callers MUST
    /// pre-validate `skill_id` per CONTRACT-164's recommendation, and a
    /// runtime panic would crash the entire auto loop on a buggy WASM
    /// caller. Drops are observable via [`SkillTracker::len`] not
    /// growing.
    pub fn record_pre_activation(&mut self, skill_id: &str, current_version: Option<u32>) {
        // Defense-in-depth: bound skill_id length and total tracker size.
        if skill_id.len() > MAX_SKILL_ID_BYTES {
            return;
        }
        // Only reject NEW entries when at capacity; re-activations of
        // already-tracked skills are first-insert-wins and don't grow
        // the HashMap.
        if !self.states.contains_key(skill_id) && self.states.len() >= MAX_TRACKED_SKILLS {
            return;
        }
        self.states
            .entry(skill_id.to_string())
            .or_insert_with(|| match current_version {
                None => SkillPreState::Absent,
                Some(v) => SkillPreState::Version(v),
            });
    }

    /// Iteration KEEP path: clear the HashMap without invoking
    /// [`SkillRollback`].
    pub fn clear(&mut self) {
        self.states.clear();
    }

    /// Iteration DISCARD path: iterate entries in deterministic sort
    /// order (by `skill_id` string compare) and dispatch per-variant via
    /// `rollback`. **Partial-drain semantics** (audit Round-1 fix):
    /// entries are removed from the HashMap one at a time, AFTER each
    /// successful dispatch. The first dispatch error short-circuits via
    /// `?`; the failing entry AND all unprocessed entries with larger
    /// `skill_id` keys remain in the HashMap, so the caller can retry
    /// `apply_discard` (or fall back to manual remediation) without
    /// losing un-restored pre-state. Successful entries are gone.
    ///
    /// **Determinism**: keys are snapshotted into a `Vec` and sorted by
    /// `skill_id` (string compare) before dispatch, so the call sequence
    /// observable from `RecordingSkillRollback` is reproducible across
    /// runs (HashMap iteration order would otherwise be random).
    pub async fn apply_discard(
        &mut self,
        agent_id: &str,
        rollback: &dyn SkillRollback,
    ) -> Result<(), SkillTrackerError> {
        let mut sorted_keys: Vec<String> = self.states.keys().cloned().collect();
        sorted_keys.sort();
        for skill_id in sorted_keys {
            // Re-read the variant from the HashMap. The key was sourced
            // from `keys()` above and `&mut self` exclusivity prevents
            // concurrent mutation — but if a future refactor breaks that
            // invariant (e.g., via interior mutability), gracefully skip
            // missing entries rather than panic the entire auto loop
            // (adversarial Round-1 W2 fix: replaced `.expect()` with
            // `let Some(_) else continue` so a stale snapshot is
            // operator-observable via tracker.len() but never crashes).
            let Some(pre_state) = self.states.get(&skill_id).cloned() else {
                continue;
            };
            match pre_state {
                SkillPreState::Absent => {
                    rollback.delete_skill(agent_id, &skill_id).await?;
                }
                SkillPreState::Version(n) => {
                    rollback.rollback_skill(agent_id, &skill_id, n).await?;
                }
            }
            // Only remove on success — failed/unprocessed entries stay
            // in the HashMap for retry.
            self.states.remove(&skill_id);
        }
        Ok(())
    }

    /// Number of recorded pre-states.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Whether the tracker has zero recorded pre-states.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Read the recorded pre-state for `skill_id`, or `None` if not tracked.
    pub fn get(&self, skill_id: &str) -> Option<&SkillPreState> {
        self.states.get(skill_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_state_variants() {
        assert_eq!(SkillPreState::Absent, SkillPreState::Absent);
        assert_eq!(SkillPreState::Version(3), SkillPreState::Version(3));
        assert_ne!(SkillPreState::Absent, SkillPreState::Version(0));
        assert_ne!(SkillPreState::Version(1), SkillPreState::Version(2));
    }

    #[test]
    fn fresh_tracker_is_empty() {
        let t = SkillTracker::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.get("nope"), None);
    }

    #[test]
    fn record_absent_then_version_first_wins() {
        let mut t = SkillTracker::new();
        t.record_pre_activation("skill_A", None);
        t.record_pre_activation("skill_A", Some(7));
        // First insert wins: Absent stays even though a Version(7) was
        // attempted afterward (PRD §12.6.5 first-insert-wins).
        assert_eq!(t.get("skill_A"), Some(&SkillPreState::Absent));
    }

    #[test]
    fn record_version_first_wins_over_later_version() {
        let mut t = SkillTracker::new();
        t.record_pre_activation("skill_B", Some(3));
        t.record_pre_activation("skill_B", Some(5));
        // First insert wins: Version(3) preserved.
        assert_eq!(t.get("skill_B"), Some(&SkillPreState::Version(3)));
    }

    #[tokio::test]
    async fn noop_rollback_returns_ok_for_both_methods() {
        let r = NoopSkillRollback;
        assert!(r.rollback_skill("a", "s", 0).await.is_ok());
        assert!(r.delete_skill("a", "s").await.is_ok());
    }

    #[tokio::test]
    async fn clear_empties_without_dispatch() {
        let mut t = SkillTracker::new();
        t.record_pre_activation("skill_C", Some(1));
        t.record_pre_activation("skill_D", None);
        assert_eq!(t.len(), 2);
        t.clear();
        assert!(t.is_empty());
    }
}
