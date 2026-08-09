//! slice wave6-laneB (leg 3, SYS-AC-186/187) — the cap-skills CONSUMER half:
//! `list/resolve_skill_candidate` wired to the cap-memory PRODUCER
//! `_skill_candidates.jsonl`. The candidate is seeded via the producer store and
//! the candidate_id round-trips verbatim (no recompute / drift).

use cap_memory::{SkillCandidate as MemCandidate, SkillCandidateStore};
use cap_skills::{CandidateAction, SkillError, SkillStore};
use tempfile::tempdir;

/// Seed a pending candidate into the producer store and return its id.
fn seed(dir: &std::path::Path, name: &str, desc: &str) -> String {
    let store = SkillCandidateStore::in_dir(dir);
    let cand = MemCandidate::new(name, desc);
    assert!(store.append_generated(&cand).expect("seed append"));
    cand.candidate_id
}

/// L3-list (186): a producer-seeded candidate is returned pending, with the
/// length-prefixed-sha256 id consumed VERBATIM (no recompute).
#[tokio::test]
async fn l3_list_returns_seeded_pending_candidate_with_roundtrip_id() {
    let dir = tempdir().unwrap();
    let id = seed(dir.path(), "summarize-pr", "Summarize a pull request diff");

    let store = SkillStore::new().with_candidate_dir(dir.path());
    let listed = store.list_skill_candidates().await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].candidate_id, id, "id round-trips verbatim");
    assert_eq!(listed[0].name, "summarize-pr");
    assert_eq!(listed[0].description, "Summarize a pull request diff");
}

/// L3-accept (187): resolve(Accept) appends a terminal `resolved` event (no
/// longer pending) and returns a REAL proposed draft-id (WIT accept→new draft-id).
#[tokio::test]
async fn l3_resolve_accept_appends_terminal_and_proposes_draft() {
    let dir = tempdir().unwrap();
    let id = seed(dir.path(), "summarize-pr", "Summarize a pull request diff");

    // In-memory-backed store (the point is the terminal event + the real draft-id,
    // not disk persistence).
    let store = SkillStore::new().with_candidate_dir(dir.path());

    let result = store
        .resolve_skill_candidate(&id, CandidateAction::Accept)
        .await
        .expect("accept");
    assert_eq!(result.candidate_id, id);
    assert!(!result.draft_id.is_empty(), "accept proposes a real draft");

    // The proposed draft is an ACTIVATABLE SKILL.md scaffold (YAML frontmatter),
    // NOT raw prose — so accept is actionable, not fake-green.
    let draft = store
        .get_draft(&result.draft_id)
        .await
        .expect("get_draft ok")
        .expect("draft present");
    assert!(
        draft.content.starts_with("---\nname: summarize-pr\n"),
        "draft must be a frontmatter scaffold, got: {}",
        draft.content
    );
    // It actually activates (the strongest witness of an actionable accept).
    store
        .activate(&result.draft_id)
        .await
        .expect("the scaffold activates");

    // No longer pending (candidate store is separate from the draft/skill store).
    assert!(store.list_skill_candidates().await.unwrap().is_empty());
}

/// L3-dismiss (187): resolve(Dismiss) appends a terminal `dismissed` event (not
/// pending) and returns an EMPTY draft-id.
#[tokio::test]
async fn l3_resolve_dismiss_appends_terminal_empty_draft() {
    let dir = tempdir().unwrap();
    let id = seed(dir.path(), "stale-skill", "A stale skill candidate");

    let store = SkillStore::new().with_candidate_dir(dir.path());
    let result = store
        .resolve_skill_candidate(&id, CandidateAction::Dismiss)
        .await
        .expect("dismiss");
    assert_eq!(result.candidate_id, id);
    assert_eq!(result.draft_id, "", "dismiss → empty draft-id");
    assert!(store.list_skill_candidates().await.unwrap().is_empty());
}

/// L3-unknown / double-resolve: an unknown id → NotFound; a second resolve of an
/// already-terminal candidate → NotFound (it is no longer pending).
#[tokio::test]
async fn l3_unknown_and_double_resolve_are_not_found() {
    let dir = tempdir().unwrap();
    let id = seed(dir.path(), "skill-d", "desc d");
    let store = SkillStore::new().with_candidate_dir(dir.path());

    // Unknown id.
    let err = store
        .resolve_skill_candidate("deadbeef", CandidateAction::Dismiss)
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::SkillNotFound(_)));

    // First resolve OK, second resolve of the same id → not pending → NotFound.
    store
        .resolve_skill_candidate(&id, CandidateAction::Dismiss)
        .await
        .expect("first resolve");
    let err2 = store
        .resolve_skill_candidate(&id, CandidateAction::Dismiss)
        .await
        .unwrap_err();
    assert!(matches!(err2, SkillError::SkillNotFound(_)));
}

/// L3-oversize-id (adversarial r4, W-C): a guest id longer than the producer's
/// id cap can never match a capped pending candidate, so resolve returns
/// `SkillNotFound` by construction (without persisting the oversize id).
#[tokio::test]
async fn l3_oversize_candidate_id_is_not_found() {
    let dir = tempdir().unwrap();
    let pending_id = seed(dir.path(), "real-skill", "a genuinely pending candidate");
    let store = SkillStore::new().with_candidate_dir(dir.path());

    let huge = "a".repeat(4096);
    let err = store
        .resolve_skill_candidate(&huge, CandidateAction::Accept)
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::SkillNotFound(_)));

    // The real pending candidate is untouched — the oversize resolve wrote nothing.
    let listed = store.list_skill_candidates().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].candidate_id, pending_id);
}

/// L3-unset-stub: a SkillStore with NO candidate_dir keeps the Slice-C stub
/// (list → empty, resolve → Err) so existing tests/configs stay green.
#[tokio::test]
async fn l3_unset_candidate_dir_preserves_slice_c_stub() {
    let store = SkillStore::new();
    assert!(store.list_skill_candidates().await.unwrap().is_empty());
    let err = store
        .resolve_skill_candidate("anything", CandidateAction::Accept)
        .await
        .unwrap_err();
    assert!(matches!(err, SkillError::SkillNotFound(_)));
}
