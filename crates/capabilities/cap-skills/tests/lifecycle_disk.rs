//! MODULE-017 Slice C — disk-backed `SkillStore` integration tests.
//!
//! Covers SC-01-disk (full happy path with `DiskSkillStorage`) and SC-02
//! (drop + reconstruct with same `TempDir` to simulate process restart).
//! In-memory variants of these scenarios live in `lifecycle::tests` (lib-side).

use std::sync::Arc;

use cap_skills::persistence::DiskSkillStorage;
use cap_skills::{SkillError, SkillStore};
use tempfile::TempDir;

fn valid_content(name: &str) -> String {
    format!("---\nname: {name}\ndescription: x\n---\n# {name}\n")
}

fn make_store(dir: &TempDir) -> SkillStore {
    let storage = Arc::new(DiskSkillStorage::with_default_writer(
        dir.path().to_path_buf(),
    ));
    SkillStore::with_storage(storage)
}

/// SC-01-disk — propose → activate → rollback → delete happy path with disk
/// persistence. Files appear on disk; final get returns SkillNotFound.
#[tokio::test]
async fn sc_01_disk_happy_path() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir);

    // Propose + activate v1.
    let d1 = store
        .propose_draft("hp".into(), valid_content("hp-v1"), vec!["t".into()])
        .await
        .unwrap();
    store.activate(&d1).await.unwrap();
    let active_md = dir.path().join(".agent/skills/hp/SKILL.md");
    assert!(active_md.exists(), "active SKILL.md should be on disk");
    assert_eq!(store.get("hp").await.unwrap().version, 1);

    // Propose + activate v2.
    let d2 = store
        .propose_draft("hp".into(), valid_content("hp-v2"), vec!["t".into()])
        .await
        .unwrap();
    store.activate(&d2).await.unwrap();
    assert_eq!(store.get("hp").await.unwrap().version, 2);
    let v1_file = dir.path().join(".agent/_skill_versions/hp/v1.md");
    assert!(v1_file.exists(), "v1 archived to _skill_versions");

    // Rollback to v1.
    store.rollback("hp", 1).await.unwrap();
    assert_eq!(store.get("hp").await.unwrap().version, 3);
    let v2_file = dir.path().join(".agent/_skill_versions/hp/v2.md");
    assert!(v2_file.exists(), "v2 archived after rollback");

    // Delete tombstones.
    store.delete("hp").await.unwrap();
    assert!(matches!(
        store.get("hp").await.unwrap_err(),
        SkillError::SkillNotFound(_)
    ));
    // Active file gone; version files preserved.
    assert!(!active_md.exists(), "delete removes active SKILL.md");
    assert!(v1_file.exists(), "v1 history preserved through tombstone");
}

/// SC-02 — drop + reconstruct (same TempDir) returns the draft.
#[tokio::test]
async fn sc_02_disk_restart_preserves_drafts() {
    let dir = TempDir::new().unwrap();
    {
        let store = make_store(&dir);
        store
            .propose_draft("restart".into(), valid_content("restart"), vec![])
            .await
            .unwrap();
    } // store dropped; storage Arc dropped.

    // Reconstruct.
    let store2 = make_store(&dir);
    let drafts = store2.list_drafts().await.unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].name, "restart");
}

/// Trust matrix on disk — Imported+Untrusted skill, delete blocked.
#[tokio::test]
async fn trust_matrix_imported_untrusted_delete_blocked_on_disk() {
    use cap_skills::persistence::{SkillBlob, SkillStorage};
    use cap_skills::{Provenance, TrustLevel};

    let dir = TempDir::new().unwrap();
    // Seed an Imported+Untrusted skill directly via storage (production
    // path: pack install via M008; out-of-scope for Slice C).
    let storage: Arc<dyn SkillStorage> = Arc::new(DiskSkillStorage::with_default_writer(
        dir.path().to_path_buf(),
    ));
    storage
        .write_active(&SkillBlob {
            skill_id: "imp".to_string(),
            version: 1,
            content: valid_content("imp"),
            tags: vec![],
            provenance: Provenance::Imported,
            trust_level: TrustLevel::Untrusted,
        })
        .await
        .unwrap();
    let store = SkillStore::with_storage(storage);

    let err = store.delete("imp").await.unwrap_err();
    assert!(matches!(err, SkillError::TrustViolation(_)));
    // Active still present.
    assert!(store.get("imp").await.is_ok());
}

/// elevate_trust persists across restart.
#[tokio::test]
async fn elevate_trust_persists_across_restart() {
    use cap_skills::TrustLevel;

    let dir = TempDir::new().unwrap();
    {
        let store = make_store(&dir);
        let d = store
            .propose_draft("trust".into(), valid_content("trust"), vec![])
            .await
            .unwrap();
        store.activate(&d).await.unwrap();
        store.elevate_trust("trust").await.unwrap();
    }
    let store2 = make_store(&dir);
    let s = store2.get("trust").await.unwrap();
    assert!(
        matches!(s.trust_level, TrustLevel::Trusted),
        "trust elevation must persist across DiskSkillStorage restart"
    );
}
