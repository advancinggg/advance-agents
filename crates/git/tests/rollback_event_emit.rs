//! MODULE-003 Slice E — AC-07 `git.rollback` event emit primitive.
//!
//! Exercises the emit gate under every branch:
//! - T06: successful `rollback(Commit)` emits once with `target_kind=version`.
//! - T06a: successful `rollback_to_checkpoint` emits once with `target_kind=checkpoint`.
//! - T06b: failed rollbacks emit zero events. Three sub-cases covered:
//!   b.1 = `RollbackError::NotFound` (non-existent checkpoint label);
//!   b.2 = `RollbackError::InvalidTarget` (malformed hex);
//!   b.3 = `RollbackError::Libgit2` (valid-format 40-hex OID referencing
//!   a commit that is not in the repo).
//! - T06d: successful-but-vacuous rollback (empty `PathScoped`) emits zero events.
//! - T06e: truncation — > `MAX_EVENT_AFFECTED_PATHS` paths produces a silent
//!   cap in payload.affected_paths; payload still has exactly the five PRD
//!   §15.3.17 fields.
//!
//! All tests use `agent_id = "root"` which short-circuits
//! `resolve_agent_root` (rollback.rs — the ROOT_AGENT_SENTINEL branch) so no
//! `.agent/config.yaml` seeding is needed.

mod common;

use advance_git::{
    bootstrap_repo_at, DefaultNamedCheckpoint, DefaultWorkspaceRollback, NamedCheckpoint,
    RollbackError, RollbackMode, RollbackTarget, WorkspaceRollback,
};
use common::CollectingEventBus;
use git2::{Repository, Signature};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

fn bootstrap() -> (TempDir, PathBuf) {
    let td = TempDir::new().unwrap();
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).unwrap();
    (td, p)
}

/// Direct git2 commit helper (avoids the async CommitQueue when the test
/// only needs a target commit to roll back to).
fn seed_commit(p: &Path, files: &[(&str, &str)], msg: &str) -> git2::Oid {
    let repo = Repository::open(p).unwrap();
    for (rel, content) in files {
        if let Some(parent) = Path::new(rel).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(p.join(parent)).unwrap();
            }
        }
        std::fs::write(p.join(rel), content).unwrap();
    }
    let mut idx = repo.index().unwrap();
    for (rel, _) in files {
        idx.add_path(Path::new(rel)).unwrap();
    }
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    let parents: Vec<git2::Commit> = match repo.head() {
        Ok(h) => vec![h.peel_to_commit().unwrap()],
        Err(_) => vec![],
    };
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &parent_refs)
        .unwrap()
}

#[tokio::test]
async fn t06_rollback_commit_emits_once_target_kind_version() {
    let (_td, p) = bootstrap();
    let target_oid = seed_commit(&p, &[("README.md", "v1")], "target");
    // Modify so rollback has non-empty paths
    seed_commit(&p, &[("README.md", "v2")], "drift");

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    let paths = rb
        .rollback(
            "root",
            RollbackTarget::Commit(target_oid.to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap();
    assert!(!paths.is_empty());

    assert_eq!(bus.len(), 1);
    let events = bus.drain();
    let event = &events[0];
    assert_eq!(event.event_type, "git.rollback");
    assert_eq!(event.agent_id, "root");
    // event.id must be parseable as a UUID (v4 per event.rs:45 invariant).
    uuid::Uuid::parse_str(&event.id).expect("event.id must be a UUID string");

    let payload = event
        .payload
        .as_object()
        .expect("payload must be a JSON object");
    assert_eq!(payload.len(), 5, "payload has exactly the 5 PRD fields");
    assert_eq!(
        payload.get("target_kind").and_then(|v| v.as_str()),
        Some("version")
    );
    assert_eq!(
        payload.get("target_ref").and_then(|v| v.as_str()),
        Some(target_oid.to_string().as_str())
    );
    assert!(
        payload
            .get("affected_paths")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "affected_paths non-empty"
    );
    assert_eq!(
        payload.get("agent_id").and_then(|v| v.as_str()),
        Some("root")
    );
    assert_eq!(
        payload.get("initiator").and_then(|v| v.as_str()),
        Some("root"),
        "initiator is the raw agent_id per PRD §15.3.17 (no 'agent:' prefix)"
    );
}

#[tokio::test]
async fn t06a_rollback_to_checkpoint_emits_once_target_kind_checkpoint() {
    let (_td, p) = bootstrap();
    seed_commit(&p, &[("README.md", "v1")], "pre-checkpoint");

    // Create a full-directory checkpoint "v1".
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("root", "v1", None).unwrap();

    // Modify so rollback has non-empty paths.
    seed_commit(&p, &[("README.md", "v2")], "drift");

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    let paths = rb.rollback_to_checkpoint("root", "v1").await.unwrap();
    assert!(!paths.is_empty());

    assert_eq!(bus.len(), 1);
    let events = bus.drain();
    let event = &events[0];
    let payload = event.payload.as_object().unwrap();
    assert_eq!(
        payload.get("target_kind").and_then(|v| v.as_str()),
        Some("checkpoint")
    );
    assert_eq!(
        payload.get("target_ref").and_then(|v| v.as_str()),
        Some("v1")
    );
    assert_eq!(
        payload.get("initiator").and_then(|v| v.as_str()),
        Some("root")
    );
}

#[tokio::test]
async fn t06b_1_rollback_to_nonexistent_checkpoint_label_emits_zero() {
    let (_td, p) = bootstrap();
    seed_commit(&p, &[("README.md", "v1")], "seed");

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    let err = rb
        .rollback_to_checkpoint("root", "does-not-exist")
        .await
        .unwrap_err();
    assert!(matches!(err, RollbackError::NotFound { .. }), "got {err:?}");
    assert_eq!(bus.len(), 0);
}

#[tokio::test]
async fn t06b_2_rollback_with_malformed_hex_emits_zero() {
    let (_td, p) = bootstrap();
    seed_commit(&p, &[("README.md", "v1")], "seed");

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    let err = rb
        .rollback(
            "root",
            RollbackTarget::Commit("notahex".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, RollbackError::InvalidTarget { .. }),
        "got {err:?}"
    );
    assert_eq!(bus.len(), 0);
}

#[tokio::test]
async fn t06b_3_rollback_with_valid_format_nonexistent_oid_emits_zero() {
    // Valid 40-hex format but references a commit that doesn't exist in
    // the repo. `resolve_target_commit` calls `Oid::from_str` (succeeds
    // because format is valid) then `repo.find_commit` (fails because
    // the object is not in the ODB) → surfaced as `RollbackError::Libgit2`.
    let (_td, p) = bootstrap();
    seed_commit(&p, &[("README.md", "v1")], "seed");

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    // Valid-format non-existent 40-hex OID — `Oid::from_str` accepts any
    // 40-character hex string, and the lookup then fails in libgit2's
    // ODB because no matching object exists. Uses a non-zero fixture
    // ("deadbeef..." × 5 = 40 chars) to avoid the all-zero OID special
    // case, guaranteeing the Libgit2 code path rather than any earlier
    // format-rejection.
    let fake_hex = "deadbeef".repeat(5);
    assert_eq!(fake_hex.len(), 40);
    let err = rb
        .rollback(
            "root",
            RollbackTarget::Commit(fake_hex),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RollbackError::Libgit2 { .. }), "got {err:?}");
    assert_eq!(bus.len(), 0);
}

#[tokio::test]
async fn t06b_4_rollback_rejects_bidi_override_in_label() {
    // Adversarial R2 regression: U+202E RLO (RIGHT-TO-LEFT OVERRIDE) is
    // a Cf-category character that libgit2's ref grammar accepts but
    // which is a bidi-override attack vector if it reaches JSONL / SQLite
    // audit sinks. validate_ref_component must reject it at the rollback
    // boundary so payload.target_ref never carries it.
    let (_td, p) = bootstrap();
    seed_commit(&p, &[("README.md", "v1")], "seed");

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    // Via rollback_to_checkpoint (direct entry).
    let err1 = rb
        .rollback_to_checkpoint("root", "\u{202E}evil")
        .await
        .unwrap_err();
    assert!(
        matches!(err1, RollbackError::Checkpoint(..)),
        "rollback_to_checkpoint must reject bidi label; got {err1:?}"
    );

    // Via rollback(RollbackTarget::Checkpoint) — the alternate public
    // entry point previously bypassed label validation.
    let err2 = rb
        .rollback(
            "root",
            RollbackTarget::Checkpoint("\u{202E}evil".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err2, RollbackError::Checkpoint(..)),
        "rollback(RollbackTarget::Checkpoint) must reject bidi label; got {err2:?}"
    );

    assert_eq!(bus.len(), 0);
}

#[tokio::test]
async fn t06d_vacuous_rollback_pathscoped_empty_emits_zero() {
    // Empty PathScoped inputs → validate_and_check_path_scoped returns
    // Ok(vec![]); PathScoped has an empty removal set, so do_rollback's
    // restructured `checkout_paths.is_empty() && removal_paths.is_empty()`
    // early return yields Ok(empty). Emit gate skips.
    let (_td, p) = bootstrap();
    let target_oid = seed_commit(&p, &[("README.md", "v1")], "seed");

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    let paths = rb
        .rollback(
            "root",
            RollbackTarget::Commit(target_oid.to_string()),
            RollbackMode::PathScoped(vec![]),
        )
        .await
        .unwrap();
    assert!(paths.is_empty());
    assert_eq!(bus.len(), 0);
}

#[tokio::test]
async fn t06e_truncation_cap_at_max_event_affected_paths() {
    // Commit 1100 files + let bootstrap's .gitignore flow through; expand
    // yields ≥ 1100 paths; payload's affected_paths is silently truncated
    // to 1000 (MAX_EVENT_AFFECTED_PATHS). Payload still has exactly the 5
    // PRD fields (no paths_truncated / paths_total extensions).
    let (_td, p) = bootstrap();

    let mut files: Vec<(String, String)> = Vec::with_capacity(1100);
    for i in 0..1100 {
        files.push((format!("file-{i:04}"), format!("v1-{i}")));
    }
    // Build &[(&str, &str)] view for seed_commit.
    let view: Vec<(&str, &str)> = files
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let target_oid = seed_commit(&p, &view, "many");
    // Produce a divergent follow-up so rollback has something to do.
    std::fs::write(p.join("file-0000"), "mutated").unwrap();

    let bus = Arc::new(CollectingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), bus.clone() as Arc<_>).unwrap();

    let paths = rb
        .rollback(
            "root",
            RollbackTarget::Commit(target_oid.to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap();
    assert!(
        paths.len() >= 1100,
        "expand_full_domain yielded fewer paths than seeded: {}",
        paths.len()
    );
    assert_eq!(bus.len(), 1);

    let events = bus.drain();
    let event = &events[0];
    let payload = event.payload.as_object().unwrap();
    assert_eq!(
        payload.len(),
        5,
        "payload must keep exactly the 5 PRD §15.3.17 keys — no truncation flags added"
    );
    for key in [
        "agent_id",
        "target_ref",
        "target_kind",
        "affected_paths",
        "initiator",
    ] {
        assert!(
            payload.contains_key(key),
            "payload missing required key {key}"
        );
    }
    assert_eq!(
        payload.get("target_kind").and_then(|v| v.as_str()),
        Some("version")
    );
    let affected = payload
        .get("affected_paths")
        .and_then(|v| v.as_array())
        .unwrap();
    assert_eq!(
        affected.len(),
        1000,
        "affected_paths truncated at MAX_EVENT_AFFECTED_PATHS"
    );
}
