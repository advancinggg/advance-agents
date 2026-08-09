//! MODULE-003 Slice B — CONTRACT-022 `NamedCheckpoint` integration tests.
//!
//! Each test uses a tempdir fixture bootstrapped via
//! [`advance_git::bootstrap_repo_at`], seeds an initial commit directly via
//! `git2` for deterministic state, and exercises the public
//! `DefaultNamedCheckpoint` surface.

use advance_git::{
    bootstrap_repo_at, CheckpointEntry, CheckpointError, DefaultNamedCheckpoint, DeniedReason,
    NamedCheckpoint,
};
use git2::{Repository, Signature};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Bootstrap a repo + seed one commit so HEAD is born. Returns the tempdir
/// (kept alive by the caller) and the canonical path.
fn seed_repo() -> (TempDir, PathBuf) {
    let td = TempDir::new().expect("tempdir");
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).expect("bootstrap");
    // Seed one file commit.
    std::fs::write(p.join("README.md"), "hello").unwrap();
    let repo = Repository::open(&p).unwrap();
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("README.md")).unwrap();
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("test", "test@example.com").unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "seed", &tree, &[])
        .unwrap();
    (td, p)
}

#[test]
fn t07_create_full_directory_checkpoint_writes_empty_object() {
    // AC-08 full-directory checkpoint: tag message is literally `{}`.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("alice", "v1", None).unwrap();

    let repo = Repository::open(&p).unwrap();
    let tag_ref = repo
        .find_reference("refs/tags/checkpoint/alice/v1")
        .unwrap();
    let tag = tag_ref.peel_to_tag().unwrap();
    let msg = std::str::from_utf8(tag.message_bytes().unwrap_or(&[])).unwrap();
    assert_eq!(msg, "{}");
}

#[test]
fn t08_create_path_scoped_checkpoint_writes_paths_array() {
    // AC-09 path-scoped checkpoint: message is `{"paths":[...]}`.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("alice", "v1", Some(vec![PathBuf::from("README.md")]))
        .unwrap();

    let repo = Repository::open(&p).unwrap();
    let tag = repo
        .find_reference("refs/tags/checkpoint/alice/v1")
        .unwrap()
        .peel_to_tag()
        .unwrap();
    let msg = std::str::from_utf8(tag.message_bytes().unwrap_or(&[])).unwrap();
    assert_eq!(msg, r#"{"paths":["README.md"]}"#);
}

#[test]
fn t19_some_empty_normalizes_to_none() {
    // AC-18 `some([])` = `none`: tag message is `{}`, not `{"paths":[]}`.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("alice", "v1", Some(vec![])).unwrap();

    let repo = Repository::open(&p).unwrap();
    let tag = repo
        .find_reference("refs/tags/checkpoint/alice/v1")
        .unwrap()
        .peel_to_tag()
        .unwrap();
    let msg = std::str::from_utf8(tag.message_bytes().unwrap_or(&[])).unwrap();
    assert_eq!(msg, "{}");
}

#[test]
fn t24_list_and_delete_roundtrip() {
    // AC-23 list/delete: create 3, delete 1, list returns 2.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p).unwrap();
    ncp.create("alice", "a", None).unwrap();
    ncp.create("alice", "b", None).unwrap();
    ncp.create("alice", "c", None).unwrap();

    let before = ncp.list("alice").unwrap();
    assert_eq!(before.len(), 3);
    let labels: Vec<&str> = before.iter().map(|e| e.label.as_str()).collect();
    assert_eq!(labels, vec!["a", "b", "c"]);

    ncp.delete("alice", "b").unwrap();

    let after = ncp.list("alice").unwrap();
    assert_eq!(after.len(), 2);
    let labels: Vec<&str> = after.iter().map(|e| e.label.as_str()).collect();
    assert_eq!(labels, vec!["a", "c"]);
}

#[test]
fn t24a_list_surfaces_valid_flag_for_corrupt_tag() {
    // AC-23 + AC-10: manually-injected corrupt tag → list returns entry with
    // valid=false, not an error.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    // Create one legitimate checkpoint.
    ncp.create("alice", "ok", None).unwrap();
    // Manually create a corrupt tag.
    let repo = Repository::open(&p).unwrap();
    let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    repo.tag(
        "checkpoint/alice/corrupt",
        head_commit.as_object(),
        &sig,
        r#"{"x":1}"#,
        false,
    )
    .unwrap();

    let entries = ncp.list("alice").unwrap();
    assert_eq!(entries.len(), 2);
    let corrupt = entries.iter().find(|e| e.label == "corrupt").unwrap();
    assert!(!corrupt.valid, "corrupt tag must surface as valid=false");
    let ok = entries.iter().find(|e| e.label == "ok").unwrap();
    assert!(ok.valid);
}

#[test]
fn t10_legacy_empty_message_tag_normalizes_to_full_directory() {
    // AC-11 legacy tag with empty message → list surfaces as valid=true, paths=None.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    // Inject directly via git2 because NamedCheckpoint::create always writes `{}`.
    let repo = Repository::open(&p).unwrap();
    let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    repo.tag(
        "checkpoint/alice/legacy",
        head_commit.as_object(),
        &sig,
        "",
        false,
    )
    .unwrap();

    let entries = ncp.list("alice").unwrap();
    let legacy = entries.iter().find(|e| e.label == "legacy").unwrap();
    assert!(legacy.valid);
    assert!(legacy.paths.is_none());
}

#[test]
fn t09_extra_key_surfaces_as_invalid() {
    // AC-10: `{"x":1}` → valid=false.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    let repo = Repository::open(&p).unwrap();
    let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    repo.tag(
        "checkpoint/alice/bad",
        head_commit.as_object(),
        &sig,
        r#"{"x":1}"#,
        false,
    )
    .unwrap();

    let entries = ncp.list("alice").unwrap();
    let bad = entries.iter().find(|e| e.label == "bad").unwrap();
    assert!(!bad.valid);
}

#[test]
fn t18a_normalize_adds_trailing_slash_for_known_directory() {
    // AC-17 stage 1 — trailing-slash on directory.
    let (_td, p) = seed_repo();
    // Commit a directory so HEAD tree has `data/` as a Tree entry.
    std::fs::create_dir(p.join("data")).unwrap();
    std::fs::write(p.join("data/x.md"), "x").unwrap();
    let repo = Repository::open(&p).unwrap();
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("data/x.md")).unwrap();
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    let parent = repo.head().unwrap().peel_to_commit().unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "add data/", &tree, &[&parent])
        .unwrap();

    // Now create checkpoint with `["data"]` (no trailing slash). The tag
    // message should have `["data/"]`.
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("alice", "v1", Some(vec![PathBuf::from("data")]))
        .unwrap();

    let tag = repo
        .find_reference("refs/tags/checkpoint/alice/v1")
        .unwrap()
        .peel_to_tag()
        .unwrap();
    let msg = std::str::from_utf8(tag.message_bytes().unwrap_or(&[])).unwrap();
    assert_eq!(msg, r#"{"paths":["data/"]}"#);
}

#[test]
fn t18b_normalize_dedupes_exact_duplicates() {
    // AC-17 stage 2 — dedupe.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create(
        "alice",
        "v1",
        Some(vec![PathBuf::from("README.md"), PathBuf::from("README.md")]),
    )
    .unwrap();
    let repo = Repository::open(&p).unwrap();
    let tag = repo
        .find_reference("refs/tags/checkpoint/alice/v1")
        .unwrap()
        .peel_to_tag()
        .unwrap();
    let msg = std::str::from_utf8(tag.message_bytes().unwrap_or(&[])).unwrap();
    assert_eq!(msg, r#"{"paths":["README.md"]}"#);
}

#[test]
fn t18c_normalize_folds_parent_child_redundancy() {
    // AC-17 stage 3 — parent-child fold.
    let (_td, p) = seed_repo();
    std::fs::create_dir(p.join("data")).unwrap();
    std::fs::write(p.join("data/x.md"), "x").unwrap();
    let repo = Repository::open(&p).unwrap();
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("data/x.md")).unwrap();
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    let parent = repo.head().unwrap().peel_to_commit().unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "data", &tree, &[&parent])
        .unwrap();

    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    // Input: [data/x.md, data/] → fold drops x.md because data/ covers it.
    ncp.create(
        "alice",
        "v1",
        Some(vec![PathBuf::from("data/x.md"), PathBuf::from("data/")]),
    )
    .unwrap();
    let tag = repo
        .find_reference("refs/tags/checkpoint/alice/v1")
        .unwrap()
        .peel_to_tag()
        .unwrap();
    let msg = std::str::from_utf8(tag.message_bytes().unwrap_or(&[])).unwrap();
    assert_eq!(msg, r#"{"paths":["data/"]}"#);
}

#[test]
fn t18d_normalize_sorts_dictionary_order() {
    // AC-17 stage 4 — dictionary sort.
    let (_td, p) = seed_repo();
    // Make `data/` a known dir so trailing slash is added.
    std::fs::create_dir(p.join("data")).unwrap();
    std::fs::write(p.join("data/x.md"), "x").unwrap();
    let repo = Repository::open(&p).unwrap();
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("data/x.md")).unwrap();
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    let parent = repo.head().unwrap().peel_to_commit().unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "data", &tree, &[&parent])
        .unwrap();
    std::fs::create_dir(p.join("b")).unwrap();
    std::fs::write(p.join("b/y.md"), "y").unwrap();
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("b/y.md")).unwrap();
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let parent = repo.head().unwrap().peel_to_commit().unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "b", &tree, &[&parent])
        .unwrap();
    std::fs::create_dir(p.join("a")).unwrap();
    std::fs::write(p.join("a/z.md"), "z").unwrap();
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("a/z.md")).unwrap();
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let parent = repo.head().unwrap().peel_to_commit().unwrap();
    repo.commit(Some("HEAD"), &sig, &sig, "a", &tree, &[&parent])
        .unwrap();

    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create(
        "alice",
        "v1",
        Some(vec![
            PathBuf::from("data"),
            PathBuf::from("b"),
            PathBuf::from("a"),
        ]),
    )
    .unwrap();
    let tag = repo
        .find_reference("refs/tags/checkpoint/alice/v1")
        .unwrap()
        .peel_to_tag()
        .unwrap();
    let msg = std::str::from_utf8(tag.message_bytes().unwrap_or(&[])).unwrap();
    assert_eq!(msg, r#"{"paths":["a/","b/","data/"]}"#);
}

#[test]
fn t07a_create_with_nonexistent_path_succeeds_declarative() {
    // Plan's explicit contract: create() does NOT check path existence; the
    // tag records the caller's declared paths, resolution happens at rollback.
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    let result = ncp.create("alice", "v1", Some(vec![PathBuf::from("never-existed.md")]));
    assert!(result.is_ok(), "create() is declarative, not validating");
}

#[test]
fn aux_create_conflict_on_duplicate_label() {
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p).unwrap();
    ncp.create("alice", "v1", None).unwrap();
    let err = ncp.create("alice", "v1", None).unwrap_err();
    assert!(matches!(err, CheckpointError::Conflict { .. }));
}

#[test]
fn aux_delete_not_found() {
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p).unwrap();
    let err = ncp.delete("alice", "nonexistent").unwrap_err();
    assert!(matches!(err, CheckpointError::NotFound { .. }));
}

#[test]
fn aux_create_rejects_dotagent_in_paths() {
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p).unwrap();
    let err = ncp
        .create(
            "alice",
            "v1",
            Some(vec![PathBuf::from(".agent/config.yaml")]),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        CheckpointError::InvalidPath {
            reason: DeniedReason::DotAgentOutsideMemoryRollback,
            ..
        }
    ));
}

#[test]
fn aux_create_rejects_parent_dir_traversal_in_paths() {
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p).unwrap();
    let err = ncp
        .create("alice", "v1", Some(vec![PathBuf::from("../escape.md")]))
        .unwrap_err();
    assert!(matches!(
        err,
        CheckpointError::InvalidPath {
            reason: DeniedReason::ParentDirTraversal,
            ..
        }
    ));
}

#[test]
fn aux_create_rejects_invalid_label() {
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p).unwrap();
    let err = ncp.create("alice", "bad label", None).unwrap_err();
    assert!(matches!(err, CheckpointError::InvalidLabel { .. }));
}

#[test]
fn aux_list_returns_empty_for_unknown_agent() {
    let (_td, p) = seed_repo();
    let ncp = DefaultNamedCheckpoint::new(p).unwrap();
    let entries: Vec<CheckpointEntry> = ncp.list("nonexistent-agent").unwrap();
    assert!(entries.is_empty());
}
