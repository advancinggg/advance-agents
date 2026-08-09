//! MODULE-003 Slice B — `rollback_to_checkpoint` end-to-end integration.
//!
//! Exercises AC-19 (checkpoint label → commit + paths delegation to
//! `rollback()`) and AC-10's rollback-side invalid-state surface
//! (RollbackError::Checkpoint(CheckpointError::InvalidState)).

use advance_git::{
    bootstrap_repo_at, CheckpointError, DefaultNamedCheckpoint, DefaultWorkspaceRollback,
    NamedCheckpoint, RollbackError, WorkspaceRollback,
};
use git2::{Repository, Signature};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn bootstrap() -> (TempDir, PathBuf) {
    let td = TempDir::new().unwrap();
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).unwrap();
    (td, p)
}

/// Seed `.agent/config.yaml` so a non-root agent_id (e.g., `alice`) is
/// recognized by rollback's FS-scan resolver.
fn seed_config_for_agent(repo_root: &Path, agent_id: &str) {
    let agent_dir = repo_root.join(".agent");
    std::fs::create_dir_all(&agent_dir).unwrap();
    std::fs::write(
        agent_dir.join("config.yaml"),
        format!("agent_id: {agent_id}\n"),
    )
    .unwrap();
}

fn seed_commit(p: &Path, files: &[(&str, &str)], msg: &str) {
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
        .unwrap();
}

#[tokio::test]
async fn t20_rollback_to_checkpoint_pathscoped_end_to_end() {
    // AC-19: rollback-to-checkpoint resolves label → commit + paths, then
    // delegates to rollback() with the PathScoped mode.
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
            ("data.md", "d1"),
        ],
        "target",
    );
    // Create a path-scoped checkpoint naming only README.md.
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("alice", "v1", Some(vec![PathBuf::from("README.md")]))
        .unwrap();

    // Modify both files so rollback has something to restore.
    seed_commit(&p, &[("README.md", "v2"), ("data.md", "d2")], "post");

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let paths = roll.rollback_to_checkpoint("alice", "v1").await.unwrap();
    // Path-scoped — only README.md was declared.
    let strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert_eq!(strs, vec!["README.md".to_string()]);
    // README.md restored to v1; data.md still v2.
    assert_eq!(std::fs::read_to_string(p.join("README.md")).unwrap(), "v1");
    assert_eq!(std::fs::read_to_string(p.join("data.md")).unwrap(), "d2");
}

#[tokio::test]
async fn t20b_rollback_to_full_directory_checkpoint() {
    // AC-19 + AC-18: full-directory checkpoint (`{}`) → FullDirectory mode.
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
            ("data.md", "d1"),
        ],
        "target",
    );
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("alice", "full", None).unwrap();

    seed_commit(&p, &[("README.md", "v2"), ("data.md", "d2")], "post");

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let paths = roll.rollback_to_checkpoint("alice", "full").await.unwrap();
    // FullDirectory — both files restored.
    let strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(strs.contains(&"README.md".to_string()));
    assert!(strs.contains(&"data.md".to_string()));
    assert_eq!(std::fs::read_to_string(p.join("README.md")).unwrap(), "v1");
    assert_eq!(std::fs::read_to_string(p.join("data.md")).unwrap(), "d1");
}

#[tokio::test]
async fn t20c_rollback_to_directory_scoped_checkpoint_expands() {
    // Adversarial R18: a DIRECTORY-scoped checkpoint (a directory path that
    // `normalize_paths` stores with a trailing slash, e.g. `docs/`) must roll
    // back by EXPANDING the directory to its writable blobs — NOT be rejected
    // (the first cut of the R17 C1 fix regressed this reachable feature).
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("docs/a.md", "A1"),
            ("docs/b.md", "B1"),
            ("other.md", "O1"),
        ],
        "target",
    );
    // Directory-scoped checkpoint naming the `docs` directory.
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    ncp.create("alice", "vdir", Some(vec![PathBuf::from("docs")]))
        .unwrap();
    // Modify everything after the checkpoint.
    seed_commit(
        &p,
        &[("docs/a.md", "A2"), ("docs/b.md", "B2"), ("other.md", "O2")],
        "post",
    );
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let paths = roll.rollback_to_checkpoint("alice", "vdir").await.unwrap();
    // The directory expanded to its constituent blobs (NOT rejected).
    let strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(strs.contains(&"docs/a.md".to_string()), "got {strs:?}");
    assert!(strs.contains(&"docs/b.md".to_string()), "got {strs:?}");
    // docs/* restored to the checkpoint; the out-of-scope file is untouched.
    assert_eq!(std::fs::read_to_string(p.join("docs/a.md")).unwrap(), "A1");
    assert_eq!(std::fs::read_to_string(p.join("docs/b.md")).unwrap(), "B1");
    assert_eq!(std::fs::read_to_string(p.join("other.md")).unwrap(), "O2");
}

#[tokio::test]
async fn t11_rollback_to_invalid_checkpoint_surfaces_wrapped_invalid_state() {
    // AC-10: rollback_to_checkpoint on a tag with corrupt message surfaces as
    // Err(RollbackError::Checkpoint(CheckpointError::InvalidState {..}))
    // per §1.4.3 line 411-413.
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
        ],
        "target",
    );
    // Manually inject a corrupt tag.
    let repo = Repository::open(&p).unwrap();
    let head = repo.head().unwrap().peel_to_commit().unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    repo.tag(
        "checkpoint/alice/bad",
        head.as_object(),
        &sig,
        r#"{"x":1}"#,
        false,
    )
    .unwrap();

    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback_to_checkpoint("alice", "bad")
        .await
        .unwrap_err();
    match err {
        RollbackError::Checkpoint(CheckpointError::InvalidState { label, .. }) => {
            assert_eq!(label, "bad");
        }
        other => panic!("expected Checkpoint(InvalidState), got {:?}", other),
    }
}

#[tokio::test]
async fn t11a_rollback_to_checkpoint_with_missing_path_surfaces_notfound() {
    // Plan's declarative-create rule: create() records paths verbatim; a
    // later rollback_to_checkpoint() where the declared path is absent from
    // the target commit tree surfaces as RollbackError::NotFound.
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
        ],
        "target",
    );
    let ncp = DefaultNamedCheckpoint::new(p.clone()).unwrap();
    // Declare a path that doesn't exist in the target commit.
    ncp.create("alice", "v1", Some(vec![PathBuf::from("never-existed.md")]))
        .unwrap();

    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback_to_checkpoint("alice", "v1")
        .await
        .unwrap_err();
    assert!(matches!(err, RollbackError::NotFound { .. }));
}
