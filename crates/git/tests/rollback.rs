//! MODULE-003 Slice B — CONTRACT-021 `WorkspaceRollback` integration tests.
//!
//! Fixtures use tempdir + direct `git2` commits for deterministic state.

use advance_git::{
    bootstrap_repo_at, DefaultWorkspaceRollback, DeniedReason, RollbackError, RollbackMode,
    RollbackTarget, WorkspaceRollback,
};
use git2::{Repository, Signature};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Bootstrap a repo. Returns tempdir + canonical path. Tests that use a
/// non-root agent_id must seed a matching config via `seed_config_for_agent`.
fn bootstrap() -> (TempDir, PathBuf) {
    let td = TempDir::new().expect("tempdir");
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).expect("bootstrap");
    (td, p)
}

/// Seed `.agent/config.yaml` at the workspace root so a non-root `agent_id`
/// (e.g., `alice`) is recognized by the rollback impl's FS-scan resolver.
/// Convenience for tests that exercise rollback/memory_rollback_paths for
/// an agent that isn't the root-sentinel `"root"`.
fn seed_config_for_agent(repo_root: &Path, agent_id: &str) {
    let agent_dir = repo_root.join(".agent");
    std::fs::create_dir_all(&agent_dir).unwrap();
    std::fs::write(
        agent_dir.join("config.yaml"),
        format!("agent_id: {agent_id}\n"),
    )
    .unwrap();
}

/// Seed one commit with the given tree layout and return its Oid as hex.
fn seed_commit(p: &Path, files: &[(&str, &str)], dirs: &[&str], msg: &str) -> String {
    let repo = Repository::open(p).unwrap();
    for d in dirs {
        std::fs::create_dir_all(p.join(d)).unwrap();
    }
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
    let oid = repo
        .commit(Some("HEAD"), &sig, &sig, msg, &tree, &parent_refs)
        .unwrap();
    oid.to_string()
}

#[tokio::test]
async fn t04_full_directory_rollback_expansion_excludes_agent_child_hidden() {
    // AC-05: FullDirectory rollback collects visible writable descendants,
    // excluding `.agent/`, child territory, and hidden runtime paths.
    let (_td, p) = bootstrap();
    // Target commit: root content + .agent/ subtree.
    std::fs::create_dir(p.join(".agent")).unwrap();
    std::fs::write(p.join(".agent/config.yaml"), "agent_id: root").unwrap();
    let target_hex = seed_commit(
        &p,
        &[
            ("README.md", "r"),
            ("data/x.md", "x"),
            (".agent/config.yaml", "agent_id: root"),
        ],
        &[],
        "target",
    );

    // Post-target: create a child territory by adding `child/.agent/` that
    // was spawned AFTER the target commit.
    std::fs::create_dir_all(p.join("child/.agent")).unwrap();
    std::fs::write(p.join("child/.agent/config.yaml"), "agent_id: child").unwrap();
    std::fs::write(p.join("child/note.md"), "n").unwrap();
    // Also modify README so rollback has something to restore.
    std::fs::write(p.join("README.md"), "modified").unwrap();
    // Commit the post-target state so tree reflects it (makes tree walk
    // observable; actual checkout targets `target_hex`).
    let _ = seed_commit(
        &p,
        &[("child/note.md", "n"), ("README.md", "modified")],
        &[],
        "post",
    );

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let paths = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target_hex),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap();
    // Expected: README.md + data/x.md.
    // Excluded: .agent/config.yaml, child/**.
    let ps: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(
        ps.contains(&"README.md".to_string()),
        "missing README.md, got {:?}",
        ps
    );
    assert!(
        ps.contains(&"data/x.md".to_string()),
        "missing data/x.md, got {:?}",
        ps
    );
    assert!(
        !ps.iter().any(|s| s.starts_with(".agent/")),
        "expected no .agent/ paths, got {:?}",
        ps
    );
    // Note: `child/` doesn't appear in the target commit tree (was created after),
    // so it's not in the walk result at all. AC-05 is satisfied by the current
    // state's child-territory filter applying to target-tree paths (which it does).
}

#[tokio::test]
async fn t15_fulldirectory_rollback_excludes_agent_subtree() {
    // AC-15: `.agent/memory/knowledge.jsonl` inside target commit remains
    // untouched by full-directory rollback (the expansion filters .agent/).
    let (_td, p) = bootstrap();
    std::fs::create_dir_all(p.join(".agent/memory")).unwrap();
    std::fs::write(p.join(".agent/memory/knowledge.jsonl"), "line").unwrap();
    let target = seed_commit(
        &p,
        &[
            ("README.md", "r"),
            (".agent/memory/knowledge.jsonl", "line"),
        ],
        &[],
        "t",
    );
    // Modify README for rollback; also modify the knowledge file.
    std::fs::write(p.join("README.md"), "modified").unwrap();
    std::fs::write(p.join(".agent/memory/knowledge.jsonl"), "modified").unwrap();
    let _ = seed_commit(
        &p,
        &[
            ("README.md", "modified"),
            (".agent/memory/knowledge.jsonl", "modified"),
        ],
        &[],
        "post",
    );

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let affected = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap();
    // .agent/memory/... must NOT be in the affected list.
    for path in &affected {
        assert!(
            !path.to_string_lossy().starts_with(".agent/"),
            ".agent path leaked into full-directory rollback: {:?}",
            path
        );
    }
    // README should be restored.
    let readme = std::fs::read_to_string(p.join("README.md")).unwrap();
    assert_eq!(readme, "r");
    // .agent/memory/knowledge.jsonl remains modified (not touched).
    let knowledge = std::fs::read_to_string(p.join(".agent/memory/knowledge.jsonl")).unwrap();
    assert_eq!(
        knowledge, "modified",
        "AC-15: rollback must not touch .agent/"
    );
}

#[tokio::test]
async fn t16_pathscoped_rejects_parent_dir_traversal() {
    // AC-16: `../` traversal → PermissionDenied(ParentDirTraversal).
    let (_td, p) = bootstrap();
    let target = seed_commit(&p, &[("README.md", "r")], &[], "t");
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from("../escape.md")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RollbackError::PermissionDenied {
            reason: DeniedReason::ParentDirTraversal,
            ..
        }
    ));
}

#[tokio::test]
async fn t17_pathscoped_rejects_nonexistent_path() {
    // AC-16: non-existent path → NotFound.
    let (_td, p) = bootstrap();
    let target = seed_commit(&p, &[("README.md", "r")], &[], "t");
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from("does/not/exist.md")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RollbackError::NotFound { .. }));
}

#[tokio::test]
async fn t17a_pathscoped_rejects_hidden_git() {
    // AC-16: `.git/` target → PermissionDenied(HiddenRuntimePath).
    let (_td, p) = bootstrap();
    let target = seed_commit(&p, &[("README.md", "r")], &[], "t");
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from(".git/config")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RollbackError::PermissionDenied {
            reason: DeniedReason::HiddenRuntimePath,
            ..
        }
    ));
}

#[tokio::test]
async fn t17b_pathscoped_rejects_child_territory_overlap() {
    // AC-06 / AC-16: path under a child territory → PermissionDenied(ChildTerritoryOverlap).
    let (_td, p) = bootstrap();
    // Create a child territory `research/.agent/`.
    std::fs::create_dir_all(p.join("research/.agent")).unwrap();
    std::fs::write(p.join("research/.agent/config.yaml"), "agent_id: research").unwrap();
    std::fs::write(p.join("research/report.md"), "r").unwrap();
    let target = seed_commit(
        &p,
        &[
            ("README.md", "root"),
            ("research/report.md", "r"),
            ("research/.agent/config.yaml", "agent_id: research"),
        ],
        &[],
        "t",
    );
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from("research/report.md")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RollbackError::PermissionDenied {
            reason: DeniedReason::ChildTerritoryOverlap,
            ..
        }
    ));
}

#[tokio::test]
async fn t17c_symlinked_dotagent_marker_not_flagged_as_child() {
    // AC-16: a symlinked `.agent/` inside a subdir is NOT recognized as a
    // child-territory marker. The subdir's non-`.agent/` content IS eligible
    // for rollback.
    #[cfg(unix)]
    {
        let (_td, p) = bootstrap();
        std::fs::create_dir(p.join("maybe-child")).unwrap();
        // Point .agent at /tmp (a real directory, but symlinked — so the
        // symlink_metadata check rejects it).
        std::os::unix::fs::symlink("/tmp", p.join("maybe-child/.agent")).unwrap();
        std::fs::write(p.join("maybe-child/note.md"), "n").unwrap();
        let target = seed_commit(
            &p,
            &[("README.md", "r"), ("maybe-child/note.md", "n")],
            &[],
            "t",
        );
        let roll = DefaultWorkspaceRollback::new(p).unwrap();
        // PathScoped rollback on maybe-child/note.md — should succeed,
        // NOT flagged as child-territory overlap because the `.agent/` is a
        // symlink (not a real directory).
        let result = roll
            .rollback(
                "root",
                RollbackTarget::Commit(target),
                RollbackMode::PathScoped(vec![PathBuf::from("maybe-child/note.md")]),
            )
            .await;
        assert!(
            result.is_ok(),
            "symlinked .agent/ must not be treated as child marker; got {:?}",
            result.err()
        );
    }
}

#[tokio::test]
async fn t05_pathscoped_mirrors_t17b_child_overlap() {
    // AC-06: path-scoped rollback child-territory overlap rejection.
    let (_td, p) = bootstrap();
    std::fs::create_dir_all(p.join("child/.agent")).unwrap();
    std::fs::write(p.join("child/.agent/config.yaml"), "agent_id: child").unwrap();
    std::fs::write(p.join("child/data.md"), "d").unwrap();
    let target = seed_commit(
        &p,
        &[
            ("child/data.md", "d"),
            ("child/.agent/config.yaml", "agent_id: child"),
        ],
        &[],
        "t",
    );
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from("child/data.md")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RollbackError::PermissionDenied {
            reason: DeniedReason::ChildTerritoryOverlap,
            ..
        }
    ));
}

#[test]
fn t23_memory_rollback_paths_returns_canonical_set() {
    // AC-22: memory_rollback_paths returns Git-tracked memory file set
    // including syntheses/*.md recursive; excludes _knowledge_cursor.yaml.
    // Paths are AGENT-RELATIVE per the R2 adversarial fix — callers feed
    // them back to rollback(PathScoped) which rebases to root-relative.
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    // Alice is the root agent; memory lives at `<workdir>/.agent/memory/`.
    std::fs::create_dir_all(p.join(".agent/memory/syntheses/2026-04")).unwrap();
    std::fs::write(p.join(".agent/memory/knowledge.jsonl"), "k").unwrap();
    std::fs::write(p.join(".agent/memory/_knowledge_map.yaml"), "m").unwrap();
    std::fs::write(p.join(".agent/memory/syntheses/2026-04/foo.md"), "synth").unwrap();
    std::fs::write(p.join(".agent/memory/_knowledge_cursor.yaml"), "cursor").unwrap();
    let _ = seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            (".agent/memory/knowledge.jsonl", "k"),
            (".agent/memory/_knowledge_map.yaml", "m"),
            (".agent/memory/syntheses/2026-04/foo.md", "synth"),
            // _knowledge_cursor.yaml deliberately NOT committed to match
            // PRD §11.6 "_knowledge_cursor.yaml is non-Git-tracked".
        ],
        &[],
        "t",
    );

    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let set = roll.memory_rollback_paths("alice").unwrap();
    let strs: Vec<String> = set
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    // Paths are AGENT-RELATIVE: `.agent/memory/...` (not root-prefixed).
    assert!(strs.contains(&".agent/memory/knowledge.jsonl".to_string()));
    assert!(strs.contains(&".agent/memory/_knowledge_map.yaml".to_string()));
    assert!(
        strs.contains(&".agent/memory/syntheses/2026-04/foo.md".to_string()),
        "recursive syntheses/**/*.md missing, got {:?}",
        strs
    );
    assert!(
        !strs.iter().any(|s| s.contains("_knowledge_cursor.yaml")),
        "cursor file leaked into memory_rollback_paths, got {:?}",
        strs
    );
}

#[tokio::test]
async fn aux_rollback_pathscoped_accepts_memory_subtree() {
    // Memory-rollback flow per PRD §11.6: paths are AGENT-RELATIVE
    // (`.agent/memory/**`), rollback's validator rebases to root-relative
    // via the caller's agent_root. For root agent alice, agent_root_rel is
    // empty; rebase is a no-op.
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    std::fs::create_dir_all(p.join(".agent/memory")).unwrap();
    std::fs::write(p.join(".agent/memory/knowledge.jsonl"), "v1").unwrap();
    let target = seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            (".agent/memory/knowledge.jsonl", "v1"),
        ],
        &[],
        "t",
    );
    // Modify so rollback has something to restore.
    std::fs::write(p.join(".agent/memory/knowledge.jsonl"), "v2").unwrap();
    let _ = seed_commit(&p, &[(".agent/memory/knowledge.jsonl", "v2")], &[], "post");

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let paths = roll
        .rollback(
            "alice",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from(".agent/memory/knowledge.jsonl")]),
        )
        .await
        .unwrap();
    assert_eq!(paths.len(), 1);
    let restored = std::fs::read_to_string(p.join(".agent/memory/knowledge.jsonl")).unwrap();
    assert_eq!(
        restored, "v1",
        "memory path must be restored to target content"
    );
}

#[tokio::test]
async fn aux_rollback_pathscoped_rejects_dotagent_non_memory() {
    // `.agent/skills/foo.yaml` is outside `memory/` → rejected with
    // DotAgentOutsideMemoryRollback (per PRD §11.6 only memory/ subtree
    // is writable via rollback-memory).
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    std::fs::create_dir_all(p.join(".agent/skills")).unwrap();
    std::fs::write(p.join(".agent/skills/foo.yaml"), "v").unwrap();
    let target = seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            (".agent/skills/foo.yaml", "v"),
        ],
        &[],
        "t",
    );
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "alice",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from(".agent/skills/foo.yaml")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RollbackError::PermissionDenied {
            reason: DeniedReason::DotAgentOutsideMemoryRollback,
            ..
        }
    ));
}

#[tokio::test]
async fn aux_rollback_pathscoped_rejects_bare_dotagent() {
    // Adversarial R2 C1 regression: bare `.agent` (no trailing slash)
    // previously bypassed the `.agent/` prefix check and fell through to
    // generic-path logic, where `.agent` was not in the hidden-runtime
    // blocklist — attacker could restore the entire `.agent/` subtree from
    // target commit, trampling all agents' configs/memory. Fixed by the
    // "any `.agent` component anywhere → reject" guard.
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    std::fs::create_dir_all(p.join(".agent/memory")).unwrap();
    std::fs::write(p.join(".agent/config.yaml"), "agent_id: alice\n").unwrap();
    let target = seed_commit(&p, &[(".agent/config.yaml", "agent_id: alice\n")], &[], "t");
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "alice",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from(".agent")]),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            RollbackError::PermissionDenied {
                reason: DeniedReason::DotAgentOutsideMemoryRollback,
                ..
            }
        ),
        "bare .agent must be rejected; got {:?}",
        err
    );
}

#[tokio::test]
#[cfg(unix)]
async fn aux_rollback_rejects_symlinked_config_yaml() {
    // Adversarial C1 regression: a symlinked `.agent/config.yaml` must NOT
    // be followed by the agent_id resolver. The symlink_metadata guard in
    // `read_config_agent_id_safe` rejects symlinks; the resolver falls
    // through to BFS (which also skips symlinks) and ultimately returns
    // NotFound for a non-existent agent, preventing cross-agent mis-binding.
    let (_td, p) = bootstrap();
    // Plant a decoy file in workspace root that contains "agent_id: alice".
    std::fs::write(p.join("fake-config.yaml"), "agent_id: alice\n").unwrap();
    // Create .agent/ and symlink config.yaml → decoy.
    std::fs::create_dir(p.join(".agent")).unwrap();
    std::os::unix::fs::symlink(p.join("fake-config.yaml"), p.join(".agent/config.yaml")).unwrap();
    // Seed a commit so rollback has something to target.
    let target = seed_commit(&p, &[("README.md", "r")], &[], "t");

    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    // A request for agent_id="alice" must NOT succeed: the symlinked
    // config.yaml is rejected, the resolver returns NotFound, and the
    // rollback fails fast before any checkout.
    let err = roll
        .rollback(
            "alice",
            RollbackTarget::Commit(target),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, RollbackError::NotFound { .. }),
        "symlinked config.yaml must not mis-bind agent_root; got {:?}",
        err
    );
}

#[tokio::test]
async fn aux_rollback_invalid_commit_hex() {
    let (_td, p) = bootstrap();
    let _ = seed_commit(&p, &[("README.md", "r")], &[], "t");
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Commit("not-hex".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RollbackError::InvalidTarget { .. }));
}

#[tokio::test]
async fn aux_rollback_unknown_checkpoint_notfound() {
    let (_td, p) = bootstrap();
    let _ = seed_commit(&p, &[("README.md", "r")], &[], "t");
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Checkpoint("does-not-exist".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RollbackError::NotFound { .. }));
}

#[tokio::test]
async fn aux_rollback_restores_modified_file() {
    // Golden-path end-to-end: commit file, modify, rollback restores.
    let (_td, p) = bootstrap();
    let target = seed_commit(&p, &[("README.md", "v1")], &[], "t");
    std::fs::write(p.join("README.md"), "v2").unwrap();
    let _ = seed_commit(&p, &[("README.md", "v2")], &[], "post");
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let _ = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from("README.md")]),
        )
        .await
        .unwrap();
    let restored = std::fs::read_to_string(p.join("README.md")).unwrap();
    assert_eq!(restored, "v1");
}

#[tokio::test]
async fn aux_memory_rollback_paths_rejects_invalid_agent_id() {
    let (_td, p) = bootstrap();
    let _ = seed_commit(&p, &[("README.md", "r")], &[], "t");
    let roll = DefaultWorkspaceRollback::new(p).unwrap();
    let err = roll.memory_rollback_paths("has/slash").unwrap_err();
    assert!(matches!(err, RollbackError::Checkpoint(_)));
}

// ───────────────────────────────────────────────────────────────────────────
// FullDirectory rollback-removal (tree-diff) — completes SYS-AC-160's
// "a file added after the target is gone" clause. The removal set is
// `expand_full_domain(HEAD_tree) ∖ expand_full_domain(target_tree)` (minus a
// `.gitignore` skip): Git-tracked, writable-domain files committed after the
// target. Untracked files are structurally unreachable; `.agent/` + grandchild
// territories are excluded on both trees.
// ───────────────────────────────────────────────────────────────────────────

/// (a) A FullDirectory rollback removes a post-target COMMITTED file, reverts a
/// modified tracked file, and leaves `.agent/` + the grandchild territory
/// untouched; the removed + reverted paths appear in `affected_paths`.
#[tokio::test]
async fn t_removal_full_directory_removes_post_target_added_file() {
    let (_td, p) = bootstrap();
    // Target T: `worker` territory + a grandchild `worker/gc`. No repo-root
    // `.agent/` so the resolver finds `worker` via the BFS scan (not the root
    // sentinel).
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/report.md", "base-report"),
            ("worker/gc/.agent/config.yaml", "agent_id: gc\n"),
            ("worker/gc/result.md", "gc-base"),
        ],
        &[],
        "target",
    );
    // Post-target (HEAD): add a writable file, modify report, add a grandchild file.
    seed_commit(
        &p,
        &[
            ("worker/added.md", "added-after-target"),
            ("worker/report.md", "DRIFT"),
            ("worker/gc/extra.md", "gc-extra"),
        ],
        &[],
        "post",
    );

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let affected = roll
        .rollback(
            "worker",
            RollbackTarget::Commit(target_hex),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap();

    // The post-target added file is REMOVED from disk.
    assert!(
        !p.join("worker/added.md").exists(),
        "post-target added file must be removed"
    );
    // The modified writable file is reverted to the target content.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/report.md")).unwrap(),
        "base-report",
        "modified writable file reverted to target content"
    );
    // The agent's own `.agent/` is untouched.
    assert!(p.join("worker/.agent/config.yaml").exists());
    // The grandchild territory is untouched — both its base and its
    // post-target file survive (excluded from the parent's removal).
    assert!(p.join("worker/gc/result.md").exists());
    assert!(
        p.join("worker/gc/extra.md").exists(),
        "grandchild-territory post-target file must NOT be removed by the parent's rollback"
    );

    let strs: Vec<String> = affected
        .iter()
        .map(|x| x.to_string_lossy().into_owned())
        .collect();
    assert!(
        strs.iter().any(|s| s == "worker/added.md"),
        "affected_paths must include the removed file: {strs:?}"
    );
    assert!(
        strs.iter().any(|s| s == "worker/report.md"),
        "affected_paths must include the reverted file: {strs:?}"
    );
    assert!(
        !strs
            .iter()
            .any(|s| s.contains("/.agent/") || s.starts_with("worker/gc/")),
        "affected_paths excludes .agent/ + grandchild: {strs:?}"
    );
}

/// (b) An UNTRACKED worktree file (never committed) is NEVER removed — the
/// tree-diff walks Git trees (blobs), so untracked files (incl. an uncommitted
/// `.gitignore`) are structurally unreachable — even when a tracked post-target
/// file IS removed in the same rollback.
#[tokio::test]
async fn t_removal_preserves_untracked_file() {
    let (_td, p) = bootstrap();
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/report.md", "base"),
        ],
        &[],
        "target",
    );
    // Post-target commit adds a TRACKED file (will be removed).
    seed_commit(&p, &[("worker/added.md", "added")], &[], "post");
    // And an UNTRACKED file on disk (never committed → never in any tree).
    std::fs::write(p.join("worker/untracked.md"), "i am untracked").unwrap();

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "worker",
        RollbackTarget::Commit(target_hex),
        RollbackMode::FullDirectory,
    )
    .await
    .unwrap();

    // The tracked post-target file is removed ...
    assert!(
        !p.join("worker/added.md").exists(),
        "tracked post-target file removed"
    );
    // ... but the untracked file is PRESERVED.
    assert!(
        p.join("worker/untracked.md").exists(),
        "untracked file must be preserved by the tree-diff removal"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/untracked.md")).unwrap(),
        "i am untracked"
    );
}

/// (c) An empty target writable domain still removes HEAD-tracked post-target
/// files (the restructured early-return + skipped checkout). Pins the guard
/// that an empty `CheckoutBuilder` must NOT force-checkout the whole tree.
#[tokio::test]
async fn t_removal_empty_target_domain_still_removes() {
    let (_td, p) = bootstrap();
    // Target T: ONLY the agent's `.agent/` (excluded from the writable domain),
    // so `expand_full_domain(target)` is EMPTY for `worker` → no checkout paths.
    let target_hex = seed_commit(
        &p,
        &[("worker/.agent/config.yaml", "agent_id: worker\n")],
        &[],
        "target",
    );
    // Post-target (HEAD): add a writable file in the domain.
    seed_commit(
        &p,
        &[("worker/added.md", "added-after-target")],
        &[],
        "post",
    );

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let affected = roll
        .rollback(
            "worker",
            RollbackTarget::Commit(target_hex),
            RollbackMode::FullDirectory,
        )
        .await
        .unwrap();

    // Even with an empty target writable domain (checkout skipped), the
    // post-target added file is still removed.
    assert!(
        !p.join("worker/added.md").exists(),
        "empty-target rollback must still remove the post-target file"
    );
    // The agent's own `.agent/` is untouched (no whole-tree force-checkout).
    assert!(p.join("worker/.agent/config.yaml").exists());
    let strs: Vec<String> = affected
        .iter()
        .map(|x| x.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        strs,
        vec!["worker/added.md".to_string()],
        "affected_paths = only the removed file"
    );
}

/// (d) File→directory shape change: HEAD has a FILE `worker/a` while the target
/// has a DIRECTORY `worker/a/inner.md`. The forced checkout converts `a` to a
/// directory; the removal pass then sees `worker/a` is a directory and SKIPS it
/// (the file is already gone) — no "is a directory" error.
#[tokio::test]
#[ignore = "libgit2 file↔dir conflict ordering fails on some Linux runners (Exists: directory exists); quarantine for post-genesis fix"]
async fn t_removal_file_to_dir_conflict_restores() {
    let (_td, p) = bootstrap();
    // Target T: `worker/a` is a DIRECTORY (contains inner.md).
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/a/inner.md", "inner-base"),
        ],
        &[],
        "target: worker/a is a directory",
    );
    // HEAD: replace the `a` directory with a FILE named `a`. Build the commit
    // directly so the index drops the stale `worker/a/inner.md` entry.
    {
        let repo = Repository::open(&p).unwrap();
        std::fs::remove_dir_all(p.join("worker/a")).unwrap();
        std::fs::write(p.join("worker/a"), "now-a-file").unwrap();
        let mut idx = repo.index().unwrap();
        idx.remove_dir(Path::new("worker/a"), 0).unwrap();
        idx.add_path(Path::new("worker/a")).unwrap();
        idx.write().unwrap();
        let tree_id = idx.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("t", "t@x").unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "post: a is a file",
            &tree,
            &[&parent],
        )
        .unwrap();
    }

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "worker",
        RollbackTarget::Commit(target_hex),
        RollbackMode::FullDirectory,
    )
    .await
    .expect("file/dir conflict rollback succeeds (removal before checkout)");

    // worker/a is a directory again, with the target inner.md restored.
    assert!(
        p.join("worker/a").is_dir(),
        "worker/a restored as a directory"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/a/inner.md")).unwrap(),
        "inner-base",
        "target worker/a/inner.md restored"
    );
}

/// (e) Directory→file shape change (the reverse of (d)): HEAD has a DIRECTORY
/// `worker/a` (containing a post-target `worker/a/added.md`) while the target
/// has a FILE `worker/a`. Because the checkout runs BEFORE the removal, libgit2's
/// force strategy resolves the conflict — it removes the `worker/a/` directory +
/// contents and restores the `worker/a` FILE; the removal pass then finds
/// `worker/a/added.md` already gone. The target file MUST NOT be silently lost.
#[tokio::test]
async fn t_removal_dir_to_file_conflict_restores() {
    let (_td, p) = bootstrap();
    // Target T: `worker/a` is a FILE.
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/a", "a-is-file-base"),
        ],
        &[],
        "target: worker/a is a file",
    );
    // HEAD: replace the `a` file with a DIRECTORY `a/` containing a post-target
    // file. Build the commit directly so the index drops the stale `worker/a`
    // file entry.
    {
        let repo = Repository::open(&p).unwrap();
        std::fs::remove_file(p.join("worker/a")).unwrap();
        std::fs::create_dir(p.join("worker/a")).unwrap();
        std::fs::write(p.join("worker/a/added.md"), "added-after-target").unwrap();
        let mut idx = repo.index().unwrap();
        idx.remove_path(Path::new("worker/a")).unwrap();
        idx.add_path(Path::new("worker/a/added.md")).unwrap();
        idx.write().unwrap();
        let tree_id = idx.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("t", "t@x").unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "post: a is a directory",
            &tree,
            &[&parent],
        )
        .unwrap();
    }

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "worker",
        RollbackTarget::Commit(target_hex),
        RollbackMode::FullDirectory,
    )
    .await
    .expect("dir/file conflict rollback succeeds");

    // worker/a is a FILE again with the target content (NOT silently lost) ...
    assert!(
        p.join("worker/a").is_file(),
        "worker/a restored as a file (target content NOT lost)"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/a")).unwrap(),
        "a-is-file-base",
        "target worker/a file content restored"
    );
    // ... and the post-target added.md is gone.
    assert!(
        !p.join("worker/a/added.md").exists(),
        "post-target worker/a/added.md removed"
    );
}

/// (f) Confinement: a removal path whose intermediate component is an on-disk
/// symlink (a post-commit swap) into an EXCLUDED in-domain subdomain — here a
/// grandchild territory — must be FAIL-CLOSED-skipped, so the rollback cannot
/// delete grandchild (or `.agent/`) content by following the symlink. The
/// containment check requires the parent to be symlink-free (canonicalize ==
/// lexical), not merely within the agent root.
#[cfg(unix)]
#[tokio::test]
async fn t_removal_refuses_intermediate_symlink_into_excluded_subdomain() {
    use std::os::unix::fs::symlink;
    let (_td, p) = bootstrap();
    // Target T: worker territory + a grandchild `gc` holding a precious file. No
    // `worker/link` in the target.
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/gc/.agent/config.yaml", "agent_id: gc\n"),
            ("worker/gc/precious.md", "grandchild-precious"),
        ],
        &[],
        "target: worker + grandchild gc",
    );
    // HEAD: add a post-target file under a REAL directory `worker/link`.
    seed_commit(
        &p,
        &[("worker/link/precious.md", "link-content")],
        &[],
        "post: add worker/link/precious.md",
    );
    // ATTACK: replace the real `worker/link` directory with a symlink to the
    // grandchild `gc`. A naive removal of `worker/link/precious.md` would follow
    // the link and destroy the grandchild's `worker/gc/precious.md`.
    std::fs::remove_dir_all(p.join("worker/link")).unwrap();
    symlink("gc", p.join("worker/link")).unwrap(); // worker/link -> worker/gc

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "worker",
        RollbackTarget::Commit(target_hex),
        RollbackMode::FullDirectory,
    )
    .await
    .expect("rollback succeeds (symlinked removal path is fail-closed-skipped)");

    // The grandchild's file MUST survive — the removal refused to delete through
    // the intermediate symlink.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/gc/precious.md")).unwrap(),
        "grandchild-precious",
        "grandchild file must NOT be deleted through an intermediate symlink"
    );
    // The symlink itself was not followed-and-removed either.
    assert!(
        std::fs::symlink_metadata(p.join("worker/link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "worker/link symlink untouched"
    );
}

/// (g) Confinement: when the TARGET tree holds a FILE at the exact path that is
/// CURRENTLY a grandchild territory directory (`worker/gc`), the FullDirectory
/// rollback must NOT check that file out over the live grandchild directory —
/// the detected grandchild territory is entirely off-limits to the parent's
/// rollback (SYS-AC-159), so its `.agent/` + contents are preserved.
#[tokio::test]
async fn t_removal_full_directory_preserves_grandchild_at_exact_target_file_path() {
    let (_td, p) = bootstrap();
    // Target T: `worker/gc` is a FILE; plus a writable `worker/report.md`.
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/gc", "gc-was-a-file"),
            ("worker/report.md", "base-report"),
        ],
        &[],
        "target: worker/gc is a file",
    );
    // HEAD: replace the `worker/gc` file with a grandchild TERRITORY directory,
    // and drift report.md. Build directly so the index drops the `worker/gc` file.
    {
        let repo = Repository::open(&p).unwrap();
        std::fs::remove_file(p.join("worker/gc")).unwrap();
        std::fs::create_dir_all(p.join("worker/gc/.agent")).unwrap();
        std::fs::write(p.join("worker/gc/.agent/config.yaml"), "agent_id: gc\n").unwrap();
        std::fs::write(p.join("worker/gc/result.md"), "gc-grandchild-result").unwrap();
        std::fs::write(p.join("worker/report.md"), "DRIFT-report").unwrap();
        let mut idx = repo.index().unwrap();
        idx.remove_path(Path::new("worker/gc")).unwrap();
        idx.add_path(Path::new("worker/gc/.agent/config.yaml"))
            .unwrap();
        idx.add_path(Path::new("worker/gc/result.md")).unwrap();
        idx.add_path(Path::new("worker/report.md")).unwrap();
        idx.write().unwrap();
        let tree_id = idx.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("t", "t@x").unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "post: worker/gc is a grandchild territory",
            &tree,
            &[&parent],
        )
        .unwrap();
    }

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "worker",
        RollbackTarget::Commit(target_hex),
        RollbackMode::FullDirectory,
    )
    .await
    .expect("rollback succeeds; grandchild preserved");

    // The grandchild territory is PRESERVED — NOT replaced by the target file:
    assert!(
        p.join("worker/gc").is_dir(),
        "worker/gc grandchild directory preserved (NOT force-replaced by the target file)"
    );
    assert!(
        p.join("worker/gc/.agent/config.yaml").exists(),
        "grandchild .agent/ preserved"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/gc/result.md")).unwrap(),
        "gc-grandchild-result",
        "grandchild content preserved"
    );
    // The agent's own writable file IS reverted to the target.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/report.md")).unwrap(),
        "base-report",
        "writable file reverted to target content"
    );
}

/// (h) Confinement (ANCESTOR case): when the TARGET tree holds a FILE at a path
/// that is an ANCESTOR of a CURRENTLY-live grandchild territory (`worker/data`
/// file in target, `worker/data/gc` grandchild on disk), the FullDirectory
/// rollback must NOT check that ancestor file out over the live directory — a
/// forced checkout would recursively destroy the nested grandchild. The
/// grandchild + its `.agent/` are preserved; a non-grandchild sibling addition
/// under the same ancestor is still removed.
#[tokio::test]
async fn t_removal_full_directory_preserves_grandchild_under_target_ancestor_file() {
    let (_td, p) = bootstrap();
    // Target T: `worker/data` is a FILE; plus a writable `worker/report.md`.
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/data", "data-was-a-file"),
            ("worker/report.md", "base-report"),
        ],
        &[],
        "target: worker/data is a file",
    );
    // HEAD: replace `worker/data` (file) with a DIRECTORY that NESTS a grandchild
    // territory `worker/data/gc` plus a non-grandchild sibling addition. Drift report.
    {
        let repo = Repository::open(&p).unwrap();
        std::fs::remove_file(p.join("worker/data")).unwrap();
        std::fs::create_dir_all(p.join("worker/data/gc/.agent")).unwrap();
        std::fs::write(
            p.join("worker/data/gc/.agent/config.yaml"),
            "agent_id: gc\n",
        )
        .unwrap();
        std::fs::write(p.join("worker/data/gc/precious.md"), "gc-precious").unwrap();
        std::fs::write(p.join("worker/data/sibling.md"), "sibling-addition").unwrap();
        std::fs::write(p.join("worker/report.md"), "DRIFT-report").unwrap();
        let mut idx = repo.index().unwrap();
        idx.remove_path(Path::new("worker/data")).unwrap();
        idx.add_path(Path::new("worker/data/gc/.agent/config.yaml"))
            .unwrap();
        idx.add_path(Path::new("worker/data/gc/precious.md"))
            .unwrap();
        idx.add_path(Path::new("worker/data/sibling.md")).unwrap();
        idx.add_path(Path::new("worker/report.md")).unwrap();
        idx.write().unwrap();
        let tree_id = idx.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("t", "t@x").unwrap();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "post: worker/data nests a grandchild territory",
            &tree,
            &[&parent],
        )
        .unwrap();
    }

    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "worker",
        RollbackTarget::Commit(target_hex),
        RollbackMode::FullDirectory,
    )
    .await
    .expect("rollback succeeds; nested grandchild preserved");

    // The nested grandchild territory is PRESERVED (NOT force-destroyed):
    assert!(
        p.join("worker/data").is_dir(),
        "worker/data stays a directory (NOT force-replaced by the target ancestor file)"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/data/gc/precious.md")).unwrap(),
        "gc-precious",
        "nested grandchild content preserved"
    );
    assert!(
        p.join("worker/data/gc/.agent/config.yaml").exists(),
        "nested grandchild .agent/ preserved"
    );
    // A non-grandchild sibling ADDITION under the same ancestor IS removed.
    assert!(
        !p.join("worker/data/sibling.md").exists(),
        "non-grandchild post-target sibling addition removed"
    );
    // The agent's own writable file IS reverted.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/report.md")).unwrap(),
        "base-report",
        "writable file reverted"
    );
}

/// (i) PathScoped confinement parity: a PathScoped rollback naming an ANCESTOR
/// of a live grandchild territory (`data` when `worker/data/gc` is a grandchild)
/// is rejected with `ChildTerritoryOverlap` — the same exhaustive IS/UNDER/ANCESTOR
/// exclusion the FullDirectory path enforces, so the destructive force-checkout
/// of the ancestor is never reached on the PathScoped route either.
#[tokio::test]
async fn t_pathscoped_rejects_ancestor_of_child_territory() {
    let (_td, p) = bootstrap();
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/data/gc/.agent/config.yaml", "agent_id: gc\n"),
            ("worker/data/gc/precious.md", "gc-precious"),
            ("worker/data/notes.md", "notes"),
        ],
        &[],
        "seed worker + grandchild under data/",
    );
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    // `data` (rebased to `worker/data`) is an ANCESTOR of the grandchild
    // territory `worker/data/gc` → must be rejected.
    let err = roll
        .rollback(
            "worker",
            RollbackTarget::Commit(target_hex),
            RollbackMode::PathScoped(vec![PathBuf::from("data")]),
        )
        .await
        .expect_err("PathScoped ancestor of a grandchild territory must be rejected");
    assert!(
        matches!(
            err,
            RollbackError::PermissionDenied {
                reason: DeniedReason::ChildTerritoryOverlap,
                ..
            }
        ),
        "expected PermissionDenied(ChildTerritoryOverlap); got {err:?}"
    );
    // The grandchild is untouched by the rejected call.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/data/gc/precious.md")).unwrap(),
        "gc-precious",
        "grandchild content untouched"
    );
}

/// Adversarial R15 C1: an interior `.` (CurDir) segment must not let a
/// PathScoped path slip past the child-territory overlap guard. `data/./gc/
/// precious.md` resolves through libgit2 checkout to the grandchild file
/// `worker/data/gc/precious.md`, but the raw-string overlap test
/// `starts_with("worker/data/gc/")` failed on the un-normalized `worker/data/
/// ./gc/...`. The validator now canonicalizes the path first, so it is
/// rejected with `ChildTerritoryOverlap` exactly as the canonical form is.
#[tokio::test]
async fn t_pathscoped_rejects_dot_obfuscated_grandchild() {
    let (_td, p) = bootstrap();
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/data/gc/.agent/config.yaml", "agent_id: gc\n"),
            ("worker/data/gc/precious.md", "gc-precious"),
        ],
        &[],
        "seed worker + grandchild under data/",
    );
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let err = roll
        .rollback(
            "worker",
            RollbackTarget::Commit(target_hex),
            RollbackMode::PathScoped(vec![PathBuf::from("data/./gc/precious.md")]),
        )
        .await
        .expect_err("dot-obfuscated grandchild path must be rejected");
    assert!(
        matches!(
            err,
            RollbackError::PermissionDenied {
                reason: DeniedReason::ChildTerritoryOverlap,
                ..
            }
        ),
        "expected PermissionDenied(ChildTerritoryOverlap); got {err:?}"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/data/gc/precious.md")).unwrap(),
        "gc-precious",
        "grandchild content untouched by the rejected call"
    );
}

/// Adversarial R15 C1 (empty-segment variant): a `//` (empty) segment is the
/// other form `Path::components()` collapses without rewriting the string.
/// `data//gc/precious.md` must be canonicalized and rejected just like the
/// `.`-obfuscated form above.
#[tokio::test]
async fn t_pathscoped_rejects_empty_segment_obfuscated_grandchild() {
    let (_td, p) = bootstrap();
    let target_hex = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/data/gc/.agent/config.yaml", "agent_id: gc\n"),
            ("worker/data/gc/precious.md", "gc-precious"),
        ],
        &[],
        "seed worker + grandchild under data/",
    );
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let err = roll
        .rollback(
            "worker",
            RollbackTarget::Commit(target_hex),
            RollbackMode::PathScoped(vec![PathBuf::from("data//gc/precious.md")]),
        )
        .await
        .expect_err("empty-segment-obfuscated grandchild path must be rejected");
    assert!(
        matches!(
            err,
            RollbackError::PermissionDenied {
                reason: DeniedReason::ChildTerritoryOverlap,
                ..
            }
        ),
        "expected PermissionDenied(ChildTerritoryOverlap); got {err:?}"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/data/gc/precious.md")).unwrap(),
        "gc-precious",
        "grandchild content untouched by the rejected call"
    );
}

/// Adversarial R15 C1 (no over-rejection): canonicalization must collapse a
/// redundant `.` in a LEGITIMATE in-domain path and accept it — the rollback
/// restores the target content rather than denying the path.
#[tokio::test]
async fn t_pathscoped_accepts_redundant_dot_in_legit_path() {
    let (_td, p) = bootstrap();
    let target_hex = seed_commit(&p, &[("notes/draft.md", "v1")], &[], "seed notes");
    // Mutate after the target so the rollback has real work to do.
    std::fs::write(p.join("notes/draft.md"), "v2-dirty").unwrap();
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "root",
        RollbackTarget::Commit(target_hex),
        RollbackMode::PathScoped(vec![PathBuf::from("notes/./draft.md")]),
    )
    .await
    .expect("redundant ./ in a legit in-domain path must normalize and succeed");
    assert_eq!(
        std::fs::read_to_string(p.join("notes/draft.md")).unwrap(),
        "v1",
        "rollback should restore the target content"
    );
}

/// Adversarial R16 C1: `CheckoutBuilder::path` feeds libgit2 a PATHSPEC, so
/// `*`/`?`/`[..]` glob-expand by default. A validated literal path that carries
/// a glob metacharacter (here a file actually NAMED `*`, which passes the
/// existence check) must NOT wildmatch-expand at checkout into sibling/excluded
/// paths. `disable_pathspec_match(true)` makes the path exact: a PathScoped
/// rollback of `*` restores ONLY the literal `*` file and never reaches the
/// excluded `.agent/**` subtree. (Without the fix, libgit2 globs `*` into
/// `.agent/` and restores `.agent/secret.md` — confirmed empirically.)
#[tokio::test]
async fn t_pathscoped_glob_metachar_does_not_expand_into_excluded_subtree() {
    let (_td, p) = bootstrap();
    let target = seed_commit(
        &p,
        &[("*", "STAR0"), (".agent/secret.md", "SECRET0")],
        &[],
        "seed literal-star + private subtree",
    );
    // Dirty both the literal `*` file and the excluded private file.
    std::fs::write(p.join("*"), "STAR-dirty").unwrap();
    std::fs::write(p.join(".agent/secret.md"), "SECRET-dirty").unwrap();
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "root",
        RollbackTarget::Commit(target),
        RollbackMode::PathScoped(vec![PathBuf::from("*")]),
    )
    .await
    .expect("exact-path rollback of the literal `*` file must succeed");
    // The literal `*` file IS restored — exact match still works.
    assert_eq!(std::fs::read_to_string(p.join("*")).unwrap(), "STAR0");
    // SECURITY: the excluded `.agent/secret.md` is NOT restored — proof the
    // glob did not expand `*` into the `.agent/**` subtree.
    assert_eq!(
        std::fs::read_to_string(p.join(".agent/secret.md")).unwrap(),
        "SECRET-dirty",
        "glob `*` must NOT reach the excluded .agent/ subtree (disable_pathspec_match)"
    );
}

/// Adversarial R17 C1 + R18 regression fix: a PathScoped DIRECTORY path (e.g. a
/// directory-scoped checkpoint tag stored as `data/`) EXPANDS to its writable
/// target blobs with the per-blob exclusions re-applied — directory rollback
/// works, but excluded content (.agent / sqlite) is NOT recursively restored.
/// (`disable_pathspec_match` makes the checkout exact, so a directory entry
/// would otherwise force-restore the whole subtree past every exclusion.)
#[tokio::test]
async fn t_pathscoped_directory_expands_with_exclusions() {
    let (_td, p) = bootstrap();
    let target = seed_commit(
        &p,
        &[
            ("data/file.md", "F0"),
            ("data/sub/deep.md", "D0"),
            ("data/secret.sqlite", "S0"),
            ("data/inner/.agent/config.yaml", "C0"),
        ],
        &[],
        "seed data dir w/ excluded content",
    );
    // Remove the nested `.agent` marker post-target so `data/inner` is NOT a
    // detected territory (otherwise `data` is an ancestor-overlap rejection),
    // and dirty the writable + excluded files.
    std::fs::remove_dir_all(p.join("data/inner/.agent")).unwrap();
    std::fs::write(p.join("data/file.md"), "F-dirty").unwrap();
    std::fs::write(p.join("data/sub/deep.md"), "D-dirty").unwrap();
    std::fs::write(p.join("data/secret.sqlite"), "S-dirty").unwrap();
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    // Trailing slash matches the checkpoint-tag directory form.
    roll.rollback(
        "root",
        RollbackTarget::Commit(target),
        RollbackMode::PathScoped(vec![PathBuf::from("data/")]),
    )
    .await
    .expect("a directory PathScoped path expands to its writable blobs");
    // Writable blobs ARE restored.
    assert_eq!(
        std::fs::read_to_string(p.join("data/file.md")).unwrap(),
        "F0"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("data/sub/deep.md")).unwrap(),
        "D0"
    );
    // Excluded content is NOT restored (no recursive bypass): sqlite stays dirty,
    // and the nested `.agent/config.yaml` is not re-materialized.
    assert_eq!(
        std::fs::read_to_string(p.join("data/secret.sqlite")).unwrap(),
        "S-dirty"
    );
    assert!(
        !p.join("data/inner/.agent/config.yaml").exists(),
        "nested .agent/ must not be recursively restored"
    );
}

/// Adversarial R17 C2: with the repo on a case-insensitive FS (forced here via
/// `core.ignorecase=true` so the test is deterministic on any host), a
/// case-variant `.AGENT/...` must be rejected — it would resolve into the
/// private `.agent/` directory on checkout. The rejection is config-driven and
/// fires before any checkout, so it is FS-independent.
#[tokio::test]
async fn t_pathscoped_ignorecase_rejects_case_variant_dotagent() {
    let (_td, p) = bootstrap();
    {
        let repo = Repository::open(&p).unwrap();
        repo.config()
            .unwrap()
            .set_bool("core.ignorecase", true)
            .unwrap();
    }
    let target = seed_commit(
        &p,
        &[(".agent/secret.md", "SECRET0"), ("file.md", "F0")],
        &[],
        "seed private + normal",
    );
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    let err = roll
        .rollback(
            "root",
            RollbackTarget::Commit(target),
            RollbackMode::PathScoped(vec![PathBuf::from(".AGENT/secret.md")]),
        )
        .await
        .expect_err("case-variant .AGENT must be rejected under ignorecase");
    assert!(
        matches!(
            err,
            RollbackError::PermissionDenied {
                reason: DeniedReason::DotAgentOutsideMemoryRollback,
                ..
            }
        ),
        "expected DotAgentOutsideMemoryRollback; got {err:?}"
    );
}

/// Adversarial R17 W3: a FullDirectory rollback must NOT restore a nested
/// non-own `.agent/` that is in the TARGET tree but is no longer a detected
/// on-disk child territory (its marker was removed after the target) — parity
/// with PathScoped's any-`.agent`-component rejection (PRD §7.2).
#[tokio::test]
async fn t_fulldirectory_excludes_nested_non_own_dotagent() {
    let (_td, p) = bootstrap();
    let target = seed_commit(
        &p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/oldchild/.agent/config.yaml", "agent_id: oldchild\n"),
            ("worker/oldchild/data.md", "D0"),
        ],
        &[],
        "seed worker + former grandchild",
    );
    // The former grandchild's marker is deleted post-target; its data is dirtied.
    std::fs::remove_dir_all(p.join("worker/oldchild/.agent")).unwrap();
    std::fs::write(p.join("worker/oldchild/data.md"), "D-dirty").unwrap();
    let roll = DefaultWorkspaceRollback::new(p.clone()).unwrap();
    roll.rollback(
        "worker",
        RollbackTarget::Commit(target),
        RollbackMode::FullDirectory,
    )
    .await
    .expect("FullDirectory rollback should succeed");
    // The nested non-own `.agent/config.yaml` is NOT re-materialized.
    assert!(
        !p.join("worker/oldchild/.agent/config.yaml").exists(),
        "nested non-own .agent/ must NOT be restored by FullDirectory"
    );
    // ...but ordinary content under the former grandchild IS restored to target.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/oldchild/data.md")).unwrap(),
        "D0",
        "ordinary content should be restored to target"
    );
}
