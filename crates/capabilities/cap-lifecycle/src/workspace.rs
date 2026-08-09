//! Slice-A workspace materialization + lexical path validation.
//!
//! Three public helpers:
//! - [`resolve_under_parent`] — lexical (no canonicalize) target_dir resolution
//!   for spawn-child / spawn-sub. Returns `target_dir` lying lexically under
//!   both `parent_workspace` and `workspace_root`.
//! - [`symlink_check`] — pre-materialization walk that rejects symlinks in
//!   the existing prefix of `target_dir`. Runs BEFORE `create_dir_all`.
//! - [`init_child_workspace`] — creates `.agent/` skeleton (config.yaml,
//!   AGENTS.md placeholder, skills/, memory/knowledge.jsonl for Child/Root).

use std::path::{Component, Path, PathBuf};

use advance_shared_types::agent_tree::AgentKind;
use chrono::Utc;

use advance_shared_types::agent_tree::{AgentId, AgentTreeSnapshot};

use crate::atomic::atomic_write;
use crate::error::{LifecycleError, SpawnError};
use crate::identifier::{is_workspace_hidden_name, validate_agent_id};
use crate::tree::AgentTreeStore;

/// `init-child-workspace` payload caps (Slice C).
pub const MAX_INIT_FILES: usize = 256;
pub const MAX_INIT_FILE_BYTES: usize = 64 * 1024;
pub const MAX_INIT_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// Maximum path depth (matches cap-fs `MAX_PATH_DEPTH`).
pub const MAX_PATH_DEPTH: usize = 32;

/// Lexical (no canonicalize) `target_dir` resolution.
///
/// Slice-A rules:
/// - `child_workspace_path` must NOT be absolute (rejected — keeps lexical
///   containment meaningful across macOS `/var` ↔ `/private/var` symlink aliases).
/// - `child_workspace_path` components must not contain `..` or hidden names.
/// - Path depth (relative to parent_workspace) must not exceed `MAX_PATH_DEPTH`.
/// - Returned `target_dir = parent_workspace.join(child_workspace_path)` MUST
///   lexically start with BOTH `parent_workspace` AND `workspace_root`.
///
/// Both `parent_workspace` and `workspace_root` SHOULD be canonical at the
/// call site (AgentTreeStore canonicalizes on insert; DefaultSpawner inherits
/// the canonical workspace_root from the tree).
pub fn resolve_under_parent(
    parent_workspace: &Path,
    child_workspace_path: &Path,
    workspace_root: &Path,
) -> Result<PathBuf, SpawnError> {
    if child_workspace_path.as_os_str().is_empty() {
        return Err(SpawnError::InvalidConfig(
            "child_workspace_path is empty".to_string(),
        ));
    }
    if child_workspace_path.is_absolute() {
        return Err(SpawnError::PathTraversal(format!(
            "child_workspace_path must be relative: {}",
            child_workspace_path.display()
        )));
    }
    // Walk relative components for `..`, hidden names, depth.
    let mut depth: usize = 0;
    for comp in child_workspace_path.components() {
        match comp {
            Component::ParentDir => {
                return Err(SpawnError::PathTraversal(format!(
                    "`..` component rejected in {}",
                    child_workspace_path.display()
                )));
            }
            Component::CurDir => continue, // skip `.`
            Component::Normal(s) => {
                let s = s.to_string_lossy();
                if is_workspace_hidden_name(&s) {
                    return Err(SpawnError::PathTraversal(format!(
                        "hidden-name component rejected: {s}"
                    )));
                }
                depth += 1;
                if depth > MAX_PATH_DEPTH {
                    return Err(SpawnError::PathTraversal(format!(
                        "path depth exceeds MAX_PATH_DEPTH={MAX_PATH_DEPTH}"
                    )));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(SpawnError::PathTraversal(format!(
                    "absolute / prefix component rejected in {}",
                    child_workspace_path.display()
                )));
            }
        }
    }
    let candidate = parent_workspace.join(child_workspace_path);
    // Lexical containment under parent_workspace (must already be true by construction).
    if !candidate.starts_with(parent_workspace) {
        return Err(SpawnError::PathTraversal(format!(
            "{} not under parent_workspace {}",
            candidate.display(),
            parent_workspace.display()
        )));
    }
    // Lexical containment under workspace_root (defense-in-depth; parent_workspace
    // is itself under workspace_root via AgentTreeStore's insert-time enforcement,
    // so this is redundant in practice but cheap).
    if !candidate.starts_with(workspace_root) {
        return Err(SpawnError::PathTraversal(format!(
            "{} not under workspace_root {}",
            candidate.display(),
            workspace_root.display()
        )));
    }
    Ok(candidate)
}

/// Walk component-by-component from `workspace_root` toward `target` using
/// `std::fs::symlink_metadata`. If any existing component is a symlink →
/// `PathTraversal`. Stops at the first non-existent component.
///
/// Slice-A threat model: detects PRE-EXISTING symlinks; does NOT defend against
/// a race attacker who plants symlinks between this call and the next FS op.
pub fn symlink_check(workspace_root: &Path, target: &Path) -> Result<(), SpawnError> {
    match std::fs::symlink_metadata(workspace_root) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(SpawnError::PathTraversal(format!(
                "workspace_root is a symlink: {}",
                workspace_root.display()
            )));
        }
        Ok(_) => {}
        Err(e) => {
            return Err(SpawnError::WorkspaceIoFailure(format!(
                "workspace_root symlink_metadata: {e}"
            )));
        }
    }
    // Walk from workspace_root toward target, one component at a time.
    let mut walk = workspace_root.to_path_buf();
    let rel = target.strip_prefix(workspace_root).unwrap_or(Path::new(""));
    for comp in rel.components() {
        walk.push(comp);
        match std::fs::symlink_metadata(&walk) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(SpawnError::PathTraversal(format!(
                    "symlink in materialized prefix at {}",
                    walk.display()
                )));
            }
            Ok(_) => continue, // exists + not a symlink → ok
            Err(_) => break,   // first non-existent component → stop walking
        }
    }
    Ok(())
}

/// Materialize the `.agent/` skeleton under `target_dir`.
///
/// Ordering (R3 Codex Critical #1 fix — symlink_check BEFORE create_dir_all):
/// 1. Fast-fail if `target_dir/.agent/` already exists.
/// 2. `symlink_check` for pre-existing symlinks in `target_dir`'s ancestry.
/// 3. `create_dir_all(target_dir)`.
/// 4. Optional re-check (belt-and-suspenders).
/// 5. Create `target_dir/.agent/` directory.
/// 6. Write `.agent/config.yaml` placeholder via `atomic_write`.
/// 7. Write `.agent/AGENTS.md` placeholder via `atomic_write`.
/// 8. Create `.agent/skills/` directory (empty).
/// 9. For `kind == Child` or `kind == Root`: create `.agent/memory/` directory
///    and write empty `.agent/memory/knowledge.jsonl` via `atomic_write`.
/// 10. For `kind == Sub`: skip memory subtree.
pub fn init_child_workspace(
    target_dir: &Path,
    kind: AgentKind,
    workspace_root: &Path,
) -> Result<(), SpawnError> {
    let agent_dir = target_dir.join(".agent");
    if agent_dir.exists() {
        return Err(SpawnError::AlreadyExists(format!(
            ".agent/ already exists at {}",
            target_dir.display()
        )));
    }
    // Pre-materialization symlink defense (Slice A scope: detect-after-each-component).
    symlink_check(workspace_root, target_dir)?;
    // Track whether target_dir existed BEFORE create_dir_all — guides best-effort
    // rollback on subsequent failure (R3 audit-fix: partial-materialization leak).
    let target_pre_existed = target_dir.exists();
    std::fs::create_dir_all(target_dir).map_err(|e| {
        SpawnError::WorkspaceIoFailure(format!("create_dir_all {}: {e}", target_dir.display()))
    })?;
    // Run the inner materialization in a closure so we can rollback on any error.
    let inner = || -> Result<(), SpawnError> {
        // Belt-and-suspenders: re-run symlink_check after create_dir_all to catch
        // a symlink raced in during the create_dir_all walk.
        symlink_check(workspace_root, target_dir)?;
        std::fs::create_dir(&agent_dir).map_err(|e| {
            SpawnError::WorkspaceIoFailure(format!("create_dir {}: {e}", agent_dir.display()))
        })?;
        let kind_label = match kind {
            AgentKind::Root => "root",
            AgentKind::Child => "child",
            AgentKind::Sub => "sub",
        };
        let config_yaml = format!(
            "# Generated by cap-lifecycle Slice A. Slice B template materialization may overwrite.\n\
             name: \"\"\n\
             created: \"{}\"\n\
             kind: \"{}\"\n",
            Utc::now().to_rfc3339(),
            kind_label,
        );
        atomic_write(&agent_dir.join("config.yaml"), config_yaml.as_bytes())?;
        let agents_md =
            b"# Self-Improvement Guidelines (placeholder - Slice B template materialization)\n";
        atomic_write(&agent_dir.join("AGENTS.md"), agents_md)?;
        let skills_dir = agent_dir.join("skills");
        std::fs::create_dir(&skills_dir).map_err(|e| {
            SpawnError::WorkspaceIoFailure(format!("create_dir {}: {e}", skills_dir.display()))
        })?;
        match kind {
            AgentKind::Child | AgentKind::Root => {
                let memory_dir = agent_dir.join("memory");
                std::fs::create_dir(&memory_dir).map_err(|e| {
                    SpawnError::WorkspaceIoFailure(format!(
                        "create_dir {}: {e}",
                        memory_dir.display()
                    ))
                })?;
                atomic_write(&memory_dir.join("knowledge.jsonl"), b"")?;
            }
            AgentKind::Sub => {
                // No memory subtree per MODULE-005 §1.3.2 ("Memory | None (or temporary)").
            }
        }
        Ok(())
    };
    match inner() {
        Ok(()) => Ok(()),
        Err(orig) => {
            // Best-effort rollback: remove the .agent/ subtree we partially built,
            // and if target_dir was newly-created by this call (didn't exist before
            // create_dir_all), remove it too. Failures during rollback are logged
            // implicitly by ignoring; the original error is surfaced.
            let _ = std::fs::remove_dir_all(&agent_dir);
            if !target_pre_existed {
                let _ = std::fs::remove_dir_all(target_dir);
            }
            Err(orig)
        }
    }
}

/// Slice C — `init-child-workspace` real file materialization (AC-01 facet).
///
/// Pre-start delta-init: writes caller-supplied `files` under the named
/// child's `workspace_path`. The child MUST be registered (→ `NotFound`).
/// Caps: ≤256 files, ≤64 KiB/file, ≤4 MiB aggregate; each `relative_path`
/// is lexically validated (no `..` / absolute / hidden-name / depth >
/// `MAX_PATH_DEPTH`) and `symlink_check`'d before write.
///
/// Pre-start invariant note (§3.8): whether the child agent has already
/// started a Run is an M008-owned signal not imported here — Slice C treats
/// the pre-start check as best-effort (the parent-driven call site is
/// expected to gate on run-state once M008 wiring lands).
pub fn init_child_workspace_files(
    tree: &AgentTreeStore,
    caller_id: &str,
    child_id: &str,
    files: &[(String, Vec<u8>)],
) -> Result<(), LifecycleError> {
    if validate_agent_id(caller_id).is_err() {
        return Err(LifecycleError::PermissionDenied(format!(
            "invalid caller id: {caller_id}"
        )));
    }
    if validate_agent_id(child_id).is_err() {
        return Err(LifecycleError::NotFound(format!(
            "invalid child id: {child_id}"
        )));
    }
    // Parent-permission gate (matches the discipline of every other
    // `child-*` operation: terminate-child, child-stats,
    // list-child-checkpoints, rollback-child). Without this, a malicious
    // peer could write arbitrary content (.agent/AGENTS.md, skill files)
    // into ANY other agent's territory pre-start, planting
    // behavior-shaping artifacts — a privilege escalation across the
    // parent/child trust boundary (PRD §1.2 parent-write-child-blocked).
    let snap = tree.snapshot();
    let child_key = AgentId(child_id.to_string());
    if !snap.parent_of.contains_key(&child_key) {
        return Err(LifecycleError::NotFound(format!("agent {child_id}")));
    }
    match snap.parent_of.get(&child_key).and_then(|p| p.clone()) {
        Some(p) if p.0 == caller_id => {}
        _ => {
            return Err(LifecycleError::PermissionDenied(format!(
                "{caller_id} is not the parent of {child_id}"
            )));
        }
    }
    let node = tree
        .get_node(&child_key)
        .ok_or_else(|| LifecycleError::NotFound(format!("agent {child_id}")))?;
    if files.len() > MAX_INIT_FILES {
        return Err(LifecycleError::InvalidTarget(format!(
            "init-child-workspace: {} files > {MAX_INIT_FILES} cap",
            files.len()
        )));
    }
    let mut total = 0usize;
    for (rel, bytes) in files {
        if bytes.len() > MAX_INIT_FILE_BYTES {
            return Err(LifecycleError::InvalidTarget(format!(
                "init-child-workspace: file {rel:?} {} > {MAX_INIT_FILE_BYTES} cap",
                bytes.len()
            )));
        }
        total += bytes.len();
        if total > MAX_INIT_TOTAL_BYTES {
            return Err(LifecycleError::InvalidTarget(format!(
                "init-child-workspace: aggregate > {MAX_INIT_TOTAL_BYTES} cap"
            )));
        }
        // Lexical rel-path validation under the child's territory.
        let dest =
            resolve_under_parent(&node.workspace_path, Path::new(rel), tree.workspace_root())
                .map_err(|e| LifecycleError::InvalidTarget(format!("path {rel:?}: {e}")))?;
        // symlink-ancestor check BEFORE create_dir_all (matches Slice-A
        // `init_child_workspace` discipline — catch a pre-existing symlinked
        // ancestor before we materialize any directory through it), then a
        // defence-in-depth re-check immediately before the write (matches
        // Slice-B rollback's pre-destructive re-check). Within the crate's
        // documented non-adversarial first-party-caller threat model this
        // bounds the workspace-local race surface; full openat2 hardening
        // remains the deferred cap-fs-reuse work item (§3.8).
        symlink_check(tree.workspace_root(), &dest).map_err(|e| {
            LifecycleError::IoFailure(format!("symlink_check (pre-mkdir) {dest:?}: {e}"))
        })?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LifecycleError::IoFailure(format!("mkdir {parent:?}: {e}")))?;
        }
        symlink_check(tree.workspace_root(), &dest).map_err(|e| {
            LifecycleError::IoFailure(format!("symlink_check (pre-write) {dest:?}: {e}"))
        })?;
        atomic_write(&dest, bytes)
            .map_err(|e| LifecycleError::IoFailure(format!("write {dest:?}: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn canon(p: &Path) -> PathBuf {
        p.canonicalize().expect("canonicalize")
    }

    #[test]
    fn rejects_parent_dir_component() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let parent = root.join("p");
        std::fs::create_dir_all(&parent).unwrap();
        let err = resolve_under_parent(&parent, Path::new("../escape"), &root).unwrap_err();
        assert!(matches!(err, SpawnError::PathTraversal(_)));
    }

    #[test]
    fn rejects_absolute_path() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let parent = root.join("p");
        std::fs::create_dir_all(&parent).unwrap();
        let err = resolve_under_parent(&parent, Path::new("/etc/passwd"), &root).unwrap_err();
        assert!(matches!(err, SpawnError::PathTraversal(_)));
    }

    #[test]
    fn rejects_hidden_name() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let parent = root.join("p");
        std::fs::create_dir_all(&parent).unwrap();
        let err = resolve_under_parent(&parent, Path::new(".git/foo"), &root).unwrap_err();
        assert!(matches!(err, SpawnError::PathTraversal(_)));
    }

    #[test]
    fn accepts_relative_inside_parent() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let parent = root.join("p");
        std::fs::create_dir_all(&parent).unwrap();
        let got = resolve_under_parent(&parent, Path::new("a/b"), &root).unwrap();
        assert_eq!(got, parent.join("a").join("b"));
    }

    #[test]
    fn rejects_overlong_depth() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let parent = root.join("p");
        std::fs::create_dir_all(&parent).unwrap();
        let mut p = PathBuf::new();
        for i in 0..(MAX_PATH_DEPTH + 1) {
            p.push(format!("d{i}"));
        }
        let err = resolve_under_parent(&parent, &p, &root).unwrap_err();
        assert!(matches!(err, SpawnError::PathTraversal(_)));
    }

    #[test]
    fn init_child_workspace_child_has_memory() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let target = root.join("agents").join("foo");
        init_child_workspace(&target, AgentKind::Child, &root).unwrap();
        assert!(target.join(".agent").is_dir());
        assert!(target.join(".agent/config.yaml").is_file());
        assert!(target.join(".agent/AGENTS.md").is_file());
        assert!(target.join(".agent/skills").is_dir());
        assert!(target.join(".agent/memory").is_dir());
        assert!(target.join(".agent/memory/knowledge.jsonl").is_file());
    }

    #[test]
    fn init_child_workspace_sub_no_memory() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let target = root.join(".sub").join("uuid-xyz");
        init_child_workspace(&target, AgentKind::Sub, &root).unwrap();
        assert!(target.join(".agent").is_dir());
        assert!(target.join(".agent/config.yaml").is_file());
        assert!(target.join(".agent/AGENTS.md").is_file());
        assert!(target.join(".agent/skills").is_dir());
        assert!(!target.join(".agent/memory").exists());
    }

    #[test]
    fn init_child_workspace_root_has_memory() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let target = root.join("root_ws");
        init_child_workspace(&target, AgentKind::Root, &root).unwrap();
        assert!(target.join(".agent/memory/knowledge.jsonl").is_file());
    }

    #[test]
    fn init_child_workspace_rejects_existing_agent_dir() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let target = root.join("dup");
        std::fs::create_dir_all(target.join(".agent")).unwrap();
        let err = init_child_workspace(&target, AgentKind::Child, &root).unwrap_err();
        assert!(matches!(err, SpawnError::AlreadyExists(_)));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_check_rejects_existing_symlink_ancestor() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.join("link");
        symlink(&real, &link).unwrap();
        let target = link.join("inside");
        let err = symlink_check(&root, &target).unwrap_err();
        assert!(matches!(err, SpawnError::PathTraversal(_)));
    }

    #[cfg(unix)]
    #[test]
    fn init_child_workspace_symlink_check_blocks_before_create_dir_all() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.join("link");
        symlink(&real, &link).unwrap();
        let target = link.join("agent_x");
        let err = init_child_workspace(&target, AgentKind::Child, &root).unwrap_err();
        assert!(matches!(err, SpawnError::PathTraversal(_)));
        // No materialization occurred via the symlink.
        assert!(!target.join(".agent").exists());
    }
}
