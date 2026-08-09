//! `VirtualPathResolver` — slice A subset of MODULE-002's 7 access rules.
//!
//! Slice A implements:
//!   - Rule 1: own-workspace read+write (the agent can read/write paths inside its
//!     own territory, where territory = `AgentNode.workspace_path` from
//!     `AgentTreeSnapshot`)
//!   - Rule 7: `/.advance/` is hidden — paths resolving under `workspace_root/.advance`
//!     return `NotFound`
//!   - Path traversal rejection: any vpath whose `Path::components()` contains
//!     `Component::ParentDir` (`..`), `Component::RootDir` (leading `/`), or
//!     `Component::Prefix(_)` (Windows `C:\`) is rejected as `InvalidPath`. Benign
//!     filenames like `..foo` or `archive..2025` (which are `Component::Normal`) are
//!     accepted — substring matching on `..` would over-reject.
//!   - Lexical containment defense in depth: after joining the vpath under the
//!     agent's workspace_path, we verify the result still starts with workspace_path
//!     via component-wise `Path::starts_with`. Catches any traversal/canonicalization
//!     edge that survived the component check (e.g. backslash-on-POSIX cases).
//!   - Workspace-scope hidden-name defense: any path whose components include
//!     `.git`, `.meta.yaml`, `*.sqlite`, or `*.sqlite-wal` is rejected as `NotFound`
//!     (per MODULE-002 §1.4.3 `HiddenScope::Workspace` — pure lexical check, no
//!     agent-tree needed). The `.agent/_*` subset of HiddenScope::AgentDir is
//!     deferred (needs agent-tree resolution).
//!
//! Deferred to slice B+:
//!   - Rule 2: read-child territory (handled by separate `read-child` host fn)
//!   - Rule 3: peer-slug read (separate `read-slug` host fn)
//!   - Rule 4: parent blocked
//!   - Rule 5: non-adjacent blocked
//!   - Rule 6: own `.agent/` read-only via host fn (write blocked)
//!   - `.agent/_*` hidden-name (needs agent-tree to know each agent's `.agent` dir)
//!
//! The resolver intentionally does NOT canonicalize — `realpath`/symlink resolution
//! is the AgentTreeSnapshot producer's responsibility (per `agent_tree.rs:24-27`'s
//! implementer-invariants block: "producers MUST validate workspace_path values
//! against `..`, absolute symlink targets outside the workspace root, or
//! non-canonical components BEFORE persisting"). Slice A trusts that contract.
//!
//! ## Symlink + case-sensitivity caveat
//!
//! On macOS APFS (case-insensitive by default), `Path::starts_with` is case-sensitive,
//! so a path returned by the OS in a different case (e.g. via mount-point
//! normalization) could fail the containment check unexpectedly. Likewise a symlink
//! inside the agent's territory pointing OUTSIDE the territory is NOT detected by
//! the lexical check — the resolver doesn't follow symlinks. These are acknowledged
//! limitations of the slice A "defense in depth" lexical guard; full canonicalization
//! semantics live with the AgentTreeSnapshot producer.
//!
//! ## Threat model boundary: post-resolve TOCTOU
//!
//! The resolver's `symlink_walk` proves "no path component is a symlink at this
//! instant" and returns a `PathBuf`. Handlers then use that path with following
//! syscalls (`tokio::fs::metadata`, `File::open`, `read_dir`, `remove_file`,
//! `atomic_write`'s persist-by-rename). A concurrent actor with workspace
//! write access — e.g. an OS-level process running outside the runtime —
//! could swap a directory component to a symlink between resolver completion
//! and a later syscall, causing the syscall to follow the swapped symlink
//! out of the agent territory.
//!
//! This is a real TOCTOU window, but it is **explicitly out of scope for the
//! WASM threat model** that drives slice B:
//!
//! - WASM agents only mutate the workspace through cap-fs host fns. None of
//!   the 18 host fns expose symlink creation; `fs.write` writes regular files
//!   via `atomic_write` (rename-replace, no symlinks). A guest cannot
//!   create the symlink that would be needed to set up this race.
//! - The threat model trusts the AgentTreeSnapshot producer (it provides
//!   `workspace_path`s; if it provides a symlinked workspace_path, that's a
//!   producer bug, not a sandbox escape). It also trusts that no OS-level
//!   concurrent process is racing with the runtime.
//! - An OS-level attacker with workspace write access can already bypass the
//!   sandbox by directly modifying file contents — the symlink-swap doesn't
//!   add capability beyond that.
//!
//! Closing the post-resolve TOCTOU completely requires `openat2` with
//! `RESOLVE_NO_SYMLINKS` (Linux only) or per-component `openat` walks
//! (significant refactor; both directions block on tokio not exposing dirfd
//! APIs). That work belongs in a future hardening pass, not slice B.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::agent_tree::AgentId;
use advance_shared_types::traits::AgentTreeSnapshot;

use crate::error::FsError;

/// Maximum number of path components in a vpath (matches MODULE-002 §2.11
/// "Max path depth: 32"). Bounds:
///   - the resolver's Step 7 symlink walk to 32 sync `symlink_metadata` syscalls
///   - atomic_write's `create_dir_all` to creating at most 32 nested dirs per call
///   - inode-exhaustion DoS via deeply-nested unique-path fs.write loops
/// 32 covers all realistic agent workspace layouts.
pub const MAX_PATH_DEPTH: usize = 32;

/// Workspace-scope hidden names (slice A subset of MODULE-002 §1.4.3
/// `HiddenScope::Workspace`). Used by:
///   - `resolve_read` Step 6 to reject any vpath whose physical path contains
///     a hidden name component.
///   - `FsListHandler` to filter enumerated entries so the hidden-name policy
///     is honored both at resolution AND at listing time. Without the listing
///     filter, `fs.list(".")` would return `.git` / `.meta.yaml` / `*.sqlite*`
///     entries even though `fs.read(".git/HEAD")` rejects — fingerprinting
///     bypass.
///
/// Also includes `.advance` so that `fs.list` of the workspace root never
/// reveals the runtime control plane directory. The `.agent/_*` subset of
/// `HiddenScope::AgentDir` is genuinely deferred to slice B+ (needs agent-tree
/// to know each agent's `.agent` dir).
pub fn is_workspace_hidden_name(name: &str) -> bool {
    if name.eq_ignore_ascii_case(".git")
        || name.eq_ignore_ascii_case(".meta.yaml")
        || name.eq_ignore_ascii_case(".advance")
    {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".sqlite")
        || lower.ends_with(".sqlite-wal")
        || lower.ends_with(".sqlite-shm")
        || lower.ends_with(".sqlite-journal")
}

/// Returns true for `_*` filenames (the `.agent/_*` hidden-subset names).
/// The full hidden check is two-component: `<dir>/.agent/_<anything>`. This
/// helper only flags the `_*` leaf-name; the walker tracks the `.agent/` ancestor.
pub fn is_agent_internal_hidden_name(name: &str) -> bool {
    name.starts_with('_')
}

/// Walk `physical`'s components, applying both workspace-scope hidden-names
/// (`.git`, `.meta.yaml`, `.advance`, `.sqlite*`) AND cross-territory `.agent/_*`
/// hidden subset (a `_*` immediately under any `.agent/` directory). Used by all
/// 5 resolve methods to share the exact same hidden-name policy regardless of
/// which agent's territory the path lands in.
pub fn apply_hidden_name_walk(target_workspace: &Path, physical: &Path) -> Result<(), FsError> {
    let relative = physical
        .strip_prefix(target_workspace)
        .unwrap_or(Path::new(""));
    let mut just_saw_agent = false;
    for comp in relative.components() {
        if let Component::Normal(name) = comp {
            let s = name.to_string_lossy();
            if is_workspace_hidden_name(&s) {
                // Sanitize: emit only the relative path (the agent's own
                // virtual path), never the absolute host path.
                // Constant payload — must match the handler-level map_io_error
                // payload exactly so a guest cannot fingerprint hidden-class
                // rejection vs visible-ENOENT by inspecting the message.
                return Err(FsError::NotFound("path not found".to_string()));
            }
            if just_saw_agent && is_agent_internal_hidden_name(&s) {
                // Constant payload — must match the handler-level map_io_error
                // payload exactly so a guest cannot fingerprint hidden-class
                // rejection vs visible-ENOENT by inspecting the message.
                return Err(FsError::NotFound("path not found".to_string()));
            }
            // Case-insensitive on `.agent` so HFS+/APFS case-folding cannot
            // bypass the cross-territory `.agent/_*` hidden subset (a guest
            // typing `.AGENT/_drafts/x` resolves to the same dir as
            // `.agent/_drafts/x` on a case-folding volume).
            just_saw_agent = s.eq_ignore_ascii_case(".agent");
        }
    }
    Ok(())
}

/// Slice B trait surface. Adds a 5th method `resolve_dir_write` for update-meta
/// host fns that need to operate on directory-level metadata (including the
/// territory root, which `resolve_write` rejects).
pub trait VirtualPathResolver: Send + Sync {
    fn resolve_read(&self, agent_id: &str, vpath: &str) -> Result<PathBuf, FsError>;
    fn resolve_write(&self, agent_id: &str, vpath: &str) -> Result<PathBuf, FsError>;
    fn resolve_child_read(
        &self,
        parent_id: &str,
        child_id: &str,
        vpath: &str,
    ) -> Result<PathBuf, FsError>;
    fn resolve_slug_read(
        &self,
        agent_id: &str,
        peer_id: &str,
        slug: &str,
        file: &str,
    ) -> Result<PathBuf, FsError>;
    /// Like `resolve_write` but allows the territory root (used by
    /// update-scope/update-entry-meta on the workspace `.meta.yaml`'s `_scope`).
    fn resolve_dir_write(&self, agent_id: &str, vpath: &str) -> Result<PathBuf, FsError>;
}

/// Default `VirtualPathResolver` impl backed by an `AgentTreeSnapshot` provider for
/// territory lookup and a `workspace_root` for the `.advance/` reference frame.
pub struct DefaultVirtualPathResolver {
    workspace_root: PathBuf,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
}

impl DefaultVirtualPathResolver {
    /// Construct a new resolver. `workspace_root` is the physical workspace root
    /// directory (the dir containing `.advance/`, `.git/`, agent territories);
    /// `agent_tree` provides per-agent `workspace_path` lookup via `snapshot()`.
    pub fn new(workspace_root: PathBuf, agent_tree: Arc<dyn AgentTreeSnapshot>) -> Self {
        Self {
            workspace_root,
            agent_tree,
        }
    }

    fn agent_workspace(&self, agent_id: &str) -> Result<PathBuf, FsError> {
        let snapshot = self.agent_tree.snapshot();
        snapshot
            .nodes
            .into_iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.workspace_path)
            .ok_or_else(|| FsError::NotFound("path not found".to_string()))
    }
}

impl VirtualPathResolver for DefaultVirtualPathResolver {
    fn resolve_read(&self, agent_id: &str, vpath: &str) -> Result<PathBuf, FsError> {
        // Step 1: component-based traversal/absolute rejection + depth cap.
        let p = Path::new(vpath);
        if p.is_absolute() {
            return Err(FsError::InvalidPath(vpath.to_string()));
        }
        // Empty / CurDir-only vpaths are ALLOWED through resolve_read because
        // `fs.list(".")` and `fs.read(".")` are legitimate "operate on my own
        // territory root" use cases (list returns territory contents; read on
        // a directory returns an OS-level io-error which is fine). Write
        // operations have a stricter rule — see resolve_write below — that
        // closes the temp-file-in-territory-parent escape vector.
        let mut depth = 0usize;
        for comp in p.components() {
            match comp {
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(FsError::InvalidPath(vpath.to_string()));
                }
                Component::Normal(name) => {
                    depth += 1;
                    if depth > MAX_PATH_DEPTH {
                        return Err(FsError::InvalidPath(format!(
                            "path depth {depth} exceeds MAX_PATH_DEPTH ({MAX_PATH_DEPTH}): {vpath}"
                        )));
                    }
                    // ASCII-only component names — surface reduction defense
                    // against Unicode-homoglyph + filesystem-normalization
                    // attacks (e.g. `.gıt/HEAD` resolving to `.git/HEAD` on
                    // HFS+ NFD or some FUSE/SMB mounts). Slice A pin: agents
                    // can only write/read ASCII-named files. UTF-8 filenames
                    // are unblocked in slice B+ once we have proper Unicode
                    // normalization in the hidden-name compare.
                    let bytes = name.to_string_lossy();
                    if !bytes.is_ascii() {
                        return Err(FsError::InvalidPath(format!(
                            "non-ASCII path component (slice A restriction): {vpath}"
                        )));
                    }
                }
                _ => {}
            }
        }

        // Step 2: agent-tree territory lookup.
        let agent_workspace = self.agent_workspace(agent_id)?;

        // Step 3: lexical join — no canonicalization (trust producer per agent_tree.rs:24-27).
        let physical = agent_workspace.join(vpath);

        // Step 4: lexical containment defense — Path::starts_with is component-wise.
        if !physical.starts_with(&agent_workspace) {
            return Err(FsError::NotFound("path not found".to_string()));
        }

        // Step 5: Rule 7 — `/.advance/` is hidden.
        if physical.starts_with(self.workspace_root.join(".advance")) {
            return Err(FsError::NotFound("path not found".to_string()));
        }

        // Step 6: hidden-name walk via shared helper. Applies BOTH workspace-scope
        // hidden names (`.git`, `.meta.yaml`, `.advance`, `.sqlite*`) AND the
        // cross-territory `.agent/_*` hidden subset (slice B). Iterates the
        // relative vpath components (not physical.components()) so a host-side
        // ancestor literally named `.git` doesn't false-positive.
        apply_hidden_name_walk(&agent_workspace, &physical)?;

        // Step 7: symlink defense — walk physical's existing components and
        // reject if any is a symlink. This closes the sandbox-escape vector
        // where a guest (or external process with workspace access) places a
        // symlink inside the territory pointing OUTSIDE — the lexical
        // containment check in Step 4 sees the symlink name only, not the
        // target. Includes `agent_workspace` itself in the walk: a buggy
        // AgentTreeSnapshot producer that registers a symlinked workspace_path
        // would otherwise let every fs op escape.
        //
        // For paths that don't yet exist (write target), the walk stops at the
        // first non-existent component. atomic_write subsequently REJECTS
        // missing parent directories (no auto-create_dir_all) so the TOCTOU
        // window between this walk and the actual disk op cannot be exploited
        // to inject a symlink at a previously-missing component.
        match std::fs::symlink_metadata(&agent_workspace) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(FsError::NotFound("path not found".to_string()));
            }
            Ok(_) => {}
            Err(_) => {
                // workspace_path itself doesn't exist on disk — caller's
                // setup error. Defer to the actual disk op for error reporting.
            }
        }

        let mut walk = agent_workspace.clone();
        let relative = physical
            .strip_prefix(&agent_workspace)
            .unwrap_or(Path::new(""));
        for comp in relative.components() {
            walk.push(comp);
            match std::fs::symlink_metadata(&walk) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(FsError::NotFound("path not found".to_string()));
                }
                Ok(_) => {}
                Err(_) => {
                    // Component doesn't exist yet — stop walking. The atomic
                    // write path now requires the parent dir to exist (no
                    // create_dir_all), so missing tail components surface as
                    // an io-error from atomic_write, not a silent traversal.
                    break;
                }
            }
        }

        Ok(physical)
    }

    fn resolve_write(&self, agent_id: &str, vpath: &str) -> Result<PathBuf, FsError> {
        let physical = self.resolve_read(agent_id, vpath)?;

        let agent_workspace = self.agent_workspace(agent_id)?;
        if physical == agent_workspace {
            return Err(FsError::InvalidPath(format!(
                "cannot write to territory root (path resolves to agent workspace itself): {vpath}"
            )));
        }
        let p = Path::new(vpath);
        if !p.components().any(|c| matches!(c, Component::Normal(_))) {
            return Err(FsError::InvalidPath(format!(
                "write path has no Normal component (resolves to territory root): {vpath}"
            )));
        }

        // Slice B Step 8 (Rule 2 — child territory write blocked): if physical
        // resolves under any descendant agent's workspace_path, reject with
        // PermissionDenied. AC-15 explicitly requires permission-denied here
        // (parent KNOWS its children — no fingerprinting concern).
        //
        // Use a case-insensitive component compare so HFS+/APFS case-folding
        // cannot bypass the check via alternate-cased child paths
        // (e.g. parent typing "Sub-A/x.md" when child is "sub-a"). A byte-
        // level `path.starts_with` would miss this, but the OS resolves both
        // to the same on-disk inode.
        let snapshot = self.agent_tree.snapshot();
        if let Some(children) = snapshot.children_of.get(&AgentId(agent_id.to_string())) {
            for child_id in children {
                if let Some(child_node) = snapshot.nodes.iter().find(|n| n.id == *child_id) {
                    if path_starts_with_ci(&physical, &child_node.workspace_path) {
                        return Err(FsError::PermissionDenied(format!(
                            "vpath resolves into child territory (Rule 2): {vpath}"
                        )));
                    }
                }
            }
        }

        // Slice B Rule 6 — own .agent/ write blocked.
        // Walk the relative path components case-insensitively so a guest
        // typing `.AGENT/x.md` on a case-folding filesystem (HFS+/APFS) is
        // blocked the same as `.agent/x.md` — a literal `starts_with` is
        // case-sensitive at the byte level and would otherwise miss the
        // bypass.
        let relative = physical
            .strip_prefix(agent_workspace)
            .unwrap_or(Path::new(""));
        for comp in relative.components() {
            if let Component::Normal(name) = comp {
                if name.to_string_lossy().eq_ignore_ascii_case(".agent") {
                    return Err(FsError::PermissionDenied(format!(
                        ".agent/ system directory is read-only via host fn: {vpath}"
                    )));
                }
            }
        }

        Ok(physical)
    }

    fn resolve_child_read(
        &self,
        parent_id: &str,
        child_id: &str,
        vpath: &str,
    ) -> Result<PathBuf, FsError> {
        // Step 1: gate path components (same as resolve_read Step 1).
        gate_path_components(vpath)?;

        // Step 2: verify child_id is a direct child of parent_id.
        // NotFound (anti-fingerprinting) for any topology mismatch.
        let snapshot = self.agent_tree.snapshot();
        let _parent_idx = snapshot
            .nodes
            .iter()
            .position(|n| n.id.0 == parent_id)
            .ok_or_else(|| FsError::NotFound("path not found".to_string()))?;
        let children = snapshot.children_of.get(&AgentId(parent_id.to_string()));
        let is_child = children
            .map(|cs| cs.iter().any(|c| c.0 == child_id))
            .unwrap_or(false);
        if !is_child {
            return Err(FsError::NotFound("path not found".to_string()));
        }

        // Step 3: lookup child workspace_path.
        let child_ws = snapshot
            .nodes
            .iter()
            .find(|n| n.id.0 == child_id)
            .map(|n| n.workspace_path.clone())
            .ok_or_else(|| FsError::NotFound("path not found".to_string()))?;

        // Step 4-7: lexical join + containment + .advance + hidden-name + symlink walk.
        let physical = child_ws.join(vpath);
        if !physical.starts_with(&child_ws) {
            return Err(FsError::NotFound("path not found".to_string()));
        }
        if physical.starts_with(self.workspace_root.join(".advance")) {
            return Err(FsError::NotFound("path not found".to_string()));
        }
        apply_hidden_name_walk(&child_ws, &physical)?;
        symlink_walk(&child_ws, &physical)?;
        Ok(physical)
    }

    fn resolve_slug_read(
        &self,
        agent_id: &str,
        peer_id: &str,
        slug: &str,
        file: &str,
    ) -> Result<PathBuf, FsError> {
        // Step 1: gate path components on `file`.
        gate_path_components(file)?;
        if slug.is_empty() || !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(FsError::InvalidPath(format!("invalid slug {slug:?}")));
        }

        // Step 2: peer_slug_map lookup. NotFound for any mismatch.
        let snapshot = self.agent_tree.snapshot();
        let agent_key = AgentId(agent_id.to_string());
        let peer_map = match snapshot.peer_slug_map.get(&agent_key) {
            Some(m) => m,
            None => {
                return Err(FsError::NotFound("path not found".to_string()));
            }
        };
        let resolved_peer = match peer_map.get(slug) {
            Some(p) => p,
            None => {
                return Err(FsError::NotFound("path not found".to_string()));
            }
        };
        if resolved_peer.0 != peer_id {
            return Err(FsError::NotFound("path not found".to_string()));
        }

        // Step 3: lookup peer workspace_path.
        let peer_ws = snapshot
            .nodes
            .iter()
            .find(|n| n.id.0 == peer_id)
            .map(|n| n.workspace_path.clone())
            .ok_or_else(|| FsError::NotFound("path not found".to_string()))?;

        // Step 4-7.
        let physical = peer_ws.join(file);
        if !physical.starts_with(&peer_ws) {
            return Err(FsError::NotFound("path not found".to_string()));
        }
        if physical.starts_with(self.workspace_root.join(".advance")) {
            return Err(FsError::NotFound("path not found".to_string()));
        }
        apply_hidden_name_walk(&peer_ws, &physical)?;
        symlink_walk(&peer_ws, &physical)?;
        Ok(physical)
    }

    fn resolve_dir_write(&self, agent_id: &str, vpath: &str) -> Result<PathBuf, FsError> {
        // Reuse resolve_read for Steps 1-7. Then add Step 8 child-territory check
        // (case-insensitive — HFS+/APFS bypass defense, mirrors resolve_write).
        let physical = self.resolve_read(agent_id, vpath)?;
        let snapshot = self.agent_tree.snapshot();
        if let Some(children) = snapshot.children_of.get(&AgentId(agent_id.to_string())) {
            for child_id in children {
                if let Some(child_node) = snapshot.nodes.iter().find(|n| n.id == *child_id) {
                    if path_starts_with_ci(&physical, &child_node.workspace_path) {
                        return Err(FsError::PermissionDenied(format!(
                            "vpath resolves into child territory (Rule 2): {vpath}"
                        )));
                    }
                }
            }
        }
        // No territory-root rejection (allowed for update-scope on territory root).
        // No .agent/ rejection here — handler-level enforcement for update-scope/entry-meta.
        Ok(physical)
    }
}

/// Case-insensitive component-wise `starts_with`. Returns true iff every
/// component of `prefix` matches the corresponding component of `path`
/// using ASCII case-insensitive comparison. Used for child-territory
/// rejection on case-folding filesystems (HFS+/APFS) where a byte-level
/// `path.starts_with` would miss alternate-cased path components that
/// resolve to the same on-disk inode.
fn path_starts_with_ci(path: &Path, prefix: &Path) -> bool {
    let mut p_iter = path.components();
    let mut q_iter = prefix.components();
    loop {
        match (q_iter.next(), p_iter.next()) {
            (None, _) => return true,
            (Some(_), None) => return false,
            (Some(q), Some(p)) => {
                let q_str = q.as_os_str().to_string_lossy();
                let p_str = p.as_os_str().to_string_lossy();
                if !q_str.eq_ignore_ascii_case(&p_str) {
                    return false;
                }
            }
        }
    }
}

/// Helper: shared "Step 1" gate used by all resolve methods.
fn gate_path_components(vpath: &str) -> Result<(), FsError> {
    let p = Path::new(vpath);
    if p.is_absolute() {
        return Err(FsError::InvalidPath(vpath.to_string()));
    }
    let mut depth = 0usize;
    for comp in p.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FsError::InvalidPath(vpath.to_string()));
            }
            Component::Normal(name) => {
                depth += 1;
                if depth > MAX_PATH_DEPTH {
                    return Err(FsError::InvalidPath(format!(
                        "path depth {depth} exceeds MAX_PATH_DEPTH ({MAX_PATH_DEPTH}): {vpath}"
                    )));
                }
                let bytes = name.to_string_lossy();
                if !bytes.is_ascii() {
                    return Err(FsError::InvalidPath(format!(
                        "non-ASCII path component (slice A restriction): {vpath}"
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Helper: symlink walk shared between resolve_read / resolve_child_read /
/// resolve_slug_read. Walks the path's components and rejects if any existing
/// component is a symlink (rejecting at sandbox-escape vector).
fn symlink_walk(target_workspace: &Path, physical: &Path) -> Result<(), FsError> {
    let relative = physical
        .strip_prefix(target_workspace)
        .unwrap_or(Path::new(""));
    match std::fs::symlink_metadata(target_workspace) {
        Ok(m) if m.file_type().is_symlink() => {
            // Constant payload to match handler-level map_io_error.
            return Err(FsError::NotFound("path not found".to_string()));
        }
        Ok(_) => {}
        Err(_) => {
            // Workspace root doesn't exist on disk — caller's setup error;
            // defer to actual disk op for error reporting.
        }
    }
    let mut walk = target_workspace.to_path_buf();
    for comp in relative.components() {
        walk.push(comp);
        match std::fs::symlink_metadata(&walk) {
            Ok(m) if m.file_type().is_symlink() => {
                // Constant payload — must match the handler-level map_io_error
                // payload exactly so a guest cannot fingerprint hidden-class
                // rejection vs visible-ENOENT by inspecting the message.
                return Err(FsError::NotFound("path not found".to_string()));
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    Ok(())
}
