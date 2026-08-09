//! MODULE-005-AC-29 — the `knowledge.jsonl` producer-boundary guard (CONTRACT-214).
//!
//! [`WorkspaceFileResidentPolicy`] is the MODULE-005-owned concrete impl of the
//! shared-types [`RememberContentPolicy`] trait consumed dependency-inverted by
//! cap-memory (MODULE-011)'s `RememberHandler`. It rejects a guest `remember()`
//! whose `content` is a WHOLE-FILE EXACT COPY (byte-for-byte, tolerating one trailing
//! `\n`) of a workspace file above a size floor, so `knowledge.jsonl` stores only
//! non-file-owned insights (REQ-210 / REQ-211).
//!
//! ## Detection rule (pinned — MODULE-005 §3.8)
//! - **The floor gates the whole scan.** `content.len() < ScanLimits.floor` (512) →
//!   `Allow` before any filesystem I/O, so ordinary short insights do ZERO work; the
//!   scan cost is incurred only for suspicious large content (the file-dump case).
//! - **Deterministic bounded DFS.** Each directory's entries are counted against
//!   `max_entries` AS they are materialized (before the sort), then sorted by name, then
//!   recursed — so a single wide directory cannot force an unbounded `Vec`/sort ahead of
//!   the cap. Global budget caps `max_entries` / `max_files` / `max_dirs` /
//!   `max_total_read`: hitting any of these STOPS the whole scan and returns `Allow`
//!   (**fail OPEN under load**). See [`ScanLimits`].
//! - **Directory denylist** (case-normalized): well-known VCS / build / dependency /
//!   runtime-state directories are skipped (a scan-efficiency heuristic, NOT a security
//!   boundary; `.agent` at every depth avoids self-matching `knowledge.jsonl`). Ordinary
//!   dotFILES (`.env`, `.config`, …) ARE scanned.
//! - **Per-entry / per-branch skips (NOT a whole-scan stop).** An I/O error (unreadable
//!   dir/file, bad stat), a symlink (`symlink_metadata` — never followed), a denylisted
//!   directory, or a subtree beyond `max_depth` cause that entry/subtree to be SKIPPED
//!   while scanning continues elsewhere. None of these ever cause a `Reject`; a match at
//!   a readable, in-depth path can still reject.
//! - **Length pre-filter + hardened bounded read.** A file is read only if its stat size
//!   ∈ {n, n+1} (n = content bytes), and the read itself is capped at n+1 bytes (so a file
//!   that GREW after the stat cannot force an unbounded read). The open is hardened against
//!   the lstat→open TOCTOU (unix `O_NOFOLLOW | O_NONBLOCK` + handle-`fstat`): a leaf swapped
//!   to a symlink fails the open (`ELOOP`), a FIFO/device returns immediately and is fstat-
//!   rejected — never followed outside the root, never parks the blocking thread.
//! - **Match.** `bytes == content` OR (`len == n+1 && bytes[..n] == content && bytes[n]
//!   == b'\n'`). First match in sorted order → `Reject` with the workspace-relative path.
//!
//! ## Best-effort ceiling (honest)
//! Whole-file-exact-copy only (substring/chunk detection deliberately excluded to avoid
//! false-positives on insights quoting a line). Therefore evadable by chunking /
//! perturbation, and it fails OPEN under scan-budget exhaustion — matching the AC-29
//! "detected as raw file-resident bytes" heuristic wording. This is a best-effort
//! producer-boundary guard, not a cryptographic guarantee.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::agent_tree::AgentId;
use advance_shared_types::traits::{RememberContentPolicy, RememberDecision};

use crate::tree::AgentTreeStore;

/// Bounds on a single `check_content` scan. Two distinct fail-open behaviours:
/// - **Global budget cap** (`max_entries` / `max_files` / `max_dirs` / `max_total_read`)
///   → STOP the whole scan and return `Allow` (fail-open under load).
/// - **Per-entry / per-branch condition** (I/O error, symlink, denylisted dir, beyond
///   `max_depth`) → SKIP that entry/subtree and CONTINUE scanning; never a `Reject`.
///
/// Injectable so tests can exercise the exhaustion paths with tiny caps; production
/// always uses [`ScanLimits::PRODUCTION`].
#[derive(Clone, Copy)]
struct ScanLimits {
    /// Content shorter than this is never rejected (gates the whole scan before any I/O).
    floor: usize,
    /// Upper bound on TOTAL `read_dir` entries examined — counted as EACH directory is
    /// materialized (before sort/skip), so a single wide directory cannot force an
    /// unbounded `Vec`/sort ahead of the cap.
    max_entries: usize,
    /// Upper bound on regular files stat-inspected.
    max_files: usize,
    /// Upper bound on directories recursed into.
    max_dirs: usize,
    /// Maximum recursion depth (matches `workspace::MAX_PATH_DEPTH`).
    max_depth: usize,
    /// Upper bound on cumulative candidate bytes read.
    max_total_read: usize,
}

impl ScanLimits {
    const PRODUCTION: ScanLimits = ScanLimits {
        floor: 512,
        max_entries: 50_000,
        max_files: 20_000,
        max_dirs: 20_000,
        max_depth: 32,
        max_total_read: 64 * 1024 * 1024,
    };
}

/// Case-normalized (ASCII-lowercase) directory basenames skipped during the scan:
/// VCS / build / dependency / runtime-state dirs. A scan-efficiency heuristic, NOT a
/// security boundary. `.agent` is skipped at every depth to avoid self-matching the
/// agent's own `knowledge.jsonl` / `syntheses/`.
const DENYLIST_DIRS: &[&str] = &[
    ".git",
    ".agent",
    ".runtime",
    ".advance",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".cache",
    ".next",
    "vendor",
];

/// How a [`WorkspaceFileResidentPolicy`] resolves the workspace root to scan.
enum WorkspaceSource {
    /// A fixed root, scanned for every `remember()` regardless of `agent_id` (the
    /// PRODUCTION form — the cli composition root has a single workspace).
    Fixed(PathBuf),
    /// Per-agent: resolve the calling agent's `workspace_path` via the tree.
    Tree(Arc<AgentTreeStore>),
}

/// MODULE-005-owned concrete [`RememberContentPolicy`] (CONTRACT-214). See the module
/// docs for the pinned detection rule.
pub struct WorkspaceFileResidentPolicy {
    source: WorkspaceSource,
}

impl WorkspaceFileResidentPolicy {
    /// Scan a FIXED workspace root for every `remember()` (ignores `agent_id`). The
    /// production form — wired at the cli composition root over the CLI's workspace.
    pub fn rooted(root: PathBuf) -> Self {
        Self {
            source: WorkspaceSource::Fixed(root),
        }
    }

    /// Per-agent form: resolve the calling agent's `workspace_path` from the tree
    /// (`Allow` — fail-open — if the agent is unknown). Retained for future per-agent
    /// scoping; production uses [`WorkspaceFileResidentPolicy::rooted`].
    pub fn from_tree(tree: Arc<AgentTreeStore>) -> Self {
        Self {
            source: WorkspaceSource::Tree(tree),
        }
    }

    fn workspace_for(&self, agent_id: &str) -> Option<PathBuf> {
        match &self.source {
            WorkspaceSource::Fixed(root) => Some(root.clone()),
            WorkspaceSource::Tree(tree) => tree
                .get_node(&AgentId(agent_id.to_string()))
                .map(|n| n.workspace_path),
        }
    }
}

impl RememberContentPolicy for WorkspaceFileResidentPolicy {
    fn check_content(&self, agent_id: &str, content: &str) -> RememberDecision {
        let n = content.len();
        // The floor gates the entire scan — short insights never touch the filesystem.
        if n < ScanLimits::PRODUCTION.floor {
            return RememberDecision::Allow;
        }
        let Some(root) = self.workspace_for(agent_id) else {
            return RememberDecision::Allow; // unknown agent → fail-open
        };
        match scan_for_match(&root, content.as_bytes(), &ScanLimits::PRODUCTION) {
            Some(rel) => RememberDecision::Reject(format!(
                "producer-boundary: remember() content ({n} bytes) duplicates workspace file {rel}; \
                 knowledge.jsonl stores only non-file-owned insights (REQ-210/211)"
            )),
            None => RememberDecision::Allow,
        }
    }
}

/// Bounded-DFS budget counters. Every axis fails OPEN (returns `Scan::Stop`) on hit.
#[derive(Default)]
struct Budget {
    entries: usize,
    files: usize,
    dirs: usize,
    read_bytes: usize,
}

/// Recursion signal: `Found` short-circuits with the matched relative path; `Stop`
/// halts the whole scan on a budget hit (→ fail-open `Allow` at the top).
enum Scan {
    Found(String),
    Stop,
}

/// Returns `Some(workspace-relative path)` of the first whole-file-copy match in
/// deterministic (sorted) order, or `None` (not found OR fail-open on budget/IO error).
fn scan_for_match(root: &Path, needle: &[u8], limits: &ScanLimits) -> Option<String> {
    let mut budget = Budget::default();
    match scan_dir(root, root, needle, &mut budget, 0, limits) {
        Err(Scan::Found(rel)) => Some(rel),
        _ => None,
    }
}

/// Read at most `max` bytes of `path`, hardened against the `symlink_metadata`→open
/// TOCTOU (mirrors `cap_fs::meta_schema::read_schema_bounded`):
/// - **Unix:** open with `O_NOFOLLOW | O_NONBLOCK`, then re-verify on the HANDLE that it
///   is still a regular file. A leaf swapped to a symlink after the lstat fails the open
///   (`ELOOP`); a FIFO/device swapped in returns immediately from `open` (`O_NONBLOCK`,
///   so it never parks the blocking thread) and is then rejected by the handle-`fstat`.
/// - **Non-unix:** plain open (residual TOCTOU accepted — the documented Slice-A posture).
///
/// Also bounds the read at `max` bytes so a file that GREW after the stat cannot force an
/// unbounded read. Returns `None` (fail-open → caller skips this entry) on any error or a
/// non-regular handle.
fn read_bounded(path: &Path, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = std::fs::File::open(path);

    let f = opened.ok()?;
    // Re-verify on the actual handle: nothing non-regular (FIFO/socket/device or a
    // symlink target) was swapped in between the lstat and this open.
    if !f.metadata().ok()?.file_type().is_file() {
        return None;
    }
    let mut buf = Vec::with_capacity(max.min(64 * 1024));
    f.take(max as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn scan_dir(
    dir: &Path,
    root: &Path,
    needle: &[u8],
    budget: &mut Budget,
    depth: usize,
    limits: &ScanLimits,
) -> Result<(), Scan> {
    // Fail-open: an unreadable directory is skipped, not treated as a rejection.
    let read = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };
    // Materialize this directory's entries while COUNTING each against the global entry
    // budget — so a single wide directory cannot force an unbounded Vec/sort ahead of the
    // cap (the sort below is then bounded by the remaining budget, never the raw fanout).
    let mut entries: Vec<std::fs::DirEntry> = Vec::new();
    for e in read {
        let Ok(e) = e else { continue }; // fail-open on a bad dir entry
        budget.entries += 1;
        if budget.entries > limits.max_entries {
            return Err(Scan::Stop); // global budget → stop the whole scan (fail-open)
        }
        entries.push(e);
    }
    entries.sort_by_cached_key(|e| e.file_name()); // deterministic order, key computed once

    let n = needle.len();
    for entry in entries {
        let path = entry.path();
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue, // fail-open on stat error (skip this entry, keep scanning)
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            continue; // never follow symlinks (skip this entry)
        }

        if ft.is_dir() {
            let name_lc = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if DENYLIST_DIRS.contains(&name_lc.as_str()) {
                continue; // skip a denylisted subtree
            }
            budget.dirs += 1;
            if budget.dirs > limits.max_dirs {
                return Err(Scan::Stop);
            }
            if depth + 1 <= limits.max_depth {
                scan_dir(&path, root, needle, budget, depth + 1, limits)?;
            }
            // Beyond max_depth: skip the deeper subtree (per-branch skip), keep scanning.
        } else if ft.is_file() {
            budget.files += 1;
            if budget.files > limits.max_files {
                return Err(Scan::Stop);
            }
            let flen = meta.len() as usize;
            // Length pre-filter: only a whole-file copy (± one trailing '\n') qualifies.
            if flen == n || flen == n + 1 {
                if budget.read_bytes.saturating_add(n + 1) > limits.max_total_read {
                    return Err(Scan::Stop);
                }
                // Bounded, TOCTOU-hardened read of at most n+1 bytes (O_NOFOLLOW |
                // O_NONBLOCK + handle-fstat) — caps the read even if the file grew, and a
                // swapped-in symlink/FIFO is rejected rather than followed/blocked.
                if let Some(bytes) = read_bounded(&path, n + 1) {
                    budget.read_bytes += bytes.len();
                    let is_match = (bytes.len() == n && bytes == needle)
                        || (bytes.len() == n + 1 && &bytes[..n] == needle && bytes[n] == b'\n');
                    if is_match {
                        let rel = path
                            .strip_prefix(root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .into_owned();
                        return Err(Scan::Found(rel));
                    }
                }
            }
        }
        // Non-regular entries (fifo/socket/…) are already counted at collection; skipped.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, bytes).unwrap();
    }

    fn policy(root: &Path) -> WorkspaceFileResidentPolicy {
        WorkspaceFileResidentPolicy::rooted(root.to_path_buf())
    }

    fn big(seed: &str, len: usize) -> String {
        seed.chars().cycle().take(len).collect()
    }

    // U3 — below-floor content is never rejected, even if it equals a file.
    #[test]
    fn u3_below_floor_allow() {
        let td = TempDir::new().unwrap();
        let content = "short insight under the floor";
        write(td.path(), "notes.txt", content.as_bytes());
        assert_eq!(
            policy(td.path()).check_content("agent:a", content),
            RememberDecision::Allow
        );
    }

    // U4 — a whole-file exact copy (≥ floor) is rejected; reason names the rel path.
    #[test]
    fn u4_exact_whole_file_reject() {
        let td = TempDir::new().unwrap();
        let content = big("data-", 800);
        write(td.path(), "report.txt", content.as_bytes());
        match policy(td.path()).check_content("agent:a", &content) {
            RememberDecision::Reject(reason) => {
                assert!(reason.contains("report.txt"), "reason: {reason}");
                assert!(reason.contains("800 bytes"), "reason: {reason}");
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // U5 — file == content + one trailing newline is still a match.
    #[test]
    fn u5_trailing_newline_reject() {
        let td = TempDir::new().unwrap();
        let content = big("line-", 600);
        let mut on_disk = content.clone().into_bytes();
        on_disk.push(b'\n');
        write(td.path(), "doc.md", &on_disk);
        assert!(matches!(
            policy(td.path()).check_content("agent:a", &content),
            RememberDecision::Reject(_)
        ));
    }

    // U6 — same length but one byte different → allow (exact match, NOT substring).
    #[test]
    fn u6_same_length_one_byte_diff_allow() {
        let td = TempDir::new().unwrap();
        let file_content = big("x", 700);
        write(td.path(), "a.txt", file_content.as_bytes());
        let mut remembered = file_content.into_bytes();
        remembered[0] = b'Y'; // differ by one byte
        let remembered = String::from_utf8(remembered).unwrap();
        assert_eq!(
            policy(td.path()).check_content("agent:a", &remembered),
            RememberDecision::Allow
        );
    }

    // U7 — identical bytes living only under `.agent/` are skipped (self-match avoided).
    #[test]
    fn u7_dot_agent_skipped() {
        let td = TempDir::new().unwrap();
        let content = big("mem-", 900);
        write(
            td.path(),
            ".agent/memory/knowledge.jsonl",
            content.as_bytes(),
        );
        assert_eq!(
            policy(td.path()).check_content("agent:a", &content),
            RememberDecision::Allow
        );
    }

    // U7b — a `.env` dotFILE with file-resident bytes IS scanned → reject (bypass closed).
    #[test]
    fn u7b_dotfile_env_reject() {
        let td = TempDir::new().unwrap();
        let content = big("SECRET=", 640);
        write(td.path(), ".env", content.as_bytes());
        assert!(matches!(
            policy(td.path()).check_content("agent:a", &content),
            RememberDecision::Reject(_)
        ));
    }

    // U7c — denylisted dirs are skipped, but a match OUTSIDE the denylist still rejects
    // even with denylist noise present.
    #[test]
    fn u7c_denylist_dir_skipped_but_outside_match_rejects() {
        let td = TempDir::new().unwrap();
        let content = big("payload-", 1024);
        // Same bytes inside a denylisted dir (skipped) AND at a real working path (caught).
        write(td.path(), "target/debug/artifact.bin", content.as_bytes());
        write(td.path(), ".runtime/events/log.jsonl", content.as_bytes());
        // A copy in a denylisted dir only → allow.
        let td2 = TempDir::new().unwrap();
        write(td2.path(), "node_modules/pkg/index.js", content.as_bytes());
        assert_eq!(
            policy(td2.path()).check_content("agent:a", &content),
            RememberDecision::Allow,
            "denylisted-only copy must be allowed"
        );
        // The same content also present at a working path → reject.
        write(td.path(), "src/data.txt", content.as_bytes());
        assert!(
            matches!(
                policy(td.path()).check_content("agent:a", &content),
                RememberDecision::Reject(_)
            ),
            "a match outside the denylist must still reject"
        );
    }

    // U7d — the dir denylist is case-insensitive (`.GIT` / `.Agent` on a
    // case-insensitive FS must still be skipped).
    #[test]
    fn u7d_denylist_case_insensitive() {
        let td = TempDir::new().unwrap();
        let content = big("cfg-", 700);
        write(td.path(), ".GIT/config", content.as_bytes());
        write(td.path(), ".Agent/state/x", content.as_bytes());
        assert_eq!(
            policy(td.path()).check_content("agent:a", &content),
            RememberDecision::Allow
        );
    }

    // U8 — a symlink whose target has identical bytes is never followed → allow.
    #[cfg(unix)]
    #[test]
    fn u8_symlink_skipped() {
        use std::os::unix::fs::symlink;
        let td = TempDir::new().unwrap();
        let content = big("linked-", 800);
        // Real file lives OUTSIDE the scanned root; only a symlink is inside.
        let external = TempDir::new().unwrap();
        let real = external.path().join("real.txt");
        fs::write(&real, content.as_bytes()).unwrap();
        symlink(&real, td.path().join("link.txt")).unwrap();
        assert_eq!(
            policy(td.path()).check_content("agent:a", &content),
            RememberDecision::Allow
        );
    }

    // U9 — an unreadable directory mid-scan is skipped (fail-open), no reject/panic.
    #[cfg(unix)]
    #[test]
    fn u9_io_error_fail_open() {
        use std::os::unix::fs::PermissionsExt;
        let td = TempDir::new().unwrap();
        let content = big("z", 700);
        let locked = td.path().join("locked");
        fs::create_dir_all(&locked).unwrap();
        write(&locked, "hidden.txt", content.as_bytes());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let decision = policy(td.path()).check_content("agent:a", &content);
        // restore perms so TempDir cleanup succeeds
        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));
        assert_eq!(decision, RememberDecision::Allow);
    }

    // U10 — correctness under a large (WITHIN-budget) file count: 2000 noise files plus
    // the real match, all under the production budget → the match IS found (Reject). No
    // panic, no hang; exercises the entry counter + sorted traversal at scale.
    #[test]
    fn u10_large_within_budget_finds_match() {
        let td = TempDir::new().unwrap();
        let content = big("q", 700);
        for i in 0..2000 {
            write(td.path(), &format!("noise/f{i:05}.txt"), b"x"); // below floor, never read
        }
        write(td.path(), "zzz_last/match.txt", content.as_bytes());
        assert!(matches!(
            policy(td.path()).check_content("agent:a", &content),
            RememberDecision::Reject(_)
        ));
    }

    // U10c — the global entry budget STOPS the whole scan and fails OPEN. Noise lives in
    // `aaa/` (sorted first) and exceeds a tiny max_entries, so the scan Stops DURING aaa's
    // collection (proving collection is bounded, not just the per-entry loop) and never
    // reaches the real match in `zzz/` → Allow. Deterministic regardless of read_dir order
    // because `aaa/` alone exhausts the budget before `zzz/` is ever visited.
    #[test]
    fn u10c_entry_budget_exhaustion_fails_open() {
        let td = TempDir::new().unwrap();
        let content = big("q", 700);
        for i in 0..10 {
            write(td.path(), &format!("aaa/f{i:02}.txt"), b"x");
        }
        write(td.path(), "zzz/match.txt", content.as_bytes());
        let tiny = ScanLimits {
            max_entries: 5,
            ..ScanLimits::PRODUCTION
        };
        assert!(
            scan_for_match(td.path(), content.as_bytes(), &tiny).is_none(),
            "entry-budget exhaustion in aaa/ must stop the scan and fail open (Allow)"
        );
        // Sanity: under the production budget the same match IS found (deterministic).
        assert!(
            scan_for_match(td.path(), content.as_bytes(), &ScanLimits::PRODUCTION).is_some(),
            "the match is found when the budget is not exhausted"
        );
    }

    // U10b — deterministic reason: two identical-byte files → the sorted-first is named.
    #[test]
    fn u10b_deterministic_reason() {
        let td = TempDir::new().unwrap();
        let content = big("dup-", 900);
        write(td.path(), "a_first.txt", content.as_bytes());
        write(td.path(), "b_second.txt", content.as_bytes());
        // Run twice; the named file must be stable (sorted order → a_first.txt).
        let r1 = policy(td.path()).check_content("agent:a", &content);
        let r2 = policy(td.path()).check_content("agent:a", &content);
        assert_eq!(r1, r2);
        match r1 {
            RememberDecision::Reject(reason) => {
                assert!(reason.contains("a_first.txt"), "reason: {reason}")
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // U11 — from_tree resolves the calling agent's workspace (reject a match under it);
    // an unknown agent → fail-open Allow.
    #[test]
    fn u11_from_tree_scoping_and_unknown_allow() {
        use advance_shared_types::agent_tree::{AgentKind, AgentNode, AgentStatus};
        let td = TempDir::new().unwrap();
        let store = AgentTreeStore::new(td.path().to_path_buf()).unwrap();
        let rws = store.workspace_root().join("root");
        fs::create_dir_all(&rws).unwrap();
        let content = big("tree-", 800);
        fs::write(rws.join("report.txt"), content.as_bytes()).unwrap();
        store
            .insert_root(AgentNode {
                id: AgentId("root".into()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: rws,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            })
            .unwrap();
        let pol = WorkspaceFileResidentPolicy::from_tree(Arc::new(store));
        // Resolves agent "root"'s workspace → report.txt is a whole-file copy → reject.
        assert!(matches!(
            pol.check_content("root", &content),
            RememberDecision::Reject(_)
        ));
        // Unknown agent → fail-open Allow.
        assert_eq!(
            pol.check_content("agent:does-not-exist", &content),
            RememberDecision::Allow
        );
    }

    // U12 — read_bounded returns Some for a regular file, capped at `max` bytes;
    // None for a missing path (fail-open).
    #[test]
    fn u12_read_bounded_regular_capped() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("f.txt");
        fs::write(&p, vec![b'a'; 1000]).unwrap();
        let got = read_bounded(&p, 10).expect("regular file reads");
        assert_eq!(got.len(), 10, "read is capped at max bytes");
        assert!(read_bounded(&td.path().join("missing"), 10).is_none());
    }

    // U13 — read_bounded rejects a FIFO (O_NONBLOCK open + handle-fstat) without
    // blocking a thread or panicking.
    #[cfg(unix)]
    #[test]
    fn u13_read_bounded_fifo_rejected() {
        let td = TempDir::new().unwrap();
        let fifo = td.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !made {
            return; // mkfifo unavailable — skip
        }
        assert!(
            read_bounded(&fifo, 16).is_none(),
            "a FIFO must be rejected (O_NONBLOCK + fstat), never read/blocked"
        );
    }

    // U14 — read_bounded rejects a symlink leaf (O_NOFOLLOW → ELOOP), never following it.
    #[cfg(unix)]
    #[test]
    fn u14_read_bounded_symlink_leaf_rejected() {
        use std::os::unix::fs::symlink;
        let td = TempDir::new().unwrap();
        let target = td.path().join("real.txt");
        fs::write(&target, vec![b'x'; 600]).unwrap();
        let link = td.path().join("link.txt");
        symlink(&target, &link).unwrap();
        assert!(
            read_bounded(&link, 601).is_none(),
            "O_NOFOLLOW must reject a symlink leaf rather than follow it"
        );
    }
}
