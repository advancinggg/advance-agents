//! User commit lane (ADR 2026-10-15, CONTRACT-247) — MODULE-003 §3.3 T27..T82 integration
//! tests for `prepare` and `commit_user` on `DefaultGitCommitQueue` (the same worker, FIFO and
//! coord mutex as CONTRACT-020), plus `files.changed`, the auto-ignore registry, history
//! labels and the one tracked-size threshold (OSS-2c).

mod common;

use advance_git::label::{parse_provenance, parse_trailers, version_label};
use advance_git::{
    bootstrap_repo_at, AdoptBudget, AdoptPolicy, BlobSource, ChangeRole, CheckpointError,
    CommitFilter, CommitRequest, CommitType, DefaultGitCommitQueue, DefaultNamedCheckpoint,
    DefaultWorkspaceRollback, EntryKind, GitCommitQueue, GitError, GitHistoryReader, GitLog,
    GitLogLevel, IndexStat, ItemChange, ItemKind, LaneTestHooks, NamedCheckpoint, NotVersioned,
    PathChange, PrepareOutcome, PrepareRequest, PrepareTarget, Provenance, RepoPath, RestoreScope,
    RestoreSource, RestoreTreeRequest, RollbackError, RollbackMode, RollbackTarget,
    SaveVersionRequest, StaticGitConfigProvider, UserActor, UserCommitLane, UserCommitOutcome,
    UserCommitRequest, UserCommitStatus, UserOpKind, UserOpRefusal, WorkspaceRollback,
    FILES_CHANGED_EVENT, MAX_EVENT_ROWS,
};
use advance_shared_types::event::Event;
use common::CollectingEventBus;
use git2::{IndexEntry, IndexTime, ObjectType, Oid, Repository, Signature, Status};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

// ── fixture ───────────────────────────────────────────────────────────────────────────

struct Vault {
    _td: TempDir,
    root: PathBuf,
    queue: DefaultGitCommitQueue,
    bus: Arc<CollectingEventBus>,
}

impl Vault {
    /// A bootstrapped vault whose `main` holds `files` (one legacy commit, `.gitignore`
    /// included), with no events left on the bus.
    async fn with(files: &[(&str, &[u8])]) -> Self {
        Self::configured(files, |_| {}).await
    }

    /// As [`Vault::with`], with `setup` run on the repository before the queue spawns.
    async fn configured(files: &[(&str, &[u8])], setup: impl FnOnce(&Repository)) -> Self {
        let td = TempDir::new().unwrap();
        let root = std::fs::canonicalize(td.path()).unwrap();
        bootstrap_repo_at(&root).unwrap();
        setup(&Repository::open(&root).unwrap());
        let bus = Arc::new(CollectingEventBus::new());
        let queue = DefaultGitCommitQueue::spawn_with_event_bus(root.clone(), bus.clone()).unwrap();
        let vault = Self {
            _td: td,
            root,
            queue,
            bus,
        };
        for (path, bytes) in files {
            vault.write(path, bytes);
        }
        if !files.is_empty() {
            let paths: Vec<&str> = files.iter().map(|(p, _)| *p).collect();
            vault.legacy(&paths).await.unwrap();
        }
        vault.bus.drain();
        vault
    }

    fn repo(&self) -> Repository {
        Repository::open(&self.root).unwrap()
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let full = self.root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, bytes).unwrap();
    }

    fn read(&self, path: &str) -> Vec<u8> {
        std::fs::read(self.root.join(path)).unwrap()
    }

    /// A legacy agent commit of `paths` (hashed from disk at commit time).
    async fn legacy(&self, paths: &[&str]) -> Result<Oid, GitError> {
        let req = CommitRequest::new(
            "writer",
            "write",
            paths.iter().map(PathBuf::from).collect(),
            CommitType::Turn,
            "agent:writer",
        );
        self.queue.submit(req).await.unwrap()
    }

    async fn commit(
        &self,
        op: UserOpKind,
        changes: Vec<PathChange>,
    ) -> Result<UserCommitOutcome, GitError> {
        self.queue.commit_user(request(op, changes)).await.unwrap()
    }

    async fn prepare(&self, targets: Vec<PrepareTarget>) -> Result<PrepareOutcome, GitError> {
        self.queue
            .prepare(PrepareRequest {
                targets,
                correlation_id: None,
            })
            .await
            .unwrap()
    }

    async fn save(
        &self,
        title: &str,
        paths: Option<&[&str]>,
        adopt: bool,
    ) -> Result<advance_git::SaveVersionOutcome, GitError> {
        self.save_at(title, paths, adopt, None).await
    }

    async fn save_at(
        &self,
        title: &str,
        paths: Option<&[&str]>,
        adopt: bool,
        at: Option<SystemTime>,
    ) -> Result<advance_git::SaveVersionOutcome, GitError> {
        self.queue
            .save_version(SaveVersionRequest {
                actor: UserActor::from_principal_id("advance"),
                title: title.to_string(),
                paths: paths.map(|ps| ps.iter().map(|p| path(p)).collect()),
                adopt,
                at,
                correlation_id: Some("op-1".to_string()),
                provenance: Some(provenance()),
            })
            .await
            .unwrap()
    }

    async fn restore(
        &self,
        source: RestoreSource,
        scope: RestoreScope,
    ) -> Result<advance_git::RestoreOutcome, GitError> {
        self.queue
            .restore_tree(RestoreTreeRequest {
                actor: UserActor::from_principal_id("advance"),
                source,
                scope,
                correlation_id: Some("op-1".to_string()),
                provenance: Some(provenance()),
            })
            .await
            .unwrap()
    }

    fn head(&self) -> Option<Oid> {
        let repo = self.repo();
        let head = repo.head().ok()?;
        head.target()
    }

    /// The object (blob or tree) at `path` in HEAD.
    fn head_entry(&self, path: &str) -> Option<Oid> {
        let repo = self.repo();
        let tree = repo.head().ok()?.peel_to_tree().ok()?;
        tree.get_path(Path::new(path)).ok().map(|e| e.id())
    }

    fn entry_in(&self, sha: &str, path: &str) -> Option<Oid> {
        let repo = self.repo();
        let commit = repo.find_commit(Oid::from_str(sha).unwrap()).unwrap();
        let tree = commit.tree().unwrap();
        tree.get_path(Path::new(path)).ok().map(|e| e.id())
    }

    fn index_entry(&self, path: &str) -> Option<IndexEntry> {
        let repo = self.repo();
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        index.get_path(Path::new(path), 0)
    }

    fn index_blob(&self, path: &str) -> Option<Oid> {
        self.index_entry(path).map(|e| e.id)
    }

    fn message(&self, sha: &str) -> String {
        let repo = self.repo();
        let commit = repo.find_commit(Oid::from_str(sha).unwrap()).unwrap();
        commit.message().unwrap().to_string()
    }

    fn parent_of(&self, sha: &str) -> Option<String> {
        let repo = self.repo();
        let commit = repo.find_commit(Oid::from_str(sha).unwrap()).unwrap();
        commit.parent_id(0).ok().map(|o| o.to_string())
    }

    /// The paths commit `sha` changed against its first parent, sorted.
    fn changed(&self, sha: &str) -> Vec<String> {
        let repo = self.repo();
        let commit = repo.find_commit(Oid::from_str(sha).unwrap()).unwrap();
        let tree = commit.tree().unwrap();
        let parent = commit.parent(0).ok().map(|p| p.tree().unwrap());
        let diff = repo
            .diff_tree_to_tree(parent.as_ref(), Some(&tree), None)
            .unwrap();
        let mut paths: Vec<String> = diff
            .deltas()
            .map(|d| {
                d.new_file()
                    .path()
                    .or_else(|| d.old_file().path())
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    fn journal_exists(&self) -> bool {
        self.root.join(".git/advance/user-lane.journal").exists()
    }

    /// Stage `bytes` at `path` in `.git/index` with zero stat (a leftover of another writer).
    fn stage_leftover(&self, path: &str, bytes: &[u8]) -> Oid {
        let repo = self.repo();
        let id = repo.blob(bytes).unwrap();
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        index.add(&smudged(path, id)).unwrap();
        index.write().unwrap();
        id
    }

    fn gitignore(&self) -> String {
        std::fs::read_to_string(self.root.join(".gitignore")).unwrap()
    }

    fn autoignore(&self) -> String {
        std::fs::read_to_string(self.root.join(".git/advance/autoignore")).unwrap_or_default()
    }
}

async fn vault_with_mb(files: &[(&str, &[u8])], mb: u64) -> Vault {
    let td = TempDir::new().unwrap();
    let root = std::fs::canonicalize(td.path()).unwrap();
    bootstrap_repo_at(&root).unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    let config = Arc::new(StaticGitConfigProvider::new(24, mb).unwrap());
    let queue =
        DefaultGitCommitQueue::spawn_with_config_and_event_bus(root.clone(), config, bus.clone())
            .unwrap();
    let vault = Vault {
        _td: td,
        root,
        queue,
        bus,
    };
    for (path, bytes) in files {
        vault.write(path, bytes);
    }
    if !files.is_empty() {
        let paths: Vec<&str> = files.iter().map(|(p, _)| *p).collect();
        vault.legacy(&paths).await.unwrap();
    }
    vault.bus.drain();
    vault
}

struct LogTap {
    records: Mutex<Vec<(GitLogLevel, &'static str, Vec<(String, String)>)>>,
}

impl GitLog for LogTap {
    fn log(&self, level: GitLogLevel, key: &'static str, fields: &[(&str, &str)]) {
        self.records.lock().unwrap().push((
            level,
            key,
            fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        ));
    }
}

fn file_stamp(root: &Path, path: &str) -> (Vec<u8>, i64, i64, u64) {
    let full = root.join(path);
    let bytes = std::fs::read(&full).unwrap();
    let meta = std::fs::metadata(&full).unwrap();
    (bytes, meta.mtime(), meta.ctime(), meta.len())
}

fn git_commits(events: &[Event]) -> Vec<&Event> {
    events
        .iter()
        .filter(|e| e.event_type == "git.commit")
        .collect()
}

fn files_changed(events: &[Event]) -> Vec<&Event> {
    events
        .iter()
        .filter(|e| e.event_type == FILES_CHANGED_EVENT)
        .collect()
}

fn smudged(path: &str, id: Oid) -> IndexEntry {
    IndexEntry {
        ctime: IndexTime::new(0, 0),
        mtime: IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode: 0o100_644,
        uid: 0,
        gid: 0,
        file_size: 0,
        id,
        flags: 0,
        flags_extended: 0,
        path: path.as_bytes().to_vec(),
    }
}

fn blob(bytes: &[u8]) -> Oid {
    Oid::hash_object(ObjectType::Blob, bytes).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    blob(bytes).to_string()
}

fn path(p: &str) -> RepoPath {
    RepoPath::parse(p).unwrap()
}

fn provenance() -> Provenance {
    Provenance {
        client: "macos".to_string(),
        session: "0123456789abcdef".to_string(),
    }
}

fn request(op: UserOpKind, changes: Vec<PathChange>) -> UserCommitRequest {
    UserCommitRequest {
        actor: UserActor::from_principal_id("advance"),
        op,
        changes,
        correlation_id: Some("op-1".to_string()),
        provenance: Some(provenance()),
    }
}

fn put(p: &str, bytes: &[u8]) -> PathChange {
    PathChange::Put {
        path: path(p),
        content: BlobSource::Bytes(bytes.to_vec()),
        role: ChangeRole::Primary,
        executable: None,
        stat: None,
    }
}

fn put_disk(p: &str, bytes: &[u8]) -> PathChange {
    PathChange::Put {
        path: path(p),
        content: BlobSource::Disk { oid: hex(bytes) },
        role: ChangeRole::Primary,
        executable: None,
        stat: None,
    }
}

fn put_sidecar(p: &str, bytes: &[u8]) -> PathChange {
    PathChange::Put {
        path: RepoPath::parse_sidecar(p).unwrap(),
        content: BlobSource::Bytes(bytes.to_vec()),
        role: ChangeRole::Sidecar,
        executable: None,
        stat: None,
    }
}

fn marker(p: &str, bytes: &[u8]) -> PathChange {
    PathChange::Put {
        path: RepoPath::parse_sidecar(p).unwrap(),
        content: BlobSource::Bytes(bytes.to_vec()),
        role: ChangeRole::Primary,
        executable: None,
        stat: None,
    }
}

fn remove(p: &str) -> PathChange {
    PathChange::Remove {
        path: path(p),
        role: ChangeRole::Primary,
    }
}

fn moved(from: &str, to: &str, oid: Option<Oid>) -> PathChange {
    PathChange::Move {
        from: path(from),
        to: path(to),
        oid: oid.map(|o| o.to_string()),
    }
}

fn file(p: &str, adopt: AdoptPolicy) -> PrepareTarget {
    PrepareTarget::File {
        path: path(p),
        adopt,
    }
}

fn tree(dir: &str) -> PrepareTarget {
    PrepareTarget::Tree {
        dir: if dir.is_empty() {
            RepoPath::root()
        } else {
            path(dir)
        },
    }
}

fn refusal<T: std::fmt::Debug>(result: Result<T, GitError>) -> UserOpRefusal {
    match result {
        Err(GitError::InvalidUserOp { reason, .. }) => reason,
        other => panic!("expected a user-lane refusal, got {other:?}"),
    }
}

fn first_line(message: &str) -> &str {
    message.split('\n').next().unwrap()
}

fn mkfifo(path: &Path) {
    // Test-only: neither std nor the pinned rustix creates a FIFO on every Unix.
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo {}", path.display());
}

/// Run `fut`, failing the test (not hanging it) after 5 s.
async fn within_5s<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("finished within 5 s")
}

// ── T27–T35: exact-content commits ──────────────────────────────────────────────────────

// MODULE-003-T27 (AC-26, AC-29): signatures, prefix, subject, trailers and provenance.
#[tokio::test]
async fn user_commit_signatures_prefix_and_trailers() {
    let v = Vault::with(&[("notes/plan.md", b"one\ntwo\nthree\n")]).await;
    let new = b"one\nTWO\nthree\nfour\n";
    v.write("notes/plan.md", new);
    let out = v
        .commit(UserOpKind::Edit, vec![put("notes/plan.md", new)])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Edit notes/plan.md (+2 −1)");
    assert_eq!(out.label.op, "edit");
    assert_eq!(out.items.len(), 1);
    assert_eq!(out.items[0].path, "notes/plan.md");
    assert_eq!(out.items[0].kind, ItemKind::File);
    assert_eq!(out.items[0].change, ItemChange::Modified);
    assert_eq!(out.items[0].oid, Some(hex(new)));
    assert_eq!(out.items[0].parent_oid, Some(hex(b"one\ntwo\nthree\n")));
    assert!(out.items[0].versioned);
    let sha = out.sha.clone().unwrap();
    assert_eq!(out.head_sha.as_deref(), Some(sha.as_str()));
    assert_eq!(v.head().unwrap().to_string(), sha);

    let repo = v.repo();
    let commit = repo.find_commit(Oid::from_str(&sha).unwrap()).unwrap();
    assert_eq!(commit.author().name(), Some("user:advance"));
    assert_eq!(commit.author().email(), Some("user@advance-agents"));
    assert_eq!(commit.committer().name(), Some("runtime"));
    assert_eq!(commit.committer().email(), Some("runtime@advance-agents"));
    let message = commit.message().unwrap();
    assert_eq!(
        first_line(message),
        "[user] [user:advance] Edit notes/plan.md (+2 −1)"
    );
    let label = parse_trailers(message).unwrap();
    assert_eq!(label, out.label);
    assert_eq!(label.paths, vec!["notes/plan.md".to_string()]);
    assert_eq!((label.lines_added, label.lines_removed), (Some(2), Some(1)));
    assert_eq!(parse_provenance(message), Some(provenance()));
    assert!(!first_line(message).contains("macos"));
    assert!(!first_line(message).contains("0123456789abcdef"));

    let page = GitHistoryReader::new(v.root.clone())
        .commits(None, 1, &CommitFilter::default())
        .unwrap();
    let entry = &page.items[0];
    assert_eq!(entry.sha, sha);
    assert_eq!(entry.commit_type, Some(CommitType::User));
    assert_eq!(entry.agent_id, None);
    assert_eq!(entry.initiator.as_deref(), Some("user:advance"));
    assert_eq!(entry.subject, "Edit notes/plan.md (+2 −1)");
    assert_eq!(entry.label.as_ref().map(|l| l.op.as_str()), Some("edit"));

    let events = v.bus.drain();
    let commits = git_commits(&events);
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].agent_id, "user:advance");
    assert_eq!(commits[0].payload["commit_type"], "user");
    assert_eq!(commits[0].payload["op"], "edit");
    assert_eq!(commits[0].payload["initiator"], "user:advance");
    let rows = files_changed(&events);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].payload["path"], "notes/plan.md");
    assert_eq!(rows[0].payload["change"], "modified");
    assert_eq!(rows[0].payload["versioned"], "yes");
    assert_eq!(rows[0].payload["seq"], 0);
    assert_eq!(rows[0].payload["total"], 1);
    let hist = GitHistoryReader::new(v.root.clone())
        .file_history("notes/plan.md")
        .unwrap();
    assert_eq!(
        hist.items[0].label.as_ref().map(|l| l.op.as_str()),
        Some("edit")
    );
}

// MODULE-003-T28 (AC-27): the commit holds the request's bytes, not the disk's.
#[tokio::test]
async fn user_commit_is_exact_content_not_disk() {
    let v = Vault::with(&[("notes/a.md", b"base\n")]).await;
    v.write("notes/a.md", b"disk changed by someone else\n");
    let out = v
        .commit(UserOpKind::Edit, vec![put("notes/a.md", b"user bytes\n")])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(v.head_entry("notes/a.md"), Some(blob(b"user bytes\n")));
    assert_eq!(v.index_blob("notes/a.md"), Some(blob(b"user bytes\n")));
    assert_eq!(v.read("notes/a.md"), b"disk changed by someone else\n");
}

// MODULE-003-T29 (AC-27): a foreign staged entry stays staged and out of the user commit.
#[tokio::test]
async fn staged_leftovers_never_enter_user_commit() {
    let v = Vault::with(&[("notes/p.md", b"p0\n"), ("notes/f.md", b"f0\n")]).await;
    v.write("notes/f.md", b"foreign\n");
    {
        let repo = v.repo();
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        index.add_path(Path::new("notes/f.md")).unwrap();
        index.write().unwrap();
    }
    let out = v
        .commit(UserOpKind::Edit, vec![put("notes/p.md", b"p1\n")])
        .await
        .unwrap();
    let sha = out.sha.unwrap();
    assert_eq!(v.changed(&sha), vec!["notes/p.md".to_string()]);
    assert_eq!(v.head_entry("notes/f.md"), Some(blob(b"f0\n")));
    assert_eq!(v.index_blob("notes/f.md"), Some(blob(b"foreign\n")));
}

// MODULE-003-T30 (AC-27): a non-committing agent rollback's staged restore stays out.
#[tokio::test]
async fn rollback_leftovers_never_enter_user_commit() {
    let v = Vault::with(&[("r.md", b"r0\n"), ("p.md", b"p0\n")]).await;
    let first = v.head().unwrap().to_string();
    v.write("r.md", b"r1\n");
    v.legacy(&["r.md"]).await.unwrap();
    DefaultWorkspaceRollback::new(v.root.clone())
        .unwrap()
        .rollback(
            "root",
            RollbackTarget::Commit(first),
            RollbackMode::PathScoped(vec![PathBuf::from("r.md")]),
        )
        .await
        .unwrap();
    assert_eq!(v.index_blob("r.md"), Some(blob(b"r0\n")), "restore staged");
    assert_eq!(v.head_entry("r.md"), Some(blob(b"r1\n")));

    let out = v
        .commit(UserOpKind::Edit, vec![put("p.md", b"p1\n")])
        .await
        .unwrap();
    assert_eq!(v.changed(&out.sha.unwrap()), vec!["p.md".to_string()]);
    assert_eq!(v.head_entry("r.md"), Some(blob(b"r1\n")));
    assert_eq!(v.index_blob("r.md"), Some(blob(b"r0\n")));
}

// MODULE-003-T31 (AC-27, AC-28): identical bytes make no commit and no event.
#[tokio::test]
async fn unchanged_edit_creates_no_commit_no_event() {
    let v = Vault::with(&[("notes/a.md", b"same\n")]).await;
    let tip = v.head().unwrap();
    let out = v
        .commit(UserOpKind::Edit, vec![put("notes/a.md", b"same\n")])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Unchanged);
    assert_eq!(out.sha, None);
    assert_eq!(out.head_sha, Some(tip.to_string()));
    assert_eq!(out.subject, "Edit notes/a.md");
    assert_eq!(out.items[0].change, ItemChange::Unchanged);
    assert_eq!(v.head(), Some(tip));
    assert!(v.bus.drain().is_empty(), "no events");
}

// MODULE-003-T32 (AC-28): a sidecar difference alone is not a change.
#[tokio::test]
async fn sidecar_only_change_is_unchanged() {
    let v = Vault::with(&[("notes/a.md", b"a\n"), ("notes/.meta.yaml", b"m0\n")]).await;
    let tip = v.head().unwrap();
    v.write("notes/.meta.yaml", b"m1\n");
    let out = v
        .commit(
            UserOpKind::Edit,
            vec![
                put("notes/a.md", b"a\n"),
                put_sidecar("notes/.meta.yaml", b"m1\n"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Unchanged);
    assert_eq!(v.head(), Some(tip));
    assert_eq!(v.head_entry("notes/.meta.yaml"), Some(blob(b"m0\n")));
    assert_eq!(
        v.read("notes/.meta.yaml"),
        b"m1\n",
        "the sidecar stays dirty"
    );
    assert_eq!(v.index_blob("notes/.meta.yaml"), Some(blob(b"m0\n")));
}

// MODULE-003-T33 (AC-28): markers make the folder; `mkdir -p` names the deepest level.
#[tokio::test]
async fn create_folder_commits_marker() {
    let v = Vault::with(&[("research/.meta.yaml", b"r\n")]).await;
    v.write("research/q4/.meta.yaml", b"q4\n");
    v.write("research/.meta.yaml", b"r q4\n");
    let out = v
        .commit(
            UserOpKind::CreateFolder,
            vec![
                marker("research/q4/.meta.yaml", b"q4\n"),
                put_sidecar("research/.meta.yaml", b"r q4\n"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Create folder research/q4/");
    assert_eq!(v.head_entry("research/q4/.meta.yaml"), Some(blob(b"q4\n")));
    assert_eq!(v.head_entry("research/.meta.yaml"), Some(blob(b"r q4\n")));
    assert_eq!(out.items.len(), 1);
    assert_eq!(out.items[0].kind, ItemKind::Dir);
    assert_eq!(out.items[0].path, "research/q4");
    assert_eq!(out.items[0].change, ItemChange::Added);
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert_eq!(rows.len(), 1, "one dir row");
    assert_eq!(rows[0].payload["kind"], "dir");
    assert_eq!(rows[0].payload["path"], "research/q4");
    assert_eq!(rows[0].payload["change"], "added");

    // `mkdir -p a/b`: one commit, the deepest level named, `count` = levels.
    let out = v
        .commit(
            UserOpKind::CreateFolder,
            vec![
                marker("a/.meta.yaml", b"a\n"),
                marker("a/b/.meta.yaml", b"b\n"),
            ],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Create folder a/b/");
    assert_eq!(out.label.count, 2);
    assert_eq!(out.items.len(), 2);
}

// MODULE-003-T34 (AC-27): renames and moves reuse blobs and subtrees; the index follows.
#[tokio::test]
async fn rename_and_move_reuse_blobs() {
    let v = Vault::with(&[
        ("notes/a.md", b"a\n"),
        ("notes/b.md", b"b\n"),
        ("todo.md", b"t\n"),
        ("drafts/x.md", b"x\n"),
        ("drafts/y.md", b"y\n"),
    ])
    .await;
    let a = blob(b"a\n");
    let out = v
        .commit(
            UserOpKind::Rename,
            vec![moved("notes/a.md", "notes/c.md", Some(a))],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Rename notes/a.md → notes/c.md");
    assert_eq!(v.head_entry("notes/c.md"), Some(a));
    assert_eq!(v.head_entry("notes/a.md"), None);
    assert_eq!(v.index_blob("notes/c.md"), Some(a));
    assert_eq!(v.index_blob("notes/a.md"), None);
    assert_eq!(
        out.items[0].change,
        ItemChange::Renamed {
            from: "notes/a.md".to_string()
        }
    );

    let drafts = v.head_entry("drafts").unwrap();
    let out = v
        .commit(
            UserOpKind::Move,
            vec![PathChange::MoveTree {
                from: path("drafts"),
                to: path("archive/drafts"),
                oid: Some(drafts.to_string()),
            }],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Move drafts/ → archive/");
    assert_eq!(v.head_entry("archive/drafts"), Some(drafts));
    assert_eq!(v.head_entry("drafts"), None);
    assert_eq!(v.index_blob("archive/drafts/x.md"), Some(blob(b"x\n")));
    assert_eq!(v.index_blob("drafts/x.md"), None);
    assert_eq!(out.items[0].kind, ItemKind::Dir);

    let out = v
        .commit(
            UserOpKind::Move,
            vec![
                moved("notes/b.md", "archive/b.md", Some(blob(b"b\n"))),
                moved("notes/c.md", "archive/c.md", Some(a)),
                moved("todo.md", "archive/todo.md", Some(blob(b"t\n"))),
            ],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Move 3 items → archive/");
    assert_eq!(v.head_entry("archive/c.md"), Some(a));
    assert_eq!(v.head_entry("notes/b.md"), None);
    assert_eq!(v.index_blob("archive/todo.md"), Some(blob(b"t\n")));
}

// MODULE-003-T35 (AC-27): folder and multi-file deletes; their index entries go too.
#[tokio::test]
async fn delete_file_and_folder() {
    let v = Vault::with(&[
        ("drafts/old/a.md", b"a\n"),
        ("drafts/old/b.md", b"b\n"),
        ("drafts/x.md", b"x\n"),
        ("drafts/y.md", b"y\n"),
        ("keep.md", b"k\n"),
    ])
    .await;
    std::fs::remove_dir_all(v.root.join("drafts/old")).unwrap();
    let out = v
        .commit(
            UserOpKind::Delete,
            vec![PathChange::RemoveTree {
                dir: path("drafts/old"),
            }],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Delete drafts/old/");
    assert_eq!(v.head_entry("drafts/old"), None);
    assert_eq!(v.index_blob("drafts/old/a.md"), None);
    assert_eq!(v.index_blob("drafts/old/b.md"), None);
    assert_eq!(out.items[0].kind, ItemKind::Dir);
    assert_eq!(out.items[0].change, ItemChange::Deleted);

    std::fs::remove_file(v.root.join("drafts/x.md")).unwrap();
    std::fs::remove_file(v.root.join("drafts/y.md")).unwrap();
    let out = v
        .commit(
            UserOpKind::Delete,
            vec![remove("drafts/x.md"), remove("drafts/y.md")],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Delete 2 items in drafts/");
    assert_eq!(v.head_entry("drafts"), None);
    assert_eq!(v.head_entry("keep.md"), Some(blob(b"k\n")));
}

// ── T37–T38, T53–T55: prepare ───────────────────────────────────────────────────────────

// MODULE-003-T37 (AC-31): an uncommitted base is recorded as runtime:adopt; the user's diff is
// then exactly C→U.
#[tokio::test]
async fn prepare_adopts_untracked_base_then_pure_delta() {
    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    let c = b"line c\n";
    v.write("notes/a.md", c);
    let st = v
        .prepare(vec![file("notes/a.md", AdoptPolicy::IfDiskIs(hex(c)))])
        .await
        .unwrap();
    let adopted = st.adopted_sha.clone().unwrap();
    assert_eq!(st.adopted_paths, vec!["notes/a.md".to_string()]);
    assert_eq!(st.adopted_count, 1);
    assert_eq!(st.head_sha.as_deref(), Some(adopted.as_str()));
    let state = &st.states[0];
    assert_eq!(state.head_oid, Some(hex(c)));
    assert_eq!(state.disk_oid, Some(hex(c)));
    assert_eq!(state.disk_kind, Some(EntryKind::File));
    assert!(state.tracked);
    assert!(state.identity.is_some());
    assert_eq!(state.size, Some(c.len() as u64));

    let repo = v.repo();
    let commit = repo.find_commit(Oid::from_str(&adopted).unwrap()).unwrap();
    assert_eq!(commit.author().name(), Some("runtime"));
    assert_eq!(commit.author().email(), Some("runtime@advance-agents"));
    assert_eq!(commit.committer().name(), Some("runtime"));
    let message = commit.message().unwrap();
    assert_eq!(
        first_line(message),
        "[micro] [runtime:adopt] Record uncommitted change to notes/a.md"
    );
    assert_eq!(parse_trailers(message).unwrap().op, "adopt");
    assert_eq!(parse_provenance(message), None);
    assert_eq!(v.index_blob("notes/a.md"), Some(blob(c)));
    let events = v.bus.drain();
    let commits = git_commits(&events);
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].payload["op"], "adopt");
    assert_eq!(commits[0].payload["commit_type"], "micro");
    assert_eq!(commits[0].agent_id, "runtime");
    let rows = files_changed(&events);
    assert!(
        rows.iter().any(|e| e.payload["path"] == "notes/a.md"),
        "adopt rows from the tree diff: {rows:?}"
    );

    let u = b"line u\n";
    v.write("notes/a.md", u);
    let out = v
        .commit(UserOpKind::Edit, vec![put("notes/a.md", u)])
        .await
        .unwrap();
    let sha = out.sha.unwrap();
    assert_eq!(v.parent_of(&sha), Some(adopted));
    assert_eq!(v.changed(&sha), vec!["notes/a.md".to_string()]);
    assert_eq!(out.subject, "Edit notes/a.md (+1 −1)");
    assert_eq!(out.items[0].parent_oid, Some(hex(c)));
}

// MODULE-003-T38 (AC-31): prepare waits for every commit queued before it.
#[tokio::test]
async fn prepare_is_fifo_behind_agent_commits() {
    let v = Vault::with(&[("p.md", b"p0\n")]).await;
    let a = b"agent bytes\n";
    v.write("p.md", a);
    let legacy = v.queue.submit(CommitRequest::new(
        "writer",
        "write p.md",
        vec![PathBuf::from("p.md")],
        CommitType::Turn,
        "agent:writer",
    ));
    let st = v
        .prepare(vec![file("p.md", AdoptPolicy::IfDiskIs(hex(a)))])
        .await
        .unwrap();
    let agent = legacy.await.unwrap().unwrap();
    assert_eq!(st.head_sha, Some(agent.to_string()));
    assert_eq!(st.states[0].head_oid, Some(hex(a)));
    assert_eq!(st.adopted_sha, None, "nothing to adopt");
}

// MODULE-003-T53 (AC-31): a Tree prepare skips Private and unrepresentable entries, flags agent
// territory, never adopts it, and bounds what it examines.
#[tokio::test]
async fn tree_prepare_skips_private_and_flags_territory() {
    let v = Vault::with(&[("team/a.md", b"a\n")]).await;
    v.write(
        "team/x/.agent/memory/_knowledge_cursor.yaml",
        b"cursor: 1\n",
    );
    v.write("team/Icon\r", b"icon\n");
    v.write("team/.runtime/x", b"runtime state\n");
    v.write("team/.DS_Store", b"junk\n");
    v.write("team/.~advance-staging-1", b"scratch\n");
    v.write("team/new.md", b"new\n");
    Repository::init(v.root.join("team/sub")).unwrap();
    v.write("team/sub/inner.md", b"inner\n");

    let st = v.prepare(vec![tree("team")]).await.unwrap();
    assert!(st.agent_territory);
    assert_eq!(st.adopted_paths, vec!["team/new.md".to_string()]);
    let unversioned: std::collections::HashSet<&str> =
        st.unversioned.iter().map(String::as_str).collect();
    for expected in ["team/Icon\r", "team/.runtime/x", "team/sub"] {
        assert!(
            unversioned.contains(expected),
            "{expected:?} in {unversioned:?}"
        );
    }
    assert!(
        !unversioned.contains("team/.DS_Store"),
        "Junk is skipped silently"
    );
    assert!(!unversioned.iter().any(|p| p.contains(".~advance-")));
    assert!(!unversioned.iter().any(|p| p.contains(".agent")));
    assert_eq!(st.unversioned_count, 3);
    assert_eq!(
        st.unversioned_bytes,
        (b"icon\n".len() + b"runtime state\n".len()) as u64
    );
    assert!(!st.adopt_incomplete);
    assert_eq!(
        v.head_entry("team/x"),
        None,
        "agent territory is never adopted"
    );
    assert_eq!(v.head_entry("team/new.md"), Some(blob(b"new\n")));
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert!(
        rows.iter().any(|e| e.payload["path"] == "team/new.md"),
        "adopted path gets a row: {rows:?}"
    );
    assert!(
        rows.iter().all(|e| {
            let p = e.payload["path"].as_str().unwrap_or("");
            !p.contains(".runtime") && !p.contains("_knowledge") && !p.contains(".DS_Store")
        }),
        "Private/Junk paths emit no rows: {rows:?}"
    );
    let head_tree = v.head_entry("team").unwrap();
    assert_eq!(st.tree_states[0].head_tree_oid, Some(head_tree.to_string()));

    // Past MAX_TREE_ADOPT_ENTRIES (10 000) the rest is counted, not examined.
    let mut ignore = std::fs::read_to_string(v.root.join(".gitignore")).unwrap();
    ignore.push_str("*.bulk\n");
    std::fs::write(v.root.join(".gitignore"), ignore).unwrap();
    std::fs::create_dir_all(v.root.join("team/bulk")).unwrap();
    for i in 0..10_001 {
        std::fs::write(v.root.join(format!("team/bulk/{i:05}.bulk")), b"").unwrap();
    }
    let st = v.prepare(vec![tree("team")]).await.unwrap();
    assert!(st.adopt_incomplete);
    assert!(st.unversioned_count > 10_000);
    assert_eq!(st.unversioned.len(), 64);
    assert_eq!(st.adopted_sha, None);
}

// MODULE-003-T53 (AC-31, AC-36), past the bounds: every status entry takes the agent-territory
// test, so a disk-side `.agent/` is reported even when it sorts after 10 000 entries; ignored
// entries (a dependency folder) have a bound of their own, so they never keep a later
// candidate from being recorded.
#[tokio::test]
async fn tree_prepare_flags_territory_past_the_entry_bounds() {
    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    let mut ignore = std::fs::read_to_string(v.root.join(".gitignore")).unwrap();
    ignore.push_str("node_modules/\n");
    std::fs::write(v.root.join(".gitignore"), ignore).unwrap();
    for i in 0..10_001 {
        v.write(&format!("team/app/node_modules/p{i:05}.js"), b"x");
    }
    v.write("team/zeta/.agent/config.yaml", b"agent_id: zeta\n");
    v.write("team/zeta/notes.md", b"zeta notes\n");
    let st = v.prepare(vec![tree("team")]).await.unwrap();
    assert!(st.agent_territory, "the territory behind the ignored tree");
    assert_eq!(st.adopted_paths, vec!["team/zeta/notes.md".to_string()]);
    assert_eq!(
        v.head_entry("team/zeta/notes.md"),
        Some(blob(b"zeta notes\n"))
    );
    assert_eq!(v.head_entry("team/zeta/.agent"), None);
    assert!(
        st.adopt_incomplete,
        "the 10 001st ignored entry was not sized"
    );
    assert_eq!(st.unversioned_count, 10_001);

    // 10 001 untracked entries before a territory (nothing hashed: the byte budget is 0).
    v.queue.set_lane_test_hooks(LaneTestHooks {
        adopt_budget: Some(AdoptBudget {
            max_bytes: 0,
            time: Duration::from_secs(3600),
            clock: None,
        }),
        ..LaneTestHooks::default()
    });
    for i in 0..10_001 {
        v.write(&format!("other/bulk/{i:05}.md"), b"y");
    }
    v.write("other/zz/.agent/config.yaml", b"agent_id: zz\n");
    let st = v.prepare(vec![tree("other")]).await.unwrap();
    assert!(
        st.agent_territory,
        "the territory past the examination bound"
    );
    assert!(st.adopt_incomplete);
    assert_eq!(st.adopted_sha, None);
    assert_eq!(st.unversioned_count, 10_001);
}

// MODULE-003-T54 (AC-31): an untracked file adopted with `Always` stays recoverable after the
// delete.
#[tokio::test]
async fn delete_untracked_file_is_recoverable() {
    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    v.write("notes/p.md", b"precious\n");
    let st = v
        .prepare(vec![file("notes/p.md", AdoptPolicy::Always)])
        .await
        .unwrap();
    let adopted = st.adopted_sha.unwrap();
    assert_eq!(st.adopted_paths, vec!["notes/p.md".to_string()]);
    std::fs::remove_file(v.root.join("notes/p.md")).unwrap();
    let out = v
        .commit(UserOpKind::Delete, vec![remove("notes/p.md")])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Delete notes/p.md");
    assert_eq!(v.head_entry("notes/p.md"), None);
    let at = GitHistoryReader::new(v.root.clone())
        .read_file_at("notes/p.md", &adopted)
        .unwrap();
    assert_eq!(at.bytes, b"precious\n");
}

// MODULE-003-T55 (AC-31): a dirty source is recorded before the move, which reuses its blob.
#[tokio::test]
async fn move_dirty_file_records_disk_bytes() {
    let v = Vault::with(&[("notes/p.md", b"B committed\n")]).await;
    let x = b"X dirty bytes\n";
    v.write("notes/p.md", x);
    let st = v
        .prepare(vec![
            file("notes/p.md", AdoptPolicy::Always),
            file("archive/p.md", AdoptPolicy::IfDiskAbsent),
        ])
        .await
        .unwrap();
    assert!(st.adopted_sha.is_some());
    assert_eq!(st.states[0].head_oid, Some(hex(x)));
    assert_eq!(st.states[1].head_oid, None);
    assert_eq!(st.states[1].disk_kind, None);
    std::fs::create_dir_all(v.root.join("archive")).unwrap();
    std::fs::rename(v.root.join("notes/p.md"), v.root.join("archive/p.md")).unwrap();
    let out = v
        .commit(
            UserOpKind::Move,
            vec![moved(
                "notes/p.md",
                "archive/p.md",
                Some(Oid::from_str(st.states[0].head_oid.as_deref().unwrap()).unwrap()),
            )],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Move notes/p.md → archive/");
    assert_eq!(v.head_entry("archive/p.md"), Some(blob(x)));
}

// ── T45–T46, T49, T59–T61, T70: verification, index and journal ─────────────────────────

// MODULE-003-T45 (AC-27): a disk source that does not hash to its oid is refused untouched.
#[tokio::test]
async fn disk_source_verified() {
    let v = Vault::with(&[("a.md", b"a0\n")]).await;
    let tip = v.head();
    v.write("a.md", b"a1\n");
    match v
        .commit(
            UserOpKind::EditExternal,
            vec![put_disk("a.md", b"something else\n")],
        )
        .await
    {
        Err(GitError::ContentChanged {
            path,
            expected,
            actual,
        }) => {
            assert_eq!(path, PathBuf::from("a.md"));
            assert_eq!(expected, hex(b"something else\n"));
            assert_eq!(actual, Some(hex(b"a1\n")));
        }
        other => panic!("expected ContentChanged, got {other:?}"),
    }
    assert_eq!(v.head(), tip);
    assert_eq!(v.index_blob("a.md"), Some(blob(b"a0\n")));
    // The matching oid commits.
    let out = v
        .commit(UserOpKind::EditExternal, vec![put_disk("a.md", b"a1\n")])
        .await
        .unwrap();
    assert_eq!(out.subject, "Edit a.md in external app (+1 −1)");
    assert_eq!(out.label.change.as_deref(), Some("modified"));
}

// MODULE-003-T46 (AC-27): the index is written before `main` moves; a lock that stays past the
// retries fails the item with nothing visible, a brief one is retried.
#[tokio::test]
async fn index_written_before_ref() {
    let v = Vault::with(&[("a.md", b"a0\n")]).await;
    let tip = v.head();
    let lock = v.root.join(".git/index.lock");
    std::fs::write(&lock, b"held").unwrap();
    let started = Instant::now();
    match v.commit(UserOpKind::Edit, vec![put("a.md", b"a1\n")]).await {
        Err(GitError::Libgit2 { code, .. }) => assert_eq!(code, "Locked"),
        other => panic!("expected Locked, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(600));
    assert_eq!(v.head(), tip);
    let main = v.repo().find_reference("refs/heads/main").unwrap().target();
    assert_eq!(main, tip);
    assert!(!v.journal_exists(), "the journal is deleted");
    assert_eq!(v.index_blob("a.md"), Some(blob(b"a0\n")));

    // A lock released within the retries is waited out.
    let releaser = {
        let lock = lock.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            std::fs::remove_file(lock).unwrap();
        })
    };
    let out = v
        .commit(UserOpKind::Edit, vec![put("a.md", b"a1\n")])
        .await
        .unwrap();
    releaser.join().unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(v.head_entry("a.md"), Some(blob(b"a1\n")));
    assert!(!v.journal_exists());
}

/// Plant what a lane item that crashed between its index write and its ref move leaves: the
/// user's bytes for `path` in the index and a journal naming it.
fn plant_crash(v: &Vault, path: &str) -> Oid {
    let stale = v.stage_leftover(path, b"crashed user bytes\n");
    let parent = v.head().unwrap();
    let journal = format!(
        r#"{{"parent":"{parent}","commit":"{}","paths":["{path}"],"prefixes":[]}}"#,
        "c".repeat(40)
    );
    std::fs::create_dir_all(v.root.join(".git/advance")).unwrap();
    std::fs::write(v.root.join(".git/advance/user-lane.journal"), journal).unwrap();
    stale
}

// MODULE-003-T49 (AC-27): a journal planted mid-run is healed before the next legacy item; with
// the index locked that item fails and makes no commit.
#[tokio::test]
async fn crash_journal_heals_index_before_every_item() {
    let v = Vault::with(&[("a.md", b"a0\n"), ("b.md", b"b0\n")]).await;
    let stale = plant_crash(&v, "a.md");
    assert_eq!(v.index_blob("a.md"), Some(stale));
    v.write("b.md", b"b1\n");
    let oid = v.legacy(&["b.md"]).await.unwrap().to_string();
    assert_eq!(
        v.entry_in(&oid, "a.md"),
        Some(blob(b"a0\n")),
        "no stale entry"
    );
    assert_eq!(v.entry_in(&oid, "b.md"), Some(blob(b"b1\n")));
    assert_eq!(v.index_blob("a.md"), Some(blob(b"a0\n")));
    assert!(!v.journal_exists());

    plant_crash(&v, "a.md");
    let tip = v.head();
    let lock = v.root.join(".git/index.lock");
    std::fs::write(&lock, b"held").unwrap();
    v.write("b.md", b"b2\n");
    match v.legacy(&["b.md"]).await {
        Err(GitError::Libgit2 { code, .. }) => assert_eq!(code, "Locked"),
        other => panic!("expected Locked, got {other:?}"),
    }
    assert_eq!(v.head(), tip, "no commit on an unhealed index");
    assert!(v.journal_exists(), "the journal waits for the next heal");
    std::fs::remove_file(&lock).unwrap();
    let oid = v.legacy(&["b.md"]).await.unwrap().to_string();
    assert_eq!(v.entry_in(&oid, "a.md"), Some(blob(b"a0\n")));
    assert_eq!(v.entry_in(&oid, "b.md"), Some(blob(b"b2\n")));
}

// MODULE-003-T59 (AC-35): FIFOs and symlinked parents are never read, never block, never
// adopted.
#[tokio::test]
async fn disk_source_refuses_fifo_and_symlinked_parent() {
    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    mkfifo(&v.root.join("pipe.md"));
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.md"), b"secret\n").unwrap();
    std::os::unix::fs::symlink(outside.path(), v.root.join("linked")).unwrap();
    let tip = v.head();

    let fifo =
        within_5s(v.commit(UserOpKind::EditExternal, vec![put_disk("pipe.md", b"x\n")])).await;
    assert!(
        matches!(fifo, Err(GitError::ContentChanged { actual: None, .. })),
        "{fifo:?}"
    );
    let linked = within_5s(v.commit(
        UserOpKind::EditExternal,
        vec![put_disk("linked/secret.md", b"secret\n")],
    ))
    .await;
    assert!(
        matches!(linked, Err(GitError::ContentChanged { actual: None, .. })),
        "{linked:?}"
    );
    assert_eq!(v.head(), tip);

    let st = within_5s(v.prepare(vec![
        file("pipe.md", AdoptPolicy::Always),
        file("linked/secret.md", AdoptPolicy::Always),
    ]))
    .await
    .unwrap();
    assert_eq!(st.adopted_sha, None);
    assert_eq!(st.states[0].disk_kind, Some(EntryKind::Other));
    assert_eq!(st.states[1].disk_kind, Some(EntryKind::Other));
    assert_eq!(st.states[1].disk_oid, None);
    assert!(st.unversioned.contains(&"linked/secret.md".to_string()));
    assert_eq!(v.head(), tip);
}

/// A `before_ref_cas` hook that runs `act` once (the first compare-and-swap) and records the
/// commit it made.
fn once_hook(
    act: impl Fn(&Repository) -> Oid + Send + 'static,
) -> (LaneTestHooks, Arc<Mutex<Option<Oid>>>) {
    let fired = AtomicBool::new(false);
    let made: Arc<Mutex<Option<Oid>>> = Arc::new(Mutex::new(None));
    let slot = made.clone();
    let hooks = LaneTestHooks {
        before_ref_cas: Some(Box::new(move |workdir: &Path| {
            if fired.swap(true, Ordering::SeqCst) {
                return;
            }
            let repo = Repository::open(workdir).unwrap();
            *slot.lock().unwrap() = Some(act(&repo));
        })),
        ..LaneTestHooks::default()
    };
    (hooks, made)
}

fn row_io_signature() -> Signature<'static> {
    Signature::new(
        "row io",
        "rowio@example.com",
        &git2::Time::new(1_700_000_000, 0),
    )
    .unwrap()
}

/// A CLI `git commit` in flight, in git's lock order: it holds `index.lock` with the index it
/// read plus `stage`, has committed that index on the current tip and holds
/// `refs/heads/main.lock`; `delay` later it renames the ref lock over the ref, then the index
/// lock over the index. Answers its commit and the thread that finishes it.
fn inflight_cli_commit(
    repo: &Repository,
    stage: impl FnOnce(&Repository, &mut git2::Index),
    delay: Duration,
) -> (Oid, std::thread::JoinHandle<()>) {
    let git_dir = repo.path().to_path_buf();
    std::fs::copy(git_dir.join("index"), git_dir.join("index.lock")).unwrap();
    let mut theirs = git2::Index::open(&git_dir.join("index.lock")).unwrap();
    stage(repo, &mut theirs);
    theirs.write().unwrap();
    let tree = repo.find_tree(theirs.write_tree_to(repo).unwrap()).unwrap();
    let head = repo.head().unwrap().peel_to_commit().unwrap();
    let sig = row_io_signature();
    let commit = repo
        .commit(None, &sig, &sig, "row io", &tree, &[&head])
        .unwrap();
    std::fs::write(git_dir.join("refs/heads/main.lock"), format!("{commit}\n")).unwrap();
    let finish = std::thread::spawn(move || {
        std::thread::sleep(delay);
        let refs = git_dir.join("refs/heads");
        std::fs::rename(refs.join("main.lock"), refs.join("main")).unwrap();
        std::fs::rename(git_dir.join("index.lock"), git_dir.join("index")).unwrap();
    });
    (commit, finish)
}

// MODULE-003-T60 (AC-27): a writer outside the queue moves `main` between the index write and
// the ref compare-and-swap; the touched entries follow the new tip.
#[tokio::test]
async fn head_moved_resets_index_to_new_tip() {
    // Scenario 1: the foreign commit sweeps the whole index (WorkspaceRowIo's `git commit`),
    // which already holds the user's bytes.
    let v = Vault::with(&[("p.md", b"p0\n"), ("q.md", b"q0\n")]).await;
    let (hooks, foreign) = once_hook(|repo| {
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        let sig = row_io_signature();
        repo.commit(Some("HEAD"), &sig, &sig, "row io", &tree, &[&head])
            .unwrap()
    });
    v.queue.set_lane_test_hooks(hooks);
    let out = v
        .commit(UserOpKind::Edit, vec![put("p.md", b"p1\n")])
        .await
        .unwrap();
    let swept = foreign.lock().unwrap().unwrap();
    assert_eq!(
        out.status,
        UserCommitStatus::Unchanged,
        "already in the new tip"
    );
    assert_eq!(out.head_sha, Some(swept.to_string()));
    assert_eq!(v.head(), Some(swept));
    assert_eq!(v.head_entry("p.md"), Some(blob(b"p1\n")));
    assert_eq!(v.index_blob("p.md"), Some(blob(b"p1\n")));
    assert!(!v.journal_exists());

    // Scenario 2: the foreign commit records another path only; the user's edit is re-made on
    // top of it.
    let (hooks, foreign) = once_hook(|repo| {
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        let row = repo.blob(b"q1\n").unwrap();
        let mut builder = git2::build::TreeUpdateBuilder::new();
        builder.upsert("q.md", row, git2::FileMode::Blob);
        let tree = builder.create_updated(repo, &head.tree().unwrap()).unwrap();
        let tree = repo.find_tree(tree).unwrap();
        let sig = row_io_signature();
        repo.commit(Some("HEAD"), &sig, &sig, "row io", &tree, &[&head])
            .unwrap()
    });
    v.queue.set_lane_test_hooks(hooks);
    let out = v
        .commit(UserOpKind::Edit, vec![put("p.md", b"p2\n")])
        .await
        .unwrap();
    let row_io = foreign.lock().unwrap().unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    let sha = out.sha.unwrap();
    assert_eq!(v.parent_of(&sha), Some(row_io.to_string()));
    assert_eq!(v.head_entry("q.md"), Some(blob(b"q1\n")));
    assert_eq!(v.head_entry("p.md"), Some(blob(b"p2\n")));
    assert_eq!(v.index_blob("p.md"), Some(blob(b"p2\n")));
    assert_eq!(v.changed(&sha), vec!["p.md".to_string()]);

    // Scenario 3: the tip moves before every compare-and-swap. After three attempts the item
    // fails with `HeadMoved`, and the index holds the new tip's entry for p, not the user's
    // bytes it was given before each swap.
    let round = Arc::new(AtomicU64::new(0));
    let last: Arc<Mutex<Option<Oid>>> = Arc::new(Mutex::new(None));
    {
        let round = round.clone();
        let last = last.clone();
        v.queue.set_lane_test_hooks(LaneTestHooks {
            before_ref_cas: Some(Box::new(move |workdir: &Path| {
                let n = round.fetch_add(1, Ordering::SeqCst);
                let repo = Repository::open(workdir).unwrap();
                let head = repo.head().unwrap().peel_to_commit().unwrap();
                let row = repo.blob(format!("q row {n}\n").as_bytes()).unwrap();
                let mut builder = git2::build::TreeUpdateBuilder::new();
                builder.upsert("q.md", row, git2::FileMode::Blob);
                let tree = builder
                    .create_updated(&repo, &head.tree().unwrap())
                    .unwrap();
                let tree = repo.find_tree(tree).unwrap();
                let sig = row_io_signature();
                let oid = repo
                    .commit(Some("HEAD"), &sig, &sig, "row io", &tree, &[&head])
                    .unwrap();
                *last.lock().unwrap() = Some(oid);
            })),
            ..LaneTestHooks::default()
        });
    }
    let before = v.head();
    match v.commit(UserOpKind::Edit, vec![put("p.md", b"p3\n")]).await {
        Err(GitError::HeadMoved { expected, actual }) => {
            let last = last.lock().unwrap().unwrap();
            assert_eq!(actual, Some(last.to_string()));
            assert_ne!(
                expected,
                before.map(|o| o.to_string()),
                "the third attempt's base"
            );
        }
        other => panic!("expected HeadMoved, got {other:?}"),
    }
    assert_eq!(round.load(Ordering::SeqCst), 3, "three attempts");
    assert_eq!(v.head_entry("p.md"), Some(blob(b"p2\n")));
    assert_eq!(
        v.index_blob("p.md"),
        Some(blob(b"p2\n")),
        "index == the new tip"
    );
    assert!(!v.journal_exists());

    // Scenario 4: the swap meets `refs/heads/main.lock`. A CLI commit that read the index after
    // the user's entry was written holds both locks and lands 50 ms later. The entry follows
    // the tip read once the index lock is free (the commit that swept the user's bytes), never
    // the one read before the wait, so the edit is `Unchanged` there.
    let inflight: Arc<Mutex<Option<(Oid, std::thread::JoinHandle<()>)>>> =
        Arc::new(Mutex::new(None));
    {
        let fired = AtomicBool::new(false);
        let slot = inflight.clone();
        v.queue.set_lane_test_hooks(LaneTestHooks {
            before_ref_cas: Some(Box::new(move |workdir: &Path| {
                if fired.swap(true, Ordering::SeqCst) {
                    return;
                }
                let repo = Repository::open(workdir).unwrap();
                *slot.lock().unwrap() = Some(inflight_cli_commit(
                    &repo,
                    |_, _| {},
                    Duration::from_millis(50),
                ));
            })),
            ..LaneTestHooks::default()
        });
    }
    let out = v
        .commit(UserOpKind::Edit, vec![put("p.md", b"p4\n")])
        .await
        .unwrap();
    let (swept, finish) = inflight.lock().unwrap().take().unwrap();
    finish.join().unwrap();
    assert_eq!(out.status, UserCommitStatus::Unchanged, "swept: {out:?}");
    assert_eq!(out.head_sha, Some(swept.to_string()));
    assert_eq!(v.head(), Some(swept));
    assert_eq!(v.head_entry("p.md"), Some(blob(b"p4\n")));
    assert_eq!(v.index_blob("p.md"), Some(blob(b"p4\n")), "index == HEAD");
    assert!(!v.journal_exists());
    v.write("q.md", b"q after the locked swap\n");
    let agent = v.legacy(&["q.md"]).await.unwrap().to_string();
    assert_eq!(v.entry_in(&agent, "p.md"), Some(blob(b"p4\n")), "no revert");

    // Scenario 5: an `Unchanged` save of p while a CLI commit of a foreign change to p holds
    // `index.lock`: the item decides against the tip it read, then waits for the lock. Its
    // index entry follows the tip the foreign commit made, and `head_sha` names that tip, so the
    // next legacy commit keeps the foreign bytes. (Were the worker slower than the foreign
    // commit, the save would be decided against that tip and commit; the index still equals
    // HEAD.)
    v.queue.set_lane_test_hooks(LaneTestHooks::default());
    v.write("p.md", b"F foreign\n");
    let (foreign, finish) = inflight_cli_commit(
        &v.repo(),
        |repo, index| {
            let mut entry = index.get_path(Path::new("p.md"), 0).unwrap();
            entry.id = repo.blob(b"F foreign\n").unwrap();
            index.add(&entry).unwrap();
        },
        Duration::from_millis(200),
    );
    let out = v
        .commit(UserOpKind::Edit, vec![put("p.md", b"p4\n")])
        .await
        .unwrap();
    finish.join().unwrap();
    if out.status == UserCommitStatus::Unchanged {
        assert_eq!(out.head_sha, Some(foreign.to_string()));
        assert_eq!(v.head(), Some(foreign));
    }
    let head_p = v.head_entry("p.md");
    assert_eq!(v.index_blob("p.md"), head_p, "index == HEAD");
    v.write("q.md", b"q after the foreign commit\n");
    let agent = v.legacy(&["q.md"]).await.unwrap().to_string();
    assert_eq!(v.entry_in(&agent, "p.md"), head_p, "no revert");
}

// MODULE-003-T61 (AC-27): an `Unchanged` save still makes the index equal HEAD for its path.
#[tokio::test]
async fn unchanged_edit_normalizes_stale_index_entry() {
    let v = Vault::with(&[("p.md", b"U\n"), ("q.md", b"q0\n")]).await;
    let leftover = v.stage_leftover("p.md", b"X leftover\n");
    assert_eq!(v.index_blob("p.md"), Some(leftover));
    let out = v
        .commit(UserOpKind::Edit, vec![put("p.md", b"U\n")])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Unchanged);
    assert_eq!(v.index_blob("p.md"), Some(blob(b"U\n")));
    v.write("q.md", b"q1\n");
    let oid = v.legacy(&["q.md"]).await.unwrap().to_string();
    assert_eq!(
        v.entry_in(&oid, "p.md"),
        Some(blob(b"U\n")),
        "X never recorded"
    );
}

fn stat_of(meta: &std::fs::Metadata) -> IndexStat {
    IndexStat {
        ctime_s: meta.ctime(),
        ctime_ns: meta.ctime_nsec() as u32,
        mtime_s: meta.mtime(),
        mtime_ns: meta.mtime_nsec() as u32,
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        gid: meta.gid(),
        size: meta.size(),
    }
}

// MODULE-003-T70 (AC-27): a provider stat that still matches the file is recorded; one that
// does not is smudged.
#[tokio::test]
async fn index_stat_recorded_when_identity_matches() {
    let v = Vault::with(&[("p.md", b"p0\n"), ("q.md", b"q0\n")]).await;
    let bytes = b"p1 written by the provider\n";
    v.write("p.md", bytes);
    let meta = std::fs::symlink_metadata(v.root.join("p.md")).unwrap();
    let change = PathChange::Put {
        path: path("p.md"),
        content: BlobSource::Bytes(bytes.to_vec()),
        role: ChangeRole::Primary,
        executable: None,
        stat: Some(stat_of(&meta)),
    };
    v.commit(UserOpKind::Edit, vec![change]).await.unwrap();
    let entry = v.index_entry("p.md").unwrap();
    assert_eq!(entry.id, blob(bytes));
    assert_eq!(entry.file_size, bytes.len() as u32);
    assert_eq!(entry.mtime.seconds(), meta.mtime() as i32);
    assert_eq!(entry.mtime.nanoseconds(), meta.mtime_nsec() as u32);
    assert_eq!(entry.ino, meta.ino() as u32);
    let status = |v: &Vault, p: &str| v.repo().status_file(Path::new(p)).unwrap();
    assert_eq!(status(&v, "p.md"), Status::CURRENT);

    // A later same-size rewrite with the mtime put back still shows (ctime moved).
    std::thread::sleep(Duration::from_millis(20));
    let rewritten = b"P1 written by someone else\n";
    assert_eq!(rewritten.len(), bytes.len());
    {
        use std::io::Write;
        let mut handle = std::fs::OpenOptions::new()
            .write(true)
            .open(v.root.join("p.md"))
            .unwrap();
        handle.write_all(rewritten).unwrap();
        handle.set_modified(meta.modified().unwrap()).unwrap();
    }
    assert!(status(&v, "p.md").contains(Status::WT_MODIFIED));

    // A stat that no longer matches the file is not recorded.
    let q = b"q1 provider bytes\n";
    v.write("q.md", q);
    let meta = std::fs::symlink_metadata(v.root.join("q.md")).unwrap();
    let mut wrong = stat_of(&meta);
    wrong.ino = wrong.ino.wrapping_add(1);
    let change = PathChange::Put {
        path: path("q.md"),
        content: BlobSource::Bytes(q.to_vec()),
        role: ChangeRole::Primary,
        executable: None,
        stat: Some(wrong),
    };
    v.commit(UserOpKind::Edit, vec![change]).await.unwrap();
    let entry = v.index_entry("q.md").unwrap();
    assert_eq!(entry.id, blob(q));
    assert_eq!(
        (entry.file_size, entry.mtime.seconds(), entry.ino),
        (0, 0, 0)
    );
    assert_eq!(
        status(&v, "q.md"),
        Status::CURRENT,
        "a smudged entry re-hashes clean"
    );
}

// ── T48, T50–T52, T62–T63: paths, idempotence and guards ─────────────────────────────────

// MODULE-003-T48 (AC-29): NFD input is stored NFC (precompose); emoji ZWJ reaches the subject.
#[tokio::test]
async fn cjk_and_emoji_paths_round_trip() {
    let v = Vault::configured(&[("keep.md", b"k\n")], |repo| {
        repo.config()
            .unwrap()
            .set_bool("core.precomposeunicode", true)
            .unwrap();
    })
    .await;
    let nfd = "笔记/cafe\u{301} 周报.md";
    let nfc = "笔记/caf\u{e9} 周报.md";
    let out = v
        .commit(UserOpKind::Create, vec![put(nfd, b"x\n")])
        .await
        .unwrap();
    assert_eq!(out.items[0].path, nfc);
    assert_eq!(out.label.paths[0], nfc);
    assert_eq!(v.head_entry(nfc), Some(blob(b"x\n")));
    assert_eq!(v.head_entry(nfd), None);

    let family = "notes/👨\u{200D}👩\u{200D}👧 family.md";
    let out = v
        .commit(UserOpKind::Create, vec![put(family, b"f\n")])
        .await
        .unwrap();
    assert_eq!(out.subject, format!("Create {family}"));
    assert_eq!(out.label.paths[0], family);
    let message = v.message(out.sha.as_deref().unwrap());
    assert_eq!(
        first_line(&message),
        format!("[user] [user:advance] Create {family}")
    );
    assert_eq!(parse_trailers(&message).unwrap().paths[0], family);
}

/// Commit `req`, then submit it again: the second time answers `Unchanged` at the same tip.
async fn twice(v: &Vault, op: UserOpKind, changes: Vec<PathChange>) -> UserCommitOutcome {
    let req = request(op, changes);
    let first = v.queue.commit_user(req.clone()).await.unwrap().unwrap();
    assert_eq!(first.status, UserCommitStatus::Committed, "{:?}", req.op);
    let again = v.queue.commit_user(req.clone()).await.unwrap().unwrap();
    assert_eq!(again.status, UserCommitStatus::Unchanged, "{:?}", req.op);
    assert_eq!(again.sha, None);
    assert_eq!(again.head_sha, first.sha, "{:?}", req.op);
    assert_eq!(v.head().map(|o| o.to_string()), first.sha);
    first
}

// MODULE-003-T50 (AC-28): every op is post-state idempotent.
#[tokio::test]
async fn retry_after_landed_commit_is_unchanged_for_every_op() {
    let v = Vault::with(&[
        ("a.md", b"a0\n"),
        ("folder/.meta.yaml", b"f\n"),
        ("folder/x.md", b"x\n"),
        ("gone.md", b"g\n"),
        ("old/y.md", b"y\n"),
    ])
    .await;
    let first = v.head().unwrap().to_string();
    let folder = v.head_entry("folder").unwrap();

    twice(&v, UserOpKind::Edit, vec![put("a.md", b"a1\n")]).await;
    twice(&v, UserOpKind::Create, vec![put("new.md", b"n\n")]).await;
    twice(
        &v,
        UserOpKind::CreateFolder,
        vec![marker("made/.meta.yaml", b"m\n")],
    )
    .await;
    twice(
        &v,
        UserOpKind::Rename,
        vec![moved("a.md", "a2.md", Some(blob(b"a1\n")))],
    )
    .await;
    twice(
        &v,
        UserOpKind::Move,
        vec![moved("a2.md", "dir/a2.md", Some(blob(b"a1\n")))],
    )
    .await;
    twice(
        &v,
        UserOpKind::Move,
        vec![PathChange::MoveTree {
            from: path("folder"),
            to: path("moved"),
            oid: Some(folder.to_string()),
        }],
    )
    .await;
    twice(
        &v,
        UserOpKind::Copy,
        vec![PathChange::Copy {
            from: path("new.md"),
            to: path("copies/new.md"),
            oid: Some(hex(b"n\n")),
        }],
    )
    .await;
    twice(&v, UserOpKind::Delete, vec![remove("gone.md")]).await;
    twice(
        &v,
        UserOpKind::Delete,
        vec![PathChange::RemoveTree { dir: path("old") }],
    )
    .await;
    twice(&v, UserOpKind::Upload, vec![put("up.bin", &[0u8, 1, 2, 3])]).await;
    v.write("ext.md", b"from another app\n");
    twice(
        &v,
        UserOpKind::EditExternal,
        vec![put_disk("ext.md", b"from another app\n")],
    )
    .await;
    let restored = twice(
        &v,
        UserOpKind::Restore(RestoreSource::Commit(first.clone())),
        vec![put("a.md", b"a0\n")],
    )
    .await;
    assert_eq!(
        restored.subject,
        format!("Restore a.md from {}", &first[..7])
    );
    assert_eq!(restored.label.from_sha.as_deref(), Some(first.as_str()));
    assert_eq!(restored.label.change.as_deref(), Some("added"));
}

// MODULE-003-T51 (AC-36): a folder delete never carries an agent territory.
#[tokio::test]
async fn remove_tree_refuses_agent_territory() {
    let v = Vault::with(&[
        ("team/research/.agent/config.yaml", b"agent_id: research\n"),
        ("team/notes.md", b"n\n"),
    ])
    .await;
    let tip = v.head();
    let refused = v
        .commit(
            UserOpKind::Delete,
            vec![PathChange::RemoveTree { dir: path("team") }],
        )
        .await;
    match &refused {
        Err(GitError::InvalidUserOp {
            reason: UserOpRefusal::AgentTerritory,
            path,
        }) => assert_eq!(path.as_deref(), Some(Path::new("team"))),
        other => panic!("expected AgentTerritory, got {other:?}"),
    }
    assert_eq!(v.head(), tip);
    assert!(v.index_blob("team/research/.agent/config.yaml").is_some());
}

// MODULE-003-T52 (AC-36): the same for folder moves and copies.
#[tokio::test]
async fn move_tree_refuses_agent_territory() {
    let v = Vault::with(&[
        ("team/research/.agent/config.yaml", b"agent_id: research\n"),
        ("team/notes.md", b"n\n"),
    ])
    .await;
    let tip = v.head();
    let team = v.head_entry("team").unwrap().to_string();
    let moved = v
        .commit(
            UserOpKind::Move,
            vec![PathChange::MoveTree {
                from: path("team"),
                to: path("archive/team"),
                oid: Some(team.clone()),
            }],
        )
        .await;
    assert_eq!(refusal(moved), UserOpRefusal::AgentTerritory);
    let copied = v
        .commit(
            UserOpKind::Copy,
            vec![PathChange::CopyTree {
                from: path("team"),
                to: path("team copy"),
                oid: Some(team),
            }],
        )
        .await;
    assert_eq!(refusal(copied), UserOpRefusal::AgentTerritory);
    assert_eq!(v.head(), tip);
}

// MODULE-003-T62 (AC-36): under `core.ignorecase` a case variant of a tracked path is refused;
// a case-only rename leaves one entry.
#[tokio::test]
async fn case_collision_refused_on_ignorecase() {
    let v = Vault::configured(&[("notes.md", b"n\n")], |repo| {
        repo.config()
            .unwrap()
            .set_bool("core.ignorecase", true)
            .unwrap();
    })
    .await;
    let created = v
        .commit(UserOpKind::Create, vec![put("Notes.md", b"N\n")])
        .await;
    assert_eq!(refusal(created), UserOpRefusal::CaseCollision);

    std::fs::rename(v.root.join("notes.md"), v.root.join("Notes.md")).unwrap();
    let out = v
        .commit(
            UserOpKind::Rename,
            vec![moved("notes.md", "Notes.md", Some(blob(b"n\n")))],
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Rename notes.md → Notes.md");
    let repo = v.repo();
    let tree = repo.head().unwrap().peel_to_tree().unwrap();
    let names: Vec<String> = tree
        .iter()
        .map(|e| String::from_utf8_lossy(e.name_bytes()).into_owned())
        .filter(|name| name.eq_ignore_ascii_case("notes.md"))
        .collect();
    assert_eq!(names, vec!["Notes.md".to_string()]);
    let mut index = repo.index().unwrap();
    index.read(true).unwrap();
    let entries: Vec<Vec<u8>> = index
        .iter()
        .map(|e| e.path)
        .filter(|p| p.eq_ignore_ascii_case(b"notes.md"))
        .collect();
    assert_eq!(entries, vec![b"Notes.md".to_vec()]);
}

// oss-git §4.2 `create` row (AC-28; INTEGRATED §3.11): a create's path must be absent from the
// parent tree or hold exactly the request's content (post-state). Other content there, from a
// commit outside the queue between `prepare(IfDiskAbsent)` and the create, is `TargetExists`:
// never replaced under a "Create" label. The same holds for `create-folder` markers.
#[tokio::test]
async fn create_refuses_a_tracked_target_with_other_bytes() {
    let v = Vault::with(&[
        ("notes/a.md", b"agent version\n"),
        ("d/.meta.yaml", b"m0\n"),
        ("keep.md", b"k\n"),
    ])
    .await;
    let tip = v.head();
    let refused = v
        .commit(
            UserOpKind::Create,
            vec![put("notes/a.md", b"user create\n")],
        )
        .await;
    match refused {
        Err(GitError::InvalidUserOp {
            reason: UserOpRefusal::TargetExists,
            path,
        }) => assert_eq!(path.as_deref(), Some(Path::new("notes/a.md"))),
        other => panic!("expected TargetExists, got {other:?}"),
    }
    let exec = PathChange::Put {
        path: path("notes/a.md"),
        content: BlobSource::Bytes(b"agent version\n".to_vec()),
        role: ChangeRole::Primary,
        executable: Some(true),
        stat: None,
    };
    let refused = v.commit(UserOpKind::Create, vec![exec]).await;
    assert_eq!(
        refusal(refused),
        UserOpRefusal::TargetExists,
        "mode differs"
    );
    let big = vec![5u8; 11 * 1024 * 1024];
    let refused = v
        .commit(UserOpKind::Create, vec![put("notes/a.md", &big)])
        .await;
    assert_eq!(refusal(refused), UserOpRefusal::TargetExists, "oversize");
    let refused = v
        .commit(
            UserOpKind::CreateFolder,
            vec![marker("d/.meta.yaml", b"m1\n")],
        )
        .await;
    assert_eq!(refusal(refused), UserOpRefusal::TargetExists, "marker");
    assert_eq!(v.head(), tip);
    assert_eq!(v.index_blob("notes/a.md"), Some(blob(b"agent version\n")));

    // The same content there is the post-state: `Unchanged`.
    let same = v
        .commit(
            UserOpKind::Create,
            vec![put("notes/a.md", b"agent version\n")],
        )
        .await
        .unwrap();
    assert_eq!(same.status, UserCommitStatus::Unchanged);
    let same = v
        .commit(
            UserOpKind::CreateFolder,
            vec![marker("d/.meta.yaml", b"m0\n")],
        )
        .await
        .unwrap();
    assert_eq!(same.status, UserCommitStatus::Unchanged);

    // A commit outside the queue adds the path after the barrier saw it absent.
    let st = v
        .prepare(vec![file("n.md", AdoptPolicy::IfDiskAbsent)])
        .await
        .unwrap();
    assert_eq!(st.states[0].head_oid, None);
    let foreign = {
        let repo = v.repo();
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        let id = repo.blob(b"foreign\n").unwrap();
        let mut builder = git2::build::TreeUpdateBuilder::new();
        builder.upsert("n.md", id, git2::FileMode::Blob);
        let tree = builder
            .create_updated(&repo, &head.tree().unwrap())
            .unwrap();
        let tree = repo.find_tree(tree).unwrap();
        let sig = row_io_signature();
        repo.commit(Some("HEAD"), &sig, &sig, "cli", &tree, &[&head])
            .unwrap()
    };
    v.write("n.md", b"user\n");
    let refused = v
        .commit(UserOpKind::Create, vec![put("n.md", b"user\n")])
        .await;
    assert_eq!(refusal(refused), UserOpRefusal::TargetExists);
    assert_eq!(v.head(), Some(foreign));
    assert_eq!(v.head_entry("n.md"), Some(blob(b"foreign\n")));
}

// oss-git §4.2 (MODULE-003 §2.8 "no side effects"): every guard runs before any object is
// written, so a refused request leaves nothing in the object store; a `Disk` source is not
// even read.
#[tokio::test]
async fn refused_requests_write_no_object() {
    let v = Vault::configured(&[("notes.md", b"n\n"), ("taken.md", b"t\n")], |repo| {
        repo.config()
            .unwrap()
            .set_bool("core.ignorecase", true)
            .unwrap();
    })
    .await;
    let stored = |bytes: &[u8]| v.repo().odb().unwrap().exists(blob(bytes));
    let collide = b"bytes of a refused case variant\n";
    let refused = v
        .commit(UserOpKind::Create, vec![put("Notes.md", collide)])
        .await;
    assert_eq!(refusal(refused), UserOpRefusal::CaseCollision);
    assert!(!stored(collide), "no blob for a refusal");

    let exists = b"bytes of a refused create\n";
    let refused = v
        .commit(UserOpKind::Create, vec![put("taken.md", exists)])
        .await;
    assert_eq!(refusal(refused), UserOpRefusal::TargetExists);
    assert!(!stored(exists));

    let disk = b"disk bytes behind a refused external edit\n";
    v.write("NOTES.md", disk);
    let refused = v
        .commit(UserOpKind::EditExternal, vec![put_disk("NOTES.md", disk)])
        .await;
    assert_eq!(refusal(refused), UserOpRefusal::CaseCollision);
    assert!(!stored(disk), "the disk source was not stored");
}

// MODULE-003 §1.4.1 "paths" (AC-27): with `core.precomposeunicode` the lane spells new tree
// paths in NFC, but the legacy lane stores the bytes an agent passed, so HEAD can hold a
// decomposed name. A user op on that file reaches the entry history has: prepare sees it
// tracked, an edit keeps its spelling, a delete and a move remove it. Nothing reads as
// untracked, so nothing is lost from history or adopted under the runtime's name.
#[tokio::test]
async fn user_ops_reach_decomposed_names_from_the_agent_lane() {
    let v = Vault::configured(&[("keep.md", b"k\n")], |repo| {
        repo.config()
            .unwrap()
            .set_bool("core.precomposeunicode", true)
            .unwrap();
    })
    .await;
    let cafe = "cafe\u{301}.md";
    let resume = "re\u{301}sume\u{301}.md";
    let notes = "note\u{301}s/a.md";
    for (p, bytes) in [(cafe, &b"agent\n"[..]), (resume, b"r\n"), (notes, b"n\n")] {
        v.write(p, bytes);
    }
    v.legacy(&[cafe, resume, notes]).await.unwrap();
    assert_eq!(
        v.head_entry(cafe),
        Some(blob(b"agent\n")),
        "stored decomposed"
    );
    assert_eq!(v.head_entry("caf\u{e9}.md"), None);

    let st = v
        .prepare(vec![
            file(cafe, AdoptPolicy::Always),
            file(notes, AdoptPolicy::Always),
        ])
        .await
        .unwrap();
    assert_eq!(st.adopted_sha, None);
    assert_eq!(st.unversioned_count, 0);
    assert!(st.states[0].tracked);
    assert_eq!(st.states[0].head_oid, Some(hex(b"agent\n")));
    assert_eq!(st.states[0].path, cafe);
    assert_eq!(st.states[1].head_oid, Some(hex(b"n\n")));

    // An edit keeps the spelling history has.
    v.write(cafe, b"user edit\n");
    let out = v
        .commit(UserOpKind::Edit, vec![put(cafe, b"user edit\n")])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.items[0].change, ItemChange::Modified);
    assert_eq!(out.items[0].path, cafe);
    assert_eq!(v.head_entry(cafe), Some(blob(b"user edit\n")));
    assert_eq!(v.head_entry("caf\u{e9}.md"), None, "one entry");
    assert_eq!(v.index_blob(cafe), Some(blob(b"user edit\n")));
    // A new file in a decomposed folder joins that folder.
    v.write("note\u{301}s/b.md", b"b\n");
    v.commit(UserOpKind::Create, vec![put("note\u{301}s/b.md", b"b\n")])
        .await
        .unwrap();
    assert_eq!(v.head_entry("note\u{301}s/b.md"), Some(blob(b"b\n")));
    assert_eq!(v.head_entry("not\u{e9}s"), None, "one folder");

    // A delete removes it; a move takes it to its new (NFC) path.
    std::fs::remove_file(v.root.join(cafe)).unwrap();
    let out = v
        .commit(UserOpKind::Delete, vec![remove(cafe)])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.items[0].versioned_reason, None);
    assert_eq!(v.head_entry(cafe), None);
    assert_eq!(v.index_blob(cafe), None);
    std::fs::create_dir_all(v.root.join("archive")).unwrap();
    std::fs::rename(v.root.join(resume), v.root.join("archive").join(resume)).unwrap();
    let out = v
        .commit(
            UserOpKind::Move,
            vec![moved(
                resume,
                &format!("archive/{resume}"),
                Some(blob(b"r\n")),
            )],
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(v.head_entry(resume), None);
    assert_eq!(
        v.head_entry("archive/r\u{e9}sum\u{e9}.md"),
        Some(blob(b"r\n"))
    );
}

// MODULE-003-T63 (AC-36): tree spellings follow `core.precomposeunicode`.
#[tokio::test]
async fn tree_paths_follow_precompose_setting() {
    let nfd = "cafe\u{301}.md";
    let nfc = "caf\u{e9}.md";
    for precompose in [false, true] {
        let v = Vault::configured(&[("keep.md", b"k\n")], |repo| {
            repo.config()
                .unwrap()
                .set_bool("core.precomposeunicode", precompose)
                .unwrap();
        })
        .await;
        v.commit(UserOpKind::Create, vec![put(nfd, b"x\n")])
            .await
            .unwrap();
        let repo = v.repo();
        let tree = repo.head().unwrap().peel_to_tree().unwrap();
        let names: Vec<Vec<u8>> = tree
            .iter()
            .map(|e| e.name_bytes().to_vec())
            .filter(|name| name.starts_with(b"caf"))
            .collect();
        let expected = if precompose { nfc } else { nfd };
        assert_eq!(
            names,
            vec![expected.as_bytes().to_vec()],
            "precompose={precompose}"
        );
    }
}

// ── T71–T72, T74: adoption budgets and abandoned items (R1) ──────────────────────────────

// MODULE-003-T71 (AC-37): content past the byte budget is counted, never hashed.
#[tokio::test]
async fn tree_adopt_respects_byte_budget() {
    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    v.queue.set_lane_test_hooks(LaneTestHooks {
        adopt_budget: Some(AdoptBudget {
            max_bytes: 10_000,
            time: Duration::from_secs(3600),
            clock: None,
        }),
        ..LaneTestHooks::default()
    });
    let content = |tag: u8| vec![tag; 4_000];
    for (name, tag) in [("a", b'a'), ("b", b'b'), ("c", b'c'), ("d", b'd')] {
        v.write(&format!("dir/{name}.bin"), &content(tag));
    }
    let st = v.prepare(vec![tree("dir")]).await.unwrap();
    assert_eq!(
        st.adopted_paths,
        vec!["dir/a.bin".to_string(), "dir/b.bin".to_string()]
    );
    assert_eq!(
        st.unversioned,
        vec!["dir/c.bin".to_string(), "dir/d.bin".to_string()]
    );
    assert_eq!(st.unversioned_count, 2);
    assert_eq!(st.unversioned_bytes, 8_000);
    assert!(st.adopt_incomplete);
    let repo = v.repo();
    let odb = repo.odb().unwrap();
    assert!(odb.exists(blob(&content(b'a'))));
    assert!(!odb.exists(blob(&content(b'c'))), "never hashed into .git");
    assert!(!odb.exists(blob(&content(b'd'))));
    assert_eq!(v.head_entry("dir/c.bin"), None);
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert!(
        !rows
            .iter()
            .any(|e| e.payload["path"] == "dir/c.bin" || e.payload["path"] == "dir/d.bin"),
        "unadopted content is not in the tree diff: {rows:?}"
    );
}

// MODULE-003-T72 (AC-37): the time budget stops adoption in path order (injected clock).
#[tokio::test]
async fn tree_adopt_respects_time_budget() {
    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    let ticks = Arc::new(AtomicU64::new(0));
    {
        let ticks = ticks.clone();
        v.queue.set_lane_test_hooks(LaneTestHooks {
            adopt_budget: Some(AdoptBudget {
                max_bytes: u64::MAX,
                time: Duration::from_secs(5),
                // Every read is 2 s later than the previous one.
                clock: Some(Box::new(move || {
                    Duration::from_secs(2 * ticks.fetch_add(1, Ordering::SeqCst))
                })),
            }),
            ..LaneTestHooks::default()
        });
    }
    for name in ["a", "b", "c", "d", "e"] {
        v.write(&format!("dir/{name}.md"), name.as_bytes());
    }
    let st = v.prepare(vec![tree("dir")]).await.unwrap();
    assert_eq!(
        st.adopted_paths,
        vec!["dir/a.md".to_string(), "dir/b.md".to_string()]
    );
    assert_eq!(
        st.unversioned,
        vec![
            "dir/c.md".to_string(),
            "dir/d.md".to_string(),
            "dir/e.md".to_string()
        ]
    );
    assert_eq!(st.unversioned_count, 3);
    assert!(st.adopt_incomplete);
    assert!(ticks.load(Ordering::SeqCst) >= 4);
}

// MODULE-003-T74 (AC-37): a prepare whose receiver is gone before the worker reaches it is
// skipped with no effects; a `commit_user` whose receiver is gone still commits (its disk
// change already happened; the T75 leg OSS-3 completes).
#[tokio::test]
async fn abandoned_prepare_is_skipped() {
    let v = Vault::with(&[("p.md", b"p0\n"), ("q.md", b"q0\n")]).await;
    v.write("dirty.md", b"uncommitted\n");
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let blocked = AtomicBool::new(false);
    v.queue.set_lane_test_hooks(LaneTestHooks {
        before_ref_cas: Some(Box::new(move |_: &Path| {
            if blocked.swap(true, Ordering::SeqCst) {
                return;
            }
            entered_tx.lock().unwrap().send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
        })),
        ..LaneTestHooks::default()
    });
    // The worker holds a user commit inside its ref compare-and-swap.
    let user = v
        .queue
        .commit_user(request(UserOpKind::Edit, vec![put("p.md", b"p1\n")]));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let abandoned = v.queue.prepare(PrepareRequest {
        targets: vec![file("dirty.md", AdoptPolicy::Always)],
        correlation_id: None,
    });
    drop(abandoned);
    let unanswered = v
        .queue
        .commit_user(request(UserOpKind::Edit, vec![put("q.md", b"q1\n")]));
    drop(unanswered);
    release_tx.send(()).unwrap();
    let out = user.await.unwrap().unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    // Nothing ran for the abandoned prepare; the unanswered commit_user landed right on the
    // first user commit.
    let barrier = v.prepare(vec![]).await.unwrap();
    assert_eq!(barrier.adopted_sha, None);
    let tip = barrier.head_sha.unwrap();
    assert_ne!(Some(tip.clone()), out.sha);
    assert_eq!(v.parent_of(&tip), out.sha);
    assert_eq!(
        first_line(&v.message(&tip)),
        "[user] [user:advance] Edit q.md (+1 −1)"
    );
    assert_eq!(v.head_entry("q.md"), Some(blob(b"q1\n")));
    assert_eq!(v.head_entry("dirty.md"), None);
    let events = v.bus.drain();
    assert!(
        git_commits(&events)
            .iter()
            .all(|e| e.payload.get("op") != Some(&serde_json::json!("adopt"))),
        "abandoned prepare emits no adopt"
    );
    assert!(
        files_changed(&events)
            .iter()
            .all(|e| e.payload["path"] != "dirty.md"),
        "abandoned prepare emits no files.changed for dirty.md"
    );
    // The same prepare, awaited, does adopt.
    let st = v
        .prepare(vec![file("dirty.md", AdoptPolicy::Always)])
        .await
        .unwrap();
    assert!(st.adopted_sha.is_some());
    assert_eq!(v.head_entry("dirty.md"), Some(blob(b"uncommitted\n")));
}

// ── T76–T78: copy and duplicate (R6) ────────────────────────────────────────────────────

// MODULE-003-T76 (AC-38): copies reuse the source blob, one commit each.
#[tokio::test]
async fn copy_file_and_duplicate_reuse_blob() {
    let v = Vault::with(&[("notes/a.md", b"a\n")]).await;
    let a = blob(b"a\n");
    let before = v.head().unwrap().to_string();
    let out = v
        .commit(
            UserOpKind::Copy,
            vec![PathChange::Copy {
                from: path("notes/a.md"),
                to: path("archive/a.md"),
                oid: Some(a.to_string()),
            }],
        )
        .await
        .unwrap();
    let sha = out.sha.clone().unwrap();
    assert_eq!(out.subject, "Copy notes/a.md → archive/");
    assert_eq!(out.label.op, "copy");
    assert_eq!(out.label.change.as_deref(), Some("added"));
    assert!(v.message(&sha).contains("\nAdvance-Change: added\n"));
    assert_eq!(v.parent_of(&sha), Some(before));
    assert_eq!(v.head_entry("archive/a.md"), Some(a));
    assert_eq!(v.head_entry("notes/a.md"), Some(a));
    assert_eq!(out.items[0].change, ItemChange::Added);

    let out = v
        .commit(
            UserOpKind::Copy,
            vec![PathChange::Copy {
                from: path("notes/a.md"),
                to: path("notes/a copy.md"),
                oid: Some(a.to_string()),
            }],
        )
        .await
        .unwrap();
    let second = out.sha.clone().unwrap();
    assert_eq!(out.subject, "Duplicate notes/a.md → notes/a copy.md");
    assert_eq!(v.parent_of(&second), Some(sha));
    assert_eq!(v.head_entry("notes/a copy.md"), Some(a));
}

// MODULE-003-T77 (AC-38): a clean tracked folder's copy reuses its subtree oid.
#[tokio::test]
async fn copy_tree_reuses_clean_subtree_oid() {
    let v = Vault::with(&[
        ("research/q4/a.md", b"a\n"),
        ("research/q4/b.md", b"b\n"),
        ("notes/x.md", b"x\n"),
    ])
    .await;
    let q4 = v.head_entry("research/q4").unwrap();
    let out = v
        .commit(
            UserOpKind::Copy,
            vec![PathChange::CopyTree {
                from: path("research/q4"),
                to: path("archive/q4"),
                oid: Some(q4.to_string()),
            }],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Copy research/q4/ → archive/");
    assert_eq!(v.head_entry("archive/q4"), Some(q4));
    assert_eq!(v.head_entry("research/q4"), Some(q4));
    assert_eq!(v.index_blob("archive/q4/a.md"), Some(blob(b"a\n")));

    let out = v
        .commit(
            UserOpKind::Copy,
            vec![
                PathChange::CopyTree {
                    from: path("research/q4"),
                    to: path("archive2/q4"),
                    oid: Some(q4.to_string()),
                },
                PathChange::Copy {
                    from: path("notes/x.md"),
                    to: path("archive2/x.md"),
                    oid: Some(hex(b"x\n")),
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Copy 2 items → archive2/");
    assert_eq!(v.head_entry("archive2/q4"), Some(q4));
}

// MODULE-003-T78 (AC-38): dirty source content is adopted first; content past the budget is
// copied on disk only and reported unversioned.
#[tokio::test]
async fn copy_dirty_source_adopted_rest_untracked() {
    let v = Vault::with(&[("src/a.md", b"a0\n")]).await;
    v.queue.set_lane_test_hooks(LaneTestHooks {
        adopt_budget: Some(AdoptBudget {
            max_bytes: 4_000,
            time: Duration::from_secs(3600),
            clock: None,
        }),
        ..LaneTestHooks::default()
    });
    let dirty = b"a1 dirty edit\n";
    let big = vec![7u8; 6_000];
    v.write("src/a.md", dirty);
    v.write("src/b.bin", &big);
    let st = v
        .prepare(vec![
            file("src/a.md", AdoptPolicy::Always),
            file("src/b.bin", AdoptPolicy::Always),
        ])
        .await
        .unwrap();
    let adopted = st.adopted_sha.clone().unwrap();
    assert_eq!(st.adopted_paths, vec!["src/a.md".to_string()]);
    assert_eq!(st.unversioned, vec!["src/b.bin".to_string()]);
    assert_eq!(st.unversioned_bytes, 6_000);
    assert!(st.adopt_incomplete);
    assert_eq!(
        first_line(&v.message(&adopted)),
        "[micro] [runtime:adopt] Record uncommitted change to src/a.md"
    );
    assert_eq!(st.states[1].head_oid, None);
    assert_eq!(st.states[1].disk_oid, None);

    v.write("dst/a.md", dirty);
    v.write("dst/b.bin", &big);
    let out = v
        .commit(
            UserOpKind::Copy,
            vec![
                PathChange::Copy {
                    from: path("src/a.md"),
                    to: path("dst/a.md"),
                    oid: st.states[0].head_oid.clone(),
                },
                PathChange::Copy {
                    from: path("src/b.bin"),
                    to: path("dst/b.bin"),
                    oid: st.states[1].head_oid.clone(),
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Copy 2 items → dst/");
    assert!(out.items[0].versioned);
    assert_eq!(out.items[0].oid, Some(hex(dirty)));
    assert!(!out.items[1].versioned);
    assert_eq!(out.items[1].versioned_reason, Some(NotVersioned::Untracked));
    assert_eq!(out.items[1].change, ItemChange::Added);
    assert_eq!(v.head_entry("dst/a.md"), Some(blob(dirty)));
    assert_eq!(v.head_entry("dst/b.bin"), None);
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert!(
        rows.iter()
            .any(|e| e.payload["path"] == "dst/b.bin" && e.payload["versioned"] == "no"),
        "untracked copy emits a versioned:no row: {rows:?}"
    );
}

// R9 (MODULE-003-AC-31): a sidecar the op will write is a prepare target with `Always`, so an
// agent's uncommitted `.meta.yaml` bytes land in the adopt commit, never in the user's.
#[tokio::test]
async fn agent_meta_edit_not_in_user_commit() {
    let v = Vault::with(&[("notes/a.md", b"a0\n"), ("notes/.meta.yaml", b"m0\n")]).await;
    v.write("notes/.meta.yaml", b"m1 written by an agent\n");
    let st = v
        .prepare(vec![
            file("notes/a.md", AdoptPolicy::IfDiskIs(hex(b"a0\n"))),
            PrepareTarget::File {
                path: RepoPath::parse_sidecar("notes/.meta.yaml").unwrap(),
                adopt: AdoptPolicy::Always,
            },
        ])
        .await
        .unwrap();
    let adopted = st.adopted_sha.clone().unwrap();
    assert_eq!(st.adopted_paths, vec!["notes/.meta.yaml".to_string()]);
    assert_eq!(
        v.entry_in(&adopted, "notes/.meta.yaml"),
        Some(blob(b"m1 written by an agent\n"))
    );
    let repo = v.repo();
    let adopt = repo.find_commit(Oid::from_str(&adopted).unwrap()).unwrap();
    assert_eq!(adopt.author().name(), Some("runtime"));

    v.write("notes/a.md", b"a1\n");
    v.write("notes/.meta.yaml", b"m2 by the files core\n");
    let out = v
        .commit(
            UserOpKind::Edit,
            vec![
                put("notes/a.md", b"a1\n"),
                put_sidecar("notes/.meta.yaml", b"m2 by the files core\n"),
            ],
        )
        .await
        .unwrap();
    let sha = out.sha.unwrap();
    assert_eq!(v.parent_of(&sha), Some(adopted));
    assert_eq!(
        v.changed(&sha),
        vec!["notes/.meta.yaml".to_string(), "notes/a.md".to_string()]
    );
    assert_eq!(
        v.entry_in(&sha, "notes/.meta.yaml"),
        Some(blob(b"m2 by the files core\n"))
    );
    let user = repo.find_commit(Oid::from_str(&sha).unwrap()).unwrap();
    assert_eq!(user.author().name(), Some("user:advance"));
}

// MODULE-003-T47 (AC-26): the legacy `submit` refuses `CommitType::User` with
// `InvalidUserOp(OpShape)` before touching the index, makes no commit and emits no
// `git.commit`; the queue keeps serving legacy commits afterwards.
#[tokio::test]
async fn legacy_submit_refuses_user_type() {
    let td = TempDir::new().unwrap();
    let workdir = std::fs::canonicalize(td.path()).unwrap();
    bootstrap_repo_at(&workdir).unwrap();
    std::fs::write(workdir.join("a.md"), b"user bytes").unwrap();

    let bus = Arc::new(CollectingEventBus::new());
    let queue = DefaultGitCommitQueue::spawn_with_event_bus(workdir.clone(), bus.clone()).unwrap();
    let req = CommitRequest::new(
        "advance",
        "Edit a.md",
        vec![PathBuf::from("a.md")],
        CommitType::User,
        "user:advance",
    );
    match queue.submit(req).await.unwrap() {
        Err(GitError::InvalidUserOp {
            reason: UserOpRefusal::OpShape,
            path: None,
        }) => {}
        other => panic!("expected InvalidUserOp(OpShape), got {other:?}"),
    }

    let repo = git2::Repository::open(&workdir).unwrap();
    assert!(
        matches!(repo.head(), Err(e) if e.code() == git2::ErrorCode::UnbornBranch),
        "no commit was made"
    );
    let index = repo.index().unwrap();
    assert!(
        index.get_path(std::path::Path::new("a.md"), 0).is_none(),
        "nothing was staged"
    );
    assert_eq!(bus.len(), 0, "a refused submit emits no git.commit");

    // The worker survives the refusal and keeps committing the legacy lane.
    let req = CommitRequest::new(
        "advance",
        "write a.md",
        vec![PathBuf::from("a.md")],
        CommitType::Turn,
        "agent:advance",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();
    let head = repo.head().unwrap().peel_to_commit().unwrap();
    assert_eq!(head.id(), oid);
    assert!(head
        .message()
        .unwrap()
        .starts_with("[turn] [agent:advance] "));
    // Count only `git.commit`: the files.changed rows that follow a commit are AC-33's.
    let commits = bus
        .drain()
        .into_iter()
        .filter(|e| e.event_type == "git.commit")
        .count();
    assert_eq!(commits, 1);
}

// MODULE-003 §2.5 (AC-35): while the lane policy cannot be applied (here `.git/info/attributes`
// is a symlink, which it never writes through), user-lane items fail with `Policy` and retry it
// first; legacy items proceed. Once the obstacle is gone the next lane item applies it.
#[tokio::test]
async fn lane_policy_failure_blocks_only_lane_items() {
    let td = TempDir::new().unwrap();
    let root = std::fs::canonicalize(td.path()).unwrap();
    bootstrap_repo_at(&root).unwrap();
    let outside = TempDir::new().unwrap();
    let victim = outside.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::fs::create_dir_all(root.join(".git/info")).unwrap();
    let attributes = root.join(".git/info/attributes");
    // Bootstrap applied the policy; replace its file with the obstacle.
    std::fs::remove_file(&attributes).unwrap();
    std::os::unix::fs::symlink(&victim, &attributes).unwrap();
    let queue = DefaultGitCommitQueue::spawn(root.clone()).unwrap();

    let refused = queue
        .commit_user(request(UserOpKind::Create, vec![put("a.md", b"a\n")]))
        .await
        .unwrap();
    match refused {
        Err(GitError::Libgit2 { code, .. }) => assert_eq!(code, "Policy"),
        other => panic!("expected Policy, got {other:?}"),
    }
    let prepared = queue
        .prepare(PrepareRequest {
            targets: vec![],
            correlation_id: None,
        })
        .await
        .unwrap();
    assert!(matches!(prepared, Err(GitError::Libgit2 { ref code, .. }) if code == "Policy"));
    std::fs::write(root.join("b.md"), b"b\n").unwrap();
    let legacy = CommitRequest::new(
        "writer",
        "write",
        vec![PathBuf::from("b.md")],
        CommitType::Turn,
        "agent:writer",
    );
    assert!(queue.submit(legacy).await.unwrap().is_ok());
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");

    std::fs::remove_file(&attributes).unwrap();
    let out = queue
        .commit_user(request(UserOpKind::Create, vec![put("a.md", b"a\n")]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(
        std::fs::read_to_string(&attributes).unwrap(),
        advance_git::LANE_ATTRIBUTES
    );
}

// The runtime's `.gitignore` rides along in the first commit that records the vault (AC-12
// durability, as the legacy lane stages it); it is not one of the user's items.
#[tokio::test]
async fn first_lane_commit_records_the_runtime_gitignore() {
    let v = Vault::with(&[]).await;
    assert_eq!(v.head(), None);
    let out = v
        .commit(UserOpKind::Create, vec![put("a.md", b"a\n")])
        .await
        .unwrap();
    let sha = out.sha.unwrap();
    assert_eq!(
        v.changed(&sha),
        vec![".gitignore".to_string(), "a.md".to_string()]
    );
    assert_eq!(
        v.head_entry(".gitignore"),
        Some(blob(&v.read(".gitignore")))
    );
    assert_eq!(out.items.len(), 1);
    assert_eq!(out.subject, "Create a.md");
    // Later commits leave it alone.
    let out = v
        .commit(UserOpKind::Create, vec![put("b.md", b"b\n")])
        .await
        .unwrap();
    assert_eq!(v.changed(&out.sha.unwrap()), vec!["b.md".to_string()]);
}

// MODULE-003 §1.4.1 "`prepare`" (AC-31): a symlink in a Tree target is recorded as a link blob
// (never followed); an entry that cannot be read is counted as unrecorded content and marks the
// adopt incomplete, without failing the walk.
#[tokio::test]
async fn tree_adopt_records_links_and_counts_unreadable() {
    use std::os::unix::fs::PermissionsExt;
    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    v.write("dir/target.md", b"target\n");
    std::os::unix::fs::symlink("target.md", v.root.join("dir/link")).unwrap();
    v.write("dir/locked.md", b"locked\n");
    let locked = v.root.join("dir/locked.md");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable = std::fs::File::open(&locked).is_err();

    let st = v.prepare(vec![tree("dir")]).await.unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(st.adopted_paths.contains(&"dir/link".to_string()));
    assert!(st.adopted_paths.contains(&"dir/target.md".to_string()));
    let repo = v.repo();
    let tree = repo.head().unwrap().peel_to_tree().unwrap();
    let link = tree.get_path(Path::new("dir/link")).unwrap();
    assert_eq!(link.filemode(), 0o120_000);
    assert_eq!(link.id(), blob(b"target.md"));
    if unreadable {
        assert_eq!(st.unversioned, vec!["dir/locked.md".to_string()]);
        assert!(st.adopt_incomplete);
        assert_eq!(v.head_entry("dir/locked.md"), None);
    }
}

// MODULE-003 §1.4.1 item 2 (AC-27): the legacy lane's index write rides the same lock retry: a
// brief foreign `index.lock` is waited out, a lasting one fails the commit with nothing visible.
#[tokio::test]
async fn legacy_index_write_retries_a_brief_lock() {
    let v = Vault::with(&[("a.md", b"a0\n")]).await;
    let lock = v.root.join(".git/index.lock");
    std::fs::write(&lock, b"held").unwrap();
    let releaser = {
        let lock = lock.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            std::fs::remove_file(lock).unwrap();
        })
    };
    v.write("a.md", b"a1\n");
    let oid = v.legacy(&["a.md"]).await.unwrap();
    releaser.join().unwrap();
    assert_eq!(v.head(), Some(oid));
    assert_eq!(v.head_entry("a.md"), Some(blob(b"a1\n")));

    let tip = v.head();
    std::fs::write(&lock, b"held").unwrap();
    v.write("a.md", b"a2\n");
    let started = Instant::now();
    match v.legacy(&["a.md"]).await {
        Err(GitError::Libgit2 { code, .. }) => assert_eq!(code, "Locked"),
        other => panic!("expected Locked, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(600));
    assert_eq!(v.head(), tip);
    std::fs::remove_file(&lock).unwrap();
}

// MODULE-003 §1.4.1 "`restore`" row (AC-29): a restore names its source. A commit restore
// says `from sha7`; a user version (a `checkpoint/user/*` tag on a lane-signed save-version
// marker) says `from “T”`; an agent checkpoint names it; unknown sources, a `user` checkpoint
// and a `user` tag that is not a lane marker are refused.
#[tokio::test]
async fn restore_sources_resolve_or_refuse() {
    use advance_git::label::{render_message, CommitLabel};
    let v = Vault::with(&[("plan.md", b"v1\n")]).await;
    let first = v.head().unwrap();
    v.write("plan.md", b"v2\n");
    v.legacy(&["plan.md"]).await.unwrap();
    let restore =
        |source: RestoreSource| request(UserOpKind::Restore(source), vec![put("plan.md", b"v1\n")]);

    // An agent checkpoint on the first commit.
    let repo = v.repo();
    let target = repo.find_commit(first).unwrap();
    repo.tag_lightweight("checkpoint/writer/pre-turn", target.as_object(), false)
        .unwrap();
    let out = v
        .queue
        .commit_user(restore(RestoreSource::Checkpoint {
            agent_id: "writer".to_string(),
            label: "pre-turn".to_string(),
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        out.subject,
        format!("Restore plan.md from {}", &first.to_string()[..7])
    );
    assert_eq!(out.label.checkpoint.as_deref(), Some("writer/pre-turn"));
    assert_eq!(out.label.from_sha, Some(first.to_string()));
    assert_eq!(out.label.change.as_deref(), Some("modified"));

    // A user version: a marker commit with the lane's signatures, tagged checkpoint/user/<l>.
    let marker_label = CommitLabel {
        op: "save-version".to_string(),
        count: 0,
        title: Some("Q4 draft".to_string()),
        checkpoint: Some("user/20261015-143210-q4-draft".to_string()),
        ..CommitLabel::default()
    };
    let message = render_message(&marker_label, "user:advance", Some(&provenance())).unwrap();
    let author = Signature::new(
        "user:advance",
        "user@advance-agents",
        &git2::Time::new(1, 0),
    )
    .unwrap();
    let committer =
        Signature::new("runtime", "runtime@advance-agents", &git2::Time::new(1, 0)).unwrap();
    let head = repo.head().unwrap().peel_to_commit().unwrap();
    let marker = repo
        .commit(
            Some("HEAD"),
            &author,
            &committer,
            &message,
            &head.tree().unwrap(),
            &[&head],
        )
        .unwrap();
    repo.tag_lightweight(
        "checkpoint/user/20261015-143210-q4-draft",
        repo.find_commit(marker).unwrap().as_object(),
        false,
    )
    .unwrap();
    v.write("plan.md", b"v3\n");
    v.legacy(&["plan.md"]).await.unwrap();
    let out = v
        .queue
        .commit_user(restore(RestoreSource::Version(
            "20261015-143210-q4-draft".to_string(),
        )))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.subject, "Restore plan.md from “Q4 draft”");
    assert_eq!(out.label.title.as_deref(), Some("Q4 draft"));
    assert_eq!(
        out.label.checkpoint.as_deref(),
        Some("user/20261015-143210-q4-draft")
    );
    assert_eq!(out.label.from_sha, Some(marker.to_string()));
    // The marker's commit, named by sha, lends its title too.
    v.write("plan.md", b"v4\n");
    v.legacy(&["plan.md"]).await.unwrap();
    let out = v
        .queue
        .commit_user(restore(RestoreSource::Commit(marker.to_string())))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.subject, "Restore plan.md from “Q4 draft”");

    // Refusals, before anything is written.
    let tip = v.head();
    repo.tag_lightweight("checkpoint/user/forged", target.as_object(), false)
        .unwrap();
    for (source, reason) in [
        (
            RestoreSource::Commit("0".repeat(40)),
            UserOpRefusal::UnknownRestoreSource,
        ),
        (
            RestoreSource::Commit("not a sha".to_string()),
            UserOpRefusal::UnknownRestoreSource,
        ),
        (
            RestoreSource::Version("missing".to_string()),
            UserOpRefusal::UnknownRestoreSource,
        ),
        (
            RestoreSource::Version("forged".to_string()),
            UserOpRefusal::NotAUserVersion,
        ),
        (
            RestoreSource::Checkpoint {
                agent_id: "USER".to_string(),
                label: "forged".to_string(),
            },
            UserOpRefusal::ReservedNamespace,
        ),
        (
            RestoreSource::Checkpoint {
                agent_id: "writer".to_string(),
                label: "missing".to_string(),
            },
            UserOpRefusal::UnknownRestoreSource,
        ),
    ] {
        let refused = v.queue.commit_user(restore(source)).await.unwrap();
        assert_eq!(refusal(refused), reason);
    }
    assert_eq!(v.head(), tip);
}

// MODULE-003 §1.4.1 "`upload`" row (R5): an upload over a tracked file reads `Replace`; several
// files name their folder and total size.
#[tokio::test]
async fn upload_labels_name_replacements_and_folders() {
    let v = Vault::with(&[("reports/a.pdf", b"old\n")]).await;
    let out = v
        .commit(
            UserOpKind::Upload,
            vec![put("reports/a.pdf", &[1u8; 1_500])],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Replace reports/a.pdf (1.5 KB)");
    assert_eq!(out.label.change.as_deref(), Some("replaced"));
    let out = v
        .commit(
            UserOpKind::Upload,
            vec![
                put("reports/q1/b.pdf", &[2u8; 1_000]),
                put("reports/c.pdf", &[3u8; 2_000]),
            ],
        )
        .await
        .unwrap();
    assert_eq!(out.subject, "Upload 2 items → reports/ (3.0 KB)");
    assert_eq!(out.label.change.as_deref(), Some("added"));
    assert_eq!(out.items.len(), 2);
}

// MODULE-003 §1.4.1 "Threshold" (AC-34, decision part): content over the tracked-size threshold
// is saved but not versioned, and a tracked file of that size leaves the tree; an untracked path
// an ignore rule matches is never staged. (The `.gitignore` auto-entry and its registry come with
// the auto-ignore registry.)
#[tokio::test]
async fn oversize_and_ignored_puts_are_not_versioned() {
    let v = Vault::with(&[("media/demo.mov", &[0u8; 1_024])]).await;
    let big = vec![9u8; 11 * 1024 * 1024];
    let out = v
        .commit(UserOpKind::Edit, vec![put("media/demo.mov", &big)])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Edit media/demo.mov (12 MB, not versioned)");
    assert_eq!(out.label.versioned, Some(false));
    assert!(!out.items[0].versioned);
    assert_eq!(out.items[0].versioned_reason, Some(NotVersioned::TooLarge));
    assert_eq!(out.items[0].oid, None);
    assert_eq!(out.items[0].size, Some(big.len() as u64));
    assert_eq!(out.max_tracked_bytes, 10 * 1024 * 1024);
    assert_eq!(v.head_entry("media/demo.mov"), None, "it left the tree");
    let repo = v.repo();
    assert!(!repo.odb().unwrap().exists(blob(&big)), "never stored");
    assert!(v.gitignore().lines().any(|l| l == "/media/demo.mov"));
    assert!(v.autoignore().lines().any(|l| l == "/media/demo.mov"));

    // An untracked oversize write records the auto-entry (primary `.gitignore` change).
    let out = v
        .commit(UserOpKind::Upload, vec![put("media/raw.mov", &big)])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Upload media/raw.mov (12 MB, not versioned)");
    assert_eq!(v.head_entry("media/raw.mov"), None);
    assert!(v.gitignore().lines().any(|l| l == "/media/raw.mov"));
    assert!(v.autoignore().lines().any(|l| l == "/media/raw.mov"));

    // An untracked path a user rule ignores is not staged.
    let mut ignore = std::fs::read_to_string(v.root.join(".gitignore")).unwrap();
    ignore.push_str("*.log\n");
    std::fs::write(v.root.join(".gitignore"), ignore).unwrap();
    let out = v
        .commit(UserOpKind::Create, vec![put("build/x.log", b"log\n")])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Unchanged);
    assert_eq!(out.items[0].versioned_reason, Some(NotVersioned::Ignored));
    assert_eq!(out.subject, "Create build/x.log (4 B, not versioned)");
    assert_eq!(v.head_entry("build/x.log"), None);
}

// ── OSS-2c: T36, T43, T44, T64, T65, T67, T68, T79 ──────────────────────────────────────

// MODULE-003-T36 (AC-34, AC-28): oversize untracks, re-save is Unchanged, shrink re-tracks.
#[tokio::test]
async fn oversize_untracks_and_shrink_retracks() {
    let v = Vault::with(&[("media/demo.mov", &[0u8; 1_024])]).await;
    let mut ignore = v.gitignore();
    ignore.push_str("/x.md\n");
    std::fs::write(v.root.join(".gitignore"), &ignore).unwrap();
    let big = vec![9u8; 11 * 1024 * 1024];
    let out = v
        .commit(UserOpKind::Edit, vec![put("media/demo.mov", &big)])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.subject, "Edit media/demo.mov (12 MB, not versioned)");
    assert_eq!(out.items[0].versioned_reason, Some(NotVersioned::TooLarge));
    assert_eq!(v.head_entry("media/demo.mov"), None);
    assert!(v.gitignore().lines().any(|l| l == "/media/demo.mov"));
    assert!(v.autoignore().lines().any(|l| l == "/media/demo.mov"));
    assert!(v.gitignore().lines().any(|l| l == "/x.md"));
    v.bus.drain();

    let again = v
        .commit(UserOpKind::Edit, vec![put("media/demo.mov", &big)])
        .await
        .unwrap();
    assert_eq!(again.status, UserCommitStatus::Unchanged);
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert!(
        rows.iter().any(|e| e.payload["path"] == "media/demo.mov"
            && e.payload["versioned"] == "no"
            && e.payload.get("sha").is_none()),
        "re-save emits a sha-less row: {rows:?}"
    );

    let small = vec![1u8; 2 * 1024];
    v.write("media/demo.mov", &small);
    let out = v
        .commit(UserOpKind::Edit, vec![put("media/demo.mov", &small)])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert!(out.items[0].versioned);
    assert_eq!(v.head_entry("media/demo.mov"), Some(blob(&small)));
    assert!(!v.gitignore().lines().any(|l| l == "/media/demo.mov"));
    assert!(!v.autoignore().lines().any(|l| l == "/media/demo.mov"));
    assert!(
        v.gitignore().lines().any(|l| l == "/x.md"),
        "a user-written line not in the registry stays"
    );
}

// MODULE-003-T43 (AC-33): git.commit then files.changed; folder op one dir row; cap 16 + total.
#[tokio::test]
async fn user_lane_events() {
    assert_eq!(FILES_CHANGED_EVENT, "files.changed");
    let v = Vault::with(&[("notes/plan.md", b"one\n")]).await;
    let out = v
        .commit(UserOpKind::Edit, vec![put("notes/plan.md", b"two\n")])
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    let events = v.bus.drain();
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(types.first().copied(), Some("git.commit"));
    assert!(types.iter().any(|t| *t == FILES_CHANGED_EVENT));
    let commits = git_commits(&events);
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].payload["commit_type"], "user");
    assert_eq!(commits[0].payload["op"], "edit");
    let rows = files_changed(&events);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].payload["path"], "notes/plan.md");
    assert_eq!(rows[0].payload["change"], "modified");
    assert_eq!(rows[0].payload["versioned"], "yes");
    assert!(rows[0].payload.get("blob_oid").is_some());
    assert_eq!(rows[0].payload["seq"], 0);
    assert_eq!(rows[0].payload["total"], 1);

    v.write("research/q4/a.md", b"a\n");
    v.legacy(&["research/q4/a.md"]).await.unwrap();
    v.bus.drain();
    std::fs::remove_dir_all(v.root.join("research")).unwrap();
    let out = v
        .commit(
            UserOpKind::Delete,
            vec![PathChange::RemoveTree {
                dir: path("research"),
            }],
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert_eq!(rows.len(), 1, "RemoveTree → one dir row: {rows:?}");
    assert_eq!(rows[0].payload["kind"], "dir");
    assert_eq!(rows[0].payload["path"], "research");
    assert_eq!(rows[0].payload["change"], "deleted");

    let names: Vec<String> = (0..70).map(|i| format!("batch/{i:02}.md")).collect();
    for n in &names {
        v.write(n, b"x\n");
    }
    let paths: Vec<&str> = names.iter().map(String::as_str).collect();
    v.legacy(&paths).await.unwrap();
    v.bus.drain();
    let changes: Vec<PathChange> = names.iter().map(|n| remove(n)).collect();
    v.commit(UserOpKind::Delete, changes).await.unwrap();
    let events = v.bus.drain();
    assert_eq!(
        events.first().map(|e| e.event_type.as_str()),
        Some("git.commit")
    );
    let rows = files_changed(&events);
    assert_eq!(rows.len(), MAX_EVENT_ROWS);
    assert_eq!(
        rows.first().map(|e| &e.payload["total"]),
        Some(&serde_json::json!(70))
    );
    assert_eq!(
        rows.last().map(|e| &e.payload["seq"]),
        Some(&serde_json::json!(15))
    );
}

// MODULE-003-T44 (AC-33): legacy rows from the tree diff (X4/X6).
#[tokio::test]
async fn legacy_commit_emits_rows_from_tree_diff() {
    let v = Vault::with(&[(".meta.yaml", b"m0\n")]).await;
    v.write("a.md", b"a\n");
    v.write(".meta.yaml", b"m1\n");
    v.legacy(&["a.md", ".meta.yaml"]).await.unwrap();
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert_eq!(
        rows.len(),
        1,
        "added a.md + modified sidecar → one row: {rows:?}"
    );
    assert_eq!(rows[0].payload["path"], "a.md");
    assert_eq!(rows[0].payload["change"], "added");

    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    v.write("swept.md", b"left\n");
    {
        let repo = v.repo();
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        index.add_path(Path::new("swept.md")).unwrap();
        index.write().unwrap();
    }
    v.legacy(&["keep.md"]).await.unwrap();
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert!(
        rows.iter().any(|e| e.payload["path"] == "swept.md"),
        "swept leftover gets a row: {rows:?}"
    );
    assert!(
        !rows.iter().any(|e| e.payload["path"] == "keep.md"),
        "unchanged staged path none: {rows:?}"
    );

    let v = Vault::with(&[("keep.md", b"k\n")]).await;
    v.write(".agent/config.yaml", b"agent: ok\n");
    v.write(".agent/_secret.yaml", b"private\n");
    v.legacy(&[".agent/config.yaml", ".agent/_secret.yaml"])
        .await
        .unwrap();
    let events = v.bus.drain();
    let rows = files_changed(&events);
    assert!(
        rows.iter()
            .any(|e| e.payload["path"] == ".agent/config.yaml"),
        "non-_ .agent/** gets a row: {rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|e| e.payload["path"] == ".agent/_secret.yaml"),
        "Private path none: {rows:?}"
    );
}

// MODULE-003-T64 (AC-29): a legacy message cannot forge a trailer block.
#[tokio::test]
async fn legacy_message_cannot_forge_trailers() {
    let v = Vault::with(&[]).await;
    v.write("a.md", b"x\n");
    let sha = v
        .queue
        .submit(CommitRequest::new(
            "writer",
            "x\n\nAdvance-Op: edit\nAdvance-Path: a.md",
            vec![PathBuf::from("a.md")],
            CommitType::Turn,
            "agent:writer",
        ))
        .await
        .unwrap()
        .unwrap();
    let message = v.message(&sha.to_string());
    assert!(
        !message.contains("\nAdvance-Op:"),
        "newlines are flattened so the trailer block cannot form: {message:?}"
    );
    assert_eq!(parse_trailers(&message), None);
    let page = GitHistoryReader::new(v.root.clone())
        .commits(None, 1, &CommitFilter::default())
        .unwrap();
    assert_eq!(page.items[0].label, None);
}

// MODULE-003-T65 (AC-29): out-of-queue commit with trailers but the wrong author.
#[tokio::test]
async fn out_of_queue_commit_with_trailers_gets_no_label() {
    let v = Vault::with(&[("a.md", b"a\n")]).await;
    {
        let repo = v.repo();
        let parent = repo.head().unwrap().peel_to_commit().unwrap();
        let tree = parent.tree().unwrap();
        let author = Signature::now("x", "x@y").unwrap();
        let committer = Signature::now("x", "x@y").unwrap();
        let msg = "[user] [user:x] Edit a.md (+1 −0)\n\nAdvance-Op: edit\nAdvance-Path: a.md\n";
        repo.commit(Some("HEAD"), &author, &committer, msg, &tree, &[&parent])
            .unwrap();
    }
    let page = GitHistoryReader::new(v.root.clone())
        .commits(None, 1, &CommitFilter::default())
        .unwrap();
    assert_eq!(page.items[0].label, None);
    let hist = GitHistoryReader::new(v.root.clone())
        .file_history("a.md")
        .unwrap();
    assert!(hist.items.iter().all(|item| item.label.is_none()));
}

// MODULE-003-T67 (AC-34): after a user auto-ignore, a small agent write re-tracks.
#[tokio::test]
async fn legacy_shrink_retracks_auto_ignored_path() {
    let v = Vault::with(&[("p.bin", &[0u8; 1_024])]).await;
    let big = vec![9u8; 11 * 1024 * 1024];
    v.commit(UserOpKind::Edit, vec![put("p.bin", &big)])
        .await
        .unwrap();
    assert_eq!(v.head_entry("p.bin"), None);
    assert!(v.autoignore().lines().any(|l| l == "/p.bin"));
    let small = vec![1u8; 512];
    v.write("p.bin", &small);
    v.legacy(&["p.bin"]).await.unwrap();
    assert_eq!(v.head_entry("p.bin"), Some(blob(&small)));
    assert!(!v.autoignore().lines().any(|l| l == "/p.bin"));
    assert!(!v.gitignore().lines().any(|l| l == "/p.bin"));
}

// MODULE-003-T68 (AC-34): move rewrites the auto-ignore entry; delete drops it.
#[tokio::test]
async fn move_rewrites_auto_ignore_entry() {
    let v = Vault::with(&[]).await;
    let big = vec![9u8; 11 * 1024 * 1024];
    v.write("a/big.mov", &big);
    v.commit(UserOpKind::Upload, vec![put("a/big.mov", &big)])
        .await
        .unwrap();
    assert!(v.gitignore().lines().any(|l| l == "/a/big.mov"));
    assert!(v.autoignore().lines().any(|l| l == "/a/big.mov"));
    std::fs::create_dir_all(v.root.join("b")).unwrap();
    std::fs::rename(v.root.join("a/big.mov"), v.root.join("b/big.mov")).unwrap();
    v.commit(
        UserOpKind::Move,
        vec![moved("a/big.mov", "b/big.mov", None)],
    )
    .await
    .unwrap();
    assert!(v.gitignore().lines().any(|l| l == "/b/big.mov"));
    assert!(v.autoignore().lines().any(|l| l == "/b/big.mov"));
    assert!(!v.gitignore().lines().any(|l| l == "/a/big.mov"));
    assert!(!v.autoignore().lines().any(|l| l == "/a/big.mov"));
    std::fs::remove_file(v.root.join("b/big.mov")).unwrap();
    v.commit(UserOpKind::Delete, vec![remove("b/big.mov")])
        .await
        .unwrap();
    assert!(!v.gitignore().lines().any(|l| l == "/b/big.mov"));
    assert!(!v.autoignore().lines().any(|l| l == "/b/big.mov"));
}

// MODULE-003-T79 (AC-34, R11): both lanes share effective_max_tracked.
#[tokio::test]
async fn both_lanes_share_tracked_threshold() {
    let v = vault_with_mb(&[], 2).await;
    let three = vec![1u8; 3 * 1024 * 1024];
    v.write("agent.bin", &three);
    v.legacy(&["agent.bin"]).await.unwrap();
    assert_eq!(v.head_entry("agent.bin"), None);
    assert!(v.autoignore().lines().any(|l| l == "/agent.bin"));
    let out = v
        .commit(UserOpKind::Upload, vec![put("user.bin", &three)])
        .await
        .unwrap();
    assert_eq!(out.max_tracked_bytes, 2 * 1024 * 1024);
    assert_eq!(out.items[0].versioned_reason, Some(NotVersioned::TooLarge));
    assert_eq!(v.head_entry("user.bin"), None);

    let v = vault_with_mb(&[("keep.md", b"k\n")], 100).await;
    let out = v
        .commit(UserOpKind::Edit, vec![put("keep.md", b"k2\n")])
        .await
        .unwrap();
    assert_eq!(out.max_tracked_bytes, 64 * 1024 * 1024);
}

// ── T39–T42, T56, T57, T66, T69, T73, T75: save_version / restore_tree (OSS-3) ──

fn index_flags() -> Status {
    Status::INDEX_NEW
        | Status::INDEX_MODIFIED
        | Status::INDEX_DELETED
        | Status::INDEX_RENAMED
        | Status::INDEX_TYPECHANGE
}

// MODULE-003-T39 (AC-30): marker + tag under coord; no files.changed.
#[tokio::test]
async fn save_version_commit_and_tag_atomic() {
    let v = Vault::with(&[("notes/a.md", b"a0\n")]).await;
    let parent = v.head().unwrap();
    let parent_tree = v.repo().find_commit(parent).unwrap().tree_id();
    let out = v.save("Q4 draft", None, false).await.unwrap();
    assert_eq!(out.title, "Q4 draft");
    assert!(out.tag.starts_with("checkpoint/user/"));
    let repo = v.repo();
    let marker = repo.find_commit(Oid::from_str(&out.sha).unwrap()).unwrap();
    assert_eq!(marker.tree_id(), parent_tree);
    assert_eq!(v.head(), Some(marker.id()));
    assert_eq!(v.parent_of(&out.sha), Some(parent.to_string()));
    let tag = repo
        .find_reference(&format!("refs/tags/{}", out.tag))
        .unwrap();
    let peeled = tag.peel_to_commit().unwrap();
    assert_eq!(peeled.id().to_string(), out.sha);
    let annotated = tag.peel_to_tag().unwrap();
    assert_eq!(
        std::str::from_utf8(annotated.message_bytes().unwrap_or(&[]))
            .unwrap()
            .trim(),
        "{}"
    );
    let parsed = parse_trailers(marker.message().unwrap()).unwrap();
    assert_eq!(parsed.op, "save-version");
    assert_eq!(parsed.title.as_deref(), Some("Q4 draft"));
    let list = GitHistoryReader::new(v.root.clone()).checkpoints(Some("user"));
    let hit = list
        .items
        .iter()
        .find(|c| c.label == out.label)
        .expect("user version listed");
    assert_eq!(hit.title.as_deref(), Some("Q4 draft"));
    let events = v.bus.drain();
    let commits = git_commits(&events);
    assert!(commits
        .iter()
        .any(|e| e.payload.get("op") == Some(&serde_json::json!("save-version"))));
    assert!(files_changed(&events).is_empty());
}

// MODULE-003-T40 (AC-30): same-second labels collide case-insensitively.
#[tokio::test]
async fn save_version_label_collision_suffix() {
    let v = Vault::with(&[("a.md", b"a\n")]).await;
    let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let first = v.save_at("Q4 draft", None, false, Some(at)).await.unwrap();
    let second = v.save_at("q4 DRAFT", None, false, Some(at)).await.unwrap();
    assert!(first.label.to_ascii_lowercase().ends_with("-q4-draft"));
    assert!(second.label.to_ascii_lowercase().ends_with("-q4-draft-2"));
    assert_ne!(first.label, second.label);
}

// MODULE-003-T41 (AC-30): generic checkpoint API refuses `user` / `USER`; list stays allowed.
#[tokio::test]
async fn user_namespace_reserved_in_generic_api() {
    let v = Vault::with(&[("a.md", b"a\n")]).await;
    let ncp = DefaultNamedCheckpoint::new(v.root.clone()).unwrap();
    for id in ["user", "USER", "User"] {
        match ncp.create(id, "v1", None) {
            Err(CheckpointError::InvalidLabel { reason, .. }) => {
                assert_eq!(reason, "reserved checkpoint namespace");
            }
            other => panic!("create {id}: {other:?}"),
        }
        match ncp.delete(id, "v1") {
            Err(CheckpointError::InvalidLabel { reason, .. }) => {
                assert_eq!(reason, "reserved checkpoint namespace");
            }
            other => panic!("delete {id}: {other:?}"),
        }
        let rb = DefaultWorkspaceRollback::new(v.root.clone()).unwrap();
        match rb.rollback_to_checkpoint(id, "v1").await {
            Err(RollbackError::InvalidTarget { target, reason }) => {
                assert_eq!(target, "checkpoint/user");
                assert!(reason.contains("forward commits"));
            }
            other => panic!("rollback {id}: {other:?}"),
        }
        match rb
            .rollback(
                id,
                RollbackTarget::Checkpoint("v1".into()),
                RollbackMode::FullDirectory,
            )
            .await
        {
            Err(RollbackError::InvalidTarget { target, reason }) => {
                assert_eq!(target, "checkpoint/user");
                assert!(reason.contains("forward commits"));
            }
            other => panic!("rollback(Checkpoint) {id}: {other:?}"),
        }
        assert!(ncp.list(id).is_ok());
    }
}

// MODULE-003-T42 (AC-32): restore_tree of an agent checkpoint is a forward commit.
#[tokio::test]
async fn restore_checkpoint_commits_forward() {
    let v = Vault::with(&[("a.md", b"a0\n"), ("b.md", b"b0\n")]).await;
    let ncp = DefaultNamedCheckpoint::new(v.root.clone()).unwrap();
    ncp.create("root", "v1", None).unwrap();
    v.write("a.md", b"a1\n");
    v.write("b.md", b"b1\n");
    v.legacy(&["a.md", "b.md"]).await.unwrap();
    v.bus.drain();
    let out = v
        .restore(
            RestoreSource::Checkpoint {
                agent_id: "root".into(),
                label: "v1".into(),
            },
            RestoreScope::CheckpointDomain,
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(
        first_line(&v.message(out.sha.as_deref().unwrap())),
        "[user] [user:advance] Restore checkpoint root/v1 (2 items)"
    );
    assert_eq!(v.read("a.md"), b"a0\n");
    assert_eq!(v.read("b.md"), b"b0\n");
    let repo = v.repo();
    let statuses = repo.statuses(None).unwrap();
    for entry in statuses.iter() {
        assert!(
            !entry.status().intersects(index_flags()),
            "{} still staged: {:?}",
            String::from_utf8_lossy(entry.path_bytes()),
            entry.status()
        );
    }
    let next = v.legacy(&["a.md", "b.md"]).await.unwrap();
    let changed = v.changed(&next.to_string());
    assert!(
        !changed.iter().any(|p| p == "a.md" || p == "b.md"),
        "legacy re-commit of restored paths: {changed:?}"
    );
    let events = v.bus.drain();
    let rollback: Vec<&Event> = events
        .iter()
        .filter(|e| e.event_type == "git.rollback")
        .collect();
    assert_eq!(rollback.len(), 1);
    assert_eq!(
        rollback[0].payload.get("initiator"),
        Some(&serde_json::json!("user:advance"))
    );
}

// MODULE-003-T56 (AC-32): restore adopts dirty state first.
#[tokio::test]
async fn restore_adopts_dirty_state_first() {
    let v = Vault::with(&[("plan.md", b"v1\n")]).await;
    let ver = v.save("keep", None, false).await.unwrap();
    v.write("plan.md", b"dirty\n");
    v.bus.drain();
    let out = v
        .restore(
            RestoreSource::Version(ver.label.clone()),
            RestoreScope::Vault,
        )
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    let adopted = out.adopted_sha.expect("adopt commit");
    assert_eq!(v.entry_in(&adopted, "plan.md"), Some(blob(b"dirty\n")));
    assert_eq!(
        v.parent_of(out.sha.as_deref().unwrap()),
        Some(adopted.clone())
    );
    assert_eq!(v.head_entry("plan.md"), Some(blob(b"v1\n")));
    assert_eq!(v.read("plan.md"), b"v1\n");
}

// MODULE-003-T57 (AC-32): a plan over MAX_RESTORE_PATHS leaves the disk untouched.
#[tokio::test]
async fn restore_plan_validated_before_checkout() {
    let v = Vault::with(&[
        ("notes/a.md", b"a\n"),
        ("notes/b.md", b"b\n"),
        ("notes/c.md", b"c\n"),
    ])
    .await;
    let ver = v.save("three", None, false).await.unwrap();
    let head_before = v.head();
    v.write("notes/a.md", b"A\n");
    v.write("notes/b.md", b"B\n");
    v.write("notes/c.md", b"C\n");
    v.write("notes/extra.md", b"untracked\n");
    let stamp_a = file_stamp(&v.root, "notes/a.md");
    let stamp_b = file_stamp(&v.root, "notes/b.md");
    let stamp_c = file_stamp(&v.root, "notes/c.md");
    let tags_before = v
        .repo()
        .tag_names(Some("checkpoint/user/*"))
        .unwrap()
        .iter()
        .flatten()
        .count();
    v.queue.set_lane_test_hooks(LaneTestHooks {
        max_restore_paths: Some(2),
        ..LaneTestHooks::default()
    });
    let err = v
        .restore(RestoreSource::Version(ver.label), RestoreScope::Vault)
        .await
        .unwrap_err();
    assert_eq!(
        match err {
            GitError::InvalidUserOp { reason, .. } => reason,
            other => panic!("{other:?}"),
        },
        UserOpRefusal::TreeTooLarge
    );
    assert_eq!(v.head(), head_before, "adopt-then-refuse would move HEAD");
    assert_eq!(file_stamp(&v.root, "notes/a.md"), stamp_a);
    assert_eq!(file_stamp(&v.root, "notes/b.md"), stamp_b);
    assert_eq!(file_stamp(&v.root, "notes/c.md"), stamp_c);
    assert_eq!(v.head_entry("notes/extra.md"), None);
    assert_eq!(v.read("notes/extra.md"), b"untracked\n");
    let tags_after = v
        .repo()
        .tag_names(Some("checkpoint/user/*"))
        .unwrap()
        .iter()
        .flatten()
        .count();
    assert_eq!(tags_after, tags_before);
}

// MODULE-003-T66 (AC-30): unborn HEAD refuses unless adopt+paths birth main.
#[tokio::test]
async fn save_version_on_unborn_head_and_adopt() {
    let v = Vault::with(&[]).await;
    assert!(v.head().is_none());
    assert_eq!(
        refusal(v.save("T", None, false).await),
        UserOpRefusal::NothingToVersion
    );
    v.write("notes/a.md", b"hi\n");
    let out = v.save("T", Some(&["notes/a.md"]), true).await.unwrap();
    let adopted_sha = out.adopted_sha.clone().expect("adopt commit");
    assert_ne!(out.sha, adopted_sha);
    assert!(v.head().is_some());
    assert_eq!(v.head_entry("notes/a.md"), Some(blob(b"hi\n")));
    let repo = v.repo();
    let marker = repo.find_commit(Oid::from_str(&out.sha).unwrap()).unwrap();
    let adopt = repo
        .find_commit(Oid::from_str(&adopted_sha).unwrap())
        .unwrap();
    assert_eq!(marker.tree_id(), adopt.tree_id());
    assert_eq!(marker.parent_id(0).unwrap().to_string(), adopted_sha);
    let parsed = parse_trailers(marker.message().unwrap()).unwrap();
    assert_eq!(parsed.op, "save-version");
    assert_eq!(parsed.title.as_deref(), Some("T"));
    let tag = repo
        .find_reference(&format!("refs/tags/{}", out.tag))
        .unwrap();
    assert_eq!(tag.peel_to_commit().unwrap().id().to_string(), out.sha);
    let annotated = tag.peel_to_tag().unwrap();
    assert_eq!(
        std::str::from_utf8(annotated.message_bytes().unwrap_or(&[]))
            .unwrap()
            .trim(),
        r#"{"paths":["notes/a.md"]}"#
    );
}

// MODULE-003-T69 (AC-32): vault restore is not bound by MAX_USER_CHANGES.
#[tokio::test]
async fn restore_vault_scope_beyond_user_change_cap() {
    let files: Vec<(String, Vec<u8>)> = (0..150)
        .map(|i| (format!("f{i:03}.md"), format!("{i}\n").into_bytes()))
        .collect();
    let listed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let v = Vault::with(&listed).await;
    let ver = v.save("many", None, false).await.unwrap();
    for (path, _) in &files {
        v.write(path, b"x\n");
    }
    v.queue.set_lane_test_hooks(LaneTestHooks {
        max_user_changes: Some(100),
        ..LaneTestHooks::default()
    });
    let out = v
        .restore(RestoreSource::Version(ver.label), RestoreScope::Vault)
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.restored_count, 150);
    let sha = out.sha.as_deref().expect("restore sha");
    let changed = v.changed(sha);
    assert_eq!(changed.len(), 150, "{changed:?}");
    assert_eq!(v.parent_of(sha), out.adopted_sha);
    assert_eq!(v.read("f000.md"), b"0\n");
    assert_eq!(v.read("f149.md"), b"149\n");
}

// MODULE-003-T73 (AC-37): save-version adopts tracked dirty + explicit paths only.
#[tokio::test]
async fn save_version_adopts_tracked_changes_and_explicit_paths_only() {
    let v = Vault::with(&[
        ("keep.md", b"k0\n"),
        ("tracked.md", b"t0\n"),
        ("gone.md", b"g0\n"),
    ])
    .await;
    let before = v.head().unwrap().to_string();
    v.write("tracked.md", b"t1\n");
    std::fs::remove_file(v.root.join("gone.md")).unwrap();
    v.write("explicit.md", b"e1\n");
    v.write("other.md", b"o1\n");
    let out = v.save("scope", Some(&["explicit.md"]), true).await.unwrap();
    let adopted = out.adopted_sha.clone().expect("adopt commit");
    assert_eq!(v.entry_in(&before, "gone.md"), Some(blob(b"g0\n")));
    assert_eq!(v.entry_in(&adopted, "gone.md"), None);
    assert_eq!(v.head_entry("tracked.md"), Some(blob(b"t1\n")));
    assert_eq!(v.head_entry("explicit.md"), Some(blob(b"e1\n")));
    assert_eq!(v.head_entry("other.md"), None);
    assert_eq!(v.read("other.md"), b"o1\n");
}

// MODULE-003-T75 (AC-37): abandoned save_version / restore_tree are skipped; commit_user is not.
#[tokio::test]
async fn abandoned_save_version_is_skipped() {
    let v = Vault::with(&[("p.md", b"p0\n"), ("q.md", b"q0\n"), ("r.md", b"r0\n")]).await;
    let ver = v.save("keep", None, false).await.unwrap();
    v.write("dirty.md", b"uncommitted\n");
    v.write("r.md", b"r1\n");
    v.bus.drain();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let release_rx = Mutex::new(release_rx);
    let blocked = AtomicBool::new(false);
    v.queue.set_lane_test_hooks(LaneTestHooks {
        before_ref_cas: Some(Box::new(move |_: &std::path::Path| {
            if blocked.swap(true, Ordering::SeqCst) {
                return;
            }
            entered_tx.lock().unwrap().send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
        })),
        ..LaneTestHooks::default()
    });
    let user = v
        .queue
        .commit_user(request(UserOpKind::Edit, vec![put("p.md", b"p1\n")]));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let abandoned_save = v.queue.save_version(SaveVersionRequest {
        actor: UserActor::from_principal_id("advance"),
        title: "skip".into(),
        paths: None,
        adopt: true,
        at: None,
        correlation_id: None,
        provenance: None,
    });
    drop(abandoned_save);
    let abandoned_restore = v.queue.restore_tree(RestoreTreeRequest {
        actor: UserActor::from_principal_id("advance"),
        source: RestoreSource::Version(ver.label.clone()),
        scope: RestoreScope::Vault,
        correlation_id: None,
        provenance: None,
    });
    drop(abandoned_restore);
    let unanswered = v
        .queue
        .commit_user(request(UserOpKind::Edit, vec![put("q.md", b"q1\n")]));
    drop(unanswered);
    release_tx.send(()).unwrap();
    let out = user.await.unwrap().unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    let barrier = v.prepare(vec![]).await.unwrap();
    let tip = barrier.head_sha.unwrap();
    assert_eq!(v.parent_of(&tip), out.sha);
    assert_eq!(
        first_line(&v.message(&tip)),
        "[user] [user:advance] Edit q.md (+1 −1)"
    );
    assert_eq!(v.head_entry("dirty.md"), None);
    assert_eq!(v.head_entry("r.md"), Some(blob(b"r0\n")));
    let repo = v.repo();
    let tags = repo.tag_names(Some("checkpoint/user/*")).unwrap();
    assert_eq!(tags.iter().flatten().count(), 1);
    let events = v.bus.drain();
    let commits = git_commits(&events);
    assert!(commits
        .iter()
        .all(|e| e.payload.get("op") != Some(&serde_json::json!("save-version"))));
    assert!(commits
        .iter()
        .all(|e| e.payload.get("op") != Some(&serde_json::json!("restore"))));
    let commit_shas: Vec<&str> = commits
        .iter()
        .filter_map(|e| e.payload.get("sha").and_then(|v| v.as_str()))
        .collect();
    for row in files_changed(&events) {
        if let Some(sha) = row.payload.get("sha").and_then(|v| v.as_str()) {
            assert!(
                commit_shas.contains(&sha),
                "files.changed sha {sha} has no matching git.commit"
            );
        }
    }
    assert!(events.iter().all(|e| e.event_type != "git.rollback"));
}

// Exact `MAX_RESTORE_PATHS` plus a later excluded blob / dir must succeed (C1).
#[tokio::test]
async fn restore_exact_path_cap_allows_trailing_excluded() {
    let v = Vault::with(&[
        ("a.md", b"a\n"),
        ("b.md", b"b\n"),
        ("z.sqlite", b"db"),
        ("zz/.meta.yaml", b"m\n"),
    ])
    .await;
    let ver = v.save("cap", None, false).await.unwrap();
    v.write("a.md", b"A\n");
    v.write("b.md", b"B\n");
    v.queue.set_lane_test_hooks(LaneTestHooks {
        max_restore_paths: Some(2),
        ..LaneTestHooks::default()
    });
    let out = v
        .restore(RestoreSource::Version(ver.label), RestoreScope::Vault)
        .await
        .unwrap();
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.restored_count, 2);
    assert_eq!(v.read("a.md"), b"a\n");
    assert_eq!(v.read("b.md"), b"b\n");
}

// Tag failure: WARN + untagged marker; the whole item (including adopt) is silent.
#[tokio::test]
async fn save_version_tag_failure_emits_no_events() {
    let td = TempDir::new().unwrap();
    let root = std::fs::canonicalize(td.path()).unwrap();
    bootstrap_repo_at(&root).unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    let log = Arc::new(LogTap {
        records: Mutex::new(Vec::new()),
    });
    let queue = DefaultGitCommitQueue::spawn_with_config_and_event_bus_and_log(
        root.clone(),
        Arc::new(StaticGitConfigProvider::defaults()),
        bus.clone(),
        log.clone(),
    )
    .unwrap();
    let v = Vault {
        _td: td,
        root,
        queue,
        bus,
    };
    v.write("keep.md", b"k0\n");
    v.legacy(&["keep.md"]).await.unwrap();
    v.write("keep.md", b"k1\n");
    let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let none: [&str; 0] = [];
    let label = version_label("Q4 draft", at, none).unwrap();
    // A file at `refs/tags/checkpoint/user` is not a `user/<label>` version, so
    // label allocation still picks `label`, but `repo.tag("checkpoint/user/…")`
    // cannot create a child of an existing ref.
    let block = v.root.join(".git/refs/tags/checkpoint");
    std::fs::create_dir_all(&block).unwrap();
    std::fs::write(block.join("user"), format!("{}\n", v.head().unwrap())).unwrap();
    v.bus.drain();
    let err = v
        .save_at("Q4 draft", None, true, Some(at))
        .await
        .unwrap_err();
    match err {
        GitError::Libgit2 { .. } => {}
        other => panic!("{other:?}"),
    }
    let head = v.head().expect("untagged marker stays");
    let repo = v.repo();
    let marker = repo.find_commit(head).unwrap();
    let parsed = parse_trailers(marker.message().unwrap()).unwrap();
    assert_eq!(parsed.op, "save-version");
    assert_eq!(v.head_entry("keep.md"), Some(blob(b"k1\n")));
    assert!(v
        .repo()
        .find_reference(&format!("refs/tags/checkpoint/user/{label}"))
        .is_err());
    let events = v.bus.drain();
    assert!(git_commits(&events).is_empty(), "{events:?}");
    assert!(files_changed(&events).is_empty(), "{events:?}");
    let records = log.records.lock().unwrap();
    assert!(
        records.iter().any(|(level, key, fields)| {
            *level == GitLogLevel::Warn
                && *key == "git.user_lane.version_tag_failed"
                && fields
                    .iter()
                    .any(|(k, val)| k == "sha" && val == &head.to_string())
        }),
        "{records:?}"
    );
}
