//! Git-family PR-2 / PR-3 — `GitHistoryReader` over real repositories: status honesty
//! (missing / not_main / unreadable are statuses, never errors), the linear `main` page
//! walk with the queue's prefix parsed, cursor + filter paging, every checkpoint shape
//! (valid `{}`, path-scoped, corrupt JSON → `valid: false`, lightweight → `{}`), the
//! summary counts, and the file-level history + read-at.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_git::history::{self, MAX_PAGE_LIMIT};
use advance_git::{
    bootstrap_repo_at, CommitFilter, CommitRequest, CommitType, DefaultGitCommitQueue,
    DefaultNamedCheckpoint, GitCommitQueue, GitHistoryReader, GitRepoStatus, HistoryError,
    NamedCheckpoint,
};
use git2::{Repository, Signature};
use tempfile::TempDir;

/// A bootstrapped workspace plus its live commit queue.
struct Fixture {
    _td: TempDir,
    root: PathBuf,
    queue: Arc<DefaultGitCommitQueue>,
}

impl Fixture {
    fn new() -> Self {
        let td = TempDir::new().unwrap();
        let root = std::fs::canonicalize(td.path()).unwrap();
        bootstrap_repo_at(&root).unwrap();
        let queue = Arc::new(DefaultGitCommitQueue::spawn(root.clone()).unwrap());
        Self {
            _td: td,
            root,
            queue,
        }
    }

    /// Write `content` to `rel` and commit it through the queue as `agent`.
    async fn write(&self, agent: &str, rel: &str, content: &str, kind: CommitType) -> String {
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        let initiator = match kind {
            CommitType::Turn => format!("agent:{agent}"),
            CommitType::Micro => "runtime:rollback".to_string(),
            CommitType::L6 => "runtime:l6".to_string(),
            CommitType::User => "user:advance".to_string(),
        };
        let req = CommitRequest::new(
            agent,
            format!("write {rel}"),
            vec![PathBuf::from(rel)],
            kind,
            initiator,
        );
        self.queue.submit(req).await.unwrap().unwrap().to_string()
    }

    async fn delete(&self, agent: &str, rel: &str) -> String {
        std::fs::remove_file(self.root.join(rel)).unwrap();
        let req = CommitRequest::new(
            agent,
            format!("delete {rel}"),
            vec![PathBuf::from(rel)],
            CommitType::Turn,
            format!("agent:{agent}"),
        );
        self.queue.submit(req).await.unwrap().unwrap().to_string()
    }

    fn reader(&self) -> GitHistoryReader {
        GitHistoryReader::new(self.root.clone())
    }

    fn repo(&self) -> Repository {
        Repository::open(&self.root).unwrap()
    }
}

/// A raw annotated tag `refs/tags/checkpoint/{agent}/{label}` with an arbitrary message
/// (bypasses `DefaultNamedCheckpoint`'s schema so corrupt messages can be planted).
fn raw_annotated_tag(repo: &Repository, agent: &str, label: &str, message: &str) {
    let head = repo.head().unwrap().peel_to_commit().unwrap();
    let sig = Signature::now("runtime", "runtime@advance-agents").unwrap();
    repo.tag(
        &format!("checkpoint/{agent}/{label}"),
        head.as_object(),
        &sig,
        message,
        false,
    )
    .unwrap();
}

// ── status honesty ──────────────────────────────────────────────────────────────────────

#[test]
fn status_missing_repository_is_a_status_not_an_error() {
    let td = TempDir::new().unwrap();
    let reader = GitHistoryReader::new(td.path().to_path_buf());
    assert_eq!(reader.status(), GitRepoStatus::Missing);
    let summary = reader.summary();
    assert_eq!(summary.status, GitRepoStatus::Missing);
    assert_eq!(summary.head_sha, None);
    assert_eq!(summary.commit_count, None);
    assert_eq!(summary.checkpoint_count, None);
    let page = reader
        .commits(None, 10, &CommitFilter::default())
        .expect("a missing repo is an empty page, not an error");
    assert_eq!(page.repo, GitRepoStatus::Missing);
    assert!(page.items.is_empty());
    assert_eq!(page.next_after, None);
    let list = reader.checkpoints(None);
    assert_eq!(list.repo, GitRepoStatus::Missing);
    assert!(list.items.is_empty());
    let history = reader.file_history("a.md").unwrap();
    assert_eq!(history.repo, GitRepoStatus::Missing);
    assert!(matches!(
        reader.read_file_at("a.md", &"0".repeat(40)),
        Err(HistoryError::Repo(GitRepoStatus::Missing))
    ));
    // A workspace that does not exist at all is `Missing` too (nothing to probe).
    let gone = GitHistoryReader::new(td.path().join("gone"));
    assert_eq!(gone.status(), GitRepoStatus::Missing);
}

#[test]
fn status_not_main_still_reads_main_history() {
    let td = TempDir::new().unwrap();
    let root = td.path().to_path_buf();
    bootstrap_repo_at(&root).unwrap();
    // Seed one commit on main, then move HEAD to a second branch — the layout the
    // runtime refuses to commit on, but whose `main` history is still readable.
    let repo = Repository::open(&root).unwrap();
    std::fs::write(root.join("README.md"), "hello").unwrap();
    let mut idx = repo.index().unwrap();
    idx.add_path(Path::new("README.md")).unwrap();
    idx.write().unwrap();
    let tree = repo.find_tree(idx.write_tree().unwrap()).unwrap();
    let sig = Signature::now("agent:seed", "runtime@advance-agents").unwrap();
    let seed = repo
        .commit(Some("HEAD"), &sig, &sig, "seed", &tree, &[])
        .unwrap();
    let seed_commit = repo.find_commit(seed).unwrap();
    repo.branch("other", &seed_commit, false).unwrap();
    repo.set_head("refs/heads/other").unwrap();
    drop(seed_commit);
    drop(tree);
    drop(repo);

    let reader = GitHistoryReader::new(root.clone());
    let expected = GitRepoStatus::NotMain {
        observed: "refs/heads/other".to_string(),
    };
    assert_eq!(reader.status(), expected);
    let summary = reader.summary();
    assert_eq!(summary.status, expected);
    assert_eq!(summary.head_sha.as_deref(), Some(seed.to_string().as_str()));
    assert_eq!(summary.commit_count, Some(1));
    let page = reader.commits(None, 10, &CommitFilter::default()).unwrap();
    assert_eq!(page.repo, expected);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].subject, "seed");
    assert_eq!(
        page.items[0].commit_type, None,
        "a foreign message has no prefix"
    );
    assert_eq!(page.items[0].agent_id.as_deref(), Some("seed"));
}

#[test]
fn status_unreadable_for_a_broken_gitfile() {
    let td = TempDir::new().unwrap();
    std::fs::write(td.path().join(".git"), "gitdir: /nonexistent/x\n").unwrap();
    let reader = GitHistoryReader::new(td.path().to_path_buf());
    assert!(matches!(reader.status(), GitRepoStatus::Unreadable { .. }));
    let page = reader.commits(None, 10, &CommitFilter::default()).unwrap();
    assert!(matches!(page.repo, GitRepoStatus::Unreadable { .. }));
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn status_ready_unborn_main_is_an_empty_history() {
    let fx = Fixture::new();
    let reader = fx.reader();
    assert_eq!(reader.status(), GitRepoStatus::Ready);
    let summary = reader.summary();
    assert_eq!(summary.status, GitRepoStatus::Ready);
    assert_eq!(summary.head_sha, None);
    assert_eq!(summary.commit_count, Some(0));
    assert_eq!(summary.checkpoint_count, Some(0));
    let page = reader.commits(None, 10, &CommitFilter::default()).unwrap();
    assert_eq!(page.repo, GitRepoStatus::Ready);
    assert!(page.items.is_empty());
    assert_eq!(page.next_after, None);
}

// ── commits ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn commits_walk_main_newest_first_with_the_prefix_parsed() {
    let fx = Fixture::new();
    let first = fx.write("alice", "a.md", "one", CommitType::Turn).await;
    let second = fx.write("bob", "b.md", "two", CommitType::Micro).await;
    let third = fx.write("alice", "c/d.md", "three", CommitType::L6).await;

    let reader = fx.reader();
    let page = reader.commits(None, 10, &CommitFilter::default()).unwrap();
    assert_eq!(page.repo, GitRepoStatus::Ready);
    assert_eq!(page.next_after, None, "three commits fit one page");
    let shas: Vec<&str> = page.items.iter().map(|c| c.sha.as_str()).collect();
    assert_eq!(shas, vec![third.as_str(), second.as_str(), first.as_str()]);

    let newest = &page.items[0];
    assert_eq!(newest.commit_type, Some(CommitType::L6));
    assert_eq!(newest.initiator.as_deref(), Some("runtime:l6"));
    assert_eq!(newest.agent_id.as_deref(), Some("alice"));
    assert_eq!(newest.subject, "write c/d.md");
    assert_eq!(newest.affected_paths_count, 1);
    assert!(newest.committed_at_ms > 1_600_000_000_000);

    let middle = &page.items[1];
    assert_eq!(middle.commit_type, Some(CommitType::Micro));
    assert_eq!(middle.initiator.as_deref(), Some("runtime:rollback"));
    assert_eq!(middle.agent_id.as_deref(), Some("bob"));

    let oldest = &page.items[2];
    assert_eq!(oldest.commit_type, Some(CommitType::Turn));
    assert_eq!(oldest.initiator.as_deref(), Some("agent:alice"));
    // The first commit also records the bootstrap `.gitignore`.
    assert_eq!(oldest.affected_paths_count, 2);

    let summary = reader.summary();
    assert_eq!(summary.head_sha.as_deref(), Some(third.as_str()));
    assert_eq!(summary.commit_count, Some(3));
}

#[tokio::test]
async fn commits_page_with_cursor_and_filters() {
    let fx = Fixture::new();
    let mut shas = Vec::new();
    for i in 0..7 {
        let agent = if i % 2 == 0 { "alice" } else { "bob" };
        let kind = if i == 3 {
            CommitType::L6
        } else {
            CommitType::Turn
        };
        shas.push(fx.write(agent, &format!("f{i}.md"), "x", kind).await);
    }
    shas.reverse(); // newest first
    let reader = fx.reader();

    // Page 1 (3), page 2 (3), page 3 (1, exhausted).
    let p1 = reader.commits(None, 3, &CommitFilter::default()).unwrap();
    assert_eq!(
        p1.items.iter().map(|c| c.sha.clone()).collect::<Vec<_>>(),
        shas[0..3]
    );
    let after = p1.next_after.clone().expect("more pages");
    assert_eq!(after, shas[2]);
    let p2 = reader
        .commits(Some(&after), 3, &CommitFilter::default())
        .unwrap();
    assert_eq!(
        p2.items.iter().map(|c| c.sha.clone()).collect::<Vec<_>>(),
        shas[3..6]
    );
    let after = p2.next_after.clone().expect("one more page");
    let p3 = reader
        .commits(Some(&after), 3, &CommitFilter::default())
        .unwrap();
    assert_eq!(
        p3.items.iter().map(|c| c.sha.clone()).collect::<Vec<_>>(),
        shas[6..7]
    );
    assert_eq!(p3.next_after, None, "exhausted");

    // A page that ends exactly at the oldest commit carries no cursor.
    let exact = reader.commits(None, 7, &CommitFilter::default()).unwrap();
    assert_eq!(exact.items.len(), 7);
    assert_eq!(exact.next_after, None);

    // Filters.
    let alice = reader
        .commits(
            None,
            10,
            &CommitFilter {
                agent_id: Some("alice".into()),
                commit_type: None,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(alice.items.len(), 4);
    assert!(alice
        .items
        .iter()
        .all(|c| c.agent_id.as_deref() == Some("alice")));
    let l6 = reader
        .commits(
            None,
            10,
            &CommitFilter {
                agent_id: None,
                commit_type: Some(CommitType::L6),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(l6.items.len(), 1);
    assert_eq!(l6.items[0].agent_id.as_deref(), Some("bob"));
    let none = reader
        .commits(
            None,
            10,
            &CommitFilter {
                agent_id: Some("carol".into()),
                commit_type: None,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(none.items.is_empty());
    assert_eq!(none.next_after, None);

    // Limit clamps, never refuses.
    let clamped = reader
        .commits(None, MAX_PAGE_LIMIT + 50, &CommitFilter::default())
        .unwrap();
    assert_eq!(clamped.items.len(), 7);
    let defaulted = reader.commits(None, 0, &CommitFilter::default()).unwrap();
    assert_eq!(defaulted.items.len(), 7);

    // Cursor errors are the caller's.
    assert!(matches!(
        reader.commits(Some("nope"), 3, &CommitFilter::default()),
        Err(HistoryError::MalformedSha(_))
    ));
    assert!(matches!(
        reader.commits(Some(&"0".repeat(40)), 3, &CommitFilter::default()),
        Err(HistoryError::UnknownCommit(_))
    ));
}

// ── checkpoints ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn checkpoints_list_every_shape_and_never_drop_corrupt_tags() {
    let fx = Fixture::new();
    let first = fx.write("alice", "a.md", "one", CommitType::Turn).await;
    let second = fx.write("alice", "b.md", "two", CommitType::Turn).await;
    let ncp = DefaultNamedCheckpoint::new(fx.root.clone()).unwrap();
    ncp.create("alice", "full", None).unwrap();
    ncp.create("alice", "scoped", Some(vec![PathBuf::from("a.md")]))
        .unwrap();
    ncp.create("bob", "v1", None).unwrap();
    let repo = fx.repo();
    raw_annotated_tag(&repo, "bob", "corrupt", r#"{"paths":null}"#);
    raw_annotated_tag(&repo, "bob", "extra", r#"{"paths":[],"x":1}"#);
    // Lightweight tag (no tag object): legacy `{}` semantics.
    {
        let head = repo.head().unwrap().peel_to_commit().unwrap();
        repo.tag_lightweight("checkpoint/carol/light", head.as_object(), false)
            .unwrap();
    }
    // An old-style tag on the FIRST commit (not HEAD).
    {
        let old = repo
            .find_commit(git2::Oid::from_str(&first).unwrap())
            .unwrap();
        let sig = Signature::now("runtime", "runtime@advance-agents").unwrap();
        repo.tag("checkpoint/alice/old", old.as_object(), &sig, "{}", false)
            .unwrap();
    }
    drop(repo);

    let reader = fx.reader();
    let list = reader.checkpoints(None);
    assert_eq!(list.repo, GitRepoStatus::Ready);
    let keys: Vec<(String, String)> = list
        .items
        .iter()
        .map(|c| (c.agent_id.clone(), c.label.clone()))
        .collect();
    assert_eq!(
        keys,
        vec![
            ("alice".into(), "full".into()),
            ("alice".into(), "old".into()),
            ("alice".into(), "scoped".into()),
            ("bob".into(), "corrupt".into()),
            ("bob".into(), "extra".into()),
            ("bob".into(), "v1".into()),
            ("carol".into(), "light".into()),
        ],
        "sorted by agent then label; corrupt tags are listed"
    );
    let by_label = |label: &str| list.items.iter().find(|c| c.label == label).unwrap();
    let full = by_label("full");
    assert!(full.valid);
    assert_eq!(full.paths, None);
    assert_eq!(full.sha, second);
    assert!(full.tagged_at_ms > 1_600_000_000_000);
    let scoped = by_label("scoped");
    assert!(scoped.valid);
    assert_eq!(scoped.paths, Some(vec!["a.md".to_string()]));
    let corrupt = by_label("corrupt");
    assert!(!corrupt.valid);
    assert_eq!(corrupt.paths, None);
    assert_eq!(corrupt.sha, second, "the target is still reported");
    assert!(!by_label("extra").valid);
    let light = by_label("light");
    assert!(light.valid, "a lightweight tag reads as `{{}}`");
    assert_eq!(light.paths, None);
    assert_eq!(light.sha, second);
    assert!(light.tagged_at_ms > 1_600_000_000_000);
    assert_eq!(by_label("old").sha, first);

    let alice = reader.checkpoints(Some("alice"));
    assert_eq!(alice.items.len(), 3);
    assert!(alice.items.iter().all(|c| c.agent_id == "alice"));
    assert!(reader.checkpoints(Some("nobody")).items.is_empty());

    let summary = reader.summary();
    assert_eq!(summary.checkpoint_count, Some(7));

    // Inlining by sha.
    let index = history::checkpoints_by_sha(list.items.clone());
    assert_eq!(index.get(&second).map(Vec::len), Some(6));
    assert_eq!(index.get(&first).map(Vec::len), Some(1));
}

// ── file history (PR-3) ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn file_history_and_read_at_follow_one_path() {
    let fx = Fixture::new();
    let v1 = fx
        .write("alice", "notes/a.md", "one", CommitType::Turn)
        .await;
    let _other = fx.write("bob", "b.md", "unrelated", CommitType::Turn).await;
    let v2 = fx
        .write("alice", "notes/a.md", "two", CommitType::Turn)
        .await;
    let gone = fx.delete("alice", "notes/a.md").await;

    let reader = fx.reader();
    let history = reader.file_history("notes/a.md").unwrap();
    assert_eq!(history.repo, GitRepoStatus::Ready);
    assert!(!history.truncated);
    let shas: Vec<(&str, bool)> = history
        .items
        .iter()
        .map(|v| (v.sha.as_str(), v.deleted))
        .collect();
    assert_eq!(
        shas,
        vec![
            (gone.as_str(), true),
            (v2.as_str(), false),
            (v1.as_str(), false)
        ],
        "only the commits that changed the path, newest first"
    );
    assert_eq!(history.items[1].commit_type, Some(CommitType::Turn));
    assert_eq!(history.items[1].agent_id.as_deref(), Some("alice"));
    assert_eq!(history.items[1].subject, "write notes/a.md");

    assert_eq!(
        reader.read_file_at("notes/a.md", &v1).unwrap().bytes,
        b"one"
    );
    assert_eq!(
        reader.read_file_at("notes/a.md", &v2).unwrap().bytes,
        b"two"
    );
    assert!(matches!(
        reader.read_file_at("notes/a.md", &gone),
        Err(HistoryError::PathNotFound { .. })
    ));
    assert!(
        matches!(
            reader.read_file_at("notes", &v2),
            Err(HistoryError::PathNotFound { .. })
        ),
        "a directory is not a blob"
    );
    assert!(matches!(
        reader.read_file_at("notes/a.md", &"0".repeat(40)),
        Err(HistoryError::UnknownCommit(_))
    ));
    assert!(matches!(
        reader.read_file_at("../x", &v2),
        Err(HistoryError::InvalidPath { .. })
    ));
    assert!(matches!(
        reader.file_history(".agent/memory/k.jsonl"),
        Err(HistoryError::InvalidPath { .. })
    ));
    let never = reader.file_history("never.md").unwrap();
    assert!(never.items.is_empty());
}
