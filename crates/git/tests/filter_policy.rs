//! MODULE-003-T58 (AC-35, R12): the user lane's repository policy is applied at bootstrap and
//! when the commit worker starts, and neutralizes `core.autocrlf` and the vault's
//! `.gitattributes` for every writer: legacy agent commits, user-lane commits, `prepare` and
//! rollback checkouts store and write the exact bytes.

use advance_git::{
    bootstrap_repo_at, AdoptPolicy, BlobSource, ChangeRole, CommitRequest, CommitType,
    DefaultGitCommitQueue, DefaultWorkspaceRollback, GitCommitQueue, PathChange, PrepareRequest,
    PrepareTarget, RepoPath, RollbackMode, RollbackTarget, UserActor, UserCommitLane,
    UserCommitRequest, UserCommitStatus, UserOpKind, WorkspaceRollback, LANE_ATTRIBUTES,
};
use git2::{ConfigLevel, ObjectType, Oid, Repository, Status, StatusOptions};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn blob(bytes: &[u8]) -> Oid {
    Oid::hash_object(ObjectType::Blob, bytes).unwrap()
}

fn head_blob(root: &Path, path: &str) -> Oid {
    let repo = Repository::open(root).unwrap();
    let tree = repo.head().unwrap().peel_to_tree().unwrap();
    tree.get_path(Path::new(path)).unwrap().id()
}

fn head_bytes(root: &Path, path: &str) -> Vec<u8> {
    let repo = Repository::open(root).unwrap();
    let id = head_blob(root, path);
    let content = repo.find_blob(id).unwrap().content().to_vec();
    content
}

/// The status of `path` as a full `statuses()` run reports it (`CURRENT` when absent).
fn status_of(root: &Path, path: &str) -> Status {
    let repo = Repository::open(root).unwrap();
    let mut opts = StatusOptions::new();
    opts.include_untracked(true);
    let statuses = repo.statuses(Some(&mut opts)).unwrap();
    statuses
        .iter()
        .find(|entry| entry.path() == Some(path))
        .map_or(Status::CURRENT, |entry| entry.status())
}

async fn legacy(queue: &DefaultGitCommitQueue, paths: &[&str]) -> Oid {
    let req = CommitRequest::new(
        "writer",
        "write",
        paths.iter().map(PathBuf::from).collect(),
        CommitType::Turn,
        "agent:writer",
    );
    queue.submit(req).await.unwrap().unwrap()
}

async fn adopts_nothing(queue: &DefaultGitCommitQueue, path: &str, bytes: &[u8]) {
    let st = queue
        .prepare(PrepareRequest {
            targets: vec![PrepareTarget::File {
                path: RepoPath::parse(path).unwrap(),
                adopt: AdoptPolicy::IfDiskIs(blob(bytes).to_string()),
            }],
            correlation_id: None,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st.adopted_sha, None, "no spurious adopt of {path}");
    assert_eq!(st.states[0].disk_oid, Some(blob(bytes).to_string()));
    assert_eq!(st.states[0].head_oid, Some(blob(bytes).to_string()));
}

// MODULE-003-T58 (AC-35): filter-free in both lanes and in checkouts, whatever `autocrlf` and
// `.gitattributes` say.
#[tokio::test]
async fn filter_policy_neutralizes_autocrlf_and_gitattributes() {
    let td = TempDir::new().unwrap();
    let root = std::fs::canonicalize(td.path()).unwrap();
    let attributes = root.join(".git/info/attributes");
    let local = || {
        Repository::open(&root)
            .unwrap()
            .config()
            .unwrap()
            .open_level(ConfigLevel::Local)
            .unwrap()
    };
    // Bootstrap applies the policy before any queue serves the vault.
    bootstrap_repo_at(&root).unwrap();
    assert_eq!(
        std::fs::read_to_string(&attributes).unwrap(),
        LANE_ATTRIBUTES
    );
    assert!(!local().get_bool("core.autocrlf").unwrap());
    // So does the worker at start: drift from before the spawn is repaired.
    std::fs::remove_file(&attributes).unwrap();
    local().set_bool("core.autocrlf", true).unwrap();
    let queue = DefaultGitCommitQueue::spawn(root.clone()).unwrap();
    // A barrier item: by the time it answers, the worker has applied the policy.
    queue
        .prepare(PrepareRequest {
            targets: vec![],
            correlation_id: None,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&attributes).unwrap(),
        LANE_ATTRIBUTES
    );
    assert!(!local().get_bool("core.autocrlf").unwrap());

    // After the policy, the operator turns conversion on, and the vault asks for CRLF and
    // ident expansion.
    local().set_str("core.autocrlf", "input").unwrap();
    std::fs::write(root.join(".gitattributes"), "* text eol=crlf\n*.md ident\n").unwrap();
    legacy(&queue, &[".gitattributes"]).await;

    // Agent lane (R12): a CRLF file with an ident marker is stored byte for byte.
    let crlf = b"line one\r\nline two $Id$\r\n";
    std::fs::write(root.join("doc.md"), crlf).unwrap();
    let first = legacy(&queue, &["doc.md"]).await;
    assert_eq!(head_bytes(&root, "doc.md"), crlf);
    assert_eq!(head_blob(&root, "doc.md"), blob(crlf));
    // `prepare` hashes the disk exactly as the agent lane stored it: nothing to adopt.
    adopts_nothing(&queue, "doc.md", crlf).await;

    // A generic rollback checkout writes the exact blob bytes (no CRLF or ident smudge).
    std::fs::write(root.join("doc.md"), b"changed\n").unwrap();
    legacy(&queue, &["doc.md"]).await;
    DefaultWorkspaceRollback::new(root.clone())
        .unwrap()
        .rollback(
            "root",
            RollbackTarget::Commit(first.to_string()),
            RollbackMode::PathScoped(vec![PathBuf::from("doc.md")]),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(root.join("doc.md")).unwrap(), crlf);
    legacy(&queue, &["doc.md"]).await;
    assert_eq!(head_bytes(&root, "doc.md"), crlf);

    // No flip-flop over alternating agent and user commits: each stores what was written and
    // leaves the file clean.
    for round in 0..3u8 {
        let agent = format!("agent round {round}\r\nkeeps CRLF $Id$\r\n").into_bytes();
        std::fs::write(root.join("doc.md"), &agent).unwrap();
        legacy(&queue, &["doc.md"]).await;
        assert_eq!(head_bytes(&root, "doc.md"), agent);
        assert_eq!(status_of(&root, "doc.md"), Status::CURRENT);
        adopts_nothing(&queue, "doc.md", &agent).await;

        let user = format!("user round {round}\r\nalso CRLF\r\n").into_bytes();
        std::fs::write(root.join("doc.md"), &user).unwrap();
        let out = queue
            .commit_user(UserCommitRequest {
                actor: UserActor::from_principal_id("advance"),
                op: UserOpKind::Edit,
                changes: vec![PathChange::Put {
                    path: RepoPath::parse("doc.md").unwrap(),
                    content: BlobSource::Bytes(user.clone()),
                    role: ChangeRole::Primary,
                    executable: None,
                    stat: None,
                }],
                correlation_id: None,
                provenance: None,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(out.status, UserCommitStatus::Committed);
        assert_eq!(head_bytes(&root, "doc.md"), user);
        assert_eq!(status_of(&root, "doc.md"), Status::CURRENT);
        adopts_nothing(&queue, "doc.md", &user).await;
    }
}
