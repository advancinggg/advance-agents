//! Integration tests for `.gitignore` handling — MODULE-003 §3.3 T12 (AC-12).

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue,
};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// MODULE-003 §3.3 T12 — AC-12 "Binary files > 10 MB excluded from tracking
// (.gitignore); SQLite files excluded".
// Verifies BOTH halves: static SQLite pattern (bootstrap-installed) AND
// dynamic >10 MiB auto-append (commit-time append_gitignore_entry).
#[tokio::test]
async fn t12_sqlite_static_and_large_binary_autoappend() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    // 20 MiB zero-filled binary — must trigger the auto-append branch.
    let big = vec![0u8; 20 * 1024 * 1024];
    std::fs::write(workdir.join("large.bin"), &big).unwrap();
    // Zero-length SQLite file — matches the static `*.sqlite` pattern.
    std::fs::write(workdir.join("foo.sqlite"), b"").unwrap();
    // 1 MiB small file — must be committed normally.
    std::fs::write(workdir.join("small.md"), b"hello").unwrap();

    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    let req = CommitRequest::new(
        "t12",
        "mixed commit",
        vec![
            PathBuf::from("large.bin"),
            PathBuf::from("foo.sqlite"),
            PathBuf::from("small.md"),
        ],
        CommitType::Turn,
        "agent:t12",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();
    drop(queue);

    // Assertion (1) `.gitignore` contains `/large.bin` (auto-appended).
    let gitignore = std::fs::read_to_string(workdir.join(".gitignore")).unwrap();
    assert!(
        gitignore.lines().any(|l| l.trim() == "/large.bin"),
        ".gitignore should auto-append /large.bin; contents: {gitignore}"
    );

    // Assertion (2) Static patterns present in `.gitignore`.
    for needle in [
        "*.sqlite",
        "*.sqlite-wal",
        "*.sqlite-shm",
        "/.runtime/",
        "/.advance/packs/*/tmp",
    ] {
        assert!(
            gitignore.lines().any(|l| l.trim() == needle),
            ".gitignore should contain static pattern {needle}; contents: {gitignore}"
        );
    }

    // Assertion (3) Commit tree contains `small.md` but NOT `large.bin` or
    // `foo.sqlite`.
    let repo = git2::Repository::open(&workdir).unwrap();
    let commit = repo.find_commit(oid).unwrap();
    let tree = commit.tree().unwrap();
    assert!(
        tree.get_path(Path::new("small.md")).is_ok(),
        "tree must contain small.md"
    );
    assert!(
        tree.get_path(Path::new("large.bin")).is_err(),
        "tree must NOT contain large.bin"
    );
    assert!(
        tree.get_path(Path::new("foo.sqlite")).is_err(),
        "tree must NOT contain foo.sqlite"
    );

    // Assertion (4) status_file for foo.sqlite reports STATUS_IGNORED
    // (covers static-pattern path).
    let status_sqlite = repo.status_file(Path::new("foo.sqlite")).unwrap();
    assert!(
        status_sqlite.contains(git2::Status::IGNORED),
        "foo.sqlite must have Status::IGNORED; got {status_sqlite:?}"
    );

    // Assertion (5) status_file for large.bin reports STATUS_IGNORED
    // (covers dynamic auto-append path — /large.bin line we just wrote).
    let status_bin = repo.status_file(Path::new("large.bin")).unwrap();
    assert!(
        status_bin.contains(git2::Status::IGNORED),
        "large.bin must have Status::IGNORED after auto-append; got {status_bin:?}"
    );
}

// Auxiliary — metacharacter escape in auto-appended gitignore entry. A
// large-binary filename containing glob metachars (`*`, `?`, `[`, `]`) must be
// written as a literal-pattern, not a glob, so it ignores ONLY itself.
#[tokio::test]
async fn aux_gitignore_metacharacter_escape() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    // File name contains `*`, `?`, `[`, `]`. Size > threshold so auto-append fires.
    let tricky_name = "weird*file?[v1].bin";
    let big = vec![0u8; 12 * 1024 * 1024];
    std::fs::write(workdir.join(tricky_name), &big).unwrap();
    // A sibling whose name would be glob-matched by a NAIVE `/weird*...` pattern.
    // Its size is well under the threshold so it'd otherwise be committed.
    let sibling = "weirdORDINARY_v1.bin";
    std::fs::write(workdir.join(sibling), b"x").unwrap();

    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    let req = CommitRequest::new(
        "esc",
        "meta commit",
        vec![PathBuf::from(tricky_name), PathBuf::from(sibling)],
        CommitType::Turn,
        "agent:esc",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();
    drop(queue);

    // The auto-appended .gitignore entry must be an escaped literal.
    let gitignore = std::fs::read_to_string(workdir.join(".gitignore")).unwrap();
    let expected = r"/weird\*file\?\[v1\].bin";
    assert!(
        gitignore.lines().any(|l| l.trim() == expected),
        ".gitignore must have escaped literal for `{tricky_name}`; got:\n{gitignore}"
    );

    // Sibling (an ordinary file smaller than threshold) MUST be in the tree —
    // it would NOT be if the ignore pattern had been written as a glob.
    let repo = git2::Repository::open(&workdir).unwrap();
    let tree = repo.find_commit(oid).unwrap().tree().unwrap();
    assert!(
        tree.get_path(Path::new(sibling)).is_ok(),
        "sibling `{sibling}` must be in the tree — the gitignore literal must not glob-match it"
    );
    assert!(
        tree.get_path(Path::new(tricky_name)).is_err(),
        "the tricky file itself must NOT be in the tree"
    );
}
