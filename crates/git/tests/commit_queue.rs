//! Integration tests for CONTRACT-020 (MODULE-003 §3.3 registry tests T01/T01a/
//! T02/T03, plus auxiliary T-norm).

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue, GitError,
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

// MODULE-003 §3.3 T01 — AC-01 "Commit via git2 only; no subprocess invoked".
#[tokio::test]
async fn t01_commit_via_git2_only_no_subprocess() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    std::fs::write(workdir.join("hello.md"), b"hi").unwrap();

    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    // Absolute path — exercises `normalize_workdir_rel`'s strip-prefix branch.
    let req = CommitRequest::new(
        "tester",
        "first commit",
        vec![workdir.join("hello.md")],
        CommitType::Turn,
        "agent:tester",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();

    // Assertion (1) Positive commit path — git log has the commit via git2.
    let repo = git2::Repository::open(&workdir).unwrap();
    let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
    assert_eq!(head_commit.id(), oid);
    let tree = head_commit.tree().unwrap();
    assert!(tree.get_path(std::path::Path::new("hello.md")).is_ok());

    // Assertion (2) Source-text no-subprocess audit. Scans the crate's four
    // source files for substrings that would indicate subprocess invocation.
    // This is the sound equivalent of "no subprocess invoked" — at runtime we
    // cannot enumerate the null set of system calls the code did not make.
    // Regression-locks AC-01.
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/commit_queue.rs"),
        include_str!("../src/repo.rs"),
        include_str!("../src/error.rs"),
    ];
    for src in &sources {
        assert!(
            !src.contains("std::process"),
            "source must not use std::process"
        );
        assert!(
            !src.contains("Command::new"),
            "source must not invoke Command::new"
        );
        assert!(
            !src.contains("process::Command"),
            "source must not use process::Command"
        );
    }
}

// MODULE-003 §3.3 T01a — AC-02 "Single repo, single main branch; all agent
// writes land on main". Covers both linearity direction (positive) and
// branch-rejection direction (negative) in one test body.
#[tokio::test]
async fn t01a_single_repo_single_branch_multi_agent() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    // --- Linearity direction: 3 commits from distinct agents, all on main. ---
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    let mut oids: Vec<git2::Oid> = Vec::new();
    for (i, agent) in ["a", "b", "c"].iter().enumerate() {
        let fname = format!("agent-{agent}.md");
        std::fs::write(workdir.join(&fname), b"x").unwrap();
        let req = CommitRequest::new(
            *agent,
            format!("commit-{i}"),
            vec![PathBuf::from(fname)],
            CommitType::Turn,
            format!("agent:{agent}"),
        );
        oids.push(queue.submit(req).await.unwrap().unwrap());
    }
    drop(queue);

    {
        let repo = git2::Repository::open(&workdir).unwrap();
        // Only `main` branch exists.
        let branches: Vec<String> = repo
            .branches(Some(git2::BranchType::Local))
            .unwrap()
            .filter_map(|b| b.ok())
            .map(|(branch, _)| branch.name().unwrap().unwrap_or("").to_string())
            .collect();
        assert_eq!(branches, vec!["main".to_string()]);

        // c descends from b descends from a.
        let c = repo.find_commit(oids[2]).unwrap();
        let b = repo.find_commit(oids[1]).unwrap();
        let a = repo.find_commit(oids[0]).unwrap();
        assert_eq!(c.parent_id(0).unwrap(), b.id());
        assert_eq!(b.parent_id(0).unwrap(), a.id());

        // Branch-rejection direction: create `feature-x` via raw git2.
        let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
        repo.branch("feature-x", &head_commit, false).unwrap();
    }

    match bootstrap_repo_at(&workdir) {
        Err(GitError::NotSingleBranch { observed }) => {
            assert_eq!(observed, "refs/heads/feature-x");
        }
        other => panic!("expected NotSingleBranch, got {other:?}"),
    }

    // Remove the branch and re-bootstrap — must succeed.
    {
        let repo = git2::Repository::open(&workdir).unwrap();
        let mut feature = repo
            .find_branch("feature-x", git2::BranchType::Local)
            .unwrap();
        feature.delete().unwrap();
    }
    bootstrap_repo_at(&workdir).unwrap();
}

// MODULE-003 §3.3 T02 — AC-03 "Serialized commit queue: concurrent submits
// produce deterministic ordering". Asserts log order == mpsc enqueue order.
#[tokio::test]
async fn t02_concurrent_commit_determinism() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    let queue = Arc::new(DefaultGitCommitQueue::spawn(workdir.clone()).unwrap());
    let mpsc_order: Arc<std::sync::Mutex<Vec<usize>>> =
        Arc::new(std::sync::Mutex::new(Vec::with_capacity(5)));

    let mut handles = Vec::new();
    for i in 0..5 {
        let queue = queue.clone();
        let workdir = workdir.clone();
        let mpsc_order = mpsc_order.clone();
        handles.push(tokio::spawn(async move {
            let fname = format!("c{i}.md");
            std::fs::write(workdir.join(&fname), b"x").unwrap();
            let req = CommitRequest::new(
                format!("agent-{i}"),
                format!("commit-{i}"),
                vec![PathBuf::from(fname)],
                CommitType::Turn,
                format!("agent:a{i}"),
            );
            // Synchronous enqueue + record-position in a single no-yield section
            // under the current-thread runtime.
            let rx = queue.submit(req);
            mpsc_order.lock().unwrap().push(i);
            rx.await.unwrap().unwrap()
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    drop(queue);

    let expected_bodies: Vec<String> = {
        let order = mpsc_order.lock().unwrap();
        order.iter().map(|i| format!("commit-{i}")).collect()
    };

    let repo = git2::Repository::open(&workdir).unwrap();
    let mut walk = repo.revwalk().unwrap();
    walk.push_head().unwrap();
    walk.set_sorting(git2::Sort::TOPOLOGICAL | git2::Sort::REVERSE)
        .unwrap();
    let oids: Vec<git2::Oid> = walk.map(|r| r.unwrap()).collect();

    assert_eq!(oids.len(), 5, "exactly 5 commits on HEAD");

    // Strictly linear chain: each later entry's single parent is the previous.
    for pair in oids.windows(2) {
        let child = repo.find_commit(pair[1]).unwrap();
        assert_eq!(
            child.parent_id(0).unwrap(),
            pair[0],
            "strictly linear chain"
        );
    }

    let commit_bodies: Vec<String> = oids
        .iter()
        .map(|oid| {
            let c = repo.find_commit(*oid).unwrap();
            let m = c.message().unwrap();
            let (_, rest) = m.split_once("] ").expect("commit_type prefix");
            let (_, body) = rest.split_once("] ").expect("initiator prefix");
            body.to_string()
        })
        .collect();

    // §3.3 T02 expected: "All 5 commits applied in mpsc order".
    assert_eq!(
        commit_bodies, expected_bodies,
        "commits appear in git log in the same order as their mpsc enqueue"
    );
}

// MODULE-003 §3.3 T03 — AC-04 "Each commit carries commit_type + initiator
// metadata". Asserts the exact `[type] [initiator] ` prefix for all 3 variants.
#[tokio::test]
async fn t03_commit_message_prefix_format() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    struct Case {
        name: &'static str,
        ct: CommitType,
        initiator: &'static str,
        expected_prefix: &'static str,
    }
    let cases = [
        Case {
            name: "t3-turn.md",
            ct: CommitType::Turn,
            initiator: "agent:research",
            expected_prefix: "[turn] [agent:research] ",
        },
        Case {
            name: "t3-micro.md",
            ct: CommitType::Micro,
            initiator: "runtime:auto-loop",
            expected_prefix: "[micro] [runtime:auto-loop] ",
        },
        Case {
            name: "t3-l6.md",
            ct: CommitType::L6,
            initiator: "runtime:l6",
            expected_prefix: "[l6] [runtime:l6] ",
        },
    ];

    let mut oids = Vec::new();
    for case in &cases {
        std::fs::write(workdir.join(case.name), b"x").unwrap();
        let req = CommitRequest::new(
            "x",
            format!("body-{}", case.name),
            vec![PathBuf::from(case.name)],
            case.ct,
            case.initiator,
        );
        oids.push((queue.submit(req).await.unwrap().unwrap(), case));
    }
    drop(queue);

    let repo = git2::Repository::open(&workdir).unwrap();
    for (oid, case) in &oids {
        let c = repo.find_commit(*oid).unwrap();
        let m = c.message().unwrap();
        assert!(
            m.starts_with(case.expected_prefix),
            "message {:?} must start with {:?}",
            m,
            case.expected_prefix
        );
    }

    // Sanity: every case's prefix is unique (no collision), covering all 3
    // CommitType variants.
    let prefixes: HashSet<&'static str> = cases.iter().map(|c| c.expected_prefix).collect();
    assert_eq!(prefixes.len(), 3);
}

// Auxiliary — initiator sanitization. Regression-locks the prefix-spoofing
// defense in `sanitize_initiator`. Not a §3.3 registry test.
#[tokio::test]
async fn aux_initiator_sanitization_prevents_prefix_spoof() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    std::fs::write(workdir.join("probe.md"), b"x").unwrap();
    // Malicious initiator trying to close the bracket early and inject a fake
    // `[commit_type]` before the real message body.
    let req = CommitRequest::new(
        "atk",
        "real body",
        vec![PathBuf::from("probe.md")],
        CommitType::Turn,
        "agent:evil] [fake] extra\nnewline\0ctrl",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();
    drop(queue);

    let repo = git2::Repository::open(&workdir).unwrap();
    let msg = repo
        .find_commit(oid)
        .unwrap()
        .message()
        .unwrap()
        .to_string();
    // Prefix must still be exactly `[turn] [<sanitized>] real body` with ALL
    // `]`, newlines, control chars replaced by `_`. No second `[ ]` pair can
    // appear in the sanitized initiator.
    assert!(
        msg.starts_with("[turn] [agent:evil_ _fake_ extra_newline_ctrl] real body"),
        "initiator sanitization failed; got: {msg:?}"
    );
    // No stray `[` or `]` characters inside the sanitized initiator block.
    let (_, rest) = msg.split_once("] ").unwrap();
    let (init, _) = rest.split_once("] ").unwrap();
    let initiator_body = init.trim_start_matches('[');
    assert!(
        !initiator_body.contains('[') && !initiator_body.contains(']'),
        "sanitized initiator must not contain [ or ]; got: {initiator_body:?}"
    );
    // Exactly two `] ` boundaries between prefix and body.
    assert_eq!(
        msg.matches("] ").count(),
        2,
        "must have exactly 2 `] ` separators"
    );
}

// Auxiliary — commit-time single-branch guard. Regression-locks the fix for
// "after bootstrap, a later detach/branch creation is still accepted by the
// queue" diff-review finding. Covers BOTH the HEAD-switched-to-side-branch
// case (a) and the HEAD-still-on-main-but-side-branch-exists case (b).
#[tokio::test]
async fn aux_commit_time_single_branch_guard() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    std::fs::write(workdir.join("first.md"), b"x").unwrap();
    queue
        .submit(CommitRequest::new(
            "a",
            "first",
            vec![PathBuf::from("first.md")],
            CommitType::Turn,
            "agent:a",
        ))
        .await
        .unwrap()
        .unwrap();

    // (a) HEAD switched to a side branch.
    {
        let repo = git2::Repository::open(&workdir).unwrap();
        let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
        repo.branch("feature-x", &head_commit, false).unwrap();
        repo.set_head("refs/heads/feature-x").unwrap();
    }
    std::fs::write(workdir.join("second.md"), b"y").unwrap();
    match queue
        .submit(CommitRequest::new(
            "a",
            "second",
            vec![PathBuf::from("second.md")],
            CommitType::Turn,
            "agent:a",
        ))
        .await
        .unwrap()
    {
        Err(GitError::NotSingleBranch { observed }) => {
            assert_eq!(observed, "refs/heads/feature-x");
        }
        other => panic!("(a) expected NotSingleBranch at commit time, got {other:?}"),
    }

    // (b) HEAD back to main, but feature-x still exists as a side branch.
    {
        let repo = git2::Repository::open(&workdir).unwrap();
        repo.set_head("refs/heads/main").unwrap();
        // Do NOT delete feature-x — we want to verify the branches-iteration
        // check catches co-existing non-main branches even when HEAD is main.
    }
    std::fs::write(workdir.join("third.md"), b"z").unwrap();
    match queue
        .submit(CommitRequest::new(
            "a",
            "third",
            vec![PathBuf::from("third.md")],
            CommitType::Turn,
            "agent:a",
        ))
        .await
        .unwrap()
    {
        Err(GitError::NotSingleBranch { observed }) => {
            assert_eq!(observed, "refs/heads/feature-x");
        }
        other => panic!("(b) expected NotSingleBranch at commit time, got {other:?}"),
    }
}

// Auxiliary — reject filenames with control characters (e.g. newline) at
// .gitignore-write boundary. Regression-locks the fix for "large-binary
// filename with newline could inject extra ignore rules" diff-review finding.
#[cfg(unix)]
#[tokio::test]
async fn aux_gitignore_control_char_rejected() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    // Create a >10 MiB file with a newline in its name (unix only — most FSes
    // accept it, git typically rejects but we're pre-empting at the ignore-
    // write boundary before git sees it).
    let evil_name = "evil\nfile.bin";
    let big = vec![0u8; 12 * 1024 * 1024];
    // Some filesystems still accept newline in filenames via raw OsStr bytes.
    use std::os::unix::ffi::OsStrExt;
    let evil_path = workdir.join(std::ffi::OsStr::from_bytes(evil_name.as_bytes()));
    if std::fs::write(&evil_path, &big).is_err() {
        // Filesystem rejects newline in filename — skip the test rather than
        // false-negative. The defense is still in place for any FS that accepts.
        eprintln!("filesystem rejected newline-in-name, skipping");
        return;
    }

    let req = CommitRequest::new(
        "x",
        "evil commit",
        vec![PathBuf::from(evil_name)],
        CommitType::Turn,
        "agent:x",
    );
    match queue.submit(req).await.unwrap() {
        Err(GitError::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        other => panic!("expected GitError::Io(InvalidInput) for newline-in-name, got {other:?}"),
    }
}

// Auxiliary — agent_id sanitization (parallel to initiator). Regression-locks
// the git-Signature-author-forgery defense.
#[tokio::test]
async fn aux_agent_id_sanitization_prevents_author_spoof() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    std::fs::write(workdir.join("probe.md"), b"x").unwrap();
    // Malicious agent_id with bracket/angle/quote/newline chars that would
    // otherwise break the `author:email<>` git signature syntax or escape
    // the `agent:<id>` author-name prefix.
    let req = CommitRequest::new(
        "evil>alice\n<other@host>\"quoted\"",
        "body",
        vec![PathBuf::from("probe.md")],
        CommitType::Turn,
        "agent:tester",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();
    drop(queue);

    let repo = git2::Repository::open(&workdir).unwrap();
    let commit = repo.find_commit(oid).unwrap();
    let author = commit.author();
    let author_name = author.name().unwrap();
    // Sanitized: each of >, \n, <, >, ", > (and both quotes) replaced with _.
    // "evil>alice\n<other@host>\"quoted\"" →
    //  "evil" "_" "alice" "_" "_" "other@host" "_" "_" "quoted" "_"
    assert_eq!(author_name, "agent:evil_alice__other@host__quoted_");
    // No raw brackets, no angle brackets, no quotes, no newlines in the final author name.
    for c in author_name.chars() {
        assert!(
            !matches!(c, '<' | '>' | '[' | ']' | '"' | '\n' | '\r' | '\0'),
            "author name must not contain metacharacter {c:?}; got {author_name:?}"
        );
    }
}

// Auxiliary — symlink escape defense. Creates a symlink inside workdir pointing
// to an outside directory; submit must reject.
#[cfg(unix)]
#[tokio::test]
async fn aux_symlink_component_escape_rejected() {
    let outside = TempDir::new().unwrap();
    let outside_secret = outside.path().join("secret.md");
    std::fs::write(&outside_secret, b"leaked").unwrap();

    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    // Create a symlink inside workdir pointing at `outside_secret`.
    std::os::unix::fs::symlink(&outside_secret, workdir.join("linked.md")).unwrap();

    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    let req = CommitRequest::new(
        "x",
        "should reject",
        vec![PathBuf::from("linked.md")],
        CommitType::Turn,
        "agent:x",
    );
    match queue.submit(req).await.unwrap() {
        Err(GitError::PathOutsideWorkdir { .. }) => {}
        other => panic!("expected PathOutsideWorkdir for symlink escape, got {other:?}"),
    }
}

// Auxiliary — gitignore durably in commit tree. Regression-locks fix for
// "ensure_gitignore writes but never stages" diff review finding.
#[tokio::test]
async fn aux_gitignore_committed_in_tree() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    std::fs::write(workdir.join("probe.md"), b"x").unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    let req = CommitRequest::new(
        "x",
        "first commit",
        vec![PathBuf::from("probe.md")],
        CommitType::Turn,
        "agent:x",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();
    drop(queue);

    let repo = git2::Repository::open(&workdir).unwrap();
    let tree = repo.find_commit(oid).unwrap().tree().unwrap();
    assert!(
        tree.get_path(std::path::Path::new(".gitignore")).is_ok(),
        ".gitignore must be durably committed into the tree so a fresh clone inherits the AC-12 exclusions"
    );
    // And the committed .gitignore body must contain the static §2.5 patterns.
    let entry = tree.get_path(std::path::Path::new(".gitignore")).unwrap();
    let blob = entry.to_object(&repo).unwrap().into_blob().ok().unwrap();
    let body = std::str::from_utf8(blob.content()).unwrap();
    for needle in ["*.sqlite", "/.runtime/"] {
        assert!(
            body.lines().any(|l| l.trim() == needle),
            "committed .gitignore must include {needle}"
        );
    }
}

// Auxiliary — duplicate-queue rejection. A second spawn on the same repo
// must fail with Io(AlreadyExists). Regression-locks the R1-adversarial
// cross-queue-mutex fix.
#[tokio::test]
async fn aux_duplicate_queue_spawn_rejected() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    let q1 = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    match DefaultGitCommitQueue::spawn(workdir.clone()) {
        Ok(_) => panic!("duplicate spawn must not succeed"),
        Err(GitError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(other) => panic!("expected Io(AlreadyExists), got {other:?}"),
    }
    drop(q1);
    // After drop, the path is free again — spawn should succeed.
    let _q2 = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
}

// Auxiliary — .git/... path self-reference rejected. A caller submitting
// `.git/hooks/post-commit` must get PathOutsideWorkdir.
#[tokio::test]
async fn aux_dotgit_self_reference_rejected() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    // Write an evil hook (not inside .git since we'd need actual .git dir
    // but the test is about REJECTION before any write).
    let evil_paths = [
        PathBuf::from(".git/hooks/post-commit"),
        PathBuf::from(".git/config"),
        PathBuf::from(".GIT/config"), // case-insensitive FS protection
        PathBuf::from("subdir/.git/foo"),
    ];
    for p in evil_paths {
        let req = CommitRequest::new("x", "evil", vec![p.clone()], CommitType::Turn, "agent:x");
        match queue.submit(req).await.unwrap() {
            Err(GitError::PathOutsideWorkdir { .. }) => {}
            other => panic!("expected PathOutsideWorkdir for {p:?}, got {other:?}"),
        }
    }
}

// Auxiliary — symlink pointing INTO .git subtree rejected. A caller submitting
// `innocent.md` whose content is actually a symlink to `.git/config` must be
// rejected because `canonicalize(workdir.join(rel))` resolves into `.git/`.
#[cfg(unix)]
#[tokio::test]
async fn aux_symlink_into_dotgit_rejected() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    // After bootstrap + a first commit, .git/config exists. Plant a symlink
    // `innocent.md -> .git/config`.
    std::fs::write(workdir.join("bootstrap.md"), b"x").unwrap();
    queue
        .submit(CommitRequest::new(
            "x",
            "bootstrap commit to materialize .git/config",
            vec![PathBuf::from("bootstrap.md")],
            CommitType::Turn,
            "agent:x",
        ))
        .await
        .unwrap()
        .unwrap();

    std::os::unix::fs::symlink(workdir.join(".git/config"), workdir.join("innocent.md")).unwrap();
    let req = CommitRequest::new(
        "x",
        "evil",
        vec![PathBuf::from("innocent.md")],
        CommitType::Turn,
        "agent:x",
    );
    match queue.submit(req).await.unwrap() {
        Err(GitError::PathOutsideWorkdir { .. }) => {}
        other => panic!("expected PathOutsideWorkdir for symlink-into-.git, got {other:?}"),
    }
}

// Auxiliary — symlinked .gitignore rejected. A pre-placed symlink at
// workdir/.gitignore must cause bootstrap_repo_at (ensure_gitignore) AND
// per-commit auto-append paths to fail with Io(InvalidInput).
#[cfg(unix)]
#[tokio::test]
async fn aux_gitignore_symlink_rejected() {
    let outside = TempDir::new().unwrap();
    let outside_target = outside.path().join("target.txt");
    std::fs::write(&outside_target, b"victim").unwrap();

    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    // Create the evil symlink BEFORE bootstrap_repo_at.
    std::os::unix::fs::symlink(&outside_target, workdir.join(".gitignore")).unwrap();

    match bootstrap_repo_at(&workdir) {
        Err(GitError::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        other => panic!("bootstrap must reject symlink .gitignore, got {other:?}"),
    }

    // Confirm the outside target was NOT overwritten.
    let preserved = std::fs::read_to_string(&outside_target).unwrap();
    assert_eq!(
        preserved, "victim",
        "symlink target must not be overwritten"
    );
}

// Auxiliary — path-traversal rejection. NOT in §3.3 registry; regression-locks
// the `..` + absolute-outside rejection paths of `normalize_workdir_rel`.
#[tokio::test]
async fn aux_path_normalization_rejects_traversal() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    // (a) Relative path with `..` component → PathOutsideWorkdir.
    let req = CommitRequest::new(
        "x",
        "should reject",
        vec![PathBuf::from("../outside.md")],
        CommitType::Turn,
        "agent:x",
    );
    match queue.submit(req).await.unwrap() {
        Err(GitError::PathOutsideWorkdir { .. }) => {}
        other => panic!("expected PathOutsideWorkdir, got {other:?}"),
    }

    // (b) Absolute path outside workdir → PathOutsideWorkdir.
    let outside = std::env::temp_dir().join("elsewhere-outside.md");
    let req = CommitRequest::new(
        "x",
        "should reject",
        vec![outside.clone()],
        CommitType::Turn,
        "agent:x",
    );
    match queue.submit(req).await.unwrap() {
        Err(GitError::PathOutsideWorkdir { .. }) => {}
        other => panic!("expected PathOutsideWorkdir, got {other:?}"),
    }

    // (c) Nested-but-innocent path → Ok.
    std::fs::create_dir_all(workdir.join("sub")).unwrap();
    std::fs::write(workdir.join("sub/inner.md"), b"x").unwrap();
    let req = CommitRequest::new(
        "x",
        "should pass",
        vec![PathBuf::from("sub/inner.md")],
        CommitType::Turn,
        "agent:x",
    );
    assert!(queue.submit(req).await.unwrap().is_ok());
}

// MODULE-003 §3.5 slice D regression — `do_commit` records a deletion when the
// path no longer exists on disk. Prior behavior errored on the inner
// `add_path` for missing files; the symlink_metadata-based add-vs-remove split
// preserves AC-12 large-file autoignore byte-identically (inner `metadata`
// follows symlinks for size) while letting fs.delete commits land cleanly.
//
// libgit2 contract observed in this test: `git_index_remove_bypath` swallows
// `GIT_ENOTFOUND` for never-tracked paths internally and returns 0; here we
// commit the file first (so it IS tracked) then remove it from disk.
#[tokio::test]
async fn commit_records_deletion_when_path_missing() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    // (1) Write + commit the file so it lands in HEAD's tree.
    std::fs::write(workdir.join("doomed.md"), b"present").unwrap();
    let req = CommitRequest::new(
        "agent-1",
        "write doomed.md",
        vec![PathBuf::from("doomed.md")],
        CommitType::Turn,
        "agent:agent-1",
    );
    queue.submit(req).await.unwrap().unwrap();

    let repo = git2::Repository::open(&workdir).unwrap();
    let head_after_write = repo.head().unwrap().peel_to_commit().unwrap();
    assert!(
        head_after_write
            .tree()
            .unwrap()
            .get_path(std::path::Path::new("doomed.md"))
            .is_ok(),
        "file must be present in tree after the write commit"
    );

    // (2) Remove from disk and submit a delete commit listing the missing path.
    std::fs::remove_file(workdir.join("doomed.md")).unwrap();
    let req = CommitRequest::new(
        "agent-1",
        "delete doomed.md",
        vec![PathBuf::from("doomed.md")],
        CommitType::Turn,
        "agent:agent-1",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();

    // (3) Submit succeeded with a real Oid; HEAD's tree no longer has the file.
    let head_after_delete = repo.find_commit(oid).unwrap();
    assert!(
        head_after_delete
            .tree()
            .unwrap()
            .get_path(std::path::Path::new("doomed.md"))
            .is_err(),
        "file must be absent from tree after the delete commit"
    );

    // (4) Two commits in HEAD history (write + delete). bootstrap_repo_at
    //     does NOT create a commit — it only initializes the repo and writes
    //     .gitignore to disk, which gets folded into the first commit.
    let mut walker = repo.revwalk().unwrap();
    walker.push_head().unwrap();
    let count = walker.count();
    assert_eq!(
        count, 2,
        "expected 2 commits in HEAD history (write + delete)"
    );
}

// MODULE-003 slice D adversarial round 1 regression — `req.message` is
// sanitized at the advance-git boundary so a vpath embedded with structural
// metacharacters cannot forge a fake `[turn] [agent:victim] write secret.md`
// log line in the commit body. Without sanitization, audit-log readers that
// split on newlines would see two attribution rows from one commit, breaking
// AC-04's "agent_id is the source-of-truth attribution" invariant.
#[tokio::test]
async fn aux_message_sanitization_prevents_audit_line_forgery() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    std::fs::write(workdir.join("probe.md"), b"x").unwrap();
    // Hostile message simulating cap-fs's `format!("write {}", vpath)` where
    // `vpath` contains a fake-prefix injection. After sanitization, every
    // `[`, `]`, `<`, `>`, `"`, `\n`, `\r`, `\0` must be replaced with `_`.
    let req = CommitRequest::new(
        "atk",
        "write evil\n[turn] [agent:victim] write secret.md",
        vec![PathBuf::from("probe.md")],
        CommitType::Turn,
        "atk",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();
    drop(queue);

    let repo = git2::Repository::open(&workdir).unwrap();
    let msg = repo
        .find_commit(oid)
        .unwrap()
        .message()
        .unwrap()
        .to_string();
    // No raw newline anywhere in the message body that could split into a
    // forged second log line.
    assert!(
        !msg.contains('\n'),
        "message must not contain a raw newline post-sanitization; got: {msg:?}"
    );
    // No `[` or `]` after the prefix's two bracket pairs (the prefix is `[turn] [atk] `,
    // so total `[`+`]` count must be 4 — the sanitizer replaces the rest with `_`).
    assert_eq!(
        msg.matches('[').count(),
        2,
        "message must contain exactly 2 `[` (the prefix opens); got: {msg:?}"
    );
    assert_eq!(
        msg.matches(']').count(),
        2,
        "message must contain exactly 2 `]` (the prefix closes); got: {msg:?}"
    );
    // The fake `[turn]`/`[agent:victim]` brackets in the body are replaced with `_`.
    assert!(
        msg.contains("_turn_") && msg.contains("_agent:victim_"),
        "structural metacharacters in body must be replaced with `_`; got: {msg:?}"
    );
}

// MODULE-003 §3.5 slice D regression — Mixed path set in a single commit:
// some paths exist on disk (added) and some are missing (removed). The split
// must handle both within one tree write without error.
#[tokio::test]
async fn commit_handles_mixed_present_and_missing_paths() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    // (1) Track two files first.
    std::fs::write(workdir.join("a.md"), b"a").unwrap();
    std::fs::write(workdir.join("b.md"), b"b").unwrap();
    let req = CommitRequest::new(
        "agent-1",
        "seed",
        vec![PathBuf::from("a.md"), PathBuf::from("b.md")],
        CommitType::Turn,
        "agent:agent-1",
    );
    queue.submit(req).await.unwrap().unwrap();

    // (2) Modify a.md, remove b.md from disk, commit BOTH paths in one request.
    std::fs::write(workdir.join("a.md"), b"a-prime").unwrap();
    std::fs::remove_file(workdir.join("b.md")).unwrap();
    let req = CommitRequest::new(
        "agent-1",
        "mixed",
        vec![PathBuf::from("a.md"), PathBuf::from("b.md")],
        CommitType::Turn,
        "agent:agent-1",
    );
    let oid = queue.submit(req).await.unwrap().unwrap();

    let repo = git2::Repository::open(&workdir).unwrap();
    let commit = repo.find_commit(oid).unwrap();
    let tree = commit.tree().unwrap();
    assert!(
        tree.get_path(std::path::Path::new("a.md")).is_ok(),
        "a.md present"
    );
    assert!(
        tree.get_path(std::path::Path::new("b.md")).is_err(),
        "b.md absent"
    );
}

// ── MODULE-003-T26 — git.commit event emission (AC-25, lifecycle-harvest) ──

mod common;
use common::CollectingEventBus;

#[tokio::test]
async fn t26_commit_with_event_bus_emits_complete_redacted_payload() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    std::fs::create_dir_all(workdir.join("notes")).unwrap();
    std::fs::write(workdir.join("notes/a.md"), b"alpha").unwrap();
    std::fs::write(workdir.join("b.md"), b"beta").unwrap();

    let bus = Arc::new(CollectingEventBus::new());
    let queue = DefaultGitCommitQueue::spawn_with_event_bus(workdir.clone(), bus.clone()).unwrap();
    let mut req = CommitRequest::new(
        "tester",
        "turn write",
        // Absolute caller paths — the payload must carry the staged
        // repo-relative forms, never these.
        vec![workdir.join("notes/a.md"), workdir.join("b.md")],
        CommitType::Turn,
        "agent:tester",
    );
    req.correlation_id = Some("corr-1".into());
    let oid = queue.submit(req).await.unwrap().unwrap();

    let events = bus.drain();
    assert_eq!(
        events.len(),
        1,
        "exactly one git.commit per successful commit"
    );
    let e = &events[0];
    assert_eq!(e.event_type, "git.commit");
    assert_eq!(e.agent_id, "tester");
    assert_eq!(e.payload["agent_id"], "tester");
    assert_eq!(e.payload["commit_type"], "turn");
    assert_eq!(e.payload["initiator"], "agent:tester");
    assert_eq!(e.payload["message"], "turn write");
    assert_eq!(e.payload["sha"], oid.to_string());
    assert!(!e.payload["sha"].as_str().unwrap().is_empty());
    assert_eq!(e.payload["correlation_id"], "corr-1");
    let paths: Vec<&str> = e.payload["affected_paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(paths.len(), 2);
    assert!(
        paths.contains(&"notes/a.md"),
        "repo-relative staged path: {paths:?}"
    );
    assert!(
        paths.contains(&"b.md"),
        "repo-relative staged path: {paths:?}"
    );
    for p in &paths {
        assert!(!p.starts_with('/'), "no absolute paths in payload: {p}");
    }
    assert_eq!(e.payload["affected_paths_count"], 2);
    assert_eq!(e.payload["files_changed"], 2);
    // Redaction: the absolute workdir prefix never appears in the dump.
    let dump = serde_json::to_string(&e.payload).unwrap();
    assert!(
        !dump.contains(workdir.to_str().unwrap()),
        "absolute workdir leaked into payload: {dump}"
    );
}

#[tokio::test]
async fn t26_no_bus_and_failure_paths_emit_nothing() {
    // Plain `spawn` (no bus): commit succeeds, nothing to emit (API has no
    // bus to inspect — success of the commit itself is the assertion).
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    std::fs::write(workdir.join("x.md"), b"x").unwrap();
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    let req = CommitRequest::new(
        "tester",
        "m",
        vec![workdir.join("x.md")],
        CommitType::Turn,
        "agent:tester",
    );
    queue.submit(req).await.unwrap().unwrap();
    drop(queue);

    // Bus-wired queue + failing commit (path outside the workdir → typed
    // error): zero events.
    let td2 = TempDir::new().unwrap();
    let workdir2 = td2.path().to_path_buf();
    bootstrap_repo_at(&workdir2).unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    let queue2 =
        DefaultGitCommitQueue::spawn_with_event_bus(workdir2.clone(), bus.clone()).unwrap();
    let req2 = CommitRequest::new(
        "tester",
        "bad",
        vec![PathBuf::from("../outside.md")],
        CommitType::Turn,
        "agent:tester",
    );
    let res = queue2.submit(req2).await.unwrap();
    assert!(res.is_err(), "path traversal must fail the commit");
    assert_eq!(bus.len(), 0, "failed commit emits nothing");
}

#[tokio::test]
async fn t26_event_visible_before_submit_ack_and_micro_type_tagged() {
    // Emit-before-reply ordering: by the time submit().await resolves, the
    // event is observable. Also pins the kebab commit_type for Micro.
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    std::fs::write(workdir.join("s.md"), b"s").unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    let queue = DefaultGitCommitQueue::spawn_with_event_bus(workdir.clone(), bus.clone()).unwrap();
    let req = CommitRequest::new(
        "tester",
        "skill micro",
        vec![workdir.join("s.md")],
        CommitType::Micro,
        "agent:tester",
    );
    queue.submit(req).await.unwrap().unwrap();
    // No sleeps/yields: the ack itself is the ordering guarantee.
    let events = bus.drain();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload["commit_type"], "micro");
}
