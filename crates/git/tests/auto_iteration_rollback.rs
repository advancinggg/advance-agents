//! MODULE-003 Slice F — AC-20 (REQ-076) M003-side verification.
//!
//! Verifies that CONTRACT-021 `WorkspaceRollback` + CONTRACT-022 `NamedCheckpoint`
//! support MODULE-015 AutoLoopDriver's per-iteration checkpoint + rollback
//! protocol (§3.3 T21). M015 caller side is 100% complete (`IterationCheckpoint`
//! / `IterationRollback` wrap these primitives — see
//! `crates/scheduler/auto-loop/tests/checkpoint_rollback.rs`); this file
//! exercises the protocol from the M003 API surface so AC-20's "integration
//! test" Verification cell is satisfied at the M003 boundary.
//!
//! The three trigger scenarios (a) discard / (b) crash / (c) guardrail-fail
//! are *narratively* distinct in M015 but routed through M003's *identical*
//! `WorkspaceRollback::rollback(agent_id, Checkpoint("auto-iter-{n}"),
//! FullDirectory)` call — the M003 surface is trigger-agnostic. The three
//! tests document each scenario explicitly per §3.3 T21's
//! "All three branches restore prior state excluding `.agent/`" requirement.
//!
//! Label format: per M015 §2.11 + M015 §3.8 note 1, libgit2's
//! `Tag::is_valid_name` rejects `:` in ref names, so the on-disk tag uses
//! the hyphen form `auto-iter-{n}` / `auto-baseline`. M015's caller
//! (`iteration_label(n)` in
//! `crates/scheduler/auto-loop/src/checkpoint.rs:24-26`) returns this exact
//! string; the tests below mirror that convention.
//!
//! Per M015 §1.3.4 line 115, the `auto-iter-{n}` tag is created at iter-n
//! start (snapshot of pre-iter-n state). When iter-n is discarded/crashed/
//! guardrail-failed, rollback target is `auto-iter-N` (the just-created tag),
//! NOT `auto-iter-(N-1)` (which would skip the tag and revert two iterations).
//!
//! Test discipline mirrors `collab_os_roundtrip.rs` (T14):
//!  - `DefaultGitCommitQueue::spawn` for the baseline + iteration-work
//!    commits;
//!  - `drop(queue)` before rollback (releases per-repo `ACTIVE_QUEUES`
//!    registration);
//!  - `DefaultNamedCheckpoint::new` for tag creation;
//!  - `DefaultWorkspaceRollback::new` for rollback (uses internal
//!    `NoopEventBus` — event emit observation is AC-07's concern, covered
//!    in `rollback_event_emit.rs`).
//!  - `agent_id = "root"` → ROOT_AGENT_SENTINEL short-circuit at
//!    `rollback.rs:215-237`. When `<workdir>/.agent/` is ABSENT, OR is
//!    present without `.agent/config.yaml`, the resolver returns
//!    `(workdir, "")` so no `.agent/config.yaml` fixture is required.
//!    The `.agent/` exclusion test below relies specifically on the
//!    `.agent/ present / config.yaml absent` branch — if M003 later
//!    tightens the resolver to require `config.yaml` when `.agent/` exists,
//!    that test would fail with a confusing diagnostic.

use std::path::PathBuf;

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, DefaultNamedCheckpoint,
    DefaultWorkspaceRollback, GitCommitQueue, NamedCheckpoint, RollbackMode, RollbackTarget,
    WorkspaceRollback,
};
use git2::Repository;
use tempfile::TempDir;

/// Fixture: bootstrap + baseline-commit `task.md = v1` + create
/// `auto-iter-{n}` checkpoint at the baseline + write the post-checkpoint
/// iter-n work commit content `task.md = v2-iter-{n}-{scenario_label}`.
/// Returns the tempdir (caller owns it; dropping cleans the fs) and the
/// commit queue. Caller drops the queue before invoking rollback so the
/// worker exits and releases the per-repo `ACTIVE_QUEUES` registration.
async fn setup_iteration(n: u32, scenario_label: &str) -> (TempDir, DefaultGitCommitQueue) {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    let agent_id = "root";

    // Baseline state: writable file task.md = v1.
    std::fs::write(workdir.join("task.md"), b"v1").unwrap();
    queue
        .submit(CommitRequest::new(
            agent_id,
            "baseline",
            vec![PathBuf::from("task.md")],
            CommitType::Turn,
            agent_id,
        ))
        .await
        .unwrap()
        .unwrap();

    // Iter-n start (M015 invariant per §1.3.4 — checkpoint BEFORE iteration
    // work). NamedCheckpoint::create with paths=None → tag JSON message
    // `{}` → full-directory checkpoint per §1.4.3.
    let ncp = DefaultNamedCheckpoint::new(workdir.clone()).unwrap();
    ncp.create(agent_id, &format!("auto-iter-{n}"), None)
        .unwrap();

    // Iteration n work — modify task.md (representing the in-progress
    // iteration content that the scenario will discard/crash/guardrail-fail).
    let iter_work_content = format!("v2-iter-{n}-{scenario_label}");
    std::fs::write(workdir.join("task.md"), iter_work_content.as_bytes()).unwrap();
    queue
        .submit(CommitRequest::new(
            agent_id,
            &format!("iter-{n} {scenario_label}"),
            vec![PathBuf::from("task.md")],
            CommitType::Turn,
            agent_id,
        ))
        .await
        .unwrap()
        .unwrap();

    (td, queue)
}

// Scenario (a): M015 evaluates iter-1 → primary metric regressed → status:
// discard → invokes rollback to auto-iter-1 (the pre-iter-1 snapshot).
#[tokio::test]
async fn auto_iter_rollback_on_discard() {
    let (td, queue) = setup_iteration(1, "discard").await;
    let workdir = td.path().to_path_buf();
    drop(queue);

    let rb = DefaultWorkspaceRollback::new(workdir.clone()).unwrap();
    let paths = rb
        .rollback(
            "root",
            RollbackTarget::Checkpoint("auto-iter-1".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect("rollback ok");

    assert!(
        !paths.is_empty(),
        "FullDirectory rollback must return non-empty affected_paths"
    );
    assert_eq!(
        std::fs::read(workdir.join("task.md")).unwrap(),
        b"v1",
        "task.md must be reverted to the pre-iter-1 snapshot (v1)"
    );
}

// Scenario (b): iter-2 crashes mid-turn (panic / process exit / unexpected
// LLM error). M015's iteration-close protocol sets status: crash → invokes
// the same M003 rollback API.
#[tokio::test]
async fn auto_iter_rollback_on_crash() {
    let (td, queue) = setup_iteration(2, "crash").await;
    let workdir = td.path().to_path_buf();
    drop(queue);

    let rb = DefaultWorkspaceRollback::new(workdir.clone()).unwrap();
    let paths = rb
        .rollback(
            "root",
            RollbackTarget::Checkpoint("auto-iter-2".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect("rollback ok");

    assert!(!paths.is_empty());
    assert_eq!(std::fs::read(workdir.join("task.md")).unwrap(), b"v1");
}

// Scenario (c): iter-3 evaluator reports guardrail breach (e.g., cost cap
// exceeded, latency above threshold). Per M015 §1.3.4 iteration-close
// protocol, guardrail failures take the `status = crash` branch (same
// terminal status as scenario (b)'s mid-turn crash) and invoke the same
// M003 rollback API. From M003's perspective scenarios (b) and (c) are
// indistinguishable both at the trigger and the rollback-target level;
// the test exists to document the trigger explicitly per §3.3 T21's
// three-scenario enumeration.
#[tokio::test]
async fn auto_iter_rollback_on_guardrail_fail() {
    let (td, queue) = setup_iteration(3, "guardrail").await;
    let workdir = td.path().to_path_buf();
    drop(queue);

    let rb = DefaultWorkspaceRollback::new(workdir.clone()).unwrap();
    let paths = rb
        .rollback(
            "root",
            RollbackTarget::Checkpoint("auto-iter-3".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect("rollback ok");

    assert!(!paths.is_empty());
    assert_eq!(std::fs::read(workdir.join("task.md")).unwrap(), b"v1");
}

// §3.3 T21 "All three branches restore prior state excluding `.agent/`"
// — the M003-specific invariant. Verified once at the rollback API
// boundary; applies to all three trigger scenarios above by construction
// (FullDirectory expansion filter, AC-15). Uses ROOT_AGENT_SENTINEL
// short-circuit via the `.agent/ present / config.yaml absent` branch
// (see module-level docs above) — this matches M015's
// `rollback_excludes_dot_agent` test pattern.
#[tokio::test]
async fn auto_iter_rollback_excludes_dot_agent() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    let agent_id = "root";
    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();

    // Baseline: BOTH writable (task.md) AND .agent/ (.agent/keep.txt)
    // tracked. The .gitignore installed by bootstrap_repo_at does NOT
    // exclude .agent/ — that's a write-time concern handled by the
    // FullDirectory expansion filter, not by .gitignore.
    std::fs::write(workdir.join("task.md"), b"v1").unwrap();
    std::fs::create_dir_all(workdir.join(".agent")).unwrap();
    std::fs::write(workdir.join(".agent/keep.txt"), b"v1").unwrap();
    queue
        .submit(CommitRequest::new(
            agent_id,
            "baseline",
            vec![PathBuf::from("task.md"), PathBuf::from(".agent/keep.txt")],
            CommitType::Turn,
            agent_id,
        ))
        .await
        .unwrap()
        .unwrap();

    let ncp = DefaultNamedCheckpoint::new(workdir.clone()).unwrap();
    ncp.create(agent_id, "auto-iter-1", None).unwrap();

    // Iter-1 work — modify BOTH.
    std::fs::write(workdir.join("task.md"), b"v2-iter1").unwrap();
    std::fs::write(workdir.join(".agent/keep.txt"), b"v2-iter1").unwrap();
    queue
        .submit(CommitRequest::new(
            agent_id,
            "iter-1 work",
            vec![PathBuf::from("task.md"), PathBuf::from(".agent/keep.txt")],
            CommitType::Turn,
            agent_id,
        ))
        .await
        .unwrap()
        .unwrap();

    drop(queue);

    let rb = DefaultWorkspaceRollback::new(workdir.clone()).unwrap();
    let paths = rb
        .rollback(
            "root",
            RollbackTarget::Checkpoint("auto-iter-1".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect("rollback ok");

    // task.md MUST be present in `paths` (FullDirectory walk picked it
    // up); .agent/keep.txt MUST NOT appear (filtered out by
    // is_excluded_from_writable_domain's `.agent/` branch — §3.8 +
    // AC-15). Returned paths are workdir-relative `PathBuf`s.
    assert!(
        paths.iter().any(|p| p.ends_with("task.md")),
        "FullDirectory rollback must restore task.md; got {:?}",
        paths
    );
    assert!(
        !paths
            .iter()
            .any(|p| p.to_string_lossy().contains(".agent/")),
        ".agent/ paths must be filtered from affected_paths; got {:?}",
        paths
    );

    assert_eq!(
        std::fs::read(workdir.join("task.md")).unwrap(),
        b"v1",
        "task.md must be rolled back to baseline"
    );
    assert_eq!(
        std::fs::read(workdir.join(".agent/keep.txt")).unwrap(),
        b"v2-iter1",
        ".agent/ MUST survive rollback (FullDirectory exclusion)"
    );
}

// M015 calls `NamedCheckpoint::create(agent_id, "auto-iter-{n}", None)`.
// The resulting tag MUST: (a) carry JSON message `{}` (full-directory
// checkpoint per §1.4.3), AND (b) point at HEAD (the iter-start commit)
// — both are properties M015's `IterationRollback` assumes when calling
// back with FullDirectory mode. Mirrors T14's tag-points-to-commit
// invariant in `collab_os_roundtrip.rs:101-110`.
#[tokio::test]
async fn auto_iter_checkpoint_tag_format_is_full_directory() {
    let td = TempDir::new().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    let queue = DefaultGitCommitQueue::spawn(workdir.clone()).unwrap();
    std::fs::write(workdir.join("seed.md"), b"x").unwrap();
    let seed_oid = queue
        .submit(CommitRequest::new(
            "root",
            "seed",
            vec![PathBuf::from("seed.md")],
            CommitType::Turn,
            "root",
        ))
        .await
        .unwrap()
        .unwrap();
    drop(queue);

    let ncp = DefaultNamedCheckpoint::new(workdir.clone()).unwrap();
    ncp.create("root", "auto-iter-1", None).unwrap();

    let repo = Repository::open(&workdir).unwrap();
    let tag_ref = repo
        .find_reference("refs/tags/checkpoint/root/auto-iter-1")
        .expect("auto-iter-1 tag exists");

    // (a) Tag message `{}` — full-directory marker per §1.4.3.
    let tag_obj = tag_ref.peel(git2::ObjectType::Tag).unwrap();
    let tag = tag_obj.as_tag().expect("annotated tag");
    assert_eq!(
        tag.message().unwrap_or("").trim(),
        "{}",
        "auto-iter-{{n}} tag must carry empty JSON object (full-directory)"
    );

    // (b) Tag points at HEAD = the iter-start (seed) commit.
    let tag_commit = tag_ref.peel_to_commit().unwrap();
    assert_eq!(
        tag_commit.id(),
        seed_oid,
        "auto-iter-{{n}} tag must point at the iteration-start HEAD commit"
    );
}
