//! Track C — SYS-J-51 (named checkpoint) witness over the REAL `advance_git`
//! providers.
//!
//! Witnesses **SYS-AC-162, SYS-AC-163, SYS-AC-164, SYS-AC-240** by driving the
//! production `DefaultNamedCheckpoint` (`NamedCheckpoint::create`) and
//! `DefaultWorkspaceRollback` (`WorkspaceRollback::rollback_to_checkpoint`)
//! against a self-built temp Git repository — NO module in the chain is
//! mocked/stubbed; the only test-owned object is the `EventBusEmit` sink, which
//! is the production-typed observation seam (exactly the `sys_j47` /
//! `rollback_event_emit.rs` discipline — the harness exposes no accessor to the
//! bus it wires into these directly-constructed providers, so the captured
//! events MUST be asserted on this in-file sink, never `assert_db_event`, which
//! reads a different bus).
//!
//! **This is a REAL-PROVIDER witness, not a guest turn.** The guest→host
//! checkpoint/rollback host-fn loop is upstream-blocked (the harness's
//! multi-agent guest loop has no reply leg — see `mode_agents_smoke.rs` +
//! crate README "HF fast-follow blockers"). Per that HF-sanctioned mode, the
//! accepted Track-C witness bar is to drive the real provider struct/fn
//! DIRECTLY over a real Git workspace. The git provider operates on any
//! bootstrapped repo path, so no `SystemUnderTest` is needed (the same
//! standalone-repo setup the J-50 rollback test uses; mirrors the in-crate
//! `rollback_checkpoint_integration.rs`).
//!
//! Setup (per the J-50/J-51 design): `bootstrap_repo_at(tmp)` leaves an UNBORN
//! HEAD (0 commits) — a checkpoint on an unborn branch returns
//! `CheckpointError::InvalidState` (`checkpoint.rs:144-150`), so every test
//! seeds >=1 commit first and writes a real agent territory
//! `<repo>/.agent/config.yaml` carrying `agent_id: alice` so the rollback
//! resolver's FS-scan recognizes the non-root agent (`rollback.rs`
//! `resolve_agent_root` / `read_config_agent_id_safe`).
//!
//! Scope discipline (witness-floor) — what this file deliberately does NOT
//! assert (recorded deferrals, NOT claimed here):
//!   - **SYS-AC-241** (rollback-to-checkpoint ~100 files < 500ms): a perf-SLO,
//!     unreliable on this shared disk-pressured parallel-worktree CI — deferred.
//!   - **SYS-AC-160** (recall/list + `.meta.yaml`/SQLite re-sync after revert):
//!     the git→fs cross-module sync is not wired in the harness — deferred.
//!   - The `git.commit` event leg is never emitted by the provider (SYS-AC-247
//!     family) and is not asserted.
//! These deferrals are recorded in `state.json.system_acceptance_deferred`
//! (mirrored to SYSTEM-ACCEPTANCE.md §3 at task SUMMARY).

use advance_git::{
    bootstrap_repo_at, CheckpointError, DefaultNamedCheckpoint, DefaultWorkspaceRollback,
    NamedCheckpoint, RollbackError, WorkspaceRollback,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use git2::{Repository, Signature};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// In-file, test-owned `EventBusEmit` sink — the production providers stay the
/// real types; only this observation seam is test-owned (the `sys_j47` /
/// `rollback_event_emit.rs` discipline). Each integration-test binary is
/// self-contained, so this is defined here and not shared with other files.
struct CapturingEventBus {
    events: Mutex<Vec<Event>>,
}

impl CapturingEventBus {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn drain(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().expect("sink mutex poisoned"))
    }

    fn len(&self) -> usize {
        self.events.lock().expect("sink mutex poisoned").len()
    }
}

impl EventBusEmit for CapturingEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().expect("sink mutex poisoned").push(event);
    }
}

/// Bootstrap a single-branch (`main`) repo at a fresh temp dir (UNBORN HEAD,
/// 0 commits — checkpoint-on-unborn would be `InvalidState`).
fn bootstrap() -> (TempDir, PathBuf) {
    let td = TempDir::new().expect("tempdir");
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).expect("bootstrap single-branch repo");
    (td, p)
}

/// Write a real agent territory at the repo root so the rollback resolver's
/// FS-scan (`resolve_agent_root` → `read_config_agent_id_safe`) recognizes the
/// non-root `agent_id` (the spawner's `init_child_workspace` writes no
/// `agent_id` field, so the test writes a valid flat-block config.yaml itself).
fn seed_config_for_agent(repo_root: &Path, agent_id: &str) {
    let agent_dir = repo_root.join(".agent");
    std::fs::create_dir_all(&agent_dir).expect("mk .agent");
    std::fs::write(
        agent_dir.join("config.yaml"),
        format!("agent_id: {agent_id}\n"),
    )
    .expect("write config.yaml");
}

/// Direct git2 commit of `files` onto HEAD (parents = current HEAD if born).
/// Returns the new commit Oid (used as a rollback target / to read tag targets).
/// Mirrors the in-crate `seed_commit` helper exactly — a real commit, no mock.
fn seed_commit(p: &Path, files: &[(&str, &str)], msg: &str) -> git2::Oid {
    let repo = Repository::open(p).expect("open repo");
    for (rel, content) in files {
        if let Some(parent) = Path::new(rel).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(p.join(parent)).expect("mk parent dir");
            }
        }
        std::fs::write(p.join(rel), content).expect("write file");
    }
    let mut idx = repo.index().expect("index");
    for (rel, _) in files {
        idx.add_path(Path::new(rel)).expect("add_path");
    }
    idx.write().expect("index write");
    let tree_id = idx.write_tree().expect("write_tree");
    let tree = repo.find_tree(tree_id).expect("find_tree");
    let sig = Signature::now("t", "t@x").expect("signature");
    let parents: Vec<git2::Commit> = match repo.head() {
        Ok(h) => vec![h.peel_to_commit().expect("peel head")],
        Err(_) => vec![],
    };
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &parent_refs)
        .expect("commit")
}

/// Read the annotated-tag message bytes for `checkpoint/<agent>/<label>` via
/// git2 directly (independent witness of what `create` wrote — does NOT go
/// through the provider's own `list()`/`parse_tag_message`).
fn read_tag_message(p: &Path, agent: &str, label: &str) -> Option<String> {
    let repo = Repository::open(p).ok()?;
    let full_ref = format!("refs/tags/checkpoint/{agent}/{label}");
    let r = repo.find_reference(&full_ref).ok()?;
    let tag = r.peel_to_tag().ok()?;
    let bytes = tag.message_bytes().unwrap_or(&[]);
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Whether the `checkpoint/<agent>/<label>` annotated tag exists (git2 read).
fn tag_exists(p: &Path, agent: &str, label: &str) -> bool {
    let repo = match Repository::open(p) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let exists = repo
        .find_reference(&format!("refs/tags/checkpoint/{agent}/{label}"))
        .is_ok();
    exists
}

/// The annotated-tag's target commit Oid (40-hex). Used to assert SYS-AC-240's
/// "original tag unchanged" — the duplicate attempt must neither replace the
/// tag object nor repoint it.
fn tag_target_oid(p: &Path, agent: &str, label: &str) -> Option<String> {
    let repo = Repository::open(p).ok()?;
    let full_ref = format!("refs/tags/checkpoint/{agent}/{label}");
    let r = repo.find_reference(&full_ref).ok()?;
    r.peel_to_commit().ok().map(|c| c.id().to_string())
}

// ---------------------------------------------------------------------------
// SYS-AC-162 — checkpoint creates an annotated tag carrying normalized paths
// (JSON), `{}` for a full-directory checkpoint.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_162_create_writes_annotated_tag_with_normalized_paths_json() {
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    // Seed >=1 commit (checkpoint on unborn HEAD → InvalidState otherwise).
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
            ("data/report.md", "r1"),
        ],
        "target",
    );

    // --- Path-scoped checkpoint: message JSON carries the normalized paths. ---
    let ncp = DefaultNamedCheckpoint::new(p.clone()).expect("DefaultNamedCheckpoint::new");
    ncp.create(
        "alice",
        "v1",
        Some(vec![
            PathBuf::from("README.md"),
            PathBuf::from("data/report.md"),
        ]),
    )
    .expect("create path-scoped checkpoint v1");

    // The annotated tag `checkpoint/alice/v1` exists (git2 read).
    assert!(
        tag_exists(&p, "alice", "v1"),
        "annotated tag checkpoint/alice/v1 must exist after create"
    );

    // Its message is strict JSON `{"paths":[...]}` carrying exactly the
    // normalized (trailing-slash → dedupe → fold → dictionary-sort) paths.
    let msg = read_tag_message(&p, "alice", "v1").expect("tag has an annotated message");
    let json: serde_json::Value = serde_json::from_str(&msg).expect("tag message is strict JSON");
    let obj = json.as_object().expect("tag message is a JSON object");
    assert_eq!(
        obj.len(),
        1,
        "path-scoped message has exactly the `paths` key"
    );
    let paths = obj
        .get("paths")
        .and_then(|v| v.as_array())
        .expect("`paths` is a JSON array");
    let path_strs: Vec<&str> = paths.iter().filter_map(|v| v.as_str()).collect();
    // Both seeded paths are present; dictionary-sorted (the create-time
    // normalization stage 4). `data/report.md` < `README.md` is NOT assumed —
    // assert membership + sorted invariant rather than a brittle literal order.
    assert!(
        path_strs.contains(&"README.md"),
        "normalized paths include README.md, got {path_strs:?}"
    );
    assert!(
        path_strs.contains(&"data/report.md"),
        "normalized paths include data/report.md, got {path_strs:?}"
    );
    let mut sorted = path_strs.clone();
    sorted.sort();
    assert_eq!(
        path_strs, sorted,
        "create() dictionary-sorts the normalized paths"
    );

    // --- Full-directory checkpoint: message is the empty object `{}`. ---
    ncp.create("alice", "full", None)
        .expect("create full-directory checkpoint");
    let full_msg = read_tag_message(&p, "alice", "full").expect("full-dir tag has a message");
    let full_json: serde_json::Value =
        serde_json::from_str(&full_msg).expect("full-dir message is strict JSON");
    assert_eq!(
        full_json,
        serde_json::json!({}),
        "full-directory checkpoint message is `{{}}` (no `paths` key)"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-163 — rollback-to-checkpoint restores exactly the tagged scope and
// emits a `git.rollback` event on the injected sink.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_163_rollback_to_checkpoint_restores_scope_and_emits_event() {
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    // Seed the checkpoint target (v1 content of two files).
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
            ("data.md", "d1"),
        ],
        "target",
    );

    // Path-scoped checkpoint naming ONLY README.md.
    let ncp = DefaultNamedCheckpoint::new(p.clone()).expect("DefaultNamedCheckpoint::new");
    ncp.create("alice", "v1", Some(vec![PathBuf::from("README.md")]))
        .expect("create checkpoint v1");

    // DIVERGE the worktree from the checkpoint target (commit drift in BOTH
    // files) so rollback has a non-empty affected set (else the `git.rollback`
    // emit is skipped — rollback.rs:566-575).
    seed_commit(&p, &[("README.md", "v2"), ("data.md", "d2")], "drift");

    let sink = Arc::new(CapturingEventBus::new());
    let rb =
        DefaultWorkspaceRollback::with_event_bus(p.clone(), sink.clone() as Arc<dyn EventBusEmit>)
            .expect("DefaultWorkspaceRollback::with_event_bus");

    let restored = rb
        .rollback_to_checkpoint("alice", "v1")
        .await
        .expect("rollback_to_checkpoint v1");

    // Exactly the tagged scope (README.md) is restored — not data.md.
    let restored_strs: Vec<String> = restored
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        restored_strs,
        vec!["README.md".to_string()],
        "only the path-scoped checkpoint member is restored"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("README.md")).expect("read README.md"),
        "v1",
        "README.md restored to the checkpointed v1 content"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("data.md")).expect("read data.md"),
        "d2",
        "data.md (outside the tagged scope) is untouched"
    );

    // A single `git.rollback` event was captured on the injected sink,
    // carrying target_kind=checkpoint, target_ref=label, and the affected path.
    assert_eq!(sink.len(), 1, "exactly one git.rollback event emitted");
    let events = sink.drain();
    let event = &events[0];
    assert_eq!(event.event_type, "git.rollback");
    assert_eq!(event.agent_id, "alice");
    let payload = event
        .payload
        .as_object()
        .expect("git.rollback payload is a JSON object");
    assert_eq!(
        payload.get("target_kind").and_then(|v| v.as_str()),
        Some("checkpoint"),
        "target_kind is checkpoint for a checkpoint rollback"
    );
    assert_eq!(
        payload.get("target_ref").and_then(|v| v.as_str()),
        Some("v1"),
        "target_ref is the checkpoint label"
    );
    let affected = payload
        .get("affected_paths")
        .and_then(|v| v.as_array())
        .expect("affected_paths array present");
    let affected_strs: Vec<&str> = affected.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(
        affected_strs,
        vec!["README.md"],
        "affected_paths carries exactly the restored scope"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-164 — corrupt / non-object tag message → rollback-to-checkpoint fails
// closed with InvalidState; NO file changes.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_164_corrupt_tag_message_rejected_fail_closed_no_file_changes() {
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
        ],
        "target",
    );

    // Manually write a CORRUPT (schema-violating, non-`paths` extra-key) tag
    // message named `checkpoint/alice/bad` via git2 — `parse_tag_message`
    // returns valid=false for `{"x":1}` (extra key → not a valid checkpoint
    // schema), which `rollback_to_checkpoint` surfaces fail-closed as
    // `RollbackError::Checkpoint(CheckpointError::InvalidState)`
    // (rollback.rs:620-627, resolve_checkpoint).
    let repo = Repository::open(&p).expect("open repo");
    let head = repo
        .head()
        .expect("head")
        .peel_to_commit()
        .expect("peel head");
    let sig = Signature::now("t", "t@x").expect("signature");
    repo.tag(
        "checkpoint/alice/bad",
        head.as_object(),
        &sig,
        r#"{"x":1}"#,
        false,
    )
    .expect("write corrupt annotated tag");

    // Snapshot the worktree file before the call to assert fail-closed (no
    // checkout happened).
    let before = std::fs::read_to_string(p.join("README.md")).expect("read README.md pre");

    let sink = Arc::new(CapturingEventBus::new());
    let rb =
        DefaultWorkspaceRollback::with_event_bus(p.clone(), sink.clone() as Arc<dyn EventBusEmit>)
            .expect("DefaultWorkspaceRollback::with_event_bus");

    let err = rb
        .rollback_to_checkpoint("alice", "bad")
        .await
        .expect_err("corrupt tag message must fail closed");
    match err {
        RollbackError::Checkpoint(CheckpointError::InvalidState { label, .. }) => {
            assert_eq!(label, "bad", "InvalidState carries the offending label");
        }
        other => panic!("expected Checkpoint(InvalidState), got {other:?}"),
    }

    // Fail-closed: no file changed and no `git.rollback` event was emitted.
    let after = std::fs::read_to_string(p.join("README.md")).expect("read README.md post");
    assert_eq!(
        before, after,
        "worktree unchanged after a rejected rollback"
    );
    assert_eq!(
        sink.len(),
        0,
        "no git.rollback event emitted on a fail-closed rejection"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-240 — duplicate checkpoint label → second create errors with
// Conflict; the original tag is unchanged.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_240_duplicate_label_conflict_original_tag_unchanged() {
    let (_td, p) = bootstrap();
    seed_config_for_agent(&p, "alice");
    seed_commit(
        &p,
        &[
            (".agent/config.yaml", "agent_id: alice\n"),
            ("README.md", "v1"),
        ],
        "target",
    );

    let ncp = DefaultNamedCheckpoint::new(p.clone()).expect("DefaultNamedCheckpoint::new");
    // First create: path-scoped checkpoint at the v1 commit.
    ncp.create("alice", "v1", Some(vec![PathBuf::from("README.md")]))
        .expect("first create v1 succeeds");

    // Record the original tag's message + target commit so we can prove the
    // failed second attempt did NOT overwrite either.
    let original_msg = read_tag_message(&p, "alice", "v1").expect("original tag message readable");
    let original_target = tag_target_oid(&p, "alice", "v1").expect("original tag target readable");

    // Advance HEAD so a (hypothetical) overwriting create would repoint the
    // tag to a DIFFERENT commit — strengthens the "unchanged" assertion.
    seed_commit(&p, &[("README.md", "v2")], "drift after checkpoint");

    // Second create with the SAME label but DIFFERENT scope (full-directory)
    // → Conflict (existing-tag guard, checkpoint.rs:131-136), BEFORE any tag
    // write.
    let err = ncp
        .create("alice", "v1", None)
        .expect_err("duplicate label must conflict");
    match err {
        CheckpointError::Conflict { label } => {
            assert_eq!(label, "v1", "Conflict carries the duplicate label");
        }
        other => panic!("expected CheckpointError::Conflict, got {other:?}"),
    }

    // The original tag is byte-for-byte unchanged: same message JSON AND same
    // target commit (the second create neither rewrote the message to `{}` nor
    // repointed the tag at the newer drift commit).
    let after_msg = read_tag_message(&p, "alice", "v1").expect("tag still present");
    assert_eq!(
        after_msg, original_msg,
        "the conflicting create did not overwrite the tag message"
    );
    let after_target = tag_target_oid(&p, "alice", "v1").expect("tag target still readable");
    assert_eq!(
        after_target, original_target,
        "the conflicting create did not repoint the tag to a new commit"
    );
    // And the original was path-scoped (its message carries `paths`), proving
    // it was not replaced by the second (full-directory `{}`) attempt.
    let orig_json: serde_json::Value =
        serde_json::from_str(&after_msg).expect("original message is JSON");
    assert!(
        orig_json.as_object().and_then(|o| o.get("paths")).is_some(),
        "original (path-scoped) tag message retains its `paths` key"
    );
}
