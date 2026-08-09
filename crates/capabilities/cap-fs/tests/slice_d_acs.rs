//! Slice D AC verification tests — covers AC-16 (REQ-004 cap-fs ↔ advance-git
//! integration: every fs.write/fs.delete produces a `[turn] [agent:<id>]`
//! commit on the workspace's single-branch repo, with
//! `runtime.degraded.git_sync_failed` fail-soft semantics on git failure).
//!
//! Tests SD-T40..SD-T49. Each test builds its own ephemeral fixture
//! (TempDir + fresh registry/emitter/queue or mock).
//!
//! Test layout:
//! - SD-T40..SD-T43: MockGitSync fast-path tests (no real git2/libgit2).
//! - SD-T44..SD-T49: real `Adv003GitSync` against a bootstrapped repo —
//!   verify HEAD progression, commit-message prefix, tree contents, and the
//!   fold-in invariant for `update-scope`/`update-entry-meta`.

mod common;

use std::path::Path;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    register_agent_fs, DefaultAtomicWriter, DefaultVirtualPathResolver, FsDeleteHandler,
    FsWriteHandler, GitSync, GitSyncOp, MetaMaintainer, MetaSchemaLoader, VirtualPathResolver,
};
use wasmtime::component::Val;

use common::{bootstrap_real_git_sync, single_agent_tree, MockGitSync, TestEmitter};

const TRACE_ID: &str = "tr-sd";

fn ctx_for(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.into(),
        trace_id: TRACE_ID.into(),
        turn_id: None,
        capability: "fs".into(),
        function: "advance:runtime/agent-fs::test".into(),
        run_id: None,
        iteration: None,
    }
}

fn unwrap_ok_none(out: Vec<Val>) {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Ok(None)) => {}
        other => panic!("expected Ok(None), got {other:?}"),
    }
}

fn schema_loader_for(tempdir_path: &Path) -> Arc<MetaSchemaLoader> {
    Arc::new(MetaSchemaLoader::new_with_default(
        tempdir_path.join("schema.yaml"),
    ))
}

fn maintainer_for(tempdir_path: &Path) -> Arc<MetaMaintainer> {
    Arc::new(MetaMaintainer::new(
        schema_loader_for(tempdir_path),
        Arc::new(DefaultAtomicWriter),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock-backed AC-16 tests (SD-T40..SD-T43).
// ─────────────────────────────────────────────────────────────────────────────

/// Build a FsWriteHandler wired with `MockGitSync` (no slice C trio — git_sync
/// is independent). For simpler tests that don't need a real bootstrapped repo.
struct MockWriteFixture {
    _tempdir: tempfile::TempDir,
    agent_workspace: std::path::PathBuf,
    handler: FsWriteHandler,
    emitter: Arc<TestEmitter>,
    git_mock: Arc<MockGitSync>,
}

fn mock_write_fixture(agent_id: &str, fail_on: Option<usize>) -> MockWriteFixture {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mock = Arc::new(match fail_on {
        Some(n) => MockGitSync::fail_on(n),
        None => MockGitSync::new(),
    });
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&mock) as Arc<dyn GitSync>),
    };
    MockWriteFixture {
        _tempdir: tempdir,
        agent_workspace,
        handler,
        emitter,
        git_mock: mock,
    }
}

// SD-T40: fs.write triggers MockGitSync::submit_fs_commit with op=Write.
#[tokio::test]
async fn sd_t40_write_invokes_git_sync_with_write_op() {
    let agent_id = "agent-1";
    let f = mock_write_fixture(agent_id, None);

    let body: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    let out = f
        .handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    let calls = f.git_mock.snapshot();
    assert_eq!(calls.len(), 1, "expected exactly 1 git_sync call");
    let call = &calls[0];
    assert_eq!(call.agent_id, agent_id);
    assert_eq!(call.op, GitSyncOp::Write);
    assert_eq!(call.vpath, "notes.md");
    assert_eq!(
        call.physical_path,
        f.agent_workspace.join("notes.md"),
        "physical_path should be the on-disk path under agent_workspace"
    );
    assert_eq!(
        call.meta_yaml_path,
        f.agent_workspace.join(".meta.yaml"),
        "meta_yaml_path should be parent_dir/.meta.yaml"
    );
}

// SD-T41: fs.write seed + fs.delete triggers two MockGitSync calls (Write
// then Delete).
#[tokio::test]
async fn sd_t41_delete_invokes_git_sync_with_delete_op() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mock = Arc::new(MockGitSync::new());
    let maintainer = maintainer_for(tempdir.path());

    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&maintainer),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&mock) as Arc<dyn GitSync>),
    };
    let body: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    let _ = write_handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("a.txt".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();

    let delete_handler = FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer,
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&mock) as Arc<dyn GitSync>),
    };
    let out = delete_handler
        .call(ctx_for(agent_id), vec![Val::String("a.txt".into())], 1)
        .await
        .unwrap();
    unwrap_ok_none(out);

    let calls = mock.snapshot();
    assert_eq!(calls.len(), 2, "expected Write + Delete call sequence");
    assert_eq!(calls[0].op, GitSyncOp::Write);
    assert_eq!(calls[1].op, GitSyncOp::Delete);
    assert_eq!(calls[1].vpath, "a.txt");
}

// SD-T42: forced git failure emits runtime.degraded.git_sync_failed but
// fs.write returns Ok().
#[tokio::test]
async fn sd_t42_git_failure_emits_runtime_degraded_event() {
    let agent_id = "agent-1";
    let f = mock_write_fixture(agent_id, Some(1));

    let body: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    let out = f
        .handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    // fs.write returns Ok() — FS source-of-truth committed; git is best-effort.
    unwrap_ok_none(out);

    // file + .meta.yaml on disk regardless.
    assert!(f.agent_workspace.join("notes.md").exists());
    assert!(f.agent_workspace.join(".meta.yaml").exists());

    let evs = f.emitter.snapshot();
    assert!(
        evs.iter()
            .any(|e| e.event_type == "runtime.degraded.git_sync_failed"),
        "expected runtime.degraded.git_sync_failed, got {:?}",
        evs.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
    // fs.write event still emitted since FS commit succeeded.
    assert!(evs.iter().any(|e| e.event_type == "fs.write"));

    // Verify payload shape.
    let degraded = evs
        .iter()
        .find(|e| e.event_type == "runtime.degraded.git_sync_failed")
        .unwrap();
    let payload = &degraded.payload;
    assert_eq!(payload["op"].as_str(), Some("write"));
    assert_eq!(payload["vpath"].as_str(), Some("notes.md"));
    assert!(payload["error"].as_str().is_some());
}

// SD-T43: git_sync = None preserves slice A/B/C compat — no git event,
// no panic.
#[tokio::test]
async fn sd_t43_git_sync_none_skips_git_leg() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());

    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };

    let body: Vec<Val> = b"hi".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("a.txt".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    let evs = emitter.snapshot();
    // No runtime.degraded.* events — git leg silently skipped.
    assert!(
        !evs.iter()
            .any(|e| e.event_type.starts_with("runtime.degraded.")),
        "no runtime.degraded events expected, got {:?}",
        evs.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Real-git AC-16 tests (SD-T44..SD-T49) — bootstrap a real repo,
// drive fs.write/fs.delete through Adv003GitSync + DefaultGitCommitQueue.
// ─────────────────────────────────────────────────────────────────────────────

fn open_repo(repo_path: &Path) -> git2::Repository {
    git2::Repository::open(repo_path).expect("open_repo")
}

fn head_commit_count(repo: &git2::Repository) -> usize {
    let head = match repo.head() {
        Ok(h) => h,
        Err(_) => return 0, // unborn branch
    };
    let mut walker = repo.revwalk().unwrap();
    walker
        .push(head.target().unwrap())
        .expect("push head target");
    walker.count()
}

fn head_commit_message(repo: &git2::Repository) -> String {
    let head = repo.head().unwrap();
    let oid = head.target().unwrap();
    let commit = repo.find_commit(oid).unwrap();
    commit.message().unwrap_or("").to_string()
}

fn head_commit_author(repo: &git2::Repository) -> String {
    let head = repo.head().unwrap();
    let oid = head.target().unwrap();
    let commit = repo.find_commit(oid).unwrap();
    let author = commit.author();
    author.name().unwrap_or("").to_string()
}

fn head_tree_blob(repo: &git2::Repository, path: &str) -> Option<Vec<u8>> {
    let head = repo.head().ok()?;
    let oid = head.target()?;
    let commit = repo.find_commit(oid).ok()?;
    let tree = commit.tree().ok()?;
    let entry = tree.get_path(Path::new(path)).ok()?;
    let object = entry.to_object(repo).ok()?;
    let blob = object.peel_to_blob().ok()?;
    Some(blob.content().to_vec())
}

// SD-T44: real Adv003GitSync; fs.write of agent-1/notes.md = "hello".
#[tokio::test]
async fn sd_t44_real_write_advances_head_with_attribution_prefix() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());

    let real_git = bootstrap_real_git_sync(&workspace_root).await;
    let pre_count = head_commit_count(&open_repo(&workspace_root));

    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&real_git.git_sync)),
    };

    let body: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    let repo = open_repo(&workspace_root);
    let post_count = head_commit_count(&repo);
    assert_eq!(
        post_count,
        pre_count + 1,
        "HEAD should advance by exactly 1 commit"
    );

    let msg = head_commit_message(&repo);
    assert!(
        msg.starts_with("[turn] [agent:agent-1] write "),
        "commit message should have the [turn] [agent:agent-1] write prefix; got {msg:?}"
    );

    let blob = head_tree_blob(&repo, "agent-1/notes.md").expect("notes.md blob in tree");
    assert_eq!(blob, b"hello");
    let meta = head_tree_blob(&repo, "agent-1/.meta.yaml").expect(".meta.yaml blob in tree");
    let meta_str = String::from_utf8(meta).unwrap();
    assert!(
        meta_str.contains("notes.md"),
        ".meta.yaml should list the new entry"
    );

    // No runtime.degraded events on the happy path.
    let evs = emitter.snapshot();
    assert!(!evs
        .iter()
        .any(|e| e.event_type.starts_with("runtime.degraded.")));
}

// SD-T45: agent_id with audit-metachars is sanitized at the advance-git
// boundary (cap-fs adds no extra sanitization).
#[tokio::test]
async fn sd_t45_real_write_sanitizes_audit_metachars_at_advance_git_boundary() {
    let agent_id = "[evil]<x>\"y\"";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let real_git = bootstrap_real_git_sync(&workspace_root).await;

    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&real_git.git_sync)),
    };

    let body: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    let repo = open_repo(&workspace_root);
    let msg = head_commit_message(&repo);
    let author = head_commit_author(&repo);
    // sanitize_audit_field replaces [, ], <, >, " with _.
    // Expected initiator after sanitization: agent:_evil__x_y_ (close-quote also stripped).
    for forbidden in ['[', ']', '<', '>', '"'] {
        // Both message and author should NOT contain raw structural metacharacters
        // EXCEPT the prefix's own [turn] [..] brackets.
        // We only check the agent_id substring portion, isolated from those brackets:
        // commit message format = `[turn] [agent:<sanitized_id>] write <vpath>` — so the
        // raw forbidden char must not appear AFTER the first ']' (which closes [turn]).
        let after_turn = msg.split_once("] ").unwrap().1; // "[agent:...]" + body
        let inner = &after_turn[1..]; // strip leading '['
        let inner_until_close = inner.split(']').next().unwrap();
        assert!(
            !inner_until_close.contains(forbidden),
            "commit message inner field should be sanitized; saw {forbidden:?} in {inner_until_close:?}"
        );
        // Author signature `agent:<sanitized_id>` must not contain the metacharacter.
        // (advance-git's signature is the prefix of author name "agent:<id>".)
        // The author NAME field is what we read; it's the sanitized form.
        assert!(
            !author.contains(forbidden),
            "author should be sanitized; saw {forbidden:?} in {author:?}"
        );
    }
}

// SD-T50 (slice D adversarial round 1 regression): a hostile vpath embedded
// with newline + bracket-prefix forge attempt MUST NOT produce a forged
// audit log line. cap-fs's `validate_path_param` only enforces length;
// `format!("write {vpath}")` would otherwise interpolate the raw vpath into
// the commit message, and an audit-log reader splitting on newlines would
// see two attribution rows from one commit. Trust boundary: advance-git's
// `do_commit` sanitizes ALL three caller-supplied audit fields (agent_id,
// initiator, message) — this test verifies the message branch end-to-end
// through cap-fs.
#[tokio::test]
async fn sd_t50_real_write_sanitizes_vpath_newline_audit_forgery() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let real_git = bootstrap_real_git_sync(&workspace_root).await;

    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&real_git.git_sync)),
    };

    // Hostile vpath: literal newline + structural metacharacters intended to
    // forge a fake `[turn] [agent:victim] write secret.md` line in the body.
    // POSIX accepts newlines in filenames; validate_path_param only enforces
    // length. The trust boundary that catches this is advance-git's
    // sanitize_audit_field on req.message.
    let hostile_vpath = "evil\n[turn] [agent:victim] write secret.md";
    let body: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx_for(agent_id),
            vec![Val::String(hostile_vpath.into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    let repo = open_repo(&workspace_root);
    let msg = head_commit_message(&repo);

    // (1) NO raw newline in the commit message — the sanitizer replaced `\n`
    //     with `_`. An audit-log reader splitting on newlines sees ONE row.
    assert!(
        !msg.contains('\n'),
        "commit message must not contain a raw newline; got: {msg:?}"
    );
    // (2) The bracket count must be exactly 2 of each (the legitimate prefix
    //     `[turn] [agent:agent-1]`). Any additional `[` or `]` from the
    //     hostile vpath was replaced with `_`.
    assert_eq!(
        msg.matches('[').count(),
        2,
        "commit message must contain exactly 2 `[` (the prefix); got: {msg:?}"
    );
    assert_eq!(
        msg.matches(']').count(),
        2,
        "commit message must contain exactly 2 `]` (the prefix); got: {msg:?}"
    );
    // (3) The forged `[turn]`/`[agent:victim]` brackets in the body show up
    //     as `_turn_` / `_agent:victim_` post-sanitization.
    assert!(
        msg.contains("_turn_") && msg.contains("_agent:victim_"),
        "structural metacharacters in body must be replaced with `_`; got: {msg:?}"
    );
    // (4) The legitimate prefix is still well-formed.
    assert!(
        msg.starts_with("[turn] [agent:agent-1] write "),
        "prefix must be intact and well-formed; got: {msg:?}"
    );
}

// SD-T46: two agents, two commits, deterministic submission order
// (sequential awaits — no tokio::join!).
#[tokio::test]
async fn sd_t46_two_agents_produce_two_attribution_commits_deterministically() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();

    let agent_a = "agent-a";
    let agent_b = "agent-b";
    let workspace_a = workspace_root.join(agent_a);
    let workspace_b = workspace_root.join(agent_b);
    std::fs::create_dir_all(&workspace_a).unwrap();
    std::fs::create_dir_all(&workspace_b).unwrap();

    let tree_a =
        Arc::new(single_agent_tree(agent_a, workspace_a.clone())) as Arc<dyn AgentTreeSnapshot>;
    let tree_b =
        Arc::new(single_agent_tree(agent_b, workspace_b.clone())) as Arc<dyn AgentTreeSnapshot>;
    let resolver_a = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree_a),
    ));
    let resolver_b = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree_b),
    ));
    let emitter = Arc::new(TestEmitter::new());

    let real_git = bootstrap_real_git_sync(&workspace_root).await;

    let handler_a = FsWriteHandler {
        resolver: resolver_a as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&real_git.git_sync)),
    };
    let handler_b = FsWriteHandler {
        resolver: resolver_b as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&real_git.git_sync)),
    };

    // Sequential: agent-a fully completes (incl. its commit) before agent-b
    // submits — pins commit order deterministically.
    let body_a: Vec<Val> = b"a".iter().copied().map(Val::U8).collect();
    let _ = handler_a
        .call(
            ctx_for(agent_a),
            vec![Val::String("notes.md".into()), Val::List(body_a)],
            1,
        )
        .await
        .unwrap();
    let body_b: Vec<Val> = b"b".iter().copied().map(Val::U8).collect();
    let _ = handler_b
        .call(
            ctx_for(agent_b),
            vec![Val::String("notes.md".into()), Val::List(body_b)],
            1,
        )
        .await
        .unwrap();

    let repo = open_repo(&workspace_root);
    let mut walker = repo.revwalk().unwrap();
    walker.push_head().unwrap();
    let oids: Vec<_> = walker.collect::<Result<_, _>>().unwrap();
    assert_eq!(oids.len(), 2);
    let head_msg = repo
        .find_commit(oids[0])
        .unwrap()
        .message()
        .unwrap()
        .to_string();
    let parent_msg = repo
        .find_commit(oids[1])
        .unwrap()
        .message()
        .unwrap()
        .to_string();
    // Walker yields commits HEAD-first, so [0] = HEAD = agent-b commit, [1] = agent-a commit.
    assert!(
        head_msg.contains("[agent:agent-b]"),
        "HEAD should be agent-b's commit; got {head_msg:?}"
    );
    assert!(
        parent_msg.contains("[agent:agent-a]"),
        "parent should be agent-a's commit; got {parent_msg:?}"
    );

    // Tree of HEAD (agent-b's commit): both agents' files should be present
    // because the second commit's index includes both agents' staged paths.
    let blob_a = head_tree_blob(&repo, "agent-a/notes.md").expect("agent-a notes.md");
    assert_eq!(blob_a, b"a");
    let blob_b = head_tree_blob(&repo, "agent-b/notes.md").expect("agent-b notes.md");
    assert_eq!(blob_b, b"b");
}

// SD-T47: fs.write then fs.delete of same file = 2 commits; second commit
// removes the blob.
#[tokio::test]
async fn sd_t47_real_write_then_delete_records_deletion_commit() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let real_git = bootstrap_real_git_sync(&workspace_root).await;
    let maintainer = maintainer_for(tempdir.path());

    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&maintainer),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&real_git.git_sync)),
    };
    let body: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    let _ = write_handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();

    let delete_handler = FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer,
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(Arc::clone(&real_git.git_sync)),
    };
    let _ = delete_handler
        .call(ctx_for(agent_id), vec![Val::String("notes.md".into())], 1)
        .await
        .unwrap();

    let repo = open_repo(&workspace_root);
    let head_count = head_commit_count(&repo);
    assert_eq!(head_count, 2, "expected 2 commits (write + delete)");
    let msg = head_commit_message(&repo);
    assert!(
        msg.starts_with("[turn] [agent:agent-1] delete "),
        "HEAD should be the delete commit; got {msg:?}"
    );

    // Second commit's tree should NOT contain notes.md.
    let blob = head_tree_blob(&repo, "agent-1/notes.md");
    assert!(
        blob.is_none(),
        "delete commit's tree should not contain notes.md"
    );

    // .meta.yaml should still exist but no longer list notes.md.
    let meta = head_tree_blob(&repo, "agent-1/.meta.yaml").expect(".meta.yaml in tree");
    let meta_str = String::from_utf8(meta).unwrap();
    assert!(
        !meta_str.contains("notes.md"),
        ".meta.yaml should no longer list notes.md after delete; got {meta_str}"
    );
}

// SD-T48: full 11-arg register_agent_fs binding-layer integration. Verifies
// that ONLY write + delete handlers wire git_sync (slice D scope), so
// dispatching all 18 fns through the registry advances HEAD by EXACTLY 2.
#[tokio::test]
async fn sd_t48_eighteen_fn_dispatch_advances_head_by_two_for_write_plus_delete() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();

    // Seed `.meta.yaml` so update-scope/update-entry-meta have something to
    // mutate (otherwise update-scope on an empty `.meta.yaml` may fail at the
    // schema-validation step).
    std::fs::write(
        agent_workspace.join(".meta.yaml"),
        "_scope:\n  description: \"\"\n  tags: []\n",
    )
    .unwrap();

    let tree: Arc<dyn AgentTreeSnapshot> =
        Arc::new(single_agent_tree(agent_id, agent_workspace.clone()));
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter: Arc<dyn EventBusEmit> = Arc::new(TestEmitter::new());
    let schema = Arc::new(MetaSchemaLoader::new_with_default(
        workspace_root.join("schema.yaml"),
    ));
    let history = Arc::new(cap_fs::StubFileHistoryProvider) as Arc<dyn cap_fs::FileHistoryProvider>;
    let writer: Arc<dyn cap_fs::AtomicWriter> = Arc::new(DefaultAtomicWriter);

    let real_git = bootstrap_real_git_sync(&workspace_root).await;
    let pre_count = head_commit_count(&open_repo(&workspace_root));

    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_fs(
        &*registry,
        Arc::clone(&resolver),
        Arc::clone(&emitter),
        schema,
        history,
        writer,
        None,
        None, // db_sync
        None, // workspace_root
        None, // agent_tree
        Some(Arc::clone(&real_git.git_sync)),
    );

    let specs = registry.lookup("fs");
    assert_eq!(specs.len(), 18);
    let mut by_name: std::collections::HashMap<String, _> = std::collections::HashMap::new();
    for s in specs {
        by_name.insert(s.name.clone(), s);
    }
    let ctx = ctx_for(agent_id);

    // Dispatch all 18 fns. write + delete bracket the others to ensure the
    // file exists for read/list/scan/etc. in between.
    let dispatches: &[(&str, Vec<Val>)] = &[
        // 1. write — creates notes.md, advances HEAD (commit C0)
        (
            "write",
            vec![
                Val::String("notes.md".into()),
                Val::List(b"hello".iter().copied().map(Val::U8).collect()),
            ],
        ),
        // 2. read — touches handler, no commit
        ("read", vec![Val::String("notes.md".into())]),
        // 3. list — touches handler, no commit
        ("list", vec![Val::String(".".into())]),
        // 4. scan — touches handler, no commit
        ("scan", vec![Val::String(".".into())]),
        // slug (3) — likely error variant (no peer slug), but dispatch must work
        (
            "read-slug",
            vec![
                Val::String("sub-x".into()),
                Val::String("slug".into()),
                Val::String("f.md".into()),
            ],
        ),
        (
            "list-slug",
            vec![Val::String("sub-x".into()), Val::String("slug".into())],
        ),
        (
            "scan-slug",
            vec![Val::String("sub-x".into()), Val::String("slug".into())],
        ),
        // child (3)
        (
            "read-child",
            vec![Val::String("sub-x".into()), Val::String("f.md".into())],
        ),
        (
            "list-child",
            vec![Val::String("sub-x".into()), Val::String(".".into())],
        ),
        (
            "scan-child",
            vec![Val::String("sub-x".into()), Val::String(".".into())],
        ),
        // history (5)
        ("file-history", vec![Val::String("notes.md".into())]),
        (
            "read-at",
            vec![Val::String("notes.md".into()), Val::String("v1".into())],
        ),
        (
            "child-file-history",
            vec![Val::String("sub-x".into()), Val::String("f.md".into())],
        ),
        (
            "read-child-at",
            vec![
                Val::String("sub-x".into()),
                Val::String("f.md".into()),
                Val::String("v1".into()),
            ],
        ),
        (
            "slug-file-history",
            vec![
                Val::String("sub-x".into()),
                Val::String("slug".into()),
                Val::String("f.md".into()),
            ],
        ),
        // update-meta (2) — slice D scope: NO git commit produced.
        (
            "update-scope",
            vec![
                Val::String(".".into()),
                Val::String("desc".into()),
                Val::List(vec![]),
            ],
        ),
        (
            "update-entry-meta",
            vec![
                Val::String(".".into()),
                Val::String("notes.md".into()),
                Val::String("e-desc".into()),
                Val::List(vec![]),
            ],
        ),
        // 18. delete — removes notes.md, advances HEAD (commit C1)
        ("delete", vec![Val::String("notes.md".into())]),
    ];
    assert_eq!(dispatches.len(), 18);

    for (name, params) in dispatches {
        let spec = by_name.get(*name).expect("spec");
        let outcome = spec.handler.call(ctx.clone(), params.clone(), 1).await;
        assert!(
            outcome.is_ok(),
            "registry-dispatched call for `{name}` returned HostCallError: {outcome:?}"
        );
    }

    let post_count = head_commit_count(&open_repo(&workspace_root));
    assert_eq!(
        post_count - pre_count,
        2,
        "expected exactly 2 commits (write + delete); update-scope/update-entry-meta should NOT advance HEAD in slice D"
    );
}

// SD-T49: fold-in invariant — update-scope + update-entry-meta + fs.write
// produce ONE commit whose tree's `.meta.yaml` contains all three mutations.
#[tokio::test]
async fn sd_t49_update_meta_then_write_folds_into_single_commit() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();

    // Seed an initial `.meta.yaml` + `seed.md` so update-scope + update-entry-meta
    // have a target that already exists.
    std::fs::write(agent_workspace.join("seed.md"), b"seed").unwrap();

    let tree: Arc<dyn AgentTreeSnapshot> =
        Arc::new(single_agent_tree(agent_id, agent_workspace.clone()));
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter: Arc<dyn EventBusEmit> = Arc::new(TestEmitter::new());
    let schema = Arc::new(MetaSchemaLoader::new_with_default(
        workspace_root.join("schema.yaml"),
    ));
    let history = Arc::new(cap_fs::StubFileHistoryProvider) as Arc<dyn cap_fs::FileHistoryProvider>;
    let writer: Arc<dyn cap_fs::AtomicWriter> = Arc::new(DefaultAtomicWriter);

    let real_git = bootstrap_real_git_sync(&workspace_root).await;
    let pre_count = head_commit_count(&open_repo(&workspace_root));

    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_fs(
        &*registry,
        Arc::clone(&resolver),
        Arc::clone(&emitter),
        schema,
        history,
        writer,
        None,
        None,
        None,
        None,
        Some(Arc::clone(&real_git.git_sync)),
    );

    let specs = registry.lookup("fs");
    let mut by_name: std::collections::HashMap<String, _> = std::collections::HashMap::new();
    for s in specs {
        by_name.insert(s.name.clone(), s);
    }
    let ctx = ctx_for(agent_id);

    // Step (a): seed-write seed.md so .meta.yaml is auto-populated by the maintainer.
    let _ = by_name
        .get("write")
        .unwrap()
        .handler
        .call(
            ctx.clone(),
            vec![
                Val::String("seed.md".into()),
                Val::List(b"seed-body".iter().copied().map(Val::U8).collect()),
            ],
            1,
        )
        .await
        .unwrap();

    // Step (b): update-scope mutates _scope description.
    let _ = by_name
        .get("update-scope")
        .unwrap()
        .handler
        .call(
            ctx.clone(),
            vec![
                Val::String(".".into()),
                Val::String("research-notes-scope".into()),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .unwrap();

    // Step (c): update-entry-meta mutates the seed.md entry's description.
    let _ = by_name
        .get("update-entry-meta")
        .unwrap()
        .handler
        .call(
            ctx.clone(),
            vec![
                Val::String(".".into()),
                Val::String("seed.md".into()),
                Val::String("seed-entry-desc".into()),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .unwrap();

    // Step (d): fs.write notes.md "hello" — advances HEAD by 1.
    let _ = by_name
        .get("write")
        .unwrap()
        .handler
        .call(
            ctx.clone(),
            vec![
                Val::String("notes.md".into()),
                Val::List(b"hello".iter().copied().map(Val::U8).collect()),
            ],
            1,
        )
        .await
        .unwrap();

    let repo = open_repo(&workspace_root);
    let post_count = head_commit_count(&repo);
    // Expected: pre + 2 (one for seed-write, one for the final fs.write).
    // update-scope + update-entry-meta produce no additional commits.
    assert_eq!(
        post_count - pre_count,
        2,
        "expected exactly 2 commits: seed-write + final fs.write — update-scope/update-entry-meta must not produce standalone commits"
    );

    // HEAD's tree's agent-1/.meta.yaml must contain ALL the cumulative mutations:
    // (b) _scope description="research-notes-scope", (c) seed.md entry
    // description="seed-entry-desc", AND (d) the new notes.md entry.
    let meta_blob =
        head_tree_blob(&repo, "agent-1/.meta.yaml").expect("agent-1/.meta.yaml in HEAD tree");
    let meta_str = String::from_utf8(meta_blob).unwrap();
    assert!(
        meta_str.contains("research-notes-scope"),
        ".meta.yaml in HEAD tree should reflect step (b) update-scope; got:\n{meta_str}"
    );
    assert!(
        meta_str.contains("seed-entry-desc"),
        ".meta.yaml in HEAD tree should reflect step (c) update-entry-meta; got:\n{meta_str}"
    );
    assert!(
        meta_str.contains("notes.md"),
        ".meta.yaml in HEAD tree should contain step (d) new entry; got:\n{meta_str}"
    );
    assert!(
        meta_str.contains("seed.md"),
        ".meta.yaml in HEAD tree should contain prior seed.md entry; got:\n{meta_str}"
    );
}
