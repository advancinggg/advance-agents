//! SYS-J-21 rollback-memory witnesses (SYS-AC-062, 063, 064).
//!
//! Real chain, no module mocked: the REAL `RollbackMemoryHandler` (registered
//! via `register_agent_memory_with_git`) drives
//!   1. the REAL `MemoryStore` in-process rollback (drops post-timestamp
//!      entries AND persists the post-rollback `knowledge.jsonl` itself — the
//!      adjudicated split-brain-avoiding division: the store owns its own
//!      file, so no git checkout can diverge from the live cache),
//!   2. the REAL MODULE-003 git half — `GitMemoryRestore` (the production cli
//!      composition-root adapter) over `DefaultWorkspaceRollback::
//!      rollback_memory_files_at`: a TIME-sorted revwalk resolves the latest
//!      commit at-or-before the timestamp and PathScoped-restores
//!      `_knowledge_map.yaml` + `syntheses/*.md` from THAT commit's tree
//!      (`git.rollback` emission included),
//!   3. the REAL `L6CursorStore` reset — with the rollback-memory slice's
//!      on-disk `_knowledge_cursor.yaml` half (`with_root`): the file is
//!      MATERIALIZED at the literal initial state (epoch/0/0), never checked
//!      out from history (it is not in `ROLLBACK_GIT_PATHS`).
//!
//! Drive surface: `call_host_fn` (the host-fn stand-in posture — the
//! properties witnessed here are all BELOW the handler boundary; the guest→
//! host call mechanics are witnessed elsewhere, e.g. sys_j20 via a real
//! guest turn). Git history is hand-seeded (direct git2 commits, the sys_j50
//! crib) because no production component commits memory files yet (the
//! L6Committer is a stub — MODULE-011 §3.6); the RESTORE side is the real
//! product under test.
//!
//! Two-clock note (MODULE-011 §3.8): knowledge `created_at` stamps and git
//! commit times are different clocks at second granularity — the witness
//! sleeps across second boundaries so the rollback timestamp cleanly
//! separates v1 (at/before) from v2 (after) on BOTH clocks.

use std::path::Path;

use git2::{Repository, Signature};
use wasmtime::component::Val;

use advance_shared_types::memory::L6Cursor;
use cap_memory::{CAPABILITY, NAMESPACE};
use system_acceptance::{Cap, SystemUnderTest, AGENT_ID};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// Direct git2 commit helper (the sys_j50 crib): write files, stage by
/// relative path, advance HEAD (creating the branch on the first call).
fn seed_commit(p: &Path, files: &[(&str, &str)], msg: &str) -> git2::Oid {
    let repo = Repository::open(p).unwrap();
    for (rel, content) in files {
        if let Some(parent) = Path::new(rel).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(p.join(parent)).unwrap();
            }
        }
        std::fs::write(p.join(rel), content).unwrap();
    }
    let mut idx = repo.index().unwrap();
    for (rel, _) in files {
        idx.add_path(Path::new(rel)).unwrap();
    }
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    let parents: Vec<git2::Commit> = match repo.head() {
        Ok(h) => vec![h.peel_to_commit().unwrap()],
        Err(_) => vec![],
    };
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &parent_refs)
        .unwrap()
}

/// Decode `remember`'s `result<string, memory-error>` ok arm.
fn expect_ok(results: &[Val], what: &str) {
    match results {
        [Val::Result(Ok(_))] => {}
        other => panic!("{what} must return the ok arm; got {other:?}"),
    }
}

/// Drive `remember(content, [])` through the registered handler.
async fn remember(sut: &SystemUnderTest, content: &str) {
    let res = sut
        .call_host_fn_n(
            CAPABILITY,
            NAMESPACE,
            "remember",
            vec![Val::String(content.to_string()), Val::List(vec![])],
            1,
        )
        .await
        .expect("remember host fn dispatches");
    expect_ok(&res, "remember");
}

/// Drive `recall(query, limit)` and return the decoded entry contents.
async fn recall_contents(sut: &SystemUnderTest, query: &str) -> Vec<String> {
    let res = sut
        .call_host_fn_n(
            CAPABILITY,
            NAMESPACE,
            "recall",
            vec![Val::String(query.to_string()), Val::U32(0)],
            1,
        )
        .await
        .expect("recall host fn dispatches");
    let Some(Val::Result(Ok(Some(list)))) = res.first() else {
        panic!("recall must return ok(list); got {res:?}");
    };
    let Val::List(entries) = list.as_ref() else {
        panic!("recall ok arm must be a list; got {list:?}");
    };
    entries
        .iter()
        .filter_map(|e| match e {
            Val::Record(fields) => fields.iter().find_map(|(k, v)| match (k.as_str(), v) {
                ("content", Val::String(c)) => Some(c.clone()),
                _ => None,
            }),
            _ => None,
        })
        .collect()
}

/// The on-disk `knowledge.jsonl` the store persists for the harness agent
/// (`<memory_dir>/<slug>/knowledge.jsonl` — slug located by glob, the layout
/// is store-private).
fn knowledge_file(sut: &SystemUnderTest) -> std::path::PathBuf {
    let dir = sut.memory_dir();
    let mut hits: Vec<_> = std::fs::read_dir(dir)
        .expect("memory dir exists")
        .flatten()
        .map(|e| e.path().join("knowledge.jsonl"))
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "exactly one agent bucket persisted: {hits:?}"
    );
    hits.remove(0)
}

fn now_rfc3339_z() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// SYS-AC-062 + 063 + 064 — one coherent scenario: build memory state v1
// (knowledge + map + synthesis, committed), advance to state v2, then
// rollback-memory(T1):
//   062: memory.rollback{entries_deactivated} emitted; knowledge.jsonl,
//        _knowledge_map.yaml and syntheses/* are all back at their v1 state
//        (knowledge.jsonl via the store's own in-process persist — asserted
//        byte-identical to the captured v1 file; map + synthesis via the
//        REAL git PathScoped restore from the resolved at-or-before commit,
//        git.rollback emitted).
//   063: _knowledge_cursor.yaml lands at the literal initial state
//        (epoch/0/0) after holding a non-initial watermark — materialized by
//        reset, NOT checked out (the cursor is never in the restored set).
//   064: recall returns the v1 set only (the post-T1 entry is absent).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_062_063_064_rollback_memory_full_chain() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Memory])
        .build(J01_SKELETON)
        .await;
    let ws = sut.workspace_root().to_path_buf();

    // resolve_agent_root contract: the workspace's own `.agent/config.yaml`
    // names the root agent by its BARE body (PRD §6.2 flat block mapping;
    // the GitMemoryRestore seam strips the canonical `agent:` prefix).
    let config = format!("agent_id: {}\n", AGENT_ID.strip_prefix("agent:").unwrap());

    // ── state v1 ──────────────────────────────────────────────────────────
    remember(&sut, "alpha entry (v1)").await;
    let knowledge_path = knowledge_file(&sut);
    let knowledge_rel = knowledge_path
        .strip_prefix(&ws)
        .expect("knowledge.jsonl under workspace")
        .to_string_lossy()
        .to_string();
    let knowledge_v1 = std::fs::read_to_string(&knowledge_path).expect("v1 knowledge");
    seed_commit(
        &ws,
        &[
            (".agent/config.yaml", config.as_str()),
            (".agent/memory/_knowledge_map.yaml", "clusters: v1\n"),
            (".agent/memory/syntheses/s1.md", "# synthesis v1\n"),
            (knowledge_rel.as_str(), knowledge_v1.as_str()),
        ],
        "memory state v1",
    );

    // T1 sits strictly after every v1 stamp and strictly before every v2
    // stamp on BOTH clocks (second granularity).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let t1 = now_rfc3339_z();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // ── state v2 ──────────────────────────────────────────────────────────
    remember(&sut, "beta entry (v2)").await;
    seed_commit(
        &ws,
        &[
            (".agent/memory/_knowledge_map.yaml", "clusters: v2\n"),
            (".agent/memory/syntheses/s1.md", "# synthesis v2\n"),
        ],
        "memory state v2",
    );
    // Both entries are live pre-rollback (control: the v2 write genuinely landed).
    let pre = recall_contents(&sut, "entry").await;
    assert_eq!(
        pre.len(),
        2,
        "both entries recallable pre-rollback: {pre:?}"
    );

    // 063 precondition: a NON-initial cursor watermark, visible in the file.
    let cursor = sut
        .cursor_store()
        .expect("Cap::Memory wires the cursor store");
    cursor.flush(
        AGENT_ID,
        L6Cursor {
            last_knowledge_id: Some("k-99".into()),
            last_completed_at: std::time::SystemTime::now(),
        },
    );
    let cursor_file = cursor
        .cursor_file_path(AGENT_ID)
        .expect("with_root store exposes the file path");
    let watermark = std::fs::read_to_string(&cursor_file).expect("cursor file written");
    assert!(
        watermark.contains("last_knowledge_id: k-99"),
        "non-initial watermark on disk pre-rollback; got {watermark:?}"
    );

    // ── rollback-memory(T1) through the registered handler ───────────────
    let res = sut
        .call_host_fn_n(
            CAPABILITY,
            NAMESPACE,
            "rollback-memory",
            vec![Val::String(t1.clone())],
            1,
        )
        .await
        .expect("rollback-memory host fn dispatches");
    expect_ok(&res, "rollback-memory");

    // ── 064: recall returns the earlier set only ──────────────────────────
    let post = recall_contents(&sut, "entry").await;
    assert_eq!(
        post,
        vec!["alpha entry (v1)".to_string()],
        "post-T1 entries are absent from recall"
    );

    // ── 062: all three Git-tracked files are back at the v1 state ────────
    let knowledge_after = std::fs::read_to_string(&knowledge_path).expect("knowledge after");
    assert_eq!(
        knowledge_after, knowledge_v1,
        "knowledge.jsonl is byte-identical to the captured v1 state \
         (the store's in-process rollback persisted it)"
    );
    assert_eq!(
        std::fs::read_to_string(ws.join(".agent/memory/_knowledge_map.yaml")).unwrap(),
        "clusters: v1\n",
        "_knowledge_map.yaml restored from the at-or-before commit"
    );
    assert_eq!(
        std::fs::read_to_string(ws.join(".agent/memory/syntheses/s1.md")).unwrap(),
        "# synthesis v1\n",
        "syntheses/*.md restored from the at-or-before commit"
    );
    let rb = sut.assert_event("memory.rollback", |e| {
        e.payload
            .get("entries_deactivated")
            .and_then(|v| v.as_u64())
            == Some(1)
    });
    assert_eq!(
        rb.agent_id, AGENT_ID,
        "memory.rollback attributed to the caller"
    );
    sut.assert_event("git.rollback", |_| true);

    // ── 063: cursor file at the literal initial state, not a checkout ────
    let cursor_after = std::fs::read_to_string(&cursor_file).expect("cursor file present");
    assert_eq!(
        cursor_after, "last_knowledge_id: null\nlast_completed_at_epoch_secs: 0\n",
        "_knowledge_cursor.yaml materialized at epoch/0/0"
    );
    let in_mem = cursor.read(AGENT_ID).expect("materialized initial state");
    assert_eq!(in_mem.last_knowledge_id, None);
    assert_eq!(in_mem.last_completed_at, std::time::SystemTime::UNIX_EPOCH);
}

// Direction control — a rollback timestamp BEFORE any commit is a no-op on
// the git half (Ok, nothing restored) while the store half still applies:
// proves the at-or-before resolver does not grab a LATER commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_before_history_restores_nothing() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Memory])
        .build(J01_SKELETON)
        .await;
    let ws = sut.workspace_root().to_path_buf();
    let config = format!("agent_id: {}\n", AGENT_ID.strip_prefix("agent:").unwrap());

    // T0 predates every commit in the repo.
    let t0 = now_rfc3339_z();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    remember(&sut, "gamma entry").await;
    seed_commit(
        &ws,
        &[
            (".agent/config.yaml", config.as_str()),
            (".agent/memory/_knowledge_map.yaml", "clusters: post-t0\n"),
        ],
        "post-t0 state",
    );

    let res = sut
        .call_host_fn_n(
            CAPABILITY,
            NAMESPACE,
            "rollback-memory",
            vec![Val::String(t0.clone())],
            1,
        )
        .await
        .expect("rollback-memory dispatches");
    expect_ok(&res, "rollback-memory (pre-history timestamp)");

    // Git half: no commit at/before T0 → nothing checked out — the post-T0
    // file content stays (NOT clobbered by some later commit's state).
    assert_eq!(
        std::fs::read_to_string(ws.join(".agent/memory/_knowledge_map.yaml")).unwrap(),
        "clusters: post-t0\n",
        "no at-or-before commit → the git half is a no-op"
    );
    // Store half still applied: the post-T0 entry is dropped.
    let post = recall_contents(&sut, "gamma").await;
    assert!(
        post.is_empty(),
        "post-T0 entry dropped by the store half: {post:?}"
    );
}
