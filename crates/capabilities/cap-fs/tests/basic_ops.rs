//! Integration tests for the 4 basic fs ops: read/write/list/delete.

mod common;

use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    DefaultAtomicWriter, DefaultVirtualPathResolver, FsDeleteHandler, FsListHandler, FsReadHandler,
    FsWriteHandler, MetaMaintainer, MetaSchemaLoader, DEFAULT_MAX_LIST_ENTRIES, MAX_PATH_BYTES,
    MAX_READ_BYTES, MAX_WRITE_BYTES,
};
use wasmtime::component::Val;

use common::{single_agent_tree, TestEmitter};

const AGENT_ID: &str = "agent-1";
const TRACE_ID: &str = "trace-xyz";

fn ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT_ID.into(),
        trace_id: TRACE_ID.into(),
        turn_id: None,
        capability: "fs".into(),
        function: "advance:runtime/agent-fs::read".into(),
        run_id: None,
        iteration: None,
    }
}

struct Fixture {
    _tempdir: tempfile::TempDir,
    _workspace_root: std::path::PathBuf,
    agent_workspace: std::path::PathBuf,
    resolver: Arc<DefaultVirtualPathResolver>,
    emitter: Arc<TestEmitter>,
}

fn fixture() -> Fixture {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("agent-1");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = single_agent_tree(AGENT_ID, agent_workspace.clone());
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    Fixture {
        _tempdir: tempdir,
        _workspace_root: workspace_root,
        agent_workspace,
        resolver,
        emitter,
    }
}

fn maintainer() -> Arc<MetaMaintainer> {
    let schema_path = std::env::temp_dir().join("schema-test.yaml");
    Arc::new(MetaMaintainer::new(
        Arc::new(MetaSchemaLoader::new_with_default(schema_path)),
        Arc::new(DefaultAtomicWriter),
    ))
}

fn read_handler(f: &Fixture) -> FsReadHandler {
    FsReadHandler {
        resolver: f.resolver.clone(),
        emitter: f.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        preview_max_bytes: None,
    }
}
fn write_handler(f: &Fixture) -> FsWriteHandler {
    FsWriteHandler {
        resolver: f.resolver.clone(),
        emitter: f.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer(),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    }
}
fn list_handler(f: &Fixture) -> FsListHandler {
    FsListHandler {
        resolver: f.resolver.clone(),
        emitter: f.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    }
}
fn delete_handler(f: &Fixture) -> FsDeleteHandler {
    FsDeleteHandler {
        resolver: f.resolver.clone(),
        emitter: f.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer(),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    }
}

fn unwrap_ok_some_list(out: Vec<Val>) -> Vec<Val> {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Ok(Some(inner))) => match *inner {
            Val::List(items) => items,
            other => panic!("expected Val::List inner, got {other:?}"),
        },
        other => panic!("expected Val::Result(Ok(Some(_))), got {other:?}"),
    }
}

fn unwrap_ok_none(out: Vec<Val>) {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Ok(None)) => {}
        other => panic!("expected Val::Result(Ok(None)), got {other:?}"),
    }
}

fn unwrap_err_variant(out: Vec<Val>) -> (String, String) {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Err(Some(inner))) => match *inner {
            Val::Variant(case, Some(payload)) => match *payload {
                Val::String(s) => (case, s),
                other => panic!("expected Val::String payload, got {other:?}"),
            },
            other => panic!("expected Val::Variant(_, Some(_)), got {other:?}"),
        },
        other => panic!("expected Val::Result(Err(Some(_))), got {other:?}"),
    }
}

// SA-T12: read existing file → Ok(Some(List<U8>)) + emits fs.read.
#[tokio::test]
async fn read_existing_file_emits_fs_read() {
    let f = fixture();
    let path = f.agent_workspace.join("notes.md");
    std::fs::write(&path, b"hello").unwrap();
    let handler = read_handler(&f);
    let out = handler
        .call(ctx(), vec![Val::String("notes.md".into())], 1)
        .await
        .unwrap();
    let bytes = unwrap_ok_some_list(out);
    assert_eq!(bytes.len(), 5);
    let evs = f.emitter.snapshot();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type, "fs.read");
    assert_eq!(evs[0].agent_id, AGENT_ID);
    assert_eq!(evs[0].trace_id, TRACE_ID);
    let payload = &evs[0].payload;
    assert_eq!(payload["Read"]["size"], 5);
    assert_eq!(payload["Read"]["source"], "Private");
}

// SA-T13: read non-existent → Err(Variant(not-found)) + no emit.
// Slice B adversarial-round-1 fix: handler-level ENOENT now maps to NotFound
// (rather than IoError) so a guest cannot fingerprint hidden-class paths
// (which always return NotFound) vs merely-missing visible paths (which
// historically returned IoError).
#[tokio::test]
async fn read_nonexistent_returns_err_no_emit() {
    let f = fixture();
    let handler = read_handler(&f);
    let out = handler
        .call(ctx(), vec![Val::String("missing.md".into())], 1)
        .await
        .unwrap();
    let (case, _msg) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(f.emitter.snapshot().len(), 0);
}

// SA-T14: write new file → Ok(None) + fs.write event with is_new_file=true.
#[tokio::test]
async fn write_new_file_unit_ok_arm() {
    let f = fixture();
    let handler = write_handler(&f);
    let data: Vec<Val> = b"abc".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(ctx(), vec![Val::String("a.txt".into()), Val::List(data)], 1)
        .await
        .unwrap();
    unwrap_ok_none(out);
    assert_eq!(
        std::fs::read(f.agent_workspace.join("a.txt")).unwrap(),
        b"abc"
    );
    let evs = f.emitter.snapshot();
    // Slice B emits both fs.write and meta.updated (AC-10 atomic; renamed Slice D per PRD §15.3.8).
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0].event_type, "fs.write");
    assert_eq!(evs[0].payload["Write"]["is_new_file"], true);
    assert_eq!(evs[0].payload["Write"]["size"], 3);
    assert_eq!(evs[1].event_type, "meta.updated");
}

// SA-T15: overwrite → is_new_file=false.
#[tokio::test]
async fn write_overwrite_emits_is_new_file_false() {
    let f = fixture();
    std::fs::write(f.agent_workspace.join("b.txt"), b"old").unwrap();
    let handler = write_handler(&f);
    let data: Vec<Val> = b"new".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(ctx(), vec![Val::String("b.txt".into()), Val::List(data)], 1)
        .await
        .unwrap();
    unwrap_ok_none(out);
    let evs = f.emitter.snapshot();
    assert_eq!(evs[0].payload["Write"]["is_new_file"], false);
}

// SA-T15b: atomic_write Err (oversized via second-gate) → Err + no emit.
#[tokio::test]
async fn write_atomic_err_no_emit() {
    let f = fixture();
    let handler = write_handler(&f);
    // Trigger atomic_write's MAX_WRITE_BYTES check by going past it. The handler-entry
    // check is 1-byte-tighter (data_vals.len() vs the conversion-loop allocation), so
    // we need the SAME bound to catch it at the atomic_write inner check. Simulate
    // an inner failure by writing to a path whose parent cannot be created. We use a
    // path under .advance/ which the resolver rejects — so the rejection happens at
    // resolve_write, NOT atomic_write. To exercise atomic_write Err specifically:
    // write to a path where the parent dir is actually a regular file (cannot be
    // create_dir_all'd).
    let blocker = f.agent_workspace.join("blocker");
    std::fs::write(&blocker, b"i am a file, not a dir").unwrap();
    let data: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx(),
            vec![Val::String("blocker/inside.txt".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "io-error");
    assert_eq!(
        f.emitter.snapshot().len(),
        0,
        "atomic_write Err must produce no fs.write event"
    );
}

// SA-T16: list directory → Ok(Some(List<Record>)) + fs.list.
#[tokio::test]
async fn list_directory_emits_fs_list() {
    let f = fixture();
    std::fs::write(f.agent_workspace.join("z.md"), b"z").unwrap();
    std::fs::write(f.agent_workspace.join("a.md"), b"a").unwrap();
    let handler = list_handler(&f);
    let out = handler
        .call(ctx(), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    let items = unwrap_ok_some_list(out);
    assert_eq!(items.len(), 2);
    // entries sorted alphabetically: a.md before z.md
    match &items[0] {
        Val::Record(fields) => match &fields[0].1 {
            Val::String(s) => assert_eq!(s, "a.md"),
            _ => panic!("expected name string"),
        },
        _ => panic!("expected Val::Record"),
    }
    let evs = f.emitter.snapshot();
    assert_eq!(evs[0].event_type, "fs.list");
    assert_eq!(evs[0].payload["List"]["count"], 2);
}

// SA-T17: list on a file (not dir) → Err.
#[tokio::test]
async fn list_on_file_returns_err_no_emit() {
    let f = fixture();
    std::fs::write(f.agent_workspace.join("file.md"), b"x").unwrap();
    let handler = list_handler(&f);
    let out = handler
        .call(ctx(), vec![Val::String("file.md".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "io-error");
    assert_eq!(f.emitter.snapshot().len(), 0);
}

// SA-T18: delete → Ok(None) + fs.delete.
#[tokio::test]
async fn delete_existing_file_unit_ok() {
    let f = fixture();
    let path = f.agent_workspace.join("d.txt");
    std::fs::write(&path, b"x").unwrap();
    let handler = delete_handler(&f);
    let out = handler
        .call(ctx(), vec![Val::String("d.txt".into())], 1)
        .await
        .unwrap();
    unwrap_ok_none(out);
    assert!(!path.exists());
    let evs = f.emitter.snapshot();
    assert_eq!(evs[0].event_type, "fs.delete");
}

// SA-T19: delete non-existent → Err + no emit.
// Slice B adversarial-round-1 fix: like read, ENOENT on delete maps to
// not-found (rather than io-error) so the variant doesn't fingerprint.
#[tokio::test]
async fn delete_nonexistent_returns_err_no_emit() {
    let f = fixture();
    let handler = delete_handler(&f);
    let out = handler
        .call(ctx(), vec![Val::String("ghost.txt".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(f.emitter.snapshot().len(), 0);
}

// SA-T24: oversized path param → typed fs-error invalid-path via WIT
// result-arm (slice B adversarial-round-6 fix: bounded inputs return
// fs-error, not HostCallError trap).
#[tokio::test]
async fn read_rejects_oversized_path() {
    let f = fixture();
    let handler = read_handler(&f);
    let big = "a".repeat(MAX_PATH_BYTES + 1);
    let out = handler
        .call(ctx(), vec![Val::String(big)], 1)
        .await
        .unwrap();
    let (case, msg) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
    assert!(msg.contains("MAX_PATH_BYTES"), "got: {msg}");
}

// SA-T25: oversized data param → HandlerError BEFORE conversion loop.
#[tokio::test]
async fn write_rejects_oversized_data_at_entry() {
    let f = fixture();
    let handler = write_handler(&f);
    // Build a Val::List of MAX_WRITE_BYTES+1 zero bytes — handler-entry check should
    // reject before the conversion loop allocates the Vec<u8>. Slice B
    // adversarial-round-7 fix: rejection now goes through WIT result-arm
    // (invalid-path) instead of HostCallError trap.
    let huge: Vec<Val> = vec![Val::U8(0); MAX_WRITE_BYTES + 1];
    let out = handler
        .call(ctx(), vec![Val::String("x.txt".into()), Val::List(huge)], 1)
        .await
        .unwrap();
    let (case, msg) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
    assert!(msg.contains("MAX_WRITE_BYTES"), "got: {msg}");
}

// SA-T25b: file > MAX_READ_BYTES → Err(io-error) via metadata pre-check + no emit.
//
// Rather than create a 64+ MiB file, we monkey-test by reading a sparse file whose
// metadata reports a size > MAX_READ_BYTES. Linux supports sparse files via
// File::set_len; macOS APFS supports them too. If the platform doesn't support
// sparse files, this test creates a real big file (slow; gated behind
// `if cfg!(not(target_os = "linux"))` for now we just try set_len which is supported
// on macOS too).
#[tokio::test]
async fn read_rejects_oversized_file_via_metadata() {
    let f = fixture();
    let path = f.agent_workspace.join("big.bin");
    let file = std::fs::File::create(&path).unwrap();
    // Sparse file — on macOS APFS and Linux ext4/xfs/btrfs, set_len doesn't allocate
    // physical blocks. On filesystems without sparse support this would actually
    // allocate, but tempfile uses the system temp dir which is sparse-capable on
    // both macOS and Linux.
    file.set_len((MAX_READ_BYTES + 1) as u64).unwrap();
    drop(file);
    let handler = read_handler(&f);
    let out = handler
        .call(ctx(), vec![Val::String("big.bin".into())], 1)
        .await
        .unwrap();
    let (case, msg) = unwrap_err_variant(out);
    assert_eq!(case, "io-error");
    assert!(
        msg.contains("MAX_READ_BYTES"),
        "expected MAX_READ_BYTES message, got: {msg}"
    );
    assert_eq!(f.emitter.snapshot().len(), 0);
}

// SA-T26: read with wrong shape → HandlerError.
#[tokio::test]
async fn read_rejects_wrong_param_shape() {
    let f = fixture();
    let handler = read_handler(&f);
    let err = handler
        .call(ctx(), vec![Val::U32(42)], 1)
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("expected single Val::String"));
}

// SA-T27: write with wrong param shape → HandlerError.
#[tokio::test]
async fn write_rejects_wrong_param_shape() {
    let f = fixture();
    let handler = write_handler(&f);
    let err = handler
        .call(ctx(), vec![Val::String("p".into())], 1)
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("Val::String"));
}

// SA-T27b: write rejects non-Val::U8 in data list.
#[tokio::test]
async fn write_rejects_non_u8_in_data_list() {
    let f = fixture();
    let handler = write_handler(&f);
    let bad = vec![Val::U8(1), Val::U16(2), Val::U8(3)];
    let err = handler
        .call(ctx(), vec![Val::String("p.txt".into()), Val::List(bad)], 1)
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("non-u8 element"));
}

#[allow(dead_code)]
fn _stay_alive(_: tempfile::TempDir) {}

// Helper to ensure tempdir lives across tests above (when fixture()'s tempdir is dropped
// at end of scope, the workspace is cleaned up — fine for individual tests since each
// builds its own fixture).
