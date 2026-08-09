//! Resolver-level + handler-level path permission tests:
//!   traversal/absolute rejection, .advance/ hidden, .git/.meta.yaml/.sqlite hidden,
//!   resolve_child_read / resolve_slug_read stubs, single-agent territory expansion.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    DefaultAtomicWriter, DefaultVirtualPathResolver, FsError, FsReadHandler, FsWriteHandler,
    MetaMaintainer, MetaSchemaLoader, VirtualPathResolver,
};

fn perm_test_maintainer() -> Arc<MetaMaintainer> {
    let schema_path = std::env::temp_dir().join("schema-perm-test.yaml");
    Arc::new(MetaMaintainer::new(
        Arc::new(MetaSchemaLoader::new_with_default(schema_path)),
        Arc::new(DefaultAtomicWriter),
    ))
}
use wasmtime::component::Val;

use common::{single_agent_tree, TestEmitter};

const AGENT_ID: &str = "agent-x";
const TRACE_ID: &str = "tr";

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

struct Setup {
    _tempdir: tempfile::TempDir,
    workspace_root: PathBuf,
    agent_workspace: PathBuf,
    resolver: DefaultVirtualPathResolver,
}

fn setup() -> Setup {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(AGENT_ID);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = single_agent_tree(AGENT_ID, agent_workspace.clone());
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    Setup {
        _tempdir: tempdir,
        workspace_root,
        agent_workspace,
        resolver,
    }
}

fn read_handler_for(setup: &Setup) -> (FsReadHandler, Arc<TestEmitter>) {
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        setup.workspace_root.clone(),
        Arc::new(single_agent_tree(AGENT_ID, setup.agent_workspace.clone()))
            as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    (
        FsReadHandler {
            resolver: resolver as Arc<dyn VirtualPathResolver>,
            emitter: emitter.clone() as Arc<dyn EventBusEmit>,
            concurrency: common::test_concurrency(),
            preview_max_bytes: None,
        },
        emitter,
    )
}

fn write_handler_for(setup: &Setup) -> (FsWriteHandler, Arc<TestEmitter>) {
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        setup.workspace_root.clone(),
        Arc::new(single_agent_tree(AGENT_ID, setup.agent_workspace.clone()))
            as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    (
        FsWriteHandler {
            resolver: resolver as Arc<dyn VirtualPathResolver>,
            emitter: emitter.clone() as Arc<dyn EventBusEmit>,
            concurrency: common::test_concurrency(),
            maintainer: perm_test_maintainer(),
            writer: Arc::new(DefaultAtomicWriter),
            db_sync: None,
            workspace_root: None,
            agent_tree: None,
            git_sync: None,
        },
        emitter,
    )
}

fn unwrap_err_variant(out: Vec<Val>) -> (String, String) {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Err(Some(inner))) => match *inner {
            Val::Variant(case, Some(payload)) => match *payload {
                Val::String(s) => (case, s),
                other => panic!("expected String payload, got {other:?}"),
            },
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("expected Err(Some), got {other:?}"),
    }
}

// ─── Resolver-level unit tests ──────────────────────────────────────────────

// SA-T04: resolve_read happy path.
#[test]
fn resolve_read_happy_path() {
    let s = setup();
    let physical = s.resolver.resolve_read(AGENT_ID, "subdir/file.md").unwrap();
    assert!(physical.starts_with(&s.agent_workspace));
    assert_eq!(physical.file_name().unwrap(), "file.md");
}

// SA-T05: traversal `..` rejected.
#[test]
fn resolve_read_rejects_parent_dir_component() {
    let s = setup();
    let err = s.resolver.resolve_read(AGENT_ID, "../escape").unwrap_err();
    assert!(matches!(err, FsError::InvalidPath(_)), "got {err:?}");
}

// SA-T05b: benign filename `..foo` (Component::Normal) accepted.
#[test]
fn resolve_read_accepts_dotdot_prefixed_filename() {
    let s = setup();
    s.resolver
        .resolve_read(AGENT_ID, "..foo")
        .expect("..foo should be a valid Normal component");
}

// SA-T05c: benign filename `archive..2025` accepted.
#[test]
fn resolve_read_accepts_double_dot_inside_name() {
    let s = setup();
    s.resolver
        .resolve_read(AGENT_ID, "archive..2025")
        .expect("archive..2025 should be a Normal component");
}

// SA-T06: absolute path rejected.
#[test]
fn resolve_read_rejects_absolute_path() {
    let s = setup();
    let err = s
        .resolver
        .resolve_read(AGENT_ID, "/etc/passwd")
        .unwrap_err();
    assert!(matches!(err, FsError::InvalidPath(_)));
}

// SA-T06b: Windows-prefix path rejected (component check rejects RootDir/Prefix).
#[test]
fn resolve_read_rejects_windows_prefix_path() {
    let s = setup();
    // On POSIX `C:\foo` is parsed as a single Normal component "C:\foo" — the
    // RootDir/Prefix check does NOT trigger. But Path::is_absolute on POSIX returns
    // false for "C:\foo" too, so it's accepted as a single funky filename. The test
    // here verifies the EXPLICIT absolute-path or RootDir rejection on Linux/macOS;
    // Windows-style prefix handling is a Windows-platform concern and not slice A.
    // So we test the more general invariant: any path whose first component is
    // RootDir is rejected. macOS path `/foo` passes that test.
    let err = s.resolver.resolve_read(AGENT_ID, "/foo").unwrap_err();
    assert!(matches!(err, FsError::InvalidPath(_)));
}

// SA-T07: defense-in-depth marker. The lexical containment guard at Step 4
// (`physical.starts_with(&agent_workspace)`) is intentionally hard to trigger
// on POSIX: any vpath that survives Step 1's `Component::ParentDir/RootDir/Prefix`
// component check produces a `Path::join` result that contains agent_workspace as
// a component prefix. So the branch protects against future canonicalization
// vectors (symlink resolution, case-insensitive filesystem normalization) that
// may surface in slice B+; on POSIX with no canonicalization, it's currently
// dead code. We verify (a) Step 1 catches the obvious cases (covered by SA-T05/06)
// and (b) the symlink defense at Step 7 catches pre-existing symlinks (SA-T07b).
#[test]
fn resolve_read_lexical_containment_acknowledged_dead_in_slice_a() {
    let s = setup();
    let physical = s
        .resolver
        .resolve_read(AGENT_ID, "deep/path/file.md")
        .unwrap();
    assert!(physical.starts_with(&s.agent_workspace));
    // Branch is documented defense-in-depth; tested indirectly via SA-T07b
    // (symlink escape) — that's the realistic failure mode the lexical guard
    // can't catch and the symlink walk catches instead.
}

// SA-T07b: symlink defense — pre-existing symlink under agent territory must
// be rejected, NOT followed. Without this, atomic_write would persist outside
// the territory.
#[cfg(unix)]
#[test]
fn resolve_read_rejects_pre_existing_symlink_in_path() {
    let s = setup();
    // Create an "outside" target dir and a symlink inside the agent workspace
    // pointing to it.
    let outside = s._tempdir.path().join("outside-territory");
    std::fs::create_dir_all(&outside).unwrap();
    let symlink_path = s.agent_workspace.join("escape");
    std::os::unix::fs::symlink(&outside, &symlink_path).unwrap();
    // Now any vpath traversing through "escape" must be rejected.
    let err = s
        .resolver
        .resolve_read(AGENT_ID, "escape/secret.txt")
        .unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

// SA-T07c: symlink at the leaf is also rejected on read.
#[cfg(unix)]
#[test]
fn resolve_read_rejects_symlink_leaf() {
    let s = setup();
    let outside = s._tempdir.path().join("outside.txt");
    std::fs::write(&outside, b"secret").unwrap();
    let leaf_link = s.agent_workspace.join("link.txt");
    std::os::unix::fs::symlink(&outside, &leaf_link).unwrap();
    let err = s.resolver.resolve_read(AGENT_ID, "link.txt").unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

// SA-T07d: MAX_PATH_DEPTH cap rejects paths with too many components.
#[test]
fn resolve_read_rejects_excessive_depth() {
    let s = setup();
    // Build a 33-component path (one over MAX_PATH_DEPTH = 32).
    let deep: String = (0..33)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join("/");
    let err = s.resolver.resolve_read(AGENT_ID, &deep).unwrap_err();
    match err {
        FsError::InvalidPath(ref msg) => assert!(
            msg.contains("MAX_PATH_DEPTH"),
            "expected MAX_PATH_DEPTH message, got: {msg}"
        ),
        other => panic!("expected InvalidPath, got {other:?}"),
    }
}

// SA-T07e: paths at exactly MAX_PATH_DEPTH (32 components) are accepted.
#[test]
fn resolve_read_accepts_max_depth() {
    let s = setup();
    let exactly_max: String = (0..32)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join("/");
    s.resolver
        .resolve_read(AGENT_ID, &exactly_max)
        .expect("32-component path should resolve");
}

// SA-T07f: non-ASCII path components rejected (slice A surface reduction
// against Unicode-homoglyph + filesystem-normalization attacks).
#[test]
fn resolve_read_rejects_non_ascii_component() {
    let s = setup();
    // Turkish dotless i, Cyrillic і, fullwidth letter all banned in slice A.
    for v in [".gıt/HEAD", ".gіt/HEAD", "ｆｉｌｅ.txt", "café.md"] {
        let err = s.resolver.resolve_read(AGENT_ID, v).unwrap_err();
        assert!(
            matches!(err, FsError::InvalidPath(ref m) if m.contains("non-ASCII")),
            "got {err:?} for {v}"
        );
    }
}

// SA-T07g: resolve_write rejects empty / CurDir-only vpaths that resolve to
// the territory root (closes the temp-file-in-territory-parent sandbox-
// escape vector found in adversarial round 3).
#[test]
fn resolve_write_rejects_empty_or_curdir_only_vpath() {
    let s = setup();
    for v in ["", ".", "./", "././."] {
        let err = s.resolver.resolve_write(AGENT_ID, v).unwrap_err();
        assert!(
            matches!(err, FsError::InvalidPath(ref m) if m.contains("territory root") || m.contains("no Normal")),
            "got {err:?} for {v:?}"
        );
    }
}

// SA-T07h: resolve_read still ACCEPTS empty / "." vpaths (legitimate "list
// my own territory" / "read territory metadata" use cases).
#[test]
fn resolve_read_accepts_curdir_for_list_use_case() {
    let s = setup();
    let physical = s
        .resolver
        .resolve_read(AGENT_ID, ".")
        .expect("resolve_read on '.' should succeed for list use case");
    assert_eq!(physical, s.agent_workspace.join("."));
}

// SA-T36: FsListHandler must FILTER hidden-name entries — closes the
// fingerprinting bypass where fs.list("."") would surface .git/.meta.yaml/
// *.sqlite/.advance entries that resolve_read rejects.
#[tokio::test]
async fn list_handler_filters_workspace_hidden_entries() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    // Territory == workspace_root so .advance/ is a sibling of test files.
    let agent_workspace = workspace_root.clone();
    let tree = single_agent_tree(AGENT_ID, agent_workspace.clone());
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = cap_fs::FsListHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: cap_fs::DEFAULT_MAX_LIST_ENTRIES,
    };
    // Plant several hidden-name entries plus one visible file.
    for hidden in [".git", ".meta.yaml", "data.sqlite", "data.sqlite-wal"] {
        std::fs::create_dir_all(agent_workspace.join(hidden)).unwrap();
    }
    std::fs::create_dir_all(agent_workspace.join(".advance")).unwrap();
    std::fs::write(agent_workspace.join("visible.md"), b"hi").unwrap();

    let out = handler
        .call(ctx(), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    let names: Vec<String> = match out.into_iter().next().unwrap() {
        Val::Result(Ok(Some(inner))) => match *inner {
            Val::List(items) => items
                .into_iter()
                .map(|item| match item {
                    Val::Record(fields) => match &fields[0].1 {
                        Val::String(s) => s.clone(),
                        _ => panic!("name field not String"),
                    },
                    _ => panic!("entry not Record"),
                })
                .collect(),
            _ => panic!("expected Val::List"),
        },
        _ => panic!("expected Ok(Some)"),
    };
    assert_eq!(names, vec!["visible.md".to_string()]);
    assert!(!names.iter().any(|n| n == ".git"));
    assert!(!names.iter().any(|n| n == ".meta.yaml"));
    assert!(!names.iter().any(|n| n == ".advance"));
    assert!(!names.iter().any(|n| n.contains(".sqlite")));
}

// SA-T37: FsListHandler must SKIP symlink entries (don't disclose target
// metadata, don't abort whole list on broken symlink).
#[cfg(unix)]
#[tokio::test]
async fn list_handler_skips_symlink_entries() {
    let s = setup();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        s.workspace_root.clone(),
        Arc::new(single_agent_tree(AGENT_ID, s.agent_workspace.clone()))
            as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = cap_fs::FsListHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: cap_fs::DEFAULT_MAX_LIST_ENTRIES,
    };
    std::fs::write(s.agent_workspace.join("real.md"), b"r").unwrap();
    let outside = s._tempdir.path().join("outside.md");
    std::fs::write(&outside, b"secret").unwrap();
    std::os::unix::fs::symlink(&outside, s.agent_workspace.join("link.md")).unwrap();
    let broken_target = s._tempdir.path().join("nonexistent");
    std::os::unix::fs::symlink(&broken_target, s.agent_workspace.join("broken-link")).unwrap();

    let out = handler
        .call(ctx(), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    let names: Vec<String> = match out.into_iter().next().unwrap() {
        Val::Result(Ok(Some(inner))) => match *inner {
            Val::List(items) => items
                .into_iter()
                .map(|item| match item {
                    Val::Record(fields) => match &fields[0].1 {
                        Val::String(s) => s.clone(),
                        _ => panic!("name not String"),
                    },
                    _ => panic!("entry not Record"),
                })
                .collect(),
            _ => panic!("expected Val::List"),
        },
        other => panic!("expected Ok(Some), got {other:?}"),
    };
    // Both symlinks (live + broken) skipped; only real file surfaces.
    assert_eq!(names, vec!["real.md".to_string()]);
}

// SA-T08c: hidden-name match is case-insensitive (defense for macOS APFS
// case-insensitive filesystems where `.GIT/HEAD` reaches `.git/HEAD`).
#[test]
fn hidden_name_check_is_case_insensitive() {
    let s = setup();
    for v in [
        ".GIT/HEAD",
        ".Git/HEAD",
        ".git/head",
        ".Meta.YAML",
        ".META.YAML",
    ] {
        let err = s.resolver.resolve_read(AGENT_ID, v).unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)), "got {err:?} for {v}");
    }
}

// SA-T08d: extended SQLite sidecar suffixes (-shm and -journal) are also hidden.
#[test]
fn hidden_name_check_covers_all_sqlite_sidecars() {
    let s = setup();
    for v in [
        "data.sqlite",
        "data.sqlite-wal",
        "data.sqlite-shm",
        "data.sqlite-journal",
        "DATA.SQLITE-JOURNAL", // case-insensitive
    ] {
        let err = s.resolver.resolve_read(AGENT_ID, v).unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)), "got {err:?} for {v}");
    }
}

// SA-T08b: hidden-name check operates on RELATIVE vpath components, not
// physical (which would false-positive-block when host workspace ancestor
// happens to be named `.git` or contains `.sqlite` etc.).
#[test]
fn hidden_name_check_does_not_false_positive_on_host_ancestor() {
    // Build a workspace whose PARENT path contains ".git" as a component.
    // E.g., if you're running tests inside a repo clone, the absolute path may
    // contain `.../.git/...` — verify the resolver does NOT block legitimate
    // intra-territory paths in that scenario.
    let outer = tempfile::TempDir::new().unwrap();
    let host_with_git = outer.path().join(".git").join("inner-clone");
    std::fs::create_dir_all(&host_with_git).unwrap();
    let agent_workspace = host_with_git.join("agent-zone");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = single_agent_tree("a-host", agent_workspace.clone());
    let resolver = DefaultVirtualPathResolver::new(
        host_with_git.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    // A benign vpath should resolve fine even though host ancestor is `.git/`.
    let physical = resolver.resolve_read("a-host", "notes.md").unwrap();
    assert!(physical.starts_with(&agent_workspace));
}

// SA-T08: resolve_read rejects path under workspace_root/.advance.
#[test]
fn resolve_read_rejects_advance_dir() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    // Make agent territory == workspace_root so .advance is reachable from a vpath.
    std::fs::create_dir_all(&workspace_root).unwrap();
    let tree = single_agent_tree(AGENT_ID, workspace_root.clone());
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    let err = resolver
        .resolve_read(AGENT_ID, ".advance/runtime-config.yaml")
        .unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

// SA-T09: agent_id not in tree → NotFound.
#[test]
fn resolve_read_unknown_agent_returns_not_found() {
    let s = setup();
    let err = s.resolver.resolve_read("unknown-agent", "x").unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

// SB-T08: resolve_child_read on a single-agent fixture returns NotFound (no children).
#[test]
fn resolve_child_read_no_children() {
    let s = setup();
    let err = s
        .resolver
        .resolve_child_read("parent", "child", "x")
        .unwrap_err();
    assert!(
        matches!(err, FsError::NotFound(_)),
        "expected NotFound for missing topology, got {err:?}"
    );
}

// SB-T10: resolve_slug_read on a single-agent fixture returns NotFound (no peers).
#[test]
fn resolve_slug_read_no_peers() {
    let s = setup();
    let err = s
        .resolver
        .resolve_slug_read("self", "peer", "slug", "f.txt")
        .unwrap_err();
    assert!(
        matches!(err, FsError::NotFound(_)),
        "expected NotFound for missing topology, got {err:?}"
    );
}

// SA-T11b: constructor stores both fields and resolve_read uses workspace_root.
#[test]
fn constructor_smoke_test() {
    let s = setup();
    let physical = s.resolver.resolve_read(AGENT_ID, "f.txt").unwrap();
    assert!(physical.starts_with(&s.agent_workspace));
}

// ─── Handler-level integration tests ────────────────────────────────────────

// SA-T20: ../escape via FsReadHandler → InvalidPath + no emit.
#[tokio::test]
async fn read_handler_invalid_path_no_emit() {
    let s = setup();
    let (handler, emitter) = read_handler_for(&s);
    let out = handler
        .call(ctx(), vec![Val::String("../escape".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T20b: backslash path on POSIX — Step 1 accepts (Normal component); resolve
// passes; tokio::fs::read returns Err → not-found variant (slice B adversarial
// fix maps ENOENT to not-found instead of io-error to defeat fingerprinting).
// Emitter saw nothing.
#[tokio::test]
async fn read_handler_backslash_path_io_error_no_emit() {
    let s = setup();
    let (handler, emitter) = read_handler_for(&s);
    let out = handler
        .call(ctx(), vec![Val::String("..\\escape".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(
        case, "not-found",
        "backslash path on POSIX is treated as a Normal filename; the file doesn't exist so we get not-found (post-fingerprinting-fix)"
    );
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T21: absolute path → invalid-path + no emit.
#[tokio::test]
async fn read_handler_absolute_path_no_emit() {
    let s = setup();
    let (handler, emitter) = read_handler_for(&s);
    let out = handler
        .call(ctx(), vec![Val::String("/etc/passwd".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T22: read .advance/ → not-found + no emit.
#[tokio::test]
async fn read_handler_rejects_advance_dir() {
    // Construct a setup where agent territory == workspace_root so the .advance/
    // path is inside the territory.
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = single_agent_tree(AGENT_ID, workspace_root.clone());
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        preview_max_bytes: None,
    };
    let out = handler
        .call(
            ctx(),
            vec![Val::String(".advance/runtime-config.yaml".into())],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T23: write into .advance/ → not-found + no emit.
#[tokio::test]
async fn write_handler_rejects_advance_dir() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = single_agent_tree(AGENT_ID, workspace_root.clone());
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: perm_test_maintainer(),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = vec![Val::U8(1)];
    let out = handler
        .call(
            ctx(),
            vec![Val::String(".advance/foo".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T31: read .git/HEAD → not-found from hidden-name check.
#[tokio::test]
async fn read_handler_rejects_dot_git() {
    let s = setup();
    let (handler, emitter) = read_handler_for(&s);
    let out = handler
        .call(ctx(), vec![Val::String(".git/HEAD".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T32: read .meta.yaml directly → not-found from hidden-name check.
#[tokio::test]
async fn read_handler_rejects_meta_yaml() {
    let s = setup();
    let (handler, emitter) = read_handler_for(&s);
    let out = handler
        .call(ctx(), vec![Val::String(".meta.yaml".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T33: read *.sqlite / *.sqlite-wal → not-found.
#[tokio::test]
async fn read_handler_rejects_sqlite_files() {
    let s = setup();
    let (handler, _emitter) = read_handler_for(&s);
    for fname in ["data.sqlite", "data.sqlite-wal"] {
        let out = handler
            .call(ctx(), vec![Val::String(fname.into())], 1)
            .await
            .unwrap();
        let (case, _) = unwrap_err_variant(out);
        assert_eq!(case, "not-found", "for {fname}");
    }
}

// SA-T34: nested .git component (subdir/.git/HEAD) → not-found.
#[tokio::test]
async fn read_handler_rejects_nested_dot_git() {
    let s = setup();
    let (handler, emitter) = read_handler_for(&s);
    let out = handler
        .call(ctx(), vec![Val::String("subdir/.git/HEAD".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(emitter.snapshot().len(), 0);
}

// SA-T35: write into .git/HEAD → not-found (resolve_write delegates to resolve_read).
#[tokio::test]
async fn write_handler_rejects_dot_git() {
    let s = setup();
    let (handler, emitter) = write_handler_for(&s);
    let data: Vec<Val> = vec![Val::U8(0)];
    let out = handler
        .call(
            ctx(),
            vec![Val::String(".git/HEAD".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
    assert_eq!(emitter.snapshot().len(), 0);
}
