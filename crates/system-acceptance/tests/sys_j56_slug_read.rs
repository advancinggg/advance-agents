//! Track C — SYS-J-56 witness: same-slug peer read + cross-territory deny.
//!
//! Witnesses **SYS-AC-176** and **SYS-AC-177** against the REAL `cap-fs`
//! `DefaultVirtualPathResolver` + the REAL slug `HostFunctionHandler` impls
//! (`FsReadSlugHandler`, `FsListSlugHandler`), wired over a REAL
//! `cap_lifecycle::AgentTreeStore` whose `snapshot()` populates the production
//! `peer_slug_map` from sibling `template_ref`s. No module in the chain is
//! mocked: the resolver is the production struct, the handlers are the
//! production structs, the tree store is the production struct. Only the
//! `EventBusEmit` SINK is test-owned (a tiny in-file `Arc<Mutex<Vec<Event>>>`
//! collector) — exactly the `sys_j47_fs_write_events.rs` discipline, where the
//! observed seam IS `EventBusEmit`. (For directly-constructed providers the
//! harness exposes no shared bus accessor, so a self-injected sink is the
//! faithful witness surface.)
//!
//! REAL-PROVIDER witness, NOT a guest turn. The harness spawner constructs with
//! `resolver: None`, so `spawn_child(template_ref=Some(..))` hard-rejects and
//! `HarnessAgentTree::snapshot()` returns an empty `peer_slug_map` — same-slug
//! peers cannot be seeded through the harness. Per the HF-sanctioned
//! `mode_agents_smoke.rs` pattern we therefore build a fresh REAL
//! `AgentTreeStore` in-test (`insert_root` then two `insert_child`s sharing one
//! charset-valid `template_ref` => `build_peer_slug_map` keys the slug), and
//! drive the REAL resolver + REAL slug handlers directly. The guest
//! `read-slug`/`list-slug` host-fn call (component-linker path) is the
//! upstream-blocked surface (UNVERSIONED-namespace linker gap); we drive the
//! production `HostFunctionHandler::call(ctx, params, results_len)` directly,
//! which is the accepted Track-C witness bar.
//!
//! Scope discipline (witness-floor) — what this file deliberately does NOT
//! assert / known deviations it DOES document:
//!   - SYS-AC-177 error-class: the criterion's wording is "PermissionDenied",
//!     but cap-fs surfaces every cross-territory / hidden / topology-mismatch
//!     denial as `FsError::NotFound` with a CONSTANT "path not found" payload
//!     (the anti-fingerprint invariant, `resolver.rs:149-155, 271-273, 466-477`)
//!     — never a literal `PermissionDenied` on the slug-read path — so a guest
//!     cannot fingerprint a hidden/forbidden peer from a visible-ENOENT one. We
//!     assert `Err(FsError::NotFound(_))` for the cross-territory READ denial
//!     and DOCUMENT that this NotFound IS the access-control denial (the
//!     criterion's PermissionDenied intent is satisfied at the resolver gate).
//!   - The peer-territory WRITE/DELETE leg: slug access is READ-ONLY (there is
//!     no `write-slug` host fn). A peer territory is a SIBLING dir, lexically
//!     unreachable from the agent's own `resolve_write` except via a `..`
//!     traversal, which the component gate rejects as `InvalidPath`
//!     (`resolver.rs:236-237`). We witness that the peer dir is unreachable for
//!     write (the denial surfaces as `InvalidPath`/`NotFound`, NOT a successful
//!     write) and document that the read-path anti-fingerprint NotFound does not
//!     apply to the write-traversal gate.
//!   - `scan-slug` (`FsScanSlugHandler`) is exercised only at the resolver
//!     level (same `resolve_slug_read` entry the read/list handlers use) to
//!     avoid the `.meta.yaml` + `MetaMaintainer` setup; the `fs.*` Slug event
//!     source is asserted via the driven `FsReadSlugHandler`/`FsListSlugHandler`.
//!   - SYS-AC-245 (scan-slug <2ms perf-SLO) is a recorded deferral (shared
//!     disk-pressured parallel-worktree CI), not claimed here.
//!
//! `#[tokio::test(flavor = "multi_thread")]` is mandatory: the slug handlers run
//! `resolve_slug_read` inside `tokio::task::spawn_blocking`
//! (`host_fn.rs:1655, 1750`), which requires a multi-thread runtime.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    DefaultVirtualPathResolver, FsError, FsListSlugHandler, FsReadSlugHandler, VirtualPathResolver,
    DEFAULT_FS_CONCURRENCY, DEFAULT_MAX_LIST_ENTRIES,
};
use cap_lifecycle::AgentTreeStore;
use tokio::sync::Semaphore;
use wasmtime::component::Val;

/// In-file capturing `EventBusEmit` sink (the only test-owned seam — the
/// resolver/handlers/store are all REAL production types). Mirrors the
/// `sys_j47` discipline: assert on THIS sink, never a harness bus accessor.
#[derive(Clone, Default)]
struct CapturingSink {
    events: Arc<Mutex<Vec<Event>>>,
}

impl CapturingSink {
    fn snapshot(&self) -> Vec<Event> {
        self.events.lock().expect("sink poisoned").clone()
    }
}

impl EventBusEmit for CapturingSink {
    fn emit(&self, event: Event) {
        self.events.lock().expect("sink poisoned").push(event);
    }
}

/// Build the per-agent `HostCallContext` the slug handlers read `agent_id` /
/// `trace_id` from (the caller identity that drives `resolve_slug_read`'s
/// `peer_slug_map[agent_id]` lookup and the emitted event's `agent_id`).
fn ctx_for(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.to_string(),
        trace_id: "trace-j56".to_string(),
        turn_id: None,
        capability: "fs".to_string(),
        function: "advance:runtime/agent-fs@0.1.0::read-slug".to_string(),
        run_id: None,
        iteration: None,
    }
}

fn node(
    id: &str,
    kind: AgentKind,
    parent: Option<&str>,
    workspace_path: PathBuf,
    template_ref: Option<&str>,
) -> AgentNode {
    AgentNode {
        id: AgentId(id.to_string()),
        kind,
        parent: parent.map(|p| AgentId(p.to_string())),
        workspace_path,
        capabilities: vec![],
        template_ref: template_ref.map(|t| t.to_string()),
        status: AgentStatus::Active,
    }
}

/// Seed a REAL `AgentTreeStore` with a root + two same-slug children whose
/// territories exist on disk under a canonical workspace root. Returns the
/// store, the canonical root, and the two child agent ids. The store's
/// `snapshot()` runs the production `build_peer_slug_map` so each child's
/// `peer_slug_map["notes"]` points at its same-slug sibling.
fn seed_same_slug_tree() -> (Arc<AgentTreeStore>, PathBuf, String, String) {
    // tempfile::tempdir() is the canonical workspace root. AgentTreeStore::new
    // canonicalizes it; all child workspace_paths must exist on disk AND
    // canonicalize under that root BEFORE insert_child (tree.rs:165-167, 341).
    let tmp = tempfile::tempdir().expect("tempdir");
    let canonical_root = tmp
        .path()
        .canonicalize()
        .expect("canonicalize workspace root");
    // Keep the TempDir alive for the whole test by leaking it — the test
    // process owns the temp tree for its full duration; OS reclaims on exit.
    // (A directly-built standalone fixture, not the harness workspace.)
    std::mem::forget(tmp);

    let store = AgentTreeStore::new(canonical_root.clone()).expect("AgentTreeStore::new");

    // (1) Root FIRST (else insert_child -> ParentNotFound). Root territory =
    // the workspace root itself (exists + canonical + under root).
    store
        .insert_root(node(
            "root",
            AgentKind::Root,
            None,
            canonical_root.clone(),
            None,
        ))
        .expect("insert_root");

    // (2) create_dir_all each child's territory on disk BEFORE insert_child.
    let child_a_ws = canonical_root.join("child-a");
    let child_b_ws = canonical_root.join("child-b");
    std::fs::create_dir_all(&child_a_ws).expect("mkdir child-a");
    std::fs::create_dir_all(&child_b_ws).expect("mkdir child-b");

    // (3) Two children sharing the SAME charset-valid template_ref "notes"
    // (matches ^[A-Za-z0-9-]+$) => build_peer_slug_map keys slug "notes".
    let parent = AgentId("root".to_string());
    store
        .insert_child(
            &parent,
            node(
                "child-a",
                AgentKind::Child,
                Some("root"),
                child_a_ws.clone(),
                Some("notes"),
            ),
        )
        .expect("insert child-a");
    store
        .insert_child(
            &parent,
            node(
                "child-b",
                AgentKind::Child,
                Some("root"),
                child_b_ws.clone(),
                Some("notes"),
            ),
        )
        .expect("insert child-b");

    (
        Arc::new(store),
        canonical_root,
        "child-a".to_string(),
        "child-b".to_string(),
    )
}

fn build_resolver(
    canonical_root: PathBuf,
    store: Arc<AgentTreeStore>,
) -> Arc<dyn VirtualPathResolver> {
    Arc::new(DefaultVirtualPathResolver::new(
        canonical_root,
        store as Arc<dyn AgentTreeSnapshot>,
    ))
}

/// SYS-AC-176 — same-slug peer read: child-a reads child-b's same-slug
/// territory via the REAL `FsReadSlugHandler` + `FsListSlugHandler`, getting
/// Ok read-only content AND an `fs.*` event whose source is `FsSource::Slug`.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_176_same_slug_peer_read_and_list_emit_slug_events() {
    let (store, canonical_root, child_a, child_b) = seed_same_slug_tree();

    // Sanity: the production peer_slug_map keyed the slug for both children.
    let snap = store.snapshot();
    let a_peer = snap
        .peer_slug_map
        .get(&AgentId(child_a.clone()))
        .and_then(|m| m.get("notes"))
        .expect("child-a peer_slug_map['notes'] populated");
    assert_eq!(a_peer.0, child_b, "child-a's 'notes' peer is child-b");

    // Seed a readable file in child-b's territory (the peer content child-a reads).
    let content = b"peer-notes-payload";
    std::fs::write(canonical_root.join("child-b").join("note.txt"), content)
        .expect("seed peer file");

    let resolver = build_resolver(canonical_root, Arc::clone(&store));
    let sink = CapturingSink::default();

    // --- read-slug: child-a reads child-b's same-slug territory. ---
    let read_handler = FsReadSlugHandler {
        resolver: Arc::clone(&resolver),
        emitter: Arc::new(sink.clone()),
        concurrency: Arc::new(Semaphore::new(DEFAULT_FS_CONCURRENCY)),
    };
    // WIT params for read-slug: (peer_id, slug, file) — host_fn.rs:1632-1635.
    let read_params = vec![
        Val::String(child_b.clone()),
        Val::String("notes".to_string()),
        Val::String("note.txt".to_string()),
    ];
    let read_out = read_handler
        .call(ctx_for(&child_a), read_params, 1)
        .await
        .expect("read-slug handler returns Ok host result");
    // OK arm of result<list<u8>, fs-error>: Val::Result(Ok(Some(Val::List(bytes)))).
    match read_out.as_slice() {
        [Val::Result(Ok(Some(boxed)))] => match boxed.as_ref() {
            Val::List(bytes) => {
                let got: Vec<u8> = bytes
                    .iter()
                    .map(|v| match v {
                        Val::U8(b) => *b,
                        other => panic!("expected Val::U8 in list, got {other:?}"),
                    })
                    .collect();
                assert_eq!(got, content, "read-slug returns the peer's file content");
            }
            other => panic!("expected Val::List ok payload, got {other:?}"),
        },
        other => panic!("expected Ok(Some(list)) read-slug result, got {other:?}"),
    }

    // --- list-slug: child-a lists child-b's same-slug territory. ---
    let list_handler = FsListSlugHandler {
        resolver: Arc::clone(&resolver),
        emitter: Arc::new(sink.clone()),
        concurrency: Arc::new(Semaphore::new(DEFAULT_FS_CONCURRENCY)),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    // WIT params for list-slug: (peer_id, slug) — host_fn.rs:1731-1732.
    let list_params = vec![
        Val::String(child_b.clone()),
        Val::String("notes".to_string()),
    ];
    let list_out = list_handler
        .call(ctx_for(&child_a), list_params, 1)
        .await
        .expect("list-slug handler returns Ok host result");
    match list_out.as_slice() {
        [Val::Result(Ok(Some(boxed)))] => match boxed.as_ref() {
            Val::List(entries) => {
                assert!(
                    !entries.is_empty(),
                    "list-slug enumerates the peer territory (>=1 entry: note.txt)"
                );
            }
            other => panic!("expected Val::List ok payload, got {other:?}"),
        },
        other => panic!("expected Ok(Some(list)) list-slug result, got {other:?}"),
    }

    // --- assert the fs.* Slug-source events landed on the test-owned sink. ---
    let events = sink.snapshot();
    let read_ev = events
        .iter()
        .find(|e| e.event_type == "fs.read")
        .expect("read-slug emitted an fs.read event");
    assert_eq!(
        read_ev.agent_id, child_a,
        "event.agent_id identifies the reading agent (child-a)"
    );
    // FsEvent is externally tagged: payload is {"Read": {..., "source":"Slug"}}.
    let read_source = read_ev
        .payload
        .get("Read")
        .and_then(|r| r.get("source"))
        .and_then(|s| s.as_str())
        .expect("fs.read payload carries Read.source");
    assert_eq!(
        read_source, "Slug",
        "fs.read event source is FsSource::Slug (identifies the slug access)"
    );

    let list_ev = events
        .iter()
        .find(|e| e.event_type == "fs.list")
        .expect("list-slug emitted an fs.list event");
    let list_source = list_ev
        .payload
        .get("List")
        .and_then(|r| r.get("source"))
        .and_then(|s| s.as_str())
        .expect("fs.list payload carries List.source");
    assert_eq!(
        list_source, "Slug",
        "fs.list event source is FsSource::Slug"
    );
    // And the slug itself is carried in the list event's path (host_fn.rs:1769).
    let list_path = list_ev
        .payload
        .get("List")
        .and_then(|r| r.get("path"))
        .and_then(|s| s.as_str())
        .expect("fs.list payload carries List.path");
    assert_eq!(list_path, "notes", "fs.list path identifies the slug");
}

/// SYS-AC-177 — cross-territory deny. Two real-provider denials:
///  (a) a non-adjacent / different-slug peer READ via `resolve_slug_read`
///      -> Err(FsError::NotFound) (the anti-fingerprint constant payload, which
///      IS the access-control denial; see docstring deviation note).
///  (b) the peer territory is unreachable for WRITE via the agent's own
///      `resolve_write` (slug is read-only; a sibling dir is lexically
///      reachable only via a `..` traversal, gated as InvalidPath) — i.e. NO
///      successful peer-territory write is possible.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_177_cross_territory_read_denied_and_peer_write_unreachable() {
    let (store, canonical_root, child_a, child_b) = seed_same_slug_tree();
    let resolver = build_resolver(canonical_root, Arc::clone(&store));

    // (a1) Wrong slug: "missing" is not a key in child-a's peer_slug_map ->
    // NotFound (resolver.rs:464-468, anti-fingerprint constant payload).
    let wrong_slug = resolver.resolve_slug_read(&child_a, &child_b, "missing", "note.txt");
    assert_eq!(
        wrong_slug,
        Err(FsError::NotFound("path not found".to_string())),
        "different/unknown slug -> NotFound (constant anti-fingerprint payload)"
    );

    // (a2) Wrong peer_id: slug "notes" maps to child-b, but the caller names
    // "root" as the peer -> peer/slug-target mismatch -> NotFound
    // (resolver.rs:475-477). Witnesses a non-adjacent / cross-territory denial.
    let wrong_peer = resolver.resolve_slug_read(&child_a, "root", "notes", "note.txt");
    assert_eq!(
        wrong_peer,
        Err(FsError::NotFound("path not found".to_string())),
        "slug resolves to a different peer than named -> NotFound"
    );

    // (a3) A caller with NO peer_slug_map entry (the Root has no siblings, so
    // build_peer_slug_map skips it) reading any slug -> NotFound
    // (resolver.rs:463-468).
    let no_peer_map = resolver.resolve_slug_read("root", &child_a, "notes", "note.txt");
    assert_eq!(
        no_peer_map,
        Err(FsError::NotFound("path not found".to_string())),
        "agent with no peer_slug_map entry -> NotFound on any slug read"
    );

    // Sanity: the legitimate same-slug read DOES resolve (the happy path is
    // fully faithful) — proves the denials above are real access control, not a
    // broken setup.
    std::fs::write(store.workspace_root().join("child-b").join("ok.txt"), b"x")
        .expect("seed peer file for positive control");
    let allowed = resolver.resolve_slug_read(&child_a, &child_b, "notes", "ok.txt");
    assert!(
        allowed.is_ok(),
        "same-slug peer read resolves (positive control): {allowed:?}"
    );

    // (b) Peer territory is UNREACHABLE for WRITE and DELETE — the criterion's
    // "a write/delete into a peer's territory returns PermissionDenied" limb.
    // Slug access is read-only (there is no write-slug/delete-slug host fn), and
    // `resolve_write` (which also resolves a delete target before it is removed)
    // confines each agent to its OWN root. A sibling can therefore only ATTEMPT
    // to reach a peer via a `..` escape, which the component path-gate rejects
    // (resolver.rs:236-237). cap-fs realises the criterion's "PermissionDenied"
    // as this path-confinement denial (InvalidPath) / cross-territory NotFound
    // anti-fingerprint: the ACCESS-CONTROL property — a sibling cannot mutate a
    // peer's files — holds; only the error VARIANT differs from the criterion's
    // literal wording (a documented deviation, same class as SYS-AC-239's
    // InvalidTarget→"invalid-state" mapping).

    // (b1) WRITE a new file into the peer's territory (escape attempt) -> denied.
    let peer_write = resolver.resolve_write(&child_a, "../child-b/pwn.txt");
    match peer_write {
        Err(FsError::InvalidPath(_)) | Err(FsError::NotFound(_)) => {}
        other => {
            panic!("peer-territory write must be denied (InvalidPath/NotFound), got {other:?}")
        }
    }

    // (b2) DELETE an existing peer file (delete resolves its target through the
    // SAME resolve_write confinement gate) -> denied. Witnesses the delete limb.
    let peer_delete_target = resolver.resolve_write(&child_a, "../child-b/note.txt");
    match peer_delete_target {
        Err(FsError::InvalidPath(_)) | Err(FsError::NotFound(_)) => {}
        other => panic!(
            "peer-territory delete-target must be denied (InvalidPath/NotFound), got {other:?}"
        ),
    }

    // And the agent CAN write its own territory (positive control: the deny is
    // territory-scoped, not a blanket write failure).
    let own_write = resolver.resolve_write(&child_a, "mine.txt");
    assert!(
        own_write.is_ok(),
        "agent writes its OWN territory (positive control): {own_write:?}"
    );
}
