//! /dev slice backbone-step3 — SYS-J-20 persistent-memory witnesses over the
//! REAL wired system (production agent loop + `WasmMessageHandler` + the real
//! `register_agent_memory` handlers, now backed by a PERSISTENT `MemoryStore::open`
//! instead of the prior in-memory `MemoryStore::new()`). No mock/stub stands in for
//! any module in the SYS-J-20 chain (witness-floor): a guest turn drives the real
//! versioned `agent-memory` host fns, which write per-agent `knowledge.jsonl` on disk.
//!
//!  - **SYS-AC-059** — `remember` emits `memory.remember` AND the entry is persisted
//!    to `knowledge.jsonl` (proven by re-opening a FRESH `MemoryStore` over the same
//!    dir — a fresh store can only return the entry if it was hydrated from disk).
//!  - **SYS-AC-212** — a `remember` whose store has hit its entry cap returns
//!    `memory-error::limit-exceeded` (observed at the WIT handler boundary over the
//!    REAL persistent cap=1 store) and persists no new `knowledge.jsonl` entry.
//!  - **MODULE-011-AC-39** (harness corroboration of the across-restart clause) —
//!    memory written under `.agent/memory/` by a wired turn survives a store
//!    drop+reopen of the SAME dir, is per-agent scoped (no cross-agent leakage), and
//!    a freshly-opened dir starts empty. (The literal production `.agent/memory/`
//!    binding through `wire_capabilities` is witnessed by the cli test
//!    `wiring_memory_persist.rs`.)
//!
//! Why the witnesses re-open the store via the public store-API rather than the
//! harness `call_host_fn`: `call_host_fn` hardcodes `results_len = 0`, which every
//! cap-memory handler REJECTS before touching the store (it returns
//! `result<.., memory-error>` and guards `results_len == 1`). The cap-limit witness
//! therefore uses `call_host_fn_n(.., 1)` (handler boundary) and the persistence
//! witnesses use `MemoryStore::open(..).recall/list` (a fresh hydrate-from-disk read).

use std::path::Path;

use cap_memory::{MemoryStore, DEFAULT_MAX_ACTIVE_PER_AGENT, NAMESPACE};
use system_acceptance::{Cap, SystemUnderTest};
use wasmtime::component::Val;

const MEM_SKELETON_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-mem-skeleton.core.wasm");

/// `true` iff any per-agent subdir under `root` contains a `knowledge.jsonl` file.
/// Enumerates subdirs rather than deriving the FNV-1a-suffixed agent slug (private
/// in cap-memory) — mirrors `integration_persistence.rs::walk_for_knowledge_jsonl`.
fn knowledge_jsonl_present(root: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() && p.join("knowledge.jsonl").is_file() {
            return true;
        }
    }
    false
}

/// SYS-AC-059: a guest `remember` through a real turn emits `memory.remember` AND
/// the entry is persisted to `knowledge.jsonl` — proven by re-opening a FRESH
/// `MemoryStore` over the harness memory dir and recalling it (a fresh store has no
/// in-memory state, so a hit means it hydrated the entry from on-disk knowledge.jsonl).
#[tokio::test]
async fn sys_ac_059_remember_persists_to_knowledge_jsonl() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory])
        .build(MEM_SKELETON_CORE)
        .await;
    // mem-skeleton remembers the payload string then recalls it.
    sut.inject_message("harness", b"durable-insight-zero-five-nine")
        .await;
    sut.run_turn().await;

    // Event leg: memory.remember fired with a content_preview.
    let remember = sut.assert_event("memory.remember", |_| true);
    assert!(
        remember
            .payload
            .get("content_preview")
            .and_then(|v| v.as_str())
            .is_some(),
        "SYS-AC-059: memory.remember carries a content_preview"
    );

    // Persistence leg: a FRESH store opened over the SAME dir hydrates the entry
    // from knowledge.jsonl. This is the "persisted to knowledge.jsonl" witness —
    // the fresh store has zero in-memory state, so a recall hit can ONLY come from
    // the on-disk file.
    let reopened = MemoryStore::open(sut.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT)
        .expect("re-open persistent memory store over the harness dir");
    let hits = reopened.recall(sut.agent_id(), "durable", 10);
    assert!(
        !hits.is_empty(),
        "SYS-AC-059: the remembered insight was persisted to knowledge.jsonl and \
         hydrated by a fresh MemoryStore::open over {} (agent_id={})",
        sut.memory_dir().display(),
        sut.agent_id()
    );

    // The literal on-disk file exists under the .agent/memory root.
    assert!(
        knowledge_jsonl_present(sut.memory_dir()),
        "SYS-AC-059: a knowledge.jsonl file is present under {}",
        sut.memory_dir().display()
    );
}

/// SYS-AC-212: with the store at its entry cap, a `remember` returns
/// `memory-error::limit-exceeded` (observed at the WIT handler boundary over the
/// REAL persistent cap=1 store) and persists no new knowledge.jsonl entry (re-open
/// list stays at exactly one).
#[tokio::test]
async fn sys_ac_212_remember_at_cap_persists_nothing() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory])
        .with_memory_cap(1)
        .build(MEM_SKELETON_CORE)
        .await;
    // Turn 1 fills the cap: mem-skeleton remembers "A" (active count 0 -> 1).
    sut.inject_message("harness", b"entry-A-at-cap").await;
    sut.run_turn().await;

    // WIT-boundary return: a second remember of "B" hits the cap → the handler
    // returns result<.., memory-error> = Err(limit-exceeded). `call_host_fn_n(.., 1)`
    // drives the REAL RememberHandler over the REAL persistent store (results_len=1,
    // which the handler requires; the convenience call_host_fn passes 0 and is
    // rejected). The store-cap check lives below the handler boundary, so this is a
    // faithful witness of the limit-exceeded return.
    let out = sut
        .call_host_fn_n(
            "memory",
            NAMESPACE,
            "remember",
            vec![Val::String("entry-B-over-cap".into()), Val::List(vec![])],
            1,
        )
        .await
        .expect("handler.call returns Ok at the host boundary (the WIT error is inside the Val)");
    match &out[0] {
        Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
            Val::Variant(name, _) => assert_eq!(
                name, "limit-exceeded",
                "SYS-AC-212: remember at cap returns memory-error::limit-exceeded"
            ),
            other => panic!("SYS-AC-212: unexpected memory-error payload: {other:?}"),
        },
        other => panic!("SYS-AC-212: expected Result::Err(limit-exceeded), got {other:?}"),
    }

    // Persist-nothing core: a fresh store over the dir hydrates EXACTLY one entry
    // ("A"); "B" was never persisted.
    let reopened = MemoryStore::open(sut.memory_dir(), 1).expect("re-open cap=1 store");
    let all = reopened.list(sut.agent_id());
    assert_eq!(
        all.len(),
        1,
        "SYS-AC-212: knowledge.jsonl holds exactly the one pre-cap entry (B not persisted); got {}",
        all.len()
    );
}

/// MODULE-011-AC-39 (across-restart clause, harness corroboration): a wired turn
/// writes memory under a `.agent/memory/` dir; after the SUT (and its store) drop,
/// re-opening the SAME dir recalls the entry (cross-restart hydration), it is
/// per-agent scoped (a different agent_id recalls nothing — no cross-agent leakage),
/// and a freshly-opened dir starts empty.
#[tokio::test]
async fn module_011_ac_39_memory_survives_restart() {
    // Caller-owned dir: it must OUTLIVE the SUT (whose own workspace tempdir drops on
    // teardown). Bind the literal `.agent/memory/` subpath under it.
    let keep = tempfile::TempDir::new().expect("caller-owned tempdir");
    let mem_dir = keep.path().join(".agent").join("memory");

    let agent_id = {
        let sut = SystemUnderTest::builder()
            .caps(&[Cap::Memory])
            .with_memory_dir(mem_dir.clone())
            .build(MEM_SKELETON_CORE)
            .await;
        let aid = sut.agent_id().to_string();
        sut.inject_message("harness", b"durable-across-restart")
            .await;
        sut.run_turn().await;
        aid
        // sut (and its Arc<MemoryStore>) drop HERE — simulates a process restart.
    };

    // Re-open the SAME dir from a fresh store: the entry hydrates from disk.
    let reopened = MemoryStore::open(&mem_dir, DEFAULT_MAX_ACTIVE_PER_AGENT)
        .expect("re-open persistent memory store over the caller-owned .agent/memory dir");
    assert!(
        !reopened.recall(&agent_id, "durable", 10).is_empty(),
        "AC-39: memory written under .agent/memory survives a store drop+reopen (cross-restart)"
    );

    // Per-agent scoping / no cross-agent leakage: a different agent recalls nothing
    // from the same persistent store.
    assert!(
        reopened
            .recall("agent:someone-else", "durable", 10)
            .is_empty(),
        "AC-39: recall is per-agent scoped — another agent_id sees no entries (no leakage)"
    );

    // Fresh agent starts empty: a brand-new dir hydrates to an empty store.
    let fresh = tempfile::TempDir::new().expect("fresh tempdir");
    let fresh_store = MemoryStore::open(
        fresh.path().join(".agent").join("memory"),
        DEFAULT_MAX_ACTIVE_PER_AGENT,
    )
    .expect("open fresh memory dir");
    assert!(
        fresh_store.recall(&agent_id, "durable", 10).is_empty(),
        "AC-39: a freshly-opened .agent/memory dir starts empty"
    );
}
