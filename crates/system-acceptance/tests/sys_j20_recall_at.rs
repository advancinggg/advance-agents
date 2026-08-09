//! B1 backbone — SYS-AC-211 (SYS-J-20) recall-at as-of witness.
//!
//! SYS-AC-211: "A recall-at(query, timestamp, limit) returns only the historical
//! memory set as of that timestamp (entries with created_at after the timestamp
//! absent) and mutates nothing — a plain recall immediately after still returns
//! the full present-day set — emitting memory.recall_at {agent_id, query,
//! timestamp, result_count}."
//!
//! Witness path (the REAL wired MODULE-011 surface; no mock/stub in the chain):
//!   pre-seed `knowledge.jsonl` on disk via `MemoryStore::open(dir).insert(...)`
//!   with hand-set distinct `created_at` BEFORE `.with_memory_dir(dir).build()` so
//!   the REGISTERED `recall-at` handler's store hydrates the seeds at build →
//!   drive `recall-at` (and a plain `recall`) over the REAL registered handler via
//!   `call_host_fn_n(.., results_len=1)` (the handler rejects `results_len != 1`,
//!   which the convenience `call_host_fn` passes) → assert the as-of filter, the
//!   non-mutation present-day set, and the `memory.recall_at` event.
//!
//! Witness-fidelity note (disclosed): `call_host_fn_n` drives the handler at its
//! boundary, bypassing the grant gate + host-authoritative identity stamping. The
//! SYS-AC-211 criterion asserts only the as-of filter, non-mutation, and the
//! 4-field event — nothing about authorization or caller attribution — so the
//! bypass is faithful to the criterion as written (the same `agent_id` flows
//! throughout). A fuller chain (a real recall-at guest fixture exercising the
//! grant gate) is a future hardening.

use cap_memory::{
    MemoryEntry, MemoryStatus, MemoryStore, MemoryType, CAPABILITY, DEFAULT_MAX_ACTIVE_PER_AGENT,
    NAMESPACE,
};
use system_acceptance::{Cap, SystemUnderTest, AGENT_ID};
use wasmtime::component::Val;

const MEM_SKELETON_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-mem-skeleton.core.wasm");

/// One active `Fact` with a hand-set `created_at` (RFC3339 second-Z, lexicographic
/// order matches chronological order — the `recall_at` filter compares the string).
fn fact(id: &str, content: &str, created_at: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: AGENT_ID.into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: created_at.into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_211_recall_at_returns_as_of_set_and_mutates_nothing() {
    // PRE-SEED on disk BEFORE build: 3 entries matching "rust" at distinct
    // created_at. The registered recall-at handler reads the store hydrated at
    // `.build()`, so seeding a store opened AFTER build would be invisible to it.
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store =
            MemoryStore::open(dir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("open seed store");
        store
            .insert(
                AGENT_ID,
                fact("m1", "rust is memory-safe", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        store
            .insert(
                AGENT_ID,
                fact(
                    "m2",
                    "rust has fearless concurrency",
                    "2026-02-01T00:00:00Z",
                ),
            )
            .unwrap();
        store
            .insert(
                AGENT_ID,
                fact("m3", "rust 2027 edition is planned", "2026-03-01T00:00:00Z"),
            )
            .unwrap();
        // store dropped → knowledge.jsonl flushed (insert atomic-appends + fsyncs).
    }

    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory])
        .with_memory_dir(dir.path().to_path_buf())
        .build(MEM_SKELETON_CORE)
        .await;

    // ── recall-at AS OF 2026-02-15 → only the two entries with created_at <= that
    //    (m1, m2); m3 (2026-03-01) is absent. limit 0 = unlimited (capped by the
    //    handler's MAX_RECALL_LIMIT, far above 2).
    let as_of = "2026-02-15T00:00:00Z";
    let recall_at = sut
        .call_host_fn_n(
            CAPABILITY,
            NAMESPACE,
            "recall-at",
            vec![
                Val::String("rust".into()),
                Val::String(as_of.into()),
                Val::U32(0),
            ],
            1,
        )
        .await
        .expect("recall-at host-fn call");
    // Decode the RETURNED list (result<list<memory-entry>, error>) and assert it
    // actually holds exactly 2 entries — not just that the event reported count 2
    // (a broken handler returning the wrong entries with a right count would NOT
    // pass this). Success lowers as Result(Ok(Some(Box<List>))).
    let returned = match recall_at.first() {
        Some(Val::Result(Ok(Some(inner)))) => match inner.as_ref() {
            Val::List(items) => items.len(),
            other => panic!("recall-at Ok payload must be a list; got {other:?}"),
        },
        other => panic!("recall-at must return Ok(Some(list)); got {other:?}"),
    };
    assert_eq!(
        returned, 2,
        "SYS-AC-211: recall-at as of {as_of} RETURNS exactly the 2 as-of entries (m3 excluded)"
    );

    // The event's named fields (the criterion's literal payload {agent_id, query,
    // timestamp, result_count}). `query` is a (truncated) preview — "rust" is short
    // so the preview equals it; assert the VALUE, not just presence.
    let ev = sut.assert_event("memory.recall_at", |_| true);
    assert_eq!(
        ev.payload.get("result_count").and_then(|v| v.as_u64()),
        Some(2),
        "SYS-AC-211: memory.recall_at result_count == 2 (the as-of set); payload = {}",
        ev.payload
    );
    assert_eq!(
        ev.payload.get("timestamp").and_then(|v| v.as_str()),
        Some(as_of),
        "SYS-AC-211: memory.recall_at carries the queried timestamp"
    );
    assert_eq!(
        ev.payload.get("agent_id").and_then(|v| v.as_str()),
        Some(AGENT_ID),
        "SYS-AC-211: memory.recall_at carries the agent_id"
    );
    assert_eq!(
        ev.payload.get("query").and_then(|v| v.as_str()),
        Some("rust"),
        "SYS-AC-211: memory.recall_at carries the query value (preview of the short query)"
    );

    // Assert the as-of set IDENTITY (not just cardinality): a fresh store re-opened
    // over the same dir, queried with the SAME (query, timestamp) the handler used,
    // returns exactly {m1, m2} and never m3 — proving the as-of filter selected the
    // correct historical entries.
    let as_of_check = MemoryStore::open(sut.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT)
        .expect("re-open for as-of identity check");
    let mut as_of_ids: Vec<String> = as_of_check
        .recall_at(AGENT_ID, "rust", as_of, 0)
        .into_iter()
        .map(|e| e.id)
        .collect();
    as_of_ids.sort();
    assert_eq!(
        as_of_ids,
        vec!["m1".to_string(), "m2".to_string()],
        "SYS-AC-211: the as-of set is exactly {{m1, m2}} (m3 at 2026-03-01 is after {as_of})"
    );

    // ── NON-MUTATION: a plain recall immediately after returns the FULL present-day
    //    set (all 3). Driven through the real `recall` handler.
    let recall = sut
        .call_host_fn_n(
            CAPABILITY,
            NAMESPACE,
            "recall",
            vec![Val::String("rust".into()), Val::U32(0)],
            1,
        )
        .await
        .expect("recall host-fn call");
    assert!(
        matches!(recall.first(), Some(Val::Result(Ok(_)))),
        "recall returns an Ok result variant; got {recall:?}"
    );
    let recall_ev = sut.assert_event("memory.recall", |_| true);
    assert_eq!(
        recall_ev
            .payload
            .get("result_count")
            .and_then(|v| v.as_u64()),
        Some(3),
        "SYS-AC-211: a plain recall after recall-at returns the full present-day set \
         (recall-at mutated nothing); payload = {}",
        recall_ev.payload
    );

    // Belt-and-suspenders: a fresh store over the same dir still hydrates all 3 —
    // recall-at wrote nothing to knowledge.jsonl.
    let reopened =
        MemoryStore::open(sut.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("re-open");
    assert_eq!(
        reopened.recall(AGENT_ID, "rust", 0).len(),
        3,
        "SYS-AC-211: on-disk knowledge.jsonl still holds all 3 entries after recall-at (non-mutation)"
    );
}
