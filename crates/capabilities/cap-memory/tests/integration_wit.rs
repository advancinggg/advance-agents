//! AC-01 WIT integration tests — the 5 `agent-memory` host functions are
//! registered + dispatchable + round-trip via the `HostFunctionHandler`
//! interface.
//!
//! The tests construct a real `InMemoryHostRegistry`, register the 5 host fns
//! via `register_agent_memory`, then call each registered handler directly
//! (using a synthesized `HostCallContext`) to verify dispatch correctness +
//! `Val` encoding shape.

use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
use cap_memory::{
    register_agent_memory, L6CursorStore, MemoryStore, NoopEventBus, CAPABILITY, NAMESPACE,
};
use wasmtime::component::Val;

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-1".to_string(),
        turn_id: None,
        capability: CAPABILITY.to_string(),
        function: format!("{}::test", NAMESPACE),
        run_id: None,
        iteration: None,
    }
}

fn registry_with_store() -> (Arc<InMemoryHostRegistry>, Arc<MemoryStore>) {
    let reg = Arc::new(InMemoryHostRegistry::new());
    let store = Arc::new(MemoryStore::new());
    // Slice G: 4-arg signature (cursor_store added). NoopEventBus +
    // fresh L6CursorStore keep these AC-01 round-trip tests behaviourally
    // identical to slice B/D (OBS-09 regression lock); `memory.*` emission
    // is asserted separately in integration_observability; cursor-reset
    // side effect is asserted separately in integration_slice_g.
    register_agent_memory(
        reg.as_ref(),
        Arc::clone(&store),
        Arc::new(NoopEventBus),
        Arc::new(L6CursorStore::new()),
    );
    (reg, store)
}

fn spec_named<'a>(
    specs: &'a [advance_runtime::host_registry::HostFunctionSpec],
    name: &str,
) -> &'a advance_runtime::host_registry::HostFunctionSpec {
    specs
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no spec named {}", name))
}

#[test]
fn agent_memory_wit_registers_under_capability_memory() {
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    assert_eq!(specs.len(), 5, "5 host fns registered");
    for s in &specs {
        assert_eq!(s.capability, CAPABILITY);
        assert_eq!(s.namespace, NAMESPACE);
    }
    let names: std::collections::HashSet<_> = specs.iter().map(|s| s.name.clone()).collect();
    for n in [
        "remember",
        "recall",
        "forget",
        "recall-at",
        "rollback-memory",
    ] {
        assert!(names.contains(n), "missing {}", n);
    }
}

#[tokio::test]
async fn remember_then_recall_round_trip() {
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let remember = spec_named(&specs, "remember");
    let recall = spec_named(&specs, "recall");

    // remember("hello world", ["tag-a", "tag-b"])
    let r = remember
        .handler
        .call(
            ctx_for("agent:a"),
            vec![
                Val::String("hello world".into()),
                Val::List(vec![
                    Val::String("tag-a".into()),
                    Val::String("tag-b".into()),
                ]),
            ],
            1,
        )
        .await
        .expect("remember dispatch ok");
    assert_eq!(r.len(), 1);
    match &r[0] {
        Val::Result(Ok(Some(payload))) => {
            assert!(matches!(payload.as_ref(), Val::String(_)));
        }
        other => panic!("expected Val::Result(Ok(Some(String))), got {:?}", other),
    }

    // recall("hello", 10) → list of length 1
    let r = recall
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("hello".into()), Val::U32(10)],
            1,
        )
        .await
        .expect("recall dispatch ok");
    match &r[0] {
        Val::Result(Ok(Some(payload))) => match payload.as_ref() {
            Val::List(items) => assert_eq!(items.len(), 1, "1 hit"),
            other => panic!("expected Val::List, got {:?}", other),
        },
        other => panic!("expected Val::Result(Ok(Some(List))), got {:?}", other),
    }
}

#[tokio::test]
async fn forget_excludes_from_subsequent_recall_and_lowers_to_unit_ok() {
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let remember = spec_named(&specs, "remember");
    let forget = spec_named(&specs, "forget");
    let recall = spec_named(&specs, "recall");

    // Insert via remember.
    let r = remember
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("the secret".into()), Val::List(vec![])],
            1,
        )
        .await
        .expect("remember ok");
    let id = match &r[0] {
        Val::Result(Ok(Some(payload))) => match payload.as_ref() {
            Val::String(s) => s.clone(),
            other => panic!("expected String id, got {:?}", other),
        },
        other => panic!("expected Ok(Some(String)), got {:?}", other),
    };

    // forget(id) — unit OK arm: Val::Result(Ok(None)).
    let r = forget
        .handler
        .call(ctx_for("agent:a"), vec![Val::String(id.clone())], 1)
        .await
        .expect("forget ok");
    match &r[0] {
        Val::Result(Ok(None)) => {}
        other => panic!(
            "forget MUST lower to Val::Result(Ok(None)) for the unit-OK arm; got {:?}",
            other
        ),
    }

    // recall: the forgotten entry is excluded.
    let r = recall
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("secret".into()), Val::U32(10)],
            1,
        )
        .await
        .expect("recall ok");
    match &r[0] {
        Val::Result(Ok(Some(payload))) => match payload.as_ref() {
            Val::List(items) => assert_eq!(items.len(), 0, "forgotten entry excluded"),
            other => panic!("expected Val::List, got {:?}", other),
        },
        other => panic!("expected Ok(Some(List)), got {:?}", other),
    }
}

#[tokio::test]
async fn recall_at_filters_by_created_at_in_process() {
    let (reg, store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let recall_at = spec_named(&specs, "recall-at");

    // Insert two entries directly into the store with different timestamps.
    // (The `remember` host fn now derives `created_at` from its injected
    // `Clock` — slice m011-memory-persist AC-42 — but this temporal-filter
    // test wants two explicit, controlled timestamps, so it inserts via the
    // store directly rather than through `remember`.)
    use cap_memory::{MemoryEntry, MemoryStatus, MemoryType};
    let early = MemoryEntry {
        id: "early".into(),
        agent_id: "agent:a".into(),
        entry_type: MemoryType::Fact,
        content: "early note".into(),
        tags: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    };
    let late = MemoryEntry {
        id: "late".into(),
        agent_id: "agent:a".into(),
        entry_type: MemoryType::Fact,
        content: "late note".into(),
        tags: vec![],
        created_at: "2026-06-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    };
    store.insert("agent:a", early).expect("early ok");
    store.insert("agent:a", late).expect("late ok");

    let r = recall_at
        .handler
        .call(
            ctx_for("agent:a"),
            vec![
                Val::String("note".into()),
                Val::String("2026-03-01T00:00:00Z".into()),
                Val::U32(10),
            ],
            1,
        )
        .await
        .expect("recall-at ok");
    match &r[0] {
        Val::Result(Ok(Some(payload))) => match payload.as_ref() {
            Val::List(items) => {
                assert_eq!(items.len(), 1, "only the early entry passes the cutoff")
            }
            other => panic!("expected Val::List, got {:?}", other),
        },
        other => panic!("expected Ok(Some(List)), got {:?}", other),
    }
}

#[tokio::test]
async fn rollback_memory_drops_entries_after_timestamp_in_process() {
    let (reg, store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let rollback = spec_named(&specs, "rollback-memory");

    use cap_memory::{MemoryEntry, MemoryStatus, MemoryType};
    for (id, ts) in [
        ("early", "2026-01-01T00:00:00Z"),
        ("late", "2026-06-01T00:00:00Z"),
    ] {
        let e = MemoryEntry {
            id: id.into(),
            agent_id: "agent:a".into(),
            entry_type: MemoryType::Fact,
            content: id.into(),
            tags: vec![],
            created_at: ts.into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        };
        store.insert("agent:a", e).expect("insert ok");
    }

    let r = rollback
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("2026-03-01T00:00:00Z".into())],
            1,
        )
        .await
        .expect("rollback-memory ok");
    match &r[0] {
        Val::Result(Ok(None)) => {}
        other => panic!(
            "rollback-memory MUST lower to Val::Result(Ok(None)) for the unit-OK arm; got {:?}",
            other
        ),
    }
    let surviving = store.list("agent:a");
    assert_eq!(surviving.len(), 1);
    assert_eq!(surviving[0].id, "early");
}

#[tokio::test]
async fn wit_error_lowering_path_returns_variant() {
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let forget = spec_named(&specs, "forget");

    // forget("nonexistent-id") — store returns Invalid("entry id ... not found"),
    // which the handler maps to WitMemoryError::NotFound for the WIT surface.
    let r = forget
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("does-not-exist".into())],
            1,
        )
        .await
        .expect("forget dispatch ok");
    match &r[0] {
        Val::Result(Err(Some(payload))) => match payload.as_ref() {
            Val::Variant(name, Some(inner)) => {
                assert_eq!(name, "not-found");
                assert!(matches!(inner.as_ref(), Val::String(_)));
            }
            other => panic!("expected Variant(not-found, Some(String)), got {:?}", other),
        },
        other => panic!("expected Err(Some(Variant)), got {:?}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Round-13 adversarial-fix coverage: DoS caps + timestamp validation
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn remember_rejects_oversized_content() {
    use cap_memory::wit_impl::MAX_CONTENT_BYTES;
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let remember = spec_named(&specs, "remember");
    let huge = "A".repeat(MAX_CONTENT_BYTES + 1);
    let r = remember
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String(huge), Val::List(vec![])],
            1,
        )
        .await
        .expect("dispatch ok");
    match &r[0] {
        Val::Result(Err(Some(payload))) => match payload.as_ref() {
            Val::Variant(name, _) => assert_eq!(name, "limit-exceeded"),
            other => panic!("expected limit-exceeded Variant, got {:?}", other),
        },
        other => panic!("expected Err(Some(...)), got {:?}", other),
    }
}

#[tokio::test]
async fn remember_rejects_too_many_tags() {
    use cap_memory::wit_impl::MAX_TAGS_COUNT;
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let remember = spec_named(&specs, "remember");
    let tags: Vec<Val> = (0..MAX_TAGS_COUNT + 1)
        .map(|i| Val::String(format!("t{}", i)))
        .collect();
    let r = remember
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("ok".into()), Val::List(tags)],
            1,
        )
        .await
        .expect("dispatch ok");
    match &r[0] {
        Val::Result(Err(Some(payload))) => match payload.as_ref() {
            Val::Variant(name, _) => assert_eq!(name, "limit-exceeded"),
            other => panic!("expected limit-exceeded Variant, got {:?}", other),
        },
        other => panic!("expected Err(Some(...)), got {:?}", other),
    }
}

#[tokio::test]
async fn recall_rejects_oversized_query() {
    use cap_memory::wit_impl::MAX_QUERY_BYTES;
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let recall = spec_named(&specs, "recall");
    let huge = "q".repeat(MAX_QUERY_BYTES + 1);
    let r = recall
        .handler
        .call(ctx_for("agent:a"), vec![Val::String(huge), Val::U32(10)], 1)
        .await
        .expect("dispatch ok");
    match &r[0] {
        Val::Result(Err(Some(payload))) => match payload.as_ref() {
            Val::Variant(name, _) => assert_eq!(name, "limit-exceeded"),
            other => panic!("expected limit-exceeded Variant, got {:?}", other),
        },
        other => panic!("expected Err(Some(...)), got {:?}", other),
    }
}

#[tokio::test]
async fn rollback_memory_rejects_malformed_timestamp() {
    let (reg, _store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let rollback = spec_named(&specs, "rollback-memory");

    for bad_ts in [
        "9",              // too short
        "9999-12-31T",    // valid shape but too short — actually len 11 = boundary
        "junk-string-zz", // doesn't match YYYY-MM-DDT
        "",               // empty
        "Z",              // single char
    ] {
        let r = rollback
            .handler
            .call(ctx_for("agent:a"), vec![Val::String(bad_ts.into())], 1)
            .await
            .expect("dispatch ok");
        match &r[0] {
            Val::Result(Err(Some(payload))) => match payload.as_ref() {
                Val::Variant(name, _) => assert_eq!(
                    name, "storage-error",
                    "malformed ts {:?} should lower to storage-error",
                    bad_ts
                ),
                other => panic!("unexpected payload shape: {:?}", other),
            },
            // Edge: "9999-12-31T" has len 11 which is the lower bound of the
            // validator. The shape prefix matches (YYYY-MM-DDT), so the
            // validator accepts it and the store rollback runs successfully
            // (just nothing to retain that's <= "9999-12-31T", but bucket is
            // empty here so Ok(None)).
            Val::Result(Ok(None)) if bad_ts == "9999-12-31T" => {}
            other => panic!("unexpected result for ts {:?}: {:?}", bad_ts, other),
        }
    }
}

#[tokio::test]
async fn recall_with_limit_zero_caps_to_max_recall_limit() {
    use cap_memory::wit_impl::MAX_RECALL_LIMIT;
    let (reg, store) = registry_with_store();
    let specs = reg.lookup(CAPABILITY);
    let recall = spec_named(&specs, "recall");

    // Seed MAX_RECALL_LIMIT + 50 entries.
    use cap_memory::{MemoryEntry, MemoryStatus, MemoryType};
    let total = MAX_RECALL_LIMIT as usize + 50;
    for i in 0..total {
        let e = MemoryEntry {
            id: format!("e{}", i),
            agent_id: "agent:a".into(),
            entry_type: MemoryType::Fact,
            content: format!("hit {}", i),
            tags: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        };
        store.insert("agent:a", e).expect("insert ok");
    }
    let r = recall
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("hit".into()), Val::U32(0)], // limit=0 → capped
            1,
        )
        .await
        .expect("recall ok");
    match &r[0] {
        Val::Result(Ok(Some(payload))) => match payload.as_ref() {
            Val::List(items) => assert_eq!(
                items.len(),
                MAX_RECALL_LIMIT as usize,
                "limit=0 must cap to MAX_RECALL_LIMIT, not return all {}",
                total
            ),
            other => panic!("expected Val::List, got {:?}", other),
        },
        other => panic!("expected Ok(Some(List)), got {:?}", other),
    }
}
