//! Integration tests for slice G (m011-slice-g): AC-18 cap-memory-half closure.
//!
//! MODULE-011-AC-18 §1.4 verification class is "integration test". T18-B/C/D
//! are the PRIMARY integration tests exercising the WIT `rollback-memory`
//! handler dispatch through to the observable cursor-reset effect. T18-A is
//! a supporting Unit-class const-equality guard against future spec
//! divergence (analogous to slice-F T42's regression-guard role).
//!
//! Two halves of AC-18:
//!
//! - **Path-set SPEC contract** (T18-A): `cap_memory::ROLLBACK_GIT_PATHS`
//!   must equal `["knowledge.jsonl", "_knowledge_map.yaml", "syntheses/*.md"]`
//!   (matches AC-18 §1.4 line 373 verbatim including the `.md` suffix).
//! - **Cursor-reset behavior** (T18-B/C/D): the WIT `rollback-memory(ts)`
//!   host fn success path resets `Components.cursor_store` to literal
//!   initial state per AC-18 §1.4 ("epoch/0/0"). Per-agent isolated.
//!   Slice-B in-process drop semantics (entries with `created_at > ts`
//!   dropped) preserved through the new wiring.

use std::sync::Arc;
use std::time::SystemTime;

use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
use advance_shared_types::memory::L6Cursor;
use cap_memory::{
    Components, FailureCooldown, InMemorySimilarityIndex, MemoryEntry, MemoryStatus, MemoryStore,
    MemoryType, MutableClock, Reconciler, StubBatchExtractor, CAPABILITY, DEFAULT_THRESHOLD,
    NAMESPACE, ROLLBACK_GIT_PATHS,
};
use wasmtime::component::Val;

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-slice-g".to_string(),
        turn_id: None,
        capability: CAPABILITY.to_string(),
        function: format!("{}::test", NAMESPACE),
        run_id: None,
        iteration: None,
    }
}

fn build_components(store: Arc<MemoryStore>) -> Components {
    let extractor = Arc::new(StubBatchExtractor::with_extraction(Default::default()));
    let similarity = Arc::new(InMemorySimilarityIndex::new());
    let reconciler = Reconciler::from_concrete(similarity, DEFAULT_THRESHOLD);
    let cooldown = Arc::new(FailureCooldown::new(600));
    let clock = Arc::new(MutableClock::new(SystemTime::UNIX_EPOCH));
    Components::with_l6_defaults(extractor, reconciler, store, cooldown, clock)
}

fn fact(id: &str, agent: &str, content: &str, created_at: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: agent.into(),
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

// ─────────────────────────────────────────────────────────────────────────
// T18-A — path-set SPEC contract (Unit-class, supporting role)
// ─────────────────────────────────────────────────────────────────────────

/// AC-18 path-set SPEC contract guard. Verifies the publicly re-exported
/// `cap_memory::ROLLBACK_GIT_PATHS` const equals MODULE-011 §1.4 line 373
/// verbatim including the `.md` suffix on `syntheses/*.md`.
///
/// Coexists with the inline `src/rollback.rs::tests::path_set_const` test
/// which exercises the const inside its declaring module — this test
/// additionally verifies the `pub use` re-export shape from `lib.rs`.
#[test]
fn t18_a_path_set_declaration() {
    assert_eq!(ROLLBACK_GIT_PATHS.len(), 3);
    assert_eq!(
        ROLLBACK_GIT_PATHS,
        &["knowledge.jsonl", "_knowledge_map.yaml", "syntheses/*.md"],
    );
}

// ─────────────────────────────────────────────────────────────────────────
// T18-B — cursor reset on rollback (PRIMARY AC-18 integration verification)
// ─────────────────────────────────────────────────────────────────────────

/// AC-18 cap-memory-half PRIMARY integration verification:
/// `rollback-memory(timestamp)` resets the L6 cursor to literal initial state
/// per §1.4 wording. Flushes a non-initial watermark, dispatches the WIT host
/// fn through `Components::register_agent_memory`, asserts the cursor reads
/// back as `Some(L6Cursor { last_knowledge_id: None, last_completed_at:
/// UNIX_EPOCH })`.
#[tokio::test]
async fn t18_b_cursor_reset_on_rollback() {
    let registry = Arc::new(InMemoryHostRegistry::new());
    let store = Arc::new(MemoryStore::new());
    let components = build_components(Arc::clone(&store));

    // Seed a non-initial cursor watermark for agent:r.
    let original_watermark = L6Cursor {
        last_knowledge_id: Some("k-100".into()),
        last_completed_at: SystemTime::now(),
    };
    components
        .cursor_store
        .flush("agent:r", original_watermark.clone());
    let pre = components
        .cursor_store
        .read("agent:r")
        .expect("watermark present pre-rollback");
    assert_eq!(pre.last_knowledge_id.as_deref(), Some("k-100"));
    assert_ne!(
        pre.last_completed_at,
        SystemTime::UNIX_EPOCH,
        "pre-rollback watermark must be non-initial",
    );

    components.register_agent_memory(registry.as_ref());

    let specs = registry.lookup(CAPABILITY);
    let rollback = specs
        .iter()
        .find(|s| s.name == "rollback-memory")
        .expect("rollback-memory spec registered");

    let r = rollback
        .handler
        .call(
            ctx_for("agent:r"),
            vec![Val::String("2999-01-01T00:00:00Z".into())],
            1,
        )
        .await
        .expect("rollback-memory ok");
    match &r[0] {
        Val::Result(Ok(None)) => {}
        other => panic!(
            "rollback-memory MUST lower to Val::Result(Ok(None)) for the unit-OK arm; got {:?}",
            other,
        ),
    }

    // AC-18 §1.4 wording: cursor reset to initial state (epoch/0/0).
    let post = components
        .cursor_store
        .read("agent:r")
        .expect("cursor materialized post-rollback (Some, not None)");
    assert_eq!(
        post.last_knowledge_id, None,
        "last_knowledge_id reset to None (initial state)",
    );
    assert_eq!(
        post.last_completed_at,
        SystemTime::UNIX_EPOCH,
        "last_completed_at reset to UNIX_EPOCH (initial state)",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// T18-C — per-agent cursor-reset isolation
// ─────────────────────────────────────────────────────────────────────────

/// `rollback-memory(ts)` for one agent must NOT touch another agent's cursor.
/// Slice G's `L6CursorStore::reset_to_epoch(agent_id)` is keyed scoped.
#[tokio::test]
async fn t18_c_per_agent_isolation() {
    let registry = Arc::new(InMemoryHostRegistry::new());
    let store = Arc::new(MemoryStore::new());
    let components = build_components(Arc::clone(&store));

    let watermark_r = L6Cursor {
        last_knowledge_id: Some("k-agent-r".into()),
        last_completed_at: SystemTime::now(),
    };
    components
        .cursor_store
        .flush("agent:r", watermark_r.clone());
    components.cursor_store.flush(
        "agent:a",
        L6Cursor {
            last_knowledge_id: Some("k-agent-a".into()),
            last_completed_at: SystemTime::now(),
        },
    );

    components.register_agent_memory(registry.as_ref());
    let specs = registry.lookup(CAPABILITY);
    let rollback = specs.iter().find(|s| s.name == "rollback-memory").unwrap();

    // Rollback ONLY agent:a.
    let r = rollback
        .handler
        .call(
            ctx_for("agent:a"),
            vec![Val::String("2999-01-01T00:00:00Z".into())],
            1,
        )
        .await
        .expect("rollback-memory ok");
    assert!(matches!(r[0], Val::Result(Ok(None))));

    // agent:a cursor reset to initial.
    let cur_a = components
        .cursor_store
        .read("agent:a")
        .expect("agent:a cursor materialized post-rollback");
    assert_eq!(cur_a.last_knowledge_id, None);
    assert_eq!(cur_a.last_completed_at, SystemTime::UNIX_EPOCH);

    // agent:r cursor watermark preserved (unaffected by agent:a rollback).
    let cur_r = components
        .cursor_store
        .read("agent:r")
        .expect("agent:r cursor preserved across agent:a rollback");
    assert_eq!(cur_r.last_knowledge_id.as_deref(), Some("k-agent-r"));
    assert_eq!(
        cur_r.last_completed_at, watermark_r.last_completed_at,
        "agent:r last_completed_at unchanged",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// T18-D — slice-B in-process drop semantics preserved (regression)
// ─────────────────────────────────────────────────────────────────────────

/// Regression guard: slice G's cursor-reset wiring does NOT regress slice-B's
/// in-process drop of entries with `created_at > timestamp`.
#[tokio::test]
async fn t18_d_store_drop_preserved() {
    let registry = Arc::new(InMemoryHostRegistry::new());
    let store = Arc::new(MemoryStore::new());
    let components = build_components(Arc::clone(&store));

    // Seed 4 entries: 2 before the cutoff, 2 after.
    for (id, ts) in [
        ("e-early-1", "2026-01-15T00:00:00Z"),
        ("e-early-2", "2026-02-15T00:00:00Z"),
        ("e-late-1", "2026-04-15T00:00:00Z"),
        ("e-late-2", "2026-05-15T00:00:00Z"),
    ] {
        store
            .insert("agent:r", fact(id, "agent:r", id, ts))
            .expect("insert ok");
    }
    assert_eq!(store.list("agent:r").len(), 4);

    components.register_agent_memory(registry.as_ref());
    let specs = registry.lookup(CAPABILITY);
    let rollback = specs.iter().find(|s| s.name == "rollback-memory").unwrap();

    // Rollback cutoff = 2026-03-01: drops 2 late entries, keeps 2 early.
    let r = rollback
        .handler
        .call(
            ctx_for("agent:r"),
            vec![Val::String("2026-03-01T00:00:00Z".into())],
            1,
        )
        .await
        .expect("rollback-memory ok");
    assert!(matches!(r[0], Val::Result(Ok(None))));

    let surviving = store.list("agent:r");
    assert_eq!(surviving.len(), 2, "2 entries surviving the cutoff");
    let ids: std::collections::HashSet<_> = surviving.iter().map(|e| e.id.as_str()).collect();
    assert!(ids.contains("e-early-1"));
    assert!(ids.contains("e-early-2"));
    assert!(!ids.contains("e-late-1"));
    assert!(!ids.contains("e-late-2"));

    // Also assert the cursor-reset side effect did fire (T18-B coverage already
    // asserts this; here it's a side-by-side regression check that BOTH the
    // store-drop AND the cursor-reset happened in the same dispatch).
    let cur = components
        .cursor_store
        .read("agent:r")
        .expect("cursor materialized");
    assert_eq!(cur.last_knowledge_id, None);
    assert_eq!(cur.last_completed_at, SystemTime::UNIX_EPOCH);
}
