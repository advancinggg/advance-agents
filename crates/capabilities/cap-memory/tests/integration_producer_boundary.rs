//! MODULE-005-AC-29 (CONSUMER seam) — the cap-memory side of the `knowledge.jsonl`
//! producer-boundary guard.
//!
//! These tests exercise the `RememberHandler` policy seam with a test-local stub
//! `RememberContentPolicy` (the concrete `WorkspaceFileResidentPolicy` lives in
//! cap-lifecycle and is witnessed end-to-end by `cap-lifecycle/tests/
//! producer_boundary_ac29.rs`). Coverage:
//!   I1 — a wired policy that Rejects → `remember()` returns `storage-error`.
//!   I2 — a wired policy that Allows → `remember()` returns `Ok(id)`.
//!   I3 — NO policy (legacy `register_agent_memory`) → the SAME would-be-rejected
//!        content is stored `Ok(id)` and recalls (default-off = byte-identical).
//!   I4 — with a Rejecting policy WIRED, the SAME content written via `store.insert`
//!        (the L6 FileRef path) still SUCCEEDS — the guard is on the `remember()`
//!        content path only, never provenance; L6 synthesis is unaffected.

use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionSpec, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::traits::{RememberContentPolicy, RememberDecision};
use cap_memory::{
    register_agent_memory, register_agent_memory_with_git_and_policy, L6CursorStore, MemoryEntry,
    MemorySource, MemoryStatus, MemoryStore, MemoryType, NoopEventBus, CAPABILITY, NAMESPACE,
};
use wasmtime::component::Val;

/// Stub policy: reject any content containing `needle`.
struct RejectContaining(&'static str);
impl RememberContentPolicy for RejectContaining {
    fn check_content(&self, _agent_id: &str, content: &str) -> RememberDecision {
        if content.contains(self.0) {
            RememberDecision::Reject(format!(
                "stub producer-boundary reject: content matched {}",
                self.0
            ))
        } else {
            RememberDecision::Allow
        }
    }
}

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-pb".to_string(),
        turn_id: None,
        capability: CAPABILITY.to_string(),
        function: format!("{}::test", NAMESPACE),
        run_id: None,
        iteration: None,
    }
}

fn spec_named<'a>(specs: &'a [HostFunctionSpec], name: &str) -> &'a HostFunctionSpec {
    specs
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no spec named {name}"))
}

/// Register the 5 host fns with an optional producer-boundary policy; return the
/// registry + the shared store.
fn registry_with_policy(
    policy: Option<Arc<dyn RememberContentPolicy>>,
) -> (Arc<InMemoryHostRegistry>, Arc<MemoryStore>) {
    let reg = Arc::new(InMemoryHostRegistry::new());
    let store = Arc::new(MemoryStore::new());
    register_agent_memory_with_git_and_policy(
        reg.as_ref(),
        Arc::clone(&store),
        Arc::new(NoopEventBus),
        Arc::new(L6CursorStore::new()),
        None,
        policy,
    );
    (reg, store)
}

async fn call_remember(reg: &InMemoryHostRegistry, agent: &str, content: &str) -> Vec<Val> {
    let specs = reg.lookup(CAPABILITY);
    let remember = spec_named(&specs, "remember");
    remember
        .handler
        .call(
            ctx_for(agent),
            vec![Val::String(content.into()), Val::List(vec![])],
            1,
        )
        .await
        .expect("remember dispatch ok")
}

// I1 — wired rejecting policy → storage-error.
#[tokio::test]
async fn i1_wired_policy_rejects_with_storage_error() {
    let (reg, store) = registry_with_policy(Some(Arc::new(RejectContaining("FILE-BYTES"))));
    let r = call_remember(&reg, "agent:a", "here are raw FILE-BYTES copied verbatim").await;
    match &r[0] {
        Val::Result(Err(Some(payload))) => match payload.as_ref() {
            Val::Variant(name, inner) => {
                assert_eq!(
                    name, "storage-error",
                    "policy reject lowers to storage-error"
                );
                assert!(
                    matches!(inner.as_deref(), Some(Val::String(s)) if !s.is_empty()),
                    "storage-error carries a non-empty reason"
                );
            }
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("expected Err(Some(..)), got {other:?}"),
    }
    // Nothing was stored (the reject precedes store.insert).
    assert!(
        store.list("agent:a").is_empty(),
        "rejected remember stores nothing"
    );
}

// I2 — wired policy that allows → Ok(id).
#[tokio::test]
async fn i2_wired_policy_allows_ok() {
    let (reg, _store) = registry_with_policy(Some(Arc::new(RejectContaining("NEVER-MATCHES"))));
    let r = call_remember(
        &reg,
        "agent:a",
        "a genuine cross-file insight worth storing",
    )
    .await;
    assert!(
        matches!(&r[0], Val::Result(Ok(Some(p))) if matches!(p.as_ref(), Val::String(_))),
        "allowed remember returns Ok(memory-id); got {:?}",
        r[0]
    );
}

// I3 — NO policy (legacy registration): the SAME would-be-rejected content is stored,
// byte-identical to the pre-guard path.
#[tokio::test]
async fn i3_default_off_byte_identical() {
    let reg = Arc::new(InMemoryHostRegistry::new());
    let store = Arc::new(MemoryStore::new());
    // Legacy entry point — no policy threaded at all.
    register_agent_memory(
        reg.as_ref(),
        Arc::clone(&store),
        Arc::new(NoopEventBus),
        Arc::new(L6CursorStore::new()),
    );
    let r = call_remember(&reg, "agent:a", "here are raw FILE-BYTES copied verbatim").await;
    assert!(
        matches!(&r[0], Val::Result(Ok(Some(_)))),
        "with no policy, even reject-triggering content is stored (byte-identical); got {:?}",
        r[0]
    );
    assert_eq!(
        store.list("agent:a").len(),
        1,
        "the entry is persisted on the default-off path"
    );
}

// I4 — the L6 / store.insert path is UNGATED even when a rejecting policy is wired into
// the handler. Proves the guard inspects remember() content, not provenance.
#[tokio::test]
async fn i4_fileref_store_insert_ungated() {
    let (_reg, store) = registry_with_policy(Some(Arc::new(RejectContaining("FILE-BYTES"))));
    // The SAME content the handler would reject, but written the way L6 synthesis writes
    // it: directly via store.insert with a FileRef provenance source.
    let entry = MemoryEntry {
        id: "l6-1".into(),
        agent_id: "agent:a".into(),
        entry_type: MemoryType::Fact,
        content: "here are raw FILE-BYTES copied verbatim".into(),
        tags: vec!["l6".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![MemorySource::FileRef {
            agent_id: "agent:a".into(),
            vpath: "data/report.csv".into(),
            commit_ish: "abc".into(),
            blob_id: "blob-1".into(),
            line_range: None,
        }],
    };
    let inserted = store.insert("agent:a", entry);
    assert!(
        inserted.is_ok(),
        "the L6/store.insert path is not gated by the remember() producer-boundary policy: {inserted:?}"
    );
    assert_eq!(store.list("agent:a").len(), 1);
}
