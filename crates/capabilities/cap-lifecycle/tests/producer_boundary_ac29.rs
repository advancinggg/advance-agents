//! MODULE-005-AC-29 (PRIMARY witness) — the `knowledge.jsonl` producer-boundary guard
//! driven end-to-end: a REAL `WorkspaceFileResidentPolicy` (cap-lifecycle / MODULE-005)
//! wired into the REAL cap-memory `remember()` handler (MODULE-011) over a REAL temp
//! workspace.
//!
//!   E1 — `remember(exact workspace-file bytes)` → REJECTED (storage-error naming the
//!        file) AND nothing is stored (the reject prevents the insert).
//!   E2 — `remember(a genuine insight)` → `Ok(id)` and it is stored.
//!   E3 — `remember(below-floor file bytes)` → `Ok(id)` (floor gates the scan).
//!   E4 — with NO policy wired, `remember(exact workspace-file bytes)` → `Ok(id)`
//!        (default-off is byte-identical).

use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionSpec, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::traits::RememberContentPolicy;
use cap_lifecycle::WorkspaceFileResidentPolicy;
use cap_memory::{
    register_agent_memory_with_git_and_policy, L6CursorStore, MemoryStore, NoopEventBus,
    CAPABILITY, NAMESPACE,
};
use tempfile::TempDir;
use wasmtime::component::Val;

fn ctx_for(agent: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "trace-ac29".to_string(),
        turn_id: None,
        capability: CAPABILITY.to_string(),
        function: format!("{NAMESPACE}::test"),
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

fn register(
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

async fn remember(reg: &InMemoryHostRegistry, agent: &str, content: &str) -> Vec<Val> {
    let specs = reg.lookup(CAPABILITY);
    spec_named(&specs, "remember")
        .handler
        .call(
            ctx_for(agent),
            vec![Val::String(content.into()), Val::List(vec![])],
            1,
        )
        .await
        .expect("remember dispatch ok")
}

/// A workspace whose `report.txt` (≥512 B) is the file-dump target.
fn workspace_with_report() -> (TempDir, String) {
    let td = TempDir::new().unwrap();
    let file_content = "The quarterly report shows revenue up 12% across all regions. ".repeat(16);
    assert!(file_content.len() >= 512);
    std::fs::write(td.path().join("report.txt"), file_content.as_bytes()).unwrap();
    (td, file_content)
}

// E1 — the core reject witness + nothing stored.
#[tokio::test]
async fn e1_reject_file_bytes_and_store_stays_empty() {
    let (td, file_content) = workspace_with_report();
    let policy = Arc::new(WorkspaceFileResidentPolicy::rooted(td.path().to_path_buf()));
    let (reg, store) = register(Some(policy));

    let r = remember(&reg, "agent:a", &file_content).await;
    match &r[0] {
        Val::Result(Err(Some(payload))) => match payload.as_ref() {
            Val::Variant(name, inner) => {
                assert_eq!(name, "storage-error");
                match inner.as_deref() {
                    Some(Val::String(reason)) => {
                        assert!(
                            reason.contains("report.txt"),
                            "reason names the file: {reason}"
                        );
                        assert!(reason.contains("producer-boundary"), "reason: {reason}");
                    }
                    other => panic!("expected String reason, got {other:?}"),
                }
            }
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("expected Err(Some(..)), got {other:?}"),
    }
    // The reject happened BEFORE store.insert — a subsequent read finds nothing.
    assert!(
        store.list("agent:a").is_empty(),
        "rejected remember must not have persisted an entry"
    );
}

// E2 — a genuine insight is accepted and stored.
#[tokio::test]
async fn e2_accept_genuine_insight() {
    let (td, _file_content) = workspace_with_report();
    let policy = Arc::new(WorkspaceFileResidentPolicy::rooted(td.path().to_path_buf()));
    let (reg, store) = register(Some(policy));

    let insight =
        "Cross-file observation: the auth retry loop double-counts tokens under contention.";
    let r = remember(&reg, "agent:a", insight).await;
    assert!(
        matches!(&r[0], Val::Result(Ok(Some(_)))),
        "a genuine insight is stored; got {:?}",
        r[0]
    );
    let stored = store.list("agent:a");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].content, insight);
}

// E3 — below-floor content equal to a file is allowed (the floor gates the scan).
#[tokio::test]
async fn e3_below_floor_allowed() {
    let td = TempDir::new().unwrap();
    let small = "short note under the floor";
    std::fs::write(td.path().join("note.txt"), small.as_bytes()).unwrap();
    let policy = Arc::new(WorkspaceFileResidentPolicy::rooted(td.path().to_path_buf()));
    let (reg, store) = register(Some(policy));

    let r = remember(&reg, "agent:a", small).await;
    assert!(
        matches!(&r[0], Val::Result(Ok(Some(_)))),
        "below-floor content is never rejected; got {:?}",
        r[0]
    );
    assert_eq!(store.list("agent:a").len(), 1);
}

// E4 — default-off (no policy) is byte-identical: the file bytes ARE stored.
#[tokio::test]
async fn e4_default_off_byte_identical() {
    let (td, file_content) = workspace_with_report();
    // Even though the concrete policy type exists, wiring NONE keeps the legacy path.
    let (reg, store) = register(None);
    let _ = &td; // workspace exists but no policy consults it

    let r = remember(&reg, "agent:a", &file_content).await;
    assert!(
        matches!(&r[0], Val::Result(Ok(Some(_)))),
        "with no policy, the file bytes are stored (byte-identical); got {:?}",
        r[0]
    );
    assert_eq!(store.list("agent:a").len(), 1);
}
