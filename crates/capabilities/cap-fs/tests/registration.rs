//! `register_agent_fs` registers exactly 18 specs under capability "fs"
//! (slice A: 4 + slice B: 14).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{register_agent_fs_default, DefaultVirtualPathResolver, MetaSchemaLoader};

use common::{single_agent_tree, TestEmitter};

// SB-T01 / SB-T02: register_agent_fs_default registers exactly 18 specs.
#[test]
fn registers_eighteen_specs_with_idempotent_flags() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = single_agent_tree("a", agent_workspace);
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new()) as Arc<dyn EventBusEmit>;
    let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));

    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_fs_default(&*registry, resolver, emitter, schema, None);

    let specs = registry.lookup("fs");
    assert_eq!(
        specs.len(),
        18,
        "expected 18 specs (slice A: 4 + slice B: 14)"
    );

    let mut by_name: std::collections::HashMap<
        &str,
        &advance_runtime::host_registry::HostFunctionSpec,
    > = std::collections::HashMap::new();
    for s in &specs {
        by_name.insert(s.name.as_str(), s);
    }

    let expected = [
        "read",
        "write",
        "list",
        "delete",
        "scan",
        "read-slug",
        "list-slug",
        "scan-slug",
        "read-child",
        "list-child",
        "scan-child",
        "file-history",
        "read-at",
        "child-file-history",
        "read-child-at",
        "slug-file-history",
        "update-scope",
        "update-entry-meta",
    ];
    for name in expected {
        let s = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing spec for {name}"));
        assert_eq!(s.capability, "fs", "capability for {name}");
        assert_eq!(
            s.namespace, "advance:runtime/agent-fs@0.1.0",
            "namespace for {name}"
        );
    }

    // Idempotent flags
    let idempotent_names = [
        "read",
        "list",
        "scan",
        "read-slug",
        "list-slug",
        "scan-slug",
        "read-child",
        "list-child",
        "scan-child",
        "file-history",
        "read-at",
        "child-file-history",
        "read-child-at",
        "slug-file-history",
    ];
    for name in idempotent_names {
        assert!(
            by_name[name].idempotent,
            "{name} should be idempotent (read-only)"
        );
    }
    let mutating_names = ["write", "delete", "update-scope", "update-entry-meta"];
    for name in mutating_names {
        assert!(
            !by_name[name].idempotent,
            "{name} must NOT be idempotent (mutating)"
        );
    }
}

// AC-01 (REQ-170): all 18 host fns are dispatch-ready through the registry —
// for each of the 18 specs, look up the handler via `registry.lookup("fs")`,
// invoke it through the same WIT-shaped `HostFunctionHandler::call` interface
// that wasmtime invokes when WASM imports `advance:runtime/agent-fs@0.1.0`, and
// confirm the dispatch returns a structured result (Ok with a Result-typed
// Val arm OR a HostCallError) rather than panicking. This proves each spec's
// handler is bound and callable through the same code path WASM would hit.
#[tokio::test]
async fn all_eighteen_specs_callable_via_registry_dispatch() {
    use advance_runtime::host_registry::HostCallContext;
    use wasmtime::component::Val;

    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = single_agent_tree("a", agent_workspace);
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new()) as Arc<dyn EventBusEmit>;
    let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));

    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_fs_default(&*registry, resolver, emitter, schema, None);

    let specs = registry.lookup("fs");
    assert_eq!(specs.len(), 18);
    let mut by_name: std::collections::HashMap<
        String,
        advance_runtime::host_registry::HostFunctionSpec,
    > = std::collections::HashMap::new();
    for s in specs {
        by_name.insert(s.name.clone(), s);
    }

    let ctx = HostCallContext {
        agent_id: "a".into(),
        trace_id: "tr-reg".into(),
        turn_id: None,
        capability: "fs".into(),
        function: "advance:runtime/agent-fs::dispatch-probe".into(),
        run_id: None,
        iteration: None,
    };

    // Per-handler params + expected results_len (one Val::Result(...) result).
    // We hand each handler a deliberate "missing path" path so the call lands
    // inside the handler body (proving dispatch works) and returns a typed
    // Result-arm error rather than panicking. The exact error variant doesn't
    // matter — what matters is "we got past dispatch into the handler".
    let dispatches: &[(&str, Vec<Val>)] = &[
        ("read", vec![Val::String("missing.md".into())]),
        (
            "write",
            vec![Val::String("note.md".into()), Val::List(vec![Val::U8(1)])],
        ),
        ("list", vec![Val::String(".".into())]),
        ("delete", vec![Val::String("missing.md".into())]),
        ("scan", vec![Val::String(".".into())]),
        (
            "read-slug",
            vec![
                Val::String("sub-x".into()),
                Val::String("slug".into()),
                Val::String("f.md".into()),
            ],
        ),
        (
            "list-slug",
            vec![Val::String("sub-x".into()), Val::String("slug".into())],
        ),
        (
            "scan-slug",
            vec![Val::String("sub-x".into()), Val::String("slug".into())],
        ),
        (
            "read-child",
            vec![Val::String("sub-x".into()), Val::String("f.md".into())],
        ),
        (
            "list-child",
            vec![Val::String("sub-x".into()), Val::String(".".into())],
        ),
        (
            "scan-child",
            vec![Val::String("sub-x".into()), Val::String(".".into())],
        ),
        ("file-history", vec![Val::String("missing.md".into())]),
        (
            "read-at",
            vec![Val::String("missing.md".into()), Val::String("v1".into())],
        ),
        (
            "child-file-history",
            vec![Val::String("sub-x".into()), Val::String("f.md".into())],
        ),
        (
            "read-child-at",
            vec![
                Val::String("sub-x".into()),
                Val::String("f.md".into()),
                Val::String("v1".into()),
            ],
        ),
        (
            "slug-file-history",
            vec![
                Val::String("sub-x".into()),
                Val::String("slug".into()),
                Val::String("f.md".into()),
            ],
        ),
        (
            "update-scope",
            vec![
                Val::String(".".into()),
                Val::String("desc".into()),
                Val::List(vec![]),
            ],
        ),
        (
            "update-entry-meta",
            vec![
                Val::String(".".into()),
                Val::String("missing.md".into()),
                Val::String("desc".into()),
                Val::List(vec![]),
            ],
        ),
    ];

    assert_eq!(dispatches.len(), 18);
    for (name, params) in dispatches {
        let spec = by_name
            .get(*name)
            .unwrap_or_else(|| panic!("spec {name} not in registry"));
        // Dispatch with the WIT-shaped params each handler declares. The call
        // MUST NOT return HostCallError (that would mean the handler rejected
        // the call shape, indicating a binding/shape mismatch); a typed
        // Result-arm error like NotFound is fine — it proves the call landed
        // inside the handler body and the WIT-level dispatch path works end
        // to end.
        let outcome = spec.handler.call(ctx.clone(), params.clone(), 1).await;
        assert!(
            outcome.is_ok(),
            "registry-dispatched call for `{name}` returned HostCallError; \
             handler shape mismatch: {outcome:?}"
        );
    }
}
