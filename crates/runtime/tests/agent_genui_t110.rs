//! MODULE-001-T110 — flag-gated L0 `agent-genui` (crate altitude).
//!
//! Witnesses register / inject / exact-signature WAT import-fail + host-fn
//! loopback. Does **not** assert catalog admit, grant allow, C219 redaction,
//! M020 projection, `genui.*` events, or a successful guest emit.

use std::sync::Arc;

use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx, HostError};
use advance_runtime::circuit_breaker::{
    BreakerError, BreakerEvent, BreakerScope, CircuitBreaker, CircuitBreakerBus,
};
use advance_runtime::component_loader::ComponentRuntime;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostRegistry, InMemoryHostRegistry,
};
use advance_runtime::register_agent_genui;
use advance_shared_types::capability::{CapParams, CapRequest, GrantDecision};
use advance_shared_types::component::ComponentType;
use advance_shared_types::traits::GrantCheck;
use wasmtime::component::Val;
use wit_component::{embed_component_metadata, ComponentEncoder, StringEncoding};
use wit_parser::{ManglingAndAbi, Resolve, Type, TypeDefKind, WorldItem};

const NS: &str = "advance:runtime/agent-genui@0.1.0";
const HOST_WIT: &str = include_str!("../wit/advance.wit");
const FIXTURE_WIT: &str = include_str!("fixtures/guest-rust-minimal/wit/advance.wit");

/// Guest component that imports the exact host WIT `agent-genui` interface
/// (`emit-document: string → result<string, genui-error>` with the seven-arm
/// projection). Built from the host WIT so the signature cannot drift.
fn emit_document_import_component() -> Vec<u8> {
    let mut resolve = Resolve::default();
    resolve
        .push_str("advance.wit", HOST_WIT)
        .expect("host WIT parses");
    let guest_pkg = resolve
        .push_str(
            "t110-guest.wit",
            "package test:t110@0.1.0;\nworld t110-guest {\n  import advance:runtime/agent-genui@0.1.0;\n}\n",
        )
        .expect("t110-guest world parses");
    let world = resolve
        .select_world(&[guest_pkg], Some("t110-guest"))
        .expect("t110-guest world exists");
    let mut core_bytes = wit_component::dummy_module(&resolve, world, ManglingAndAbi::Standard32);
    embed_component_metadata(&mut core_bytes, &resolve, world, StringEncoding::UTF8)
        .expect("embed component metadata");
    ComponentEncoder::default()
        .validate(true)
        .module(&core_bytes)
        .expect("core module accepted")
        .encode()
        .expect("component encoded")
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

struct AlwaysAllowGrant;
impl GrantCheck for AlwaysAllowGrant {
    fn check(
        &self,
        _agent_id: &str,
        _capability: &str,
        _function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct ClosedBreaker;
impl CircuitBreakerBus for ClosedBreaker {
    fn is_open_capability(&self, _cap: &str) -> Option<String> {
        None
    }
    fn is_open_component_type(&self, _kind: ComponentType) -> Option<String> {
        None
    }
    fn is_open_agent(&self, _agent_id: &str) -> Option<String> {
        None
    }
    fn open(&self, _b: CircuitBreaker) -> Result<(), BreakerError> {
        Ok(())
    }
    fn close(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        Ok(())
    }
    fn half_open(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        Ok(())
    }
    fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<BreakerEvent> {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        rx
    }
}

fn build_injector(registry: Arc<dyn HostRegistry>) -> CapabilityInjector {
    CapabilityInjector::new(
        registry,
        Arc::new(AlwaysAllowGrant),
        Arc::new(ClosedBreaker),
    )
}

fn new_linker(runtime: &ComponentRuntime) -> wasmtime::component::Linker<ComponentCtx> {
    wasmtime::component::Linker::new(runtime.host_engine_handle().engine())
}

fn genui_request() -> Vec<CapRequest> {
    vec![CapRequest {
        capability: advance_shared_types::capability::CapabilityId::from("genui"),
    }]
}

fn host_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: "t110".into(),
        trace_id: "t110".into(),
        turn_id: None,
        capability: "genui".into(),
        function: format!("{NS}::emit-document"),
        run_id: None,
        iteration: None,
    }
}

fn decode_err(vals: &[Val]) -> (&str, Option<&str>) {
    match vals {
        [Val::Result(Err(Some(boxed)))] => match boxed.as_ref() {
            Val::Variant(case, None) => (case.as_str(), None),
            Val::Variant(case, Some(payload)) => match payload.as_ref() {
                Val::String(s) => (case.as_str(), Some(s.as_str())),
                other => panic!("expected string payload, got {other:?}"),
            },
            other => panic!("expected Variant error, got {other:?}"),
        },
        other => panic!("expected Err result, got {other:?}"),
    }
}

#[test]
fn t110_3_flag_off_lookup_empty_inject_unknown() {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    assert!(registry.lookup("genui").is_empty());

    let injector = build_injector(registry);
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker = new_linker(&runtime);
    match injector.inject(&mut linker, &genui_request()) {
        Err(HostError::UnknownCapability(c)) => assert_eq!(c, "genui"),
        other => panic!("expected UnknownCapability(\"genui\"), got {other:?}"),
    }
}

#[test]
fn t110_4_register_then_lookup_and_inject() {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_genui(&*registry, 262_144);
    let specs = registry.lookup("genui");
    assert_eq!(specs.len(), 1, "exactly one emit-document spec");
    assert_eq!(specs[0].capability, "genui");
    assert_eq!(specs[0].namespace, NS);
    assert_eq!(specs[0].name, "emit-document");
    assert!(!specs[0].idempotent);

    let injector = build_injector(registry);
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker = new_linker(&runtime);
    injector
        .inject(&mut linker, &genui_request())
        .expect("inject genui");
}

#[test]
fn t110_5_exact_signature_wat_fails_instantiate_when_off() {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let injector = build_injector(registry);
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let linker = new_linker(&runtime);
    // Flag off: do not register, do not inject genui.
    let _ = injector;

    let bytes = emit_document_import_component();
    let component = runtime.load_component(&bytes).expect("load");
    let mut store = wasmtime::Store::new(
        runtime.host_engine_handle().engine(),
        ComponentCtx::new("agent-t110".into(), "trace-t110".into(), Vec::new()),
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    let result = rt.block_on(async {
        linker
            .instantiate_async(&mut store, component.component())
            .await
    });
    let err = result.expect_err("instantiate must fail when agent-genui is not linked");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("agent-genui")
            || msg.contains("advance:runtime/agent-genui")
            || msg.contains("import")
            || msg.contains("not found")
            || msg.contains("unknown"),
        "error should mention missing import / namespace; got: {msg}"
    );
}

#[test]
fn t110_5b_exact_signature_wat_instantiates_when_on() {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_genui(&*registry, 262_144);
    let injector = build_injector(registry);
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker = new_linker(&runtime);
    injector
        .inject(&mut linker, &genui_request())
        .expect("inject");

    let bytes = emit_document_import_component();
    let component = runtime.load_component(&bytes).expect("load");
    let mut store = wasmtime::Store::new(
        runtime.host_engine_handle().engine(),
        ComponentCtx::new(
            "agent-t110".into(),
            "trace-t110".into(),
            vec!["genui".into()],
        ),
    );
    // Default epoch_deadline is 0 (already elapsed) and traps; dummy-module
    // initialize would otherwise interrupt before we can witness the link.
    store.set_epoch_deadline(u64::MAX / 2);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    let result = rt.block_on(async {
        linker
            .instantiate_async(&mut store, component.component())
            .await
    });
    assert!(
        result.is_ok(),
        "instantiate must succeed when genui is registered+injected: {result:?}"
    );
}

#[tokio::test]
async fn t110_8_loopback_handler_encoding() {
    let registry = InMemoryHostRegistry::new();
    register_agent_genui(&registry, 8);
    let spec = registry.lookup("genui").into_iter().next().expect("spec");

    let empty = spec
        .handler
        .call(host_ctx(), vec![Val::String(String::new())], 1)
        .await
        .expect("empty is a typed error, not a trap");
    let (case, payload) = decode_err(&empty);
    assert_eq!(case, "invalid-props");
    assert_eq!(payload, Some("empty document-json"));

    let oversize = spec
        .handler
        .call(host_ctx(), vec![Val::String("0123456789".into())], 1)
        .await
        .expect("oversize is a typed error, not a trap");
    let (case, payload) = decode_err(&oversize);
    assert_eq!(case, "document-too-large");
    assert_eq!(payload, None, "document-too-large must be payloadless");

    let loopback = spec
        .handler
        .call(host_ctx(), vec![Val::String("{}".into())], 1)
        .await
        .expect("under-cap is a typed surface-unavailable, not Ok");
    let (case, payload) = decode_err(&loopback);
    assert_eq!(case, "surface-unavailable");
    assert_eq!(payload, Some("l0-loopback"));

    let bad_len = spec
        .handler
        .call(host_ctx(), vec![Val::String("x".into())], 0)
        .await;
    assert!(
        matches!(bad_len, Err(HostCallError::HandlerError(_))),
        "results_len != 1 must trap: {bad_len:?}"
    );

    let bad_params = spec.handler.call(host_ctx(), vec![Val::U32(1)], 1).await;
    assert!(
        matches!(bad_params, Err(HostCallError::HandlerError(_))),
        "non-string params must trap: {bad_params:?}"
    );
}

#[test]
fn t110_10_structural_wit_lock() {
    let mut resolve = Resolve::default();
    let pkg = resolve
        .push_str("advance.wit", HOST_WIT)
        .expect("host WIT parses");
    let iface_id = resolve.packages[pkg]
        .interfaces
        .get("agent-genui")
        .copied()
        .expect("interface agent-genui exists");
    let iface = &resolve.interfaces[iface_id];

    let fn_names: std::collections::BTreeSet<&str> =
        iface.functions.keys().map(|s| s.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> = ["emit-document"].into_iter().collect();
    assert_eq!(
        fn_names, expected,
        "agent-genui function set must be exactly {{emit-document}}"
    );

    let func = iface.functions.get("emit-document").expect("emit-document");
    assert_eq!(func.params.len(), 1);
    assert_eq!(func.params[0].name, "document-json");
    assert!(
        matches!(func.params[0].ty, Type::String),
        "document-json must be string, got {:?}",
        func.params[0].ty
    );
    let ret = func
        .result
        .as_ref()
        .expect("emit-document must return a result");
    let Type::Id(ret_id) = ret else {
        panic!("return must be a TypeId, got {ret:?}");
    };
    let TypeDefKind::Result(res) = &resolve.types[*ret_id].kind else {
        panic!(
            "return must be result<_, _>, got {:?}",
            resolve.types[*ret_id].kind
        );
    };
    assert!(
        matches!(res.ok, Some(Type::String)),
        "ok arm must be string, got {:?}",
        res.ok
    );
    let Type::Id(err_id) = res.err.expect("err arm present") else {
        panic!("err arm must be genui-error TypeId, got {:?}", res.err);
    };
    let err_named = iface
        .types
        .get("genui-error")
        .copied()
        .expect("interface type genui-error");
    assert_eq!(err_id, err_named, "result err must be genui-error");

    let TypeDefKind::Variant(variant) = &resolve.types[err_id].kind else {
        panic!("genui-error must be a variant");
    };
    let got: Vec<(&str, bool)> = variant
        .cases
        .iter()
        .map(|c| {
            let string_payload = match c.ty {
                None => false,
                Some(Type::String) => true,
                other => panic!("unexpected payload for {}: {other:?}", c.name),
            };
            (c.name.as_str(), string_payload)
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("denied", false),
            ("invalid-component", true),
            ("invalid-props", true),
            ("document-too-large", false),
            ("invalid-action", true),
            ("surface-unavailable", true),
            ("bridge-violation", false),
        ]
    );

    for world_name in ["advance-host", "advance-host-with-capabilities"] {
        let world_id = resolve
            .select_world(&[pkg], Some(world_name))
            .unwrap_or_else(|_| panic!("{world_name} exists"));
        let world = &resolve.worlds[world_id];
        for item in world.imports.values() {
            if let WorldItem::Interface { id, .. } = item {
                let name = resolve.interfaces[*id].name.as_deref();
                assert_ne!(
                    name,
                    Some("agent-genui"),
                    "{world_name} must not import agent-genui"
                );
            }
        }
    }

    assert!(
        FIXTURE_WIT.contains("interface agent-genui"),
        "T47 fixture WIT must contain interface agent-genui"
    );
}
