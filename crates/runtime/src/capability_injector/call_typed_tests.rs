//! MODULE-001-AC-31: `HostFunctionHandler::call_typed` runs after L1 / the breaker.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use advance_shared_types::capability::{CapParams, CapRequest, GrantDecision};
use advance_shared_types::component::ComponentType;
use advance_shared_types::traits::GrantCheck;
use wasmtime::component::Val;

use super::{CapabilityInjector, ComponentCtx};
use crate::circuit_breaker::{
    BreakerError, BreakerEvent, BreakerScope, CircuitBreaker, CircuitBreakerBus,
};
use crate::component_loader::ComponentRuntime;
use crate::config::WasmConfig;
use crate::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
    InMemoryHostRegistry,
};

const TYPED_WAT: &str = r#"
(component
  (import "test:typed/host" (instance $h
    (export "go" (func))
  ))
  (core func $go_lowered (canon lower (func $h "go")))
  (core module $m
    (import "test:typed" "go" (func $go_imp))
    (func (export "run") call $go_imp)
  )
  (core instance $i (instantiate $m
    (with "test:typed" (instance (export "go" (func $go_lowered))))
  ))
  (func (export "run") (canon lift (core func $i "run")))
)
"#;

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

#[derive(Clone)]
enum GrantPolicy {
    AlwaysAllow,
    AlwaysDeny(String),
}

struct MockGrantCheck {
    policy: GrantPolicy,
    calls: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl MockGrantCheck {
    fn new(policy: GrantPolicy) -> (Arc<Self>, Arc<Mutex<Vec<(String, String, String)>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let me = Arc::new(MockGrantCheck {
            policy,
            calls: calls.clone(),
        });
        (me, calls)
    }
}

impl GrantCheck for MockGrantCheck {
    fn check(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        self.calls.lock().unwrap().push((
            agent_id.to_string(),
            capability.to_string(),
            function.to_string(),
        ));
        match &self.policy {
            GrantPolicy::AlwaysAllow => GrantDecision::Allow,
            GrantPolicy::AlwaysDeny(reason) => GrantDecision::Deny(reason.clone()),
        }
    }
}

#[derive(Clone)]
enum BreakerPolicy {
    AllClosed,
    CapabilityOpen(String),
}

struct MockBreakerBus {
    policy: BreakerPolicy,
}

impl CircuitBreakerBus for MockBreakerBus {
    fn is_open_capability(&self, _cap: &str) -> Option<String> {
        match &self.policy {
            BreakerPolicy::AllClosed => None,
            BreakerPolicy::CapabilityOpen(r) => Some(r.clone()),
        }
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

struct RecordingHandler {
    typed: AtomicUsize,
    call: AtomicUsize,
    arity: Mutex<Option<(usize, usize)>>,
}

impl RecordingHandler {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            typed: AtomicUsize::new(0),
            call: AtomicUsize::new(0),
            arity: Mutex::new(None),
        })
    }
}

impl HostFunctionHandler for RecordingHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        self.call.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Vec::new()) })
    }

    fn call_typed(
        &self,
        func: &wasmtime::component::types::ComponentFunc,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        self.typed.fetch_add(1, Ordering::SeqCst);
        *self.arity.lock().unwrap() = Some((func.params().len(), func.results().len()));
        self.call(ctx, params, results_len)
    }
}

struct CallOnlyHandler;

impl HostFunctionHandler for CallOnlyHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        Box::pin(async { Err(HostCallError::HandlerError("x".into())) })
    }
}

fn invoke(
    handler: Arc<dyn HostFunctionHandler>,
    grant: GrantPolicy,
    breaker: BreakerPolicy,
) -> Result<(), String> {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    registry.register(HostFunctionSpec {
        capability: "typed".into(),
        namespace: "test:typed/host".into(),
        name: "go".into(),
        handler,
        idempotent: false,
    });
    let (gc, _) = MockGrantCheck::new(grant);
    let br: Arc<dyn CircuitBreakerBus> = Arc::new(MockBreakerBus { policy: breaker });
    let injector = CapabilityInjector::new(registry, gc, br);

    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker = wasmtime::component::Linker::new(runtime.host_engine_handle().engine());
    let caps = vec![CapRequest {
        capability: advance_shared_types::capability::CapabilityId::from("typed"),
    }];
    injector.inject(&mut linker, &caps).expect("inject");

    let bytes = wat::parse_str(TYPED_WAT).expect("wat");
    let loaded = runtime.load_component(&bytes).expect("load");
    let mut store = wasmtime::Store::new(
        runtime.host_engine_handle().engine(),
        ComponentCtx::new(
            "agent-typed".into(),
            "trace-typed".into(),
            vec!["typed".into()],
        ),
    );
    store.set_epoch_deadline(u64::MAX / 2);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio");
    rt.block_on(async {
        let pre = linker
            .instantiate_pre(loaded.component())
            .map_err(|e| format!("{e:#}"))?;
        let instance = pre
            .instantiate_async(&mut store)
            .await
            .map_err(|e| format!("{e:#}"))?;
        let run = instance
            .get_func(&mut store, "run")
            .ok_or_else(|| "missing export run".to_string())?;
        let typed = run.typed::<(), ()>(&store).map_err(|e| format!("{e:#}"))?;
        typed
            .call_async(&mut store, ())
            .await
            .map_err(|e| format!("{e:#}"))
    })
}

#[test]
fn module_001_ac31_call_typed_runs_after_l1_and_sees_the_guest_type() {
    let handler = RecordingHandler::new();
    invoke(
        Arc::clone(&handler) as Arc<dyn HostFunctionHandler>,
        GrantPolicy::AlwaysAllow,
        BreakerPolicy::AllClosed,
    )
    .expect("allow");
    assert_eq!(handler.typed.load(Ordering::SeqCst), 1);
    assert_eq!(handler.call.load(Ordering::SeqCst), 1);
    assert_eq!(*handler.arity.lock().unwrap(), Some((0, 0)));

    let handler = RecordingHandler::new();
    let err = invoke(
        Arc::clone(&handler) as Arc<dyn HostFunctionHandler>,
        GrantPolicy::AlwaysDeny("nope".into()),
        BreakerPolicy::AllClosed,
    )
    .expect_err("deny");
    assert!(err.contains("capability-denied: nope"), "deny trap: {err}");
    assert_eq!(handler.typed.load(Ordering::SeqCst), 0);
    assert_eq!(handler.call.load(Ordering::SeqCst), 0);

    let handler = RecordingHandler::new();
    let err = invoke(
        Arc::clone(&handler) as Arc<dyn HostFunctionHandler>,
        GrantPolicy::AlwaysAllow,
        BreakerPolicy::CapabilityOpen("tripped".into()),
    )
    .expect_err("breaker");
    assert!(
        err.contains("circuit-breaker: tripped"),
        "breaker trap: {err}"
    );
    assert_eq!(handler.typed.load(Ordering::SeqCst), 0);
    assert_eq!(handler.call.load(Ordering::SeqCst), 0);
}

#[test]
fn module_001_ac31_call_typed_default_delegates_to_call() {
    let err = invoke(
        Arc::new(CallOnlyHandler),
        GrantPolicy::AlwaysAllow,
        BreakerPolicy::AllClosed,
    )
    .expect_err("handler error");
    assert!(
        err.contains('x'),
        "trap should carry the handler error: {err}"
    );
}
