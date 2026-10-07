//! Host-function registrar replay, signature walker, and containment adapter.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use futures::FutureExt;
use wasmtime::component::types::{ComponentFunc, Type};
use wasmtime::component::Val;

use crate::api::log_keys;
use crate::api::{
    ComposeError, ExtensionPhase, HostFunctionFailure, HostFunctionRefusal, HostFunctionRegistrar,
    PanicAnswer,
};
use crate::compose_log::LogHandle;
use crate::extension::call::{scope, scope_sync, CallIdentity};
use crate::extension::guard;
use crate::extension::set::ExtensionSet;

type BoxedHostFuture =
    Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>;

/// Call every extension's `host_functions`, then replay accepted specs into `registry`.
pub(crate) fn run_host_functions(
    exts: &ExtensionSet,
    registry: &dyn HostRegistry,
    log: &LogHandle,
) -> Result<usize, ComposeError> {
    let taken = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let counts = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let mut pending = Vec::new();
    for (id, ext, cx) in exts.iter_with_cx()? {
        let mut reg = HostFunctionRegistrar::new(
            id,
            exts.capabilities_of(id),
            Arc::clone(&taken),
            Arc::clone(&counts),
        );
        let result = guard::run_sync_callback(id, ExtensionPhase::HostFunctions, || {
            ext.host_functions(cx, &mut reg)
        })?;
        if let Some(refusal) = reg.first_refusal() {
            return Err(ComposeError::HostFunction {
                extension: id,
                refusal: refusal.clone(),
            });
        }
        if let Err(error) = result {
            return Err(guard::failed(id, ExtensionPhase::HostFunctions, &error));
        }
        if let Some(capability) = reg.capability_without_function() {
            return Err(ComposeError::HostFunction {
                extension: id,
                refusal: HostFunctionRefusal::CapabilityWithoutFunction {
                    capability: capability.to_owned(),
                },
            });
        }
        pending.extend(reg.take_pending());
    }
    let n = pending.len();
    for spec in pending {
        let failure = HostFunctionFailure {
            extension: spec.extension,
            namespace: spec.namespace.clone(),
            name: spec.name.clone(),
        };
        registry.register(HostFunctionSpec {
            capability: spec.capability,
            namespace: spec.namespace,
            name: spec.name,
            handler: Arc::new(ContainedHostFunction {
                failure,
                inner: Some(spec.handler),
                panic_answer: spec.panic_answer,
                log: log.clone(),
            }),
            idempotent: spec.idempotent,
        });
    }
    Ok(n)
}

pub(crate) struct ContainedHostFunction {
    failure: HostFunctionFailure,
    inner: Option<Arc<dyn HostFunctionHandler>>,
    panic_answer: Option<PanicAnswer>,
    log: LogHandle,
}

impl HostFunctionHandler for ContainedHostFunction {
    fn call(&self, ctx: HostCallContext, params: Vec<Val>, results_len: usize) -> BoxedHostFuture {
        self.contained(None, ctx, params, results_len)
    }

    fn call_typed(
        &self,
        func: &ComponentFunc,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> BoxedHostFuture {
        if let Some(what) = unsupported_signature(func) {
            return ready_err(unsupported_text(what, &self.failure));
        }
        self.contained(Some(func), ctx, params, results_len)
    }
}

impl ContainedHostFunction {
    fn contained(
        &self,
        func: Option<&ComponentFunc>,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> BoxedHostFuture {
        let Some(inner) = self.inner.as_ref() else {
            return ready_err(self.failure.to_string());
        };
        let fallback = Fallback::new(&self.failure, self.panic_answer.clone(), func, &self.log);
        let id = CallIdentity::host_function(self.failure.extension, &ctx);
        let built = std::panic::catch_unwind(AssertUnwindSafe(|| {
            scope_sync(id.clone(), || match func {
                Some(f) => inner.call_typed(f, ctx, params, results_len),
                None => inner.call(ctx, params, results_len),
            })
        }));
        let fut = match built {
            Ok(fut) => fut,
            Err(_) => return Box::pin(std::future::ready(fallback.on_panic(results_len))),
        };
        Box::pin(async move {
            match AssertUnwindSafe(scope(id, fut)).catch_unwind().await {
                Ok(result) => result,
                Err(_) => fallback.on_panic(results_len),
            }
        })
    }
}

impl Drop for ContainedHostFunction {
    fn drop(&mut self) {
        let parts = (self.inner.take(), self.panic_answer.take());
        if std::panic::catch_unwind(AssertUnwindSafe(move || drop(parts))).is_err() {
            self.log.err(
                log_keys::EXT_HOST_FUNCTION_PANICKED,
                format!(
                    "advance: WARN extension {} host function {}::{} panicked in drop; ignored",
                    self.failure.extension, self.failure.namespace, self.failure.name
                ),
            );
        }
    }
}

struct Fallback {
    failure: HostFunctionFailure,
    panic_answer: Option<PanicAnswer>,
    result_types: Option<Vec<Type>>,
    auto_answer: Option<Vec<Val>>,
    log: LogHandle,
}

impl Fallback {
    fn new(
        failure: &HostFunctionFailure,
        panic_answer: Option<PanicAnswer>,
        func: Option<&ComponentFunc>,
        log: &LogHandle,
    ) -> Self {
        let (result_types, auto_answer) = match func {
            Some(func) => {
                let result_types: Vec<Type> = func.results().collect();
                let auto_answer = auto_answer_for(failure, &result_types);
                (Some(result_types), auto_answer)
            }
            None => (None, None),
        };
        Self {
            failure: failure.clone(),
            panic_answer,
            result_types,
            auto_answer,
            log: log.clone(),
        }
    }

    fn on_panic(&self, results_len: usize) -> Result<Vec<Val>, HostCallError> {
        if let Some(answer) = &self.panic_answer {
            match std::panic::catch_unwind(AssertUnwindSafe(|| answer.call(&self.failure))) {
                Ok(vals) => {
                    let why = if vals.len() != results_len {
                        Some("wrong arity")
                    } else if self.result_types.as_ref().is_some_and(|types| {
                        vals.iter().zip(types).any(|(v, t)| !val_conforms(v, t))
                    }) {
                        Some("wrong type")
                    } else {
                        None
                    };
                    if let Some(why) = why {
                        self.log.err(
                            log_keys::EXT_HOST_FUNCTION_ANSWER_INVALID,
                            format!(
                                "advance: WARN extension {} host function {}::{}: panic answer unusable ({why})",
                                self.failure.extension,
                                self.failure.namespace,
                                self.failure.name
                            ),
                        );
                    } else {
                        self.log_panicked("answered in band");
                        return Ok(vals);
                    }
                }
                Err(_) => {
                    self.log.err(
                        log_keys::EXT_HOST_FUNCTION_ANSWER_INVALID,
                        format!(
                            "advance: WARN extension {} host function {}::{}: panic answer unusable (the answer panicked)",
                            self.failure.extension,
                            self.failure.namespace,
                            self.failure.name
                        ),
                    );
                }
            }
        }
        if let Some(auto) = &self.auto_answer {
            self.log_panicked("answered in band");
            return Ok(auto.clone());
        }
        self.log_panicked("the call traps");
        Err(HostCallError::HandlerError(self.failure.to_string()))
    }

    fn log_panicked(&self, how: &str) {
        self.log.err(
            log_keys::EXT_HOST_FUNCTION_PANICKED,
            format!(
                "advance: WARN extension {} host function {}::{} panicked; {how}",
                self.failure.extension, self.failure.namespace, self.failure.name
            ),
        );
    }
}

fn auto_answer_for(failure: &HostFunctionFailure, result_types: &[Type]) -> Option<Vec<Val>> {
    if result_types.len() != 1 {
        return None;
    }
    let Type::Result(r) = &result_types[0] else {
        return None;
    };
    if r.err() != Some(Type::String) {
        return None;
    }
    Some(vec![Val::Result(Err(Some(Box::new(Val::String(
        failure.to_string(),
    )))))])
}

fn ready_err(message: String) -> BoxedHostFuture {
    Box::pin(std::future::ready(Err(HostCallError::HandlerError(
        message,
    ))))
}

fn unsupported_text(what: &str, failure: &HostFunctionFailure) -> String {
    format!(
        "unsupported-signature: {what} is not supported on the extension host-function path ({failure})"
    )
}

pub(crate) fn unsupported_signature(func: &ComponentFunc) -> Option<&'static str> {
    for (_, ty) in func.params() {
        if let Some(what) = unsupported(&ty, false) {
            return Some(what);
        }
    }
    for ty in func.results() {
        if let Some(what) = unsupported(&ty, false) {
            return Some(what);
        }
    }
    None
}

fn unsupported(ty: &Type, in_list: bool) -> Option<&'static str> {
    match ty {
        Type::Own(_) | Type::Borrow(_) => Some("a resource"),
        Type::Future(_) | Type::Stream(_) | Type::ErrorContext => Some("an async value"),
        Type::Variant(_) if in_list => Some("list<variant>"),
        Type::Variant(v) => v
            .cases()
            .find_map(|c| c.ty.as_ref().and_then(|t| unsupported(t, in_list))),
        Type::List(l) => unsupported(&l.ty(), true),
        Type::Record(r) => r.fields().find_map(|f| unsupported(&f.ty, in_list)),
        Type::Tuple(t) => t.types().find_map(|t| unsupported(&t, in_list)),
        Type::Option(o) => unsupported(&o.ty(), in_list),
        Type::Result(r) => r
            .ok()
            .and_then(|t| unsupported(&t, in_list))
            .or_else(|| r.err().and_then(|t| unsupported(&t, in_list))),
        _ => None,
    }
}

/// Deep check that `v` lowers as `t` (so a PanicAnswer can never cause a lowering trap).
pub(crate) fn val_conforms(v: &Val, t: &Type) -> bool {
    match (v, t) {
        (Val::Bool(_), Type::Bool)
        | (Val::S8(_), Type::S8)
        | (Val::U8(_), Type::U8)
        | (Val::S16(_), Type::S16)
        | (Val::U16(_), Type::U16)
        | (Val::S32(_), Type::S32)
        | (Val::U32(_), Type::U32)
        | (Val::S64(_), Type::S64)
        | (Val::U64(_), Type::U64)
        | (Val::Float32(_), Type::Float32)
        | (Val::Float64(_), Type::Float64)
        | (Val::Char(_), Type::Char)
        | (Val::String(_), Type::String) => true,
        (Val::List(vals), Type::List(list)) => {
            let elem = list.ty();
            vals.iter().all(|v| val_conforms(v, &elem))
        }
        (Val::Record(fields), Type::Record(record)) => {
            let declared: Vec<_> = record.fields().collect();
            if fields.len() != declared.len() {
                return false;
            }
            fields
                .iter()
                .zip(declared.iter())
                .all(|((name, val), field)| name == field.name && val_conforms(val, &field.ty))
        }
        (Val::Tuple(vals), Type::Tuple(tuple)) => {
            let types: Vec<_> = tuple.types().collect();
            vals.len() == types.len()
                && vals
                    .iter()
                    .zip(types.iter())
                    .all(|(v, t)| val_conforms(v, t))
        }
        (Val::Variant(name, payload), Type::Variant(variant)) => {
            let Some(case) = variant.cases().find(|c| c.name == name) else {
                return false;
            };
            match (payload, case.ty) {
                (None, None) => true,
                (Some(v), Some(ty)) => val_conforms(v, &ty),
                _ => false,
            }
        }
        (Val::Enum(name), Type::Enum(en)) => en.names().any(|n| n == name),
        (Val::Option(None), Type::Option(_)) => true,
        (Val::Option(Some(v)), Type::Option(opt)) => val_conforms(v, &opt.ty()),
        (Val::Result(Ok(payload)), Type::Result(r)) => match (payload, r.ok()) {
            (None, None) => true,
            (Some(v), Some(ty)) => val_conforms(v, &ty),
            _ => false,
        },
        (Val::Result(Err(payload)), Type::Result(r)) => match (payload, r.err()) {
            (None, None) => true,
            (Some(v), Some(ty)) => val_conforms(v, &ty),
            _ => false,
        },
        (Val::Flags(names), Type::Flags(flags)) => {
            let allowed: Vec<_> = flags.names().collect();
            names.iter().all(|n| allowed.iter().any(|a| *a == n))
        }
        (
            _,
            Type::Own(_) | Type::Borrow(_) | Type::Future(_) | Type::Stream(_) | Type::ErrorContext,
        ) => false,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        ComposeCx, ComposeError, ComposeExtension, ComposeProfile, ExtensionError,
        ExtensionFailure, ExtensionPhase, HostFunctionDef, ProcessPolicy,
    };
    use crate::extension::set::{CxParts, ExtensionPlan, ExtensionSet};
    use crate::test_support::MemoryComposeLog;
    use advance_runtime::host_registry::{
        InMemoryHostRegistry, MAX_SPECS_PER_CAPABILITY, MAX_SPEC_STRING_LEN,
    };
    use advance_shared_types::event::Event;
    use advance_shared_types::traits::{EventBusEmit, GrantCheck};
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, Weak};
    use wasmtime::component::types::ComponentItem;

    struct Nop;

    impl HostFunctionHandler for Nop {
        fn call(
            &self,
            _ctx: HostCallContext,
            _params: Vec<Val>,
            _results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn nop() -> Arc<dyn HostFunctionHandler> {
        Arc::new(Nop)
    }

    fn registrar(declared: &'static [&'static str]) -> HostFunctionRegistrar {
        HostFunctionRegistrar::new(
            "fixture",
            declared,
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(BTreeMap::new())),
        )
    }

    fn def(capability: &str, namespace: &str, name: &str) -> HostFunctionDef {
        HostFunctionDef::new(capability, namespace, name, nop())
    }

    fn valid(name: &str) -> HostFunctionDef {
        def("fixture.probe", "fixture:probe/host@0.1.0", name)
    }

    fn plan() -> ExtensionPlan {
        ExtensionPlan {
            home: Arc::from(Path::new("/tmp")),
            profile: ComposeProfile::Daemon,
            processes: ProcessPolicy::Allow,
        }
    }

    fn dummy_parts() -> CxParts {
        struct NopEmit;
        impl EventBusEmit for NopEmit {
            fn emit(&self, _: Event) {}
        }
        struct NopGrant;
        impl GrantCheck for NopGrant {
            fn check(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &advance_shared_types::capability::CapParams,
            ) -> crate::api::GrantDecision {
                crate::api::GrantDecision::Deny("none".into())
            }
        }
        fn dangling<T: ?Sized>(strong: Arc<T>) -> Weak<T> {
            Arc::downgrade(&strong)
        }
        CxParts {
            config: Weak::new(),
            event_bus: dangling(Arc::new(NopEmit) as Arc<dyn EventBusEmit>),
            run_manager: Weak::new(),
            grant_check: dangling(Arc::new(NopGrant) as Arc<dyn GrantCheck>),
            secret_store: None,
            leak_detector: Arc::new(cap_http::DefaultLeakDetector::new()),
        }
    }

    struct Script {
        id: &'static str,
        caps: &'static [&'static str],
        act: Box<
            dyn Fn(&ComposeCx, &mut HostFunctionRegistrar) -> Result<(), ExtensionError>
                + Send
                + Sync,
        >,
    }

    impl ComposeExtension for Script {
        fn id(&self) -> &'static str {
            self.id
        }

        fn capabilities(&self) -> &'static [&'static str] {
            self.caps
        }

        fn host_functions(
            &self,
            cx: &ComposeCx,
            reg: &mut HostFunctionRegistrar,
        ) -> Result<(), ExtensionError> {
            (self.act)(cx, reg)
        }
    }

    fn script(
        id: &'static str,
        caps: &'static [&'static str],
        act: impl Fn(&ComposeCx, &mut HostFunctionRegistrar) -> Result<(), ExtensionError>
            + Send
            + Sync
            + 'static,
    ) -> Arc<dyn ComposeExtension> {
        Arc::new(Script {
            id,
            caps,
            act: Box::new(act),
        })
    }

    fn prepare_set(exts: Vec<Arc<dyn ComposeExtension>>) -> Arc<ExtensionSet> {
        let set = ExtensionSet::prepare(exts, plan(), LogHandle::null()).expect("prepare");
        set.install_contexts(dummy_parts());
        set
    }

    fn run_set(set: &ExtensionSet) -> (Result<usize, ComposeError>, InMemoryHostRegistry) {
        let registry = InMemoryHostRegistry::new();
        let result = run_host_functions(set, &registry, &LogHandle::null());
        (result, registry)
    }

    fn failure() -> HostFunctionFailure {
        HostFunctionFailure {
            extension: "fixture",
            namespace: "fixture:probe/host".into(),
            name: "call".into(),
        }
    }

    fn ctx() -> HostCallContext {
        HostCallContext {
            agent_id: "root".into(),
            trace_id: String::new(),
            turn_id: None,
            capability: "fixture.probe".into(),
            function: "fixture:probe/host::call".into(),
            run_id: None,
            iteration: None,
        }
    }

    fn wrap(
        inner: Arc<dyn HostFunctionHandler>,
        panic_answer: Option<PanicAnswer>,
    ) -> (ContainedHostFunction, MemoryComposeLog) {
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink.clone()));
        (
            ContainedHostFunction {
                failure: failure(),
                inner: Some(inner),
                panic_answer,
                log,
            },
            sink,
        )
    }

    fn load_funcs(wat: &str) -> Vec<(String, ComponentFunc)> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        let engine = wasmtime::Engine::new(&config).expect("engine");
        let bytes = wat::parse_str(wat).unwrap_or_else(|e| panic!("wat: {e:?}\n{wat}"));
        let component = wasmtime::component::Component::new(&engine, &bytes)
            .unwrap_or_else(|e| panic!("component: {e:?}\n{wat}"));
        let mut funcs = Vec::new();
        for (name, item) in component.component_type().imports(&engine) {
            match item {
                ComponentItem::ComponentFunc(func) => funcs.push((name.to_owned(), func)),
                ComponentItem::ComponentInstance(instance) => {
                    for (export_name, export) in instance.exports(&engine) {
                        if let ComponentItem::ComponentFunc(func) = export {
                            funcs.push((export_name.to_owned(), func));
                        }
                    }
                }
                _ => {}
            }
        }
        funcs
    }

    fn named<'a>(funcs: &'a [(String, ComponentFunc)], name: &str) -> &'a ComponentFunc {
        match funcs.iter().find(|(n, _)| n == name) {
            Some((_, func)) => func,
            None => {
                let have: Vec<_> = funcs.iter().map(|(n, _)| n.as_str()).collect();
                panic!("missing func {name}, have {have:?}");
            }
        }
    }

    fn param0(func: &ComponentFunc) -> Type {
        func.params().next().expect("param").1
    }

    fn identity_now() -> Option<(String, String, String)> {
        crate::extension::call::current().map(|id| {
            (
                id.extension().to_owned(),
                id.agent_id().to_owned(),
                id.function().to_owned(),
            )
        })
    }

    #[test]
    fn module_001_ac31_registrar_refusals_recorded() {
        const CAPS: &[&str] = &["fixture.probe"];

        // 1. ReservedNamespace — raw prefix, before grammar.
        let mut reg = registrar(CAPS);
        let reserved = def("fixture.probe", "advance:runtime/host", "call");
        let err = reg.register(reserved).expect_err("reserved");
        assert_eq!(
            err,
            HostFunctionRefusal::ReservedNamespace {
                namespace: "advance:runtime/host".into(),
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        let mut ignored = registrar(CAPS);
        let _ = ignored.register(def("fixture.probe", "wasi:cli/run", "call"));
        assert_eq!(
            ignored.first_refusal(),
            Some(&HostFunctionRefusal::ReservedNamespace {
                namespace: "wasi:cli/run".into(),
            })
        );
        assert_eq!(
            ignored.first_refusal().unwrap().to_string(),
            "namespace \"wasi:cli/run\" is reserved (advance:* and wasi:* belong to OSS)"
        );
        // Prefix wins over grammar: `advance:` with a malformed rest is still reserved.
        let mut prefix = registrar(CAPS);
        let _ = prefix.register(def("fixture.probe", "advance:NOT VALID", "call"));
        assert!(matches!(
            prefix.first_refusal(),
            Some(HostFunctionRefusal::ReservedNamespace { .. })
        ));

        // 2. Malformed namespace.
        let mut reg = registrar(CAPS);
        let too_long = "x".repeat(MAX_SPEC_STRING_LEN + 1);
        let err = reg
            .register(def("fixture.probe", &too_long, "call"))
            .expect_err("long ns");
        assert_eq!(
            err,
            HostFunctionRefusal::Malformed {
                namespace: too_long.clone(),
                name: "call".into(),
                reason: "longer than 256 bytes",
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        let ns256 = format!("a:b/{}", "c".repeat(MAX_SPEC_STRING_LEN - 4));
        assert_eq!(ns256.len(), MAX_SPEC_STRING_LEN);
        registrar(CAPS)
            .register(def("fixture.probe", &ns256, "call"))
            .expect("256-byte namespace");
        for (namespace, reason) in [
            ("not-a-namespace", "not <ns>:<pkg>/<iface>[@<semver>]"),
            ("a:b/c/d", "not <ns>:<pkg>/<iface>[@<semver>]"),
            ("a:b:c/d", "not <ns>:<pkg>/<iface>[@<semver>]"),
            ("a:b/c@not-a-version", "not <ns>:<pkg>/<iface>[@<semver>]"),
            ("a:b/c@1.0", "not <ns>:<pkg>/<iface>[@<semver>]"),
            ("A:b/c", "not <ns>:<pkg>/<iface>[@<semver>]"),
        ] {
            let mut reg = registrar(CAPS);
            let _ = reg.register(def("fixture.probe", namespace, "call"));
            assert_eq!(
                reg.first_refusal(),
                Some(&HostFunctionRefusal::Malformed {
                    namespace: namespace.into(),
                    name: "call".into(),
                    reason,
                }),
                "{namespace}"
            );
            assert_eq!(
                reg.first_refusal().unwrap().to_string(),
                format!("{namespace}::call: {reason}")
            );
        }

        // 3. Malformed name.
        let mut reg = registrar(CAPS);
        let long_name = "x".repeat(MAX_SPEC_STRING_LEN + 1);
        let err = reg
            .register(def("fixture.probe", "fixture:probe/host@0.1.0", &long_name))
            .expect_err("long name");
        assert_eq!(
            err,
            HostFunctionRefusal::Malformed {
                namespace: "fixture:probe/host@0.1.0".into(),
                name: long_name,
                reason: "longer than 256 bytes",
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        let name256 = "a".repeat(MAX_SPEC_STRING_LEN);
        registrar(CAPS)
            .register(def("fixture.probe", "fixture:probe/host@0.1.0", &name256))
            .expect("256-byte name");
        for name in ["Call", "", "_x", "1call", "call_name"] {
            let mut reg = registrar(CAPS);
            let _ = reg.register(def("fixture.probe", "fixture:probe/host@0.1.0", name));
            assert_eq!(
                reg.first_refusal(),
                Some(&HostFunctionRefusal::Malformed {
                    namespace: "fixture:probe/host@0.1.0".into(),
                    name: name.into(),
                    reason: "not a WIT label",
                }),
                "{name:?}"
            );
        }

        // 4. UndeclaredCapability — including an OSS name.
        let mut reg = registrar(CAPS);
        let err = reg
            .register(def("fs", "fixture:probe/host@0.1.0", "call"))
            .expect_err("undeclared");
        assert_eq!(
            err,
            HostFunctionRefusal::UndeclaredCapability {
                capability: "fs".into(),
                namespace: "fixture:probe/host@0.1.0".into(),
                name: "call".into(),
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        let mut ignored = registrar(CAPS);
        let _ = ignored.register(def("other.x", "fixture:probe/host@0.1.0", "call"));
        assert_eq!(
            ignored.first_refusal().unwrap().to_string(),
            "fixture:probe/host@0.1.0::call is registered under \"other.x\", which this extension does not declare"
        );
        // Undeclared before Duplicate: same pair, wrong capability.
        let mut reg = registrar(CAPS);
        reg.register(valid("call")).expect("first");
        let _ = reg.register(def("fs", "fixture:probe/host@0.1.0", "call"));
        assert!(matches!(
            reg.first_refusal(),
            Some(HostFunctionRefusal::UndeclaredCapability { .. })
        ));

        // 5. Duplicate, including across registrars sharing `taken`.
        let mut reg = registrar(CAPS);
        reg.register(valid("call")).expect("first");
        let err = reg.register(valid("call")).expect_err("dup");
        assert_eq!(
            err,
            HostFunctionRefusal::Duplicate {
                namespace: "fixture:probe/host@0.1.0".into(),
                name: "call".into(),
                owner: "fixture",
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        assert_eq!(
            err.to_string(),
            "fixture:probe/host@0.1.0::call is already registered by extension fixture"
        );
        let taken = Arc::new(Mutex::new(BTreeMap::new()));
        let counts = Arc::new(Mutex::new(BTreeMap::new()));
        let mut first =
            HostFunctionRegistrar::new("fixture", CAPS, Arc::clone(&taken), Arc::clone(&counts));
        let mut second = HostFunctionRegistrar::new(
            "other",
            &["other.x"],
            Arc::clone(&taken),
            Arc::clone(&counts),
        );
        first.register(valid("call")).expect("owner");
        let _ = second.register(def("other.x", "fixture:probe/host@0.1.0", "call"));
        assert_eq!(
            second.first_refusal(),
            Some(&HostFunctionRefusal::Duplicate {
                namespace: "fixture:probe/host@0.1.0".into(),
                name: "call".into(),
                owner: "fixture",
            })
        );

        // 6. TooMany — increment only on success; shared per-capability count.
        let mut reg = registrar(CAPS);
        for i in 0..MAX_SPECS_PER_CAPABILITY {
            reg.register(valid(&format!("f{i}")))
                .unwrap_or_else(|_| panic!("function {i} under the cap"));
        }
        assert!(reg.first_refusal().is_none());
        let err = reg
            .register(valid(&format!("f{MAX_SPECS_PER_CAPABILITY}")))
            .expect_err("257th");
        assert_eq!(
            err,
            HostFunctionRefusal::TooMany {
                capability: "fixture.probe".into(),
                limit: MAX_SPECS_PER_CAPABILITY,
            }
        );
        assert_eq!(reg.first_refusal(), Some(&err));
        assert_eq!(
            err.to_string(),
            format!("more than {MAX_SPECS_PER_CAPABILITY} host functions under \"fixture.probe\"")
        );
        let taken = Arc::new(Mutex::new(BTreeMap::new()));
        let counts = Arc::new(Mutex::new(BTreeMap::new()));
        let mut a =
            HostFunctionRegistrar::new("fixture", CAPS, Arc::clone(&taken), Arc::clone(&counts));
        let mut b =
            HostFunctionRegistrar::new("other", CAPS, Arc::clone(&taken), Arc::clone(&counts));
        for i in 0..MAX_SPECS_PER_CAPABILITY {
            a.register(valid(&format!("f{i}"))).expect("fill");
        }
        let _ = b.register(valid("overflow"));
        assert!(matches!(
            b.first_refusal(),
            Some(HostFunctionRefusal::TooMany { .. })
        ));
    }

    #[tokio::test]
    async fn module_001_ac31_run_host_functions_precedence_and_replay() {
        let empty = ExtensionSet::empty();
        let (result, registry) = run_set(&empty);
        assert_eq!(result.expect("empty"), 0);
        assert_eq!(registry.capability_count(), 0);

        let identity = prepare_set(vec![script("fixture", &[], |_, _| Ok(()))]);
        let (result, registry) = run_set(&identity);
        assert_eq!(result.expect("identity"), 0);
        assert_eq!(registry.capability_count(), 0);

        // panic > refusal: a recorded refusal is discarded when the callback panics.
        let set = prepare_set(vec![script("fixture", &["fixture.probe"], |_, reg| {
            let _ = reg.register(def("fixture.probe", "advance:runtime/host", "call"));
            panic!("host_functions panics");
        })]);
        match run_set(&set).0 {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::HostFunctions,
                failure: ExtensionFailure::Panicked(ref message),
            }) if message.contains("host_functions panics") => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        // refusal > Err: ignored Err from register, then an extension Err.
        let set = prepare_set(vec![script("fixture", &["fixture.probe"], |_, reg| {
            let _ = reg.register(def("fixture.probe", "advance:runtime/host", "call"));
            Err(ExtensionError::new("boom\nline"))
        })]);
        match run_set(&set).0 {
            Err(ComposeError::HostFunction {
                extension: "fixture",
                refusal: HostFunctionRefusal::ReservedNamespace { ref namespace },
            }) if namespace == "advance:runtime/host" => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        // Err (sanitized) > no-function.
        let set = prepare_set(vec![script("fixture", &["fixture.probe"], |_, _| {
            Err(ExtensionError::new("boom\nline"))
        })]);
        match run_set(&set).0 {
            Err(ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::HostFunctions,
                failure: ExtensionFailure::Failed(ref message),
            }) if message == "boom line" => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        // no-function, declaration order.
        let set = prepare_set(vec![script(
            "fixture",
            &["fixture.probe", "fixture.other"],
            |_, reg| {
                reg.register(valid("call")).map_err(ExtensionError::from)?;
                Ok(())
            },
        )]);
        match run_set(&set).0 {
            Err(ComposeError::HostFunction {
                extension: "fixture",
                refusal: HostFunctionRefusal::CapabilityWithoutFunction { ref capability },
            }) if capability == "fixture.other" => {}
            Ok(_) => panic!("unexpected Ok"),
            Err(other) => panic!("{other:?}"),
        }

        // Replay only after every extension: a failing second leaves no first spec.
        let first_ok = || {
            script("fixture", &["fixture.probe"], |_, reg| {
                reg.register(valid("call")).map_err(ExtensionError::from)
            })
        };
        for second in [
            script("other", &["other.x"], |_, _| panic!("second panics")),
            script("other", &["other.x"], |_, reg| {
                let _ = reg.register(def("other.x", "advance:runtime/host", "call"));
                Ok(())
            }),
            script("other", &["other.x"], |_, _| {
                Err(ExtensionError::new("second failed"))
            }),
            script("other", &["other.x"], |_, _| Ok(())),
        ] {
            let set = prepare_set(vec![first_ok(), second]);
            let (result, registry) = run_set(&set);
            assert!(result.is_err(), "{result:?}");
            assert!(
                registry.lookup("fixture.probe").is_empty(),
                "failing second must not replay the first"
            );
            assert_eq!(registry.capability_count(), 0);
        }

        let set = prepare_set(vec![
            script("fixture", &["fixture.probe"], |_, reg| {
                reg.register(valid("call")).map_err(ExtensionError::from)
            }),
            script("other", &["other.x"], |_, reg| {
                reg.register(def("other.x", "other:x/host@0.1.0", "call"))
                    .map_err(ExtensionError::from)
            }),
        ]);
        let (result, registry) = run_set(&set);
        assert_eq!(result.expect("replay"), 2);
        assert_eq!(registry.lookup("fixture.probe").len(), 1);
        assert_eq!(registry.lookup("other.x").len(), 1);
        assert_eq!(
            registry.lookup("fixture.probe")[0].namespace,
            "fixture:probe/host@0.1.0"
        );
        assert_eq!(registry.lookup("other.x")[0].name, "call");
    }

    const WALKER_WAT: &str = r#"
(component
  (type $host (instance
    (type $var-x0 (variant (case "x" u32)))
    (export "var-x" (type $var-x (eq $var-x0)))
    (type $list-var0 (list $var-x))
    (export "list-var-ty" (type $list-var (eq $list-var0)))
    (export "list-var" (func (param "a" $list-var)))
    (type $rec0 (record (field "f" $var-x)))
    (export "rec" (type $rec (eq $rec0)))
    (type $list-rec0 (list $rec))
    (export "list-rec-ty" (type $list-rec (eq $list-rec0)))
    (export "list-rec-var" (func (param "a" $list-rec)))
    (type $opt0 (option u32))
    (export "opt" (type $opt (eq $opt0)))
    (type $list-opt0 (list $opt))
    (export "list-opt-ty" (type $list-opt (eq $list-opt0)))
    (export "list-opt" (func (param "a" $list-opt)))
    (export "string" (func (param "a" string)))
    (export "variant" (func (param "a" $var-x)))
    (export "r" (type $r (sub resource)))
    (export "own-r" (func (param "a" (own $r))))
    (export "borrow-r" (func (param "a" (borrow $r))))
  ))
  (import "test:sig/host" (instance (type $host)))
)
"#;

    #[test]
    fn module_001_ac31_unsupported_signature_walker() {
        let funcs = load_funcs(WALKER_WAT);
        assert_eq!(
            unsupported_signature(named(&funcs, "list-var")),
            Some("list<variant>")
        );
        assert_eq!(
            unsupported_signature(named(&funcs, "list-rec-var")),
            Some("list<variant>")
        );
        assert_eq!(
            unsupported_signature(named(&funcs, "own-r")),
            Some("a resource")
        );
        assert_eq!(
            unsupported_signature(named(&funcs, "borrow-r")),
            Some("a resource")
        );
        assert_eq!(unsupported_signature(named(&funcs, "list-opt")), None);
        assert_eq!(unsupported_signature(named(&funcs, "string")), None);
        assert_eq!(unsupported_signature(named(&funcs, "variant")), None);
    }

    #[derive(Default)]
    struct Counting {
        typed: AtomicUsize,
        call: AtomicUsize,
    }

    impl HostFunctionHandler for Counting {
        fn call(
            &self,
            _ctx: HostCallContext,
            _params: Vec<Val>,
            _results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            self.call.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(Vec::new()) })
        }

        fn call_typed(
            &self,
            _func: &ComponentFunc,
            ctx: HostCallContext,
            params: Vec<Val>,
            results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            self.typed.fetch_add(1, Ordering::SeqCst);
            self.call(ctx, params, results_len)
        }
    }

    #[tokio::test]
    async fn module_001_ac31_contained_call_typed_refuses_unsupported_signature_before_extension_code(
    ) {
        let funcs = load_funcs(WALKER_WAT);
        let inner = Arc::new(Counting::default());
        let (contained, sink) = wrap(Arc::clone(&inner) as Arc<dyn HostFunctionHandler>, None);
        let err = contained
            .call_typed(named(&funcs, "list-var"), ctx(), Vec::new(), 0)
            .await
            .expect_err("unsupported");
        match err {
            HostCallError::HandlerError(message) => {
                assert!(
                    message.starts_with(
                        "unsupported-signature: list<variant> is not supported on the extension host-function path ("
                    ),
                    "{message}"
                );
                assert!(message.contains(&failure().to_string()), "{message}");
            }
            other => panic!("{other}"),
        }
        assert_eq!(inner.typed.load(Ordering::SeqCst), 0);
        assert_eq!(inner.call.load(Ordering::SeqCst), 0);
        assert!(sink.lines().is_empty());
    }

    struct PanicOnBuild;
    impl HostFunctionHandler for PanicOnBuild {
        fn call(
            &self,
            _ctx: HostCallContext,
            _params: Vec<Val>,
            _results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            panic!("sync-payload");
        }
    }

    struct PanicOnPoll;
    impl HostFunctionHandler for PanicOnPoll {
        fn call(
            &self,
            _ctx: HostCallContext,
            _params: Vec<Val>,
            _results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            Box::pin(async { panic!("async-payload") })
        }
    }

    struct Sequence {
        n: AtomicUsize,
        ok: Vec<Val>,
        err: String,
        sync: Mutex<Option<(String, String, String)>>,
        polled: Arc<Mutex<Option<(String, String, String)>>>,
    }

    impl HostFunctionHandler for Sequence {
        fn call(
            &self,
            _ctx: HostCallContext,
            _params: Vec<Val>,
            _results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            *self.sync.lock().expect("sync") = identity_now();
            let n = self.n.fetch_add(1, Ordering::SeqCst);
            let polled = Arc::clone(&self.polled);
            let ok = self.ok.clone();
            let err = self.err.clone();
            Box::pin(async move {
                *polled.lock().expect("polled") = identity_now();
                if n == 0 {
                    Err(HostCallError::HandlerError(err))
                } else {
                    Ok(ok)
                }
            })
        }

        fn call_typed(
            &self,
            _func: &ComponentFunc,
            ctx: HostCallContext,
            params: Vec<Val>,
            results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            self.call(ctx, params, results_len)
        }
    }

    struct DropPanic;
    impl HostFunctionHandler for DropPanic {
        fn call(
            &self,
            _ctx: HostCallContext,
            _params: Vec<Val>,
            _results_len: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }
    }
    impl Drop for DropPanic {
        fn drop(&mut self) {
            panic!("drop-payload");
        }
    }

    const PANIC_WAT: &str = r#"
(component
  (type $host (instance
    (type $ok-err0 (result string (error string)))
    (export "ok-err" (type $ok-err (eq $ok-err0)))
    (export "auto" (func (result $ok-err)))
    (type $failed0 (variant (case "failed")))
    (export "failed" (type $failed (eq $failed0)))
    (type $var-err0 (result u32 (error $failed)))
    (export "var-err" (type $var-err (eq $var-err0)))
    (export "variant-err" (func (result $var-err)))
    (export "plain-u32" (func (result u32)))
  ))
  (import "test:panic/host" (instance (type $host)))
)
"#;

    fn auto_answer_value() -> Vec<Val> {
        vec![Val::Result(Err(Some(Box::new(Val::String(
            failure().to_string(),
        )))))]
    }

    fn texts(sink: &MemoryComposeLog) -> Vec<(String, String)> {
        sink.lines()
            .into_iter()
            .map(|line| (line.key.to_owned(), line.text))
            .collect()
    }

    fn assert_no_payload(sink: &MemoryComposeLog) {
        for line in sink.lines() {
            for payload in [
                "sync-payload",
                "async-payload",
                "answer-payload",
                "drop-payload",
            ] {
                assert!(
                    !line.text.contains(payload),
                    "log leaked panic payload {payload:?}: {}",
                    line.text
                );
            }
        }
    }

    #[tokio::test]
    async fn module_001_ac31_contained_panic_answers() {
        let funcs = load_funcs(PANIC_WAT);
        let auto = named(&funcs, "auto");
        let variant_err = named(&funcs, "variant-err");
        let plain = named(&funcs, "plain-u32");
        let expected_id = (
            "fixture".to_owned(),
            "root".to_owned(),
            "fixture:probe/host::call".to_owned(),
        );

        for (label, inner) in [
            (
                "sync",
                Arc::new(PanicOnBuild) as Arc<dyn HostFunctionHandler>,
            ),
            (
                "async",
                Arc::new(PanicOnPoll) as Arc<dyn HostFunctionHandler>,
            ),
        ] {
            let (contained, sink) = wrap(inner, None);
            let got = contained
                .call_typed(auto, ctx(), Vec::new(), 1)
                .await
                .expect(label);
            assert_eq!(got, auto_answer_value(), "{label}");
            assert_eq!(
                texts(&sink),
                vec![(
                    log_keys::EXT_HOST_FUNCTION_PANICKED.to_owned(),
                    format!(
                        "advance: WARN extension fixture host function fixture:probe/host::call panicked; answered in band"
                    ),
                )]
            );
            assert_no_payload(&sink);
        }

        let custom = vec![Val::Result(Ok(Some(Box::new(Val::String(
            "custom".into(),
        )))))];
        let answer = {
            let custom = custom.clone();
            PanicAnswer::new(move |_| custom.clone())
        };
        let (contained, sink) = wrap(Arc::new(PanicOnBuild), Some(answer));
        let got = contained
            .call_typed(auto, ctx(), Vec::new(), 1)
            .await
            .expect("panic answer wins");
        assert_eq!(got, custom);
        assert_eq!(sink.count(log_keys::EXT_HOST_FUNCTION_PANICKED), 1);
        assert_eq!(sink.count(log_keys::EXT_HOST_FUNCTION_ANSWER_INVALID), 0);
        assert!(texts(&sink)[0].1.contains("answered in band"));

        for (why, answer) in [
            ("wrong arity", PanicAnswer::new(|_| Vec::new())),
            ("wrong type", PanicAnswer::new(|_| vec![Val::U32(0)])),
            (
                "the answer panicked",
                PanicAnswer::new(|_| panic!("answer-payload")),
            ),
        ] {
            let (contained, sink) = wrap(Arc::new(PanicOnPoll), Some(answer));
            let got = contained
                .call_typed(auto, ctx(), Vec::new(), 1)
                .await
                .expect(why);
            assert_eq!(got, auto_answer_value(), "{why}");
            let lines = texts(&sink);
            assert_eq!(lines.len(), 2, "{why}: {lines:?}");
            assert_eq!(lines[0].0, log_keys::EXT_HOST_FUNCTION_ANSWER_INVALID);
            assert!(
                lines[0]
                    .1
                    .contains(&format!("panic answer unusable ({why})")),
                "{why}: {}",
                lines[0].1
            );
            assert_eq!(lines[1].0, log_keys::EXT_HOST_FUNCTION_PANICKED);
            assert!(lines[1].1.contains("answered in band"), "{why}");
            assert_no_payload(&sink);
        }

        let (contained, sink) = wrap(
            Arc::new(PanicOnBuild),
            Some(PanicAnswer::new(|_| Vec::new())),
        );
        match contained.call_typed(plain, ctx(), Vec::new(), 1).await {
            Err(HostCallError::HandlerError(message)) if message == failure().to_string() => {}
            other => panic!("{other:?}"),
        }
        let lines = texts(&sink);
        assert_eq!(lines[0].0, log_keys::EXT_HOST_FUNCTION_ANSWER_INVALID);
        assert!(lines[0].1.contains("wrong arity"));
        assert_eq!(lines[1].0, log_keys::EXT_HOST_FUNCTION_PANICKED);
        assert!(lines[1].1.contains("the call traps"));

        let (contained, sink) = wrap(Arc::new(PanicOnPoll), None);
        match contained
            .call_typed(variant_err, ctx(), Vec::new(), 1)
            .await
        {
            Err(HostCallError::HandlerError(message)) if message == failure().to_string() => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(
            texts(&sink),
            vec![(
                log_keys::EXT_HOST_FUNCTION_PANICKED.to_owned(),
                "advance: WARN extension fixture host function fixture:probe/host::call panicked; the call traps"
                    .into(),
            )]
        );

        let seq = Arc::new(Sequence {
            n: AtomicUsize::new(0),
            ok: vec![Val::U32(7)],
            err: "x".into(),
            sync: Mutex::new(None),
            polled: Arc::new(Mutex::new(None)),
        });
        let (contained, sink) = wrap(Arc::clone(&seq) as Arc<dyn HostFunctionHandler>, None);
        match contained.call_typed(plain, ctx(), Vec::new(), 1).await {
            Err(HostCallError::HandlerError(message)) if message == "x" => {}
            other => panic!("{other:?}"),
        }
        let got = contained
            .call_typed(plain, ctx(), Vec::new(), 1)
            .await
            .expect("next call");
        assert_eq!(got, vec![Val::U32(7)]);
        assert_eq!(seq.n.load(Ordering::SeqCst), 2);
        assert_eq!(seq.sync.lock().expect("sync").as_ref(), Some(&expected_id));
        assert_eq!(
            seq.polled.lock().expect("polled").as_ref(),
            Some(&expected_id)
        );
        assert!(sink.lines().is_empty());

        let sink = MemoryComposeLog::new();
        let contained = ContainedHostFunction {
            failure: failure(),
            inner: Some(Arc::new(DropPanic)),
            panic_answer: None,
            log: LogHandle::new(Arc::new(sink.clone())),
        };
        drop(contained);
        assert_eq!(
            texts(&sink),
            vec![(
                log_keys::EXT_HOST_FUNCTION_PANICKED.to_owned(),
                "advance: WARN extension fixture host function fixture:probe/host::call panicked in drop; ignored"
                    .into(),
            )]
        );
        assert_no_payload(&sink);
    }

    const VAL_WAT: &str = r#"
(component
  (type $host (instance
    (export "bool" (func (param "a" bool)))
    (export "s8" (func (param "a" s8)))
    (export "u8" (func (param "a" u8)))
    (export "s16" (func (param "a" s16)))
    (export "u16" (func (param "a" u16)))
    (export "s32" (func (param "a" s32)))
    (export "u32" (func (param "a" u32)))
    (export "s64" (func (param "a" s64)))
    (export "u64" (func (param "a" u64)))
    (export "f32" (func (param "a" f32)))
    (export "f64" (func (param "a" f64)))
    (export "char" (func (param "a" char)))
    (export "string" (func (param "a" string)))
    (type $list0 (list u32))
    (export "list-ty" (type $list (eq $list0)))
    (export "list" (func (param "a" $list)))
    (type $rec0 (record (field "f" u32) (field "g" string)))
    (export "rec" (type $rec (eq $rec0)))
    (export "record" (func (param "a" $rec)))
    (type $tup0 (tuple u32 string))
    (export "tup" (type $tup (eq $tup0)))
    (export "tuple" (func (param "a" $tup)))
    (type $var0 (variant (case "x" u32) (case "y")))
    (export "var" (type $var (eq $var0)))
    (export "variant" (func (param "a" $var)))
    (type $en0 (enum "red" "blue"))
    (export "en" (type $en (eq $en0)))
    (export "an-enum" (func (param "a" $en)))
    (type $opt0 (option u32))
    (export "opt" (type $opt (eq $opt0)))
    (export "option" (func (param "a" $opt)))
    (type $res0 (result u32 (error string)))
    (export "res" (type $res (eq $res0)))
    (export "a-result" (func (param "a" $res)))
    (type $empty0 (result))
    (export "empty" (type $empty (eq $empty0)))
    (export "empty-result" (func (param "a" $empty)))
    (type $fl0 (flags "read" "write"))
    (export "fl" (type $fl (eq $fl0)))
    (export "flags" (func (param "a" $fl)))
    (export "r" (type $r (sub resource)))
    (export "own-r" (func (param "a" (own $r))))
    (export "borrow-r" (func (param "a" (borrow $r))))
  ))
  (import "test:val/host" (instance (type $host)))
)
"#;

    #[test]
    fn module_001_ac31_val_conforms() {
        let funcs = load_funcs(VAL_WAT);
        let ty = |name: &str| param0(named(&funcs, name));

        let pairs: &[(&str, Val, bool)] = &[
            ("bool", Val::Bool(true), true),
            ("bool", Val::U32(1), false),
            ("s8", Val::S8(1), true),
            ("s8", Val::U8(1), false),
            ("u8", Val::U8(1), true),
            ("u8", Val::S8(1), false),
            ("s16", Val::S16(1), true),
            ("s16", Val::U16(1), false),
            ("u16", Val::U16(1), true),
            ("u16", Val::S16(1), false),
            ("s32", Val::S32(1), true),
            ("s32", Val::U32(1), false),
            ("u32", Val::U32(1), true),
            ("u32", Val::S32(1), false),
            ("s64", Val::S64(1), true),
            ("s64", Val::U64(1), false),
            ("u64", Val::U64(1), true),
            ("u64", Val::S64(1), false),
            ("f32", Val::Float32(1.0), true),
            ("f32", Val::Float64(1.0), false),
            ("f64", Val::Float64(1.0), true),
            ("f64", Val::Float32(1.0), false),
            ("char", Val::Char('a'), true),
            ("char", Val::String("a".into()), false),
            ("string", Val::String("a".into()), true),
            ("string", Val::Char('a'), false),
            ("list", Val::List(Vec::new()), true),
            ("list", Val::List(vec![Val::U32(1)]), true),
            ("list", Val::List(vec![Val::String("x".into())]), false),
            ("list", Val::U32(1), false),
            (
                "record",
                Val::Record(vec![
                    ("f".into(), Val::U32(1)),
                    ("g".into(), Val::String("x".into())),
                ]),
                true,
            ),
            (
                "record",
                Val::Record(vec![
                    ("g".into(), Val::String("x".into())),
                    ("f".into(), Val::U32(1)),
                ]),
                false,
            ),
            (
                "record",
                Val::Record(vec![("f".into(), Val::U32(1))]),
                false,
            ),
            (
                "tuple",
                Val::Tuple(vec![Val::U32(1), Val::String("x".into())]),
                true,
            ),
            ("tuple", Val::Tuple(vec![Val::U32(1)]), false),
            (
                "variant",
                Val::Variant("x".into(), Some(Box::new(Val::U32(1)))),
                true,
            ),
            ("variant", Val::Variant("y".into(), None), true),
            ("variant", Val::Variant("x".into(), None), false),
            (
                "variant",
                Val::Variant("y".into(), Some(Box::new(Val::U32(1)))),
                false,
            ),
            ("variant", Val::Variant("z".into(), None), false),
            (
                "variant",
                Val::Variant("x".into(), Some(Box::new(Val::String("n".into())))),
                false,
            ),
            ("an-enum", Val::Enum("red".into()), true),
            ("an-enum", Val::Enum("green".into()), false),
            ("an-enum", Val::String("red".into()), false),
            ("option", Val::Option(None), true),
            ("option", Val::Option(Some(Box::new(Val::U32(1)))), true),
            (
                "option",
                Val::Option(Some(Box::new(Val::String("x".into())))),
                false,
            ),
            (
                "a-result",
                Val::Result(Ok(Some(Box::new(Val::U32(1))))),
                true,
            ),
            (
                "a-result",
                Val::Result(Err(Some(Box::new(Val::String("e".into()))))),
                true,
            ),
            ("a-result", Val::Result(Ok(None)), false),
            ("empty-result", Val::Result(Ok(None)), true),
            ("empty-result", Val::Result(Err(None)), true),
            (
                "empty-result",
                Val::Result(Ok(Some(Box::new(Val::U32(1))))),
                false,
            ),
            ("flags", Val::Flags(Vec::new()), true),
            ("flags", Val::Flags(vec!["read".into()]), true),
            (
                "flags",
                Val::Flags(vec!["read".into(), "write".into()]),
                true,
            ),
            ("flags", Val::Flags(vec!["exec".into()]), false),
            ("own-r", Val::U32(1), false),
            ("own-r", Val::String("x".into()), false),
            ("borrow-r", Val::U32(1), false),
            ("borrow-r", Val::String("x".into()), false),
        ];
        for (name, val, ok) in pairs {
            assert_eq!(
                val_conforms(val, &ty(name)),
                *ok,
                "{name} {val:?} expected {ok}"
            );
        }
    }
}
