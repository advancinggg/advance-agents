//! `agent-callables` host functions under capability `llm`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::callable_registry::{CallableDefinition, CallableError, CallableOutcome};
use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use wasmtime::component::Val;

use super::dispatch::CallableDispatcher;

const CAPABILITY: &str = "llm";
const NAMESPACE: &str = "advance:runtime/agent-callables@0.1.0";

const MAX_CALL_ID: usize = 128;
const MAX_NAME: usize = 256;
const MAX_ARGUMENTS: usize = 1024 * 1024;

/// Register `list-callables` + `invoke-callable` on the host registry.
pub fn register_agent_callables(registry: &dyn HostRegistry, dispatcher: Arc<CallableDispatcher>) {
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.into(),
        namespace: NAMESPACE.into(),
        name: "list-callables".into(),
        handler: Arc::new(ListCallablesHandler {
            dispatcher: Arc::clone(&dispatcher),
        }),
        idempotent: true,
    });
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.into(),
        namespace: NAMESPACE.into(),
        name: "invoke-callable".into(),
        handler: Arc::new(InvokeCallableHandler { dispatcher }),
        idempotent: false,
    });
}

struct ListCallablesHandler {
    dispatcher: Arc<CallableDispatcher>,
}

impl HostFunctionHandler for ListCallablesHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        _params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let dispatcher = Arc::clone(&self.dispatcher);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for list-callables, got {results_len}"
                )));
            }
            match dispatcher.list(&ctx.agent_id) {
                Ok(defs) => Ok(vec![encode_list_ok(defs)]),
                Err(err) => Ok(vec![encode_callable_error(&err)]),
            }
        })
    }
}

struct InvokeCallableHandler {
    dispatcher: Arc<CallableDispatcher>,
}

impl HostFunctionHandler for InvokeCallableHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let dispatcher = Arc::clone(&self.dispatcher);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for invoke-callable, got {results_len}"
                )));
            }
            let (call_id, name, arguments) = match decode_invoke_params(&params) {
                Ok(t) => t,
                Err(msg) => {
                    return Ok(vec![encode_callable_error(
                        &CallableError::InvalidArguments(msg),
                    )]);
                }
            };
            match dispatcher.invoke(ctx, call_id, name, arguments).await {
                Ok(outcome) => Ok(vec![encode_callable_result(outcome)]),
                Err(err) => Ok(vec![encode_callable_error(&err)]),
            }
        })
    }
}

fn decode_invoke_params(params: &[Val]) -> Result<(String, String, String), String> {
    match params {
        [Val::String(call_id), Val::String(name), Val::String(arguments)] => {
            if call_id.len() > MAX_CALL_ID {
                return Err(format!("call-id exceeds {MAX_CALL_ID} bytes"));
            }
            if name.len() > MAX_NAME {
                return Err(format!("name exceeds {MAX_NAME} bytes"));
            }
            if arguments.len() > MAX_ARGUMENTS {
                return Err(format!("arguments exceed {MAX_ARGUMENTS} bytes"));
            }
            Ok((call_id.clone(), name.clone(), arguments.clone()))
        }
        _ => Err("invoke-callable: expected (string, string, string)".into()),
    }
}

fn encode_list_ok(defs: Vec<CallableDefinition>) -> Val {
    let list = defs.into_iter().map(encode_definition).collect();
    Val::Result(Ok(Some(Box::new(Val::List(list)))))
}

fn encode_definition(def: CallableDefinition) -> Val {
    let idempotent = match def.idempotent {
        Some(b) => Val::Option(Some(Box::new(Val::Bool(b)))),
        None => Val::Option(None),
    };
    Val::Record(vec![
        ("name".into(), Val::String(def.name)),
        ("description".into(), Val::String(def.description)),
        ("parameters".into(), Val::String(def.parameters.to_string())),
        (
            "source".into(),
            Val::Enum(def.source.as_wit_name().to_string()),
        ),
        ("idempotent".into(), idempotent),
    ])
}

fn encode_callable_result(outcome: CallableOutcome) -> Val {
    Val::Result(Ok(Some(Box::new(Val::Record(vec![
        ("call-id".into(), Val::String(outcome.call_id)),
        ("content".into(), Val::String(outcome.content)),
        ("is-error".into(), Val::Bool(outcome.is_error)),
    ])))))
}

fn encode_callable_error(err: &CallableError) -> Val {
    Val::Result(Err(Some(Box::new(Val::Variant(
        err.wit_case().to_string(),
        Some(Box::new(Val::String(err.payload().to_string()))),
    )))))
}
