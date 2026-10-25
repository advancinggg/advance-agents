//! Opt-in host-fn catalog specs (fs / memory / genui).
//!
//! Each spec wraps the already-registered `HostFunctionHandler` with a JSON →
//! `Val` adapter. The original capability/function identity is preserved for
//! L1 GrantCheck. There is no WASM linker hop.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::callable_registry::{
    CallableError, CallableHandler, CallableOutcome, CallableRegistry, CallableSpec,
};
use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler, HostRegistry};
use serde_json::{json, Value};
use wasmtime::component::Val;

const FS_NS: &str = "advance:runtime/agent-fs@0.1.0";
const MEMORY_NS: &str = "advance:runtime/agent-memory@0.1.0";
const GENUI_NS: &str = "advance:runtime/agent-genui@0.1.0";

/// Register model-facing fs callables: write / read / list / delete / scan / mkdir.
pub fn register_fs_callables(callables: &dyn CallableRegistry, hosts: &dyn HostRegistry) {
    register_one(
        callables,
        hosts,
        "fs",
        "write",
        FS_NS,
        "Write a file at the given path with the given text content. Parent directories must already exist (call mkdir first).",
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "content": { "type": "string" }
            },
            "required": ["path", "content"],
            "additionalProperties": false
        }),
        false,
        EncodeKind::FsWrite,
    );
    for (name, desc, idempotent) in [
        ("read", "Read the file at the given path.", true),
        (
            "list",
            "List entries in the directory at the given path.",
            true,
        ),
        (
            "delete",
            "Delete the file or directory at the given path.",
            false,
        ),
        ("scan", "Scan the directory tree at the given path.", true),
        (
            "mkdir",
            "Create a directory at the given path, one component at a time. Existing directories are left in place. Parent components that are symlinks are refused.",
            false,
        ),
    ] {
        register_one(
            callables,
            hosts,
            "fs",
            name,
            FS_NS,
            desc,
            json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
                "additionalProperties": false
            }),
            idempotent,
            EncodeKind::Path,
        );
    }
}

/// Register model-facing memory callables: remember / recall / forget.
pub fn register_memory_callables(callables: &dyn CallableRegistry, hosts: &dyn HostRegistry) {
    register_one(
        callables,
        hosts,
        "memory",
        "remember",
        MEMORY_NS,
        "Store a memory entry with optional tags.",
        json!({
            "type": "object",
            "properties": {
                "content": { "type": "string" },
                "tags": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["content"],
            "additionalProperties": false
        }),
        false,
        EncodeKind::Remember,
    );
    register_one(
        callables,
        hosts,
        "memory",
        "recall",
        MEMORY_NS,
        "Recall memory entries matching a query.",
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "limit": { "type": "integer", "minimum": 1 }
            },
            "required": ["query"],
            "additionalProperties": false
        }),
        true,
        EncodeKind::Recall,
    );
    register_one(
        callables,
        hosts,
        "memory",
        "forget",
        MEMORY_NS,
        "Forget a memory entry by id.",
        json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"],
            "additionalProperties": false
        }),
        false,
        EncodeKind::Forget,
    );
}

/// Register model-facing genui callable: emit-document.
pub fn register_genui_callables(callables: &dyn CallableRegistry, hosts: &dyn HostRegistry) {
    register_one(
        callables,
        hosts,
        "genui",
        "emit-document",
        GENUI_NS,
        "Emit a UI document as JSON.",
        json!({
            "type": "object",
            "properties": { "document-json": { "type": "string" } },
            "required": ["document-json"],
            "additionalProperties": false
        }),
        false,
        EncodeKind::EmitDocument,
    );
}

#[allow(clippy::too_many_arguments)]
fn register_one(
    callables: &dyn CallableRegistry,
    hosts: &dyn HostRegistry,
    capability: &str,
    name: &str,
    namespace: &str,
    description: &str,
    parameters: Value,
    idempotent: bool,
    encode: EncodeKind,
) {
    let Some(handler) = find_handler(hosts, capability, name) else {
        return;
    };
    callables.register(CallableSpec {
        capability: capability.into(),
        name: name.into(),
        description: description.into(),
        parameters,
        idempotent,
        original_function: format!("{namespace}::{name}"),
        handler: Arc::new(HostFnBridge { handler, encode }),
    });
}

fn find_handler(
    hosts: &dyn HostRegistry,
    capability: &str,
    name: &str,
) -> Option<Arc<dyn HostFunctionHandler>> {
    hosts
        .lookup(capability)
        .into_iter()
        .find(|s| s.name == name)
        .map(|s| s.handler)
}

#[derive(Clone, Copy)]
enum EncodeKind {
    FsWrite,
    Path,
    Remember,
    Recall,
    Forget,
    EmitDocument,
}

struct HostFnBridge {
    handler: Arc<dyn HostFunctionHandler>,
    encode: EncodeKind,
}

impl CallableHandler for HostFnBridge {
    fn call(
        &self,
        ctx: HostCallContext,
        call_id: String,
        arguments: Value,
    ) -> Pin<Box<dyn Future<Output = Result<CallableOutcome, CallableError>> + Send + 'static>>
    {
        let handler = Arc::clone(&self.handler);
        let encode = self.encode;
        Box::pin(async move {
            let vals = encode.encode(&arguments)?;
            match handler.call(ctx, vals, 1).await {
                Ok(results) => Ok(val_to_outcome(call_id, results)),
                Err(err) => Err(CallableError::Internal(err.to_string())),
            }
        })
    }
}

impl EncodeKind {
    fn encode(self, args: &Value) -> Result<Vec<Val>, CallableError> {
        match self {
            Self::FsWrite => {
                let path = require_str(args, "path")?;
                let content = require_str(args, "content")?;
                Ok(vec![
                    Val::String(path.to_string()),
                    Val::List(content.as_bytes().iter().copied().map(Val::U8).collect()),
                ])
            }
            Self::Path => Ok(vec![Val::String(require_str(args, "path")?.to_string())]),
            Self::Remember => {
                let content = require_str(args, "content")?;
                let tags = args
                    .get("tags")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(|s| Val::String(s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(vec![Val::String(content.to_string()), Val::List(tags)])
            }
            Self::Recall => {
                let query = require_str(args, "query")?;
                let limit = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(10)
                    .min(u32::MAX as u64) as u32;
                Ok(vec![Val::String(query.to_string()), Val::U32(limit)])
            }
            Self::Forget => Ok(vec![Val::String(require_str(args, "id")?.to_string())]),
            Self::EmitDocument => Ok(vec![Val::String(
                require_str(args, "document-json")?.to_string(),
            )]),
        }
    }
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, CallableError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| CallableError::InvalidArguments(format!("missing string field `{key}`")))
}

fn val_to_outcome(call_id: String, results: Vec<Val>) -> CallableOutcome {
    let Some(first) = results.into_iter().next() else {
        return CallableOutcome {
            call_id,
            content: "ok".into(),
            is_error: false,
        };
    };
    match first {
        Val::Result(Ok(payload)) => CallableOutcome {
            call_id,
            content: payload
                .as_deref()
                .map(val_to_string)
                .unwrap_or_else(|| "ok".into()),
            is_error: false,
        },
        Val::Result(Err(payload)) => CallableOutcome {
            call_id,
            content: payload
                .as_deref()
                .map(val_to_string)
                .unwrap_or_else(|| "error".into()),
            is_error: true,
        },
        other => CallableOutcome {
            call_id,
            content: val_to_string(&other),
            is_error: false,
        },
    }
}

fn val_to_string(val: &Val) -> String {
    match val_to_json(val) {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

fn val_to_json(val: &Val) -> Value {
    match val {
        Val::Bool(b) => json!(b),
        Val::S8(n) => json!(n),
        Val::U8(n) => json!(n),
        Val::S16(n) => json!(n),
        Val::U16(n) => json!(n),
        Val::S32(n) => json!(n),
        Val::U32(n) => json!(n),
        Val::S64(n) => json!(n),
        Val::U64(n) => json!(n),
        Val::Float32(n) => json!(n),
        Val::Float64(n) => json!(n),
        Val::Char(c) => json!(c.to_string()),
        Val::String(s) => json!(s),
        Val::List(items) => {
            if !items.is_empty() && items.iter().all(|v| matches!(v, Val::U8(_))) {
                let bytes: Vec<u8> = items
                    .iter()
                    .map(|v| match v {
                        Val::U8(b) => *b,
                        _ => 0,
                    })
                    .collect();
                json!(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                Value::Array(items.iter().map(val_to_json).collect())
            }
        }
        Val::Record(fields) => {
            let mut map = serde_json::Map::new();
            for (k, v) in fields {
                map.insert(k.clone(), val_to_json(v));
            }
            Value::Object(map)
        }
        Val::Tuple(items) => Value::Array(items.iter().map(val_to_json).collect()),
        Val::Variant(tag, payload) => match payload {
            Some(inner) => json!({ "case": tag, "payload": val_to_json(inner) }),
            None => json!({ "case": tag }),
        },
        Val::Enum(name) => json!(name),
        Val::Option(inner) => match inner {
            Some(v) => val_to_json(v),
            None => Value::Null,
        },
        Val::Result(Ok(inner)) => json!({ "ok": inner.as_deref().map(val_to_json) }),
        Val::Result(Err(inner)) => json!({ "err": inner.as_deref().map(val_to_json) }),
        Val::Flags(names) => json!(names),
        other => json!(format!("{other:?}")),
    }
}
