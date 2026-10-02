//! [`DataTool`] — the `data` host tool: nine methods, JSON in / JSON out, every error
//! projected to a `tool-error` arm.
//!
//! Authorization: the tool is a second interface onto the files the `fs` capability governs,
//! so it asks the caller's `fs` grant and has no grant family of its own. Reach is the `tools`
//! capability (checked by the injector before the call gets here).
//!
//! | method | `fs` request |
//! |---|---|
//! | `describe` | any Active `fs` grant |
//! | `get`, `history` | `read-paths` on the target's file (an anchored `get` on the row's indexed path) |
//! | `create`, `patch`, `apply` | `read-paths` + `write-paths` on the file |
//! | `query` | `read-paths` on `/` |
//! | `promote`, `demote` | `read-paths` + `write-paths` on `/` (the second file is computed by the store) |
//!
//! A param-less `fs` grant covers every request. Paths are territory-relative with a leading `/`.

use std::sync::Arc;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::entity::EntityQuery;
use advance_shared_types::traits::GrantCheck;
use async_trait::async_trait;
use cap_tools::{HostTool, MethodInfo, ToolDescription, ToolError};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::store::{
    DataError, DataStore, IdempotencyKey, PatchOp, QueryRequest, Record, Target, Tier,
};

/// The nine methods, in the order `describe()` lists them.
pub const METHODS: &[&str] = &[
    "describe", "query", "get", "create", "patch", "promote", "demote", "history", "apply",
];

fn is_read(method: &str) -> bool {
    matches!(method, "describe" | "query" | "get" | "history")
}

pub struct DataTool {
    store: Arc<DataStore>,
    grant: Arc<dyn GrantCheck>,
}

impl DataTool {
    pub fn new(store: Arc<DataStore>, grant: Arc<dyn GrantCheck>) -> Self {
        Self { store, grant }
    }

    pub fn store(&self) -> Arc<DataStore> {
        Arc::clone(&self.store)
    }

    fn check_fs(
        &self,
        agent_id: &str,
        method: &str,
        params: CapParams,
        what: &str,
    ) -> Result<(), ToolError> {
        match self
            .grant
            .check(agent_id, FS_CAPABILITY, &format!("data.{method}"), &params)
        {
            GrantDecision::Allow => Ok(()),
            GrantDecision::Deny(reason) => Err(ToolError::PermissionDenied(format!(
                "data.{method} needs fs {what} for {agent_id}: {reason}"
            ))),
        }
    }

    /// The `fs` gate of one call (see the module table). `Ok(true)` asks the caller to check
    /// read on the returned row's path as well (anchored `get`).
    fn authorize(&self, agent_id: &str, method: &str, params: &[u8]) -> Result<bool, ToolError> {
        // Holding `fs` at all comes first, so an agent without it never learns more.
        self.check_fs(agent_id, method, CapParams::empty(), "access")?;
        let root = String::from("/");
        match method {
            "describe" => Ok(false),
            "query" => self
                .check_fs(agent_id, method, fs_request(Some(&root), None), "read on /")
                .map(|()| false),
            "promote" | "demote" => self
                .check_fs(
                    agent_id,
                    method,
                    fs_request(Some(&root), Some(&root)),
                    "read and write on /",
                )
                .map(|()| false),
            _ => {
                let key = if method == "create" {
                    "parent"
                } else {
                    "target"
                };
                // A target that does not parse is reported by `dispatch` as invalid input.
                let Some(target) = serde_json::from_slice::<Value>(params)
                    .ok()
                    .and_then(|v| v.get(key).and_then(Value::as_str).map(str::to_string))
                    .and_then(|t| Target::parse(&t).ok())
                else {
                    return Ok(false);
                };
                if method == "get" && matches!(target, Target::Anchored { .. }) {
                    return Ok(true);
                }
                let path = grant_path(target.path());
                if is_read(method) {
                    self.check_fs(
                        agent_id,
                        method,
                        fs_request(Some(&path), None),
                        &format!("read on {path}"),
                    )
                } else {
                    self.check_fs(
                        agent_id,
                        method,
                        fs_request(Some(&path), Some(&path)),
                        &format!("read and write on {path}"),
                    )
                }
                .map(|()| false)
            }
        }
    }

    async fn dispatch(&self, agent: &str, method: &str, params: &[u8]) -> Result<Value, DataError> {
        let params: Value = if params.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(params)
                .map_err(|e| DataError::Invalid(format!("params: {e}")))?
        };
        match method {
            "describe" => {
                let d = self.store.describe_async(agent).await;
                serde_json::to_value(d).map_err(|e| DataError::Io(e.to_string()))
            }
            "query" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    #[serde(default)]
                    query: Option<String>,
                    #[serde(default)]
                    args: Option<Value>,
                    #[serde(default)]
                    filter: Option<EntityQuery>,
                }
                let p: P = parse(params)?;
                let req = match (p.query, p.filter) {
                    (Some(name), None) => QueryRequest::named(&name, p.args.unwrap_or(Value::Null)),
                    (None, Some(mut f)) => {
                        f.agent_id = agent.to_string();
                        QueryRequest::ad_hoc(f)
                    }
                    _ => {
                        return Err(DataError::Invalid(
                            "query takes either `query` or `filter`".into(),
                        ))
                    }
                };
                let rows = self.store.query(agent, req).await?;
                serde_json::to_value(rows).map_err(|e| DataError::Io(e.to_string()))
            }
            "get" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    target: String,
                }
                let p: P = parse(params)?;
                let row = self.store.get(agent, Target::parse(&p.target)?).await?;
                serde_json::to_value(row).map_err(|e| DataError::Io(e.to_string()))
            }
            "create" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    parent: String,
                    record: Value,
                }
                let p: P = parse(params)?;
                let id = self
                    .store
                    .create(
                        agent,
                        Target::parse(&p.parent)?,
                        Record::from_json(p.record),
                    )
                    .await?;
                Ok(
                    json!({ "id": id.0, "target": format!("{}#{}", p.parent.trim_start_matches('/'), id.0) }),
                )
            }
            "patch" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Op {
                    #[serde(default)]
                    set: Option<String>,
                    #[serde(default)]
                    value: Option<Value>,
                    #[serde(default)]
                    unset: Option<String>,
                }
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    target: String,
                    ops: Vec<Op>,
                }
                let p: P = parse(params)?;
                let mut ops = Vec::with_capacity(p.ops.len());
                for o in p.ops {
                    match (o.set, o.unset) {
                        (Some(f), None) => {
                            ops.push(PatchOp::Set(f, o.value.unwrap_or(Value::Null)))
                        }
                        (None, Some(f)) => ops.push(PatchOp::Unset(f)),
                        _ => {
                            return Err(DataError::Invalid(
                                "each op is either {set, value} or {unset}".into(),
                            ))
                        }
                    }
                }
                let row = self
                    .store
                    .patch(agent, Target::parse(&p.target)?, ops)
                    .await?;
                serde_json::to_value(row).map_err(|e| DataError::Io(e.to_string()))
            }
            "promote" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    target: String,
                    to: Tier,
                }
                let p: P = parse(params)?;
                let t = self
                    .store
                    .promote(agent, Target::parse(&p.target)?, p.to)
                    .await?;
                Ok(json!({ "target": t.render() }))
            }
            "demote" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    target: String,
                }
                let p: P = parse(params)?;
                let t = self.store.demote(agent, Target::parse(&p.target)?).await?;
                Ok(json!({ "target": t.render() }))
            }
            "history" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    target: String,
                    #[serde(default)]
                    limit: Option<usize>,
                }
                let p: P = parse(params)?;
                let versions = self
                    .store
                    .history(agent, Target::parse(&p.target)?, p.limit.unwrap_or(20))
                    .await?;
                serde_json::to_value(versions).map_err(|e| DataError::Io(e.to_string()))
            }
            "apply" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct P {
                    op: String,
                    target: String,
                    #[serde(default)]
                    args: Value,
                    #[serde(default)]
                    idempotency_key: Option<String>,
                }
                let p: P = parse(params)?;
                let result = self
                    .store
                    .apply(
                        agent,
                        &p.op,
                        Target::parse(&p.target)?,
                        p.args,
                        p.idempotency_key.map(IdempotencyKey),
                    )
                    .await?;
                serde_json::to_value(result).map_err(|e| DataError::Io(e.to_string()))
            }
            other => Err(DataError::OpUnavailable(format!("unknown method {other}"))),
        }
    }
}

/// The grant family that governs the files this tool touches.
const FS_CAPABILITY: &str = "fs";

/// A territory-relative path in the form `fs` grant params use (leading `/`). A path the grant
/// grammar cannot carry (a comma, edge whitespace, control bytes) asks for `/` instead, which
/// can only require a broader grant.
fn grant_path(path: &str) -> String {
    let safe = !path.is_empty()
        && path.trim() == path
        && !path.contains(',')
        && !path.chars().any(|c| c.is_control());
    if safe {
        format!("/{path}")
    } else {
        "/".to_string()
    }
}

fn fs_request(read: Option<&str>, write: Option<&str>) -> CapParams {
    let mut m = serde_json::Map::new();
    if let Some(p) = read {
        m.insert("read-paths".into(), Value::String(p.to_string()));
    }
    if let Some(p) = write {
        m.insert("write-paths".into(), Value::String(p.to_string()));
    }
    CapParams::new(Value::Object(m))
}

fn parse<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, DataError> {
    serde_json::from_value(v).map_err(|e| DataError::Invalid(format!("params: {e}")))
}

fn map_error(e: DataError) -> ToolError {
    match e {
        DataError::Invalid(m) => ToolError::InputValidationFailed(m),
        DataError::Transition { .. } | DataError::PreconditionFailed { .. } => {
            ToolError::InputValidationFailed(e.to_string())
        }
        DataError::PromoteRequired { .. } => ToolError::InputValidationFailed(e.to_string()),
        DataError::NotFound(m) => ToolError::NotFound(m),
        DataError::Forbidden(m) => ToolError::PermissionDenied(m),
        DataError::OpUnavailable(m) => ToolError::MethodNotFound(m),
        DataError::Io(m) => ToolError::InvocationFailed(m),
    }
}

fn schema_str(v: Value) -> Option<String> {
    serde_json::to_string(&v).ok()
}

#[async_trait]
impl HostTool for DataTool {
    fn describe(&self) -> ToolDescription {
        let target = json!({ "type": "string", "description": "\"path\" or \"path#e-…\"" });
        let obj = |props: Value, required: Vec<&str>| json!({ "type": "object", "properties": props, "required": required, "additionalProperties": false });
        let method = |name: &str, desc: &str, input: Value, output: Value| MethodInfo {
            name: name.to_string(),
            description: Some(desc.to_string()),
            input_schema: schema_str(input),
            output_schema: schema_str(output),
            idempotent: Some(is_read(name)),
        };
        let row = json!({ "type": "object" });
        let rows = json!({ "type": "array", "items": { "type": "object" } });
        ToolDescription {
            description: "Structured data over frontmatter: describe the schema, query the index, and create / patch / promote / demote / apply operations on entities. Every write is validated against the schema and committed by the host.".into(),
            methods: vec![
                method("describe", "The merged schema: aspects, fields, queries, views, operations", obj(json!({}), vec![]), json!({ "type": "object" })),
                method("query", "Run a named query (`query` + `args`) or an ad-hoc `filter`", obj(json!({ "query": { "type": "string" }, "args": { "type": "object" }, "filter": { "type": "object" } }), vec![]), rows.clone()),
                method("get", "One record", obj(json!({ "target": target }), vec!["target"]), row.clone()),
                method("create", "Add an inline item under a file", obj(json!({ "parent": { "type": "string" }, "record": { "type": "object" } }), vec!["parent", "record"]), json!({ "type": "object", "properties": { "id": { "type": "string" }, "target": { "type": "string" } } })),
                method("patch", "Set / unset fields of a record", obj(json!({ "target": target, "ops": { "type": "array", "items": { "type": "object" } } }), vec!["target", "ops"]), row.clone()),
                method("promote", "Inline item → file, or file → directory", obj(json!({ "target": target, "to": { "type": "string", "enum": ["file", "dir"] } }), vec!["target", "to"]), json!({ "type": "object" })),
                method("demote", "File → inline item of its parent", obj(json!({ "target": target }), vec!["target"]), json!({ "type": "object" })),
                method("history", "Versions of one record, newest first", obj(json!({ "target": target, "limit": { "type": "integer", "minimum": 1, "maximum": 200 } }), vec!["target"]), rows),
                method("apply", "Run a pack operation (pure WASM reducer) in one transaction", obj(json!({ "op": { "type": "string" }, "target": target, "args": { "type": "object" }, "idempotency_key": { "type": "string" } }), vec!["op", "target"]), json!({ "type": "object" })),
            ],
        }
    }

    async fn execute(&self, method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
        Err(ToolError::PermissionDenied(format!(
            "data.{method} needs the calling agent's identity (use invoke_as)"
        )))
    }

    async fn execute_as(
        &self,
        agent_id: &str,
        method: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        if !METHODS.contains(&method) {
            return Err(ToolError::MethodNotFound(method.to_string()));
        }
        let check_row_path = self.authorize(agent_id, method, params)?;
        let value = self
            .dispatch(agent_id, method, params)
            .await
            .map_err(map_error)?;
        if check_row_path {
            // An anchored `get` is answered from the index, so the file that holds the record
            // is known only now; nothing is returned unless the caller may read it.
            let path = grant_path(value.get("path").and_then(Value::as_str).unwrap_or(""));
            self.check_fs(
                agent_id,
                method,
                fs_request(Some(&path), None),
                &format!("read on {path}"),
            )?;
        }
        serde_json::to_vec(&value).map_err(|e| ToolError::InvocationFailed(e.to_string()))
    }
}
