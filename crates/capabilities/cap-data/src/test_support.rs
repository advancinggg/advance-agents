//! Doubles for witnesses and composition tests: a plain-directory [`WorkspaceFs`], an
//! in-memory [`EntityIndex`], deterministic ids / clock, a recording event sink, a scripted
//! reducer, and grant checks that always allow / deny.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::entity::{
    EntityId, EntityIndex, EntityIndexError, EntityQuery, EntityRow, OrderKey,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use async_trait::async_trait;
use cap_fs::meta_schema::MetaSchemaLoader;
use cap_tools::DeterministicCtx;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::store::{
    Clock, DataError, EntityIds, FileVersion, PureReducer, WorkspaceFs, WriteReceipt,
};

/// The shipped `packs/agenda` aspect file as a loader (workspace form: one aspect, no
/// required fields — enough for record validation).
pub fn agenda_schema() -> Arc<MetaSchemaLoader> {
    const AGENDA_YAML: &str =
        include_str!("../../../../packs/agenda/meta-schema-extensions/agenda.yaml");
    Arc::new(
        MetaSchemaLoader::from_yaml(PathBuf::from("/nonexistent/meta-schema.yaml"), AGENDA_YAML)
            .expect("agenda.yaml parses with the v2 grammar"),
    )
}

/// Plain directory + in-memory version log (fake commit ids `c-1`, `c-2`, …).
pub struct DirWorkspaceFs {
    root: PathBuf,
    commits: AtomicU32,
    log: Mutex<HashMap<String, Vec<FileVersion>>>,
}

impl DirWorkspaceFs {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            commits: AtomicU32::new(0),
            log: Mutex::new(HashMap::new()),
        }
    }
    fn abs(&self, path: &str) -> Result<PathBuf, DataError> {
        if path.contains("..") {
            return Err(DataError::Forbidden(format!(
                "path escapes the workspace: {path}"
            )));
        }
        Ok(self.root.join(path.trim_start_matches('/')))
    }
    fn next_commit(&self) -> String {
        format!("c-{}", self.commits.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

#[async_trait]
impl WorkspaceFs for DirWorkspaceFs {
    async fn read(&self, _agent: &str, path: &str) -> Result<Option<Vec<u8>>, DataError> {
        match std::fs::read(self.abs(path)?) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(DataError::Io(e.to_string())),
        }
    }
    async fn write(
        &self,
        _agent: &str,
        path: &str,
        bytes: &[u8],
        message: &str,
    ) -> Result<WriteReceipt, DataError> {
        let abs = self.abs(path)?;
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DataError::Io(e.to_string()))?;
        }
        let tmp = abs.with_extension("tmp-write");
        std::fs::write(&tmp, bytes).map_err(|e| DataError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &abs).map_err(|e| DataError::Io(e.to_string()))?;
        let commit = self.next_commit();
        self.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(path.trim_start_matches('/').to_string())
            .or_default()
            .push(FileVersion {
                commit: commit.clone(),
                message: message.to_string(),
                bytes: bytes.to_vec(),
            });
        Ok(WriteReceipt {
            commit: Some(commit),
        })
    }
    async fn remove(
        &self,
        _agent: &str,
        path: &str,
        _message: &str,
    ) -> Result<WriteReceipt, DataError> {
        std::fs::remove_file(self.abs(path)?).map_err(|e| DataError::Io(e.to_string()))?;
        Ok(WriteReceipt {
            commit: Some(self.next_commit()),
        })
    }
    async fn rename(
        &self,
        _agent: &str,
        from: &str,
        to: &str,
        _message: &str,
    ) -> Result<WriteReceipt, DataError> {
        let to_abs = self.abs(to)?;
        if let Some(parent) = to_abs.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DataError::Io(e.to_string()))?;
        }
        std::fs::rename(self.abs(from)?, to_abs).map_err(|e| DataError::Io(e.to_string()))?;
        let mut log = self.log.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = log.remove(from.trim_start_matches('/')) {
            log.insert(to.trim_start_matches('/').to_string(), v);
        }
        Ok(WriteReceipt {
            commit: Some(self.next_commit()),
        })
    }
    async fn history(
        &self,
        _agent: &str,
        path: &str,
        limit: usize,
    ) -> Result<Vec<FileVersion>, DataError> {
        let log = self.log.lock().unwrap_or_else(|p| p.into_inner());
        let mut v = log
            .get(path.trim_start_matches('/'))
            .cloned()
            .unwrap_or_default();
        v.reverse();
        v.truncate(limit);
        Ok(v)
    }
}

/// In-memory index with the same filter semantics as the SQLite one (single occurrence per
/// `starts`; no RRULE expansion — witnesses that need expansion use `advance-database`).
#[derive(Default)]
pub struct MemoryEntityIndex {
    rows: Mutex<Vec<EntityRow>>,
}

impl MemoryEntityIndex {
    pub fn rows(&self) -> Vec<EntityRow> {
        self.rows.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

fn field_value(row: &EntityRow, field: &str) -> Option<Value> {
    match field {
        "due" | "due_at" => row.due_at.map(|t| Value::String(t.to_rfc3339())),
        "starts" | "starts_at" => row.starts_at.map(|t| Value::String(t.to_rfc3339())),
        "ends" | "ends_at" => row.ends_at.map(|t| Value::String(t.to_rfc3339())),
        "priority" => row.priority.map(Value::from),
        "title" => row.title.clone().map(Value::String),
        "status" => row.status.clone().map(Value::String),
        "type" => Some(Value::String(row.r#type.clone())),
        "updated_at" => Some(Value::String(row.updated_at.to_rfc3339())),
        other => row.fields.get(other).cloned(),
    }
}

fn cmp_values(a: &Value, b: &Value) -> std::cmp::Ordering {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x
            .as_f64()
            .unwrap_or(0.0)
            .partial_cmp(&y.as_f64().unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal),
        _ => a.to_string().cmp(&b.to_string()),
    }
}

#[async_trait]
impl EntityIndex for MemoryEntityIndex {
    async fn replace_path(
        &self,
        agent_id: &str,
        path: &str,
        rows: Vec<EntityRow>,
    ) -> Result<(), EntityIndexError> {
        let path = path.trim_start_matches('/');
        let mut all = self.rows.lock().unwrap_or_else(|p| p.into_inner());
        all.retain(|r| !(r.agent_id == agent_id && r.path == path));
        for row in rows {
            all.retain(|r| !(r.agent_id == agent_id && r.id == row.id));
            all.push(EntityRow {
                path: path.to_string(),
                ..row
            });
        }
        Ok(())
    }
    async fn delete_path(&self, agent_id: &str, path: &str) -> Result<(), EntityIndexError> {
        let path = path.trim_start_matches('/');
        self.rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|r| !(r.agent_id == agent_id && r.path == path));
        Ok(())
    }
    async fn get(
        &self,
        agent_id: &str,
        id: &EntityId,
    ) -> Result<Option<EntityRow>, EntityIndexError> {
        Ok(self
            .rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|r| r.agent_id == agent_id && &r.id == id)
            .cloned())
    }
    async fn query(&self, q: &EntityQuery) -> Result<Vec<EntityRow>, EntityIndexError> {
        if q.limit == 0 || q.limit > advance_shared_types::entity::MAX_ENTITY_QUERY_LIMIT {
            return Err(EntityIndexError::InvalidQuery(format!("limit {}", q.limit)));
        }
        let in_window = |t: Option<DateTime<Utc>>, w: (DateTime<Utc>, DateTime<Utc>)| {
            t.map(|t| t >= w.0 && t < w.1).unwrap_or(false)
        };
        let mut out: Vec<EntityRow> = self
            .rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|r| r.agent_id == q.agent_id)
            .filter(|r| {
                q.parent
                    .as_ref()
                    .map(|p| r.parent.as_ref() == Some(p))
                    .unwrap_or(true)
            })
            .filter(|r| q.r#type.as_ref().map(|t| &r.r#type == t).unwrap_or(true))
            .filter(|r| {
                q.aspect
                    .as_ref()
                    .map(|a| r.aspects.contains(a))
                    .unwrap_or(true)
            })
            .filter(|r| {
                q.status
                    .as_ref()
                    .map(|s| r.status.as_ref().map(|x| s.contains(x)).unwrap_or(false))
                    .unwrap_or(true)
            })
            .filter(|r| {
                q.due_between
                    .map(|w| in_window(r.due_at, w))
                    .unwrap_or(true)
            })
            .filter(|r| {
                q.occurs_between
                    .map(|w| in_window(r.starts_at, w))
                    .unwrap_or(true)
            })
            .filter(|r| {
                q.any_between
                    .map(|w| in_window(r.due_at, w) || in_window(r.starts_at, w))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        let order: Vec<OrderKey> = if q.order.is_empty() {
            vec![OrderKey {
                field: "updated_at".into(),
                ascending: false,
            }]
        } else {
            q.order.clone()
        };
        out.sort_by(|a, b| {
            for k in &order {
                let (va, vb) = (field_value(a, &k.field), field_value(b, &k.field));
                let ord = match (va, vb) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (Some(x), Some(y)) => {
                        let o = cmp_values(&x, &y);
                        if k.ascending {
                            o
                        } else {
                            o.reverse()
                        }
                    }
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            std::cmp::Ordering::Equal
        });
        out.truncate(q.limit);
        Ok(out)
    }
    async fn truncate(&self, agent_id: &str) -> Result<(), EntityIndexError> {
        self.rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|r| r.agent_id != agent_id);
        Ok(())
    }
}

/// `e-000…001`, `e-000…002`, … (26-character zero-padded counters).
#[derive(Default)]
pub struct SequentialIds(AtomicU32);

impl EntityIds for SequentialIds {
    fn next_id(&self) -> String {
        format!("e-{:026}", self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

pub struct FixedClock(DateTime<Utc>);

impl FixedClock {
    pub fn at(rfc3339: &str) -> Self {
        Self(rfc3339.parse().expect("rfc3339"))
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Default)]
pub struct RecordingEvents(Mutex<Vec<Event>>);

impl RecordingEvents {
    pub fn snapshot(&self) -> Vec<Event> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl EventBusEmit for RecordingEvents {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).push(event);
    }
}

/// Returns a fixed reply for every call and records the inputs it saw.
pub struct ScriptedReducer {
    reply: Value,
    tools: Vec<String>,
    calls: AtomicUsize,
    inputs: Mutex<Vec<Value>>,
    ctxs: Mutex<Vec<DeterministicCtx>>,
}

impl ScriptedReducer {
    pub fn returning(reply: Value) -> Self {
        Self {
            reply,
            tools: Vec::new(),
            calls: AtomicUsize::new(0),
            inputs: Mutex::new(Vec::new()),
            ctxs: Mutex::new(Vec::new()),
        }
    }
    /// Mark `tool_id` (e.g. `skill::agenda`) as registered.
    pub fn with_tool(mut self, tool_id: &str) -> Self {
        self.tools.push(tool_id.to_string());
        self
    }
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    pub fn last_input(&self) -> Option<Value> {
        self.inputs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last()
            .cloned()
    }
    pub fn last_ctx(&self) -> Option<DeterministicCtx> {
        self.ctxs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last()
            .copied()
    }
}

#[async_trait]
impl PureReducer for ScriptedReducer {
    async fn available(&self, tool_id: &str) -> bool {
        self.tools.iter().any(|t| t == tool_id)
    }
    async fn reduce(
        &self,
        _tool_id: &str,
        _method: &str,
        input: &[u8],
        ctx: DeterministicCtx,
    ) -> Result<Vec<u8>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(v) = serde_json::from_slice::<Value>(input) {
            self.inputs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(v);
        }
        self.ctxs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(ctx);
        serde_json::to_vec(&self.reply).map_err(|e| e.to_string())
    }
}

pub struct AllowAll;

impl GrantCheck for AllowAll {
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

pub struct DenyAll;

impl GrantCheck for DenyAll {
    fn check(
        &self,
        _agent_id: &str,
        _capability: &str,
        _function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        GrantDecision::Deny("denied by test".into())
    }
}

/// Convenience for tests: the record fields of a row as a map.
pub fn fields_of(row: &EntityRow) -> BTreeMap<String, Value> {
    advance_shared_types::entity::fields_map(row)
}
