//! [`DataStore`] — the entity operations and the one host-owned write transaction.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use advance_shared_types::entity::{
    EntityId, EntityIndex, EntityQuery, EntityRow, OrderKey, DEFAULT_ENTITY_QUERY_LIMIT,
    ENTITY_ID_PREFIX, MAX_ENTITY_QUERY_LIMIT,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use cap_fs::entity_projection::project_entities;
use cap_fs::frontmatter::{
    canonicalize, normalize_doc, parse_frontmatter, FrontmatterDoc, FrontmatterError, IdSource,
    MAX_ITEMS_PER_FILE,
};
use cap_fs::meta_schema::{
    FieldSpec, FieldType, MetaSchema, MetaSchemaLoader, QuerySpec, ValueExpr, WhereClause,
};
use cap_fs::schema_v2::{eval_expr, format_datetime, parse_datetime, yaml_to_json};
use cap_tools::DeterministicCtx;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_yml::{Mapping, Value as Yaml};
use sha2::{Digest, Sha256};

use crate::effects::{Effect, ReducerOutput, MAX_REDUCER_INPUT_BYTES};

/// The event type every committed transaction emits.
pub const ENTITY_CHANGED_EVENT: &str = "data.entity_changed";
/// Pre-allocated ids handed to a reducer per `apply`.
pub const IDS_PER_APPLY: usize = 8;
/// Bound on the in-process idempotency table.
pub const MAX_IDEMPOTENCY_ENTRIES: usize = 1024;
/// The commit-message trailer that names the operation (read back by `history`).
pub const OP_TRAILER: &str = "Advance-Data-Op";
const SKILL_TOOL_PREFIX: &str = "skill::";

// ── seams ───────────────────────────────────────────────────────────────────────────────────

/// The clock every derived timestamp / event / reducer input comes from.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// The production clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Shared id supply (interior mutability so one source can back many stores).
pub trait EntityIds: Send + Sync {
    fn next_id(&self) -> String;
}

/// The production id supply (`e-` + ULID).
#[derive(Debug, Default, Clone, Copy)]
pub struct UlidEntityIds;

impl EntityIds for UlidEntityIds {
    fn next_id(&self) -> String {
        format!("{ENTITY_ID_PREFIX}{}", ulid_new())
    }
}

fn ulid_new() -> String {
    // cap-fs owns the `ulid` dependency; reuse its source so both mint identically.
    let mut src = cap_fs::frontmatter::UlidIdSource;
    src.next_id()
        .strip_prefix(ENTITY_ID_PREFIX)
        .unwrap_or_default()
        .to_string()
}

/// What a committed write reports back.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteReceipt {
    /// The git commit that recorded the write, when the workspace is git-backed.
    pub commit: Option<String>,
}

/// One historical version of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVersion {
    pub commit: String,
    pub message: String,
    pub bytes: Vec<u8>,
}

/// Which side of a receipt a caller wants (kept for API symmetry of the cli adapter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptKind {
    Write,
    Remove,
    Rename,
}

/// The workspace filesystem the store writes through. The production implementation composes
/// cap-fs's primitives (territory resolver, atomic writer, `.meta.yaml` maintainer, SQLite +
/// git sync); tests use a plain directory. Paths are workspace-relative, no leading slash.
#[async_trait]
pub trait WorkspaceFs: Send + Sync {
    async fn read(&self, agent: &str, path: &str) -> Result<Option<Vec<u8>>, DataError>;
    /// Atomic write + commit; `message` is the commit message (carries the op trailer).
    async fn write(
        &self,
        agent: &str,
        path: &str,
        bytes: &[u8],
        message: &str,
    ) -> Result<WriteReceipt, DataError>;
    async fn remove(
        &self,
        agent: &str,
        path: &str,
        message: &str,
    ) -> Result<WriteReceipt, DataError>;
    async fn rename(
        &self,
        agent: &str,
        from: &str,
        to: &str,
        message: &str,
    ) -> Result<WriteReceipt, DataError>;
    /// Newest first, at most `limit` versions.
    async fn history(
        &self,
        agent: &str,
        path: &str,
        limit: usize,
    ) -> Result<Vec<FileVersion>, DataError>;
}

/// Runs a pack's pure reducer tool. The production implementation wraps
/// `LazyToolRegistry::invoke_deterministic`.
#[async_trait]
pub trait PureReducer: Send + Sync {
    /// `true` iff `tool_id` (e.g. `skill::agenda`) is registered.
    async fn available(&self, tool_id: &str) -> bool;
    async fn reduce(
        &self,
        tool_id: &str,
        method: &str,
        input: &[u8],
        ctx: DeterministicCtx,
    ) -> Result<Vec<u8>, String>;
}

// ── request / result types ──────────────────────────────────────────────────────────────────

/// `"path"` (a file / directory record) or `"path#e-…"` (an inline item).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Target {
    Path(String),
    Anchored { path: String, id: EntityId },
}

impl Target {
    pub fn parse(text: &str) -> Result<Self, DataError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(DataError::Invalid("empty target".into()));
        }
        match text.split_once('#') {
            None => Ok(Target::Path(normalize_path(text)?)),
            Some((path, id)) => {
                if !id.starts_with(ENTITY_ID_PREFIX) {
                    return Err(DataError::Invalid(format!("malformed entity id {id:?}")));
                }
                Ok(Target::Anchored {
                    path: normalize_path(path)?,
                    id: EntityId(id.to_string()),
                })
            }
        }
    }
    pub fn path(&self) -> &str {
        match self {
            Target::Path(p) => p,
            Target::Anchored { path, .. } => path,
        }
    }
    pub fn render(&self) -> String {
        match self {
            Target::Path(p) => p.clone(),
            Target::Anchored { path, id } => format!("{path}#{}", id.0),
        }
    }
}

fn normalize_path(p: &str) -> Result<String, DataError> {
    let p = p.trim().trim_start_matches('/');
    if p.is_empty() || p.contains("..") || p.contains('\0') || p.len() > 4096 {
        return Err(DataError::Invalid(format!("invalid path {p:?}")));
    }
    Ok(p.to_string())
}

/// A record as supplied by a caller (JSON object of declared / free-form fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record(pub serde_json::Map<String, Value>);

impl Record {
    pub fn from_json(v: Value) -> Self {
        match v {
            Value::Object(m) => Record(m),
            _ => Record(serde_json::Map::new()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatchOp {
    Set(String, Value),
    Unset(String),
}

/// Promotion target tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdempotencyKey(pub String);

/// A named query with arguments, or an ad-hoc [`EntityQuery`].
#[derive(Debug, Clone, PartialEq)]
pub enum QueryRequest {
    Named { name: String, args: Value },
    AdHoc(EntityQuery),
}

impl QueryRequest {
    pub fn named(name: &str, args: Value) -> Self {
        Self::Named {
            name: name.to_string(),
            args,
        }
    }
    pub fn ad_hoc(q: EntityQuery) -> Self {
        Self::AdHoc(q)
    }
}

/// One version of one record (newest first from `history`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordVersion {
    pub commit: String,
    pub op: Option<String>,
    pub record: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplyResult {
    pub op: String,
    /// Every record the apply touched or created, after the write.
    pub rows: Vec<EntityRow>,
    pub commit: Option<String>,
}

// ── describe ────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldDescription {
    pub name: String,
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#enum: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transitions: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    pub inherit: bool,
    #[serde(default)]
    pub derived: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryDescription {
    pub name: String,
    pub args: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ViewDescription {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    #[serde(default)]
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationDescription {
    pub name: String,
    /// The registry id of the bound tool (`skill::<tool>`).
    pub tool: String,
    pub method: String,
    /// `true` iff the tool is registered right now (`apply` would run).
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AspectDescription {
    pub name: String,
    pub key: Vec<String>,
    pub fields: Vec<FieldDescription>,
    pub queries: Vec<QueryDescription>,
    pub views: Vec<ViewDescription>,
    pub operations: Vec<OperationDescription>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaDescription {
    pub hash: String,
    pub aspects: Vec<AspectDescription>,
}

// ── errors ──────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataError {
    Invalid(String),
    NotFound(String),
    Transition {
        field: String,
        from: String,
        to: String,
    },
    PreconditionFailed {
        op: String,
        reason: String,
    },
    PromoteRequired {
        path: String,
        items: usize,
    },
    Forbidden(String),
    OpUnavailable(String),
    Io(String),
}

impl std::fmt::Display for DataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Transition { field, from, to } => {
                write!(f, "transition {field}: {from} -> {to} is not declared")
            }
            Self::PreconditionFailed { op, reason } => {
                write!(f, "{op}: precondition failed: {reason}")
            }
            Self::PromoteRequired { path, items } => {
                write!(
                    f,
                    "{path} holds {items} inline items; promote before adding more"
                )
            }
            Self::Forbidden(m) => write!(f, "forbidden: {m}"),
            Self::OpUnavailable(m) => write!(f, "operation unavailable: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
        }
    }
}

impl std::error::Error for DataError {}

impl From<FrontmatterError> for DataError {
    fn from(e: FrontmatterError) -> Self {
        match e {
            FrontmatterError::Transition {
                field, from, to, ..
            } => DataError::Transition { field, from, to },
            other => DataError::Invalid(other.to_string()),
        }
    }
}

// ── the store ───────────────────────────────────────────────────────────────────────────────

struct IdsAdapter<'a>(&'a dyn EntityIds);

impl IdSource for IdsAdapter<'_> {
    fn next_id(&mut self) -> String {
        self.0.next_id()
    }
}

#[derive(Clone)]
struct IdemEntry {
    request_hash: String,
    result: ApplyResult,
}

pub struct DataStore {
    fs: Arc<dyn WorkspaceFs>,
    index: Arc<dyn EntityIndex>,
    schema: Arc<MetaSchemaLoader>,
    ids: Arc<dyn EntityIds>,
    clock: Arc<dyn Clock>,
    events: Option<Arc<dyn EventBusEmit>>,
    reducer: Option<Arc<dyn PureReducer>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    idempotency: Mutex<Vec<(String, IdemEntry)>>,
}

impl DataStore {
    pub fn new(
        fs: Arc<dyn WorkspaceFs>,
        index: Arc<dyn EntityIndex>,
        schema: Arc<MetaSchemaLoader>,
        ids: Arc<dyn EntityIds>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            fs,
            index,
            schema,
            ids,
            clock,
            events: None,
            reducer: None,
            locks: Mutex::new(HashMap::new()),
            idempotency: Mutex::new(Vec::new()),
        }
    }

    pub fn with_events(mut self, events: Arc<dyn EventBusEmit>) -> Self {
        self.events = Some(events);
        self
    }

    pub fn with_reducer(mut self, reducer: Arc<dyn PureReducer>) -> Self {
        self.reducer = Some(reducer);
        self
    }

    pub fn schema_loader(&self) -> Arc<MetaSchemaLoader> {
        Arc::clone(&self.schema)
    }

    pub fn index(&self) -> Arc<dyn EntityIndex> {
        Arc::clone(&self.index)
    }

    fn schema(&self) -> Arc<MetaSchema> {
        self.schema.current()
    }

    fn lock_for(&self, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(locks.entry(path.to_string()).or_default())
    }

    async fn read_doc(
        &self,
        agent: &str,
        path: &str,
    ) -> Result<(FrontmatterDoc, Vec<u8>), DataError> {
        let bytes = self
            .fs
            .read(agent, path)
            .await?
            .ok_or_else(|| DataError::NotFound(path.to_string()))?;
        let (doc, offset) = parse_frontmatter(&bytes)?
            .ok_or_else(|| DataError::Invalid(format!("{path}: no frontmatter block")))?;
        Ok((doc, bytes[offset..].to_vec()))
    }

    fn render(&self, doc: &FrontmatterDoc, body: &[u8], schema: &MetaSchema) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 256);
        out.extend_from_slice(b"---\n");
        out.extend_from_slice(canonicalize(doc, schema).as_bytes());
        out.extend_from_slice(b"---\n");
        out.extend_from_slice(body);
        out
    }

    /// The transaction tail shared by every write: normalize against the previous document,
    /// write + commit, replace the path's rows, emit ONE event. Returns the projected rows.
    #[allow(clippy::too_many_arguments)]
    async fn commit_doc(
        &self,
        agent: &str,
        path: &str,
        mut doc: FrontmatterDoc,
        previous: Option<&FrontmatterDoc>,
        body: &[u8],
        op: &str,
        touched: &[EntityId],
    ) -> Result<(Vec<EntityRow>, Option<String>), DataError> {
        let schema = self.schema();
        let now = self.clock.now();
        let mut ids = IdsAdapter(self.ids.as_ref());
        normalize_doc(&mut doc, previous, &schema, &mut ids, now)?;
        let bytes = self.render(&doc, body, &schema);
        let receipt = self
            .fs
            .write(agent, path, &bytes, &commit_message(op, path))
            .await?;
        let rows = project_entities(&doc, &schema, agent, path, now);
        self.index
            .replace_path(agent, path, rows.clone())
            .await
            .map_err(|e| DataError::Io(e.to_string()))?;
        self.emit(agent, path, op, touched, receipt.commit.as_deref());
        Ok((rows, receipt.commit))
    }

    fn emit(&self, agent: &str, path: &str, op: &str, touched: &[EntityId], commit: Option<&str>) {
        let Some(bus) = &self.events else { return };
        let ids: Vec<&str> = touched.iter().map(|t| t.0.as_str()).collect();
        bus.emit(Event::observability(
            ENTITY_CHANGED_EVENT,
            agent,
            json!({
                "agent_id": agent,
                "path": path,
                "entity_id": ids.first().copied().unwrap_or_default(),
                "entity_ids": ids,
                "op": op,
                "kind": "record",
                "commit": commit,
            }),
            None,
        ));
    }

    // ── describe ────────────────────────────────────────────────────────────────────────────

    /// The merged schema for `agent`, with each operation's `available` flag taken from the
    /// wired reducer (no reducer ⇒ every operation is unavailable).
    pub async fn describe(&self, agent: &str) -> SchemaDescription {
        self.describe_async(agent).await
    }

    /// `describe` with an availability oracle for operation tools (sync callers).
    pub fn describe_with(&self, available: impl Fn(&str) -> bool) -> SchemaDescription {
        let schema = self.schema();
        let aspects = schema
            .aspects
            .iter()
            .map(|(name, a)| AspectDescription {
                name: name.clone(),
                key: a.key.clone(),
                fields: a.fields.iter().map(|(n, f)| describe_field(n, f)).collect(),
                queries: a
                    .queries
                    .iter()
                    .map(|(n, q)| QueryDescription {
                        name: n.clone(),
                        args: q
                            .args
                            .iter()
                            .map(|(k, t)| (k.clone(), type_name(t)))
                            .collect(),
                    })
                    .collect(),
                views: a
                    .views
                    .iter()
                    .map(|(n, v)| ViewDescription {
                        name: n.clone(),
                        kind: v.kind.as_str().to_string(),
                        query: v.query.clone(),
                        group_by: v.group_by.clone(),
                        columns: v.columns.clone(),
                    })
                    .collect(),
                operations: a
                    .operations
                    .iter()
                    .map(|(n, o)| {
                        let tool = format!("{SKILL_TOOL_PREFIX}{}", o.tool);
                        OperationDescription {
                            name: n.clone(),
                            available: available(&tool),
                            tool,
                            method: o.method.clone(),
                        }
                    })
                    .collect(),
            })
            .collect();
        SchemaDescription {
            hash: schema.schema_hash(),
            aspects,
        }
    }

    /// `describe` that consults the wired reducer for operation availability.
    pub async fn describe_async(&self, _agent: &str) -> SchemaDescription {
        let mut d = self.describe_with(|_| false);
        if let Some(r) = &self.reducer {
            for a in &mut d.aspects {
                for o in &mut a.operations {
                    o.available = r.available(&o.tool).await;
                }
            }
        }
        d
    }

    // ── reads ───────────────────────────────────────────────────────────────────────────────

    pub async fn get(&self, agent: &str, target: Target) -> Result<EntityRow, DataError> {
        match &target {
            Target::Anchored { id, .. } => self
                .index
                .get(agent, id)
                .await
                .map_err(|e| DataError::Io(e.to_string()))?
                .ok_or_else(|| DataError::NotFound(target.render())),
            Target::Path(path) => {
                let (doc, _) = self.read_doc(agent, path).await?;
                let schema = self.schema();
                let rows = project_entities(&doc, &schema, agent, path, self.clock.now());
                rows.into_iter()
                    .next()
                    .ok_or_else(|| DataError::NotFound(format!("{path}: record has no id")))
            }
        }
    }

    pub async fn query(&self, agent: &str, req: QueryRequest) -> Result<Vec<EntityRow>, DataError> {
        let (q, post) = match req {
            QueryRequest::AdHoc(q) => {
                if q.agent_id != agent {
                    return Err(DataError::Forbidden(
                        "query agent does not match caller".into(),
                    ));
                }
                (q, Vec::new())
            }
            QueryRequest::Named { name, args } => self.compile_query(agent, &name, &args)?,
        };
        if q.limit == 0 || q.limit > MAX_ENTITY_QUERY_LIMIT {
            return Err(DataError::Invalid(format!(
                "limit must be 1..={MAX_ENTITY_QUERY_LIMIT}"
            )));
        }
        let rows = self.index.query(&q).await.map_err(|e| match e {
            advance_shared_types::entity::EntityIndexError::InvalidQuery(m) => {
                DataError::Invalid(m)
            }
            other => DataError::Io(other.to_string()),
        })?;
        if post.is_empty() {
            return Ok(rows);
        }
        Ok(rows
            .into_iter()
            .filter(|r| {
                post.iter()
                    .all(|(field, clause)| where_holds(r, field, clause))
            })
            .collect())
    }

    /// Named query → `EntityQuery` + in-memory post-filters (for `where` fields the index does
    /// not promote).
    fn compile_query(
        &self,
        agent: &str,
        name: &str,
        args: &Value,
    ) -> Result<(EntityQuery, Vec<(String, ResolvedClause)>), DataError> {
        let schema = self.schema();
        let (aspect_name, spec): (&str, &QuerySpec) = schema
            .aspects
            .iter()
            .find_map(|(a, s)| s.queries.get(name).map(|q| (a.as_str(), q)))
            .ok_or_else(|| DataError::Invalid(format!("unknown query {name:?}")))?;
        let args_map: BTreeMap<String, Yaml> = match args {
            Value::Object(m) => m
                .iter()
                .map(|(k, v)| (k.clone(), json_to_yaml(v)))
                .collect(),
            Value::Null => BTreeMap::new(),
            _ => return Err(DataError::Invalid("query args must be an object".into())),
        };
        for (aname, atype) in &spec.args {
            let v = args_map.get(aname).ok_or_else(|| {
                DataError::Invalid(format!("query {name}: missing argument {aname:?}"))
            })?;
            if !cap_fs::frontmatter::value_matches(atype, v) {
                return Err(DataError::Invalid(format!(
                    "query {name}: argument {aname:?} is not a {}",
                    type_name(atype)
                )));
            }
        }
        let now = self.clock.now();
        let empty = Mapping::new();
        let eval = |e: &ValueExpr| -> Result<Yaml, DataError> {
            eval_expr(e, now, &empty, &args_map)
                .map_err(|m| DataError::Invalid(format!("query {name}: {m}")))
        };
        let window = |w: &Option<(ValueExpr, ValueExpr)>| -> Result<Option<(DateTime<Utc>, DateTime<Utc>)>, DataError> {
            match w {
                None => Ok(None),
                Some((a, b)) => {
                    let a = eval(a)?;
                    let b = eval(b)?;
                    let a = a
                        .as_str()
                        .and_then(parse_datetime)
                        .ok_or_else(|| DataError::Invalid(format!("query {name}: window start is not a datetime")))?;
                    let b = b
                        .as_str()
                        .and_then(parse_datetime)
                        .ok_or_else(|| DataError::Invalid(format!("query {name}: window end is not a datetime")))?;
                    Ok(Some((a, b)))
                }
            }
        };
        let mut q = EntityQuery::for_agent(agent);
        q.aspect = Some(aspect_name.to_string());
        q.due_between = window(&spec.due_between)?;
        q.occurs_between = window(&spec.occurs_between)?;
        q.any_between = window(&spec.any_between)?;
        q.order = spec
            .order
            .iter()
            .map(|o| OrderKey {
                field: o.field.clone(),
                ascending: o.ascending,
            })
            .collect();
        q.limit = DEFAULT_ENTITY_QUERY_LIMIT;
        let mut post = Vec::new();
        for (field, clause) in &spec.where_ {
            let resolved = match clause {
                WhereClause::Eq(v) => ResolvedClause::Eq(yaml_to_json(v)),
                WhereClause::In(vs) => ResolvedClause::In(vs.iter().map(yaml_to_json).collect()),
                WhereClause::Cmp(op, e) => ResolvedClause::Cmp(*op, yaml_to_json(&eval(e)?)),
            };
            match (field.as_str(), &resolved) {
                ("status", ResolvedClause::In(vs)) => {
                    q.status = Some(
                        vs.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect(),
                    );
                }
                ("status", ResolvedClause::Eq(v)) => {
                    q.status = Some(vec![v.as_str().unwrap_or_default().to_string()]);
                }
                ("type", ResolvedClause::Eq(v)) => q.r#type = v.as_str().map(str::to_string),
                _ => post.push((field.clone(), resolved)),
            }
        }
        Ok((q, post))
    }

    pub async fn history(
        &self,
        agent: &str,
        target: Target,
        limit: usize,
    ) -> Result<Vec<RecordVersion>, DataError> {
        let limit = limit.clamp(1, 200);
        let versions = self.fs.history(agent, target.path(), limit * 4).await?;
        let mut out: Vec<RecordVersion> = Vec::new();
        for v in versions {
            let Ok(Some((doc, _))) = parse_frontmatter(&v.bytes) else {
                continue;
            };
            let record = match &target {
                Target::Path(_) => Some(&doc.fields),
                Target::Anchored { id, .. } => doc.item(&id.0),
            };
            let Some(record) = record else { continue };
            let json = mapping_to_json(record);
            if out.last().map(|l| l.record == json).unwrap_or(false) {
                continue;
            }
            out.push(RecordVersion {
                commit: v.commit,
                op: op_from_message(&v.message),
                record: json,
            });
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    // ── writes ──────────────────────────────────────────────────────────────────────────────

    pub async fn create(
        &self,
        agent: &str,
        parent: Target,
        record: Record,
    ) -> Result<EntityId, DataError> {
        let Target::Path(parent_path) = parent else {
            return Err(DataError::Invalid(
                "create parent must be a file path".into(),
            ));
        };
        if record.0.contains_key("items") {
            return Err(DataError::Invalid("a record cannot carry `items`".into()));
        }
        let lock = self.lock_for(&parent_path);
        let _guard = lock.lock().await;
        let (prev, body) = self.read_doc(agent, &parent_path).await?;
        if prev.items.len() >= MAX_ITEMS_PER_FILE {
            return Err(DataError::PromoteRequired {
                path: parent_path,
                items: prev.items.len(),
            });
        }
        let mut doc = prev.clone();
        let mut item = json_map_to_yaml(&record.0);
        if !item.contains_key(Yaml::String("id".into())) {
            item.insert(Yaml::String("id".into()), Yaml::String(self.ids.next_id()));
        }
        let id = EntityId(
            item.get(Yaml::String("id".into()))
                .and_then(Yaml::as_str)
                .unwrap_or_default()
                .to_string(),
        );
        doc.items.push(item);
        self.commit_doc(
            agent,
            &parent_path,
            doc,
            Some(&prev),
            &body,
            "create",
            &[id.clone()],
        )
        .await?;
        Ok(id)
    }

    pub async fn patch(
        &self,
        agent: &str,
        target: Target,
        ops: Vec<PatchOp>,
    ) -> Result<EntityRow, DataError> {
        if ops.is_empty() {
            return Err(DataError::Invalid("patch needs at least one op".into()));
        }
        let path = target.path().to_string();
        let lock = self.lock_for(&path);
        let _guard = lock.lock().await;
        let (prev, body) = self.read_doc(agent, &path).await?;
        let mut doc = prev.clone();
        let record = record_mut(&mut doc, &target)?;
        for op in &ops {
            match op {
                PatchOp::Set(field, value) => {
                    check_patch_field(field)?;
                    record.insert(Yaml::String(field.clone()), json_to_yaml(value));
                }
                PatchOp::Unset(field) => {
                    check_patch_field(field)?;
                    record.remove(Yaml::String(field.clone()));
                }
            }
        }
        let id = record_id(&doc, &target)?;
        let (rows, _) = self
            .commit_doc(
                agent,
                &path,
                doc,
                Some(&prev),
                &body,
                "patch",
                &[id.clone()],
            )
            .await?;
        rows.into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| DataError::Io("patched record missing from projection".into()))
    }

    pub async fn promote(
        &self,
        agent: &str,
        target: Target,
        to: Tier,
    ) -> Result<Target, DataError> {
        match (&target, to) {
            (Target::Anchored { path, id }, Tier::File) => self.promote_item(agent, path, id).await,
            (Target::Path(path), Tier::Dir) => self.promote_file_to_dir(agent, path).await,
            (Target::Path(_), Tier::File) => {
                Err(DataError::Invalid("a file is already a file".into()))
            }
            (Target::Anchored { .. }, Tier::Dir) => {
                Err(DataError::Invalid("promote an item to a file first".into()))
            }
        }
    }

    async fn promote_item(
        &self,
        agent: &str,
        parent_path: &str,
        id: &EntityId,
    ) -> Result<Target, DataError> {
        let lock = self.lock_for(parent_path);
        let _guard = lock.lock().await;
        let (prev, body) = self.read_doc(agent, parent_path).await?;
        let item = prev
            .item(&id.0)
            .cloned()
            .ok_or_else(|| DataError::NotFound(format!("{parent_path}#{}", id.0)))?;
        // The child lives in the parent's container: beside `dir/launch.md` (as
        // `dir/<slug>.md`) or, when the parent is a directory entity `dir/launch/index.md`,
        // inside that directory. Turning a file into a directory entity is the separate
        // `promote(file, Tier::Dir)`.
        let container_dir = match cap_fs::entity_projection::dir_of_index(parent_path) {
            Some(dir) => dir,
            None => parent_path
                .rsplit_once('/')
                .map(|(d, _)| d.to_string())
                .unwrap_or_default(),
        };
        let parent_new_path = parent_path.to_string();
        let child_name = format!("{}.md", slug_of(&item).unwrap_or_else(|| id.0.clone()));
        let child_path = if container_dir.is_empty() {
            child_name
        } else {
            format!("{container_dir}/{child_name}")
        };
        if child_path == parent_new_path || self.fs.read(agent, &child_path).await?.is_some() {
            return Err(DataError::Invalid(format!("{child_path} already exists")));
        }
        // Child file: the item's record as its frontmatter, plus a `parent` back-reference.
        let mut child_fields = item.clone();
        child_fields.insert(
            Yaml::String("parent".into()),
            Yaml::String(parent_new_path.clone()),
        );
        let child_doc = FrontmatterDoc {
            fields: child_fields,
            items: Vec::new(),
        };
        let (child_rows, _) = self
            .commit_doc(
                agent,
                &child_path,
                child_doc,
                None,
                b"",
                "promote",
                &[id.clone()],
            )
            .await?;
        // Parent keeps a stub `{id, ref}`.
        let mut doc = prev.clone();
        for it in &mut doc.items {
            if it.get(Yaml::String("id".into())).and_then(Yaml::as_str) == Some(id.0.as_str()) {
                let mut stub = Mapping::new();
                stub.insert(Yaml::String("id".into()), Yaml::String(id.0.clone()));
                stub.insert(
                    Yaml::String("type".into()),
                    it.get(Yaml::String("type".into()))
                        .cloned()
                        .unwrap_or(Yaml::String("ref".into())),
                );
                stub.insert(
                    Yaml::String("ref".into()),
                    Yaml::String(format!("./{}", child_name_of(&child_path))),
                );
                *it = stub;
            }
        }
        self.commit_doc(
            agent,
            &parent_new_path,
            doc,
            Some(&prev),
            &body,
            "promote",
            &[id.clone()],
        )
        .await?;
        let _ = child_rows;
        Ok(Target::Path(child_path))
    }

    async fn promote_file_to_dir(&self, agent: &str, path: &str) -> Result<Target, DataError> {
        if cap_fs::entity_projection::dir_of_index(path).is_some() {
            return Err(DataError::Invalid("already a directory entity".into()));
        }
        let lock = self.lock_for(path);
        let _guard = lock.lock().await;
        let (prev, body) = self.read_doc(agent, path).await?;
        let stem = path.strip_suffix(".md").unwrap_or(path).to_string();
        let new_path = format!("{stem}/index.md");
        let message = commit_message("promote", path);
        self.fs.rename(agent, path, &new_path, &message).await?;
        self.index
            .delete_path(agent, path)
            .await
            .map_err(|e| DataError::Io(e.to_string()))?;
        let id = EntityId(prev.id().unwrap_or_default().to_string());
        self.commit_doc(
            agent,
            &new_path,
            prev.clone(),
            Some(&prev),
            &body,
            "promote",
            &[id],
        )
        .await?;
        Ok(Target::Path(new_path))
    }

    pub async fn demote(&self, agent: &str, target: Target) -> Result<Target, DataError> {
        let Target::Path(child_path) = target else {
            return Err(DataError::Invalid("demote takes a file path".into()));
        };
        let child_lock = self.lock_for(&child_path);
        let _child_guard = child_lock.lock().await;
        let (child, _) = self.read_doc(agent, &child_path).await?;
        if !child.items.is_empty() {
            return Err(DataError::Invalid(
                "a file with inline items cannot be demoted".into(),
            ));
        }
        let parent_path = child
            .fields
            .get(Yaml::String("parent".into()))
            .and_then(Yaml::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                DataError::Invalid(format!("{child_path} has no `parent` back-reference"))
            })?;
        let id = EntityId(child.id().unwrap_or_default().to_string());
        let parent_lock = self.lock_for(&parent_path);
        let _parent_guard = parent_lock.lock().await;
        let (prev, body) = self.read_doc(agent, &parent_path).await?;
        let mut record = child.fields.clone();
        record.remove(Yaml::String("parent".into()));
        let mut doc = prev.clone();
        let mut replaced = false;
        for it in &mut doc.items {
            if it.get(Yaml::String("id".into())).and_then(Yaml::as_str) == Some(id.0.as_str()) {
                *it = record.clone();
                replaced = true;
            }
        }
        if !replaced {
            if doc.items.len() >= MAX_ITEMS_PER_FILE {
                return Err(DataError::PromoteRequired {
                    path: parent_path,
                    items: doc.items.len(),
                });
            }
            doc.items.push(record);
        }
        let message = commit_message("demote", &child_path);
        self.fs.remove(agent, &child_path, &message).await?;
        self.index
            .delete_path(agent, &child_path)
            .await
            .map_err(|e| DataError::Io(e.to_string()))?;
        self.commit_doc(
            agent,
            &parent_path,
            doc,
            Some(&prev),
            &body,
            "demote",
            &[id.clone()],
        )
        .await?;
        Ok(Target::Anchored {
            path: parent_path,
            id,
        })
    }

    // ── apply ───────────────────────────────────────────────────────────────────────────────

    pub async fn apply(
        &self,
        agent: &str,
        op: &str,
        target: Target,
        args: Value,
        key: Option<IdempotencyKey>,
    ) -> Result<ApplyResult, DataError> {
        let request_hash = hash_request(agent, op, &target, &args);
        if let Some(k) = &key {
            if let Some(hit) = self.idempotency_lookup(agent, k) {
                if hit.request_hash != request_hash {
                    return Err(DataError::Invalid(format!(
                        "idempotency key {:?} was used for a different request",
                        k.0
                    )));
                }
                return Ok(hit.result);
            }
        }
        let schema = self.schema();
        let binding = schema
            .aspects
            .values()
            .find_map(|a| a.operations.get(op))
            .ok_or_else(|| DataError::OpUnavailable(format!("unknown operation {op:?}")))?;
        let tool_id = format!("{SKILL_TOOL_PREFIX}{}", binding.tool);
        let reducer = self
            .reducer
            .as_ref()
            .ok_or_else(|| DataError::OpUnavailable(format!("{op}: no reducer wired")))?;
        if !reducer.available(&tool_id).await {
            return Err(DataError::OpUnavailable(format!(
                "{op}: tool {tool_id} is not registered"
            )));
        }

        let path = target.path().to_string();
        let lock = self.lock_for(&path);
        let _guard = lock.lock().await;
        let (prev, body) = self.read_doc(agent, &path).await?;
        let self_record = match &target {
            Target::Path(_) => prev.fields.clone(),
            Target::Anchored { id, .. } => prev
                .item(&id.0)
                .cloned()
                .ok_or_else(|| DataError::NotFound(target.render()))?,
        };
        let parent_record = match &target {
            Target::Path(_) => None,
            Target::Anchored { .. } => Some(mapping_to_json(&prev.fields)),
        };
        let now = self.clock.now();
        let ids: Vec<String> = (0..IDS_PER_APPLY).map(|_| self.ids.next_id()).collect();
        let input = json!({
            "op": op,
            "target": target.render(),
            "self": mapping_to_json(&self_record),
            "parent": parent_record,
            "args": args,
            "now": format_datetime(now),
            "ids": ids,
        });
        let input_bytes = serde_json::to_vec(&input).map_err(|e| DataError::Io(e.to_string()))?;
        if input_bytes.len() > MAX_REDUCER_INPUT_BYTES {
            return Err(DataError::Invalid(
                "reducer input exceeds the size cap".into(),
            ));
        }
        let seed = {
            let mut h = Sha256::new();
            h.update(key.as_ref().map(|k| k.0.as_bytes()).unwrap_or(&input_bytes));
            let d = h.finalize();
            u64::from_le_bytes(d[..8].try_into().unwrap_or([0; 8]))
        };
        let output = reducer
            .reduce(
                &tool_id,
                &binding.method,
                &input_bytes,
                DeterministicCtx { now, seed },
            )
            .await
            .map_err(|e| DataError::Io(format!("{op}: reducer: {e}")))?;
        let parsed = ReducerOutput::parse(&output).map_err(DataError::Invalid)?;
        if let Some(reason) = parsed.error {
            return Err(DataError::PreconditionFailed {
                op: op.to_string(),
                reason,
            });
        }

        // Apply the effects to an in-memory copy; every target must be this file.
        let mut doc = prev.clone();
        let mut touched: Vec<EntityId> = Vec::new();
        let self_id = record_id(&prev, &target)?;
        touched.push(self_id.clone());
        let mut created: Vec<EntityId> = Vec::new();
        for effect in parsed.effects {
            match effect {
                Effect::Set {
                    target: t,
                    field,
                    value,
                } => {
                    let t = Target::parse(&t)?;
                    check_effect_target(&t, &path)?;
                    check_patch_field(&field)?;
                    let rec = record_mut(&mut doc, &t)?;
                    rec.insert(Yaml::String(field), json_to_yaml(&value));
                    touched.push(record_id(&doc, &t)?);
                }
                Effect::Unset { target: t, field } => {
                    let t = Target::parse(&t)?;
                    check_effect_target(&t, &path)?;
                    check_patch_field(&field)?;
                    let rec = record_mut(&mut doc, &t)?;
                    rec.remove(Yaml::String(field));
                    touched.push(record_id(&doc, &t)?);
                }
                Effect::Create { parent, record } => {
                    let parent = normalize_path(&parent)?;
                    if parent != path {
                        return Err(DataError::Forbidden(format!(
                            "effect creates under {parent}, outside the transaction's file {path}"
                        )));
                    }
                    if doc.items.len() >= MAX_ITEMS_PER_FILE {
                        return Err(DataError::PromoteRequired {
                            path: path.clone(),
                            items: doc.items.len(),
                        });
                    }
                    let Value::Object(m) = record else {
                        return Err(DataError::Invalid(
                            "create effect record must be an object".into(),
                        ));
                    };
                    let mut item = json_map_to_yaml(&m);
                    if !item.contains_key(Yaml::String("id".into())) {
                        item.insert(Yaml::String("id".into()), Yaml::String(self.ids.next_id()));
                    }
                    let id = EntityId(
                        item.get(Yaml::String("id".into()))
                            .and_then(Yaml::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    );
                    created.push(id.clone());
                    touched.push(id);
                    doc.items.push(item);
                }
                Effect::Promote { .. } | Effect::Demote { .. } => {
                    return Err(DataError::Invalid(
                        "promote / demote effects are not supported inside apply yet".into(),
                    ));
                }
            }
        }
        touched.dedup();
        let (rows, commit) = self
            .commit_doc(agent, &path, doc, Some(&prev), &body, op, &touched)
            .await?;
        let rows: Vec<EntityRow> = rows
            .into_iter()
            .filter(|r| touched.contains(&r.id))
            .collect();
        let result = ApplyResult {
            op: op.to_string(),
            rows,
            commit,
        };
        if let Some(k) = key {
            self.idempotency_store(agent, k, request_hash, result.clone());
        }
        Ok(result)
    }

    fn idempotency_lookup(&self, agent: &str, key: &IdempotencyKey) -> Option<IdemEntry> {
        let table = self.idempotency.lock().unwrap_or_else(|p| p.into_inner());
        let k = format!("{agent}\u{1f}{}", key.0);
        table
            .iter()
            .find(|(kk, _)| *kk == k)
            .map(|(_, e)| e.clone())
    }

    fn idempotency_store(
        &self,
        agent: &str,
        key: IdempotencyKey,
        request_hash: String,
        result: ApplyResult,
    ) {
        let mut table = self.idempotency.lock().unwrap_or_else(|p| p.into_inner());
        if table.len() >= MAX_IDEMPOTENCY_ENTRIES {
            table.remove(0);
        }
        table.push((
            format!("{agent}\u{1f}{}", key.0),
            IdemEntry {
                request_hash,
                result,
            },
        ));
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────────────────────

fn commit_message(op: &str, path: &str) -> String {
    format!("data: {op} {path}\n\n{OP_TRAILER}: {op}\n")
}

fn op_from_message(message: &str) -> Option<String> {
    message.lines().find_map(|l| {
        l.strip_prefix(&format!("{OP_TRAILER}: "))
            .map(|s| s.trim().to_string())
    })
}

fn hash_request(agent: &str, op: &str, target: &Target, args: &Value) -> String {
    let mut h = Sha256::new();
    h.update(agent.as_bytes());
    h.update([0x1f]);
    h.update(op.as_bytes());
    h.update([0x1f]);
    h.update(target.render().as_bytes());
    h.update([0x1f]);
    h.update(serde_json::to_vec(args).unwrap_or_default());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn check_patch_field(field: &str) -> Result<(), DataError> {
    if field == "id" || field == "items" {
        return Err(DataError::Invalid(format!(
            "field {field:?} cannot be patched"
        )));
    }
    if field.is_empty()
        || field.len() > 64
        || !field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(DataError::Invalid(format!("bad field name {field:?}")));
    }
    Ok(())
}

fn check_effect_target(t: &Target, path: &str) -> Result<(), DataError> {
    if t.path() != path {
        return Err(DataError::Forbidden(format!(
            "effect targets {}, outside the transaction's file {path}",
            t.render()
        )));
    }
    Ok(())
}

fn record_mut<'a>(
    doc: &'a mut FrontmatterDoc,
    target: &Target,
) -> Result<&'a mut Mapping, DataError> {
    match target {
        Target::Path(_) => Ok(&mut doc.fields),
        Target::Anchored { id, .. } => doc
            .items
            .iter_mut()
            .find(|m| {
                m.get(Yaml::String("id".into())).and_then(Yaml::as_str) == Some(id.0.as_str())
            })
            .ok_or_else(|| DataError::NotFound(target.render())),
    }
}

fn record_id(doc: &FrontmatterDoc, target: &Target) -> Result<EntityId, DataError> {
    match target {
        Target::Path(p) => doc
            .id()
            .map(|s| EntityId(s.to_string()))
            .ok_or_else(|| DataError::Invalid(format!("{p}: record has no id"))),
        Target::Anchored { id, .. } => Ok(id.clone()),
    }
}

fn slug_of(record: &Mapping) -> Option<String> {
    let title = record.get(Yaml::String("title".into()))?.as_str()?;
    let mut out = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        None
    } else {
        Some(out.chars().take(48).collect())
    }
}

fn child_name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub(crate) fn json_to_yaml(v: &Value) -> Yaml {
    match v {
        Value::Null => Yaml::Null,
        Value::Bool(b) => Yaml::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Yaml::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                Yaml::Number(u.into())
            } else {
                Yaml::Number(n.as_f64().unwrap_or(0.0).into())
            }
        }
        Value::String(s) => Yaml::String(s.clone()),
        Value::Array(a) => Yaml::Sequence(a.iter().map(json_to_yaml).collect()),
        Value::Object(m) => Yaml::Mapping(json_map_to_yaml(m)),
    }
}

pub(crate) fn json_map_to_yaml(m: &serde_json::Map<String, Value>) -> Mapping {
    let mut out = Mapping::new();
    for (k, v) in m {
        out.insert(Yaml::String(k.clone()), json_to_yaml(v));
    }
    out
}

pub(crate) fn mapping_to_json(m: &Mapping) -> Value {
    let mut out = serde_json::Map::new();
    for (k, v) in m {
        if let Some(name) = k.as_str() {
            out.insert(name.to_string(), yaml_to_json(v));
        }
    }
    Value::Object(out)
}

fn type_name(t: &FieldType) -> String {
    match t {
        FieldType::String => "string".into(),
        FieldType::Integer => "integer".into(),
        FieldType::Boolean => "boolean".into(),
        FieldType::DateTime => "datetime".into(),
        FieldType::Duration => "duration".into(),
        FieldType::ListString => "list<string>".into(),
        FieldType::ListDateTime => "list<datetime>".into(),
        FieldType::EnumString(_) => "enum".into(),
    }
}

fn describe_field(name: &str, f: &FieldSpec) -> FieldDescription {
    FieldDescription {
        name: name.to_string(),
        r#type: type_name(&f.field_type),
        r#enum: match &f.field_type {
            FieldType::EnumString(v) => Some(v.clone()),
            _ => None,
        },
        default: f.default.as_ref().map(yaml_to_json),
        transitions: f.transitions.clone(),
        inherit: f.inherit,
        derived: f.derive.is_some(),
    }
}

/// A `where` clause with its expressions evaluated (post-filter form).
#[derive(Debug, Clone)]
pub enum ResolvedClause {
    Eq(Value),
    In(Vec<Value>),
    Cmp(cap_fs::meta_schema::Cmp, Value),
}

fn where_holds(row: &EntityRow, field: &str, clause: &ResolvedClause) -> bool {
    let value = match field {
        "title" => row.title.clone().map(Value::String),
        "type" => Some(Value::String(row.r#type.clone())),
        _ => row.fields.get(field).cloned(),
    };
    match clause {
        ResolvedClause::Eq(v) => value.as_ref() == Some(v),
        ResolvedClause::In(vs) => value.map(|v| vs.contains(&v)).unwrap_or(false),
        ResolvedClause::Cmp(op, bound) => {
            let (Some(a), Some(b)) = (
                value
                    .as_ref()
                    .and_then(|v| v.as_str())
                    .and_then(parse_datetime),
                bound.as_str().and_then(parse_datetime),
            ) else {
                return match (value.as_ref().and_then(Value::as_i64), bound.as_i64()) {
                    (Some(a), Some(b)) => op.holds(&a, &b),
                    _ => false,
                };
            };
            op.holds(&a, &b)
        }
    }
}
