//! CONTRACT-190 `schema` + `entities` families — the client-facing entity data surface
//! (entity-data lane E3).
//!
//! Routes (families `schema` and `entities`):
//! - `GET  /client/schema`                              the merged meta-schema (`Scope::ReadInventory`)
//! - `POST /client/entities:query`                      a named or ad-hoc query (`ReadInventory`; a
//!   POST *read* — the body carries the query, no idempotency key is needed)
//! - `GET  /client/entities/{agent_id}/{entity_id}`     one row (`ReadInventory`)
//! - `POST /client/entities:create`                     an inline item under a file (`WriteEntities`)
//! - `POST /client/entities/{entity_id}:patch`          set / unset fields (`WriteEntities`)
//! - `POST /client/entities/{entity_id}:apply`          a schema-declared logic operation (`WriteEntities`)
//! - `POST /client/entities/{entity_id}:promote`        item → file, file → directory (`WriteEntities`)
//! - `POST /client/entities/{entity_id}:demote`         the inverse (`WriteEntities`)
//!
//! Single-operator model: every request names the `agent_id` whose territory it reads or
//! writes (the operator may address any agent). The provider (the cli adapter over the `data`
//! store) runs the same host-owned transaction the `data` host tool runs for agents: schema
//! validation, transitions, derived fields, canonical write, commit, index update, one
//! `data.entity_changed` event. This family only projects shapes and validates the request
//! before the provider is consulted.
//!
//! Error projection (provider → client): unknown entity → `not_found`; an undeclared
//! transition, a failed operation precondition, or a container at its item cap →
//! `invalid_state`; a malformed record / op / target → `invalid_request`; a territory the agent
//! may not touch → `forbidden`; an operation whose tool is not installed → `module_unavailable`.

use std::collections::BTreeMap;

use advance_shared_types::entity::MAX_ENTITY_QUERY_LIMIT;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agents::validate_agent_id;
use crate::api::{ClientApi, HandlerCtx, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::provider::{provider_or_unavailable, EntityProviderSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// Bound on an entity id (`e-` + ULID / test counter).
pub const MAX_ENTITY_ID_LEN: usize = 64;
/// Bound on a workspace-relative path.
pub const MAX_ENTITY_PATH_LEN: usize = 4096;
/// Bound on a field / query / operation / aspect name.
pub const MAX_IDENTIFIER_LEN: usize = 64;
/// Bound on the number of ops in one patch.
pub const MAX_PATCH_OPS: usize = 64;
/// Bound on the number of `status` values in an ad-hoc filter.
pub const MAX_FILTER_STATUSES: usize = 32;
/// Bound on the number of `order` keys in an ad-hoc filter.
pub const MAX_ORDER_KEYS: usize = 4;

// ── Schema DTOs (CONTRACT-192 schema components) ─────────────────────────────────────────────

/// `GET /client/schema`: the merged meta-schema every client renders forms / boards /
/// calendars from. `hash` identifies the exact schema (sha256 of its canonical JSON).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientSchema {
    pub hash: String,
    /// Ordered by aspect name.
    pub aspects: Vec<ClientAspect>,
}

/// One aspect: a named bundle of fields, queries, views and operations a record gains when
/// any of its `key` fields is present.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAspect {
    pub name: String,
    pub key: Vec<String>,
    pub fields: Vec<ClientAspectField>,
    pub queries: Vec<ClientAspectQuery>,
    pub views: Vec<ClientAspectView>,
    pub operations: Vec<ClientAspectOperation>,
}

/// A declared field: its type (`string`, `integer`, `boolean`, `datetime`, `duration`, `enum`,
/// `list<string>`, `list<datetime>`), enum values, default, declared transitions
/// (`from → [to…]`), whether inline items inherit it from their file, and whether the host
/// derives it (a derived field is never written by a client).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAspectField {
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

/// A named query and the argument names / types it takes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAspectQuery {
    pub name: String,
    pub args: BTreeMap<String, String>,
}

/// A declared view: `kind` ∈ `list | table | board | calendar | form` (the GenUI catalog maps
/// each kind to one component), the query it renders, the board column field, the columns.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAspectView {
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    #[serde(default)]
    pub columns: Vec<String>,
}

/// A declared logic operation bound to a pack skill tool; `available` says whether the tool
/// is installed right now (`:apply` answers `module_unavailable` otherwise).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAspectOperation {
    pub name: String,
    pub tool: String,
    pub method: String,
    pub available: bool,
}

// ── Entity DTOs ──────────────────────────────────────────────────────────────────────────────

/// One entity row (a file record, an inline item, or a directory's `index.md`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientEntityRow {
    pub id: String,
    pub agent_id: String,
    /// Workspace-relative path of the file holding the record (an item: its parent file).
    pub path: String,
    /// The inline item's id inside `path`'s `items[]`; absent for a file / directory record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// `file | item | dir`.
    pub kind: String,
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The aspects the record has, sorted.
    pub aspects: Vec<String>,
    /// Every frontmatter field of the record (declared and free-form).
    pub fields: Value,
    /// RFC 3339.
    pub updated_at: String,
}

/// `POST /client/entities:query` result. `next_cursor` is reserved (the v1 provider answers a
/// bounded page and no cursor).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientEntityPage {
    pub rows: Vec<ClientEntityRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Where a record lives after a promote / demote: a path, plus the item id when inline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientEntityTarget {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
}

// ── Request DTOs ─────────────────────────────────────────────────────────────────────────────

/// A schema-declared named query with its arguments.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientNamedQuery {
    pub name: String,
    #[serde(default)]
    pub args: Value,
}

/// A half-open RFC 3339 window `[start, end)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEntityWindow {
    pub start: String,
    pub end: String,
}

/// One ordering key of an ad-hoc filter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientOrderKey {
    pub field: String,
    #[serde(default)]
    pub ascending: bool,
}

/// An ad-hoc filter (the projection's query surface): every clause is optional and ANDed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEntityFilter {
    /// Restrict to the inline items of this file entity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aspect: Option<String>,
    /// `status IN (…)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_between: Option<ClientEntityWindow>,
    /// Matched against the expanded occurrences (repeat-aware).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurs_between: Option<ClientEntityWindow>,
    /// `due_between` OR `occurs_between` on the same window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any_between: Option<ClientEntityWindow>,
    /// Empty = `updated_at` descending.
    #[serde(default)]
    pub order: Vec<ClientOrderKey>,
}

/// `POST /client/entities:query` body: a named query, an ad-hoc filter, or neither (every
/// entity of the agent, newest first). `limit` ≤ 1000 (default 100).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEntityQueryRequest {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<ClientNamedQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<ClientEntityFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// `POST /client/entities:create` body: a new inline item under the file at `parent`
/// (workspace-relative path); `record` is the item's fields (`id` is assigned by the host).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEntityCreateRequest {
    pub agent_id: String,
    pub parent: String,
    pub record: Value,
}

/// `{ "set": "<field>", "value": … }`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientPatchSet {
    pub set: String,
    pub value: Value,
}

/// `{ "unset": "<field>" }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientPatchUnset {
    pub unset: String,
}

/// One patch op.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ClientPatchOp {
    Set(ClientPatchSet),
    Unset(ClientPatchUnset),
}

impl ClientPatchOp {
    /// The field the op touches.
    pub fn field(&self) -> &str {
        match self {
            ClientPatchOp::Set(s) => &s.set,
            ClientPatchOp::Unset(u) => &u.unset,
        }
    }
}

/// `POST /client/entities/{entity_id}:patch` body.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEntityPatchRequest {
    pub agent_id: String,
    pub ops: Vec<ClientPatchOp>,
}

/// `POST /client/entities/{entity_id}:apply` body: a schema-declared operation and its
/// arguments (validated against the declaration by the host).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEntityApplyRequest {
    pub agent_id: String,
    pub op: String,
    #[serde(default)]
    pub args: Value,
}

/// `POST /client/entities/{entity_id}:promote` / `:demote` body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEntityAgentRequest {
    pub agent_id: String,
}

// ── Validation ───────────────────────────────────────────────────────────────────────────────

fn invalid(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, message)
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

/// `^e-[A-Za-z0-9_-]{1,62}$`.
pub fn validate_entity_id(id: &str) -> Result<(), ClientError> {
    let ok = id.len() > 2
        && id.len() <= MAX_ENTITY_ID_LEN
        && id.starts_with("e-")
        && id.chars().all(is_ident_char);
    if !ok {
        return Err(invalid("invalid entity id"));
    }
    Ok(())
}

/// A field / query / operation / aspect name: `^[A-Za-z0-9_-]{1,64}$`.
pub fn validate_identifier(name: &str) -> Result<(), ClientError> {
    if name.is_empty() || name.len() > MAX_IDENTIFIER_LEN || !name.chars().all(is_ident_char) {
        return Err(invalid("invalid identifier"));
    }
    Ok(())
}

/// A workspace-relative path: bounded, no NUL / control byte, no `..` segment, not absolute.
pub fn validate_entity_path(path: &str) -> Result<(), ClientError> {
    if path.is_empty()
        || path.len() > MAX_ENTITY_PATH_LEN
        || path.chars().any(|c| c.is_control())
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|seg| seg == "..")
    {
        return Err(invalid("invalid entity path"));
    }
    Ok(())
}

fn validate_window(w: &ClientEntityWindow) -> Result<(), ClientError> {
    let start = chrono::DateTime::parse_from_rfc3339(&w.start)
        .map_err(|_| invalid("invalid window timestamp"))?;
    let end = chrono::DateTime::parse_from_rfc3339(&w.end)
        .map_err(|_| invalid("invalid window timestamp"))?;
    if end < start {
        return Err(invalid("window end precedes start"));
    }
    Ok(())
}

/// Validate a query request: agent id, bounded limit, identifier-shaped names, RFC 3339
/// windows, bounded lists.
pub fn validate_query_request(req: &ClientEntityQueryRequest) -> Result<(), ClientError> {
    validate_agent_id(&req.agent_id)?;
    if let Some(limit) = req.limit {
        if limit == 0 || limit > MAX_ENTITY_QUERY_LIMIT {
            return Err(invalid("query limit out of bounds"));
        }
    }
    if let Some(q) = &req.query {
        validate_identifier(&q.name)?;
        if !q.args.is_object() && !q.args.is_null() {
            return Err(invalid("query args must be an object"));
        }
    }
    if let Some(f) = &req.filter {
        if let Some(parent) = &f.parent {
            validate_entity_id(parent)?;
        }
        if let Some(t) = &f.r#type {
            validate_identifier(t)?;
        }
        if let Some(a) = &f.aspect {
            validate_identifier(a)?;
        }
        if let Some(statuses) = &f.status {
            if statuses.len() > MAX_FILTER_STATUSES {
                return Err(invalid("too many status values"));
            }
            for s in statuses {
                validate_identifier(s)?;
            }
        }
        for w in [&f.due_between, &f.occurs_between, &f.any_between]
            .into_iter()
            .flatten()
        {
            validate_window(w)?;
        }
        if f.order.len() > MAX_ORDER_KEYS {
            return Err(invalid("too many order keys"));
        }
        for k in &f.order {
            validate_identifier(&k.field)?;
        }
    }
    Ok(())
}

/// Validate a create request: agent id, parent path, an object record without `items`.
pub fn validate_create_request(req: &ClientEntityCreateRequest) -> Result<(), ClientError> {
    validate_agent_id(&req.agent_id)?;
    validate_entity_path(&req.parent)?;
    let Some(obj) = req.record.as_object() else {
        return Err(invalid("record must be an object"));
    };
    if obj.contains_key("items") {
        return Err(invalid("a record cannot carry items"));
    }
    for key in obj.keys() {
        validate_identifier(key)?;
    }
    Ok(())
}

/// Validate a patch request: agent id, bounded ops, identifier-shaped fields (`id` / `items`
/// are never patchable).
pub fn validate_patch_request(req: &ClientEntityPatchRequest) -> Result<(), ClientError> {
    validate_agent_id(&req.agent_id)?;
    if req.ops.len() > MAX_PATCH_OPS {
        return Err(invalid("too many patch ops"));
    }
    for op in &req.ops {
        validate_identifier(op.field())?;
        if matches!(op.field(), "id" | "items") {
            return Err(invalid("field is not patchable"));
        }
    }
    Ok(())
}

/// Validate an apply request: agent id, identifier-shaped op, object args.
pub fn validate_apply_request(req: &ClientEntityApplyRequest) -> Result<(), ClientError> {
    validate_agent_id(&req.agent_id)?;
    validate_identifier(&req.op)?;
    if !req.args.is_object() && !req.args.is_null() {
        return Err(invalid("op args must be an object"));
    }
    Ok(())
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, ClientError> {
    if !body.is_object() {
        return Err(invalid("invalid entity request body"));
    }
    serde_json::from_value(body.clone()).map_err(|_| invalid("invalid entity request body"))
}

/// Mark the irreversible provider-entry boundary (CONTRACT-190 reserve-before-execute): a
/// write commits to the workspace, so a key never re-enters the provider.
fn mark_provider_entry(ctx: &HandlerCtx) -> Result<(), ClientError> {
    match ctx.mutation.as_ref() {
        Some(mutation) => mutation.mark_provider_entry(),
        None => Ok(()),
    }
}

fn entity_param(ctx: &HandlerCtx) -> Result<String, ClientError> {
    let id = ctx.path_param("entity_id")?;
    validate_entity_id(&id)?;
    Ok(id)
}

// ── Handlers ─────────────────────────────────────────────────────────────────────────────────

/// Register the schema + entities routes, capturing the shared provider slot so a builder can
/// inject the concrete provider AFTER registration. Routes are always registered; an absent
/// provider yields `module_unavailable` (never `unknown_route`).
pub(crate) fn register(api: &mut ClientApi, slot: EntityProviderSlot) {
    // GET /client/schema — the merged meta-schema.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_SCHEMA,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let schema = provider
                .describe()
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(schema).expect("ClientSchema serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // POST /client/entities:query — a read over POST (the body carries the query).
    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_ENTITIES_QUERY,
        HandlerSpec::read(true, move |ctx| {
            let req: ClientEntityQueryRequest = parse_body(&ctx.body)?;
            validate_query_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            let page = provider
                .query(&req)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(page).expect("ClientEntityPage serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // GET /client/entities/{agent_id}/{entity_id} — one row.
    let s = slot.clone();
    api.register_templated(
        Method::Get,
        routes::TPL_ENTITY_GET,
        HandlerSpec::read(true, move |ctx| {
            let agent_id = ctx.path_param("agent_id")?;
            validate_agent_id(&agent_id)?;
            let entity_id = entity_param(ctx)?;
            let provider = provider_or_unavailable(&s)?;
            let row = provider
                .get(&agent_id, &entity_id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(row).expect("ClientEntityRow serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // POST /client/entities:create — mutation (idempotency key + CSRF gated).
    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_ENTITIES_CREATE,
        HandlerSpec::mutation(true, move |ctx| {
            let req: ClientEntityCreateRequest = parse_body(&ctx.body)?;
            validate_create_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let row = provider
                .create(&req)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(row).expect("ClientEntityRow serializes"))
        })
        .with_scopes(vec![Scope::WriteEntities]),
    );

    // POST /client/entities/{entity_id}:patch — mutation.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_ENTITY_PATCH,
        HandlerSpec::mutation(true, move |ctx| {
            let entity_id = entity_param(ctx)?;
            let req: ClientEntityPatchRequest = parse_body(&ctx.body)?;
            validate_patch_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let row = provider
                .patch(&entity_id, &req)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(row).expect("ClientEntityRow serializes"))
        })
        .with_scopes(vec![Scope::WriteEntities]),
    );

    // POST /client/entities/{entity_id}:apply — mutation.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_ENTITY_APPLY,
        HandlerSpec::mutation(true, move |ctx| {
            let entity_id = entity_param(ctx)?;
            let req: ClientEntityApplyRequest = parse_body(&ctx.body)?;
            validate_apply_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let rows = provider
                .apply(&entity_id, &req)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(rows).expect("rows serialize"))
        })
        .with_scopes(vec![Scope::WriteEntities]),
    );

    // POST /client/entities/{entity_id}:promote — mutation.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_ENTITY_PROMOTE,
        HandlerSpec::mutation(true, move |ctx| {
            let entity_id = entity_param(ctx)?;
            let req: ClientEntityAgentRequest = parse_body(&ctx.body)?;
            validate_agent_id(&req.agent_id)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let target = provider
                .promote(&req.agent_id, &entity_id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(target).expect("ClientEntityTarget serializes"))
        })
        .with_scopes(vec![Scope::WriteEntities]),
    );

    // POST /client/entities/{entity_id}:demote — mutation.
    let s = slot;
    api.register_templated(
        Method::Post,
        routes::TPL_ENTITY_DEMOTE,
        HandlerSpec::mutation(true, move |ctx| {
            let entity_id = entity_param(ctx)?;
            let req: ClientEntityAgentRequest = parse_body(&ctx.body)?;
            validate_agent_id(&req.agent_id)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let target = provider
                .demote(&req.agent_id, &entity_id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(target).expect("ClientEntityTarget serializes"))
        })
        .with_scopes(vec![Scope::WriteEntities]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entity_id_grammar() {
        assert!(validate_entity_id("e-1").is_ok());
        assert!(validate_entity_id("e-01J9ABCDEF0123456789ABCDEF").is_ok());
        for bad in ["", "e-", "x-1", "e-a/b", "e-a b", "e-\u{0}", ".hidden"] {
            assert!(validate_entity_id(bad).is_err(), "{bad:?}");
        }
        assert!(validate_entity_id(&format!("e-{}", "x".repeat(62))).is_ok());
        assert!(validate_entity_id(&format!("e-{}", "x".repeat(63))).is_err());
    }

    #[test]
    fn path_grammar() {
        assert!(validate_entity_path("launch.md").is_ok());
        assert!(validate_entity_path("projects/launch/index.md").is_ok());
        for bad in ["", "/etc/passwd", "a/../b.md", "a\\b.md", "a\nb.md", ".."] {
            assert!(validate_entity_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn query_request_bounds() {
        let ok: ClientEntityQueryRequest = serde_json::from_value(json!({
            "agent_id": "alice",
            "filter": {
                "status": ["todo", "doing"],
                "any_between": { "start": "2026-09-21T00:00:00Z", "end": "2026-09-28T00:00:00Z" },
                "order": [{ "field": "due", "ascending": true }]
            },
            "limit": 50
        }))
        .unwrap();
        assert!(validate_query_request(&ok).is_ok());
        let mut bad = ok.clone();
        bad.limit = Some(0);
        assert!(validate_query_request(&bad).is_err());
        let mut bad = ok.clone();
        bad.limit = Some(MAX_ENTITY_QUERY_LIMIT + 1);
        assert!(validate_query_request(&bad).is_err());
        let mut bad = ok.clone();
        bad.filter.as_mut().unwrap().any_between = Some(ClientEntityWindow {
            start: "2026-09-28T00:00:00Z".into(),
            end: "2026-09-21T00:00:00Z".into(),
        });
        assert!(validate_query_request(&bad).is_err(), "reversed window");
        let mut bad = ok;
        bad.query = Some(ClientNamedQuery {
            name: "open items".into(),
            args: json!({}),
        });
        assert!(validate_query_request(&bad).is_err(), "query name shape");
        assert!(
            serde_json::from_value::<ClientEntityQueryRequest>(
                json!({ "agent_id": "a", "nope": 1 })
            )
            .is_err(),
            "unknown fields are rejected"
        );
    }

    #[test]
    fn patch_ops_parse_and_validate() {
        let req: ClientEntityPatchRequest = serde_json::from_value(json!({
            "agent_id": "alice",
            "ops": [{ "set": "status", "value": "done" }, { "unset": "due" }]
        }))
        .unwrap();
        assert_eq!(req.ops.len(), 2);
        assert_eq!(req.ops[0].field(), "status");
        assert!(matches!(req.ops[1], ClientPatchOp::Unset(_)));
        assert!(validate_patch_request(&req).is_ok());
        let id: ClientEntityPatchRequest = serde_json::from_value(json!({
            "agent_id": "alice",
            "ops": [{ "set": "id", "value": "e-9" }]
        }))
        .unwrap();
        assert!(validate_patch_request(&id).is_err(), "id is not patchable");
        assert!(
            serde_json::from_value::<ClientEntityPatchRequest>(json!({
                "agent_id": "alice",
                "ops": [{ "set": "status", "value": "done", "extra": 1 }]
            }))
            .is_err(),
            "unknown op keys are rejected"
        );
    }

    #[test]
    fn create_and_apply_requests() {
        let c: ClientEntityCreateRequest = serde_json::from_value(json!({
            "agent_id": "alice", "parent": "launch.md", "record": { "title": "t", "status": "todo" }
        }))
        .unwrap();
        assert!(validate_create_request(&c).is_ok());
        let nested = ClientEntityCreateRequest {
            record: json!({ "items": [] }),
            ..c.clone()
        };
        assert!(validate_create_request(&nested).is_err());
        let scalar = ClientEntityCreateRequest {
            record: json!("x"),
            ..c
        };
        assert!(validate_create_request(&scalar).is_err());
        let a: ClientEntityApplyRequest = serde_json::from_value(json!({
            "agent_id": "alice", "op": "detach_occurrence", "args": { "at": "2026-10-05T02:00:00Z" }
        }))
        .unwrap();
        assert!(validate_apply_request(&a).is_ok());
        let bad = ClientEntityApplyRequest {
            args: json!([1]),
            ..a
        };
        assert!(validate_apply_request(&bad).is_err());
    }
}
