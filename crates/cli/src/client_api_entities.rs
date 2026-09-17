//! CLI-served `EntityProvider` (CONTRACT-190 `schema` + `entities` families, entity-data lane
//! E3) over the ONE production `DataStore` the `data` host tool uses — a client write runs the
//! same host-owned transaction an agent write runs (schema validation, transitions, derived
//! fields, canonical write, commit, index update, one `data.entity_changed` event).
//!
//! Clients address records by entity id; the store addresses them by target (`path` /
//! `path#item`). The adapter resolves an id through the entity index (the projection the
//! store maintains), so an id the index does not know is `not_found` even when the file
//! exists — the index is rebuilt at boot and after every write.
//!
//! `ClientApi::handle()` is SYNC and may run on a tokio worker (the transport wraps it in
//! `spawn_blocking`); the store is async. Each call therefore runs on an OWNED current-thread
//! runtime on a scoped OS thread — never `Handle::block_on` (workspace clippy disallows it;
//! it panics on a worker).
//!
//! Limits of this first adapter: a named query's page size is the query's own bound (the
//! client `limit` only truncates), and `next_cursor` is never set.

use std::sync::Arc;

use advance_client_api::entities::{
    ClientAspect, ClientAspectField, ClientAspectOperation, ClientAspectQuery, ClientAspectView,
    ClientEntityApplyRequest, ClientEntityCreateRequest, ClientEntityPage,
    ClientEntityPatchRequest, ClientEntityQueryRequest, ClientEntityRow, ClientEntityTarget,
    ClientPatchOp, ClientSchema,
};
use advance_client_api::{EntityProvider, ProviderError};
use advance_shared_types::entity::{
    EntityId, EntityKind, EntityQuery, EntityRow, OrderKey, DEFAULT_ENTITY_QUERY_LIMIT,
};
use cap_data::{DataError, DataStore, PatchOp, QueryRequest, Record, Target, Tier};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;

/// The production `EntityProvider`.
pub struct WiredEntityProvider {
    store: Arc<DataStore>,
}

impl WiredEntityProvider {
    pub fn new(store: Arc<DataStore>) -> Self {
        Self { store }
    }

    /// Run an async store call on an owned current-thread runtime (see module docs).
    fn block_on<F>(fut: F) -> Result<F::Output, ProviderError>
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        std::thread::scope(|s| {
            s.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        ProviderError::Unavailable(format!(
                            "entity call: failed to build the owned runtime: {e}"
                        ))
                    })?;
                Ok(runtime.block_on(fut))
            })
            .join()
            .map_err(|_| ProviderError::Unavailable("entity call panicked".into()))?
        })
    }

    /// The index row for `entity_id` and the store target that addresses it.
    fn resolve(
        &self,
        agent_id: &str,
        entity_id: &str,
    ) -> Result<(EntityRow, Target), ProviderError> {
        let index = self.store.index();
        let id = EntityId(entity_id.to_string());
        let row = Self::block_on(async move { index.get(agent_id, &id).await })?
            .map_err(|e| ProviderError::Unavailable(format!("entity index: {e}")))?
            .ok_or_else(|| ProviderError::NotFound(entity_id.to_string()))?;
        let target = target_of(&row);
        Ok((row, target))
    }

    fn row_by_id(&self, agent_id: &str, id: &EntityId) -> Result<ClientEntityRow, ProviderError> {
        let index = self.store.index();
        let id_owned = id.clone();
        let row = Self::block_on(async move { index.get(agent_id, &id_owned).await })?
            .map_err(|e| ProviderError::Unavailable(format!("entity index: {e}")))?
            .ok_or_else(|| ProviderError::Unavailable(format!("entity {} not indexed", id.0)))?;
        Ok(row_dto(row))
    }
}

/// The store target of an index row: an inline item is `path#id`, a directory entity is its
/// `index.md`, a file record is its path.
fn target_of(row: &EntityRow) -> Target {
    match (&row.kind, &row.anchor) {
        (EntityKind::Item, Some(anchor)) => Target::Anchored {
            path: row.path.clone(),
            id: anchor.clone(),
        },
        (EntityKind::Dir, _) => {
            Target::Path(format!("{}/index.md", row.path.trim_end_matches('/')))
        }
        _ => Target::Path(row.path.clone()),
    }
}

fn kind_str(kind: &EntityKind) -> &'static str {
    match kind {
        EntityKind::File => "file",
        EntityKind::Item => "item",
        EntityKind::Dir => "dir",
    }
}

fn row_dto(row: EntityRow) -> ClientEntityRow {
    ClientEntityRow {
        id: row.id.0,
        agent_id: row.agent_id,
        path: row.path,
        anchor: row.anchor.map(|a| a.0),
        kind: kind_str(&row.kind).to_string(),
        r#type: row.r#type,
        title: row.title,
        aspects: row.aspects,
        fields: row.fields,
        updated_at: row.updated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn target_dto(t: Target) -> ClientEntityTarget {
    match t {
        Target::Path(path) => ClientEntityTarget { path, anchor: None },
        Target::Anchored { path, id } => ClientEntityTarget {
            path,
            anchor: Some(id.0),
        },
    }
}

fn map_err(e: DataError) -> ProviderError {
    match e {
        DataError::NotFound(m) => ProviderError::NotFound(m),
        DataError::Transition { field, from, to } => {
            ProviderError::InvalidState(format!("transition {field}: {from} -> {to}"))
        }
        DataError::PreconditionFailed { op, reason } => {
            ProviderError::InvalidState(format!("{op}: {reason}"))
        }
        DataError::PromoteRequired { path, items } => {
            ProviderError::InvalidState(format!("{path}: {items} inline items (promote first)"))
        }
        DataError::Invalid(m) => ProviderError::InvalidRequest(m),
        DataError::Forbidden(m) => ProviderError::Forbidden(m),
        DataError::OpUnavailable(m) | DataError::Io(m) => ProviderError::Unavailable(m),
    }
}

fn object_or_empty(v: &Value) -> Value {
    if v.is_object() {
        v.clone()
    } else {
        Value::Object(serde_json::Map::new())
    }
}

fn parse_window(
    w: &Option<advance_client_api::entities::ClientEntityWindow>,
) -> Result<Option<(DateTime<Utc>, DateTime<Utc>)>, ProviderError> {
    let Some(w) = w else { return Ok(None) };
    let parse = |s: &str| {
        DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|_| ProviderError::InvalidRequest(format!("bad timestamp {s:?}")))
    };
    Ok(Some((parse(&w.start)?, parse(&w.end)?)))
}

impl EntityProvider for WiredEntityProvider {
    fn describe(&self) -> Result<ClientSchema, ProviderError> {
        let store = Arc::clone(&self.store);
        let d = Self::block_on(async move { store.describe("client").await })?;
        Ok(ClientSchema {
            hash: d.hash,
            aspects: d
                .aspects
                .into_iter()
                .map(|a| ClientAspect {
                    name: a.name,
                    key: a.key,
                    fields: a
                        .fields
                        .into_iter()
                        .map(|f| ClientAspectField {
                            name: f.name,
                            r#type: f.r#type,
                            r#enum: f.r#enum,
                            default: f.default,
                            transitions: f.transitions,
                            inherit: f.inherit,
                            derived: f.derived,
                        })
                        .collect(),
                    queries: a
                        .queries
                        .into_iter()
                        .map(|q| ClientAspectQuery {
                            name: q.name,
                            args: q.args,
                        })
                        .collect(),
                    views: a
                        .views
                        .into_iter()
                        .map(|v| ClientAspectView {
                            name: v.name,
                            kind: v.kind,
                            query: v.query,
                            group_by: v.group_by,
                            columns: v.columns,
                        })
                        .collect(),
                    operations: a
                        .operations
                        .into_iter()
                        .map(|o| ClientAspectOperation {
                            name: o.name,
                            tool: o.tool,
                            method: o.method,
                            available: o.available,
                        })
                        .collect(),
                })
                .collect(),
        })
    }

    fn query(&self, request: &ClientEntityQueryRequest) -> Result<ClientEntityPage, ProviderError> {
        let limit = request.limit.unwrap_or(DEFAULT_ENTITY_QUERY_LIMIT);
        let req = match (&request.query, &request.filter) {
            (Some(q), _) => QueryRequest::named(&q.name, object_or_empty(&q.args)),
            (None, f) => {
                let mut eq = EntityQuery::for_agent(&request.agent_id);
                eq.limit = limit;
                if let Some(f) = f {
                    eq.parent = f.parent.clone().map(EntityId);
                    eq.r#type = f.r#type.clone();
                    eq.aspect = f.aspect.clone();
                    eq.status = f.status.clone();
                    eq.due_between = parse_window(&f.due_between)?;
                    eq.occurs_between = parse_window(&f.occurs_between)?;
                    eq.any_between = parse_window(&f.any_between)?;
                    eq.order = f
                        .order
                        .iter()
                        .map(|k| OrderKey {
                            field: k.field.clone(),
                            ascending: k.ascending,
                        })
                        .collect();
                }
                QueryRequest::ad_hoc(eq)
            }
        };
        let store = Arc::clone(&self.store);
        let agent = request.agent_id.clone();
        let rows =
            Self::block_on(async move { store.query(&agent, req).await })?.map_err(map_err)?;
        Ok(ClientEntityPage {
            rows: rows.into_iter().take(limit).map(row_dto).collect(),
            next_cursor: None,
        })
    }

    fn get(&self, agent_id: &str, entity_id: &str) -> Result<ClientEntityRow, ProviderError> {
        let (row, _) = self.resolve(agent_id, entity_id)?;
        Ok(row_dto(row))
    }

    fn create(
        &self,
        request: &ClientEntityCreateRequest,
    ) -> Result<ClientEntityRow, ProviderError> {
        let store = Arc::clone(&self.store);
        let agent = request.agent_id.clone();
        let parent = Target::Path(request.parent.clone());
        let record = Record::from_json(request.record.clone());
        let id = Self::block_on(async move { store.create(&agent, parent, record).await })?
            .map_err(map_err)?;
        self.row_by_id(&request.agent_id, &id)
    }

    fn patch(
        &self,
        entity_id: &str,
        request: &ClientEntityPatchRequest,
    ) -> Result<ClientEntityRow, ProviderError> {
        let (_, target) = self.resolve(&request.agent_id, entity_id)?;
        let ops: Vec<PatchOp> = request
            .ops
            .iter()
            .map(|op| match op {
                ClientPatchOp::Set(s) => PatchOp::Set(s.set.clone(), s.value.clone()),
                ClientPatchOp::Unset(u) => PatchOp::Unset(u.unset.clone()),
            })
            .collect();
        let store = Arc::clone(&self.store);
        let agent = request.agent_id.clone();
        let row = Self::block_on(async move { store.patch(&agent, target, ops).await })?
            .map_err(map_err)?;
        Ok(row_dto(row))
    }

    fn apply(
        &self,
        entity_id: &str,
        request: &ClientEntityApplyRequest,
    ) -> Result<Vec<ClientEntityRow>, ProviderError> {
        let (_, target) = self.resolve(&request.agent_id, entity_id)?;
        let store = Arc::clone(&self.store);
        let agent = request.agent_id.clone();
        let op = request.op.clone();
        let args = object_or_empty(&request.args);
        // The API layer already replays on the client's idempotency key; the store's own
        // table is for the `data` tool's agent callers.
        let result =
            Self::block_on(async move { store.apply(&agent, &op, target, args, None).await })?
                .map_err(map_err)?;
        Ok(result.rows.into_iter().map(row_dto).collect())
    }

    fn promote(
        &self,
        agent_id: &str,
        entity_id: &str,
    ) -> Result<ClientEntityTarget, ProviderError> {
        let (row, target) = self.resolve(agent_id, entity_id)?;
        let tier = match row.kind {
            EntityKind::Item => Tier::File,
            EntityKind::File => Tier::Dir,
            EntityKind::Dir => {
                return Err(ProviderError::InvalidState(
                    "a directory entity cannot be promoted".into(),
                ))
            }
        };
        let store = Arc::clone(&self.store);
        let agent = agent_id.to_string();
        let out = Self::block_on(async move { store.promote(&agent, target, tier).await })?
            .map_err(map_err)?;
        Ok(target_dto(out))
    }

    fn demote(&self, agent_id: &str, entity_id: &str) -> Result<ClientEntityTarget, ProviderError> {
        let (_, target) = self.resolve(agent_id, entity_id)?;
        let store = Arc::clone(&self.store);
        let agent = agent_id.to_string();
        let out =
            Self::block_on(async move { store.demote(&agent, target).await })?.map_err(map_err)?;
        Ok(target_dto(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(kind: EntityKind, anchor: Option<&str>) -> EntityRow {
        EntityRow {
            id: EntityId("e-1".into()),
            agent_id: "alice".into(),
            path: "projects/launch".into(),
            anchor: anchor.map(|a| EntityId(a.into())),
            parent: None,
            kind,
            r#type: "work-item".into(),
            title: None,
            aspects: vec![],
            status: None,
            due_at: None,
            starts_at: None,
            ends_at: None,
            priority: None,
            fields: Value::Object(serde_json::Map::new()),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn targets_follow_the_row_kind() {
        assert_eq!(
            target_of(&row(EntityKind::Item, Some("e-7"))),
            Target::Anchored {
                path: "projects/launch".into(),
                id: EntityId("e-7".into())
            }
        );
        assert_eq!(
            target_of(&row(EntityKind::Dir, None)),
            Target::Path("projects/launch/index.md".into())
        );
        assert_eq!(
            target_of(&row(EntityKind::File, None)),
            Target::Path("projects/launch".into())
        );
    }

    #[test]
    fn errors_project_per_contract() {
        assert!(matches!(
            map_err(DataError::NotFound("x".into())),
            ProviderError::NotFound(_)
        ));
        assert!(matches!(
            map_err(DataError::Transition {
                field: "status".into(),
                from: "done".into(),
                to: "doing".into()
            }),
            ProviderError::InvalidState(_)
        ));
        assert!(matches!(
            map_err(DataError::PromoteRequired {
                path: "a.md".into(),
                items: 256
            }),
            ProviderError::InvalidState(_)
        ));
        assert!(matches!(
            map_err(DataError::Invalid("x".into())),
            ProviderError::InvalidRequest(_)
        ));
        assert!(matches!(
            map_err(DataError::OpUnavailable("x".into())),
            ProviderError::Unavailable(_)
        ));
    }
}
