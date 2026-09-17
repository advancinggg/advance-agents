//! Frontmatter → [`EntityRow`] projection: the ONE
//! function that turns a normalized document into index rows, used by the `fs.write` SQL leg,
//! by the index rebuild scanner (through [`SchemaEntityProjector`]) and by cap-data.

use std::sync::Arc;

use advance_shared_types::entity::{EntityId, EntityKind, EntityProjector, EntityRow};
use chrono::{DateTime, Utc};
use serde_yml::{Mapping, Value};

use crate::frontmatter::{parse_frontmatter, FrontmatterDoc};
use crate::meta_schema::{MetaSchema, MetaSchemaLoader};
use crate::schema_v2::{parse_datetime, yaml_to_json};

const INDEX_MD: &str = "index.md";

/// Project a document at workspace-relative `path` for `agent_id`.
///
/// The file-level record becomes a `File` row (or a `Dir` row keyed by the directory path when
/// the file is `index.md`); each inline item becomes an `Item` row anchored by its id, with
/// `inherit` fields filled from the file record (effective values). Records without an `id`
/// are skipped (a document that never went through `normalize`).
pub fn project_entities(
    doc: &FrontmatterDoc,
    schema: &MetaSchema,
    agent_id: &str,
    path: &str,
    updated_at: DateTime<Utc>,
) -> Vec<EntityRow> {
    let mut rows = Vec::with_capacity(1 + doc.items.len());
    let Some(file_id) = doc.id() else {
        return rows;
    };
    let (kind, row_path) = match dir_of_index(path) {
        Some(dir) => (EntityKind::Dir, dir),
        None => (EntityKind::File, path.to_string()),
    };
    rows.push(row_from(
        &doc.fields,
        schema,
        agent_id,
        &row_path,
        kind,
        None,
        None,
        updated_at,
    ));
    let inherited = schema.inherited_fields();
    for item in &doc.items {
        let Some(_) = item.get(Value::String("id".into())).and_then(Value::as_str) else {
            continue;
        };
        let mut effective = item.clone();
        for f in &inherited {
            let k = Value::String(f.clone());
            if !effective.contains_key(&k) {
                if let Some(v) = doc.fields.get(&k) {
                    effective.insert(k, v.clone());
                }
            }
        }
        let anchor = effective
            .get(Value::String("id".into()))
            .and_then(Value::as_str)
            .map(|s| EntityId(s.to_string()));
        rows.push(row_from(
            &effective,
            schema,
            agent_id,
            &row_path,
            EntityKind::Item,
            anchor,
            Some(EntityId(file_id.to_string())),
            updated_at,
        ));
    }
    rows
}

/// `Some(dir)` when `path` names a directory's `index.md` (`launch/index.md` → `launch`;
/// a top-level `index.md` → `""`).
pub fn dir_of_index(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    if trimmed == INDEX_MD {
        return Some(String::new());
    }
    trimmed
        .strip_suffix(&format!("/{INDEX_MD}"))
        .map(|d| d.to_string())
}

#[allow(clippy::too_many_arguments)]
fn row_from(
    record: &Mapping,
    schema: &MetaSchema,
    agent_id: &str,
    path: &str,
    kind: EntityKind,
    anchor: Option<EntityId>,
    parent: Option<EntityId>,
    updated_at: DateTime<Utc>,
) -> EntityRow {
    let get = |k: &str| record.get(Value::String(k.to_string()));
    let text = |k: &str| get(k).and_then(Value::as_str).map(str::to_string);
    let when = |k: &str| get(k).and_then(Value::as_str).and_then(parse_datetime);
    let mut fields = serde_json::Map::new();
    for (k, v) in record {
        if let Some(name) = k.as_str() {
            if name == "items" {
                continue;
            }
            fields.insert(name.to_string(), yaml_to_json(v));
        }
    }
    EntityRow {
        id: EntityId(text("id").unwrap_or_default()),
        agent_id: agent_id.to_string(),
        path: path.to_string(),
        anchor,
        parent,
        kind,
        r#type: text("type").unwrap_or_else(|| {
            if kind == EntityKind::Dir {
                "collection".to_string()
            } else {
                "document".to_string()
            }
        }),
        title: text("title"),
        aspects: schema.aspects_of(record),
        status: text("status"),
        due_at: when("due"),
        starts_at: when("starts"),
        ends_at: when("ends"),
        priority: get("priority").and_then(Value::as_i64),
        fields: serde_json::Value::Object(fields),
        updated_at,
    }
}

/// Parse + project raw file bytes (no normalization — the file is taken as it is on disk).
pub fn project_bytes(
    bytes: &[u8],
    schema: &MetaSchema,
    agent_id: &str,
    path: &str,
    updated_at: DateTime<Utc>,
) -> Result<Vec<EntityRow>, String> {
    match parse_frontmatter(bytes).map_err(|e| e.to_string())? {
        Some((doc, _)) => Ok(project_entities(&doc, schema, agent_id, path, updated_at)),
        None => Ok(Vec::new()),
    }
}

/// The production [`EntityProjector`]: projects with the live workspace schema.
pub struct SchemaEntityProjector {
    loader: Arc<MetaSchemaLoader>,
}

impl SchemaEntityProjector {
    pub fn new(loader: Arc<MetaSchemaLoader>) -> Self {
        Self { loader }
    }
}

impl EntityProjector for SchemaEntityProjector {
    fn project(
        &self,
        agent_id: &str,
        path: &str,
        bytes: &[u8],
        updated_at: DateTime<Utc>,
    ) -> Result<Vec<EntityRow>, String> {
        let schema = self.loader.current();
        project_bytes(bytes, &schema, agent_id, path, updated_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_md_maps_to_its_directory() {
        assert_eq!(dir_of_index("launch/index.md"), Some("launch".into()));
        assert_eq!(dir_of_index("/index.md"), Some(String::new()));
        assert_eq!(dir_of_index("launch.md"), None);
        assert_eq!(dir_of_index("a/b/notes.md"), None);
    }
}
