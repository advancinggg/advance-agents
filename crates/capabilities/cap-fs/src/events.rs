//! `FsEvent` — full 8-variant event enum + emit helper.
//!
//! Slice A declared the original 7 FsEvent variants per MODULE-002 §2.3 to lock the
//! contract surface that downstream M004 indexer + M011 post-processor subscribe to
//! via the `fs.*` event_type strings. Slice C added the 8th — `ReconcileCompleted`
//! — for the startup-reconciliation aggregate signal (CONTRACT-011 additive,
//! event_type `"fs.reconcile_completed"`). Slice A only emits the first four
//! (`Read`/`Write`/`Delete`/`List`); `Scan`/`History`/`MetaUpdated` ship in slice B;
//! `ReconcileCompleted` ships in slice C.
//!
//! The `event_type_for` helper is a single exhaustive `match` — adding a new variant
//! without updating the mapping is a compile error, ensuring the event_type-string
//! contract stays synchronised.

use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Where a read/list/scan/history operation reads from. Slice A only emits `Private`
/// (own-territory access via `read`/`write`/`list`/`delete`); the other variants ship
/// when slug/child/history host fns ship in slices B+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsSource {
    Private,
    Child,
    Slug,
    History,
}

/// Origin of a `.meta.yaml` mutation. Declared for forward-compatibility; not emitted
/// in slice A (no `.meta.yaml` maintenance until slice B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaSource {
    FsWrite,
    FsDelete,
    UpdateScope,
    UpdateEntryMeta,
    Reconcile,
}

/// Bounded payload-side projection of `advance_database::RebuildReport` (slice C).
/// The M004 type carries an unbounded `errors: Vec<String>` which would inflate
/// the EventBus payload; we project to a count for event-payload bound discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildReportSummary {
    pub meta_rows: u64,
    pub content_rows: u64,
    pub memory_rows: u64,
    pub task_rows: u64,
    pub turn_rows: u64,
    pub embed_calls: u64,
    pub elapsed_ms: u64,
    pub errors_count: u64,
}

/// Full 8-variant FsEvent enum mirroring MODULE-002 §2.3. Slice A emits 4;
/// slice B emits Scan/History/MetaUpdated; slice C emits ReconcileCompleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsEvent {
    Read {
        agent_id: String,
        path: String,
        source: FsSource,
        size: usize,
    },
    Write {
        agent_id: String,
        path: String,
        size: usize,
        is_new_file: bool,
    },
    Delete {
        agent_id: String,
        path: String,
    },
    List {
        agent_id: String,
        path: String,
        source: FsSource,
        count: usize,
    },
    Scan {
        agent_id: String,
        path: String,
        source: FsSource,
        children_count: usize,
    },
    History {
        agent_id: String,
        path: String,
        source: FsSource,
        versions_count: usize,
    },
    MetaUpdated {
        dir: String,
        entry: String,
        source: MetaSource,
        fields: Vec<String>,
    },
    /// Slice C: emitted by `WorkspaceReconciler::reconcile()` after the workspace
    /// walk + `IndexRebuild::rebuild_full()` complete. ONE event per reconcile call
    /// (no per-dir MetaUpdated during reconciliation — those would flood the bus
    /// at 10K dirs and race the bulk SQL truncate-and-reinsert in `rebuild_full`).
    ///
    /// `event_type` string: `"fs.reconcile_completed"`.
    ReconcileCompleted {
        dirs_scanned: u64,
        meta_yaml_created: u64,
        entries_added: u64,
        entries_removed: u64,
        fields_repaired: u64,
        rebuild_report_summary: Option<RebuildReportSummary>,
        errors_count: u64,
    },
}

/// Map an [`FsEvent`] variant to its canonical `event_type` string. The exhaustive
/// match means adding a new variant is a compile error until the mapping is extended.
///
/// Slice A only emits Read/Write/Delete/List, but all 8 strings (slice C added
/// `fs.reconcile_completed`) are pinned here so future slices can't accidentally
/// rename `"fs.scan"` to `"fs.scan_completed"` or similar — the cross-module
/// subscriber contract is locked.
///
/// Slice D rename (cap-fs slice-D taxonomy alignment): `MetaUpdated` returns
/// `"meta.updated"` (PRD §15.3.8 canonical — the metadata-mutation event lives
/// in the `meta.*` namespace, not `fs.*`).
pub fn event_type_for(ev: &FsEvent) -> &'static str {
    match ev {
        FsEvent::Read { .. } => "fs.read",
        FsEvent::Write { .. } => "fs.write",
        FsEvent::Delete { .. } => "fs.delete",
        FsEvent::List { .. } => "fs.list",
        FsEvent::Scan { .. } => "fs.scan",
        FsEvent::History { .. } => "fs.history",
        FsEvent::MetaUpdated { .. } => "meta.updated",
        FsEvent::ReconcileCompleted { .. } => "fs.reconcile_completed",
    }
}

/// Build an `Event` from `FsEvent` + caller context and emit via the supplied
/// [`EventBusEmit`] implementer. Always called AFTER the underlying disk I/O has
/// succeeded — emit on success, no emit on failure (MODULE-002 §1.4.4 invariant).
pub fn emit_fs_event(emitter: &dyn EventBusEmit, agent_id: &str, trace_id: &str, ev: FsEvent) {
    let event_type = event_type_for(&ev).to_string();
    let payload = serde_json::to_value(&ev).expect("FsEvent always serializes");
    let event = Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: trace_id.to_string(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type,
        payload,
        duration_ms: None,
    };
    emitter.emit(event);
}

/// Emit a `runtime.degraded.{reason}` event surfacing non-recoverable
/// inconsistencies to operators. Used by slice B's atomic-rollback failure
/// modes (fs_write_meta_rollback_failed, fs_delete_meta_rollback_failed).
/// `extra_payload` (typically a `serde_json::Map`) is merged with `reason` to
/// produce the final payload; both `event_type` and `payload.reason` carry the
/// reason for flexible subscriber filtering.
pub fn emit_runtime_degraded(
    emitter: &dyn EventBusEmit,
    agent_id: &str,
    trace_id: &str,
    reason: &str,
    extra_payload: serde_json::Value,
) {
    let mut payload_map = match extra_payload {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    payload_map.insert(
        "reason".to_string(),
        serde_json::Value::String(reason.to_string()),
    );
    let event = Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: trace_id.to_string(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: format!("runtime.degraded.{reason}"),
        payload: serde_json::Value::Object(payload_map),
        duration_ms: None,
    };
    emitter.emit(event);
}

/// Canonical event type for the SQLite index-rebuild volume signal (stage-B,
/// 2026-06-15). MUST stay byte-identical to `taxonomy::runtime::INDEX_REBUILD`
/// in `crates/event-bus/src/taxonomy.rs` (the source of truth, already enumerated
/// in `ALL_EVENT_TYPES`) — redefined locally because cap-fs deliberately takes no
/// event-bus dependency edge (same posture as `SCHEMA_RELOADED_EVENT_TYPE` + the
/// `event_type_for` string literals above).
pub const INDEX_REBUILD_EVENT_TYPE: &str = "runtime.index_rebuild";

/// Emit a `runtime.index_rebuild { total_files, total_dirs }` event surfacing the
/// SQLite index-rebuild volume after `WorkspaceReconciler::reconcile` runs a
/// SUCCESSFUL `IndexRebuild::rebuild_full` (emitted ONLY on the rebuild-Ok branch,
/// alongside `fs.reconcile_completed`; the failure branch already surfaces
/// `runtime.degraded.sqlite_rebuild_failed`). `total_files` is the M004 rebuild
/// `content_rows`; `total_dirs` is the reconcile pass's `dirs_scanned`. Additive
/// observability — no contract/signature change. (MODULE-002 §2.14; SYS-AC-147.)
pub fn emit_runtime_index_rebuild(
    emitter: &dyn EventBusEmit,
    agent_id: &str,
    trace_id: &str,
    total_files: u64,
    total_dirs: u64,
) {
    let payload = serde_json::json!({
        "total_files": total_files,
        "total_dirs": total_dirs,
    });
    let event = Event {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: trace_id.to_string(),
        span_id: Uuid::new_v4().to_string(),
        parent_span_id: None,
        event_type: INDEX_REBUILD_EVENT_TYPE.to_string(),
        payload,
        duration_ms: None,
    };
    emitter.emit(event);
}

/// Canonical event type for meta-schema hot-reload (hotreload pre-build,
/// 2026-06-10). MUST stay byte-identical to `taxonomy::runtime::SCHEMA_RELOADED`
/// in `crates/event-bus/src/taxonomy.rs` (the source of truth) — redefined
/// locally because cap-fs deliberately takes no event-bus dependency edge
/// (the same posture as the `event_type_for` string literals above).
pub const SCHEMA_RELOADED_EVENT_TYPE: &str = "runtime.schema_reloaded";

/// Per-bucket name cap for the `runtime.schema_reloaded` payload.
const SCHEMA_EVENT_MAX_NAMES_PER_BUCKET: usize = 64;
/// Per-name byte cap (char-boundary-safe truncation) for the payload.
const SCHEMA_EVENT_MAX_NAME_BYTES: usize = 64;

/// Truncate a field name to `SCHEMA_EVENT_MAX_NAME_BYTES` on a char boundary.
fn truncate_name(name: &str) -> String {
    if name.len() <= SCHEMA_EVENT_MAX_NAME_BYTES {
        return name.to_string();
    }
    let mut end = SCHEMA_EVENT_MAX_NAME_BYTES;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

/// Bound one bucket: at most `SCHEMA_EVENT_MAX_NAMES_PER_BUCKET` names, each
/// truncated to `SCHEMA_EVENT_MAX_NAME_BYTES` bytes.
fn bounded_bucket(names: &[String]) -> Vec<String> {
    names
        .iter()
        .take(SCHEMA_EVENT_MAX_NAMES_PER_BUCKET)
        .map(|n| truncate_name(n))
        .collect()
}

/// Build + emit the `runtime.schema_reloaded` event — the SINGLE canonical
/// payload builder (the `MetaSchemaWatcher` tick calls this inside its panic
/// containment; no second payload-construction path may exist).
///
/// Payload bound rationale: `parse_and_validate` imposes no field-name length
/// bound and a legal 1 MiB schema can declare thousands of fields, while the
/// production event bus SILENTLY DROPS payloads over its 64 KiB cap — so each
/// of the 6 name buckets is capped at 64 names × 64 bytes (≈27 KiB worst case
/// with JSON overhead) and the 6 FULL counts are always present, preserving
/// observability when name lists truncate. Names only — never field specs,
/// defaults, or values.
pub fn emit_schema_reloaded(
    emitter: &dyn EventBusEmit,
    changes: &crate::meta_schema::SchemaChanges,
) {
    let payload = serde_json::json!({
        "required_added": bounded_bucket(&changes.required_added),
        "required_removed": bounded_bucket(&changes.required_removed),
        "required_changed": bounded_bucket(&changes.required_changed),
        "optional_added": bounded_bucket(&changes.optional_added),
        "optional_removed": bounded_bucket(&changes.optional_removed),
        "optional_changed": bounded_bucket(&changes.optional_changed),
        "required_added_count": changes.required_added.len(),
        "required_removed_count": changes.required_removed.len(),
        "required_changed_count": changes.required_changed.len(),
        "optional_added_count": changes.optional_added.len(),
        "optional_removed_count": changes.optional_removed.len(),
        "optional_changed_count": changes.optional_changed.len(),
    });
    let event = Event::observability(SCHEMA_RELOADED_EVENT_TYPE, "runtime", payload, None);
    emitter.emit(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustive_event_type_mapping_all_eight_variants() {
        assert_eq!(
            event_type_for(&FsEvent::Read {
                agent_id: "a".into(),
                path: "p".into(),
                source: FsSource::Private,
                size: 0
            }),
            "fs.read"
        );
        assert_eq!(
            event_type_for(&FsEvent::Write {
                agent_id: "a".into(),
                path: "p".into(),
                size: 0,
                is_new_file: true
            }),
            "fs.write"
        );
        assert_eq!(
            event_type_for(&FsEvent::Delete {
                agent_id: "a".into(),
                path: "p".into()
            }),
            "fs.delete"
        );
        assert_eq!(
            event_type_for(&FsEvent::List {
                agent_id: "a".into(),
                path: "p".into(),
                source: FsSource::Private,
                count: 0
            }),
            "fs.list"
        );
        assert_eq!(
            event_type_for(&FsEvent::Scan {
                agent_id: "a".into(),
                path: "p".into(),
                source: FsSource::Private,
                children_count: 0
            }),
            "fs.scan"
        );
        assert_eq!(
            event_type_for(&FsEvent::History {
                agent_id: "a".into(),
                path: "p".into(),
                source: FsSource::History,
                versions_count: 0
            }),
            "fs.history"
        );
        assert_eq!(
            event_type_for(&FsEvent::MetaUpdated {
                dir: "d".into(),
                entry: "e".into(),
                source: MetaSource::FsWrite,
                fields: vec!["x".into()]
            }),
            "meta.updated"
        );
        assert_eq!(
            event_type_for(&FsEvent::ReconcileCompleted {
                dirs_scanned: 0,
                meta_yaml_created: 0,
                entries_added: 0,
                entries_removed: 0,
                fields_repaired: 0,
                rebuild_report_summary: None,
                errors_count: 0,
            }),
            "fs.reconcile_completed"
        );
    }

    #[test]
    fn fs_event_serde_roundtrip_read() {
        let ev = FsEvent::Read {
            agent_id: "agent-1".into(),
            path: "notes.md".into(),
            source: FsSource::Private,
            size: 42,
        };
        let json = serde_json::to_value(&ev).unwrap();
        let back: FsEvent = serde_json::from_value(json).unwrap();
        assert_eq!(ev, back);
    }
}
