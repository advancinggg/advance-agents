//! cap-fs — MODULE-002 Slice A foundation.
//!
//! Library crate providing:
//! - [`FsError`]: WIT `fs-error` variant + Wasmtime `Val::Variant` encoding helpers.
//! - [`Entry`] / [`entry::entry_to_val`] / [`entry::from_metadata`] /
//!   [`entry::from_metadata_with_mtime`]: WIT `record entry` value-type with a test
//!   seam for forcing the graceful-degradation branch when `meta.modified()`
//!   returns `Err`.
//! - [`atomic_write`]: same-fs temp file + persist helper bounded by
//!   [`atomic::MAX_WRITE_BYTES`].
//! - [`VirtualPathResolver`] trait + [`DefaultVirtualPathResolver`]: slice A subset
//!   of MODULE-002's 7 access rules — Rule 1 (self workspace) + Rule 7 (`.advance/`
//!   hidden) + traversal/absolute rejection + workspace-scope hidden-name defense
//!   for `.git` / `.meta.yaml` / `*.sqlite` / `*.sqlite-wal`. Rules 2/3/4/5/6 and
//!   `.agent/_*` are forward-looking spec, deferred to slice B+.
//! - [`FsEvent`] + [`emit_fs_event`] + [`event_type_for`]: full 7-variant FsEvent
//!   enum (Read/Write/Delete/List/Scan/History/MetaUpdated) declared, with
//!   compile-time-exhaustive event_type-string mapping. Slice A emits only the
//!   first four variants.
//! - 4 [`HostFunctionHandler`](advance_runtime::host_registry::HostFunctionHandler)
//!   impls (`FsReadHandler`, `FsWriteHandler`, `FsListHandler`, `FsDeleteHandler`)
//!   and the [`register_agent_fs`] entry point that registers all four under
//!   capability `"fs"` and namespace `"advance:runtime/agent-fs@0.1.0"`.
//!
//! Slice A is library-only; production wiring of `agent-fs` into
//! `component_loader::instantiate_advance_host_async` is a future MODULE-001 slice
//! responsibility — matching the cap-secrets / cap-llm precedent.
//!
//! See `docs/modules/MODULE-002-filesystem.md` §3.7 Change History for slice context.

#![forbid(unsafe_code)]

pub mod atomic;
pub mod entry;
pub mod error;
pub mod events;
pub mod git_sync;
pub mod history_provider;
pub mod host_fn;
pub mod meta_maintainer;
pub mod meta_schema;
pub mod reconcile;
pub mod resolver;
pub mod sqlite_sync;

pub use atomic::{atomic_write, AtomicWriter, DefaultAtomicWriter, MAX_WRITE_BYTES};
pub use entry::{
    child_meta_to_val, entry_to_val, scan_result_to_val, scope_meta_to_val, version_entry_to_val,
    ChildMeta, Entry, ScanResult, ScopeMeta, VersionEntry,
};
pub use error::{fs_error_to_val, sanitize_io_error, FsError};
pub use events::{
    emit_fs_event, emit_runtime_degraded, emit_schema_reloaded, event_type_for, FsEvent, FsSource,
    MetaSource, RebuildReportSummary, SCHEMA_RELOADED_EVENT_TYPE,
};
pub use git_sync::{Adv003GitSync, GitSync, GitSyncError, GitSyncOp};
pub use history_provider::{FileHistoryProvider, StubFileHistoryProvider};
pub use host_fn::{
    list_over_limit_msg, register_agent_fs, register_agent_fs_default, FsChildFileHistoryHandler,
    FsDeleteHandler, FsFileHistoryHandler, FsListChildHandler, FsListHandler, FsListSlugHandler,
    FsReadAtHandler, FsReadChildAtHandler, FsReadChildHandler, FsReadHandler, FsReadSlugHandler,
    FsScanChildHandler, FsScanHandler, FsScanSlugHandler, FsSlugFileHistoryHandler,
    FsUpdateEntryMetaHandler, FsUpdateScopeHandler, FsWriteHandler, DEFAULT_FS_CONCURRENCY,
    DEFAULT_MAX_LIST_ENTRIES, MAX_PATH_BYTES, MAX_READ_BYTES,
};
pub use meta_maintainer::{EntryMetaValues, MetaFile, MetaMaintainer};
pub use meta_schema::{
    schema_changes, AutoRule, FieldSpec, FieldType, MetaSchema, MetaSchemaError, MetaSchemaLoader,
    MetaSchemaWatcher, SchemaChanges, DEFAULT_SCHEMA_POLL_INTERVAL, MAX_META_SCHEMA_SIZE,
};
pub use reconcile::{
    is_reconciler_skipped_name, ReconcileReport, WorkspaceReconciler, MAX_RECONCILE_ERRORS,
};
pub use resolver::{
    apply_hidden_name_walk, is_agent_internal_hidden_name, is_workspace_hidden_name,
    DefaultVirtualPathResolver, VirtualPathResolver, MAX_PATH_DEPTH,
};
pub use sqlite_sync::{
    agent_id_for_m004, is_text_for_sql_index, normalize_ws_path, Db030SqliteSync, FsSyncError,
    SqliteSync, MAX_SQL_PREVIEW_CHARS,
};
