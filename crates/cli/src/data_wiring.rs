//! Entity-data lane E1 (plan §2.8) — composition-root wiring of the `data` host tool.
//!
//! - [`ChainedWorkspaceFs`]: cap-data's `WorkspaceFs` over the SAME cap-fs primitives the
//!   `fs.*` host functions use (territory resolver, `.meta.yaml` maintainer + its write lock,
//!   atomic writer, git commit queue), so a `data.patch` and an `fs.write` of the same file
//!   serialize on one lock and produce the same `.meta.yaml` / commit shape.
//! - [`DeterministicToolReducer`]: cap-data's `PureReducer` over the production
//!   `LazyToolRegistry` (`invoke_deterministic` — frozen clock + seed).
//! - [`register_data_tool`]: registers `DataTool` under id `data`; it MUST run before
//!   `start.rs` snapshots `ToolRegistry::list()` into the context assembler's tool inventory,
//!   or the model never sees the tool.
//! - [`seed_entity_index`]: a one-shot projection of every Markdown file into the entity index
//!   at boot (the production index is not rebuilt from disk anywhere else).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::entity::{EntityIndex, EntityProjector, DATA_TOOL_ID};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use async_trait::async_trait;
use cap_data::{
    Clock, DataError, DataStore, DataTool, FileVersion, PureReducer, SystemClock, UlidEntityIds,
    WorkspaceFs, WriteReceipt,
};
use cap_fs::{
    AtomicWriter, FileHistoryProvider, FsError, GitSync, GitSyncOp, MetaMaintainer,
    MetaSchemaLoader, SchemaEntityProjector, VirtualPathResolver,
};
use cap_tools::{DeterministicCtx, LazyToolRegistry, ToolError, ToolRegistry};

/// Bound on the files [`seed_entity_index`] projects at boot.
pub const MAX_SEED_FILES: usize = 10_000;

/// The cap-fs primitives the data store writes through (all shared with `register_agent_fs`).
pub struct DataFsParts {
    pub workspace_root: PathBuf,
    pub resolver: Arc<dyn VirtualPathResolver>,
    pub schema: Arc<MetaSchemaLoader>,
    pub writer: Arc<dyn AtomicWriter>,
    pub maintainer: Arc<MetaMaintainer>,
    pub git_sync: Option<Arc<dyn GitSync>>,
    pub history: Arc<dyn FileHistoryProvider>,
}

fn fs_err(e: FsError) -> DataError {
    match e {
        FsError::NotFound(m) => DataError::NotFound(m),
        FsError::PermissionDenied(m) => DataError::Forbidden(m),
        FsError::InvalidPath(m) => DataError::Forbidden(m),
        other => DataError::Io(format!("{other:?}")),
    }
}

fn split(physical: &Path) -> Result<(PathBuf, String), DataError> {
    let parent = physical
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| DataError::Io("no parent dir".into()))?;
    let name = physical
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .ok_or_else(|| DataError::Io("invalid file name".into()))?;
    Ok((parent, name))
}

/// Production [`WorkspaceFs`].
pub struct ChainedWorkspaceFs {
    parts: DataFsParts,
}

impl ChainedWorkspaceFs {
    pub fn new(parts: DataFsParts) -> Self {
        Self { parts }
    }

    async fn commit(
        &self,
        agent: &str,
        op: GitSyncOp,
        vpath: &str,
        paths: Vec<PathBuf>,
        message: &str,
    ) -> WriteReceipt {
        let Some(git) = &self.parts.git_sync else {
            return WriteReceipt { commit: None };
        };
        // Git is best-effort audit (same posture as fs.write): a queue failure never fails
        // the data write, whose source of truth is already on disk.
        match git
            .submit_commit_with_message(agent, op, vpath, paths, message)
            .await
        {
            Ok(commit) => WriteReceipt { commit },
            Err(_) => WriteReceipt { commit: None },
        }
    }
}

#[async_trait]
impl WorkspaceFs for ChainedWorkspaceFs {
    async fn read(&self, agent: &str, path: &str) -> Result<Option<Vec<u8>>, DataError> {
        let physical = self
            .parts
            .resolver
            .resolve_read(agent, path)
            .map_err(fs_err)?;
        match tokio::fs::read(&physical).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(DataError::Io(e.to_string())),
        }
    }

    async fn write(
        &self,
        agent: &str,
        path: &str,
        bytes: &[u8],
        message: &str,
    ) -> Result<WriteReceipt, DataError> {
        let physical = self
            .parts
            .resolver
            .resolve_write(agent, path)
            .map_err(fs_err)?;
        let (parent_dir, file_name) = split(&physical)?;
        let maintainer = &self.parts.maintainer;
        {
            // Meta-first commit under the shared `.meta.yaml` lock (mirrors FsWriteHandler).
            let _guard = maintainer.acquire().await;
            let meta_pre = maintainer.load(&parent_dir).await.map_err(fs_err)?;
            let (meta_new, _) = maintainer
                .add_entry_for_write(meta_pre.clone(), &file_name, bytes)
                .map_err(fs_err)?;
            maintainer
                .write(&parent_dir, &meta_new)
                .await
                .map_err(fs_err)?;
            if let Err(e) = self.parts.writer.write(&physical, bytes).await {
                let _ = match &meta_pre {
                    None => maintainer.delete_meta_file(&parent_dir).await,
                    Some(pre) => maintainer.write(&parent_dir, pre).await.map(|_| ()),
                };
                return Err(fs_err(e));
            }
        }
        let meta_path = MetaMaintainer::meta_path(&parent_dir);
        Ok(self
            .commit(
                agent,
                GitSyncOp::Write,
                path,
                vec![physical, meta_path],
                message,
            )
            .await)
    }

    async fn remove(
        &self,
        agent: &str,
        path: &str,
        message: &str,
    ) -> Result<WriteReceipt, DataError> {
        let physical = self
            .parts
            .resolver
            .resolve_write(agent, path)
            .map_err(fs_err)?;
        let (parent_dir, file_name) = split(&physical)?;
        let maintainer = &self.parts.maintainer;
        {
            let _guard = maintainer.acquire().await;
            if let Some(meta) = maintainer.load(&parent_dir).await.map_err(fs_err)? {
                let (meta_new, changed) = maintainer.remove_entry(meta, &file_name);
                if !changed.is_empty() {
                    maintainer
                        .write(&parent_dir, &meta_new)
                        .await
                        .map_err(fs_err)?;
                }
            }
            match tokio::fs::remove_file(&physical).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(DataError::Io(e.to_string())),
            }
        }
        let meta_path = MetaMaintainer::meta_path(&parent_dir);
        Ok(self
            .commit(
                agent,
                GitSyncOp::Delete,
                path,
                vec![physical, meta_path],
                message,
            )
            .await)
    }

    async fn rename(
        &self,
        agent: &str,
        from: &str,
        to: &str,
        message: &str,
    ) -> Result<WriteReceipt, DataError> {
        // Two commits (write the new path, remove the old one): the commit queue has no
        // multi-path move primitive; the entity id in the frontmatter keeps identity stable.
        let bytes = self
            .read(agent, from)
            .await?
            .ok_or_else(|| DataError::NotFound(from.to_string()))?;
        let receipt = self.write(agent, to, &bytes, message).await?;
        self.remove(agent, from, message).await?;
        Ok(receipt)
    }

    async fn history(
        &self,
        agent: &str,
        path: &str,
        limit: usize,
    ) -> Result<Vec<FileVersion>, DataError> {
        let physical = self
            .parts
            .resolver
            .resolve_read(agent, path)
            .map_err(fs_err)?;
        let entries = self.parts.history.file_history(&physical).map_err(fs_err)?;
        let mut out = Vec::new();
        for entry in entries.into_iter().take(limit) {
            let bytes = match self.parts.history.read_at(&physical, &entry.version) {
                Ok(b) => b,
                Err(_) => continue,
            };
            out.push(FileVersion {
                commit: entry.version,
                message: entry.message.unwrap_or_default(),
                bytes,
            });
        }
        Ok(out)
    }
}

/// `PureReducer` over the production tool registry.
pub struct DeterministicToolReducer {
    registry: Arc<LazyToolRegistry>,
}

impl DeterministicToolReducer {
    pub fn registry(&self) -> Arc<LazyToolRegistry> {
        Arc::clone(&self.registry)
    }
}

#[async_trait]
impl PureReducer for DeterministicToolReducer {
    async fn available(&self, tool_id: &str) -> bool {
        self.registry.list().await.iter().any(|t| t.id == tool_id)
    }

    async fn reduce(
        &self,
        tool_id: &str,
        method: &str,
        input: &[u8],
        ctx: DeterministicCtx,
    ) -> Result<Vec<u8>, String> {
        self.registry
            .invoke_deterministic(tool_id, method, input, ctx)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Build the reducer over `registry`.
pub fn deterministic_reducer(registry: Arc<LazyToolRegistry>) -> Arc<DeterministicToolReducer> {
    Arc::new(DeterministicToolReducer { registry })
}

/// Build the production `DataStore` (system clock, ULID ids, event bus, reducer) and seed the
/// entity index from the workspace's Markdown files.
pub async fn build_data_store(
    parts: DataFsParts,
    index: Arc<dyn EntityIndex>,
    events: Arc<dyn EventBusEmit>,
    reducer: Arc<DeterministicToolReducer>,
    seed_agent_id: &str,
) -> Arc<DataStore> {
    let schema = Arc::clone(&parts.schema);
    let workspace_root = parts.workspace_root.clone();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = DataStore::new(
        Arc::new(ChainedWorkspaceFs::new(parts)),
        Arc::clone(&index),
        Arc::clone(&schema),
        Arc::new(UlidEntityIds),
        clock,
    )
    .with_events(events)
    .with_reducer(reducer);
    let projector = SchemaEntityProjector::new(schema);
    seed_entity_index(&workspace_root, seed_agent_id, &projector, index.as_ref()).await;
    Arc::new(store)
}

/// Project every `.md` under `workspace_root` (hidden dirs skipped) for `agent_id`.
/// Best-effort: unreadable / unparsable files are skipped, never fatal. Returns the number
/// of files projected.
pub async fn seed_entity_index(
    workspace_root: &Path,
    agent_id: &str,
    projector: &dyn EntityProjector,
    index: &dyn EntityIndex,
) -> usize {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(workspace_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| !(e.depth() > 0 && e.file_name().to_string_lossy().starts_with('.')))
    {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        let is_md = entry
            .path()
            .extension()
            .and_then(|x| x.to_str())
            .map(|x| x.eq_ignore_ascii_case("md"))
            .unwrap_or(false);
        if is_md {
            files.push(entry.path().to_path_buf());
            if files.len() >= MAX_SEED_FILES {
                break;
            }
        }
    }
    let now = chrono::Utc::now();
    let mut projected = 0usize;
    for path in files {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(workspace_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(rows) = projector.project(agent_id, &rel, &bytes, now) else {
            continue;
        };
        if rows.is_empty() {
            continue;
        }
        if index.replace_path(agent_id, &rel, rows).await.is_ok() {
            projected += 1;
        }
    }
    projected
}

/// Register the `data` host tool. Call BEFORE the tool-inventory snapshot.
pub async fn register_data_tool(
    registry: &LazyToolRegistry,
    store: Arc<DataStore>,
    grant: Arc<dyn GrantCheck>,
) -> Result<(), ToolError> {
    // Same posture as `reconcile_pack_tool_exposure`: a declared operation whose bound skill
    // tool is not registered is reported once at boot (WARN, never blocks); `describe` shows
    // it as unavailable and `apply` answers `op_unavailable` until the pack's tool is present.
    for aspect in store.describe("boot").await.aspects {
        for op in aspect.operations.iter().filter(|o| !o.available) {
            eprintln!(
                "advance: WARN data operation {}.{} is bound to tool {} ({}), which is not \
                 registered — install the pack that provides it",
                aspect.name, op.name, op.tool, op.method
            );
        }
    }
    registry
        .register_host(DATA_TOOL_ID, Arc::new(DataTool::new(store, grant)))
        .await
}
