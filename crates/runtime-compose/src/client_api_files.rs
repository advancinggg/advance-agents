//! Production `FilesProvider` over [`OperatorFiles`].
//!
//! `ClientApi::handle()` is sync and may run on a tokio worker. Operator mutations
//! are async, so each async call runs on an owned current-thread runtime on a
//! scoped OS thread — never `Handle::block_on`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use advance_client_api::file_ticket::etag_for;
use advance_client_api::files::detail::{CapacityKind, FilesFailure, Oid40, VcsUnavailableReason};
use advance_client_api::files::{
    ClientFileChange, ClientFileCommit, ClientFileEntry, ClientFileList, ClientFileMutationResult,
    ClientFileSearchResult, ClientFileStat, ClientFileVersionResult, ClientFileWriteResult,
    FileReadSource, FileReadVersion, FileUploadHandle, FileUploadSink, FileWriteTarget, FilesActor,
    FilesCommitBatch, FilesCopyItem, FilesDelete, FilesExternalItem, FilesListOrder, FilesListPage,
    FilesListQuery, FilesListSort, FilesMkdir, FilesMoveItem, FilesReadQuery, FilesRestore,
    FilesSaveVersion, FilesSearchQuery, FilesStatQuery, WriteCheck, WriteIntent,
};
use advance_client_api::git::ClientGitCommitLabel;
use advance_client_api::session::Platform;
use advance_client_api::{FilesProvider, ProviderError};
use advance_git::{repo_status, GitHistoryReader, GitRepoStatus, HistoryError};
use advance_shared_types::media_type::content_type_for_name;
use cap_fs::operator::{self as op, OperatorFiles, VcsPathState};
use cap_fs::FilesError;
use sha2::{Digest, Sha256};

/// Files-state directory: `<state_root>/files/<hex16(sha256(home))>` when a state
/// root is set, else `<home>/.runtime/files`. Open does not create it.
pub(crate) fn files_state_path(state_root: Option<&Path>, home: &Path) -> PathBuf {
    match state_root {
        Some(root) => {
            let mut hasher = Sha256::new();
            hasher.update(home.to_string_lossy().as_bytes());
            let digest = hasher.finalize();
            root.join("files").join(hex::encode(&digest[..8]))
        }
        None => home.join(".runtime").join("files"),
    }
}

/// The production files-family adapter.
pub struct WiredFilesProvider {
    core: Arc<OperatorFiles>,
    history: GitHistoryReader,
}

impl WiredFilesProvider {
    pub fn new(core: Arc<OperatorFiles>, history: GitHistoryReader) -> Self {
        Self { core, history }
    }

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
                            "files call: failed to build the owned runtime: {e}"
                        ))
                    })?;
                Ok(runtime.block_on(fut))
            })
            .join()
            .map_err(|_| ProviderError::Unavailable("files call panicked".into()))?
        })
    }

    fn require_writable_repo(&self) -> Result<(), ProviderError> {
        match repo_status(self.core.home()) {
            GitRepoStatus::Ready => Ok(()),
            GitRepoStatus::NotMain { .. } => {
                Err(ProviderError::Files(FilesFailure::VcsUnavailable {
                    reason: Some(VcsUnavailableReason::NotMain),
                }))
            }
            GitRepoStatus::Missing => Err(ProviderError::Files(FilesFailure::VcsUnavailable {
                reason: Some(VcsUnavailableReason::NoRepo),
            })),
            GitRepoStatus::Unreadable { .. } => {
                Err(ProviderError::Files(FilesFailure::VcsUnavailable {
                    reason: Some(VcsUnavailableReason::NoRepo),
                }))
            }
        }
    }
}

impl FilesProvider for WiredFilesProvider {
    fn list(&self, q: &FilesListQuery) -> Result<FilesListPage, ProviderError> {
        let (offset, fingerprint) = match q.cursor.as_deref() {
            None => (0, None),
            Some(raw) => {
                let (offset, fingerprint) = decode_cursor(raw)?;
                (offset, Some(fingerprint))
            }
        };
        let listing = self
            .core
            .list(&op::ListQuery {
                dir: q.path.as_str().to_string(),
                offset,
                fingerprint,
                limit: q.limit,
                sort: map_sort(q.sort),
                descending: matches!(q.order, FilesListOrder::Desc),
                folders_first: q.folders_first,
            })
            .map_err(map_files_error)?;
        Ok(FilesListPage {
            list: ClientFileList {
                path: listing.path,
                entries: listing.entries.into_iter().map(map_entry).collect(),
                total: listing.total as u64,
                next_cursor: listing
                    .next_offset
                    .map(|next| encode_cursor(next, &listing.fingerprint)),
                truncated: listing.truncated,
                skipped: listing.skipped_unsupported as u64,
                vcs: if listing.vcs_available {
                    "ready".into()
                } else {
                    "unknown".into()
                },
            },
        })
    }

    fn stat(&self, q: &FilesStatQuery) -> Result<ClientFileStat, ProviderError> {
        let result = self
            .core
            .stat(&op::StatQuery {
                path: q.path.as_str().to_string(),
            })
            .map_err(map_files_error)?;
        let _ = q.want_oid;
        Ok(ClientFileStat {
            entry: map_entry(result.entry),
            head_oid: None,
            versioned: None,
            versioned_reason: None,
        })
    }

    fn search(&self, q: &FilesSearchQuery) -> Result<ClientFileSearchResult, ProviderError> {
        let result = self
            .core
            .search(&op::SearchQuery {
                path: q.path.as_str().to_string(),
                q: q.query.clone(),
                limit: q.limit,
            })
            .map_err(map_files_error)?;
        let items = result
            .items
            .into_iter()
            .filter(|entry| q.dotfiles || !entry.dotfile)
            .map(map_entry)
            .collect();
        Ok(ClientFileSearchResult {
            query: result.query,
            path: result.path,
            items,
            truncated: result.truncated,
            visited: result.visited as u64,
        })
    }

    fn prepare_read(&self, q: &FilesReadQuery) -> Result<FileReadVersion, ProviderError> {
        let version = self
            .core
            .prepare_read(&op::ReadQuery {
                path: q.path.as_str().to_string(),
                rev: q.rev.as_ref().map(|oid| oid.as_str().to_string()),
                want_oid: q.want_oid,
            })
            .map_err(map_files_error)?;
        Ok(FileReadVersion {
            path: version.path,
            size: version.size,
            content_type: version.content_type,
            oid: parse_oid(version.oid.as_deref()),
            identity: version.identity,
            rev: parse_oid(version.rev.as_deref()),
            already_current: version.already_current,
        })
    }

    fn open_read(
        &self,
        path: &advance_client_api::files::FilesPath,
        v: &FileReadVersion,
    ) -> Result<FileReadSource, ProviderError> {
        let source = self
            .core
            .open_read(
                path.as_str(),
                &op::ReadVersion {
                    path: v.path.clone(),
                    size: v.size,
                    content_type: v.content_type.clone(),
                    oid: v.oid.as_ref().map(|oid| oid.as_str().to_string()),
                    identity: v.identity,
                    rev: v.rev.as_ref().map(|oid| oid.as_str().to_string()),
                    already_current: v.already_current,
                },
            )
            .map_err(map_files_error)?;
        Ok(match source {
            op::ReadSource::Bytes(bytes) => FileReadSource::Bytes(bytes),
            op::ReadSource::Path(path) => FileReadSource::Path(path),
        })
    }

    fn check_write(
        &self,
        actor: &FilesActor,
        t: &FileWriteTarget,
    ) -> Result<WriteCheck, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let target = map_write_target(t);
        let check = self
            .core
            .check_write(&mapped, &target)
            .map_err(map_files_error)?;
        Ok(map_write_check(check, t))
    }

    fn begin_upload(
        &self,
        actor: &FilesActor,
        t: &FileWriteTarget,
    ) -> Result<FileUploadSink, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let target = map_write_target(t);
        let sink = self
            .core
            .begin_upload(&mapped, &target)
            .map_err(map_files_error)?;
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .open(&sink.staging_path)
        {
            Ok(file) => file,
            Err(error) => {
                self.core.abort_upload(sink.handle);
                return Err(ProviderError::Unavailable(error.to_string()));
            }
        };
        Ok(FileUploadSink::file(sink.handle.token, file))
    }

    fn finish_upload(
        &self,
        actor: &FilesActor,
        t: &FileWriteTarget,
        h: FileUploadHandle,
    ) -> Result<ClientFileWriteResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let target = map_write_target(t);
        let handle = op::FileUploadHandle { token: h.id };
        let core = Arc::clone(&self.core);
        let result =
            Self::block_on(async move { core.finish_upload(&mapped, &target, handle).await })?
                .map_err(map_files_error)?;
        Ok(map_write_result(result, t, actor))
    }

    fn abort_upload(&self, h: FileUploadHandle) {
        self.core.abort_upload(op::FileUploadHandle { token: h.id });
    }

    fn mkdir(
        &self,
        actor: &FilesActor,
        r: &FilesMkdir,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let req = op::FilesMkdir {
            path: r.path.as_str().to_string(),
            parents: r.parents,
        };
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.mkdir(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let change = ClientFileChange {
            path: r.path.as_str().to_string(),
            kind: "dir".into(),
            change: "added".into(),
            from_path: None,
            blob_oid: None,
            size: None,
            versioned: matches!(result.commit, op::CommitState::Committed),
            versioned_reason: None,
        };
        Ok(map_mutation(result, vec![change], actor, "mkdir"))
    }

    fn move_items(
        &self,
        actor: &FilesActor,
        items: &[FilesMoveItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let req: Vec<op::FilesMoveItem> = items
            .iter()
            .map(|item| op::FilesMoveItem {
                from: item.from.as_str().to_string(),
                to: item.to.as_str().to_string(),
                base_oid: item.base_oid.as_ref().map(|oid| oid.as_str().to_string()),
            })
            .collect();
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.move_items(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let changes = items
            .iter()
            .map(|item| ClientFileChange {
                path: item.to.as_str().to_string(),
                kind: "file".into(),
                change: "renamed".into(),
                from_path: Some(item.from.as_str().to_string()),
                blob_oid: None,
                size: None,
                versioned: matches!(result.commit, op::CommitState::Committed),
                versioned_reason: None,
            })
            .collect();
        Ok(map_mutation(result, changes, actor, "move"))
    }

    fn delete(
        &self,
        actor: &FilesActor,
        r: &FilesDelete,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let req = op::FilesDelete {
            items: r
                .items
                .iter()
                .map(|item| op::FilesDeleteItem {
                    path: item.path.as_str().to_string(),
                    base_oid: item.base_oid.as_ref().map(|oid| oid.as_str().to_string()),
                })
                .collect(),
            recursive: r.recursive,
            include_uncommitted: true,
            confirm_unversioned: r.confirm_unversioned,
        };
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.delete(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let changes = r
            .items
            .iter()
            .map(|item| ClientFileChange {
                path: item.path.as_str().to_string(),
                kind: "file".into(),
                change: "deleted".into(),
                from_path: None,
                blob_oid: None,
                size: None,
                versioned: matches!(result.commit, op::CommitState::Committed),
                versioned_reason: None,
            })
            .collect();
        Ok(map_mutation(result, changes, actor, "delete"))
    }

    fn restore(
        &self,
        actor: &FilesActor,
        r: &FilesRestore,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.require_writable_repo()?;
        let from_sha = r.from_sha.as_str();
        let mut items = Vec::with_capacity(r.items.len());
        for item in &r.items {
            let at = self
                .history
                .read_file_at(item.path.as_str(), from_sha)
                .map_err(map_history_error)?;
            items.push(op::FilesRestoreItem {
                path: item.path.as_str().to_string(),
                from_sha: from_sha.to_string(),
                base_oid: item.base_oid.as_ref().map(|oid| oid.as_str().to_string()),
                bytes: at.bytes,
                executable: false,
            });
        }
        let mapped = map_actor(actor);
        let req = op::FilesRestore { items };
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.restore(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let changes = r
            .items
            .iter()
            .map(|item| ClientFileChange {
                path: item.path.as_str().to_string(),
                kind: "file".into(),
                change: "replaced".into(),
                from_path: None,
                blob_oid: None,
                size: None,
                versioned: matches!(result.commit, op::CommitState::Committed),
                versioned_reason: None,
            })
            .collect();
        Ok(map_mutation(result, changes, actor, "restore"))
    }

    fn save_version(
        &self,
        actor: &FilesActor,
        r: &FilesSaveVersion,
    ) -> Result<ClientFileVersionResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let paths = r
            .paths
            .as_ref()
            .map(|paths| paths.iter().map(|p| p.as_str().to_string()).collect());
        let req = op::FilesSaveVersion {
            title: r.title.clone(),
            paths: paths.clone(),
        };
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.save_version(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let path_list = paths.unwrap_or_default();
        let count = path_list.len() as u32;
        Ok(ClientFileVersionResult {
            tag: result.tag,
            version_label: result.label.clone(),
            title: result.title.clone(),
            paths: r
                .paths
                .as_ref()
                .map(|paths| paths.iter().map(|p| p.as_str().to_string()).collect()),
            commit: file_commit(
                &result.sha,
                actor,
                "save-version",
                path_list,
                count,
                Some(result.title.clone()),
                Some(result.label.clone()),
            ),
            pending_before: result.pending_before,
            adopt_incomplete: result.adopt_incomplete,
            unversioned_count: 0,
        })
    }

    fn commit_external(
        &self,
        actor: &FilesActor,
        items: &[FilesExternalItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let req: Vec<op::FilesExternalItem> = items
            .iter()
            .map(|item| op::FilesExternalItem {
                path: item.path.as_str().to_string(),
                oid: item.oid.as_ref().map(|oid| oid.as_str().to_string()),
            })
            .collect();
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.commit_external(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let changes = items
            .iter()
            .map(|item| ClientFileChange {
                path: item.path.as_str().to_string(),
                kind: "file".into(),
                change: "modified".into(),
                from_path: None,
                blob_oid: item.oid.as_ref().map(|oid| oid.as_str().to_string()),
                size: None,
                versioned: matches!(result.commit, op::CommitState::Committed),
                versioned_reason: None,
            })
            .collect();
        Ok(map_mutation(result, changes, actor, "commit-external"))
    }

    fn copy_items(
        &self,
        actor: &FilesActor,
        items: &[FilesCopyItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let req: Vec<op::CopyItem> = items
            .iter()
            .map(|item| op::CopyItem {
                from: item.from.as_str().to_string(),
                to: item.to.as_str().to_string(),
            })
            .collect();
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.copy_items(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let changes = items
            .iter()
            .map(|item| ClientFileChange {
                path: item.to.as_str().to_string(),
                kind: "file".into(),
                change: "added".into(),
                from_path: Some(item.from.as_str().to_string()),
                blob_oid: None,
                size: None,
                versioned: matches!(result.commit, op::CommitState::Committed),
                versioned_reason: None,
            })
            .collect();
        Ok(map_mutation(result, changes, actor, "copy"))
    }

    fn commit_batch(
        &self,
        actor: &FilesActor,
        r: &FilesCommitBatch,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.require_writable_repo()?;
        let mapped = map_actor(actor);
        let req = op::FilesCommitBatch {
            batch: r.batch.clone(),
            mkdirs: r
                .mkdirs
                .iter()
                .map(|path| path.as_str().to_string())
                .collect(),
            parents: r.parents,
        };
        let core = Arc::clone(&self.core);
        let result = Self::block_on(async move { core.commit_batch(&mapped, &req).await })?
            .map_err(map_files_error)?;
        let changes: Vec<ClientFileChange> = r
            .mkdirs
            .iter()
            .map(|path| ClientFileChange {
                path: path.as_str().to_string(),
                kind: "dir".into(),
                change: "added".into(),
                from_path: None,
                blob_oid: None,
                size: None,
                versioned: matches!(result.commit, op::CommitState::Committed),
                versioned_reason: None,
            })
            .collect();
        Ok(map_mutation(result, changes, actor, "upload"))
    }
}

fn map_actor(actor: &FilesActor) -> op::FilesActor {
    op::FilesActor {
        principal_id: actor.principal_id.clone(),
        os_user: actor.os_user.clone(),
        platform: platform_token(actor.platform),
        session_ref: actor.session_ref.clone(),
    }
}

fn platform_token(platform: Platform) -> String {
    match platform {
        Platform::Web => "web",
        Platform::Mac => "macos",
        Platform::Ios => "ios",
        Platform::Android => "android",
        Platform::Windows => "windows",
    }
    .to_string()
}

fn map_write_target(t: &FileWriteTarget) -> op::FileWriteTarget {
    op::FileWriteTarget {
        path: t.path.as_str().to_string(),
        intent: match t.intent {
            WriteIntent::Edit => op::WriteIntent::Edit,
            WriteIntent::Create => op::WriteIntent::Create,
            WriteIntent::Upload => op::WriteIntent::Upload,
        },
        base_oid: t.base_oid.as_ref().map(|oid| oid.as_str().to_string()),
        expected_bytes: Some(t.size),
        batch: t.batch.clone(),
    }
}

fn map_write_check(check: op::WriteCheck, t: &FileWriteTarget) -> WriteCheck {
    let content_type = content_type_for_name(t.path.as_str()).to_string();
    let etag = etag_for(Some(&t.oid), None);
    match check {
        op::WriteCheck::AlreadyCurrent { oid } => WriteCheck::AlreadyCurrent {
            oid: parse_oid(Some(&oid)).unwrap_or_else(|| t.oid.clone()),
            size: t.size,
            content_type,
            etag,
            identity: None,
        },
        op::WriteCheck::Allowed { current_oid } => {
            if current_oid
                .as_deref()
                .is_some_and(|oid| oid == t.oid.as_str())
            {
                WriteCheck::AlreadyCurrent {
                    oid: t.oid.clone(),
                    size: t.size,
                    content_type,
                    etag,
                    identity: None,
                }
            } else {
                WriteCheck::Ok {
                    etag,
                    oid: t.oid.clone(),
                    size: t.size,
                    content_type,
                    identity: None,
                }
            }
        }
    }
}

fn map_write_result(
    result: op::WriteResult,
    t: &FileWriteTarget,
    actor: &FilesActor,
) -> ClientFileWriteResult {
    let oid = result
        .oid
        .clone()
        .unwrap_or_else(|| t.oid.as_str().to_string());
    let commit = result.sha.as_deref().map(|sha| {
        file_commit(
            sha,
            actor,
            "write",
            vec![result.path.clone()],
            1,
            None,
            None,
        )
    });
    ClientFileWriteResult {
        path: result.path,
        oid,
        size: t.size,
        versioned: matches!(result.commit, op::CommitState::Committed),
        versioned_reason: None,
        commit_state: commit_state_token(result.commit),
        commit,
    }
}

fn map_mutation(
    result: op::MutationResult,
    mut changes: Vec<ClientFileChange>,
    actor: &FilesActor,
    op_name: &str,
) -> ClientFileMutationResult {
    if matches!(
        result.commit,
        op::CommitState::Unchanged | op::CommitState::NoCommit
    ) && !result.disk_changed
    {
        changes.clear();
    }
    let paths: Vec<String> = changes.iter().map(|c| c.path.clone()).collect();
    let count = paths.len() as u32;
    let commit = result
        .sha
        .as_deref()
        .map(|sha| file_commit(sha, actor, op_name, paths, count, None, None));
    ClientFileMutationResult {
        changes_total: changes.len() as u64,
        changes,
        commit_state: commit_state_token(result.commit),
        commit,
    }
}

fn file_commit(
    sha: &str,
    actor: &FilesActor,
    op: &str,
    paths: Vec<String>,
    count: u32,
    title: Option<String>,
    checkpoint: Option<String>,
) -> ClientFileCommit {
    ClientFileCommit {
        sha: sha.to_string(),
        parent_sha: None,
        subject: title.clone().unwrap_or_default(),
        label: ClientGitCommitLabel {
            op: op.to_string(),
            paths,
            to: None,
            count,
            lines_added: None,
            lines_removed: None,
            size_bytes: None,
            versioned: Some(true),
            from_sha: None,
            checkpoint,
            title,
            change: None,
        },
        commit_type: "user".into(),
        initiator: actor.principal_id.clone(),
        committed_at_ms: now_ms(),
    }
}

fn commit_state_token(state: op::CommitState) -> String {
    match state {
        op::CommitState::Committed => "committed",
        op::CommitState::Unchanged => "unchanged",
        op::CommitState::Pending => "pending",
        op::CommitState::Failed => "failed",
        op::CommitState::NoCommit => "no_commit",
        op::CommitState::Staged => "staged",
    }
    .to_string()
}

fn map_sort(sort: FilesListSort) -> op::ListSort {
    match sort {
        FilesListSort::Name => op::ListSort::Name,
        FilesListSort::Modified => op::ListSort::Modified,
        FilesListSort::Size => op::ListSort::Size,
        FilesListSort::Kind => op::ListSort::Kind,
    }
}

fn map_entry(entry: op::ListEntry) -> ClientFileEntry {
    ClientFileEntry {
        name: entry.name,
        path: entry.path,
        kind: entry.kind.as_str().to_string(),
        size: entry.size,
        modified_at_ms: ms_from_ns(entry.modified_ns),
        oid: entry.oid,
        vcs: match entry.vcs {
            None | Some(VcsPathState::Unavailable) => None,
            Some(state) => Some(state.as_str().to_string()),
        },
        content_type: entry.content_type.map(str::to_string),
        read_only: entry.read_only,
        read_only_reason: entry
            .read_only_reason
            .map(|reason| reason.reason().to_string()),
        territory_root: entry.territory_root,
        dotfile: entry.dotfile,
        package: entry.package,
        description: None,
    }
}

fn ms_from_ns(ns: Option<i64>) -> Option<u64> {
    let ns = ns?;
    u64::try_from(ns.saturating_div(1_000_000)).ok()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn encode_cursor(offset: usize, fingerprint: &str) -> String {
    format!("{offset}_{fingerprint}")
}

fn decode_cursor(raw: &str) -> Result<(usize, String), ProviderError> {
    let Some((offset, fingerprint)) = raw.split_once('_') else {
        return Err(ProviderError::Files(FilesFailure::CursorStale));
    };
    let offset = offset
        .parse::<usize>()
        .map_err(|_| ProviderError::Files(FilesFailure::CursorStale))?;
    if fingerprint.is_empty() {
        return Err(ProviderError::Files(FilesFailure::CursorStale));
    }
    Ok((offset, fingerprint.to_string()))
}

fn parse_oid(raw: Option<&str>) -> Option<Oid40> {
    Oid40::parse(raw?).ok()
}

fn map_capacity(kind: op::CapacityKind) -> CapacityKind {
    match kind {
        op::CapacityKind::RawRead => CapacityKind::RawRead,
        op::CapacityKind::RawUpload => CapacityKind::RawUpload,
        op::CapacityKind::SessionRead => CapacityKind::SessionRead,
        op::CapacityKind::SessionUpload => CapacityKind::SessionUpload,
        op::CapacityKind::History => CapacityKind::History,
        op::CapacityKind::Hash => CapacityKind::Hash,
        op::CapacityKind::Mutation => CapacityKind::Mutation,
        op::CapacityKind::Versioning => CapacityKind::Versioning,
        op::CapacityKind::Journal => CapacityKind::Journal,
    }
}

fn map_files_error(err: FilesError) -> ProviderError {
    match err {
        FilesError::InvalidPath(defect) => ProviderError::Files(FilesFailure::InvalidPath(defect)),
        FilesError::NotFound => ProviderError::Files(FilesFailure::NotFound),
        FilesError::ParentNotFound => {
            ProviderError::Files(FilesFailure::ParentNotFound { item: None })
        }
        FilesError::ReadOnly(reason) => {
            ProviderError::Files(FilesFailure::ReadOnly { reason, item: None })
        }
        FilesError::TargetExists {
            current_oid,
            name_collision,
        } => ProviderError::Files(FilesFailure::TargetExists {
            current_oid: parse_oid(current_oid.as_deref()),
            name_collision,
            item: None,
        }),
        FilesError::StaleBase { current_oid, item } => {
            ProviderError::Files(FilesFailure::StaleBase {
                current_oid: parse_oid(current_oid.as_deref()),
                item,
            })
        }
        FilesError::BatchExpired { item } => {
            ProviderError::Files(FilesFailure::BatchExpired { item })
        }
        FilesError::FileBusy => ProviderError::Files(FilesFailure::FileBusy),
        FilesError::Capacity { kind } => {
            ProviderError::Files(FilesFailure::Capacity(map_capacity(kind)))
        }
        FilesError::Unsupported => ProviderError::Unavailable("files".into()),
        FilesError::NotADirectory => {
            ProviderError::Files(FilesFailure::NotADirectory { item: None })
        }
        FilesError::NotAFile { item } => ProviderError::Files(FilesFailure::NotAFile { item }),
        FilesError::NotEmpty { item } => ProviderError::Files(FilesFailure::NotEmpty { item }),
        FilesError::Overlap { item } => ProviderError::Files(FilesFailure::Overlap { item }),
        FilesError::MixedDestinations => ProviderError::Files(FilesFailure::MixedDestinations),
        FilesError::ListingChanged => ProviderError::Files(FilesFailure::CursorStale),
        FilesError::UnversionedContent {
            files,
            bytes,
            unknown: _,
        } => ProviderError::Files(FilesFailure::UnversionedContent {
            files: Some(u64::from(files)),
            bytes: Some(bytes),
            item: None,
        }),
        FilesError::ContentMismatch => ProviderError::Files(FilesFailure::ContentMismatch),
        FilesError::CommitFailed => ProviderError::Files(FilesFailure::CommitFailed),
        FilesError::UnknownVersion => {
            ProviderError::Files(FilesFailure::UnknownVersion { item: None })
        }
        FilesError::TooManyEntries => ProviderError::Files(FilesFailure::TooManyEntries),
        FilesError::BlobTooLarge => ProviderError::Files(FilesFailure::BlobTooLarge),
        FilesError::InsufficientStorage => ProviderError::Files(FilesFailure::InsufficientStorage),
        FilesError::VcsUnavailable { reason } => {
            ProviderError::Files(FilesFailure::VcsUnavailable {
                reason: match reason {
                    "repo" | "no_repo" | "missing" => Some(VcsUnavailableReason::NoRepo),
                    "not_main" => Some(VcsUnavailableReason::NotMain),
                    "locked" => Some(VcsUnavailableReason::Locked),
                    _ => None,
                },
            })
        }
        FilesError::InvalidRequest { token } => match token {
            "ticket_invalid" => ProviderError::Files(FilesFailure::TicketInvalid),
            "head_moved" => ProviderError::Files(FilesFailure::HeadMoved),
            "reserved_namespace" => ProviderError::Files(FilesFailure::ReservedNamespace),
            other => ProviderError::InvalidRequest(other.into()),
        },
        FilesError::Io(msg) => ProviderError::Unavailable(msg),
    }
}

fn map_history_error(err: HistoryError) -> ProviderError {
    match err {
        HistoryError::MalformedSha(_) | HistoryError::UnknownCommit(_) => {
            ProviderError::Files(FilesFailure::UnknownVersion { item: None })
        }
        HistoryError::InvalidPath { .. } => ProviderError::Files(FilesFailure::InvalidPath(
            advance_shared_types::workspace_path::PathDefect::Syntax,
        )),
        HistoryError::PathNotFound { .. } => {
            ProviderError::Files(FilesFailure::UnknownVersion { item: None })
        }
        HistoryError::BlobTooLarge { .. } => ProviderError::Files(FilesFailure::BlobTooLarge),
        HistoryError::Repo(_) => ProviderError::Files(FilesFailure::VcsUnavailable {
            reason: Some(VcsUnavailableReason::NoRepo),
        }),
    }
}
