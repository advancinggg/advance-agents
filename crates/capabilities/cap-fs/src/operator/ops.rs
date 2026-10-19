//! Operator mutation ops (INTEGRATED §3.8–§3.10, OSS-5.md Behaviour).
//!
//! Shared sequence for every op except save-version: validate and optimistic
//! work outside L1, then under L1 replay → prepare (R9 sidecar Always) → CAS
//! → journal.intent → meta-first data → `commit_user` enqueue. save-version
//! replays every pending record and is never journaled.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use advance_git::{
    AdoptPolicy, BlobSource, ChangeRole, GitError, PathChange, PrepareOutcome, PrepareRequest,
    PrepareTarget, Provenance, RepoPath, RestoreSource, SaveVersionOutcome, SaveVersionRequest,
    UserActor, UserCommitLane, UserCommitOutcome, UserCommitRequest, UserCommitStatus, UserOpKind,
    UserOpRefusal,
};
use advance_shared_types::file_identity::FileIdentity;
use advance_shared_types::workspace_path::{
    normalize_workspace_path, PathDefect, ReadOnlyReason, META_SIDECAR_NAME,
};
use rustix::fs::{unlinkat, AtFlags, Dir, FileType};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;
use ulid::Ulid;

use super::fsops::{
    copy_regular_noreplace, mkdir_at, mtime_ns, open_dir_nofollow, publish_noreplace, stat_dev,
    stat_ino, statat_nofollow, trash_rename, DirChain, RootDir,
};
use super::identity::hash_opened_file;
use super::journal::{
    self, drop_record, load_journal, record_touches_path, ItemKind as JournalItemKind, JournalItem,
    JournalMeta, JournalRecord, TypedOp,
};
use super::meta_ops::{put_entry, rekey_entry, take_entry};
use super::policy::{
    allows, check_create_name, portable_keys_collide, CreateRefusal, FilesOp, NodeProtection,
    SubtreeClass,
};
use super::{CapacityKind, FilesError, OperatorFiles};
use crate::meta_maintainer::MetaFile;

/// Concurrent mutation slots (INTEGRATED §3.5).
pub const MUTATION_GATE: usize = 4;
const MUTATION_GATE_WAIT: Duration = Duration::from_millis(250);
const L1_ACQUIRE: Duration = Duration::from_secs(15);
const PREPARE_WAIT: Duration = Duration::from_secs(10);
const DISK_SOURCE_WAIT: Duration = Duration::from_secs(30);
const COMMIT_WAIT: Duration = Duration::from_secs(5);
const SAVE_VERSION_WAIT: Duration = Duration::from_secs(30);
const PAYLOAD_BUDGET: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_TRACKED: u64 = 10 * 1024 * 1024;
const MAX_MUTATION_ITEMS: usize = 256;
const STAGING_DIR: &str = "staging";
const TRASH_DIR: &str = "trash";
const BATCH_TTL: Duration = Duration::from_secs(600);

/// In-flight upload (token → staging name + target).
#[derive(Debug, Clone)]
pub(crate) struct UploadSlot {
    pub staging_name: String,
    pub target: FileWriteTarget,
}

/// Session principal the adapter maps from Client API (INTEGRATED §3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesActor {
    pub principal_id: String,
    pub os_user: String,
    pub platform: String,
    pub session_ref: String,
}

/// Write-ticket intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteIntent {
    Edit,
    Create,
    Upload,
}

/// `check_write` / upload target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWriteTarget {
    pub path: String,
    pub intent: WriteIntent,
    pub base_oid: Option<String>,
    pub expected_bytes: Option<u64>,
    pub batch: Option<String>,
}

/// Lock-free write precheck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteCheck {
    Allowed { current_oid: Option<String> },
    AlreadyCurrent { oid: String },
}

/// Opaque upload ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUploadHandle {
    pub token: String,
}

/// Staging sink the raw route writes into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUploadSink {
    pub handle: FileUploadHandle,
    pub staging_path: PathBuf,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesMkdir {
    pub path: String,
    pub parents: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesMoveItem {
    pub from: String,
    pub to: String,
    pub base_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesDeleteItem {
    pub path: String,
    pub base_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesDelete {
    pub items: Vec<FilesDeleteItem>,
    pub recursive: bool,
    pub include_uncommitted: bool,
    pub confirm_unversioned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesRestoreItem {
    pub path: String,
    pub from_sha: String,
    pub base_oid: Option<String>,
    pub bytes: Vec<u8>,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesRestore {
    pub items: Vec<FilesRestoreItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesSaveVersion {
    pub title: String,
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesExternalItem {
    pub path: String,
    pub oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyItem {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesCommitBatch {
    pub batch: String,
    pub mkdirs: Vec<String>,
    pub parents: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct StagedBatchItem {
    pub path: String,
    pub oid: String,
    #[allow(dead_code)]
    pub size: u64,
    pub base_oid: Option<String>,
    pub staging_name: String,
    pub put_at: std::time::Instant,
    #[allow(dead_code)]
    pub intent: WriteIntent,
    pub force_expired: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitState {
    Committed,
    Unchanged,
    Pending,
    Failed,
    NoCommit,
    Staged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationResult {
    pub op_id: String,
    pub disk_changed: bool,
    pub commit: CommitState,
    pub sha: Option<String>,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    pub op_id: String,
    pub path: String,
    pub oid: Option<String>,
    pub disk_changed: bool,
    pub commit: CommitState,
    pub sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionResult {
    pub op_id: String,
    pub label: String,
    pub tag: String,
    pub title: String,
    pub sha: String,
    pub pending_before: bool,
    pub adopt_incomplete: bool,
}

struct MutationLock<'a> {
    core: &'a OperatorFiles,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _l1: tokio::sync::MutexGuard<'a, ()>,
    lane: Arc<dyn UserCommitLane>,
    op_id: String,
    actor: UserActor,
    provenance: Option<Provenance>,
}

struct ApplyOut {
    changes: Vec<PathChange>,
    #[allow(dead_code)]
    items: Vec<JournalItem>,
    #[allow(dead_code)]
    metas: Vec<JournalMeta>,
    disk_changed: bool,
    await_disk: bool,
    undo: Vec<Undo>,
}

enum Undo {
    Unlink {
        parent: PathBuf,
        name: String,
        dir: bool,
    },
    RenameBack {
        from_parent: PathBuf,
        from_name: String,
        to_parent: PathBuf,
        to_name: String,
    },
}

impl OperatorFiles {
    /// Lock-free write mint (INTEGRATED §3.10).
    pub fn check_write(
        &self,
        _actor: &FilesActor,
        target: &FileWriteTarget,
    ) -> Result<WriteCheck, FilesError> {
        let rel = normalize_rel(&target.path, false)?;
        let (chain, leaf) = match DirChain::walk_parent(&self.root, &rel) {
            Ok(pair) => pair,
            Err(FilesError::NotFound | FilesError::ParentNotFound) if target.batch.is_some() => {
                let Some(name) = rel.rsplit('/').next().filter(|s| !s.is_empty()) else {
                    return Err(FilesError::InvalidPath(PathDefect::Missing));
                };
                check_create_name(name).map_err(map_create)?;
                return Ok(WriteCheck::Allowed { current_oid: None });
            }
            Err(e) => return Err(e),
        };
        match target.intent {
            WriteIntent::Create | WriteIntent::Upload => {
                refuse_write(FilesOp::CreateIn, chain.facts())?;
                check_create_name(&leaf).map_err(map_create)?;
                match statat_nofollow(chain.current_fd(), &leaf) {
                    Ok(_) => {
                        if target.intent == WriteIntent::Create {
                            let current_oid =
                                super::fsops::open_regular_at(chain.current_fd(), &leaf)
                                    .ok()
                                    .and_then(|file| hash_opened_file(&file).ok());
                            let name_collision =
                                sibling_portable_collision(chain.current_fd(), &leaf)?;
                            return Err(FilesError::TargetExists {
                                current_oid,
                                name_collision,
                            });
                        }
                    }
                    Err(FilesError::NotFound) => {
                        if sibling_portable_collision(chain.current_fd(), &leaf)? {
                            return Err(FilesError::TargetExists {
                                current_oid: None,
                                name_collision: true,
                            });
                        }
                    }
                    Err(e) => return Err(e),
                }
                Ok(WriteCheck::Allowed { current_oid: None })
            }
            WriteIntent::Edit => {
                let facts = leaf_facts(&chain, &leaf)?;
                refuse_write(FilesOp::EditInPlace, facts)?;
                let file = super::fsops::open_regular_at(chain.current_fd(), &leaf)?;
                let oid = hash_opened_file(&file).ok();
                if let (Some(base), Some(disk)) = (target.base_oid.as_deref(), oid.as_deref()) {
                    if base != disk {
                        return Err(FilesError::StaleBase {
                            current_oid: oid,
                            item: None,
                        });
                    }
                }
                Ok(WriteCheck::Allowed { current_oid: oid })
            }
        }
    }

    pub fn begin_upload(
        &self,
        actor: &FilesActor,
        target: &FileWriteTarget,
    ) -> Result<FileUploadSink, FilesError> {
        let mut t = target.clone();
        if matches!(t.intent, WriteIntent::Edit) {
            t.intent = WriteIntent::Upload;
        }
        let _ = self.check_write(actor, &t)?;
        if let Some(n) = t.expected_bytes {
            if n > self.limits.max_upload_bytes || n > PAYLOAD_BUDGET {
                return Err(FilesError::BlobTooLarge);
            }
        }
        let token = Ulid::new().to_string();
        let staging_name = format!("up-{token}");
        let dir = ensure_state_subdir(&self.files_state, STAGING_DIR)?;
        let staging_path = dir.join(&staging_name);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .map_err(io)?;
        {
            let mut slots = lock_std(&self.uploads);
            slots.insert(
                token.clone(),
                UploadSlot {
                    staging_name,
                    target: t,
                },
            );
        }
        Ok(FileUploadSink {
            handle: FileUploadHandle { token },
            staging_path,
            max_bytes: self.limits.max_upload_bytes.min(PAYLOAD_BUDGET),
        })
    }

    pub fn abort_upload(&self, handle: FileUploadHandle) {
        let slot = {
            let mut slots = lock_std(&self.uploads);
            slots.remove(&handle.token)
        };
        if let Some(slot) = slot {
            let path = self.files_state.join(STAGING_DIR).join(&slot.staging_name);
            let _ = std::fs::remove_file(path);
        }
    }

    pub async fn finish_upload(
        &self,
        actor: &FilesActor,
        target: &FileWriteTarget,
        handle: FileUploadHandle,
    ) -> Result<WriteResult, FilesError> {
        let slot = {
            let mut slots = lock_std(&self.uploads);
            slots.remove(&handle.token)
        }
        .ok_or(FilesError::InvalidRequest {
            token: "ticket_invalid",
        })?;
        let staging = self.files_state.join(STAGING_DIR).join(&slot.staging_name);
        let file = File::open(&staging).map_err(io)?;
        let meta = file.metadata().map_err(io)?;
        let size = meta.len();
        if size > self.limits.max_upload_bytes || size > PAYLOAD_BUDGET {
            let _ = std::fs::remove_file(&staging);
            return Err(FilesError::BlobTooLarge);
        }
        if let Some(want) = target.expected_bytes.or(slot.target.expected_bytes) {
            if want != size {
                let _ = std::fs::remove_file(&staging);
                return Err(FilesError::ContentMismatch);
            }
        }
        let oid = hash_opened_file(&file).map_err(|e| FilesError::Io(e.to_string()))?;
        let rel = normalize_rel(&target.path, false)?;
        let batch_id = target.batch.clone().or_else(|| slot.target.batch.clone());
        if let Some(batch) = batch_id {
            {
                let mut batches = lock_std(&self.batches);
                batches.entry(batch).or_default().push(StagedBatchItem {
                    path: rel.clone(),
                    oid: oid.clone(),
                    size,
                    base_oid: target.base_oid.clone().or(slot.target.base_oid.clone()),
                    staging_name: slot.staging_name.clone(),
                    put_at: std::time::Instant::now(),
                    intent: target.intent,
                    force_expired: false,
                });
            }
            return Ok(WriteResult {
                op_id: Ulid::new().to_string(),
                path: rel,
                oid: Some(oid),
                disk_changed: false,
                commit: CommitState::Staged,
                sha: None,
            });
        }
        let exists = DirChain::walk_parent(&self.root, &rel)
            .ok()
            .and_then(|(chain, leaf)| statat_nofollow(chain.current_fd(), &leaf).ok())
            .is_some();
        let create = matches!(target.intent, WriteIntent::Create | WriteIntent::Upload)
            && slot.target.base_oid.is_none()
            && target.base_oid.is_none()
            && !exists;
        let parent_rel = parent_of(&rel);
        let mut targets = vec![if create {
            file_target(&rel, AdoptPolicy::IfDiskAbsent)?
        } else {
            file_target(
                &rel,
                target
                    .base_oid
                    .clone()
                    .or(slot.target.base_oid.clone())
                    .map(AdoptPolicy::IfDiskIs)
                    .unwrap_or(AdoptPolicy::IfDiskAbsent),
            )?
        }];
        push_sidecar(&mut targets, &parent_rel)?;
        let typed = if create {
            TypedOp::Create
        } else {
            TypedOp::Upload
        };
        let user_op = if create {
            UserOpKind::Create
        } else {
            UserOpKind::Upload
        };
        let await_disk = size > DEFAULT_MAX_TRACKED;
        let content = if await_disk {
            BlobSource::Disk { oid: oid.clone() }
        } else {
            let bytes = std::fs::read(&staging).map_err(io)?;
            BlobSource::Bytes(bytes)
        };
        let staging_name = slot.staging_name.clone();
        let rel_clone = rel.clone();
        let oid_clone = oid.clone();
        let out = self
            .run_mutation(actor, typed, user_op, vec![rel.clone()], targets, |lock| {
                let (parent, leaf) = DirChain::walk_parent(&lock.core.root, &rel_clone)?;
                refuse_write(
                    if create {
                        FilesOp::CreateIn
                    } else {
                        FilesOp::EditInPlace
                    },
                    if create {
                        parent.facts()
                    } else {
                        leaf_facts(&parent, &leaf)?
                    },
                )?;
                if create {
                    check_create_name(&leaf).map_err(map_create)?;
                    if sibling_portable_collision(parent.current_fd(), &leaf)? {
                        return Err(FilesError::TargetExists {
                            current_oid: None,
                            name_collision: true,
                        });
                    }
                }
                let stage_dir = ensure_state_subdir(&lock.core.files_state, STAGING_DIR)?;
                let stage_root = RootDir::open(&stage_dir)?;
                let mut undo = Vec::new();
                if !create {
                    match statat_nofollow(parent.current_fd(), &leaf) {
                        Ok(_) => {
                            let trash = ensure_state_subdir(&lock.core.files_state, TRASH_DIR)?;
                            let trash_root = RootDir::open(&trash)?;
                            let trash_name = format!("ov-{}", lock.op_id);
                            trash_rename(parent.current_fd(), &leaf, trash_root.fd(), &trash_name)?;
                            undo.push(Undo::RenameBack {
                                from_parent: trash,
                                from_name: trash_name,
                                to_parent: abs_rel(lock.core, &parent_rel),
                                to_name: leaf.clone(),
                            });
                        }
                        Err(FilesError::NotFound) => {}
                        Err(e) => return Err(e),
                    }
                }
                let body_for_meta = if create {
                    Some(
                        std::fs::read(lock.core.files_state.join(STAGING_DIR).join(&staging_name))
                            .map_err(io)?,
                    )
                } else {
                    None
                };
                publish_noreplace(stage_root.fd(), &staging_name, parent.current_fd(), &leaf)?;
                undo.push(Undo::Unlink {
                    parent: abs_rel(lock.core, &parent_rel),
                    name: leaf.clone(),
                    dir: false,
                });
                let put = PathChange::Put {
                    path: repo_path(&rel_clone)?,
                    content,
                    role: ChangeRole::Primary,
                    executable: None,
                    stat: None,
                };
                let mut changes = vec![put];
                let mut metas = Vec::new();
                if create {
                    if let Some(m) = lock.core.maintainer.as_ref() {
                        let parent_abs = abs_rel(lock.core, &parent_rel);
                        let body = body_for_meta.unwrap_or_default();
                        let pre = load_meta_file(&parent_abs);
                        if let Ok((meta_new, _)) = m.add_entry_for_write(pre, &leaf, &body) {
                            store_meta_file(&parent_abs, &meta_new)?;
                            let yaml =
                                std::fs::read(parent_abs.join(META_SIDECAR_NAME)).map_err(io)?;
                            if !yaml.is_empty() {
                                changes.push(sidecar_put_role(
                                    &parent_rel,
                                    yaml,
                                    ChangeRole::Sidecar,
                                )?);
                                metas.push(JournalMeta {
                                    dir_rel: parent_rel.clone(),
                                    post_oid: String::new(),
                                });
                            }
                        }
                    }
                }
                Ok(ApplyOut {
                    changes,
                    items: vec![JournalItem {
                        kind: JournalItemKind::Write,
                        from_rel: None,
                        to_rel: rel_clone.clone(),
                        dev_ino: None,
                        pre_identity: None,
                        pre_oid: target.base_oid.clone(),
                        post_identity: None,
                        post_oid: Some(oid_clone.clone()),
                        entry_pre: None,
                        temp_location: Some(format!("{STAGING_DIR}/{staging_name}")),
                    }],
                    metas,
                    disk_changed: true,
                    await_disk,
                    undo,
                })
            })
            .await;
        if out.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        let result = out?;
        Ok(WriteResult {
            op_id: result.op_id,
            path: rel,
            oid: Some(oid),
            disk_changed: result.disk_changed,
            commit: result.commit,
            sha: result.sha,
        })
    }

    /// Test seam: age every staged PUT of `batch` past the 10-minute TTL.
    pub fn expire_staged_puts(&self, batch: &str) {
        let mut batches = lock_std(&self.batches);
        if let Some(items) = batches.get_mut(batch) {
            for item in items {
                item.force_expired = true;
            }
        }
    }

    pub async fn commit_batch(
        &self,
        actor: &FilesActor,
        req: &FilesCommitBatch,
    ) -> Result<MutationResult, FilesError> {
        if req.mkdirs.len() > MAX_MUTATION_ITEMS {
            return Err(FilesError::InvalidRequest {
                token: "item_count",
            });
        }
        let items = {
            let mut batches = lock_std(&self.batches);
            batches.remove(&req.batch).unwrap_or_default()
        };
        if items.is_empty() {
            return Err(FilesError::BatchExpired { item: None });
        }
        for (i, item) in items.iter().enumerate() {
            if item.force_expired || item.put_at.elapsed() > BATCH_TTL {
                drop_staged_files(self, &items);
                return Err(FilesError::BatchExpired {
                    item: Some(i as u32),
                });
            }
            if let Some(base) = item.base_oid.as_deref() {
                let disk = current_oid_at(self, &item.path)?;
                if disk.as_deref() != Some(base) {
                    drop_staged_files(self, &items);
                    return Err(FilesError::StaleBase {
                        current_oid: disk,
                        item: Some(i as u32),
                    });
                }
            }
        }
        let mut mkdir_rels = Vec::new();
        let mut seen_mkdir = HashSet::new();
        for raw in &req.mkdirs {
            let rel = normalize_rel(raw, false)?;
            if seen_mkdir.insert(rel.clone()) {
                mkdir_rels.push(rel);
            }
        }
        let mut targets = Vec::new();
        let mut touch = Vec::new();
        for rel in &mkdir_rels {
            touch.push(rel.clone());
            push_sidecar(&mut targets, rel)?;
            push_sidecar(&mut targets, &parent_of(rel))?;
        }
        for item in &items {
            touch.push(item.path.clone());
            let adopt = item
                .base_oid
                .clone()
                .map(AdoptPolicy::IfDiskIs)
                .unwrap_or(AdoptPolicy::IfDiskAbsent);
            targets.push(file_target(&item.path, adopt)?);
            push_sidecar(&mut targets, &parent_of(&item.path))?;
        }
        let targets = unique_prepare_targets(targets);
        let mkdir_parents = req.parents;
        let mkdir_rels_clone = mkdir_rels.clone();
        let items_clone = items.clone();
        let out = self
            .run_mutation(
                actor,
                TypedOp::Upload,
                UserOpKind::Upload,
                touch,
                targets,
                move |lock| {
                    let mut changes = Vec::new();
                    let mut jitems = Vec::new();
                    let mut metas = Vec::new();
                    let mut undo = Vec::new();
                    for rel in &mkdir_rels_clone {
                        ensure_dir_rel(
                            lock,
                            rel,
                            mkdir_parents,
                            &mut changes,
                            &mut jitems,
                            &mut metas,
                            &mut undo,
                        )?;
                    }
                    for item in &items_clone {
                        publish_staged_item(
                            lock,
                            item,
                            &mut changes,
                            &mut jitems,
                            &mut metas,
                            &mut undo,
                        )?;
                    }
                    Ok(ApplyOut {
                        changes: unique_put_changes(changes),
                        items: jitems,
                        metas,
                        disk_changed: true,
                        await_disk: false,
                        undo,
                    })
                },
            )
            .await;
        if out.is_err() {
            drop_staged_files(self, &items);
        } else {
            drop_staged_files(self, &items);
        }
        out
    }

    pub async fn mkdir(
        &self,
        actor: &FilesActor,
        req: &FilesMkdir,
    ) -> Result<MutationResult, FilesError> {
        let rel = normalize_rel(&req.path, false)?;
        let parts: Vec<String> = rel.split('/').map(str::to_string).collect();
        let mut chain = DirChain::new(&self.root);
        let mut missing: Vec<String> = Vec::new();
        for name in &parts {
            if !missing.is_empty() {
                missing.push(name.clone());
                continue;
            }
            match chain.descend(name) {
                Ok(()) => {}
                Err(FilesError::NotFound) => missing.push(name.clone()),
                Err(e) => return Err(e),
            }
        }
        if missing.is_empty() {
            if req.parents {
                return Ok(unchanged_result());
            }
            return Err(FilesError::TargetExists {
                current_oid: None,
                name_collision: false,
            });
        }
        if !req.parents && missing.len() != 1 {
            return Err(FilesError::ParentNotFound);
        }
        refuse_write(FilesOp::MkdirIn, chain.facts())?;
        for name in &missing {
            check_create_name(name).map_err(map_create)?;
        }
        let ancestor = chain.rel_disk();
        let mut targets = Vec::new();
        let mut created_rels = Vec::new();
        let mut cursor = ancestor.clone();
        for name in &missing {
            cursor = join_rel(&cursor, name);
            created_rels.push(cursor.clone());
            push_sidecar(&mut targets, &cursor)?;
        }
        push_sidecar(&mut targets, &ancestor)?;
        self.run_mutation(
            actor,
            TypedOp::CreateFolder,
            UserOpKind::CreateFolder,
            created_rels.clone(),
            targets,
            |lock| {
                let mut parent_chain = if ancestor.is_empty() {
                    DirChain::new(&lock.core.root)
                } else {
                    DirChain::walk_dir(&lock.core.root, &ancestor)?
                };
                let mut changes = Vec::new();
                let mut items = Vec::new();
                let mut metas = Vec::new();
                let mut undo = Vec::new();
                let mut parent_rel = ancestor.clone();
                for name in &missing {
                    mkdir_at(parent_chain.current_fd(), name)?;
                    undo.push(Undo::Unlink {
                        parent: abs_rel(lock.core, &parent_rel),
                        name: name.clone(),
                        dir: true,
                    });
                    parent_chain.descend(name)?;
                    let child_rel = join_rel(&parent_rel, name);
                    if let Some(m) = lock.core.maintainer.as_ref() {
                        let child_abs = abs_rel(lock.core, &child_rel);
                        let bytes = write_dir_sidecar(m, &child_abs, name)?;
                        if !bytes.is_empty() {
                            changes.push(sidecar_put_role(&child_rel, bytes, ChangeRole::Primary)?);
                            metas.push(JournalMeta {
                                dir_rel: child_rel.clone(),
                                post_oid: String::new(),
                            });
                        }
                    }
                    items.push(JournalItem {
                        kind: JournalItemKind::Mkdir,
                        from_rel: None,
                        to_rel: child_rel.clone(),
                        dev_ino: None,
                        pre_identity: None,
                        pre_oid: None,
                        post_identity: None,
                        post_oid: None,
                        entry_pre: None,
                        temp_location: None,
                    });
                    parent_rel = child_rel;
                }
                Ok(ApplyOut {
                    changes,
                    items,
                    metas,
                    disk_changed: true,
                    await_disk: false,
                    undo,
                })
            },
        )
        .await
    }

    pub async fn move_items(
        &self,
        actor: &FilesActor,
        items: &[FilesMoveItem],
    ) -> Result<MutationResult, FilesError> {
        if items.is_empty() || items.len() > MAX_MUTATION_ITEMS {
            return Err(FilesError::InvalidRequest {
                token: "item_count",
            });
        }
        let mut normalized: Vec<(String, String, Option<String>)> = Vec::new();
        for (i, it) in items.iter().enumerate() {
            let from = normalize_rel(&it.from, false)?;
            let to = normalize_rel(&it.to, false)?;
            if paths_overlap(&from, &to) {
                return Err(FilesError::Overlap {
                    item: Some(i as u32),
                });
            }
            for (j, prev) in normalized.iter().enumerate() {
                if paths_overlap(&prev.0, &from) {
                    return Err(FilesError::Overlap {
                        item: Some(j as u32),
                    });
                }
            }
            let dest_leaf = leaf_of(&to);
            check_create_name(&dest_leaf).map_err(map_create)?;
            normalized.push((from, to, it.base_oid.clone()));
        }
        let dest_parents: Vec<String> = normalized.iter().map(|(_, to, _)| parent_of(to)).collect();
        if dest_parents.windows(2).any(|w| w[0] != w[1]) {
            return Err(FilesError::MixedDestinations);
        }
        let mut targets = Vec::new();
        let mut touch: Vec<String> = Vec::new();
        for (from, to, _) in &normalized {
            targets.push(file_or_tree(self, from, AdoptPolicy::Always)?);
            targets.push(file_target(to, AdoptPolicy::IfDiskAbsent)?);
            push_sidecar(&mut targets, &parent_of(from))?;
            push_sidecar(&mut targets, &parent_of(to))?;
            touch.push(from.clone());
            touch.push(to.clone());
        }
        let rename = normalized.len() == 1
            && normalized
                .first()
                .is_some_and(|(from, to, _)| parent_of(from) == parent_of(to));
        let op = if rename {
            UserOpKind::Rename
        } else {
            UserOpKind::Move
        };
        let typed = if rename {
            TypedOp::Rename
        } else {
            TypedOp::Move
        };
        self.run_mutation(actor, typed, op, touch, targets, |lock| {
            let mut changes = Vec::new();
            let mut jitems = Vec::new();
            let mut undo = Vec::new();
            for (i, (from, to, _base)) in normalized.iter().enumerate() {
                let (from_chain, from_leaf) = DirChain::walk_parent(&lock.core.root, from)?;
                refuse_write(FilesOp::MoveSource, leaf_facts(&from_chain, &from_leaf)?)?;
                let (to_chain, to_leaf) = DirChain::walk_parent(&lock.core.root, to)?;
                refuse_write(FilesOp::CreateIn, to_chain.facts())?;
                let st = statat_nofollow(from_chain.current_fd(), &from_leaf)?;
                let is_dir = FileType::from_raw_mode(st.st_mode) == FileType::Directory;
                rekey_move_sidecars(lock.core, from, to, &from_leaf, &to_leaf)?;
                publish_noreplace(
                    from_chain.current_fd(),
                    &from_leaf,
                    to_chain.current_fd(),
                    &to_leaf,
                )?;
                undo.push(Undo::RenameBack {
                    from_parent: abs_rel(lock.core, &parent_of(to)),
                    from_name: to_leaf.clone(),
                    to_parent: abs_rel(lock.core, &parent_of(from)),
                    to_name: from_leaf.clone(),
                });
                let from_p = repo_path(from)?;
                let to_p = repo_path(to)?;
                changes.push(if is_dir {
                    PathChange::MoveTree {
                        from: from_p,
                        to: to_p,
                        oid: None,
                    }
                } else {
                    PathChange::Move {
                        from: from_p,
                        to: to_p,
                        oid: None,
                    }
                });
                jitems.push(JournalItem {
                    kind: JournalItemKind::Move,
                    from_rel: Some(from.clone()),
                    to_rel: to.clone(),
                    dev_ino: Some(journal::DevIno {
                        dev: stat_dev(&st),
                        ino: stat_ino(&st),
                    }),
                    pre_identity: None,
                    pre_oid: items.get(i).and_then(|it| it.base_oid.clone()),
                    post_identity: None,
                    post_oid: None,
                    entry_pre: None,
                    temp_location: None,
                });
            }
            Ok(ApplyOut {
                changes,
                items: jitems,
                metas: Vec::new(),
                disk_changed: true,
                await_disk: false,
                undo,
            })
        })
        .await
    }

    pub async fn delete(
        &self,
        actor: &FilesActor,
        req: &FilesDelete,
    ) -> Result<MutationResult, FilesError> {
        if req.items.is_empty() || req.items.len() > MAX_MUTATION_ITEMS {
            return Err(FilesError::InvalidRequest {
                token: "item_count",
            });
        }
        let mut paths: Vec<String> = Vec::new();
        for (i, it) in req.items.iter().enumerate() {
            let p = normalize_rel(&it.path, false)?;
            for prev in &paths {
                if paths_overlap(prev, &p) {
                    return Err(FilesError::Overlap {
                        item: Some(i as u32),
                    });
                }
            }
            paths.push(p);
        }
        let mut targets = Vec::new();
        for p in &paths {
            targets.push(file_or_tree(self, p, AdoptPolicy::Always)?);
            push_sidecar(&mut targets, &parent_of(p))?;
        }
        let recursive = req.recursive;
        let confirm = req.confirm_unversioned;
        let include = req.include_uncommitted;
        self.run_mutation(
            actor,
            TypedOp::Delete,
            UserOpKind::Delete,
            paths.clone(),
            targets,
            |lock| {
                let st = lock.last_prepare.as_ref();
                if let Some(prep) = st {
                    if (prep.unversioned_count > 0 || prep.adopt_incomplete) && !confirm {
                        return Err(FilesError::UnversionedContent {
                            files: prep.unversioned_count,
                            bytes: prep.unversioned_bytes,
                            unknown: prep.adopt_incomplete,
                        });
                    }
                    if prep.unversioned_count > 0 && !include && !confirm {
                        return Err(FilesError::InvalidRequest {
                            token: "uncommitted_changes",
                        });
                    }
                }
                let trash = ensure_state_subdir(&lock.core.files_state, TRASH_DIR)?;
                let trash_root = RootDir::open(&trash)?;
                let mut changes = Vec::new();
                let mut jitems = Vec::new();
                let mut undo = Vec::new();
                for (n, p) in paths.iter().enumerate() {
                    let (chain, leaf) = DirChain::walk_parent(&lock.core.root, p)?;
                    refuse_write(FilesOp::Delete, leaf_facts(&chain, &leaf)?)?;
                    let st = statat_nofollow(chain.current_fd(), &leaf)?;
                    let is_dir = FileType::from_raw_mode(st.st_mode) == FileType::Directory;
                    if is_dir && !recursive && dir_has_user_children(chain.current_fd(), &leaf)? {
                        return Err(FilesError::NotEmpty {
                            item: Some(n as u32),
                        });
                    }
                    let trash_name = format!("{}-{n}", lock.op_id);
                    trash_rename(chain.current_fd(), &leaf, trash_root.fd(), &trash_name)?;
                    undo.push(Undo::RenameBack {
                        from_parent: trash.clone(),
                        from_name: trash_name.clone(),
                        to_parent: abs_rel(lock.core, &parent_of(p)),
                        to_name: leaf.clone(),
                    });
                    let rp = repo_path(p)?;
                    changes.push(if is_dir {
                        PathChange::RemoveTree { dir: rp }
                    } else {
                        PathChange::Remove {
                            path: rp,
                            role: ChangeRole::Primary,
                        }
                    });
                    jitems.push(JournalItem {
                        kind: JournalItemKind::Trash,
                        from_rel: Some(p.clone()),
                        to_rel: p.clone(),
                        dev_ino: Some(journal::DevIno {
                            dev: stat_dev(&st),
                            ino: stat_ino(&st),
                        }),
                        pre_identity: None,
                        pre_oid: req.items.get(n).and_then(|it| it.base_oid.clone()),
                        post_identity: None,
                        post_oid: None,
                        entry_pre: None,
                        temp_location: Some(format!("{TRASH_DIR}/{trash_name}")),
                    });
                }
                Ok(ApplyOut {
                    changes,
                    items: jitems,
                    metas: Vec::new(),
                    disk_changed: true,
                    await_disk: false,
                    undo,
                })
            },
        )
        .await
    }

    pub async fn restore(
        &self,
        actor: &FilesActor,
        req: &FilesRestore,
    ) -> Result<MutationResult, FilesError> {
        if req.items.is_empty() || req.items.len() > MAX_MUTATION_ITEMS {
            return Err(FilesError::InvalidRequest {
                token: "item_count",
            });
        }
        let mut targets = Vec::new();
        let mut touch = Vec::new();
        let mut total = 0u64;
        for it in &req.items {
            if it.from_sha.is_empty() {
                return Err(FilesError::UnknownVersion);
            }
            if it.bytes.len() as u64 > 64 * 1024 * 1024 {
                return Err(FilesError::BlobTooLarge);
            }
            total = total.saturating_add(it.bytes.len() as u64);
            if total > PAYLOAD_BUDGET {
                return Err(FilesError::BlobTooLarge);
            }
            let rel = normalize_rel(&it.path, false)?;
            let exists = DirChain::walk_parent(&self.root, &rel)
                .ok()
                .and_then(|(chain, leaf)| statat_nofollow(chain.current_fd(), &leaf).ok())
                .is_some();
            let adopt = match it.base_oid.clone() {
                Some(oid) => AdoptPolicy::IfDiskIs(oid),
                None if exists => AdoptPolicy::Always,
                None => AdoptPolicy::IfDiskAbsent,
            };
            targets.push(file_target(&rel, adopt)?);
            push_sidecar(&mut targets, &parent_of(&rel))?;
            touch.push(rel);
        }
        let sha = req
            .items
            .first()
            .map(|it| it.from_sha.clone())
            .unwrap_or_default();
        let items = req.items.clone();
        self.run_mutation(
            actor,
            TypedOp::Restore { sha: sha.clone() },
            UserOpKind::Restore(RestoreSource::Commit(sha)),
            touch,
            targets,
            |lock| {
                let mut changes = Vec::new();
                let mut jitems = Vec::new();
                let mut undo = Vec::new();
                for it in &items {
                    let rel = normalize_rel(&it.path, false)?;
                    let (parent, leaf) = DirChain::walk_parent(&lock.core.root, &rel)?;
                    let exists = statat_nofollow(parent.current_fd(), &leaf).is_ok();
                    if exists {
                        refuse_write(FilesOp::EditInPlace, leaf_facts(&parent, &leaf)?)?;
                        let trash = ensure_state_subdir(&lock.core.files_state, TRASH_DIR)?;
                        let trash_root = RootDir::open(&trash)?;
                        let trash_name = format!("rs-ov-{}", lock.op_id);
                        trash_rename(parent.current_fd(), &leaf, trash_root.fd(), &trash_name)?;
                        undo.push(Undo::RenameBack {
                            from_parent: trash,
                            from_name: trash_name,
                            to_parent: abs_rel(lock.core, &parent_of(&rel)),
                            to_name: leaf.clone(),
                        });
                    } else {
                        refuse_write(FilesOp::CreateIn, parent.facts())?;
                        check_create_name(&leaf).map_err(map_create)?;
                    }
                    let stage_dir = ensure_state_subdir(&lock.core.files_state, STAGING_DIR)?;
                    let tmp = format!("rs-{}-{leaf}", lock.op_id);
                    let tmp_path = stage_dir.join(&tmp);
                    std::fs::write(&tmp_path, &it.bytes).map_err(io)?;
                    let stage_root = RootDir::open(&stage_dir)?;
                    publish_noreplace(stage_root.fd(), &tmp, parent.current_fd(), &leaf)?;
                    let _ = std::fs::remove_file(&tmp_path);
                    undo.push(Undo::Unlink {
                        parent: abs_rel(lock.core, &parent_of(&rel)),
                        name: leaf,
                        dir: false,
                    });
                    changes.push(PathChange::Put {
                        path: repo_path(&rel)?,
                        content: BlobSource::Bytes(it.bytes.clone()),
                        role: ChangeRole::Primary,
                        executable: Some(it.executable),
                        stat: None,
                    });
                    jitems.push(JournalItem {
                        kind: JournalItemKind::Write,
                        from_rel: None,
                        to_rel: rel,
                        dev_ino: None,
                        pre_identity: None,
                        pre_oid: it.base_oid.clone(),
                        post_identity: None,
                        post_oid: None,
                        entry_pre: None,
                        temp_location: None,
                    });
                }
                Ok(ApplyOut {
                    changes,
                    items: jitems,
                    metas: Vec::new(),
                    disk_changed: true,
                    await_disk: false,
                    undo,
                })
            },
        )
        .await
    }

    pub async fn save_version(
        &self,
        actor: &FilesActor,
        req: &FilesSaveVersion,
    ) -> Result<VersionResult, FilesError> {
        if req.title.is_empty() {
            return Err(FilesError::InvalidRequest {
                token: "invalid_title",
            });
        }
        let permit = self.acquire_mutation_permit().await?;
        let lock = self.begin_lock(actor, permit).await?;
        let pending_before = replay_records(lock.core, &lock.lane, None)?;
        let paths = match &req.paths {
            Some(ps) => {
                let mut out = Vec::new();
                for p in ps {
                    out.push(repo_path(&normalize_rel(p, false)?)?);
                }
                Some(out)
            }
            None => None,
        };
        let rx = lock.lane.save_version(SaveVersionRequest {
            actor: lock.actor.clone(),
            title: req.title.clone(),
            paths,
            adopt: true,
            at: None,
            correlation_id: Some(lock.op_id.clone()),
            provenance: lock.provenance.clone(),
        });
        let outcome = recv_save(rx, SAVE_VERSION_WAIT).await?;
        Ok(VersionResult {
            op_id: lock.op_id.clone(),
            label: outcome.label,
            tag: outcome.tag,
            title: outcome.title,
            sha: outcome.sha,
            pending_before,
            adopt_incomplete: outcome.adopt_incomplete,
        })
    }

    pub async fn commit_external(
        &self,
        actor: &FilesActor,
        items: &[FilesExternalItem],
    ) -> Result<MutationResult, FilesError> {
        if items.is_empty() || items.len() > 64 {
            return Err(FilesError::InvalidRequest {
                token: "item_count",
            });
        }
        let mut targets = Vec::new();
        let mut touch = Vec::new();
        for it in items {
            let rel = normalize_rel(&it.path, false)?;
            targets.push(file_target(&rel, AdoptPolicy::Never)?);
            push_sidecar(&mut targets, &parent_of(&rel))?;
            touch.push(rel);
        }
        let captured: Vec<FilesExternalItem> = items.to_vec();
        self.run_mutation(
            actor,
            TypedOp::EditExternal,
            UserOpKind::EditExternal,
            touch,
            targets,
            |lock| {
                let mut changes = Vec::new();
                let mut jitems = Vec::new();
                for it in &captured {
                    let rel = normalize_rel(&it.path, false)?;
                    let present = DirChain::walk_parent(&lock.core.root, &rel)
                        .ok()
                        .and_then(|(c, leaf)| statat_nofollow(c.current_fd(), &leaf).ok());
                    match (present, it.oid.as_ref()) {
                        (None, None) => {
                            changes.push(PathChange::Remove {
                                path: repo_path(&rel)?,
                                role: ChangeRole::Primary,
                            });
                        }
                        (None, Some(_)) => {
                            return Err(FilesError::StaleBase {
                                current_oid: None,
                                item: None,
                            });
                        }
                        (Some(_), None) => {
                            return Err(FilesError::StaleBase {
                                current_oid: None,
                                item: None,
                            });
                        }
                        (Some(st), Some(oid)) => {
                            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                                return Err(FilesError::NotAFile { item: None });
                            }
                            let ident = FileIdentity {
                                dev: stat_dev(&st),
                                ino: stat_ino(&st),
                                size: st.st_size as u64,
                                mtime_ns: mtime_ns(&st),
                            };
                            if let Some(cached) = {
                                let mut cache = lock_std(&lock.core.oids);
                                cache.get(&ident).map(str::to_string)
                            } {
                                if cached != *oid {
                                    return Err(FilesError::StaleBase {
                                        current_oid: Some(cached),
                                        item: None,
                                    });
                                }
                            }
                            changes.push(PathChange::Put {
                                path: repo_path(&rel)?,
                                content: BlobSource::Disk { oid: oid.clone() },
                                role: ChangeRole::Primary,
                                executable: None,
                                stat: None,
                            });
                        }
                    }
                    jitems.push(JournalItem {
                        kind: JournalItemKind::Write,
                        from_rel: None,
                        to_rel: rel,
                        dev_ino: None,
                        pre_identity: None,
                        pre_oid: it.oid.clone(),
                        post_identity: None,
                        post_oid: it.oid.clone(),
                        entry_pre: None,
                        temp_location: None,
                    });
                }
                Ok(ApplyOut {
                    changes,
                    items: jitems,
                    metas: Vec::new(),
                    disk_changed: false,
                    await_disk: true,
                    undo: Vec::new(),
                })
            },
        )
        .await
    }

    pub async fn copy_items(
        &self,
        actor: &FilesActor,
        items: &[CopyItem],
    ) -> Result<MutationResult, FilesError> {
        if items.is_empty() || items.len() > MAX_MUTATION_ITEMS {
            return Err(FilesError::InvalidRequest {
                token: "item_count",
            });
        }
        let mut normalized: Vec<(String, String)> = Vec::new();
        for it in items {
            let from = normalize_rel(&it.from, false)?;
            let to = normalize_rel(&it.to, false)?;
            check_create_name(&leaf_of(&to)).map_err(map_create)?;
            normalized.push((from, to));
        }
        let dest_parents: Vec<String> = normalized.iter().map(|(_, to)| parent_of(to)).collect();
        if dest_parents.windows(2).any(|w| w[0] != w[1]) {
            return Err(FilesError::MixedDestinations);
        }
        let mut targets = Vec::new();
        let mut touch = Vec::new();
        for (from, to) in &normalized {
            targets.push(file_or_tree(self, from, AdoptPolicy::Always)?);
            targets.push(file_target(to, AdoptPolicy::IfDiskAbsent)?);
            push_sidecar(&mut targets, &parent_of(to))?;
            touch.push(from.clone());
            touch.push(to.clone());
        }
        self.run_mutation(
            actor,
            TypedOp::Copy,
            UserOpKind::Copy,
            touch,
            targets,
            |lock| {
                let mut changes = Vec::new();
                let mut jitems = Vec::new();
                let mut undo = Vec::new();
                for (from, to) in &normalized {
                    let (from_chain, from_leaf) = DirChain::walk_parent(&lock.core.root, from)?;
                    refuse_write(FilesOp::Read, from_chain.facts())?;
                    let (to_chain, to_leaf) = DirChain::walk_parent(&lock.core.root, to)?;
                    refuse_write(FilesOp::CreateIn, to_chain.facts())?;
                    let st = statat_nofollow(from_chain.current_fd(), &from_leaf)?;
                    let is_dir = FileType::from_raw_mode(st.st_mode) == FileType::Directory;
                    if is_dir {
                        mkdir_at(to_chain.current_fd(), &to_leaf)?;
                        copy_dir_children(
                            from_chain.current_fd(),
                            &from_leaf,
                            to_chain.current_fd(),
                            &to_leaf,
                        )?;
                        changes.push(PathChange::CopyTree {
                            from: repo_path(from)?,
                            to: repo_path(to)?,
                            oid: None,
                        });
                    } else {
                        copy_regular_noreplace(
                            from_chain.current_fd(),
                            &from_leaf,
                            to_chain.current_fd(),
                            &to_leaf,
                        )?;
                        changes.push(PathChange::Copy {
                            from: repo_path(from)?,
                            to: repo_path(to)?,
                            oid: None,
                        });
                    }
                    undo.push(Undo::Unlink {
                        parent: abs_rel(lock.core, &parent_of(to)),
                        name: to_leaf,
                        dir: is_dir,
                    });
                    jitems.push(JournalItem {
                        kind: JournalItemKind::Write,
                        from_rel: Some(from.clone()),
                        to_rel: to.clone(),
                        dev_ino: None,
                        pre_identity: None,
                        pre_oid: None,
                        post_identity: None,
                        post_oid: None,
                        entry_pre: None,
                        temp_location: None,
                    });
                }
                Ok(ApplyOut {
                    changes,
                    items: jitems,
                    metas: Vec::new(),
                    disk_changed: true,
                    await_disk: false,
                    undo,
                })
            },
        )
        .await
    }
}

struct MutationLockExt<'a> {
    inner: MutationLock<'a>,
    last_prepare: Option<PrepareOutcome>,
}

impl<'a> std::ops::Deref for MutationLockExt<'a> {
    type Target = MutationLock<'a>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl OperatorFiles {
    async fn acquire_mutation_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, FilesError> {
        tokio::time::timeout(
            MUTATION_GATE_WAIT,
            Arc::clone(&self.mutation_gate).acquire_owned(),
        )
        .await
        .map_err(|_| FilesError::Capacity {
            kind: CapacityKind::Mutation,
        })?
        .map_err(|_| FilesError::Capacity {
            kind: CapacityKind::Mutation,
        })
    }

    async fn acquire_l1(&self) -> Result<tokio::sync::MutexGuard<'_, ()>, FilesError> {
        let Some(m) = self.maintainer.as_ref() else {
            return Err(FilesError::Capacity {
                kind: CapacityKind::Versioning,
            });
        };
        if let Some(g) = m.try_acquire() {
            return Ok(g);
        }
        tokio::time::timeout(L1_ACQUIRE, m.acquire())
            .await
            .map_err(|_| FilesError::Capacity {
                kind: CapacityKind::Versioning,
            })
    }

    fn require_lane(&self) -> Result<Arc<dyn UserCommitLane>, FilesError> {
        self.lane.clone().ok_or(FilesError::Capacity {
            kind: CapacityKind::Versioning,
        })
    }

    async fn begin_lock(
        &self,
        actor: &FilesActor,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<MutationLock<'_>, FilesError> {
        let lane = self.require_lane()?;
        let l1 = self.acquire_l1().await?;
        Ok(MutationLock {
            core: self,
            _permit: permit,
            _l1: l1,
            lane,
            op_id: Ulid::new().to_string(),
            actor: UserActor::from_principal_id(&actor.principal_id),
            provenance: provenance_of(actor),
        })
    }

    async fn run_mutation<F>(
        &self,
        actor: &FilesActor,
        typed: TypedOp,
        user_op: UserOpKind,
        touch: Vec<String>,
        targets: Vec<PrepareTarget>,
        apply: F,
    ) -> Result<MutationResult, FilesError>
    where
        F: FnOnce(&MutationLockExt<'_>) -> Result<ApplyOut, FilesError>,
    {
        let permit = self.acquire_mutation_permit().await?;
        let lock = self.begin_lock(actor, permit).await?;
        let _ = replay_records(lock.core, &lock.lane, Some(&touch))?;
        let prep = prepare_cas(lock.core, &lock.lane, targets, &lock.op_id).await?;
        let ext = MutationLockExt {
            inner: lock,
            last_prepare: Some(prep),
        };
        let mut record = JournalRecord::new(ext.op_id.clone(), ext.actor.initiator(), typed);
        record.items = placeholder_items(&touch);
        record.disk_changed = true;
        if let Err(e) = ext.core.journal_intent(&record) {
            return Err(e);
        }
        let applied = match apply(&ext) {
            Ok(a) => a,
            Err(e) => {
                let _ = drop_record(&ext.core.files_state, &ext.op_id);
                return Err(e);
            }
        };
        let req = UserCommitRequest {
            actor: ext.actor.clone(),
            op: user_op,
            changes: applied.changes,
            correlation_id: Some(ext.op_id.clone()),
            provenance: ext.provenance.clone(),
        };
        let mut rx = ext.lane.commit_user(req);
        let mut under = None;
        if applied.await_disk {
            under = take_commit(&mut rx, DISK_SOURCE_WAIT).await;
        }
        let op_id = ext.op_id.clone();
        let files_state = ext.core.files_state.clone();
        drop(ext);
        let settled = match under {
            Some(Ok(out)) => classify_commit(out),
            Some(Err(FilesError::CommitFailed)) => {
                undo_disk(&applied.undo);
                let _ = drop_record(&files_state, &op_id);
                return Err(FilesError::CommitFailed);
            }
            Some(Err(e)) => return Err(e),
            None => match take_commit(&mut rx, COMMIT_WAIT).await {
                Some(Ok(out)) => classify_commit(out),
                _ => (CommitState::Pending, None),
            },
        };
        match settled.0 {
            CommitState::Committed
            | CommitState::Unchanged
            | CommitState::NoCommit
            | CommitState::Staged => {
                let _ = drop_record(&files_state, &op_id);
                purge_trash_for_op(&files_state, &op_id);
            }
            CommitState::Pending | CommitState::Failed => {
                self.notify_retry();
            }
        }
        Ok(MutationResult {
            op_id,
            disk_changed: applied.disk_changed,
            commit: settled.0,
            sha: settled.1,
            warnings: Vec::new(),
        })
    }
}

fn placeholder_items(touch: &[String]) -> Vec<JournalItem> {
    touch
        .iter()
        .map(|p| JournalItem {
            kind: JournalItemKind::Write,
            from_rel: None,
            to_rel: p.clone(),
            dev_ino: None,
            pre_identity: None,
            pre_oid: None,
            post_identity: None,
            post_oid: None,
            entry_pre: None,
            temp_location: None,
        })
        .collect()
}

fn replay_records(
    core: &OperatorFiles,
    lane: &Arc<dyn UserCommitLane>,
    only: Option<&[String]>,
) -> Result<bool, FilesError> {
    let recs = load_journal(&core.files_state)?;
    let mut any = false;
    let mut held = Vec::new();
    for rec in recs {
        let touch = match only {
            Some(paths) => paths.iter().any(|p| record_touches_path(&rec, p)),
            None => true,
        };
        if !touch {
            continue;
        }
        any = true;
        if let Some(req) = resubmit(&rec) {
            held.push(lane.commit_user(req));
        }
    }
    drop(held);
    Ok(any)
}

fn resubmit(rec: &JournalRecord) -> Option<UserCommitRequest> {
    let op = match &rec.op {
        TypedOp::Edit => UserOpKind::Edit,
        TypedOp::Create => UserOpKind::Create,
        TypedOp::CreateFolder => UserOpKind::CreateFolder,
        TypedOp::Rename => UserOpKind::Rename,
        TypedOp::Move => UserOpKind::Move,
        TypedOp::Copy => UserOpKind::Copy,
        TypedOp::Delete => UserOpKind::Delete,
        TypedOp::Restore { sha } => UserOpKind::Restore(RestoreSource::Commit(sha.clone())),
        TypedOp::Upload => UserOpKind::Upload,
        TypedOp::EditExternal => UserOpKind::EditExternal,
    };
    let mut changes = Vec::new();
    for item in &rec.items {
        let Ok(path) = repo_path(&item.to_rel) else {
            continue;
        };
        match item.kind {
            JournalItemKind::Write => {
                if let Some(oid) = &item.post_oid {
                    changes.push(PathChange::Put {
                        path,
                        content: BlobSource::Disk { oid: oid.clone() },
                        role: ChangeRole::Primary,
                        executable: None,
                        stat: None,
                    });
                }
            }
            JournalItemKind::Move => {
                if let Some(from) = &item.from_rel {
                    if let Ok(fp) = repo_path(from) {
                        changes.push(PathChange::Move {
                            from: fp,
                            to: path,
                            oid: item.pre_oid.clone(),
                        });
                    }
                }
            }
            JournalItemKind::Trash => {
                changes.push(PathChange::Remove {
                    path,
                    role: ChangeRole::Primary,
                });
            }
            JournalItemKind::Mkdir => {}
        }
    }
    if changes.is_empty() {
        return None;
    }
    Some(UserCommitRequest {
        actor: UserActor::from_principal_id(&rec.actor_handle),
        op,
        changes,
        correlation_id: Some(rec.op_id.clone()),
        provenance: None,
    })
}

async fn prepare_cas(
    core: &OperatorFiles,
    lane: &Arc<dyn UserCommitLane>,
    targets: Vec<PrepareTarget>,
    op_id: &str,
) -> Result<PrepareOutcome, FilesError> {
    let mut attempt = 0u8;
    loop {
        let rx = lane.prepare(PrepareRequest {
            targets: targets.clone(),
            correlation_id: Some(op_id.to_string()),
        });
        let st = recv_prepare(rx, PREPARE_WAIT).await?;
        if identities_match(core, &st) {
            return Ok(st);
        }
        if attempt >= 1 {
            return Err(FilesError::FileBusy);
        }
        attempt = attempt.saturating_add(1);
    }
}

fn identities_match(core: &OperatorFiles, st: &PrepareOutcome) -> bool {
    for ps in &st.states {
        let Some(want) = ps.identity else {
            continue;
        };
        let Ok(got) = identity_now(core, &ps.path) else {
            return false;
        };
        if got != want {
            return false;
        }
    }
    true
}

fn identity_now(core: &OperatorFiles, rel: &str) -> Result<FileIdentity, FilesError> {
    let (chain, leaf) = DirChain::walk_parent(&core.root, rel)?;
    let st = statat_nofollow(chain.current_fd(), &leaf)?;
    Ok(FileIdentity {
        dev: stat_dev(&st),
        ino: stat_ino(&st),
        size: st.st_size as u64,
        mtime_ns: mtime_ns(&st),
    })
}

async fn recv_prepare(
    rx: oneshot::Receiver<Result<PrepareOutcome, GitError>>,
    budget: Duration,
) -> Result<PrepareOutcome, FilesError> {
    match tokio::time::timeout(budget, rx).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(e))) => Err(map_git(e)),
        Ok(Err(_)) => Err(FilesError::Capacity {
            kind: CapacityKind::Versioning,
        }),
        Err(_) => Err(FilesError::Capacity {
            kind: CapacityKind::Versioning,
        }),
    }
}

async fn recv_save(
    rx: oneshot::Receiver<Result<SaveVersionOutcome, GitError>>,
    budget: Duration,
) -> Result<SaveVersionOutcome, FilesError> {
    match tokio::time::timeout(budget, rx).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(e))) => Err(map_git(e)),
        Ok(Err(_)) => Err(FilesError::CommitFailed),
        Err(_) => Err(FilesError::Capacity {
            kind: CapacityKind::Versioning,
        }),
    }
}

async fn take_commit(
    rx: &mut oneshot::Receiver<Result<UserCommitOutcome, GitError>>,
    budget: Duration,
) -> Option<Result<UserCommitOutcome, FilesError>> {
    match tokio::time::timeout(budget, rx).await {
        Ok(Ok(Ok(v))) => Some(Ok(v)),
        Ok(Ok(Err(e))) => Some(Err(map_git(e))),
        Ok(Err(_)) => Some(Err(FilesError::CommitFailed)),
        Err(_) => None,
    }
}

fn classify_commit(out: UserCommitOutcome) -> (CommitState, Option<String>) {
    match out.status {
        UserCommitStatus::Committed => (CommitState::Committed, out.sha),
        UserCommitStatus::Unchanged => {
            if out.items.iter().any(|i| !i.versioned) {
                (CommitState::NoCommit, None)
            } else {
                (CommitState::Unchanged, None)
            }
        }
    }
}

fn undo_disk(steps: &[Undo]) {
    for step in steps.iter().rev() {
        match step {
            Undo::Unlink { parent, name, dir } => {
                let flags = if *dir {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                };
                if let Ok(root) = RootDir::open(parent) {
                    let _ = unlinkat(root.fd(), name.as_str(), flags);
                }
            }
            Undo::RenameBack {
                from_parent,
                from_name,
                to_parent,
                to_name,
            } => {
                if let (Ok(src), Ok(dst)) = (RootDir::open(from_parent), RootDir::open(to_parent)) {
                    let _ = publish_noreplace(src.fd(), from_name, dst.fd(), to_name);
                }
            }
        }
    }
}

fn load_meta_file(dir_abs: &Path) -> Option<MetaFile> {
    let path = dir_abs.join(META_SIDECAR_NAME);
    let bytes = std::fs::read(path).ok()?;
    crate::meta_maintainer::MetaMaintainer::parse_meta_bytes(&bytes).ok()
}

fn store_meta_file(dir_abs: &Path, meta: &MetaFile) -> Result<(), FilesError> {
    std::fs::create_dir_all(dir_abs).map_err(io)?;
    let desc = meta.scope.description.replace(['\n', '"'], " ");
    let mut yaml = format!("_scope:\n  description: \"{desc}\"\n");
    for (name, entry) in &meta.entries {
        let safe = name.replace('"', "");
        let ename = entry.name.replace('"', "");
        let edesc = entry.description.replace(['\n', '"'], " ");
        yaml.push_str(&format!(
            "{safe}:\n  name: \"{ename}\"\n  description: \"{edesc}\"\n"
        ));
        if !entry.tags.is_empty() {
            yaml.push_str("  tags:\n");
            for tag in &entry.tags {
                let t = tag.replace(['\n', '"'], " ");
                yaml.push_str(&format!("    - \"{t}\"\n"));
            }
        }
    }
    std::fs::write(dir_abs.join(META_SIDECAR_NAME), yaml).map_err(io)
}

fn purge_trash_for_op(files_state: &Path, op_id: &str) {
    let trash = files_state.join(TRASH_DIR);
    let Ok(rd) = std::fs::read_dir(&trash) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == op_id || name.starts_with(&format!("{op_id}-")) || name == format!("ov-{op_id}")
        {
            let path = ent.path();
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

fn rekey_move_sidecars(
    core: &OperatorFiles,
    from: &str,
    to: &str,
    from_leaf: &str,
    to_leaf: &str,
) -> Result<(), FilesError> {
    let src_parent = abs_rel(core, &parent_of(from));
    let dst_parent = abs_rel(core, &parent_of(to));
    let mut src_meta = load_meta_file(&src_parent).unwrap_or_default();
    let taken = take_entry(&mut src_meta, from_leaf);
    if src_parent == dst_parent {
        if let Some(entry) = taken {
            let _ = put_entry(&mut src_meta, to_leaf, entry);
        } else {
            let _ = rekey_entry(&mut src_meta, from_leaf, to_leaf);
        }
        store_meta_file(&src_parent, &src_meta)?;
        return Ok(());
    }
    store_meta_file(&src_parent, &src_meta)?;
    let mut dst_meta = load_meta_file(&dst_parent).unwrap_or_default();
    if let Some(entry) = taken {
        let _ = put_entry(&mut dst_meta, to_leaf, entry);
    }
    store_meta_file(&dst_parent, &dst_meta)?;
    Ok(())
}

fn write_dir_sidecar(
    maintainer: &crate::meta_maintainer::MetaMaintainer,
    dir_abs: &Path,
    dir_name: &str,
) -> Result<Vec<u8>, FilesError> {
    let meta = maintainer.build_default_meta(dir_name);
    let desc = meta.scope.description.replace(['\n', '"'], " ");
    let yaml = format!("_scope:\n  description: \"{desc}\"\n");
    let bytes = yaml.into_bytes();
    std::fs::create_dir_all(dir_abs).map_err(io)?;
    std::fs::write(dir_abs.join(META_SIDECAR_NAME), &bytes).map_err(io)?;
    Ok(bytes)
}

fn copy_dir_children(
    from_parent: BorrowedFd<'_>,
    from_name: &str,
    to_parent: BorrowedFd<'_>,
    to_name: &str,
) -> Result<(), FilesError> {
    let src = open_dir_nofollow(from_parent, from_name, true)?;
    let dst = open_dir_nofollow(to_parent, to_name, true)?;
    let dir = Dir::read_from(src.as_fd()).map_err(io)?;
    for ent in dir {
        let ent = ent.map_err(io)?;
        let Some(name) = ent.file_name().to_str().ok() else {
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        let name = name.to_string();
        let st = match statat_nofollow(src.as_fd(), &name) {
            Ok(st) => st,
            Err(_) => continue,
        };
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            mkdir_at(dst.as_fd(), &name)?;
            copy_dir_children(src.as_fd(), &name, dst.as_fd(), &name)?;
        } else if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile {
            copy_regular_noreplace(src.as_fd(), &name, dst.as_fd(), &name)?;
        }
    }
    Ok(())
}

fn dir_has_user_children(parent: BorrowedFd<'_>, name: &str) -> Result<bool, FilesError> {
    let fd = open_dir_nofollow(parent, name, true)?;
    let dir = Dir::read_from(fd.as_fd()).map_err(io)?;
    for ent in dir {
        let ent = ent.map_err(io)?;
        let Some(n) = ent.file_name().to_str().ok() else {
            continue;
        };
        if n == "." || n == ".." || n == META_SIDECAR_NAME {
            continue;
        }
        if n.starts_with('.') {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

fn sibling_portable_collision(parent: BorrowedFd<'_>, leaf: &str) -> Result<bool, FilesError> {
    let dir = Dir::read_from(parent).map_err(io)?;
    for ent in dir {
        let ent = ent.map_err(io)?;
        let Some(name) = ent.file_name().to_str().ok() else {
            continue;
        };
        if name == "." || name == ".." || name == leaf {
            continue;
        }
        if portable_keys_collide(name, leaf) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn leaf_facts(
    chain: &DirChain<'_>,
    leaf: &str,
) -> Result<super::policy::PhysicalFacts, FilesError> {
    let st = statat_nofollow(chain.current_fd(), leaf)?;
    let mut facts = chain.facts();
    if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
        facts.subtree = SubtreeClass::Symlink;
        return Ok(facts);
    }
    // Parent directory protection (workspace / territory root) does not
    // make the child itself undeletable.
    if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
        && matches!(
            facts.protection,
            Some(NodeProtection::WorkspaceRoot | NodeProtection::TerritoryRoot)
        )
    {
        facts.protection = None;
        facts.subtree = SubtreeClass::Normal;
    }
    Ok(facts)
}

fn refuse_write(op: FilesOp, facts: super::policy::PhysicalFacts) -> Result<(), FilesError> {
    if matches!(facts.protection, Some(NodeProtection::VcsControl)) {
        return Err(FilesError::ReadOnly(ReadOnlyReason::VcsControl));
    }
    if allows(op, facts) {
        return Ok(());
    }
    let reason = match facts.subtree {
        SubtreeClass::AgentSystem => ReadOnlyReason::AgentSystem,
        SubtreeClass::ForeignRepo => ReadOnlyReason::ForeignRepo,
        SubtreeClass::MountPoint => ReadOnlyReason::MountPoint,
        SubtreeClass::Symlink => ReadOnlyReason::Symlink,
        SubtreeClass::Special => ReadOnlyReason::Special,
        _ => match facts.protection {
            Some(NodeProtection::TerritoryRoot) | Some(NodeProtection::WorkspaceRoot) => {
                ReadOnlyReason::TerritoryRoot
            }
            Some(NodeProtection::Locked) => ReadOnlyReason::Locked,
            Some(NodeProtection::Unversionable) => ReadOnlyReason::Unversionable,
            Some(NodeProtection::VcsControl) => ReadOnlyReason::VcsControl,
            None => ReadOnlyReason::Permission,
        },
    };
    Err(FilesError::ReadOnly(reason))
}

fn map_create(r: CreateRefusal) -> FilesError {
    match r {
        CreateRefusal::Defect(d) => FilesError::InvalidPath(d),
        CreateRefusal::ReadOnly(r) => FilesError::ReadOnly(r),
    }
}

fn map_git(err: GitError) -> FilesError {
    match err {
        GitError::WorkerClosed => FilesError::CommitFailed,
        GitError::HeadMoved { .. } => FilesError::InvalidRequest {
            token: "head_moved",
        },
        GitError::ContentChanged { actual, .. } => FilesError::StaleBase {
            current_oid: actual,
            item: None,
        },
        GitError::InvalidUserOp { reason, .. } => match reason {
            UserOpRefusal::TargetExists => FilesError::TargetExists {
                current_oid: None,
                name_collision: false,
            },
            UserOpRefusal::AgentTerritory => {
                FilesError::ReadOnly(ReadOnlyReason::ContainsTerritory)
            }
            UserOpRefusal::ReadOnlyPath => FilesError::ReadOnly(ReadOnlyReason::VcsControl),
            UserOpRefusal::PrivatePath => FilesError::NotFound,
            UserOpRefusal::ReservedNamespace => FilesError::InvalidRequest {
                token: "reserved_namespace",
            },
            UserOpRefusal::SourceMissing => FilesError::NotFound,
            UserOpRefusal::Symlink => FilesError::ReadOnly(ReadOnlyReason::Symlink),
            UserOpRefusal::InvalidTitle => FilesError::InvalidRequest {
                token: "invalid_title",
            },
            _ => FilesError::CommitFailed,
        },
        GitError::Io(e) => FilesError::Io(e.to_string()),
        other => FilesError::Io(other.to_string()),
    }
}

fn normalize_rel(path: &str, allow_root: bool) -> Result<String, FilesError> {
    normalize_workspace_path(path, allow_root).map_err(FilesError::InvalidPath)
}

fn parent_of(rel: &str) -> String {
    match rel.rsplit_once('/') {
        Some((p, _)) => p.to_string(),
        None => String::new(),
    }
}

fn leaf_of(rel: &str) -> String {
    match rel.rsplit_once('/') {
        Some((_, l)) => l.to_string(),
        None => rel.to_string(),
    }
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn paths_overlap(a: &str, b: &str) -> bool {
    a == b
        || (!a.is_empty() && b.starts_with(a) && b.as_bytes().get(a.len()) == Some(&b'/'))
        || (!b.is_empty() && a.starts_with(b) && a.as_bytes().get(b.len()) == Some(&b'/'))
}

fn abs_rel(core: &OperatorFiles, rel: &str) -> PathBuf {
    if rel.is_empty() {
        core.root.canonical().to_path_buf()
    } else {
        core.root.canonical().join(rel)
    }
}

fn repo_path(rel: &str) -> Result<RepoPath, FilesError> {
    RepoPath::parse(rel).map_err(|r| match r {
        UserOpRefusal::PrivatePath => FilesError::NotFound,
        UserOpRefusal::ReadOnlyPath => FilesError::ReadOnly(ReadOnlyReason::VcsControl),
        UserOpRefusal::InvalidPath => FilesError::InvalidPath(PathDefect::Syntax),
        _ => FilesError::InvalidPath(PathDefect::Syntax),
    })
}

fn sidecar_repo(dir_rel: &str) -> Result<RepoPath, FilesError> {
    let given = if dir_rel.is_empty() {
        META_SIDECAR_NAME.to_string()
    } else {
        format!("{dir_rel}/{META_SIDECAR_NAME}")
    };
    RepoPath::parse_sidecar(&given).map_err(|_| FilesError::InvalidPath(PathDefect::ReservedName))
}

fn file_target(rel: &str, adopt: AdoptPolicy) -> Result<PrepareTarget, FilesError> {
    Ok(PrepareTarget::File {
        path: repo_path(rel)?,
        adopt,
    })
}

fn file_or_tree(
    core: &OperatorFiles,
    rel: &str,
    adopt: AdoptPolicy,
) -> Result<PrepareTarget, FilesError> {
    let (chain, leaf) = DirChain::walk_parent(&core.root, rel)?;
    match statat_nofollow(chain.current_fd(), &leaf) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Directory => {
            Ok(PrepareTarget::Tree {
                dir: repo_path(rel)?,
            })
        }
        Ok(_) => file_target(rel, adopt),
        Err(FilesError::NotFound) => file_target(rel, adopt),
        Err(e) => Err(e),
    }
}

fn push_sidecar(targets: &mut Vec<PrepareTarget>, dir_rel: &str) -> Result<(), FilesError> {
    targets.push(PrepareTarget::File {
        path: sidecar_repo(dir_rel)?,
        adopt: AdoptPolicy::Always,
    });
    Ok(())
}

fn unique_prepare_targets(targets: Vec<PrepareTarget>) -> Vec<PrepareTarget> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let key = match &t {
            PrepareTarget::File { path, .. } => format!("f:{}", path.nfc()),
            PrepareTarget::Tree { dir } => format!("t:{}", dir.nfc()),
        };
        if seen.insert(key) {
            out.push(t);
        }
    }
    out
}

fn unique_put_changes(changes: Vec<PathChange>) -> Vec<PathChange> {
    let mut last: HashMap<String, usize> = HashMap::new();
    for (i, c) in changes.iter().enumerate() {
        if let PathChange::Put { path, .. } = c {
            last.insert(path.nfc().to_string(), i);
        }
    }
    let keep: HashSet<usize> = last.into_values().collect();
    changes
        .into_iter()
        .enumerate()
        .filter(|(i, c)| !matches!(c, PathChange::Put { .. }) || keep.contains(i))
        .map(|(_, c)| c)
        .collect()
}

fn sidecar_put_role(
    dir_rel: &str,
    bytes: Vec<u8>,
    role: ChangeRole,
) -> Result<PathChange, FilesError> {
    Ok(PathChange::Put {
        path: sidecar_repo(dir_rel)?,
        content: BlobSource::Bytes(bytes),
        role,
        executable: None,
        stat: None,
    })
}

fn drop_staged_files(core: &OperatorFiles, items: &[StagedBatchItem]) {
    for item in items {
        let path = core.files_state.join(STAGING_DIR).join(&item.staging_name);
        let _ = std::fs::remove_file(path);
    }
}

fn current_oid_at(core: &OperatorFiles, rel: &str) -> Result<Option<String>, FilesError> {
    match DirChain::walk_parent(&core.root, rel) {
        Ok((chain, leaf)) => match super::fsops::open_regular_at(chain.current_fd(), &leaf) {
            Ok(file) => Ok(hash_opened_file(&file).ok()),
            Err(FilesError::NotFound) => Ok(None),
            Err(e) => Err(e),
        },
        Err(FilesError::NotFound) | Err(FilesError::ParentNotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

fn ensure_dir_rel(
    lock: &MutationLockExt<'_>,
    rel: &str,
    parents: bool,
    changes: &mut Vec<PathChange>,
    items: &mut Vec<JournalItem>,
    metas: &mut Vec<JournalMeta>,
    undo: &mut Vec<Undo>,
) -> Result<(), FilesError> {
    let parts: Vec<String> = rel
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let mut chain = DirChain::new(&lock.core.root);
    let mut missing: Vec<String> = Vec::new();
    for name in &parts {
        if !missing.is_empty() {
            missing.push(name.clone());
            continue;
        }
        match chain.descend(name) {
            Ok(()) => {}
            Err(FilesError::NotFound) => missing.push(name.clone()),
            Err(e) => return Err(e),
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    if !parents && missing.len() != 1 {
        return Err(FilesError::ParentNotFound);
    }
    refuse_write(FilesOp::MkdirIn, chain.facts())?;
    for name in &missing {
        check_create_name(name).map_err(map_create)?;
    }
    let mut parent_rel = chain.rel_disk();
    for name in &missing {
        mkdir_at(chain.current_fd(), name)?;
        undo.push(Undo::Unlink {
            parent: abs_rel(lock.core, &parent_rel),
            name: name.clone(),
            dir: true,
        });
        chain.descend(name)?;
        let child_rel = join_rel(&parent_rel, name);
        if let Some(m) = lock.core.maintainer.as_ref() {
            let child_abs = abs_rel(lock.core, &child_rel);
            let bytes = write_dir_sidecar(m, &child_abs, name)?;
            if !bytes.is_empty() {
                // Upload cannot carry a primary `.meta.yaml` (CreateFolder-only).
                changes.push(sidecar_put_role(&child_rel, bytes, ChangeRole::Sidecar)?);
                metas.push(JournalMeta {
                    dir_rel: child_rel.clone(),
                    post_oid: String::new(),
                });
            }
        }
        items.push(JournalItem {
            kind: JournalItemKind::Mkdir,
            from_rel: None,
            to_rel: child_rel.clone(),
            dev_ino: None,
            pre_identity: None,
            pre_oid: None,
            post_identity: None,
            post_oid: None,
            entry_pre: None,
            temp_location: None,
        });
        parent_rel = child_rel;
    }
    Ok(())
}

fn publish_staged_item(
    lock: &MutationLockExt<'_>,
    item: &StagedBatchItem,
    changes: &mut Vec<PathChange>,
    items: &mut Vec<JournalItem>,
    metas: &mut Vec<JournalMeta>,
    undo: &mut Vec<Undo>,
) -> Result<(), FilesError> {
    let rel = &item.path;
    let (parent, leaf) = DirChain::walk_parent(&lock.core.root, rel)?;
    let exists = statat_nofollow(parent.current_fd(), &leaf).is_ok();
    let create = item.base_oid.is_none() && !exists;
    refuse_write(
        if create {
            FilesOp::CreateIn
        } else {
            FilesOp::EditInPlace
        },
        if create {
            parent.facts()
        } else {
            leaf_facts(&parent, &leaf)?
        },
    )?;
    if create {
        check_create_name(&leaf).map_err(map_create)?;
        if sibling_portable_collision(parent.current_fd(), &leaf)? {
            return Err(FilesError::TargetExists {
                current_oid: None,
                name_collision: true,
            });
        }
    }
    let parent_rel = parent_of(rel);
    if !create {
        match statat_nofollow(parent.current_fd(), &leaf) {
            Ok(_) => {
                let trash = ensure_state_subdir(&lock.core.files_state, TRASH_DIR)?;
                let trash_root = RootDir::open(&trash)?;
                let trash_name = format!("ov-{}", lock.op_id);
                trash_rename(parent.current_fd(), &leaf, trash_root.fd(), &trash_name)?;
                undo.push(Undo::RenameBack {
                    from_parent: trash,
                    from_name: trash_name,
                    to_parent: abs_rel(lock.core, &parent_rel),
                    to_name: leaf.clone(),
                });
            }
            Err(FilesError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }
    let stage_dir = ensure_state_subdir(&lock.core.files_state, STAGING_DIR)?;
    let stage_root = RootDir::open(&stage_dir)?;
    let body_for_meta = if create {
        Some(std::fs::read(stage_dir.join(&item.staging_name)).map_err(io)?)
    } else {
        None
    };
    publish_noreplace(
        stage_root.fd(),
        &item.staging_name,
        parent.current_fd(),
        &leaf,
    )?;
    undo.push(Undo::Unlink {
        parent: abs_rel(lock.core, &parent_rel),
        name: leaf.clone(),
        dir: false,
    });
    let published = abs_rel(lock.core, rel);
    let bytes = std::fs::read(&published).map_err(io)?;
    changes.push(PathChange::Put {
        path: repo_path(rel)?,
        content: BlobSource::Bytes(bytes),
        role: ChangeRole::Primary,
        executable: None,
        stat: None,
    });
    if create {
        if let Some(m) = lock.core.maintainer.as_ref() {
            let parent_abs = abs_rel(lock.core, &parent_rel);
            let body = body_for_meta.unwrap_or_default();
            let pre = load_meta_file(&parent_abs);
            if let Ok((meta_new, _)) = m.add_entry_for_write(pre, &leaf, &body) {
                store_meta_file(&parent_abs, &meta_new)?;
                let yaml = std::fs::read(parent_abs.join(META_SIDECAR_NAME)).map_err(io)?;
                if !yaml.is_empty() {
                    changes.push(sidecar_put_role(&parent_rel, yaml, ChangeRole::Sidecar)?);
                    metas.push(JournalMeta {
                        dir_rel: parent_rel.clone(),
                        post_oid: String::new(),
                    });
                }
            }
        }
    }
    items.push(JournalItem {
        kind: JournalItemKind::Write,
        from_rel: None,
        to_rel: rel.clone(),
        dev_ino: None,
        pre_identity: None,
        pre_oid: item.base_oid.clone(),
        post_identity: None,
        post_oid: Some(item.oid.clone()),
        entry_pre: None,
        temp_location: Some(format!("{STAGING_DIR}/{}", item.staging_name)),
    });
    Ok(())
}

fn provenance_of(actor: &FilesActor) -> Option<Provenance> {
    if actor.platform.is_empty() && actor.session_ref.is_empty() {
        return None;
    }
    Some(Provenance {
        client: actor.platform.clone(),
        session: session_hex(&actor.session_ref),
    })
}

fn session_hex(session_ref: &str) -> String {
    let mut h = Sha256::new();
    h.update(session_ref.as_bytes());
    let d = h.finalize();
    let mut out = String::with_capacity(16);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in d.iter().take(8) {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

fn ensure_state_subdir(files_state: &Path, name: &str) -> Result<PathBuf, FilesError> {
    if let Some(parent) = files_state.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    std::fs::create_dir_all(files_state).map_err(io)?;
    let dir = files_state.join(name);
    std::fs::create_dir_all(&dir).map_err(io)?;
    Ok(dir)
}

fn unchanged_result() -> MutationResult {
    MutationResult {
        op_id: Ulid::new().to_string(),
        disk_changed: false,
        commit: CommitState::Unchanged,
        sha: None,
        warnings: Vec::new(),
    }
}

fn lock_std<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn io(err: impl std::fmt::Display) -> FilesError {
    FilesError::Io(err.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::atomic::DefaultAtomicWriter;
    use crate::meta_maintainer::MetaMaintainer;
    use crate::meta_schema::MetaSchemaLoader;
    use crate::operator::journal::{journal_dir, JournalRecord, TypedOp, JOURNAL_RECORD_CAP};
    use crate::operator::{OperatorFilesConfig, OperatorLimits};
    use advance_git::{CommitLabel, PrepareOutcome, RestoreOutcome, RestoreTreeRequest};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    struct MockLane {
        prepares: Mutex<usize>,
    }

    impl MockLane {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                prepares: Mutex::new(0),
            })
        }
    }

    impl UserCommitLane for MockLane {
        fn prepare(
            &self,
            _req: PrepareRequest,
        ) -> oneshot::Receiver<Result<PrepareOutcome, GitError>> {
            *self.prepares.lock().unwrap() += 1;
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Ok(PrepareOutcome {
                head_sha: None,
                adopted_sha: None,
                adopted_paths: Vec::new(),
                adopted_count: 0,
                states: Vec::new(),
                tree_states: Vec::new(),
                unversioned: Vec::new(),
                unversioned_count: 0,
                unversioned_bytes: 0,
                agent_territory: false,
                adopt_incomplete: false,
            }));
            rx
        }

        fn commit_user(
            &self,
            _req: UserCommitRequest,
        ) -> oneshot::Receiver<Result<UserCommitOutcome, GitError>> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Ok(UserCommitOutcome {
                status: UserCommitStatus::Committed,
                sha: Some("aa".repeat(20)),
                head_sha: Some("aa".repeat(20)),
                subject: String::new(),
                label: CommitLabel::default(),
                items: Vec::new(),
                max_tracked_bytes: DEFAULT_MAX_TRACKED,
            }));
            rx
        }

        fn save_version(
            &self,
            req: SaveVersionRequest,
        ) -> oneshot::Receiver<Result<SaveVersionOutcome, GitError>> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Ok(SaveVersionOutcome {
                sha: "bb".repeat(20),
                label: "20261016-000000".into(),
                tag: "checkpoint/user/20261016-000000".into(),
                title: req.title,
                paths: None,
                adopted_sha: None,
                adopt_incomplete: false,
                unversioned_count: 0,
            }));
            rx
        }

        fn restore_tree(
            &self,
            _req: RestoreTreeRequest,
        ) -> oneshot::Receiver<Result<RestoreOutcome, GitError>> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Err(GitError::WorkerClosed));
            rx
        }
    }

    fn actor() -> FilesActor {
        FilesActor {
            principal_id: "advance".into(),
            os_user: "advance".into(),
            platform: "macos".into(),
            session_ref: "sess".into(),
        }
    }

    fn maintainer() -> Arc<MetaMaintainer> {
        let schema_path = std::env::temp_dir().join("schema-ops-oss5d.yaml");
        let loader = Arc::new(MetaSchemaLoader::new_with_default(schema_path));
        Arc::new(MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter)))
    }

    async fn open_core(
        home: &Path,
        lane: Option<Arc<dyn UserCommitLane>>,
        maint: Option<Arc<MetaMaintainer>>,
    ) -> Arc<OperatorFiles> {
        OperatorFiles::open(OperatorFilesConfig {
            home: home.to_path_buf(),
            files_state: home.join(".runtime").join("files"),
            limits: OperatorLimits::default(),
            vcs: None,
            maintainer: maint,
            lane,
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn check_write_refuses_vcs_control() {
        let home = tempfile::tempdir().unwrap();
        let core = open_core(home.path(), None, None).await;
        let err = core
            .check_write(
                &actor(),
                &FileWriteTarget {
                    path: ".gitignore".into(),
                    intent: WriteIntent::Create,
                    base_oid: None,
                    expected_bytes: None,
                    batch: None,
                },
            )
            .unwrap_err();
        assert_eq!(err, FilesError::ReadOnly(ReadOnlyReason::VcsControl));
        assert_eq!(err.to_string(), "read_only reason:vcs_control");
    }

    #[tokio::test]
    async fn mkdir_parents_existing_is_unchanged() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("notes")).unwrap();
        let core = open_core(home.path(), None, None).await;
        let out = core
            .mkdir(
                &actor(),
                &FilesMkdir {
                    path: "notes".into(),
                    parents: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(out.commit, CommitState::Unchanged);
        assert!(!out.disk_changed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mkdir_journal_cap_refuses() {
        let home = tempfile::tempdir().unwrap();
        let lane = MockLane::new();
        let core = open_core(home.path(), Some(lane), Some(maintainer())).await;
        let dir = journal_dir(core.files_state());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for i in 0..JOURNAL_RECORD_CAP {
            let op_id = format!("cap{i:04}ok");
            let rec = JournalRecord::new(op_id.clone(), "user:h".into(), TypedOp::Edit);
            let path = dir.join(format!("{op_id}.json"));
            std::fs::write(&path, serde_json::to_vec(&rec).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = core
            .mkdir(
                &actor(),
                &FilesMkdir {
                    path: "fresh".into(),
                    parents: false,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            FilesError::Capacity {
                kind: CapacityKind::Journal
            }
        );
    }

    #[tokio::test]
    async fn copy_items_refuses_mixed_destinations() {
        let home = tempfile::tempdir().unwrap();
        let core = open_core(home.path(), None, None).await;
        let err = core
            .copy_items(
                &actor(),
                &[
                    CopyItem {
                        from: "a.md".into(),
                        to: "d1/x.md".into(),
                    },
                    CopyItem {
                        from: "b.md".into(),
                        to: "d2/y.md".into(),
                    },
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(err, FilesError::MixedDestinations);
    }
}
