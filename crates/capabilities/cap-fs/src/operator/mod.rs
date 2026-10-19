//! Operator file core (INTEGRATED §1.2). OSS-5d: mutation ops + optional lane.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unimplemented)]
#![deny(clippy::todo)]

pub mod fsops;
pub mod identity;
pub mod journal;
pub mod list;
pub mod meta_ops;
pub mod ops;
pub mod policy;
pub mod vcs;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

use advance_git::UserCommitLane;
use advance_shared_types::workspace_path::{PathDefect, ReadOnlyReason};

use crate::meta_maintainer::MetaMaintainer;
use crate::operator::identity::{OidCache, OID_CACHE_CAPACITY};
use crate::operator::list::ListingCache;

pub use fsops::{
    copy_regular_noreplace, mkdir_at, publish_noreplace, trash_rename, DirChain, OpenClass, RootDir,
};
pub use identity::{hash_opened_file, hash_opened_file_known_len, IdentityError};
pub use list::{
    DirListing, EntryKind, ListEntry, ListQuery, ListSort, ReadQuery, ReadSource, ReadVersion,
    SearchQuery, SearchResult, StatQuery, StatResult, LIST_DEFAULT_LIMIT, LIST_MAX_PAGE_LIMIT,
    SEARCH_DEFAULT_LIMIT, SEARCH_MAX_LIMIT, UNSTABLE_READ_OID_THRESHOLD,
};
pub use ops::{
    CommitState, CopyItem, FileUploadHandle, FileUploadSink, FileWriteTarget, FilesActor,
    FilesCommitBatch, FilesDelete, FilesDeleteItem, FilesExternalItem, FilesMkdir, FilesMoveItem,
    FilesRestore, FilesRestoreItem, FilesSaveVersion, MutationResult, VersionResult, WriteCheck,
    WriteIntent, WriteResult,
};
pub use policy::{
    allows, check_create_name, classify_h1, classify_stored_path, portable_keys_collide,
    stored_nfc, vcs_control_directory_covers_descendants, CreateRefusal, FilesOp, NodeProtection,
    PhysicalFacts, SubtreeClass,
};
pub use vcs::{GitVcsReadPort, VcsPathState, VcsReadPort};

/// Directory scan cap (oss-fs-core §2.9 `LIST_SCAN_CAP`).
pub const LIST_SCAN_CAP: usize = 65_536;

/// Operator-facing error vocabulary (INTEGRATED §3.3.3 tokens).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesError {
    InvalidPath(PathDefect),
    NotFound,
    ParentNotFound,
    ReadOnly(ReadOnlyReason),
    TargetExists {
        current_oid: Option<String>,
        name_collision: bool,
    },
    StaleBase {
        current_oid: Option<String>,
        item: Option<u32>,
    },
    BatchExpired {
        item: Option<u32>,
    },
    FileBusy,
    Capacity {
        kind: CapacityKind,
    },
    Unsupported,
    NotADirectory,
    NotAFile {
        item: Option<u32>,
    },
    NotEmpty {
        item: Option<u32>,
    },
    Overlap {
        item: Option<u32>,
    },
    MixedDestinations,
    ListingChanged,
    UnversionedContent {
        files: u32,
        bytes: u64,
        unknown: bool,
    },
    ContentMismatch,
    CommitFailed,
    UnknownVersion,
    TooManyEntries,
    BlobTooLarge,
    InsufficientStorage,
    VcsUnavailable {
        reason: &'static str,
    },
    InvalidRequest {
        token: &'static str,
    },
    Io(String),
}

/// `capacity kind:<k>` (INTEGRATED §3.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityKind {
    RawRead,
    RawUpload,
    SessionRead,
    SessionUpload,
    History,
    Hash,
    Mutation,
    Versioning,
    Journal,
}

impl CapacityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RawRead => "raw_read",
            Self::RawUpload => "raw_upload",
            Self::SessionRead => "session_read",
            Self::SessionUpload => "session_upload",
            Self::History => "history",
            Self::Hash => "hash",
            Self::Mutation => "mutation",
            Self::Versioning => "versioning",
            Self::Journal => "journal",
        }
    }
}

impl std::fmt::Display for FilesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(d) => write!(f, "invalid_path reason:{}", d.reason()),
            Self::NotFound => f.write_str("not_found"),
            Self::ParentNotFound => f.write_str("parent_not_found"),
            Self::ReadOnly(r) => write!(f, "read_only reason:{}", r.reason()),
            Self::TargetExists { name_collision, .. } => {
                if *name_collision {
                    f.write_str("target_exists name_collision")
                } else {
                    f.write_str("target_exists")
                }
            }
            Self::StaleBase { .. } => f.write_str("stale_base"),
            Self::BatchExpired { .. } => f.write_str("batch_expired"),
            Self::FileBusy => f.write_str("file_busy"),
            Self::Capacity { kind } => write!(f, "capacity kind:{}", kind.as_str()),
            Self::Unsupported => f.write_str("unsupported"),
            Self::NotADirectory => f.write_str("not_a_directory"),
            Self::NotAFile { .. } => f.write_str("not_a_file"),
            Self::NotEmpty { .. } => f.write_str("not_empty"),
            Self::Overlap { .. } => f.write_str("overlap"),
            Self::MixedDestinations => f.write_str("mixed_destinations"),
            Self::ListingChanged => f.write_str("listing_changed"),
            Self::UnversionedContent {
                files,
                bytes,
                unknown,
            } => {
                if *unknown {
                    write!(f, "unversioned_content unknown files:{files} bytes:{bytes}")
                } else {
                    write!(f, "unversioned_content files:{files} bytes:{bytes}")
                }
            }
            Self::ContentMismatch => f.write_str("content_mismatch"),
            Self::CommitFailed => f.write_str("commit_failed"),
            Self::UnknownVersion => f.write_str("unknown_version"),
            Self::TooManyEntries => f.write_str("too_many_entries"),
            Self::BlobTooLarge => f.write_str("blob_too_large"),
            Self::InsufficientStorage => f.write_str("insufficient_storage"),
            Self::VcsUnavailable { reason } => write!(f, "vcs_unavailable reason:{reason}"),
            Self::InvalidRequest { token } => f.write_str(token),
            Self::Io(msg) => write!(f, "io:{msg}"),
        }
    }
}

impl std::error::Error for FilesError {}

/// Limits the later fsops/list/ops slices honour. Stored now so OSS-5b does not
/// change `open`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorLimits {
    pub max_list_entries: usize,
    pub max_upload_bytes: u64,
    pub oid_cache_capacity: usize,
}

impl Default for OperatorLimits {
    fn default() -> Self {
        Self {
            max_list_entries: 65_536,
            max_upload_bytes: 1 << 30,
            oid_cache_capacity: OID_CACHE_CAPACITY,
        }
    }
}

/// Construction input for [`OperatorFiles::open`].
///
/// `maintainer` / `lane` stay `None` for list/open tests. Mutations without a
/// lane return [`FilesError::Capacity`] `{ kind: Versioning }`.
pub struct OperatorFilesConfig {
    pub home: PathBuf,
    pub files_state: PathBuf,
    pub limits: OperatorLimits,
    pub vcs: Option<Arc<dyn VcsReadPort>>,
    pub maintainer: Option<Arc<MetaMaintainer>>,
    pub lane: Option<Arc<dyn UserCommitLane>>,
}

/// Operator core handle. OSS-5d: open + list + journal + mutation ops.
pub struct OperatorFiles {
    pub(crate) home: PathBuf,
    pub(crate) files_state: PathBuf,
    pub(crate) limits: OperatorLimits,
    pub(crate) vcs: Option<Arc<dyn VcsReadPort>>,
    pub(crate) maintainer: Option<Arc<MetaMaintainer>>,
    pub(crate) lane: Option<Arc<dyn UserCommitLane>>,
    pub(crate) oids: Mutex<OidCache>,
    pub(crate) root: RootDir,
    pub(crate) listings: Mutex<ListingCache>,
    pub(crate) retry_notify: Arc<Notify>,
    pub(crate) retry_task: Mutex<Option<JoinHandle<()>>>,
    pub(crate) mutation_gate: Arc<Semaphore>,
    pub(crate) uploads: Mutex<HashMap<String, ops::UploadSlot>>,
    pub(crate) batches: Mutex<HashMap<String, Vec<ops::StagedBatchItem>>>,
}

impl OperatorFiles {
    /// Open the core. Canonicalizes `home` and keeps a [`RootDir`] fd.
    /// Non-unix hosts get [`FilesError::Unsupported`] (empty slot).
    pub async fn open(config: OperatorFilesConfig) -> Result<Arc<Self>, FilesError> {
        #[cfg(not(unix))]
        {
            let _ = config;
            return Err(FilesError::Unsupported);
        }
        #[cfg(unix)]
        {
            let cap = config.limits.oid_cache_capacity;
            let root = RootDir::open(&config.home)?;
            let core = Arc::new(Self {
                home: config.home,
                files_state: config.files_state,
                limits: config.limits,
                vcs: config.vcs,
                maintainer: config.maintainer,
                lane: config.lane,
                oids: Mutex::new(OidCache::new(cap)),
                root,
                listings: Mutex::new(list::new_listing_cache()),
                retry_notify: Arc::new(Notify::new()),
                retry_task: Mutex::new(None),
                mutation_gate: Arc::new(Semaphore::new(ops::MUTATION_GATE)),
                uploads: Mutex::new(HashMap::new()),
                batches: Mutex::new(HashMap::new()),
            });
            journal::attach_retry_pump(&core);
            let _ = journal::recover_on_open(&core);
            Ok(core)
        }
    }

    pub fn home(&self) -> &PathBuf {
        &self.home
    }

    pub fn files_state(&self) -> &PathBuf {
        &self.files_state
    }

    pub fn limits(&self) -> &OperatorLimits {
        &self.limits
    }

    /// The `.meta.yaml` maintainer this core was opened with (shared with cap-fs).
    pub fn maintainer(&self) -> Option<&Arc<MetaMaintainer>> {
        self.maintainer.as_ref()
    }

    /// The user-commit lane this core was opened with (the per-repo git queue).
    pub fn lane(&self) -> Option<&Arc<dyn UserCommitLane>> {
        self.lane.as_ref()
    }

    /// Abort the retry pump. Wiring calls this inside `holds.git_queue` before
    /// `close_and_join`, so the pump cannot enqueue after the lane is gone.
    pub fn abort_retry_pump(&self) {
        journal::abort_retry_pump(self.retry_notify.as_ref(), &self.retry_task);
    }
}

impl Drop for OperatorFiles {
    fn drop(&mut self) {
        journal::abort_retry_pump(self.retry_notify.as_ref(), &self.retry_task);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_stores_config_on_unix() {
        let home = tempfile::tempdir().expect("home");
        let state = home.path().join(".runtime").join("files");
        let core = OperatorFiles::open(OperatorFilesConfig {
            home: home.path().to_path_buf(),
            files_state: state.clone(),
            limits: OperatorLimits::default(),
            vcs: None,
            maintainer: None,
            lane: None,
        })
        .await
        .expect("open");
        assert_eq!(core.home(), home.path());
        assert_eq!(core.files_state(), &state);
        assert_eq!(core.limits().oid_cache_capacity, OID_CACHE_CAPACITY);
    }
}
