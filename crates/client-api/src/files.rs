//! CONTRACT-246 `files` family — vault working-tree JSON routes.
//!
//! Thirteen JSON routes (transport 11 + R6 `POST /client/files:copy` + R2b
//! `POST /client/files:commit-batch`). The raw byte route is transport-owned and
//! lives in [`crate::files_raw`]. Handler order (A24): loopback → parse/`FilesPath`
//! → `provider_or_unavailable` → `mark_provider_entry` (mutations) → provider.

pub mod detail;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use advance_git::label::normalize_title;
use advance_shared_types::file_identity::FileIdentity;
use advance_shared_types::workspace_path::{
    classify_lexical, gate, normalize_workspace_path, GateRefusal, PathClass, PathDefect,
};

use crate::api::{ClientApi, HandlerCtx, HandlerSpec};
use crate::clock::Clock;
use crate::config::SessionAdmission;
use crate::cursor::{ClientCursorCodec, SealPurpose, SEAL_TAG_FILE_TICKET};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::file_ticket::{self, FileTicketBody, TicketIntent};
use crate::git::ClientGitCommitLabel;
use crate::provider::{provider_or_unavailable, CursorCodecSlot, FilesProviderSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::{session_digest, session_ref_hex, Platform, Scope};

pub use advance_shared_types::workspace_path::PathUse;
pub use detail::{
    invalid_cursor, invalid_files_body, invalid_intent, invalid_oid, invalid_query, invalid_rev,
    invalid_title, item_count, loopback_only, reserved_agent_id, reserved_namespace, CapacityKind,
    FilesFailure, Oid40,
};

/// Maximum UTF-8 length of a workspace path after NFC.
pub const MAX_FILES_PATH_BYTES: usize = 1024;
pub const FILES_DEFAULT_PAGE_LIMIT: usize = 200;
pub const FILES_MAX_PAGE_LIMIT: usize = 500;
pub const FILES_MAX_BATCH_ITEMS: usize = 256;
pub const FILES_MAX_EXTERNAL_ITEMS: usize = 1;
pub const FILES_MAX_SEARCH_LIMIT: usize = 200;
pub const FILES_DEFAULT_SEARCH_LIMIT: usize = 50;
pub const FILES_MAX_QUERY_CHARS: usize = 128;
pub const FILES_MAX_CURSOR_CHARS: usize = 1536;
pub const FILES_MAX_PAGE_BYTES: usize = 1024 * 1024;
pub const FILES_READ_TTL_DEFAULT_MS: u64 = 60_000;
pub const FILES_READ_TTL_MIN_MS: u64 = 1_000;
pub const FILES_READ_TTL_MAX_MS: u64 = 10 * 60 * 1_000;
pub const FILES_WRITE_TTL_MS: u64 = 60_000;
pub const FILES_MAX_UPLOAD_BYTES: u64 = 1 << 30;
pub const FILES_MAX_DESCRIPTION_CHARS: usize = 280;

// ── Path gate ─────────────────────────────────────────────────────────────────────────────

/// A workspace-relative NFC path that has already passed the lexical gate for a [`PathUse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesPath {
    normalized: String,
    class: PathClass,
}

impl FilesPath {
    /// NFC-normalize, classify, and apply [`gate`] for `use_`.
    pub fn parse(raw: &str, use_: PathUse) -> Result<Self, ClientError> {
        let allow_root = matches!(use_, PathUse::List | PathUse::Read);
        let normalized = normalize_workspace_path(raw, allow_root)
            .map_err(|d| FilesFailure::InvalidPath(d).into_client_error())?;
        let class = classify_lexical(&normalized);
        gate(class.access, use_).map_err(|refusal| match refusal {
            GateRefusal::NotFound => FilesFailure::NotFound.into_client_error(),
            GateRefusal::ParentNotFound => {
                FilesFailure::ParentNotFound { item: None }.into_client_error()
            }
            GateRefusal::InvalidPath(d) => FilesFailure::InvalidPath(d).into_client_error(),
            GateRefusal::ReadOnly(reason) => {
                FilesFailure::ReadOnly { reason, item: None }.into_client_error()
            }
        })?;
        Ok(Self { normalized, class })
    }

    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    pub fn class(&self) -> PathClass {
        self.class
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileEntry {
    pub name: String,
    pub path: String,
    /// `file` | `dir` | `symlink` | `other`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    /// `committed` | `modified` | `untracked` | `ignored` | `unknown`; null = repo unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_reason: Option<String>,
    pub territory_root: bool,
    pub dotfile: bool,
    pub package: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileList {
    pub path: String,
    pub entries: Vec<ClientFileEntry>,
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub skipped: u64,
    /// `ready` | `unknown`.
    pub vcs: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileStat {
    pub entry: ClientFileEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versioned: Option<bool>,
    /// `too_large` | `ignored` | `untracked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versioned_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileSearchResult {
    pub query: String,
    pub path: String,
    pub items: Vec<ClientFileEntry>,
    pub truncated: bool,
    pub visited: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileTicket {
    pub ticket: String,
    pub url: String,
    /// `read` | `write`.
    pub mode: String,
    pub expires_at_ms: u64,
    pub path: String,
    pub etag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
    pub size: u64,
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_oid: Option<String>,
    pub already_current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileCommit {
    pub sha: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_sha: Option<String>,
    pub subject: String,
    pub label: ClientGitCommitLabel,
    /// Always `user` on this family.
    pub commit_type: String,
    pub initiator: String,
    pub committed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileChange {
    pub path: String,
    /// `file` | `dir`.
    pub kind: String,
    /// `added` | `modified` | `deleted` | `renamed` | `replaced`.
    pub change: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub versioned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versioned_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileWriteResult {
    pub path: String,
    pub oid: String,
    pub size: u64,
    pub versioned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versioned_reason: Option<String>,
    pub commit_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<ClientFileCommit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileMutationResult {
    pub changes: Vec<ClientFileChange>,
    pub changes_total: u64,
    pub commit_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<ClientFileCommit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientFileVersionResult {
    pub tag: String,
    pub version_label: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    pub commit: ClientFileCommit,
    pub pending_before: bool,
    pub adopt_incomplete: bool,
    pub unversioned_count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileReadTicketRequest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    #[serde(default)]
    pub want_oid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileWriteTicketRequest {
    pub path: String,
    pub intent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_oid: Option<String>,
    pub size: u64,
    pub oid: String,
    /// R2b batch id (`^[A-Za-z0-9_-]{16,64}$`). PUT then answers `commit_state: staged`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileCommitBatchRequest {
    pub batch: String,
    #[serde(default)]
    pub mkdirs: Vec<String>,
    #[serde(default)]
    pub parents: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileMkdirRequest {
    pub path: String,
    #[serde(default)]
    pub parents: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileMoveItem {
    pub from: String,
    pub to: String,
    /// Observed CAS base; missing or `null` means absent.
    #[serde(default)]
    pub base_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileMoveRequest {
    pub items: Vec<ClientFileMoveItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileDeleteItem {
    pub path: String,
    /// Observed CAS base; missing or `null` means absent.
    #[serde(default)]
    pub base_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileDeleteRequest {
    pub items: Vec<ClientFileDeleteItem>,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub confirm_unversioned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileRestoreItem {
    pub path: String,
    /// Observed CAS base; missing or `null` means absent.
    #[serde(default)]
    pub base_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileRestoreRequest {
    pub from_sha: String,
    pub items: Vec<ClientFileRestoreItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileSaveVersionRequest {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileExternalItem {
    pub path: String,
    /// Observed blob oid; missing or `null` means absent.
    #[serde(default)]
    pub oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileCommitExternalRequest {
    pub items: Vec<ClientFileExternalItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileCopyItem {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientFileCopyRequest {
    pub items: Vec<ClientFileCopyItem>,
}

// ── Provider port types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesActor {
    pub principal_id: String,
    pub os_user: String,
    pub platform: Platform,
    pub session_ref: String,
}

/// Closed `sort` tokens for `GET /client/files/entries` (`kind` is forwarded; OSS-5 plans it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesListSort {
    Name,
    Modified,
    Size,
    Kind,
}

impl FilesListSort {
    pub fn as_str(self) -> &'static str {
        match self {
            FilesListSort::Name => "name",
            FilesListSort::Modified => "modified",
            FilesListSort::Size => "size",
            FilesListSort::Kind => "kind",
        }
    }
}

/// Closed `order` tokens for `GET /client/files/entries`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesListOrder {
    Asc,
    Desc,
}

impl FilesListOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            FilesListOrder::Asc => "asc",
            FilesListOrder::Desc => "desc",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilesListQuery {
    pub path: FilesPath,
    pub limit: usize,
    pub cursor: Option<String>,
    pub folders_first: bool,
    pub want_oid: bool,
    pub sort: FilesListSort,
    pub order: FilesListOrder,
}

#[derive(Debug, Clone)]
pub struct FilesListPage {
    pub list: ClientFileList,
}

#[derive(Debug, Clone)]
pub struct FilesStatQuery {
    pub path: FilesPath,
    pub want_oid: bool,
}

#[derive(Debug, Clone)]
pub struct FilesSearchQuery {
    pub query: String,
    pub path: FilesPath,
    pub limit: usize,
    pub dotfiles: bool,
}

#[derive(Debug, Clone)]
pub struct FilesReadQuery {
    pub path: FilesPath,
    pub rev: Option<Oid40>,
    pub want_oid: bool,
}

#[derive(Debug, Clone)]
pub struct FileReadVersion {
    pub path: String,
    pub size: u64,
    pub content_type: String,
    pub oid: Option<Oid40>,
    pub identity: Option<FileIdentity>,
    pub rev: Option<Oid40>,
    pub already_current: bool,
}

#[derive(Debug, Clone)]
pub enum FileReadSource {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteIntent {
    Edit,
    Create,
    Upload,
}

impl WriteIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteIntent::Edit => "edit",
            WriteIntent::Create => "create",
            WriteIntent::Upload => "upload",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, ClientError> {
        match raw {
            "edit" => Ok(WriteIntent::Edit),
            "create" => Ok(WriteIntent::Create),
            "upload" => Ok(WriteIntent::Upload),
            _ => Err(invalid_intent()),
        }
    }

    pub fn ticket_intent(self) -> TicketIntent {
        match self {
            WriteIntent::Edit => TicketIntent::Edit,
            WriteIntent::Create => TicketIntent::Create,
            WriteIntent::Upload => TicketIntent::Upload,
        }
    }

    pub fn path_use(self) -> PathUse {
        match self {
            WriteIntent::Create => PathUse::CreateTarget,
            WriteIntent::Edit | WriteIntent::Upload => PathUse::WriteExisting,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileWriteTarget {
    pub path: FilesPath,
    pub intent: WriteIntent,
    pub size: u64,
    pub oid: Oid40,
    pub base_oid: Option<Oid40>,
    pub batch: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FilesCommitBatch {
    pub batch: String,
    pub mkdirs: Vec<FilesPath>,
    pub parents: bool,
}

#[derive(Debug, Clone)]
pub enum WriteCheck {
    Ok {
        etag: String,
        oid: Oid40,
        size: u64,
        content_type: String,
        identity: Option<FileIdentity>,
    },
    AlreadyCurrent {
        oid: Oid40,
        size: u64,
        content_type: String,
        etag: String,
        identity: Option<FileIdentity>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUploadHandle {
    pub id: String,
}

pub struct FileUploadSink {
    pub handle: FileUploadHandle,
    inner: FileUploadInner,
}

enum FileUploadInner {
    Memory(Arc<Mutex<Vec<u8>>>),
    File(std::fs::File),
}

impl FileUploadSink {
    pub fn memory(id: impl Into<String>) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                handle: FileUploadHandle { id: id.into() },
                inner: FileUploadInner::Memory(Arc::clone(&buf)),
            },
            buf,
        )
    }

    pub fn file(id: impl Into<String>, file: std::fs::File) -> Self {
        Self {
            handle: FileUploadHandle { id: id.into() },
            inner: FileUploadInner::File(file),
        }
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), ProviderError> {
        match &mut self.inner {
            FileUploadInner::Memory(buf) => {
                buf.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend_from_slice(bytes);
                Ok(())
            }
            FileUploadInner::File(file) => {
                use std::io::Write;
                file.write_all(bytes)
                    .map_err(|e| ProviderError::Unavailable(e.to_string()))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilesMkdir {
    pub path: FilesPath,
    pub parents: bool,
}

#[derive(Debug, Clone)]
pub struct FilesMoveItem {
    pub from: FilesPath,
    pub to: FilesPath,
    pub base_oid: Option<Oid40>,
}

#[derive(Debug, Clone)]
pub struct FilesDeleteItem {
    pub path: FilesPath,
    pub base_oid: Option<Oid40>,
}

#[derive(Debug, Clone)]
pub struct FilesDelete {
    pub items: Vec<FilesDeleteItem>,
    pub recursive: bool,
    pub confirm_unversioned: bool,
}

#[derive(Debug, Clone)]
pub struct FilesRestoreItem {
    pub path: FilesPath,
    pub base_oid: Option<Oid40>,
}

#[derive(Debug, Clone)]
pub struct FilesRestore {
    pub from_sha: Oid40,
    pub items: Vec<FilesRestoreItem>,
}

#[derive(Debug, Clone)]
pub struct FilesSaveVersion {
    pub title: String,
    pub paths: Option<Vec<FilesPath>>,
}

#[derive(Debug, Clone)]
pub struct FilesExternalItem {
    pub path: FilesPath,
    pub oid: Option<Oid40>,
}

#[derive(Debug, Clone)]
pub struct FilesCopyItem {
    pub from: FilesPath,
    pub to: FilesPath,
}

// ── Parse helpers ─────────────────────────────────────────────────────────────────────────

fn query_opt_str<'a>(body: &'a Value, key: &str) -> Result<Option<&'a str>, ClientError> {
    match body {
        Value::Null => Ok(None),
        Value::Object(m) => match m.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.as_str())),
            Some(_) => Err(invalid_files_body()),
        },
        _ => Err(invalid_files_body()),
    }
}

fn query_opt_u64(body: &Value, key: &str) -> Result<Option<u64>, ClientError> {
    match body {
        Value::Null => Ok(None),
        Value::Object(m) => match m.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => n.as_u64().ok_or_else(invalid_files_body).map(Some),
            Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(|_| invalid_files_body()),
            Some(_) => Err(invalid_files_body()),
        },
        _ => Err(invalid_files_body()),
    }
}

fn query_opt_bool(body: &Value, key: &str) -> Result<bool, ClientError> {
    query_opt_bool_default(body, key, false)
}

fn query_opt_bool_default(body: &Value, key: &str, default: bool) -> Result<bool, ClientError> {
    match body {
        Value::Null => Ok(default),
        Value::Object(m) => match m.get(key) {
            None | Some(Value::Null) => Ok(default),
            Some(Value::Bool(b)) => Ok(*b),
            Some(Value::String(s)) if s == "true" => Ok(true),
            Some(Value::String(s)) if s == "false" => Ok(false),
            Some(_) => Err(invalid_files_body()),
        },
        _ => Err(invalid_files_body()),
    }
}

fn parse_optional_oid(raw: Option<&str>) -> Result<Option<Oid40>, ClientError> {
    match raw {
        None => Ok(None),
        Some(s) => Oid40::parse(s).map(Some),
    }
}

fn parse_list_sort(body: &Value) -> Result<FilesListSort, ClientError> {
    match query_opt_str(body, "sort")? {
        None => Ok(FilesListSort::Name),
        Some("name") => Ok(FilesListSort::Name),
        Some("modified") => Ok(FilesListSort::Modified),
        Some("size") => Ok(FilesListSort::Size),
        Some("kind") => Ok(FilesListSort::Kind),
        Some(_) => Err(invalid_files_body()),
    }
}

fn parse_list_order(body: &Value) -> Result<FilesListOrder, ClientError> {
    match query_opt_str(body, "order")? {
        None => Ok(FilesListOrder::Asc),
        Some("asc") => Ok(FilesListOrder::Asc),
        Some("desc") => Ok(FilesListOrder::Desc),
        Some(_) => Err(invalid_files_body()),
    }
}

fn refuse_mixed_dest(items: impl Iterator<Item = String>) -> Result<(), ClientError> {
    let mut dest_parent: Option<String> = None;
    for parent in items {
        match &dest_parent {
            None => dest_parent = Some(parent),
            Some(expected) if expected == &parent => {}
            Some(_) => return Err(FilesFailure::MixedDestinations.into_client_error()),
        }
    }
    Ok(())
}

fn require_loopback(ctx: &HandlerCtx) -> Result<(), ClientError> {
    if !ctx.is_loopback_peer {
        return Err(loopback_only());
    }
    Ok(())
}

fn require_path(body: &Value, use_: PathUse) -> Result<FilesPath, ClientError> {
    match query_opt_str(body, "path")? {
        None => Err(FilesFailure::InvalidPath(PathDefect::Missing).into_client_error()),
        Some(p) => FilesPath::parse(p, use_),
    }
}

fn parse_cursor(raw: Option<&str>) -> Result<Option<String>, ClientError> {
    match raw {
        None | Some("") => Ok(None),
        Some(s) if s.len() > FILES_MAX_CURSOR_CHARS => Err(invalid_cursor()),
        Some(s) => {
            if !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(invalid_cursor());
            }
            Ok(Some(s.to_string()))
        }
    }
}

fn clamp_page_limit(raw: Option<u64>) -> usize {
    match raw {
        None => FILES_DEFAULT_PAGE_LIMIT,
        Some(0) => 1,
        Some(n) => (n as usize).clamp(1, FILES_MAX_PAGE_LIMIT),
    }
}

fn clamp_search_limit(raw: Option<u64>) -> usize {
    match raw {
        None => FILES_DEFAULT_SEARCH_LIMIT,
        Some(0) => 1,
        Some(n) => (n as usize).min(FILES_MAX_SEARCH_LIMIT).max(1),
    }
}

fn actor_from(ctx: &HandlerCtx) -> Result<FilesActor, ClientError> {
    if let Some(obj) = ctx.body.as_object() {
        if obj.contains_key("initiator") {
            return Err(invalid_files_body());
        }
    }
    let principal = ctx
        .principal
        .clone()
        .ok_or_else(|| ClientError::new(ClientErrorCode::Unauthenticated, "missing session"))?;
    let platform = ctx
        .platform
        .ok_or_else(|| ClientError::new(ClientErrorCode::Unauthenticated, "missing session"))?;
    let session_id = ctx
        .session_id
        .as_deref()
        .ok_or_else(|| ClientError::new(ClientErrorCode::Unauthenticated, "missing session"))?;
    Ok(FilesActor {
        principal_id: principal.id,
        os_user: principal.os_user,
        platform,
        session_ref: session_ref_hex(session_id),
    })
}

fn mark_provider_entry(ctx: &HandlerCtx) -> Result<(), ClientError> {
    match ctx.mutation.as_ref() {
        Some(mutation) => mutation.mark_provider_entry(),
        None => Ok(()),
    }
}

fn map_provider(err: ProviderError) -> ClientError {
    err.into_client_error()
}

fn json_ok<T: Serialize>(value: T) -> Result<Value, ClientError> {
    Ok(serde_json::to_value(value).expect("files DTO serializes"))
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
}

fn codec_or_unavailable(slot: &CursorCodecSlot) -> Result<Arc<dyn ClientCursorCodec>, ClientError> {
    provider_or_unavailable(slot)
}

fn session_digest_of(ctx: &HandlerCtx) -> Result<[u8; 32], ClientError> {
    let session_id = ctx
        .session_id
        .as_deref()
        .ok_or_else(|| ClientError::new(ClientErrorCode::Unauthenticated, "missing session"))?;
    Ok(session_digest(session_id))
}

fn read_ttl_ms(raw: Option<u64>, admission: SessionAdmission) -> Result<u64, ClientError> {
    let requested = raw.unwrap_or(FILES_READ_TTL_DEFAULT_MS);
    if requested < FILES_READ_TTL_MIN_MS || requested > FILES_READ_TTL_MAX_MS {
        return Err(invalid_files_body());
    }
    let cap = if admission == SessionAdmission::InProcessOnly {
        FILES_READ_TTL_DEFAULT_MS
    } else {
        FILES_READ_TTL_MAX_MS
    };
    Ok(requested.min(cap))
}

fn ticket_url(token: &str) -> String {
    format!("/client/files/raw/{token}")
}

fn mint_ticket(
    codec: &dyn ClientCursorCodec,
    body: &FileTicketBody,
) -> Result<String, ClientError> {
    let bytes = body.encode().map_err(|_| {
        ClientError::new(
            ClientErrorCode::ModuleUnavailable,
            "file ticket unavailable",
        )
    })?;
    codec.seal(
        SealPurpose::FileTicket,
        file_ticket::STREAM_ID,
        SEAL_TAG_FILE_TICKET,
        &bytes,
    )
}

// ── Handlers ──────────────────────────────────────────────────────────────────────────────

fn handle_entries(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let path = require_path(&ctx.body, PathUse::List)?;
    let limit = clamp_page_limit(query_opt_u64(&ctx.body, "limit")?);
    let cursor = parse_cursor(query_opt_str(&ctx.body, "cursor")?)?;
    let folders_first = query_opt_bool_default(&ctx.body, "folders_first", true)?;
    let want_oid = query_opt_bool(&ctx.body, "want_oid")?;
    let sort = parse_list_sort(&ctx.body)?;
    let order = parse_list_order(&ctx.body)?;
    let provider = provider_or_unavailable(slot)?;
    let page = provider
        .list(&FilesListQuery {
            path,
            limit,
            cursor,
            folders_first,
            want_oid,
            sort,
            order,
        })
        .map_err(map_provider)?;
    json_ok(page.list)
}

fn handle_stat(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let path = require_path(&ctx.body, PathUse::List)?;
    let want_oid = query_opt_bool(&ctx.body, "want_oid")?;
    let provider = provider_or_unavailable(slot)?;
    let stat = provider
        .stat(&FilesStatQuery { path, want_oid })
        .map_err(map_provider)?;
    json_ok(stat)
}

fn handle_search(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let q = query_opt_str(&ctx.body, "q")?.unwrap_or("");
    if q.is_empty() || q.chars().count() > FILES_MAX_QUERY_CHARS {
        return Err(invalid_query());
    }
    let path = match query_opt_str(&ctx.body, "path")? {
        None => FilesPath::parse("", PathUse::List)?,
        Some(p) => FilesPath::parse(p, PathUse::List)?,
    };
    let limit = clamp_search_limit(query_opt_u64(&ctx.body, "limit")?);
    let dotfiles = query_opt_bool(&ctx.body, "dotfiles")?;
    let provider = provider_or_unavailable(slot)?;
    let result = provider
        .search(&FilesSearchQuery {
            query: q.to_string(),
            path,
            limit,
            dotfiles,
        })
        .map_err(map_provider)?;
    json_ok(result)
}

fn handle_read_ticket(
    ctx: &HandlerCtx,
    slot: &FilesProviderSlot,
    codec_slot: &CursorCodecSlot,
    clock: &dyn Clock,
    admission: SessionAdmission,
) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileReadTicketRequest = if ctx.body.is_null() {
        return Err(FilesFailure::InvalidPath(PathDefect::Missing).into_client_error());
    } else {
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?
    };
    let path = FilesPath::parse(&req.path, PathUse::Read)?;
    let rev = match req.rev.as_deref() {
        None => None,
        Some(s) => Some(Oid40::parse_rev(s)?),
    };
    if let Some(d) = req.disposition.as_deref() {
        if d != "inline" && d != "attachment" {
            return Err(invalid_files_body());
        }
    }
    let ttl = read_ttl_ms(req.ttl_ms, admission)?;
    let digest = session_digest_of(ctx)?;
    let codec = codec_or_unavailable(codec_slot)?;
    let provider = provider_or_unavailable(slot)?;
    let version = provider
        .prepare_read(&FilesReadQuery {
            path: path.clone(),
            rev: rev.clone(),
            want_oid: req.want_oid,
        })
        .map_err(map_provider)?;
    let now = clock.now_millis();
    let expires = now.saturating_add(ttl);
    let attachment = req.disposition.as_deref() == Some("attachment");
    let body = FileTicketBody::read(
        &version.path,
        digest,
        expires,
        version.oid.clone(),
        version.rev.clone().or(rev),
        version.identity,
        version.size,
        attachment,
    );
    let token = mint_ticket(codec.as_ref(), &body)?;
    json_ok(ClientFileTicket {
        url: ticket_url(&token),
        ticket: token,
        mode: "read".into(),
        expires_at_ms: expires,
        path: version.path,
        etag: file_ticket::etag_for(version.oid.as_ref(), version.identity.as_ref()),
        oid: version.oid.as_ref().map(Oid40::as_str).map(str::to_string),
        size: version.size,
        content_type: version.content_type,
        rev: version.rev.as_ref().map(Oid40::as_str).map(str::to_string),
        base_oid: None,
        already_current: version.already_current,
    })
}

fn handle_write_ticket(
    ctx: &HandlerCtx,
    slot: &FilesProviderSlot,
    codec_slot: &CursorCodecSlot,
    clock: &dyn Clock,
    max_upload: u64,
) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileWriteTicketRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    let intent = WriteIntent::parse(&req.intent)?;
    match intent {
        WriteIntent::Edit if req.base_oid.is_none() => return Err(invalid_intent()),
        WriteIntent::Create if req.base_oid.is_some() => return Err(invalid_intent()),
        _ => {}
    }
    if req.size > max_upload {
        return Err(FilesFailure::UploadTooLarge.into_client_error());
    }
    let oid = Oid40::parse(&req.oid)?;
    let base_oid = match req.base_oid.as_deref() {
        None => None,
        Some(s) => Some(Oid40::parse(s)?),
    };
    let path = FilesPath::parse(&req.path, intent.path_use())?;
    let digest = session_digest_of(ctx)?;
    let actor = actor_from(ctx)?;
    let codec = codec_or_unavailable(codec_slot)?;
    let provider = provider_or_unavailable(slot)?;
    let batch = match req.batch.as_deref() {
        None => None,
        Some(raw) => Some(parse_batch_id(raw)?),
    };
    let target = FileWriteTarget {
        path: path.clone(),
        intent,
        size: req.size,
        oid: oid.clone(),
        base_oid: base_oid.clone(),
        batch: batch.clone(),
    };
    let check = provider
        .check_write(&actor, &target)
        .map_err(map_provider)?;
    let now = clock.now_millis();
    let expires = now.saturating_add(FILES_WRITE_TTL_MS);
    let (already_current, etag, content_type, identity, size, result_oid) = match check {
        WriteCheck::AlreadyCurrent {
            oid: current,
            size,
            content_type,
            etag,
            identity,
        } => (true, etag, content_type, identity, size, current),
        WriteCheck::Ok {
            etag,
            oid: current,
            size,
            content_type,
            identity,
        } => (false, etag, content_type, identity, size, current),
    };
    let body = FileTicketBody::write(
        path.as_str(),
        digest,
        expires,
        result_oid.clone(),
        base_oid.clone(),
        identity,
        size,
        intent.ticket_intent(),
    )
    .with_batch(batch);
    let token = mint_ticket(codec.as_ref(), &body)?;
    json_ok(ClientFileTicket {
        url: ticket_url(&token),
        ticket: token,
        mode: "write".into(),
        expires_at_ms: expires,
        path: path.as_str().to_string(),
        etag,
        oid: Some(result_oid.as_str().to_string()),
        size,
        content_type,
        rev: None,
        base_oid: base_oid.as_ref().map(|o| o.as_str().to_string()),
        already_current,
    })
}

fn handle_mkdir(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileMkdirRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    let path = FilesPath::parse(&req.path, PathUse::CreateTarget)?;
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    let result = provider
        .mkdir(
            &actor,
            &FilesMkdir {
                path,
                parents: req.parents,
            },
        )
        .map_err(map_provider)?;
    json_ok(result)
}

fn parse_move_items(body: &Value) -> Result<Vec<FilesMoveItem>, ClientError> {
    let req: ClientFileMoveRequest =
        serde_json::from_value(body.clone()).map_err(|_| invalid_files_body())?;
    if req.items.is_empty() || req.items.len() > FILES_MAX_BATCH_ITEMS {
        return Err(item_count());
    }
    let mut out = Vec::with_capacity(req.items.len());
    for item in req.items {
        out.push(FilesMoveItem {
            from: FilesPath::parse(&item.from, PathUse::WriteExisting)?,
            to: FilesPath::parse(&item.to, PathUse::CreateTarget)?,
            base_oid: parse_optional_oid(item.base_oid.as_deref())?,
        });
    }
    refuse_mixed_dest(
        out.iter()
            .map(|item| parent_of(item.to.as_str()).to_string()),
    )?;
    Ok(out)
}

fn handle_move(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let items = parse_move_items(&ctx.body)?;
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    json_ok(provider.move_items(&actor, &items).map_err(map_provider)?)
}

fn handle_delete(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileDeleteRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    if req.items.is_empty() || req.items.len() > FILES_MAX_BATCH_ITEMS {
        return Err(item_count());
    }
    let mut items = Vec::with_capacity(req.items.len());
    for item in req.items {
        items.push(FilesDeleteItem {
            path: FilesPath::parse(&item.path, PathUse::WriteExisting)?,
            base_oid: parse_optional_oid(item.base_oid.as_deref())?,
        });
    }
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    json_ok(
        provider
            .delete(
                &actor,
                &FilesDelete {
                    items,
                    recursive: req.recursive,
                    confirm_unversioned: req.confirm_unversioned,
                },
            )
            .map_err(map_provider)?,
    )
}

fn handle_restore(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileRestoreRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    if req.items.is_empty() || req.items.len() > FILES_MAX_BATCH_ITEMS {
        return Err(item_count());
    }
    let from_sha = Oid40::parse_rev(&req.from_sha)?;
    let mut items = Vec::with_capacity(req.items.len());
    for item in req.items {
        items.push(FilesRestoreItem {
            path: FilesPath::parse(&item.path, PathUse::CreateTarget)?,
            base_oid: parse_optional_oid(item.base_oid.as_deref())?,
        });
    }
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    json_ok(
        provider
            .restore(&actor, &FilesRestore { from_sha, items })
            .map_err(map_provider)?,
    )
}

fn handle_save_version(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileSaveVersionRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    let title = normalize_title(&req.title).map_err(|_| invalid_title())?;
    if let Some(paths) = &req.paths {
        if paths.len() > FILES_MAX_BATCH_ITEMS {
            return Err(item_count());
        }
    }
    let paths = match req.paths {
        None => None,
        Some(ps) => {
            let mut out = Vec::with_capacity(ps.len());
            for p in ps {
                out.push(FilesPath::parse(&p, PathUse::Read)?);
            }
            Some(out)
        }
    };
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    json_ok(
        provider
            .save_version(&actor, &FilesSaveVersion { title, paths })
            .map_err(map_provider)?,
    )
}

fn handle_commit_external(
    ctx: &HandlerCtx,
    slot: &FilesProviderSlot,
) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileCommitExternalRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    if req.items.len() != FILES_MAX_EXTERNAL_ITEMS {
        return Err(item_count());
    }
    let mut items = Vec::with_capacity(req.items.len());
    for item in req.items {
        items.push(FilesExternalItem {
            path: FilesPath::parse(&item.path, PathUse::WriteExisting)?,
            oid: parse_optional_oid(item.oid.as_deref())?,
        });
    }
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    json_ok(
        provider
            .commit_external(&actor, &items)
            .map_err(map_provider)?,
    )
}

fn handle_copy(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileCopyRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    if req.items.is_empty() || req.items.len() > FILES_MAX_BATCH_ITEMS {
        return Err(item_count());
    }
    let mut items = Vec::with_capacity(req.items.len());
    for item in req.items {
        let from = FilesPath::parse(&item.from, PathUse::Read)?;
        let to = FilesPath::parse(&item.to, PathUse::CreateTarget)?;
        items.push(FilesCopyItem { from, to });
    }
    refuse_mixed_dest(
        items
            .iter()
            .map(|item| parent_of(item.to.as_str()).to_string()),
    )?;
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    json_ok(provider.copy_items(&actor, &items).map_err(map_provider)?)
}

fn parse_batch_id(raw: &str) -> Result<String, ClientError> {
    let ok = (16..=64).contains(&raw.len())
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(raw.to_string())
    } else {
        Err(invalid_files_body())
    }
}

fn handle_commit_batch(ctx: &HandlerCtx, slot: &FilesProviderSlot) -> Result<Value, ClientError> {
    require_loopback(ctx)?;
    let req: ClientFileCommitBatchRequest =
        serde_json::from_value(ctx.body.clone()).map_err(|_| invalid_files_body())?;
    let batch = parse_batch_id(&req.batch)?;
    if req.mkdirs.len() > FILES_MAX_BATCH_ITEMS {
        return Err(item_count());
    }
    let mut mkdirs = Vec::with_capacity(req.mkdirs.len());
    for path in req.mkdirs {
        mkdirs.push(FilesPath::parse(&path, PathUse::CreateTarget)?);
    }
    let actor = actor_from(ctx)?;
    let provider = provider_or_unavailable(slot)?;
    mark_provider_entry(ctx)?;
    json_ok(
        provider
            .commit_batch(
                &actor,
                &FilesCommitBatch {
                    batch,
                    mkdirs,
                    parents: req.parents,
                },
            )
            .map_err(map_provider)?,
    )
}

/// Register the thirteen JSON files routes. Routes are always registered; an absent provider is
/// `module_unavailable` (never `unknown_route`).
pub(crate) fn register(
    api: &mut ClientApi,
    slot: FilesProviderSlot,
    codec_slot: CursorCodecSlot,
    clock: Arc<dyn Clock>,
) {
    let admission = api.config().session_admission;
    let max_upload = api.config().max_upload_bytes;

    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_FILES_ENTRIES,
        HandlerSpec::read(true, move |ctx| handle_entries(ctx, &s))
            .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_FILES_STAT,
        HandlerSpec::read(true, move |ctx| handle_stat(ctx, &s))
            .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_FILES_SEARCH,
        HandlerSpec::read(true, move |ctx| handle_search(ctx, &s))
            .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    let c = codec_slot.clone();
    let clk = Arc::clone(&clock);
    api.register(
        Method::Post,
        routes::PATH_FILES_READ_TICKET,
        HandlerSpec::post_read(true, move |ctx| {
            handle_read_ticket(ctx, &s, &c, clk.as_ref(), admission)
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    let c = codec_slot.clone();
    let clk = Arc::clone(&clock);
    api.register(
        Method::Post,
        routes::PATH_FILES_WRITE_TICKET,
        HandlerSpec::post_read(true, move |ctx| {
            handle_write_ticket(ctx, &s, &c, clk.as_ref(), max_upload)
        })
        .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_FILES_MKDIR,
        HandlerSpec::mutation(true, move |ctx| handle_mkdir(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_FILES_MOVE,
        HandlerSpec::mutation(true, move |ctx| handle_move(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_FILES_DELETE,
        HandlerSpec::mutation(true, move |ctx| handle_delete(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_FILES_RESTORE,
        HandlerSpec::mutation(true, move |ctx| handle_restore(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_FILES_SAVE_VERSION,
        HandlerSpec::mutation(true, move |ctx| handle_save_version(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_FILES_COMMIT_EXTERNAL,
        HandlerSpec::mutation(true, move |ctx| handle_commit_external(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_FILES_COPY,
        HandlerSpec::mutation(true, move |ctx| handle_copy(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );

    let s = slot;
    api.register(
        Method::Post,
        routes::PATH_FILES_COMMIT_BATCH,
        HandlerSpec::mutation(true, move |ctx| handle_commit_batch(ctx, &s))
            .with_scopes(vec![Scope::WriteEntities]),
    );
}
