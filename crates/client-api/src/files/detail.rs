//! CONTRACT-246 detail-token registry for the `files` family.
//!
//! Grammar: `^[a-z][a-z0-9_]{0,47}(:[0-9a-z_]{1,64})?$`. `details[0]` is the stable token;
//! parameters follow as `key:value`. Published on every platform surface as `{token, code, params}`.

use advance_shared_types::workspace_path::{PathDefect, ReadOnlyReason};
use serde::Serialize;

use crate::envelope::{ClientError, ClientErrorCode};

/// One published registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DetailEntry {
    pub token: &'static str,
    pub code: &'static str,
    pub params: &'static [&'static str],
}

/// Every files-family detail token the surface publishes.
pub const REGISTRY: &[DetailEntry] = &[
    DetailEntry {
        token: "invalid_path",
        code: "invalid_request",
        params: &["reason"],
    },
    DetailEntry {
        token: "invalid_oid",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "invalid_rev",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "invalid_intent",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "invalid_title",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "invalid_query",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "invalid_cursor",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "item_count",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "mixed_destinations",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "reserved_namespace",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "reserved_agent_id",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "not_a_directory",
        code: "invalid_request",
        params: &["item"],
    },
    DetailEntry {
        token: "not_a_file",
        code: "invalid_request",
        params: &["item"],
    },
    DetailEntry {
        token: "not_empty",
        code: "invalid_request",
        params: &["item"],
    },
    DetailEntry {
        token: "overlap",
        code: "invalid_request",
        params: &["item"],
    },
    DetailEntry {
        token: "content_mismatch",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "content_length_required",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "upload_stalled",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "range_not_satisfiable",
        code: "invalid_request",
        params: &[],
    },
    DetailEntry {
        token: "read_only",
        code: "forbidden",
        params: &["reason", "item"],
    },
    DetailEntry {
        token: "loopback_only",
        code: "forbidden",
        params: &[],
    },
    DetailEntry {
        token: "host_not_allowed",
        code: "forbidden",
        params: &[],
    },
    DetailEntry {
        token: "fetch_dest",
        code: "forbidden",
        params: &[],
    },
    DetailEntry {
        token: "parent_not_found",
        code: "not_found",
        params: &["item"],
    },
    DetailEntry {
        token: "unknown_version",
        code: "not_found",
        params: &["item"],
    },
    DetailEntry {
        token: "ticket_invalid",
        code: "not_found",
        params: &[],
    },
    DetailEntry {
        token: "ticket_expired",
        code: "not_found",
        params: &[],
    },
    DetailEntry {
        token: "ticket_session_ended",
        code: "unauthenticated",
        params: &[],
    },
    DetailEntry {
        token: "stale_base",
        code: "invalid_state",
        params: &["current_oid", "item"],
    },
    DetailEntry {
        token: "batch_expired",
        code: "invalid_state",
        params: &["item"],
    },
    DetailEntry {
        token: "stale_ticket",
        code: "invalid_state",
        params: &[],
    },
    DetailEntry {
        token: "file_busy",
        code: "invalid_state",
        params: &[],
    },
    DetailEntry {
        token: "head_moved",
        code: "invalid_state",
        params: &[],
    },
    DetailEntry {
        token: "unversioned_content",
        code: "invalid_state",
        params: &["files", "bytes", "item"],
    },
    DetailEntry {
        token: "vcs_unavailable",
        code: "invalid_state",
        params: &["reason"],
    },
    DetailEntry {
        token: "cursor_stale",
        code: "invalid_state",
        params: &[],
    },
    DetailEntry {
        token: "meta_unsafe",
        code: "invalid_state",
        params: &[],
    },
    DetailEntry {
        token: "meta_too_large",
        code: "invalid_state",
        params: &[],
    },
    DetailEntry {
        token: "too_many_entries",
        code: "invalid_state",
        params: &[],
    },
    DetailEntry {
        token: "cross_device",
        code: "invalid_state",
        params: &["item"],
    },
    DetailEntry {
        token: "target_exists",
        code: "already_exists",
        params: &["current_oid", "item"],
    },
    DetailEntry {
        token: "upload_too_large",
        code: "request_too_large",
        params: &[],
    },
    DetailEntry {
        token: "blob_too_large",
        code: "request_too_large",
        params: &[],
    },
    DetailEntry {
        token: "insufficient_storage",
        code: "request_too_large",
        params: &[],
    },
    DetailEntry {
        token: "capacity",
        code: "stream_backpressure",
        params: &["kind"],
    },
    DetailEntry {
        token: "commit_failed",
        code: "module_unavailable",
        params: &[],
    },
];

const TOKEN_GRAMMAR: &str = r"^[a-z][a-z0-9_]{0,47}(:[0-9a-z_]{1,64})?$";

/// A 40-character lowercase hex git blob / commit id. Constructor rejects anything else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Oid40(String);

impl Oid40 {
    /// Accept upper or lower hex; store lowercase.
    pub fn parse(raw: &str) -> Result<Self, ClientError> {
        if raw.len() != 40 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid_oid());
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }

    /// Same as [`parse`] but the token is `invalid_rev`.
    pub fn parse_rev(raw: &str) -> Result<Self, ClientError> {
        if raw.len() != 40 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid_rev());
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode a 40-hex string into 20 bytes.
    pub fn to_bytes(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        hex::decode_to_slice(&self.0, &mut out).expect("constructor validated");
        out
    }

    pub fn from_bytes(bytes: &[u8; 20]) -> Self {
        Self(hex::encode(bytes))
    }
}

impl AsRef<str> for Oid40 {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Capacity kinds (`capacity kind:<k>`).
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
    pub const fn token(self) -> &'static str {
        match self {
            CapacityKind::RawRead => "raw_read",
            CapacityKind::RawUpload => "raw_upload",
            CapacityKind::SessionRead => "session_read",
            CapacityKind::SessionUpload => "session_upload",
            CapacityKind::History => "history",
            CapacityKind::Hash => "hash",
            CapacityKind::Mutation => "mutation",
            CapacityKind::Versioning => "versioning",
            CapacityKind::Journal => "journal",
        }
    }

    pub const ALL: [CapacityKind; 9] = [
        CapacityKind::RawRead,
        CapacityKind::RawUpload,
        CapacityKind::SessionRead,
        CapacityKind::SessionUpload,
        CapacityKind::History,
        CapacityKind::Hash,
        CapacityKind::Mutation,
        CapacityKind::Versioning,
        CapacityKind::Journal,
    ];
}

/// Why a repository is unusable (`vcs_unavailable reason:<r>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcsUnavailableReason {
    NoRepo,
    NotMain,
    Locked,
}

impl VcsUnavailableReason {
    pub const fn token(self) -> &'static str {
        match self {
            VcsUnavailableReason::NoRepo => "no_repo",
            VcsUnavailableReason::NotMain => "not_main",
            VcsUnavailableReason::Locked => "locked",
        }
    }
}

/// Typed files-family failure. Rendered by [`FilesFailure::into_client_error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesFailure {
    NotFound,
    ParentNotFound {
        item: Option<u32>,
    },
    UnknownVersion {
        item: Option<u32>,
    },
    InvalidPath(PathDefect),
    NotADirectory {
        item: Option<u32>,
    },
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
    ContentMismatch,
    ContentLengthRequired,
    UploadStalled,
    RangeNotSatisfiable,
    ReadOnly {
        reason: ReadOnlyReason,
        item: Option<u32>,
    },
    LoopbackOnly,
    HostNotAllowed,
    FetchDest,
    TargetExists {
        current_oid: Option<Oid40>,
        name_collision: bool,
        item: Option<u32>,
    },
    StaleBase {
        current_oid: Option<Oid40>,
        item: Option<u32>,
    },
    StaleTicket,
    FileBusy,
    HeadMoved,
    UnversionedContent {
        files: Option<u64>,
        bytes: Option<u64>,
        item: Option<u32>,
    },
    VcsUnavailable {
        reason: Option<VcsUnavailableReason>,
    },
    CursorStale,
    MetaUnsafe,
    MetaTooLarge,
    TooManyEntries,
    CrossDevice {
        item: Option<u32>,
    },
    ReservedNamespace,
    UploadTooLarge,
    BlobTooLarge,
    InsufficientStorage,
    Capacity(CapacityKind),
    CommitFailed,
    TicketInvalid,
    TicketExpired,
    TicketSessionEnded,
    BatchExpired {
        item: Option<u32>,
    },
}

impl FilesFailure {
    pub fn into_client_error(self) -> ClientError {
        let (code, message, details) = self.render();
        ClientError::new(code, message).with_details(details)
    }

    /// Token, code, message and detail list — used by the registry witness.
    pub fn render(&self) -> (ClientErrorCode, &'static str, Vec<String>) {
        match self {
            FilesFailure::NotFound => (ClientErrorCode::NotFound, "resource not found", Vec::new()),
            FilesFailure::ParentNotFound { item } => (
                ClientErrorCode::NotFound,
                "resource not found",
                with_item(vec!["parent_not_found".into()], *item),
            ),
            FilesFailure::UnknownVersion { item } => (
                ClientErrorCode::NotFound,
                "resource not found",
                with_item(vec!["unknown_version".into()], *item),
            ),
            FilesFailure::InvalidPath(reason) => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                vec!["invalid_path".into(), format!("reason:{}", reason.reason())],
            ),
            FilesFailure::NotADirectory { item } => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                with_item(vec!["not_a_directory".into()], *item),
            ),
            FilesFailure::NotAFile { item } => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                with_item(vec!["not_a_file".into()], *item),
            ),
            FilesFailure::NotEmpty { item } => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                with_item(vec!["not_empty".into()], *item),
            ),
            FilesFailure::Overlap { item } => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                with_item(vec!["overlap".into()], *item),
            ),
            FilesFailure::MixedDestinations => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                vec!["mixed_destinations".into()],
            ),
            FilesFailure::ContentMismatch => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                vec!["content_mismatch".into()],
            ),
            FilesFailure::ContentLengthRequired => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                vec!["content_length_required".into()],
            ),
            FilesFailure::UploadStalled => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                vec!["upload_stalled".into()],
            ),
            FilesFailure::RangeNotSatisfiable => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                vec!["range_not_satisfiable".into()],
            ),
            FilesFailure::ReadOnly { reason, item } => (
                ClientErrorCode::Forbidden,
                "path not accessible",
                with_item(
                    vec!["read_only".into(), format!("reason:{}", reason.reason())],
                    *item,
                ),
            ),
            FilesFailure::LoopbackOnly => (
                ClientErrorCode::Forbidden,
                "not allowed",
                vec!["loopback_only".into()],
            ),
            FilesFailure::HostNotAllowed => (
                ClientErrorCode::Forbidden,
                "not allowed",
                vec!["host_not_allowed".into()],
            ),
            FilesFailure::FetchDest => (
                ClientErrorCode::Forbidden,
                "not allowed",
                vec!["fetch_dest".into()],
            ),
            FilesFailure::TargetExists {
                current_oid,
                name_collision,
                item,
            } => {
                let mut d = vec!["target_exists".into()];
                if let Some(oid) = current_oid {
                    d.push(format!("current_oid:{}", oid.as_str()));
                }
                if *name_collision {
                    d.push("name_collision".into());
                }
                (
                    ClientErrorCode::AlreadyExists,
                    "resource already exists",
                    with_item(d, *item),
                )
            }
            FilesFailure::StaleBase { current_oid, item } => {
                let mut d = vec!["stale_base".into()];
                match current_oid {
                    Some(oid) => d.push(format!("current_oid:{}", oid.as_str())),
                    None => d.push("current_absent".into()),
                }
                (
                    ClientErrorCode::InvalidState,
                    "file changed since it was read",
                    with_item(d, *item),
                )
            }
            FilesFailure::StaleTicket => (
                ClientErrorCode::InvalidState,
                "file changed since the ticket was issued",
                vec!["stale_ticket".into()],
            ),
            FilesFailure::FileBusy => (
                ClientErrorCode::InvalidState,
                "file is being written",
                vec!["file_busy".into()],
            ),
            FilesFailure::HeadMoved => (
                ClientErrorCode::InvalidState,
                "invalid request state",
                vec!["head_moved".into()],
            ),
            FilesFailure::UnversionedContent { files, bytes, item } => {
                let mut d = vec!["unversioned_content".into()];
                if let Some(n) = files {
                    d.push(format!("files:{n}"));
                }
                match bytes {
                    Some(n) => d.push(format!("bytes:{n}")),
                    None if files.is_some() => d.push("unknown".into()),
                    None => {}
                }
                (
                    ClientErrorCode::InvalidState,
                    "content not in history",
                    with_item(d, *item),
                )
            }
            FilesFailure::VcsUnavailable { reason } => {
                let mut d = vec!["vcs_unavailable".into()];
                if let Some(r) = reason {
                    d.push(format!("reason:{}", r.token()));
                }
                (ClientErrorCode::InvalidState, "invalid request state", d)
            }
            FilesFailure::CursorStale => (
                ClientErrorCode::InvalidState,
                "invalid request state",
                vec!["cursor_stale".into()],
            ),
            FilesFailure::MetaUnsafe => (
                ClientErrorCode::InvalidState,
                "invalid request state",
                vec!["meta_unsafe".into()],
            ),
            FilesFailure::MetaTooLarge => (
                ClientErrorCode::InvalidState,
                "invalid request state",
                vec!["meta_too_large".into()],
            ),
            FilesFailure::TooManyEntries => (
                ClientErrorCode::InvalidState,
                "invalid request state",
                vec!["too_many_entries".into()],
            ),
            FilesFailure::CrossDevice { item } => (
                ClientErrorCode::InvalidState,
                "invalid request state",
                with_item(vec!["cross_device".into()], *item),
            ),
            FilesFailure::ReservedNamespace => (
                ClientErrorCode::InvalidRequest,
                "invalid request",
                vec!["reserved_namespace".into()],
            ),
            FilesFailure::UploadTooLarge => (
                ClientErrorCode::RequestTooLarge,
                "request too large",
                vec!["upload_too_large".into()],
            ),
            FilesFailure::BlobTooLarge => (
                ClientErrorCode::RequestTooLarge,
                "request too large",
                vec!["blob_too_large".into()],
            ),
            FilesFailure::InsufficientStorage => (
                ClientErrorCode::RequestTooLarge,
                "request too large",
                vec!["insufficient_storage".into()],
            ),
            FilesFailure::Capacity(kind) => (
                ClientErrorCode::StreamBackpressure,
                "capacity exceeded",
                vec!["capacity".into(), format!("kind:{}", kind.token())],
            ),
            FilesFailure::CommitFailed => (
                ClientErrorCode::ModuleUnavailable,
                "provider unavailable",
                vec!["commit_failed".into()],
            ),
            FilesFailure::TicketInvalid => (
                ClientErrorCode::NotFound,
                "file ticket not found",
                vec!["ticket_invalid".into()],
            ),
            FilesFailure::TicketExpired => (
                ClientErrorCode::NotFound,
                "file ticket not found",
                vec!["ticket_expired".into()],
            ),
            FilesFailure::TicketSessionEnded => (
                ClientErrorCode::Unauthenticated,
                "session ended",
                vec!["ticket_session_ended".into()],
            ),
            FilesFailure::BatchExpired { item } => (
                ClientErrorCode::InvalidState,
                "operation not valid for the resource's current state",
                with_item(vec!["batch_expired".into()], *item),
            ),
        }
    }

    /// The `details[0]` token (empty for bare `NotFound`).
    pub fn token(&self) -> Option<&'static str> {
        match self {
            FilesFailure::NotFound => None,
            FilesFailure::ParentNotFound { .. } => Some("parent_not_found"),
            FilesFailure::UnknownVersion { .. } => Some("unknown_version"),
            FilesFailure::InvalidPath(_) => Some("invalid_path"),
            FilesFailure::NotADirectory { .. } => Some("not_a_directory"),
            FilesFailure::NotAFile { .. } => Some("not_a_file"),
            FilesFailure::NotEmpty { .. } => Some("not_empty"),
            FilesFailure::Overlap { .. } => Some("overlap"),
            FilesFailure::MixedDestinations => Some("mixed_destinations"),
            FilesFailure::ContentMismatch => Some("content_mismatch"),
            FilesFailure::ContentLengthRequired => Some("content_length_required"),
            FilesFailure::UploadStalled => Some("upload_stalled"),
            FilesFailure::RangeNotSatisfiable => Some("range_not_satisfiable"),
            FilesFailure::ReadOnly { .. } => Some("read_only"),
            FilesFailure::LoopbackOnly => Some("loopback_only"),
            FilesFailure::HostNotAllowed => Some("host_not_allowed"),
            FilesFailure::FetchDest => Some("fetch_dest"),
            FilesFailure::TargetExists { .. } => Some("target_exists"),
            FilesFailure::StaleBase { .. } => Some("stale_base"),
            FilesFailure::StaleTicket => Some("stale_ticket"),
            FilesFailure::FileBusy => Some("file_busy"),
            FilesFailure::HeadMoved => Some("head_moved"),
            FilesFailure::UnversionedContent { .. } => Some("unversioned_content"),
            FilesFailure::VcsUnavailable { .. } => Some("vcs_unavailable"),
            FilesFailure::CursorStale => Some("cursor_stale"),
            FilesFailure::MetaUnsafe => Some("meta_unsafe"),
            FilesFailure::MetaTooLarge => Some("meta_too_large"),
            FilesFailure::TooManyEntries => Some("too_many_entries"),
            FilesFailure::CrossDevice { .. } => Some("cross_device"),
            FilesFailure::ReservedNamespace => Some("reserved_namespace"),
            FilesFailure::UploadTooLarge => Some("upload_too_large"),
            FilesFailure::BlobTooLarge => Some("blob_too_large"),
            FilesFailure::InsufficientStorage => Some("insufficient_storage"),
            FilesFailure::Capacity(_) => Some("capacity"),
            FilesFailure::CommitFailed => Some("commit_failed"),
            FilesFailure::TicketInvalid => Some("ticket_invalid"),
            FilesFailure::TicketExpired => Some("ticket_expired"),
            FilesFailure::TicketSessionEnded => Some("ticket_session_ended"),
            FilesFailure::BatchExpired { .. } => Some("batch_expired"),
        }
    }
}

fn with_item(mut details: Vec<String>, item: Option<u32>) -> Vec<String> {
    if let Some(n) = item {
        details.push(format!("item:{n}"));
    }
    details
}

pub fn invalid_oid() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["invalid_oid".into()])
}

pub fn invalid_rev() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["invalid_rev".into()])
}

pub fn invalid_intent() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["invalid_intent".into()])
}

pub fn invalid_title() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["invalid_title".into()])
}

pub fn invalid_query() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["invalid_query".into()])
}

pub fn invalid_cursor() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["invalid_cursor".into()])
}

pub fn item_count() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["item_count".into()])
}

pub fn reserved_namespace() -> ClientError {
    FilesFailure::ReservedNamespace.into_client_error()
}

pub fn reserved_agent_id() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, "invalid request")
        .with_details(vec!["reserved_agent_id".into()])
}

pub fn invalid_files_body() -> ClientError {
    ClientError::new(
        ClientErrorCode::InvalidRequest,
        "invalid files request body",
    )
}

pub fn loopback_only() -> ClientError {
    FilesFailure::LoopbackOnly.into_client_error()
}

/// Every `details` token matches the published grammar.
pub fn token_matches_grammar(token: &str) -> bool {
    if token.len() > 48 + 1 + 64 {
        return false;
    }
    let (head, param) = match token.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (token, None),
    };
    fn ident(s: &str, max: usize) -> bool {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() => {}
            _ => return false,
        }
        let rest = chars.as_str();
        rest.len() < max
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }
    if !ident(head, 48) {
        return false;
    }
    match param {
        None => true,
        Some(p) => {
            !p.is_empty()
                && p.len() <= 64
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }
    }
}

/// Registry rows as JSON values (`{token, code, params}`).
pub fn registry_json() -> serde_json::Value {
    serde_json::to_value(REGISTRY).expect("registry serializes")
}

#[allow(dead_code)]
const _GRAMMAR_DOC: &str = TOKEN_GRAMMAR;
