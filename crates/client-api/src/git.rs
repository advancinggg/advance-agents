//! CONTRACT-190 `git` family — workspace history the Client API consumers read
//! (and the operator writes) without opening the runtime-private `.git`.
//!
//! Routes (family `git`):
//! - `GET  /client/git/status`                              repo honesty (`Scope::ReadInventory`)
//! - `GET  /client/git/commits?cursor&limit&agent_id&commit_type`
//! - `GET  /client/git/checkpoints?agent_id`
//! - `GET  /client/git/files/history?path=`                 (PR-3)
//! - `GET  /client/git/files/content?path=&sha=`            (PR-3)
//! - `POST /client/git/checkpoints:create`                  (PR-4, `ApproveGrants`)
//! - `POST /client/git/checkpoints/{agent_id}/{label}:rollback` (PR-4)
//!
//! File paths ride the query string: a workspace-relative path contains `/`, and
//! the existing segment matcher cannot bind `{path}` across slashes (or `{path}@{sha}`
//! as two parameters). Transport `query_body` already lifts `path` / `sha` into the
//! GET body.
//!
//! Honesty: a missing / off-`main` / unreadable repository is a **200 + status**,
//! never a 500. An absent provider slot is `module_unavailable`. The only 4xx
//! cases are the caller's (malformed cursor / sha / path).

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use advance_git::{
    checkpoints_by_sha, clamp_limit, validate_workspace_path, CheckpointRecord, CommitFilter,
    CommitType, DefaultNamedCheckpoint, DefaultWorkspaceRollback, GitHistoryReader, HistoryError,
    NamedCheckpoint, RepoSummary, WorkspaceRollback, DEFAULT_PAGE_LIMIT, MAX_BLOB_BYTES,
    MAX_PAGE_LIMIT,
};

use crate::agents::validate_agent_id;
use crate::api::{ClientApi, HandlerCtx, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::pagination::Cursor;
use crate::provider::{provider_or_unavailable, GitProviderSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// Bound on a checkpoint label (matches CONTRACT-022 / cap-lifecycle).
pub const MAX_CHECKPOINT_LABEL_LEN: usize = 128;
/// Bound on path-scoped checkpoint `paths` entries.
pub const MAX_CHECKPOINT_PATHS: usize = 256;
/// Bound on one workspace-relative path string.
pub const MAX_GIT_PATH_LEN: usize = 512;

// ── DTOs (CONTRACT-192 schema components) ────────────────────────────────────────────────────

/// `GET /client/git/status` (also the optional `git` object on `/client/health`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitStatus {
    /// `ready` / `missing` / `not_main` / `unreadable`.
    pub repo: String,
    /// Always `main` — the only branch this runtime commits on.
    pub branch: String,
    pub head_sha: Option<String>,
    pub commit_count: Option<u64>,
    pub checkpoint_count: Option<u64>,
    /// The observed HEAD / extra branch when `repo` is `not_main`.
    pub observed_ref: Option<String>,
    /// libgit2 / probe reason when `repo` is `unreadable`.
    pub reason: Option<String>,
}

/// One `refs/tags/checkpoint/{agent}/{label}` tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitCheckpointEntry {
    pub agent_id: String,
    pub label: String,
    pub sha: String,
    pub tagged_at_ms: u64,
    /// `null` = full-directory; a list = path-scoped. Always `null` when `valid` is false.
    pub paths: Option<Vec<String>>,
    pub valid: bool,
}

/// One linear `main` commit, with the checkpoints that point at it inlined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitCommitEntry {
    pub sha: String,
    pub committed_at_ms: u64,
    pub commit_type: Option<String>,
    pub initiator: Option<String>,
    pub subject: String,
    pub affected_paths_count: u32,
    pub checkpoints: Vec<ClientGitCheckpointEntry>,
}

/// `GET /client/git/commits`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitCommitPage {
    pub items: Vec<ClientGitCommitEntry>,
    pub next_cursor: Option<String>,
}

/// `GET /client/git/checkpoints`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitCheckpointList {
    pub items: Vec<ClientGitCheckpointEntry>,
}

/// One version of a file (`GET /client/git/files/history`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitFileVersion {
    pub sha: String,
    pub committed_at_ms: u64,
    pub commit_type: Option<String>,
    pub initiator: Option<String>,
    pub subject: String,
    pub deleted: bool,
}

/// `GET /client/git/files/history`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitFileHistory {
    pub items: Vec<ClientGitFileVersion>,
    pub truncated: bool,
}

/// `GET /client/git/files/content`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitFileAt {
    pub sha: String,
    pub path: String,
    pub size: u64,
    /// Standard base64 (no URL-safe alphabet) so a client can decode without a second codec.
    pub content_base64: String,
}

/// `POST /client/git/checkpoints:create` body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientGitCreateCheckpointRequest {
    pub agent_id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
}

/// `POST /client/git/checkpoints/{agent_id}/{label}:rollback` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGitRollbackResult {
    pub agent_id: String,
    pub label: String,
    pub restored_path_count: u32,
}

/// Query of `GET /client/git/commits` after handler-side validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedGitCommitQuery {
    pub after: Option<String>,
    pub limit: usize,
    pub filter: CommitFilter,
}

// ── Validation ───────────────────────────────────────────────────────────────────────────────

fn invalid(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, message)
}

/// `^[A-Za-z0-9._-]{1,128}$` plus no `..` — a checkpoint label / the git-ref component.
pub fn validate_checkpoint_label(label: &str) -> Result<(), ClientError> {
    if label.is_empty()
        || label.len() > MAX_CHECKPOINT_LABEL_LEN
        || label.contains("..")
        || label.contains('/')
        || !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(invalid("invalid checkpoint label"));
    }
    Ok(())
}

fn parse_commit_type(raw: &str) -> Result<CommitType, ClientError> {
    CommitType::parse_token(raw).ok_or_else(|| invalid("invalid commit_type"))
}

fn parse_limit(raw: &Value) -> Result<usize, ClientError> {
    match raw {
        Value::Null => Ok(0),
        Value::Number(n) => n
            .as_u64()
            .map(|n| n as usize)
            .ok_or_else(|| invalid("invalid limit")),
        Value::String(s) => s.parse::<usize>().map_err(|_| invalid("invalid limit")),
        _ => Err(invalid("invalid limit")),
    }
}

fn decode_cursor(raw: &str) -> Result<String, ClientError> {
    let cursor = Cursor::decode(raw).ok_or_else(|| invalid("invalid cursor"))?;
    cursor
        .last_id
        .filter(|id| id.len() == 40 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("invalid cursor"))
}

fn encode_cursor(sha: &str) -> String {
    Cursor::new(0, Some(sha.to_string())).encode()
}

/// Parse the GET body (query-string object, or `null`).
pub fn validate_commit_query(body: &Value) -> Result<ValidatedGitCommitQuery, ClientError> {
    if body.is_null() {
        return Ok(ValidatedGitCommitQuery {
            after: None,
            limit: DEFAULT_PAGE_LIMIT,
            filter: CommitFilter::default(),
        });
    }
    let obj = body
        .as_object()
        .ok_or_else(|| invalid("invalid git commit query"))?;
    let after = match obj.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(decode_cursor(s)?),
        Some(_) => return Err(invalid("invalid cursor")),
    };
    let limit = match obj.get("limit") {
        None => 0,
        Some(v) => parse_limit(v)?,
    };
    let agent_id = match obj.get("agent_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            validate_agent_id(s)?;
            Some(s.clone())
        }
        Some(_) => return Err(invalid("invalid agent id")),
    };
    let commit_type = match obj.get("commit_type") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(parse_commit_type(s)?),
        Some(_) => return Err(invalid("invalid commit_type")),
    };
    Ok(ValidatedGitCommitQuery {
        after,
        limit: clamp_limit(limit),
        filter: CommitFilter {
            agent_id,
            commit_type,
        },
    })
}

fn query_string_field<'a>(
    body: &'a Value,
    key: &'static str,
) -> Result<Option<&'a str>, ClientError> {
    match body {
        Value::Null => Ok(None),
        Value::Object(m) => match m.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.as_str())),
            Some(_) => Err(invalid("invalid git query")),
        },
        _ => Err(invalid("invalid git query")),
    }
}

fn require_path(body: &Value) -> Result<&str, ClientError> {
    let path = query_string_field(body, "path")?.ok_or_else(|| invalid("invalid path"))?;
    if path.len() > MAX_GIT_PATH_LEN {
        return Err(invalid("invalid path"));
    }
    validate_workspace_path(path).map_err(|_| invalid("invalid path"))?;
    Ok(path)
}

fn parse_create_request(body: &Value) -> Result<ClientGitCreateCheckpointRequest, ClientError> {
    if !body.is_object() {
        return Err(invalid("invalid git request body"));
    }
    let req: ClientGitCreateCheckpointRequest =
        serde_json::from_value(body.clone()).map_err(|_| invalid("invalid git request body"))?;
    validate_agent_id(&req.agent_id)?;
    validate_checkpoint_label(&req.label)?;
    if let Some(paths) = &req.paths {
        if paths.len() > MAX_CHECKPOINT_PATHS {
            return Err(invalid("too many checkpoint paths"));
        }
        for p in paths {
            if p.len() > MAX_GIT_PATH_LEN {
                return Err(invalid("invalid path"));
            }
            validate_workspace_path(p).map_err(|_| invalid("invalid path"))?;
        }
    }
    Ok(req)
}

fn mark_provider_entry(ctx: &HandlerCtx) -> Result<(), ClientError> {
    match ctx.mutation.as_ref() {
        Some(mutation) => mutation.mark_provider_entry(),
        None => Ok(()),
    }
}

fn checkpoint_dto(r: CheckpointRecord) -> ClientGitCheckpointEntry {
    ClientGitCheckpointEntry {
        agent_id: r.agent_id,
        label: r.label,
        sha: r.sha,
        tagged_at_ms: r.tagged_at_ms,
        paths: r.paths,
        valid: r.valid,
    }
}

fn status_from_summary(summary: RepoSummary) -> ClientGitStatus {
    let (observed_ref, reason) = match &summary.status {
        advance_git::GitRepoStatus::NotMain { observed } => (Some(observed.clone()), None),
        advance_git::GitRepoStatus::Unreadable { reason } => (None, Some(reason.clone())),
        _ => (None, None),
    };
    ClientGitStatus {
        repo: summary.status.token().to_string(),
        branch: "main".to_string(),
        head_sha: summary.head_sha,
        commit_count: summary.commit_count,
        checkpoint_count: summary.checkpoint_count,
        observed_ref,
        reason,
    }
}

fn commit_type_token(kind: Option<CommitType>) -> Option<String> {
    kind.map(|k| k.as_token().to_string())
}

fn map_history_err(err: HistoryError) -> ProviderError {
    match err {
        HistoryError::MalformedSha(_) => ProviderError::InvalidRequest("malformed sha".into()),
        HistoryError::UnknownCommit(_) => ProviderError::NotFound("commit".into()),
        HistoryError::InvalidPath { .. } => ProviderError::InvalidRequest("invalid path".into()),
        HistoryError::PathNotFound { .. } => ProviderError::NotFound("path".into()),
        HistoryError::BlobTooLarge { .. } => ProviderError::TooLarge("blob".into()),
        HistoryError::Repo(_) => ProviderError::Unavailable("repository".into()),
    }
}

// ── Provider adapter over [`GitHistoryReader`] ───────────────────────────────────────────────

/// Production adapter: one [`GitHistoryReader`] per workspace. Write methods take the
/// per-repo coord mutex through [`DefaultNamedCheckpoint`] / [`DefaultWorkspaceRollback`].
#[derive(Debug, Clone)]
pub struct GitHistoryReaderProvider {
    reader: GitHistoryReader,
}

impl GitHistoryReaderProvider {
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            reader: GitHistoryReader::new(workspace),
        }
    }

    pub fn reader(&self) -> &GitHistoryReader {
        &self.reader
    }
}

impl crate::provider::GitHistoryProvider for GitHistoryReaderProvider {
    fn status(&self) -> Result<ClientGitStatus, ProviderError> {
        Ok(status_from_summary(self.reader.summary()))
    }

    fn commits(
        &self,
        query: &ValidatedGitCommitQuery,
    ) -> Result<ClientGitCommitPage, ProviderError> {
        let page = self
            .reader
            .commits(query.after.as_deref(), query.limit, &query.filter)
            .map_err(map_history_err)?;
        let mut by_sha = checkpoints_by_sha(self.reader.checkpoints(None).items);
        let items = page
            .items
            .into_iter()
            .map(|c| {
                let checkpoints = by_sha.remove(&c.sha).unwrap_or_default();
                ClientGitCommitEntry {
                    sha: c.sha,
                    committed_at_ms: c.committed_at_ms,
                    commit_type: commit_type_token(c.commit_type),
                    initiator: c.initiator,
                    subject: c.subject,
                    affected_paths_count: c.affected_paths_count,
                    checkpoints: checkpoints.into_iter().map(checkpoint_dto).collect(),
                }
            })
            .collect();
        Ok(ClientGitCommitPage {
            items,
            next_cursor: page.next_after.as_deref().map(encode_cursor),
        })
    }

    fn checkpoints(
        &self,
        agent_id: Option<&str>,
    ) -> Result<ClientGitCheckpointList, ProviderError> {
        let list = self.reader.checkpoints(agent_id);
        Ok(ClientGitCheckpointList {
            items: list.items.into_iter().map(checkpoint_dto).collect(),
        })
    }

    fn file_history(&self, path: &str) -> Result<ClientGitFileHistory, ProviderError> {
        let history = self.reader.file_history(path).map_err(map_history_err)?;
        Ok(ClientGitFileHistory {
            items: history
                .items
                .into_iter()
                .map(|v| ClientGitFileVersion {
                    sha: v.sha,
                    committed_at_ms: v.committed_at_ms,
                    commit_type: commit_type_token(v.commit_type),
                    initiator: v.initiator,
                    subject: v.subject,
                    deleted: v.deleted,
                })
                .collect(),
            truncated: history.truncated,
        })
    }

    fn file_at(&self, path: &str, sha: &str) -> Result<ClientGitFileAt, ProviderError> {
        let at = self
            .reader
            .read_file_at(path, sha)
            .map_err(map_history_err)?;
        Ok(ClientGitFileAt {
            sha: at.sha,
            path: path.to_string(),
            size: at.bytes.len() as u64,
            content_base64: {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&at.bytes)
            },
        })
    }

    fn create_checkpoint(
        &self,
        request: &ClientGitCreateCheckpointRequest,
    ) -> Result<ClientGitCheckpointEntry, ProviderError> {
        let named = DefaultNamedCheckpoint::new(self.reader.workspace().to_path_buf())
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;
        let paths = request
            .paths
            .as_ref()
            .map(|ps| ps.iter().map(PathBuf::from).collect());
        named
            .create(&request.agent_id, &request.label, paths)
            .map_err(|e| match e {
                advance_git::CheckpointError::Conflict { .. } => {
                    ProviderError::AlreadyExists("checkpoint".into())
                }
                advance_git::CheckpointError::InvalidLabel { .. }
                | advance_git::CheckpointError::InvalidPath { .. } => {
                    ProviderError::InvalidRequest("checkpoint".into())
                }
                other => ProviderError::Unavailable(other.to_string()),
            })?;
        self.checkpoints(Some(&request.agent_id))?
            .items
            .into_iter()
            .find(|c| c.label == request.label)
            .ok_or_else(|| ProviderError::Unavailable("checkpoint missing after create".into()))
    }

    fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
    ) -> Result<ClientGitRollbackResult, ProviderError> {
        let rollback = DefaultWorkspaceRollback::new(self.reader.workspace().to_path_buf())
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| ProviderError::Unavailable("no async runtime".into()))?;
        let paths = handle
            .block_on(rollback.rollback_to_checkpoint(agent_id, label))
            .map_err(|e| match e {
                advance_git::RollbackError::NotFound { .. } => {
                    ProviderError::NotFound("checkpoint".into())
                }
                advance_git::RollbackError::PermissionDenied { .. } => {
                    ProviderError::Forbidden("rollback".into())
                }
                other => ProviderError::Unavailable(other.to_string()),
            })?;
        Ok(ClientGitRollbackResult {
            agent_id: agent_id.to_string(),
            label: label.to_string(),
            restored_path_count: u32::try_from(paths.len()).unwrap_or(u32::MAX),
        })
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────────────────────

/// Register the git routes. Routes are always registered; an absent provider is
/// `module_unavailable` (never `unknown_route`).
pub(crate) fn register(api: &mut ClientApi, slot: GitProviderSlot) {
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_GIT_STATUS,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let status = provider
                .status()
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(status).expect("ClientGitStatus serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_GIT_COMMITS,
        HandlerSpec::read(true, move |ctx| {
            let query = validate_commit_query(&ctx.body)?;
            let provider = provider_or_unavailable(&s)?;
            let page = provider
                .commits(&query)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(page).expect("ClientGitCommitPage serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_GIT_CHECKPOINTS,
        HandlerSpec::read(true, move |ctx| {
            let agent_id = match query_string_field(&ctx.body, "agent_id")? {
                None => None,
                Some(id) => {
                    validate_agent_id(id)?;
                    Some(id.to_string())
                }
            };
            let provider = provider_or_unavailable(&s)?;
            let list = provider
                .checkpoints(agent_id.as_deref())
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(list).expect("ClientGitCheckpointList serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_GIT_FILE_HISTORY,
        HandlerSpec::read(true, move |ctx| {
            let path = require_path(&ctx.body)?;
            let provider = provider_or_unavailable(&s)?;
            let history = provider
                .file_history(path)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(history).expect("ClientGitFileHistory serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_GIT_FILE_AT,
        HandlerSpec::read(true, move |ctx| {
            let path = require_path(&ctx.body)?;
            let sha =
                query_string_field(&ctx.body, "sha")?.ok_or_else(|| invalid("invalid sha"))?;
            if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(invalid("invalid sha"));
            }
            let provider = provider_or_unavailable(&s)?;
            let at = provider
                .file_at(path, sha)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(at).expect("ClientGitFileAt serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_GIT_CHECKPOINT_CREATE,
        HandlerSpec::mutation(true, move |ctx| {
            let req = parse_create_request(&ctx.body)?;
            mark_provider_entry(ctx)?;
            let provider = provider_or_unavailable(&s)?;
            let created = provider
                .create_checkpoint(&req)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(created).expect("ClientGitCheckpointEntry serializes"))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    let s = slot;
    api.register_templated(
        Method::Post,
        routes::TPL_GIT_CHECKPOINT_ROLLBACK,
        HandlerSpec::mutation(true, move |ctx| {
            let agent_id = ctx.path_param("agent_id")?;
            let label = ctx.path_param("label")?;
            validate_agent_id(&agent_id)?;
            validate_checkpoint_label(&label)?;
            mark_provider_entry(ctx)?;
            let provider = provider_or_unavailable(&s)?;
            let result = provider
                .rollback_to_checkpoint(&agent_id, &label)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(result).expect("ClientGitRollbackResult serializes"))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );
}

/// Re-export the page-size cap so schema / tests can name it without importing advance-git.
pub const GIT_PAGE_LIMIT: usize = MAX_PAGE_LIMIT;
pub const GIT_DEFAULT_PAGE_LIMIT: usize = DEFAULT_PAGE_LIMIT;
pub const GIT_MAX_BLOB_BYTES: usize = MAX_BLOB_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_query_defaults_and_clamps() {
        let q = validate_commit_query(&Value::Null).unwrap();
        assert_eq!(q.limit, DEFAULT_PAGE_LIMIT);
        assert!(q.after.is_none());
        let q = validate_commit_query(&serde_json::json!({"limit": 9999})).unwrap();
        assert_eq!(q.limit, MAX_PAGE_LIMIT);
        let q = validate_commit_query(&serde_json::json!({
            "commit_type": "turn",
            "agent_id": "alice"
        }))
        .unwrap();
        assert_eq!(q.filter.commit_type, Some(CommitType::Turn));
        assert_eq!(q.filter.agent_id.as_deref(), Some("alice"));
        assert!(validate_commit_query(&serde_json::json!({"commit_type": "fix"})).is_err());
    }

    #[test]
    fn cursor_round_trips_a_sha() {
        let sha = "a".repeat(40);
        let token = encode_cursor(&sha);
        assert_eq!(decode_cursor(&token).unwrap(), sha);
        assert!(decode_cursor("not-a-cursor").is_err());
    }

    #[test]
    fn checkpoint_label_grammar() {
        assert!(validate_checkpoint_label("pre-turn").is_ok());
        for bad in ["", "has/slash", "..", "a..b", "bad label", "/abs"] {
            assert!(validate_checkpoint_label(bad).is_err(), "{bad:?}");
        }
    }
}
