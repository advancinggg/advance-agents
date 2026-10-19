//! CONTRACT-190 git family — status / commits / checkpoints / file history /
//! create / rollback.
//!
//! Drives `ClientApi::handle()` against a recording in-memory `GitHistoryProvider`
//! (same posture as `packs.rs`). Honesty cases (`missing` / `not_main` /
//! `valid=false` / lightweight) are envelope-level: the provider returns the
//! status the reader would, and the handler answers 200.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::{EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS};
use advance_client_api::git::{
    ClientGitCheckpointEntry, ClientGitCheckpointList, ClientGitCommitEntry, ClientGitCommitPage,
    ClientGitCreateCheckpointRequest, ClientGitFileAt, ClientGitFileHistory, ClientGitFileVersion,
    ClientGitRollbackResult, ClientGitStatus, ValidatedGitCommitQuery,
};
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientEnvelope, ClientErrorCode, ClientRequest, ClientSession,
    GitHistoryProvider, Platform, Principal, ProviderError, Scope,
};

// ── Recording in-memory provider ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Calls {
    status: AtomicUsize,
    commits: AtomicUsize,
    checkpoints: AtomicUsize,
    file_history: AtomicUsize,
    file_at: AtomicUsize,
    create: AtomicUsize,
    rollback: AtomicUsize,
}

struct MemoryGit {
    calls: Calls,
    status: Mutex<ClientGitStatus>,
    commits: Mutex<Vec<ClientGitCommitEntry>>,
    checkpoints: Mutex<Vec<ClientGitCheckpointEntry>>,
    file_history: Mutex<ClientGitFileHistory>,
    file_at: Mutex<Option<ClientGitFileAt>>,
    fail: Option<ProviderError>,
}

fn ready_status() -> ClientGitStatus {
    ClientGitStatus {
        repo: "ready".into(),
        branch: "main".into(),
        head_sha: Some("a".repeat(40)),
        commit_count: Some(1),
        checkpoint_count: Some(1),
        observed_ref: None,
        reason: None,
    }
}

fn sample_label() -> advance_client_api::ClientGitCommitLabel {
    advance_client_api::ClientGitCommitLabel {
        op: "edit".into(),
        paths: vec!["a.md".into()],
        to: None,
        count: 1,
        lines_added: Some(1),
        lines_removed: Some(0),
        size_bytes: Some(4),
        versioned: Some(true),
        from_sha: None,
        checkpoint: None,
        title: Some("wire title".into()),
        change: Some("modified".into()),
    }
}

fn commit_entry() -> ClientGitCommitEntry {
    ClientGitCommitEntry {
        sha: "a".repeat(40),
        committed_at_ms: 1_700_000_000_000,
        commit_type: Some("turn".into()),
        initiator: Some("agent:alice".into()),
        subject: "write a.md".into(),
        affected_paths_count: 1,
        checkpoints: vec![checkpoint("alice", "snap", true, None)],
        label: Some(sample_label()),
    }
}

fn user_commit_entry() -> ClientGitCommitEntry {
    ClientGitCommitEntry {
        sha: "b".repeat(40),
        committed_at_ms: 1_700_000_000_100,
        commit_type: Some("user".into()),
        initiator: Some("user:advance".into()),
        subject: "save a.md".into(),
        affected_paths_count: 1,
        checkpoints: vec![],
        label: Some(sample_label()),
    }
}

fn checkpoint(
    agent: &str,
    label: &str,
    valid: bool,
    paths: Option<Vec<String>>,
) -> ClientGitCheckpointEntry {
    ClientGitCheckpointEntry {
        agent_id: agent.into(),
        label: label.into(),
        sha: "a".repeat(40),
        tagged_at_ms: 1_700_000_000_000,
        paths,
        valid,
        title: Some("saved version".into()),
    }
}

impl MemoryGit {
    fn ready() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            status: Mutex::new(ready_status()),
            commits: Mutex::new(vec![commit_entry(), user_commit_entry()]),
            checkpoints: Mutex::new(vec![checkpoint("alice", "snap", true, None)]),
            file_history: Mutex::new(ClientGitFileHistory {
                items: vec![ClientGitFileVersion {
                    sha: "a".repeat(40),
                    committed_at_ms: 1_700_000_000_000,
                    commit_type: Some("turn".into()),
                    initiator: Some("agent:alice".into()),
                    subject: "write a.md".into(),
                    deleted: false,
                    label: None,
                }],
                truncated: false,
            }),
            file_at: Mutex::new(Some(ClientGitFileAt {
                sha: "a".repeat(40),
                path: "a.md".into(),
                size: 4,
                content_base64: "aGVsbA==".into(),
            })),
            fail: None,
        })
    }

    fn with_status(status: ClientGitStatus) -> Arc<Self> {
        let git = Self::ready();
        *git.status.lock().unwrap() = status;
        git.commits.lock().unwrap().clear();
        git.checkpoints.lock().unwrap().clear();
        git
    }

    fn gate(&self) -> Result<(), ProviderError> {
        match &self.fail {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

impl GitHistoryProvider for MemoryGit {
    fn status(&self) -> Result<ClientGitStatus, ProviderError> {
        self.calls.status.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        Ok(self.status.lock().unwrap().clone())
    }
    fn commits(
        &self,
        query: &ValidatedGitCommitQuery,
    ) -> Result<ClientGitCommitPage, ProviderError> {
        self.calls.commits.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let mut items = self.commits.lock().unwrap().clone();
        if let Some(initiator) = &query.filter.initiator {
            items.retain(|c| c.initiator.as_deref() == Some(initiator.as_str()));
        }
        Ok(ClientGitCommitPage {
            items,
            next_cursor: None,
        })
    }
    fn checkpoints(
        &self,
        agent_id: Option<&str>,
    ) -> Result<ClientGitCheckpointList, ProviderError> {
        self.calls.checkpoints.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        let mut items = self.checkpoints.lock().unwrap().clone();
        if let Some(id) = agent_id {
            items.retain(|c| c.agent_id == id);
        }
        Ok(ClientGitCheckpointList { items })
    }
    fn file_history(&self, _path: &str) -> Result<ClientGitFileHistory, ProviderError> {
        self.calls.file_history.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        Ok(self.file_history.lock().unwrap().clone())
    }
    fn file_at(&self, _path: &str, _sha: &str) -> Result<ClientGitFileAt, ProviderError> {
        self.calls.file_at.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        self.file_at
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| ProviderError::NotFound("path".into()))
    }
    fn create_checkpoint(
        &self,
        request: &ClientGitCreateCheckpointRequest,
    ) -> Result<ClientGitCheckpointEntry, ProviderError> {
        self.calls.create.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        Ok(checkpoint(
            &request.agent_id,
            &request.label,
            true,
            request.paths.clone(),
        ))
    }
    fn rollback_to_checkpoint(
        &self,
        agent_id: &str,
        label: &str,
        _principal: &Principal,
    ) -> Result<ClientGitRollbackResult, ProviderError> {
        self.calls.rollback.fetch_add(1, Ordering::SeqCst);
        self.gate()?;
        Ok(ClientGitRollbackResult {
            agent_id: agent_id.into(),
            label: label.into(),
            restored_path_count: 1,
            commit_sha: Some("b".repeat(40)),
        })
    }
}

// ── Harness ──────────────────────────────────────────────────────────────────────────────────

fn api_with(provider: Arc<dyn GitHistoryProvider>) -> (ClientApi, RecordingSink) {
    let sink = RecordingSink::new();
    let api = ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink.clone()),
    )
    .with_git_provider(provider);
    (api, sink)
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: format!("sess-{token}"),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes,
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

fn operator(api: &ClientApi) {
    mint(api, "tok", Scope::operator_default());
}

fn get(path: &str) -> ClientRequest {
    ClientRequest::get(path).with_session("tok")
}

fn get_query(path: &str, body: Value) -> ClientRequest {
    let mut req = get(path);
    req.body = body;
    req
}

fn post(path: &str, body: Value, key: &str) -> ClientRequest {
    ClientRequest::post(path, body)
        .with_session("tok")
        .with_idempotency_key(key)
}

fn code(env: &ClientEnvelope<Value>) -> Option<ClientErrorCode> {
    env.error_code()
}

fn data<T: serde::de::DeserializeOwned>(env: &ClientEnvelope<Value>) -> T {
    assert!(env.is_ok(), "expected ok envelope, got {:?}", env.error);
    serde_json::from_value(env.data.clone().unwrap()).expect("payload parses")
}

// ── Never-attached ───────────────────────────────────────────────────────────────────────────

#[test]
fn git_absent_provider_is_module_unavailable_not_unknown_route() {
    let api = ClientApi::new(ClientApiConfig::default());
    operator(&api);
    for req in [
        get(routes::PATH_GIT_STATUS),
        get(routes::PATH_GIT_COMMITS),
        get(routes::PATH_GIT_CHECKPOINTS),
        get_query(routes::PATH_GIT_FILE_HISTORY, json!({"path": "a.md"})),
        get_query(
            routes::PATH_GIT_FILE_AT,
            json!({"path": "a.md", "sha": "a".repeat(40)}),
        ),
        post(
            routes::PATH_GIT_CHECKPOINT_CREATE,
            json!({"agent_id": "alice", "label": "snap"}),
            "k1",
        ),
        post(
            "/client/git/checkpoints/alice/snap:rollback",
            json!({}),
            "k2",
        ),
    ] {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{:?}",
            env.error
        );
    }
}

// ── Success samples ──────────────────────────────────────────────────────────────────────────

#[test]
fn git_status_ready() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    let status: ClientGitStatus = data(&api.handle(get(routes::PATH_GIT_STATUS)));
    assert_eq!(status.repo, "ready");
    assert_eq!(status.branch, "main");
    assert_eq!(status.head_sha.as_deref(), Some("a".repeat(40).as_str()));
    assert_eq!(status.commit_count, Some(1));
}

#[test]
fn git_commits_ready_inlines_checkpoints() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    let page: ClientGitCommitPage = data(&api.handle(get(routes::PATH_GIT_COMMITS)));
    assert_eq!(page.items.len(), 2);
    let turn = page
        .items
        .iter()
        .find(|c| c.initiator.as_deref() == Some("agent:alice"))
        .expect("turn commit");
    assert_eq!(turn.commit_type.as_deref(), Some("turn"));
    assert_eq!(turn.checkpoints.len(), 1);
    assert_eq!(turn.checkpoints[0].label, "snap");
    assert!(page.next_cursor.is_none());
}

#[test]
fn git_checkpoints_ready() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    let list: ClientGitCheckpointList = data(&api.handle(get(routes::PATH_GIT_CHECKPOINTS)));
    assert_eq!(list.items.len(), 1);
    assert!(list.items[0].valid);
    assert!(list.items[0].paths.is_none());
}

// ── Honesty: missing / not_main / valid=false / lightweight ──────────────────────────────────

#[test]
fn git_status_missing_is_200() {
    let (api, _) = api_with(MemoryGit::with_status(ClientGitStatus {
        repo: "missing".into(),
        branch: "main".into(),
        head_sha: None,
        commit_count: None,
        checkpoint_count: None,
        observed_ref: None,
        reason: None,
    }));
    operator(&api);
    let status: ClientGitStatus = data(&api.handle(get(routes::PATH_GIT_STATUS)));
    assert_eq!(status.repo, "missing");
    assert!(status.head_sha.is_none());
    let page: ClientGitCommitPage = data(&api.handle(get(routes::PATH_GIT_COMMITS)));
    assert!(page.items.is_empty());
}

#[test]
fn git_status_not_main_is_200() {
    let (api, _) = api_with(MemoryGit::with_status(ClientGitStatus {
        repo: "not_main".into(),
        branch: "main".into(),
        head_sha: Some("b".repeat(40)),
        commit_count: Some(1),
        checkpoint_count: Some(0),
        observed_ref: Some("refs/heads/other".into()),
        reason: None,
    }));
    operator(&api);
    let status: ClientGitStatus = data(&api.handle(get(routes::PATH_GIT_STATUS)));
    assert_eq!(status.repo, "not_main");
    assert_eq!(status.observed_ref.as_deref(), Some("refs/heads/other"));
}

#[test]
fn git_checkpoint_valid_false_is_listed() {
    let git = MemoryGit::ready();
    git.checkpoints
        .lock()
        .unwrap()
        .push(checkpoint("alice", "corrupt", false, None));
    let (api, _) = api_with(git);
    operator(&api);
    let list: ClientGitCheckpointList = data(&api.handle(get(routes::PATH_GIT_CHECKPOINTS)));
    let corrupt = list.items.iter().find(|c| c.label == "corrupt").unwrap();
    assert!(!corrupt.valid);
    assert!(corrupt.paths.is_none());
}

#[test]
fn git_lightweight_tag_is_full_directory() {
    // Lightweight tags are listed as valid + paths=null (`{}`).
    let git = MemoryGit::ready();
    git.checkpoints
        .lock()
        .unwrap()
        .push(checkpoint("bob", "lite", true, None));
    let (api, _) = api_with(git);
    operator(&api);
    let list: ClientGitCheckpointList = data(&api.handle(get_query(
        routes::PATH_GIT_CHECKPOINTS,
        json!({"agent_id": "bob"}),
    )));
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].label, "lite");
    assert!(list.items[0].valid);
    assert!(list.items[0].paths.is_none());
}

// ── File history + writes ────────────────────────────────────────────────────────────────────

#[test]
fn git_file_history_and_content() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    let history: ClientGitFileHistory = data(&api.handle(get_query(
        routes::PATH_GIT_FILE_HISTORY,
        json!({"path": "a.md"}),
    )));
    assert_eq!(history.items.len(), 1);
    assert!(!history.items[0].deleted);
    let at: ClientGitFileAt = data(&api.handle(get_query(
        routes::PATH_GIT_FILE_AT,
        json!({"path": "a.md", "sha": "a".repeat(40)}),
    )));
    assert_eq!(at.size, 4);
}

#[test]
fn git_file_path_refusals() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    for path in [
        ".git/config",
        ".agent/memory/k.jsonl",
        "../x",
        "/etc/passwd",
    ] {
        let env = api.handle(get_query(
            routes::PATH_GIT_FILE_HISTORY,
            json!({ "path": path }),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{path}");
    }
}

#[test]
fn git_create_and_rollback() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    let created: ClientGitCheckpointEntry = data(&api.handle(post(
        routes::PATH_GIT_CHECKPOINT_CREATE,
        json!({"agent_id": "alice", "label": "pre-turn"}),
        "create-1",
    )));
    assert_eq!(created.label, "pre-turn");
    let rolled: ClientGitRollbackResult = data(&api.handle(post(
        "/client/git/checkpoints/alice/pre-turn:rollback",
        json!({}),
        "rollback-1",
    )));
    assert_eq!(rolled.restored_path_count, 1);
}

#[test]
fn git_write_requires_approve_grants() {
    let (api, _) = api_with(MemoryGit::ready());
    mint(&api, "tok", vec![Scope::ReadInventory]);
    let env = api.handle(post(
        routes::PATH_GIT_CHECKPOINT_CREATE,
        json!({"agent_id": "alice", "label": "x"}),
        "k",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
}

#[test]
fn git_reads_require_inventory_scope() {
    let (api, _) = api_with(MemoryGit::ready());
    mint(&api, "ro", vec![Scope::ReadRuns]);
    let env = api.handle(ClientRequest::get(routes::PATH_GIT_STATUS).with_session("ro"));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
}

#[test]
fn git_health_inlines_status_when_wired() {
    let (api, _) = api_with(MemoryGit::ready());
    let env = api.handle(ClientRequest::get(routes::PATH_HEALTH));
    assert!(env.is_ok());
    let git = env.data.unwrap()["git"].clone();
    assert_eq!(git["repo"], "ready");
}

#[test]
fn git_path_cap_raised_to_1024() {
    let git = MemoryGit::ready();
    let (api, _) = api_with(git.clone());
    operator(&api);
    let ok = vec!["n".repeat(204); 5].join("/");
    assert_eq!(ok.len(), 1024);
    let env = api.handle(get_query(
        routes::PATH_GIT_FILE_HISTORY,
        json!({ "path": ok }),
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(git.calls.file_history.load(Ordering::SeqCst), 1);
    let too_long = format!("{ok}x");
    assert_eq!(too_long.len(), 1025);
    let env = api.handle(get_query(
        routes::PATH_GIT_FILE_HISTORY,
        json!({ "path": too_long }),
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(git.calls.file_history.load(Ordering::SeqCst), 1);
}

#[test]
fn git_reserved_namespace_is_invalid_request() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    for id in ["user", "User"] {
        let env = api.handle(post(
            routes::PATH_GIT_CHECKPOINT_CREATE,
            json!({"agent_id": id, "label": "snap"}),
            &format!("create-{id}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{id}");
        assert_eq!(
            env.error.as_ref().unwrap().details,
            vec!["reserved_namespace".to_string()],
            "{id}"
        );
        let env = api.handle(post(
            &format!("/client/git/checkpoints/{id}/snap:rollback"),
            json!({}),
            &format!("rb-{id}"),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{id}");
        assert_eq!(
            env.error.as_ref().unwrap().details,
            vec!["reserved_namespace".to_string()],
            "{id}"
        );
    }
}

#[test]
fn git_commits_accept_initiator_and_user_type() {
    let (api, _) = api_with(MemoryGit::ready());
    operator(&api);
    let env = api.handle(get_query(
        routes::PATH_GIT_COMMITS,
        json!({ "initiator": "user:advance", "commit_type": "user" }),
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    let items = env.data.as_ref().unwrap()["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["initiator"], "user:advance");
    assert_eq!(items[0]["label"]["title"], "wire title");
    assert_eq!(items[0]["label"]["change"], "modified");
    let env = api.handle(ClientRequest::get(routes::PATH_GIT_CHECKPOINTS).with_session("tok"));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(
        env.data.as_ref().unwrap()["items"][0]["title"],
        "saved version"
    );
    let env = api.handle(post(
        "/client/git/checkpoints/alice/snap:rollback",
        json!({}),
        "rb-sha",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(env.data.as_ref().unwrap()["commit_sha"], "b".repeat(40));
    for bad in ["bad id", "x:", "other:ok"] {
        let env = api.handle(get_query(
            routes::PATH_GIT_COMMITS,
            json!({ "initiator": bad }),
        ));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{bad}");
    }
}

#[test]
fn git_schema_components_inventoried() {
    let art = generate_schema_artifact();
    let components = art.schema["components"]
        .as_object()
        .expect("components object");
    for r in [
        "ClientGitStatus",
        "ClientGitCheckpointEntry",
        "ClientGitCommitEntry",
        "ClientGitCommitPage",
        "ClientGitCheckpointList",
        "ClientGitFileHistory",
        "ClientGitFileAt",
        "ClientGitRollbackResult",
    ] {
        assert!(components.contains_key(r), "{r} in schema");
        assert!(RESPONSE_COMPONENTS.contains(&r), "{r} inventoried");
    }
    assert!(components.contains_key("ClientGitCreateCheckpointRequest"));
    assert!(EXCLUDED_COMPONENTS.contains(&"ClientGitCreateCheckpointRequest"));
}
