//! CONTRACT-246 files family — JSON routes, DTOs, path gate, and provider port.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::compat::{EXCLUDED_COMPONENTS, RESPONSE_COMPONENTS};
use advance_client_api::files::detail::{
    CapacityKind, FilesFailure, Oid40, VcsUnavailableReason, REGISTRY,
};
use advance_client_api::files::{
    ClientFileList, ClientFileMutationResult, ClientFileSearchResult, ClientFileStat,
    ClientFileTicket, ClientFileVersionResult, ClientFileWriteResult, FileReadSource,
    FileReadVersion, FileUploadHandle, FileUploadSink, FileWriteTarget, FilesActor,
    FilesCommitBatch, FilesCopyItem, FilesDelete, FilesExternalItem, FilesListPage, FilesListQuery,
    FilesMkdir, FilesMoveItem, FilesPath, FilesReadQuery, FilesRestore, FilesSaveVersion,
    FilesSearchQuery, FilesStatQuery, PathUse, WriteCheck, FILES_MAX_PAGE_LIMIT,
    MAX_FILES_PATH_BYTES,
};
use advance_client_api::git::{
    ClientGitCheckpointEntry, ClientGitCheckpointList, ClientGitCommitPage, ClientGitFileAt,
    ClientGitFileHistory, ClientGitRollbackResult, ClientGitStatus, ValidatedGitCommitQuery,
    MAX_GIT_PATH_LEN,
};
use advance_client_api::routes;
use advance_client_api::schema::generate_schema_artifact;
use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientCursorCodec, ClientEnvelope,
    ClientErrorCode, ClientRequest, ClientSession, FilesProvider, GitHistoryProvider,
    MemoryCursorKeyCustody, OsCursorEntropy, Platform, Principal, ProviderError, Scope,
    SystemCursorClock,
};
use advance_shared_types::file_identity::FileIdentity;
use advance_shared_types::workspace_path::{PathDefect, ReadOnlyReason};
use serde_json::{json, Value};

const OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Default)]
struct Calls {
    list: AtomicUsize,
    stat: AtomicUsize,
    search: AtomicUsize,
    prepare_read: AtomicUsize,
    mkdir: AtomicUsize,
    copy: AtomicUsize,
    commit_batch: AtomicUsize,
}

struct Last {
    paths: Vec<String>,
    actor: Option<FilesActor>,
    limit: Option<usize>,
    query: Option<String>,
    folders_first: Option<bool>,
    sort: Option<String>,
    order: Option<String>,
    dotfiles: Option<bool>,
    base_oid: Option<String>,
    batch: Option<String>,
}

struct MemoryFiles {
    calls: Calls,
    last: Mutex<Last>,
    fail: Mutex<Option<ProviderError>>,
    list_cursor_stale: bool,
    write: Mutex<WriteMode>,
    copy_ok: bool,
}

enum WriteMode {
    Ok,
    AlreadyCurrent,
    StaleBase,
}

impl Default for Last {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            actor: None,
            limit: None,
            query: None,
            folders_first: None,
            sort: None,
            order: None,
            dotfiles: None,
            base_oid: None,
            batch: None,
        }
    }
}

fn identity(size: u64) -> FileIdentity {
    FileIdentity {
        dev: 1,
        ino: 2,
        size,
        mtime_ns: 0,
    }
}

fn empty_list(path: &str) -> ClientFileList {
    ClientFileList {
        path: path.to_string(),
        entries: Vec::new(),
        total: 0,
        next_cursor: None,
        truncated: false,
        skipped: 0,
        vcs: "unknown".into(),
    }
}

fn empty_mutation() -> ClientFileMutationResult {
    ClientFileMutationResult {
        changes: Vec::new(),
        changes_total: 0,
        commit_state: "committed".into(),
        commit: None,
    }
}

fn sample_entry(path: &str) -> advance_client_api::ClientFileEntry {
    advance_client_api::ClientFileEntry {
        name: path.rsplit('/').next().unwrap_or(path).into(),
        path: path.into(),
        kind: "file".into(),
        size: Some(4),
        modified_at_ms: None,
        oid: Some(OID.into()),
        vcs: Some("unknown".into()),
        content_type: Some("text/plain".into()),
        read_only: false,
        read_only_reason: None,
        territory_root: false,
        dotfile: false,
        package: false,
        description: None,
    }
}

impl MemoryFiles {
    fn ready() -> Arc<Self> {
        Arc::new(Self {
            calls: Calls::default(),
            last: Mutex::new(Last::default()),
            fail: Mutex::new(None),
            list_cursor_stale: false,
            write: Mutex::new(WriteMode::Ok),
            copy_ok: false,
        })
    }

    fn record(&self, path: &str, actor: Option<&FilesActor>) {
        let mut last = self.last.lock().unwrap();
        last.paths.push(path.to_string());
        if let Some(a) = actor {
            last.actor = Some(a.clone());
        }
    }

    fn gate(&self) -> Result<(), ProviderError> {
        match self.fail.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl FilesProvider for MemoryFiles {
    fn list(&self, q: &FilesListQuery) -> Result<FilesListPage, ProviderError> {
        self.calls.list.fetch_add(1, Ordering::SeqCst);
        self.record(q.path.as_str(), None);
        self.last.lock().unwrap().limit = Some(q.limit);
        self.last.lock().unwrap().folders_first = Some(q.folders_first);
        self.last.lock().unwrap().sort = Some(q.sort.as_str().to_string());
        self.last.lock().unwrap().order = Some(q.order.as_str().to_string());
        self.gate()?;
        if self.list_cursor_stale {
            return Err(ProviderError::Files(FilesFailure::CursorStale));
        }
        Ok(FilesListPage {
            list: empty_list(q.path.as_str()),
        })
    }
    fn stat(&self, q: &FilesStatQuery) -> Result<ClientFileStat, ProviderError> {
        self.calls.stat.fetch_add(1, Ordering::SeqCst);
        self.record(q.path.as_str(), None);
        self.gate()?;
        Ok(ClientFileStat {
            entry: sample_entry(q.path.as_str()),
            head_oid: None,
            versioned: Some(true),
            versioned_reason: None,
        })
    }
    fn search(&self, q: &FilesSearchQuery) -> Result<ClientFileSearchResult, ProviderError> {
        self.calls.search.fetch_add(1, Ordering::SeqCst);
        self.record(q.path.as_str(), None);
        self.last.lock().unwrap().query = Some(q.query.clone());
        self.last.lock().unwrap().limit = Some(q.limit);
        self.last.lock().unwrap().dotfiles = Some(q.dotfiles);
        self.gate()?;
        Ok(ClientFileSearchResult {
            query: q.query.clone(),
            path: q.path.as_str().to_string(),
            items: Vec::new(),
            truncated: false,
            visited: 0,
        })
    }
    fn prepare_read(&self, q: &FilesReadQuery) -> Result<FileReadVersion, ProviderError> {
        self.calls.prepare_read.fetch_add(1, Ordering::SeqCst);
        self.record(q.path.as_str(), None);
        self.gate()?;
        let large = q.path.as_str().contains("large-unstable");
        Ok(FileReadVersion {
            path: q.path.as_str().to_string(),
            size: if large { 20 * 1024 * 1024 } else { 4 },
            content_type: "text/plain".into(),
            oid: if large {
                None
            } else {
                Some(Oid40::parse(OID).unwrap())
            },
            identity: Some(identity(if large { 20 * 1024 * 1024 } else { 4 })),
            rev: q.rev.clone(),
            already_current: false,
        })
    }
    fn open_read(
        &self,
        path: &FilesPath,
        _v: &FileReadVersion,
    ) -> Result<FileReadSource, ProviderError> {
        Ok(FileReadSource::Bytes(
            format!("ok:{}", path.as_str()).into_bytes(),
        ))
    }
    fn check_write(
        &self,
        actor: &FilesActor,
        t: &FileWriteTarget,
    ) -> Result<WriteCheck, ProviderError> {
        self.record(t.path.as_str(), Some(actor));
        self.last.lock().unwrap().batch = t.batch.clone();
        self.gate()?;
        match *self.write.lock().unwrap() {
            WriteMode::StaleBase => Err(ProviderError::Files(FilesFailure::StaleBase {
                current_oid: Some(Oid40::parse(OID).unwrap()),
                item: None,
            })),
            WriteMode::AlreadyCurrent => Ok(WriteCheck::AlreadyCurrent {
                oid: t.oid.clone(),
                size: t.size,
                content_type: "text/plain".into(),
                etag: t.oid.as_str().to_string(),
                identity: Some(identity(t.size)),
            }),
            WriteMode::Ok => Ok(WriteCheck::Ok {
                etag: t.oid.as_str().to_string(),
                oid: t.oid.clone(),
                size: t.size,
                content_type: "text/plain".into(),
                identity: Some(identity(t.size)),
            }),
        }
    }
    fn begin_upload(
        &self,
        _actor: &FilesActor,
        _t: &FileWriteTarget,
    ) -> Result<FileUploadSink, ProviderError> {
        Ok(FileUploadSink::memory("up-1").0)
    }
    fn finish_upload(
        &self,
        _actor: &FilesActor,
        t: &FileWriteTarget,
        _h: FileUploadHandle,
    ) -> Result<ClientFileWriteResult, ProviderError> {
        Ok(ClientFileWriteResult {
            path: t.path.as_str().to_string(),
            oid: t.oid.as_str().to_string(),
            size: t.size,
            versioned: true,
            versioned_reason: None,
            commit_state: if t.batch.is_some() {
                "staged".into()
            } else {
                "committed".into()
            },
            commit: None,
        })
    }
    fn abort_upload(&self, _h: FileUploadHandle) {}
    fn mkdir(
        &self,
        actor: &FilesActor,
        r: &FilesMkdir,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.calls.mkdir.fetch_add(1, Ordering::SeqCst);
        self.record(r.path.as_str(), Some(actor));
        self.gate()?;
        Ok(empty_mutation())
    }
    fn move_items(
        &self,
        actor: &FilesActor,
        items: &[FilesMoveItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
        if let Some(item) = items.first() {
            self.record(item.from.as_str(), Some(actor));
            self.last.lock().unwrap().base_oid =
                item.base_oid.as_ref().map(|o| o.as_str().to_string());
        }
        Ok(empty_mutation())
    }
    fn delete(
        &self,
        actor: &FilesActor,
        r: &FilesDelete,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        if let Some(item) = r.items.first() {
            self.record(item.path.as_str(), Some(actor));
            self.last.lock().unwrap().base_oid =
                item.base_oid.as_ref().map(|o| o.as_str().to_string());
        }
        Ok(empty_mutation())
    }
    fn restore(
        &self,
        actor: &FilesActor,
        r: &FilesRestore,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        if let Some(item) = r.items.first() {
            self.record(item.path.as_str(), Some(actor));
            self.last.lock().unwrap().base_oid =
                item.base_oid.as_ref().map(|o| o.as_str().to_string());
        }
        Ok(empty_mutation())
    }
    fn save_version(
        &self,
        actor: &FilesActor,
        r: &FilesSaveVersion,
    ) -> Result<ClientFileVersionResult, ProviderError> {
        self.record(r.title.as_str(), Some(actor));
        Ok(ClientFileVersionResult {
            tag: "user/v1".into(),
            version_label: "v1".into(),
            title: r.title.clone(),
            paths: None,
            commit: advance_client_api::files::ClientFileCommit {
                sha: OID.into(),
                parent_sha: None,
                subject: r.title.clone(),
                label: advance_client_api::ClientGitCommitLabel {
                    op: "save-version".into(),
                    paths: Vec::new(),
                    to: None,
                    count: 0,
                    lines_added: None,
                    lines_removed: None,
                    size_bytes: None,
                    versioned: None,
                    from_sha: None,
                    checkpoint: None,
                    title: Some(r.title.clone()),
                    change: None,
                },
                commit_type: "user".into(),
                initiator: format!("user:{}", actor.os_user),
                committed_at_ms: 1,
            },
            pending_before: false,
            adopt_incomplete: false,
            unversioned_count: 0,
        })
    }
    fn commit_external(
        &self,
        actor: &FilesActor,
        items: &[FilesExternalItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
        if let Some(item) = items.first() {
            self.record(item.path.as_str(), Some(actor));
        }
        Ok(empty_mutation())
    }
    fn copy_items(
        &self,
        actor: &FilesActor,
        items: &[FilesCopyItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.calls.copy.fetch_add(1, Ordering::SeqCst);
        if let Some(item) = items.first() {
            self.record(item.from.as_str(), Some(actor));
        }
        if !self.copy_ok {
            return Err(ProviderError::Unavailable("copy".into()));
        }
        Ok(empty_mutation())
    }
    fn commit_batch(
        &self,
        actor: &FilesActor,
        r: &FilesCommitBatch,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        self.calls.commit_batch.fetch_add(1, Ordering::SeqCst);
        self.record(&r.batch, Some(actor));
        self.last.lock().unwrap().batch = Some(r.batch.clone());
        self.gate()?;
        Ok(ClientFileMutationResult {
            changes: r
                .mkdirs
                .iter()
                .map(|p| advance_client_api::ClientFileChange {
                    path: p.as_str().to_string(),
                    kind: "dir".into(),
                    change: "added".into(),
                    from_path: None,
                    blob_oid: None,
                    size: None,
                    versioned: true,
                    versioned_reason: None,
                })
                .collect(),
            changes_total: r.mkdirs.len() as u64,
            commit_state: "committed".into(),
            commit: Some(advance_client_api::files::ClientFileCommit {
                sha: OID.into(),
                parent_sha: None,
                subject: "Upload 3 items → reports/ (S)".into(),
                label: advance_client_api::ClientGitCommitLabel {
                    op: "upload".into(),
                    paths: vec!["reports".into()],
                    to: None,
                    count: 3,
                    lines_added: None,
                    lines_removed: None,
                    size_bytes: None,
                    versioned: None,
                    from_sha: None,
                    checkpoint: None,
                    title: None,
                    change: None,
                },
                commit_type: "user".into(),
                initiator: format!("user:{}", actor.os_user),
                committed_at_ms: 1,
            }),
        })
    }
}

fn codec() -> Arc<dyn ClientCursorCodec> {
    Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_for_tests()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ))
}

fn api_bare() -> ClientApi {
    ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(RecordingSink::new()),
    )
    .with_cursor_codec(codec())
}

fn api_with(provider: Arc<dyn FilesProvider>) -> ClientApi {
    api_bare().with_files_provider(provider)
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

fn get_q(path: &str, body: Value) -> ClientRequest {
    let mut req = ClientRequest::get(path).with_session("tok");
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

fn details(env: &ClientEnvelope<Value>) -> Vec<String> {
    env.error
        .as_ref()
        .map(|e| e.details.clone())
        .unwrap_or_default()
}

fn json_routes() -> [(&'static str, ClientRequest); 13] {
    [
        (
            routes::PATH_FILES_ENTRIES,
            get_q(routes::PATH_FILES_ENTRIES, json!({"path": "notes"})),
        ),
        (
            routes::PATH_FILES_STAT,
            get_q(routes::PATH_FILES_STAT, json!({"path": "notes/a.md"})),
        ),
        (
            routes::PATH_FILES_SEARCH,
            get_q(routes::PATH_FILES_SEARCH, json!({"q": "a", "path": ""})),
        ),
        (
            routes::PATH_FILES_READ_TICKET,
            post(
                routes::PATH_FILES_READ_TICKET,
                json!({"path": "notes/a.md"}),
                "rt",
            ),
        ),
        (
            routes::PATH_FILES_WRITE_TICKET,
            post(
                routes::PATH_FILES_WRITE_TICKET,
                json!({"path": "notes/a.md", "intent": "edit", "base_oid": OID, "size": 4, "oid": OID}),
                "wt",
            ),
        ),
        (
            routes::PATH_FILES_MKDIR,
            post(routes::PATH_FILES_MKDIR, json!({"path": "notes/d"}), "mk"),
        ),
        (
            routes::PATH_FILES_MOVE,
            post(
                routes::PATH_FILES_MOVE,
                json!({"items": [{"from": "notes/a.md", "to": "notes/b.md"}]}),
                "mv",
            ),
        ),
        (
            routes::PATH_FILES_DELETE,
            post(
                routes::PATH_FILES_DELETE,
                json!({"items": [{"path": "notes/a.md"}]}),
                "del",
            ),
        ),
        (
            routes::PATH_FILES_RESTORE,
            post(
                routes::PATH_FILES_RESTORE,
                json!({"from_sha": OID, "items": [{"path": "notes/a.md"}]}),
                "rs",
            ),
        ),
        (
            routes::PATH_FILES_SAVE_VERSION,
            post(
                routes::PATH_FILES_SAVE_VERSION,
                json!({"title": "snap"}),
                "sv",
            ),
        ),
        (
            routes::PATH_FILES_COMMIT_EXTERNAL,
            post(
                routes::PATH_FILES_COMMIT_EXTERNAL,
                json!({"items": [{"path": "notes/a.md"}]}),
                "ce",
            ),
        ),
        (
            routes::PATH_FILES_COPY,
            post(
                routes::PATH_FILES_COPY,
                json!({"items": [{"from": "notes/a.md", "to": "notes/b.md"}]}),
                "cp",
            ),
        ),
        (
            routes::PATH_FILES_COMMIT_BATCH,
            post(
                routes::PATH_FILES_COMMIT_BATCH,
                json!({"batch": "abcdefghijklmnop", "mkdirs": ["reports"], "parents": true}),
                "cb",
            ),
        ),
    ]
}

#[test]
fn files_absent_provider_is_module_unavailable_on_every_route() {
    let api = api_bare();
    operator(&api);
    for (path, req) in json_routes() {
        let env = api.handle(req);
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::ModuleUnavailable),
            "{path} {:?}",
            env.error
        );
        assert_ne!(code(&env), Some(ClientErrorCode::UnknownRoute), "{path}");
    }
}

#[test]
fn files_absent_provider_stays_retryable() {
    let api = api_bare();
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": "notes/d"}),
        "K",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::ModuleUnavailable));
    let provider = MemoryFiles::ready();
    api.install_files_provider(provider.clone());
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": "notes/d"}),
        "K",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(provider.calls.mkdir.load(Ordering::SeqCst), 1);
    assert!(env.warnings.iter().all(|w| w.code != "idempotent_replay"));
}

#[test]
fn files_routes_have_the_documented_gates() {
    let table = ClientApi::new(ClientApiConfig::default()).route_table();
    let find = |path: &str| {
        table
            .iter()
            .find(|e| e.path == path)
            .unwrap_or_else(|| panic!("missing {path}"))
    };
    for path in [
        routes::PATH_FILES_ENTRIES,
        routes::PATH_FILES_STAT,
        routes::PATH_FILES_SEARCH,
    ] {
        let e = find(path);
        assert_eq!(e.method, advance_client_api::Method::Get);
        assert!(!e.templated);
        assert!(e.requires_session);
        assert!(!e.is_mutation);
        assert_eq!(e.required_scopes, vec![Scope::ReadInventory]);
    }
    let read_ticket = find(routes::PATH_FILES_READ_TICKET);
    assert_eq!(read_ticket.method, advance_client_api::Method::Post);
    assert!(read_ticket.requires_session);
    assert!(!read_ticket.is_mutation);
    assert_eq!(read_ticket.required_scopes, vec![Scope::ReadInventory]);
    let wt = find(routes::PATH_FILES_WRITE_TICKET);
    assert!(!wt.is_mutation);
    assert_eq!(wt.required_scopes, vec![Scope::WriteEntities]);
    for path in [
        routes::PATH_FILES_MKDIR,
        routes::PATH_FILES_MOVE,
        routes::PATH_FILES_DELETE,
        routes::PATH_FILES_RESTORE,
        routes::PATH_FILES_SAVE_VERSION,
        routes::PATH_FILES_COMMIT_EXTERNAL,
        routes::PATH_FILES_COPY,
        routes::PATH_FILES_COMMIT_BATCH,
    ] {
        let e = find(path);
        assert!(e.is_mutation);
        assert_eq!(e.required_scopes, vec![Scope::WriteEntities]);
    }
    assert!(table.iter().all(|e| e.path != routes::TPL_FILES_RAW));
}

#[test]
fn files_reads_require_read_inventory_writes_require_write_entities() {
    let api = api_with(MemoryFiles::ready());
    mint(&api, "none", Vec::new());
    mint(&api, "ro", vec![Scope::ReadInventory]);
    let env = api.handle(ClientRequest::get(routes::PATH_FILES_ENTRIES).with_session("none"));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
    let env = api.handle(
        ClientRequest::post(
            routes::PATH_FILES_WRITE_TICKET,
            json!({"path": "notes/a.md", "intent": "edit", "base_oid": OID, "size": 4, "oid": OID}),
        )
        .with_session("ro"),
    );
    assert_eq!(
        code(&env),
        Some(ClientErrorCode::Forbidden),
        "{:?}",
        env.error
    );
    let env = api.handle(
        ClientRequest::post(routes::PATH_FILES_MKDIR, json!({"path": "notes/d"}))
            .with_session("ro")
            .with_idempotency_key("m"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
    operator(&api);
    let env = api.handle(
        ClientRequest::post(routes::PATH_FILES_MKDIR, json!({"path": "notes/d"}))
            .with_session("tok"),
    );
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyRequired));
    let _ = env;
}

#[test]
fn files_routes_refuse_non_loopback_peers() {
    let provider = MemoryFiles::ready();
    let mut cfg = ClientApiConfig::default();
    cfg.remote_bind_enabled = true;
    let api = ClientApi::with_parts(
        cfg,
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(RecordingSink::new()),
    )
    .with_cursor_codec(codec())
    .with_files_provider(provider.clone());
    operator(&api);
    for (path, req) in json_routes() {
        let env = api.handle(req.with_loopback_peer(false));
        assert_eq!(code(&env), Some(ClientErrorCode::Forbidden), "{path}");
        assert_eq!(
            details(&env).first().map(String::as_str),
            Some("loopback_only"),
            "{path}"
        );
    }
    assert_eq!(provider.calls.list.load(Ordering::SeqCst), 0);
    assert_eq!(provider.calls.mkdir.load(Ordering::SeqCst), 0);
}

#[test]
fn files_private_paths_answer_not_found_without_provider_call() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    for path in [
        ".git/config",
        ".triggers/components.db",
        ".g\u{200D}it/config",
    ] {
        let env = api.handle(get_q(routes::PATH_FILES_STAT, json!({ "path": path })));
        assert_eq!(code(&env), Some(ClientErrorCode::NotFound), "{path}");
        assert!(
            details(&env).is_empty() || details(&env)[0] != path,
            "{path}"
        );
    }
    assert_eq!(provider.calls.stat.load(Ordering::SeqCst), 0);
}

#[test]
fn files_create_of_reserved_name_is_invalid_path() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": ".triggers"}),
        "r1",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(
        details(&env),
        vec!["invalid_path".to_string(), "reason:reserved_name".into()]
    );
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": ".DS_Store"}),
        "r2",
    ));
    assert_eq!(
        details(&env),
        vec!["invalid_path".to_string(), "reason:junk_name".into()]
    );
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": ".git/x"}),
        "r3",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::NotFound));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("parent_not_found")
    );
    assert_eq!(provider.calls.mkdir.load(Ordering::SeqCst), 0);
}

#[test]
fn files_readonly_paths_refused_for_writes() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_WRITE_TICKET,
        json!({"path": ".agent/AGENTS.md", "intent": "edit", "base_oid": OID, "size": 4, "oid": OID}),
        "ro",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::Forbidden));
    assert!(details(&env).contains(&"read_only".into()));
    assert!(details(&env).iter().any(|d| d == "reason:agent_system"));
    let env = api.handle(post(
        routes::PATH_FILES_READ_TICKET,
        json!({"path": ".agent/AGENTS.md"}),
        "rd",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(provider.calls.prepare_read.load(Ordering::SeqCst), 1);
}

#[test]
fn files_provider_receives_nfc_paths() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let nfd = "notes/cafe\u{0301}.md";
    let env = api.handle(get_q(routes::PATH_FILES_STAT, json!({ "path": nfd })));
    assert!(env.is_ok(), "{:?}", env.error);
    let got = provider.last.lock().unwrap().paths.last().cloned().unwrap();
    assert_eq!(got, "notes/café.md");
    assert_ne!(got, nfd);
}

#[test]
fn files_actor_comes_from_the_session() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": "notes/d", "initiator": "agent:x"}),
        "init",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(provider.calls.mkdir.load(Ordering::SeqCst), 0);
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": "notes/d"}),
        "ok",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    let actor = provider.last.lock().unwrap().actor.clone().unwrap();
    assert_eq!(actor.principal_id, "operator");
    assert_eq!(actor.os_user, "operator");
    assert_eq!(actor.platform, Platform::Mac);
    assert_eq!(
        actor.session_ref,
        advance_client_api::session::session_ref_hex("sess-tok")
    );
}

#[test]
fn files_entries_limits_cursor_and_budget() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let _ = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "limit": 0}),
    ));
    assert_eq!(provider.last.lock().unwrap().limit, Some(1));
    let _ = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "limit": 9999}),
    ));
    assert_eq!(
        provider.last.lock().unwrap().limit,
        Some(FILES_MAX_PAGE_LIMIT)
    );
    let env = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "cursor": "%%%"}),
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_cursor")
    );
    let env = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "cursor": "x".repeat(2000)}),
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_cursor")
    );
    let stale = Arc::new(MemoryFiles {
        calls: Calls::default(),
        last: Mutex::new(Last::default()),
        fail: Mutex::new(None),
        list_cursor_stale: true,
        write: Mutex::new(WriteMode::Ok),
        copy_ok: false,
    });
    let api = api_with(stale);
    operator(&api);
    let env = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "cursor": "abc"}),
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("cursor_stale")
    );
}

#[test]
fn files_get_without_query_is_invalid_path_missing() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    for path in [routes::PATH_FILES_ENTRIES, routes::PATH_FILES_STAT] {
        let env = api.handle(ClientRequest::get(path).with_session("tok"));
        assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest), "{path}");
        assert_eq!(
            details(&env),
            vec!["invalid_path".to_string(), "reason:missing".into()],
            "{path}"
        );
    }
}

#[test]
fn files_search_bounds() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(get_q(routes::PATH_FILES_SEARCH, json!({"q": ""})));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_query")
    );
    let env = api.handle(get_q(
        routes::PATH_FILES_SEARCH,
        json!({"q": "x".repeat(129)}),
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_query")
    );
    let env = api.handle(get_q(
        routes::PATH_FILES_SEARCH,
        json!({"q": "ok", "limit": 999}),
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(provider.last.lock().unwrap().limit, Some(200));
}

#[test]
fn files_write_ticket_validation() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_WRITE_TICKET,
        json!({"path": "notes/a.md", "intent": "edit", "size": 4, "oid": OID}),
        "e1",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_intent")
    );
    let env = api.handle(post(
        routes::PATH_FILES_WRITE_TICKET,
        json!({"path": "notes/new.md", "intent": "create", "base_oid": OID, "size": 4, "oid": OID}),
        "e2",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_intent")
    );
    let env = api.handle(post(
        routes::PATH_FILES_WRITE_TICKET,
        json!({"path": "notes/a.md", "intent": "upload", "size": (1u64 << 30) + 1, "oid": OID}),
        "e3",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::RequestTooLarge));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("upload_too_large")
    );
    let env = api.handle(post(
        routes::PATH_FILES_WRITE_TICKET,
        json!({"path": "notes/a.md", "intent": "upload", "size": 4, "oid": "zz"}),
        "e4",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_oid")
    );
    *provider.write.lock().unwrap() = WriteMode::StaleBase;
    let env = api.handle(post(
        routes::PATH_FILES_WRITE_TICKET,
        json!({"path": "notes/a.md", "intent": "edit", "base_oid": OID, "size": 4, "oid": OID}),
        "e5",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("stale_base")
    );
    *provider.write.lock().unwrap() = WriteMode::AlreadyCurrent;
    let env = api.handle(post(
        routes::PATH_FILES_WRITE_TICKET,
        json!({"path": "notes/a.md", "intent": "edit", "base_oid": OID, "size": 4, "oid": OID}),
        "e6",
    ));
    let ticket: ClientFileTicket = serde_json::from_value(env.data.unwrap()).unwrap();
    assert!(ticket.already_current);
}

#[test]
fn files_detail_tokens_match_grammar_and_registry() {
    let token_ok = |t: &str| {
        let b = t.as_bytes();
        !b.is_empty()
            && b.len() <= 48
            && b[0].is_ascii_lowercase()
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
    };
    for row in REGISTRY {
        assert!(token_ok(row.token), "{}", row.token);
        assert!(!row.code.is_empty());
    }
    let samples = [
        FilesFailure::NotFound,
        FilesFailure::InvalidPath(PathDefect::Missing),
        FilesFailure::MixedDestinations,
        FilesFailure::ReadOnly {
            reason: ReadOnlyReason::AgentSystem,
            item: None,
        },
        FilesFailure::CursorStale,
        FilesFailure::Capacity(CapacityKind::RawRead),
        FilesFailure::TicketInvalid,
        FilesFailure::BatchExpired { item: Some(0) },
        FilesFailure::ReservedNamespace,
        FilesFailure::VcsUnavailable {
            reason: Some(VcsUnavailableReason::NoRepo),
        },
    ];
    for f in samples {
        let (_c, _m, details) = f.render();
        if let Some(token) = details.first() {
            assert!(
                REGISTRY.iter().any(|r| r.token == token.as_str()),
                "{token} missing from registry"
            );
        }
    }
    assert!(Oid40::parse("zz").is_err());
    assert!(Oid40::parse(OID).is_ok());
    let reg = advance_client_api::files::detail::registry_json();
    assert!(reg[0]["token"].is_string());
    assert!(reg[0]["code"].is_string());
    assert!(reg[0]["params"].is_array());
}

#[test]
fn files_provider_errors_are_fixed_messages() {
    let cases = [
        (FilesFailure::NotFound, "resource not found"),
        (
            FilesFailure::ReadOnly {
                reason: ReadOnlyReason::AgentSystem,
                item: None,
            },
            "path not accessible",
        ),
        (FilesFailure::FileBusy, "file is being written"),
        (
            FilesFailure::StaleTicket,
            "file changed since the ticket was issued",
        ),
        (
            FilesFailure::StaleBase {
                current_oid: None,
                item: None,
            },
            "file changed since it was read",
        ),
        (
            FilesFailure::BatchExpired { item: Some(1) },
            "operation not valid for the resource's current state",
        ),
        (FilesFailure::TicketInvalid, "file ticket not found"),
        (
            FilesFailure::Capacity(CapacityKind::RawRead),
            "capacity exceeded",
        ),
        (FilesFailure::LoopbackOnly, "not allowed"),
    ];
    for (failure, message) in cases {
        let (_c, msg, _) = failure.render();
        assert_eq!(msg, message, "{failure:?}");
    }
}

#[test]
fn files_mutations_replay_and_conflict() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    let body = json!({"path": "notes/d"});
    let first = api.handle(post(routes::PATH_FILES_MKDIR, body.clone(), "same"));
    assert!(first.is_ok(), "{:?}", first.error);
    let replay = api.handle(post(routes::PATH_FILES_MKDIR, body, "same"));
    assert!(replay.is_ok());
    assert!(replay
        .warnings
        .iter()
        .any(|w| w.code == "idempotent_replay"));
    let env = api.handle(post(
        routes::PATH_FILES_MKDIR,
        json!({"path": "notes/other"}),
        "same",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::IdempotencyConflict));
}

#[test]
fn files_save_version_title_normalization() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_SAVE_VERSION,
        json!({"title": "  周报\u{3000}v2\n"}),
        "t1",
    ));
    let result: ClientFileVersionResult = serde_json::from_value(env.data.unwrap()).unwrap();
    assert_eq!(result.title, "周报 v2");
    let env = api.handle(post(
        routes::PATH_FILES_SAVE_VERSION,
        json!({"title": "[x] <y> \"z\""}),
        "t2",
    ));
    let result: ClientFileVersionResult = serde_json::from_value(env.data.unwrap()).unwrap();
    assert_eq!(result.title, "[x] <y> \"z\"");
    for (title, key) in [("", "t3"), (&"x".repeat(81), "t4")] {
        let env = api.handle(post(
            routes::PATH_FILES_SAVE_VERSION,
            json!({ "title": title }),
            key,
        ));
        assert_eq!(
            details(&env).first().map(String::as_str),
            Some("invalid_title")
        );
    }
}

#[test]
fn files_restore_batch_validation() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_RESTORE,
        json!({"from_sha": OID, "items": []}),
        "r0",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("item_count")
    );
    let items: Vec<Value> = (0..257).map(|_| json!({"path": "notes/a.md"})).collect();
    let env = api.handle(post(
        routes::PATH_FILES_RESTORE,
        json!({"from_sha": OID, "items": items}),
        "r257",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("item_count")
    );
    let env = api.handle(post(
        routes::PATH_FILES_RESTORE,
        json!({"from_sha": "zz", "items": [{"path": "notes/a.md"}]}),
        "rbad",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("invalid_rev")
    );
}

#[test]
fn files_commit_external_single_item_v1() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_COMMIT_EXTERNAL,
        json!({"items": [{"path": "a.md"}, {"path": "b.md"}]}),
        "two",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("item_count")
    );
}

#[test]
fn files_copy_route_is_registered() {
    let table = ClientApi::new(ClientApiConfig::default()).route_table();
    assert!(table.iter().any(|e| e.path == routes::PATH_FILES_COPY));
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_COPY,
        json!({"items": [
            {"from": "notes/a.md", "to": "notes/b.md"},
            {"from": "notes/c.md", "to": "other/d.md"}
        ]}),
        "mix",
    ));
    assert_eq!(
        details(&env).first().map(String::as_str),
        Some("mixed_destinations")
    );
    assert_eq!(provider.calls.copy.load(Ordering::SeqCst), 0);
    let api = api_bare();
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_COPY,
        json!({"items": [{"from": "notes/a.md", "to": "notes/b.md"}]}),
        "abs",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::ModuleUnavailable));
}

#[test]
fn files_copy_mixed_destinations_refused() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_COPY,
        json!({"items": [
            {"from": "a.md", "to": "dir1/x.md"},
            {"from": "b.md", "to": "dir2/y.md"}
        ]}),
        "mix2",
    ));
    assert_eq!(details(&env), vec!["mixed_destinations".to_string()]);
    assert_eq!(provider.calls.copy.load(Ordering::SeqCst), 0);
}

#[test]
fn files_read_ticket_large_unstable_still_mints() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_READ_TICKET,
        json!({"path": "notes/large-unstable.bin"}),
        "big",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_ne!(details(&env).first().map(String::as_str), Some("file_busy"));
    let ticket: ClientFileTicket = serde_json::from_value(env.data.unwrap()).unwrap();
    assert!(ticket.oid.is_none());
    assert!(ticket.etag.starts_with("id-"));
}

#[test]
fn git_path_cap_raised_to_1024() {
    assert_eq!(MAX_GIT_PATH_LEN, 1024);
    assert_eq!(MAX_FILES_PATH_BYTES, 1024);
    struct CapGit {
        hits: AtomicUsize,
    }
    impl GitHistoryProvider for CapGit {
        fn status(&self) -> Result<ClientGitStatus, ProviderError> {
            Ok(ClientGitStatus {
                repo: "ready".into(),
                branch: "main".into(),
                head_sha: None,
                commit_count: None,
                checkpoint_count: None,
                observed_ref: None,
                reason: None,
            })
        }
        fn commits(
            &self,
            _query: &ValidatedGitCommitQuery,
        ) -> Result<ClientGitCommitPage, ProviderError> {
            Ok(ClientGitCommitPage {
                items: vec![],
                next_cursor: None,
            })
        }
        fn checkpoints(
            &self,
            _agent_id: Option<&str>,
        ) -> Result<ClientGitCheckpointList, ProviderError> {
            Ok(ClientGitCheckpointList { items: vec![] })
        }
        fn file_history(&self, _path: &str) -> Result<ClientGitFileHistory, ProviderError> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok(ClientGitFileHistory {
                items: vec![],
                truncated: false,
            })
        }
        fn file_at(&self, _path: &str, _sha: &str) -> Result<ClientGitFileAt, ProviderError> {
            Err(ProviderError::NotFound("path".into()))
        }
        fn create_checkpoint(
            &self,
            _request: &advance_client_api::ClientGitCreateCheckpointRequest,
        ) -> Result<ClientGitCheckpointEntry, ProviderError> {
            Err(ProviderError::Unavailable("x".into()))
        }
        fn rollback_to_checkpoint(
            &self,
            _agent_id: &str,
            _label: &str,
            _principal: &Principal,
        ) -> Result<ClientGitRollbackResult, ProviderError> {
            Err(ProviderError::Unavailable("x".into()))
        }
    }
    let git = Arc::new(CapGit {
        hits: AtomicUsize::new(0),
    });
    let api = api_bare().with_git_provider(git.clone());
    operator(&api);
    let ok = vec!["n".repeat(204); 5].join("/");
    let env = api.handle({
        let mut req = ClientRequest::get(routes::PATH_GIT_FILE_HISTORY).with_session("tok");
        req.body = json!({ "path": ok });
        req
    });
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(git.hits.load(Ordering::SeqCst), 1);
    let env = api.handle({
        let mut req = ClientRequest::get(routes::PATH_GIT_FILE_HISTORY).with_session("tok");
        req.body = json!({ "path": format!("{ok}x") });
        req
    });
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
    assert_eq!(git.hits.load(Ordering::SeqCst), 1);
}

#[test]
fn files_schema_components_inventoried() {
    let art = generate_schema_artifact();
    let components = art.schema["components"].as_object().unwrap();
    for name in [
        "ClientFileEntry",
        "ClientFileList",
        "ClientFileStat",
        "ClientFileSearchResult",
        "ClientFileTicket",
        "ClientGitCommitLabel",
        "ClientFileCommit",
        "ClientFileChange",
        "ClientFileWriteResult",
        "ClientFileMutationResult",
        "ClientFileVersionResult",
    ] {
        assert!(RESPONSE_COMPONENTS.contains(&name), "{name}");
        assert!(components.contains_key(name), "{name}");
    }
    for name in [
        "ClientFileReadTicketRequest",
        "ClientFileWriteTicketRequest",
        "ClientFileCommitBatchRequest",
        "ClientFileMkdirRequest",
        "ClientFileMoveItem",
        "ClientFileMoveRequest",
        "ClientFileDeleteItem",
        "ClientFileDeleteRequest",
        "ClientFileRestoreItem",
        "ClientFileRestoreRequest",
        "ClientFileSaveVersionRequest",
        "ClientFileExternalItem",
        "ClientFileCommitExternalRequest",
        "ClientFileCopyItem",
        "ClientFileCopyRequest",
    ] {
        assert!(EXCLUDED_COMPONENTS.contains(&name), "{name}");
        assert!(components.contains_key(name), "{name}");
    }
    let allowed = [
        "added",
        "asc",
        "attachment",
        "committed",
        "compact",
        "create",
        "deleted",
        "desc",
        "dir",
        "edit",
        "extreme",
        "file",
        "ignored",
        "inline",
        "kind",
        "medium",
        "modified",
        "name",
        "other",
        "read",
        "replaced",
        "size",
        "staged",
        "symlink",
        "too_large",
        "unknown",
        "untracked",
        "upload",
        "user",
        "wide",
        "write",
    ];
    let mut found = Vec::new();
    for (name, node) in components {
        if name.starts_with("ClientFile") || name.starts_with("ClientGit") {
            collect_enums(node, &mut found);
        }
    }
    for value in found {
        assert!(
            allowed.contains(&value.as_str()),
            "unexpected closed-enum leaf {value}"
        );
    }
}

fn collect_enums(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            if let Some(Value::Array(vals)) = map.get("enum") {
                for v in vals {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
            for v in map.values() {
                collect_enums(v, out);
            }
        }
        Value::Array(vals) => {
            for v in vals {
                collect_enums(v, out);
            }
        }
        _ => {}
    }
}

#[test]
fn files_list_sort_order_and_folders_first_default() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let _ = api.handle(get_q(routes::PATH_FILES_ENTRIES, json!({"path": "notes"})));
    let last = provider.last.lock().unwrap();
    assert_eq!(last.folders_first, Some(true));
    assert_eq!(last.sort.as_deref(), Some("name"));
    assert_eq!(last.order.as_deref(), Some("asc"));
    drop(last);
    let env = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "sort": "modified", "order": "desc", "folders_first": false}),
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    let last = provider.last.lock().unwrap();
    assert_eq!(last.folders_first, Some(false));
    assert_eq!(last.sort.as_deref(), Some("modified"));
    assert_eq!(last.order.as_deref(), Some("desc"));
    drop(last);
    let env = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "sort": "kind"}),
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(provider.last.lock().unwrap().sort.as_deref(), Some("kind"));
    let env = api.handle(get_q(
        routes::PATH_FILES_ENTRIES,
        json!({"path": "notes", "sort": "mtime"}),
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
}

#[test]
fn files_search_forwards_dotfiles() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(get_q(
        routes::PATH_FILES_SEARCH,
        json!({"q": "ok", "dotfiles": true}),
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(provider.last.lock().unwrap().dotfiles, Some(true));
}

#[test]
fn files_move_mixed_destinations_refused() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_MOVE,
        json!({"items": [
            {"from": "a.md", "to": "dir1/x.md", "base_oid": null},
            {"from": "b.md", "to": "dir2/y.md"}
        ]}),
        "mix-move",
    ));
    assert_eq!(details(&env), vec!["mixed_destinations".to_string()]);
}

#[test]
fn files_mutation_items_accept_cas_fields() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_MOVE,
        json!({"items": [{"from": "notes/a.md", "to": "notes/b.md", "base_oid": OID}]}),
        "cas-move",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(provider.last.lock().unwrap().base_oid.as_deref(), Some(OID));
    let env = api.handle(post(
        routes::PATH_FILES_DELETE,
        json!({"items": [{"path": "notes/a.md", "base_oid": null}]}),
        "cas-del",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    let env = api.handle(post(
        routes::PATH_FILES_RESTORE,
        json!({"from_sha": OID, "items": [{"path": "notes/a.md", "base_oid": OID}]}),
        "cas-rst",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    let env = api.handle(post(
        routes::PATH_FILES_COMMIT_EXTERNAL,
        json!({"items": [{"path": "notes/a.md", "oid": null}]}),
        "cas-ext",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
}

#[test]
fn files_path_parse_round_trip() {
    assert!(FilesPath::parse("notes/a.md", PathUse::Read).is_ok());
}

const BATCH_OK: &str = "abcdefghijklmnop";

#[test]
fn files_write_ticket_rejects_malformed_batch_id() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    for (batch, key) in [
        ("short", "b1"),
        ("has space in batchid", "b2"),
        (&"x".repeat(65), "b3"),
        ("bad/slash/batchid!", "b4"),
    ] {
        let env = api.handle(post(
            routes::PATH_FILES_WRITE_TICKET,
            json!({"path": "notes/a.md", "intent": "upload", "size": 4, "oid": OID, "batch": batch}),
            key,
        ));
        assert_eq!(
            code(&env),
            Some(ClientErrorCode::InvalidRequest),
            "{batch} {:?}",
            env.error
        );
    }
}

#[test]
fn files_commit_batch_rejects_malformed_batch_id() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_COMMIT_BATCH,
        json!({"batch": "too-short", "mkdirs": ["reports"], "parents": true}),
        "bad-cb",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
}

#[test]
fn files_commit_batch_unknown_field_is_invalid_request() {
    let api = api_with(MemoryFiles::ready());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_COMMIT_BATCH,
        json!({"batch": BATCH_OK, "mkdirs": ["reports"], "parents": true, "extra": true}),
        "unk",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidRequest));
}

#[test]
fn files_commit_batch_one_upload_commit() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone());
    operator(&api);
    for (path, key) in [
        ("reports/a.md", "wt-a"),
        ("reports/b.md", "wt-b"),
        ("reports/c.md", "wt-c"),
    ] {
        let env = api.handle(post(
            routes::PATH_FILES_WRITE_TICKET,
            json!({
                "path": path,
                "intent": "create",
                "size": 4,
                "oid": OID,
                "batch": BATCH_OK
            }),
            key,
        ));
        assert!(env.is_ok(), "{path} {:?}", env.error);
    }
    assert_eq!(
        provider.last.lock().unwrap().batch.as_deref(),
        Some(BATCH_OK)
    );
    let env = api.handle(post(
        routes::PATH_FILES_COMMIT_BATCH,
        json!({"batch": BATCH_OK, "mkdirs": ["reports"], "parents": true}),
        "cb-ok",
    ));
    assert!(env.is_ok(), "{:?}", env.error);
    assert_eq!(provider.calls.commit_batch.load(Ordering::SeqCst), 1);
    let result: ClientFileMutationResult = serde_json::from_value(env.data.unwrap()).unwrap();
    assert_eq!(result.commit_state, "committed");
    let commit = result.commit.expect("one upload commit");
    assert_eq!(commit.label.op, "upload");
    assert_eq!(commit.commit_type, "user");
}

#[test]
fn files_commit_batch_expired_commits_nothing() {
    let provider = MemoryFiles::ready();
    *provider.fail.lock().unwrap() = Some(ProviderError::Files(FilesFailure::BatchExpired {
        item: Some(0),
    }));
    let api = api_with(provider.clone());
    operator(&api);
    let env = api.handle(post(
        routes::PATH_FILES_COMMIT_BATCH,
        json!({"batch": BATCH_OK, "mkdirs": ["reports"], "parents": true}),
        "cb-exp",
    ));
    assert_eq!(code(&env), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        details(&env),
        vec!["batch_expired".to_string(), "item:0".into()]
    );
    assert_eq!(provider.calls.commit_batch.load(Ordering::SeqCst), 1);
}
