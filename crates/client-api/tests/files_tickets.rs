//! File-ticket seal/open, session binding, and dedicated files.raw idempotency.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::file_ticket::{self, FileTicketBody, TicketIntent, TicketMode, STREAM_ID};
use advance_client_api::files::detail::{FilesFailure, Oid40};
use advance_client_api::files::{
    ClientFileTicket, ClientFileWriteResult, FileReadSource, FileReadVersion, FileUploadHandle,
    FileUploadSink, FileWriteTarget, FilesActor, FilesDelete, FilesExternalItem, FilesListPage,
    FilesListQuery, FilesMkdir, FilesMoveItem, FilesPath, FilesReadQuery, FilesRestore,
    FilesSaveVersion, FilesSearchQuery, FilesStatQuery, WriteCheck,
};
use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer, ClientCursorCodec,
    ClientRequest, ClientSession, FilesProvider, MemoryCursorKeyCustody, OpenedSeal,
    OsCursorEntropy, Platform, Principal, ProviderError, Scope, SealPurpose, SystemCursorClock,
    SEAL_TAG_FILE_TICKET,
};
use advance_shared_types::file_identity::FileIdentity;
use serde_json::json;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct MemoryFiles {
    finish: AtomicUsize,
    already: Mutex<bool>,
    stale: Mutex<bool>,
}

impl MemoryFiles {
    fn ready() -> Arc<Self> {
        Arc::new(Self {
            finish: AtomicUsize::new(0),
            already: Mutex::new(false),
            stale: Mutex::new(false),
        })
    }
}

impl FilesProvider for MemoryFiles {
    fn list(&self, q: &FilesListQuery) -> Result<FilesListPage, ProviderError> {
        Ok(FilesListPage {
            list: advance_client_api::ClientFileList {
                path: q.path.as_str().to_string(),
                entries: vec![],
                total: 0,
                next_cursor: None,
                truncated: false,
                skipped: 0,
                vcs: "unknown".into(),
            },
        })
    }
    fn stat(
        &self,
        q: &FilesStatQuery,
    ) -> Result<advance_client_api::ClientFileStat, ProviderError> {
        Err(ProviderError::NotFound(q.path.as_str().into()))
    }
    fn search(
        &self,
        _q: &FilesSearchQuery,
    ) -> Result<advance_client_api::ClientFileSearchResult, ProviderError> {
        Err(ProviderError::Unavailable("search".into()))
    }
    fn prepare_read(&self, q: &FilesReadQuery) -> Result<FileReadVersion, ProviderError> {
        Ok(FileReadVersion {
            path: q.path.as_str().to_string(),
            size: 4,
            content_type: "text/plain".into(),
            oid: Some(Oid40::parse(OID).unwrap()),
            identity: Some(FileIdentity {
                dev: 1,
                ino: 2,
                size: 4,
                mtime_ns: 0,
            }),
            rev: None,
            already_current: false,
        })
    }
    fn open_read(
        &self,
        _path: &FilesPath,
        _v: &FileReadVersion,
    ) -> Result<FileReadSource, ProviderError> {
        Ok(FileReadSource::Bytes(b"data".to_vec()))
    }
    fn check_write(
        &self,
        _actor: &FilesActor,
        t: &FileWriteTarget,
    ) -> Result<WriteCheck, ProviderError> {
        if *self.stale.lock().unwrap() {
            return Err(ProviderError::Files(FilesFailure::StaleBase {
                current_oid: Some(t.oid.clone()),
                item: None,
            }));
        }
        if *self.already.lock().unwrap() {
            return Ok(WriteCheck::AlreadyCurrent {
                oid: t.oid.clone(),
                size: t.size,
                content_type: "text/plain".into(),
                etag: t.oid.as_str().to_string(),
                identity: None,
            });
        }
        Ok(WriteCheck::Ok {
            etag: t.oid.as_str().to_string(),
            oid: t.oid.clone(),
            size: t.size,
            content_type: "text/plain".into(),
            identity: None,
        })
    }
    fn begin_upload(
        &self,
        _actor: &FilesActor,
        _t: &FileWriteTarget,
    ) -> Result<FileUploadSink, ProviderError> {
        Ok(FileUploadSink::memory("up").0)
    }
    fn finish_upload(
        &self,
        _actor: &FilesActor,
        t: &FileWriteTarget,
        _h: FileUploadHandle,
    ) -> Result<ClientFileWriteResult, ProviderError> {
        self.finish.fetch_add(1, Ordering::SeqCst);
        Ok(ClientFileWriteResult {
            path: t.path.as_str().to_string(),
            oid: t.oid.as_str().to_string(),
            size: t.size,
            versioned: true,
            versioned_reason: None,
            commit_state: "committed".into(),
            commit: None,
        })
    }
    fn abort_upload(&self, _h: FileUploadHandle) {}
    fn mkdir(
        &self,
        _a: &FilesActor,
        _r: &FilesMkdir,
    ) -> Result<advance_client_api::ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn move_items(
        &self,
        _a: &FilesActor,
        _i: &[FilesMoveItem],
    ) -> Result<advance_client_api::ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn delete(
        &self,
        _a: &FilesActor,
        _r: &FilesDelete,
    ) -> Result<advance_client_api::ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn restore(
        &self,
        _a: &FilesActor,
        _r: &FilesRestore,
    ) -> Result<advance_client_api::ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn save_version(
        &self,
        _a: &FilesActor,
        _r: &FilesSaveVersion,
    ) -> Result<advance_client_api::ClientFileVersionResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn commit_external(
        &self,
        _a: &FilesActor,
        _i: &[FilesExternalItem],
    ) -> Result<advance_client_api::ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
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

fn api_with(provider: Arc<dyn FilesProvider>, sink: RecordingSink) -> ClientApi {
    ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink),
    )
    .with_cursor_codec(codec())
    .with_files_provider(provider)
}

fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>, session_id: &str) {
    api.sessions().insert(
        token.to_string(),
        ClientSession {
            session_id: session_id.into(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes,
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
}

fn digest(id: &str) -> [u8; 32] {
    advance_client_api::session::session_digest(id)
}

fn hello_oid() -> String {
    advance_git::blob_oid_of_bytes(b"hello")
}

fn mint_read(api: &ClientApi, token: &str) -> String {
    let env = api.handle(
        ClientRequest::post("/client/files:read-ticket", json!({"path": "notes/a.md"}))
            .with_session(token),
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let ticket: ClientFileTicket = serde_json::from_value(env.data.unwrap()).unwrap();
    ticket.ticket
}

fn mint_write(api: &ClientApi, token: &str) -> String {
    let oid = hello_oid();
    let env = api.handle(
        ClientRequest::post(
            "/client/files:write-ticket",
            json!({"path": "notes/a.md", "intent": "edit", "base_oid": oid, "size": 5, "oid": oid}),
        )
        .with_session(token),
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let ticket: ClientFileTicket = serde_json::from_value(env.data.unwrap()).unwrap();
    ticket.ticket
}

struct HttpResp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn envelope_details(&self) -> Vec<String> {
        let v: Value = serde_json::from_slice(&self.body).unwrap_or(Value::Null);
        v["error"]["details"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
    fn warning_codes(&self) -> Vec<String> {
        let v: Value = serde_json::from_slice(&self.body).unwrap_or(Value::Null);
        v["warnings"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|w| w["code"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Option<&[u8]>,
) -> HttpResp {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    if let Some(b) = body {
        stream.write_all(b).await.unwrap();
    }
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(buf.len());
    let head = String::from_utf8_lossy(&buf[..split]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    HttpResp {
        status,
        headers,
        body: buf[split.saturating_add(4)..].to_vec(),
    }
}

async fn bind(
    api: ClientApi,
) -> (
    ClientApiServer,
    std::net::SocketAddr,
    std::sync::Arc<ClientApi>,
) {
    let api = std::sync::Arc::new(api);
    let server = ClientApiServer::bind(std::sync::Arc::clone(&api), 0)
        .await
        .unwrap();
    let addr = server.local_addr();
    (server, addr, api)
}

fn mint_body(path: &str, session: &str, expires: u64, mode: TicketMode) -> FileTicketBody {
    match mode {
        TicketMode::Read => FileTicketBody::read(
            path,
            digest(session),
            expires,
            Some(Oid40::parse(OID).unwrap()),
            None,
            None,
            4,
            false,
        ),
        TicketMode::Write => FileTicketBody::write(
            path,
            digest(session),
            expires,
            Oid40::parse(OID).unwrap(),
            Some(Oid40::parse(OID).unwrap()),
            None,
            4,
            TicketIntent::Edit,
        ),
    }
}

#[test]
fn file_ticket_round_trip_max_path() {
    let codec = codec();
    let path = format!("notes/{}x", "文".repeat(339));
    assert_eq!(path.len(), 1024);
    let body = mint_body(&path, "sess-x", 2_000_000, TicketMode::Read);
    let bytes = body.encode().unwrap();
    let token = codec
        .seal(
            SealPurpose::FileTicket,
            STREAM_ID,
            SEAL_TAG_FILE_TICKET,
            &bytes,
        )
        .unwrap();
    assert!(token.len() <= 2048);
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')));
    let grant = file_ticket::open_file_ticket(codec.as_ref(), &token, 1_000_000).unwrap();
    assert_eq!(grant.path, path);
    assert_eq!(grant.mode, TicketMode::Read);
}

#[test]
fn file_ticket_tamper_rejected() {
    let codec = codec();
    let body = mint_body("a.md", "sess-x", 2_000_000, TicketMode::Read);
    let mut token = codec
        .seal(
            SealPurpose::FileTicket,
            STREAM_ID,
            SEAL_TAG_FILE_TICKET,
            &body.encode().unwrap(),
        )
        .unwrap();
    let b = token.pop().unwrap();
    token.push(if b == 'A' { 'B' } else { 'A' });
    let err = file_ticket::open_file_ticket(codec.as_ref(), &token, 1_000_000).unwrap_err();
    assert_eq!(
        err.details.first().map(String::as_str),
        Some("ticket_invalid")
    );
}

#[test]
fn file_ticket_purpose_and_tag_isolation() {
    assert_eq!(SEAL_TAG_FILE_TICKET, 0x04);
    let codec = codec();
    let body = mint_body("a.md", "sess-x", 2_000_000, TicketMode::Read);
    let token = codec
        .seal(
            SealPurpose::FileTicket,
            STREAM_ID,
            SEAL_TAG_FILE_TICKET,
            &body.encode().unwrap(),
        )
        .unwrap();
    assert!(codec.open(SealPurpose::Cursor, STREAM_ID, &token).is_err());
    let opened = codec
        .open(SealPurpose::FileTicket, STREAM_ID, &token)
        .unwrap();
    assert!(matches!(opened, OpenedSeal::FileTicket(_)));
}

#[test]
fn file_ticket_expiry_boundary() {
    let codec = codec();
    let body = mint_body("a.md", "sess-x", 1_000_000, TicketMode::Read);
    let token = codec
        .seal(
            SealPurpose::FileTicket,
            STREAM_ID,
            SEAL_TAG_FILE_TICKET,
            &body.encode().unwrap(),
        )
        .unwrap();
    assert!(file_ticket::open_file_ticket(codec.as_ref(), &token, 1_000_000).is_ok());
    let err = file_ticket::open_file_ticket(codec.as_ref(), &token, 1_000_001).unwrap_err();
    assert_eq!(
        err.details.first().map(String::as_str),
        Some("ticket_expired")
    );
}

#[tokio::test]
async fn file_ticket_session_binding() {
    let api = api_with(MemoryFiles::ready(), RecordingSink::new());
    mint(&api, "tok", Scope::operator_default(), "sess-a");
    let ticket = mint_read(&api, "tok");
    let (server, addr, api) = bind(api).await;
    let ok = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        None,
    )
    .await;
    assert_eq!(ok.status, 200, "{}", String::from_utf8_lossy(&ok.body));
    mint(api.as_ref(), "tok-b", Scope::operator_default(), "sess-b");
    let via_b = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok-b")],
        None,
    )
    .await;
    assert_eq!(
        via_b.status,
        200,
        "{}",
        String::from_utf8_lossy(&via_b.body)
    );
    api.sessions().revoke("tok");
    let ended = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok-b")],
        None,
    )
    .await;
    assert_eq!(
        ended.envelope_details().first().map(String::as_str),
        Some("ticket_session_ended")
    );
    mint(api.as_ref(), "tok2", Scope::operator_default(), "sess-a");
    let (new_tok, _) = api
        .sessions()
        .refresh("tok2", 0, u64::MAX, "tok2b".into())
        .unwrap();
    let fresh = mint_read(api.as_ref(), &new_tok);
    let after_refresh = http(
        addr,
        "GET",
        &format!("/client/files/raw/{fresh}"),
        &[("Authorization", &format!("Bearer {new_tok}"))],
        None,
    )
    .await;
    assert_eq!(after_refresh.status, 200);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn file_ticket_mode_isolation() {
    let api = api_with(MemoryFiles::ready(), RecordingSink::new());
    mint(&api, "tok", Scope::operator_default(), "sess-a");
    let read = mint_read(&api, "tok");
    let write = mint_write(&api, "tok");
    let (server, addr, _) = bind(api).await;
    let put_read = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{read}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(
        put_read.envelope_details().first().map(String::as_str),
        Some("ticket_invalid")
    );
    let get_write = http(
        addr,
        "GET",
        &format!("/client/files/raw/{write}"),
        &[("Authorization", "Bearer tok")],
        None,
    )
    .await;
    assert_eq!(
        get_write.envelope_details().first().map(String::as_str),
        Some("ticket_invalid")
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn file_ticket_scope_rechecked_at_redeem() {
    let api = api_with(MemoryFiles::ready(), RecordingSink::new());
    mint(&api, "tok", Scope::operator_default(), "sess-a");
    let ticket = mint_read(&api, "tok");
    api.sessions().insert(
        "tok".into(),
        ClientSession {
            session_id: "sess-a".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: vec![Scope::ReadRuns],
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        None,
    )
    .await;
    assert_eq!(resp.status, 403);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn write_ticket_single_use_and_replay() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone(), RecordingSink::new());
    mint(&api, "tok", Scope::operator_default(), "sess-a");
    let ticket = mint_write(&api, "tok");
    let (server, addr, _) = bind(api).await;
    let first = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    let second = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(second.status, 200);
    assert!(second
        .warning_codes()
        .iter()
        .any(|c| c == "idempotent_replay"));
    assert_eq!(provider.finish.load(Ordering::SeqCst), 1);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn write_ticket_replay_reproduces_status_and_etag() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone(), RecordingSink::new());
    mint(&api, "tok", Scope::operator_default(), "sess-a");
    let ticket = mint_write(&api, "tok");
    let (server, addr, api) = bind(api).await;
    let first = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(first.status, 200);
    assert!(first.header("etag").is_some());
    let replay = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(replay.status, 200);
    assert_eq!(replay.header("etag"), first.header("etag"));
    assert!(replay
        .warning_codes()
        .iter()
        .any(|c| c == "idempotent_replay"));

    let stale_ticket = mint_write(api.as_ref(), "tok");
    *provider.stale.lock().unwrap() = true;
    let stale = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{stale_ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(
        stale.envelope_details().first().map(String::as_str),
        Some("stale_base")
    );
    let stale_replay = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{stale_ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(
        stale_replay.envelope_details().first().map(String::as_str),
        Some("stale_base")
    );
    assert!(stale_replay
        .warning_codes()
        .iter()
        .any(|c| c == "idempotent_replay"));
    let _ = server.shutdown().await;
}

#[test]
fn write_ticket_store_is_separate() {
    use advance_client_api::idempotency::{Begin, IdempotencyScope};
    use advance_client_api::request::Method;
    let api = api_with(MemoryFiles::ready(), RecordingSink::new());
    let before = api.idempotency().len();
    for i in 0..10_001u32 {
        let scope = IdempotencyScope {
            principal: "operator".into(),
            method: Method::Post,
            family: "files.raw".into(),
            key: format!("n-{i}"),
        };
        if let Begin::Reserved(r) =
            api.files_raw_idempotency()
                .begin_fingerprinted(&scope, [(i % 256) as u8; 32], i as u64)
        {
            r.commit(json!({"i": i}), format!("r-{i}"), i as u64);
        }
    }
    assert_eq!(api.idempotency().len(), before);
    assert!(api.files_raw_idempotency().len() > 0);
}

#[tokio::test]
async fn write_ticket_lost_record_retry_is_unchanged_not_stale() {
    let provider = MemoryFiles::ready();
    let api = api_with(provider.clone(), RecordingSink::new());
    mint(&api, "tok", Scope::operator_default(), "sess-a");
    let ticket = mint_write(&api, "tok");
    let (server, addr, api) = bind(api).await;
    let first = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(
        first.status,
        200,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert!(api.files_raw_idempotency().evict_all_done() >= 1);
    *provider.already.lock().unwrap() = true;
    let retry = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    assert_eq!(
        retry.status,
        200,
        "{}",
        String::from_utf8_lossy(&retry.body)
    );
    let v: Value = serde_json::from_slice(&retry.body).unwrap();
    assert_eq!(v["data"]["commit_state"], "unchanged");
    assert_ne!(
        retry.envelope_details().first().map(String::as_str),
        Some("stale_base")
    );
    assert_eq!(provider.finish.load(Ordering::SeqCst), 1);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn file_ticket_never_logged() {
    let sink = RecordingSink::new();
    let api = api_with(MemoryFiles::ready(), sink.clone());
    mint(&api, "tok", Scope::operator_default(), "sess-a");
    let read = mint_read(&api, "tok");
    let write = mint_write(&api, "tok");
    let (server, addr, _) = bind(api).await;
    let _ = http(
        addr,
        "GET",
        &format!("/client/files/raw/{read}"),
        &[("Authorization", "Bearer tok")],
        None,
    )
    .await;
    let _ = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{write}"),
        &[("Authorization", "Bearer tok")],
        Some(b"hello"),
    )
    .await;
    let events = sink.events();
    assert!(events
        .iter()
        .any(|e| e.family == "files" && e.method == "RawGet"));
    assert!(events
        .iter()
        .any(|e| e.family == "files" && e.method == "RawPut"));
    for ev in events {
        assert!(!ev.method.contains(&read) && !ev.method.contains(&write));
        assert!(!ev.family.contains(&read) && !ev.family.contains(&write));
        assert!(!ev.request_id.contains(&read) && !ev.request_id.contains(&write));
    }
    let _ = server.shutdown().await;
}
