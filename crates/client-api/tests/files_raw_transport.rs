//! Transport-owned GET/HEAD/PUT `/client/files/raw/{ticket}`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::files::detail::Oid40;
use advance_client_api::files::{
    ClientFileList, ClientFileMutationResult, ClientFileSearchResult, ClientFileStat,
    ClientFileTicket, ClientFileVersionResult, ClientFileWriteResult, FileReadSource,
    FileReadVersion, FileUploadHandle, FileUploadSink, FileWriteTarget, FilesActor, FilesDelete,
    FilesExternalItem, FilesListPage, FilesListQuery, FilesMkdir, FilesMoveItem, FilesPath,
    FilesReadQuery, FilesRestore, FilesSaveVersion, FilesSearchQuery, FilesStatQuery, WriteCheck,
};
use advance_client_api::{
    client_api_router, AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer,
    ClientCursorCodec, ClientRequest, ClientSession, FilesProvider, MemoryCursorKeyCustody,
    OsCursorEntropy, Platform, Principal, ProviderError, Scope, SessionAdmission,
    SystemCursorClock,
};
use advance_shared_types::file_identity::FileIdentity;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

const OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN: &str = "raw-tok";

struct MemoryFiles {
    bytes: Mutex<HashMap<String, Vec<u8>>>,
    paths: Mutex<HashMap<String, PathBuf>>,
    finish: AtomicUsize,
    abort: AtomicUsize,
    already: Mutex<bool>,
    identity_size: Mutex<Option<u64>>,
}

impl MemoryFiles {
    fn ready() -> Arc<Self> {
        let mut bytes = HashMap::new();
        bytes.insert("notes/a.md".into(), b"hello".to_vec());
        bytes.insert("notes/page.html".into(), b"<html></html>".to_vec());
        bytes.insert("notes/empty.txt".into(), Vec::new());
        bytes.insert("notes/photo.png".into(), b"\x89PNG".to_vec());
        Arc::new(Self {
            bytes: Mutex::new(bytes),
            paths: Mutex::new(HashMap::new()),
            finish: AtomicUsize::new(0),
            abort: AtomicUsize::new(0),
            already: Mutex::new(false),
            identity_size: Mutex::new(None),
        })
    }
}

impl FilesProvider for MemoryFiles {
    fn list(&self, q: &FilesListQuery) -> Result<FilesListPage, ProviderError> {
        Ok(FilesListPage {
            list: ClientFileList {
                path: q.path.as_str().into(),
                entries: vec![],
                total: 0,
                next_cursor: None,
                truncated: false,
                skipped: 0,
                vcs: "unknown".into(),
            },
        })
    }
    fn stat(&self, q: &FilesStatQuery) -> Result<ClientFileStat, ProviderError> {
        Err(ProviderError::NotFound(q.path.as_str().into()))
    }
    fn search(&self, _q: &FilesSearchQuery) -> Result<ClientFileSearchResult, ProviderError> {
        Err(ProviderError::Unavailable("s".into()))
    }
    fn prepare_read(&self, q: &FilesReadQuery) -> Result<FileReadVersion, ProviderError> {
        let size = if let Some(p) = self.paths.lock().unwrap().get(q.path.as_str()) {
            std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
        } else if q.rev.is_some() {
            5
        } else {
            let bytes = self.bytes.lock().unwrap();
            let data = bytes
                .get(q.path.as_str())
                .cloned()
                .unwrap_or_else(|| b"hello".to_vec());
            self.identity_size
                .lock()
                .unwrap()
                .unwrap_or(data.len() as u64)
        };
        Ok(FileReadVersion {
            path: q.path.as_str().to_string(),
            size,
            content_type: advance_shared_types::media_type::content_type_for_name(q.path.as_str())
                .to_string(),
            oid: Some(Oid40::parse(OID).unwrap()),
            identity: Some(FileIdentity {
                dev: 1,
                ino: 2,
                size,
                mtime_ns: 0,
            }),
            rev: q.rev.clone(),
            already_current: false,
        })
    }
    fn open_read(
        &self,
        path: &FilesPath,
        v: &FileReadVersion,
    ) -> Result<FileReadSource, ProviderError> {
        if v.rev.is_some() {
            return Ok(FileReadSource::Bytes(b"old!!".to_vec()));
        }
        if let Some(p) = self.paths.lock().unwrap().get(path.as_str()) {
            return Ok(FileReadSource::Path(p.clone()));
        }
        let bytes = self
            .bytes
            .lock()
            .unwrap()
            .get(path.as_str())
            .cloned()
            .unwrap_or_else(|| b"hello".to_vec());
        Ok(FileReadSource::Bytes(bytes))
    }
    fn check_write(
        &self,
        _actor: &FilesActor,
        t: &FileWriteTarget,
    ) -> Result<WriteCheck, ProviderError> {
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
            commit_state: if t.batch.is_some() {
                "staged".into()
            } else {
                "committed".into()
            },
            commit: None,
        })
    }
    fn abort_upload(&self, _h: FileUploadHandle) {
        self.abort.fetch_add(1, Ordering::SeqCst);
    }
    fn mkdir(
        &self,
        _a: &FilesActor,
        _r: &FilesMkdir,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn move_items(
        &self,
        _a: &FilesActor,
        _i: &[FilesMoveItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn delete(
        &self,
        _a: &FilesActor,
        _r: &FilesDelete,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn restore(
        &self,
        _a: &FilesActor,
        _r: &FilesRestore,
    ) -> Result<ClientFileMutationResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn save_version(
        &self,
        _a: &FilesActor,
        _r: &FilesSaveVersion,
    ) -> Result<ClientFileVersionResult, ProviderError> {
        Err(ProviderError::Unavailable("x".into()))
    }
    fn commit_external(
        &self,
        _a: &FilesActor,
        _i: &[FilesExternalItem],
    ) -> Result<ClientFileMutationResult, ProviderError> {
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

fn api_parts(
    cfg: ClientApiConfig,
    provider: Arc<dyn FilesProvider>,
    sink: RecordingSink,
) -> ClientApi {
    let api = ClientApi::with_parts(
        cfg,
        "operator",
        Arc::new(TestClock::new(1_000_000)) as Arc<dyn Clock>,
        Arc::new(sink),
    )
    .with_cursor_codec(codec())
    .with_files_provider(provider);
    api.sessions().insert(
        TOKEN.into(),
        ClientSession {
            session_id: "sess-raw".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: Some("csrf-raw".into()),
            expires_at: u64::MAX,
        },
        0,
    );
    api
}

fn hello_oid() -> String {
    advance_git::blob_oid_of_bytes(b"hello")
}

fn mint_ticket(api: &ClientApi, path: &str, write: bool) -> String {
    let env = if write {
        let oid = hello_oid();
        api.handle(
            ClientRequest::post(
                "/client/files:write-ticket",
                json!({"path": path, "intent": "edit", "base_oid": oid, "size": 5, "oid": oid}),
            )
            .with_session(TOKEN),
        )
    } else {
        api.handle(
            ClientRequest::post("/client/files:read-ticket", json!({ "path": path }))
                .with_session(TOKEN),
        )
    };
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

async fn bind(api: ClientApi) -> (ClientApiServer, std::net::SocketAddr, Arc<ClientApi>) {
    let api = Arc::new(api);
    let server = ClientApiServer::bind(Arc::clone(&api), 0).await.unwrap();
    let addr = server.local_addr();
    (server, addr, api)
}

#[tokio::test]
async fn raw_get_full_headers() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type"), Some("text/markdown"));
    assert!(resp.header("etag").is_some());
    assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
    assert!(resp.header("content-security-policy").is_some());
    assert_eq!(resp.body, b"hello");
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_active_types_attachment_and_real_type() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/page.html", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(resp.header("content-type"), Some("text/html"));
    let disp = resp.header("content-disposition").unwrap_or("");
    assert!(disp.starts_with("attachment"), "{disp}");
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_refuses_script_destinations() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Sec-Fetch-Dest", "script"),
        ],
        None,
    )
    .await;
    assert_eq!(resp.status, 403);
    assert_eq!(
        resp.envelope_details().first().map(String::as_str),
        Some("fetch_dest")
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_refuses_foreign_host() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET /client/files/raw/{ticket} HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("403") || text.contains("host_not_allowed"),
        "{text}"
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_content_disposition_encodes_attr_char_only() {
    let provider = MemoryFiles::ready();
    provider
        .bytes
        .lock()
        .unwrap()
        .insert("notes/a b.md".into(), b"x".to_vec());
    let api = api_parts(ClientApiConfig::default(), provider, RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a b.md", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    let disp = resp.header("content-disposition").unwrap_or("");
    assert!(disp.contains("%20"), "{disp}");
    assert!(!disp.contains("a b"), "{disp}");
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_range_matrix() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let empty = mint_ticket(&api, "notes/empty.txt", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Range", "bytes=0-1"),
        ],
        None,
    )
    .await;
    assert_eq!(resp.status, 206);
    assert_eq!(resp.body, b"he");
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{empty}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Range", "bytes=0-0"),
        ],
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty());
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_conditional_304() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let env = api.handle(
        ClientRequest::post("/client/files:read-ticket", json!({ "path": "notes/a.md" }))
            .with_session(TOKEN),
    );
    let ticket: ClientFileTicket = serde_json::from_value(env.data.unwrap()).unwrap();
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{}", ticket.ticket),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("If-None-Match", &format!("\"{}\"", ticket.etag)),
        ],
        None,
    )
    .await;
    assert_eq!(resp.status, 304);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_head_matches_get_without_body() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let get = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    let head = http(
        addr,
        "HEAD",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(head.status, get.status);
    assert_eq!(head.header("content-type"), get.header("content-type"));
    assert!(head.body.is_empty());
    assert!(!get.body.is_empty());
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_stale_after_change() {
    let provider = MemoryFiles::ready();
    *provider.identity_size.lock().unwrap() = Some(5);
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    provider
        .bytes
        .lock()
        .unwrap()
        .insert("notes/a.md".into(), b"changed!!".to_vec());
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(
        resp.envelope_details().first().map(String::as_str),
        Some("stale_ticket")
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_bounded_read_ahead() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    let payload = vec![b'x'; 200_000];
    std::fs::write(&path, &payload).unwrap();
    let provider = MemoryFiles::ready();
    provider
        .paths
        .lock()
        .unwrap()
        .insert("notes/a.md".into(), path);
    let api = api_parts(ClientApiConfig::default(), provider, RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.len(), payload.len());
    assert_eq!(resp.body, payload);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_get_historical_blob_and_range() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let env = api.handle(
        ClientRequest::post(
            "/client/files:read-ticket",
            json!({"path": "notes/a.md", "rev": OID}),
        )
        .with_session(TOKEN),
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let ticket: ClientFileTicket = serde_json::from_value(env.data.unwrap()).unwrap();
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{}", ticket.ticket),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Range", "bytes=1-2"),
        ],
        None,
    )
    .await;
    assert_eq!(resp.status, 206);
    assert_eq!(resp.body, b"ld");
    let _ = server.shutdown().await;
}

async fn quota_case(cfg: ClientApiConfig) {
    let api = api_parts(cfg, MemoryFiles::ready(), RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let _hold = api
        .hold_raw_read_slot("sess-raw")
        .expect("occupy one raw-read slot");
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(resp.status, 429, "{}", String::from_utf8_lossy(&resp.body));
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_read_capacity_429() {
    let mut cfg = ClientApiConfig::default();
    cfg.raw_read_slots = 1;
    quota_case(cfg).await;
}

#[tokio::test]
async fn raw_session_quota_429() {
    let mut cfg = ClientApiConfig::default();
    cfg.raw_session_read_slots = 1;
    cfg.raw_read_slots = 16;
    quota_case(cfg).await;
}

#[tokio::test]
async fn raw_routes_loopback_only() {
    let mut cfg = ClientApiConfig::default();
    cfg.remote_bind_enabled = true;
    let api = Arc::new(api_parts(cfg, MemoryFiles::ready(), RecordingSink::new()));
    let ticket = mint_ticket(api.as_ref(), "notes/a.md", false);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/client/files/raw/{ticket}"))
        .header("host", "127.0.0.1")
        .header("authorization", format!("Bearer {TOKEN}"))
        .extension(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 9))))
        .body(Body::empty())
        .unwrap();
    let resp = client_api_router(Arc::clone(&api))
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["details"][0], "loopback_only");
}

#[tokio::test]
async fn raw_origin_rules() {
    let mut cfg = ClientApiConfig::default();
    cfg.allowed_origins = vec!["http://127.0.0.1:1".into()];
    let api = api_parts(cfg, MemoryFiles::ready(), RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    let denied = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Origin", "http://evil.example"),
        ],
        None,
    )
    .await;
    assert_eq!(denied.status, 403);
    let allowed = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Origin", "http://127.0.0.1:1"),
        ],
        None,
    )
    .await;
    assert_eq!(allowed.status, 200);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_route_pre_auth_parity() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let (server, addr, _) = bind(api).await;
    let resp = http(addr, "GET", "/client/files/raw/not-a-ticket", &[], None).await;
    assert!(
        resp.status == 401 || resp.status == 404 || resp.status == 400,
        "{}",
        resp.status
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_route_does_not_shadow_catch_all() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        "/client/files/entries",
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("x-advance-api-version", "2026-09-17"),
        ],
        None,
    )
    .await;
    assert_ne!(resp.status, 404);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_success() {
    let provider = MemoryFiles::ready();
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(b"hello"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(provider.finish.load(Ordering::SeqCst), 1);
    assert!(resp.header("etag").is_some());
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_browser_csrf() {
    let mut cfg = ClientApiConfig::default();
    cfg.allowed_origins = vec!["http://127.0.0.1:1".into()];
    let api = api_parts(cfg, MemoryFiles::ready(), RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Origin", "http://127.0.0.1:1"),
        ],
        Some(b"hello"),
    )
    .await;
    assert_eq!(resp.status, 403);
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Origin", "http://127.0.0.1:1"),
            ("x-csrf-token", "csrf-raw"),
        ],
        Some(b"hello"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_length_and_integrity() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "PUT /client/files/raw/{ticket} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\nhello"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("content_length_required") || text.contains("400"),
        "{text}"
    );
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(b"hell"),
    )
    .await;
    assert_eq!(
        resp.envelope_details().first().map(String::as_str),
        Some("content_mismatch")
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_conflict_before_body_with_expect() {
    let provider = MemoryFiles::ready();
    *provider.already.lock().unwrap() = true;
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let started = std::time::Instant::now();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "PUT /client/files/raw/{ticket} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut buf))
        .await
        .expect("Expect refusal must not wait for the body")
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(800));
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("unchanged"), "{text}");
    assert_eq!(provider.finish.load(Ordering::SeqCst), 0);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_conflict_before_body_without_expect() {
    let provider = MemoryFiles::ready();
    *provider.already.lock().unwrap() = true;
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(b"hello"),
    )
    .await;
    assert_eq!(resp.status, 200);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(v["data"]["commit_state"], "unchanged");
    assert_eq!(provider.finish.load(Ordering::SeqCst), 0);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_already_current_is_no_commit() {
    let provider = MemoryFiles::ready();
    *provider.already.lock().unwrap() = true;
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(b"hello"),
    )
    .await;
    assert_eq!(provider.finish.load(Ordering::SeqCst), 0);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(v["data"]["commit_state"], "unchanged");
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_disconnect_cleans_staging() {
    let provider = MemoryFiles::ready();
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "PUT /client/files/raw/{ticket} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhe"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        drop(stream);
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while provider.abort.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("disconnect must abort the upload");
    assert!(provider.abort.load(Ordering::SeqCst) >= 1);
    assert_eq!(provider.finish.load(Ordering::SeqCst), 0);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_disconnect_during_finish_records_outcome() {
    let provider = MemoryFiles::ready();
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(b"hello"),
    )
    .await;
    assert_eq!(resp.status, 200);
    let replay = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(b"hello"),
    )
    .await;
    let v: Value = serde_json::from_slice(&replay.body).unwrap();
    assert!(v["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|w| w["code"] == "idempotent_replay"));
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_stall_aborts() {
    let mut cfg = ClientApiConfig::default();
    cfg.raw_stall_ms = 40;
    cfg.raw_min_rate_bps = 0;
    let api = api_parts(cfg, MemoryFiles::ready(), RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "PUT /client/files/raw/{ticket} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("upload_stalled") || text.contains("400"),
        "{text}"
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_put_min_rate_deadline() {
    let mut cfg = ClientApiConfig::default();
    cfg.raw_min_rate_bps = 1 << 20;
    cfg.raw_stall_ms = 60_000;
    let provider = MemoryFiles::ready();
    let api = api_parts(cfg, provider.clone(), RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", true);
    let (server, addr, _) = bind(api).await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "PUT /client/files/raw/{ticket} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nh"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("upload_stalled"), "{text}");
    assert_eq!(provider.finish.load(Ordering::SeqCst), 0);
    assert!(provider.abort.load(Ordering::SeqCst) >= 1);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_shutdown_ends_streams() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let (server, addr, _) = bind(api).await;
    let _ = server.shutdown().await;
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn raw_retire_ends_streams_and_revoke_all_kills_tickets() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, _addr, api) = bind(api).await;
    let retired = server.retire(Duration::from_millis(500)).await;
    api.sessions().revoke_all();
    let server = ClientApiServer::bind(retired.api, 0).await.unwrap();
    let addr = server.local_addr();
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert!(
        resp.status == 401
            || resp
                .envelope_details()
                .iter()
                .any(|d| d == "ticket_session_ended"),
        "{}",
        resp.status
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn logout_ends_inflight_raw_stream() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    std::fs::write(&path, vec![b'z'; 4 * 1024 * 1024]).unwrap();
    let provider = MemoryFiles::ready();
    provider
        .paths
        .lock()
        .unwrap()
        .insert("notes/a.md".into(), path);
    let api = api_parts(ClientApiConfig::default(), provider, RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, api) = bind(api).await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET /client/files/raw/{ticket} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut head = [0u8; 64];
    let n = stream.read(&mut head).await.unwrap();
    assert!(n > 0, "stream must start");
    api.sessions().revoke_all();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await;
    assert!(
        rest.len() + n < 4 * 1024 * 1024,
        "logout must cut the inflight Path stream"
    );
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_read_idle_timeout_frees_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    std::fs::write(&path, vec![b'y'; 4 * 1024 * 1024]).unwrap();
    let provider = MemoryFiles::ready();
    provider
        .paths
        .lock()
        .unwrap()
        .insert("notes/a.md".into(), path);
    let mut cfg = ClientApiConfig::default();
    cfg.raw_idle_ms = 80;
    cfg.raw_read_slots = 1;
    let api = api_parts(cfg, provider, RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let mut held = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET /client/files/raw/{ticket} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: keep-alive\r\n\r\n"
    );
    held.write_all(req.as_bytes()).await.unwrap();
    let mut peek = [0u8; 32];
    let _ = tokio::time::timeout(Duration::from_secs(1), held.read(&mut peek)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let second = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(
        second.status,
        200,
        "idle must free the only read slot: {}",
        String::from_utf8_lossy(&second.body)
    );
    drop(held);
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_route_through_client_api_router() {
    let api = Arc::new(api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    ));
    let ticket = mint_ticket(api.as_ref(), "notes/a.md", false);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/client/files/raw/{ticket}"))
        .header("host", "127.0.0.1")
        .header("authorization", format!("Bearer {TOKEN}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))))
        .body(Body::empty())
        .unwrap();
    let resp = client_api_router(Arc::clone(&api))
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"hello");
}

#[tokio::test]
async fn in_process_raw_route_requires_bearer() {
    let mut cfg = ClientApiConfig::default();
    cfg.session_admission = SessionAdmission::InProcessOnly;
    let api = api_parts(cfg, MemoryFiles::ready(), RecordingSink::new());
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[],
        None,
    )
    .await;
    assert_eq!(resp.status, 401);
    let resp = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let _ = server.shutdown().await;
}

#[tokio::test]
async fn raw_resume_with_fresh_ticket_and_if_range() {
    let api = api_parts(
        ClientApiConfig::default(),
        MemoryFiles::ready(),
        RecordingSink::new(),
    );
    let ticket = mint_ticket(&api, "notes/a.md", false);
    let (server, addr, api) = bind(api).await;
    let first = http(
        addr,
        "GET",
        &format!("/client/files/raw/{ticket}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Range", "bytes=0-1"),
        ],
        None,
    )
    .await;
    assert_eq!(first.body, b"he");
    let fresh = mint_ticket(api.as_ref(), "notes/a.md", false);
    let second = http(
        addr,
        "GET",
        &format!("/client/files/raw/{fresh}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Range", "bytes=2-4"),
            ("If-Range", first.header("etag").unwrap_or("")),
        ],
        None,
    )
    .await;
    assert_eq!(second.body, b"llo");
    let mismatch = http(
        addr,
        "GET",
        &format!("/client/files/raw/{fresh}"),
        &[
            ("Authorization", &format!("Bearer {TOKEN}")),
            ("Range", "bytes=2-4"),
            ("If-Range", "\"not-the-etag\""),
        ],
        None,
    )
    .await;
    assert_eq!(mismatch.status, 200);
    assert_eq!(mismatch.body, b"hello");
    let _ = server.shutdown().await;
}

fn mint_batch_ticket(api: &ClientApi, path: &str, batch: &str) -> String {
    let oid = hello_oid();
    let env = api.handle(
        ClientRequest::post(
            "/client/files:write-ticket",
            json!({
                "path": path,
                "intent": "create",
                "size": 5,
                "oid": oid,
                "batch": batch
            }),
        )
        .with_session(TOKEN),
    );
    assert!(env.is_ok(), "{:?}", env.error);
    let ticket: ClientFileTicket = serde_json::from_value(env.data.unwrap()).unwrap();
    ticket.ticket
}

#[tokio::test]
async fn raw_put_batch_answers_staged() {
    let provider = MemoryFiles::ready();
    let api = api_parts(
        ClientApiConfig::default(),
        provider.clone(),
        RecordingSink::new(),
    );
    let ticket = mint_batch_ticket(&api, "reports/a.md", "abcdefghijklmnop");
    let (server, addr, _) = bind(api).await;
    let resp = http(
        addr,
        "PUT",
        &format!("/client/files/raw/{ticket}"),
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(b"hello"),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(provider.finish.load(Ordering::SeqCst), 1);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(v["data"]["commit_state"], "staged");
    assert!(v["data"]["commit"].is_null());
    let _ = server.shutdown().await;
}
