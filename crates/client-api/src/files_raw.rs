//! Transport-owned GET/HEAD/PUT `/client/files/raw/{ticket}`.
//!
//! Not a `ClientApi` route: `handle()` answers `unknown_route` and `route_table()` does not list
//! it. Pre-auth is [`ClientApi::pre_auth_gate`] with audit path [`routes::TPL_FILES_RAW`].

use std::collections::HashMap;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST,
    ORIGIN,
};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_core::Stream;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::Semaphore;

use crate::audit::AuditEvent;
use crate::config::SessionAdmission;
use crate::envelope::{ClientEnvelope, ClientError, ClientErrorCode};
use crate::file_ticket::{self, FileTicketGrant, TicketMode};
use crate::files::detail::FilesFailure;
use crate::files::{
    FileReadSource, FileReadVersion, FileWriteTarget, FilesActor, FilesPath, PathUse, WriteCheck,
    WriteIntent,
};
use crate::idempotency::{Begin, IdempotencyOutcome, IdempotencyScope, Reservation};
use crate::provider::provider_or_unavailable;
use crate::request::{ClientRequest, Method};
use crate::routes;
use crate::session::{session_ref_hex, Scope};
use crate::transport::{envelope_response, TransportState};
use crate::ClientApi;

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; media-src data:; frame-ancestors 'self'; sandbox";
const REFUSED_FETCH_DEST: &[&str] = &[
    "script",
    "style",
    "worker",
    "sharedworker",
    "serviceworker",
    "audioworklet",
    "paintworklet",
    "xslt",
    "manifest",
    "json",
    "object",
    "embed",
    "report",
];

struct SessionRawUse {
    reads: u32,
    uploads: u32,
}

/// Listener + per-session raw-route slot table.
pub struct RawSlotTable {
    listener_reads: Arc<Semaphore>,
    listener_uploads: Arc<Semaphore>,
    max_session_reads: u32,
    max_session_uploads: u32,
    session: Mutex<HashMap<[u8; 32], SessionRawUse>>,
}

enum SlotKind {
    Read,
    Upload,
}

pub(crate) struct SlotGuard {
    table: Arc<RawSlotTable>,
    digest: [u8; 32],
    kind: SlotKind,
    _listener: tokio::sync::OwnedSemaphorePermit,
}

impl RawSlotTable {
    pub fn new(config: &crate::ClientApiConfig) -> Self {
        Self {
            listener_reads: Arc::new(Semaphore::new(config.raw_read_slots.max(1))),
            listener_uploads: Arc::new(Semaphore::new(config.raw_upload_slots.max(1))),
            max_session_reads: config.raw_session_read_slots.max(1) as u32,
            max_session_uploads: config.raw_session_upload_slots.max(1) as u32,
            session: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn acquire(
        self: &Arc<Self>,
        digest: [u8; 32],
        upload: bool,
    ) -> Result<SlotGuard, ClientError> {
        let (sem, kind, cap) = if upload {
            (
                Arc::clone(&self.listener_uploads),
                SlotKind::Upload,
                self.max_session_uploads,
            )
        } else {
            (
                Arc::clone(&self.listener_reads),
                SlotKind::Read,
                self.max_session_reads,
            )
        };
        let permit = sem.try_acquire_owned().map_err(|_| {
            FilesFailure::Capacity(if upload {
                crate::files::CapacityKind::RawUpload
            } else {
                crate::files::CapacityKind::RawRead
            })
            .into_client_error()
        })?;
        {
            let mut map = self.session.lock().unwrap_or_else(|e| e.into_inner());
            let use_ = map.entry(digest).or_insert(SessionRawUse {
                reads: 0,
                uploads: 0,
            });
            let current = if upload { use_.uploads } else { use_.reads };
            if current >= cap {
                return Err(FilesFailure::Capacity(if upload {
                    crate::files::CapacityKind::SessionUpload
                } else {
                    crate::files::CapacityKind::SessionRead
                })
                .into_client_error());
            }
            if upload {
                use_.uploads += 1;
            } else {
                use_.reads += 1;
            }
        }
        Ok(SlotGuard {
            table: Arc::clone(self),
            digest,
            kind,
            _listener: permit,
        })
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut map = self.table.session.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(use_) = map.get_mut(&self.digest) {
            match self.kind {
                SlotKind::Read => use_.reads = use_.reads.saturating_sub(1),
                SlotKind::Upload => use_.uploads = use_.uploads.saturating_sub(1),
            }
            if use_.reads == 0 && use_.uploads == 0 {
                map.remove(&self.digest);
            }
        }
    }
}

fn seed_request(
    _api: &ClientApi,
    headers: &HeaderMap,
    peer_loopback: bool,
    method: Method,
) -> ClientRequest {
    ClientRequest {
        api_version: headers
            .get("x-advance-api-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(crate::envelope::API_VERSION)
            .to_string(),
        method,
        path: routes::TPL_FILES_RAW.to_string(),
        session_token: bearer(headers),
        origin: headers
            .get(ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        csrf_token: headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        idempotency_key: headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        is_loopback_peer: peer_loopback,
        body: Value::Null,
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn host_allowed(headers: &HeaderMap, local: Option<SocketAddr>) -> bool {
    let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let host = host.trim();
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) if !host.starts_with('[') => (n, p.parse::<u16>().ok()),
        Some((n, p)) if host.starts_with('[') && n.ends_with(']') => (n, p.parse::<u16>().ok()),
        _ => (host, None),
    };
    let name_ok = matches!(
        name.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "[::1]" | "::1"
    );
    if !name_ok {
        return false;
    }
    if let (Some(local), Some(port)) = (local, port) {
        return port == local.port();
    }
    true
}

fn fetch_dest_refused(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-dest")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|d| REFUSED_FETCH_DEST.iter().any(|r| d.eq_ignore_ascii_case(r)))
}

fn content_disposition(filename: &str, attachment: bool) -> String {
    let kind = if attachment { "attachment" } else { "inline" };
    let encoded = percent_encode_attr(filename);
    format!("{kind}; filename*=UTF-8''{encoded}")
}

fn percent_encode_attr(name: &str) -> String {
    let mut out = String::new();
    for b in name.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn apply_safe_headers(
    builder: axum::http::response::Builder,
    content_type: &str,
    filename: &str,
    attachment: bool,
) -> axum::http::response::Builder {
    let attach = attachment || advance_shared_types::media_type::is_active_type(content_type);
    builder
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_DISPOSITION, content_disposition(filename, attach))
        .header("x-content-type-options", "nosniff")
        .header("content-security-policy", CSP)
        .header("cross-origin-resource-policy", "same-origin")
        .header("referrer-policy", "no-referrer")
        .header(CACHE_CONTROL, "no-store")
        .header("accept-ranges", "bytes")
}

fn filename_of(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

fn error_response(
    api: &ClientApi,
    request_id: &str,
    family: &str,
    method: &str,
    err: ClientError,
) -> Response {
    let mut resp = envelope_response(api.denied_for(request_id, family, method, err.clone()));
    if err.code == ClientErrorCode::StreamBackpressure {
        resp.headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
    }
    if err.details.first().map(String::as_str) == Some("range_not_satisfiable") {
        *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    }
    let _ = family;
    let _ = method;
    resp
}

struct Redeemed {
    request_id: String,
    family: String,
    _method: &'static str,
    grant: FileTicketGrant,
    session: crate::session::ClientSession,
}

fn redeem(
    api: &ClientApi,
    headers: &HeaderMap,
    peer_loopback: bool,
    local: Option<SocketAddr>,
    ticket: &str,
    want: TicketMode,
    method: &'static str,
) -> Result<Redeemed, Response> {
    let seed = seed_request(api, headers, peer_loopback, Method::Get);
    let pre = match api.pre_auth_gate(&seed) {
        Ok(p) => p,
        Err(env) => return Err(envelope_response(env)),
    };
    api.emit_audit(AuditEvent::new(
        "client_api.request",
        &pre.request_id,
        "files",
        method,
    ));
    if !peer_loopback {
        return Err(error_response(
            api,
            &pre.request_id,
            &pre.family,
            method,
            FilesFailure::LoopbackOnly.into_client_error(),
        ));
    }
    if !host_allowed(headers, local) {
        return Err(error_response(
            api,
            &pre.request_id,
            &pre.family,
            method,
            FilesFailure::HostNotAllowed.into_client_error(),
        ));
    }
    if fetch_dest_refused(headers) {
        return Err(error_response(
            api,
            &pre.request_id,
            &pre.family,
            method,
            FilesFailure::FetchDest.into_client_error(),
        ));
    }
    let now = api.now_millis();
    let codec = match api.cursor_codec() {
        Some(c) => c,
        None => {
            return Err(error_response(
                api,
                &pre.request_id,
                &pre.family,
                method,
                ClientError::new(ClientErrorCode::ModuleUnavailable, "provider not wired"),
            ))
        }
    };
    let grant = match file_ticket::open_file_ticket(codec.as_ref(), ticket, now) {
        Ok(g) => g,
        Err(e) => return Err(error_response(api, &pre.request_id, &pre.family, method, e)),
    };
    if grant.mode != want {
        return Err(error_response(
            api,
            &pre.request_id,
            &pre.family,
            method,
            FilesFailure::TicketInvalid.into_client_error(),
        ));
    }
    let session = match api
        .sessions()
        .get_valid_by_session_digest(&grant.session_digest, now)
    {
        Ok(s) => s,
        Err(ClientErrorCode::SessionExpired) | Err(ClientErrorCode::Unauthenticated) => {
            return Err(error_response(
                api,
                &pre.request_id,
                &pre.family,
                method,
                FilesFailure::TicketSessionEnded.into_client_error(),
            ))
        }
        Err(code) => {
            return Err(error_response(
                api,
                &pre.request_id,
                &pre.family,
                method,
                ClientError::new(code, "session"),
            ))
        }
    };
    if api.config().session_admission == SessionAdmission::InProcessOnly {
        match bearer(headers) {
            None => {
                return Err(error_response(
                    api,
                    &pre.request_id,
                    &pre.family,
                    method,
                    ClientError::new(ClientErrorCode::Unauthenticated, "missing session"),
                ))
            }
            Some(tok) => match api.sessions().get_valid(&tok, now) {
                Ok(live)
                    if session_ref_hex(&live.session_id)
                        == session_ref_hex(&session.session_id) => {}
                _ => {
                    return Err(error_response(
                        api,
                        &pre.request_id,
                        &pre.family,
                        method,
                        FilesFailure::TicketSessionEnded.into_client_error(),
                    ))
                }
            },
        }
    }
    let need = match want {
        TicketMode::Read => Scope::ReadInventory,
        TicketMode::Write => Scope::WriteEntities,
    };
    if !session.scopes.contains(&need) {
        return Err(error_response(
            api,
            &pre.request_id,
            &pre.family,
            method,
            ClientError::new(ClientErrorCode::Forbidden, "insufficient scope"),
        ));
    }
    Ok(Redeemed {
        request_id: pre.request_id,
        family: pre.family,
        _method: method,
        grant,
        session,
    })
}

fn parse_range(headers: &HeaderMap, size: u64) -> Result<(u64, u64, bool), ClientError> {
    let Some(raw) = headers.get("range").and_then(|v| v.to_str().ok()) else {
        return Ok((0, size, false));
    };
    let spec = raw
        .strip_prefix("bytes=")
        .ok_or_else(|| FilesFailure::RangeNotSatisfiable.into_client_error())?;
    if spec.contains(',') {
        return Err(FilesFailure::RangeNotSatisfiable.into_client_error());
    }
    let (start, end) = spec
        .split_once('-')
        .ok_or_else(|| FilesFailure::RangeNotSatisfiable.into_client_error())?;
    let (from, to) = if start.is_empty() {
        let suffix: u64 = end
            .parse()
            .map_err(|_| FilesFailure::RangeNotSatisfiable.into_client_error())?;
        if suffix == 0 || size == 0 {
            return Ok((0, 0, false));
        }
        let from = size.saturating_sub(suffix);
        (from, size)
    } else {
        let from: u64 = start
            .parse()
            .map_err(|_| FilesFailure::RangeNotSatisfiable.into_client_error())?;
        let to = if end.is_empty() {
            size
        } else {
            let inclusive: u64 = end
                .parse()
                .map_err(|_| FilesFailure::RangeNotSatisfiable.into_client_error())?;
            inclusive.saturating_add(1).min(size)
        };
        (from, to)
    };
    if size == 0 {
        return Ok((0, 0, false));
    }
    if from >= size || from > to {
        return Err(FilesFailure::RangeNotSatisfiable.into_client_error());
    }
    Ok((from, to, true))
}

fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim().trim_matches('"') == etag))
}

/// Strong If-Range only. Missing header → honor Range. Mismatch / date / weak → 200 full.
fn if_range_matches(headers: &HeaderMap, etag: &str) -> bool {
    let Some(raw) = headers.get("if-range").and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let token = raw.trim();
    if token.starts_with("W/") || !token.contains('"') {
        return false;
    }
    token.trim_matches('"') == etag
}

fn expect_continue(headers: &HeaderMap) -> bool {
    headers
        .get("expect")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
}

const RAW_READ_CHUNK: usize = 64 * 1024;
const RAW_READ_AHEAD: usize = 2;
const PUT_DRAIN_MAX: usize = 1024 * 1024;
const PUT_DRAIN_MS: u64 = 2_000;
const PUT_RATE_GRACE_MS: u64 = 50;

struct BytesRx(tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>);

impl Stream for BytesRx {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

async fn next_body_chunk(
    stream: &mut axum::body::BodyDataStream,
) -> Result<Option<Bytes>, axum::Error> {
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx))
        .await
        .transpose()
}

async fn source_len(source: &FileReadSource) -> Result<u64, ClientError> {
    match source {
        FileReadSource::Bytes(b) => Ok(b.len() as u64),
        FileReadSource::Path(p) => tokio::fs::metadata(p).await.map(|m| m.len()).map_err(|_| {
            ClientError::new(ClientErrorCode::ModuleUnavailable, "provider unavailable")
        }),
    }
}

fn stale_len(grant: &FileTicketGrant, size: u64) -> bool {
    grant.identity.is_some_and(|identity| identity.size != size)
}

fn stream_path(
    path: std::path::PathBuf,
    from: u64,
    len: u64,
    idle: Duration,
    api: Arc<ClientApi>,
    digest: [u8; 32],
    slot: SlotGuard,
) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(RAW_READ_AHEAD);
    tokio::spawn(async move {
        let _slot = slot;
        let sessions = api.sessions().clone();
        let run = async {
            let mut file = tokio::fs::File::open(&path).await?;
            file.seek(SeekFrom::Start(from)).await?;
            let mut left = len;
            let mut buf = vec![0u8; RAW_READ_CHUNK];
            while left > 0 {
                if !sessions.is_live_digest(&digest, api.now_millis()) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "session ended",
                    ));
                }
                let take = std::cmp::min(buf.len(), left as usize);
                let n = file.read(&mut buf[..take]).await?;
                if n == 0 {
                    break;
                }
                left = left.saturating_sub(n as u64);
                match tokio::time::timeout(idle, tx.send(Ok(Bytes::copy_from_slice(&buf[..n]))))
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => {
                        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle"))
                    }
                }
            }
            Ok(())
        };
        if let Err(e) = run.await {
            let _ = tx.try_send(Err(e));
        }
    });
    Body::from_stream(BytesRx(rx))
}

async fn drain_or_expect(request: Request<Body>, expect: bool) {
    if expect {
        return;
    }
    let body = request.into_body();
    let _ = tokio::time::timeout(
        Duration::from_millis(PUT_DRAIN_MS),
        to_bytes(body, PUT_DRAIN_MAX),
    )
    .await;
}

async fn raw_get_or_head(
    state: TransportState,
    peer: Option<std::net::SocketAddr>,
    ticket: String,
    request: Request<Body>,
    head: bool,
) -> Response {
    let api = state.api;
    let peer_loopback = peer.map(|p| p.ip().is_loopback()).unwrap_or(false);
    let local = state.local_addr;
    let method = if head { "RawHead" } else { "RawGet" };
    let redeemed = match redeem(
        api.as_ref(),
        request.headers(),
        peer_loopback,
        local,
        &ticket,
        TicketMode::Read,
        method,
    ) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let slots = api.raw_slots();
    let slot = match slots.acquire(redeemed.grant.session_digest, false) {
        Ok(g) => g,
        Err(e) => {
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                method,
                e,
            )
        }
    };
    let provider = match provider_or_unavailable(api.files_provider_slot()) {
        Ok(p) => p,
        Err(e) => {
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                method,
                e,
            )
        }
    };
    let path = match FilesPath::parse(&redeemed.grant.path, PathUse::Read) {
        Ok(p) => p,
        Err(e) => {
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                method,
                e,
            )
        }
    };
    let version = FileReadVersion {
        path: redeemed.grant.path.clone(),
        size: redeemed.grant.size,
        content_type: advance_shared_types::media_type::content_type_for_name(&redeemed.grant.path)
            .to_string(),
        oid: redeemed.grant.oid.clone(),
        identity: redeemed.grant.identity,
        rev: redeemed.grant.rev.clone(),
        already_current: false,
    };
    let source = match provider.open_read(&path, &version) {
        Ok(s) => s,
        Err(e) => {
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                method,
                e.into_client_error(),
            )
        }
    };
    let size = match source_len(&source).await {
        Ok(n) => n,
        Err(e) => {
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                method,
                e,
            )
        }
    };
    if stale_len(&redeemed.grant, size) {
        return error_response(
            api.as_ref(),
            &redeemed.request_id,
            &redeemed.family,
            method,
            FilesFailure::StaleTicket.into_client_error(),
        );
    }
    let etag = redeemed.grant.etag();
    if if_none_match(request.headers(), &etag) {
        return apply_safe_headers(
            Response::builder().status(StatusCode::NOT_MODIFIED),
            &version.content_type,
            filename_of(&redeemed.grant.path),
            redeemed.grant.attachment,
        )
        .header(ETAG, format!("\"{etag}\""))
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    let honor_range = if_range_matches(request.headers(), &etag);
    let (from, to, partial) = if honor_range {
        match parse_range(request.headers(), size) {
            Ok(v) => v,
            Err(e) => {
                return error_response(
                    api.as_ref(),
                    &redeemed.request_id,
                    &redeemed.family,
                    method,
                    e,
                )
            }
        }
    } else {
        (0, size, false)
    };
    let status = if partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut builder = apply_safe_headers(
        Response::builder().status(status),
        &version.content_type,
        filename_of(&redeemed.grant.path),
        redeemed.grant.attachment,
    )
    .header(ETAG, format!("\"{etag}\""))
    .header(CONTENT_LENGTH, (to.saturating_sub(from)).to_string());
    if partial {
        builder = builder.header(
            "content-range",
            format!("bytes {from}-{}/{}", to.saturating_sub(1), size),
        );
    }
    if head {
        return builder
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    let body = match source {
        FileReadSource::Bytes(bytes) => {
            let _hold = slot;
            let slice = bytes
                .get(from as usize..to as usize)
                .unwrap_or(&[])
                .to_vec();
            Body::from(slice)
        }
        FileReadSource::Path(path) => {
            let idle = Duration::from_millis(api.config().raw_idle_ms.max(1));
            stream_path(
                path,
                from,
                to.saturating_sub(from),
                idle,
                Arc::clone(&api),
                redeemed.grant.session_digest,
                slot,
            )
        }
    };
    builder
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub async fn raw_get(
    State(state): State<TransportState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(ticket): Path<String>,
    request: Request<Body>,
) -> Response {
    raw_get_or_head(state, Some(peer), ticket, request, false).await
}

pub async fn raw_head(
    State(state): State<TransportState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(ticket): Path<String>,
    request: Request<Body>,
) -> Response {
    raw_get_or_head(state, Some(peer), ticket, request, true).await
}

pub async fn raw_put(
    State(state): State<TransportState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(ticket): Path<String>,
    request: Request<Body>,
) -> Response {
    let api = state.api;
    let peer_loopback = peer.ip().is_loopback();
    let local = state.local_addr;
    let headers = request.headers().clone();
    let redeemed = match redeem(
        api.as_ref(),
        &headers,
        peer_loopback,
        local,
        &ticket,
        TicketMode::Write,
        "RawPut",
    ) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let slots = api.raw_slots();
    let _slot = match slots.acquire(redeemed.grant.session_digest, true) {
        Ok(g) => g,
        Err(e) => {
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                e,
            )
        }
    };
    let origin = headers.get(ORIGIN).and_then(|v| v.to_str().ok());
    if origin.is_some() {
        let csrf = headers.get("x-csrf-token").and_then(|v| v.to_str().ok());
        if csrf != redeemed.session.csrf_token.as_deref() {
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                ClientError::new(ClientErrorCode::CsrfInvalid, "csrf"),
            );
        }
    }
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let Some(declared) = declared else {
        return error_response(
            api.as_ref(),
            &redeemed.request_id,
            &redeemed.family,
            "RawPut",
            FilesFailure::ContentLengthRequired.into_client_error(),
        );
    };
    if declared != redeemed.grant.size {
        return error_response(
            api.as_ref(),
            &redeemed.request_id,
            &redeemed.family,
            "RawPut",
            FilesFailure::ContentMismatch.into_client_error(),
        );
    }
    if declared > api.config().max_upload_bytes {
        return error_response(
            api.as_ref(),
            &redeemed.request_id,
            &redeemed.family,
            "RawPut",
            FilesFailure::UploadTooLarge.into_client_error(),
        );
    }
    let scope = IdempotencyScope {
        principal: redeemed.session.principal.id.clone(),
        method: Method::Post,
        family: "files.raw".into(),
        key: redeemed.grant.nonce_hex(),
    };
    let now = api.now_millis();
    let begin = api.files_raw_idempotency().begin_fingerprinted(
        &scope,
        nonce_fingerprint(&redeemed.grant.nonce),
        now,
    );
    match begin {
        Begin::Replay(record) => replay_put(&redeemed, record.outcome),
        Begin::InProgress => error_response(
            api.as_ref(),
            &redeemed.request_id,
            &redeemed.family,
            "RawPut",
            ClientError::new(ClientErrorCode::IdempotencyInProgress, "in progress"),
        ),
        Begin::Conflict => error_response(
            api.as_ref(),
            &redeemed.request_id,
            &redeemed.family,
            "RawPut",
            ClientError::new(ClientErrorCode::IdempotencyConflict, "conflict"),
        ),
        Begin::Reserved(reservation) => {
            finish_put(api, redeemed, request, reservation, declared).await
        }
    }
}

fn replay_put(redeemed: &Redeemed, outcome: IdempotencyOutcome) -> Response {
    match outcome {
        IdempotencyOutcome::Success(data) => {
            let etag = data
                .get("oid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut resp = envelope_response(ClientEnvelope::ok(
                redeemed.request_id.clone(),
                data,
                vec![crate::envelope::ClientWarning::new(
                    "idempotent_replay",
                    "replayed prior outcome",
                )],
            ));
            if !etag.is_empty() {
                resp.headers_mut().insert(
                    ETAG,
                    HeaderValue::from_str(&format!("\"{etag}\""))
                        .unwrap_or(HeaderValue::from_static("\"\"")),
                );
            }
            resp
        }
        IdempotencyOutcome::Error(err) => envelope_response(ClientEnvelope::error(
            redeemed.request_id.clone(),
            err,
            vec![crate::envelope::ClientWarning::new(
                "idempotent_replay",
                "replayed prior outcome",
            )],
        )),
    }
}

async fn finish_put(
    api: Arc<ClientApi>,
    redeemed: Redeemed,
    request: Request<Body>,
    reservation: Reservation,
    declared: u64,
) -> Response {
    let provider = match provider_or_unavailable(api.files_provider_slot()) {
        Ok(p) => p,
        Err(e) => {
            drop(reservation);
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                e,
            );
        }
    };
    let intent = redeemed
        .grant
        .intent
        .write_intent()
        .unwrap_or(WriteIntent::Upload);
    let path = match FilesPath::parse(&redeemed.grant.path, intent.path_use()) {
        Ok(p) => p,
        Err(e) => {
            drop(reservation);
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                e,
            );
        }
    };
    let oid = match redeemed.grant.oid.clone() {
        Some(o) => o,
        None => {
            drop(reservation);
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                FilesFailure::TicketInvalid.into_client_error(),
            );
        }
    };
    let actor = FilesActor {
        principal_id: redeemed.session.principal.id.clone(),
        os_user: redeemed.session.principal.os_user.clone(),
        platform: redeemed.session.platform,
        session_ref: session_ref_hex(&redeemed.session.session_id),
    };
    let target = FileWriteTarget {
        path: path.clone(),
        intent,
        size: declared,
        oid: oid.clone(),
        base_oid: redeemed.grant.base_oid.clone(),
        batch: redeemed.grant.batch.clone(),
    };
    let expect = expect_continue(request.headers());
    match provider.check_write(&actor, &target) {
        Ok(WriteCheck::AlreadyCurrent { oid: current, .. }) => {
            drain_or_expect(request, expect).await;
            let result = crate::files::ClientFileWriteResult {
                path: path.as_str().to_string(),
                oid: current.as_str().to_string(),
                size: declared,
                versioned: true,
                versioned_reason: None,
                commit_state: "unchanged".into(),
                commit: None,
            };
            let value = serde_json::to_value(&result).expect("serializes");
            reservation.commit(value.clone(), redeemed.request_id.clone(), api.now_millis());
            let mut resp = envelope_response(ClientEnvelope::ok(
                redeemed.request_id.clone(),
                value,
                vec![],
            ));
            resp.headers_mut().insert(
                ETAG,
                HeaderValue::from_str(&format!("\"{}\"", current.as_str()))
                    .unwrap_or(HeaderValue::from_static("\"\"")),
            );
            return resp;
        }
        Ok(WriteCheck::Ok { .. }) => {}
        Err(e) => {
            let err = e.into_client_error();
            if err.details.first().map(String::as_str) == Some("stale_base") {
                reservation.commit_error(
                    err.clone(),
                    redeemed.request_id.clone(),
                    vec![],
                    api.now_millis(),
                );
            } else {
                drop(reservation);
            }
            drain_or_expect(request, expect).await;
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                err,
            );
        }
    }
    let mut sink = match provider.begin_upload(&actor, &target) {
        Ok(s) => s,
        Err(e) => {
            drop(reservation);
            drain_or_expect(request, expect).await;
            return error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                e.into_client_error(),
            );
        }
    };
    let stall = Duration::from_millis(api.config().raw_stall_ms.max(1));
    let rate_deadline = if api.config().raw_min_rate_bps > 0 {
        Duration::from_millis(
            declared
                .saturating_mul(1000)
                .saturating_div(api.config().raw_min_rate_bps)
                .max(1)
                .saturating_add(PUT_RATE_GRACE_MS),
        )
    } else {
        Duration::from_secs(86_400)
    };
    let mut stream = request.into_body().into_data_stream();
    let mut hasher = advance_git::BlobHasher::new(declared);
    let mut got = 0u64;
    let started = Instant::now();
    let put_fail = |api: &ClientApi,
                    redeemed: &Redeemed,
                    provider: &Arc<dyn crate::provider::FilesProvider>,
                    handle: crate::files::FileUploadHandle,
                    reservation: Reservation,
                    err: ClientError| {
        provider.abort_upload(handle);
        drop(reservation);
        error_response(api, &redeemed.request_id, &redeemed.family, "RawPut", err)
    };
    loop {
        if got < declared && started.elapsed() >= rate_deadline {
            return put_fail(
                api.as_ref(),
                &redeemed,
                &provider,
                sink.handle.clone(),
                reservation,
                FilesFailure::UploadStalled.into_client_error(),
            );
        }
        let wait = stall.min(rate_deadline.saturating_sub(started.elapsed()));
        match tokio::time::timeout(
            wait.max(Duration::from_millis(1)),
            next_body_chunk(&mut stream),
        )
        .await
        {
            Err(_) => {
                return put_fail(
                    api.as_ref(),
                    &redeemed,
                    &provider,
                    sink.handle.clone(),
                    reservation,
                    FilesFailure::UploadStalled.into_client_error(),
                );
            }
            Ok(Err(_)) => {
                return put_fail(
                    api.as_ref(),
                    &redeemed,
                    &provider,
                    sink.handle.clone(),
                    reservation,
                    FilesFailure::ContentMismatch.into_client_error(),
                );
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(chunk))) => {
                got = got.saturating_add(chunk.len() as u64);
                if got > declared {
                    return put_fail(
                        api.as_ref(),
                        &redeemed,
                        &provider,
                        sink.handle.clone(),
                        reservation,
                        FilesFailure::UploadTooLarge.into_client_error(),
                    );
                }
                hasher.update(&chunk);
                if let Err(e) = sink.write_all(&chunk) {
                    return put_fail(
                        api.as_ref(),
                        &redeemed,
                        &provider,
                        sink.handle.clone(),
                        reservation,
                        e.into_client_error(),
                    );
                }
            }
        }
    }
    if got != declared {
        return put_fail(
            api.as_ref(),
            &redeemed,
            &provider,
            sink.handle.clone(),
            reservation,
            FilesFailure::ContentMismatch.into_client_error(),
        );
    }
    match hasher.finish() {
        Ok(hashed) if hashed == oid.as_str() => {}
        _ => {
            return put_fail(
                api.as_ref(),
                &redeemed,
                &provider,
                sink.handle.clone(),
                reservation,
                FilesFailure::ContentMismatch.into_client_error(),
            );
        }
    }
    match provider.finish_upload(&actor, &target, sink.handle.clone()) {
        Ok(result) => {
            let value = serde_json::to_value(&result).expect("serializes");
            reservation.commit(value.clone(), redeemed.request_id.clone(), api.now_millis());
            let mut resp = envelope_response(ClientEnvelope::ok(
                redeemed.request_id.clone(),
                value,
                vec![],
            ));
            resp.headers_mut().insert(
                ETAG,
                HeaderValue::from_str(&format!("\"{}\"", result.oid))
                    .unwrap_or(HeaderValue::from_static("\"\"")),
            );
            resp
        }
        Err(e) => {
            let err = e.into_client_error();
            reservation.commit_error(
                err.clone(),
                redeemed.request_id.clone(),
                vec![],
                api.now_millis(),
            );
            error_response(
                api.as_ref(),
                &redeemed.request_id,
                &redeemed.family,
                "RawPut",
                err,
            )
        }
    }
}

fn nonce_fingerprint(nonce: &[u8; 16]) -> [u8; 32] {
    let mut fp = [0u8; 32];
    fp[..16].copy_from_slice(nonce);
    fp
}
