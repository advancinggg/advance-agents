//! Buffered and streaming HTTP executor seams with mock + reqwest implementations.
//!
//! `HttpExecutor` is the buffered step-7 "actually do the HTTP" abstraction;
//! `HttpStreamExecutor` returns a response head plus pull-based wire chunks for
//! CONTRACT-233. `MockHttpExecutor` serves deterministic tests, while
//! `ReqwestHttpExecutor` is the shipped production implementation for both
//! seams (manual redirect loop, connect-time SSRF resolver, response limits and
//! transport deadlines).
//!
//! `RedirectCheck::check` is the per-hop async revalidation hook. The
//! `DefaultRedirectCheck` impl wraps the chain's allowlist + leak_detector +
//! ssrf_guard fields and is constructed per-execute.

use crate::ssrf::{build_forbidden_table, normalize_ip};
use advance_shared_types::security_validator::Allowlist;
use advance_shared_types::security_validator::{
    CidrClass, HttpMethod, HttpRequest, HttpResponse, HttpResponseHead, LeakDetector,
    RedirectCheck, RedirectRejectReason, ScanContext, SsrfGuard,
};
use async_trait::async_trait;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Executor-layer error kind. Distinct from `HttpError`; the security chain
/// converts these into `HttpError::Transport` / `RedirectRejected` etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorError {
    /// A redirect was rejected by `RedirectCheck::check`.
    RedirectRejected {
        reason: RedirectRejectReason,
        target: String,
    },
    /// Underlying transport failure (DNS, TLS, connect, etc.).
    Transport,
    /// Request timeout.
    Timeout,
}

/// Async HTTP executor. Production impl wraps `reqwest`; test impl uses
/// `MockHttpExecutor`.
#[async_trait]
pub trait HttpExecutor: Send + Sync {
    /// Execute the request, following redirects. For each redirect target,
    /// invoke `redirect_check.check(target_url, target_headers).await` and
    /// abort with `ExecutorError::RedirectRejected` if the check returns Err.
    /// Credentials are NOT re-injected on redirects (chain invariant 3).
    async fn execute(
        &self,
        req: &HttpRequest,
        redirect_check: std::sync::Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError>;
}

/// Raw wire-chunk pull object returned by [`HttpStreamExecutor::execute_stream`].
/// Chunks are PRE-scan transport bytes — the security chain's streaming wrapper
/// (`ScanningWireStream`, CONTRACT-233) is the only intended consumer.
/// After the first `Some(Err(_))` or `None`, subsequent calls return `None`.
///
/// # Implementer invariant
///
/// Both dropping this object and cancelling/dropping a future returned by
/// [`WireChunkStream::next`] MUST be bounded, non-blocking and panic-free. They
/// MUST NOT perform network I/O or wait for transport/application progress.
/// The security chain uses synchronous guarded destruction and timer
/// cancellation; in-process Rust cannot pre-empt or safely reclaim a custom
/// destructor/future-drop that never returns. This seam invariant is one
/// specialization of `with_stream_executor`'s transitive CONTRACT-233
/// composition precondition. The shipped Mock and Reqwest implementations
/// satisfy it.
#[async_trait]
pub trait WireChunkStream: Send {
    async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>>;
}

/// cap-http-OWNED streaming transport seam (ADR 2026-07-22 slice S3). Public
/// only so a composition root can name the trait when wiring
/// `with_stream_executor`; it is NOT part of the shared-types CONTRACT-233
/// surface, is not re-exported at the crate root, and its chunks are PRE-scan
/// transport bytes — consuming them anywhere but
/// `DefaultHttpSecurityChain::execute_streaming`'s scanning wrapper bypasses
/// the MODULE-012 §2.9 scan contract.
///
/// Deliberately NOT a method on the shared [`HttpExecutor`] trait (ADR Option-3
/// rejection): a defaulted streaming method would silently grant the fail-closed
/// `NotWiredHttpExecutor` sentinel a streaming path, and a required one would
/// break the shared trait's implementors. Only `ReqwestHttpExecutor` and
/// `MockHttpExecutor` implement this; `DefaultHttpSecurityChain` consumes it via
/// the opt-in `with_stream_executor` builder (unwired chains fail CLOSED).
///
/// Head-first: the call resolves redirects (same per-hop `redirect_check`
/// revalidation + zero-carry contract as [`HttpExecutor::execute`]) and returns
/// the final response HEAD plus the raw body chunk stream. There is NO
/// reconnect / `Last-Event-ID` / resume surface (it would replay the injected
/// auth header — MODULE-012 §2.9 term 7).
///
/// # Implementer invariant
///
/// Cancelling or dropping the future returned by [`execute_stream`](Self::execute_stream)
/// MUST be bounded, non-blocking and panic-free. This guarantee is transitive
/// over state owned by that future, including any nested
/// [`RedirectCheck::check`] future. Cancellation/destruction MUST NOT perform
/// network I/O or wait for transport/application progress. Dropping the
/// executor object itself and the returned [`WireChunkStream`] is subject to
/// the same bound. These seam rules specialize `with_stream_executor`'s
/// broader CONTRACT-233 composition precondition; custom implementations that
/// violate it are non-conforming, and spawning unbounded cleanup workers
/// cannot make a non-returning in-process destructor safe. An implementation
/// MUST also treat any `RedirectCheck::check` error as a terminal hop result
/// and MUST NOT dispatch another redirect callback or network request after
/// that error. The default streaming chain uses a deadline-aware redirect
/// checker whose late-stage sentinel relies on this fail-stop rule; the outer
/// HEAD wrapper then classifies the result as `Transport(Timeout)`.
#[async_trait]
pub trait HttpStreamExecutor: Send + Sync {
    async fn execute_stream(
        &self,
        req: &HttpRequest,
        redirect_check: std::sync::Arc<dyn RedirectCheck>,
    ) -> Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError>;
}

/// In-process mock executor for integration tests.
///
/// Programmatic shape: configure a sequence of (request-matcher → response-or-redirect)
/// fixtures. The mock walks the redirect chain by re-invoking itself with the
/// redirect target until either a non-redirect response is hit, the
/// redirect-check fails, or the redirect chain exceeds the max length.
///
/// Tests use builder methods (`.with_response`, `.with_redirect`) to set up
/// the fixture; the test harness can inspect `recorded_requests` after
/// execute to verify what URL/headers the mock saw.
pub struct MockHttpExecutor {
    fixtures: Mutex<Vec<MockFixture>>,
    /// Records every (URL, headers) combination the mock observed during
    /// execute (includes redirect targets). Test inspectors check this.
    pub recorded_requests: Mutex<Vec<(String, Vec<(String, String)>)>>,
    /// Records every (URL, headers) the mock invoked `redirect_check.check`
    /// against — useful for verifying T12g cold-cache redirect resolution.
    pub redirect_check_invocations: Mutex<Vec<(String, Vec<(String, String)>)>>,
    pub max_redirects: usize,
    /// S4 test seam: url_prefix → gate for Stream fixtures (feature-gated side
    /// table so the ungated default path is unaffected by the feature).
    #[cfg(feature = "test-stream-gate")]
    stream_gates: Mutex<Vec<(String, StreamGate)>>,
}

#[derive(Clone)]
enum MockFixture {
    /// Match on URL prefix; respond with the given response.
    Response {
        url_prefix: String,
        response: HttpResponse,
    },
    /// Match on URL prefix; redirect to the given target URL with the given
    /// optional headers.
    Redirect {
        url_prefix: String,
        target: String,
        target_headers: Vec<(String, String)>,
    },
    /// Match on URL prefix; stream the given head + scripted body chunks
    /// (ADR 2026-07-22 slice S3 — the CONTRACT-233 witness foundation the
    /// MODULE-009-AC-20 flip is gated on). The buffered `execute` path treats
    /// this fixture as head + concatenated chunks so the enum stays total.
    Stream {
        url_prefix: String,
        head: HttpResponseHead,
        chunks: Vec<Vec<u8>>,
    },
    /// grok-repass Item 2e: error-capable sibling of `Stream` — each scripted
    /// pull is a `Result`, so a mid-stream `ExecutorError` is scriptable
    /// (the fault vocabulary fail-closed streaming witnesses need). Gated
    /// behind `test-stream-gate` per the S4 CONTRACT-233 precedent recorded
    /// at docs/ARCHITECTURE.md (test-only additions to this executor sit
    /// behind the feature and ship in no production composition); `Stream`
    /// itself stays byte-identical — its shape is named verbatim in four
    /// frozen doc anchors.
    #[cfg(feature = "test-stream-gate")]
    StreamResults {
        url_prefix: String,
        head: HttpResponseHead,
        chunks: Vec<Result<Vec<u8>, ExecutorError>>,
    },
}

impl MockHttpExecutor {
    pub fn new() -> Self {
        Self {
            fixtures: Mutex::new(Vec::new()),
            recorded_requests: Mutex::new(Vec::new()),
            redirect_check_invocations: Mutex::new(Vec::new()),
            max_redirects: 10,
            #[cfg(feature = "test-stream-gate")]
            stream_gates: Mutex::new(Vec::new()),
        }
    }

    pub fn with_response(self, url_prefix: &str, response: HttpResponse) -> Self {
        self.fixtures.lock().unwrap().push(MockFixture::Response {
            url_prefix: url_prefix.to_string(),
            response,
        });
        self
    }

    pub fn with_redirect(
        self,
        url_prefix: &str,
        target: &str,
        target_headers: Vec<(String, String)>,
    ) -> Self {
        self.fixtures.lock().unwrap().push(MockFixture::Redirect {
            url_prefix: url_prefix.to_string(),
            target: target.to_string(),
            target_headers,
        });
        self
    }

    /// Streaming fixture (`MockFixture::Stream { head, chunks }`): the mock's
    /// `execute_stream` yields `head` then the scripted `chunks` one per pull.
    /// S4 gated stream fixture: like `with_stream`, but every pull (incl. the
    /// terminal `None`) awaits a permit the returned `StreamGate` releases.
    #[cfg(feature = "test-stream-gate")]
    pub fn with_gated_stream(
        self,
        url_prefix: &str,
        head: HttpResponseHead,
        chunks: Vec<Vec<u8>>,
    ) -> (Self, StreamGate) {
        let gate = StreamGate::new();
        self.stream_gates
            .lock()
            .unwrap()
            .push((url_prefix.to_string(), gate.clone()));
        let me = self.with_stream(url_prefix, head, chunks);
        (me, gate)
    }

    pub fn with_stream(
        self,
        url_prefix: &str,
        head: HttpResponseHead,
        chunks: Vec<Vec<u8>>,
    ) -> Self {
        self.fixtures.lock().unwrap().push(MockFixture::Stream {
            url_prefix: url_prefix.to_string(),
            head,
            chunks,
        });
        self
    }

    /// grok-repass Item 2e: error-capable streaming fixture
    /// (`MockFixture::StreamResults`). `execute_stream` yields the scripted
    /// `Result`s one per pull (terminal is absorbing after the first `Err`
    /// or exhaustion, per the `WireChunkStream` doc); buffered `execute`
    /// returns head + concatenated chunks when all are `Ok`, else the first
    /// scripted `Err`.
    #[cfg(feature = "test-stream-gate")]
    pub fn with_stream_results(
        self,
        url_prefix: &str,
        head: HttpResponseHead,
        chunks: Vec<Result<Vec<u8>, ExecutorError>>,
    ) -> Self {
        self.fixtures
            .lock()
            .unwrap()
            .push(MockFixture::StreamResults {
                url_prefix: url_prefix.to_string(),
                head,
                chunks,
            });
        self
    }

    fn match_fixture(&self, url: &str) -> Option<MockFixture> {
        let fixtures = self.fixtures.lock().unwrap();
        for fx in fixtures.iter() {
            let prefix = match fx {
                MockFixture::Response { url_prefix, .. } => url_prefix,
                MockFixture::Redirect { url_prefix, .. } => url_prefix,
                MockFixture::Stream { url_prefix, .. } => url_prefix,
                #[cfg(feature = "test-stream-gate")]
                MockFixture::StreamResults { url_prefix, .. } => url_prefix,
            };
            if url.starts_with(prefix) {
                return Some(fx.clone());
            }
        }
        None
    }
}

impl Default for MockHttpExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpExecutor for MockHttpExecutor {
    async fn execute(
        &self,
        req: &HttpRequest,
        redirect_check: std::sync::Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        let mut current_url = req.url.clone();
        let mut current_headers = req.headers.clone();
        let mut hops = 0usize;

        loop {
            self.recorded_requests
                .lock()
                .unwrap()
                .push((current_url.clone(), current_headers.clone()));

            let fixture = self
                .match_fixture(&current_url)
                .ok_or(ExecutorError::Transport)?;

            match fixture {
                MockFixture::Response { response, .. } => return Ok(response),
                MockFixture::Stream { head, chunks, .. } => {
                    // Buffered view of a streaming fixture: head + concatenated
                    // chunks (keeps the fixture enum total for both paths).
                    return Ok(HttpResponse {
                        status: head.status,
                        headers: head.headers,
                        body: chunks.concat(),
                    });
                }
                #[cfg(feature = "test-stream-gate")]
                MockFixture::StreamResults { head, chunks, .. } => {
                    // Buffered view mirrors Stream: all-Ok → head + concat;
                    // otherwise the first scripted Err fails the whole call.
                    let mut body = Vec::new();
                    for chunk in chunks {
                        match chunk {
                            Ok(bytes) => body.extend_from_slice(&bytes),
                            Err(e) => return Err(e),
                        }
                    }
                    return Ok(HttpResponse {
                        status: head.status,
                        headers: head.headers,
                        body,
                    });
                }
                MockFixture::Redirect {
                    target,
                    target_headers,
                    ..
                } => {
                    if hops >= self.max_redirects {
                        return Err(ExecutorError::Transport);
                    }
                    hops += 1;

                    self.redirect_check_invocations
                        .lock()
                        .unwrap()
                        .push((target.clone(), target_headers.clone()));

                    redirect_check
                        .check(&target, &target_headers)
                        .await
                        .map_err(|reason| ExecutorError::RedirectRejected {
                            reason,
                            target: target.clone(),
                        })?;

                    // Follow the redirect — note credentials are NOT
                    // re-injected (chain invariant 3); we walk with
                    // target_headers ONLY (no Authorization carried over).
                    current_url = target;
                    current_headers = target_headers;
                }
            }
        }
    }
}

/// Scripted chunk stream backing `MockHttpExecutor`'s streaming fixtures.
/// Yields the scripted chunks in order, then `None`. Terminal is absorbing.
/// Ungated (default): zero-await immediate (regression pin per plan).
struct ScriptedChunkStream {
    chunks: std::vec::IntoIter<Vec<u8>>,
}

#[async_trait]
impl WireChunkStream for ScriptedChunkStream {
    async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
        self.chunks.next().map(Ok)
    }
}

// S4 (feature "test-stream-gate"): REAL pull gate. Every `next()` — including
// the terminal `None` pull after the last chunk — awaits one semaphore permit
// the TEST releases via `StreamGate::release`. Drop-safe: dropping the stream or
// a pending `next()` future acquires nothing and blocks nothing. This is a
// sanctioned test-only deviation from the wire-seam "no waiting for application
// progress" precondition (documented; the ungated default path stays zero-await
// regardless of the feature).
#[cfg(feature = "test-stream-gate")]
#[derive(Clone)]
pub struct StreamGate(std::sync::Arc<tokio::sync::Semaphore>);

#[cfg(feature = "test-stream-gate")]
impl StreamGate {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(std::sync::Arc::new(tokio::sync::Semaphore::new(0)))
    }
    /// Release `n` pulls (each chunk consumes one; the pull AFTER the last chunk
    /// — the terminal `None` — consumes one more).
    pub fn release(&self, n: usize) {
        self.0.add_permits(n);
    }
    /// Ungate entirely.
    pub fn open(&self) {
        self.0.add_permits(1 << 20);
    }
}

/// grok-repass Item 2e: the error-capable sibling of `ScriptedChunkStream`,
/// backing `MockFixture::StreamResults`. Yields each scripted `Result` in
/// order; terminal is ABSORBING after the first `Err` or exhaustion, per the
/// `WireChunkStream` doc ("after the first Some(Err(_)) or None, subsequent
/// calls return None"). Private and identically feature-gated, so it widens
/// no surface. Ungated (zero-await) like the default `Stream` path.
#[cfg(feature = "test-stream-gate")]
struct ScriptedResultChunkStream {
    chunks: std::vec::IntoIter<Result<Vec<u8>, ExecutorError>>,
    done: bool,
}

#[cfg(feature = "test-stream-gate")]
#[async_trait]
impl WireChunkStream for ScriptedResultChunkStream {
    async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
        if self.done {
            return None;
        }
        match self.chunks.next() {
            Some(Ok(chunk)) => Some(Ok(chunk)),
            Some(Err(e)) => {
                self.done = true;
                Some(Err(e))
            }
            None => {
                self.done = true;
                None
            }
        }
    }
}

#[cfg(feature = "test-stream-gate")]
struct GatedScriptedChunkStream {
    chunks: std::vec::IntoIter<Vec<u8>>,
    gate: std::sync::Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "test-stream-gate")]
#[async_trait]
impl WireChunkStream for GatedScriptedChunkStream {
    async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
        match self.gate.acquire().await {
            Ok(permit) => permit.forget(),
            Err(_) => return None, // closed gate = end of stream (defensive)
        }
        self.chunks.next().map(Ok)
    }
}

#[async_trait]
impl HttpStreamExecutor for MockHttpExecutor {
    async fn execute_stream(
        &self,
        req: &HttpRequest,
        redirect_check: std::sync::Arc<dyn RedirectCheck>,
    ) -> Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError> {
        let mut current_url = req.url.clone();
        let mut current_headers = req.headers.clone();
        let mut hops = 0usize;

        loop {
            self.recorded_requests
                .lock()
                .unwrap()
                .push((current_url.clone(), current_headers.clone()));

            let fixture = self
                .match_fixture(&current_url)
                .ok_or(ExecutorError::Transport)?;

            match fixture {
                MockFixture::Stream { head, chunks, .. } => {
                    // Gated only when the test registered a gate for this prefix
                    // (side table) — the ungated default stays zero-await even
                    // with the feature compiled in.
                    #[cfg(feature = "test-stream-gate")]
                    {
                        let gate = {
                            let gates = self.stream_gates.lock().unwrap();
                            gates
                                .iter()
                                .find(|(prefix, _)| current_url.starts_with(prefix.as_str()))
                                .map(|(_, g)| g.clone())
                        };
                        if let Some(g) = gate {
                            return Ok((
                                head,
                                Box::new(GatedScriptedChunkStream {
                                    chunks: chunks.into_iter(),
                                    gate: g.0.clone(),
                                }),
                            ));
                        }
                    }
                    return Ok((
                        head,
                        Box::new(ScriptedChunkStream {
                            chunks: chunks.into_iter(),
                        }),
                    ));
                }
                #[cfg(feature = "test-stream-gate")]
                MockFixture::StreamResults { head, chunks, .. } => {
                    return Ok((
                        head,
                        Box::new(ScriptedResultChunkStream {
                            chunks: chunks.into_iter(),
                            done: false,
                        }),
                    ));
                }
                MockFixture::Response { response, .. } => {
                    // A buffered fixture on the streaming path: head + a single
                    // body chunk (empty body → zero chunks).
                    let HttpResponse {
                        status,
                        headers,
                        body,
                    } = response;
                    let chunks = if body.is_empty() { vec![] } else { vec![body] };
                    {
                        return Ok((
                            HttpResponseHead { status, headers },
                            Box::new(ScriptedChunkStream {
                                chunks: chunks.into_iter(),
                            }),
                        ));
                    }
                }
                MockFixture::Redirect {
                    target,
                    target_headers,
                    ..
                } => {
                    if hops >= self.max_redirects {
                        return Err(ExecutorError::Transport);
                    }
                    hops += 1;

                    self.redirect_check_invocations
                        .lock()
                        .unwrap()
                        .push((target.clone(), target_headers.clone()));

                    redirect_check
                        .check(&target, &target_headers)
                        .await
                        .map_err(|reason| ExecutorError::RedirectRejected {
                            reason,
                            target: target.clone(),
                        })?;

                    // Same zero-carry walk contract as the buffered path.
                    current_url = target;
                    current_headers = target_headers;
                }
            }
        }
    }
}

/// `DefaultRedirectCheck` — the impl handed to the executor by
/// `DefaultHttpSecurityChain`. Performs allowlist + leak (URL + headers) +
/// SSRF check on the redirect target.
pub struct DefaultRedirectCheck {
    pub allowlist: Allowlist,
    pub leak_detector: std::sync::Arc<dyn LeakDetector>,
    pub ssrf_guard: std::sync::Arc<dyn SsrfGuard>,
}

/// Streaming-only wrapper that carries the CONTRACT-233 entry deadline into
/// the nested redirect validator without changing the shared `RedirectCheck`
/// signature or buffered `DefaultRedirectCheck` behavior.
pub(crate) struct DeadlineRedirectCheck {
    inner: DefaultRedirectCheck,
    deadline: tokio::time::Instant,
}

fn ensure_redirect_deadline(
    deadline: Option<tokio::time::Instant>,
) -> Result<(), RedirectRejectReason> {
    if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        // This internal sentinel cannot escape the streaming chain: the
        // ownership-aware outer HEAD wrapper observes the same monotonic
        // deadline and classifies the completed executor result as Timeout.
        Err(RedirectRejectReason::SsrfBlocked)
    } else {
        Ok(())
    }
}

impl DefaultRedirectCheck {
    pub(crate) fn with_deadline(self, deadline: tokio::time::Instant) -> DeadlineRedirectCheck {
        DeadlineRedirectCheck {
            inner: self,
            deadline,
        }
    }

    async fn check_with_deadline(
        &self,
        target_url: &str,
        target_headers: &[(String, String)],
        deadline: Option<tokio::time::Instant>,
    ) -> Result<(), RedirectRejectReason> {
        // 1. Allowlist
        ensure_redirect_deadline(deadline)?;
        let allowed = self.allowlist.matches(target_url);
        ensure_redirect_deadline(deadline)?;
        if !allowed {
            return Err(RedirectRejectReason::AllowlistBlocked);
        }
        // 2. Leak scan — URL with HttpRedirect context.
        let url_scan = self
            .leak_detector
            .scan(target_url, ScanContext::HttpRedirect);
        ensure_redirect_deadline(deadline)?;
        if !url_scan.is_clean()
            && !matches!(
                url_scan,
                advance_shared_types::security_validator::ScanResult::Warned { .. }
            )
        {
            return Err(RedirectRejectReason::LeakBlocked);
        }
        // 2b. Leak scan — headers.
        ensure_redirect_deadline(deadline)?;
        let header_scan = self.leak_detector.scan_headers(target_headers);
        ensure_redirect_deadline(deadline)?;
        if !header_scan.is_clean()
            && !matches!(
                header_scan,
                advance_shared_types::security_validator::ScanResult::Warned { .. }
            )
        {
            return Err(RedirectRejectReason::HeaderLeakBlocked);
        }
        // 3. SSRF
        ensure_redirect_deadline(deadline)?;
        let ssrf_result = match deadline {
            Some(deadline) => {
                crate::ssrf::with_stream_ssrf_deadline(deadline, self.ssrf_guard.check(target_url))
                    .await
            }
            None => self.ssrf_guard.check(target_url).await,
        };
        ensure_redirect_deadline(deadline)?;
        ssrf_result.map_err(|_| RedirectRejectReason::SsrfBlocked)?;
        ensure_redirect_deadline(deadline)?;
        Ok(())
    }
}

#[async_trait]
impl RedirectCheck for DefaultRedirectCheck {
    async fn check(
        &self,
        target_url: &str,
        target_headers: &[(String, String)],
    ) -> Result<(), RedirectRejectReason> {
        self.check_with_deadline(target_url, target_headers, None)
            .await
    }
}

#[async_trait]
impl RedirectCheck for DeadlineRedirectCheck {
    async fn check(
        &self,
        target_url: &str,
        target_headers: &[(String, String)],
    ) -> Result<(), RedirectRejectReason> {
        self.inner
            .check_with_deadline(target_url, target_headers, Some(self.deadline))
            .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReqwestHttpExecutor — production reqwest-backed HttpExecutor (Slice E).
//
// See MODULE-012-security.md §3.8 for the full design rationale. Summary:
//   - redirect(Policy::none()) + a manual per-hop loop (reqwest's sync redirect
//     policies cannot run the chain's async RedirectCheck, nor enforce zero-carry).
//   - On a redirect, follow ONLY absolute / absolute-path Locations (so url::Url::join
//     sources path+query wholly from Location and never preserves the injected base
//     path (UrlPath) / query (QueryParam)); relative / query-only / fragment-only /
//     empty Locations are rejected → Transport. Follow with a zero-carry clean GET
//     (no headers, empty body) so Bearer/Basic/CustomHeader header creds + the body
//     never reach a redirect target. Provably drops all 5 credential positions.
// ─────────────────────────────────────────────────────────────────────────────

/// Default response timeout for [`ReqwestHttpExecutor`] (`with_timeout` / `from_config`
/// override). Mirrors MODULE-012 §2.11.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default max redirect hops before [`ReqwestHttpExecutor`] gives up
/// (`ExecutorError::Transport`). Matches [`MockHttpExecutor::max_redirects`].
pub const DEFAULT_MAX_REDIRECTS: usize = 10;

/// Default hard cap on the buffered response-body size (8 MiB). reqwest's `.timeout()`
/// bounds the response in TIME, not SIZE, so without this a compromised-but-allowlisted
/// endpoint could stream an unbounded body within the timeout window and exhaust memory
/// before the step-8 inbound scan runs. (The inbound leak scanner itself fails-closed at
/// 1 MiB, so any accepted body is well under this cap; the cap only bounds pathological
/// streams.) Exceeding it → `ExecutorError::Transport`.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Default connect-phase timeout. Bounds a stalled/slowloris connect independently of the
/// total response timeout (round-9 adversarial W3). Clamped to `config.timeout` when smaller.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Entry-anchored PULL deadline for a streaming execute (ADR 2026-07-22 slice
/// S3; MODULE-012 §2.9 term 8). Aligned with cap-llm's `STREAM_HANDLE_TTL`
/// (300 s): the head walk and every attempted body read share this instant.
/// The pull-shaped stream does not autonomously expire while the caller leaves
/// it unpolled; the first pull after the instant drops the response and reports
/// `Timeout`, while S4's handle reap owns unpolled-object lifetime. Enforced by
/// the head `timeout_at`, a per-request reqwest timeout override, and the chunk
/// puller's check before every read.
pub const MAX_STREAM_DURATION: Duration = Duration::from_secs(300);

/// reqwest DNS resolver that CIDR-checks resolved IPs at CONNECT time and rejects any
/// resolution landing in the SSRF forbidden ranges — installed via
/// `ClientBuilder::dns_resolver`. The IPs reqwest actually connects to are validated by the
/// SAME forbidden table as the chain's `DefaultSsrfGuard`, closing the DNS-rebinding TOCTOU
/// where the guard validated a hostname's resolution that the connecting client re-resolved
/// independently (round-9 adversarial Critical). Static `.resolve()` overrides bypass this
/// resolver (reqwest checks overrides first), which is what lets the test harness reach a
/// loopback mock server.
struct SsrfDnsResolver {
    forbidden: Vec<(IpNet, CidrClass)>,
    timeout: Duration,
    /// Wave-16 Lane-4 (MODULE-012 AC-17): optional live `security.ssrf.dns_timeout_ms`
    /// source. `None` → the fixed `timeout` (prior behaviour). When wired, the
    /// connect-time DNS-rebinding resolver honours a hot-reloaded timeout — same
    /// value the chain's `DefaultSsrfGuard` pre-flight resolver reads — so a
    /// hot-reloaded timeout is applied to BOTH DNS lookups, not just the pre-flight.
    timeout_source: Option<crate::ssrf::DnsTunableSource>,
}

impl SsrfDnsResolver {
    fn new() -> Self {
        Self {
            forbidden: build_forbidden_table(),
            timeout: Duration::from_millis(crate::ssrf::DEFAULT_DNS_TIMEOUT_MS),
            timeout_source: None,
        }
    }

    fn with_timeout_source(source: crate::ssrf::DnsTunableSource) -> Self {
        Self {
            forbidden: build_forbidden_table(),
            timeout: Duration::from_millis(crate::ssrf::DEFAULT_DNS_TIMEOUT_MS),
            timeout_source: Some(source),
        }
    }

    /// Effective per-resolve DNS timeout: the live source if wired, else the fixed
    /// default. Read per `resolve()` so a hot-reloaded value applies without restart.
    fn effective_timeout(&self) -> Duration {
        match &self.timeout_source {
            Some(f) => Duration::from_millis(f()),
            None => self.timeout,
        }
    }
}

impl reqwest::dns::Resolve for SsrfDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let forbidden = self.forbidden.clone();
        let timeout = self.effective_timeout();
        // `Resolve::resolve` is synchronous even though it returns a future.
        // The live timeout callback above may cross CONTRACT-233's deadline;
        // capture the task-scoped instant after it returns and carry that value
        // into the returned future so a later/library-owned poll cannot lose
        // the context before `lookup_host` begins. Buffered calls have no scope.
        let stream_deadline = crate::ssrf::current_stream_ssrf_deadline();
        Box::pin(async move {
            if stream_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "ssrf-dns-resolver: stream deadline elapsed before lookup",
                ));
            }
            let lookup = tokio::net::lookup_host((host.as_str(), 0u16));
            let addrs: Vec<SocketAddr> = match tokio::time::timeout(timeout, lookup).await {
                Ok(Ok(it)) => it.collect(),
                Ok(Err(e)) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
                Err(_) => {
                    return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                        "ssrf-dns-resolver: lookup timed out",
                    ))
                }
            };
            if addrs.is_empty() {
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "ssrf-dns-resolver: no addresses resolved",
                ));
            }
            // Fail-closed: reject the WHOLE resolution if ANY resolved IP is forbidden
            // (defends multi-record DNS rebinding at resolution time, like `check_ips`).
            for sa in &addrs {
                let ip = normalize_ip(sa.ip());
                if forbidden.iter().any(|(net, _)| net.contains(&ip)) {
                    return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                        "ssrf-dns-resolver: resolved IP in forbidden range",
                    ));
                }
            }
            let addrs_iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs_iter)
        })
    }
}

/// Configuration for [`ReqwestHttpExecutor::from_config`].
///
/// Note `redirect(Policy::none())` is enforced INTERNALLY and is deliberately NOT a
/// field — no caller can re-enable reqwest auto-redirects and thereby bypass the
/// chain's per-hop `RedirectCheck` revalidation.
#[derive(Clone, Debug)]
pub struct ReqwestExecutorConfig {
    /// Total per-request response timeout.
    pub timeout: Duration,
    /// DNS overrides applied via `reqwest::ClientBuilder::resolve` (host → socket addr).
    /// Primarily for tests (loopback bridging) + advanced production host-pinning.
    pub dns_overrides: Vec<(String, SocketAddr)>,
    /// Max redirect hops before failing with `ExecutorError::Transport`.
    pub max_redirects: usize,
    /// Hard cap on the buffered response-body size (see [`DEFAULT_MAX_RESPONSE_BYTES`]).
    pub max_response_bytes: usize,
}

impl Default for ReqwestExecutorConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            dns_overrides: Vec::new(),
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Production `reqwest`-backed [`HttpExecutor`]. Drop-in replacement for
/// [`MockHttpExecutor`] honoring the same redirect/`ExecutorError` contract.
pub struct ReqwestHttpExecutor {
    client: reqwest::Client,
    max_redirects: usize,
    max_response_bytes: usize,
    /// Cumulative deadline for a whole `execute` (all redirect hops together).
    timeout: Duration,
    /// Forbidden SSRF CIDRs, for the executor-layer IP-literal host check. hyper-util
    /// short-circuits DNS for IP-literal hosts so the `SsrfDnsResolver` is never consulted
    /// for them; this is the executor-layer backstop (round-11 adversarial W1).
    forbidden: Vec<(IpNet, CidrClass)>,
}

impl ReqwestHttpExecutor {
    /// Production constructor: 30 s timeout, `redirect(none)`, rustls-tls.
    ///
    /// # Panics
    /// Panics only if the rustls TLS backend fails to initialize — an
    /// environment/build fault, not a runtime condition (mirrors
    /// `reqwest::Client::new`). Use [`Self::from_config`] for the same behavior.
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    /// Production constructor with an explicit total response timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self::from_config(ReqwestExecutorConfig {
            timeout,
            ..Default::default()
        })
    }

    /// Build from explicit config. `redirect(Policy::none())` is ALWAYS enforced
    /// here (there is no constructor that accepts a pre-built `reqwest::Client`),
    /// so the per-hop revalidation contract cannot be bypassed by construction.
    ///
    /// # Panics
    /// Panics only if the TLS backend fails to initialize (see [`Self::new`]).
    pub fn from_config(config: ReqwestExecutorConfig) -> Self {
        Self::from_config_with_dns_source(config, None)
    }

    /// Wave-16 Lane-4 (MODULE-012 AC-17): build with the default executor config but
    /// a LIVE `security.ssrf.dns_timeout_ms` source threaded into the connect-time
    /// `SsrfDnsResolver`, so a hot-reloaded DNS timeout applies to the executor's
    /// connect-time DNS-rebinding check (not just the chain's pre-flight guard).
    /// Behaviourally identical to [`Self::new`] except the connect-time DNS timeout
    /// is read live instead of fixed at 50 ms.
    pub fn with_dns_timeout_source(source: crate::ssrf::DnsTunableSource) -> Self {
        Self::from_config_with_dns_source(ReqwestExecutorConfig::default(), Some(source))
    }

    fn from_config_with_dns_source(
        config: ReqwestExecutorConfig,
        dns_timeout_source: Option<crate::ssrf::DnsTunableSource>,
    ) -> Self {
        // connect_timeout ≤ total timeout; bounds a stalled connect (round-9 W3).
        let connect_timeout = config.timeout.min(DEFAULT_CONNECT_TIMEOUT);
        let resolver = match dns_timeout_source {
            Some(s) => SsrfDnsResolver::with_timeout_source(s),
            None => SsrfDnsResolver::new(),
        };
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .connect_timeout(connect_timeout)
            // No idle connection reuse: every request makes a fresh connection, so the
            // SSRF DNS resolver below re-validates the host's IPs each time (a pooled
            // connection would skip resolution and decouple reuse from the SSRF check) —
            // also bounds the pool (round-9 W2).
            .pool_max_idle_per_host(0)
            // Connect-time SSRF IP validation — closes the DNS-rebinding TOCTOU (round-9
            // Critical). Static `.resolve()` overrides (below) are checked first and bypass
            // this resolver, which is how the test harness reaches the loopback server.
            .dns_resolver(Arc::new(resolver));
        for (host, addr) in &config.dns_overrides {
            builder = builder.resolve(host, *addr);
        }
        let client = builder
            .build()
            .expect("reqwest client (rustls) failed to initialize");
        Self {
            client,
            max_redirects: config.max_redirects,
            max_response_bytes: config.max_response_bytes,
            timeout: config.timeout,
            forbidden: build_forbidden_table(),
        }
    }

    /// Issue a single request (no auto-redirect). Header-build failures and any
    /// send/connect/DNS/TLS error map to `ExecutorError::Transport`; a reqwest
    /// timeout maps to `ExecutorError::Timeout`. `timeout_override` (streaming
    /// walk only) replaces the client-level total timeout for this request so a
    /// live body may outlive it — the caller still bounds the HEAD phase.
    async fn send_once(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout_override: Option<Duration>,
    ) -> Result<reqwest::Response, ExecutorError> {
        let mut rb = self.client.request(method, url);
        for (name, value) in headers {
            let hname = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ExecutorError::Transport)?;
            let hval = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
                .map_err(|_| ExecutorError::Transport)?;
            rb = rb.header(hname, hval);
        }
        if let Some(t) = timeout_override {
            rb = rb.timeout(t);
        }
        rb = rb.body(body.to_vec());
        rb.send().await.map_err(map_reqwest_err)
    }
}

impl Default for ReqwestHttpExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpExecutor for ReqwestHttpExecutor {
    async fn execute(
        &self,
        req: &HttpRequest,
        redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        // Cumulative deadline across ALL redirect hops: each hop is bounded by reqwest's
        // per-request `.timeout()`, but this outer bound stops N hops from multiplying the
        // budget to N×timeout (round-9 adversarial W4).
        match tokio::time::timeout(self.timeout, self.execute_inner(req, redirect_check)).await {
            Ok(result) => result,
            Err(_) => Err(ExecutorError::Timeout),
        }
    }
}

impl ReqwestHttpExecutor {
    /// The redirect-following request loop (wrapped by `execute` in a cumulative deadline).
    async fn execute_inner(
        &self,
        req: &HttpRequest,
        redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        let resp = self.walk_to_final(req, redirect_check, None).await?;
        map_response(resp, self.max_response_bytes).await
    }

    /// Walk redirects to the final (non-redirect) response and return it RAW.
    /// Shared by the buffered path (`execute_inner` → `map_response`) and the
    /// streaming path (`execute_stream` → head + chunk pull). Behavior is the
    /// buffered path's loop verbatim; `per_request_timeout` is `None` on the
    /// buffered path (client-level timeout applies) and `MAX_STREAM_DURATION`
    /// on the streaming path (so the final hop's live body may outlive the
    /// client-level total timeout — the HEAD phase is still bounded by the
    /// caller's cumulative deadline).
    async fn walk_to_final(
        &self,
        req: &HttpRequest,
        redirect_check: Arc<dyn RedirectCheck>,
        per_request_timeout: Option<Duration>,
    ) -> Result<reqwest::Response, ExecutorError> {
        let mut current_url = req.url.clone();
        // Hop 0 carries the original request's method/headers/body. Redirect hops use
        // a zero-carry clean GET (no headers, empty body) per chain invariant 3.
        let mut first_hop = true;
        let mut hops = 0usize;

        loop {
            // Executor-layer SSRF check for IP-LITERAL hosts: hyper-util short-circuits DNS
            // for literals so the SsrfDnsResolver never sees them (round-11 adversarial W1).
            // Hostname hosts return false here and are validated by the SsrfDnsResolver at
            // connect time. Covers the initial request AND every redirect target.
            if literal_host_forbidden(&current_url, &self.forbidden) {
                return Err(ExecutorError::Transport);
            }
            let resp = if first_hop {
                self.send_once(
                    map_method(&req.method),
                    &current_url,
                    &req.headers,
                    &req.body,
                    per_request_timeout,
                )
                .await?
            } else {
                self.send_once(
                    reqwest::Method::GET,
                    &current_url,
                    &[],
                    &[],
                    per_request_timeout,
                )
                .await?
            };

            // Is this a redirect we should surface to the chain?
            if let Some(location) = redirect_location(&resp) {
                if hops >= self.max_redirects {
                    return Err(ExecutorError::Transport);
                }
                hops += 1;
                first_hop = false;

                // Follow ONLY absolute / absolute-path Locations — those whose join
                // sources path+query wholly from Location, so the injected base path
                // (UrlPath) / query (QueryParam) is never preserved. Reject the rest.
                let target = resolve_redirect_target(&current_url, &location)
                    .ok_or(ExecutorError::Transport)?;

                // Per-hop revalidation with ZERO carried headers (drops Bearer/Basic +
                // arbitrary CustomHeader creds; the body is dropped via the clean GET).
                redirect_check.check(&target, &[]).await.map_err(|reason| {
                    ExecutorError::RedirectRejected {
                        reason,
                        target: target.clone(),
                    }
                })?;

                current_url = target;
                continue;
            }

            // Non-redirect (or a 3xx with no Location) → the final response.
            return Ok(resp);
        }
    }
}

/// Chunk puller backing `ReqwestHttpExecutor::execute_stream`. Enforces the
/// per-frame idle timeout, the entry-anchored `MAX_STREAM_DURATION` deadline on
/// every pull, and the cumulative wire-byte cap. It does not run a background
/// expiry task while unpolled. Terminal is absorbing (`resp` dropped →
/// connection closed; subsequent pulls return `None`).
struct ReqwestChunkStream {
    resp: Option<reqwest::Response>,
    idle: Duration,
    deadline: tokio::time::Instant,
    total: usize,
    max_bytes: usize,
}

/// Per-pull time budget for a streaming body read: `None` once the absolute
/// deadline has passed (the pull must not happen), else the per-frame idle
/// window clamped so a single pull can never overshoot the deadline.
/// Free function so the deadline arithmetic is unit-testable without a live
/// socket (the 300 s absolute arm is impractical to witness in real time).
fn remaining_pull_budget(
    idle: Duration,
    deadline: tokio::time::Instant,
    now: tokio::time::Instant,
) -> Option<Duration> {
    if now >= deadline {
        return None;
    }
    Some(idle.min(deadline - now))
}

/// Checked cumulative byte accounting shared by buffered and streaming bodies.
/// Overflow is indistinguishable from exceeding the configured cap and must
/// fail CLOSED rather than wrapping below it on 32-bit targets.
fn checked_cumulative_len(current: usize, next: usize, max: usize) -> Result<usize, ExecutorError> {
    match current.checked_add(next) {
        Some(total) if total <= max => Ok(total),
        _ => Err(ExecutorError::Transport),
    }
}

#[async_trait]
impl WireChunkStream for ReqwestChunkStream {
    async fn next(&mut self) -> Option<Result<Vec<u8>, ExecutorError>> {
        let resp = self.resp.as_mut()?;
        let now = tokio::time::Instant::now();
        let per_pull = match remaining_pull_budget(self.idle, self.deadline, now) {
            None => {
                self.resp = None;
                return Some(Err(ExecutorError::Timeout));
            }
            Some(d) => d,
        };
        match tokio::time::timeout(per_pull, resp.chunk()).await {
            Err(_) => {
                self.resp = None;
                Some(Err(ExecutorError::Timeout))
            }
            Ok(Err(e)) => {
                self.resp = None;
                Some(Err(map_reqwest_err(e)))
            }
            Ok(Ok(None)) => {
                self.resp = None;
                None
            }
            Ok(Ok(Some(bytes))) => {
                self.total = match checked_cumulative_len(self.total, bytes.len(), self.max_bytes) {
                    Ok(total) => total,
                    Err(err) => {
                        // Same rationale as the buffered body cap: a
                        // compromised-but-allowlisted endpoint must not stream
                        // unbounded bytes inside the deadline window. Checked
                        // addition also makes integer overflow fail CLOSED.
                        self.resp = None;
                        return Some(Err(err));
                    }
                };
                Some(Ok(bytes.to_vec()))
            }
        }
    }
}

#[async_trait]
impl HttpStreamExecutor for ReqwestHttpExecutor {
    async fn execute_stream(
        &self,
        req: &HttpRequest,
        redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<(HttpResponseHead, Box<dyn WireChunkStream>), ExecutorError> {
        // Pull-deadline anchor (audit round 1+2): both the head bound and every
        // attempted body read use ONE `started` instant from ENTRY. `timeout_at`
        // (not relative `timeout`) removes any capture-to-arm gap. An unpolled
        // body does not autonomously expire; the first later pull observes the
        // elapsed deadline and drops the response. The head is bounded by the
        // EARLIER of the executor's per-call timeout and the stream deadline.
        let started = tokio::time::Instant::now();
        let deadline = started + MAX_STREAM_DURATION;
        let head_deadline = deadline.min(started + self.timeout);

        // HEAD phase (redirect walk + response head) — connect errors and
        // rejected redirects fail HERE, before any stream object exists
        // (begin-site error gating). Final non-redirect HTTP statuses, including
        // 4xx/5xx, return a head and are scanned by the chain before the body is
        // handed out. The connect-time SsrfDnsResolver and the
        // literal-host backstop inside `walk_to_final` are untouched.
        let resp = match tokio::time::timeout_at(
            head_deadline,
            self.walk_to_final(req, redirect_check, Some(MAX_STREAM_DURATION)),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => return Err(ExecutorError::Timeout),
        };

        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();

        // Early reject on a declared Content-Length over the cumulative wire cap
        // (cheap; before any body read — mirrors `map_response`).
        if let Some(len) = resp.content_length() {
            if len > self.max_response_bytes as u64 {
                return Err(ExecutorError::Transport);
            }
        }

        Ok((
            HttpResponseHead { status, headers },
            Box::new(ReqwestChunkStream {
                resp: Some(resp),
                idle: self.timeout,
                // The SAME entry-anchored instant — every attempted body read
                // inherits whatever the head phase left of the 300 s budget.
                deadline,
                total: 0,
                max_bytes: self.max_response_bytes,
            }),
        ))
    }
}

/// Map the chain's `HttpMethod` to reqwest's `Method`.
fn map_method(m: &HttpMethod) -> reqwest::Method {
    match m {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Delete => reqwest::Method::DELETE,
        HttpMethod::Head => reqwest::Method::HEAD,
        HttpMethod::Options => reqwest::Method::OPTIONS,
    }
}

/// Returns true if `url`'s host is an IP LITERAL that falls in a forbidden SSRF range.
/// hyper-util short-circuits DNS for IP-literal hosts so the `SsrfDnsResolver` is never
/// consulted for them; this executor-layer check is the backstop (round-11 adversarial
/// W1). A non-literal (hostname) host returns false — the `SsrfDnsResolver` validates it
/// at connect time. Uses the same `normalize_ip` + forbidden table as `DefaultSsrfGuard`.
fn literal_host_forbidden(url: &str, forbidden: &[(IpNet, CidrClass)]) -> bool {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let ip: std::net::IpAddr = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => std::net::IpAddr::V4(v4),
        Some(url::Host::Ipv6(v6)) => std::net::IpAddr::V6(v6),
        // Domain (hostname) or no host → not a literal; handled by the SsrfDnsResolver.
        _ => return false,
    };
    let ip = normalize_ip(ip);
    forbidden.iter().any(|(net, _)| net.contains(&ip))
}

/// A reqwest error is a timeout (→ `Timeout`) or any other transport failure
/// (→ `Transport`). The chain folds both into `HttpError::Transport(...)`.
fn map_reqwest_err(e: reqwest::Error) -> ExecutorError {
    if e.is_timeout() {
        ExecutorError::Timeout
    } else {
        ExecutorError::Transport
    }
}

/// Returns the `Location` value iff `resp` is a redirect status (301/302/303/307/308)
/// carrying a `Location` header. A redirect status without `Location` is treated as a
/// normal response (returns `None`).
fn redirect_location(resp: &reqwest::Response) -> Option<String> {
    if !matches!(resp.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let loc = resp.headers().get(reqwest::header::LOCATION)?;
    // Require a valid-UTF-8 Location. A non-UTF-8 Location is NOT lossily decoded and then
    // trusted (which could mangle attacker bytes into a surprising target); instead we
    // return None, so the 3xx surfaces as a normal response rather than being followed
    // (round-5 diff W2).
    Some(loc.to_str().ok()?.to_string())
}

/// Resolve a redirect target, following ONLY a fully-absolute http(s) URL or a relative
/// reference that resolves to the SAME ORIGIN as the base (so it cannot change host).
///
/// - Absolute http(s) URL (`http(s)://host/path`): the host change is EXPLICIT; the
///   per-hop `redirect_check` (allowlist + SSRF) validates the (possibly new) host before
///   we follow.
/// - Relative reference: it MUST be a `/`-prefixed absolute path AND `url::Url::join` must
///   resolve it to the SAME origin (scheme + host + port) as the base. The origin check is
///   what actually enforces "no silent host change" — it is robust to WHATWG `join`
///   normalization (`//host`, `/\host`, `/<tab>/host`, … all resolve to a DIFFERENT origin
///   and are rejected), unlike a string-prefix heuristic (round-6 diff W1). A same-origin
///   `/x` sources path+query wholly from the Location, so the injected base path
///   (`UrlPath` cred) / query (`QueryParam` cred) is never carried over.
///
/// REJECTED → `None` (caller maps to `ExecutorError::Transport`): non-http(s) schemes; any
/// relative reference that is not `/`-prefixed (relative-path / `?query` / `#frag` / empty
/// — would preserve the base path/query); and any `/`-prefixed reference whose `join`
/// changes the origin (network-path `//host` and its backslash/tab equivalents).
fn resolve_redirect_target(current: &str, location: &str) -> Option<String> {
    let loc = location.trim();

    // 1. Fully-absolute URL → follow iff http(s). The host is explicit; redirect_check
    //    allowlist+SSRF-validates it in `execute`.
    if let Ok(u) = url::Url::parse(loc) {
        return match u.scheme() {
            "http" | "https" => Some(u.to_string()),
            _ => None,
        };
    }

    // 2. Relative reference. Require a `/`-prefixed absolute path; anything else
    //    (relative-path / `?query` / `#frag` / empty) would preserve the base path/query.
    if !loc.starts_with('/') {
        return None;
    }
    let base = url::Url::parse(current).ok()?;
    let joined = base.join(loc).ok()?;
    // 3. Robust no-host-change check: the resolved ORIGIN must equal the base origin. This
    //    catches `//host`, `/\host`, `/<tab>/host`, etc. regardless of WHATWG normalization,
    //    so a host change can NEVER hide behind a `/`-prefixed reference.
    if joined.scheme() != base.scheme()
        || joined.host_str() != base.host_str()
        || joined.port_or_known_default() != base.port_or_known_default()
    {
        return None;
    }
    Some(joined.to_string())
}

/// Map a reqwest `Response` to the chain's `HttpResponse` (status u16, header pairs,
/// raw body bytes). Header values that are not valid UTF-8 are decoded lossily. The body
/// is streamed with a hard `max_bytes` cap; exceeding it → `ExecutorError::Transport`.
async fn map_response(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<HttpResponse, ExecutorError> {
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();

    // Early reject on a declared Content-Length over the cap (cheap; before any read).
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(ExecutorError::Transport);
        }
    }

    // Stream the body with a hard size cap so a compromised-but-allowlisted endpoint cannot
    // exhaust memory by streaming an unbounded body within the timeout window (round-6 diff
    // W2). reqwest's `.timeout()` bounds time, not size; `chunk()` lets us bound size.
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(map_reqwest_err)? {
        checked_cumulative_len(body.len(), chunk.len(), max_bytes)?;
        body.extend_from_slice(&chunk);
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod s3_stream_tests {
    use super::*;

    /// S3 — the entry-anchored pull deadline (≤ 300 s,
    /// `STREAM_HANDLE_TTL`-aligned; MODULE-012 §2.9 term 8) is enforced by
    /// `remaining_pull_budget`: past the deadline no pull happens; near it, the
    /// idle window is clamped so an attempted read cannot overshoot. The stream
    /// is pull-shaped and does not autonomously expire while unpolled. (The
    /// wall-clock 300 s arm is impractical to run live; the reqwest per-request
    /// timeout override enforces attempted I/O at the transport layer too.)
    #[tokio::test]
    async fn s3_remaining_pull_budget_deadline_arithmetic() {
        let idle = Duration::from_secs(30);
        let now = tokio::time::Instant::now();

        // Deadline already passed → no pull budget (enum-coded Timeout arm).
        assert_eq!(
            remaining_pull_budget(idle, now - Duration::from_secs(1), now),
            None
        );
        assert_eq!(remaining_pull_budget(idle, now, now), None);

        // Far deadline → the idle window governs.
        let far = now + Duration::from_secs(1000);
        assert_eq!(remaining_pull_budget(idle, far, now), Some(idle));

        // Near deadline → clamped to the remaining time (never overshoots).
        let near = now + Duration::from_secs(5);
        assert_eq!(
            remaining_pull_budget(idle, near, now),
            Some(Duration::from_secs(5))
        );
    }

    /// The cumulative wire cap must fail CLOSED both when the configured
    /// maximum is crossed and when `usize` accounting would wrap below it.
    #[test]
    fn s3_cumulative_wire_cap_overflow_fails_closed() {
        assert_eq!(checked_cumulative_len(7, 3, 10).unwrap(), 10);
        assert!(matches!(
            checked_cumulative_len(8, 3, 10),
            Err(ExecutorError::Transport)
        ));
        assert!(matches!(
            checked_cumulative_len(usize::MAX - 1, 2, usize::MAX),
            Err(ExecutorError::Transport)
        ));
    }

    /// The absolute deadline constant stays aligned with cap-llm's
    /// `STREAM_HANDLE_TTL` (300 s) — a drift here silently decouples the
    /// transport deadline from the handle TTL the ADR pinned them to.
    #[test]
    fn s3_max_stream_duration_pinned_to_handle_ttl() {
        assert_eq!(MAX_STREAM_DURATION, Duration::from_secs(300));
    }
}

#[cfg(test)]
mod ac17_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// MODULE-012-T17g — the executor's connect-time `SsrfDnsResolver` reads the
    /// live `security.ssrf.dns_timeout_ms` source (so a hot-reloaded timeout
    /// governs the connect-time DNS-rebinding resolver, not just the SSRF guard's
    /// pre-flight resolver). Without a wired source it falls back to the fixed
    /// compile-time default.
    #[test]
    fn t17g_executor_dns_resolver_reads_live_timeout() {
        // No source → fixed default.
        let fixed = SsrfDnsResolver::new();
        assert_eq!(
            fixed.effective_timeout(),
            Duration::from_millis(crate::ssrf::DEFAULT_DNS_TIMEOUT_MS)
        );

        // Live source → reflects the swappable value (hot-reload).
        let ms = Arc::new(AtomicU64::new(5));
        let live = {
            let m = ms.clone();
            SsrfDnsResolver::with_timeout_source(Arc::new(move || m.load(Ordering::Relaxed)))
        };
        assert_eq!(live.effective_timeout(), Duration::from_millis(5));
        ms.store(2_000, Ordering::Relaxed);
        assert_eq!(
            live.effective_timeout(),
            Duration::from_millis(2_000),
            "executor DNS timeout must reflect a hot-reloaded value"
        );
    }

    /// MODULE-012-T29v — the connect-time resolver's synchronous live timeout
    /// callback cannot start `lookup_host` after the chain deadline. The
    /// numeric public host is deterministic and would resolve successfully in
    /// the pre-fix implementation, so an error discriminates the inner gate.
    #[tokio::test]
    async fn t29v_connect_resolver_deadline_stops_lookup() {
        use reqwest::dns::Resolve;

        let resolver = SsrfDnsResolver::with_timeout_source(Arc::new(|| {
            std::thread::sleep(Duration::from_millis(500));
            crate::ssrf::DEFAULT_DNS_TIMEOUT_MS
        }));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        let result = crate::ssrf::with_stream_ssrf_deadline(deadline, async {
            resolver.resolve("93.184.216.34".parse().unwrap()).await
        })
        .await;
        assert!(
            result.is_err(),
            "a late connect-time DNS tunable must gate lookup_host"
        );
    }
}
