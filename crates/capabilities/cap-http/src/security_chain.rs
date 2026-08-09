//! `DefaultHttpSecurityChain` — implements the 10-step pipeline from MODULE-012 §1.4.3.
//!
//! Steps:
//!   1. Allowlist check
//!   2. Outbound leak scan (URL + headers + body — three SEPARATE scans)
//!   3. Placeholder substitution (`{name}` → secret)
//!   4. Credential injection (5 positions)
//!   5. SSRF check (async)
//!   6. Rate limit (per (agent_id, host))
//!   7. Execute (with redirect callback re-running 1+2+5)
//!   8. Inbound leak scan (response BODY)
//!   9. Response header redaction (scans response HEADERS on ALL status codes;
//!      Slice C adversarial-R1 upgrade — was 4xx/5xx-only before; see the
//!      step-9 implementation comment)
//!  10. Return sanitized
//!
//! Each step entry is reported via the optional `step_tracer` callback, used
//! by AC-06 integration tests to verify ordering + short-circuit behavior.

use crate::executor::{DefaultRedirectCheck, ExecutorError, HttpExecutor};
use crate::rate_limit::RateLimiter;
use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpMethod, HttpRequest, HttpResponse, HttpSecurityChain,
    LeakDetector, RedirectCheck, ScanContext, ScanResult, SsrfGuard, TransportErrorKind,
};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use cap_secrets::SecretStore;
use serde_json::json;
use std::sync::Arc;

/// Step name strings handed to `step_tracer`.
pub const STEP_ALLOWLIST: &str = "allowlist";
pub const STEP_OUTBOUND_LEAK_SCAN: &str = "outbound_leak_scan";
pub const STEP_SUBSTITUTE_PLACEHOLDERS: &str = "substitute_placeholders";
pub const STEP_INJECT_CREDENTIALS: &str = "inject_credentials";
pub const STEP_SSRF_CHECK: &str = "ssrf_check";
pub const STEP_RATE_LIMIT: &str = "rate_limit";
pub const STEP_EXECUTE: &str = "execute";
pub const STEP_INBOUND_LEAK_SCAN: &str = "inbound_leak_scan";
pub const STEP_REDACT_ERROR_MESSAGE: &str = "redact_error_message";
pub const STEP_RETURN: &str = "return";

/// `DefaultHttpSecurityChain` — production-shape 10-step chain. Constructed
/// with a `SecretStore` (Slice A) + `LeakDetector` / `SsrfGuard` /
/// `RateLimiter` / `HttpExecutor` trait objects.
///
/// Enabling CONTRACT-233 streaming through [`Self::with_stream_executor`]
/// adds the transitive composition precondition documented on that builder.
/// The precondition is streaming-only: the shared collaborator traits and the
/// buffered [`HttpSecurityChain`] semantics are unchanged.
pub struct DefaultHttpSecurityChain {
    secret_store: Arc<SecretStore>,
    pub(crate) leak_detector: Arc<dyn LeakDetector>,
    pub(crate) ssrf_guard: Arc<dyn SsrfGuard>,
    rate_limiter: Arc<dyn RateLimiter>,
    executor: Arc<dyn HttpExecutor>,
    step_tracer: Option<Arc<dyn Fn(&'static str) + Send + Sync>>,
    /// Phase-3 kickoff (2026-06-06): optional observability sink. `None`
    /// (default) → no emits (all ~25 existing `new()` call sites unchanged); the
    /// production wiring opts in via [`Self::with_event_bus`]. Emits
    /// `http.request`/`http.response`/`http.blocked`/`security.ssrf_blocked`/
    /// `security.leak_detected`/`secret.injected` with **host-only redacted**
    /// payloads — MODULE-019-AC-22.
    pub(crate) event_bus: Option<Arc<dyn EventBusEmit>>,
    /// ADR 2026-07-22 slice S3 (CONTRACT-233): OPT-IN streaming transport seam.
    /// `None` (default — every pre-existing `new()` call site) → the
    /// `HttpStreamingChain::execute_streaming` impl fails CLOSED with
    /// `HttpError::Transport(Other)`; production/test wiring opts in via
    /// [`Self::with_stream_executor`]. The shared `HttpExecutor` trait and the
    /// fail-closed `NotWiredHttpExecutor` never gain a streaming path.
    pub(crate) stream_executor: Option<Arc<dyn crate::executor::HttpStreamExecutor>>,
    /// Absolute CONTRACT-233 chain duration. Production construction fixes
    /// this at `MAX_STREAM_DURATION`; only an in-crate test helper can shorten
    /// it to exercise the production `execute_streaming` deadline call site.
    pub(crate) stream_duration: std::time::Duration,
}

impl DefaultHttpSecurityChain {
    pub fn new(
        secret_store: Arc<SecretStore>,
        leak_detector: Arc<dyn LeakDetector>,
        ssrf_guard: Arc<dyn SsrfGuard>,
        rate_limiter: Arc<dyn RateLimiter>,
        executor: Arc<dyn HttpExecutor>,
    ) -> Self {
        Self {
            secret_store,
            leak_detector,
            ssrf_guard,
            rate_limiter,
            executor,
            step_tracer: None,
            event_bus: None,
            stream_executor: None,
            stream_duration: crate::executor::MAX_STREAM_DURATION,
        }
    }

    pub fn with_step_tracer(mut self, tracer: Arc<dyn Fn(&'static str) + Send + Sync>) -> Self {
        self.step_tracer = Some(tracer);
        self
    }

    /// ADR 2026-07-22 slice S3 opt-in builder: wire the streaming transport
    /// seam (CONTRACT-233). Additive — a chain without it keeps zero streaming
    /// surface (`execute_streaming` fails CLOSED).
    ///
    /// # CONTRACT-233 streaming composition precondition
    ///
    /// Opting in requires **every** collaborator transitively reached by
    /// `execute_streaming` or its returned body to make synchronous callbacks,
    /// cancellation/drop of returned futures, and object `Drop` bounded,
    /// non-blocking, and panic-free. Cancellation and destruction must not do
    /// network I/O or wait for transport/application progress. This includes
    /// the secret backend, leak detector, SSRF guard, rate limiter, step
    /// tracer, event sink, stream executor and its nested `RedirectCheck`, and
    /// every returned `WireChunkStream`. The shipped production composition
    /// and mocks satisfy this precondition; a violating injection is
    /// non-conforming for streaming even if it remains usable by a buffered
    /// path whose contract makes no such deadline/destruction guarantee. The
    /// streaming implementation propagates its stage checkpoint through
    /// compound credential and redirect operations so the bound is enforced
    /// between their nested collaborator calls too.
    pub fn with_stream_executor(
        mut self,
        stream_executor: Arc<dyn crate::executor::HttpStreamExecutor>,
    ) -> Self {
        self.stream_executor = Some(stream_executor);
        self
    }

    /// Shorten the otherwise fixed production stream duration so unit tests
    /// can drive deadline behavior through the real `execute_streaming` call
    /// site without waiting 300 seconds.
    #[cfg(test)]
    pub(crate) fn with_stream_duration_for_test(
        mut self,
        stream_duration: std::time::Duration,
    ) -> Self {
        assert!(
            !stream_duration.is_zero(),
            "test stream duration must be non-zero"
        );
        self.stream_duration = stream_duration;
        self
    }

    /// Phase-3 kickoff opt-in builder — wire an observability sink. Mirrors
    /// [`Self::with_step_tracer`]; additive, so existing 5-arg `new()` callers
    /// compile unchanged and emit nothing.
    pub fn with_event_bus(mut self, bus: Arc<dyn EventBusEmit>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    pub(crate) fn trace(&self, name: &'static str) {
        if let Some(t) = &self.step_tracer {
            t(name);
        }
    }

    /// Emit an observability event when a sink is wired. Payloads are built by
    /// the caller and MUST be host-only redacted (no path/query/userinfo/headers/
    /// body/findings/secret values).
    pub(crate) fn emit(
        &self,
        agent_id: &str,
        event_type: &str,
        payload: serde_json::Value,
        duration_ms: Option<u64>,
    ) {
        if let Some(bus) = &self.event_bus {
            bus.emit(Event::observability(
                event_type,
                agent_id,
                payload,
                duration_ms,
            ));
        }
    }
}

/// Extract a **redaction-safe** host + scheme from a URL. `Url::host_str()`
/// excludes userinfo (`user:secret@`), so even a post-injection URL whose path/
/// query carries a credential yields a secret-free host. Returns `("unknown",
/// "unknown")` for an unparseable/host-less URL (never the raw URL).
pub(crate) fn redacted_host_scheme(url: &str) -> (String, String) {
    match url::Url::parse(url) {
        Ok(u) => (
            u.host_str().unwrap_or("unknown").to_string(),
            u.scheme().to_string(),
        ),
        Err(_) => ("unknown".to_string(), "unknown".to_string()),
    }
}

/// Stable lowercase method label for event payloads (never the raw request).
pub(crate) fn method_label(m: &HttpMethod) -> &'static str {
    match m {
        HttpMethod::Get => "get",
        HttpMethod::Post => "post",
        HttpMethod::Put => "put",
        HttpMethod::Patch => "patch",
        HttpMethod::Delete => "delete",
        HttpMethod::Head => "head",
        HttpMethod::Options => "options",
    }
}

/// Accept the result of a synchronous outbound stage only while the optional
/// CONTRACT-233 deadline is still live. Buffered CONTRACT-111 calls pass
/// `None`; streaming calls pass their entry-anchored deadline. The streaming
/// composition precondition makes each callback bounded, but this gate is
/// still required between callbacks so a late stage cannot dispatch another
/// collaborator or network-capable future.
pub(crate) fn ensure_stream_stage_deadline(
    deadline: Option<tokio::time::Instant>,
) -> Result<(), HttpError> {
    if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        Err(HttpError::Transport(TransportErrorKind::Timeout))
    } else {
        Ok(())
    }
}

impl DefaultHttpSecurityChain {
    /// Outbound half of the chain — pre-step-1 URL guard + steps 1–6 — shared
    /// VERBATIM by the buffered `execute` (CONTRACT-111) and the streaming
    /// `execute_streaming` (CONTRACT-233; §2.9 term 1 "byte-identical reuse",
    /// single step-4 credential-injection site). Mutates `req` in place
    /// (placeholder substitution + credential injection) and returns the
    /// post-injection host for the rate-limit key / event payloads.
    pub(crate) async fn outbound_steps(
        &self,
        agent_id: &str,
        req: &mut HttpRequest,
        cap: &HttpCapability,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<String, HttpError> {
        // R3-W2: pre-step-1 syntactic URL parse. Pre-substitution malformed
        // URLs route through `HttpError::InvalidUrl(req.url)` per invariant 7
        // (reserved for pre-step-3 syntactic invalidity ONLY). This is
        // distinct from step-1 allowlist rejection: a URL that parses but
        // doesn't match an allowlist entry → `AllowlistBlocked`. A URL that
        // FAILS to parse at all → `InvalidUrl`. Both `Allowlist::matches` and
        // step-5 SSRF would also fail on a malformed URL, but they fold those
        // failures into other variants — without this pre-check, the
        // `InvalidUrl` discriminator would be dead. No tracer entry: AC-06's
        // 10-step trace lock (T06a) requires exactly 10 entries starting at
        // `allowlist`; this pre-check is a guard, not a step.
        let parsed = url::Url::parse(&req.url);
        ensure_stream_stage_deadline(deadline)?;
        if parsed.is_err() {
            return Err(HttpError::InvalidUrl(req.url.clone()));
        }

        // ─── Step 1: Allowlist ────────────────────────────────────────────
        self.trace(STEP_ALLOWLIST);
        ensure_stream_stage_deadline(deadline)?;
        let allowed = cap.allowlist.matches(&req.url);
        ensure_stream_stage_deadline(deadline)?;
        if !allowed {
            let (host, _scheme) = redacted_host_scheme(&req.url);
            ensure_stream_stage_deadline(deadline)?;
            self.emit(
                agent_id,
                "http.blocked",
                json!({"host": host, "reason": "allowlist"}),
                None,
            );
            ensure_stream_stage_deadline(deadline)?;
            return Err(HttpError::AllowlistBlocked(req.url.clone()));
        }

        // ─── Step 2: Outbound leak scan ───────────────────────────────────
        // THREE SEPARATE invocations per Implementer Invariant 2 (URL +
        // headers + body), aggregated with union of findings.
        self.trace(STEP_OUTBOUND_LEAK_SCAN);
        ensure_stream_stage_deadline(deadline)?;
        let mut findings = Vec::new();

        let url_scan = self.leak_detector.scan(&req.url, ScanContext::HttpOutbound);
        ensure_stream_stage_deadline(deadline)?;
        if let ScanResult::Blocked { findings: f } = &url_scan {
            findings.extend(f.clone());
            ensure_stream_stage_deadline(deadline)?;
        }

        let header_scan = self.leak_detector.scan_headers(&req.headers);
        ensure_stream_stage_deadline(deadline)?;
        if let ScanResult::Blocked { findings: f } = &header_scan {
            findings.extend(f.clone());
            ensure_stream_stage_deadline(deadline)?;
        }

        let body_str = String::from_utf8_lossy(&req.body);
        ensure_stream_stage_deadline(deadline)?;
        let body_scan = self
            .leak_detector
            .scan(&body_str, ScanContext::HttpOutbound);
        ensure_stream_stage_deadline(deadline)?;
        if let ScanResult::Blocked { findings: f } = &body_scan {
            findings.extend(f.clone());
            ensure_stream_stage_deadline(deadline)?;
        }

        if !findings.is_empty() {
            // security.leak_detected: count only — NEVER the findings (they carry
            // the matched secret).
            self.emit(
                agent_id,
                "security.leak_detected",
                json!({"scan_context": "http_outbound", "finding_count": findings.len()}),
                None,
            );
            ensure_stream_stage_deadline(deadline)?;
            return Err(HttpError::LeakBlocked(findings));
        }

        // ─── Step 3: Substitute placeholders ──────────────────────────────
        self.trace(STEP_SUBSTITUTE_PLACEHOLDERS);
        ensure_stream_stage_deadline(deadline)?;
        // Capability-scope set: names of secrets the cap's bindings reference.
        // Step 3 placeholder substitution is restricted to this set, preventing
        // a guest from exfiltrating secrets outside the cap's authorized list.
        let allowed_secret_names: std::collections::HashSet<String> = cap
            .credentials
            .iter()
            .map(|b| b.secret_name.clone())
            .collect();
        ensure_stream_stage_deadline(deadline)?;
        let substitution = {
            let mut checkpoint = || ensure_stream_stage_deadline(deadline);
            crate::credential_injection::substitute_placeholders_with_checkpoint(
                req,
                &self.secret_store,
                &allowed_secret_names,
                &mut checkpoint,
            )
        };
        ensure_stream_stage_deadline(deadline)?;
        substitution?;

        // ─── Step 4: Inject credentials ───────────────────────────────────
        self.trace(STEP_INJECT_CREDENTIALS);
        ensure_stream_stage_deadline(deadline)?;
        let injection = {
            let mut checkpoint = || ensure_stream_stage_deadline(deadline);
            crate::credential_injection::inject_credentials_with_checkpoint(
                req,
                &cap.credentials,
                &self.secret_store,
                &mut checkpoint,
            )
        };
        ensure_stream_stage_deadline(deadline)?;
        injection?;
        // secret.injected — only when the cap actually declares credential
        // bindings (the channel-egress chain passes none → no spurious event).
        // `credential_bindings` is the DECLARED binding count (not the
        // substituted-on-wire count); never the secret value or positions. Host
        // from the post-injection URL (`host_str()` excludes any injected
        // url-path/query/userinfo secret).
        if !cap.credentials.is_empty() {
            let (host, _scheme) = redacted_host_scheme(&req.url);
            ensure_stream_stage_deadline(deadline)?;
            self.emit(
                agent_id,
                "secret.injected",
                json!({"host": host, "credential_bindings": cap.credentials.len()}),
                None,
            );
            ensure_stream_stage_deadline(deadline)?;
        }

        // ─── Step 5: SSRF check ───────────────────────────────────────────
        self.trace(STEP_SSRF_CHECK);
        ensure_stream_stage_deadline(deadline)?;
        let ssrf_result = match deadline {
            Some(deadline) => {
                crate::ssrf::with_stream_ssrf_deadline(deadline, self.ssrf_guard.check(&req.url))
                    .await
            }
            None => self.ssrf_guard.check(&req.url).await,
        };
        ensure_stream_stage_deadline(deadline)?;
        match ssrf_result {
            Ok(()) => {}
            Err(advance_shared_types::security_validator::SsrfError::Forbidden(class)) => {
                let (host, _scheme) = redacted_host_scheme(&req.url);
                ensure_stream_stage_deadline(deadline)?;
                self.emit(
                    agent_id,
                    "security.ssrf_blocked",
                    json!({"host": host, "cidr_class": format!("{class:?}")}),
                    None,
                );
                ensure_stream_stage_deadline(deadline)?;
                return Err(HttpError::SsrfBlocked(class));
            }
            Err(advance_shared_types::security_validator::SsrfError::DnsTimeout)
            | Err(advance_shared_types::security_validator::SsrfError::DnsFailed) => {
                return Err(HttpError::Transport(TransportErrorKind::Dns));
            }
            Err(advance_shared_types::security_validator::SsrfError::InvalidUrl(_))
            | Err(advance_shared_types::security_validator::SsrfError::NoHost) => {
                // Post-step-3 URL parse failure routes through Transport(Other)
                // per invariant 7 (NOT InvalidUrl, which is reserved for
                // pre-step-3 syntactic invalidity).
                return Err(HttpError::Transport(TransportErrorKind::Other));
            }
        }

        // Extract host for rate-limit key (post-injection URL).
        let host = url::Url::parse(&req.url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        ensure_stream_stage_deadline(deadline)?;

        // ─── Step 6: Rate limit ───────────────────────────────────────────
        self.trace(STEP_RATE_LIMIT);
        ensure_stream_stage_deadline(deadline)?;
        let rate_result = self.rate_limiter.check(agent_id, &host);
        ensure_stream_stage_deadline(deadline)?;
        if let Err(retry_after_ms) = rate_result {
            self.emit(
                agent_id,
                "http.blocked",
                json!({"host": host, "reason": "rate-limited", "retry_after_ms": retry_after_ms}),
                None,
            );
            ensure_stream_stage_deadline(deadline)?;
            return Err(HttpError::RateLimited { retry_after_ms });
        }

        ensure_stream_stage_deadline(deadline)?;
        Ok(host)
    }
}

#[async_trait]
impl HttpSecurityChain for DefaultHttpSecurityChain {
    async fn execute(
        &self,
        agent_id: &str,
        req: HttpRequest,
        cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        let mut req = req;

        // Pre-step-1 URL guard + steps 1–6 (shared with the streaming path).
        let host = self.outbound_steps(agent_id, &mut req, cap, None).await?;

        // ─── Step 7: Execute (with redirect callback) ────────────────────
        self.trace(STEP_EXECUTE);
        let redirect_check: Arc<dyn RedirectCheck> = Arc::new(DefaultRedirectCheck {
            allowlist: cap.allowlist.clone(),
            leak_detector: self.leak_detector.clone(),
            ssrf_guard: self.ssrf_guard.clone(),
        });
        // http.request — host/scheme/method ONLY (NEVER the path/query/userinfo;
        // a bot token lives in the URL path). `host` is the post-injection host
        // (`host_str()` excludes any injected secret).
        let (_h, scheme) = redacted_host_scheme(&req.url);
        let method = method_label(&req.method);
        self.emit(
            agent_id,
            "http.request",
            json!({"host": host, "scheme": scheme, "method": method}),
            None,
        );
        let started = std::time::Instant::now();
        let response = match self.executor.execute(&req, redirect_check).await {
            Ok(r) => {
                // http.response — status + sizes/counts; latency as the top-level
                // Event.duration_ms.
                let dur = started.elapsed().as_millis() as u64;
                self.emit(
                    agent_id,
                    "http.response",
                    json!({
                        "host": host,
                        "method": method,
                        "status": r.status,
                        "body_bytes": r.body.len(),
                        "headers_count": r.headers.len(),
                    }),
                    Some(dur),
                );
                r
            }
            Err(ExecutorError::RedirectRejected { reason, target }) => {
                // http.blocked — static reason label, host only (NEVER the
                // target URL, which the `RedirectRejected` error embeds).
                self.emit(
                    agent_id,
                    "http.blocked",
                    json!({"host": host, "reason": "redirect-rejected"}),
                    None,
                );
                return Err(HttpError::RedirectRejected { reason, target });
            }
            Err(ExecutorError::Transport) => {
                return Err(HttpError::Transport(TransportErrorKind::Other));
            }
            Err(ExecutorError::Timeout) => {
                return Err(HttpError::Transport(TransportErrorKind::Timeout));
            }
        };

        // ─── Step 8: Inbound leak scan (BODY) ────────────────────────────
        self.trace(STEP_INBOUND_LEAK_SCAN);
        let mut response = response;
        let body_str = String::from_utf8_lossy(&response.body).into_owned();
        let body_scan = self.leak_detector.scan(&body_str, ScanContext::HttpInbound);
        match body_scan {
            ScanResult::Clean | ScanResult::Warned { .. } => {}
            ScanResult::Blocked { findings } => {
                self.emit(
                    agent_id,
                    "security.leak_detected",
                    json!({"scan_context": "http_inbound", "finding_count": findings.len()}),
                    None,
                );
                return Err(HttpError::InboundLeakBlocked(findings));
            }
            ScanResult::Redacted { redacted, .. } => {
                response.body = redacted.into_bytes();
            }
        }

        // ─── Step 9: redact_error_message (HEADERS on ALL status codes) ───
        // Adversarial R1 fix: previously gated to 4xx/5xx only — but 2xx
        // responses can ALSO carry credentials in headers (Set-Cookie auth
        // tokens, X-Debug-* dev artifacts, custom session/jwt headers). The
        // gate is removed — step 9 now scans response headers regardless of
        // status, providing defense-in-depth on all surfaces.
        self.trace(STEP_REDACT_ERROR_MESSAGE);
        let header_scan = self.leak_detector.scan_headers(&response.headers);
        match header_scan {
            ScanResult::Clean | ScanResult::Warned { .. } => {}
            ScanResult::Blocked { findings } => {
                self.emit(
                    agent_id,
                    "security.leak_detected",
                    json!({"scan_context": "http_inbound", "finding_count": findings.len()}),
                    None,
                );
                return Err(HttpError::InboundLeakBlocked(findings));
            }
            ScanResult::Redacted { .. } => {
                // R3-C1 fix: per-header re-scan must include the HEADER
                // NAME (not just the value), because some BUILTIN_PATTERNS
                // are name-anchored (e.g. `auth_header_basic` requires the
                // literal `Authorization:` prefix). A pure value-only
                // rescan would pass-through a real `Authorization: Basic
                // ...` header that the outer scan_headers correctly
                // flagged. We rebuild the same `name: value` line shape
                // scan_headers uses internally.
                for (name, value) in response.headers.iter_mut() {
                    let line = format!("{}: {}", name, value);
                    let line_scan = self.leak_detector.scan(&line, ScanContext::HttpInbound);
                    match line_scan {
                        ScanResult::Blocked { .. } | ScanResult::Redacted { .. } => {
                            *value = "[REDACTED]".to_string();
                        }
                        _ => {}
                    }
                }
            }
        }

        // ─── Step 10: Return sanitized ───────────────────────────────────
        self.trace(STEP_RETURN);
        Ok(response)
    }
}
