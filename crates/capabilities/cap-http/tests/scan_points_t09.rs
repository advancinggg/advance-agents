//! T09 (cap-http side) — AC-09 verification: HttpRedirect context-arg
//! observability.
//!
//! Existing T12d (security_chain.rs:661) locks the OUTCOME of a
//! redirect-with-leak path (`HttpError::RedirectRejected{LeakBlocked}`)
//! but does NOT observe the `ScanContext` argument actually passed to
//! `LeakDetector::scan` at each call site. This test attaches a
//! `SpyingLeakDetector` (a thin wrapper recording every `(text,
//! context)` arg pair) and asserts that a redirect-with-leak path
//! emits BOTH a `scan(.., HttpOutbound)` call (from
//! `security_chain.rs:124` step 2 outbound URL scan) AND a `scan(.., HttpRedirect)`
//! call (from `executor.rs:211` `DefaultRedirectCheck::check`) — locking
//! per-call-site context-tag forwarding for telemetry / Tier-2 routing
//! per `shared-types/src/security_validator.rs:256` doc.
//!
//! `scan_headers` is also delegated by the spy (required by the
//! `LeakDetector` trait), but `scan_headers` has no `ScanContext`
//! argument so its calls are not observable in the `(text, context)`
//! recording — this test only asserts on `scan` calls.
//!
//! See also `crates/event-bus/tests/scan_points_t09_log_output.rs`
//! for the LogOutput end-to-end half of T09 (real-detector
//! `apply_scan_to_outbound` integration).

use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, HttpError, HttpMethod, HttpRequest, HttpSecurityChain, LeakDetector,
    RedirectRejectReason, ScanContext, ScanResult,
};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultSsrfGuard, HttpExecutor,
    MockHttpExecutor, MockResolver,
};
use cap_secrets::{InMemorySecretStorage, SecretStorage, SecretStore};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

mod private_helpers {
    pub use cap_http::rate_limit::AlwaysAllow;
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn store() -> Arc<SecretStore> {
    let storage: Arc<dyn SecretStorage> = Arc::new(InMemorySecretStorage::new());
    let master = Zeroizing::new([0xab; 32]);
    Arc::new(SecretStore::new(master, storage))
}

fn cap_with_allowlist(patterns: &[&str]) -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
        },
        credentials: vec![],
        component_id: "test-component".to_string(),
    }
}

/// Records every `(text, context)` pair passed to `scan`. Delegates to
/// an inner `DefaultLeakDetector` so behavior matches production.
struct SpyingLeakDetector {
    inner: DefaultLeakDetector,
    scan_calls: Mutex<Vec<(String, ScanContext)>>,
}

impl SpyingLeakDetector {
    fn new() -> Self {
        Self {
            inner: DefaultLeakDetector::new(),
            scan_calls: Mutex::new(Vec::new()),
        }
    }

    fn scan_calls(&self) -> Vec<(String, ScanContext)> {
        self.scan_calls.lock().unwrap().clone()
    }
}

impl LeakDetector for SpyingLeakDetector {
    fn scan(&self, text: &str, context: ScanContext) -> ScanResult {
        self.scan_calls
            .lock()
            .unwrap()
            .push((text.to_string(), context.clone()));
        self.inner.scan(text, context)
    }

    fn scan_headers(&self, headers: &[(String, String)]) -> ScanResult {
        // No ScanContext arg on this trait method — calls are not part of
        // the per-call-site context-tag forwarding assertion this test
        // makes. Delegate to inner so behavior matches production.
        self.inner.scan_headers(headers)
    }
}

// ─── t09_redirect_context_arg_observability ─────────────────────────────
//
// AC-09 (4 production-wired scan points). Verifies that the production
// HTTP chain forwards distinct `ScanContext` tags to `LeakDetector::scan`
// at the outbound (step 2) and redirect (DefaultRedirectCheck::check)
// call sites. Locks the per-call-site context-tag forwarding contract
// for telemetry / Tier-2 routing.

#[tokio::test]
async fn t09_redirect_context_arg_observability() {
    let spy = Arc::new(SpyingLeakDetector::new());
    let leak: Arc<dyn LeakDetector> = Arc::clone(&spy) as Arc<dyn LeakDetector>;

    let resolver = MockResolver::new().with("api.example.com", vec![ip("8.8.8.8")]);
    let ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard> =
        Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver)));
    let rl: Arc<dyn cap_http::rate_limit::RateLimiter> = Arc::new(private_helpers::AlwaysAllow);

    // Redirect target URL contains a known leak pattern (`sk-proj-...`
    // openai_api_key BUILTIN_PATTERN match — same fixture every other
    // M012 leak test uses).
    let exec = MockHttpExecutor::new().with_redirect(
        "https://api.example.com/",
        "https://api.example.com/?token=sk-proj-abcdefghijklmnop1234ABCD",
        vec![],
    );
    let exec_arc: Arc<dyn HttpExecutor> = Arc::new(exec);

    let chain = DefaultHttpSecurityChain::new(store(), Arc::clone(&leak), ssrf, rl, exec_arc);

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![],
        body: vec![],
    };
    let cap = cap_with_allowlist(&["api.example.com"]);

    // Outcome: chain MUST reject the redirect with LeakBlocked (matching
    // the existing T12d outcome).
    let err = chain.execute("agent-1", req, &cap).await.unwrap_err();
    assert!(
        matches!(
            err,
            HttpError::RedirectRejected {
                reason: RedirectRejectReason::LeakBlocked,
                ..
            }
        ),
        "expected RedirectRejected{{LeakBlocked}}, got {:?}",
        err,
    );

    // Per-call-site context-tag forwarding assertion: bind specific
    // (text, ScanContext) pairs to specific call sites. Step 2 calls
    // scan(URL, HttpOutbound) at security_chain.rs:124 with the request URL
    // (`https://api.example.com/x`). The redirect callback calls
    // scan(target_url, HttpRedirect) at executor.rs:211 with the leak-bearing
    // target URL. Asserting MEMBERSHIP-with-text (not just context membership)
    // locks each call site individually — a regression that swapped the URL
    // call's context tag would still be caught even if the body call kept
    // HttpOutbound.
    let calls = spy.scan_calls();

    // Step 2 URL scan: the original request URL with HttpOutbound context.
    let url_outbound = calls.iter().any(|(text, ctx)| {
        text == "https://api.example.com/x" && *ctx == ScanContext::HttpOutbound
    });
    assert!(
        url_outbound,
        "expected scan(\"https://api.example.com/x\", HttpOutbound) call from \
         step 2 URL scan at security_chain.rs:124; recorded: {:?}",
        calls,
    );

    // Redirect callback: target URL containing the leak with HttpRedirect context.
    let redirect_target = "https://api.example.com/?token=sk-proj-abcdefghijklmnop1234ABCD";
    let target_redirect = calls
        .iter()
        .any(|(text, ctx)| text == redirect_target && *ctx == ScanContext::HttpRedirect);
    assert!(
        target_redirect,
        "expected scan({:?}, HttpRedirect) call from DefaultRedirectCheck::check \
         at executor.rs:211; recorded: {:?}",
        redirect_target, calls,
    );
}
