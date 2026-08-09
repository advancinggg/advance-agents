//! SYS-J-17 — agent outbound HTTP returns a sanitized response after the cap-http
//! 10-step security chain (allowlist → outbound leak scan → secret injection → SSRF
//! → rate limit → execute → inbound scan → header redaction).
//! Chain: MODULE-012 (cap-http security) → MODULE-013 (grant) → MODULE-019 (observability).
//!
//! Witnessed test-local against the REAL `cap_http::DefaultHttpSecurityChain` (all five
//! real collaborators: `DefaultLeakDetector`, `DefaultSsrfGuard`, secret store, rate
//! limiter, `ReqwestHttpExecutor`) doing a REAL TCP request to a local axum backend.
//! Only the external HTTP peer (the backend) and the SSRF/dns bridge are doubled — the
//! `llm_loopback.rs` proven pattern. NO security module is mocked.
//!
//! In-scope SYS-AC: 049, 050, 051, 052, 206, 207, 208.
//!
//! Note on events: as of Phase-3 kickoff (2026-06-06) `DefaultHttpSecurityChain`
//! emits `http.request` / `http.response` / `secret.injected` /
//! `security.ssrf_blocked` / `security.leak_detected` / `http.blocked` when an
//! `EventBus` is wired (`with_event_bus`) — **SYS-AC-050 is now WITNESSED**
//! (`sys_ac_050_*` below) with host-only redacted payloads (MODULE-019-AC-22).

#[path = "e_support/mod.rs"]
mod e_support;

use std::sync::{Arc, Mutex};

use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    Allowlist, CidrClass, CredentialBinding, CredentialPosition, HttpCapability, HttpError,
    HttpMethod, HttpRequest, HttpSecurityChain, RedirectRejectReason,
};
use advance_shared_types::traits::EventBusEmit;
use cap_http::DefaultHttpSecurityChain;
use e_support::*;

const AGENT: &str = "agent:track-e";

/// Phase-3 kickoff: a recording observability sink for the SYS-AC-050 witness.
#[derive(Default)]
struct RecordingBus(Mutex<Vec<Event>>);
impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}
impl RecordingBus {
    fn types(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }
    fn payload_of(&self, t: &str) -> Option<serde_json::Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.event_type == t)
            .map(|e| e.payload.clone())
    }
    fn serialized(&self) -> String {
        serde_json::to_string(&*self.0.lock().unwrap()).unwrap()
    }
}

fn http_cap(allow: &[&str], creds: Vec<CredentialBinding>) -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: allow.iter().map(|s| s.to_string()).collect(),
        },
        credentials: creds,
        component_id: "track-e".into(),
    }
}

fn get(url: &str) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: url.to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_049_sanitized_response_through_ten_step_chain_in_order() {
    let backend = Backend::fixed("backend.test", BackendResp::ok_text("hello-from-backend")).await;
    let tracer = StepTracer::new();
    let chain = DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[backend.dns_override()]),
    )
    .with_step_tracer(tracer.callback());

    let resp = chain
        .execute(
            AGENT,
            get("http://backend.test/v1/data"),
            &http_cap(&["backend.test"], vec![]),
        )
        .await
        .expect("allowlisted request returns a sanitized response");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello-from-backend");
    assert_eq!(
        tracer.steps(),
        vec![
            "allowlist",
            "outbound_leak_scan",
            "substitute_placeholders",
            "inject_credentials",
            "ssrf_check",
            "rate_limit",
            "execute",
            "inbound_leak_scan",
            "redact_error_message",
            "return",
        ],
        "all 10 cap-http chain steps ran in the declared order"
    );
    assert_eq!(
        backend.recorded().len(),
        1,
        "exactly one real request reached the backend"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_051_plaintext_secret_never_in_guest_request_real_credential_on_wire() {
    let secret = "supersecret-bearer-value"; // benign — not a leak pattern
    let backend = Backend::fixed("backend.test", BackendResp::ok_text("ok")).await;
    let chain = DefaultHttpSecurityChain::new(
        secret_store(&[("api-key", secret)]),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[backend.dns_override()]),
    );

    // The guest builds a request with NO Authorization header — it declares only the
    // credential BINDING (the secret NAME); the host injects the value at egress.
    let guest_req = get("http://backend.test/call");
    assert!(
        guest_req
            .headers
            .iter()
            .all(|(k, _)| !k.eq_ignore_ascii_case("authorization")),
        "guest request carries no Authorization header (binding/placeholder only)"
    );
    let cap = http_cap(
        &["backend.test"],
        vec![CredentialBinding {
            position: CredentialPosition::BearerToken,
            secret_name: "api-key".into(),
        }],
    );

    chain
        .execute(AGENT, guest_req, &cap)
        .await
        .expect("request succeeds");

    let wire = backend.last().expect("backend saw the request");
    let auth = wire
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.clone());
    let expected = format!("Bearer {secret}");
    assert_eq!(
        auth.as_deref(),
        Some(expected.as_str()),
        "the REAL credential was injected onto the wire by the host"
    );
    // The plaintext secret never appears in any wire location other than the
    // host-injected Authorization header (the guest never supplied it).
    assert!(
        !String::from_utf8_lossy(&wire.body).contains(secret),
        "secret is not echoed into the request body"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_052_non_allowlisted_blocked_and_private_ip_ssrf_blocked() {
    // (a) Non-allowlisted URL → AllowlistBlocked at step 1 (before any egress).
    let chain_a = DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[]),
    );
    let err_a = chain_a
        .execute(
            AGENT,
            get("http://evil.test/"),
            &http_cap(&["backend.test"], vec![]),
        )
        .await
        .expect_err("non-allowlisted URL is blocked");
    assert!(
        matches!(err_a, HttpError::AllowlistBlocked(_)),
        "got {err_a:?}"
    );

    // (b) URL resolving to a private/metadata IP → SsrfBlocked at step 5 (allowlist
    //     passes; the SSRF guard rejects the private resolution).
    let chain_b = DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("internal.test", PRIVATE_IP)]),
        rate_allow(),
        reqwest_executor(&[]),
    );
    let err_b = chain_b
        .execute(
            AGENT,
            get("http://internal.test/meta"),
            &http_cap(&["internal.test"], vec![]),
        )
        .await
        .expect_err("private-IP resolution is SSRF-blocked");
    assert!(
        matches!(err_b, HttpError::SsrfBlocked(CidrClass::PrivateIpv4)),
        "got {err_b:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_206_rate_limited_blocks_before_the_network() {
    let backend = Backend::fixed("backend.test", BackendResp::ok_text("should-not-reach")).await;
    let chain = DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_deny(250),
        reqwest_executor(&[backend.dns_override()]),
    );
    let err = chain
        .execute(
            AGENT,
            get("http://backend.test/x"),
            &http_cap(&["backend.test"], vec![]),
        )
        .await
        .expect_err("rate-limited at step 6");
    assert!(
        matches!(
            err,
            HttpError::RateLimited {
                retry_after_ms: 250
            }
        ),
        "got {err:?}"
    );
    assert!(
        backend.recorded().is_empty(),
        "no outbound request reached the network (step 6 precedes step 7)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_207_followed_redirect_revalidated_per_hop() {
    // (a) Redirect target resolves to a private IP → RedirectRejected{SsrfBlocked}.
    let backend = Backend::fixed(
        "backend.test",
        BackendResp::redirect("http://internal.test/secret"),
    )
    .await;
    let chain = DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP), ("internal.test", PRIVATE_IP)]),
        rate_allow(),
        reqwest_executor(&[backend.dns_override()]),
    );
    let err = chain
        .execute(
            AGENT,
            get("http://backend.test/start"),
            &http_cap(&["backend.test", "internal.test"], vec![]),
        )
        .await
        .expect_err("redirect hop to a private IP is rejected per-hop");
    assert!(
        matches!(
            err,
            HttpError::RedirectRejected {
                reason: RedirectRejectReason::SsrfBlocked,
                ..
            }
        ),
        "got {err:?}"
    );

    // (b) Redirect target off the allowlist → RedirectRejected{AllowlistBlocked}.
    let backend2 = Backend::fixed("backend.test", BackendResp::redirect("http://evil.test/")).await;
    let chain2 = DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[backend2.dns_override()]),
    );
    let err2 = chain2
        .execute(
            AGENT,
            get("http://backend.test/start"),
            &http_cap(&["backend.test"], vec![]),
        )
        .await
        .expect_err("redirect hop off the allowlist is rejected");
    assert!(
        matches!(
            err2,
            HttpError::RedirectRejected {
                reason: RedirectRejectReason::AllowlistBlocked,
                ..
            }
        ),
        "got {err2:?}"
    );
}

/// Drive a single-binding request through the real chain and return the post-chain
/// wire request the backend observed.
async fn wire_for(
    binding: CredentialBinding,
    secret_name: &str,
    secret: &str,
    url: &str,
) -> RecordedReq {
    let backend = Backend::fixed("backend.test", BackendResp::ok_text("ok")).await;
    let chain = DefaultHttpSecurityChain::new(
        secret_store(&[(secret_name, secret)]),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[backend.dns_override()]),
    );
    chain
        .execute(AGENT, get(url), &http_cap(&["backend.test"], vec![binding]))
        .await
        .expect("request succeeds");
    backend.last().expect("backend saw the request")
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Drive the REAL host-boundary credential injector (cap-http step 4,
/// `cap_http::inject_credentials`) on a guest request with a single binding and
/// return the post-injection (wire-bound) request.
fn injected(binding: CredentialBinding, secret_name: &str, secret: &str, url: &str) -> HttpRequest {
    let store = secret_store(&[(secret_name, secret)]);
    let mut req = get(url);
    cap_http::inject_credentials(&mut req, &[binding], &store).expect("inject_credentials");
    req
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_208_all_five_credential_positions_substituted_on_the_wire() {
    // Witnessed via the REAL host-boundary credential injector
    // (`cap_http::inject_credentials`, cap-http step 4) — the literal subject of
    // SYS-AC-208 ("Host-boundary credential injection covers all 5 position types").
    // The guest's pre-injection request carries only the placeholder / no credential;
    // the host substitutes the real secret into each position's wire location.
    //
    // Note on UrlPath through the FULL chain: step 3 (capability-scoped placeholder
    // substitution) runs BEFORE step 4 and processes `{key}` first, so a step-4
    // `UrlPath` binding cannot be exercised via `chain.execute` (the other 4 positions
    // can, and are corroborated end-to-end below). The host-boundary injector is the
    // correct, precise instrument for the per-position coverage this criterion names.

    // BearerToken → Authorization: Bearer <secret>
    let bearer = injected(
        CredentialBinding {
            position: CredentialPosition::BearerToken,
            secret_name: "k".into(),
        },
        "k",
        "alphaBEARER1",
        "http://backend.test/p",
    );
    assert_eq!(
        header(&bearer.headers, "authorization"),
        Some("Bearer alphaBEARER1")
    );

    // BasicAuth{username} → Authorization: Basic base64(username:secret)
    let basic = injected(
        CredentialBinding {
            position: CredentialPosition::BasicAuth {
                username: "u".into(),
            },
            secret_name: "k".into(),
        },
        "k",
        "alphaBASIC2",
        "http://backend.test/p",
    );
    let auth = header(&basic.headers, "authorization").expect("authorization header");
    let b64 = auth.strip_prefix("Basic ").expect("Basic prefix");
    assert_eq!(
        b64_decode(b64),
        b"u:alphaBASIC2",
        "BasicAuth: base64(username:secret) on the wire"
    );

    // CustomHeader{key} → <key>: <secret>
    let custom = injected(
        CredentialBinding {
            position: CredentialPosition::CustomHeader {
                key: "x-token".into(),
            },
            secret_name: "k".into(),
        },
        "k",
        "alphaCUSTOM3",
        "http://backend.test/p",
    );
    assert_eq!(header(&custom.headers, "x-token"), Some("alphaCUSTOM3"));

    // QueryParam{key} → ?<key>=<percent-encoded(secret)> (alnum → identity)
    let query = injected(
        CredentialBinding {
            position: CredentialPosition::QueryParam { key: "q".into() },
            secret_name: "k".into(),
        },
        "k",
        "alphaQUERY4",
        "http://backend.test/p",
    );
    assert!(
        query.url.contains("q=alphaQUERY4"),
        "QueryParam on the wire: {}",
        query.url
    );

    // UrlPath{key} → {key} placeholder in the URL path substituted with the secret.
    // Guest pre-injection URL carries only the `{seg}` placeholder.
    let guest_url = "http://backend.test/{seg}/end";
    let urlpath = injected(
        CredentialBinding {
            position: CredentialPosition::UrlPath { key: "seg".into() },
            secret_name: "k".into(),
        },
        "k",
        "alphaPATH5",
        guest_url,
    );
    assert!(
        guest_url.contains("{seg}"),
        "guest saw only the {{seg}} placeholder"
    );
    assert_eq!(
        urlpath.url, "http://backend.test/alphaPATH5/end",
        "UrlPath placeholder substituted into the path on the wire"
    );

    // End-to-end corroboration: an injected credential reaches a REAL backend over
    // the full chain + real TCP (CustomHeader; Bearer is corroborated in SYS-AC-051).
    let wire = wire_for(
        CredentialBinding {
            position: CredentialPosition::CustomHeader {
                key: "x-token".into(),
            },
            secret_name: "k".into(),
        },
        "k",
        "alphaWIRE6",
        "http://backend.test/p",
    )
    .await;
    assert_eq!(
        header(&wire.headers, "x-token"),
        Some("alphaWIRE6"),
        "injected credential reached the real backend on the wire through the full chain"
    );
}

// ─── SYS-AC-050 (Phase-3 kickoff 2026-06-06) ─────────────────────────────────
// http.request, http.response, AND secret.injected are emitted for an allowlisted
// real-chain call when an EventBus is wired — host-only redacted payloads.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_050_http_request_response_secret_injected_emitted() {
    let backend = Backend::fixed("backend.test", BackendResp::ok_text("ok")).await;
    let rec = Arc::new(RecordingBus::default());
    let secret = "SYS-AC-050-SECRET-VALUE";
    let chain = DefaultHttpSecurityChain::new(
        secret_store(&[("api-key", secret)]),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[backend.dns_override()]),
    )
    .with_event_bus(rec.clone());

    // BearerToken injects the secret into the Authorization header (works through
    // the full chain; the secret never touches a URL/payload).
    let cap = http_cap(
        &["backend.test"],
        vec![CredentialBinding {
            position: CredentialPosition::BearerToken,
            secret_name: "api-key".into(),
        }],
    );
    let resp = chain
        .execute(AGENT, get("http://backend.test/v1/data"), &cap)
        .await
        .expect("allowlisted request succeeds");
    assert_eq!(resp.status, 200);

    let types = rec.types();
    assert!(
        types.iter().any(|t| t == "http.request"),
        "types: {types:?}"
    );
    assert!(
        types.iter().any(|t| t == "http.response"),
        "types: {types:?}"
    );
    assert!(
        types.iter().any(|t| t == "secret.injected"),
        "types: {types:?}"
    );

    // Redacted: host only; the injected secret never appears in any payload.
    let req = rec.payload_of("http.request").unwrap();
    assert_eq!(req["host"], "backend.test");
    assert!(req.get("path").is_none() && req.get("url").is_none());
    assert_eq!(rec.payload_of("http.response").unwrap()["status"], 200);
    assert_eq!(
        rec.payload_of("secret.injected").unwrap()["credential_bindings"],
        1
    );
    assert!(
        !rec.serialized().contains(secret),
        "secret leaked into an event payload"
    );
}
