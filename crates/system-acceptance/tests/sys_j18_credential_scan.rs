//! SYS-J-18 — a response/error carrying a credential pattern is blocked or redacted
//! before it reaches the guest.
//! Chain: MODULE-009 (cap-llm/provider) → MODULE-012 (cap-http security) → MODULE-019.
//!
//! Witnessed test-local against the REAL `cap_http::DefaultHttpSecurityChain` inbound
//! scan (step 8 body + step 9 headers, real `DefaultLeakDetector`) over a REAL TCP
//! response from a local axum backend scripted to return credential-bearing bodies /
//! headers. Only the external HTTP peer is doubled; no security module is mocked.
//!
//! In-scope SYS-AC: 053, 054, 209, 210.
//!
//! Note on events: as of Phase-3 kickoff (2026-06-06) `DefaultHttpSecurityChain`
//! emits `security.leak_detected` (with a finding COUNT, never the secret) on an
//! inbound block when an `EventBus` is wired — **SYS-AC-054 is now WITNESSED**
//! (`sys_ac_054_*` below).

#[path = "e_support/mod.rs"]
mod e_support;

use std::sync::{Arc, Mutex};

use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, HttpError, HttpMethod, HttpRequest, HttpSecurityChain,
};
use advance_shared_types::traits::EventBusEmit;
use cap_http::DefaultHttpSecurityChain;
use e_support::*;

const AGENT: &str = "agent:track-e";

/// Phase-3 kickoff: recording observability sink for the SYS-AC-054 witness.
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

fn allow_backend() -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: vec!["backend.test".into()],
        },
        credentials: Vec::new(),
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

/// Build the real chain wired to `backend` (real inbound scan over real TCP).
fn chain_to(backend: &Backend) -> DefaultHttpSecurityChain {
    DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[backend.dns_override()]),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_053_response_body_credential_blocked_before_guest() {
    // Each Block-class credential pattern in the response body → InboundLeakBlocked,
    // so the body never reaches the guest.
    for secret in [SECRET_OPENAI, SECRET_AWS, SECRET_PEM] {
        let body = format!("upstream said: {secret} — do not leak");
        let backend = Backend::fixed("backend.test", BackendResp::ok_text(&body)).await;
        let chain = chain_to(&backend);
        let err = chain
            .execute(AGENT, get("http://backend.test/data"), &allow_backend())
            .await
            .expect_err("credential-bearing response body is blocked");
        assert!(
            matches!(err, HttpError::InboundLeakBlocked(_)),
            "secret {secret:?} → expected InboundLeakBlocked, got {err:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_209_block_vs_redact_discrimination() {
    // (a) Block-class credential (sk-proj-…) → body withheld entirely (InboundLeakBlocked).
    let backend_block = Backend::fixed(
        "backend.test",
        BackendResp::ok_text(&format!("key={SECRET_OPENAI}")),
    )
    .await;
    let err = chain_to(&backend_block)
        .execute(AGENT, get("http://backend.test/b"), &allow_backend())
        .await
        .expect_err("Block-class credential withholds the body");
    assert!(
        matches!(err, HttpError::InboundLeakBlocked(_)),
        "got {err:?}"
    );

    // (b) Redact-class token (Bearer eyJ…) → masked in place; the cleaned body is
    //     still returned (NOT blanket-blocked), proving the discrimination.
    let body = format!("here is a token: {SECRET_BEARER_JWT} keep going");
    let backend_redact = Backend::fixed("backend.test", BackendResp::ok_text(&body)).await;
    let resp = chain_to(&backend_redact)
        .execute(AGENT, get("http://backend.test/r"), &allow_backend())
        .await
        .expect("Redact-class token returns a cleaned body");
    let returned = String::from_utf8_lossy(&resp.body);
    assert_eq!(resp.status, 200);
    assert!(
        !returned.contains("eyJhbGc"),
        "the JWT was redacted out of the returned body: {returned:?}"
    );
    assert!(
        returned.contains("[REDACTED]"),
        "the redaction marker is present in the returned body: {returned:?}"
    );
    assert!(
        returned.contains("keep going"),
        "surrounding clean content is preserved"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_210_credential_in_header_redacted_on_non_2xx() {
    // A credential in a response HEADER on a 5xx error response is redacted by step 9
    // (which runs on ALL status codes), before it surfaces to the guest.
    let backend = Backend::fixed(
        "backend.test",
        BackendResp::status_text(500, "internal error")
            .with_header("authorization", "Basic dXNlcjpwYXNz"),
    )
    .await;
    let resp = chain_to(&backend)
        .execute(AGENT, get("http://backend.test/err"), &allow_backend())
        .await
        .expect("non-2xx response with a credential header is returned redacted");

    assert_eq!(resp.status, 500, "the error status is preserved");
    let auth = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        auth.as_deref(),
        Some("[REDACTED]"),
        "the credential header was redacted on a 5xx response (step 9 runs on all status codes)"
    );
}

// ─── SYS-AC-054 (Phase-3 kickoff 2026-06-06) ─────────────────────────────────
// A credential-bearing response body trips the inbound leak scan → the chain
// emits security.leak_detected (finding COUNT only, never the secret) recording
// the scan action.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_054_security_leak_detected_emitted_on_inbound_block() {
    let backend = Backend::fixed(
        "backend.test",
        BackendResp::ok_text(&format!("leak: {SECRET_AWS}")),
    )
    .await;
    let rec = Arc::new(RecordingBus::default());
    let chain = DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(&[("backend.test", PUBLIC_IP)]),
        rate_allow(),
        reqwest_executor(&[backend.dns_override()]),
    )
    .with_event_bus(rec.clone());

    let err = chain
        .execute(AGENT, get("http://backend.test/data"), &allow_backend())
        .await
        .expect_err("credential-bearing response body is blocked");
    assert!(
        matches!(err, HttpError::InboundLeakBlocked(_)),
        "got {err:?}"
    );

    let types = rec.types();
    assert!(
        types.iter().any(|t| t == "security.leak_detected"),
        "types: {types:?}"
    );
    let p = rec.payload_of("security.leak_detected").unwrap();
    assert_eq!(p["scan_context"], "http_inbound");
    assert!(p["finding_count"].as_u64().unwrap() >= 1);
    // The matched secret must NEVER be in any emitted payload (count only).
    assert!(
        !rec.serialized().contains(SECRET_AWS),
        "secret leaked into a security.leak_detected payload"
    );
}
