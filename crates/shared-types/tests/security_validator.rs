//! Serde + wire-format tests for `advance_shared_types::security_validator`.

use advance_shared_types::mailbox::AgentAction;
use advance_shared_types::security_validator::{
    Action, AgentAction as AgentActionFromSecurityValidator, Finding, InjectionFlag, ScanContext,
    ScanResult, SecurityError, Severity, TrustLevel,
};

#[test]
fn severity_round_trip() {
    for s in [Severity::Critical, Severity::High, Severity::Medium] {
        let json = serde_json::to_string(&s).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn severity_wire_format_lock() {
    assert_eq!(
        serde_json::to_string(&Severity::Critical).unwrap(),
        "\"Critical\""
    );
    assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"High\"");
    assert_eq!(
        serde_json::to_string(&Severity::Medium).unwrap(),
        "\"Medium\""
    );
}

#[test]
fn injection_flag_round_trip() {
    let f = InjectionFlag {
        offset: 10,
        length: 30,
        pattern_name: "ignore-instructions".to_string(),
        severity: Severity::High,
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: InjectionFlag = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

#[test]
fn injection_flag_deny_unknown_fields() {
    let bad = r#"{"offset":0,"length":1,"pattern_name":"p","severity":"High","extra":true}"#;
    let err = serde_json::from_str::<InjectionFlag>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn security_error_round_trip() {
    for e in [
        SecurityError::InvalidAction("x".to_string()),
        SecurityError::OversizedMessage,
        SecurityError::RateExceeded("r".to_string()),
        SecurityError::CapabilityDenied("c".to_string()),
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: SecurityError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn trust_level_round_trip() {
    for t in [TrustLevel::Trusted, TrustLevel::Untrusted] {
        let json = serde_json::to_string(&t).unwrap();
        let back: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}

#[test]
fn agent_action_reexport_from_security_validator_matches_mailbox() {
    // Both paths resolve to the same nominal type.
    let a1: AgentAction = AgentAction {
        payload: b"x".to_vec(),
    };
    let a2: AgentActionFromSecurityValidator = a1.clone();
    assert_eq!(a1, a2);
}

// ─────────────────────────────────────────────────────────────────────────
// Slice m012-B: wire-format roundtrips for the new LeakDetector supporting
// types (Action / ScanContext / Finding / ScanResult).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn action_round_trip() {
    for a in [Action::Block, Action::Redact, Action::Warn] {
        let json = serde_json::to_string(&a).unwrap();
        let back: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}

#[test]
fn action_wire_format_lock() {
    assert_eq!(serde_json::to_string(&Action::Block).unwrap(), "\"Block\"");
    assert_eq!(
        serde_json::to_string(&Action::Redact).unwrap(),
        "\"Redact\""
    );
    assert_eq!(serde_json::to_string(&Action::Warn).unwrap(), "\"Warn\"");
}

#[test]
fn scan_context_round_trip() {
    for c in [
        ScanContext::HttpOutbound,
        ScanContext::HttpInbound,
        ScanContext::HttpRedirect,
        ScanContext::NotifyOutbound,
        ScanContext::ChannelBidi,
        ScanContext::LogOutput,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: ScanContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }
}

#[test]
fn finding_round_trip() {
    let f = Finding {
        pattern_name: "openai_api_key".to_string(),
        offset: 4,
        length: 32,
        action: Action::Block,
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

#[test]
fn finding_deny_unknown_fields() {
    let bad = r#"{"pattern_name":"p","offset":0,"length":1,"action":"Block","extra":true}"#;
    let err = serde_json::from_str::<Finding>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn scan_result_round_trip() {
    let f = Finding {
        pattern_name: "p".to_string(),
        offset: 0,
        length: 4,
        action: Action::Block,
    };
    for r in [
        ScanResult::Clean,
        ScanResult::Blocked {
            findings: vec![f.clone()],
        },
        ScanResult::Redacted {
            redacted: "[REDACTED]".to_string(),
            findings: vec![f.clone()],
        },
        ScanResult::Warned { findings: vec![f] },
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Slice m012-C — CONTRACT-111 supporting types: wire-format roundtrips +
// Allowlist tests (T06-allow-1..6) + manual-Debug-redaction tests (T-debug-1..4).
// ─────────────────────────────────────────────────────────────────────────

use advance_shared_types::security_validator::{
    Allowlist, CidrClass, CredentialBinding, CredentialPosition, CredentialPositionTag, HttpError,
    HttpMethod, HttpRequest, HttpResponse, RedirectRejectReason, SecretResolutionReason, SsrfError,
    TransportErrorKind,
};

#[test]
fn http_method_round_trip() {
    for m in [
        HttpMethod::Get,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Patch,
        HttpMethod::Delete,
        HttpMethod::Head,
        HttpMethod::Options,
    ] {
        let j = serde_json::to_string(&m).unwrap();
        let back: HttpMethod = serde_json::from_str(&j).unwrap();
        assert_eq!(back, m);
    }
}

#[test]
fn http_request_round_trip() {
    let req = HttpRequest {
        method: HttpMethod::Post,
        url: "https://api.example.com/v1/x".to_string(),
        headers: vec![("X-Foo".to_string(), "bar".to_string())],
        body: vec![1, 2, 3],
    };
    let j = serde_json::to_string(&req).unwrap();
    let back: HttpRequest = serde_json::from_str(&j).unwrap();
    assert_eq!(back, req);
}

#[test]
fn http_response_round_trip() {
    let resp = HttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: br#"{"ok":true}"#.to_vec(),
    };
    let j = serde_json::to_string(&resp).unwrap();
    let back: HttpResponse = serde_json::from_str(&j).unwrap();
    assert_eq!(back, resp);
}

#[test]
fn http_error_round_trip() {
    use Finding;
    let f = Finding {
        pattern_name: "x".to_string(),
        offset: 0,
        length: 1,
        action: Action::Block,
    };
    for e in [
        HttpError::AllowlistBlocked("https://x.com".to_string()),
        HttpError::LeakBlocked(vec![f.clone()]),
        HttpError::SecretResolution(SecretResolutionReason::MissingSecretFor(
            CredentialPositionTag::BearerToken,
        )),
        HttpError::SecretResolution(SecretResolutionReason::PlaceholderNotInUrl),
        HttpError::SsrfBlocked(CidrClass::PrivateIpv4),
        HttpError::SsrfBlocked(CidrClass::CloudMetadata),
        HttpError::RateLimited {
            retry_after_ms: 100,
        },
        HttpError::Transport(TransportErrorKind::Dns),
        HttpError::Transport(TransportErrorKind::Other),
        HttpError::InboundLeakBlocked(vec![f]),
        HttpError::RedirectRejected {
            reason: RedirectRejectReason::AllowlistBlocked,
            target: "https://evil.com".to_string(),
        },
        HttpError::InvalidUrl("not a url".to_string()),
    ] {
        let j = serde_json::to_string(&e).unwrap();
        let back: HttpError = serde_json::from_str(&j).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn cidr_class_round_trip() {
    for c in [
        CidrClass::PrivateIpv4,
        CidrClass::Loopback,
        CidrClass::LinkLocal,
        CidrClass::UniqueLocalIpv6,
        CidrClass::CloudMetadata,
    ] {
        let j = serde_json::to_string(&c).unwrap();
        let back: CidrClass = serde_json::from_str(&j).unwrap();
        assert_eq!(back, c);
    }
}

#[test]
fn ssrf_error_round_trip() {
    for e in [
        SsrfError::InvalidUrl("x".to_string()),
        SsrfError::NoHost,
        SsrfError::DnsFailed,
        SsrfError::DnsTimeout,
        SsrfError::Forbidden(CidrClass::Loopback),
    ] {
        let j = serde_json::to_string(&e).unwrap();
        let back: SsrfError = serde_json::from_str(&j).unwrap();
        assert_eq!(back, e);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// T06-allow-1..6 — Allowlist port semantics + grammar locks (AC-06 step 1).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn t06_allow_1_host_only_matches_any_port() {
    let a = Allowlist {
        patterns: vec!["api.example.com".to_string()],
    };
    assert!(a.matches("https://api.example.com:8443/foo"));
    assert!(a.matches("https://api.example.com:443/foo"));
    assert!(a.matches("https://api.example.com/foo"));
    assert!(a.matches("http://api.example.com:80/foo"));
}

#[test]
fn t06_allow_2_url_prefix_default_port_only() {
    let a = Allowlist {
        patterns: vec!["https://api.example.com/v1/".to_string()],
    };
    // Default port (443) — url::Url::as_str() normalizes default port out.
    assert!(a.matches("https://api.example.com/v1/foo"));
    // Non-default port — must NOT match (pattern's no-explicit-port = default-only).
    assert!(!a.matches("https://api.example.com:8443/v1/foo"));
}

#[test]
fn t06_allow_3_url_prefix_explicit_port() {
    let a = Allowlist {
        patterns: vec!["https://api.example.com:8443/".to_string()],
    };
    assert!(a.matches("https://api.example.com:8443/foo"));
    assert!(!a.matches("https://api.example.com/foo")); // bare 443
    assert!(!a.matches("https://api.example.com:443/foo")); // explicit 443 (also default)
}

#[test]
fn t06_allow_3b_url_prefix_explicit_default_port_required() {
    // R3-W3 fix regression lock: pattern with explicit `:443` should NOT
    // match non-default-port URLs. The canonical url::Url::as_str strips
    // default port from BOTH pattern and URL, so :443 explicit-pattern
    // collapses to the same form as the default-port URL — this is the
    // intended grammar (default-port-explicit ≡ default-port-implicit).
    let a = Allowlist {
        patterns: vec!["https://api.example.com:443/".to_string()],
    };
    assert!(a.matches("https://api.example.com:443/foo"));
    assert!(a.matches("https://api.example.com/foo"));
    assert!(!a.matches("https://api.example.com:8443/foo"));
}

#[test]
fn t06_allow_4_subdomain_wildcard_suffix_anchor() {
    let a = Allowlist {
        patterns: vec!["*.example.com".to_string()],
    };
    assert!(a.matches("https://a.example.com/foo"));
    assert!(a.matches("https://a.b.example.com/foo"));
    // Adversarial cases that MUST NOT match:
    assert!(!a.matches("https://evil-example.com/foo")); // suffix-shadow
    assert!(!a.matches("https://example.com/foo")); // bare host
    assert!(!a.matches("https://attacker.evil.example.com.attacker.com/foo")); // tail attacker
}

#[test]
fn t06_allow_5_non_http_scheme_rejected() {
    let a = Allowlist {
        patterns: vec!["api.example.com".to_string()],
    };
    assert!(!a.matches("file:///etc/passwd"));
    assert!(!a.matches("gopher://api.example.com/x"));
    assert!(!a.matches("ftp://api.example.com/x"));
}

#[test]
fn t06_allow_6_empty_list_denies_all() {
    let a = Allowlist { patterns: vec![] };
    assert!(!a.matches("https://api.example.com/x"));
    assert!(!a.matches("http://anywhere.com/y"));
    assert!(!a.matches(""));
}

// ─────────────────────────────────────────────────────────────────────────
// T-debug-1..4 — manual-Debug-redaction assertions (R3-C5 + R7-W1 + R8-W1).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn t_debug_1_http_request_redacts_authorization_and_body() {
    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://api.example.com/x".to_string(),
        headers: vec![
            ("Authorization".to_string(), "Bearer xoxb-1234".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: vec![1, 2, 3],
    };
    let dbg = format!("{:?}", req);
    assert!(
        dbg.contains("[REDACTED]"),
        "auth should be redacted: {}",
        dbg
    );
    assert!(
        !dbg.contains("xoxb-1234"),
        "secret leaked in Debug: {}",
        dbg
    );
    assert!(
        dbg.contains("[BODY_LEN=3]"),
        "body should show length: {}",
        dbg
    );
    assert!(
        !dbg.contains("[1, 2, 3]"),
        "body bytes leaked in Debug: {}",
        dbg
    );
    // Non-sensitive header passes through.
    assert!(
        dbg.contains("application/json"),
        "Content-Type should pass: {}",
        dbg
    );
}

#[test]
fn t_debug_2_http_request_suffix_pattern_redaction() {
    let req = HttpRequest {
        method: HttpMethod::Get,
        url: "https://x.com/".to_string(),
        headers: vec![
            ("X-Custom-Token".to_string(), "tok123".to_string()),
            ("Foo-Api-Key".to_string(), "apikey456".to_string()),
            ("Bar-Secret".to_string(), "sec789".to_string()),
            ("Baz-Password".to_string(), "pw0".to_string()),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ],
        body: vec![],
    };
    let dbg = format!("{:?}", req);
    assert!(
        !dbg.contains("tok123"),
        "token suffix should redact: {}",
        dbg
    );
    assert!(
        !dbg.contains("apikey456"),
        "key suffix should redact: {}",
        dbg
    );
    assert!(
        !dbg.contains("sec789"),
        "secret suffix should redact: {}",
        dbg
    );
    assert!(
        !dbg.contains("pw0"),
        "password suffix should redact: {}",
        dbg
    );
    assert!(
        dbg.contains("text/plain"),
        "Content-Type should NOT redact: {}",
        dbg
    );
}

#[test]
fn t_debug_3_credential_binding_redacts_secret_name() {
    let cb = CredentialBinding {
        position: CredentialPosition::BearerToken,
        secret_name: "stripe-prod-key".to_string(),
    };
    let dbg = format!("{:?}", cb);
    assert!(
        dbg.contains("[SECRET_NAME]"),
        "secret_name should be tagged: {}",
        dbg
    );
    assert!(
        !dbg.contains("stripe-prod-key"),
        "secret_name leaked: {}",
        dbg
    );
}

#[test]
fn t_debug_4_http_response_global_redaction() {
    let resp = HttpResponse {
        status: 500,
        headers: vec![
            ("Set-Cookie".to_string(), "session=abc123".to_string()),
            ("X-Access-Token".to_string(), "deadbeef".to_string()),
            ("X-Foo-Password".to_string(), "hunter2".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: vec![1, 2, 3, 4, 5],
    };
    let dbg = format!("{:?}", resp);
    assert!(!dbg.contains("abc123"), "Set-Cookie value leaked: {}", dbg);
    assert!(!dbg.contains("deadbeef"), "X-Access-Token leaked: {}", dbg);
    assert!(!dbg.contains("hunter2"), "X-Foo-Password leaked: {}", dbg);
    // Non-sensitive Content-Type passes through.
    assert!(
        dbg.contains("application/json"),
        "Content-Type should pass: {}",
        dbg
    );
    // Body length-only.
    assert!(
        dbg.contains("[BODY_LEN=5]"),
        "body should show length: {}",
        dbg
    );
    assert!(
        !dbg.contains("[1, 2, 3, 4, 5]"),
        "body bytes leaked: {}",
        dbg
    );
}
