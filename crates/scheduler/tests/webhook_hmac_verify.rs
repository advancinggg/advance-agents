//! sched-triggers (trigger-chain product pre-build): webhook HMAC-SHA256 verify
//! + 401/413 admission decision (`webhook_hmac.rs`).
//!
//! Future-witness targets:
//! - SYS-AC-105: valid HMAC-SHA256 signature → admitted (Ok).
//! - SYS-AC-106: missing / mismatched / malformed signature → 401; weak/empty
//!   secret fails closed → 401.
//! - SYS-AC-107: body over the 1 MiB cap → 413, checked BEFORE any HMAC.

use advance_scheduler::types::WebhookConfig;
use advance_scheduler::webhook_hmac::{
    compute_signature_hex, verify_webhook, WebhookRejection, MIN_WEBHOOK_SECRET_BYTES,
    WEBHOOK_MAX_BODY_BYTES,
};

const GOOD_SECRET: &str = "this-is-a-strong-enough-secret"; // >= 16 bytes

fn cfg_with_secret(secret: Option<&str>) -> WebhookConfig {
    WebhookConfig {
        path: "/hooks/test".into(),
        secret: secret.map(|s| s.to_owned()),
    }
}

// SYS-AC-105 — valid signature admits.
#[test]
fn valid_signature_is_accepted() {
    let body = b"{\"event\":\"push\"}";
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), body);
    assert!(verify_webhook(&cfg, body, Some(&sig), WEBHOOK_MAX_BODY_BYTES).is_ok());
}

// SYS-AC-105 — provided hex is case-insensitive (normalized to lowercase).
#[test]
fn valid_signature_uppercase_is_accepted() {
    let body = b"payload";
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), body).to_uppercase();
    assert!(verify_webhook(&cfg, body, Some(&sig), WEBHOOK_MAX_BODY_BYTES).is_ok());
}

// SYS-AC-106 — missing signature → 401.
#[test]
fn missing_signature_is_unauthorized() {
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    let rej = verify_webhook(&cfg, b"body", None, WEBHOOK_MAX_BODY_BYTES).unwrap_err();
    assert_eq!(rej, WebhookRejection::Unauthorized);
    assert_eq!(rej.http_status(), 401);
}

// SYS-AC-106 — mismatched signature (tampered body) → 401.
#[test]
fn mismatched_signature_is_unauthorized() {
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), b"original");
    let rej = verify_webhook(&cfg, b"tampered", Some(&sig), WEBHOOK_MAX_BODY_BYTES).unwrap_err();
    assert_eq!(rej.http_status(), 401);
}

// SYS-AC-106 — malformed (non-hex / wrong-length) signature → 401, no panic.
#[test]
fn malformed_signature_is_unauthorized() {
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    // Wrong length.
    assert_eq!(
        verify_webhook(&cfg, b"body", Some("deadbeef"), WEBHOOK_MAX_BODY_BYTES).unwrap_err(),
        WebhookRejection::Unauthorized
    );
    // Right length (64), non-hex garbage — fails the constant-time compare.
    let garbage = "z".repeat(64);
    assert_eq!(
        verify_webhook(&cfg, b"body", Some(&garbage), WEBHOOK_MAX_BODY_BYTES).unwrap_err(),
        WebhookRejection::Unauthorized
    );
}

// SYS-AC-107 — oversize body → 413, even with a valid signature (size first).
#[test]
fn oversize_body_is_413_before_hmac_even_with_valid_signature() {
    let cap = 1024;
    let body = vec![b'a'; cap + 1];
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    // A *valid* signature for the oversize body — must STILL be rejected 413
    // because the size gate runs before HMAC.
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), &body);
    let rej = verify_webhook(&cfg, &body, Some(&sig), cap).unwrap_err();
    assert_eq!(rej, WebhookRejection::PayloadTooLarge { len: cap + 1, cap });
    assert_eq!(rej.http_status(), 413);
}

#[test]
fn body_at_cap_boundary_is_allowed() {
    let cap = 1024;
    let body = vec![b'a'; cap]; // exactly at cap — not over
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), &body);
    assert!(verify_webhook(&cfg, &body, Some(&sig), cap).is_ok());
}

// SYS-AC-106 — weak/empty secret fails closed → 401.
#[test]
fn empty_secret_fails_closed() {
    let cfg = cfg_with_secret(Some(""));
    // Even a "signature" computed against the empty key is rejected.
    let sig = compute_signature_hex(b"", b"body");
    assert_eq!(
        verify_webhook(&cfg, b"body", Some(&sig), WEBHOOK_MAX_BODY_BYTES).unwrap_err(),
        WebhookRejection::Unauthorized
    );
}

#[test]
fn short_secret_below_minimum_fails_closed() {
    let short = "x".repeat(MIN_WEBHOOK_SECRET_BYTES - 1);
    let cfg = cfg_with_secret(Some(&short));
    let sig = compute_signature_hex(short.as_bytes(), b"body");
    assert_eq!(
        verify_webhook(&cfg, b"body", Some(&sig), WEBHOOK_MAX_BODY_BYTES).unwrap_err(),
        WebhookRejection::Unauthorized
    );
}

#[test]
fn secret_exactly_at_minimum_length_works() {
    let exact = "x".repeat(MIN_WEBHOOK_SECRET_BYTES);
    let cfg = cfg_with_secret(Some(&exact));
    let sig = compute_signature_hex(exact.as_bytes(), b"body");
    assert!(verify_webhook(&cfg, b"body", Some(&sig), WEBHOOK_MAX_BODY_BYTES).is_ok());
}

// No secret configured → no auth required (documented opt-out); size cap still applies.
#[test]
fn no_secret_is_opt_out_but_size_still_enforced() {
    let cfg = cfg_with_secret(None);
    assert!(verify_webhook(&cfg, b"anything", None, WEBHOOK_MAX_BODY_BYTES).is_ok());

    let cap = 8;
    let big = vec![0u8; cap + 1];
    assert_eq!(
        verify_webhook(&cfg, &big, None, cap)
            .unwrap_err()
            .http_status(),
        413
    );
}

// compute_signature_hex is a stable lowercase 64-char hex of the HMAC tag and
// round-trips through verify_webhook.
#[test]
fn signature_hex_is_64_lowercase_hex_and_roundtrips() {
    let sig = compute_signature_hex(GOOD_SECRET.as_bytes(), b"hello");
    assert_eq!(sig.len(), 64);
    assert!(sig
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    let cfg = cfg_with_secret(Some(GOOD_SECRET));
    assert!(verify_webhook(&cfg, b"hello", Some(&sig), WEBHOOK_MAX_BODY_BYTES).is_ok());
}

// Sanity: the production cap constant is the 1 MiB channels.webhook_max_body_bytes.
#[test]
fn webhook_max_body_bytes_is_one_mib() {
    assert_eq!(WEBHOOK_MAX_BODY_BYTES, 1_048_576);
}
