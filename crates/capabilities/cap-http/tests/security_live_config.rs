//! MODULE-012 AC-17 — behavioural witnesses that the `security.*` tunables are
//! read LIVE at the point of use (hot-reload) for the four live keys, and that
//! the action-validator threshold is a configurable construction SNAPSHOT.
//!
//! These exercise the cap-http live-source mechanism directly with swappable
//! sources (the same `with_*_source` closures the cli composition root injects
//! off the `RuntimeConfigProvider`). The cli `security_config_ac17` test drives
//! the SAME path end-to-end through the production `live_security_components`
//! helper + a real swappable `RuntimeConfigProvider`.

use advance_shared_types::mailbox::AgentAction;
use advance_shared_types::security_validator::{
    ActionValidator, LeakDetector, ScanContext, ScanResult, SecurityError, SsrfGuard,
};
use cap_http::{
    DefaultActionValidator, DefaultLeakDetector, DefaultRateLimiter, DefaultSsrfGuard,
    MockResolver, RateLimiter, RealResolver, DEFAULT_MAX_DUPLICATE_PAYLOADS,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// T17 — leak_detector.max_scan_bytes hot-reload: a real over-cap scan flips
/// `Blocked → Clean` after the live source returns a larger cap, with no rebuild.
#[test]
fn t17_leak_detector_live_cap_blocks_then_clean() {
    let cap = Arc::new(AtomicUsize::new(10)); // 10-byte cap
    let det = {
        let c = cap.clone();
        DefaultLeakDetector::new().with_scan_cap_source(Arc::new(move || c.load(Ordering::Relaxed)))
    };
    // A >10-byte string with NO leak patterns (spaces break any base64/hex run,
    // so the large-cap scan returns Clean rather than a base64_payload Warn).
    let text = "hello world this is a fine clean message";

    // cap = 10 < 64  → fail-closed Blocked with the synthetic scan_overflow finding.
    match det.scan(&text, ScanContext::HttpOutbound) {
        ScanResult::Blocked { findings } => {
            assert_eq!(findings[0].pattern_name, "scan_overflow");
        }
        other => panic!("expected Blocked at small cap, got {other:?}"),
    }

    // Hot-reload: bump the cap to 1 MiB. SAME detector instance → next scan reads
    // the new value and the 64-byte clean text now passes.
    cap.store(1024 * 1024, Ordering::Relaxed);
    assert!(
        det.scan(&text, ScanContext::HttpOutbound).is_clean(),
        "expected Clean after the cap hot-reloaded to 1 MiB"
    );
}

/// T17c — rate_limit.per_component_rps hot-reload: a low rps throttles the 2nd
/// immediate request; a raised rps admits the 2nd request on a fresh cell.
#[test]
fn t17c_rate_limit_live_rps_throttle_then_admit() {
    let rps = Arc::new(Mutex::new(1.0_f64));
    let limiter = {
        let r = rps.clone();
        DefaultRateLimiter::new().with_rps_source(Arc::new(move || *r.lock().unwrap()))
    };

    // rps = 1.0 → first request on host-a fills then drains the bucket to 0; the
    // immediate 2nd request has < 1 token → throttled.
    assert!(
        limiter.check("agent", "host-a").is_ok(),
        "1st request admitted"
    );
    assert!(
        limiter.check("agent", "host-a").is_err(),
        "2nd immediate request throttled at rps=1"
    );

    // Hot-reload rps up; use a FRESH cell (host-b) so residual bucket state from
    // host-a doesn't confound the observation (the bucket is per (agent, host)).
    *rps.lock().unwrap() = 1000.0;
    assert!(
        limiter.check("agent", "host-b").is_ok(),
        "1st on host-b admitted"
    );
    assert!(
        limiter.check("agent", "host-b").is_ok(),
        "2nd request on host-b admitted after rps hot-reloaded up"
    );
}

/// T17d — ssrf.dns_timeout_ms + ssrf.dns_cache_ttl_seconds are read LIVE: the
/// injected sources are consulted at the point of use (per-resolve / per-lookup).
#[tokio::test]
async fn t17d_ssrf_live_dns_sources_consulted() {
    // dns_timeout_ms: read per-resolve. `.invalid` TLD reliably fails (RFC 6761),
    // so the resolve returns quickly; the timeout source is consulted regardless.
    let timeout_reads = Arc::new(AtomicU64::new(0));
    let resolver = {
        let c = timeout_reads.clone();
        RealResolver::new().with_timeout_source(Arc::new(move || {
            c.fetch_add(1, Ordering::Relaxed);
            5 // 5 ms
        }))
    };
    use cap_http::Resolver;
    let _ = resolver.resolve("nonexistent-host.invalid.").await; // Err expected
    assert!(
        timeout_reads.load(Ordering::Relaxed) >= 1,
        "dns_timeout_ms source must be consulted per resolve"
    );

    // dns_cache_ttl_seconds: read per-lookup at the freshness check. Map a host to
    // a PUBLIC ip so `check` passes the CIDR gate; two checks → the 2nd reads ttl.
    let ttl_reads = Arc::new(AtomicU64::new(0));
    let public_ip: IpAddr = "1.1.1.1".parse().unwrap();
    let guard = {
        let c = ttl_reads.clone();
        DefaultSsrfGuard::with_resolver(Box::new(
            MockResolver::new().with("ex.test", vec![public_ip]),
        ))
        .with_cache_ttl_source(Arc::new(move || {
            c.fetch_add(1, Ordering::Relaxed);
            300
        }))
    };
    assert!(guard.check("http://ex.test/").await.is_ok(), "1st check ok");
    assert!(
        guard.check("http://ex.test/").await.is_ok(),
        "2nd check ok (cached)"
    );
    assert!(
        ttl_reads.load(Ordering::Relaxed) >= 1,
        "dns_cache_ttl_seconds source must be consulted at the freshness check"
    );
}

/// T17e — action_validator.max_message_size is a configurable construction
/// SNAPSHOT: `with_thresholds(small, ..)` rejects an oversized action that the
/// default 1 MiB validator admits. Determinism (CONTRACT-113) is preserved —
/// the threshold is fixed for a given validator instance.
#[test]
fn t17e_action_validator_threshold_snapshot_configurable() {
    let small = DefaultActionValidator::with_thresholds(10, DEFAULT_MAX_DUPLICATE_PAYLOADS);
    let action = AgentAction {
        payload: vec![0u8; 11], // 11 bytes > 10
    };
    assert_eq!(
        small.validate("agent-001", std::slice::from_ref(&action)),
        Err(SecurityError::OversizedMessage),
        "small max_message_size rejects the 11-byte action"
    );

    // The default 1 MiB validator admits the same action — proving the threshold
    // (not anything else) drove the rejection, and that it is config-driven.
    let default = DefaultActionValidator::new();
    assert_eq!(
        default.validate("agent-001", std::slice::from_ref(&action)),
        Ok(()),
        "default 1 MiB max_message_size admits the same action"
    );

    // Determinism: same input twice → same result for a fixed instance.
    assert_eq!(
        small.validate("agent-001", std::slice::from_ref(&action)),
        small.validate("agent-001", std::slice::from_ref(&action)),
    );
}
