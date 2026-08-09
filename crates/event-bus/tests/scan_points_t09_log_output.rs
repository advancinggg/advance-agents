//! T09 (event-bus side) — AC-09 verification: LogOutput end-to-end
//! through real `apply_scan_to_outbound` + real `DefaultLeakDetector` +
//! real BUILTIN_PATTERNS engine.
//!
//! Existing tests in `crates/event-bus/tests/leak_scrub.rs` use
//! hand-rolled `CleanDetector`/`RedactDetector`/`WarnDetector`/`BlockDetector`
//! mocks — no test today exercises the real `cap_http::DefaultLeakDetector`
//! through `advance_event_bus::apply_scan_to_outbound`. cap-http tests
//! don't go through `apply_scan_to_outbound` at all. This test closes
//! the real-detector + real-production-fn-call-path gap end-to-end for
//! the LogOutput surface.
//!
//! Companion test in `crates/capabilities/cap-http/tests/scan_points_t09.rs`
//! covers the HttpRedirect context-arg observability half of T09.

use std::sync::Arc;

use advance_event_bus::{apply_scan_to_outbound, ScrubOutcome};
use advance_shared_types::traits::LeakDetector;
use cap_http::DefaultLeakDetector;

// ─── t09_log_output_e2e_via_apply_scan_to_outbound ──────────────────────
//
// AC-09 (4 production-wired scan points). Verifies that the production
// `apply_scan_to_outbound` function — which calls `LeakDetector::scan(.,
// ScanContext::LogOutput)` internally per `crates/event-bus/src/leak.rs:39`
// — correctly drops a payload containing a real BUILTIN_PATTERN match
// when wired to the real `cap_http::DefaultLeakDetector`.
//
// Payload uses the canonical `sk-proj-...` openai_api_key pattern (the
// same fixture every other M012 leak-detector test uses).

#[test]
fn t09_log_output_e2e_via_apply_scan_to_outbound() {
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());

    // Canonical openai_api_key BUILTIN_PATTERN — matches Block-action
    // path in DefaultLeakDetector. apply_scan_to_outbound uses
    // ScanContext::LogOutput internally.
    let payload = "log entry with leak: sk-proj-abcdefghijklmnop1234ABCD trailer";

    match apply_scan_to_outbound(payload, Some(detector.as_ref())) {
        ScrubOutcome::Drop => {}
        ScrubOutcome::Send(text) => panic!(
            "expected ScrubOutcome::Drop for sk-proj leak through real DefaultLeakDetector, \
             got Send({:?})",
            text,
        ),
    }
}
