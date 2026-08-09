//! LeakDetector wiring for output paths (Slice B AC-18 LeakDetector half).
//!
//! Both `file_writer` (JSONL) and `ws_broadcaster` (WebSocket payload) call
//! `apply_scan_to_outbound` before writing/broadcasting the serialized event JSON.
//! See plan §"LeakDetector wiring algorithm" for the full algorithm.
//!
//! This module ships the LeakDetector PATTERN-based scrub (Aho-Corasick +
//! regex). The complementary `sensitive_params` PARAMETER-NAME-based scrub (the
//! previously-deferred AC-18 half) ships in the sibling `redact.rs` (Wave-20
//! security lane), applied in the production async `EmitPipeline::emit` AND the
//! Sync emit arm (`new_synchronous_for_tests`). CONTRACT-217 v0.2 declarations
//! populate the production registry-backed source after durable admission.

use advance_shared_types::security_validator::{ScanContext, ScanResult};
use advance_shared_types::traits::LeakDetector;

/// What to do with the outbound text after applying the LeakDetector.
pub enum ScrubOutcome {
    /// Send the (possibly redacted) text downstream.
    Send(String),
    /// Drop the text entirely (Blocked path); caller should NOT write/broadcast.
    Drop,
}

/// Apply LeakDetector::scan to outbound text and return the post-scrub action.
///
/// - When `detector` is `None`: pass through (`Send(text)`).
/// - When `Clean`: pass through (`Send(text)`).
/// - When `Redacted`: replace text with `redacted` (`Send(redacted)`).
/// - When `Warned`: pass through (`Send(text)`); side-emit of the
///   `security.leak_detected` event is the caller's responsibility (see
///   re-entrancy guard in plan).
/// - When `Blocked`: drop entirely (`Drop`); side-emit of
///   `security.leak_detected` is the caller's responsibility.
pub fn apply_scan_to_outbound(text: &str, detector: Option<&dyn LeakDetector>) -> ScrubOutcome {
    let Some(detector) = detector else {
        return ScrubOutcome::Send(text.to_string());
    };
    match detector.scan(text, ScanContext::LogOutput) {
        ScanResult::Clean => ScrubOutcome::Send(text.to_string()),
        ScanResult::Redacted { redacted, .. } => ScrubOutcome::Send(redacted),
        ScanResult::Warned { .. } => ScrubOutcome::Send(text.to_string()),
        ScanResult::Blocked { .. } => ScrubOutcome::Drop,
    }
}
