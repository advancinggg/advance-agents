//! AC-13 — prompt-injection layer 1 (sanitization / pattern flagging).
//!
//! §1.4 AC-13: "calls `PromptInjectionHelpers::flag_injection_patterns`
//! (MODULE-012) and attaches returned `InjectionFlag`s to the L4/L5 context
//! record; **no in-module pattern matching duplication**".
//!
//! This module is a **thin forwarder** over the CANONICAL CONTRACT-114
//! [`PromptInjectionHelpers`] trait (shared-types `security_validator.rs`).
//! MODULE-010 does NOT own a pattern engine — it calls into the M012 helper so
//! the provider (M012) and consumer (M010) share one pattern database. The
//! returned [`InjectionFlag`]s are the CANONICAL shared-types type (no local
//! rematerialization).
//!
//! Non-wired scope (MODULE-010 §3.6 Slice-D (c)): the adapter is exported +
//! unit-tested but not yet wired into a live L4/L5 producer (no L4/L5 ingress
//! exists until the deferred history-load / Tier-2-⑮ wiring slice). The
//! `t_no_layer1_pattern_engine` test `include_str!`-greps THIS file to assert
//! no inline regex / pattern-name literals leak in (the §1.4 "no duplication"
//! criterion).

use advance_shared_types::security_validator::{InjectionFlag, PromptInjectionHelpers};

use crate::ports::Tier45ContextRecord;

/// Layer-1 forward: call the canonical CONTRACT-114
/// `flag_injection_patterns` and return the flags verbatim. No pattern
/// matching happens here — this is purely a forwarder so MODULE-010 reuses the
/// single M012 pattern database.
pub fn layer1_flag(content: &str, helpers: &dyn PromptInjectionHelpers) -> Vec<InjectionFlag> {
    helpers.flag_injection_patterns(content)
}

/// Attach layer-1 flags to the L4/L5 context-record carrier (the §1.4
/// "attaches returned `InjectionFlag`s to the L4/L5 context record" half). The
/// carrier is the receiver-side shape; the live L4/L5 producer that populates
/// it from real ingress is a future slice (§3.6 Slice-D (c)).
pub fn attach_flags_to_record(content: &str, flags: Vec<InjectionFlag>) -> Tier45ContextRecord {
    Tier45ContextRecord {
        content: content.to_string(),
        flags,
    }
}
