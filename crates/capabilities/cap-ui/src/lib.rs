//! `cap-ui` — UI automation for the agent (ADR 2026-10-28 D2): the model-facing
//! `browser__*` and `screen__*` callables, their grant-param policy, the
//! observation scan and the `ui.*` events. Text mode (S1): element refs from
//! accessibility / DOM snapshots; pixel verbs follow with the multimodal
//! transcript (S3 / S4).
//!
//! The crate owns no platform code. A product (or a test) injects a
//! [`BrowserDriverPort`] / [`ScreenDriverPort`] through
//! `ComposeExtension::ui_drivers`; the composition registers the family's
//! [`CallableSpec`]s with the Layer 3 registry when the home declares `browser`
//! / `screen`. With no driver attached every callable still exists and answers
//! the fixed refusal [`NO_DRIVER_REASON`] so a model learns the surface is off.
//!
//! Every call goes through, in order: argument parsing (the dispatcher already
//! validated the JSON Schema) → policy from the grant (`UiPolicyReader`) →
//! allowlist via `GrantCheck` with the request's `origins` / `targets`
//! (CONTRACT-122) → the driver → observation rendering between fixed
//! delimiters → the inbound content scan (`ScanContext::ToolOutput`) → `ui.*`
//! events → a text result the dispatcher records into the turn transcript.
//!
//! The Fake drivers ([`fake`]) and the conformance suite ([`conformance`]) are
//! the M025 pattern: every product driver must pass the same cases.

#![forbid(unsafe_code)]

pub mod browser;
pub mod common;
pub mod conformance;
pub mod events;
pub mod fake;
pub mod family;
pub mod policy;
pub mod render;
pub mod screen;
pub mod testing;

pub use advance_shared_types::ui::{
    AllowRule, BrowserAction, BrowserDriverPort, BrowserGrantPolicy, ConfirmPolicy, HistoryAction,
    MouseButton, ScreenAction, ScreenDriverPort, ScreenGrantPolicy, ScreenMode, SnapshotOptions,
    TabAction, UiActionResult, UiElement, UiError, UiImage, UiPolicyReader, UiReadResult, UiRect,
    UiScope, UiSnapshot, UiState, UiSurface, UiTargetInfo, UiTargetKind, WaitCondition,
    BROWSER_CAPABILITY, SCREEN_CAPABILITY,
};
pub use family::{register_ui_callables, UiDeps, UiDrivers, UiFamily, UiSurfaces};
pub use policy::{NO_DRIVER_REASON, OBSERVATION_BLOCKED_TEXT};
pub use render::{OBSERVATION_BEGIN, OBSERVATION_END, OUTSIDE_GRANT_NOTE};

/// The namespace half of a browser callable's `original_function`
/// (`advance:runtime/ui-browser@0.1.0::<verb>`), the id `GrantCheck` sees.
pub const BROWSER_NS: &str = "advance:runtime/ui-browser@0.1.0";
/// The namespace half of a screen callable's `original_function`.
pub const SCREEN_NS: &str = "advance:runtime/ui-screen@0.1.0";

/// Catalog (model-facing) name of a verb: `browser__navigate`, `screen__click`.
/// `normalize_callable_name` maps the dotted alias `browser.navigate` onto it.
pub fn callable_name(surface: UiSurface, verb: &str) -> String {
    format!("{}__{verb}", surface.as_str())
}
