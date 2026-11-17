//! Policy decisions the family makes before a driver is called.

use advance_runtime::callable_registry::CallableError;
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use advance_shared_types::ui::{origin_of, AllowRule, UiError, UiSurface};
use serde_json::json;

/// The fixed reason every callable answers when the composition attached no
/// driver for its surface (ADR D2).
pub const NO_DRIVER_REASON: &str = "no ui driver attached";

/// The safe-class text a blocked observation is replaced with (ADR D2
/// observation security: `Blocked` → `is-error` with the safe-class text).
pub const OBSERVATION_BLOCKED_TEXT: &str =
    "[ui observation withheld: the inbound content scan blocked it]";

/// Schemes a top-level navigation may use. `javascript:`, `data:`, `file:`
/// and everything else are refused (ADR D2).
pub const ALLOWED_SCHEMES: &[&str] = &["http", "https"];

/// Map a driver error onto the Layer 3 refusal class (ADR 2026-10-24 D4:
/// refusals are `Err`, execution failures are `Ok { is_error }`).
///
/// - `NoDriver` → `not-found` with the fixed reason;
/// - `SecureField`, `Refused` → `permission-denied`;
/// - `StaleRef`, `UnknownRef`, `UnknownTarget`, `Unsupported` → `invalid-arguments`
///   (the model can repair the call: take a new snapshot, pick another ref);
/// - `Unavailable`, `Timeout`, `Driver` → an execution failure (`Ok` with `is_error`),
///   so the caller sees the text and the turn continues.
pub enum Mapped {
    Refusal(CallableError),
    Failure(String),
}

pub fn map_driver_error(err: &UiError) -> Mapped {
    match err {
        UiError::NoDriver => Mapped::Refusal(CallableError::NotFound(NO_DRIVER_REASON.into())),
        UiError::SecureField { .. } | UiError::Refused { .. } => {
            Mapped::Refusal(CallableError::PermissionDenied(err.to_string()))
        }
        UiError::StaleRef { .. }
        | UiError::UnknownRef { .. }
        | UiError::UnknownTarget { .. }
        | UiError::Unsupported { .. } => {
            Mapped::Refusal(CallableError::InvalidArguments(err.to_string()))
        }
        UiError::Unavailable { .. } | UiError::Timeout | UiError::Driver { .. } => {
            Mapped::Failure(err.to_string())
        }
    }
}

/// Check a navigation URL's scheme. Returns the normalized origin.
pub fn navigable_origin(url: &str) -> Result<String, CallableError> {
    let parsed = url::Url::parse(url).map_err(|e| {
        CallableError::InvalidArguments(format!("browser.navigate: url does not parse: {e}"))
    })?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if !ALLOWED_SCHEMES.contains(&scheme.as_str()) {
        return Err(CallableError::PermissionDenied(format!(
            "browser.navigate: scheme {scheme:?} is not allowed (http and https only)"
        )));
    }
    origin_of(url).ok_or_else(|| {
        CallableError::InvalidArguments("browser.navigate: url has no host".to_string())
    })
}

/// The origin of a page cap-ui may read or operate: an `http` / `https` URL
/// with a host ([`ALLOWED_SCHEMES`]). Any other page (`file:`, `data:`,
/// `chrome:`, an application's custom scheme…) has none, even under a
/// whole-capability grant.
pub fn operable_origin(url: &str) -> Option<String> {
    let origin = origin_of(url)?;
    let (scheme, _) = origin.split_once("://")?;
    ALLOWED_SCHEMES.contains(&scheme).then_some(origin)
}

/// A URL's scheme as a refusal or an action line may name it: lower-case ASCII
/// alphanumerics and `+-.`, at most 16 characters, `unknown` when there is
/// none. The rest of the URL is never echoed (a `data:` URL carries any text).
pub fn scheme_label(url: &str) -> String {
    let label = url
        .split_once(':')
        .map(|(scheme, _)| scheme)
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    if label.is_empty() {
        "unknown".to_string()
    } else {
        label
    }
}

/// The L1 allowlist gate: `GrantCheck(agent, <capability>, <function>, {origins|targets: value})`.
/// CONTRACT-122 decides coverage (cap-grant's `browser` / `screen` rules); a
/// `Deny` becomes `permission-denied` with the gate's reason.
pub fn check_allowlist(
    grant: &dyn GrantCheck,
    ctx: &HostCallContext,
    surface: UiSurface,
    value: &str,
) -> Result<(), CallableError> {
    let key = match surface {
        UiSurface::Browser => "origins",
        UiSurface::Screen => "targets",
    };
    match grant.check(
        &ctx.agent_id,
        surface.capability(),
        &ctx.function,
        &CapParams::new(json!({ key: value })),
    ) {
        GrantDecision::Allow => Ok(()),
        GrantDecision::Deny(reason) => Err(CallableError::PermissionDenied(format!(
            "{}.{key}: {value:?} is not allowed by the agent's grant ({reason})",
            surface.as_str()
        ))),
    }
}

/// Whether `origin` is named EXACTLY (no wildcard) by the allowlist: the operator
/// opted into this host, so the SSRF guard's private-address rule yields to the
/// allowlist (ADR D2: "the allowlist is the sandbox"). Wildcard entries and
/// whole-capability grants keep the guard.
pub fn exactly_allowlisted(rule: &AllowRule, origin: &str) -> bool {
    match rule {
        AllowRule::Any => false,
        AllowRule::List(entries) => entries
            .iter()
            .any(|e| !e.contains('*') && e.trim().eq_ignore_ascii_case(origin)),
    }
}
