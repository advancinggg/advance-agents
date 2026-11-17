//! UI-automation seam (ADR 2026-10-28 D2) — the driver ports a product implements
//! for the `browser` and `screen` capability families, the typed values that
//! cross them, and the policy reader that projects an agent's `browser` /
//! `screen` grants.
//!
//! OSS owns the mechanism (`cap-ui`: the model-facing `browser__*` / `screen__*`
//! callables, the grant-param readers, the observation scan, the events); a
//! product owns the drivers (a WKWebView, the Mac's screen through
//! ScreenCaptureKit + Accessibility, an iPhone through Mirroring) and injects
//! them through `ComposeExtension::ui_drivers`. Nothing here names a platform.
//!
//! Text mode first (ADR D5): every observation is a typed snapshot of element
//! refs; pixels (`UiImage`) are carried by the types so S4 adds verbs, not
//! shapes. A `ref` is stable within one `generation`; a stale ref is a typed
//! refusal ([`UiError::StaleRef`]), never a guess.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Capability id of the browser family (ADR 2026-10-28 D1).
pub const BROWSER_CAPABILITY: &str = "browser";
/// Capability id of the screen family (ADR 2026-10-28 D1).
pub const SCREEN_CAPABILITY: &str = "screen";

/// Hard upper bound on the elements one snapshot may carry.
pub const MAX_SNAPSHOT_ELEMENTS: usize = 1000;
/// Default element budget of a snapshot when the model names none.
pub const DEFAULT_SNAPSHOT_ELEMENTS: usize = 200;
/// Longest wait a single `wait` callable may ask for (ADR D2 `wait {ms ≤ 5000}`).
pub const MAX_WAIT_MS: u64 = 5_000;
/// Longest text a single `read` returns before truncation (the dispatcher caps
/// a whole result at 32 KiB; this keeps room for the delimiters).
pub const MAX_READ_BYTES: usize = 24 * 1024;

/// Which family a value belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiSurface {
    Browser,
    Screen,
}

impl UiSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            UiSurface::Browser => "browser",
            UiSurface::Screen => "screen",
        }
    }

    /// The capability id that grants the family.
    pub fn capability(self) -> &'static str {
        match self {
            UiSurface::Browser => BROWSER_CAPABILITY,
            UiSurface::Screen => SCREEN_CAPABILITY,
        }
    }
}

impl fmt::Display for UiSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of thing a target id names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiTargetKind {
    /// A browser tab (in-app WebView or an external browser's tab).
    Tab,
    /// One window of an application.
    Window,
    /// An application as a whole (its front window is operated).
    App,
}

/// A tab (browser) or a window / application (screen) a driver can operate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiTargetInfo {
    /// Driver-chosen id, stable for the life of the target.
    pub id: String,
    pub kind: UiTargetKind,
    pub title: String,
    /// Browser: the tab's current URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Screen: the owning application (a bundle id on macOS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// The selected tab / the frontmost window.
    #[serde(default)]
    pub active: bool,
}

impl UiTargetInfo {
    /// `scheme://host[:port]` of `url`, lower-cased; `None` when the URL does
    /// not parse or has no host. This is the value the `browser.origins`
    /// allowlist is checked against.
    pub fn origin(&self) -> Option<String> {
        self.url.as_deref().and_then(origin_of)
    }
}

/// `scheme://host[:port]` of a URL, lower-cased, default ports dropped.
pub fn origin_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let mut origin = format!("{scheme}://{}", host.to_ascii_lowercase());
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Some(origin)
}

/// Does one `browser.origins` allowlist entry cover a request origin?
///
/// Entries are `scheme://host[:port]` (exact, case-insensitive) or
/// `scheme://*.host[:port]` (one leading wildcard label: any proper subdomain
/// of `host`, never `host` itself). Paths, queries and bare hosts are not
/// patterns and cover nothing; a request origin is always the normalized
/// `scheme://host[:port]` form of [`origin_of`]. cap-grant's CONTRACT-122
/// `browser` rule and cap-ui's listing filter share this one definition.
pub fn origin_covered(entry: &str, origin: &str) -> bool {
    let entry = entry.trim().to_ascii_lowercase();
    let origin = origin.trim().to_ascii_lowercase();
    let Some((e_scheme, e_rest)) = entry.split_once("://") else {
        return false;
    };
    let Some((o_scheme, o_rest)) = origin.split_once("://") else {
        return false;
    };
    if e_scheme.is_empty()
        || e_scheme != o_scheme
        || e_rest.is_empty()
        || o_rest.is_empty()
        || e_rest.contains('/')
        || o_rest.contains('/')
    {
        return false;
    }
    if let Some(suffix) = e_rest.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return false;
        }
        // Port must match when the entry names one; otherwise the request must
        // name none either (the default-port form).
        let (e_host, e_port) = split_host_port(suffix);
        let (o_host, o_port) = split_host_port(o_rest);
        return e_port == o_port
            && o_host.len() > e_host.len()
            && o_host.ends_with(e_host)
            && o_host.as_bytes()[o_host.len() - e_host.len() - 1] == b'.';
    }
    if e_rest.contains('*') {
        return false;
    }
    e_rest == o_rest
}

fn split_host_port(s: &str) -> (&str, Option<&str>) {
    // IPv6 literals (`[::1]:8080`) keep their brackets in the host part.
    if let Some(end) = s.rfind(']') {
        let (host, rest) = s.split_at(end + 1);
        return (host, rest.strip_prefix(':'));
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host, Some(port))
        }
        _ => (s, None),
    }
}

/// A rectangle in the target's own coordinate space (CSS pixels for a tab,
/// screen points for a window). Pixel-mode coordinates (S4) use the same space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// A state flag on an element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiState {
    /// Clickable / typeable / selectable.
    Interactive,
    Focused,
    Disabled,
    Checked,
    Selected,
    Expanded,
    Required,
    Readonly,
    /// A secure text field (`AXSecureTextField`, `<input type=password>`): its
    /// value is masked and typing into it is refused unless the grant says
    /// `secure-input: true` (ADR D2 observation security).
    Secure,
}

/// One element of a snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiElement {
    /// Stable within one generation, e.g. `e12`.
    #[serde(rename = "ref")]
    pub r#ref: String,
    /// ARIA / Accessibility role, lower-case (`link`, `button`, `textbox`, …).
    pub role: String,
    /// Accessible name (label, text content, title).
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounds: Option<UiRect>,
    #[serde(default)]
    pub states: Vec<UiState>,
    /// Nesting depth in the source tree (0 = root).
    #[serde(default)]
    pub depth: u32,
}

impl UiElement {
    pub fn has(&self, state: UiState) -> bool {
        self.states.contains(&state)
    }

    pub fn is_interactive(&self) -> bool {
        self.has(UiState::Interactive)
    }

    pub fn is_secure(&self) -> bool {
        self.has(UiState::Secure)
    }
}

/// A text observation of a target (`browser.snapshot`, `screen.describe`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiSnapshot {
    /// Bumped by the driver after every action that may have changed the
    /// element set; refs are valid only for this generation.
    pub generation: u64,
    pub target: UiTargetInfo,
    pub elements: Vec<UiElement>,
    /// Visible text, when the driver has it cheaply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The element budget cut the list.
    #[serde(default)]
    pub truncated: bool,
}

/// The result of an action.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiActionResult {
    pub generation: u64,
    /// The driver observed a change (navigation, value, focus…).
    pub changed: bool,
    /// The driver judged the action sensitive (secure field, payment-like
    /// origin, destructive verb); the confirmation gate (ADR D3) reads it.
    #[serde(default)]
    pub sensitive: bool,
    /// Driver-authored text, never page or application content: the action
    /// line shows it outside the observation delimiters, unscanned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The target after the action (its URL after a navigation). The action
    /// line reports only its origin (browser) or its id and application id
    /// (screen); titles and URLs reach the model through observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<UiTargetInfo>,
}

/// The result of a `read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiReadResult {
    pub generation: u64,
    pub text: String,
    #[serde(default)]
    pub truncated: bool,
}

/// A captured image (ADR D4 / S4). Carried by the types from S1 so the pixel
/// verbs add handlers, not shapes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UiImage {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// Capture scale (points → pixels), kept so a model point maps back.
    pub scale: f32,
}

/// Which part of a target a snapshot covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiScope {
    /// What is visible now (the viewport, the visible window content).
    Viewport,
    /// The whole document / window tree.
    Full,
}

/// Snapshot options (`browser.snapshot`, `screen.describe`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotOptions {
    pub scope: UiScope,
    pub interactive_only: bool,
    pub max_elements: usize,
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            scope: UiScope::Viewport,
            interactive_only: false,
            max_elements: DEFAULT_SNAPSHOT_ELEMENTS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

impl Default for MouseButton {
    fn default() -> Self {
        MouseButton::Left
    }
}

/// `browser.tabs {action}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum TabAction {
    List,
    New { url: Option<String> },
    Close { tab_id: String },
    Select { tab_id: String },
}

/// `browser.back` / `forward` / `reload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryAction {
    Back,
    Forward,
    Reload,
}

/// A browser action on the current (or named) tab. Text mode (S1) only; pixel
/// verbs arrive with S4.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum BrowserAction {
    Click {
        #[serde(rename = "ref")]
        r#ref: String,
        #[serde(default)]
        button: MouseButton,
        /// 1 = click, 2 = double click.
        #[serde(default = "one")]
        count: u32,
    },
    Type {
        #[serde(rename = "ref")]
        r#ref: String,
        text: String,
        /// Press Enter afterwards.
        #[serde(default)]
        submit: bool,
        /// Clear the field first.
        #[serde(default)]
        clear: bool,
        /// Set by the family from the grant (`secure-input: true`); a driver
        /// refuses typing into a [`UiState::Secure`] field when this is false.
        #[serde(default)]
        allow_secure: bool,
    },
    Press {
        /// A key or chord in the vendor-neutral form `Enter`, `Escape`,
        /// `Tab`, `ArrowDown`, `cmd+a`, `ctrl+shift+t`.
        key: String,
    },
    Scroll {
        #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
        r#ref: Option<String>,
        /// Pixels; positive = right / down.
        dx: i64,
        dy: i64,
    },
    Select {
        #[serde(rename = "ref")]
        r#ref: String,
        values: Vec<String>,
    },
    Hover {
        #[serde(rename = "ref")]
        r#ref: String,
    },
}

fn one() -> u32 {
    1
}

/// A screen action on the current (or named) target. Text (AX) mode only in S1.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum ScreenAction {
    Click {
        #[serde(rename = "ref")]
        r#ref: String,
        #[serde(default)]
        button: MouseButton,
        #[serde(default = "one")]
        count: u32,
        /// `cmd`, `shift`, `alt`, `ctrl`.
        #[serde(default)]
        modifiers: Vec<String>,
    },
    Type {
        /// The element to type into; `None` = the focused element.
        #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
        r#ref: Option<String>,
        text: String,
        /// Replace the current value instead of appending.
        #[serde(default)]
        replace: bool,
        #[serde(default)]
        allow_secure: bool,
    },
    Key {
        /// A chord such as `cmd+s`, `Enter`, `Escape`.
        keys: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hold_ms: Option<u64>,
    },
    Scroll {
        #[serde(rename = "ref")]
        r#ref: String,
        dx: i64,
        dy: i64,
    },
    /// Bring the target to the front and make it the current one.
    Focus,
}

/// `browser.wait {text?, ms?}`: wait up to `ms` for `text` to appear (or just
/// `ms` when `text` is `None`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WaitCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub ms: u64,
}

/// A typed refusal or failure from a driver. The family maps every arm onto a
/// Layer 3 refusal class and a fixed reason; a driver never answers with a
/// guess.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UiError {
    /// No driver is attached for the surface (the composition registered none).
    NoDriver,
    /// A driver exists but its surface is not ready (the app is not connected,
    /// mirroring is off, the device is locked). The text is the reason.
    Unavailable {
        reason: String,
    },
    UnknownTarget {
        target: String,
    },
    /// The ref belongs to an earlier generation; take a new snapshot.
    StaleRef {
        #[serde(rename = "ref")]
        r#ref: String,
        generation: u64,
    },
    UnknownRef {
        #[serde(rename = "ref")]
        r#ref: String,
    },
    /// Typing into a secure field without `secure-input`.
    SecureField {
        #[serde(rename = "ref")]
        r#ref: String,
    },
    /// The driver cannot perform this verb on this target / site.
    Unsupported {
        reason: String,
    },
    Timeout,
    /// Driver-side policy (own windows, downloads, a locked phone…).
    Refused {
        reason: String,
    },
    /// Anything else, with the driver's message.
    Driver {
        message: String,
    },
}

impl fmt::Display for UiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UiError::NoDriver => f.write_str("no ui driver attached"),
            UiError::Unavailable { reason } => write!(f, "ui driver unavailable: {reason}"),
            UiError::UnknownTarget { target } => write!(f, "unknown target {target:?}"),
            UiError::StaleRef { r#ref, generation } => write!(
                f,
                "stale ref {ref:?}: the page changed (generation is now {generation}); take a new snapshot",
                ref = r#ref
            ),
            UiError::UnknownRef { r#ref } => write!(f, "unknown ref {ref:?}", ref = r#ref),
            UiError::SecureField { r#ref } => write!(
                f,
                "{ref:?} is a secure field; typing into it is refused (grant `secure-input` is false)",
                ref = r#ref
            ),
            UiError::Unsupported { reason } => write!(f, "unsupported: {reason}"),
            UiError::Timeout => f.write_str("timed out"),
            UiError::Refused { reason } => write!(f, "refused: {reason}"),
            UiError::Driver { message } => write!(f, "driver error: {message}"),
        }
    }
}

impl std::error::Error for UiError {}

/// The browser family's driver (ADR D2 `BrowserDriverPort`). `tab: None` means
/// the selected tab. Implemented by a product (the in-app WKWebView on macOS and
/// iOS; an external browser through MCP is an operator option, not a port).
#[async_trait]
pub trait BrowserDriverPort: Send + Sync {
    /// `in-app` or `external` — matched against the grant's `surfaces`.
    fn surface_kind(&self) -> &'static str {
        "in-app"
    }

    /// Perform a tab action and return the tab list afterwards.
    async fn tabs(&self, action: TabAction) -> Result<Vec<UiTargetInfo>, UiError>;

    /// The named (or selected) tab, with its current URL.
    async fn current(&self, tab: Option<&str>) -> Result<UiTargetInfo, UiError>;

    /// Top-level navigation. The family has already checked the scheme, the
    /// origin allowlist and the SSRF guard.
    async fn navigate(&self, tab: Option<&str>, url: &str) -> Result<UiActionResult, UiError>;

    async fn history(
        &self,
        tab: Option<&str>,
        action: HistoryAction,
    ) -> Result<UiActionResult, UiError>;

    async fn snapshot(
        &self,
        tab: Option<&str>,
        options: SnapshotOptions,
    ) -> Result<UiSnapshot, UiError>;

    async fn act(
        &self,
        tab: Option<&str>,
        action: BrowserAction,
    ) -> Result<UiActionResult, UiError>;

    /// Text of one element, or of the page when `r#ref` is `None`.
    async fn read(&self, tab: Option<&str>, r#ref: Option<&str>) -> Result<UiReadResult, UiError>;

    async fn wait(
        &self,
        tab: Option<&str>,
        condition: WaitCondition,
    ) -> Result<UiActionResult, UiError>;
}

/// The screen family's driver (ADR D2 `ScreenDriverPort`). Refs are scoped to
/// the *current* target: the one last described or focused. `target: None`
/// means that current target.
#[async_trait]
pub trait ScreenDriverPort: Send + Sync {
    /// Windows / apps the driver can operate. A product driver never lists its
    /// own windows; the family additionally filters by the grant's `targets`.
    async fn list_targets(&self) -> Result<Vec<UiTargetInfo>, UiError>;

    /// The current target, if any.
    async fn current(&self) -> Result<Option<UiTargetInfo>, UiError>;

    /// Describe a target and make it the current one.
    async fn describe(&self, target: &str, options: SnapshotOptions)
        -> Result<UiSnapshot, UiError>;

    async fn act(
        &self,
        target: Option<&str>,
        action: ScreenAction,
    ) -> Result<UiActionResult, UiError>;

    async fn read(&self, target: Option<&str>, r#ref: &str) -> Result<UiReadResult, UiError>;

    async fn wait(&self, target: Option<&str>, ms: u64) -> Result<UiActionResult, UiError>;
}

// ─────────────────────────────────────────────────────────────────────────
// Grant policy projection (CONTRACT-122 param families `browser` / `screen`)
// ─────────────────────────────────────────────────────────────────────────

/// When the family parks a call for the user's confirmation (ADR D3; enforced
/// from S2 — S1 reads and reports it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmPolicy {
    Never,
    Sensitive,
    Always,
}

impl ConfirmPolicy {
    /// Most restrictive first: `always` > `sensitive` > `never`.
    pub fn rank(self) -> u8 {
        match self {
            ConfirmPolicy::Never => 0,
            ConfirmPolicy::Sensitive => 1,
            ConfirmPolicy::Always => 2,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "never" => Some(ConfirmPolicy::Never),
            "sensitive" => Some(ConfirmPolicy::Sensitive),
            "always" => Some(ConfirmPolicy::Always),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ConfirmPolicy::Never => "never",
            ConfirmPolicy::Sensitive => "sensitive",
            ConfirmPolicy::Always => "always",
        }
    }
}

/// `screen.mode`: `ax` (text, S1) or `pixel` (S4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenMode {
    Ax,
    Pixel,
}

impl ScreenMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "ax" => Some(ScreenMode::Ax),
            "pixel" => Some(ScreenMode::Pixel),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ScreenMode::Ax => "ax",
            ScreenMode::Pixel => "pixel",
        }
    }
}

/// An allowlist dimension of a grant: `origins` (browser) or `targets` (screen).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllowRule {
    /// The grant names no list (`browser: true`, or params without the key): any
    /// value is allowed — the whole-capability form of CONTRACT-122.
    Any,
    /// Exactly these entries; an empty list denies everything (ADR D2).
    List(Vec<String>),
}

impl AllowRule {
    pub fn is_empty_list(&self) -> bool {
        matches!(self, AllowRule::List(v) if v.is_empty())
    }

    /// `browser.origins`: does the rule cover a normalized origin
    /// (`scheme://host[:port]`)? `Any` covers everything; a list covers what
    /// one of its entries covers ([`origin_covered`]).
    pub fn covers_origin(&self, origin: &str) -> bool {
        match self {
            AllowRule::Any => true,
            AllowRule::List(entries) => entries.iter().any(|e| origin_covered(e, origin)),
        }
    }

    /// `screen.targets`: does the rule name an application id (exact,
    /// case-insensitive)?
    pub fn covers_target(&self, target: &str) -> bool {
        match self {
            AllowRule::Any => true,
            AllowRule::List(entries) => entries
                .iter()
                .any(|e| e.trim().eq_ignore_ascii_case(target.trim())),
        }
    }
}

/// The agent's effective `browser` grant, merged across its active grants
/// (union, like `tools.ids`). Knobs default to their most restrictive value
/// when no grant names them (ADR D2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserGrantPolicy {
    pub origins: AllowRule,
    /// `in-app`, `external`.
    pub surfaces: Vec<String>,
    pub confirm: ConfirmPolicy,
    pub downloads: bool,
}

impl BrowserGrantPolicy {
    /// Whole-capability grant with every knob at its most restrictive value.
    pub fn whole_capability() -> Self {
        Self {
            origins: AllowRule::Any,
            surfaces: vec!["in-app".to_string()],
            confirm: ConfirmPolicy::Always,
            downloads: false,
        }
    }
}

/// The agent's effective `screen` grant (see [`BrowserGrantPolicy`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenGrantPolicy {
    /// Application ids (bundle ids on macOS).
    pub targets: AllowRule,
    pub mode: ScreenMode,
    pub confirm: ConfirmPolicy,
    pub secure_input: bool,
}

impl ScreenGrantPolicy {
    pub fn whole_capability() -> Self {
        Self {
            targets: AllowRule::Any,
            mode: ScreenMode::Ax,
            confirm: ConfirmPolicy::Always,
            secure_input: false,
        }
    }
}

/// Per-agent projection of the `browser` / `screen` grants, for the policy knobs
/// and for filtering listings. Provided by MODULE-013 (`cap_grant::UiPolicyReaderImpl`
/// over `GrantStore`); dependency-inverted like [`crate::traits::ToolsGrantReader`].
///
/// Read-only and silent: it authorizes nothing and emits no `authz.checked` event.
/// Allowlist decisions stay with [`crate::traits::GrantCheck`], which the family
/// calls with the request's `origins` / `targets` params (CONTRACT-122 subset).
pub trait UiPolicyReader: Send + Sync + fmt::Debug {
    /// `None` = no active, unexpired `browser` grant.
    fn browser_policy(&self, agent_id: &str) -> Option<BrowserGrantPolicy>;
    /// `None` = no active, unexpired `screen` grant.
    fn screen_policy(&self, agent_id: &str) -> Option<ScreenGrantPolicy>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_of_normalizes_scheme_host_and_default_port() {
        assert_eq!(
            origin_of("HTTPS://Example.COM/path?q=1").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            origin_of("http://localhost:8080/x").as_deref(),
            Some("http://localhost:8080")
        );
        assert_eq!(origin_of("javascript:alert(1)"), None);
        assert_eq!(origin_of("not a url"), None);
    }

    #[test]
    fn confirm_policy_ranks_most_restrictive_highest() {
        assert!(ConfirmPolicy::Always.rank() > ConfirmPolicy::Sensitive.rank());
        assert!(ConfirmPolicy::Sensitive.rank() > ConfirmPolicy::Never.rank());
        assert_eq!(
            ConfirmPolicy::parse("sensitive"),
            Some(ConfirmPolicy::Sensitive)
        );
        assert_eq!(ConfirmPolicy::parse("maybe"), None);
    }

    #[test]
    fn actions_round_trip_through_json() {
        let action = BrowserAction::Type {
            r#ref: "e3".into(),
            text: "hello".into(),
            submit: true,
            clear: false,
            allow_secure: false,
        };
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"verb\":\"type\""));
        assert!(json.contains("\"ref\":\"e3\""));
        let back: BrowserAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, action);

        let err = UiError::StaleRef {
            r#ref: "e1".into(),
            generation: 4,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"kind\":\"stale_ref\""));
        let back: UiError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }
}
