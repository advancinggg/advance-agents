//! CONTRACT-190 providers family — the operator-facing LLM provider administration surface
//!.
//!
//! Routes (family `providers`; `/client/costs/providers/…` stays in the `costs` family):
//! - `GET  /client/providers`                              list, YAML order, index 0 is `selected` (`Scope::ReadInventory`)
//! - `POST /client/providers`                              create an entry, never a key (`Scope::ApproveGrants`, mutation)
//! - `GET  /client/providers/{provider_id}`                one entry
//! - `POST /client/providers/{provider_id}:update`         replace the given fields; `provider_id` is immutable
//! - `POST /client/providers/{provider_id}:delete`         refused for the last entry / a referenced entry
//! - `POST /client/providers/{provider_id}:set-key`        SENSITIVE body; loopback peers only; preflight before store
//! - `POST /client/providers/{provider_id}:clear-key`
//! - `POST /client/providers/{provider_id}:preflight`      re-check the stored key
//! - `POST /client/providers/{provider_id}:select`         move to index 0
//!
//! The family reuses the packs-family scopes on purpose: `Scope` is a closed enum inventoried by
//! the AC-14 compat gate, so minting `ReadProviders` / `ManageProviders` is an
//! `api_version`-incrementing change (§2.12).
//!
//! Every request is validated HERE, before the provider is consulted (id charset, bounded
//! strings, control-free strings, closed enum spellings, finite numbers). The runtime's own
//! `load_config` validation (https-only endpoints, positive costs, required rate limits, …) is the
//! provider's job; it answers `invalid_request`. Provider outcomes are projected through
//! [`ProviderError::into_client_error`] with fixed client-safe messages.
//!
//! Key hygiene: the `:set-key` body is the only place key material enters this crate. The
//! request DTO's `Debug` is redacted, the key is never copied into an error, a warning, an audit
//! record (audit carries route + family only) or a response (`ClientProviderKeyResult` reports
//! `stored` and the preflight verdict), and the idempotency layer fingerprints the body with
//! SHA-256 instead of retaining it.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{ClientApi, HandlerCtx, HandlerResponse, HandlerSpec};
use crate::envelope::{
    ClientError, ClientErrorCode, ClientWarning, WARNING_PREFLIGHT_SKIPPED, WARNING_RELOAD_PENDING,
    WARNING_RESTART_REQUIRED,
};
use crate::provider::{provider_or_unavailable, ProviderAdminSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// Provider id bound: `^[A-Za-z0-9_-]{1,64}$` (mirrors the agents-family id rule).
pub const MAX_PROVIDER_ID_LEN: usize = 64;
/// Bound on an endpoint URL string.
pub const MAX_ENDPOINT_LEN: usize = 2048;
/// Bound on the number of `model_aliases` entries.
pub const MAX_MODEL_ALIASES: usize = 64;
/// Bound on one alias key / value.
pub const MAX_MODEL_ALIAS_LEN: usize = 128;
/// Secret reference name bound: `^[A-Za-z0-9_.-]{1,128}$`.
pub const MAX_SECRET_NAME_LEN: usize = 128;
/// Bound on key material accepted by `:set-key` (bytes).
pub const MAX_KEY_BYTES: usize = 8 * 1024;
/// Bound on a sidecar command path.
pub const MAX_SIDECAR_COMMAND_LEN: usize = 1024;
/// Bound on the sidecar argument list / one argument.
pub const MAX_SIDECAR_ARGS: usize = 64;
pub const MAX_SIDECAR_ARG_LEN: usize = 1024;
/// Bound on the free-form optional strings (`embedding_model`, `profile_id`, `device_id`).
pub const MAX_OPTIONAL_STRING_LEN: usize = 256;

/// Closed spellings of `backend_class` (`InferenceBackendClass`).
pub const BACKEND_CLASSES: &[&str] = &["cloud-http", "local", "mesh-remote"];
/// Closed spellings of `backend` (`ProviderBackend`).
pub const BACKENDS: &[&str] = &["openai-chat", "openai-responses", "anthropic-messages"];
/// Closed spellings of `auth_scheme` (`AuthScheme`).
pub const AUTH_SCHEMES: &[&str] = &["bearer", "x-api-key", "api-key"];
/// The `backend_class` a create defaults to.
pub const DEFAULT_BACKEND_CLASS: &str = "cloud-http";

const RELOAD_PENDING_MESSAGE: &str =
    "runtime-config.yaml was written but the daemon has not observed the reload yet; it applies at the next watcher tick";
const RESTART_REQUIRED_MESSAGE: &str =
    "a sidecar-backed local provider is spawned at daemon start; restart the daemon to apply";
const PREFLIGHT_SKIPPED_MESSAGE: &str =
    "preflight runs only for cloud-http providers; the key was stored without verification";

// ── DTOs (CONTRACT-192 schema components) ────────────────────────────────────────────────────

/// Per-million-token prices (USD) of one provider entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientProviderCost {
    pub input_per_mtoken: f64,
    pub output_per_mtoken: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_per_mtoken: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_per_mtoken: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_1h_per_mtoken: Option<f64>,
}

/// The provider's rate limit (required by the runtime for every entry).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientProviderRateLimit {
    pub requests_per_minute: u64,
    pub tokens_per_minute: u64,
}

/// The provider's retry defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientProviderRetry {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

/// A local-class provider's sidecar launch spec. Request-only: an absolute host command path is
/// never echoed back (summaries report `sidecar_present`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientProviderSidecar {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// The provider's key reference: the secret NAME and whether a value is stored. Never a value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderKey {
    pub secret_name: String,
    pub present: bool,
}

/// One preflight verdict (`:set-key` / `:preflight`). `reason` is a fixed vocabulary: the
/// `LlmError` variant name (`model-not-available`, `provider-error`, …), `timeout`, `cancelled`,
/// `missing-key`, `missing-provider`, or `unsupported-backend-class`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderPreflightResult {
    pub ok: bool,
    /// Unix milliseconds of the check.
    pub checked_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One provider entry (`GET /client/providers` rows, `GET /client/providers/{id}`, and the
/// response of every entry mutation).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderSummary {
    pub provider_id: String,
    /// `cloud-http | local | mesh-remote`.
    pub backend_class: String,
    /// `openai-chat | openai-responses | anthropic-messages`; absent = resolver-side inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Connect URL for `cloud-http`; may be empty for other classes.
    pub endpoint: String,
    /// Alias key → concrete model id.
    pub model_aliases: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,
    /// `bearer | x-api-key | api-key`; absent = the backend's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_scheme: Option<String>,
    pub cost: ClientProviderCost,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<ClientProviderRateLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_default: Option<ClientProviderRetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Whether the entry carries a sidecar launch spec (the spec itself is never echoed).
    pub sidecar_present: bool,
    pub key: ClientProviderKey,
    /// `true` for the first YAML entry — the provider the runtime resolves by default.
    pub selected: bool,
    /// The last preflight verdict recorded by this daemon (in-memory; cleared at restart).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_preflight: Option<ClientProviderPreflightResult>,
}

/// `GET /client/providers`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderList {
    /// YAML order; exactly the first entry (if any) is `selected`.
    pub providers: Vec<ClientProviderSummary>,
}

/// The body of `POST /client/providers`. Carries NO key material — keys go through `:set-key`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientCreateProviderRequest {
    /// `^[A-Za-z0-9_-]{1,64}$`; the YAML `id`.
    pub provider_id: String,
    /// `cloud-http` (default) | `local` | `mesh-remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Required for `cloud-http`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Non-empty.
    pub model_aliases: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_scheme: Option<String>,
    /// Secret reference name; defaults to `<provider_id>-api-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_secret: Option<String>,
    pub cost: ClientProviderCost,
    /// Required (the runtime refuses an entry without a rate limit).
    pub rate_limit: ClientProviderRateLimit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_default: Option<ClientProviderRetry>,
    /// `local` class only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar: Option<ClientProviderSidecar>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Required by the runtime for `mesh-remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// The body of `POST /client/providers/{provider_id}:update`. Every field is optional; at least
/// one is required. A present field REPLACES the stored one; an absent field (and any YAML key
/// this DTO does not model) is left untouched. The id is immutable.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientUpdateProviderRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_aliases: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<ClientProviderCost>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<ClientProviderRateLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_default: Option<ClientProviderRetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar: Option<ClientProviderSidecar>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

impl ClientUpdateProviderRequest {
    /// Whether the update names at least one field.
    pub fn is_empty(&self) -> bool {
        self.backend_class.is_none()
            && self.backend.is_none()
            && self.endpoint.is_none()
            && self.model_aliases.is_none()
            && self.embedding_model.is_none()
            && self.auth_scheme.is_none()
            && self.api_key_secret.is_none()
            && self.cost.is_none()
            && self.rate_limit.is_none()
            && self.retry_default.is_none()
            && self.sidecar.is_none()
            && self.profile_id.is_none()
            && self.device_id.is_none()
    }
}

/// The body of `POST /client/providers/{provider_id}:set-key`. SENSITIVE: `Debug` is redacted
/// and the value is never echoed by any response, warning, error or audit record.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientSetProviderKeyRequest {
    pub key: String,
}

impl std::fmt::Debug for ClientSetProviderKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSetProviderKeyRequest")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// The result of `:set-key`: whether the key was stored (only after a passing preflight for
/// `cloud-http`) and the preflight verdict (absent when preflight was skipped).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderKeyResult {
    pub stored: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight: Option<ClientProviderPreflightResult>,
}

/// The result of `:delete`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderDeleteResult {
    pub provider_id: String,
    /// The new first entry (the provider the runtime now resolves by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_provider_id: Option<String>,
}

// ── Provider-side outcome shape (not a wire DTO) ─────────────────────────────────────────────

/// A non-fatal advisory a provider attaches to a successful mutation. The handler maps each to
/// a fixed [`ClientWarning`] (code + message); adapters never author warning text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAdminWarning {
    /// The YAML was written but the daemon's config watcher did not report the reload in time.
    ReloadPending,
    /// A sidecar-backed local entry applies at the next daemon start.
    RestartRequired,
    /// The key was stored without a preflight (non-`cloud-http` entry).
    PreflightSkipped,
}

impl ProviderAdminWarning {
    pub fn to_client_warning(self) -> ClientWarning {
        match self {
            ProviderAdminWarning::ReloadPending => {
                ClientWarning::new(WARNING_RELOAD_PENDING, RELOAD_PENDING_MESSAGE)
            }
            ProviderAdminWarning::RestartRequired => {
                ClientWarning::new(WARNING_RESTART_REQUIRED, RESTART_REQUIRED_MESSAGE)
            }
            ProviderAdminWarning::PreflightSkipped => {
                ClientWarning::new(WARNING_PREFLIGHT_SKIPPED, PREFLIGHT_SKIPPED_MESSAGE)
            }
        }
    }
}

/// A successful provider mutation plus its advisories.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderAdminOutcome<T> {
    pub value: T,
    pub warnings: Vec<ProviderAdminWarning>,
}

impl<T> ProviderAdminOutcome<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: ProviderAdminWarning) -> Self {
        self.warnings.push(warning);
        self
    }
}

// ── Validation ───────────────────────────────────────────────────────────────────────────────

fn invalid(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, message)
}

/// `^[A-Za-z0-9_-]{1,64}$`.
pub fn validate_provider_id(id: &str) -> Result<(), ClientError> {
    if id.is_empty()
        || id.len() > MAX_PROVIDER_ID_LEN
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(invalid("invalid provider id"));
    }
    Ok(())
}

/// `^[A-Za-z0-9_.-]{1,128}$` — a secret reference name.
pub fn validate_secret_name(name: &str) -> Result<(), ClientError> {
    if name.is_empty()
        || name.len() > MAX_SECRET_NAME_LEN
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(invalid("invalid api_key_secret name"));
    }
    Ok(())
}

/// Bounded, control-free, `https://` or `http://` (the localhost-only rule for `http://` is the
/// runtime's `load_config` check).
pub fn validate_endpoint(endpoint: &str) -> Result<(), ClientError> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_LEN
        || endpoint
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        || !(endpoint.starts_with("https://") || endpoint.starts_with("http://"))
    {
        return Err(invalid("invalid endpoint"));
    }
    Ok(())
}

/// Non-empty, bounded map of bounded control-free strings.
pub fn validate_model_aliases(aliases: &BTreeMap<String, String>) -> Result<(), ClientError> {
    if aliases.is_empty() || aliases.len() > MAX_MODEL_ALIASES {
        return Err(invalid("model_aliases must have 1..=64 entries"));
    }
    for (key, value) in aliases {
        for s in [key, value] {
            if s.is_empty() || s.len() > MAX_MODEL_ALIAS_LEN || s.chars().any(|c| c.is_control()) {
                return Err(invalid("invalid model alias"));
            }
        }
    }
    Ok(())
}

/// Key material accepted by `:set-key`: non-empty after trimming, bounded, control-free.
pub fn validate_key(key: &str) -> Result<(), ClientError> {
    if key.len() > MAX_KEY_BYTES {
        return Err(invalid("key exceeds the size bound"));
    }
    if key.trim().is_empty() {
        return Err(invalid("key must not be empty"));
    }
    if key.chars().any(|c| c.is_control()) {
        return Err(invalid("key must not contain control characters"));
    }
    Ok(())
}

fn validate_enum(value: &str, allowed: &[&str], what: &'static str) -> Result<(), ClientError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(invalid(what))
    }
}

fn validate_optional_string(value: &str, what: &'static str) -> Result<(), ClientError> {
    if value.is_empty()
        || value.len() > MAX_OPTIONAL_STRING_LEN
        || value.chars().any(|c| c.is_control())
    {
        return Err(invalid(what));
    }
    Ok(())
}

fn finite_non_negative(v: f64) -> bool {
    v.is_finite() && v >= 0.0
}

pub fn validate_cost(cost: &ClientProviderCost) -> Result<(), ClientError> {
    let ok = finite_non_negative(cost.input_per_mtoken)
        && finite_non_negative(cost.output_per_mtoken)
        && cost.cache_read_per_mtoken.is_none_or(finite_non_negative)
        && cost.cache_write_per_mtoken.is_none_or(finite_non_negative)
        && cost
            .cache_write_1h_per_mtoken
            .is_none_or(finite_non_negative);
    if ok {
        Ok(())
    } else {
        Err(invalid("cost values must be finite and non-negative"))
    }
}

pub fn validate_rate_limit(rl: &ClientProviderRateLimit) -> Result<(), ClientError> {
    if rl.requests_per_minute == 0 || rl.tokens_per_minute == 0 {
        return Err(invalid("rate_limit values must be > 0"));
    }
    Ok(())
}

pub fn validate_retry(retry: &ClientProviderRetry) -> Result<(), ClientError> {
    if retry.max_delay_ms < retry.base_delay_ms {
        return Err(invalid(
            "retry_default.max_delay_ms must be >= base_delay_ms",
        ));
    }
    Ok(())
}

pub fn validate_sidecar(sidecar: &ClientProviderSidecar) -> Result<(), ClientError> {
    if sidecar.command.is_empty()
        || sidecar.command.len() > MAX_SIDECAR_COMMAND_LEN
        || sidecar.command.chars().any(|c| c.is_control())
    {
        return Err(invalid("invalid sidecar command"));
    }
    if sidecar.args.len() > MAX_SIDECAR_ARGS {
        return Err(invalid("too many sidecar args"));
    }
    for arg in &sidecar.args {
        if arg.len() > MAX_SIDECAR_ARG_LEN || arg.chars().any(|c| c.is_control()) {
            return Err(invalid("invalid sidecar arg"));
        }
    }
    Ok(())
}

/// Validate a create request (everything the handler can decide without the runtime).
pub fn validate_create_request(req: &ClientCreateProviderRequest) -> Result<(), ClientError> {
    validate_provider_id(&req.provider_id)?;
    let class = req
        .backend_class
        .as_deref()
        .unwrap_or(DEFAULT_BACKEND_CLASS);
    validate_enum(class, BACKEND_CLASSES, "invalid backend_class")?;
    if let Some(backend) = &req.backend {
        validate_enum(backend, BACKENDS, "invalid backend")?;
    }
    match &req.endpoint {
        Some(endpoint) => validate_endpoint(endpoint)?,
        None if class == "cloud-http" => {
            return Err(invalid("endpoint is required for cloud-http providers"))
        }
        None => {}
    }
    validate_model_aliases(&req.model_aliases)?;
    if let Some(model) = &req.embedding_model {
        validate_optional_string(model, "invalid embedding_model")?;
    }
    if let Some(scheme) = &req.auth_scheme {
        validate_enum(scheme, AUTH_SCHEMES, "invalid auth_scheme")?;
    }
    if let Some(name) = &req.api_key_secret {
        validate_secret_name(name)?;
    }
    validate_cost(&req.cost)?;
    validate_rate_limit(&req.rate_limit)?;
    if let Some(retry) = &req.retry_default {
        validate_retry(retry)?;
    }
    if let Some(sidecar) = &req.sidecar {
        if class != "local" {
            return Err(invalid("sidecar is only valid for local providers"));
        }
        validate_sidecar(sidecar)?;
    }
    if let Some(profile) = &req.profile_id {
        validate_optional_string(profile, "invalid profile_id")?;
    }
    if let Some(device) = &req.device_id {
        validate_optional_string(device, "invalid device_id")?;
    }
    Ok(())
}

/// Validate an update request: at least one field, each present field well-formed.
pub fn validate_update_request(req: &ClientUpdateProviderRequest) -> Result<(), ClientError> {
    if req.is_empty() {
        return Err(invalid("empty provider update"));
    }
    if let Some(class) = &req.backend_class {
        validate_enum(class, BACKEND_CLASSES, "invalid backend_class")?;
    }
    if let Some(backend) = &req.backend {
        validate_enum(backend, BACKENDS, "invalid backend")?;
    }
    if let Some(endpoint) = &req.endpoint {
        validate_endpoint(endpoint)?;
    }
    if let Some(aliases) = &req.model_aliases {
        validate_model_aliases(aliases)?;
    }
    if let Some(model) = &req.embedding_model {
        validate_optional_string(model, "invalid embedding_model")?;
    }
    if let Some(scheme) = &req.auth_scheme {
        validate_enum(scheme, AUTH_SCHEMES, "invalid auth_scheme")?;
    }
    if let Some(name) = &req.api_key_secret {
        validate_secret_name(name)?;
    }
    if let Some(cost) = &req.cost {
        validate_cost(cost)?;
    }
    if let Some(rl) = &req.rate_limit {
        validate_rate_limit(rl)?;
    }
    if let Some(retry) = &req.retry_default {
        validate_retry(retry)?;
    }
    if let Some(sidecar) = &req.sidecar {
        validate_sidecar(sidecar)?;
    }
    if let Some(profile) = &req.profile_id {
        validate_optional_string(profile, "invalid profile_id")?;
    }
    if let Some(device) = &req.device_id {
        validate_optional_string(device, "invalid device_id")?;
    }
    Ok(())
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, ClientError> {
    if !body.is_object() {
        return Err(invalid("invalid provider request body"));
    }
    serde_json::from_value(body.clone()).map_err(|_| invalid("invalid provider request body"))
}

/// Mark the irreversible provider-entry boundary (CONTRACT-190 reserve-before-execute): every
/// mutation of this family has filesystem / secret-store / network side effects, so a key never
/// re-enters the provider. Called only after validation AND after the slot resolved, so a
/// validation failure or an absent provider stays retryable under the same key.
fn mark_provider_entry(ctx: &HandlerCtx) -> Result<(), ClientError> {
    match ctx.mutation.as_ref() {
        Some(mutation) => mutation.mark_provider_entry(),
        None => Ok(()),
    }
}

fn outcome_response<T: Serialize>(outcome: ProviderAdminOutcome<T>) -> HandlerResponse {
    let data = serde_json::to_value(outcome.value).expect("provider outcome serializes");
    if outcome.warnings.is_empty() {
        HandlerResponse::data(data)
    } else {
        HandlerResponse::with_warnings(
            data,
            outcome
                .warnings
                .into_iter()
                .map(ProviderAdminWarning::to_client_warning)
                .collect(),
        )
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────────────────────

/// Register the providers routes, capturing the shared provider slot so a builder can inject
/// the concrete provider AFTER registration. Routes are always registered; an absent provider
/// yields `module_unavailable` (never `unknown_route`).
pub(crate) fn register(api: &mut ClientApi, slot: ProviderAdminSlot) {
    // GET /client/providers — every entry, YAML order.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_PROVIDERS,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let providers = provider
                .list_providers()
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(ClientProviderList { providers })
                .expect("ClientProviderList serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // POST /client/providers — create an entry (no key).
    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_PROVIDERS,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let req: ClientCreateProviderRequest = parse_body(&ctx.body)?;
            validate_create_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let outcome = provider
                .create_provider(&req)
                .map_err(ProviderError::into_client_error)?;
            Ok(outcome_response(outcome))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    // GET /client/providers/{provider_id} — one entry.
    let s = slot.clone();
    api.register_templated(
        Method::Get,
        routes::TPL_PROVIDER_GET,
        HandlerSpec::read(true, move |ctx| {
            let id = ctx.path_param("provider_id")?;
            validate_provider_id(&id)?;
            let provider = provider_or_unavailable(&s)?;
            let summary = provider
                .get_provider(&id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(summary).expect("ClientProviderSummary serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // POST /client/providers/{provider_id}:update — replace the given fields.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_PROVIDER_UPDATE,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let id = ctx.path_param("provider_id")?;
            validate_provider_id(&id)?;
            let req: ClientUpdateProviderRequest = parse_body(&ctx.body)?;
            validate_update_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let outcome = provider
                .update_provider(&id, &req)
                .map_err(ProviderError::into_client_error)?;
            Ok(outcome_response(outcome))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    // POST /client/providers/{provider_id}:delete.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_PROVIDER_DELETE,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let id = ctx.path_param("provider_id")?;
            validate_provider_id(&id)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let outcome = provider
                .delete_provider(&id)
                .map_err(ProviderError::into_client_error)?;
            Ok(outcome_response(outcome))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    // POST /client/providers/{provider_id}:set-key — SENSITIVE; loopback peers only.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_PROVIDER_SET_KEY,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            if !ctx.is_loopback_peer {
                return Err(ClientError::new(
                    ClientErrorCode::Forbidden,
                    "key material is accepted from loopback peers only",
                ));
            }
            let id = ctx.path_param("provider_id")?;
            validate_provider_id(&id)?;
            let req: ClientSetProviderKeyRequest = parse_body(&ctx.body)?;
            validate_key(&req.key)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let outcome = provider
                .set_key(&id, &req.key)
                .map_err(ProviderError::into_client_error)?;
            Ok(outcome_response(outcome))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    // POST /client/providers/{provider_id}:clear-key.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_PROVIDER_CLEAR_KEY,
        HandlerSpec::mutation(true, move |ctx| {
            let id = ctx.path_param("provider_id")?;
            validate_provider_id(&id)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let summary = provider
                .clear_key(&id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(summary).expect("ClientProviderSummary serializes"))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    // POST /client/providers/{provider_id}:preflight — re-check the stored key.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_PROVIDER_PREFLIGHT,
        HandlerSpec::mutation(true, move |ctx| {
            let id = ctx.path_param("provider_id")?;
            validate_provider_id(&id)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let result = provider
                .preflight(&id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(result).expect("ClientProviderPreflightResult serializes"))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    // POST /client/providers/{provider_id}:select — move to index 0.
    let s = slot;
    api.register_templated(
        Method::Post,
        routes::TPL_PROVIDER_SELECT,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let id = ctx.path_param("provider_id")?;
            validate_provider_id(&id)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let outcome = provider
                .select_provider(&id)
                .map_err(ProviderError::into_client_error)?;
            Ok(outcome_response(outcome))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_req() -> ClientCreateProviderRequest {
        ClientCreateProviderRequest {
            provider_id: "anthropic".into(),
            endpoint: Some("https://api.anthropic.com".into()),
            model_aliases: [("sonnet".to_string(), "claude-sonnet-4-5".to_string())]
                .into_iter()
                .collect(),
            cost: ClientProviderCost {
                input_per_mtoken: 3.0,
                output_per_mtoken: 15.0,
                ..Default::default()
            },
            rate_limit: ClientProviderRateLimit {
                requests_per_minute: 1000,
                tokens_per_minute: 400_000,
            },
            ..Default::default()
        }
    }

    #[test]
    fn provider_id_grammar() {
        for ok in ["a", "anthropic", "open_ai-2", &"x".repeat(64)] {
            assert!(validate_provider_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "a/b", "a.b", "é", &"x".repeat(65)] {
            assert!(validate_provider_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn create_request_rules() {
        assert!(validate_create_request(&create_req()).is_ok());
        let mut r = create_req();
        r.endpoint = None;
        assert!(
            validate_create_request(&r).is_err(),
            "cloud-http needs endpoint"
        );
        r.backend_class = Some("local".into());
        assert!(
            validate_create_request(&r).is_ok(),
            "local needs no endpoint"
        );
        r.sidecar = Some(ClientProviderSidecar {
            command: "/usr/bin/true".into(),
            args: vec![],
        });
        assert!(validate_create_request(&r).is_ok());
        r.backend_class = Some("cloud-http".into());
        r.endpoint = Some("https://x".into());
        assert!(
            validate_create_request(&r).is_err(),
            "sidecar only on local"
        );
        let mut r = create_req();
        r.model_aliases.clear();
        assert!(validate_create_request(&r).is_err());
        let mut r = create_req();
        r.endpoint = Some("ftp://x".into());
        assert!(validate_create_request(&r).is_err());
        let mut r = create_req();
        r.endpoint = Some("https://x\n".into());
        assert!(validate_create_request(&r).is_err());
        let mut r = create_req();
        r.rate_limit.tokens_per_minute = 0;
        assert!(validate_create_request(&r).is_err());
        let mut r = create_req();
        r.cost.input_per_mtoken = f64::NAN;
        assert!(validate_create_request(&r).is_err());
        let mut r = create_req();
        r.backend = Some("grpc".into());
        assert!(validate_create_request(&r).is_err());
        let mut r = create_req();
        r.auth_scheme = Some("basic".into());
        assert!(validate_create_request(&r).is_err());
        let mut r = create_req();
        r.api_key_secret = Some("bad name".into());
        assert!(validate_create_request(&r).is_err());
    }

    #[test]
    fn update_request_rules() {
        assert!(validate_update_request(&ClientUpdateProviderRequest::default()).is_err());
        let ok = ClientUpdateProviderRequest {
            endpoint: Some("https://proxy.example".into()),
            ..Default::default()
        };
        assert!(validate_update_request(&ok).is_ok());
        let bad = ClientUpdateProviderRequest {
            model_aliases: Some(BTreeMap::new()),
            ..Default::default()
        };
        assert!(validate_update_request(&bad).is_err());
    }

    #[test]
    fn key_rules_and_redacted_debug() {
        assert!(validate_key("sk-live-123").is_ok());
        assert!(validate_key("   ").is_err());
        assert!(validate_key("sk\n").is_err());
        assert!(validate_key(&"k".repeat(MAX_KEY_BYTES)).is_ok());
        assert!(validate_key(&"k".repeat(MAX_KEY_BYTES + 1)).is_err());
        let req = ClientSetProviderKeyRequest {
            key: "sk-super-secret".into(),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("sk-super-secret"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn warnings_map_to_fixed_codes() {
        assert_eq!(
            ProviderAdminWarning::ReloadPending.to_client_warning().code,
            WARNING_RELOAD_PENDING
        );
        assert_eq!(
            ProviderAdminWarning::RestartRequired
                .to_client_warning()
                .code,
            WARNING_RESTART_REQUIRED
        );
        assert_eq!(
            ProviderAdminWarning::PreflightSkipped
                .to_client_warning()
                .code,
            WARNING_PREFLIGHT_SKIPPED
        );
    }
}
