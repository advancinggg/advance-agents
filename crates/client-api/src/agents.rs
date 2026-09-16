//! CONTRACT-190 agents family — the operator-facing agent CRUD surface.
//!
//! Routes (family `agents`, plus the read-only `agent-templates` family):
//! - `GET  /client/agents`                       list agents (`Scope::ReadRuns`)
//! - `POST /client/agents`                       create a child agent (`Scope::ControlRuns`, mutation)
//! - `GET  /client/agents/{agent_id}`            read one agent + its config document (`ReadRuns`)
//! - `POST /client/agents/{agent_id}:update`     update display name / config document / persisted capabilities (`ControlRuns`)
//! - `POST /client/agents/{agent_id}:delete`     terminate + de-register an agent (`ControlRuns`)
//! - `GET  /client/agent-templates`              list the templates a create may reference (`ReadRuns`)
//!
//! The family reuses the run-control scopes on purpose: `Scope` is a closed enum inventoried by the
//! AC-14 compat gate, so minting `ReadAgents` / `ManageAgents` is an `api_version`-incrementing
//! change (§2.12). Reads ride `ReadRuns` (the same scope `GET /client/runs/tree` already uses for
//! the agent-tree view); mutations ride `ControlRuns`.
//!
//! Every request is validated HERE, before the provider is consulted: id charset, workspace-path
//! containment (relative, no `..`, no hidden components, bounded depth), bounded config document,
//! bounded display name, bounded capability list. Provider-side outcomes are projected through
//! [`ProviderError::into_client_error`] with fixed client-safe messages — a raw tree/filesystem
//! error never reaches the client. Semantic validation of the config document (YAML parse, the
//! `capabilities:` / `agents:` schema) is the provider's job; it answers `invalid_request`.
//!
//! The `restart_required` warning is attached whenever a config document is written: the daemon's
//! L0 capability wiring reads `.agent/config.yaml` once at boot, so capability declarations edited
//! through this surface apply at the next daemon start (the tree node of a live child keeps the
//! capabilities it was created with).
//!
//! Lane agent-llm-policy (2026-09-16): the typed `llm` block ([`ClientAgentLlm`]) rides the same
//! routes — `config.llm` on every detail, `llm` on create/update as a WHOLE-BLOCK replacement
//! (`{}` clears it). An `llm`-only update carries NO `restart_required`: the gateway re-reads the
//! block on the agent's next LLM call. The provider validates that `llm.provider` names a live
//! `llm-providers[].id` and answers `invalid_request` + details `["unknown_provider"]` otherwise.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::{ClientApi, HandlerCtx, HandlerResponse, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode, ClientWarning};
use crate::provider::{provider_or_unavailable, AgentProviderSlot, ProviderError};
use crate::providers::grants::ClientCapParam;
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// Agent id bound: `^[A-Za-z0-9_-]{1,64}$` (mirrors the MODULE-005 `AgentId` implementer invariant).
pub const MAX_AGENT_ID_LEN: usize = 64;
/// Bound on a config document carried by create/update (matches the lifecycle atomic-write cap).
pub const MAX_AGENT_CONFIG_BYTES: usize = 64 * 1024;
/// Bound on a display name (matches the first-open display-name persist cap).
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;
/// Bound on a workspace path string.
pub const MAX_WORKSPACE_PATH_BYTES: usize = 512;
/// Bound on workspace path depth (matches the lifecycle `MAX_PATH_DEPTH`).
pub const MAX_WORKSPACE_PATH_DEPTH: usize = 32;
/// Bound on a template reference.
pub const MAX_TEMPLATE_REF_BYTES: usize = 128;
/// Bound on the capability list a create may request (matches the tree's per-node cap).
pub const MAX_REQUESTED_CAPABILITIES: usize = 64;
/// Bound on an `llm.model` hint (an alias key or a literal model id).
pub const MAX_LLM_MODEL_BYTES: usize = 128;
/// Bound on the `<id>` of an `llm.constraint` `device:<id>`.
pub const MAX_LLM_DEVICE_ID_BYTES: usize = 128;
/// Warning code attached when a config document was written (applies at the next daemon start).
/// Shared with the other administrative families — the constant lives in [`crate::envelope`].
pub use crate::envelope::WARNING_RESTART_REQUIRED;

const RESTART_REQUIRED_MESSAGE: &str =
    "capability changes (config document or persisted capability list) apply at the next daemon start";

// ── DTOs (CONTRACT-192 schema components) ────────────────────────────────────────────────────

/// One agent as listed by `GET /client/agents` (a client-safe projection of the tree node).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentSummary {
    pub agent_id: String,
    /// `root | child | sub`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// `active | paused | terminated | failed`.
    pub status: String,
    /// Workspace-root-relative directory of the agent's territory (`.` for the root agent). Never
    /// an absolute host path.
    pub workspace_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_ref: Option<String>,
    /// The user-visible name persisted at `<workspace>/.agent/display-name`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// One `capabilities:` entry of `.agent/config.yaml`, typed for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentCapability {
    pub name: String,
    /// `false` iff the entry is `<name>: false` (operator opt-out).
    pub enabled: bool,
    /// `false` iff the entry carries `auto-grant: false` (host fn linked, no persistent grant).
    pub auto_grant: bool,
    /// Remaining scalar/structured settings of a mapping entry, rendered as strings.
    pub params: Vec<ClientCapParam>,
}

/// One declared child of the `agents:` hierarchy block (materialized at daemon start).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentDeclaredChild {
    pub alias: String,
    pub template: String,
    /// Relative to the declaring parent's workspace.
    pub target_path: String,
    /// Whole-capability ids the child is (re-)materialized with at daemon start — the persisted
    /// form of a create's `capabilities` / an update's `capabilities`.
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub children: Vec<ClientAgentDeclaredChild>,
}

/// The typed `llm:` policy block of an agent's config document (lane agent-llm-policy): the
/// provider the agent is pinned to, its default model hint, and a hard placement constraint.
/// Every field is optional. On create/update the block is replaced as a whole; `{}` clears it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientAgentLlm {
    /// An `llm-providers[].id` of the runtime config (`^[A-Za-z0-9_-]{1,64}$`). Must name a
    /// configured provider; a request naming another id is `invalid_request` +
    /// details `["unknown_provider"]`. A pinned provider that later disappears from the config
    /// makes the agent's LLM calls fail closed (never a silent fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Default model hint (an alias key or a literal model id); an explicit per-call model wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Hard placement constraint: `always-local` | `never-cloud` | `device:<id>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint: Option<String>,
}

impl ClientAgentLlm {
    /// `true` when no field is set — the "clear the block" form on create/update.
    pub fn is_empty(&self) -> bool {
        self.provider.is_none() && self.model.is_none() && self.constraint.is_none()
    }
}

/// The agent's config document plus a typed projection of the parts the runtime understands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentConfig {
    /// Verbatim `.agent/config.yaml` (absent when the file is missing, unreadable, or over the
    /// document bound). This is the editable form accepted by `:update`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_yaml: Option<String>,
    pub capabilities: Vec<ClientAgentCapability>,
    pub declared_children: Vec<ClientAgentDeclaredChild>,
    /// The typed `llm:` policy block, when present and well-formed (absent otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<ClientAgentLlm>,
}

/// The `GET /client/agents/{agent_id}` / create / update response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentDetail {
    pub agent: ClientAgentSummary,
    pub config: ClientAgentConfig,
    /// The capability ids the LIVE tree node carries (the operative set a served child is
    /// linked with; for the root, its declared active capabilities). Ids only — never params.
    pub capabilities: Vec<String>,
    /// Direct children (tree ids).
    pub children: Vec<String>,
    /// Whether a loadable driver (`.agent/behavior.component.wasm` or `.agent/behavior.wasm`) is
    /// present in the agent's territory.
    pub driver_present: bool,
}

/// The body of `POST /client/agents`. The idempotency key is envelope-level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientCreateAgentRequest {
    /// `^[A-Za-z0-9_-]{1,64}$`; becomes the tree id.
    pub agent_id: String,
    /// Parent tree id; defaults to the root agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Directory RELATIVE TO THE PARENT's workspace; defaults to `agent_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
    /// The template the child is materialized from (also recorded in the parent's declared
    /// hierarchy so the child is re-materialized at the next daemon start).
    pub template_ref: String,
    /// Capability ids requested for the child (must be a subset of the parent's).
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional initial config document written after materialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_yaml: Option<String>,
    /// Optional `llm:` policy block written into the new agent's config document (after
    /// `config_yaml`, so it wins over a block the document may carry). `{}` writes nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<ClientAgentLlm>,
}

/// The body of `POST /client/agents/{agent_id}:update`. At least one field is required.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientUpdateAgentRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Full replacement of `.agent/config.yaml` (validated by the provider before the write).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_yaml: Option<String>,
    /// Full replacement of a CHILD agent's persisted capability list (subset-gated against the
    /// parent; applies at the next daemon start — the live node keeps its current set). The
    /// root agent's capabilities live in its config document, so this field is refused for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    /// Whole-block replacement of the agent's `llm:` policy (`{}` clears it). Applies at the
    /// agent's next LLM call — no `restart_required`. Allowed for the root agent too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<ClientAgentLlm>,
}

/// The body of `POST /client/agents/{agent_id}:delete` (a `null` body means the defaults).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientDeleteAgentRequest {
    /// `false` (default): terminate the agent and remove only its `.agent/` marker directory, so
    /// the directory stops being agent-managed but its content survives. `true`: also remove the
    /// whole workspace directory (containment-guarded; never the root workspace).
    #[serde(default)]
    pub remove_workspace: bool,
}

/// The result of a delete: the cascade removes the agent and every descendant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentDeleteResult {
    pub agent_id: String,
    /// Every tree id removed by the cascade (the agent itself and its descendants).
    pub removed_agent_ids: Vec<String>,
    pub workspace_removed: bool,
}

/// One template a create may reference (`GET /client/agent-templates`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentTemplate {
    pub template_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ── Validation (shared by the handlers and reusable by adapters) ─────────────────────────────

fn invalid(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, message)
}

fn is_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// `^[A-Za-z0-9_-]{1,64}$`.
pub fn validate_agent_id(id: &str) -> Result<(), ClientError> {
    if id.is_empty() || id.len() > MAX_AGENT_ID_LEN || !id.chars().all(is_id_char) {
        return Err(invalid("invalid agent id"));
    }
    Ok(())
}

/// A capability id: `^[A-Za-z0-9_-]{1,64}$` (never a `:`-carrying scoped form).
pub fn validate_capability_name(name: &str) -> Result<(), ClientError> {
    if name.is_empty() || name.len() > MAX_AGENT_ID_LEN || !name.chars().all(is_id_char) {
        return Err(invalid("invalid capability id"));
    }
    Ok(())
}

/// A relative, contained workspace path: non-empty, bounded, no absolute/`..`/`.`/empty/hidden
/// components, no backslash or NUL, depth ≤ [`MAX_WORKSPACE_PATH_DEPTH`].
pub fn validate_workspace_path(path: &str) -> Result<(), ClientError> {
    let err = || invalid("invalid workspace path");
    if path.is_empty()
        || path.len() > MAX_WORKSPACE_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(|c| c == '\0' || c.is_control())
    {
        return Err(err());
    }
    let mut depth = 0usize;
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.starts_with('.')
        {
            return Err(err());
        }
        depth += 1;
        if depth > MAX_WORKSPACE_PATH_DEPTH {
            return Err(err());
        }
    }
    Ok(())
}

/// A template reference: bounded, printable, path-safe (`[A-Za-z0-9_.@:/-]`, no `..` segment).
pub fn validate_template_ref(template_ref: &str) -> Result<(), ClientError> {
    let err = || invalid("invalid template reference");
    if template_ref.is_empty()
        || template_ref.len() > MAX_TEMPLATE_REF_BYTES
        || template_ref.starts_with('/')
        || !template_ref
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '/' | '-'))
        || template_ref
            .split('/')
            .any(|seg| seg.is_empty() || seg == ".." || seg == ".")
    {
        return Err(err());
    }
    Ok(())
}

/// A display name: trimmed non-empty, bounded, single line (no control characters).
pub fn validate_display_name(name: &str) -> Result<(), ClientError> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_DISPLAY_NAME_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err(invalid("invalid display name"));
    }
    Ok(())
}

/// A config document: bounded (`request_too_large` beyond [`MAX_AGENT_CONFIG_BYTES`]) and NUL-free.
/// Parse/schema validation is the provider's responsibility.
pub fn validate_config_document(yaml: &str) -> Result<(), ClientError> {
    if yaml.len() > MAX_AGENT_CONFIG_BYTES {
        return Err(ClientError::new(
            ClientErrorCode::RequestTooLarge,
            "agent config document exceeds max size",
        ));
    }
    if yaml.contains('\0') {
        return Err(invalid("invalid agent config document"));
    }
    Ok(())
}

/// An `llm.constraint`: exactly `always-local` | `never-cloud` | `device:<id>` with
/// `<id>` `^[A-Za-z0-9_.:-]{1,128}$` (the cap-llm `parse_constraint` grammar).
pub fn validate_llm_constraint(constraint: &str) -> Result<(), ClientError> {
    let err = || invalid("invalid llm constraint");
    match constraint {
        "always-local" | "never-cloud" => Ok(()),
        other => {
            let id = other.strip_prefix("device:").ok_or_else(err)?;
            if id.is_empty()
                || id.len() > MAX_LLM_DEVICE_ID_BYTES
                || !id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
            {
                return Err(err());
            }
            Ok(())
        }
    }
}

/// An `llm` block: provider id charset, bounded single-line model hint, constraint grammar.
/// Provider EXISTENCE is the provider's check (it owns the live runtime config).
pub fn validate_agent_llm(llm: &ClientAgentLlm) -> Result<(), ClientError> {
    if let Some(provider) = &llm.provider {
        if provider.is_empty()
            || provider.len() > MAX_AGENT_ID_LEN
            || !provider.chars().all(is_id_char)
        {
            return Err(invalid("invalid llm provider id"));
        }
    }
    if let Some(model) = &llm.model {
        if model.is_empty()
            || model.len() > MAX_LLM_MODEL_BYTES
            || model.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(invalid("invalid llm model"));
        }
    }
    if let Some(constraint) = &llm.constraint {
        validate_llm_constraint(constraint)?;
    }
    Ok(())
}

/// The requested capability list: bounded, each a valid id, no duplicates.
pub fn validate_capabilities(capabilities: &[String]) -> Result<(), ClientError> {
    if capabilities.len() > MAX_REQUESTED_CAPABILITIES {
        return Err(invalid("too many capabilities requested"));
    }
    for (i, cap) in capabilities.iter().enumerate() {
        validate_capability_name(cap)?;
        if capabilities[..i].iter().any(|c| c == cap) {
            return Err(invalid("duplicate capability requested"));
        }
    }
    Ok(())
}

/// Validate a full create request (every field, in a fixed order).
pub fn validate_create_request(req: &ClientCreateAgentRequest) -> Result<(), ClientError> {
    validate_agent_id(&req.agent_id)?;
    if let Some(parent) = &req.parent {
        validate_agent_id(parent)?;
    }
    if let Some(path) = &req.workspace_path {
        validate_workspace_path(path)?;
    }
    validate_template_ref(&req.template_ref)?;
    validate_capabilities(&req.capabilities)?;
    if let Some(name) = &req.display_name {
        validate_display_name(name)?;
    }
    if let Some(yaml) = &req.config_yaml {
        validate_config_document(yaml)?;
    }
    if let Some(llm) = &req.llm {
        validate_agent_llm(llm)?;
    }
    Ok(())
}

/// Validate an update request: at least one field, each within bounds.
pub fn validate_update_request(req: &ClientUpdateAgentRequest) -> Result<(), ClientError> {
    if req.display_name.is_none()
        && req.config_yaml.is_none()
        && req.capabilities.is_none()
        && req.llm.is_none()
    {
        return Err(invalid("empty agent update"));
    }
    if let Some(name) = &req.display_name {
        validate_display_name(name)?;
    }
    if let Some(yaml) = &req.config_yaml {
        validate_config_document(yaml)?;
    }
    if let Some(capabilities) = &req.capabilities {
        validate_capabilities(capabilities)?;
    }
    if let Some(llm) = &req.llm {
        validate_agent_llm(llm)?;
    }
    Ok(())
}

/// Whether an update changes something that only takes effect at the next daemon start. An
/// `llm`-only update does NOT (the policy is re-read at the next LLM call).
fn update_needs_restart(req: &ClientUpdateAgentRequest) -> bool {
    req.config_yaml.is_some() || req.capabilities.is_some()
}

// ── Handlers ─────────────────────────────────────────────────────────────────────────────────

fn parse_body<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, ClientError> {
    serde_json::from_value(body.clone()).map_err(|_| invalid("invalid agent request body"))
}

/// Mark the irreversible provider-entry boundary (CONTRACT-190 reserve-before-execute). Called only
/// after validation AND after the provider slot resolved, so a validation failure or an absent
/// provider stays retryable under the same key, while any outcome the provider itself returns
/// (success or a projected rejection) is recorded for exactly-once replay — an agent create/delete
/// has filesystem + tree side effects, so a key is never allowed to re-enter the provider.
fn mark_provider_entry(ctx: &HandlerCtx) -> Result<(), ClientError> {
    match ctx.mutation.as_ref() {
        Some(mutation) => mutation.mark_provider_entry(),
        None => Ok(()),
    }
}

fn detail_response(detail: ClientAgentDetail, config_written: bool) -> HandlerResponse {
    let data = serde_json::to_value(detail).expect("ClientAgentDetail serializes");
    if config_written {
        HandlerResponse::with_warnings(
            data,
            vec![ClientWarning::new(
                WARNING_RESTART_REQUIRED,
                RESTART_REQUIRED_MESSAGE,
            )],
        )
    } else {
        HandlerResponse::data(data)
    }
}

/// Register the agents + agent-templates routes, capturing the shared provider slot in each closure
/// so a builder can inject the concrete provider AFTER registration. Routes are always registered;
/// an absent provider yields `module_unavailable` (never `unknown_route`).
pub(crate) fn register(api: &mut ClientApi, slot: AgentProviderSlot) {
    // GET /client/agents — list every agent in the tree.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_AGENTS,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let agents = provider
                .list_agents()
                .map_err(ProviderError::into_client_error)?;
            Ok(json!({ "agents": agents }))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    // GET /client/agent-templates — the templates a create may reference.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_AGENT_TEMPLATES,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let templates = provider
                .list_templates()
                .map_err(ProviderError::into_client_error)?;
            Ok(json!({ "templates": templates }))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    // POST /client/agents — create a child agent (mutation: idempotency key + CSRF gated).
    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_AGENTS,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let req: ClientCreateAgentRequest = parse_body(&ctx.body)?;
            validate_create_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let detail = provider
                .create_agent(&req)
                .map_err(ProviderError::into_client_error)?;
            Ok(detail_response(detail, req.config_yaml.is_some()))
        })
        .with_scopes(vec![Scope::ControlRuns]),
    );

    // GET /client/agents/{agent_id} — one agent + its config document.
    let s = slot.clone();
    api.register_templated(
        Method::Get,
        routes::TPL_AGENT_GET,
        HandlerSpec::read(true, move |ctx| {
            let agent_id = ctx.path_param("agent_id")?;
            validate_agent_id(&agent_id)?;
            let provider = provider_or_unavailable(&s)?;
            let detail = provider
                .get_agent(&agent_id)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(detail).expect("ClientAgentDetail serializes"))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    // POST /client/agents/{agent_id}:update — display name and/or config document.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_AGENT_UPDATE,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let agent_id = ctx.path_param("agent_id")?;
            validate_agent_id(&agent_id)?;
            let req: ClientUpdateAgentRequest = parse_body(&ctx.body)?;
            validate_update_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let detail = provider
                .update_agent(&agent_id, &req)
                .map_err(ProviderError::into_client_error)?;
            Ok(detail_response(detail, update_needs_restart(&req)))
        })
        .with_scopes(vec![Scope::ControlRuns]),
    );

    // POST /client/agents/{agent_id}:delete — terminate cascade + de-register.
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        routes::TPL_AGENT_DELETE,
        HandlerSpec::mutation(true, move |ctx| {
            let agent_id = ctx.path_param("agent_id")?;
            validate_agent_id(&agent_id)?;
            let req: ClientDeleteAgentRequest = if ctx.body.is_null() {
                ClientDeleteAgentRequest::default()
            } else {
                parse_body(&ctx.body)?
            };
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let result = provider
                .delete_agent(&agent_id, &req)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(result).expect("ClientAgentDeleteResult serializes"))
        })
        .with_scopes(vec![Scope::ControlRuns]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_charset() {
        assert!(validate_agent_id("default-agent").is_ok());
        assert!(validate_agent_id("A_b-9").is_ok());
        assert!(validate_agent_id(&"x".repeat(64)).is_ok());
        for bad in ["", " ", "a b", "agent:x", "../x", "ünï", "x/y"] {
            assert!(validate_agent_id(bad).is_err(), "{bad:?}");
        }
        assert!(validate_agent_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn llm_block_grammar() {
        let ok = ClientAgentLlm {
            provider: Some("local".into()),
            model: Some("tiny".into()),
            constraint: Some("always-local".into()),
        };
        assert!(validate_agent_llm(&ok).is_ok());
        assert!(validate_agent_llm(&ClientAgentLlm::default()).is_ok());
        assert!(ClientAgentLlm::default().is_empty() && !ok.is_empty());
        for c in [
            "always-local",
            "never-cloud",
            "device:phone",
            "device:mac.local:1",
        ] {
            assert!(validate_llm_constraint(c).is_ok(), "{c}");
        }
        for c in [
            "",
            "Always-Local",
            " always-local",
            "device",
            "device:",
            "device:a b",
            "device:a/b",
            "cloud-only",
        ] {
            assert!(validate_llm_constraint(c).is_err(), "{c:?}");
        }
        assert!(validate_llm_constraint(&format!("device:{}", "x".repeat(128))).is_ok());
        assert!(validate_llm_constraint(&format!("device:{}", "x".repeat(129))).is_err());
        for bad in [
            ClientAgentLlm {
                provider: Some("agent:x".into()),
                ..Default::default()
            },
            ClientAgentLlm {
                provider: Some(String::new()),
                ..Default::default()
            },
            ClientAgentLlm {
                model: Some("a b".into()),
                ..Default::default()
            },
            ClientAgentLlm {
                model: Some("x".repeat(129)),
                ..Default::default()
            },
            ClientAgentLlm {
                constraint: Some("gpu".into()),
                ..Default::default()
            },
        ] {
            assert!(validate_agent_llm(&bad).is_err(), "{bad:?}");
        }
        // The request DTO rejects unknown keys.
        assert!(serde_json::from_value::<ClientAgentLlm>(json!({ "providr": "x" })).is_err());
        assert!(
            serde_json::from_value::<ClientUpdateAgentRequest>(json!({ "llm": {} }))
                .unwrap()
                .llm
                .unwrap()
                .is_empty()
        );
        let update: ClientUpdateAgentRequest =
            serde_json::from_value(json!({ "llm": {} })).unwrap();
        assert!(
            validate_update_request(&update).is_ok(),
            "llm alone is a non-empty update"
        );
        assert!(!update_needs_restart(&update));
    }

    #[test]
    fn workspace_path_containment() {
        for ok in ["a", "a/b", "teams/writer", "研究", "a b/c"] {
            assert!(validate_workspace_path(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "", "/a", "a/../b", "..", ".", "a//b", "a/./b", ".agent", "a/.sub", "a\\b", "a/",
            "a\0b",
        ] {
            assert!(validate_workspace_path(bad).is_err(), "{bad:?}");
        }
        let deep = vec!["d"; MAX_WORKSPACE_PATH_DEPTH].join("/");
        assert!(validate_workspace_path(&deep).is_ok());
        let too_deep = vec!["d"; MAX_WORKSPACE_PATH_DEPTH + 1].join("/");
        assert!(validate_workspace_path(&too_deep).is_err());
    }

    #[test]
    fn template_ref_shape() {
        for ok in ["explorer", "pack@1.0/researcher", "team:planner"] {
            assert!(validate_template_ref(ok).is_ok(), "{ok:?}");
        }
        for bad in ["", "a b", "../x", "/x", "x//y", "x/./y"] {
            assert!(validate_template_ref(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn display_name_and_config_bounds() {
        assert!(validate_display_name("  Research Desk  ").is_ok());
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("a\tb").is_err());
        assert!(validate_config_document("capabilities:\n  fs: true\n").is_ok());
        let too_big = "#".repeat(MAX_AGENT_CONFIG_BYTES + 1);
        assert_eq!(
            validate_config_document(&too_big).unwrap_err().code,
            ClientErrorCode::RequestTooLarge
        );
        assert_eq!(
            validate_config_document("a\0b").unwrap_err().code,
            ClientErrorCode::InvalidRequest
        );
    }

    #[test]
    fn capability_list_bounds() {
        assert!(validate_capabilities(&["fs".into(), "llm".into()]).is_ok());
        assert!(validate_capabilities(&["fs".into(), "fs".into()]).is_err());
        assert!(validate_capabilities(&["a:b".into()]).is_err());
        let many: Vec<String> = (0..=MAX_REQUESTED_CAPABILITIES)
            .map(|i| format!("c{i}"))
            .collect();
        assert!(validate_capabilities(&many).is_err());
    }
}
