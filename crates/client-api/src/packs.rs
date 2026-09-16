//! CONTRACT-190 packs family — the operator-facing pack administration surface
//! (pack lanes follow-up, 2026-09-16).
//!
//! Routes (family `packs`):
//! - `GET  /client/packs`                          installed packs (`Scope::ReadInventory`)
//! - `GET  /client/packs/{pack_id}`                one pack + its declared provides
//! - `POST /client/packs:install`                  install from a source (`Scope::ApproveGrants`)
//! - `POST /client/packs/{pack_id}:uninstall`      uninstall (`Scope::ApproveGrants`)
//!
//! `pack_id` is the registry key `{name}@{version}` (refs are always versioned, MODULE-018).
//!
//! Approval model: the CLI prompts the operator on stdin for a pack's `required-capabilities`.
//! Over the API the request itself IS the operator's decision: the client echoes the
//! capabilities it accepts in `accepted_capabilities`, and the runtime approves only if the
//! manifest's `required-capabilities` is a subset of that list (a pack with no requirements
//! needs no list). Nothing is ever auto-approved. The capability catalog / signature / trust
//! rules of the CLI path apply unchanged — this family only projects shapes and validates the
//! request before the provider is consulted.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{ClientApi, HandlerCtx, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::provider::{provider_or_unavailable, PackProviderSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// Bound on an install `source` string (a path, `git+…` URL, `.tar.gz` path or
/// `registry:name@version`).
pub const MAX_SOURCE_LEN: usize = 2048;
/// Bound on a pack name (`pack.yaml` `name`, a bare ASCII identifier).
pub const MAX_PACK_NAME_LEN: usize = 128;
/// Bound on a pack version string (semver).
pub const MAX_PACK_VERSION_LEN: usize = 64;
/// Bound on one accepted capability id (`fs`, `llm`, `advance.structured-data`, …).
pub const MAX_CAPABILITY_ID_LEN: usize = 64;
/// Bound on the number of accepted capabilities in one install request.
pub const MAX_ACCEPTED_CAPABILITIES: usize = 64;

// ── DTOs (CONTRACT-192 schema components) ────────────────────────────────────────────────────

/// One installed pack (`GET /client/packs` rows and the `summary` of a detail).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPackSummary {
    pub name: String,
    pub version: String,
    /// Effective trust level from the pack index: `trusted | untrusted`. `trusted` only when the
    /// manifest claimed it AND a configured trust root signed `pack.yaml` at install.
    pub trust_level: String,
    /// Lower-case hex public key of the trust root that signed `pack.yaml`; absent for an
    /// unsigned pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// The capability ids the pack declared it needs (what the operator approved at install).
    pub required_capabilities: Vec<String>,
}

/// One declared `provides` entry of an installed pack.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPackProvide {
    /// The provide category directory name (`behavior-binaries`, `agent-templates`, `skills`,
    /// `components`, `channel-adapters`, `mcp-servers`, `presets`, `workflows`, `memory-seeds`,
    /// `meta-schema-extensions`, `resource-capabilities`).
    pub kind: String,
    pub name: String,
}

/// `GET /client/packs/{pack_id}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPackDetail {
    pub summary: ClientPackSummary,
    /// Ordered by kind (registry order), then name.
    pub provides: Vec<ClientPackProvide>,
}

/// `GET /client/packs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPackList {
    /// Ordered by name, then version.
    pub packs: Vec<ClientPackSummary>,
}

/// `POST /client/packs:install` body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientPackInstallRequest {
    /// A local directory, `git+https://…[@ref]`, a `.tar.gz` path, or `registry:name@version`.
    pub source: String,
    /// The capability ids the operator accepts granting to this pack. The install is refused
    /// unless the manifest's `required-capabilities` is a subset of this list.
    #[serde(default)]
    pub accepted_capabilities: Vec<String>,
}

/// `POST /client/packs:install` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPackInstallResult {
    pub name: String,
    pub version: String,
    /// The install directory, relative to the packs dir (`{name}@{version}`).
    pub install_path: String,
}

/// `POST /client/packs/{pack_id}:uninstall` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPackUninstallResult {
    pub name: String,
    pub version: String,
}

// ── Validation ───────────────────────────────────────────────────────────────────────────────

fn invalid(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, message)
}

/// `^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$` — the manifest's bare-identifier rule (no leading `.`,
/// no separators, no `@`).
pub fn validate_pack_name(name: &str) -> Result<(), ClientError> {
    let mut chars = name.chars();
    let ok = match chars.next() {
        Some(c) => c.is_ascii_alphanumeric() || matches!(c, '_' | '-'),
        None => false,
    };
    if !ok
        || name.len() > MAX_PACK_NAME_LEN
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(invalid("invalid pack name"));
    }
    Ok(())
}

/// `^[0-9A-Za-z.+-]{1,64}$` — a semver string's charset (the registry parses it strictly).
pub fn validate_pack_version(version: &str) -> Result<(), ClientError> {
    if version.is_empty()
        || version.len() > MAX_PACK_VERSION_LEN
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
    {
        return Err(invalid("invalid pack version"));
    }
    Ok(())
}

/// Split and validate a `{name}@{version}` path parameter.
pub fn parse_pack_id(pack_id: &str) -> Result<(String, String), ClientError> {
    let (name, version) = pack_id
        .split_once('@')
        .ok_or_else(|| invalid("pack id must be name@version"))?;
    validate_pack_name(name)?;
    validate_pack_version(version)?;
    Ok((name.to_string(), version.to_string()))
}

/// `^[A-Za-z0-9_.:-]{1,64}$` — runtime capability ids and pack resource-capability ids.
pub fn validate_capability_id(id: &str) -> Result<(), ClientError> {
    if id.is_empty()
        || id.len() > MAX_CAPABILITY_ID_LEN
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err(invalid("invalid capability id"));
    }
    Ok(())
}

/// Validate an install request: bounded, control-free source; bounded, well-formed accepted
/// capability ids.
pub fn validate_install_request(req: &ClientPackInstallRequest) -> Result<(), ClientError> {
    if req.source.is_empty() || req.source.len() > MAX_SOURCE_LEN {
        return Err(invalid("invalid pack source"));
    }
    if req.source.chars().any(|c| c.is_control()) {
        return Err(invalid("invalid pack source"));
    }
    if req.accepted_capabilities.len() > MAX_ACCEPTED_CAPABILITIES {
        return Err(invalid("too many accepted capabilities"));
    }
    for cap in &req.accepted_capabilities {
        validate_capability_id(cap)?;
    }
    Ok(())
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, ClientError> {
    if !body.is_object() {
        return Err(invalid("invalid pack request body"));
    }
    serde_json::from_value(body.clone()).map_err(|_| invalid("invalid pack request body"))
}

/// Mark the irreversible provider-entry boundary (CONTRACT-190 reserve-before-execute): an
/// install/uninstall has filesystem side effects, so a key never re-enters the provider.
fn mark_provider_entry(ctx: &HandlerCtx) -> Result<(), ClientError> {
    match ctx.mutation.as_ref() {
        Some(mutation) => mutation.mark_provider_entry(),
        None => Ok(()),
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────────────────────

/// Register the packs routes, capturing the shared provider slot so a builder can inject the
/// concrete provider AFTER registration. Routes are always registered; an absent provider yields
/// `module_unavailable` (never `unknown_route`).
pub(crate) fn register(api: &mut ClientApi, slot: PackProviderSlot) {
    // GET /client/packs — installed packs.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_PACKS,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let packs = provider
                .list_packs()
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(ClientPackList { packs }).expect("ClientPackList serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // GET /client/packs/{pack_id} — one pack + provides.
    let s = slot.clone();
    api.register_templated(
        Method::Get,
        routes::TPL_PACK_GET,
        HandlerSpec::read(true, move |ctx| {
            let (name, version) = parse_pack_id(&ctx.path_param("pack_id")?)?;
            let provider = provider_or_unavailable(&s)?;
            let detail = provider
                .get_pack(&name, &version)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(detail).expect("ClientPackDetail serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // POST /client/packs:install — mutation (idempotency key + CSRF gated).
    let s = slot.clone();
    api.register(
        Method::Post,
        routes::PATH_PACK_INSTALL,
        HandlerSpec::mutation(true, move |ctx| {
            let req: ClientPackInstallRequest = parse_body(&ctx.body)?;
            validate_install_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let result = provider
                .install_pack(&req)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(result).expect("ClientPackInstallResult serializes"))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    // POST /client/packs/{pack_id}:uninstall — mutation.
    let s = slot;
    api.register_templated(
        Method::Post,
        routes::TPL_PACK_UNINSTALL,
        HandlerSpec::mutation(true, move |ctx| {
            let (name, version) = parse_pack_id(&ctx.path_param("pack_id")?)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let result = provider
                .uninstall_pack(&name, &version)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(result).expect("ClientPackUninstallResult serializes"))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_id_grammar() {
        assert_eq!(
            parse_pack_id("foo@1.0.0").unwrap(),
            ("foo".to_string(), "1.0.0".to_string())
        );
        assert!(parse_pack_id("my-pack@2.1.0-beta.1+build").is_ok());
        for bad in [
            "foo",
            "@1.0.0",
            "foo@",
            ".hidden@1.0.0",
            "a/b@1.0.0",
            "foo@1.0.0/x",
            "foo@1 0",
            "fo\u{0}o@1.0.0",
        ] {
            assert!(parse_pack_id(bad).is_err(), "{bad:?}");
        }
        assert!(parse_pack_id(&format!("{}@1.0.0", "x".repeat(128))).is_ok());
        assert!(parse_pack_id(&format!("{}@1.0.0", "x".repeat(129))).is_err());
    }

    #[test]
    fn install_request_bounds() {
        let ok = ClientPackInstallRequest {
            source: "/tmp/pack".into(),
            accepted_capabilities: vec!["fs".into(), "advance.structured-data".into()],
        };
        assert!(validate_install_request(&ok).is_ok());
        let empty = ClientPackInstallRequest {
            source: String::new(),
            accepted_capabilities: vec![],
        };
        assert!(validate_install_request(&empty).is_err());
        let control = ClientPackInstallRequest {
            source: "git+https://h/r\n".into(),
            accepted_capabilities: vec![],
        };
        assert!(validate_install_request(&control).is_err());
        let bad_cap = ClientPackInstallRequest {
            source: "/tmp/pack".into(),
            accepted_capabilities: vec!["a b".into()],
        };
        assert!(validate_install_request(&bad_cap).is_err());
        let too_many = ClientPackInstallRequest {
            source: "/tmp/pack".into(),
            accepted_capabilities: (0..65).map(|i| format!("c{i}")).collect(),
        };
        assert!(validate_install_request(&too_many).is_err());
    }
}
