//! Secrets family — the operator-facing secrets-mode surface.
//!
//! Routes (family `secrets`):
//! - `GET  /client/secrets/mode`        the home's secrets mode (`Scope::ReadInventory`)
//! - `POST /client/secrets:set-mode`    switch it (`Scope::ApproveGrants`, mutation)
//!
//! `mode` is `file` (master key + ciphertext in the home: `.advance/master.key` +
//! `.advance/secrets.json`) or `keychain-sync` (both live as synchronizable data-protection
//! keychain items that iCloud Keychain carries between the user's devices; the home keeps
//! only secret names). A switch rewrites ONLY the `secrets:` block of `runtime-config.yaml`
//! (validated before it replaces the live file) and takes effect at the next daemon start,
//! so the response carries `restart_required`. The daemon migrates the ciphertext itself
//! at that start (File → keychain-sync; the reverse is `advance secrets migrate --to file`).
//!
//! The family reuses the packs family's scopes on purpose: `Scope` is a closed enum
//! inventoried by the AC-14 compat gate (§2.12). No secret value, master key, or ciphertext
//! ever crosses this surface — it is a mode switch, not a key store.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{ClientApi, HandlerCtx, HandlerResponse, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode, ClientWarning, WARNING_RESTART_REQUIRED};
use crate::provider::{provider_or_unavailable, ProviderError, SecretsProviderSlot};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// `mode` value: the File layout.
pub const MODE_FILE: &str = "file";
/// `mode` value: the iCloud-Keychain-synchronized layout.
pub const MODE_KEYCHAIN_SYNC: &str = "keychain-sync";
/// Bound on a keychain namespace (`^[A-Za-z0-9_-]{1,64}$`, the runtime config rule).
pub const MAX_NAMESPACE_LEN: usize = 64;

const RESTART_REQUIRED_MESSAGE: &str =
    "the secrets mode applies at the next daemon start (the daemon migrates the stored secrets then)";

// ── DTOs (CONTRACT-192 schema components) ────────────────────────────────────────────────────

/// `GET /client/secrets/mode` and the `set-mode` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientSecretsMode {
    /// `file | keychain-sync`.
    pub mode: String,
    /// The raw `secrets.master-key-source`: `keychain | env-var | keychain-sync`.
    pub master_key_source: String,
    /// keychain-sync: whether this device's items are synchronizable (`false` =
    /// ThisDeviceOnly). Always `true` in File mode.
    pub synchronizable: bool,
    /// keychain-sync item namespace (`default` unless configured).
    pub namespace: String,
    /// keychain-sync access group, when configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_group: Option<String>,
    /// Whether this daemon build/platform can serve `keychain-sync` (Apple platforms).
    pub platform_supported: bool,
}

/// `POST /client/secrets:set-mode` body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientSetSecretsModeRequest {
    /// `file | keychain-sync`.
    pub mode: String,
    /// keychain-sync only: `false` opts this device out of sync (ThisDeviceOnly items;
    /// already-synced items are read through and never deleted). Absent → unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synchronizable: Option<bool>,
    /// keychain-sync only: the item namespace. Absent → unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

// ── Validation ───────────────────────────────────────────────────────────────────────────────

fn invalid(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, message)
}

/// `^[A-Za-z0-9_-]{1,64}$`.
pub fn validate_namespace(namespace: &str) -> Result<(), ClientError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_LEN
        || !namespace
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(invalid("invalid keychain namespace"));
    }
    Ok(())
}

/// Validate a set-mode request: closed `mode` vocabulary; `synchronizable` / `namespace`
/// only with `keychain-sync`; namespace grammar.
pub fn validate_set_mode_request(req: &ClientSetSecretsModeRequest) -> Result<(), ClientError> {
    match req.mode.as_str() {
        MODE_FILE => {
            if req.synchronizable.is_some() || req.namespace.is_some() {
                return Err(invalid(
                    "synchronizable / namespace are keychain-sync settings",
                ));
            }
        }
        MODE_KEYCHAIN_SYNC => {
            if let Some(ns) = &req.namespace {
                validate_namespace(ns)?;
            }
        }
        _ => return Err(invalid("invalid secrets mode")),
    }
    Ok(())
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &Value) -> Result<T, ClientError> {
    if !body.is_object() {
        return Err(invalid("invalid secrets request body"));
    }
    serde_json::from_value(body.clone()).map_err(|_| invalid("invalid secrets request body"))
}

/// Mark the irreversible provider-entry boundary (CONTRACT-190 reserve-before-execute): a mode
/// switch rewrites the config file, so a key never re-enters the provider.
fn mark_provider_entry(ctx: &HandlerCtx) -> Result<(), ClientError> {
    match ctx.mutation.as_ref() {
        Some(mutation) => mutation.mark_provider_entry(),
        None => Ok(()),
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────────────────────

/// Register the secrets routes, capturing the shared provider slot so a builder can inject the
/// concrete provider AFTER registration. Routes are always registered; an absent provider yields
/// `module_unavailable` (never `unknown_route`).
pub(crate) fn register(api: &mut ClientApi, slot: SecretsProviderSlot) {
    // GET /client/secrets/mode — the current mode.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_SECRETS_MODE,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let mode = provider.mode().map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(mode).expect("ClientSecretsMode serializes"))
        })
        .with_scopes(vec![Scope::ReadInventory]),
    );

    // POST /client/secrets:set-mode — mutation (idempotency key + CSRF gated).
    let s = slot;
    api.register(
        Method::Post,
        routes::PATH_SECRETS_SET_MODE,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let req: ClientSetSecretsModeRequest = parse_body(&ctx.body)?;
            validate_set_mode_request(&req)?;
            let provider = provider_or_unavailable(&s)?;
            mark_provider_entry(ctx)?;
            let mode = provider
                .set_mode(&req)
                .map_err(ProviderError::into_client_error)?;
            let data = serde_json::to_value(mode).expect("ClientSecretsMode serializes");
            Ok(HandlerResponse::with_warnings(
                data,
                vec![ClientWarning::new(
                    WARNING_RESTART_REQUIRED,
                    RESTART_REQUIRED_MESSAGE,
                )],
            ))
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(mode: &str) -> ClientSetSecretsModeRequest {
        ClientSetSecretsModeRequest {
            mode: mode.into(),
            synchronizable: None,
            namespace: None,
        }
    }

    #[test]
    fn set_mode_vocabulary_and_settings() {
        assert!(validate_set_mode_request(&req("file")).is_ok());
        assert!(validate_set_mode_request(&req("keychain-sync")).is_ok());
        assert!(validate_set_mode_request(&req("keychain")).is_err());
        assert!(validate_set_mode_request(&req("")).is_err());
        let mut file_with_sync = req("file");
        file_with_sync.synchronizable = Some(false);
        assert!(validate_set_mode_request(&file_with_sync).is_err());
        let mut ok = req("keychain-sync");
        ok.synchronizable = Some(false);
        ok.namespace = Some("work-1".into());
        assert!(validate_set_mode_request(&ok).is_ok());
    }

    #[test]
    fn namespace_grammar() {
        assert!(validate_namespace("default").is_ok());
        assert!(validate_namespace(&"n".repeat(64)).is_ok());
        for bad in ["", "a b", "a.b", "a/b", "ns\u{0}", "名字"] {
            assert!(validate_namespace(bad).is_err(), "{bad:?}");
        }
        assert!(validate_namespace(&"n".repeat(65)).is_err());
    }
}
