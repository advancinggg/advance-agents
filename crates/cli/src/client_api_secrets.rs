//! CLI-served `SecretsAdminProvider` (secrets family)
//! over the home's `runtime-config.yaml` `secrets:` block.
//!
//! Reads go through the validating config loader (`advance_home::read_secrets_mode`); a mode
//! switch goes through `advance_home::rewrite_secrets_mode` — the same tmp + `load_config` +
//! rename chain the selected-provider rewrite uses, touching only the `secrets:` block. The
//! switch takes effect at the next daemon start (the wiring migrates File artifacts into the
//! keychain then); the handler attaches `restart_required`.

use std::path::PathBuf;
use std::sync::Arc;

use advance_client_api::secrets_admin::{
    ClientSecretsMode, ClientSetSecretsModeRequest, MODE_FILE, MODE_KEYCHAIN_SYNC,
};
use advance_client_api::{ClientApi, ProviderError, SecretsAdminProvider};
use advance_home::{
    read_secrets_mode, rewrite_secrets_mode, SecretsMode, SecretsModeChange, SecretsModeView,
    SecretsModeWriteError,
};
use advance_runtime::config::MasterKeySource;

/// The production `SecretsAdminProvider`.
pub struct WiredSecretsAdmin {
    home: PathBuf,
}

impl WiredSecretsAdmin {
    pub fn new(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn home(&self) -> &std::path::Path {
        &self.home
    }
}

fn source_name(source: &MasterKeySource) -> &'static str {
    match source {
        MasterKeySource::Keychain => "keychain",
        MasterKeySource::EnvVar => "env-var",
        MasterKeySource::KeychainSync => "keychain-sync",
    }
}

/// Project a config view to the client DTO.
pub fn project_mode(view: &SecretsModeView) -> ClientSecretsMode {
    ClientSecretsMode {
        mode: match view.mode {
            SecretsMode::File => MODE_FILE.to_string(),
            SecretsMode::KeychainSync => MODE_KEYCHAIN_SYNC.to_string(),
        },
        master_key_source: source_name(&view.master_key_source).to_string(),
        synchronizable: view.synchronizable,
        namespace: view.namespace.clone(),
        access_group: view.access_group.clone(),
        platform_supported: cap_secrets::platform_supports_keychain_sync(),
    }
}

fn write_error(e: SecretsModeWriteError) -> ProviderError {
    match e {
        SecretsModeWriteError::Invalid(reason) => {
            ProviderError::InvalidRequest(format!("secrets config rejected: {reason}"))
        }
        other => ProviderError::Unavailable(format!("secrets config: {other}")),
    }
}

impl SecretsAdminProvider for WiredSecretsAdmin {
    fn mode(&self) -> Result<ClientSecretsMode, ProviderError> {
        read_secrets_mode(&self.home)
            .map(|v| project_mode(&v))
            .map_err(|e| ProviderError::Unavailable(format!("secrets config: {e}")))
    }

    fn set_mode(
        &self,
        request: &ClientSetSecretsModeRequest,
    ) -> Result<ClientSecretsMode, ProviderError> {
        let mode = match request.mode.as_str() {
            MODE_FILE => SecretsMode::File,
            MODE_KEYCHAIN_SYNC => {
                if !cap_secrets::platform_supports_keychain_sync() {
                    return Err(ProviderError::PlatformUnsupported(
                        MODE_KEYCHAIN_SYNC.into(),
                    ));
                }
                SecretsMode::KeychainSync
            }
            _ => return Err(ProviderError::InvalidRequest("secrets mode".into())),
        };
        rewrite_secrets_mode(
            &self.home,
            &SecretsModeChange {
                mode,
                synchronizable: request.synchronizable,
                namespace: request.namespace.clone(),
            },
        )
        .map(|v| project_mode(&v))
        .map_err(write_error)
    }
}

/// Late-install the adapter into an already-bound API (tests over a booted daemon).
pub fn install_secrets_admin(api: &ClientApi, adapter: Arc<WiredSecretsAdmin>) {
    api.install_secrets_provider(adapter);
}
