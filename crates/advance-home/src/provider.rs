//! provider_status / store_and_preflight / confirm / YAML selected-provider rewrite, plus the
//! shared `llm-providers` writer (lane providers-family, 2026-09-16) the Landing first-open flow
//! and the cli `/client/providers` adapter both go through: every rewrite of
//! `runtime-config.yaml` is "mutate the parsed `serde_yml::Value` → write `runtime-config.yaml.tmp`
//! (0600, nofollow) → `load_config(&tmp)` → rename", so an invalid document never replaces a
//! valid one.

use std::path::Path;
use std::sync::Arc;

use advance_runtime::config::{load_config, LlmProviderConfig, MasterKeySource, RuntimeConfig};
use cap_http::{DefaultHttpSecurityChain, DefaultLeakDetector, DefaultRateLimiter};
use cap_llm::{chat_preflight, StaticConfig};
use cap_secrets::{
    ensure_master_key, DefaultEntryProvider, FileSecretStorage, InMemorySecretStorage,
    MasterKeyConfig, SecretStore, DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE,
};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::cancel::CancelToken;
use crate::contract::{PreflightFail, PreflightPass, ProviderStatus};
use crate::discovery::block_on_io;
use crate::ports::{GeneratePathPreflight, PreflightPort};
use crate::scaffold::MINIMAL_STARTER;
use crate::secret_bytes::SecretBytes;

pub fn provider_status(home: &Path) -> ProviderStatus {
    let cfg_path = home.join(".advance").join("runtime-config.yaml");
    let Ok(cfg) = load_config(&cfg_path) else {
        return ProviderStatus::Absent;
    };
    let Some(first) = cfg.llm_providers.first() else {
        return ProviderStatus::Absent;
    };
    let Ok(store) = open_file_store(home, &cfg) else {
        return ProviderStatus::Absent;
    };
    match store.exists(&first.api_key_secret) {
        Ok(true) => ProviderStatus::Present {
            provider_id: first.id.clone(),
        },
        _ => ProviderStatus::Absent,
    }
}

pub fn store_and_preflight(
    home: &Path,
    provider_id: &str,
    key: SecretBytes,
    cancel: &CancelToken,
    port: &dyn PreflightPort,
) -> Result<PreflightPass, PreflightFail> {
    if cancel.is_cancelled() {
        return Err(PreflightFail::Cancelled);
    }
    if provider_id.trim().is_empty() {
        return Err(PreflightFail::ProviderRejected {
            reason: "unknown-provider".into(),
        });
    }
    let cfg_path = home.join(".advance").join("runtime-config.yaml");
    let cfg = load_config(&cfg_path).map_err(|_| PreflightFail::ProviderRejected {
        reason: "unknown-provider".into(),
    })?;
    let named = find_or_starter_provider(&cfg, provider_id)?;
    port.preflight(home, &named, &key, cancel)?;
    commit_secret_and_select(home, &cfg, &named, key.expose())?;
    Ok(PreflightPass {
        provider_id: named.id,
    })
}

pub fn confirm_existing_provider(
    home: &Path,
    cancel: &CancelToken,
    port: &dyn PreflightPort,
) -> Result<PreflightPass, PreflightFail> {
    if cancel.is_cancelled() {
        return Err(PreflightFail::Cancelled);
    }
    match provider_status(home) {
        ProviderStatus::Absent => Err(PreflightFail::MissingProvider),
        ProviderStatus::Present { provider_id } => {
            let cfg_path = home.join(".advance").join("runtime-config.yaml");
            let cfg = load_config(&cfg_path).map_err(|_| PreflightFail::MissingProvider)?;
            let named = find_or_starter_provider(&cfg, &provider_id)?;
            let store = open_file_store(home, &cfg).map_err(|_| PreflightFail::MissingProvider)?;
            let secret = store
                .resolve(&named.api_key_secret)
                .map_err(|_| PreflightFail::MissingProvider)?;
            let key = SecretBytes::new(secret.expose_secret().to_string());
            port.preflight(home, &named, &key, cancel)?;
            Ok(PreflightPass { provider_id })
        }
    }
}

fn find_or_starter_provider(
    cfg: &RuntimeConfig,
    provider_id: &str,
) -> Result<LlmProviderConfig, PreflightFail> {
    if let Some(p) = cfg.llm_providers.iter().find(|p| p.id == provider_id) {
        return Ok(p.clone());
    }
    starter_provider(provider_id).ok_or(PreflightFail::ProviderRejected {
        reason: "unknown-provider".into(),
    })
}

pub fn starter_provider(provider_id: &str) -> Option<LlmProviderConfig> {
    let parsed: serde_yml::Value = serde_yml::from_str(MINIMAL_STARTER).ok()?;
    let seq = parsed.get("llm-providers")?.as_sequence()?;
    for item in seq {
        if item.get("id")?.as_str() == Some(provider_id) {
            return serde_yml::from_value(item.clone()).ok();
        }
    }
    None
}

fn commit_secret_and_select(
    home: &Path,
    cfg: &RuntimeConfig,
    named: &LlmProviderConfig,
    key: &str,
) -> Result<(), PreflightFail> {
    let store = open_file_store(home, cfg).map_err(|_| PreflightFail::ProviderRejected {
        reason: "provider-error".into(),
    })?;
    store
        .store(&named.api_key_secret, key)
        .map_err(|_| PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        })?;
    rewrite_selected_provider_yaml(home, &named.id)?;
    Ok(())
}

fn rewrite_selected_provider_yaml(home: &Path, provider_id: &str) -> Result<(), PreflightFail> {
    // Landing semantics: an id absent from the document but present in the starter is injected
    // (a fresh home whose YAML was hand-trimmed); the cli adapter uses the strict
    // [`select_provider`] instead.
    let starter = starter_provider_value(provider_id);
    let result = rewrite_llm_providers(home, |seq| {
        if let Some(idx) = seq
            .iter()
            .position(|e| e.get("id").and_then(|i| i.as_str()) == Some(provider_id))
        {
            let entry = seq.remove(idx);
            seq.insert(0, entry);
            Ok(())
        } else if let Some(entry) = starter {
            seq.insert(0, entry);
            Ok(())
        } else {
            Err(ProviderWriteError::NotFound)
        }
    });
    match result {
        Ok(()) => Ok(()),
        Err(ProviderWriteError::NotFound) => Err(PreflightFail::ProviderRejected {
            reason: "unknown-provider".into(),
        }),
        Err(_) => Err(PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        }),
    }
}

// ── Shared `llm-providers` writer (lane providers-family) ────────────────────────────────────

/// Errors of the shared `llm-providers` writer. Distinct from [`PreflightFail`] (the Landing
/// first-open vocabulary): the cli adapter projects these to `ProviderError` variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderWriteError {
    /// No entry with the given id.
    NotFound,
    /// A create names an id that already exists.
    AlreadyExists,
    /// The rewritten document failed the runtime's `load_config` validation (or the existing
    /// document does not parse). Carries the validator's message (never key material).
    Invalid(String),
    /// A read / write / rename of the config file failed.
    Io(String),
}

impl std::fmt::Display for ProviderWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "provider not found"),
            Self::AlreadyExists => write!(f, "provider already exists"),
            Self::Invalid(m) => write!(f, "invalid runtime config: {m}"),
            Self::Io(m) => write!(f, "runtime config io: {m}"),
        }
    }
}

impl std::error::Error for ProviderWriteError {}

/// Create-vs-update discriminator of [`upsert_provider_entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertMode {
    /// The id must be absent; the entry is appended (never selected unless it is the only one).
    Create,
    /// The id must be present; every key of the given mapping REPLACES the stored key, keys the
    /// mapping does not name survive verbatim.
    Update,
}

/// Bound on the runtime config document the writer is willing to rewrite.
const MAX_RUNTIME_CONFIG_BYTES: u64 = 256 * 1024;

fn runtime_config_path(home: &Path) -> std::path::PathBuf {
    home.join(".advance").join("runtime-config.yaml")
}

/// The parsed `llm-providers` entries of `<home>/.advance/runtime-config.yaml`, in YAML order.
pub fn list_provider_entries(home: &Path) -> Result<Vec<LlmProviderConfig>, ProviderWriteError> {
    let cfg = load_config(&runtime_config_path(home))
        .map_err(|e| ProviderWriteError::Invalid(e.to_string()))?;
    Ok(cfg.llm_providers)
}

/// Create or update one `llm-providers` entry. `entry` is the YAML mapping in the runtime's
/// kebab-case spelling (`id`, `endpoint`, `api-key-secret`, `model-aliases`, …); its `id` key
/// names the entry. Runs the atomic tmp → validate → rename chain.
pub fn upsert_provider_entry(
    home: &Path,
    entry: serde_yml::Value,
    mode: UpsertMode,
) -> Result<(), ProviderWriteError> {
    let id = entry
        .get("id")
        .and_then(|i| i.as_str())
        .ok_or_else(|| ProviderWriteError::Invalid("entry has no id".into()))?
        .to_string();
    let mapping = match entry {
        serde_yml::Value::Mapping(m) => m,
        _ => return Err(ProviderWriteError::Invalid("entry is not a mapping".into())),
    };
    rewrite_llm_providers(home, move |seq| {
        let existing = seq
            .iter()
            .position(|e| e.get("id").and_then(|i| i.as_str()) == Some(id.as_str()));
        match (mode, existing) {
            (UpsertMode::Create, Some(_)) => Err(ProviderWriteError::AlreadyExists),
            (UpsertMode::Create, None) => {
                seq.push(serde_yml::Value::Mapping(mapping));
                Ok(())
            }
            (UpsertMode::Update, None) => Err(ProviderWriteError::NotFound),
            (UpsertMode::Update, Some(idx)) => {
                let target = seq[idx]
                    .as_mapping_mut()
                    .ok_or_else(|| ProviderWriteError::Invalid("entry is not a mapping".into()))?;
                for (key, value) in mapping {
                    if key.as_str() == Some("id") {
                        continue;
                    }
                    target.insert(key, value);
                }
                Ok(())
            }
        }
    })
}

/// Remove one entry by id (the stored key, if any, is left in the secret store).
pub fn remove_provider_entry(home: &Path, provider_id: &str) -> Result<(), ProviderWriteError> {
    rewrite_llm_providers(home, |seq| {
        let idx = seq
            .iter()
            .position(|e| e.get("id").and_then(|i| i.as_str()) == Some(provider_id))
            .ok_or(ProviderWriteError::NotFound)?;
        seq.remove(idx);
        Ok(())
    })
}

/// Move one entry to index 0 — the provider the runtime resolves by default. Strict: an id
/// absent from the document is `NotFound` (no starter injection).
pub fn select_provider(home: &Path, provider_id: &str) -> Result<(), ProviderWriteError> {
    rewrite_llm_providers(home, |seq| {
        let idx = seq
            .iter()
            .position(|e| e.get("id").and_then(|i| i.as_str()) == Some(provider_id))
            .ok_or(ProviderWriteError::NotFound)?;
        let entry = seq.remove(idx);
        seq.insert(0, entry);
        Ok(())
    })
}

/// The one write chain: parse the current document, hand the `llm-providers` sequence to `f`,
/// render, write `runtime-config.yaml.tmp` (0600, nofollow), validate the tmp with the
/// runtime's `load_config`, rename over the live file. A document without an `llm-providers`
/// key gets an empty sequence (so a create on a hand-trimmed config works).
fn rewrite_llm_providers<F>(home: &Path, f: F) -> Result<(), ProviderWriteError>
where
    F: FnOnce(&mut Vec<serde_yml::Value>) -> Result<(), ProviderWriteError>,
{
    let cfg_path = runtime_config_path(home);
    let raw = crate::scaffold::read_small_regular(&cfg_path, MAX_RUNTIME_CONFIG_BYTES)
        .ok_or_else(|| ProviderWriteError::Io("runtime-config.yaml unreadable".into()))?;
    let mut value: serde_yml::Value =
        serde_yml::from_str(&raw).map_err(|e| ProviderWriteError::Invalid(e.to_string()))?;
    let doc = value
        .as_mapping_mut()
        .ok_or_else(|| ProviderWriteError::Invalid("document is not a mapping".into()))?;
    let key = serde_yml::Value::String("llm-providers".into());
    if !matches!(doc.get(&key), Some(serde_yml::Value::Sequence(_))) {
        doc.insert(key.clone(), serde_yml::Value::Sequence(Vec::new()));
    }
    let seq = match doc.get_mut(&key) {
        Some(serde_yml::Value::Sequence(seq)) => seq,
        _ => unreachable!("llm-providers sequence was just ensured"),
    };
    f(seq)?;
    let rendered =
        serde_yml::to_string(&value).map_err(|e| ProviderWriteError::Invalid(e.to_string()))?;
    let tmp = home.join(".advance").join("runtime-config.yaml.tmp");
    crate::scaffold::write_0600_nofollow(&tmp, rendered.as_bytes())
        .map_err(|e| ProviderWriteError::Io(e.to_string()))?;
    if let Err(e) = load_config(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProviderWriteError::Invalid(e.to_string()));
    }
    std::fs::rename(&tmp, &cfg_path).map_err(|e| ProviderWriteError::Io(e.to_string()))?;
    Ok(())
}

fn starter_provider_value(provider_id: &str) -> Option<serde_yml::Value> {
    let parsed: serde_yml::Value = serde_yml::from_str(MINIMAL_STARTER).ok()?;
    parsed
        .get("llm-providers")?
        .as_sequence()?
        .iter()
        .find(|e| e.get("id").and_then(|i| i.as_str()) == Some(provider_id))
        .cloned()
}

/// Open the home's secret store the way the Landing first-open flow does (master key per
/// `SecretsConfig`, ciphertext in `.advance/secrets.json`). NOTE for daemon-side callers: the
/// file backend caches at open, so a daemon that already holds a live `SecretStore` must write
/// through THAT instance, not a fresh one from here.
pub fn open_home_secret_store(home: &Path, cfg: &RuntimeConfig) -> Result<SecretStore, String> {
    open_file_store(home, cfg)
}

fn open_file_store(home: &Path, cfg: &RuntimeConfig) -> Result<SecretStore, String> {
    let mk = master_key_config(cfg);
    let key = ensure_master_key(home, &mk, &DefaultEntryProvider).map_err(|e| e.to_string())?;
    let storage = FileSecretStorage::open(home.join(".advance").join("secrets.json"))
        .map_err(|e| e.to_string())?;
    Ok(SecretStore::new(key, Arc::new(storage)))
}

fn master_key_config(cfg: &RuntimeConfig) -> MasterKeyConfig {
    match cfg.secrets.master_key_source {
        MasterKeySource::EnvVar => MasterKeyConfig::EnvVar(cfg.secrets.env_var_name.clone()),
        MasterKeySource::Keychain => MasterKeyConfig::Keychain {
            service: DEFAULT_KEYCHAIN_SERVICE.to_string(),
            account: DEFAULT_KEYCHAIN_ACCOUNT.to_string(),
            fallback_env_var: Some(cfg.secrets.env_var_name.clone()),
        },
    }
}

impl PreflightPort for GeneratePathPreflight {
    fn preflight(
        &self,
        home: &Path,
        provider: &LlmProviderConfig,
        key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail> {
        if cancel.is_cancelled() {
            return Err(PreflightFail::Cancelled);
        }
        let cfg_path = home.join(".advance").join("runtime-config.yaml");
        let mut cfg = load_config(&cfg_path).map_err(|_| PreflightFail::ProviderRejected {
            reason: "provider-error".into(),
        })?;
        cfg.llm_providers = vec![provider.clone()];
        let overlay_storage = Arc::new(InMemorySecretStorage::default());
        let master = Zeroizing::new([0x11u8; 32]);
        let overlay = SecretStore::new(master, overlay_storage);
        overlay
            .store(&provider.api_key_secret, key.expose())
            .map_err(|_| PreflightFail::ProviderRejected {
                reason: "provider-error".into(),
            })?;
        let chain = Arc::new(DefaultHttpSecurityChain::new(
            Arc::new(overlay),
            Arc::new(DefaultLeakDetector::new()),
            Arc::clone(&self.ssrf),
            Arc::new(DefaultRateLimiter::new()),
            Arc::clone(&self.executor),
        ));
        let config = Arc::new(StaticConfig(Arc::new(cfg)));
        let event_bus = Arc::clone(&self.event_bus);
        let cancelled = cancel.is_cancelled();
        let result = block_on_io({
            let flag = cancel.clone();
            async move {
                tokio::select! {
                    r = chat_preflight(config, chain, event_bus, flag.as_atomic()) => r,
                    _ = async {
                        while !flag.is_cancelled() {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    } => Err(cap_llm::LlmError::ProviderError("cancelled".into())),
                }
            }
        });
        if cancel.is_cancelled() || cancelled {
            return Err(PreflightFail::Cancelled);
        }
        match result {
            Ok(()) => Ok(()),
            Err(e)
                if e.variant_name() == "provider-error" && format!("{e}").contains("cancelled") =>
            {
                Err(PreflightFail::Cancelled)
            }
            Err(e) => Err(PreflightFail::ProviderRejected {
                reason: e.variant_name().to_string(),
            }),
        }
    }
}
