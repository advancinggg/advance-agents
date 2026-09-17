//! `advance secrets set|list|remove` — admin provisioning of the on-disk
//! encrypted secret store (/dev WS-A, 2026-06-04).
//!
//! Secrets persist to `<workspace>/.advance/secrets.json` via
//! [`cap_secrets::FileSecretStorage`]; values are AES-256-GCM-encrypted by
//! [`cap_secrets::SecretStore`] under the keychain/env master key BEFORE they
//! touch disk. This is the operator path that provisions provider API keys
//! (e.g. `anthropic-api-key`) which the `advance start` daemon then resolves at
//! LLM-request time.
//!
//! - `set <name>` reads the value from **STDIN** (never argv — argv leaks via
//!   `ps`/shell history), loads the master key (same `SecretsConfig` source as
//!   the daemon), and stores the encrypted blob.
//! - `list` prints stored secret NAMES only (never values; no master key
//!   needed).
//! - `remove <name>` deletes a stored secret (no master key needed).
//! - `migrate --to file|keychain-sync` moves every secret between the File layout and the
//!   iCloud-Keychain-synchronized layout and repoints `secrets.master-key-source`.
//!
//! Every store open goes through the cap-secrets factory, so the layout follows the
//! workspace's `secrets:` block (File sources keep the pre-existing behaviour).
//!
//! Workspace resolution mirrors `advance start`: `--workspace` →
//! `$ADVANCE_WORKSPACE` → current dir.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use advance_runtime::config::SecretsConfig;
use cap_secrets::{
    open_secret_storage_unkeyed, open_secret_store, DefaultEntryProvider, MasterKeyPolicy,
    MigrationReport, MigrationTarget, SecItemOps, SecretStorage, SecretsBackend,
};

/// `advance secrets set <name>` — read the value from stdin and store it
/// encrypted in `<ws>/.advance/secrets.json`.
pub fn run_set(name: String, workspace: Option<PathBuf>) -> ExitCode {
    match run_set_inner(&name, workspace) {
        Ok(()) => {
            println!("advance secrets: stored {name:?}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("advance secrets set: {msg}");
            ExitCode::from(1)
        }
    }
}

fn run_set_inner(name: &str, workspace: Option<PathBuf>) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("secret name must not be empty".to_string());
    }
    let workspace = resolve_workspace(workspace)?;

    // Read the value from stdin (NOT argv). Strip trailing CR/LF (the common
    // `printf %s "$KEY" | ...` or `echo "$KEY" | ...` shape) but preserve any
    // interior bytes. API keys never legitimately end in a newline.
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .map_err(|e| format!("failed to read secret value from stdin: {e}"))?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err(
            "no secret value read from stdin (pipe the value, e.g. `printf %s \"$KEY\" | advance secrets set <name>`)"
                .to_string(),
        );
    }

    // Load the master key from the SAME SecretsConfig the daemon uses, so the
    // value `advance start` later resolves was encrypted under the same key.
    let cfg_path = workspace.join(".advance").join("runtime-config.yaml");
    let cfg = advance_runtime::config::load_config(&cfg_path).map_err(|e| {
        format!(
            "could not load {} (run `advance init <workspace>` first): {e}",
            cfg_path.display()
        )
    })?;
    // The factory picks the layout `secrets:` selects (File sources keep the never-mint
    // precedence env → workspace file → keyring; keychain-sync mints a keychain item only for
    // an empty namespace) — the same mapping `advance start` uses (wiring.rs).
    let policy = match cap_secrets::backend_of(&cfg.secrets) {
        SecretsBackend::File => MasterKeyPolicy::Resolve,
        SecretsBackend::KeychainSync => MasterKeyPolicy::Ensure,
    };
    let store = open_secret_store(
        &workspace,
        &cfg.secrets,
        &DefaultEntryProvider,
        None,
        policy,
    )
    .map_err(|e| {
        // Name the ACTUAL env var the config points at (env-var-name), which may
        // be customized from the SECRETS_MASTER_KEY default.
        format!(
            "{e}; provision the master key (set ${} to 64 hex chars, or store it in the OS keychain) before `advance secrets set`",
            cfg.secrets.env_var_name
        )
    })?
    .into_store();
    store
        .store(name, value)
        .map_err(|e| format!("failed to store secret {name:?}: {e}"))?;
    Ok(())
}

/// The `secrets:` block of the workspace config, or the File-layout view when the config is
/// absent/unreadable (`list` / `remove` never needed the config before this lane; an
/// un-inited directory still answers the empty File layout).
fn secrets_config_or_file(workspace: &Path) -> SecretsConfig {
    let cfg_path = workspace.join(".advance").join("runtime-config.yaml");
    match advance_runtime::config::load_config(&cfg_path) {
        Ok(cfg) => cfg.secrets,
        Err(_) => SecretsConfig {
            master_key_source: advance_runtime::config::MasterKeySource::EnvVar,
            env_var_name: "SECRETS_MASTER_KEY".into(),
            keychain: None,
            dependencies: Default::default(),
        },
    }
}

/// `advance secrets list` — print stored secret names (NOT values).
pub fn run_list(workspace: Option<PathBuf>) -> ExitCode {
    match run_list_inner(workspace) {
        Ok(names) => {
            for n in names {
                println!("{n}");
            }
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("advance secrets list: {msg}");
            ExitCode::from(1)
        }
    }
}

fn run_list_inner(workspace: Option<PathBuf>) -> Result<Vec<String>, String> {
    let workspace = resolve_workspace(workspace)?;
    // No master key needed — names are not secret. Absent file → empty list.
    let storage: Arc<dyn SecretStorage> =
        open_secret_storage_unkeyed(&workspace, &secrets_config_or_file(&workspace), None)
            .map_err(|e| format!("could not open the secret store: {e}"))?;
    Ok(storage.names())
}

/// `advance secrets remove <name>` — delete a stored secret.
pub fn run_remove(name: String, workspace: Option<PathBuf>) -> ExitCode {
    match run_remove_inner(&name, workspace) {
        Ok(true) => {
            println!("advance secrets: removed {name:?}");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("advance secrets remove: no secret named {name:?}");
            ExitCode::from(1)
        }
        Err(msg) => {
            eprintln!("advance secrets remove: {msg}");
            ExitCode::from(1)
        }
    }
}

fn run_remove_inner(name: &str, workspace: Option<PathBuf>) -> Result<bool, String> {
    let workspace = resolve_workspace(workspace)?;
    let storage: Arc<dyn SecretStorage> =
        open_secret_storage_unkeyed(&workspace, &secrets_config_or_file(&workspace), None)
            .map_err(|e| format!("could not open the secret store: {e}"))?;
    storage
        .remove(name)
        .map_err(|e| format!("failed to remove secret {name:?}: {e}"))
}

/// `advance secrets migrate --to file|keychain-sync` — move every stored secret into the
/// target layout (each name round-trip verified), then point `secrets.master-key-source` at
/// it.
pub fn run_migrate(to: String, workspace: Option<PathBuf>) -> ExitCode {
    let Some(target) = MigrationTarget::parse(&to) else {
        eprintln!("advance secrets migrate: --to must be `file` or `keychain-sync` (got {to:?})");
        return ExitCode::from(2);
    };
    match run_migrate_with(target, workspace, None, &DefaultEntryProvider) {
        Ok(report) if report.nothing_to_do => {
            println!("advance secrets migrate: nothing to migrate; config now targets {to}");
            ExitCode::SUCCESS
        }
        Ok(report) => {
            println!(
                "advance secrets migrate: moved {} secret(s) to {to} ({} file(s) renamed)",
                report.migrated.len(),
                report.renamed.len()
            );
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("advance secrets migrate: {msg}");
            ExitCode::from(1)
        }
    }
}

/// [`run_migrate`] with an injectable keychain (`ops = None` → the platform's real
/// Security.framework; tests pass a `MockSecItemOps`) and `keyring` seam (`entries`; the
/// File target's master key follows the scaffold `keychain` source: env → `master.key` →
/// `keyring` → mint). On success the YAML `secrets:` block is rewritten to the target
/// (`keychain-sync`, or the scaffold default `keychain` File source) through the validating
/// tmp+rename chain.
pub fn run_migrate_with(
    target: MigrationTarget,
    workspace: Option<PathBuf>,
    ops: Option<Arc<dyn SecItemOps>>,
    entries: &dyn cap_secrets::EntryProvider,
) -> Result<MigrationReport, String> {
    let workspace = resolve_workspace(workspace)?;
    let cfg_path = workspace.join(".advance").join("runtime-config.yaml");
    let cfg = advance_runtime::config::load_config(&cfg_path).map_err(|e| {
        format!(
            "could not load {} (run `advance init <workspace>` first): {e}",
            cfg_path.display()
        )
    })?;
    let (report, mode) = match target {
        MigrationTarget::KeychainSync => {
            if !cap_secrets::platform_supports_keychain_sync() {
                return Err(cap_secrets::PLATFORM_UNSUPPORTED_MSG.to_string());
            }
            let report =
                cap_secrets::migrate_file_to_keychain(&workspace, &cfg.secrets, entries, ops)
                    .map_err(|e| format!("file → keychain-sync migration failed: {e}"))?;
            (report, advance_home::SecretsMode::KeychainSync)
        }
        MigrationTarget::File => {
            let report =
                cap_secrets::migrate_keychain_to_file(&workspace, &cfg.secrets, entries, ops)
                    .map_err(|e| format!("keychain-sync → file migration failed: {e}"))?;
            (report, advance_home::SecretsMode::File)
        }
    };
    advance_home::rewrite_secrets_mode(
        &workspace,
        &advance_home::SecretsModeChange {
            mode,
            synchronizable: None,
            namespace: None,
        },
    )
    .map_err(|e| format!("secrets migrated but the config rewrite failed: {e}"))?;
    Ok(report)
}

/// Resolve the workspace dir: `--workspace` → `$ADVANCE_WORKSPACE` → CWD.
/// (Mirrors `commands::start::resolve_workspace`.)
fn resolve_workspace(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(ws) = std::env::var_os("ADVANCE_WORKSPACE") {
        if !ws.is_empty() {
            return Ok(PathBuf::from(ws));
        }
    }
    std::env::current_dir().map_err(|e| format!("cannot resolve CWD as workspace: {e}"))
}
