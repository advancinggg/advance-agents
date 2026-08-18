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
//!
//! Workspace resolution mirrors `advance start`: `--workspace` →
//! `$ADVANCE_WORKSPACE` → current dir.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use cap_secrets::{FileSecretStorage, SecretStorage, SecretStore};

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
    let key = crate::wiring::load_real_master_key(&workspace, &cfg.secrets).map_err(|e| {
        // Name the ACTUAL env var the config points at (env-var-name), which may
        // be customized from the SECRETS_MASTER_KEY default.
        format!(
            "{e}; provision the master key (set ${} to 64 hex chars, or store it in the OS keychain) before `advance secrets set`",
            cfg.secrets.env_var_name
        )
    })?;

    let secrets_path = workspace.join(".advance").join("secrets.json");
    let storage: Arc<dyn SecretStorage> = Arc::new(
        FileSecretStorage::open(&secrets_path)
            .map_err(|e| format!("could not open {}: {e}", secrets_path.display()))?,
    );
    let store = SecretStore::new(key, storage);
    store
        .store(name, value)
        .map_err(|e| format!("failed to store secret {name:?}: {e}"))?;
    Ok(())
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
    let secrets_path = workspace.join(".advance").join("secrets.json");
    // No master key needed — names are not secret. Absent file → empty list.
    let storage = FileSecretStorage::open(&secrets_path)
        .map_err(|e| format!("could not open {}: {e}", secrets_path.display()))?;
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
    let secrets_path = workspace.join(".advance").join("secrets.json");
    let storage = FileSecretStorage::open(&secrets_path)
        .map_err(|e| format!("could not open {}: {e}", secrets_path.display()))?;
    storage
        .remove(name)
        .map_err(|e| format!("failed to remove secret {name:?}: {e}"))
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
