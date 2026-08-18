//! Idle / Starting / Running + selected-provider adopt file.

use std::fs;
use std::path::Path;

use advance_runtime::runtime_lock::{inspect_lock, LockInspection};

use crate::contract::RuntimeState;
use crate::discovery::{client_api_accepts, read_client_api_discovery};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedProvider {
    pub pid: u32,
    pub provider_id: String,
}

pub fn selected_provider_path(home: &Path) -> std::path::PathBuf {
    home.join(".runtime").join("selected-provider")
}

pub fn write_selected_provider(
    home: &Path,
    pid: u32,
    provider_id: &str,
) -> Result<(), std::io::Error> {
    fs::create_dir_all(home.join(".runtime"))?;
    if provider_id
        .bytes()
        .any(|b| b < 0x21 || b == b'"' || b > 0x7e)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "provider_id must be a single-line token",
        ));
    }
    let body = format!("pid: {pid}\nprovider_id: \"{provider_id}\"\n");
    crate::scaffold::write_0600_nofollow(&selected_provider_path(home), body.as_bytes())
}

pub fn read_selected_provider(home: &Path) -> Option<SelectedProvider> {
    let raw = crate::scaffold::read_small_regular(&selected_provider_path(home), 256)?;
    let mut pid = None;
    let mut provider_id = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("pid:") {
            pid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("provider_id:") {
            let v = rest.trim().trim_matches('"');
            if !v.is_empty() {
                provider_id = Some(v.to_string());
            }
        }
    }
    Some(SelectedProvider {
        pid: pid?,
        provider_id: provider_id?,
    })
}

pub fn runtime_state(home: &Path) -> RuntimeState {
    match inspect_lock(home) {
        LockInspection::Absent | LockInspection::Stale { .. } => RuntimeState::Idle,
        LockInspection::Live { pid } => {
            let Some(disc) = read_client_api_discovery(home) else {
                return RuntimeState::Starting;
            };
            if disc.pid != pid {
                return RuntimeState::Starting;
            }
            if client_api_accepts(&disc.client_api_base) {
                RuntimeState::Running
            } else {
                RuntimeState::Starting
            }
        }
    }
}

pub fn committed_provider_id(home: &Path) -> Option<String> {
    let cfg_path = home.join(".advance").join("runtime-config.yaml");
    let cfg = advance_runtime::config::load_config(&cfg_path).ok()?;
    cfg.llm_providers.first().map(|p| p.id.clone())
}
