//! A temp home with a sibling state root, a runtime config, and an optional driver.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::api::{ComposeLog, ComposeOptions, HostPlatform, MasterKeyInput, Zeroizing};
use crate::test_support::{ComposeFailpoints, ComposeProbe};

use super::guests::{hello_llm_core, llm_noerr_core, minimal_core};

pub const FIXTURE_MASTER_KEY: [u8; 32] = [7u8; 32];

pub enum CapDecl {
    Granted(&'static str),
    DeclaredNoGrant(&'static str),
}

#[non_exhaustive]
pub enum FixtureDriver {
    None,
    Minimal,
    HelloLlm,
    LlmNoErr,
    Core(&'static [u8]),
}

pub struct FixtureHomeSpec {
    pub capabilities: Vec<CapDecl>,
    pub driver: FixtureDriver,
    pub git: bool,
    pub providers_yaml: Option<String>,
}

pub struct FixtureHome {
    _dir: tempfile::TempDir,
    _state: tempfile::TempDir,
    home: PathBuf,
    state_root: PathBuf,
}

impl FixtureHome {
    pub fn new(spec: FixtureHomeSpec) -> io::Result<Self> {
        let dir = tempfile::tempdir()?;
        let state = tempfile::tempdir()?;
        let home = std::fs::canonicalize(dir.path())?;
        let state_root = std::fs::canonicalize(state.path())?;
        for path in [
            home.join(".advance"),
            home.join(".runtime/events/jsonl"),
            home.join(".agent"),
        ] {
            std::fs::create_dir_all(&path)?;
        }
        std::fs::write(
            home.join(".advance/runtime-config.yaml"),
            runtime_yaml(spec.providers_yaml.as_deref()),
        )?;
        std::fs::write(
            home.join(".agent/config.yaml"),
            agent_yaml(&spec.capabilities),
        )?;
        if let Some(bytes) = driver_bytes(&spec.driver) {
            std::fs::write(home.join(".agent/behavior.wasm"), bytes)?;
        }
        if spec.git {
            advance_git::bootstrap_repo_at(&home)
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
        }
        Ok(Self {
            _dir: dir,
            _state: state,
            home,
            state_root,
        })
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub fn options(&self, log: Arc<dyn ComposeLog>, probe: Arc<ComposeProbe>) -> ComposeOptions {
        ComposeOptions::daemon(self.home.clone(), log)
            .with_state_root(self.state_root.clone())
            .with_master_key(MasterKeyInput::Provided(Zeroizing::new(FIXTURE_MASTER_KEY)))
            .with_failpoints(ComposeFailpoints {
                probe: Some(probe),
                ..ComposeFailpoints::default()
            })
    }

    /// `ComposeOptions::embedded(home, platform, log)` (the ADR D3 table row) plus exactly
    /// what `options()` adds to `ComposeOptions::daemon`: this fixture's state root, the
    /// `Provided` fixture master key and the probe.
    pub fn embedded_options(
        &self,
        platform: HostPlatform,
        log: Arc<dyn ComposeLog>,
        probe: Arc<ComposeProbe>,
    ) -> ComposeOptions {
        ComposeOptions::embedded(self.home.clone(), platform, log)
            .with_state_root(self.state_root.clone())
            .with_master_key(MasterKeyInput::Provided(Zeroizing::new(FIXTURE_MASTER_KEY)))
            .with_failpoints(ComposeFailpoints {
                probe: Some(probe),
                ..ComposeFailpoints::default()
            })
    }

    pub fn rewrite_agent_config(&self, caps: &[CapDecl]) -> io::Result<()> {
        std::fs::write(self.home.join(".agent/config.yaml"), agent_yaml(caps))
    }

    pub fn rewrite_providers(&self, providers_yaml: &str) -> io::Result<()> {
        let path = self.home.join(".advance/runtime-config.yaml");
        let yaml = std::fs::read_to_string(&path)?;
        std::fs::write(path, replace_providers_block(&yaml, providers_yaml))
    }
}

fn driver_bytes(driver: &FixtureDriver) -> Option<&'static [u8]> {
    match driver {
        FixtureDriver::None => None,
        FixtureDriver::Minimal => Some(minimal_core()),
        FixtureDriver::HelloLlm => Some(hello_llm_core()),
        FixtureDriver::LlmNoErr => Some(llm_noerr_core()),
        FixtureDriver::Core(bytes) => Some(*bytes),
    }
}

fn runtime_yaml(providers: Option<&str>) -> String {
    let providers = providers.unwrap_or("llm-providers: []");
    format!(
        r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

{providers}

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADV_FIXTURE_MASTER_KEY_UNUSED

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    )
}

fn agent_yaml(caps: &[CapDecl]) -> String {
    if caps.is_empty() {
        return "capabilities: {}\n".to_owned();
    }
    let mut yaml = String::from("capabilities:\n");
    for cap in caps {
        match cap {
            CapDecl::Granted(name) => yaml.push_str(&format!("  {name}: true\n")),
            CapDecl::DeclaredNoGrant(name) => {
                yaml.push_str(&format!("  {name}:\n    auto-grant: false\n"));
            }
        }
    }
    yaml
}

fn replace_providers_block(yaml: &str, block: &str) -> String {
    let mut lines = yaml.lines().peekable();
    let mut out = String::new();
    let mut replaced = false;
    while let Some(line) = lines.next() {
        if !replaced && line.starts_with("llm-providers:") {
            out.push_str(block.trim_end());
            out.push('\n');
            while let Some(next) = lines.peek() {
                if next.starts_with(' ') || next.starts_with('\t') || next.is_empty() {
                    lines.next();
                } else {
                    break;
                }
            }
            replaced = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        out.push('\n');
        out.push_str(block.trim_end());
        out.push('\n');
    }
    out
}
