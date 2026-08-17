//! BridgeConfig and fail-closed validation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::BridgeError;
use crate::types::{BridgePlatform, CompositionMode, EngineMode};

/// Public configuration for [`crate::start`].
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub platform: BridgePlatform,
    pub engine_mode: EngineMode,
    pub composition_mode: CompositionMode,
    pub config_path: Option<PathBuf>,
    pub supervise_command: Option<PathBuf>,
    pub supervise_ready_marker: Option<String>,
    pub supervise_ready_file: Option<PathBuf>,
    pub supervise_ready_timeout: Option<Duration>,
    /// Default true (MODULE-022). false = keep-available detach (macOS only).
    pub supervise_kill_on_drop: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            platform: BridgePlatform::Mac,
            engine_mode: EngineMode::Jit,
            composition_mode: CompositionMode::Embed,
            config_path: None,
            supervise_command: None,
            supervise_ready_marker: None,
            supervise_ready_file: None,
            supervise_ready_timeout: None,
            supervise_kill_on_drop: true,
        }
    }
}

impl BridgeConfig {
    pub fn ready_marker(&self) -> &str {
        self.supervise_ready_marker
            .as_deref()
            .unwrap_or("advance: runtime ready")
    }

    pub fn ready_timeout(&self) -> Duration {
        const MAX: Duration = Duration::from_secs(300);
        let d = self
            .supervise_ready_timeout
            .unwrap_or(Duration::from_secs(30));
        if d > MAX {
            MAX
        } else if d.is_zero() {
            Duration::from_secs(1)
        } else {
            d
        }
    }

    /// Fail-closed validation (policy + platform matrix).
    pub fn validate(&self) -> Result<(), BridgeError> {
        // Compiled-target mobile gate (cannot bypass via desktop enum).
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
            if matches!(self.engine_mode, EngineMode::Jit) {
                return Err(BridgeError::InvalidConfig(
                    "compiled mobile target forbids EngineMode::Jit".into(),
                ));
            }
            if matches!(self.composition_mode, CompositionMode::Supervise) {
                return Err(BridgeError::InvalidConfig(
                    "compiled mobile target forbids Supervise".into(),
                ));
            }
        }

        if matches!(
            self.platform,
            BridgePlatform::Ios | BridgePlatform::Android
        ) {
            if matches!(self.engine_mode, EngineMode::Jit) {
                return Err(BridgeError::InvalidConfig(
                    "iOS/Android require EngineMode::Interpreter".into(),
                ));
            }
            if matches!(self.composition_mode, CompositionMode::Supervise) {
                return Err(BridgeError::InvalidConfig(
                    "iOS/Android forbid CompositionMode::Supervise".into(),
                ));
            }
        }

        if let Some(ref m) = self.supervise_ready_marker {
            if m.is_empty() {
                return Err(BridgeError::InvalidConfig(
                    "supervise_ready_marker must be non-empty".into(),
                ));
            }
        }

        if matches!(self.composition_mode, CompositionMode::Supervise)
            && self.supervise_ready_file.is_some()
            && self.supervise_command.is_none()
        {
            return Err(BridgeError::InvalidConfig(
                "supervise_ready_file requires custom supervise_command".into(),
            ));
        }

        if matches!(self.composition_mode, CompositionMode::Supervise)
            && !self.supervise_kill_on_drop
        {
            // Keep-available: macOS host + Mac platform + ready_file + custom command.
            #[cfg(not(target_os = "macos"))]
            {
                return Err(BridgeError::InvalidConfig(
                    "keep-available (kill_on_drop=false) requires macOS host".into(),
                ));
            }
            #[cfg(target_os = "macos")]
            {
                if !matches!(self.platform, BridgePlatform::Mac) {
                    return Err(BridgeError::InvalidConfig(
                        "keep-available requires BridgePlatform::Mac".into(),
                    ));
                }
                if self.supervise_ready_file.is_none() {
                    return Err(BridgeError::InvalidConfig(
                        "keep-available requires supervise_ready_file".into(),
                    ));
                }
                if self.supervise_command.is_none() {
                    return Err(BridgeError::InvalidConfig(
                        "keep-available requires custom supervise_command (default advance has no ready-file protocol)".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Resolve config path under workspace (confined).
pub fn resolve_config_path(workspace: &Path, cfg: &BridgeConfig) -> Result<PathBuf, BridgeError> {
    match &cfg.config_path {
        Some(p) => confine_under_workspace(workspace, p),
        None => Ok(workspace.join(".advance").join("runtime-config.yaml")),
    }
}

/// Confine a path under workspace; reject escapes.
pub fn confine_under_workspace(workspace: &Path, path: &Path) -> Result<PathBuf, BridgeError> {
    let ws = workspace
        .canonicalize()
        .map_err(|e| BridgeError::InvalidWorkspace(format!("canonicalize workspace: {e}")))?;
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        ws.join(path)
    };
    // Reject .. components before canonicalize when possible.
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(BridgeError::InvalidConfig(
            "path must not contain ..".into(),
        ));
    }
    if joined.exists() {
        let canon = joined
            .canonicalize()
            .map_err(|e| BridgeError::InvalidConfig(format!("canonicalize path: {e}")))?;
        if !canon.starts_with(&ws) {
            return Err(BridgeError::InvalidConfig(
                "path escapes workspace".into(),
            ));
        }
        Ok(canon)
    } else {
        // Resolve the nearest existing ancestor (never lexical-only starts_with)
        // so an intermediate symlink cannot later escape the workspace.
        let mut anc = joined.parent();
        let mut existing = None;
        while let Some(p) = anc {
            if p.as_os_str().is_empty() {
                break;
            }
            if p.exists() {
                existing = Some(p.to_path_buf());
                break;
            }
            anc = p.parent();
        }
        let Some(existing) = existing else {
            return Err(BridgeError::InvalidConfig(
                "path has no existing ancestor".into(),
            ));
        };
        let p = existing.canonicalize().map_err(|e| {
            BridgeError::InvalidConfig(format!("canonicalize ancestor: {e}"))
        })?;
        if !p.starts_with(&ws) {
            return Err(BridgeError::InvalidConfig(
                "path escapes workspace".into(),
            ));
        }
        Ok(joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t01_ios_jit_invalid() {
        let mut c = BridgeConfig::default();
        c.platform = BridgePlatform::Ios;
        c.engine_mode = EngineMode::Jit;
        assert!(matches!(c.validate(), Err(BridgeError::InvalidConfig(_))));
    }

    #[test]
    fn t02_android_supervise_invalid() {
        let mut c = BridgeConfig::default();
        c.platform = BridgePlatform::Android;
        c.engine_mode = EngineMode::Interpreter;
        c.composition_mode = CompositionMode::Supervise;
        assert!(matches!(c.validate(), Err(BridgeError::InvalidConfig(_))));
    }

    #[test]
    fn t03_mac_embed_jit_ok() {
        let c = BridgeConfig::default();
        assert!(c.validate().is_ok());
    }
}
