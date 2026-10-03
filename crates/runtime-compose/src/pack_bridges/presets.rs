//! Presets bridge (§3.1 row 2): an installed pack's `presets/{name}.yaml` →
//! cap-grant's `PresetRegistry` through ITS loader (`load_custom_yaml`: 1 MiB
//! cap, 16-level depth gate, built-in-name shadow refusal, resolver-name
//! whitelist, grant/ttl grammar). Applying the preset to an agent still goes
//! through cap-grant's `apply_preset` (subset-checked, atomic) — this bridge
//! only makes the preset KNOWN by name.

use std::sync::Arc;

use advance_pack_manager::{ComponentKind, PackError, PackRegistry};
use cap_grant::preset::PresetRegistry;

use super::{resolve_kind, PackBridgeError};

pub struct PackPresetBridge {
    registry: Arc<dyn PackRegistry>,
}

impl PackPresetBridge {
    pub fn new(registry: Arc<dyn PackRegistry>) -> Self {
        Self { registry }
    }

    /// Load `{pack}@{ver}/presets/{name}` into `presets`; returns the preset's
    /// declared `name` (the registry key — it may differ from the file stem).
    pub fn load(
        &self,
        pack_ref: &str,
        presets: &mut PresetRegistry,
    ) -> Result<String, PackBridgeError> {
        let resolution = resolve_kind(&*self.registry, pack_ref, ComponentKind::Preset)?;
        // cap-grant's loader stats through symlinks; refuse a symlinked preset
        // file here (same posture as `DefaultMaterializer::apply_preset`).
        let md = std::fs::symlink_metadata(&resolution.local_path).map_err(|e| PackError::Io {
            path: resolution.local_path.clone(),
            source: e,
        })?;
        if md.file_type().is_symlink() || !md.is_file() {
            return Err(PackBridgeError::Pack(PackError::InvalidManifest(format!(
                "preset yaml must be a regular file (not a symlink): {}",
                resolution.local_path.display()
            ))));
        }
        let preset = presets
            .load_custom_yaml(&resolution.local_path)
            .map_err(|e| PackBridgeError::Grant(e.to_string()))?;
        Ok(preset.name.clone())
    }
}
