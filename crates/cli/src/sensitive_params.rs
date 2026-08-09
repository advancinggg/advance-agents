//! Wave-20 security lane (MODULE-012-AC-10): the production `SensitiveParamsSource`
//! for the MODULE-019 EventBus `sensitive_params` redaction seam.
//!
//! [`RegistrySensitiveParamsSource`] holds an in-memory snapshot
//! (`agent_id → param-name set`) built from the M014 [`ComponentRegistry`] at
//! boot. `names_for` is an O(1) map lookup on the emit hot path (no SQLite read).
//!
//! CONTRACT-217 v0.2 carries the declaration through the M005 WIT boundary. The
//! CLI seeds this source from durable registry rows at boot and publishes a new
//! declaration only after scheduler admission succeeds, so no daemon restart is
//! needed before EventBus observes it.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

use advance_event_bus::SensitiveParamsSource;
use advance_scheduler::registry::{ComponentRegistry, RegistryError};

/// Open the lifecycle registry inside a symlink-confined `.triggers` root.
/// This is the single pre-EventBus open used by CONTRACT-217 composition.
pub async fn open_component_registry(workspace: &Path) -> Result<Arc<ComponentRegistry>, String> {
    let canonical_workspace = tokio::fs::canonicalize(workspace)
        .await
        .map_err(|error| format!("canonicalize workspace: {error}"))?;
    let triggers = workspace.join(".triggers");
    if let Ok(metadata) = tokio::fs::symlink_metadata(&triggers).await {
        if metadata.file_type().is_symlink() {
            return Err(".triggers is a symlink".to_owned());
        }
    }
    tokio::fs::create_dir_all(&triggers)
        .await
        .map_err(|error| format!("create .triggers: {error}"))?;
    let canonical_triggers = tokio::fs::canonicalize(&triggers)
        .await
        .map_err(|error| format!("canonicalize .triggers: {error}"))?;
    if !canonical_triggers.starts_with(&canonical_workspace) {
        return Err(".triggers escapes the workspace".to_owned());
    }
    ComponentRegistry::open_in(&canonical_triggers, "components.db")
        .await
        .map(Arc::new)
        .map_err(|error| format!("open component registry: {error}"))
}

/// In-memory `sensitive_params` source keyed by emitting `agent_id` (the
/// component id the scheduler emitters stamp as `Event.agent_id`).
pub struct RegistrySensitiveParamsSource {
    map: RwLock<HashMap<String, Arc<HashSet<String>>>>,
}

impl RegistrySensitiveParamsSource {
    /// Build from a `agent_id → param-names` snapshot (e.g. the value returned by
    /// [`ComponentRegistry::sensitive_params_snapshot`]). Empty per-component
    /// lists are dropped (they would redact nothing).
    pub fn from_map(snapshot: HashMap<String, Vec<String>>) -> Self {
        let map = snapshot
            .into_iter()
            .filter(|(_, names)| !names.is_empty())
            .map(|(id, names)| (id, Arc::new(names.into_iter().collect::<HashSet<String>>())))
            .collect();
        Self {
            map: RwLock::new(map),
        }
    }

    /// An empty source — redacts nothing until boot hydration or a committed v0.2 submit.
    pub fn empty() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Publish a just-committed CONTRACT-217 declaration to the EventBus hot
    /// path. The scheduler bridge calls this only after durable admission.
    pub fn publish_component(&self, id: String, names: Vec<String>) {
        let mut map = self.map.write().unwrap_or_else(|error| error.into_inner());
        if names.is_empty() {
            map.remove(&id);
        } else {
            map.insert(id, Arc::new(names.into_iter().collect()));
        }
    }

    pub fn remove_component(&self, id: &str) {
        self.map
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .remove(id);
    }

    /// Read the durable declarations used to hydrate the production hot path.
    pub async fn from_registry(registry: &ComponentRegistry) -> Result<Self, RegistryError> {
        Ok(Self::from_map(registry.sensitive_params_snapshot().await?))
    }
}

impl SensitiveParamsSource for RegistrySensitiveParamsSource {
    fn names_for(&self, agent_id: &str) -> Option<Arc<HashSet<String>>> {
        self.map
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(agent_id)
            .cloned()
    }
}

/// Best-effort production wiring: build a [`SensitiveParamsSource`] from the
/// daemon's component registry at `<workspace>/.triggers/components.db`.
///
/// Reads an EXISTING registry only — it never CREATES the db (start.rs owns
/// registry creation/migration); a missing or unreadable registry yields an
/// empty source so boot never fails on this defense-in-depth seam. Normal
/// lifecycle-enabled composition uses [`open_component_registry`] instead and
/// treats registry/open errors as boot failures.
pub async fn build_sensitive_params_source(workspace: &Path) -> Arc<RegistrySensitiveParamsSource> {
    let triggers = workspace.join(".triggers");
    let db = triggers.join("components.db");
    if tokio::fs::try_exists(&db).await.unwrap_or(false) {
        if let Ok(reg) = ComponentRegistry::open_in(&triggers, "components.db").await {
            if let Ok(src) = RegistrySensitiveParamsSource::from_registry(&reg).await {
                return Arc::new(src);
            }
        }
    }
    Arc::new(RegistrySensitiveParamsSource::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_map_lookup_and_empty_filter() {
        let mut snap = HashMap::new();
        snap.insert("comp-a".to_string(), vec!["api_key".to_string()]);
        snap.insert("comp-empty".to_string(), Vec::new()); // dropped
        let src = RegistrySensitiveParamsSource::from_map(snap);
        let names = src.names_for("comp-a").expect("comp-a present");
        assert!(names.contains("api_key"));
        assert!(src.names_for("comp-empty").is_none(), "empty list dropped");
        assert!(src.names_for("unknown").is_none());
    }

    #[test]
    fn empty_source_redacts_nothing() {
        let src = RegistrySensitiveParamsSource::empty();
        assert!(src.names_for("anything").is_none());
    }

    #[test]
    fn dynamic_publish_and_remove_are_visible_without_restart() {
        let src = RegistrySensitiveParamsSource::empty();
        src.publish_component("comp-live".to_owned(), vec!["api_key".to_owned()]);
        assert!(src
            .names_for("comp-live")
            .expect("published declaration")
            .contains("api_key"));
        src.remove_component("comp-live");
        assert!(src.names_for("comp-live").is_none());
    }

    #[tokio::test]
    async fn from_registry_reads_declared_sensitive_params() {
        // The POPULATED hook: a component declaring sensitive_params surfaces in
        // the source (the same boot-hydration mechanism production uses).
        use advance_scheduler::types::ComponentSubmitConfig;
        use advance_shared_types::component::ComponentType;
        let tmp = tempfile::tempdir().unwrap();
        let reg = ComponentRegistry::open_in(tmp.path(), "components.db")
            .await
            .unwrap();
        let cfg = ComponentSubmitConfig {
            id: "comp-secretful".to_string(),
            component_type: ComponentType::Task,
            binary: Vec::new(),
            capabilities: Vec::new(),
            output_dir: None,
            trigger: None,
            restart_policy: None,
            delay: None,
            initial_grants: None,
            preset: None,
            retry: None,
            sensitive_params: vec!["api_key".to_string(), "password".to_string()],
        };
        reg.insert("submitter", &cfg, None).await.unwrap();
        let src = RegistrySensitiveParamsSource::from_registry(&reg)
            .await
            .unwrap();
        let names = src.names_for("comp-secretful").expect("present");
        assert!(names.contains("api_key") && names.contains("password"));
    }
}
