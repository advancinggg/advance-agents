//! CLI-served `AgentAdminProvider` (CONTRACT-190 agents family) over the production agent tree.
//!
//! The adapter binds the SAME `AgentTreeStore` every daemon consumer reads, the production
//! spawner (`DefaultSpawner` + the per-child serve observer, so a client-created child is served
//! exactly like a runtime `spawn-child`), a `DefaultTerminateController` composed with the real
//! grant/run/mailbox/workspace cascades (+ the per-child `LoopCascade` when messaging is wired),
//! and the built-in template registry.
//!
//! Persistence: the daemon's tree is in-memory. A client-created child is recorded in the root
//! `.agent/config.yaml` `agents:` hierarchy block (the MODULE-005-AC-25 boot materializer's
//! input) — alias / template / target-path / `capabilities` — so it is re-materialized at the
//! next daemon start with the capability set it was created (or last updated) with; a delete
//! removes the declaration.
//! The root document is rewritten through `serde_yml` (comments are not preserved). A child whose
//! parent is itself undeclared (a guest-spawned, non-persisted parent) is created live but not
//! persisted, because the parent will not exist after a restart either.
//!
//! Config-document rule (`:update`): a replacement document that carries no top-level `agents`
//! key keeps the agent's existing `agents:` block (the hierarchy is managed through create/delete,
//! never silently dropped by a capabilities edit); a document that carries `agents` replaces it and
//! is validated with the same schema the boot materializer uses. Every write of the ROOT document
//! (create / delete / capability update / root config edit) is additionally checked for boot
//! consistency: each declared child's `capabilities` must be covered by its parent's (the root's
//! active capabilities for top-level children), otherwise the request is refused — the API can
//! never persist a hierarchy the next daemon start would abort on.
//!
//! Lane agent-llm-policy (2026-09-16): a create/update `llm` block is written as the top-level
//! `llm:` key of the TARGET agent's own `.agent/config.yaml` (every other key kept; the root's
//! document included). `llm.provider` must name an `llm-providers[].id` of the LIVE runtime
//! config (`RuntimeConfigProvider::current()`), otherwise `UnknownProvider`. The gateway's
//! `WorkspaceAgentLlmPolicy` re-reads the file by mtime, so the block applies at the agent's
//! next LLM call — no restart.

use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_client_api::agents::{
    validate_display_name, ClientAgentCapability, ClientAgentConfig, ClientAgentDeclaredChild,
    ClientAgentDeleteResult, ClientAgentDetail, ClientAgentLlm, ClientAgentSummary,
    ClientAgentTemplate, ClientCreateAgentRequest, ClientDeleteAgentRequest,
    ClientUpdateAgentRequest, MAX_AGENT_CONFIG_BYTES,
};
use advance_client_api::{AgentAdminProvider, ClientApi, ClientCapParam, ProviderError};
use advance_home::TopLevelDisplayName;
use advance_messaging::MailboxStore;
use advance_run_manager::RunManager;
use advance_runtime::config::RuntimeConfigProvider;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot, Capability,
};
use advance_shared_types::capability::{CapParams, CapabilityId};
use advance_shared_types::mailbox::{Message, MessageKind};
use cap_grant::GrantStore;
use cap_lifecycle::spawn::{SpawnChildConfig, Spawner, SpawnerSubsetGate};
use cap_lifecycle::templates::TemplateResolver;
use cap_lifecycle::terminate::{LoopCascade, MailboxCascade, TerminateController};
use cap_lifecycle::{
    atomic_write, AgentTreeStore, CapGrantSubsetAdapter, DefaultTerminateController,
    FsMemoryArchiver, FsWorkspaceCleanup, GrantRevokeCascade, LifecycleError, RunManagerCascade,
    SpawnError,
};
use serde_yml::{Mapping, Value};

use crate::agent_config::{
    parse_agent_llm_config, parse_agents_config, read_agent_yaml, upsert_llm_block, AgentDecl,
    AgentLlmDecl,
};

const AGENT_DIR: &str = ".agent";
const CONFIG_FILE: &str = "config.yaml";
const MAX_PROJECTED_PARAMS: usize = 64;
const MAX_PROJECTED_PARAM_BYTES: usize = 4096;

/// The production `AgentAdminProvider`.
pub struct AgentAdminAdapter {
    tree: AgentTreeStore,
    spawner: Arc<dyn Spawner>,
    terminator: Arc<dyn TerminateController>,
    templates: Arc<dyn TemplateResolver>,
    root_id: AgentId,
    workspace_root: PathBuf,
    /// The live runtime config: `llm.provider` ids are validated against its `llm-providers`.
    config: Arc<dyn RuntimeConfigProvider>,
    /// Serializes every mutation: tree edits + root-config rewrites must not interleave.
    mutation: Mutex<()>,
}

impl AgentAdminAdapter {
    pub fn new(
        tree: AgentTreeStore,
        spawner: Arc<dyn Spawner>,
        terminator: Arc<dyn TerminateController>,
        templates: Arc<dyn TemplateResolver>,
        root_id: AgentId,
        config: Arc<dyn RuntimeConfigProvider>,
    ) -> Self {
        let workspace_root = tree.workspace_root().to_path_buf();
        Self {
            tree,
            spawner,
            terminator,
            templates,
            root_id,
            workspace_root,
            config,
            mutation: Mutex::new(()),
        }
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    // ── projections ──────────────────────────────────────────────────────────────────────────

    fn node(&self, agent_id: &str) -> Result<AgentNode, ProviderError> {
        self.tree
            .get_node(&AgentId(agent_id.to_string()))
            .ok_or_else(|| ProviderError::NotFound("agent".into()))
    }

    fn relative_path(&self, workspace: &Path) -> String {
        let rel = workspace
            .strip_prefix(&self.workspace_root)
            .unwrap_or(workspace);
        let parts: Vec<String> = rel
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        if parts.is_empty() {
            ".".to_string()
        } else {
            parts.join("/")
        }
    }

    fn summary(&self, node: &AgentNode) -> ClientAgentSummary {
        ClientAgentSummary {
            agent_id: node.id.0.clone(),
            kind: kind_name(&node.kind).to_string(),
            parent: node.parent.as_ref().map(|p| p.0.clone()),
            status: status_name(&node.status).to_string(),
            workspace_path: self.relative_path(&node.workspace_path),
            template_ref: node.template_ref.clone(),
            display_name: TopLevelDisplayName::get(&node.workspace_path),
        }
    }

    fn detail(&self, node: &AgentNode) -> ClientAgentDetail {
        let mut children = self.tree.children_of(&node.id.0);
        children.sort();
        let agent_dir = node.workspace_path.join(AGENT_DIR);
        ClientAgentDetail {
            agent: self.summary(node),
            config: project_config(read_config_document(&node.workspace_path).as_deref()),
            capabilities: node
                .capabilities
                .iter()
                .map(|c| c.id.as_str().to_string())
                .collect(),
            children,
            driver_present: is_regular_file(&agent_dir.join("behavior.component.wasm"))
                || is_regular_file(&agent_dir.join("behavior.wasm")),
        }
    }

    // ── root-config (`agents:` block) persistence ────────────────────────────────────────────

    fn root_workspace(&self) -> Result<PathBuf, ProviderError> {
        Ok(self.node(&self.root_id.0)?.workspace_path)
    }

    fn load_document(&self, workspace: &Path) -> Result<Mapping, ProviderError> {
        let path = workspace.join(AGENT_DIR).join(CONFIG_FILE);
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(Mapping::new());
        }
        let bytes = read_agent_yaml(workspace)
            .ok_or_else(|| ProviderError::Unavailable("agent config unreadable".into()))?;
        parse_mapping(&bytes)
            .map_err(|_| ProviderError::Unavailable("agent config unparseable".into()))
    }

    fn write_document(&self, workspace: &Path, doc: &Mapping) -> Result<(), ProviderError> {
        let text = serde_yml::to_string(&Value::Mapping(doc.clone()))
            .map_err(|_| ProviderError::Unavailable("agent config serialize".into()))?;
        // The rewritten hierarchy must still pass the boot materializer's schema + caps.
        parse_agents_config(Some(text.as_bytes()))
            .map_err(|_| ProviderError::InvalidRequest("declared hierarchy".into()))?;
        if workspace == self.root_workspace()? {
            check_hierarchy_capabilities(&text)?;
        }
        self.write_config_text(workspace, &text)
    }

    fn write_config_text(&self, workspace: &Path, text: &str) -> Result<(), ProviderError> {
        if text.len() > MAX_AGENT_CONFIG_BYTES {
            return Err(ProviderError::InvalidRequest(
                "agent config too large".into(),
            ));
        }
        let agent_dir = workspace.join(AGENT_DIR);
        if !is_real_dir(&agent_dir) {
            return Err(ProviderError::Unavailable("agent dir missing".into()));
        }
        atomic_write(&agent_dir.join(CONFIG_FILE), text.as_bytes())
            .map_err(|_| ProviderError::Unavailable("agent config write".into()))
    }

    /// Record `alias` under `parent_id` in the root document. Returns `Ok(true)` when persisted,
    /// `Ok(false)` when the parent is not itself declared (nothing to nest under).
    fn record_declared_child(
        &self,
        parent_id: &str,
        alias: &str,
        template: &str,
        target_path: &str,
        capabilities: &[String],
    ) -> Result<bool, ProviderError> {
        let root_ws = self.root_workspace()?;
        let mut doc = self.load_document(&root_ws)?;
        let mut entry = Mapping::new();
        entry.insert(str_value("alias"), str_value(alias));
        entry.insert(str_value("template"), str_value(template));
        entry.insert(str_value("target-path"), str_value(target_path));
        if !capabilities.is_empty() {
            entry.insert(str_value("capabilities"), capabilities_value(capabilities));
        }
        let agents = decl_sequence_mut(&mut doc);
        // A stale declaration with the same alias (left behind by an older daemon) is replaced.
        remove_decl(agents, alias);
        if parent_id == self.root_id.0 {
            agents.push(Value::Mapping(entry));
        } else {
            match find_decl_mut(agents, parent_id) {
                Some(parent_decl) => {
                    children_sequence_mut(parent_decl).push(Value::Mapping(entry));
                }
                None => return Ok(false),
            }
        }
        self.write_document(&root_ws, &doc)?;
        Ok(true)
    }

    /// Remove `alias` (and its nested declarations) from the root document; returns the removed
    /// declaration so a failed cascade can restore it.
    fn remove_declared_child(&self, alias: &str) -> Result<Option<Value>, ProviderError> {
        let root_ws = self.root_workspace()?;
        let mut doc = self.load_document(&root_ws)?;
        let removed = match doc.get_mut(str_value("agents")) {
            Some(Value::Sequence(seq)) => remove_decl(seq, alias),
            _ => None,
        };
        if removed.is_some() {
            self.write_document(&root_ws, &doc)?;
        }
        Ok(removed)
    }

    /// Replace the persisted `capabilities:` of `alias`'s declaration. `Ok(false)` when the agent
    /// is not declared (a guest-spawned, non-persisted child).
    fn set_declared_capabilities(
        &self,
        alias: &str,
        capabilities: &[String],
    ) -> Result<bool, ProviderError> {
        let root_ws = self.root_workspace()?;
        let mut doc = self.load_document(&root_ws)?;
        let Some(Value::Sequence(agents)) = doc.get_mut(str_value("agents")) else {
            return Ok(false);
        };
        let Some(decl) = find_decl_mut(agents, alias) else {
            return Ok(false);
        };
        if capabilities.is_empty() {
            decl.remove(str_value("capabilities"));
        } else {
            decl.insert(str_value("capabilities"), capabilities_value(capabilities));
        }
        self.write_document(&root_ws, &doc)?;
        Ok(true)
    }

    fn restore_declared_child(&self, parent_id: &str, decl: Value) -> Result<(), ProviderError> {
        let root_ws = self.root_workspace()?;
        let mut doc = self.load_document(&root_ws)?;
        let agents = decl_sequence_mut(&mut doc);
        if parent_id == self.root_id.0 {
            agents.push(decl);
        } else if let Some(parent_decl) = find_decl_mut(agents, parent_id) {
            children_sequence_mut(parent_decl).push(decl);
        } else {
            return Ok(());
        }
        self.write_document(&root_ws, &doc)
    }

    // ── llm policy block (lane agent-llm-policy) ─────────────────────────────────────────────

    /// `llm.provider` must name a configured `llm-providers[].id` (the live config, so a provider
    /// added by a hot-reload is accepted without a restart).
    fn validate_llm_provider(&self, llm: &ClientAgentLlm) -> Result<(), ProviderError> {
        if let Some(provider) = &llm.provider {
            let cfg = self.config.current();
            if !cfg.llm_providers.iter().any(|p| &p.id == provider) {
                return Err(ProviderError::UnknownProvider(provider.clone()));
            }
        }
        Ok(())
    }

    /// Replace (or, for an empty block, remove) the top-level `llm:` key of the agent's own
    /// config document, keeping every other key.
    fn write_llm_block(&self, workspace: &Path, llm: &ClientAgentLlm) -> Result<(), ProviderError> {
        let mut doc = self.load_document(workspace)?;
        let decl = llm_to_decl(llm);
        upsert_llm_block(&mut doc, Some(&decl));
        self.write_document(workspace, &doc)
    }

    // ── validation ───────────────────────────────────────────────────────────────────────────

    /// Validate a replacement config document with the runtime's own readers: bounded, YAML that
    /// parses to a mapping (or an empty document), a well-formed `capabilities:` mapping, and an
    /// `agents:` block that passes the boot materializer's schema/caps.
    fn validate_config_document(&self, yaml: &str) -> Result<(), ProviderError> {
        if yaml.len() > MAX_AGENT_CONFIG_BYTES {
            return Err(ProviderError::InvalidRequest(
                "agent config too large".into(),
            ));
        }
        let invalid = || ProviderError::InvalidRequest("agent config document".into());
        // Anchor/alias amplification guard + strict `agents:` schema (the lenient whole-doc parse
        // inside is followed by our own strict parse below).
        parse_agents_config(Some(yaml.as_bytes())).map_err(|_| invalid())?;
        let doc = parse_mapping(yaml.as_bytes()).map_err(|_| invalid())?;
        if let Some(caps) = doc.get(str_value("capabilities")) {
            let caps = caps.as_mapping().ok_or_else(invalid)?;
            for (key, value) in caps {
                let name = key.as_str().ok_or_else(invalid)?;
                if name.is_empty() || name.contains(':') {
                    return Err(invalid());
                }
                match value {
                    Value::Bool(_) => {}
                    Value::Mapping(m) => {
                        if m.keys().any(|k| k.as_str().is_none()) {
                            return Err(invalid());
                        }
                    }
                    _ => return Err(invalid()),
                }
            }
        }
        Ok(())
    }

    /// Guarded recursive removal: only under the workspace root, never the root itself, no `..`,
    /// no symlink in the materialized prefix. An absent path is a successful no-op.
    fn guarded_remove_dir_all(&self, path: &Path) -> Result<(), ProviderError> {
        let invalid = || ProviderError::InvalidRequest("workspace path".into());
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(invalid());
        }
        if !path.starts_with(&self.workspace_root) || path == self.workspace_root {
            return Err(invalid());
        }
        cap_lifecycle::workspace::symlink_check(&self.workspace_root, path)
            .map_err(|_| invalid())?;
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ProviderError::Unavailable("workspace remove".into())),
        }
    }
}

impl AgentAdminProvider for AgentAdminAdapter {
    fn list_agents(&self) -> Result<Vec<ClientAgentSummary>, ProviderError> {
        let snapshot = self.tree.snapshot();
        let mut agents: Vec<ClientAgentSummary> =
            snapshot.nodes.iter().map(|n| self.summary(n)).collect();
        // Root first, then by id — a stable order for clients.
        agents.sort_by(|a, b| {
            (a.parent.is_some(), a.agent_id.as_str())
                .cmp(&(b.parent.is_some(), b.agent_id.as_str()))
        });
        Ok(agents)
    }

    fn get_agent(&self, agent_id: &str) -> Result<ClientAgentDetail, ProviderError> {
        let node = self.node(agent_id)?;
        Ok(self.detail(&node))
    }

    fn create_agent(
        &self,
        request: &ClientCreateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        let _guard = self.mutation.lock().unwrap_or_else(|p| p.into_inner());
        let parent_id = request
            .parent
            .clone()
            .unwrap_or_else(|| self.root_id.0.clone());
        let parent = self
            .node(&parent_id)
            .map_err(|_| ProviderError::NotFound("parent".into()))?;
        if parent.kind == AgentKind::Sub {
            return Err(ProviderError::InvalidRequest("sub parent".into()));
        }
        if self.tree.contains(&AgentId(request.agent_id.clone())) {
            return Err(ProviderError::AlreadyExists("agent id".into()));
        }
        self.templates
            .resolve(&request.template_ref)
            .map_err(|_| ProviderError::InvalidRequest("template".into()))?;
        if let Some(yaml) = &request.config_yaml {
            self.validate_config_document(yaml)?;
        }
        if let Some(llm) = &request.llm {
            self.validate_llm_provider(llm)?;
        }
        if let Some(name) = &request.display_name {
            validate_display_name(name)
                .map_err(|_| ProviderError::InvalidRequest("display name".into()))?;
        }
        let relative = request
            .workspace_path
            .clone()
            .unwrap_or_else(|| request.agent_id.clone());
        // Territory pre-checks (clean codes instead of the spawner's stringly tree errors).
        let target = parent.workspace_path.join(&relative);
        if self
            .tree
            .snapshot()
            .nodes
            .iter()
            .any(|n| n.workspace_path == target)
            || is_real_dir(&target.join(AGENT_DIR))
        {
            return Err(ProviderError::AlreadyExists("workspace".into()));
        }
        let capabilities: Vec<Capability> = request
            .capabilities
            .iter()
            .map(|c| Capability {
                id: CapabilityId::new(c.as_str()),
                params: CapParams::empty(),
            })
            .collect();

        // Persist FIRST so a spawn failure can roll the declaration back; a successful spawn is
        // never left undeclared.
        let persisted = self.record_declared_child(
            &parent_id,
            &request.agent_id,
            &request.template_ref,
            &relative,
            &request.capabilities,
        )?;
        let cfg = SpawnChildConfig {
            parent_id: AgentId(parent_id.clone()),
            child_id: AgentId(request.agent_id.clone()),
            child_workspace_path: PathBuf::from(&relative),
            capabilities,
            template_ref: Some(request.template_ref.clone()),
            binary: None,
        };
        if let Err(e) = self.spawner.spawn_child(cfg) {
            if persisted {
                let _ = self.remove_declared_child(&request.agent_id);
            }
            return Err(map_spawn_err(e));
        }
        let node = self.node(&request.agent_id)?;
        if let Some(yaml) = &request.config_yaml {
            self.write_config_text(&node.workspace_path, yaml)?;
        }
        // The llm block goes in AFTER the document so it wins over a block the document carries.
        if let Some(llm) = &request.llm {
            self.write_llm_block(&node.workspace_path, llm)?;
        }
        if let Some(name) = &request.display_name {
            TopLevelDisplayName::set(&node.workspace_path, name)
                .map_err(|_| ProviderError::Unavailable("display name write".into()))?;
        }
        Ok(self.detail(&node))
    }

    fn update_agent(
        &self,
        agent_id: &str,
        request: &ClientUpdateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        let _guard = self.mutation.lock().unwrap_or_else(|p| p.into_inner());
        let node = self.node(agent_id)?;
        // Validate the llm block FIRST so a refused provider id leaves nothing half-applied.
        if let Some(llm) = &request.llm {
            self.validate_llm_provider(llm)?;
        }
        if let Some(yaml) = &request.config_yaml {
            self.validate_config_document(yaml)?;
            let replacement = parse_mapping(yaml.as_bytes())
                .map_err(|_| ProviderError::InvalidRequest("agent config document".into()))?;
            let existing = self.load_document(&node.workspace_path)?;
            match (
                replacement.contains_key(str_value("agents")),
                existing.get(str_value("agents")),
            ) {
                // Carry the declared hierarchy over: a capabilities edit never drops it.
                (false, Some(agents)) => {
                    let mut merged = replacement;
                    merged.insert(str_value("agents"), agents.clone());
                    self.write_document(&node.workspace_path, &merged)?;
                }
                _ => {
                    if node.kind == AgentKind::Root {
                        // A root document defines the next boot's root capability set AND (when
                        // it carries `agents`) the hierarchy: keep them consistent, fail closed.
                        check_hierarchy_capabilities(yaml)?;
                    }
                    self.write_config_text(&node.workspace_path, yaml)?
                }
            }
        }
        if let Some(name) = &request.display_name {
            validate_display_name(name)
                .map_err(|_| ProviderError::InvalidRequest("display name".into()))?;
            TopLevelDisplayName::set(&node.workspace_path, name)
                .map_err(|_| ProviderError::Unavailable("display name write".into()))?;
        }
        if let Some(capabilities) = &request.capabilities {
            // The persisted capability list is a CHILD-declaration concept: the root's operative
            // set is its own config document, and a Sub is never declared.
            if node.kind != AgentKind::Child {
                return Err(ProviderError::InvalidRequest(
                    "capabilities on non-child".into(),
                ));
            }
            let parent_id = node
                .parent
                .clone()
                .ok_or_else(|| ProviderError::InvalidRequest("orphan agent".into()))?;
            let parent = self.node(&parent_id.0)?;
            let requested: Vec<Capability> = capabilities
                .iter()
                .map(|c| Capability {
                    id: CapabilityId::new(c.as_str()),
                    params: CapParams::empty(),
                })
                .collect();
            CapGrantSubsetAdapter::new()
                .check(&parent.capabilities, &requested)
                .map_err(|_| ProviderError::InvalidRequest("capability subset".into()))?;
            if !self.set_declared_capabilities(agent_id, capabilities)? {
                return Err(ProviderError::InvalidRequest("agent not declared".into()));
            }
        }
        if let Some(llm) = &request.llm {
            // Whole-block replacement of the agent's OWN document's `llm:` key (root included);
            // `{}` clears it. Applies at the next LLM call (mtime-tracked), no restart.
            self.write_llm_block(&node.workspace_path, llm)?;
        }
        Ok(self.detail(&node))
    }

    fn delete_agent(
        &self,
        agent_id: &str,
        request: &ClientDeleteAgentRequest,
    ) -> Result<ClientAgentDeleteResult, ProviderError> {
        let _guard = self.mutation.lock().unwrap_or_else(|p| p.into_inner());
        let node = self.node(agent_id)?;
        if node.kind == AgentKind::Root {
            return Err(ProviderError::InvalidRequest("root agent".into()));
        }
        let parent = node
            .parent
            .clone()
            .ok_or_else(|| ProviderError::InvalidRequest("orphan agent".into()))?;
        // The removal set BEFORE the cascade (post-order: descendants first, the target last).
        let snapshot = self.tree.snapshot();
        let mut order: Vec<AgentId> = Vec::new();
        let mut stack = vec![(node.id.clone(), false)];
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                order.push(id);
                continue;
            }
            stack.push((id.clone(), true));
            for child in snapshot.children_of.get(&id).into_iter().flatten() {
                stack.push((child.clone(), false));
            }
        }
        let removed_nodes: Vec<AgentNode> = order
            .iter()
            .filter_map(|id| snapshot.nodes.iter().find(|n| &n.id == id).cloned())
            .collect();

        // De-register first (rolled back if the cascade fails); then the MODULE-005 cascade.
        let declaration = self.remove_declared_child(agent_id)?;
        if let Err(e) = self.terminator.terminate_child(&parent.0, agent_id) {
            if let Some(decl) = declaration {
                let _ = self.restore_declared_child(&parent.0, decl);
            }
            return Err(map_lifecycle_err(e));
        }
        // Territory cleanup: a Child directory stays (its content is the user's) but stops being
        // agent-managed — the `.agent/` marker is removed. Sub workspaces were removed by the
        // cascade. With `remove_workspace`, the target's whole directory (which contains every
        // descendant territory) is removed.
        let mut workspace_removed = false;
        if request.remove_workspace {
            self.guarded_remove_dir_all(&node.workspace_path)?;
            workspace_removed = true;
        } else {
            for removed in removed_nodes.iter().filter(|n| n.kind == AgentKind::Child) {
                self.guarded_remove_dir_all(&removed.workspace_path.join(AGENT_DIR))?;
            }
        }
        Ok(ClientAgentDeleteResult {
            agent_id: agent_id.to_string(),
            removed_agent_ids: order
                .into_iter()
                .filter(|id| !self.tree.contains(id))
                .map(|id| id.0)
                .collect(),
            workspace_removed,
        })
    }

    fn list_templates(&self) -> Result<Vec<ClientAgentTemplate>, ProviderError> {
        let mut names = self.templates.list();
        names.sort();
        names.dedup();
        Ok(names
            .into_iter()
            .map(|name| {
                let description = self
                    .templates
                    .resolve(&name)
                    .ok()
                    .and_then(|t| manifest_description(&t.manifest_yaml));
                ClientAgentTemplate {
                    template_ref: name,
                    description,
                }
            })
            .collect())
    }
}

// ── production terminate controller ──────────────────────────────────────────────────────────

/// Bare-tree-id → served mailbox key (e.g. `default-agent` → `agent:default`, `b` → `agent:b`).
pub type MailboxKeyResolver = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Colon-aware `MailboxCascade`: the terminate cascade hands BARE tree ids, but served mailboxes
/// are colon-keyed, so both the flush and the parent notice resolve through the daemon's key
/// resolver (the cap-lifecycle `MailboxFlushCascade` would probe a bare key that never exists).
pub struct ColonMailboxCascade {
    store: Arc<MailboxStore>,
    resolver: MailboxKeyResolver,
}

impl ColonMailboxCascade {
    pub fn new(store: Arc<MailboxStore>, resolver: MailboxKeyResolver) -> Self {
        Self { store, resolver }
    }
}

impl MailboxCascade for ColonMailboxCascade {
    fn flush_mailbox(&self, agent_id: &str) -> Result<(), LifecycleError> {
        let key = (self.resolver)(agent_id);
        if let Some(mb) = self.store.get(&key) {
            mb.unfreeze();
            let mut budget = mb.depth().saturating_add(8);
            while budget > 0 && mb.poll().is_some() {
                budget -= 1;
            }
        }
        Ok(())
    }

    fn notify_parent_crash(
        &self,
        parent_id: &str,
        child_id: &str,
        reason: &str,
    ) -> Result<(), LifecycleError> {
        let key = (self.resolver)(parent_id);
        let mb = self.store.get_or_create(&key).map_err(|e| {
            LifecycleError::CascadePartial(format!("get parent mailbox {key}: {e:?}"))
        })?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let payload = serde_json::json!({
            "event": "component.terminated",
            "child": child_id,
            "reason": reason,
        })
        .to_string()
        .into_bytes();
        let msg = Message {
            id: format!("sys-crash:{child_id}:{nanos}"),
            kind: MessageKind::System,
            from: "system".to_string(),
            to: key.clone(),
            payload,
            context: None,
            timestamp: std::time::SystemTime::now(),
            origin: None,
        };
        mb.deliver(msg).map_err(|e| {
            LifecycleError::CascadePartial(format!("deliver crash notice to {key}: {e:?}"))
        })
    }
}

/// Compose the production `DefaultTerminateController` the agents family drives: real grant
/// revoke, colon-aware mailbox flush, synchronous run cancel, containment-guarded Sub workspace
/// removal, memory archiving, and (when the per-child manager exists) the serve-loop cascade.
pub fn build_agent_terminate_controller(
    tree: AgentTreeStore,
    grant_store: Arc<GrantStore>,
    mailbox_store: Arc<MailboxStore>,
    run_manager: Arc<RunManager>,
    workspace_root: PathBuf,
    resolver: MailboxKeyResolver,
    loop_cascade: Option<Arc<dyn LoopCascade>>,
) -> DefaultTerminateController {
    let mut controller = DefaultTerminateController::new(
        tree,
        Arc::new(GrantRevokeCascade::new(grant_store)),
        Arc::new(ColonMailboxCascade::new(mailbox_store, resolver)),
        Arc::new(RunManagerCascade::new(run_manager)),
        Arc::new(FsWorkspaceCleanup::new(workspace_root)),
    )
    .with_memory_archiver(Arc::new(FsMemoryArchiver::new()));
    if let Some(cascade) = loop_cascade {
        controller = controller.with_loop_cascade(cascade);
    }
    controller
}

/// Late-install the agents provider into an already-bound `Arc<ClientApi>`.
pub fn install_agent_admin(api: &ClientApi, adapter: Arc<AgentAdminAdapter>) {
    api.install_agent_provider(adapter);
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────────

fn kind_name(kind: &AgentKind) -> &'static str {
    match kind {
        AgentKind::Root => "root",
        AgentKind::Child => "child",
        AgentKind::Sub => "sub",
    }
}

fn status_name(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "active",
        AgentStatus::Paused => "paused",
        AgentStatus::Terminated => "terminated",
        AgentStatus::Failed => "failed",
    }
}

fn map_spawn_err(e: SpawnError) -> ProviderError {
    match e {
        SpawnError::AlreadyExists(_) => ProviderError::AlreadyExists("agent".into()),
        SpawnError::ParentNotFound(_) => ProviderError::NotFound("parent".into()),
        SpawnError::InvalidConfig(_)
        | SpawnError::PathTraversal(_)
        | SpawnError::SubsetViolation(_) => ProviderError::InvalidRequest("spawn".into()),
        SpawnError::TreeStateInvalid(_) => ProviderError::InvalidState("tree".into()),
        SpawnError::WorkspaceIoFailure(_) => ProviderError::Unavailable("workspace".into()),
    }
}

fn map_lifecycle_err(e: LifecycleError) -> ProviderError {
    match e {
        LifecycleError::NotFound(_) => ProviderError::NotFound("agent".into()),
        LifecycleError::PermissionDenied(_) => ProviderError::InvalidState("terminate".into()),
        LifecycleError::InvalidTarget(_) | LifecycleError::RollbackGate(_) => {
            ProviderError::InvalidRequest("terminate".into())
        }
        LifecycleError::IoFailure(_) | LifecycleError::CascadePartial(_) => {
            ProviderError::Unavailable("terminate".into())
        }
    }
}

fn str_value(s: &str) -> Value {
    Value::String(s.to_string())
}

fn capabilities_value(capabilities: &[String]) -> Value {
    Value::Sequence(capabilities.iter().map(|c| str_value(c)).collect())
}

/// The next boot materializes every declared child with its `capabilities:` and subset-gates
/// them against the parent node (the root's node set is the root document's active
/// capabilities). A root document whose hierarchy violates that would abort the next daemon
/// start, so every write of the root document is checked here first (fail-closed →
/// `invalid_request`). Whole-capability ids only, so containment is the exact gate.
fn check_hierarchy_capabilities(root_document: &str) -> Result<(), ProviderError> {
    let bytes = root_document.as_bytes();
    let decls = parse_agents_config(Some(bytes))
        .map_err(|_| ProviderError::InvalidRequest("declared hierarchy".into()))?;
    let root_caps: Vec<String> = crate::agent_config::active_capabilities(Some(bytes))
        .into_iter()
        .map(|c| c.capability.as_str().to_string())
        .collect();
    fn covered(parent: &[String], decls: &[AgentDecl]) -> bool {
        decls.iter().all(|d| {
            d.capabilities.iter().all(|c| parent.contains(c))
                && covered(&d.capabilities, &d.children)
        })
    }
    if covered(&root_caps, &decls) {
        Ok(())
    } else {
        Err(ProviderError::InvalidRequest(
            "declared capabilities exceed the parent's".into(),
        ))
    }
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false)
}

fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// Parse a config document into its top-level mapping (an empty document is an empty mapping).
fn parse_mapping(bytes: &[u8]) -> Result<Mapping, ()> {
    match serde_yml::from_slice::<Value>(bytes).map_err(|_| ())? {
        Value::Mapping(m) => Ok(m),
        Value::Null => Ok(Mapping::new()),
        _ => Err(()),
    }
}

/// The verbatim config document under `workspace`, when present, readable, and within bound.
fn read_config_document(workspace: &Path) -> Option<String> {
    let bytes = read_agent_yaml(workspace)?;
    if bytes.len() > MAX_AGENT_CONFIG_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn decl_sequence_mut(doc: &mut Mapping) -> &mut Vec<Value> {
    let key = str_value("agents");
    if !matches!(doc.get(&key), Some(Value::Sequence(_))) {
        doc.insert(key.clone(), Value::Sequence(Vec::new()));
    }
    match doc.get_mut(&key) {
        Some(Value::Sequence(seq)) => seq,
        _ => unreachable!("agents sequence was just ensured"),
    }
}

fn children_sequence_mut(decl: &mut Mapping) -> &mut Vec<Value> {
    let key = str_value("children");
    if !matches!(decl.get(&key), Some(Value::Sequence(_))) {
        decl.insert(key.clone(), Value::Sequence(Vec::new()));
    }
    match decl.get_mut(&key) {
        Some(Value::Sequence(seq)) => seq,
        _ => unreachable!("children sequence was just ensured"),
    }
}

fn decl_alias(value: &Value) -> Option<&str> {
    value
        .as_mapping()?
        .get(str_value("alias"))
        .and_then(Value::as_str)
}

fn find_decl_mut<'a>(seq: &'a mut Vec<Value>, alias: &str) -> Option<&'a mut Mapping> {
    for value in seq.iter_mut() {
        if decl_alias(value) == Some(alias) {
            return value.as_mapping_mut();
        }
        if let Some(Value::Sequence(children)) = value
            .as_mapping_mut()
            .and_then(|m| m.get_mut(str_value("children")))
        {
            if let Some(found) = find_decl_mut(children, alias) {
                return Some(found);
            }
        }
    }
    None
}

fn remove_decl(seq: &mut Vec<Value>, alias: &str) -> Option<Value> {
    if let Some(i) = seq.iter().position(|v| decl_alias(v) == Some(alias)) {
        return Some(seq.remove(i));
    }
    for value in seq.iter_mut() {
        if let Some(Value::Sequence(children)) = value
            .as_mapping_mut()
            .and_then(|m| m.get_mut(str_value("children")))
        {
            if let Some(removed) = remove_decl(children, alias) {
                return Some(removed);
            }
        }
    }
    None
}

fn manifest_description(manifest_yaml: &str) -> Option<String> {
    let doc = parse_mapping(manifest_yaml.as_bytes()).ok()?;
    doc.get(str_value("description"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn llm_to_decl(llm: &ClientAgentLlm) -> AgentLlmDecl {
    AgentLlmDecl {
        provider: llm.provider.clone(),
        model: llm.model.clone(),
        constraint: llm.constraint.clone(),
    }
}

fn decl_to_llm(decl: &AgentLlmDecl) -> ClientAgentLlm {
    ClientAgentLlm {
        provider: decl.provider.clone(),
        model: decl.model.clone(),
        constraint: decl.constraint.clone(),
    }
}

/// The typed `llm:` view of a document: present and well-formed → `Some`; absent, empty, or
/// malformed → `None` (the verbatim text still carries it).
fn project_llm(yaml: &str) -> Option<ClientAgentLlm> {
    parse_agent_llm_config(Some(yaml.as_bytes()))
        .ok()
        .flatten()
        .map(|decl| decl_to_llm(&decl))
}

fn declared_child(decl: &AgentDecl) -> ClientAgentDeclaredChild {
    ClientAgentDeclaredChild {
        alias: decl.alias.clone(),
        template: decl.template.clone(),
        target_path: decl
            .target_path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
        capabilities: decl.capabilities.clone(),
        children: decl.children.iter().map(declared_child).collect(),
    }
}

/// Typed projection of a config document: the `capabilities:` mapping (bool / mapping forms, the
/// same shapes the L0 gate + cap-grant compiler read) and the `agents:` hierarchy. A document
/// that fails the boot materializer's guards projects no typed view (the verbatim text is still
/// returned).
pub fn project_config(yaml: Option<&str>) -> ClientAgentConfig {
    let Some(yaml) = yaml else {
        return ClientAgentConfig {
            config_yaml: None,
            capabilities: Vec::new(),
            declared_children: Vec::new(),
            llm: None,
        };
    };
    let Ok(decls) = parse_agents_config(Some(yaml.as_bytes())) else {
        return ClientAgentConfig {
            config_yaml: Some(yaml.to_string()),
            capabilities: Vec::new(),
            declared_children: Vec::new(),
            llm: None,
        };
    };
    let mut capabilities = Vec::new();
    if let Ok(doc) = parse_mapping(yaml.as_bytes()) {
        if let Some(caps) = doc
            .get(str_value("capabilities"))
            .and_then(Value::as_mapping)
        {
            for (key, value) in caps {
                let Some(name) = key.as_str() else { continue };
                let (enabled, auto_grant, params) = match value {
                    Value::Bool(b) => (*b, true, Vec::new()),
                    Value::Mapping(m) => {
                        let auto_grant =
                            !matches!(m.get(str_value("auto-grant")), Some(Value::Bool(false)));
                        let params = m
                            .iter()
                            .filter(|(k, _)| k.as_str() != Some("auto-grant"))
                            .filter_map(|(k, v)| {
                                let key = k.as_str()?.to_string();
                                let mut value = serde_yml::to_string(v).ok()?;
                                while value.ends_with('\n') {
                                    value.pop();
                                }
                                value.truncate(MAX_PROJECTED_PARAM_BYTES);
                                Some(ClientCapParam { key, value })
                            })
                            .take(MAX_PROJECTED_PARAMS)
                            .collect();
                        (true, auto_grant, params)
                    }
                    _ => (false, true, Vec::new()),
                };
                capabilities.push(ClientAgentCapability {
                    name: name.to_string(),
                    enabled,
                    auto_grant,
                    params,
                });
            }
        }
    }
    ClientAgentConfig {
        config_yaml: Some(yaml.to_string()),
        capabilities,
        declared_children: decls.iter().map(declared_child).collect(),
        llm: project_llm(yaml),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_capability_shapes() {
        let cfg = project_config(Some(
            "capabilities:\n  fs: true\n  llm: false\n  secrets:\n    auto-grant: false\n    scope: [a, b]\nagents:\n  - alias: r\n    template: explorer\n    target-path: teams/r\n",
        ));
        let by_name = |n: &str| {
            cfg.capabilities
                .iter()
                .find(|c| c.name == n)
                .unwrap()
                .clone()
        };
        assert!(by_name("fs").enabled && by_name("fs").auto_grant);
        assert!(!by_name("llm").enabled);
        let secrets = by_name("secrets");
        assert!(secrets.enabled && !secrets.auto_grant);
        assert_eq!(secrets.params.len(), 1);
        assert_eq!(secrets.params[0].key, "scope");
        assert_eq!(cfg.declared_children[0].alias, "r");
        assert_eq!(cfg.declared_children[0].target_path, "teams/r");
    }

    #[test]
    fn projects_llm_block() {
        let cfg = project_config(Some(
            "capabilities:\n  llm: true\nllm:\n  provider: local\n  model: tiny\n  constraint: device:mac\n",
        ));
        let llm = cfg.llm.expect("typed llm view");
        assert_eq!(llm.provider.as_deref(), Some("local"));
        assert_eq!(llm.model.as_deref(), Some("tiny"));
        assert_eq!(llm.constraint.as_deref(), Some("device:mac"));
        assert!(project_config(Some("capabilities:\n  fs: true\n"))
            .llm
            .is_none());
        // Malformed block: no typed view, verbatim text kept.
        let cfg = project_config(Some("capabilities:\n  fs: true\nllm:\n  providr: x\n"));
        assert!(cfg.llm.is_none());
        assert!(cfg.config_yaml.unwrap().contains("providr"));
        assert_eq!(cfg.capabilities.len(), 1, "the rest still projects");
    }

    #[test]
    fn malformed_hierarchy_projects_no_typed_view() {
        let cfg = project_config(Some("capabilities:\n  fs: true\nagents:\n  - bogus: 1\n"));
        assert!(cfg.capabilities.is_empty());
        assert!(cfg.declared_children.is_empty());
        assert!(cfg.config_yaml.is_some());
    }

    #[test]
    fn hierarchy_capabilities_must_be_covered() {
        assert!(check_hierarchy_capabilities(
            "capabilities:\n  fs: true\nagents:\n  - alias: a\n    template: t\n    target-path: a\n    capabilities: [fs]\n    children:\n      - alias: b\n        template: t\n        target-path: b\n        capabilities: [fs]\n"
        )
        .is_ok());
        // root lacks llm
        assert!(check_hierarchy_capabilities(
            "capabilities:\n  fs: true\nagents:\n  - alias: a\n    template: t\n    target-path: a\n    capabilities: [llm]\n"
        )
        .is_err());
        // grandchild exceeds its parent
        assert!(check_hierarchy_capabilities(
            "capabilities:\n  fs: true\n  llm: true\nagents:\n  - alias: a\n    template: t\n    target-path: a\n    capabilities: [fs]\n    children:\n      - alias: b\n        template: t\n        target-path: b\n        capabilities: [llm]\n"
        )
        .is_err());
        // opted-out (`fs: false`) does not cover a child
        assert!(check_hierarchy_capabilities(
            "capabilities:\n  fs: false\nagents:\n  - alias: a\n    template: t\n    target-path: a\n    capabilities: [fs]\n"
        )
        .is_err());
        // no hierarchy ⇒ trivially consistent
        assert!(check_hierarchy_capabilities("capabilities:\n  fs: true\n").is_ok());
    }

    #[test]
    fn nested_decl_edit_helpers() {
        let mut doc = parse_mapping(
            b"agents:\n  - alias: a\n    template: t\n    target-path: a\n    children:\n      - alias: b\n        template: t\n        target-path: b\n",
        )
        .unwrap();
        {
            let seq = decl_sequence_mut(&mut doc);
            assert!(find_decl_mut(seq, "b").is_some());
            assert!(find_decl_mut(seq, "zzz").is_none());
            let removed = remove_decl(seq, "b").expect("nested removal");
            assert_eq!(decl_alias(&removed), Some("b"));
            assert!(find_decl_mut(seq, "b").is_none());
            assert!(find_decl_mut(seq, "a").is_some());
        }
    }
}
