//! The composition's effective capability set: [`KNOWN_CAPABILITIES`] plus the
//! names the registered extensions declared. Default = known only (plain OSS).

use std::sync::Arc;

use advance_shared_types::agent_tree::Capability;
use cap_lifecycle::{CapGrantSubsetAdapter, SpawnError, SpawnerSubsetGate};

use crate::agent_config::KNOWN_CAPABILITIES;

/// Maximum byte length of one extension capability name (`<id>.<name>`).
pub const EXTENSION_CAPABILITY_MAX_LEN: usize = 64;

/// cap-lifecycle/src/tree.rs:38 (private `MAX_CAPABILITIES` there).
const AGENT_NODE_CAPABILITY_BOUND: usize = 64;

/// Per-compose bound on extension capability names, so a root that declares
/// every known capability and every extension capability still fits the agent
/// tree's per-node cap.
pub const MAX_EXTENSION_CAPABILITIES: usize =
    AGENT_NODE_CAPABILITY_BOUND - KNOWN_CAPABILITIES.len();

const _: () =
    assert!(MAX_EXTENSION_CAPABILITIES + KNOWN_CAPABILITIES.len() <= AGENT_NODE_CAPABILITY_BOUND);

/// Names that must never be declared as extension capabilities (the spec's
/// `KNOWN ∪ {web, data}` plus the two OSS dotted grant names).
pub const RESERVED_CAPABILITY_NAMES: &[&str] = &["web", "data", "mcp.servers", "mcp.tool-patterns"];

/// `KNOWN_CAPABILITIES` ∪ the composition's extension capabilities.
/// Default = known only (plain OSS).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveCapabilities {
    /// `(name, owner)`, declaration order.
    extension: Arc<[(&'static str, &'static str)]>,
}

impl EffectiveCapabilities {
    /// Known capabilities only. Equal to [`Default`].
    pub fn known_only() -> Self {
        Self::default()
    }

    /// Builds from VALIDATED declarations (`ExtensionSet::prepare` after
    /// `check_names` / `check_total`).
    #[doc(hidden)]
    pub fn from_extension_entries(entries: &[(&'static str, &'static [&'static str])]) -> Self {
        let mut extension = Vec::new();
        for (owner, names) in entries {
            for name in *names {
                extension.push((*name, *owner));
            }
        }
        Self {
            extension: extension.into(),
        }
    }

    /// True when there are no extension entries: every `*_with` equals the old fn.
    pub fn is_empty_extension(&self) -> bool {
        self.extension.is_empty()
    }

    /// True when `name` is an extension capability in this set.
    pub fn is_extension(&self, name: &str) -> bool {
        self.extension.iter().any(|(n, _)| *n == name)
    }

    /// True when `name` is known or an extension capability in this set.
    pub fn contains(&self, name: &str) -> bool {
        KNOWN_CAPABILITIES.contains(&name) || self.is_extension(name)
    }

    /// Known names in known order, then extension names in declaration order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        KNOWN_CAPABILITIES
            .iter()
            .copied()
            .chain(self.extension_names())
    }

    /// Extension names in declaration order.
    pub fn extension_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.extension.iter().map(|(n, _)| *n)
    }

    /// The extension that declared `name`, if it is an extension capability.
    pub fn owner_of(&self, name: &str) -> Option<&'static str> {
        self.extension
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, owner)| *owner)
    }

    /// Names declared by `extension`, in declaration order.
    pub fn declared_by<'a>(
        &'a self,
        extension: &'a str,
    ) -> impl Iterator<Item = &'static str> + 'a {
        self.extension
            .iter()
            .filter(move |(_, owner)| *owner == extension)
            .map(|(n, _)| *n)
    }
}

/// CONTRACT-122 subset gate over the effective set: extension capabilities are
/// whole-capability only; everything else goes to cap-grant's
/// `CapGrantSubsetAdapter` unchanged.
pub struct EffectiveSubsetGate {
    capabilities: EffectiveCapabilities,
}

impl EffectiveSubsetGate {
    pub fn new(capabilities: EffectiveCapabilities) -> Self {
        Self { capabilities }
    }
}

impl SpawnerSubsetGate for EffectiveSubsetGate {
    fn check(&self, parent: &[Capability], child: &[Capability]) -> Result<(), SpawnError> {
        if self.capabilities.is_empty_extension() {
            return CapGrantSubsetAdapter::new().check(parent, child);
        }
        if child.len() > cap_grant::capability_subset::MAX_CAPABILITIES_PER_CALL {
            return Err(SpawnError::SubsetViolation(format!(
                "child capability slice length {} exceeds MAX_CAPABILITIES_PER_CALL={} (fail-closed)",
                child.len(),
                cap_grant::capability_subset::MAX_CAPABILITIES_PER_CALL,
            )));
        }
        for child_cap in child {
            let id = child_cap.id.as_str();
            if !self.capabilities.is_extension(id) {
                continue;
            }
            if !is_whole_capability(&child_cap.params) {
                return Err(SpawnError::SubsetViolation(format!(
                    "extension capability {id} is whole-capability only"
                )));
            }
            let mut matching_parents = parent.iter().filter(|p| p.id.as_str() == id);
            let parent_cap = match matching_parents.next() {
                Some(p) => p,
                None => {
                    return Err(SpawnError::SubsetViolation(format!(
                        "child requests capability {id:?} but parent \
                         grant set does not include it (fail-closed)"
                    )));
                }
            };
            if matching_parents.next().is_some() {
                return Err(SpawnError::SubsetViolation(format!(
                    "parent grant set contains duplicate capability id \
                     {id:?} — ambiguous which one to subset against; \
                     fail-closed (operator should ensure parent capabilities \
                     have unique ids)"
                )));
            }
            if !is_whole_capability(&parent_cap.params) {
                return Err(SpawnError::SubsetViolation(format!(
                    "extension capability {id} is whole-capability only"
                )));
            }
        }
        let parent_rest: Vec<Capability> = parent
            .iter()
            .filter(|c| !self.capabilities.is_extension(c.id.as_str()))
            .cloned()
            .collect();
        let child_rest: Vec<Capability> = child
            .iter()
            .filter(|c| !self.capabilities.is_extension(c.id.as_str()))
            .cloned()
            .collect();
        CapGrantSubsetAdapter::new().check(&parent_rest, &child_rest)
    }
}

fn is_whole_capability(params: &advance_shared_types::capability::CapParams) -> bool {
    match params.as_value() {
        serde_json::Value::Null => true,
        serde_json::Value::Object(map) if map.is_empty() => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
    use advance_shared_types::capability::{CapParams, CapabilityId};
    use cap_lifecycle::AgentTreeStore;
    use serde_json::json;

    fn cap(id: &str, params: serde_json::Value) -> Capability {
        Capability {
            id: CapabilityId::from(id),
            params: CapParams::new(params),
        }
    }

    fn whole(id: &str) -> Capability {
        cap(id, serde_json::Value::Null)
    }

    fn whole_owned(id: String) -> Capability {
        Capability {
            id: CapabilityId::new(id),
            params: CapParams::empty(),
        }
    }

    fn txt(r: Result<(), SpawnError>) -> Result<(), String> {
        r.map_err(|e| e.to_string())
    }

    #[test]
    fn module_001_ac31_extension_capability_bound_fits_agent_node() {
        assert_eq!(
            MAX_EXTENSION_CAPABILITIES,
            AGENT_NODE_CAPABILITY_BOUND - KNOWN_CAPABILITIES.len()
        );
        let tmp = tempfile::tempdir().unwrap();
        let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
        let root_ws = tree.workspace_root().join("root");
        std::fs::create_dir_all(&root_ws).unwrap();
        let mut caps: Vec<Capability> = KNOWN_CAPABILITIES.iter().copied().map(whole).collect();
        for i in 0..MAX_EXTENSION_CAPABILITIES {
            caps.push(whole_owned(format!("e{i:02}")));
        }
        assert_eq!(caps.len(), AGENT_NODE_CAPABILITY_BOUND);
        tree.insert_root_with_handle(
            AgentNode {
                id: AgentId("root".into()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: root_ws.clone(),
                capabilities: caps,
                template_ref: None,
                status: AgentStatus::Active,
            },
            Some("root".into()),
        )
        .unwrap();

        let tmp65 = tempfile::tempdir().unwrap();
        let tree65 = AgentTreeStore::new(tmp65.path().to_path_buf()).unwrap();
        let root65 = tree65.workspace_root().join("root");
        std::fs::create_dir_all(&root65).unwrap();
        let caps65: Vec<Capability> = (0..=AGENT_NODE_CAPABILITY_BOUND)
            .map(|i| whole_owned(format!("n{i:02}")))
            .collect();
        assert_eq!(caps65.len(), 65);
        let err = tree65
            .insert_root_with_handle(
                AgentNode {
                    id: AgentId("root".into()),
                    kind: AgentKind::Root,
                    parent: None,
                    workspace_path: root65,
                    capabilities: caps65,
                    template_ref: None,
                    status: AgentStatus::Active,
                },
                Some("root".into()),
            )
            .unwrap_err();
        assert!(matches!(err, SpawnError::InvalidConfig(_)), "{err:?}");
    }

    #[test]
    fn module_001_ac31_effective_subset_gate_delegates_and_gates_extensions() {
        let adapter = CapGrantSubsetAdapter::new();
        let empty = EffectiveSubsetGate::new(EffectiveCapabilities::default());
        let fs_parent = [cap("fs", json!({"read-paths": "/tmp"}))];
        let fs_child = [cap("fs", json!({"read-paths": "/tmp"}))];
        let memory = [whole("memory")];
        let missing_child = [whole("llm")];
        let duplicate_parent = [whole("fs"), whole("fs")];
        let oversize: Vec<Capability> = (0..257).map(|_| whole("fs")).collect();

        let corpus: &[(&[Capability], &[Capability])] = &[
            (&fs_parent, &fs_child),
            (&memory, &memory),
            (&fs_parent, &missing_child),
            (&duplicate_parent, &fs_child),
            (&fs_parent, &oversize),
        ];
        for (parent, child) in corpus {
            assert_eq!(
                txt(empty.check(parent, child)),
                txt(adapter.check(parent, child)),
                "empty-set identity {parent:?} / {child:?}"
            );
        }

        let set = EffectiveCapabilities::from_extension_entries(&[("fixture", &["fixture.probe"])]);
        let gate = EffectiveSubsetGate::new(set.clone());
        let probe = whole("fixture.probe");
        let probe_params = cap("fixture.probe", json!({"x": 1}));
        assert!(gate.check(&[probe.clone()], &[probe.clone()]).is_ok());
        let with_params = txt(gate.check(&[probe.clone()], &[probe_params.clone()]));
        assert!(
            with_params
                .as_ref()
                .unwrap_err()
                .contains("extension capability fixture.probe is whole-capability only"),
            "{with_params:?}"
        );
        let missing = txt(gate.check(&[whole("fs")], &[probe.clone()]));
        assert!(
            missing.as_ref().unwrap_err().contains(
                "child requests capability \"fixture.probe\" but parent grant set does not include it (fail-closed)"
            ),
            "{missing:?}"
        );
        let dup = txt(gate.check(&[probe.clone(), probe.clone()], &[probe.clone()]));
        assert!(
            dup.as_ref()
                .unwrap_err()
                .contains("parent grant set contains duplicate capability id \"fixture.probe\""),
            "{dup:?}"
        );
        let parent_params = txt(gate.check(&[probe_params.clone()], &[probe.clone()]));
        assert!(
            parent_params
                .as_ref()
                .unwrap_err()
                .contains("extension capability fixture.probe is whole-capability only"),
            "{parent_params:?}"
        );

        let mixed_parent = [whole("fs")];
        let mixed_child = [probe.clone(), whole("llm")];
        let mixed = txt(gate.check(&mixed_parent, &mixed_child));
        assert!(
            mixed.as_ref().unwrap_err().contains(
                "child requests capability \"fixture.probe\" but parent grant set does not include it (fail-closed)"
            ),
            "{mixed:?}"
        );

        let oss_parent = [cap("fs", json!({"read-paths": "/tmp"}))];
        let oss_child = [cap("fs", json!({"read-paths": "/nope"}))];
        let with_ext_parent = [cap("fs", json!({"read-paths": "/tmp"})), probe.clone()];
        assert_eq!(
            txt(gate.check(&with_ext_parent, &oss_child)),
            txt(adapter.check(&oss_parent, &oss_child)),
        );

        let entries = EffectiveCapabilities::from_extension_entries(&[
            ("fixture", &["fixture.probe", "fixture.echo"]),
            ("other", &["other.x"]),
        ]);
        assert_eq!(
            entries.extension_names().collect::<Vec<_>>(),
            vec!["fixture.probe", "fixture.echo", "other.x"]
        );
        assert_eq!(entries.owner_of("fixture.probe"), Some("fixture"));
        assert_eq!(entries.owner_of("other.x"), Some("other"));
        assert_eq!(entries.owner_of("fs"), None);
        assert_eq!(
            entries.declared_by("fixture").collect::<Vec<_>>(),
            vec!["fixture.probe", "fixture.echo"]
        );
        assert!(entries.contains("fs"));
        assert!(entries.contains("fixture.probe"));
        assert!(!entries.contains("nope"));
        assert!(!entries.is_extension("fs"));
        assert!(entries.is_extension("fixture.probe"));
        assert_eq!(
            entries.names().collect::<Vec<_>>(),
            KNOWN_CAPABILITIES
                .iter()
                .copied()
                .chain(["fixture.probe", "fixture.echo", "other.x"])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            EffectiveCapabilities::known_only(),
            EffectiveCapabilities::default()
        );
        assert!(EffectiveCapabilities::default().is_empty_extension());
        assert!(!entries.is_empty_extension());
    }
}
