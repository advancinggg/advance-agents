//! MCP bridge (§3.1 row 3, §3.2 rule 2): an installed pack's
//! `mcp-servers/{name}.yaml` (schema: `advance_pack_manager::mcp_server_manifest`)
//! → a `cap_mcp::McpServerEntry` ready for `McpServersConfig::builder().add_server`.
//!
//! - `stdio` transport from a pack whose EFFECTIVE trust is `untrusted` →
//!   [`PackBridgeError::TrustDenied`] (a subprocess is arbitrary code execution);
//! - `http` transport is admitted from any pack: the entry carries an
//!   `HttpCapability` whose allowlist is exactly the endpoint's host, so the
//!   cap-http security chain (SSRF / redirect / TLS policy) governs every request;
//! - the manifest's `secret-refs` (`ENV_NAME → secret key`) are resolved through
//!   the pack-manager `SecretStore` into the stdio child's `env` (missing key →
//!   `MissingSecret`); a workflow step's pre-resolved secrets can be merged in
//!   through [`PackMcpBridge::entry_with_env`] under the same env-name grammar.
//!
//! [`McpEntrySink`] is where a `WorkflowExecutor::register_mcp_server` hands
//! the built entry: the daemon has no live MCP-client whitelist to hot-swap yet,
//! so the composition root retains entries in an [`InMemoryMcpEntrySink`]
//! (duplicate `server_id` refused, mirroring the whitelist builder) for the MCP
//! client wiring to consume — nothing is silently dropped and no fake id is
//! minted for an entry that went nowhere.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use advance_pack_manager::{
    parse_mcp_server_manifest, ComponentKind, McpTransportDecl, PackError, PackRegistry,
    SecretStore, SecretValue, TrustLevel as PackTrust,
};
use advance_shared_types::security_validator::{Allowlist, HttpCapability};
use cap_mcp::{McpError, McpServerEntry, McpServersConfig, McpTransportSpec};

use super::{effective_trust, pack_id, resolve_kind, PackBridgeError};

pub struct PackMcpBridge {
    registry: Arc<dyn PackRegistry>,
}

impl PackMcpBridge {
    pub fn new(registry: Arc<dyn PackRegistry>) -> Self {
        Self { registry }
    }

    /// Build the whitelist entry for `{pack}@{ver}/mcp-servers/{name}`.
    pub fn entry(
        &self,
        pack_ref: &str,
        secrets: &dyn SecretStore,
    ) -> Result<McpServerEntry, PackBridgeError> {
        self.entry_with_env(pack_ref, secrets, &BTreeMap::new())
    }

    /// [`Self::entry`] plus `extra_env` — a workflow step's already-resolved
    /// `secret-refs` (placeholder = environment-variable name) merged into the
    /// stdio child's environment. A placeholder that is not an env-var name, or
    /// that collides with a manifest `secret-refs` entry, is refused; on an
    /// `http` transport a non-empty `extra_env` has no destination and is
    /// refused too (fail-closed — the secret is never silently discarded).
    pub fn entry_with_env(
        &self,
        pack_ref: &str,
        secrets: &dyn SecretStore,
        extra_env: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerEntry, PackBridgeError> {
        let resolution = resolve_kind(&*self.registry, pack_ref, ComponentKind::McpServer)?;
        let pack = pack_id(&resolution);
        let manifest = parse_mcp_server_manifest(&resolution.local_path)?;
        let trust = effective_trust(&*self.registry, &resolution.pack_name, &resolution.version)?;

        let transport = match manifest.transport {
            McpTransportDecl::Stdio { command, args } => {
                if trust != PackTrust::Trusted {
                    return Err(PackBridgeError::TrustDenied {
                        pack,
                        reason: format!(
                            "mcp-server {} declares a stdio transport (a subprocess runs \
                             arbitrary code); only an admin-approved trusted pack may register \
                             one — effective trust is untrusted",
                            manifest.server_id
                        ),
                    });
                }
                let mut env: BTreeMap<String, String> = BTreeMap::new();
                for (env_name, key) in &manifest.secret_refs {
                    let value = secrets
                        .get(key)
                        .ok_or_else(|| PackError::MissingSecret { key: key.clone() })?;
                    env.insert(env_name.clone(), value.expose_secret().to_string());
                }
                for (env_name, value) in extra_env {
                    if !is_env_var_name(env_name) {
                        return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                            reason: format!(
                                "register-mcp-server secret-ref placeholder {env_name:?} is not \
                                 an environment-variable name ([A-Za-z_][A-Za-z0-9_]*)"
                            ),
                        }));
                    }
                    if env.contains_key(env_name) {
                        return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                            reason: format!(
                                "register-mcp-server secret-ref {env_name} collides with the \
                                 server manifest's own secret-refs"
                            ),
                        }));
                    }
                    env.insert(env_name.clone(), value.expose_secret().to_string());
                }
                McpTransportSpec::Stdio { command, args, env }
            }
            McpTransportDecl::Http { endpoint_url } => {
                if !extra_env.is_empty() {
                    return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                        reason: format!(
                            "register-mcp-server secret-refs have no destination on the http \
                             transport of {} (http credentials belong to the cap-http \
                             credential chain)",
                            manifest.server_id
                        ),
                    }));
                }
                let host = endpoint_host(&endpoint_url).to_string();
                McpTransportSpec::Http {
                    endpoint_url,
                    capability: HttpCapability {
                        allowlist: Allowlist {
                            patterns: vec![host],
                        },
                        credentials: Vec::new(),
                        component_id: manifest.server_id.clone(),
                    },
                }
            }
        };

        Ok(McpServerEntry {
            server_id: manifest.server_id,
            description: manifest.description,
            transport,
            tool_patterns: None,
            tool_schemas: BTreeMap::new(),
        })
    }
}

/// Where a workflow's `register-mcp-server` step delivers its built entry.
pub trait McpEntrySink: Send + Sync {
    /// Retain / publish `entry`. A duplicate `server_id` must be refused.
    fn register(&self, entry: McpServerEntry) -> Result<(), PackBridgeError>;
}

/// Retains registered entries (duplicate `server_id` refused) until an MCP
/// client consumer drains them into a `McpServersConfig`.
#[derive(Default)]
pub struct InMemoryMcpEntrySink {
    entries: Mutex<Vec<McpServerEntry>>,
}

impl InMemoryMcpEntrySink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registered server ids, in registration order.
    pub fn server_ids(&self) -> Vec<String> {
        self.entries
            .lock()
            .expect("mcp entry sink poisoned")
            .iter()
            .map(|e| e.server_id.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("mcp entry sink poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Move every retained entry out (the sink is empty afterwards).
    pub fn take_all(&self) -> Vec<McpServerEntry> {
        std::mem::take(&mut *self.entries.lock().expect("mcp entry sink poisoned"))
    }

    /// Drain the retained entries into a whitelist config (the consumer then
    /// hot-swaps it into its MCP client). Fails on a builder refusal (cap,
    /// pattern) — the drained entries are NOT restored, so callers treat an
    /// error as terminal for those entries.
    pub fn drain_into_config(&self) -> Result<McpServersConfig, McpError> {
        let mut builder = McpServersConfig::builder();
        for entry in self.take_all() {
            builder = builder.add_server(entry)?;
        }
        Ok(builder.build())
    }
}

impl McpEntrySink for InMemoryMcpEntrySink {
    fn register(&self, entry: McpServerEntry) -> Result<(), PackBridgeError> {
        let mut entries = self.entries.lock().expect("mcp entry sink poisoned");
        if entries.iter().any(|e| e.server_id == entry.server_id) {
            return Err(PackBridgeError::Mcp(McpError::invalid_response(format!(
                "duplicate server_id '{}'",
                entry.server_id
            ))));
        }
        entries.push(entry);
        Ok(())
    }
}

fn is_env_var_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    s.len() <= 256 && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Host of an already-validated `scheme://authority/…` URL (port stripped; an
/// IPv6 literal keeps its brackets off).
fn endpoint_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("");
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_host_strips_scheme_port_and_path() {
        assert_eq!(
            endpoint_host("https://mcp.example.com/sse"),
            "mcp.example.com"
        );
        assert_eq!(endpoint_host("http://127.0.0.1:8080/x"), "127.0.0.1");
        assert_eq!(endpoint_host("http://[::1]:9/x"), "::1");
    }

    #[test]
    fn sink_refuses_duplicate_server_ids() {
        let sink = InMemoryMcpEntrySink::new();
        let mk = |id: &str| McpServerEntry {
            server_id: id.into(),
            description: String::new(),
            transport: McpTransportSpec::Stdio {
                command: "true".into(),
                args: vec![],
                env: BTreeMap::new(),
            },
            tool_patterns: None,
            tool_schemas: BTreeMap::new(),
        };
        sink.register(mk("a")).unwrap();
        assert!(matches!(
            sink.register(mk("a")),
            Err(PackBridgeError::Mcp(_))
        ));
        assert_eq!(sink.server_ids(), vec!["a".to_string()]);
        let cfg = sink.drain_into_config().unwrap();
        assert!(cfg.get("a").is_ok());
        assert!(sink.is_empty());
    }
}
