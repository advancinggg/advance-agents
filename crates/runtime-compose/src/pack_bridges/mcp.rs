//! MCP bridge (§3.1 row 3, §3.2 rule 2): an installed pack's
//! `mcp-servers/{name}.yaml` (schema: `advance_pack_manager::mcp_server_manifest`),
//! checked against the pack and turned into what the runtime keeps of it. Both paths
//! below make the same checks:
//!
//! - `stdio` transport from a pack whose EFFECTIVE trust is `untrusted` →
//!   [`PackBridgeError::TrustDenied`] (a subprocess is arbitrary code execution);
//! - `http` transport is admitted from any pack, and the cap-http security chain
//!   (SSRF / redirect / TLS policy) governs every request; an endpoint on loopback is
//!   refused ([`PackError::ConstraintViolation`]): only a server file the operator
//!   wrote may reach the host's own loopback;
//! - a manifest that binds `credentials` is refused from any pack
//!   ([`PackError::ConstraintViolation`]): pack-origin http servers may not bind
//!   cap-secrets credentials, only a server file the operator wrote may;
//! - a workflow step's own secrets (`ENV_NAME → secret key`) go to a stdio server
//!   only, each under an environment-variable name the manifest does not already
//!   give a literal or a secret.
//!
//! [`PackMcpBridge::plan`] is the path of a workflow's `register-mcp-server` step,
//! and it resolves no secret: the registration carries the manifest's transport
//! unchanged (a stdio server's `env` literals and `cwd` included), the manifest's
//! and the step's `secret-refs` as secret-store keys (never values) and the origin
//! pack. [`McpEntrySink`] is where the step hands it: the control-plane sink writes
//! it as a server file and the MCP client reloads, and the loader resolves the
//! secrets when it reads the file, as for an operator's file.
//!
//! [`PackMcpBridge::entry`] / [`PackMcpBridge::entry_with_env`] build a client entry
//! (`cap_mcp::McpServerEntry`, for `McpServersConfig::builder().add_server`) instead,
//! resolving the manifest's `secret-refs` through the pack-manager `SecretStore` at
//! once (missing key → `MissingSecret`) and merging a step's pre-resolved secrets:
//! the stdio environment is built as the loader builds an operator server's
//! ([`crate::mcp_wiring::stdio_child_env`]), the manifest's `cwd` is the working
//! directory, and an http entry's allowlist is exactly the endpoint's host. The
//! daemon registers a pack's servers through [`PackMcpBridge::plan`] and the server
//! file only.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use advance_pack_manager::{
    parse_mcp_server_manifest, ComponentKind, McpServerManifest, McpTransportDecl, PackError,
    PackRegistry, SecretStore, SecretValue, TrustLevel as PackTrust,
};
use advance_shared_types::security_validator::{Allowlist, HttpCapability};
use cap_mcp::{McpServerEntry, McpTransportSpec};

use super::{effective_trust, pack_id, resolve_kind, PackBridgeError};
use crate::mcp_wiring::stdio_child_env;

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
    /// stdio child's environment with the manifest's own. A placeholder that is
    /// not an env-var name, or that collides with a manifest `secret-refs` entry
    /// or `env` literal, is refused; on an `http` transport a non-empty
    /// `extra_env` has no destination and is refused too (fail-closed — the
    /// secret is never silently discarded). The child's environment is
    /// [`stdio_child_env`] of the daemon's own, the manifest's `env` literals and
    /// all those secrets; its working directory is the manifest's `cwd`.
    pub fn entry_with_env(
        &self,
        pack_ref: &str,
        secrets: &dyn SecretStore,
        extra_env: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerEntry, PackBridgeError> {
        let resolution = resolve_kind(&*self.registry, pack_ref, ComponentKind::McpServer)?;
        let pack = pack_id(&resolution);
        let manifest = parse_mcp_server_manifest(&resolution.local_path)?;
        refuse_credentials(&manifest, &pack)?;
        let trust = effective_trust(&*self.registry, &resolution.pack_name, &resolution.version)?;

        let transport = match manifest.transport {
            McpTransportDecl::Stdio {
                command,
                args,
                env: literals,
                cwd,
            } => {
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
                let mut resolved: BTreeMap<String, String> = BTreeMap::new();
                for (env_name, key) in &manifest.secret_refs {
                    let value = secrets
                        .get(key)
                        .ok_or_else(|| PackError::MissingSecret { key: key.clone() })?;
                    resolved.insert(env_name.clone(), value.expose_secret().to_string());
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
                    if resolved.contains_key(env_name) {
                        return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                            reason: format!(
                                "register-mcp-server secret-ref {env_name} collides with the \
                                 server manifest's own secret-refs"
                            ),
                        }));
                    }
                    if literals.contains_key(env_name) {
                        return Err(env_literal_collision(env_name));
                    }
                    resolved.insert(env_name.clone(), value.expose_secret().to_string());
                }
                McpTransportSpec::Stdio {
                    command,
                    args,
                    env: stdio_child_env(std::env::vars_os(), &literals, resolved),
                    cwd: cwd.map(PathBuf::from),
                }
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
                if cap_http::LoopbackExemptions::is_loopback_endpoint(&endpoint_url) {
                    return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                        reason: format!(
                            "mcp-server {} of pack {pack} points at a loopback endpoint; a \
                             pack's server may not reach the host's loopback (only an \
                             operator's own server file may)",
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

    /// The registration a control-plane sink would persist: the pack's
    /// manifest (its transport unchanged, a stdio server's `env` literals and
    /// `cwd` included), extra secret-ref *ids* (never values), and the origin
    /// pack. Same trust, loopback, credentials and placeholder checks as
    /// [`Self::entry_with_env`].
    pub fn plan(
        &self,
        pack_ref: &str,
        extra_secret_refs: &BTreeMap<String, String>,
    ) -> Result<McpRegistration, PackBridgeError> {
        let resolution = resolve_kind(&*self.registry, pack_ref, ComponentKind::McpServer)?;
        let pack = pack_id(&resolution);
        let manifest = parse_mcp_server_manifest(&resolution.local_path)?;
        refuse_credentials(&manifest, &pack)?;
        let trust = effective_trust(&*self.registry, &resolution.pack_name, &resolution.version)?;

        match &manifest.transport {
            McpTransportDecl::Stdio { .. } => {
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
            }
            McpTransportDecl::Http { endpoint_url } => {
                if !extra_secret_refs.is_empty() {
                    return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                        reason: format!(
                            "register-mcp-server secret-refs have no destination on the http \
                             transport of {} (http credentials belong to the cap-http \
                             credential chain)",
                            manifest.server_id
                        ),
                    }));
                }
                if cap_http::LoopbackExemptions::is_loopback_endpoint(endpoint_url) {
                    return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                        reason: format!(
                            "mcp-server {} of pack {pack} points at a loopback endpoint; a \
                             pack's server may not reach the host's loopback (only an \
                             operator's own server file may)",
                            manifest.server_id
                        ),
                    }));
                }
            }
        }

        let mut secret_refs = manifest.secret_refs.clone();
        for (env_name, key) in extra_secret_refs {
            if !is_env_var_name(env_name) {
                return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                    reason: format!(
                        "register-mcp-server secret-ref placeholder {env_name:?} is not \
                         an environment-variable name ([A-Za-z_][A-Za-z0-9_]*)"
                    ),
                }));
            }
            if secret_refs.contains_key(env_name) {
                return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                    reason: format!(
                        "register-mcp-server secret-ref {env_name} collides with the \
                         server manifest's own secret-refs"
                    ),
                }));
            }
            if matches!(
                &manifest.transport,
                McpTransportDecl::Stdio { env, .. } if env.contains_key(env_name)
            ) {
                return Err(env_literal_collision(env_name));
            }
            secret_refs.insert(env_name.clone(), key.clone());
        }

        Ok(McpRegistration {
            server_id: manifest.server_id,
            description: manifest.description,
            transport: manifest.transport,
            secret_refs,
            origin_pack: pack,
            origin_ref: pack_ref.to_string(),
        })
    }
}

/// A pack server ready to persist as an operator server file (ids only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRegistration {
    pub server_id: String,
    pub description: String,
    pub transport: McpTransportDecl,
    pub secret_refs: BTreeMap<String, String>,
    pub origin_pack: String,
    pub origin_ref: String,
}

/// Outcome of [`McpEntrySink::register`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpRegister {
    /// A new file was written.
    Created(String),
    /// The same origin already had this exact server; nothing was written.
    Unchanged(String),
}

impl McpRegister {
    /// The server id, whether created or already present.
    pub fn server_id(&self) -> &str {
        match self {
            Self::Created(id) | Self::Unchanged(id) => id,
        }
    }

    pub fn created(&self) -> bool {
        matches!(self, Self::Created(_))
    }
}

/// Where a workflow's `register-mcp-server` step delivers its planned server.
pub trait McpEntrySink: Send + Sync {
    /// Persist `registration`. Idempotent: the same origin and the same
    /// content succeed without writing. A different origin or different
    /// content for the same server id is refused.
    fn register(&self, registration: McpRegistration) -> Result<McpRegister, PackBridgeError>;

    /// Remove the persisted file of `server_id` when it is a pack-origin file
    /// this sink created. An operator file (no origin) is left alone and
    /// reported as an error.
    fn deregister(&self, server_id: &str) -> Result<(), PackBridgeError>;
}

/// Refuse a pack's server manifest that binds `credentials`: only a server file the
/// operator wrote may bind cap-secrets credentials to an http server's requests.
fn refuse_credentials(manifest: &McpServerManifest, pack: &str) -> Result<(), PackBridgeError> {
    if manifest.credentials.is_empty() {
        return Ok(());
    }
    Err(PackBridgeError::Pack(PackError::ConstraintViolation {
        reason: format!(
            "mcp-server {} of pack {pack} binds credentials; pack-origin http servers may not \
             bind cap-secrets credentials (only an operator's own server file may)",
            manifest.server_id
        ),
    }))
}

/// The refusal of a workflow step's secret-ref named as one of the manifest's `env` literals: a
/// variable of the server's environment is either a literal or a secret.
fn env_literal_collision(env_name: &str) -> PackBridgeError {
    PackBridgeError::Pack(PackError::ConstraintViolation {
        reason: format!(
            "register-mcp-server secret-ref {env_name} collides with the server manifest's env \
             literal of the same name"
        ),
    })
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
}
