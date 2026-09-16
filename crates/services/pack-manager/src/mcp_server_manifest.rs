//! Pack lane P2 — the schema of a pack's
//! `mcp-servers/{name}.yaml` and its bounded, fail-closed parser.
//!
//! Before P2 the file had NO schema: `DefaultMaterializer::register_mcp_server`
//! only probed that it existed and resolved the caller's `secret-refs`. This
//! module defines the document and is the single parser used by BOTH the
//! materializer (validation at materialize time) and the cli `PackMcpBridge`
//! (which turns the manifest into a `cap_mcp::McpServerEntry`).
//!
//! ```yaml
//! server-id: local-tools            # [A-Za-z0-9._-]{1,128}; the whitelist key
//! description: optional free text   # ≤ 1 KiB, no control bytes
//! transport:
//!   kind: stdio                     # subprocess — arbitrary code execution
//!   command: /usr/bin/true
//!   args: []
//! # or
//! transport:
//!   kind: http                      # https://… (any host) or http://<loopback>
//!   endpoint-url: https://mcp.example.com/sse
//! secret-refs:                      # stdio only: ENV_NAME → secret-store key
//!   API_TOKEN: mcp-token
//! ```
//!
//! Rules (all fail-closed):
//! - unknown keys anywhere → `InvalidManifest` (`deny_unknown_fields`);
//! - `secret-refs` keys must be environment-variable names
//!   (`[A-Za-z_][A-Za-z0-9_]*`), values non-empty secret-store keys;
//! - `secret-refs` on an `http` transport → `ConstraintViolation` — the only
//!   injection point the bridge implements is the stdio child's `env`; http
//!   credentials belong to cap-http's `CredentialBinding` chain, never to a
//!   pack YAML;
//! - `http` endpoints must be `https://`, or `http://` on a loopback host;
//!   userinfo (`user@host`) is refused (credential smuggling / redaction hazard);
//! - the file is read through `O_NOFOLLOW` + fstat, capped at
//!   [`MAX_MCP_SERVER_YAML_BYTES`], alias-guarded and nesting-bounded like every
//!   other pack-shipped YAML this crate parses.
//!
//! Trust (§3.2 rule 2) is NOT decided here — the manifest carries no trust; the
//! bridge refuses `stdio` from a pack whose `.meta.yaml` trust is `untrusted`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::component_manifest::yaml_nesting_within_bound;
use crate::error::PackError;
use crate::manifest::yaml_has_alias_refs;
use crate::materialize_impl::read_bytes_nofollow_bounded;

/// Size cap on `mcp-servers/{name}.yaml` (the document is a handful of lines).
pub const MAX_MCP_SERVER_YAML_BYTES: u64 = 64 * 1024;
const MAX_SERVER_ID_LEN: usize = 128;
const MAX_DESCRIPTION_LEN: usize = 1024;
const MAX_COMMAND_LEN: usize = 4096;
const MAX_ARGS: usize = 64;
const MAX_ARG_LEN: usize = 4096;
const MAX_SECRET_REFS: usize = 32;
const MAX_SECRET_REF_LEN: usize = 256;
const MAX_ENDPOINT_URL_LEN: usize = 2048;

/// Parsed + validated `mcp-servers/{name}.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerManifest {
    /// The whitelist key (`McpServerEntry::server_id`).
    pub server_id: String,
    /// Free text (empty when absent).
    pub description: String,
    pub transport: McpTransportDecl,
    /// `ENV_NAME → secret-store key`; empty unless `transport` is `stdio`.
    pub secret_refs: BTreeMap<String, String>,
}

/// The declared transport. Mirrors `cap_mcp::McpTransportSpec` minus the
/// resolved runtime material (env / http capability), which the bridge adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTransportDecl {
    Stdio { command: String, args: Vec<String> },
    Http { endpoint_url: String },
}

impl McpTransportDecl {
    pub fn is_stdio(&self) -> bool {
        matches!(self, McpTransportDecl::Stdio { .. })
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            McpTransportDecl::Stdio { .. } => "stdio",
            McpTransportDecl::Http { .. } => "http",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(rename = "server-id")]
    server_id: String,
    #[serde(default)]
    description: Option<String>,
    transport: RawTransport,
    #[serde(default, rename = "secret-refs")]
    secret_refs: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RawTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
    Http {
        #[serde(rename = "endpoint-url")]
        endpoint_url: String,
    },
}

/// Read + parse + validate `path` (see the module docs for the rules).
pub fn parse_mcp_server_manifest(path: &Path) -> Result<McpServerManifest, PackError> {
    let bytes = read_bytes_nofollow_bounded(path, MAX_MCP_SERVER_YAML_BYTES, "mcp-server config")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        PackError::InvalidManifest(format!(
            "mcp-server config is not valid UTF-8: {}",
            path.display()
        ))
    })?;
    parse_mcp_server_manifest_str(text).map_err(|e| match e {
        PackError::InvalidManifest(msg) => {
            PackError::InvalidManifest(format!("mcp-server config {}: {msg}", path.display()))
        }
        PackError::ConstraintViolation { reason } => PackError::ConstraintViolation {
            reason: format!("mcp-server config {}: {reason}", path.display()),
        },
        other => other,
    })
}

/// Parse + validate an in-memory document (the file-level guards — symlink,
/// size, UTF-8 — are [`parse_mcp_server_manifest`]'s).
pub fn parse_mcp_server_manifest_str(yaml: &str) -> Result<McpServerManifest, PackError> {
    if yaml_has_alias_refs(yaml) {
        return Err(PackError::InvalidManifest(
            "contains alias references (`*name`) — rejected to prevent billion-laughs \
             amplification"
                .into(),
        ));
    }
    if !yaml_nesting_within_bound(yaml) {
        return Err(PackError::InvalidManifest(
            "nesting/indentation is too deep — rejected to prevent parse-time resource \
             exhaustion"
                .into(),
        ));
    }
    let raw: RawManifest = serde_yml::from_str(yaml)
        .map_err(|e| PackError::InvalidManifest(format!("yaml parse: {e}")))?;

    validate_server_id(&raw.server_id)?;
    let description = raw.description.unwrap_or_default();
    if description.len() > MAX_DESCRIPTION_LEN {
        return Err(PackError::InvalidManifest(format!(
            "description exceeds {MAX_DESCRIPTION_LEN} bytes"
        )));
    }
    if description.chars().any(char::is_control) {
        return Err(PackError::InvalidManifest(
            "description contains control characters".into(),
        ));
    }

    let transport = match raw.transport {
        RawTransport::Stdio { command, args } => {
            validate_text("transport.command", &command, MAX_COMMAND_LEN)?;
            if args.len() > MAX_ARGS {
                return Err(PackError::InvalidManifest(format!(
                    "transport.args has {} entries (max {MAX_ARGS})",
                    args.len()
                )));
            }
            for (i, a) in args.iter().enumerate() {
                if a.len() > MAX_ARG_LEN {
                    return Err(PackError::InvalidManifest(format!(
                        "transport.args[{i}] exceeds {MAX_ARG_LEN} bytes"
                    )));
                }
                if a.contains('\0') {
                    return Err(PackError::InvalidManifest(format!(
                        "transport.args[{i}] contains a null byte"
                    )));
                }
            }
            McpTransportDecl::Stdio { command, args }
        }
        RawTransport::Http { endpoint_url } => {
            validate_endpoint_url(&endpoint_url)?;
            McpTransportDecl::Http { endpoint_url }
        }
    };

    if raw.secret_refs.len() > MAX_SECRET_REFS {
        return Err(PackError::InvalidManifest(format!(
            "secret-refs has {} entries (max {MAX_SECRET_REFS})",
            raw.secret_refs.len()
        )));
    }
    for (env_name, key) in &raw.secret_refs {
        if !is_env_var_name(env_name) {
            return Err(PackError::InvalidManifest(format!(
                "secret-refs key {env_name:?} is not an environment-variable name \
                 ([A-Za-z_][A-Za-z0-9_]*, ≤ {MAX_SECRET_REF_LEN} bytes)"
            )));
        }
        if key.is_empty() || key.len() > MAX_SECRET_REF_LEN || key.chars().any(char::is_control) {
            return Err(PackError::InvalidManifest(format!(
                "secret-refs value for {env_name} must be a non-empty secret key \
                 (≤ {MAX_SECRET_REF_LEN} bytes, no control characters)"
            )));
        }
    }
    if !raw.secret_refs.is_empty() && !transport.is_stdio() {
        return Err(PackError::ConstraintViolation {
            reason: format!(
                "secret-refs require a stdio transport (they are injected into the child \
                 process environment); {} transport credentials belong to the cap-http \
                 credential chain",
                transport.kind_str()
            ),
        });
    }

    Ok(McpServerManifest {
        server_id: raw.server_id,
        description,
        transport,
        secret_refs: raw.secret_refs,
    })
}

fn validate_server_id(id: &str) -> Result<(), PackError> {
    if id.is_empty() || id.len() > MAX_SERVER_ID_LEN {
        return Err(PackError::InvalidManifest(format!(
            "server-id must be 1..={MAX_SERVER_ID_LEN} bytes"
        )));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(PackError::InvalidManifest(format!(
            "server-id {id:?} must match [A-Za-z0-9._-]+"
        )));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max: usize) -> Result<(), PackError> {
    if value.is_empty() {
        return Err(PackError::InvalidManifest(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > max {
        return Err(PackError::InvalidManifest(format!(
            "{field} exceeds {max} bytes"
        )));
    }
    if value.contains('\0') {
        return Err(PackError::InvalidManifest(format!(
            "{field} contains a null byte"
        )));
    }
    Ok(())
}

fn is_env_var_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    s.len() <= MAX_SECRET_REF_LEN && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `https://<host>…` for any host; `http://<host>…` only when `<host>` is a
/// loopback literal. No userinfo, no whitespace / control bytes.
fn validate_endpoint_url(url: &str) -> Result<(), PackError> {
    if url.len() > MAX_ENDPOINT_URL_LEN {
        return Err(PackError::InvalidManifest(format!(
            "transport.endpoint-url exceeds {MAX_ENDPOINT_URL_LEN} bytes"
        )));
    }
    if url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || !c.is_ascii())
    {
        return Err(PackError::InvalidManifest(
            "transport.endpoint-url contains whitespace, control or non-ASCII characters".into(),
        ));
    }
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        PackError::InvalidManifest("transport.endpoint-url must be https:// or http://".into())
    })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(PackError::InvalidManifest(
            "transport.endpoint-url has no host".into(),
        ));
    }
    if authority.contains('@') {
        return Err(PackError::InvalidManifest(
            "transport.endpoint-url must not carry userinfo (`user@host`)".into(),
        ));
    }
    let host = endpoint_host(authority);
    match scheme {
        "https" => Ok(()),
        "http" if is_loopback_host(host) => Ok(()),
        "http" => Err(PackError::InvalidManifest(format!(
            "transport.endpoint-url: plain http:// is only allowed for loopback hosts \
             (got {host:?})"
        ))),
        other => Err(PackError::InvalidManifest(format!(
            "transport.endpoint-url scheme {other:?} not allowed (https:// or http://loopback)"
        ))),
    }
}

/// Strip the port from an authority (`host:port` / `[v6]:port`) → host.
pub(crate) fn endpoint_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: everything up to the closing bracket.
        return rest.split(']').next().unwrap_or("");
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower == "::1" {
        return true;
    }
    match lower.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STDIO: &str = "server-id: local-tools\ndescription: stdio server\ntransport:\n  kind: stdio\n  command: /usr/bin/true\n  args: []\nsecret-refs:\n  API_TOKEN: mcp-token\n";
    const HTTP: &str = "server-id: remote-tools\ndescription: http server\ntransport:\n  kind: http\n  endpoint-url: https://mcp.example.com/sse\n";

    #[test]
    fn parses_stdio_and_http_fixtures() {
        let m = parse_mcp_server_manifest_str(STDIO).unwrap();
        assert_eq!(m.server_id, "local-tools");
        assert!(m.transport.is_stdio());
        assert_eq!(m.secret_refs.get("API_TOKEN").unwrap(), "mcp-token");
        let m = parse_mcp_server_manifest_str(HTTP).unwrap();
        assert_eq!(
            m.transport,
            McpTransportDecl::Http {
                endpoint_url: "https://mcp.example.com/sse".into()
            }
        );
        assert!(m.secret_refs.is_empty());
    }

    #[test]
    fn rejects_unknown_keys_bad_ids_and_alias_bombs() {
        assert!(matches!(
            parse_mcp_server_manifest_str(
                "server-id: x\nextra: 1\ntransport:\n  kind: http\n  endpoint-url: https://h/\n"
            ),
            Err(PackError::InvalidManifest(_))
        ));
        assert!(matches!(
            parse_mcp_server_manifest_str(
                "server-id: \"bad id\"\ntransport:\n  kind: http\n  endpoint-url: https://h/\n"
            ),
            Err(PackError::InvalidManifest(_))
        ));
        assert!(matches!(
            parse_mcp_server_manifest_str(
                "a: &x [1]\nserver-id: *x\ntransport:\n  kind: http\n  endpoint-url: https://h/\n"
            ),
            Err(PackError::InvalidManifest(_))
        ));
        assert!(matches!(
            parse_mcp_server_manifest_str("server-id: x\ntransport:\n  kind: ssh\n  host: h\n"),
            Err(PackError::InvalidManifest(_))
        ));
    }

    #[test]
    fn http_secret_refs_are_a_constraint_violation() {
        let doc = "server-id: x\ntransport:\n  kind: http\n  endpoint-url: https://h/\nsecret-refs:\n  TOKEN: k\n";
        match parse_mcp_server_manifest_str(doc) {
            Err(PackError::ConstraintViolation { reason }) => {
                assert!(reason.contains("stdio"), "{reason}")
            }
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_url_policy() {
        assert!(validate_endpoint_url("https://mcp.example.com/sse").is_ok());
        assert!(validate_endpoint_url("http://127.0.0.1:8080/mcp").is_ok());
        assert!(validate_endpoint_url("http://localhost/mcp").is_ok());
        assert!(validate_endpoint_url("http://[::1]:9/mcp").is_ok());
        assert!(validate_endpoint_url("http://mcp.example.com/sse").is_err());
        assert!(validate_endpoint_url("https://user:pw@mcp.example.com/").is_err());
        assert!(validate_endpoint_url("ftp://h/").is_err());
        assert!(validate_endpoint_url("https:///nohost").is_err());
        assert!(validate_endpoint_url("https://h/ with space").is_err());
    }

    #[test]
    fn secret_ref_keys_must_be_env_names() {
        let doc =
            "server-id: x\ntransport:\n  kind: stdio\n  command: c\nsecret-refs:\n  \"1BAD\": k\n";
        assert!(matches!(
            parse_mcp_server_manifest_str(doc),
            Err(PackError::InvalidManifest(_))
        ));
        let doc =
            "server-id: x\ntransport:\n  kind: stdio\n  command: c\nsecret-refs:\n  GOOD_1: \"\"\n";
        assert!(matches!(
            parse_mcp_server_manifest_str(doc),
            Err(PackError::InvalidManifest(_))
        ));
    }
}
