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
//! server-id: local-tools            # [A-Za-z0-9._-]{1,128}, no leading '.'; the whitelist key
//! description: optional free text   # ≤ 1 KiB, no control bytes
//! transport:
//!   kind: stdio                     # subprocess — arbitrary code execution
//!   command: /usr/bin/true          # an absolute path (a bare name is looked up on a PATH)
//!   args: []
//!   env:                            # non-secret literals: ENV_NAME → value
//!     LOG_LEVEL: info
//!   cwd: /srv/local-tools           # the working directory, an absolute path (default /)
//! # or
//! transport:
//!   kind: http                      # https://… (any host) or http://<loopback>
//!   endpoint-url: https://mcp.example.com/mcp   # the Streamable HTTP endpoint
//! secret-refs:                      # stdio only: ENV_NAME → secret-store key
//!   API_TOKEN: mcp-token
//! credentials:                      # http only, operator files only: secret-store keys
//!   - position: bearer              # Authorization: Bearer <secret>
//!     secret: mcp-token
//!   - position: header              # <key>: <secret>
//!     key: X-Api-Key
//!     secret: mcp-api-key
//! # `position: basic` with `username` sends Authorization: Basic base64(username:secret)
//! # (instead of bearer); `position: query` with `key` adds <key>=<secret> to the URL's query.
//! ```
//!
//! Rules (all fail-closed):
//! - unknown keys anywhere → `InvalidManifest` (`deny_unknown_fields`); `env` and `cwd` are
//!   keys of a `stdio` transport, so an `http` transport carrying either is refused;
//! - `transport.env` holds at most [`MAX_ENV_VARS`] entries; each key is an
//!   environment-variable name (`[A-Za-z_][A-Za-z0-9_]*`, at most 256 bytes), each value at
//!   most 4096 bytes without control characters (it may be empty); a value is a literal, never
//!   a secret: a key that is also a `secret-refs` key → `ConstraintViolation`;
//! - `transport.cwd` is an absolute path of at most 4096 bytes without control characters
//!   (NUL included);
//! - `secret-refs` keys must be environment-variable names
//!   (`[A-Za-z_][A-Za-z0-9_]*`), values non-empty secret-store keys;
//! - `secret-refs` on an `http` transport → `ConstraintViolation` — the only
//!   injection point the bridge implements is the stdio child's `env`; an http
//!   server's secrets are its `credentials`;
//! - `credentials` bind secret-store secrets to positions of the requests an `http`
//!   server is sent, as [`CredentialBinding`]s: the manifest holds secret names, never
//!   values, and the cap-http security chain resolves and injects each one at every
//!   request. Each of these is an `InvalidManifest`:
//!   - more than [`MAX_CREDENTIALS`] entries, or a `position` other than `bearer`,
//!     `basic`, `header` and `query` (there is no `url-path` position);
//!   - a `secret` that is not a non-empty secret-store key of at most 256 bytes without
//!     control characters (the rule of a `secret-refs` value);
//!   - a second `bearer` or `basic` entry: each sets `Authorization`;
//!   - a `header` key that is not a header name (visible ASCII without delimiters, at
//!     most 256 bytes), that is bound twice (in any case), or that names a header the
//!     transport or the http stack sets: `Authorization`, `Host`, `Content-Length`,
//!     `Transfer-Encoding`, `Content-Type`, `Accept`, `Mcp-Session-Id`,
//!     `MCP-Protocol-Version`, in any case;
//!   - a `query` key outside `[A-Za-z0-9._-]+` or over 256 bytes, or bound twice;
//!   - a `username` with a `:` or a control character, or over 256 bytes;
//! - `credentials` on a `stdio` transport → `ConstraintViolation` (its secrets are its
//!   `secret-refs`);
//! - `credentials` in a document with an `origin` block → `ConstraintViolation`: a server
//!   file a pack wrote may not bind cap-secrets credentials, only the operator's own may;
//! - `http` endpoints must be `https://`, or `http://` on a loopback host;
//!   userinfo (`user@host`) is refused (credential smuggling / redaction hazard), and so
//!   are `{` and `}` (the security chain reads `{name}` in a request URL as a placeholder
//!   for the secret `name`, which would put a credential in the URL);
//! - the file is read through `O_NOFOLLOW` + fstat, capped at
//!   [`MAX_MCP_SERVER_YAML_BYTES`], alias-guarded and nesting-bounded like every
//!   other pack-shipped YAML this crate parses.
//!
//! An `http` endpoint is the server's one Streamable HTTP endpoint. A server
//! on the older HTTP+SSE transport (a GET stream such as `/sse` beside a
//! separate message endpoint) parses here, but the MCP client refuses it when
//! it connects.
//!
//! Trust (§3.2 rule 2) is NOT decided here — the manifest carries no trust; the
//! bridge refuses `stdio` from a pack whose `.meta.yaml` trust is `untrusted`.
//!
//! [`parse_mcp_server_origin_str`] reads a document's `origin` block alone, ignoring
//! every other key and their rules: what decides whether a materialized file still
//! belongs to an installed pack, whatever else the file says.

use std::collections::BTreeMap;
use std::path::Path;

use advance_shared_types::mcp::{is_valid_server_id, MAX_SERVER_ID_BYTES};
use advance_shared_types::security_validator::{CredentialBinding, CredentialPosition};
use serde::Deserialize;

use crate::component_manifest::yaml_nesting_within_bound;
use crate::error::PackError;
use crate::manifest::yaml_has_alias_refs;
use crate::materialize_impl::read_bytes_nofollow_bounded;

/// Size cap on `mcp-servers/{name}.yaml` (the document is a handful of lines).
pub const MAX_MCP_SERVER_YAML_BYTES: u64 = 64 * 1024;
const MAX_DESCRIPTION_LEN: usize = 1024;
const MAX_COMMAND_LEN: usize = 4096;
const MAX_ARGS: usize = 64;
const MAX_ARG_LEN: usize = 4096;
const MAX_SECRET_REFS: usize = 32;
const MAX_SECRET_REF_LEN: usize = 256;
/// Most `transport.env` entries one stdio server may set.
pub const MAX_ENV_VARS: usize = 64;
/// Longest `transport.env` value, in bytes.
const MAX_ENV_VALUE_LEN: usize = 4096;
/// Longest `transport.cwd`, in bytes.
const MAX_CWD_LEN: usize = 4096;
const MAX_ENDPOINT_URL_LEN: usize = 2048;
/// Most `credentials` one server file may bind.
pub const MAX_CREDENTIALS: usize = 8;
/// Longest header key, query key or basic username of a credential, in bytes.
const MAX_CREDENTIAL_KEY_LEN: usize = 256;
/// The headers the MCP http transport and the http stack set themselves: a `header`
/// credential may not name one (compared in any case).
const TRANSPORT_HEADERS: [&str; 8] = [
    "authorization",
    "host",
    "content-length",
    "transfer-encoding",
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
];

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
    /// Secret-store secrets bound to positions of the server's requests, by name; the
    /// cap-http security chain resolves and injects them at each request. Empty unless
    /// `transport` is `http` and the document has no `origin` (an operator's file).
    pub credentials: Vec<CredentialBinding>,
    /// The pack that materialized this file into the operator's servers
    /// directory. `None` on a file the operator wrote.
    pub origin: Option<McpServerOrigin>,
}

/// The pack that wrote a server file under `.advance/mcp-servers/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerOrigin {
    /// `name@version` of the installed pack.
    pub pack: String,
    /// The FQ ref that registered it (`{pack}@{ver}/mcp-servers/{name}`).
    pub config_ref: String,
}

/// The declared transport. Mirrors `cap_mcp::McpTransportSpec` minus the
/// resolved runtime material (the child's whole environment, the http capability),
/// which the loader and the bridge add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTransportDecl {
    Stdio {
        command: String,
        args: Vec<String>,
        /// `ENV_NAME → value`: non-secret literals for the child's environment (empty when
        /// absent). No key is also a `secret-refs` key.
        env: BTreeMap<String, String>,
        /// The child's working directory, an absolute path; `None`: `/`.
        cwd: Option<String>,
    },
    Http {
        endpoint_url: String,
    },
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
    #[serde(default)]
    credentials: Vec<RawCredential>,
    #[serde(default)]
    origin: Option<RawOrigin>,
}

/// One entry of `credentials`, by its `position`.
#[derive(Deserialize)]
#[serde(tag = "position", rename_all = "kebab-case", deny_unknown_fields)]
enum RawCredential {
    Bearer { secret: String },
    Basic { username: String, secret: String },
    Header { key: String, secret: String },
    Query { key: String, secret: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOrigin {
    pack: String,
    #[serde(rename = "config-ref")]
    config_ref: String,
}

/// A document read for its `origin` block only ([`parse_mcp_server_origin_str`]): every other
/// key is ignored, whatever it holds.
#[derive(Deserialize)]
struct RawOriginOnly {
    #[serde(default)]
    origin: Option<RawOrigin>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RawTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        cwd: Option<String>,
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
        RawTransport::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
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
            validate_env(&env)?;
            if let Some(cwd) = &cwd {
                validate_cwd(cwd)?;
            }
            McpTransportDecl::Stdio {
                command,
                args,
                env,
                cwd,
            }
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
    if let McpTransportDecl::Stdio { env, .. } = &transport {
        if let Some(name) = env.keys().find(|name| raw.secret_refs.contains_key(*name)) {
            return Err(PackError::ConstraintViolation {
                reason: format!(
                    "transport.env key {name} is also a secret-refs key: a variable of the \
                     server's environment is either a literal or a secret"
                ),
            });
        }
    }

    let credentials = validate_credentials(raw.credentials)?;
    if !credentials.is_empty() && transport.is_stdio() {
        return Err(PackError::ConstraintViolation {
            reason: "credentials require an http transport (the cap-http security chain \
                     injects them into the server's requests); a stdio server's secrets are \
                     its secret-refs"
                .into(),
        });
    }

    let origin = validate_origin(raw.origin)?;
    if !credentials.is_empty() && origin.is_some() {
        return Err(PackError::ConstraintViolation {
            reason: "credentials are bound only in a server file the operator wrote: a \
                     pack-origin server may not bind cap-secrets credentials"
                .into(),
        });
    }

    Ok(McpServerManifest {
        server_id: raw.server_id,
        description,
        transport,
        secret_refs: raw.secret_refs,
        credentials,
        origin,
    })
}

/// The `credentials` of a document as the bindings the security chain applies (see the
/// module docs for the rules).
fn validate_credentials(raw: Vec<RawCredential>) -> Result<Vec<CredentialBinding>, PackError> {
    if raw.len() > MAX_CREDENTIALS {
        return Err(PackError::InvalidManifest(format!(
            "credentials has {} entries (max {MAX_CREDENTIALS})",
            raw.len()
        )));
    }
    let mut authorization = false;
    let mut headers: Vec<String> = Vec::new();
    let mut query_keys: Vec<String> = Vec::new();
    let mut bindings = Vec::with_capacity(raw.len());
    for (i, credential) in raw.into_iter().enumerate() {
        let (position, secret) = match credential {
            RawCredential::Bearer { secret } => (CredentialPosition::BearerToken, secret),
            RawCredential::Basic { username, secret } => {
                if username.len() > MAX_CREDENTIAL_KEY_LEN
                    || username.contains(':')
                    || username.chars().any(char::is_control)
                {
                    return Err(PackError::InvalidManifest(format!(
                        "credentials[{i}].username must hold no ':' and no control \
                         characters (≤ {MAX_CREDENTIAL_KEY_LEN} bytes)"
                    )));
                }
                (CredentialPosition::BasicAuth { username }, secret)
            }
            RawCredential::Header { key, secret } => {
                if !is_header_name(&key) {
                    return Err(PackError::InvalidManifest(format!(
                        "credentials[{i}].key is not a header name (visible ASCII without \
                         delimiters, ≤ {MAX_CREDENTIAL_KEY_LEN} bytes)"
                    )));
                }
                let lower = key.to_ascii_lowercase();
                if TRANSPORT_HEADERS.contains(&lower.as_str()) {
                    return Err(PackError::InvalidManifest(format!(
                        "credentials[{i}].key {key:?} is a header the transport sets"
                    )));
                }
                if headers.contains(&lower) {
                    return Err(PackError::InvalidManifest(format!(
                        "credentials[{i}].key {key:?} is bound twice"
                    )));
                }
                headers.push(lower);
                (CredentialPosition::CustomHeader { key }, secret)
            }
            RawCredential::Query { key, secret } => {
                if !is_query_key(&key) {
                    return Err(PackError::InvalidManifest(format!(
                        "credentials[{i}].key is not a query key ([A-Za-z0-9._-]+, \
                         ≤ {MAX_CREDENTIAL_KEY_LEN} bytes)"
                    )));
                }
                if query_keys.contains(&key) {
                    return Err(PackError::InvalidManifest(format!(
                        "credentials[{i}].key {key:?} is bound twice"
                    )));
                }
                query_keys.push(key.clone());
                (CredentialPosition::QueryParam { key }, secret)
            }
        };
        if matches!(
            position,
            CredentialPosition::BearerToken | CredentialPosition::BasicAuth { .. }
        ) {
            if authorization {
                return Err(PackError::InvalidManifest(format!(
                    "credentials[{i}]: one bearer or basic credential at most (each sets \
                     the Authorization header)"
                )));
            }
            authorization = true;
        }
        if secret.is_empty()
            || secret.len() > MAX_SECRET_REF_LEN
            || secret.chars().any(char::is_control)
        {
            return Err(PackError::InvalidManifest(format!(
                "credentials[{i}].secret must be a non-empty secret key \
                 (≤ {MAX_SECRET_REF_LEN} bytes, no control characters)"
            )));
        }
        bindings.push(CredentialBinding {
            position,
            secret_name: secret,
        });
    }
    Ok(bindings)
}

/// A header name the security chain injects: visible ASCII without the delimiters of
/// RFC 9110 (the token characters), as cap-http checks it, within
/// [`MAX_CREDENTIAL_KEY_LEN`].
fn is_header_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_CREDENTIAL_KEY_LEN
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !b"\"(),/:;<=>?@[\\]{}".contains(&b))
}

/// A query key the security chain injects: `[A-Za-z0-9._-]+`, as cap-http checks it, within
/// [`MAX_CREDENTIAL_KEY_LEN`].
fn is_query_key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_CREDENTIAL_KEY_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// The `origin` block of an in-memory server-file document, and nothing else: `Ok(None)` for a
/// document without one (an operator's file), `Ok(Some(..))` for a pack's. The other keys are
/// not read, so a file the full parser refuses (an unknown key, a transport the loader will
/// not accept, an oversize description) still tells which pack wrote it. The document itself
/// must be YAML within the same alias and nesting bounds, and an `origin` block that is present
/// must be well-formed.
pub fn parse_mcp_server_origin_str(yaml: &str) -> Result<Option<McpServerOrigin>, PackError> {
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
    let raw: RawOriginOnly = serde_yml::from_str(yaml)
        .map_err(|e| PackError::InvalidManifest(format!("yaml parse: {e}")))?;
    validate_origin(raw.origin)
}

fn validate_origin(origin: Option<RawOrigin>) -> Result<Option<McpServerOrigin>, PackError> {
    let Some(origin) = origin else {
        return Ok(None);
    };
    if origin.pack.trim().is_empty()
        || origin.pack.contains('\0')
        || origin.pack.len() > MAX_SECRET_REF_LEN
    {
        return Err(PackError::InvalidManifest(
            "origin.pack must be a non-empty pack id (name@version)".into(),
        ));
    }
    if origin.config_ref.trim().is_empty()
        || origin.config_ref.contains('\0')
        || origin.config_ref.len() > MAX_COMMAND_LEN
    {
        return Err(PackError::InvalidManifest(
            "origin.config-ref must be a non-empty pack FQ ref".into(),
        ));
    }
    Ok(Some(McpServerOrigin {
        pack: origin.pack,
        config_ref: origin.config_ref,
    }))
}

/// The shared server-id grammar (`advance_shared_types::mcp::is_valid_server_id`), which
/// cap-mcp's whitelist applies too. The id is quoted in the error only when its length is in
/// range.
fn validate_server_id(id: &str) -> Result<(), PackError> {
    if is_valid_server_id(id) {
        return Ok(());
    }
    if id.is_empty() || id.len() > MAX_SERVER_ID_BYTES {
        return Err(PackError::InvalidManifest(format!(
            "server-id must be 1..={MAX_SERVER_ID_BYTES} bytes"
        )));
    }
    Err(PackError::InvalidManifest(format!(
        "server-id {id:?} must match [A-Za-z0-9._-]+ and not start with '.'"
    )))
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

/// A stdio transport's `env`: at most [`MAX_ENV_VARS`] literals, each named as an environment
/// variable, each value at most [`MAX_ENV_VALUE_LEN`] bytes without control characters (an
/// empty value is a variable set to nothing).
fn validate_env(env: &BTreeMap<String, String>) -> Result<(), PackError> {
    if env.len() > MAX_ENV_VARS {
        return Err(PackError::InvalidManifest(format!(
            "transport.env has {} entries (max {MAX_ENV_VARS})",
            env.len()
        )));
    }
    for (name, value) in env {
        if !is_env_var_name(name) {
            return Err(PackError::InvalidManifest(format!(
                "transport.env key {name:?} is not an environment-variable name \
                 ([A-Za-z_][A-Za-z0-9_]*, ≤ {MAX_SECRET_REF_LEN} bytes)"
            )));
        }
        if value.len() > MAX_ENV_VALUE_LEN || value.chars().any(char::is_control) {
            return Err(PackError::InvalidManifest(format!(
                "transport.env value for {name} must hold no control characters \
                 (≤ {MAX_ENV_VALUE_LEN} bytes)"
            )));
        }
    }
    Ok(())
}

/// A stdio transport's `cwd`: an absolute path of at most [`MAX_CWD_LEN`] bytes without
/// control characters (NUL among them).
fn validate_cwd(cwd: &str) -> Result<(), PackError> {
    if cwd.len() > MAX_CWD_LEN {
        return Err(PackError::InvalidManifest(format!(
            "transport.cwd exceeds {MAX_CWD_LEN} bytes"
        )));
    }
    if cwd.chars().any(char::is_control) {
        return Err(PackError::InvalidManifest(
            "transport.cwd contains a control character".into(),
        ));
    }
    if !Path::new(cwd).is_absolute() {
        return Err(PackError::InvalidManifest(format!(
            "transport.cwd {cwd:?} is not an absolute path"
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
    // The security chain reads `{name}` in a request URL as a placeholder for the secret
    // `name`: a credential goes only where `credentials` puts it.
    if url.contains(['{', '}']) {
        return Err(PackError::InvalidManifest(
            "transport.endpoint-url must not contain '{' or '}'".into(),
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

    // The manifest accepts exactly the shared server-id grammar, which cap-mcp's whitelist
    // applies too.
    #[test]
    fn server_ids_follow_the_shared_grammar() {
        let longest = "a".repeat(MAX_SERVER_ID_BYTES);
        let too_long = "a".repeat(MAX_SERVER_ID_BYTES + 1);
        for id in [
            "a",
            "srv-1",
            "alpha.beta_gamma",
            longest.as_str(),
            "",
            "a b",
            "srv:1",
            "ü",
            too_long.as_str(),
            ".",
            ".hidden",
        ] {
            let doc = format!(
                "server-id: {id:?}\ntransport:\n  kind: http\n  endpoint-url: https://h/\n"
            );
            let parsed = parse_mcp_server_manifest_str(&doc);
            assert_eq!(parsed.is_ok(), is_valid_server_id(id), "{id:?}: {parsed:?}");
        }
        match parse_mcp_server_manifest_str(
            "server-id: .hidden\ntransport:\n  kind: http\n  endpoint-url: https://h/\n",
        ) {
            Err(PackError::InvalidManifest(reason)) => {
                assert!(reason.contains("not start with '.'"), "{reason}")
            }
            other => panic!("expected InvalidManifest, got {other:?}"),
        }
    }

    // The origin block is read on its own: whatever the rest of the document holds, and
    // whether or not the full parser would accept it.
    #[test]
    fn the_origin_block_is_read_whatever_the_rest_of_the_document_says() {
        let origin = |doc: &str| parse_mcp_server_origin_str(doc).unwrap();
        assert_eq!(origin(HTTP), None, "an operator file has no origin");
        let expected = Some(McpServerOrigin {
            pack: "p@1.0.0".into(),
            config_ref: "p@1.0.0/mcp-servers/srv".into(),
        });
        let block = "origin:\n  pack: p@1.0.0\n  config-ref: p@1.0.0/mcp-servers/srv\n";
        assert_eq!(origin(&format!("{STDIO}{block}")), expected);
        for rest in [
            // An unknown key, a transport the full parser refuses, an oversize description,
            // an id outside the grammar, a document that is not even a server file.
            "server-id: x\nextra: 1\ntransport:\n  kind: http\n  endpoint-url: https://h/\n",
            "server-id: x\ntransport:\n  kind: ssh\n  host: h\n",
            &format!("server-id: x\ndescription: {}\n", "d".repeat(4096)),
            "server-id: .hidden\ntransport: 5\n",
            "whatever: [1, 2, 3]\n",
        ] {
            assert!(parse_mcp_server_manifest_str(rest).is_err(), "{rest}");
            assert_eq!(origin(&format!("{rest}{block}")), expected, "{rest}");
        }
        // The block itself must be well-formed, and the document must be YAML within bounds.
        for bad in [
            "server-id: x\norigin:\n  pack: p@1.0.0\n",
            "server-id: x\norigin:\n  pack: \"\"\n  config-ref: r\n",
            "server-id: x\norigin: 5\n",
            "server-id: [unclosed\n",
            "a: &x [1]\norigin: *x\n",
        ] {
            assert!(parse_mcp_server_origin_str(bad).is_err(), "{bad}");
        }
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
        // `{name}` would be a secret placeholder to the security chain.
        for braced in [
            "https://h/{token}/mcp",
            "https://h/mcp?key={token}",
            "https://h/mcp}",
            "http://127.0.0.1:9/{",
        ] {
            match validate_endpoint_url(braced) {
                Err(PackError::InvalidManifest(reason)) => {
                    assert!(reason.contains("'{' or '}'"), "{braced}: {reason}")
                }
                other => panic!("{braced}: expected InvalidManifest, got {other:?}"),
            }
        }
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

    /// An http server whose `credentials` are the YAML flow sequence `list`.
    fn with_credentials(list: &str) -> Result<McpServerManifest, PackError> {
        parse_mcp_server_manifest_str(&format!(
            "server-id: x\ntransport:\n  kind: http\n  endpoint-url: https://h/mcp\n\
             credentials: {list}\n"
        ))
    }

    /// The reason of an `InvalidManifest` refusal of `list`.
    fn credentials_refused(list: &str) -> String {
        match with_credentials(list) {
            Err(PackError::InvalidManifest(reason)) => reason,
            other => panic!("{list}: expected InvalidManifest, got {other:?}"),
        }
    }

    fn binding(position: CredentialPosition, secret: &str) -> CredentialBinding {
        CredentialBinding {
            position,
            secret_name: secret.into(),
        }
    }

    // An http server binds secret-store secrets, by name, to the four positions the security
    // chain injects; a file without the key binds none.
    #[test]
    fn credentials_bind_secret_names_to_the_four_positions() {
        let m = with_credentials(
            "[{position: bearer, secret: s3cret-name}, \
             {position: header, key: X-Api-Key, secret: api-key}, \
             {position: query, key: api_key, secret: query-key}]",
        )
        .unwrap();
        assert_eq!(
            m.credentials,
            [
                binding(CredentialPosition::BearerToken, "s3cret-name"),
                binding(
                    CredentialPosition::CustomHeader {
                        key: "X-Api-Key".into()
                    },
                    "api-key"
                ),
                binding(
                    CredentialPosition::QueryParam {
                        key: "api_key".into()
                    },
                    "query-key"
                ),
            ]
        );
        assert!(
            !format!("{m:?}").contains("s3cret-name"),
            "a manifest's Debug hides the secret names"
        );
        for username in ["bot", "\"\""] {
            let m = with_credentials(&format!(
                "[{{position: basic, username: {username}, secret: pw}}]"
            ))
            .unwrap();
            assert_eq!(
                m.credentials,
                [binding(
                    CredentialPosition::BasicAuth {
                        username: username.trim_matches('"').into()
                    },
                    "pw"
                )]
            );
        }
        assert!(parse_mcp_server_manifest_str(HTTP)
            .unwrap()
            .credentials
            .is_empty());
    }

    // At most MAX_CREDENTIALS entries, each naming its secret by a secret-store key of the
    // `secret-refs` value rule.
    #[test]
    fn credentials_are_bounded_and_name_their_secrets_as_secret_refs_do() {
        let entry = |i: usize| format!("{{position: header, key: X-K{i}, secret: s{i}}}");
        let list = |n: usize| format!("[{}]", (0..n).map(entry).collect::<Vec<_>>().join(", "));
        assert_eq!(
            with_credentials(&list(MAX_CREDENTIALS))
                .unwrap()
                .credentials
                .len(),
            MAX_CREDENTIALS
        );
        assert!(credentials_refused(&list(MAX_CREDENTIALS + 1)).contains("max 8"));

        let longest = "k".repeat(256);
        assert!(with_credentials(&format!("[{{position: bearer, secret: {longest}}}]")).is_ok());
        for secret in [
            "\"\"".to_string(),
            "k".repeat(257),
            "\"a\\tb\"".to_string(),
            "\"a\\u0085b\"".to_string(),
        ] {
            let reason = credentials_refused(&format!("[{{position: bearer, secret: {secret}}}]"));
            assert!(
                reason.contains("non-empty secret key"),
                "{secret}: {reason}"
            );
        }
    }

    // `bearer` and `basic` both set Authorization: one of them at most.
    #[test]
    fn one_bearer_or_basic_credential_at_most() {
        for list in [
            "[{position: bearer, secret: a}, {position: basic, username: u, secret: b}]",
            "[{position: basic, username: u, secret: b}, {position: bearer, secret: a}]",
            "[{position: bearer, secret: a}, {position: bearer, secret: b}]",
            "[{position: basic, username: u, secret: a}, {position: basic, username: v, secret: b}]",
        ] {
            assert!(
                credentials_refused(list).contains("one bearer or basic credential at most"),
                "{list}"
            );
        }
        with_credentials(
            "[{position: bearer, secret: a}, {position: header, key: X-K, secret: b}]",
        )
        .unwrap();
    }

    // A header credential names a header (a token of visible ASCII), once, and never one the
    // transport or the http stack sets, whatever its case.
    #[test]
    fn a_header_credential_names_a_header_the_transport_does_not_set() {
        let header = |key: &str| format!("[{{position: header, key: {key}, secret: s}}]");
        let longest = "h".repeat(256);
        let too_long = "h".repeat(257);
        for key in [
            "X-Api-Key",
            "x_token",
            "X.Trace~1!#$%&'*+^`|",
            longest.as_str(),
        ] {
            let quoted = format!("{key:?}");
            assert!(with_credentials(&header(&quoted)).is_ok(), "{key}");
        }
        for key in [
            "\"\"",
            "\"X Api\"",
            "\"X:Api\"",
            "\"X-Api\\r\\nHost: evil\"",
            "\"X\\u0001\"",
            "\"X(1)\"",
            "\"X/1\"",
            "\"X{a}\"",
            "\"Ü-Key\"",
            too_long.as_str(),
        ] {
            assert!(
                credentials_refused(&header(key)).contains("is not a header name"),
                "{key}"
            );
        }
        for key in [
            "Authorization",
            "HOST",
            "content-length",
            "Transfer-Encoding",
            "Content-Type",
            "ACCEPT",
            "Mcp-Session-Id",
            "mcp-protocol-version",
        ] {
            let reason = credentials_refused(&header(key));
            assert!(
                reason.contains("a header the transport sets"),
                "{key}: {reason}"
            );
        }
        let twice = credentials_refused(
            "[{position: header, key: X-Key, secret: a}, {position: header, key: x-key, secret: b}]",
        );
        assert!(twice.contains("bound twice"), "{twice}");
    }

    // A query credential's key is a plain query key, bound once.
    #[test]
    fn a_query_credential_key_is_a_plain_query_key() {
        let query = |key: &str| format!("[{{position: query, key: {key}, secret: s}}]");
        let longest = "q".repeat(256);
        let too_long = "q".repeat(257);
        for key in ["api_key", "key.v2", "a-b", longest.as_str()] {
            assert!(with_credentials(&query(key)).is_ok(), "{key}");
        }
        for key in [
            "\"\"",
            "\"a=b\"",
            "\"a&b\"",
            "\"a?b\"",
            "\"a#b\"",
            "\"a b\"",
            "\"a\\r\\nb\"",
            "\"a\\tb\"",
            "\"ключ\"",
            "\"{key}\"",
            too_long.as_str(),
        ] {
            assert!(
                credentials_refused(&query(key)).contains("is not a query key"),
                "{key}"
            );
        }
        let twice = credentials_refused(
            "[{position: query, key: k, secret: a}, {position: query, key: k, secret: b}]",
        );
        assert!(twice.contains("bound twice"), "{twice}");
    }

    // A basic credential's username holds no ':' (RFC 7617) and no control character.
    #[test]
    fn a_basic_username_holds_no_colon_and_no_control_character() {
        let basic =
            |username: &str| format!("[{{position: basic, username: {username}, secret: s}}]");
        assert!(with_credentials(&basic(&"u".repeat(256))).is_ok());
        let too_long = "u".repeat(257);
        for username in [
            "\"a:b\"",
            "\"a\\tb\"",
            "\"a\\nb\"",
            "\"a\\u0085b\"",
            too_long.as_str(),
        ] {
            assert!(
                credentials_refused(&basic(username)).contains("username must hold no ':'"),
                "{username}"
            );
        }
    }

    // A position outside the four, a key a position does not take and a missing field are
    // refused: there is no url-path position.
    #[test]
    fn credentials_take_the_four_positions_and_their_keys_only() {
        for list in [
            "[{position: url-path, key: k, secret: s}]",
            "[{position: cookie, secret: s}]",
            "[{secret: s}]",
            "[{position: bearer, secret: s, key: k}]",
            "[{position: bearer, secret: s, username: u}]",
            "[{position: header, secret: s}]",
            "[{position: basic, secret: s}]",
            "[{position: query, key: k}]",
            "[{position: bearer, secret: [s]}]",
            "{position: bearer, secret: s}",
        ] {
            credentials_refused(list);
        }
    }

    // Credentials are an http server's: on a stdio transport they are a constraint violation.
    #[test]
    fn stdio_credentials_are_a_constraint_violation() {
        let doc = "server-id: x\ntransport:\n  kind: stdio\n  command: /bin/true\n\
                   credentials: [{position: bearer, secret: s}]\n";
        match parse_mcp_server_manifest_str(doc) {
            Err(PackError::ConstraintViolation { reason }) => {
                assert!(reason.contains("require an http transport"), "{reason}")
            }
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    // A server file a pack wrote (it has an `origin` block) may not bind credentials; the
    // sweep still reads which pack wrote it.
    #[test]
    fn pack_origin_credentials_are_a_constraint_violation() {
        let doc = "server-id: x\ntransport:\n  kind: http\n  endpoint-url: https://h/mcp\n\
                   credentials: [{position: bearer, secret: s}]\n\
                   origin:\n  pack: p@1.0.0\n  config-ref: p@1.0.0/mcp-servers/x\n";
        match parse_mcp_server_manifest_str(doc) {
            Err(PackError::ConstraintViolation { reason }) => {
                assert!(
                    reason.contains("pack-origin server may not bind cap-secrets credentials"),
                    "{reason}"
                )
            }
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
        assert_eq!(
            parse_mcp_server_origin_str(doc).unwrap().map(|o| o.pack),
            Some("p@1.0.0".to_string())
        );
    }

    /// A stdio server whose transport ends with `tail` (more transport keys, each line
    /// indented by two spaces) and whose document ends with `rest`.
    fn stdio_with(tail: &str, rest: &str) -> Result<McpServerManifest, PackError> {
        parse_mcp_server_manifest_str(&format!(
            "server-id: x\ntransport:\n  kind: stdio\n  command: /bin/true\n{tail}{rest}"
        ))
    }

    /// The reason of an `InvalidManifest` refusal of the stdio transport keys `tail`.
    fn stdio_refused(tail: &str) -> String {
        match stdio_with(tail, "") {
            Err(PackError::InvalidManifest(reason)) => reason,
            other => panic!("{tail}: expected InvalidManifest, got {other:?}"),
        }
    }

    /// A transport `env` block of the `entries` (`KEY: value` lines).
    fn env_block(entries: &[String]) -> String {
        let lines: String = entries.iter().map(|e| format!("    {e}\n")).collect();
        format!("  env:\n{lines}")
    }

    // A stdio transport sets non-secret literals of its child's environment, an empty one
    // included, and its working directory; without them it sets no literal and keeps the
    // default directory.
    #[test]
    fn a_stdio_transport_takes_env_literals_and_a_working_directory() {
        let m = stdio_with(
            "  env:\n    LOG_LEVEL: info\n    EMPTY: \"\"\n    _UNDER_1: \"a b: c #d\"\n  \
             cwd: /srv/tools\n",
            "",
        )
        .unwrap();
        assert_eq!(
            m.transport,
            McpTransportDecl::Stdio {
                command: "/bin/true".into(),
                args: vec![],
                env: BTreeMap::from([
                    ("EMPTY".to_string(), String::new()),
                    ("LOG_LEVEL".to_string(), "info".to_string()),
                    ("_UNDER_1".to_string(), "a b: c #d".to_string()),
                ]),
                cwd: Some("/srv/tools".into()),
            }
        );
        assert_eq!(
            stdio_with("", "").unwrap().transport,
            McpTransportDecl::Stdio {
                command: "/bin/true".into(),
                args: vec![],
                env: BTreeMap::new(),
                cwd: None,
            }
        );
    }

    // At most MAX_ENV_VARS literals, each named as an environment variable.
    #[test]
    fn env_keys_are_environment_variable_names_and_bounded_in_number() {
        let entries = |n: usize| -> Vec<String> { (0..n).map(|i| format!("V{i}: x")).collect() };
        match stdio_with(&env_block(&entries(MAX_ENV_VARS)), "")
            .unwrap()
            .transport
        {
            McpTransportDecl::Stdio { env, .. } => assert_eq!(env.len(), MAX_ENV_VARS),
            other => panic!("a stdio transport: {other:?}"),
        }
        let reason = stdio_refused(&env_block(&entries(MAX_ENV_VARS + 1)));
        assert!(reason.contains("max 64"), "{reason}");

        let longest = format!("V{}", "A".repeat(255));
        stdio_with(&env_block(&[format!("{longest}: x")]), "").unwrap();
        let too_long = format!("V{}", "A".repeat(256));
        for key in [
            "\"1BAD\"",
            "\"A-B\"",
            "\"A B\"",
            "\"A=B\"",
            "\"\"",
            "\"Ü\"",
            too_long.as_str(),
        ] {
            let reason = stdio_refused(&env_block(&[format!("{key}: x")]));
            assert!(
                reason.contains("is not an environment-variable name"),
                "{key}: {reason}"
            );
        }
    }

    // A literal is at most 4096 bytes without control characters, and may be empty.
    #[test]
    fn env_values_are_bounded_and_hold_no_control_characters() {
        let longest = "v".repeat(4096);
        stdio_with(&env_block(&[format!("V: {longest}")]), "").unwrap();
        stdio_with(&env_block(&["V: \"\"".to_string()]), "").unwrap();
        for value in [
            "v".repeat(4097),
            "\"a\\tb\"".to_string(),
            "\"a\\nb\"".to_string(),
            "\"a\\u0000b\"".to_string(),
            "\"a\\u007fb\"".to_string(),
            "\"a\\u0085b\"".to_string(),
        ] {
            let reason = stdio_refused(&env_block(&[format!("V: {value}")]));
            assert!(
                reason.contains("value for V must hold no control characters"),
                "{value}: {reason}"
            );
        }
    }

    // A variable of the child's environment is a literal or a secret, never both.
    #[test]
    fn an_env_key_that_is_also_a_secret_ref_is_a_constraint_violation() {
        match stdio_with(
            "  env:\n    API_TOKEN: literal\n",
            "secret-refs:\n  API_TOKEN: mcp-token\n",
        ) {
            Err(PackError::ConstraintViolation { reason }) => assert!(
                reason.contains("API_TOKEN") && reason.contains("also a secret-refs key"),
                "{reason}"
            ),
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
        let m = stdio_with(
            "  env:\n    LOG_LEVEL: info\n",
            "secret-refs:\n  API_TOKEN: mcp-token\n",
        )
        .unwrap();
        assert_eq!(m.secret_refs.len(), 1);
    }

    // The working directory is an absolute path of at most 4096 bytes without control
    // characters.
    #[test]
    fn cwd_is_an_absolute_path_without_control_characters() {
        let longest = format!("/{}", "d".repeat(4095));
        match stdio_with(&format!("  cwd: {longest}\n"), "")
            .unwrap()
            .transport
        {
            McpTransportDecl::Stdio { cwd, .. } => assert_eq!(cwd, Some(longest)),
            other => panic!("a stdio transport: {other:?}"),
        }
        let too_long = format!("/{}", "d".repeat(4096));
        for (cwd, why) in [
            ("srv/tools", "is not an absolute path"),
            ("./tools", "is not an absolute path"),
            ("\"~/tools\"", "is not an absolute path"),
            ("\"\"", "is not an absolute path"),
            (too_long.as_str(), "exceeds 4096 bytes"),
            ("\"/srv/\\u0000x\"", "contains a control character"),
            ("\"/srv/\\tx\"", "contains a control character"),
            ("\"/srv/\\nx\"", "contains a control character"),
        ] {
            let reason = stdio_refused(&format!("  cwd: {cwd}\n"));
            assert!(reason.contains(why), "{cwd}: {reason}");
        }
    }

    // `env` and `cwd` are keys of a stdio transport: a stdio transport takes either, an http
    // transport carrying either is refused, and neither is a key of the document itself.
    #[test]
    fn env_and_cwd_belong_to_the_stdio_transport() {
        for key in ["env:\n    A: b\n", "cwd: /srv\n"] {
            stdio_with(&format!("  {key}"), "")
                .unwrap_or_else(|e| panic!("a stdio transport takes {key}: {e:?}"));
            for doc in [
                format!(
                    "server-id: x\ntransport:\n  kind: http\n  endpoint-url: https://h/mcp\n  \
                     {key}"
                ),
                format!("server-id: x\ntransport:\n  kind: stdio\n  command: /bin/true\n{key}"),
            ] {
                match parse_mcp_server_manifest_str(&doc) {
                    Err(PackError::InvalidManifest(reason)) => {
                        assert!(reason.contains("unknown field"), "{doc}: {reason}")
                    }
                    other => panic!("{doc}: expected InvalidManifest, got {other:?}"),
                }
            }
        }
    }
}
