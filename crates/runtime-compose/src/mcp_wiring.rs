//! The MCP client of `advance start`: the operator's server files, the client built from
//! them, and the `mcp-client` host functions of an agent that declares `mcp`.
//!
//! All of it exists only when the root agent's `.agent/config.yaml` declares the `mcp`
//! capability. A home that does not declare it reads no server file, builds no client,
//! registers no host function and starts no server.
//!
//! ## Server files
//!
//! [`McpControlPlane`] reads `<workspace>/<mcp.servers-dir>` (default
//! `.advance/mcp-servers`). Each `*.yaml` file there describes one server in the schema of a
//! pack's `mcp-servers/{name}.yaml` ([`advance_pack_manager::mcp_server_manifest`]), and is
//! named after its server: `github.yaml` holds `server-id: github`. The directory is the
//! operator's: the runtime configuration only accepts one inside `.advance/`, which cap-fs
//! hides from every agent, so no agent can write a server file.
//!
//! Reading never stops the daemon. A file that cannot serve is skipped with a warning on
//! stderr, and the other servers are kept:
//!
//! - an entry that is not a regular file (a symlink, a FIFO, a directory), a file over
//!   [`MAX_MCP_SERVER_YAML_BYTES`], or one the schema refuses;
//! - a file whose name is not its `server-id` followed by `.yaml`;
//! - a `stdio` server while `mcp.allow-stdio` is `false`;
//! - a server whose `secret-refs` name a secret the store does not hold;
//! - anything past [`cap_mcp::MAX_SERVERS`] servers.
//!
//! An absent directory is a home without servers. Entries that are not named `*.yaml`, and
//! hidden ones (a name starting with a dot), are not server files and are ignored. The loader
//! visits the directory's entries and compares each file's name with the id inside it; it
//! never builds a path from a server id.
//!
//! ## Transports
//!
//! A `stdio` server is a process the daemon starts, on its first use, with nothing in its
//! environment but its `secret-refs`. An `http` server is reached through a cap-http security
//! chain that only the MCP client uses (leak scans, SSRF guard, rate limit, redirect re-check,
//! `http.*` events), whose executor allows a request the configured
//! `mcp.request-timeout-sec`. The server's allowlist is the origin of its endpoint: scheme,
//! host and port.
//!
//! An endpoint on loopback (`localhost`, `127.0.0.0/8`, `::1`) is reachable although the
//! chain forbids loopback: the server file exempts exactly that host and port
//! ([`LoopbackExemptions`]), in the chain's guard and in its executor. Nothing else on
//! loopback becomes reachable, and an endpoint in any other forbidden range stays blocked.
//! Only the operator's files exempt anything: a pack's server on loopback is refused when the
//! pack registers it ([`crate::pack_bridges::PackMcpBridge`]).
//!
//! ## Secrets
//!
//! Only a `stdio` server's `secret-refs` need the secret store: each names a secret that
//! becomes one variable of the server's environment. When a server file has some, the daemon
//! opens its secret store as it does for `secrets` or `llm`, which needs the home's master
//! key: without that key the daemon does not start, as with those two. Otherwise `mcp` needs
//! no master key, and the http chain is built on an empty store: no server file binds a
//! credential to an http request.
//!
//! ## What an agent may reach
//!
//! The host functions are registered under the one capability `mcp`. Each call is decided by
//! an [`McpGate`] over the daemon's grant check and grant store: a call by the check, a
//! listing by the silent grant readers, both keyed by the caller's agent id as the runtime
//! stamps it (the id its grants are stored under). The web family tools also need the `web`
//! grant; in the `offline` web mode the gate holds no web grant and withholds them from
//! every agent.
//!
//! ## Shutdown
//!
//! A stdio server leads its own process group and would outlive the daemon.
//! [`McpRuntime::shutdown`] closes every connection and stops those groups; the daemon calls
//! it when it stops, and dropping the last handle to the runtime does the same.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use advance_pack_manager::mcp_server_manifest::MAX_MCP_SERVER_YAML_BYTES;
use advance_pack_manager::{
    parse_mcp_server_manifest_str, McpServerManifest, McpTransportDecl, PackError,
    SecretStore as ManifestSecrets,
};
use advance_runtime::config::{McpConfig, RuntimeConfigProvider};
use advance_runtime::host_registry::HostRegistry;
use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, HttpSecurityChain, LeakDetector, SsrfGuard,
};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use advance_shared_types::web_search::WebRunMode;
use cap_grant::{GrantStore, McpGrantReaderImpl, WebGrantReaderImpl};
use cap_http::{
    DefaultHttpSecurityChain, LoopbackExemptSsrfGuard, LoopbackExemptions, ReqwestExecutorConfig,
    ReqwestHttpExecutor,
};
use cap_mcp::{
    register_mcp_client, McpClient, McpClientLimits, McpGate, McpServerEntry, McpServersConfig,
    McpTransportSpec, McpWebGrant,
};
use cap_secrets::{InMemorySecretStorage, SecretStore};
use zeroize::Zeroizing;

use crate::api::log_keys;
use crate::compose_log::LogHandle;
use crate::pack_bridges::{McpEntrySink, McpRegister, McpRegistration, PackBridgeError};
use crate::pack_production::CapSecretsSecretStore;

/// The suffix of a server file's name.
const SERVER_FILE_SUFFIX: &str = ".yaml";

/// Most directory entries one scan visits; the rest of a larger directory is not read.
const MAX_DIR_ENTRIES: usize = 1024;

/// Most `*.yaml` files one scan reads: twice the server cap, so a few refused files do not
/// crowd out servers, while a directory of refused files costs a bounded amount of work.
const MAX_SERVER_FILES: usize = 2 * cap_mcp::MAX_SERVERS;

/// Most warnings one load keeps; further ones are counted.
const MAX_WARNINGS: usize = 64;

/// Longest warning printed, in bytes.
const MAX_WARNING_BYTES: usize = 512;

/// Servers whose tools the warm-up lists at the same time.
const WARM_UP_CONCURRENCY: usize = 4;

/// The warnings of one load, bounded: the first [`MAX_WARNINGS`] are kept, each made safe to
/// print, and the rest are counted.
#[derive(Debug, Default)]
struct Warnings {
    kept: Vec<String>,
    dropped: usize,
}

impl Warnings {
    fn push(&mut self, warning: String) {
        if self.kept.len() < MAX_WARNINGS {
            self.kept.push(printable(&warning));
        } else {
            self.dropped += 1;
        }
    }

    fn into_lines(mut self) -> Vec<String> {
        if self.dropped > 0 {
            self.kept
                .push(format!("{} more warnings are not shown", self.dropped));
        }
        self.kept
    }
}

/// `text` without control characters, cut to [`MAX_WARNING_BYTES`]: a warning quotes file
/// names and parser messages, which must not reach a terminal raw.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_WARNING_BYTES));
    for c in text.chars() {
        if out.len() + c.len_utf8() > MAX_WARNING_BYTES {
            out.push('…');
            break;
        }
        out.push(if c.is_control() { '?' } else { c });
    }
    out
}

/// The directory of the operator's MCP server files (see the module docs).
#[derive(Debug, Clone)]
pub struct McpControlPlane {
    dir: PathBuf,
    allow_stdio: bool,
    log: LogHandle,
}

impl McpControlPlane {
    /// The control plane of `workspace` under the `mcp:` block `config`.
    pub fn new(workspace: &Path, config: &McpConfig) -> Self {
        Self {
            dir: workspace.join(&config.servers_dir),
            allow_stdio: config.allow_stdio,
            log: LogHandle::null(),
        }
    }

    /// Report skip and stale-file warnings to `log`.
    pub fn with_log(mut self, log: LogHandle) -> Self {
        self.log = log;
        self
    }

    /// The directory the server files are read from.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Delete pack-origin server files whose origin pack is not in
    /// `installed` (`name@version`). Operator files (no origin) are left.
    /// Returns the server ids removed.
    pub fn remove_origins_not_in(&self, installed: &BTreeSet<String>) -> Vec<String> {
        let mut removed = Vec::new();
        for manifest in self.scan().manifests() {
            let Some(origin) = &manifest.origin else {
                continue;
            };
            if installed.contains(&origin.pack) {
                continue;
            }
            let path = self
                .dir
                .join(format!("{}{SERVER_FILE_SUFFIX}", manifest.server_id));
            match std::fs::remove_file(&path) {
                Ok(()) => removed.push(manifest.server_id.clone()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => self.log.err(
                    log_keys::MCP_WARN,
                    format!(
                        "advance: WARN mcp: could not remove stale server file {}: {e}",
                        path.display()
                    ),
                ),
            }
        }
        removed
    }

    /// Read every server file. Never fails: what cannot serve is left out, with a warning
    /// (see the module docs). No secret is read.
    pub fn scan(&self) -> McpServerFiles {
        let mut files = McpServerFiles::default();
        match std::fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => {}
            // `symlink_metadata` does not follow: a symlinked directory is refused, not read.
            Ok(_) => {
                files.warnings.push(format!(
                    "{:?} is not a directory: no server file is read",
                    self.dir
                ));
                return files;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return files,
            Err(e) => {
                files
                    .warnings
                    .push(format!("{:?} cannot be read: {e}", self.dir));
                return files;
            }
        }
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) => {
                files
                    .warnings
                    .push(format!("{:?} cannot be read: {e}", self.dir));
                return files;
            }
        };

        // The names first, sorted: which servers a crowded directory yields does not depend
        // on the order the file system lists it in.
        let mut names: Vec<String> = Vec::new();
        for (visited, entry) in entries.enumerate() {
            if visited >= MAX_DIR_ENTRIES {
                files.warnings.push(format!(
                    "{:?} holds more than {MAX_DIR_ENTRIES} entries: the rest is not read",
                    self.dir
                ));
                break;
            }
            // A name that is not UTF-8 cannot be a server id followed by `.yaml`.
            let Some(name) = entry.ok().and_then(|e| e.file_name().into_string().ok()) else {
                continue;
            };
            if name.ends_with(SERVER_FILE_SUFFIX) && !name.starts_with('.') {
                names.push(name);
            }
        }
        names.sort();

        for (read, name) in names.iter().enumerate() {
            let unread = names.len() - read;
            if read >= MAX_SERVER_FILES {
                files.warnings.push(format!(
                    "more than {MAX_SERVER_FILES} server files: {unread} are not read, \
                     from {name:?} on"
                ));
                break;
            }
            if files.servers.len() >= cap_mcp::MAX_SERVERS {
                files.warnings.push(format!(
                    "more than {} servers: {unread} files are not read, from {name:?} on",
                    cap_mcp::MAX_SERVERS
                ));
                break;
            }
            match self.read_server(name) {
                Ok(manifest) => {
                    if let McpTransportDecl::Stdio { command, .. } = &manifest.transport {
                        if !Path::new(command).is_absolute() {
                            files.warnings.push(format!(
                                "server '{}': command {command:?} is not an absolute path; \
                                 the server starts with an empty environment, so it is looked \
                                 up on the system's default search path",
                                manifest.server_id
                            ));
                        }
                    }
                    files.servers.push(manifest);
                }
                Err(reason) => files
                    .warnings
                    .push(format!("server file {name:?} is skipped: {reason}")),
            }
        }
        files
    }

    /// The server the file `name` of the directory describes. `name` comes from the directory
    /// listing; the server id it must carry is only compared, never made into a path.
    fn read_server(&self, name: &str) -> Result<McpServerManifest, String> {
        let text = read_server_file(&self.dir.join(name))?;
        // The parser's own reason: its error type words it for a pack's files.
        let manifest = parse_mcp_server_manifest_str(&text).map_err(|e| match e {
            PackError::InvalidManifest(reason) | PackError::ConstraintViolation { reason } => {
                reason
            }
            other => other.to_string(),
        })?;
        let stem = name.strip_suffix(SERVER_FILE_SUFFIX).unwrap_or(name);
        if manifest.server_id != stem {
            return Err(format!(
                "it holds server-id '{}', and a server file is named after its server \
                 ('{}{SERVER_FILE_SUFFIX}')",
                manifest.server_id, manifest.server_id
            ));
        }
        if manifest.transport.is_stdio() && !self.allow_stdio {
            return Err("stdio servers are disabled (mcp.allow-stdio: false)".into());
        }
        Ok(manifest)
    }
}

/// The text of the server file at `path`: a regular file of at most
/// [`MAX_MCP_SERVER_YAML_BYTES`], never a symlink, read without waiting on a FIFO or a device.
fn read_server_file(path: &Path) -> Result<String, String> {
    let too_large = || format!("it is larger than {MAX_MCP_SERVER_YAML_BYTES} bytes");
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("it cannot be read: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err("it is a symbolic link".into());
    }
    if !meta.file_type().is_file() {
        return Err("it is not a regular file".into());
    }
    if meta.len() > MAX_MCP_SERVER_YAML_BYTES {
        return Err(too_large());
    }
    let file = open_without_following(path).map_err(|e| format!("it cannot be read: {e}"))?;
    // The entry may have been replaced since it was examined: decide on the file that opened.
    let opened = file
        .metadata()
        .map_err(|e| format!("it cannot be read: {e}"))?;
    if !opened.is_file() {
        return Err("it is not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_MCP_SERVER_YAML_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("it cannot be read: {e}"))?;
    if bytes.len() as u64 > MAX_MCP_SERVER_YAML_BYTES {
        return Err(too_large());
    }
    String::from_utf8(bytes).map_err(|_| "it is not valid UTF-8".to_string())
}

/// Open `path` for reading without following a symlink at its last component and without
/// blocking on a FIFO that has no writer.
#[cfg(unix)]
fn open_without_following(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_without_following(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The server files of one scan ([`McpControlPlane::scan`]): the servers that can serve, in
/// server-id order, and what was skipped. No secret has been read yet.
#[derive(Debug, Default)]
pub struct McpServerFiles {
    servers: Vec<McpServerManifest>,
    warnings: Warnings,
}

impl McpServerFiles {
    /// The ids of the servers read, in order.
    pub fn server_ids(&self) -> Vec<&str> {
        self.servers.iter().map(|m| m.server_id.as_str()).collect()
    }

    /// The manifests that can serve, in server-id order.
    pub fn manifests(&self) -> &[McpServerManifest] {
        &self.servers
    }

    /// Whether a server needs the secret store: it names `secret-refs`.
    pub fn need_secrets(&self) -> bool {
        self.servers.iter().any(|m| !m.secret_refs.is_empty())
    }

    /// The warnings of the scan so far.
    pub fn warnings(&self) -> &[String] {
        &self.warnings.kept
    }

    /// Build the client's server set, resolving each `secret-refs` entry through `secrets`.
    /// A server whose secret is missing is left out with a warning, as is every server that
    /// needs secrets when there is no store (`None`).
    pub fn into_servers(self, secrets: Option<&dyn ManifestSecrets>) -> McpServers {
        let mut warnings = self.warnings;
        let mut loopback = LoopbackExemptions::none();
        let mut builder = McpServersConfig::builder();
        for manifest in self.servers {
            let server_id = manifest.server_id.clone();
            let entry = match server_entry(manifest, secrets) {
                Ok(entry) => entry,
                Err(reason) => {
                    warnings.push(format!("server '{server_id}' is skipped: {reason}"));
                    continue;
                }
            };
            let endpoint = match &entry.transport {
                McpTransportSpec::Http { endpoint_url, .. } => Some(endpoint_url.clone()),
                McpTransportSpec::Stdio { .. } => None,
            };
            // The scan admits valid, distinct ids up to the server cap, which is all the
            // builder asks: a refusal here would lose the servers added so far.
            builder = match builder.add_server(entry) {
                Ok(builder) => builder,
                Err(e) => {
                    warnings.push(format!(
                        "server '{server_id}' is refused ({}): no server is configured",
                        e.message
                    ));
                    return McpServers {
                        config: McpServersConfig::builder().build(),
                        loopback: LoopbackExemptions::none(),
                        warnings: warnings.into_lines(),
                    };
                }
            };
            if let Some(endpoint) = endpoint {
                // Exempts the endpoint only when it is on loopback.
                loopback.allow_endpoint(&endpoint);
            }
        }
        McpServers {
            config: builder.build(),
            loopback,
            warnings: warnings.into_lines(),
        }
    }
}

/// The client's entry for the server `manifest` describes.
fn server_entry(
    manifest: McpServerManifest,
    secrets: Option<&dyn ManifestSecrets>,
) -> Result<McpServerEntry, String> {
    let transport = match manifest.transport {
        McpTransportDecl::Stdio { command, args } => {
            let mut env = BTreeMap::new();
            for (variable, key) in &manifest.secret_refs {
                let Some(secrets) = secrets else {
                    return Err(
                        "it needs secrets and the secret store is not open; the store is \
                         opened when the daemon starts"
                            .into(),
                    );
                };
                let value = secrets.get(key).ok_or_else(|| {
                    format!("secret {key:?} (for {variable}) is not in the secret store")
                })?;
                env.insert(variable.clone(), value.expose_secret().to_string());
            }
            McpTransportSpec::Stdio { command, args, env }
        }
        McpTransportDecl::Http { endpoint_url } => {
            let allowlist = Allowlist {
                patterns: vec![origin_prefix(&endpoint_url)
                    .ok_or_else(|| "its endpoint-url has no host".to_string())?],
            };
            if !allowlist.matches(&endpoint_url) {
                return Err("its endpoint-url is not a URL the http chain can address".into());
            }
            McpTransportSpec::Http {
                endpoint_url,
                capability: HttpCapability {
                    allowlist,
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

/// The allowlist pattern of an endpoint: its origin (`scheme://host[:port]/`), so the server
/// is reached on that scheme, host and port only.
fn origin_prefix(endpoint_url: &str) -> Option<String> {
    let (scheme, rest) = endpoint_url.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    Some(format!("{scheme}://{authority}/"))
}

/// The client's server set, built from the server files ([`McpServerFiles::into_servers`]).
#[derive(Debug)]
pub struct McpServers {
    /// The servers the client knows.
    pub config: McpServersConfig,
    /// The loopback endpoints of those servers: what the http chain may reach on loopback.
    pub loopback: LoopbackExemptions,
    /// What the load skipped, each line safe to print.
    pub warnings: Vec<String>,
}

/// The client's bounds under the `mcp:` block `config`.
pub fn client_limits(config: &McpConfig) -> McpClientLimits {
    McpClientLimits {
        request_timeout: Duration::from_secs(config.request_timeout_sec),
        startup_timeout: Duration::from_secs(config.startup_timeout_sec),
        max_result_bytes: config.max_result_bytes,
        ..McpClientLimits::default()
    }
}

/// The http executor's configuration: it allows a request the client's request timeout (the
/// executor's own default would cut a longer one short) and connects to the loopback
/// endpoints in `loopback`.
fn executor_config(
    limits: &McpClientLimits,
    loopback: LoopbackExemptions,
) -> ReqwestExecutorConfig {
    ReqwestExecutorConfig {
        timeout: limits.request_timeout,
        loopback_exemptions: loopback,
        ..ReqwestExecutorConfig::default()
    }
}

/// The cap-http security chain of the http servers, and the leak detector it shares with the
/// stdio transports. Its `security.*` tunables are read live off `config_provider`, as on the
/// daemon's other chains; `secrets` is the store it would resolve credential bindings from.
fn http_chain(
    secrets: Arc<SecretStore>,
    limits: &McpClientLimits,
    loopback: LoopbackExemptions,
    config_provider: Arc<dyn RuntimeConfigProvider>,
    event_bus: Arc<dyn EventBusEmit>,
) -> (Arc<dyn HttpSecurityChain>, Arc<dyn LeakDetector>) {
    let (leak, ssrf, rate) =
        crate::channels_boot::live_security_components(Some(Arc::clone(&config_provider)));
    let leak: Arc<dyn LeakDetector> = leak;
    let ssrf: Arc<dyn SsrfGuard> = Arc::new(LoopbackExemptSsrfGuard::new(ssrf, loopback.clone()));
    let executor = Arc::new(ReqwestHttpExecutor::from_config_with_dns_timeout_source(
        executor_config(limits, loopback),
        Arc::new(move || config_provider.current().security.ssrf.dns_timeout_ms),
    ));
    let chain = DefaultHttpSecurityChain::new(secrets, Arc::clone(&leak), ssrf, rate, executor)
        .with_event_bus(event_bus);
    (Arc::new(chain), leak)
}

/// A secret store that holds nothing: what the http chain is built on when no server needs a
/// secret.
fn empty_secret_store() -> Arc<SecretStore> {
    Arc::new(SecretStore::new(
        Zeroizing::new([0u8; 32]),
        Arc::new(InMemorySecretStorage::new()),
    ))
}

/// The gate of the `mcp-client` host functions: calls decided by `grant_check`, listings read
/// from the same grants in `grants`. The web family tools are decided by the `web` grant of
/// those grants, except in the `offline` web mode, where the gate holds no web grant and
/// withholds them from every agent (a listing reads grants, not the mode).
pub fn mcp_gate(
    grant_check: Arc<dyn GrantCheck>,
    grants: Arc<GrantStore>,
    web_mode: WebRunMode,
) -> McpGate {
    let web = (web_mode != WebRunMode::Offline).then(|| {
        McpWebGrant::new(
            Arc::clone(&grant_check),
            Arc::new(WebGrantReaderImpl::new(Arc::clone(&grants))),
        )
    });
    McpGate::new(grant_check, Arc::new(McpGrantReaderImpl::new(grants)), web)
}

/// What [`compose_mcp`] builds the MCP client from.
pub struct McpComposition<'a> {
    /// The server files read for this start ([`McpControlPlane::scan`]).
    pub servers: McpServerFiles,
    /// The `mcp:` block.
    pub config: &'a McpConfig,
    /// The registry the capability injector links guests from.
    pub registry: &'a dyn HostRegistry,
    /// The daemon's grant check, which decides calls.
    pub grant_check: Arc<dyn GrantCheck>,
    /// The grant store that check reads, which listings read too.
    pub grant_store: Arc<GrantStore>,
    /// The daemon's secret store, when one is open.
    pub secret_store: Option<Arc<SecretStore>>,
    /// Where the client and the host functions emit their `mcp.*` events, and the chain its
    /// `http.*` events.
    pub event_bus: Arc<dyn EventBusEmit>,
    /// The live runtime configuration (the chain's `security.*` tunables).
    pub config_provider: Arc<dyn RuntimeConfigProvider>,
    /// The web run mode.
    pub web_mode: WebRunMode,
    /// The daemon's runtime: stdio servers and the warm-up run on it.
    pub runtime: tokio::runtime::Handle,
    /// The root agent's id, whose grants say which servers the warm-up connects.
    pub root_agent_id: &'a str,
    /// The control plane the runtime reloads from.
    pub plane: McpControlPlane,
    /// Where skip and warm-up warnings go (`advance start` prints them on stderr).
    pub log: LogHandle,
}

/// Build the MCP client and register the seven `mcp-client` host functions under `mcp`.
/// Never fails: each server that cannot serve is skipped with a warning on stderr, and with no
/// server at all the host functions are still registered, so a guest that declares `mcp`
/// links.
pub fn compose_mcp(parts: McpComposition<'_>) -> Arc<McpRuntime> {
    // One store for everything MCP reads secrets from: the daemon's when a server needs
    // secrets, an empty one otherwise.
    let live_secrets = parts.secret_store.clone();
    let secret_store = match live_secrets.as_ref() {
        Some(store) if parts.servers.need_secrets() => Some(Arc::clone(store)),
        _ => None,
    };
    let manifest_secrets = secret_store
        .as_ref()
        .map(|store| CapSecretsSecretStore::new(Arc::clone(store)));
    let servers = parts.servers.into_servers(
        manifest_secrets
            .as_ref()
            .map(|secrets| secrets as &dyn ManifestSecrets),
    );
    for warning in &servers.warnings {
        parts.log.err(
            log_keys::MCP_WARN,
            format!("advance: WARN mcp: {warning}"),
        );
    }

    let limits = client_limits(parts.config);
    let (chain, leak) = http_chain(
        secret_store.unwrap_or_else(empty_secret_store),
        &limits,
        servers.loopback,
        parts.config_provider,
        Arc::clone(&parts.event_bus),
    );
    let client = Arc::new(
        McpClient::new(Arc::new(servers.config), leak, Some(chain))
            .with_limits(limits)
            .with_runtime(parts.runtime.clone())
            .with_event_bus(Arc::clone(&parts.event_bus)),
    );
    let gate = mcp_gate(parts.grant_check, parts.grant_store, parts.web_mode);
    register_mcp_client(
        parts.registry,
        Arc::clone(&client),
        gate.clone(),
        parts.event_bus,
    );

    let runtime = Arc::new(McpRuntime {
        client,
        gate,
        runtime: parts.runtime,
        warnings: servers.warnings,
        plane: parts.plane,
        secret_store: live_secrets,
        log: parts.log,
    });
    if parts.config.warm_tool_cache {
        runtime.warm_tool_cache(parts.root_agent_id);
    }
    runtime
}

/// The daemon's MCP client and the gate of its host functions.
///
/// Dropping the last handle shuts the client down ([`shutdown`](Self::shutdown)): keep one for
/// as long as agents run.
pub struct McpRuntime {
    client: Arc<McpClient>,
    gate: McpGate,
    runtime: tokio::runtime::Handle,
    warnings: Vec<String>,
    plane: McpControlPlane,
    secret_store: Option<Arc<SecretStore>>,
    log: LogHandle,
}

impl McpRuntime {
    /// The client the host functions call.
    pub fn client(&self) -> &Arc<McpClient> {
        &self.client
    }

    /// The gate that decides the host functions' calls and filters their listings.
    pub fn gate(&self) -> &McpGate {
        &self.gate
    }

    /// What the load skipped when the daemon started, as printed on stderr.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Connect, in the background, every configured server one of `agent_id`'s `mcp` grants
    /// reaches and list its tools, which fills the client's tool cache. A few servers are
    /// listed at a time (`WARM_UP_CONCURRENCY`), each within the client's timeouts; a server
    /// that fails is reported on stderr and connected again on its next use. Returns at once.
    pub fn warm_tool_cache(&self, agent_id: &str) {
        let scopes = self.gate.scopes(agent_id);
        let client = Arc::clone(&self.client);
        let log = self.log.clone();
        self.runtime.spawn(async move {
            let mut servers = client
                .list_servers()
                .await
                .into_iter()
                .map(|server| server.id)
                .filter(|id| scopes.reaches_server(id));
            let mut listings = tokio::task::JoinSet::new();
            loop {
                while listings.len() < WARM_UP_CONCURRENCY {
                    let Some(server_id) = servers.next() else {
                        break;
                    };
                    let client = Arc::clone(&client);
                    let log = log.clone();
                    listings.spawn(async move {
                        if let Err(e) = client.list_tools(None, &server_id).await {
                            // A client shut down meanwhile fails every listing: say nothing.
                            if !client.is_shut_down() {
                                log.err(
                                    log_keys::MCP_LISTING_FAILED,
                                    format!(
                                        "advance: WARN mcp: the tools of server '{server_id}' \
                                         could not be listed: {}",
                                        printable(&e.message)
                                    ),
                                );
                            }
                        }
                    });
                }
                if listings.join_next().await.is_none() {
                    break;
                }
            }
        });
    }

    /// Close every MCP connection now and stop the stdio servers' process groups; no server
    /// is connected afterwards, and every later call fails
    /// ([`McpClient::shutdown`]).
    pub fn shutdown(&self) {
        self.client.shutdown();
    }

    /// Re-read the server files and swap them into the client. Connections of a
    /// removed or changed server are closed and their tool-cache entries
    /// dropped. Listings of added or changed servers run on the daemon runtime
    /// and are not awaited here.
    pub fn reload(&self) {
        let files = self.plane.scan();
        let manifest_secrets = self
            .secret_store
            .as_ref()
            .map(|store| CapSecretsSecretStore::new(Arc::clone(store)));
        let servers = files.into_servers(
            manifest_secrets
                .as_ref()
                .map(|secrets| secrets as &dyn ManifestSecrets),
        );
        for warning in &servers.warnings {
            self.log.err(
                log_keys::MCP_WARN,
                format!("advance: WARN mcp: {warning}"),
            );
        }
        let reconfig = self.client.replace_config(servers.config);
        for id in reconfig.added.iter().chain(reconfig.changed.iter()) {
            let client = Arc::clone(&self.client);
            let id = id.clone();
            self.runtime.spawn(async move {
                let _ = client.list_tools(None, &id).await;
            });
        }
    }

    /// Delete pack-origin files whose origin pack is not installed, then
    /// [`reload`](Self::reload).
    pub fn drop_uninstalled_origins(&self, installed: &BTreeSet<String>) {
        self.plane.remove_origins_not_in(installed);
        self.reload();
    }
}

/// Persists a pack's MCP server as a file in the operator's servers directory.
pub struct ControlPlaneMcpSink {
    plane: McpControlPlane,
    runtime: Mutex<Option<Weak<McpRuntime>>>,
}

impl ControlPlaneMcpSink {
    /// A sink that writes under `plane`'s directory.
    pub fn new(plane: McpControlPlane) -> Self {
        Self {
            plane,
            runtime: Mutex::new(None),
        }
    }

    /// The runtime that reloads after a register or deregister. Absent: files
    /// are still written, and nothing is connected.
    pub fn bind_runtime(&self, runtime: Arc<McpRuntime>) {
        *self.runtime.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(&runtime));
    }

    fn reload(&self) {
        if let Some(runtime) = self
            .runtime
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(Weak::upgrade)
        {
            runtime.reload();
        }
    }

    fn path_for(&self, server_id: &str) -> PathBuf {
        self.plane
            .dir()
            .join(format!("{server_id}{SERVER_FILE_SUFFIX}"))
    }
}

impl McpEntrySink for ControlPlaneMcpSink {
    fn register(&self, registration: McpRegistration) -> Result<McpRegister, PackBridgeError> {
        let id = registration.server_id.clone();
        let path = self.path_for(&id);
        let body = render_server_file(&registration);
        if let Ok(existing) = std::fs::read_to_string(&path) {
            match parse_mcp_server_manifest_str(&existing) {
                Ok(manifest) => match &manifest.origin {
                    None => {
                        return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                            reason: format!(
                                "mcp-server '{id}' already exists as an operator file; a \
                                     pack may not replace it"
                            ),
                        }));
                    }
                    Some(origin)
                        if origin.pack != registration.origin_pack
                            || origin.config_ref != registration.origin_ref =>
                    {
                        return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                            reason: format!(
                                "mcp-server '{id}' already belongs to pack {}",
                                origin.pack
                            ),
                        }));
                    }
                    Some(_) if existing_matches(&manifest, &registration) => {
                        return Ok(McpRegister::Unchanged(id));
                    }
                    Some(_) => {
                        return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                            reason: format!(
                                "mcp-server '{id}' is already registered with different \
                                     content"
                            ),
                        }));
                    }
                },
                Err(e) => {
                    return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                        reason: format!("mcp-server '{id}' already exists and cannot be read: {e}"),
                    }));
                }
            }
        }
        std::fs::create_dir_all(self.plane.dir()).map_err(|source| {
            PackBridgeError::Pack(PackError::Io {
                path: self.plane.dir().to_path_buf(),
                source,
            })
        })?;
        let tmp = self.plane.dir().join(format!(".{id}.yaml.tmp"));
        std::fs::write(&tmp, body.as_bytes()).map_err(|source| {
            PackBridgeError::Pack(PackError::Io {
                path: tmp.clone(),
                source,
            })
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path).map_err(|source| {
            PackBridgeError::Pack(PackError::Io {
                path: path.clone(),
                source,
            })
        })?;
        self.reload();
        Ok(McpRegister::Created(id))
    }

    fn deregister(&self, server_id: &str) -> Result<(), PackBridgeError> {
        let path = self.path_for(server_id);
        match std::fs::read_to_string(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(PackBridgeError::Pack(PackError::Io {
                    path: path.clone(),
                    source,
                }));
            }
            Ok(text) => {
                let manifest =
                    parse_mcp_server_manifest_str(&text).map_err(PackBridgeError::Pack)?;
                if manifest.origin.is_none() {
                    return Err(PackBridgeError::Pack(PackError::ConstraintViolation {
                        reason: format!(
                            "mcp-server '{server_id}' is an operator file and is not removed \
                             by a pack"
                        ),
                    }));
                }
            }
        }
        std::fs::remove_file(&path)
            .map_err(|source| PackBridgeError::Pack(PackError::Io { path, source }))?;
        self.reload();
        Ok(())
    }
}

fn existing_matches(manifest: &McpServerManifest, registration: &McpRegistration) -> bool {
    manifest.server_id == registration.server_id
        && manifest.description == registration.description
        && manifest.transport == registration.transport
        && manifest.secret_refs == registration.secret_refs
}

fn render_server_file(registration: &McpRegistration) -> String {
    let mut yaml = format!("server-id: {}\n", registration.server_id);
    if !registration.description.is_empty() {
        yaml.push_str(&format!(
            "description: {}\n",
            yaml_string(&registration.description)
        ));
    }
    match &registration.transport {
        McpTransportDecl::Stdio { command, args } => {
            yaml.push_str("transport:\n  kind: stdio\n");
            yaml.push_str(&format!("  command: {}\n", yaml_string(command)));
            if !args.is_empty() {
                yaml.push_str("  args:\n");
                for arg in args {
                    yaml.push_str(&format!("    - {}\n", yaml_string(arg)));
                }
            }
        }
        McpTransportDecl::Http { endpoint_url } => {
            yaml.push_str("transport:\n  kind: http\n");
            yaml.push_str(&format!("  endpoint-url: {}\n", yaml_string(endpoint_url)));
        }
    }
    if !registration.secret_refs.is_empty() {
        yaml.push_str("secret-refs:\n");
        for (env, key) in &registration.secret_refs {
            yaml.push_str(&format!("  {env}: {}\n", yaml_string(key)));
        }
    }
    yaml.push_str("origin:\n");
    yaml.push_str(&format!(
        "  pack: {}\n  config-ref: {}\n",
        yaml_string(&registration.origin_pack),
        yaml_string(&registration.origin_ref)
    ));
    yaml
}

/// A YAML double-quoted scalar, so a value with `:`, `#` or a newline cannot
/// change the document's shape.
fn yaml_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Drop for McpRuntime {
    fn drop(&mut self) {
        self.client.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
    use advance_shared_types::capability::{CapParams, GrantDecision};
    use advance_shared_types::event::Event;
    use cap_grant::{
        Grant, GrantId, GrantIssuer, GrantProvenance, GrantSqliteIndex, GrantStatus, GrantTtl,
    };

    use super::*;
    use crate::pack_production::ClosureSecretStore;

    const STDIO: &str = "transport:\n  kind: stdio\n  command: /bin/true\n";

    fn plane(workspace: &Path) -> McpControlPlane {
        McpControlPlane::new(workspace, &McpConfig::default())
    }

    /// Write `<workspace>/.advance/mcp-servers/<name>` holding `body`.
    fn server_file(workspace: &Path, name: &str, body: &str) -> PathBuf {
        let dir = workspace.join(".advance/mcp-servers");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    fn stdio_server(workspace: &Path, id: &str) {
        server_file(
            workspace,
            &format!("{id}.yaml"),
            &format!("server-id: {id}\n{STDIO}"),
        );
    }

    fn http_server(workspace: &Path, id: &str, endpoint: &str) {
        server_file(
            workspace,
            &format!("{id}.yaml"),
            &format!("server-id: {id}\ntransport:\n  kind: http\n  endpoint-url: {endpoint}\n"),
        );
    }

    fn one_warning<'a>(warnings: &'a [String], about: &str) -> &'a str {
        let matching: Vec<&String> = warnings.iter().filter(|w| w.contains(about)).collect();
        assert_eq!(
            matching.len(),
            1,
            "one warning about {about:?}: {warnings:?}"
        );
        matching[0]
    }

    #[test]
    fn a_home_without_the_directory_has_no_server_and_no_warning() {
        let ws = tempfile::tempdir().unwrap();
        let files = plane(ws.path()).scan();
        assert!(files.server_ids().is_empty());
        assert!(files.warnings().is_empty());
        assert!(!files.need_secrets());
        assert!(
            !ws.path().join(".advance").exists(),
            "a scan creates nothing"
        );

        let servers = files.into_servers(None);
        assert!(servers.config.is_empty());
        assert!(servers.loopback.is_empty());
        assert!(servers.warnings.is_empty());
    }

    #[test]
    fn server_files_load_in_id_order_and_other_entries_are_ignored() {
        let ws = tempfile::tempdir().unwrap();
        stdio_server(ws.path(), "zeta");
        http_server(ws.path(), "alpha", "https://mcp.example.com/mcp");
        server_file(ws.path(), "README.md", "not a server\n");
        server_file(ws.path(), "notes.yml", "server-id: notes\n");
        server_file(ws.path(), "alpha.yaml.tmp", "server-id: alpha\n");
        // Hidden entries, whatever they hold.
        server_file(ws.path(), "._alpha.yaml", "\u{0}\u{5}\u{16}\u{7}");
        server_file(ws.path(), ".yaml", &format!("server-id: hidden\n{STDIO}"));
        server_file(
            ws.path(),
            ".hidden.yaml",
            &format!("server-id: .hidden\n{STDIO}"),
        );
        std::fs::create_dir(ws.path().join(".advance/mcp-servers/nested")).unwrap();

        let control = plane(ws.path());
        assert_eq!(control.dir(), ws.path().join(".advance/mcp-servers"));
        let files = control.scan();
        assert_eq!(files.server_ids(), ["alpha", "zeta"]);
        assert!(files.warnings().is_empty(), "{:?}", files.warnings());

        let servers = files.into_servers(None);
        assert!(servers.warnings.is_empty(), "{:?}", servers.warnings);
        assert_eq!(servers.config.len(), 2);
        let zeta = servers.config.get("zeta").unwrap();
        assert!(zeta.tool_patterns.is_none() && zeta.tool_schemas.is_empty());
        match &zeta.transport {
            McpTransportSpec::Stdio { command, args, env } => {
                assert_eq!(command, "/bin/true");
                assert!(args.is_empty() && env.is_empty());
            }
            other => panic!("zeta is a stdio server: {other:?}"),
        }
    }

    // Each file that cannot serve is skipped with one warning; the good server next to them
    // still loads.
    #[test]
    fn a_file_that_cannot_serve_is_skipped_with_a_warning() {
        let ws = tempfile::tempdir().unwrap();
        stdio_server(ws.path(), "good");
        server_file(ws.path(), "broken.yaml", "server-id: [unclosed\n");
        server_file(
            ws.path(),
            "extra-key.yaml",
            &format!("server-id: extra-key\n{STDIO}tool-patterns: [a]\n"),
        );
        server_file(
            ws.path(),
            "renamed.yaml",
            &format!("server-id: original\n{STDIO}"),
        );
        server_file(
            ws.path(),
            "plain-http.yaml",
            "server-id: plain-http\ntransport:\n  kind: http\n  endpoint-url: http://mcp.example.com/mcp\n",
        );
        server_file(
            ws.path(),
            "big.yaml",
            &format!(
                "server-id: big\n{STDIO}# {}\n",
                "x".repeat(MAX_MCP_SERVER_YAML_BYTES as usize)
            ),
        );
        server_file(ws.path(), "binary.yaml", "");
        std::fs::write(
            ws.path().join(".advance/mcp-servers/binary.yaml"),
            [0xff, 0xfe, 0x00],
        )
        .unwrap();
        std::fs::create_dir(ws.path().join(".advance/mcp-servers/dir.yaml")).unwrap();

        let files = plane(ws.path()).scan();
        assert_eq!(files.server_ids(), ["good"]);
        let warnings = files.warnings();
        for (name, why) in [
            ("\"broken.yaml\"", "yaml"),
            ("\"extra-key.yaml\"", "tool-patterns"),
            (
                "\"renamed.yaml\"",
                "named after its server ('original.yaml')",
            ),
            ("\"plain-http.yaml\"", "loopback"),
            ("\"big.yaml\"", "larger than"),
            ("\"binary.yaml\"", "UTF-8"),
            ("\"dir.yaml\"", "not a regular file"),
        ] {
            let warning = one_warning(warnings, name);
            assert!(warning.contains("is skipped"), "{warning}");
            assert!(warning.contains(why), "{name}: {warning}");
        }
        assert_eq!(warnings.len(), 7, "{warnings:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_or_a_fifo_is_refused_without_being_read() {
        let ws = tempfile::tempdir().unwrap();
        stdio_server(ws.path(), "good");
        let dir = ws.path().join(".advance/mcp-servers");
        // A valid server file outside the directory, reached through a symlink in it.
        let outside = ws.path().join("linked.yaml");
        std::fs::write(&outside, format!("server-id: linked\n{STDIO}")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("linked.yaml")).unwrap();
        // A FIFO nobody writes to: opening it for reading would wait for ever.
        let made = std::process::Command::new("mkfifo")
            .arg(dir.join("pipe.yaml"))
            .status()
            .expect("mkfifo runs");
        assert!(made.success());

        let files = plane(ws.path()).scan();
        assert_eq!(files.server_ids(), ["good"]);
        let symlink = one_warning(files.warnings(), "\"linked.yaml\"");
        assert!(symlink.contains("symbolic link"), "{symlink}");
        let fifo = one_warning(files.warnings(), "\"pipe.yaml\"");
        assert!(fifo.contains("not a regular file"), "{fifo}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_read() {
        let ws = tempfile::tempdir().unwrap();
        let elsewhere = ws.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(
            elsewhere.join("srv.yaml"),
            format!("server-id: srv\n{STDIO}"),
        )
        .unwrap();
        std::fs::create_dir_all(ws.path().join(".advance")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ws.path().join(".advance/mcp-servers")).unwrap();

        let files = plane(ws.path()).scan();
        assert!(files.server_ids().is_empty());
        let warning = one_warning(files.warnings(), "is not a directory");
        assert!(warning.contains("no server file is read"), "{warning}");
    }

    // `.` and `..` are valid server ids, and as path components they would leave the
    // directory. No file can carry them: the file of the server `..` would be the hidden
    // `...yaml`, and a file under another name that claims the id is not that server. The
    // loader reads the entries it lists and nothing else.
    #[test]
    fn a_server_id_is_never_made_into_a_path() {
        let ws = tempfile::tempdir().unwrap();
        server_file(ws.path(), "...yaml", &format!("server-id: \"..\"\n{STDIO}"));
        server_file(ws.path(), "..yaml", &format!("server-id: \".\"\n{STDIO}"));
        server_file(ws.path(), "a.yaml", &format!("server-id: \"..\"\n{STDIO}"));
        // Where `<dir>/<id>.yaml` would point for the id `../mcp-servers`.
        std::fs::write(
            ws.path().join(".advance/mcp-servers.yaml"),
            format!("server-id: mcp-servers\n{STDIO}"),
        )
        .unwrap();

        let files = plane(ws.path()).scan();
        assert!(files.server_ids().is_empty());
        assert_eq!(files.warnings().len(), 1, "{:?}", files.warnings());
        let warning = one_warning(files.warnings(), "\"a.yaml\"");
        assert!(
            warning.contains("named after its server ('...yaml')"),
            "{warning}"
        );
        assert!(files.into_servers(None).config.is_empty());
    }

    #[test]
    fn stdio_servers_are_refused_when_stdio_is_not_allowed() {
        let ws = tempfile::tempdir().unwrap();
        server_file(
            ws.path(),
            "local.yaml",
            &format!("server-id: local\n{STDIO}secret-refs:\n  TOKEN: local-token\n"),
        );
        http_server(ws.path(), "remote", "https://mcp.example.com/mcp");
        let config = McpConfig {
            allow_stdio: false,
            ..McpConfig::default()
        };
        let files = McpControlPlane::new(ws.path(), &config).scan();
        assert_eq!(files.server_ids(), ["remote"]);
        let warning = one_warning(files.warnings(), "\"local.yaml\"");
        assert!(warning.contains("mcp.allow-stdio: false"), "{warning}");
        assert!(
            !files.need_secrets(),
            "a refused server asks for no secret store"
        );
    }

    #[test]
    fn a_relative_stdio_command_loads_with_a_warning() {
        let ws = tempfile::tempdir().unwrap();
        server_file(
            ws.path(),
            "tools.yaml",
            "server-id: tools\ntransport:\n  kind: stdio\n  command: npx\n  args: [some-server]\n",
        );
        let files = plane(ws.path()).scan();
        assert_eq!(files.server_ids(), ["tools"]);
        let warning = one_warning(files.warnings(), "server 'tools'");
        assert!(warning.contains("not an absolute path"), "{warning}");
    }

    #[test]
    fn the_servers_dir_follows_the_config() {
        let ws = tempfile::tempdir().unwrap();
        let dir = ws.path().join(".advance/ops/mcp");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("srv.yaml"), format!("server-id: srv\n{STDIO}")).unwrap();
        stdio_server(ws.path(), "default-dir");
        let config = McpConfig {
            servers_dir: ".advance/ops/mcp".into(),
            ..McpConfig::default()
        };
        config.validate().expect("a directory inside .advance");
        let control = McpControlPlane::new(ws.path(), &config);
        assert_eq!(control.dir(), dir);
        assert_eq!(control.scan().server_ids(), ["srv"]);
    }

    // Past the server cap nothing more is read, and the scan says how much it left.
    #[test]
    fn a_crowded_directory_is_read_up_to_the_server_cap() {
        let ws = tempfile::tempdir().unwrap();
        for n in 0..cap_mcp::MAX_SERVERS + 3 {
            stdio_server(ws.path(), &format!("s{n:04}"));
        }
        let files = plane(ws.path()).scan();
        let ids = files.server_ids();
        assert_eq!(ids.len(), cap_mcp::MAX_SERVERS);
        assert_eq!((ids[0], ids[ids.len() - 1]), ("s0000", "s0127"));
        let warning = one_warning(files.warnings(), "more than 128 servers");
        assert!(
            warning.contains("3 files are not read, from \"s0128.yaml\" on"),
            "{warning}"
        );
        let servers = files.into_servers(None);
        assert_eq!(servers.config.len(), cap_mcp::MAX_SERVERS);
    }

    #[test]
    fn warnings_are_bounded_and_safe_to_print() {
        let ws = tempfile::tempdir().unwrap();
        for n in 0..MAX_WARNINGS + 5 {
            server_file(ws.path(), &format!("bad{n:03}.yaml"), "nonsense\n");
        }
        // A file name with a control character, quoted in its warning.
        server_file(ws.path(), "a\u{1b}[31m.yaml", "nonsense\n");
        let files = plane(ws.path()).scan();
        assert_eq!(files.warnings().len(), MAX_WARNINGS);
        assert!(
            files.warnings()[0].contains("31m.yaml"),
            "{:?}",
            files.warnings()[0]
        );
        assert!(files
            .warnings()
            .iter()
            .all(|w| !w.chars().any(char::is_control) && w.len() <= MAX_WARNING_BYTES + 4));
        let lines = files.into_servers(None).warnings;
        assert_eq!(lines.len(), MAX_WARNINGS + 1);
        assert_eq!(lines[MAX_WARNINGS], "6 more warnings are not shown");

        assert_eq!(printable("a\nb\u{1b}c"), "a?b?c");
        let long = printable(&"é".repeat(MAX_WARNING_BYTES));
        assert!(long.len() <= MAX_WARNING_BYTES + '…'.len_utf8() && long.ends_with('…'));
    }

    #[test]
    fn secret_refs_become_the_environment_of_a_stdio_server() {
        let ws = tempfile::tempdir().unwrap();
        server_file(
            ws.path(),
            "local.yaml",
            &format!(
                "server-id: local\n{STDIO}secret-refs:\n  API_TOKEN: local-token\n  \
                 OTHER: other-key\n"
            ),
        );
        server_file(
            ws.path(),
            "lacking.yaml",
            &format!("server-id: lacking\n{STDIO}secret-refs:\n  API_TOKEN: absent-key\n"),
        );
        stdio_server(ws.path(), "plain");
        let secrets = ClosureSecretStore::new(|key| match key {
            "local-token" => Some("t0ken".to_string()),
            "other-key" => Some("0ther".to_string()),
            _ => None,
        });

        let files = plane(ws.path()).scan();
        assert!(files.need_secrets());
        let servers = files.into_servers(Some(&secrets));
        match &servers.config.get("local").unwrap().transport {
            McpTransportSpec::Stdio { env, .. } => assert_eq!(
                env,
                &BTreeMap::from([
                    ("API_TOKEN".to_string(), "t0ken".to_string()),
                    ("OTHER".to_string(), "0ther".to_string()),
                ])
            ),
            other => panic!("local is a stdio server: {other:?}"),
        }
        assert!(servers.config.get("plain").is_ok());
        assert!(servers.config.get("lacking").is_err());
        let warning = one_warning(&servers.warnings, "server 'lacking' is skipped");
        assert!(
            warning.contains("\"absent-key\"") && warning.contains("API_TOKEN"),
            "{warning}"
        );
        assert!(
            servers.warnings.iter().all(|w| !w.contains("t0ken")),
            "a warning never holds a secret"
        );

        // Without a store, every server that needs secrets is left out, and only those.
        let servers = plane(ws.path()).scan().into_servers(None);
        assert_eq!(
            servers
                .config
                .list_servers()
                .map(|e| e.server_id.as_str())
                .collect::<Vec<_>>(),
            ["plain"]
        );
        for id in ["local", "lacking"] {
            let warning = one_warning(&servers.warnings, &format!("server '{id}' is skipped"));
            assert!(warning.contains("secret store is not open"), "{warning}");
        }
    }

    // An http server is allowlisted on its origin, and exempt from the loopback rule on
    // exactly its own host and port when it is on loopback.
    #[test]
    fn http_servers_are_allowlisted_on_their_origin_and_loopback_ones_exempted() {
        let ws = tempfile::tempdir().unwrap();
        http_server(ws.path(), "remote", "https://mcp.example.com/v1/mcp?x=1");
        http_server(ws.path(), "local", "http://127.0.0.1:8931/mcp");
        http_server(ws.path(), "named", "http://localhost:9000/mcp");
        http_server(ws.path(), "v6", "http://[::1]:9/mcp");
        http_server(ws.path(), "lan", "https://10.0.0.5/mcp");
        let files = plane(ws.path()).scan();
        assert!(!files.need_secrets());
        let servers = files.into_servers(None);
        assert!(servers.warnings.is_empty(), "{:?}", servers.warnings);

        let capability = |id: &str| match &servers.config.get(id).unwrap().transport {
            McpTransportSpec::Http {
                endpoint_url,
                capability,
            } => (endpoint_url.clone(), capability.clone()),
            other => panic!("{id} is an http server: {other:?}"),
        };
        for (id, origin) in [
            ("remote", "https://mcp.example.com/"),
            ("local", "http://127.0.0.1:8931/"),
            ("named", "http://localhost:9000/"),
            ("v6", "http://[::1]:9/"),
            ("lan", "https://10.0.0.5/"),
        ] {
            let (endpoint, capability) = capability(id);
            assert_eq!(capability.allowlist.patterns, [origin], "{id}");
            assert!(capability.allowlist.matches(&endpoint), "{id}");
            assert!(capability.credentials.is_empty(), "{id}");
            assert_eq!(capability.component_id, id);
        }
        let (_, local) = capability("local");
        assert!(local.allowlist.matches("http://127.0.0.1:8931/other"));
        for elsewhere in [
            "http://127.0.0.1:8932/mcp",
            "http://127.0.0.1/mcp",
            "https://127.0.0.1:8931/mcp",
            "http://localhost:8931/mcp",
            "http://127.0.0.1:8931@evil.example.com/mcp",
        ] {
            assert!(!local.allowlist.matches(elsewhere), "{elsewhere}");
        }
        let (_, remote) = capability("remote");
        assert!(!remote
            .allowlist
            .matches("https://mcp.example.com:8443/v1/mcp"));
        assert!(!remote.allowlist.matches("http://mcp.example.com/v1/mcp"));

        // Loopback is exempt on the configured endpoints only; no other range is.
        for exempt in [
            "http://127.0.0.1:8931/mcp",
            "http://localhost:9000/mcp",
            "http://[::1]:9/mcp",
        ] {
            assert!(servers.loopback.covers(exempt), "{exempt}");
        }
        for forbidden in [
            "http://127.0.0.1:9000/mcp",
            "http://localhost:8931/mcp",
            "http://127.0.0.1/mcp",
            "https://10.0.0.5/mcp",
            "https://mcp.example.com/v1/mcp",
        ] {
            assert!(!servers.loopback.covers(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn the_client_and_its_executor_take_their_bounds_from_the_config() {
        let config = McpConfig {
            request_timeout_sec: 120,
            startup_timeout_sec: 45,
            max_result_bytes: 65_536,
            ..McpConfig::default()
        };
        let limits = client_limits(&config);
        assert_eq!(limits.request_timeout, Duration::from_secs(120));
        assert_eq!(limits.startup_timeout, Duration::from_secs(45));
        assert_eq!(limits.max_result_bytes, 65_536);
        assert_eq!(
            client_limits(&McpConfig::default()),
            McpClientLimits::default()
        );

        // The executor's own default would cut a request at 30 s.
        let mut loopback = LoopbackExemptions::none();
        assert!(loopback.allow_endpoint("http://127.0.0.1:8931/mcp"));
        let executor = executor_config(&limits, loopback.clone());
        assert_eq!(executor.timeout, Duration::from_secs(120));
        assert_eq!(executor.loopback_exemptions, loopback);
        assert!(executor.dns_overrides.is_empty());
    }

    struct NullBus;
    impl EventBusEmit for NullBus {
        fn emit(&self, _: Event) {}
    }

    /// Allows everything, recording the capability of each request.
    #[derive(Default)]
    struct RecordingCheck(std::sync::Mutex<Vec<String>>);
    impl GrantCheck for RecordingCheck {
        fn check(&self, _: &str, capability: &str, _: &str, _: &CapParams) -> GrantDecision {
            self.0.lock().unwrap().push(capability.to_string());
            GrantDecision::Allow
        }
    }

    fn grant_store() -> Arc<GrantStore> {
        let sqlite: Arc<dyn SqliteIndexHandle> =
            Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("sqlite"));
        let index = GrantSqliteIndex::new(sqlite);
        index.ensure_schema().expect("grant schema");
        Arc::new(GrantStore::new(index, Arc::new(NullBus)))
    }

    fn grant(store: &GrantStore, grantee: &str, capability: &str) {
        store
            .insert(Grant {
                id: GrantId::new(format!("static:{grantee}:{capability}")),
                grantee: grantee.to_string(),
                capability: capability.to_string(),
                params: Vec::new(),
                ttl: GrantTtl::Persistent,
                issuer: GrantIssuer::Config,
                provenance: GrantProvenance::StaticConfig,
                status: GrantStatus::Active,
                created_at: chrono::Utc::now(),
                expires_at: None,
            })
            .expect("grant");
    }

    fn tool(name: &str) -> cap_mcp::McpToolInfo {
        cap_mcp::McpToolInfo {
            name: name.into(),
            description: String::new(),
            server_id: "srv".into(),
            input_schema: None,
        }
    }

    // In every web mode but `offline` the gate decides the web family tools by the `web`
    // grant, for a call and for a listing alike; offline it withholds them from both.
    #[test]
    fn the_web_grant_is_bound_unless_the_web_mode_is_offline() {
        let store = grant_store();
        grant(&store, "root", "mcp");
        grant(&store, "root", "web");
        grant(&store, "plain", "mcp");
        let listing = || vec![tool("echo"), tool("web.search")];
        let names = |tools: Vec<cap_mcp::McpToolInfo>| -> Vec<String> {
            tools.into_iter().map(|t| t.name).collect()
        };

        for mode in [
            WebRunMode::Standard,
            WebRunMode::Privacy,
            WebRunMode::Enterprise,
        ] {
            let check = Arc::new(RecordingCheck::default());
            let gate = mcp_gate(check.clone(), store.clone(), mode);
            assert!(gate.check_web("root", "f").is_ok(), "{mode:?}");
            assert_eq!(*check.0.lock().unwrap(), ["web"], "{mode:?}");
            let scopes = gate.scopes("root");
            assert_eq!(
                names(gate.visible_tools("root", &scopes, false, listing())),
                ["echo", "web.search"],
                "{mode:?}"
            );
            // An agent without the `web` grant is not shown them.
            let scopes = gate.scopes("plain");
            assert_eq!(
                names(gate.visible_tools("plain", &scopes, false, listing())),
                ["echo"],
                "{mode:?}"
            );
        }

        let check = Arc::new(RecordingCheck::default());
        let gate = mcp_gate(check.clone(), store.clone(), WebRunMode::Offline);
        assert!(gate.check_web("root", "f").is_err());
        assert!(
            check.0.lock().unwrap().is_empty(),
            "offline, no grant is asked about the web family"
        );
        let scopes = gate.scopes("root");
        assert_eq!(
            names(gate.visible_tools("root", &scopes, false, listing())),
            ["echo"]
        );
    }

    // The listing reads the grants of the store the gate was given: an agent's scopes follow
    // its `mcp` grant there.
    #[test]
    fn the_gate_lists_from_the_grant_store_it_was_given() {
        let store = grant_store();
        grant(&store, "root", "mcp");
        let gate = mcp_gate(
            Arc::new(RecordingCheck::default()),
            store,
            WebRunMode::Standard,
        );
        assert!(gate.scopes("root").reaches_server("srv"));
        assert!(!gate.scopes("someone-else").reaches_server("srv"));
    }

    fn registration(id: &str, pack: &str) -> McpRegistration {
        McpRegistration {
            server_id: id.into(),
            description: "d".into(),
            transport: McpTransportDecl::Http {
                endpoint_url: "https://mcp.example.com/mcp".into(),
            },
            secret_refs: BTreeMap::new(),
            origin_pack: pack.into(),
            origin_ref: format!("{pack}/mcp-servers/{id}"),
        }
    }

    #[test]
    fn the_control_plane_sink_is_idempotent_and_refuses_a_collision() {
        let ws = tempfile::tempdir().unwrap();
        let sink = ControlPlaneMcpSink::new(plane(ws.path()));
        let first = sink.register(registration("srv", "p@1.0.0")).unwrap();
        assert!(first.created());
        let body =
            std::fs::read_to_string(ws.path().join(".advance/mcp-servers/srv.yaml")).unwrap();
        assert!(body.contains("origin:"));
        assert!(body.contains("p@1.0.0"));
        assert!(!body.contains("secret:"));
        let again = sink.register(registration("srv", "p@1.0.0")).unwrap();
        assert!(!again.created());
        let other = sink.register(registration("srv", "q@1.0.0"));
        assert!(other.is_err(), "{other:?}");
        sink.deregister("srv").unwrap();
        assert!(!ws.path().join(".advance/mcp-servers/srv.yaml").exists());
    }

    #[test]
    fn stale_pack_origin_files_are_removed_when_the_pack_is_gone() {
        let ws = tempfile::tempdir().unwrap();
        let control = plane(ws.path());
        let sink = ControlPlaneMcpSink::new(control.clone());
        sink.register(registration("srv", "p@1.0.0")).unwrap();
        http_server(ws.path(), "ops", "https://mcp.example.com/ops");
        let mut installed = BTreeSet::new();
        assert_eq!(control.remove_origins_not_in(&installed), ["srv"]);
        assert!(!ws.path().join(".advance/mcp-servers/srv.yaml").exists());
        assert!(ws.path().join(".advance/mcp-servers/ops.yaml").exists());
        installed.insert("p@1.0.0".into());
        sink.register(registration("srv", "p@1.0.0")).unwrap();
        assert!(control.remove_origins_not_in(&installed).is_empty());
        assert!(ws.path().join(".advance/mcp-servers/srv.yaml").exists());
    }
}
