//! The MCP client of `advance start`: the operator's server files, the client built from
//! them, and the `mcp-client` host functions of an agent that declares `mcp`.
//!
//! All of it exists only when the root agent's `.agent/config.yaml` declares the `mcp`
//! capability. A home that does not declare it loads no server file, builds no client,
//! registers no host function and starts no server; it reads its server files only to remove
//! those of packs that are gone (below).
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
//!   [`MAX_MCP_SERVER_YAML_BYTES`], or one the schema refuses (among them a file with an
//!   `origin` block that binds `credentials`);
//! - a file whose name is not its `server-id` followed by `.yaml`;
//! - a `stdio` server while `mcp.allow-stdio` is `false`;
//! - an `http` server of a file with an `origin` block whose endpoint is on loopback;
//! - a server whose `secret-refs` or `credentials` name a secret the store does not hold, and
//!   every server that names a secret while no secret store is open;
//! - anything past [`cap_mcp::MAX_SERVERS`] servers.
//!
//! An absent directory is a home without servers. Entries that are not named `*.yaml`, and
//! hidden ones (a name starting with a dot), are not server files and are ignored. The loader
//! visits the directory's entries and compares each file's name with the id inside it; it
//! never builds a path from a server id.
//!
//! A pack's server is a file in the same directory, written by the pack's workflow
//! ([`ControlPlaneMcpSink`]) with an `origin` block naming the pack, and gone with the pack:
//! every pack event and every start of the daemon (for a root that declares `mcp`,
//! [`McpRuntime::start`], before the warm-up) sweep the files whose origin pack is not
//! installed ([`McpControlPlane::remove_origins_not_in`]), so a pack uninstalled while the
//! daemon was down (`advance pack uninstall` touches no server file) loses its servers before
//! an agent runs. The sweep reads each `*.yaml` entry for its `origin` block alone, hidden
//! names included and whatever the loader makes of the rest of the file; a file whose origin
//! cannot be read is reported and left. The sink writes only what the loader will read back
//! as the same server: an id of the shared grammar (no leading dot, so the file is never
//! hidden), a stdio transport only while `mcp.allow-stdio` is `true`, a body within the size
//! cap that re-parses to the registration, into the directory itself (never through a
//! symlink), through a fresh temporary file renamed into place.
//!
//! ## Transports
//!
//! A `stdio` server is a process the daemon starts on its first use: the file's `command` with
//! its `args`, in the working directory `cwd` (an absolute path; `/` when the file gives none).
//! Its environment ([`stdio_child_env`]) is built in three layers, each over the one before:
//! the daemon's own `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`
//! and `TZ`, those the daemon has set ([`STDIO_BASELINE_ENV`]); the file's `env` literals; its
//! `secret-refs`, each the value of a secret (a name is never both a literal and a secret).
//! Nothing else of the daemon's environment, its API keys and tokens among it, reaches a
//! server. A `command` that is a bare name is looked up on the `PATH` the server is started
//! with (the system's default search path when it has none), so give an absolute path: the
//! loader warns about a command that is not one.
//!
//! An `http` server is reached through a cap-http security chain that only the MCP client uses
//! (leak scans, credential injection, SSRF guard, rate limit, redirect re-check, `http.*`
//! events), whose executor allows a request the configured `mcp.request-timeout-sec`. The
//! server's allowlist is the origin of its endpoint: scheme, host and port.
//!
//! An endpoint on loopback (`localhost`, `127.0.0.0/8`, `::1`) is reachable although the
//! chain forbids loopback: the server file exempts exactly that host and port
//! ([`LoopbackExemptions`]), in the chain's guard and in its executor. Nothing else on
//! loopback becomes reachable, and an endpoint in any other forbidden range stays blocked.
//! Only the operator's files exempt anything: a pack's server on loopback is refused when the
//! pack registers it ([`crate::pack_bridges::PackMcpBridge`]), and the loader skips, with a
//! warning, a server file with an `origin` block whose endpoint is on loopback, however the
//! file got there. The exemptions are those of the files read when the daemon started: a
//! loopback server that appears on a later reload is refused with a warning until the daemon
//! restarts ([`McpServerFiles::keep_loopback_within`]).
//!
//! ## Secrets
//!
//! Two kinds of server file name secrets of the daemon's secret store. A `stdio` server's
//! `secret-refs` each name a secret that becomes one variable of the server's environment,
//! resolved when the file is read. An `http` server's `credentials` each bind a secret to a
//! position of every request the chain sends the server: `Authorization: Bearer`,
//! `Authorization: Basic` with a username, a header of the file's choosing, or a query
//! parameter. The server's entry holds those secrets' names only; the chain resolves each one
//! in the store at every request and puts the value into that request alone, never into a
//! file, an event or a log line. Only the operator's files bind credentials: a server file
//! with an `origin` block that binds some is refused by the schema, and a pack whose server
//! manifest binds some cannot register it ([`crate::pack_bridges::PackMcpBridge`]).
//!
//! When a server file names a secret either way, the daemon opens its secret store as it does
//! for `secrets` or `llm`, which needs the home's master key: without that key the daemon does
//! not start, as with those two. Otherwise `mcp` needs no master key. A server that names a
//! secret the store does not hold when its file is read is skipped with a warning, and so is
//! every server that names a secret while no store is open (one a reload brings to a daemon
//! that opened none).
//!
//! The http chain is built on the daemon's secret store whenever one is open, whatever opened
//! it, and on an empty store otherwise, so a credentialed server a reload admits resolves its
//! secrets as one read at start does. A request carries the value the store holds when the
//! request is made: the synchronized keychain is read at each request, so a value changed
//! there is sent from the next request on, without a restart; the file layout's store reads
//! `secrets.json` when the daemon starts (and keeps what the daemon itself stores), so a value
//! another process writes into the file, as `advance secrets set` does, is sent once the daemon
//! restarts.
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
//! ## What an agent is shown
//!
//! The root agent's prompt and the Client API's `GET /client/tools` read the MCP tools from
//! the client's tool cache through a [`LiveCallableInventory`], filtered by the same grant
//! readers. One read shows at most [`MCP_PROMPT_BUDGET_BYTES`] of tool text: the tools of the
//! operator's servers first, then those of trusted packs' servers, then the others, each
//! group by server id and tool name. The tools past it are counted, the prompt's tools
//! section closes with a line saying how many, and stderr says so once for each number. A
//! read lists in the background the servers the cache lacks, so the first read after the
//! daemon starts shows no MCP tools unless `mcp.warm-tool-cache` filled the cache.
//!
//! ## Shutdown
//!
//! A stdio server leads its own process group and would outlive the daemon.
//! [`McpRuntime::shutdown`] closes every connection and stops those groups; the daemon calls
//! it when it stops, and dropping the last handle to the runtime does the same.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use advance_pack_manager::mcp_server_manifest::MAX_MCP_SERVER_YAML_BYTES;
use advance_pack_manager::{
    parse_mcp_server_manifest_str, parse_mcp_server_origin_str, McpServerManifest,
    McpTransportDecl, PackError, SecretStore as ManifestSecrets,
};
use advance_runtime::config::{McpConfig, RuntimeConfigProvider};
use advance_runtime::host_registry::HostRegistry;
use advance_shared_types::capability::{McpToolEntry, McpToolsShown, ToolEntry};
use advance_shared_types::mcp::{is_valid_server_id, MAX_SERVER_ID_BYTES};
use advance_shared_types::security_validator::{
    Allowlist, CredentialPosition, HttpCapability, HttpSecurityChain, LeakDetector, SsrfGuard,
};
use advance_shared_types::traits::CallableInventoryReader;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use advance_shared_types::web_search::WebRunMode;
use cap_grant::{GrantStore, McpGrantReaderImpl, WebGrantReaderImpl};
use cap_http::{
    DefaultHttpSecurityChain, LoopbackExemptSsrfGuard, LoopbackExemptions, ReqwestExecutorConfig,
    ReqwestHttpExecutor,
};
use cap_mcp::{
    cut_description_to, register_mcp_client, McpClient, McpClientLimits, McpGate, McpScopes,
    McpServerEntry, McpServersConfig, McpToolInfo, McpTransportSpec, McpWebGrant,
    MAX_TOOL_DESCRIPTION_BYTES,
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

/// Most a sweep reads of one server file to find its `origin` block. Wider than the loader's
/// cap ([`MAX_MCP_SERVER_YAML_BYTES`]): a pack-origin file the loader skips for its size still
/// goes with its pack. A larger file is reported and left.
const MAX_SWEEP_FILE_BYTES: u64 = 1024 * 1024;

/// Most warnings one load keeps; further ones are counted.
const MAX_WARNINGS: usize = 64;

/// Longest warning printed, in bytes.
const MAX_WARNING_BYTES: usize = 512;

/// Servers whose tools the warm-up lists at the same time.
const WARM_UP_CONCURRENCY: usize = 4;

/// Most bytes of MCP tool text one read of a [`LiveCallableInventory`] hands an agent:
/// what Tier-2 renders, at most, of the MCP tools it shows (for each, the line
/// `- <server>__<tool>(<arguments>) — <description>`). The tools past it are left out
/// and counted, and the prompt's tools section closes with a line saying how many.
pub const MCP_PROMPT_BUDGET_BYTES: usize = 32 * 1024;

/// What a Tier-2 line adds around a tool's name, argument names and description: `- `,
/// `(`, `) — ` and the line end.
const PROMPT_LINE_FRAMING_BYTES: usize = "- ".len() + "(".len() + ") — ".len() + "\n".len();

/// What Tier-2 puts between two argument names.
const PROMPT_ARG_SEPARATOR_BYTES: usize = ", ".len();

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

    /// Delete the pack-origin server files whose origin pack is not in `installed`
    /// (`name@version`); operator files (no origin) are left. Every `*.yaml` entry of the
    /// directory is read for its `origin` block alone ([`parse_mcp_server_origin_str`]), as a
    /// regular file of at most [`MAX_SWEEP_FILE_BYTES`] and never through a symlink: hidden
    /// names included, and whatever the loader makes of the rest of the file, so a file the
    /// scan skips (a stdio server while `mcp.allow-stdio` is `false`, an oversize or mis-named
    /// file, one with a key the schema refuses, one past the server cap) goes with its pack
    /// too. A file whose origin cannot be read is reported in the sweep's warnings (bounded
    /// and safe to print, as the loader's are) and left. Each removal is logged. Like the
    /// loader, the sweep visits the entries it lists and never builds a path from a server id.
    ///
    /// A directory the loader cannot read either (absent, not a directory, a symlink, or
    /// unreadable) is not swept and adds no warning: no file in it can serve, and the loader
    /// reports it whenever it reads.
    pub fn remove_origins_not_in(&self, installed: &BTreeSet<String>) -> McpSweep {
        let mut sweep = McpSweep::default();
        let Ok(Some(entries)) = self.entries() else {
            return sweep;
        };
        let mut warnings = Warnings::default();
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|name| name.ends_with(SERVER_FILE_SUFFIX))
            .collect();
        names.sort();
        for name in names {
            let path = self.dir.join(&name);
            let text = match read_bounded_file(&path, MAX_SWEEP_FILE_BYTES) {
                Ok(text) => text,
                Err(reason) => {
                    warnings.push(format!("server file {name:?} is not swept: {reason}"));
                    continue;
                }
            };
            let origin = match parse_mcp_server_origin_str(&text) {
                Ok(Some(origin)) => origin,
                Ok(None) => continue,
                Err(e) => {
                    warnings.push(format!(
                        "server file {name:?} is not swept: its origin cannot be read: {}",
                        manifest_reason(e)
                    ));
                    continue;
                }
            };
            if installed.contains(&origin.pack) {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    self.log.err(
                        log_keys::MCP_STALE_FILE_REMOVED,
                        printable(&format!(
                            "advance: mcp: removed server file {}: its pack {} is not installed",
                            path.display(),
                            origin.pack
                        )),
                    );
                    sweep.removed.push(name);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warnings.push(format!(
                    "server file {name:?} of the uninstalled pack {} could not be removed: {e}",
                    origin.pack
                )),
            }
        }
        sweep.warnings = warnings.into_lines();
        sweep
    }

    /// The directory's entries: `Ok(None)` when there is no directory, `Err` with the warning
    /// to report when the entry is not a directory (a symlink is never followed) or cannot be
    /// read.
    fn entries(&self) -> Result<Option<std::fs::ReadDir>, String> {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "{:?} is not a directory: no server file is read",
                    self.dir
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{:?} cannot be read: {e}", self.dir)),
        }
        std::fs::read_dir(&self.dir)
            .map(Some)
            .map_err(|e| format!("{:?} cannot be read: {e}", self.dir))
    }

    /// Read every server file. Never fails: what cannot serve is left out, with a warning
    /// (see the module docs). No secret is read.
    pub fn scan(&self) -> McpServerFiles {
        let mut files = McpServerFiles::default();
        let entries = match self.entries() {
            Ok(Some(entries)) => entries,
            Ok(None) => return files,
            Err(warning) => {
                files.warnings.push(warning);
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
                                "server '{}': command {command:?} is not an absolute path; it \
                                 is looked up on the PATH the server is started with (the \
                                 file's own, else the daemon's, else the system's default \
                                 search path)",
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
        let manifest = parse_mcp_server_manifest_str(&text).map_err(manifest_reason)?;
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
        // Only a file the operator wrote may reach the host's loopback (and so exempt it).
        if let (Some(origin), McpTransportDecl::Http { endpoint_url }) =
            (&manifest.origin, &manifest.transport)
        {
            if LoopbackExemptions::is_loopback_endpoint(endpoint_url) {
                return Err(format!(
                    "the pack {} wrote it and its endpoint is on loopback, which only a \
                     server file the operator wrote may reach",
                    origin.pack
                ));
            }
        }
        Ok(manifest)
    }
}

/// The parser's own reason for refusing a document: its error type words it for a pack's
/// files.
fn manifest_reason(e: PackError) -> String {
    match e {
        PackError::InvalidManifest(reason) | PackError::ConstraintViolation { reason } => reason,
        other => other.to_string(),
    }
}

/// The text of the server file at `path`: a regular file of at most
/// [`MAX_MCP_SERVER_YAML_BYTES`], never a symlink, read without waiting on a FIFO or a device.
fn read_server_file(path: &Path) -> Result<String, String> {
    read_bounded_file(path, MAX_MCP_SERVER_YAML_BYTES)
}

/// The text of the regular file at `path`, of at most `cap` bytes, never a symlink, read
/// without waiting on a FIFO or a device.
fn read_bounded_file(path: &Path, cap: u64) -> Result<String, String> {
    let too_large = || format!("it is larger than {cap} bytes");
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("it cannot be read: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err("it is a symbolic link".into());
    }
    if !meta.file_type().is_file() {
        return Err("it is not a regular file".into());
    }
    if meta.len() > cap {
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
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("it cannot be read: {e}"))?;
    if bytes.len() as u64 > cap {
        return Err(too_large());
    }
    String::from_utf8(bytes).map_err(|_| "it is not valid UTF-8".to_string())
}

/// What one sweep of the pack-origin server files did
/// ([`McpControlPlane::remove_origins_not_in`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct McpSweep {
    /// The names of the files removed, in name order.
    pub removed: Vec<String>,
    /// The files left although they may be stale, each with why: its origin could not be
    /// read, or it could not be removed. Bounded as a load's warnings are, each safe to print.
    pub warnings: Vec<String>,
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

    /// Whether a server needs the secret store: it names `secret-refs` or binds `credentials`.
    pub fn need_secrets(&self) -> bool {
        self.servers
            .iter()
            .any(|m| !m.secret_refs.is_empty() || !m.credentials.is_empty())
    }

    /// The warnings of the scan so far.
    pub fn warnings(&self) -> &[String] {
        &self.warnings.kept
    }

    /// Leave out every http server whose endpoint is on loopback and not in `exempt`, with a
    /// warning each. The http chain exempts the loopback endpoints of the files read when the
    /// daemon started and nothing else, so a loopback server that appears on a reload cannot be
    /// reached until the daemon restarts; it is refused rather than configured unreachable.
    pub fn keep_loopback_within(&mut self, exempt: &LoopbackExemptions) {
        let mut kept = Vec::with_capacity(self.servers.len());
        for manifest in std::mem::take(&mut self.servers) {
            if let McpTransportDecl::Http { endpoint_url } = &manifest.transport {
                if LoopbackExemptions::is_loopback_endpoint(endpoint_url)
                    && !exempt.covers(endpoint_url)
                {
                    self.warnings.push(format!(
                        "server '{}' is skipped: its endpoint is on loopback and was not \
                         exempted when the daemon started (only the loopback endpoints of the \
                         server files read at start are); restart the daemon to reach it",
                        manifest.server_id
                    ));
                    continue;
                }
            }
            kept.push(manifest);
        }
        self.servers = kept;
    }

    /// Build the client's server set, resolving each `secret-refs` entry through `secrets` and
    /// checking that `secrets` holds the secret of each credential. A server whose secret is
    /// missing is left out with a warning, as is every server that needs secrets when there is
    /// no store (`None`).
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

/// Why a server that names secrets is skipped while no secret store is open.
const NO_SECRET_STORE: &str =
    "it needs secrets and the secret store is not open; the store is opened when the daemon \
     starts";

/// The client's entry for the server `manifest` describes. A stdio server's process gets the
/// environment [`stdio_child_env`] builds from the daemon's own environment, the file's `env`
/// literals and its `secret-refs`, resolved through `secrets`, and runs in the file's `cwd`. An
/// http server's `credentials` stay secret names, which the http chain resolves at each
/// request: here they are only checked to be in `secrets`, and no value is kept.
fn server_entry(
    manifest: McpServerManifest,
    secrets: Option<&dyn ManifestSecrets>,
) -> Result<McpServerEntry, String> {
    let transport = match manifest.transport {
        McpTransportDecl::Stdio {
            command,
            args,
            env: literals,
            cwd,
        } => {
            let mut resolved = BTreeMap::new();
            for (variable, key) in &manifest.secret_refs {
                let secrets = secrets.ok_or(NO_SECRET_STORE)?;
                let value = secrets.get(key).ok_or_else(|| {
                    format!("secret {key:?} (for {variable}) is not in the secret store")
                })?;
                resolved.insert(variable.clone(), value.expose_secret().to_string());
            }
            McpTransportSpec::Stdio {
                command,
                args,
                env: stdio_child_env(std::env::vars_os(), &literals, resolved),
                cwd: cwd.map(PathBuf::from),
            }
        }
        McpTransportDecl::Http { endpoint_url } => {
            let allowlist = Allowlist {
                patterns: vec![origin_prefix(&endpoint_url)
                    .ok_or_else(|| "its endpoint-url has no host".to_string())?],
            };
            if !allowlist.matches(&endpoint_url) {
                return Err("its endpoint-url is not a URL the http chain can address".into());
            }
            for binding in &manifest.credentials {
                let secrets = secrets.ok_or(NO_SECRET_STORE)?;
                if secrets.get(&binding.secret_name).is_none() {
                    return Err(format!(
                        "secret {:?} (for its {} credential) is not in the secret store",
                        binding.secret_name,
                        credential_label(&binding.position)
                    ));
                }
            }
            McpTransportSpec::Http {
                endpoint_url,
                capability: HttpCapability {
                    allowlist,
                    credentials: manifest.credentials,
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

/// The variables of the daemon's own environment a stdio server's process is given, each one
/// only when the daemon has it set: what a server, or a launcher such as `npx` or `uvx`, needs to
/// find programs, a home, a temporary directory, a locale and a time zone. No other variable
/// of the daemon's environment (its API keys and tokens among them) reaches a server.
pub const STDIO_BASELINE_ENV: [&str; 9] = [
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ",
];

/// The whole environment of a stdio server's process, in three layers, each over the one
/// before: the [`STDIO_BASELINE_ENV`] variables `host` (the daemon's own environment) sets,
/// with the daemon's values; the server file's `env` literals (`literals`); and its
/// `secret-refs` resolved to their values (`secrets`). A baseline variable `host` does not set,
/// or sets to a value that is not UTF-8, is absent (not empty), and no other variable of
/// `host` is ever taken. The loader ([`McpServerFiles::into_servers`]) and the pack bridge
/// ([`crate::pack_bridges::PackMcpBridge::entry_with_env`]) both build a server's environment
/// here.
pub fn stdio_child_env(
    host: impl IntoIterator<Item = (OsString, OsString)>,
    literals: &BTreeMap<String, String>,
    secrets: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = host
        .into_iter()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            if !STDIO_BASELINE_ENV.contains(&name.as_str()) {
                return None;
            }
            Some((name, value.into_string().ok()?))
        })
        .collect();
    env.extend(
        literals
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    env.extend(secrets);
    env
}

/// A credential's position as a server file writes it, for a warning.
fn credential_label(position: &CredentialPosition) -> String {
    match position {
        CredentialPosition::BearerToken => "bearer".into(),
        CredentialPosition::BasicAuth { .. } => "basic".into(),
        CredentialPosition::CustomHeader { key } => format!("header {key:?}"),
        CredentialPosition::QueryParam { key } => format!("query {key:?}"),
        CredentialPosition::UrlPath { key } => format!("url-path {key:?}"),
    }
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
/// daemon's other chains; `secrets` is the store it resolves the servers' credentials in, at
/// each request.
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

/// A secret store that holds nothing: what the http chain is built on when the daemon has no
/// secret store open.
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
    /// The root agent's id, whose grants say which servers the warm-up and a reload list.
    pub root_agent_id: &'a str,
    /// The control plane the runtime reloads from.
    pub plane: McpControlPlane,
    /// Where skip and warm-up warnings go (`advance start` prints them on stderr).
    pub log: LogHandle,
}

/// Build the MCP client and register the seven `mcp-client` host functions under `mcp`.
/// Never fails: each server that cannot serve is skipped with a warning on stderr, and with no
/// server at all the host functions are still registered, so a guest that declares `mcp`
/// links. The warm-up `mcp.warm-tool-cache` asks for is left to [`McpRuntime::start`], which
/// the daemon calls once the pack runtime is attached, after its sweep of the files of
/// packs that are gone.
pub fn compose_mcp(parts: McpComposition<'_>) -> Arc<McpRuntime> {
    let origins: BTreeMap<String, String> = parts
        .servers
        .manifests()
        .iter()
        .filter_map(|manifest| {
            manifest
                .origin
                .as_ref()
                .map(|origin| (manifest.server_id.clone(), origin.pack.clone()))
        })
        .collect();
    // One store for everything MCP reads secrets from: the daemon's whenever one is open,
    // whatever opened it, so a server a later reload admits resolves its secrets there too; an
    // empty one otherwise.
    let live_secrets = parts.secret_store.clone();
    let manifest_secrets = live_secrets
        .as_ref()
        .map(|store| CapSecretsSecretStore::new(Arc::clone(store)));
    let servers = parts.servers.into_servers(
        manifest_secrets
            .as_ref()
            .map(|secrets| secrets as &dyn ManifestSecrets),
    );
    for warning in &servers.warnings {
        parts
            .log
            .err(log_keys::MCP_WARN, format!("advance: WARN mcp: {warning}"));
    }

    let limits = client_limits(parts.config);
    let loopback = servers.loopback.clone();
    let (chain, leak) = http_chain(
        live_secrets.clone().unwrap_or_else(empty_secret_store),
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

    let printed = Mutex::new(servers.warnings.iter().cloned().collect());
    let runtime = Arc::new(McpRuntime {
        client,
        gate,
        runtime: parts.runtime,
        warnings: servers.warnings,
        printed,
        plane: parts.plane,
        secret_store: live_secrets,
        origins: Mutex::new(origins),
        trusted_packs: Mutex::new(BTreeSet::new()),
        root_agent_id: parts.root_agent_id.to_string(),
        loopback,
        listings_in_flight: Arc::new(Mutex::new(BTreeSet::new())),
        warm_up_pending: AtomicBool::new(parts.config.warm_tool_cache),
        log: parts.log,
    });
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
    /// The warnings of the latest load (at start, or the latest reload): a reload prints only
    /// those not among them.
    printed: Mutex<BTreeSet<String>>,
    plane: McpControlPlane,
    /// The daemon's secret store, when one is open: what a reload resolves the servers'
    /// secrets in (the http chain holds the same store).
    secret_store: Option<Arc<SecretStore>>,
    origins: Mutex<BTreeMap<String, String>>,
    /// The installed packs (`name@version`) that are trusted, as the pack runtime last
    /// applied them ([`set_trusted_packs`](Self::set_trusted_packs)).
    trusted_packs: Mutex<BTreeSet<String>>,
    /// The root agent's id: whose `mcp` grants say which servers a reload lists.
    root_agent_id: String,
    /// The loopback endpoints the http chain exempts, fixed when the daemon started.
    loopback: LoopbackExemptions,
    /// Server ids whose `list_tools` is running; dropped when it finishes so a
    /// failed listing can be tried again.
    listings_in_flight: Arc<Mutex<BTreeSet<String>>>,
    /// Set while the warm-up `mcp.warm-tool-cache` asks for waits for [`start`](Self::start).
    warm_up_pending: AtomicBool,
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

    /// Re-read the server files and swap them into the client. Connections of a removed or
    /// changed server are closed and their tool-cache entries dropped. An added or changed
    /// server that one of the root agent's `mcp` grants reaches is listed on the daemon
    /// runtime, as the root, and not awaited here; one no grant reaches is left for its first
    /// use, as the warm-up leaves it. A server on a loopback endpoint the chain did not exempt
    /// when the daemon started is refused with a warning
    /// ([`McpServerFiles::keep_loopback_within`]). A warning the previous load already printed
    /// is not printed again.
    pub fn reload(&self) {
        let mut files = self.plane.scan();
        files.keep_loopback_within(&self.loopback);
        let origins: BTreeMap<String, String> = files
            .manifests()
            .iter()
            .filter_map(|manifest| {
                manifest
                    .origin
                    .as_ref()
                    .map(|origin| (manifest.server_id.clone(), origin.pack.clone()))
            })
            .collect();
        *self.origins.lock().unwrap_or_else(|e| e.into_inner()) = origins;
        let manifest_secrets = self
            .secret_store
            .as_ref()
            .map(|store| CapSecretsSecretStore::new(Arc::clone(store)));
        let servers = files.into_servers(
            manifest_secrets
                .as_ref()
                .map(|secrets| secrets as &dyn ManifestSecrets),
        );
        self.print_new_warnings(&servers.warnings);
        let reconfig = self.client.replace_config(servers.config);
        let scopes = self.gate.scopes(&self.root_agent_id);
        for id in reconfig.added.iter().chain(reconfig.changed.iter()) {
            if scopes.reaches_server(id) {
                self.spawn_listing(id);
            }
        }
    }

    /// Print the warnings of a reload the latest load did not have: a file that keeps failing
    /// is reported once, not on every reload, and again if it fails anew after a load without
    /// that warning (as the pack runtime reports its own warnings).
    fn print_new_warnings(&self, warnings: &[String]) {
        let mut printed = self.printed.lock().unwrap_or_else(|e| e.into_inner());
        for warning in warnings {
            if !printed.contains(warning) {
                self.log
                    .err(log_keys::MCP_WARN, format!("advance: WARN mcp: {warning}"));
            }
        }
        *printed = warnings.iter().cloned().collect();
    }

    /// List the tools of `server_id` on the daemon runtime, as the root agent, unless a
    /// listing of it is running. A failed listing is not cached, so a later read tries again.
    fn spawn_listing(&self, server_id: &str) {
        let Some(claim) = self.claim_listing(server_id) else {
            return;
        };
        let client = Arc::clone(&self.client);
        let caller = self.root_agent_id.clone();
        self.runtime.spawn(async move {
            let _ = client.list_tools(Some(&caller), &claim.server_id).await;
            drop(claim);
        });
    }

    /// Mark a listing of `server_id` as running, unless one is. The mark goes when the
    /// returned claim is dropped, however the listing ends (a failed one, or one whose task
    /// stopped with the runtime), so a later read or reload can list the server again.
    fn claim_listing(&self, server_id: &str) -> Option<ListingClaim> {
        self.listings_in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(server_id.to_string())
            .then(|| ListingClaim {
                in_flight: Arc::clone(&self.listings_in_flight),
                server_id: server_id.to_string(),
            })
    }

    /// Whether a listing of `server_id` is running.
    fn is_listing(&self, server_id: &str) -> bool {
        self.listings_in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(server_id)
    }

    /// Record which of the installed packs (`name@version`) are trusted, as the pack runtime
    /// applies them: an agent's prompt shows the MCP tools of the operator's servers first,
    /// then those of trusted packs' servers, then the others ([`LiveCallableInventory`]). A
    /// pack-origin server whose pack is not among them counts as an untrusted pack's.
    pub fn set_trusted_packs(&self, trusted: BTreeSet<String>) {
        *self.trusted_packs.lock().unwrap_or_else(|e| e.into_inner()) = trusted;
    }

    /// Where `server_id` comes from, and its origin pack (`name@version`) when a pack
    /// registered it.
    fn source_of(&self, server_id: &str) -> (ServerSource, Option<String>) {
        let origin = self.pack_origin(server_id);
        let source = match &origin {
            None => ServerSource::Operator,
            Some(pack)
                if self
                    .trusted_packs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(pack) =>
            {
                ServerSource::TrustedPack
            }
            Some(_) => ServerSource::UntrustedPack,
        };
        (source, origin)
    }

    /// Delete the pack-origin files whose origin pack is not installed
    /// ([`McpControlPlane::remove_origins_not_in`]), then [`reload`](Self::reload).
    pub fn drop_uninstalled_origins(&self, installed: &BTreeSet<String>) -> McpSweep {
        let sweep = self.plane.remove_origins_not_in(installed);
        self.reload();
        sweep
    }

    /// Finish the start of the client, which the daemon built from the server files as they
    /// were: delete the pack-origin files whose origin pack is not in `installed`
    /// ([`McpControlPlane::remove_origins_not_in`]), reloading only when one went, then run the
    /// warm-up `mcp.warm-tool-cache` asks for ([`warm_tool_cache`](Self::warm_tool_cache), as
    /// the root). The daemon calls this once, once the pack runtime is attached
    /// ([`PackRuntime::sweep_mcp_origins`](crate::pack_runtime::PackRuntime::sweep_mcp_origins)):
    /// a pack uninstalled while the daemon was down (`advance pack uninstall` touches no server
    /// file) loses its servers before an agent runs, and the warm-up never starts one of them.
    /// A later call only sweeps.
    pub fn start(&self, installed: &BTreeSet<String>) -> McpSweep {
        let sweep = self.plane.remove_origins_not_in(installed);
        if !sweep.removed.is_empty() {
            self.reload();
        }
        if self.warm_up_pending.swap(false, Ordering::SeqCst) {
            self.warm_tool_cache(&self.root_agent_id);
        }
        sweep
    }

    /// The pack `name@version` that materialized `server_id`, if it is a
    /// pack-origin server.
    pub fn pack_origin(&self, server_id: &str) -> Option<String> {
        self.origins
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(server_id)
            .cloned()
    }

    #[cfg(test)]
    fn for_test(
        client: Arc<McpClient>,
        gate: McpGate,
        origins: BTreeMap<String, String>,
    ) -> Arc<Self> {
        Self::for_test_over(
            client,
            gate,
            origins,
            McpControlPlane::new(Path::new("/"), &McpConfig::default()),
            LoopbackExemptions::none(),
        )
    }

    /// A runtime for the root agent `root` that reloads from `plane`, whose http chain
    /// exempts `loopback`.
    #[cfg(test)]
    fn for_test_over(
        client: Arc<McpClient>,
        gate: McpGate,
        origins: BTreeMap<String, String>,
        plane: McpControlPlane,
        loopback: LoopbackExemptions,
    ) -> Arc<Self> {
        let log = plane.log.clone();
        Arc::new(Self {
            client,
            gate,
            runtime: tokio::runtime::Handle::current(),
            warnings: Vec::new(),
            printed: Mutex::new(BTreeSet::new()),
            plane,
            secret_store: None,
            origins: Mutex::new(origins),
            trusted_packs: Mutex::new(BTreeSet::new()),
            root_agent_id: "root".into(),
            loopback,
            listings_in_flight: Arc::new(Mutex::new(BTreeSet::new())),
            warm_up_pending: AtomicBool::new(false),
            log,
        })
    }
}

/// Who a server comes from, in the order an agent is shown MCP tools: the operator's
/// servers first, then trusted packs' servers, then the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ServerSource {
    /// A server file the operator wrote (it has no `origin` block).
    Operator,
    /// A server a trusted pack registered.
    TrustedPack,
    /// A server a pack registered that is not trusted, or whose pack's trust is not known.
    UntrustedPack,
}

/// A running listing of one server ([`McpRuntime::claim_listing`]); dropping it lets a later
/// read or reload list the server again.
struct ListingClaim {
    in_flight: Arc<Mutex<BTreeSet<String>>>,
    server_id: String,
}

impl Drop for ListingClaim {
    fn drop(&mut self) {
        self.in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.server_id);
    }
}

/// `[pack {origin}]`, with `[`, `]` and controls in `origin` replaced by `_` so the marker
/// cannot be spoofed from the origin string.
fn pack_marker(origin: &str) -> String {
    let mut marker = String::from("[pack ");
    marker.extend(origin.chars().map(|c| {
        if c == '[' || c == ']' || c.is_control() {
            '_'
        } else {
            c
        }
    }));
    marker.push(']');
    marker
}

/// A tool's description as an agent is shown it. The description of a pack's server's tool
/// ends in the pack's marker ([`pack_marker`]): the text before it is cut, as a listing cuts
/// a description (ending in `…`), so that both fit [`MAX_TOOL_DESCRIPTION_BYTES`], and the
/// marker itself is never cut.
fn shown_description(description: &str, origin: Option<&str>) -> String {
    let Some(origin) = origin else {
        return description.to_string();
    };
    let marker = pack_marker(origin);
    let room = MAX_TOOL_DESCRIPTION_BYTES.saturating_sub(marker.len() + " ".len());
    let body = cut_description_to(description.to_string(), room);
    if body.is_empty() {
        marker
    } else {
        format!("{body} {marker}")
    }
}

/// A tool's model-facing name: `<server>__<tool>`, or the tool's own name when it already
/// reads so.
fn model_facing_name(tool: &McpToolInfo) -> String {
    let prefix = format!("{}__", tool.server_id);
    if tool.name.starts_with(&prefix) {
        tool.name.clone()
    } else {
        format!("{prefix}{}", tool.name)
    }
}

/// What Tier-2 renders for one tool at most, in bytes: the line `- name(arguments) —
/// description`, whose arguments are the top-level `properties` of the input schema, `, `
/// between two. Tier-2's sanitizing never lengthens a name, an argument or a description.
fn prompt_line_bytes(name: &str, description: &str, schema: Option<&serde_json::Value>) -> usize {
    let arguments = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(serde_json::Value::as_object)
        .map_or(0, |properties| {
            properties.keys().map(String::len).sum::<usize>()
                + PROMPT_ARG_SEPARATOR_BYTES * properties.len().saturating_sub(1)
        });
    PROMPT_LINE_FRAMING_BYTES + name.len() + arguments + description.len()
}

/// Live MCP half of the callable inventory: what an agent is shown of the client's tool
/// cache, read without contacting any server.
///
/// A read names its agent by one of the agent's ids. The grants are stored under the
/// agent's immutable id, while the context assembler and the Client API tools provider read
/// under the mailbox key `agent:<handle>` the agent is served under. An inventory built with
/// [`for_agent`](Self::for_agent) maps each of those aliases to the stored id before it
/// reads the grants, so both readers list what the agent's own calls are decided by.
///
/// A read shows the cached tools the agent's `mcp` grants cover (the web family tools only
/// as the gate allows them), chosen before any tool is copied, within
/// [`MCP_PROMPT_BUDGET_BYTES`]: the tools of the operator's servers first, then those of
/// trusted packs' servers, then the others, each group by server id and then by name, as
/// many as fit in that order. The rest are left out and counted
/// ([`McpToolsShown::not_shown`]; the prompt's tools section closes with a line saying how
/// many), and a read that leaves tools out is logged, again only when the number changes.
/// The prompt and the Client API read the same entries.
///
/// An entry's name is the model-facing `<server>__<tool>`, the one callable name the prompt
/// and the Client API share; `server_id` names the server beside it. The description of a
/// pack's server's tool ends in `[pack name@version]`, within the description cap.
///
/// A read also lists, in the background on the daemon runtime, each server the agent's
/// grants reach whose tools the cache does not hold as far as it could
/// ([`McpClient::servers_to_list`]: not listed yet, listed in vain, or cut to less than the
/// room the cache now has for it) and that no listing is running for. The read does not
/// wait: the first read after the daemon starts shows no MCP tools unless
/// `mcp.warm-tool-cache` filled the cache. A read of a cache that holds every such server as
/// far as it can starts nothing.
pub struct LiveCallableInventory {
    wasm: Vec<ToolEntry>,
    tools_grant: Option<Arc<dyn advance_shared_types::traits::ToolsGrantReader>>,
    mcp: Arc<McpRuntime>,
    grantee: Option<Grantee>,
    /// The agent and the number of MCP tools the latest logged read left out.
    reported: Mutex<Option<(String, usize)>>,
}

/// The id an agent's grants are stored under, and the other ids a read may name it by.
struct Grantee {
    agent_id: String,
    aliases: Vec<String>,
}

impl LiveCallableInventory {
    /// The WASM snapshot plus the live MCP client of `mcp`; a read looks the grants up under
    /// the id it names.
    pub fn new(wasm: Vec<ToolEntry>, mcp: Arc<McpRuntime>) -> Self {
        Self {
            wasm,
            tools_grant: None,
            mcp,
            grantee: None,
            reported: Mutex::new(None),
        }
    }

    /// As [`new`](Self::new), for the agent whose grants are stored under `agent_id`: a read
    /// under `agent_id` or under any id in `aliases` (its mailbox key `agent:<handle>`) reads
    /// that agent's grants. A read under any other id looks the grants up as named.
    pub fn for_agent(
        wasm: Vec<ToolEntry>,
        mcp: Arc<McpRuntime>,
        agent_id: &str,
        aliases: &[String],
    ) -> Self {
        Self {
            grantee: Some(Grantee {
                agent_id: agent_id.to_string(),
                aliases: aliases.to_vec(),
            }),
            ..Self::new(wasm, mcp)
        }
    }

    /// The id whose grants a read naming `agent_id` reads.
    fn grantee<'a>(&'a self, agent_id: &'a str) -> &'a str {
        match &self.grantee {
            Some(grantee)
                if grantee.agent_id == agent_id
                    || grantee.aliases.iter().any(|alias| alias == agent_id) =>
            {
                &grantee.agent_id
            }
            _ => agent_id,
        }
    }

    pub fn with_tools_grant_reader(
        mut self,
        reader: Arc<dyn advance_shared_types::traits::ToolsGrantReader>,
    ) -> Self {
        self.tools_grant = Some(reader);
        self
    }

    /// List, in the background, the tools of each server `scopes` reach that a listing would
    /// add tools to the cache for ([`McpClient::servers_to_list`]) and that no listing is
    /// running for: one after another, each for no agent. A failed listing is not cached, so
    /// a later read tries again. Starts nothing when there is no such server, or once the
    /// client is shut down.
    fn kick_refresh(&self, scopes: &McpScopes) {
        if self.mcp.client().is_shut_down() {
            return;
        }
        let pending: Vec<String> = self
            .mcp
            .client()
            .servers_to_list()
            .into_iter()
            .filter(|server_id| scopes.reaches_server(server_id) && !self.mcp.is_listing(server_id))
            .collect();
        if pending.is_empty() {
            return;
        }
        let mcp = Arc::clone(&self.mcp);
        self.mcp.runtime.spawn(async move {
            for server_id in pending {
                let Some(_claim) = mcp.claim_listing(&server_id) else {
                    continue;
                };
                // Another read, or a reload, may have listed it meanwhile.
                if !mcp.client().servers_to_list().contains(&server_id) {
                    continue;
                }
                let _ = mcp.client().list_tools(None, &server_id).await;
            }
        });
    }

    /// What a read naming `agent_id` is shown (see the type docs).
    fn shown(&self, agent_id: &str) -> McpToolsShown {
        let agent_id = self.grantee(agent_id);
        let gate = self.mcp.gate();
        let client = self.mcp.client();
        let scopes = gate.scopes(agent_id);
        self.kick_refresh(&scopes);

        let listings = client.cached_tools();
        // The visible tools of each server the grants reach, by name, with where the server
        // comes from.
        type Tools<'a> = Vec<(String, &'a McpToolInfo)>;
        let mut servers: Vec<(ServerSource, Option<String>, Tools<'_>)> = Vec::new();
        for listing in &listings {
            if !scopes.reaches_server(&listing.server_id) {
                continue;
            }
            let refuses_web = client.refuses_web_tools(&listing.server_id);
            let mut tools: Tools<'_> = gate
                .visible_tool_refs(agent_id, &scopes, refuses_web, &listing.tools)
                .into_iter()
                .map(|tool| (model_facing_name(tool), tool))
                .collect();
            if tools.is_empty() {
                continue;
            }
            tools.sort_by(|a, b| a.0.cmp(&b.0));
            let (source, origin) = self.mcp.source_of(&listing.server_id);
            servers.push((source, origin, tools));
        }
        // The cache holds its listings in server-id order, which a stable sort keeps within
        // each source.
        servers.sort_by_key(|(source, _, _)| *source);

        let visible: usize = servers.iter().map(|(_, _, tools)| tools.len()).sum();
        let mut shown = Vec::new();
        let mut spent = 0;
        'servers: for (_, origin, tools) in &servers {
            for (name, tool) in tools {
                let description = shown_description(&tool.description, origin.as_deref());
                let bytes = prompt_line_bytes(name, &description, tool.input_schema.as_ref());
                if spent + bytes > MCP_PROMPT_BUDGET_BYTES {
                    break 'servers;
                }
                spent += bytes;
                shown.push(McpToolEntry {
                    name: name.clone(),
                    description,
                    params_schema: tool
                        .input_schema
                        .clone()
                        .unwrap_or_else(|| serde_json::json!({})),
                    server_id: tool.server_id.clone(),
                });
            }
        }
        let not_shown = visible - shown.len();
        self.report_not_shown(agent_id, visible, not_shown);
        McpToolsShown {
            tools: shown,
            not_shown,
        }
    }

    /// Log that a read left `not_shown` of the `visible` MCP tools of `agent_id` out: a read
    /// that leaves out as many tools of the same agent as the latest logged one says nothing,
    /// and one that leaves none out lets the next that does log again.
    fn report_not_shown(&self, agent_id: &str, visible: usize, not_shown: usize) {
        let now = (not_shown > 0).then(|| (agent_id.to_string(), not_shown));
        {
            let mut reported = self.reported.lock().unwrap_or_else(|e| e.into_inner());
            if *reported == now {
                return;
            }
            *reported = now;
        }
        if not_shown > 0 {
            self.mcp.log.err(
                log_keys::MCP_TOOLS_NOT_SHOWN,
                format!(
                    "advance: WARN mcp: {not_shown} of the {visible} MCP tools agent {} may \
                     call are left out of its prompt and its /client/tools listing: they do \
                     not fit the {MCP_PROMPT_BUDGET_BYTES}-byte budget for MCP tool text",
                    printable(agent_id)
                ),
            );
        }
    }
}

impl CallableInventoryReader for LiveCallableInventory {
    fn list_wasm_tools(&self, agent_id: &str) -> Vec<ToolEntry> {
        let agent_id = self.grantee(agent_id);
        match &self.tools_grant {
            None => self.wasm.clone(),
            Some(reader) => match reader.tool_allowlist(agent_id) {
                None => self.wasm.clone(),
                Some(allow) => self
                    .wasm
                    .iter()
                    .filter(|t| allow.iter().any(|a| a == &t.name))
                    .cloned()
                    .collect(),
            },
        }
    }

    fn list_mcp_tools(&self, agent_id: &str) -> Vec<McpToolEntry> {
        self.shown(agent_id).tools
    }

    fn mcp_tools_shown(&self, agent_id: &str) -> McpToolsShown {
        self.shown(agent_id)
    }
}

/// Persists a pack's MCP server as a file in the operator's servers directory.
///
/// It writes only what the loader reads back as the same server: an id of the shared grammar
/// (its file is never hidden), a stdio transport only while `mcp.allow-stdio` is `true`, and
/// a body within [`MAX_MCP_SERVER_YAML_BYTES`] that re-parses to the registration. It reads an
/// existing file as the loader does (a regular file within the cap, never through a symlink)
/// and refuses to replace or remove what it cannot read; it refuses a servers directory the
/// loader would not read (a symlink, or an entry that is not a directory); and it writes
/// through a fresh temporary file renamed into place.
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

    /// Whether the servers directory exists. An entry the loader would not read as the
    /// directory (a symlink, which is never followed, or anything else that is not a
    /// directory) is an error: nothing is written or removed through it.
    fn servers_dir_exists(&self) -> Result<bool, String> {
        let dir = self.plane.dir();
        match std::fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() => Ok(true),
            Ok(_) => Err(format!(
                "{} is not a directory, and the loader reads no server file through it",
                dir.display()
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("{} cannot be read: {e}", dir.display())),
        }
    }

    /// `<dir>/<id>.yaml`, for an id the shared grammar admits (no separator, no leading dot).
    fn path_for(&self, server_id: &str) -> PathBuf {
        self.plane
            .dir()
            .join(format!("{server_id}{SERVER_FILE_SUFFIX}"))
    }

    /// The text of the server file at `path`, read as the loader reads it: `Ok(None)` when
    /// there is no entry. An entry that cannot be read that way (a symlink, something that is
    /// not a regular file, a file over the cap) is an error: the sink never replaces or
    /// removes what it cannot read.
    fn existing_server_file(path: &Path) -> Result<Option<String>, String> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("it cannot be read: {e}")),
            Ok(_) => read_server_file(path).map(Some),
        }
    }

    fn refuse_unreadable_id(server_id: &str) -> Result<(), PackBridgeError> {
        if is_valid_server_id(server_id) {
            return Ok(());
        }
        Err(violation(format!(
            "mcp-server {server_id:?} is not a server id the loader reads \
             ([A-Za-z0-9._-]{{1,{MAX_SERVER_ID_BYTES}}}, not starting with '.')"
        )))
    }
}

fn violation(reason: String) -> PackBridgeError {
    PackBridgeError::Pack(PackError::ConstraintViolation { reason })
}

impl McpEntrySink for ControlPlaneMcpSink {
    fn register(&self, registration: McpRegistration) -> Result<McpRegister, PackBridgeError> {
        let id = registration.server_id.clone();
        Self::refuse_unreadable_id(&id)?;
        if registration.transport.is_stdio() && !self.plane.allow_stdio {
            return Err(violation(format!(
                "mcp-server '{id}' declares a stdio transport while stdio servers are disabled \
                 (mcp.allow-stdio: false): it would never load"
            )));
        }
        let body = render_server_file(&registration);
        if body.len() as u64 > MAX_MCP_SERVER_YAML_BYTES {
            return Err(violation(format!(
                "mcp-server '{id}' renders to {} bytes, more than the {MAX_MCP_SERVER_YAML_BYTES} \
                 a server file may hold",
                body.len()
            )));
        }
        match parse_mcp_server_manifest_str(&body) {
            Ok(rendered) if matches_registration(&rendered, &registration) => {}
            Ok(_) => {
                return Err(violation(format!(
                    "mcp-server '{id}' does not round-trip through its server file: the file \
                     would describe a different server"
                )));
            }
            Err(e) => {
                return Err(violation(format!(
                    "mcp-server '{id}' does not round-trip through its server file: {}",
                    manifest_reason(e)
                )));
            }
        }
        let dir_exists = self
            .servers_dir_exists()
            .map_err(|reason| violation(format!("mcp-server '{id}' is not written: {reason}")))?;
        let path = self.path_for(&id);
        let existing = if dir_exists {
            Self::existing_server_file(&path).map_err(|reason| {
                violation(format!(
                    "mcp-server '{id}' already exists and cannot be read: {reason}"
                ))
            })?
        } else {
            None
        };
        if let Some(existing) = existing {
            let manifest = parse_mcp_server_manifest_str(&existing).map_err(|e| {
                violation(format!(
                    "mcp-server '{id}' already exists and cannot be read: {}",
                    manifest_reason(e)
                ))
            })?;
            match &manifest.origin {
                None => {
                    return Err(violation(format!(
                        "mcp-server '{id}' already exists as an operator file; a pack may not \
                         replace it"
                    )));
                }
                Some(origin) if origin.pack != registration.origin_pack => {
                    return Err(violation(format!(
                        "mcp-server '{id}' already belongs to pack {}",
                        origin.pack
                    )));
                }
                Some(origin) if origin.config_ref != registration.origin_ref => {
                    return Err(violation(format!(
                        "mcp-server '{id}' is already registered by {} of the same pack",
                        origin.config_ref
                    )));
                }
                Some(_) if matches_registration(&manifest, &registration) => {
                    return Ok(McpRegister::Unchanged(id));
                }
                Some(_) => {
                    return Err(violation(format!(
                        "mcp-server '{id}' is already registered with different content"
                    )));
                }
            }
        }
        write_server_file(self.plane.dir(), &path, &id, &body)?;
        self.reload();
        Ok(McpRegister::Created(id))
    }

    fn deregister(&self, server_id: &str) -> Result<(), PackBridgeError> {
        Self::refuse_unreadable_id(server_id)?;
        let dir_exists = self.servers_dir_exists().map_err(|reason| {
            violation(format!("mcp-server '{server_id}' is not removed: {reason}"))
        })?;
        if !dir_exists {
            return Ok(());
        }
        let path = self.path_for(server_id);
        let Some(text) = Self::existing_server_file(&path).map_err(|reason| {
            violation(format!(
                "mcp-server '{server_id}' cannot be read, so it is not removed: {reason}"
            ))
        })?
        else {
            return Ok(());
        };
        let manifest = parse_mcp_server_manifest_str(&text).map_err(PackBridgeError::Pack)?;
        if manifest.origin.is_none() {
            return Err(violation(format!(
                "mcp-server '{server_id}' is an operator file and is not removed by a pack"
            )));
        }
        std::fs::remove_file(&path)
            .map_err(|source| PackBridgeError::Pack(PackError::Io { path, source }))?;
        self.reload();
        Ok(())
    }
}

/// Whether `manifest` describes exactly the server `registration` writes: the same id,
/// description, transport (a stdio server's `env` literals and `cwd` included), secret-ref ids
/// and origin, and no credentials (a registration binds none).
fn matches_registration(manifest: &McpServerManifest, registration: &McpRegistration) -> bool {
    manifest.server_id == registration.server_id
        && manifest.description == registration.description
        && manifest.transport == registration.transport
        && manifest.secret_refs == registration.secret_refs
        && manifest.credentials.is_empty()
        && manifest.origin.as_ref().is_some_and(|origin| {
            origin.pack == registration.origin_pack && origin.config_ref == registration.origin_ref
        })
}

/// Write `body` to `path` (`<dir>/<id>.yaml`) through a temporary file beside it, created
/// fresh with mode 0600 and renamed into place; a failure leaves no temporary file behind.
/// Nothing is followed: a symlink planted under either name is replaced as a name, its target
/// untouched (the caller has already refused to replace a readable entry that is a symlink).
fn write_server_file(dir: &Path, path: &Path, id: &str, body: &str) -> Result<(), PackBridgeError> {
    let io = |path: &Path, source: std::io::Error| {
        PackBridgeError::Pack(PackError::Io {
            path: path.to_path_buf(),
            source,
        })
    };
    std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    let tmp = dir.join(format!(".{id}{SERVER_FILE_SUFFIX}.tmp"));
    // A leftover of an interrupted write, or a planted name: removed as a name, never read.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(&tmp, e)),
    }
    let written = create_fresh(&tmp).and_then(|mut file| {
        file.write_all(body.as_bytes())?;
        file.sync_all()
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(&tmp, e));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(path, e));
    }
    Ok(())
}

/// Create the file at `path`, which must not exist yet, for writing, with mode 0600 and
/// without following a symlink.
#[cfg(unix)]
fn create_fresh(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_fresh(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// The server file of `registration`: every scalar double-quoted, the keys of `env` and
/// `secret-refs` included, so no value and no name can change the document's shape or be read
/// as another YAML type.
fn render_server_file(registration: &McpRegistration) -> String {
    let mut yaml = format!("server-id: {}\n", yaml_string(&registration.server_id));
    if !registration.description.is_empty() {
        yaml.push_str(&format!(
            "description: {}\n",
            yaml_string(&registration.description)
        ));
    }
    match &registration.transport {
        McpTransportDecl::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            yaml.push_str("transport:\n  kind: stdio\n");
            yaml.push_str(&format!("  command: {}\n", yaml_string(command)));
            if !args.is_empty() {
                yaml.push_str("  args:\n");
                for arg in args {
                    yaml.push_str(&format!("    - {}\n", yaml_string(arg)));
                }
            }
            if !env.is_empty() {
                yaml.push_str("  env:\n");
                for (name, value) in env {
                    yaml.push_str(&format!(
                        "    {}: {}\n",
                        yaml_string(name),
                        yaml_string(value)
                    ));
                }
            }
            if let Some(cwd) = cwd {
                yaml.push_str(&format!("  cwd: {}\n", yaml_string(cwd)));
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
            yaml.push_str(&format!("  {}: {}\n", yaml_string(env), yaml_string(key)));
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
    use advance_shared_types::security_validator::{CredentialBinding, ScanContext, ScanResult};
    use cap_grant::{
        CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantSqliteIndex, GrantStatus,
        GrantTtl,
    };

    use super::*;
    use crate::api::{ComposeLog, ComposeLogLine};
    use crate::pack_production::ClosureSecretStore;

    const STDIO: &str = "transport:\n  kind: stdio\n  command: /bin/true\n";

    /// An `origin` block of the pack `pack` (`name@version`) for the server `id`.
    fn origin_block(pack: &str, id: &str) -> String {
        format!("origin:\n  pack: \"{pack}\"\n  config-ref: \"{pack}/mcp-servers/{id}\"\n")
    }

    /// Keeps every line the composition would print.
    #[derive(Default)]
    struct RecordingLog(std::sync::Mutex<Vec<String>>);

    impl ComposeLog for RecordingLog {
        fn line(&self, line: &ComposeLogLine) {
            self.0.lock().unwrap().push(line.text.clone());
        }
        fn ready(&self, _: &ComposeLogLine) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RecordingLog {
        fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

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
            McpTransportSpec::Stdio {
                command,
                args,
                env,
                cwd,
            } => {
                assert_eq!(command, "/bin/true");
                assert!(args.is_empty() && cwd.is_none());
                assert_eq!(
                    env,
                    &stdio_child_env(std::env::vars_os(), &BTreeMap::new(), BTreeMap::new()),
                    "the daemon's baseline variables alone"
                );
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
        std::fs::write(
            elsewhere.join("stale.yaml"),
            format!(
                "server-id: stale\n{STDIO}{}",
                origin_block("gone@1.0.0", "stale")
            ),
        )
        .unwrap();
        std::fs::create_dir_all(ws.path().join(".advance")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ws.path().join(".advance/mcp-servers")).unwrap();

        let files = plane(ws.path()).scan();
        assert!(files.server_ids().is_empty());
        let warning = one_warning(files.warnings(), "is not a directory");
        assert!(warning.contains("no server file is read"), "{warning}");

        // The sweep follows nothing either: the stale file behind the link stays, and the
        // sweep does not repeat the loader's warning.
        let sweep = plane(ws.path()).remove_origins_not_in(&BTreeSet::new());
        assert_eq!(sweep, McpSweep::default());
        assert!(elsewhere.join("stale.yaml").is_file());
    }

    // The sink neither writes nor removes a server file through a servers directory the loader
    // would not read: a symlink to a directory elsewhere.
    #[cfg(unix)]
    #[test]
    fn the_sink_refuses_a_symlinked_servers_directory() {
        let ws = tempfile::tempdir().unwrap();
        let elsewhere = ws.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(ws.path().join(".advance")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ws.path().join(".advance/mcp-servers")).unwrap();
        let sink = ControlPlaneMcpSink::new(plane(ws.path()));

        let reason = refusal(sink.register(registration("other", "p@1.0.0")));
        assert!(
            reason.contains("is not written") && reason.contains("is not a directory"),
            "{reason}"
        );
        let body = render_server_file(&registration("mine", "p@1.0.0"));
        std::fs::write(elsewhere.join("mine.yaml"), &body).unwrap();
        let reason = refusal(sink.deregister("mine"));
        assert!(
            reason.contains("is not removed") && reason.contains("is not a directory"),
            "{reason}"
        );
        assert_eq!(
            std::fs::read_to_string(elsewhere.join("mine.yaml")).unwrap(),
            body
        );
        let names: Vec<String> = std::fs::read_dir(&elsewhere)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["mine.yaml"], "nothing is written behind the link");
    }

    // `.` and `..` are not server ids (the shared grammar refuses a leading dot): as path
    // components they would leave the directory, and the file of the server `..` would be the
    // hidden `...yaml`. A file under another name that claims such an id is refused for the
    // id. The loader reads the entries it lists and nothing else.
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
        assert!(warning.contains("not start with '.'"), "{warning}");
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

    // A bare command loads, with a warning that it is looked up on the server's PATH.
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
        assert!(
            warning.contains("\"npx\" is not an absolute path")
                && warning.contains("looked up on the PATH the server is started with"),
            "{warning}"
        );
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

    // The sweep's warnings are bounded and safe to print as the loader's are: a parser message
    // can quote a control character back from the file.
    #[test]
    fn the_sweep_warnings_are_bounded_and_safe_to_print() {
        let ws = tempfile::tempdir().unwrap();
        for n in 0..MAX_WARNINGS + 5 {
            server_file(
                ws.path(),
                &format!("bad{n:03}.yaml"),
                "server-id: [unclosed\n",
            );
        }
        // An origin block the parser refuses for a key it quotes in its message.
        server_file(
            ws.path(),
            "ansi.yaml",
            "server-id: ansi\norigin:\n  \"\\e[31mpack\": gone@1.0.0\n",
        );
        let sweep = plane(ws.path()).remove_origins_not_in(&BTreeSet::new());
        assert!(sweep.removed.is_empty());
        assert_eq!(
            sweep.warnings.len(),
            MAX_WARNINGS + 1,
            "{:?}",
            sweep.warnings
        );
        let ansi = one_warning(&sweep.warnings, "\"ansi.yaml\"");
        assert!(
            ansi.contains("is not swept: its origin cannot be read") && ansi.contains("[31mpack"),
            "{ansi:?}"
        );
        assert!(sweep
            .warnings
            .iter()
            .all(|w| !w.chars().any(char::is_control) && w.len() <= MAX_WARNING_BYTES + 4));
        assert_eq!(
            sweep.warnings[MAX_WARNINGS],
            "6 more warnings are not shown"
        );
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
                &stdio_child_env(
                    std::env::vars_os(),
                    &BTreeMap::new(),
                    BTreeMap::from([
                        ("API_TOKEN".to_string(), "t0ken".to_string()),
                        ("OTHER".to_string(), "0ther".to_string()),
                    ])
                )
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

    /// A host environment holding `vars`.
    fn host_env(vars: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        vars.iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    /// `pairs` as an environment map.
    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    // The daemon passes exactly these variables of its own environment on to a stdio server.
    #[test]
    fn the_baseline_names_the_variables_a_stdio_server_is_given() {
        assert_eq!(
            STDIO_BASELINE_ENV,
            ["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ"]
        );
    }

    // The child's environment is the daemon's baseline, the file's literals over it, and the
    // resolved secret-refs over both.
    #[test]
    fn a_stdio_child_env_layers_the_baseline_the_literals_and_the_secrets() {
        let env = stdio_child_env(
            host_env(&[
                ("PATH", "/daemon/bin"),
                ("HOME", "/home/daemon"),
                ("LANG", "C.UTF-8"),
                ("TZ", "UTC"),
            ]),
            &env_of(&[
                ("PATH", "/server/bin"),
                ("GREETING", "hello"),
                ("TZ", "Europe/Paris"),
            ]),
            env_of(&[("TZ", "Asia/Tokyo"), ("API_TOKEN", "t0ken")]),
        );
        assert_eq!(
            env,
            env_of(&[
                ("API_TOKEN", "t0ken"),
                ("GREETING", "hello"),
                ("HOME", "/home/daemon"),
                ("LANG", "C.UTF-8"),
                ("PATH", "/server/bin"),
                ("TZ", "Asia/Tokyo"),
            ])
        );
    }

    // Nothing but the baseline names comes from the daemon's environment: a canary, the
    // daemon's own credentials, other locale variables and names that only look like a
    // baseline name stay behind.
    #[test]
    fn nothing_but_the_baseline_passes_from_the_daemon_environment() {
        let mut host: Vec<(OsString, OsString)> = STDIO_BASELINE_ENV
            .iter()
            .map(|name| {
                (
                    OsString::from(name),
                    OsString::from(format!("{name}-value")),
                )
            })
            .collect();
        host.extend(host_env(&[
            ("ADVANCE_MCP_CANARY", "canary"),
            ("ANTHROPIC_API_KEY", "sk-daemon"),
            ("AWS_SECRET_ACCESS_KEY", "aws-daemon"),
            ("LC_MESSAGES", "fr_FR.UTF-8"),
            ("path", "/lower/case"),
            ("PATH_EXTRA", "/extra"),
            (" PATH", "/spaced"),
            ("PWD", "/daemon/cwd"),
            ("SHELL", "/bin/zsh"),
        ]));
        let env = stdio_child_env(host, &BTreeMap::new(), BTreeMap::new());
        let expected: BTreeMap<String, String> = STDIO_BASELINE_ENV
            .iter()
            .map(|name| (name.to_string(), format!("{name}-value")))
            .collect();
        assert_eq!(env, expected);
        assert!(!env.values().any(|value| value == "canary"));
    }

    // A baseline variable the daemon does not set is absent from the child's environment, not
    // set to an empty value; one the daemon sets to an empty value is passed as such, and one
    // whose value is not UTF-8 is left out.
    #[test]
    fn an_unset_baseline_variable_is_absent_not_empty() {
        let env = stdio_child_env(
            host_env(&[("PATH", "/bin"), ("LANG", "")]),
            &BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(env, env_of(&[("LANG", ""), ("PATH", "/bin")]));
        for name in [
            "HOME", "USER", "LOGNAME", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ",
        ] {
            assert!(!env.contains_key(name), "{name} is absent");
        }
        assert!(stdio_child_env(Vec::new(), &BTreeMap::new(), BTreeMap::new()).is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let env = stdio_child_env(
                vec![
                    (OsString::from("HOME"), OsString::from_vec(vec![b'/', 0xff])),
                    (OsString::from("TZ"), OsString::from("UTC")),
                ],
                &BTreeMap::new(),
                BTreeMap::new(),
            );
            assert_eq!(env, env_of(&[("TZ", "UTC")]));
        }
    }

    // A stdio server file's `env` literals and `cwd` reach the process the client starts: the
    // literals over the daemon's own baseline, the secret-refs over both, and the working
    // directory as written.
    #[test]
    fn a_server_file_sets_the_literals_and_the_working_directory_of_its_process() {
        let ws = tempfile::tempdir().unwrap();
        server_file(
            ws.path(),
            "local.yaml",
            "server-id: local\ntransport:\n  kind: stdio\n  command: /bin/true\n  env:\n    \
             GREETING: hello\n    PATH: /server/bin\n  cwd: /srv/local\nsecret-refs:\n  \
             API_TOKEN: local-token\n",
        );
        let secrets = ClosureSecretStore::new(|key| match key {
            "local-token" => Some("t0ken".to_string()),
            _ => None,
        });
        let servers = plane(ws.path()).scan().into_servers(Some(&secrets));
        assert!(servers.warnings.is_empty(), "{:?}", servers.warnings);
        match &servers.config.get("local").unwrap().transport {
            McpTransportSpec::Stdio { env, cwd, .. } => {
                assert_eq!(cwd.as_deref(), Some(Path::new("/srv/local")));
                assert_eq!(env.get("GREETING").map(String::as_str), Some("hello"));
                assert_eq!(env.get("PATH").map(String::as_str), Some("/server/bin"));
                assert_eq!(env.get("API_TOKEN").map(String::as_str), Some("t0ken"));
                for (name, value) in env {
                    if ["GREETING", "PATH", "API_TOKEN"].contains(&name.as_str()) {
                        continue;
                    }
                    assert!(
                        STDIO_BASELINE_ENV.contains(&name.as_str()),
                        "{name} is a baseline variable"
                    );
                    assert_eq!(
                        std::env::var(name).ok().as_ref(),
                        Some(value),
                        "{name} has the daemon's value"
                    );
                }
                assert_eq!(
                    env,
                    &stdio_child_env(
                        std::env::vars_os(),
                        &env_of(&[("GREETING", "hello"), ("PATH", "/server/bin")]),
                        env_of(&[("API_TOKEN", "t0ken")]),
                    )
                );
            }
            other => panic!("local is a stdio server: {other:?}"),
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

    /// The operator file of the http server `id` at `endpoint`, binding `credentials` (a YAML
    /// flow sequence).
    fn credentialed_server(workspace: &Path, id: &str, endpoint: &str, credentials: &str) {
        server_file(
            workspace,
            &format!("{id}.yaml"),
            &format!(
                "server-id: {id}\ntransport:\n  kind: http\n  endpoint-url: {endpoint}\n\
                 credentials: {credentials}\n"
            ),
        );
    }

    // An http server's credentials stay secret names in its entry, each checked to be in the
    // store; a server whose secret is missing is skipped with a warning naming the secret and
    // the position, and without a store every server that binds credentials is skipped. A
    // pack's file may not bind credentials at all.
    #[test]
    fn credentials_bind_secret_names_to_an_http_server() {
        let ws = tempfile::tempdir().unwrap();
        credentialed_server(
            ws.path(),
            "remote",
            "https://mcp.example.com/mcp",
            "[{position: bearer, secret: remote-token}, \
             {position: header, key: X-Api-Key, secret: remote-key}]",
        );
        credentialed_server(
            ws.path(),
            "lacking",
            "https://lacking.example.com/mcp",
            "[{position: query, key: api_key, secret: absent-key}]",
        );
        http_server(ws.path(), "plain", "https://plain.example.com/mcp");
        server_file(
            ws.path(),
            "packed.yaml",
            &format!(
                "server-id: packed\ntransport:\n  kind: http\n  \
                 endpoint-url: https://packed.example.com/mcp\n\
                 credentials: [{{position: bearer, secret: remote-token}}]\n{}",
                origin_block("p@1.0.0", "packed")
            ),
        );
        let secrets = ClosureSecretStore::new(|key| match key {
            "remote-token" => Some("t0ken".to_string()),
            "remote-key" => Some("k3y".to_string()),
            _ => None,
        });

        let files = plane(ws.path()).scan();
        assert_eq!(files.server_ids(), ["lacking", "plain", "remote"]);
        let packed = one_warning(files.warnings(), "\"packed.yaml\"");
        assert!(
            packed.contains("is skipped")
                && packed.contains("pack-origin server may not bind cap-secrets credentials"),
            "{packed}"
        );
        assert!(files.need_secrets(), "credentials need the secret store");
        let servers = files.into_servers(Some(&secrets));
        match &servers.config.get("remote").unwrap().transport {
            McpTransportSpec::Http { capability, .. } => assert_eq!(
                capability.credentials,
                [
                    CredentialBinding {
                        position: CredentialPosition::BearerToken,
                        secret_name: "remote-token".into(),
                    },
                    CredentialBinding {
                        position: CredentialPosition::CustomHeader {
                            key: "X-Api-Key".into()
                        },
                        secret_name: "remote-key".into(),
                    },
                ]
            ),
            other => panic!("remote is an http server: {other:?}"),
        }
        let shown = format!("{:?}", servers.config);
        for hidden in ["t0ken", "k3y", "remote-token", "remote-key"] {
            assert!(!shown.contains(hidden), "the entry's Debug shows {hidden}");
        }
        assert!(servers.config.get("plain").is_ok());
        assert!(servers.config.get("lacking").is_err());
        let warning = one_warning(&servers.warnings, "server 'lacking' is skipped");
        assert!(
            warning.contains("\"absent-key\"") && warning.contains("query \"api_key\""),
            "{warning}"
        );
        assert!(
            servers
                .warnings
                .iter()
                .all(|w| !w.contains("t0ken") && !w.contains("k3y")),
            "a warning never holds a secret"
        );

        // Without a store, every server that binds credentials is left out, and only those.
        let servers = plane(ws.path()).scan().into_servers(None);
        assert_eq!(
            servers
                .config
                .list_servers()
                .map(|e| e.server_id.as_str())
                .collect::<Vec<_>>(),
            ["plain"]
        );
        for id in ["remote", "lacking"] {
            let warning = one_warning(&servers.warnings, &format!("server '{id}' is skipped"));
            assert!(warning.contains("secret store is not open"), "{warning}");
        }
    }

    // A server file with an `origin` block may not reach the host's loopback: the loader skips
    // it with a warning and exempts nothing for it, while an operator's loopback file keeps its
    // exemption and a pack's file off loopback loads.
    #[test]
    fn a_pack_server_file_on_loopback_is_skipped_and_exempts_nothing() {
        let ws = tempfile::tempdir().unwrap();
        http_server(ws.path(), "operator", "http://127.0.0.1:8931/mcp");
        for (id, endpoint) in [
            ("packed", "http://127.0.0.1:8932/mcp"),
            ("named", "http://localhost:8933/mcp"),
            ("remote", "https://mcp.example.com/mcp"),
        ] {
            server_file(
                ws.path(),
                &format!("{id}.yaml"),
                &format!(
                    "server-id: {id}\ntransport:\n  kind: http\n  endpoint-url: {endpoint}\n{}",
                    origin_block("p@1.0.0", id)
                ),
            );
        }

        let files = plane(ws.path()).scan();
        assert_eq!(files.server_ids(), ["operator", "remote"]);
        for name in ["\"packed.yaml\"", "\"named.yaml\""] {
            let warning = one_warning(files.warnings(), name);
            assert!(
                warning.contains("is skipped")
                    && warning.contains("the pack p@1.0.0 wrote it")
                    && warning.contains("loopback"),
                "{warning}"
            );
        }
        let servers = files.into_servers(None);
        assert!(servers.loopback.covers("http://127.0.0.1:8931/mcp"));
        for refused in ["http://127.0.0.1:8932/mcp", "http://localhost:8933/mcp"] {
            assert!(
                !servers.loopback.covers(refused),
                "a pack's file exempts nothing: {refused}"
            );
        }
        assert!(servers.config.get("packed").is_err());
        assert!(servers.config.get("remote").is_ok());
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
        grant_params(store, grantee, capability, &[]);
    }

    fn grant_params(store: &GrantStore, grantee: &str, capability: &str, params: &[(&str, &str)]) {
        store
            .insert(Grant {
                id: GrantId::new(format!("static:{grantee}:{capability}")),
                grantee: grantee.to_string(),
                capability: capability.to_string(),
                params: params
                    .iter()
                    .map(|(key, value)| CapParam {
                        key: (*key).into(),
                        value: (*value).into(),
                    })
                    .collect(),
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

    struct CleanLeak;
    impl LeakDetector for CleanLeak {
        fn scan(&self, _: &str, _: ScanContext) -> ScanResult {
            ScanResult::Clean
        }
        fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    fn cached_tool(server: &str, name: &str, description: &str) -> cap_mcp::McpToolInfo {
        cap_mcp::McpToolInfo {
            name: name.into(),
            description: description.into(),
            server_id: server.into(),
            input_schema: None,
        }
    }

    // A grant-filtered cache listing is what the model sees: `<server>__<tool>`,
    // pack origin in the description, web-family tools only with the `web` grant; the
    // operator's servers come first, each server's tools by name.
    #[tokio::test]
    async fn a_grant_filtered_cache_listing_is_shown_as_server_tool() {
        let store = grant_store();
        grant_params(
            &store,
            "alice",
            "mcp",
            &[("servers", "scholar"), ("tool-patterns", "search*,web.*")],
        );
        grant(&store, "alice", "web");
        grant(&store, "bob", "mcp");
        grant(&store, "dave", "web");
        let client = Arc::new(McpClient::new(
            Arc::new(McpServersConfig::builder().build()),
            Arc::new(CleanLeak),
            None,
        ));
        client.store_cached_tools(
            "scholar",
            vec![
                cached_tool("scholar", "search_papers", "Search papers"),
                cached_tool("scholar", "fetch_pdf", "Fetch a PDF"),
                cached_tool("scholar", "web.search", "Search the web"),
                cached_tool("scholar", "scholar__already", "Already named"),
            ],
        );
        client.store_cached_tools(
            "private",
            vec![cached_tool("private", "secret", "Do not leak")],
        );
        client.store_cached_tools(
            "local-tools",
            vec![cached_tool("local-tools", "echo", "Echo")],
        );
        let mut origins = BTreeMap::new();
        origins.insert("scholar".into(), "papers]@1.0.0".into());
        let runtime = McpRuntime::for_test(
            client,
            mcp_gate(
                Arc::new(RecordingCheck::default()),
                store,
                WebRunMode::Standard,
            ),
            origins,
        );
        let inv = LiveCallableInventory::new(
            vec![ToolEntry {
                name: "editor.format".into(),
                description: "Format".into(),
                params_schema: serde_json::json!({}),
            }],
            runtime,
        );

        let names = |agent: &str| -> Vec<String> {
            inv.list_mcp_tools(agent)
                .into_iter()
                .map(|e| e.name)
                .collect()
        };
        assert_eq!(
            names("alice"),
            ["scholar__search_papers", "scholar__web.search"]
        );
        assert_eq!(
            names("bob"),
            [
                "local-tools__echo",
                "private__secret",
                "scholar__already",
                "scholar__fetch_pdf",
                "scholar__search_papers"
            ]
        );
        assert!(names("carol").is_empty());
        assert!(names("dave").is_empty());

        let alice = inv.list_mcp_tools("alice");
        assert_eq!(alice[0].description, "Search papers [pack papers_@1.0.0]");
        assert_eq!(alice[0].server_id, "scholar");
        assert_eq!(
            inv.list_wasm_tools("alice")
                .into_iter()
                .map(|t| t.name)
                .collect::<Vec<_>>(),
            ["editor.format"]
        );
    }

    // The daemon reads the inventory under the root's mailbox key `agent:<handle>` while the
    // root's grants are stored under its id. An inventory built for the agent maps the key
    // to the id, so a read under either lists the same tools and reads the same `web` grant;
    // the handle on its own, or any other id, holds nothing. Without the mapping the mailbox
    // key is looked up as named, and nothing is stored under it.
    #[tokio::test]
    async fn a_read_under_an_alias_reads_the_grants_stored_under_the_agent_id() {
        const ROOT_ID: &str = "0b1f6c4e-root-id";
        let store = grant_store();
        grant_params(&store, ROOT_ID, "mcp", &[("servers", "scholar")]);
        grant(&store, ROOT_ID, "web");
        let client = Arc::new(McpClient::new(
            Arc::new(McpServersConfig::builder().build()),
            Arc::new(CleanLeak),
            None,
        ));
        client.store_cached_tools(
            "scholar",
            vec![
                cached_tool("scholar", "search_papers", "Search papers"),
                cached_tool("scholar", "web.search", "Search the web"),
            ],
        );
        let runtime = McpRuntime::for_test(
            client,
            mcp_gate(
                Arc::new(RecordingCheck::default()),
                store,
                WebRunMode::Standard,
            ),
            BTreeMap::new(),
        );
        let aliases = [ROOT_ID.to_string(), "agent:root".to_string()];
        let inv = LiveCallableInventory::for_agent(vec![], Arc::clone(&runtime), ROOT_ID, &aliases);
        let names = |agent: &str| -> Vec<String> {
            inv.list_mcp_tools(agent)
                .into_iter()
                .map(|e| e.name)
                .collect()
        };
        assert_eq!(
            names("agent:root"),
            ["scholar__search_papers", "scholar__web.search"]
        );
        assert_eq!(names(ROOT_ID), names("agent:root"));
        assert!(
            names("root").is_empty(),
            "the handle alone names no grantee"
        );
        assert!(names("agent:someone-else").is_empty());
        assert!(names("someone-else").is_empty());

        let as_named = LiveCallableInventory::new(vec![], runtime);
        assert_eq!(
            as_named
                .list_mcp_tools(ROOT_ID)
                .into_iter()
                .map(|e| e.name)
                .collect::<Vec<_>>(),
            ["scholar__search_papers", "scholar__web.search"]
        );
        assert!(as_named.list_mcp_tools("agent:root").is_empty());
    }

    fn mcp_names(inventory: &LiveCallableInventory, agent: &str) -> Vec<String> {
        inventory
            .list_mcp_tools(agent)
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    // An agent is shown, within the MCP budget, the tools of the operator's servers first,
    // then those of trusted packs' servers, then the other packs', each group by server id
    // and each server's tools by name. The tools past the budget are left out and counted,
    // the prompt's tools section closes with a line saying how many, and the first read that
    // leaves tools out is logged, a later read leaving out as many is not.
    #[tokio::test]
    async fn the_mcp_budget_goes_to_operator_then_trusted_then_untrusted_servers() {
        let ws = tempfile::tempdir().unwrap();
        let store = grant_store();
        grant(&store, "root", "mcp");
        let client = Arc::new(McpClient::new(
            Arc::new(McpServersConfig::builder().build()),
            Arc::new(CleanLeak),
            None,
        ));
        // Six tools a server, listed out of name order; each line about 1.5 KiB.
        let text = "d".repeat(1500);
        for server in ["zeta", "alpha", "beta", "gamma", "aaa"] {
            client.store_cached_tools(
                server,
                (0..6)
                    .rev()
                    .map(|i| cached_tool(server, &format!("t{i}"), &text))
                    .collect(),
            );
        }
        let mut origins = BTreeMap::new();
        origins.insert("beta".to_string(), "trusted@1.0.0".to_string());
        origins.insert("gamma".to_string(), "other@1.0.0".to_string());
        origins.insert("aaa".to_string(), "third@1.0.0".to_string());
        let log = Arc::new(RecordingLog::default());
        let runtime = McpRuntime::for_test_over(
            client,
            mcp_gate(
                Arc::new(RecordingCheck::default()),
                store,
                WebRunMode::Standard,
            ),
            origins,
            plane(ws.path()).with_log(LogHandle::new(log.clone())),
            LoopbackExemptions::none(),
        );
        runtime.set_trusted_packs(BTreeSet::from(["trusted@1.0.0".to_string()]));
        let inv = LiveCallableInventory::new(vec![], runtime);

        let order: Vec<String> = ["alpha", "zeta", "beta", "aaa", "gamma"]
            .iter()
            .flat_map(|server| (0..6).map(move |i| format!("{server}__t{i}")))
            .collect();
        let shown = inv.mcp_tools_shown("root");
        let names: Vec<&str> = shown.tools.iter().map(|e| e.name.as_str()).collect();
        // The operator's 12 lines and the trusted pack's 6 fit; 3 of the next untrusted
        // pack's fit before the budget is spent.
        assert_eq!(names.len(), 21, "{names:?}");
        assert_eq!(names, order[..21]);
        assert_eq!(shown.not_shown, 9);
        assert_eq!(
            mcp_names(&inv, "root"),
            names,
            "the Client API reads the same entries"
        );

        // What the model is shown: the lines within the budget, closed by the count.
        let section = advance_context_engine::format_available_tools_section_with_not_shown(
            &advance_context_engine::assemble_unified(vec![], vec![], shown.tools.clone()),
            shown.not_shown,
        );
        let line_bytes: Vec<usize> = section
            .lines()
            .filter(|l| l.starts_with("- "))
            .map(|l| l.len() + 1)
            .collect();
        assert_eq!(line_bytes.len(), 21);
        let spent: usize = line_bytes.iter().sum();
        assert!(spent <= MCP_PROMPT_BUDGET_BYTES, "{spent}");
        assert!(
            spent + line_bytes[line_bytes.len() - 1] > MCP_PROMPT_BUDGET_BYTES,
            "the next line would not fit: {spent}"
        );
        assert_eq!(
            section.lines().last(),
            Some("… 9 more MCP tools not shown"),
            "{section}"
        );

        let lines = log.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("9 of the 30 MCP tools agent root may call are left out"),
            "{lines:?}"
        );
        inv.mcp_tools_shown("root");
        assert_eq!(log.lines().len(), 1, "the same cut is logged once");
        assert!(inv.mcp_tools_shown("someone-else").tools.is_empty());
        assert_eq!(
            log.lines().len(),
            1,
            "a read that leaves nothing out logs nothing"
        );
        inv.mcp_tools_shown("root");
        assert_eq!(log.lines().len(), 2, "after one, a cut is logged again");
    }

    // The description of a pack's server's tool ends in the pack's marker within the
    // description cap: the text before the marker is cut, never the marker. An operator's
    // tool keeps its description as listed.
    #[tokio::test]
    async fn the_pack_marker_is_kept_within_the_description_cap() {
        let store = grant_store();
        grant(&store, "root", "mcp");
        let client = Arc::new(McpClient::new(
            Arc::new(McpServersConfig::builder().build()),
            Arc::new(CleanLeak),
            None,
        ));
        // A description at the cap, of two-byte characters.
        let full = "é".repeat(MAX_TOOL_DESCRIPTION_BYTES / 2);
        client.store_cached_tools(
            "pk",
            vec![
                cached_tool("pk", "long", &full),
                cached_tool("pk", "short", "Short"),
                cached_tool("pk", "none", ""),
            ],
        );
        client.store_cached_tools("op", vec![cached_tool("op", "long", &full)]);
        let mut origins = BTreeMap::new();
        origins.insert("pk".to_string(), "p@1.0.0".to_string());
        let runtime = McpRuntime::for_test(
            client,
            mcp_gate(
                Arc::new(RecordingCheck::default()),
                store,
                WebRunMode::Standard,
            ),
            origins,
        );
        let inv = LiveCallableInventory::new(vec![], runtime);
        let shown = inv.list_mcp_tools("root");
        let description = |name: &str| -> String {
            shown
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("{name} shown: {shown:?}"))
                .description
                .clone()
        };

        let long = description("pk__long");
        assert!(long.len() <= MAX_TOOL_DESCRIPTION_BYTES, "{}", long.len());
        let body = long
            .strip_suffix(" [pack p@1.0.0]")
            .unwrap_or_else(|| panic!("the marker ends the description: {long}"));
        assert!(body.ends_with('…'), "the text before it is cut");
        assert!(body.trim_end_matches('…').chars().all(|c| c == 'é'));
        assert_eq!(description("pk__short"), "Short [pack p@1.0.0]");
        assert_eq!(description("pk__none"), "[pack p@1.0.0]");
        assert_eq!(
            description("op__long"),
            full,
            "an operator's tool is as listed"
        );
    }

    /// An MCP server double that answers every `tools/list` with the tools it is given and
    /// counts the listings: fails each while it is given none, and holds each while it is
    /// held, until released.
    struct ListingServer {
        server_id: String,
        tools: std::sync::Mutex<Option<Vec<String>>>,
        hold: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
        listings: std::sync::atomic::AtomicUsize,
    }

    impl ListingServer {
        fn new(server_id: &str, tools: Option<Vec<String>>) -> Arc<Self> {
            Arc::new(Self {
                server_id: server_id.to_string(),
                tools: std::sync::Mutex::new(tools),
                hold: std::sync::Mutex::new(None),
                listings: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn answer(&self, tools: Option<Vec<String>>) {
            *self.tools.lock().unwrap() = tools;
        }

        /// Hold each listing until the returned notify is notified.
        fn hold(&self) -> Arc<tokio::sync::Notify> {
            let notify = Arc::new(tokio::sync::Notify::new());
            *self.hold.lock().unwrap() = Some(Arc::clone(&notify));
            notify
        }

        fn listings(&self) -> usize {
            self.listings.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl cap_mcp::McpTransport for ListingServer {
        async fn invoke(
            &self,
            _caller: Option<&str>,
            method: &str,
            _params: serde_json::Value,
        ) -> Result<Vec<u8>, cap_mcp::McpError> {
            assert_eq!(method, "tools/list");
            self.listings.fetch_add(1, Ordering::SeqCst);
            let hold = self.hold.lock().unwrap().clone();
            if let Some(hold) = hold {
                hold.notified().await;
            }
            let tools = self.tools.lock().unwrap().clone();
            match tools {
                Some(names) => {
                    let tools: Vec<serde_json::Value> = names
                        .iter()
                        .map(|name| serde_json::json!({ "name": name }))
                        .collect();
                    Ok(serde_json::to_vec(&serde_json::json!({ "tools": tools })).unwrap())
                }
                None => Err(cap_mcp::McpError::transport("the server is down")),
            }
        }

        async fn notify(
            &self,
            _method: &str,
            _params: Option<serde_json::Value>,
        ) -> Result<(), cap_mcp::McpError> {
            Ok(())
        }

        fn server_id(&self) -> &str {
            &self.server_id
        }
    }

    /// A client whose configured servers are `servers`, each already connected.
    fn listing_client(servers: &[Arc<ListingServer>]) -> Arc<McpClient> {
        let mut config = McpServersConfig::builder();
        let mut injected: std::collections::HashMap<String, Arc<dyn cap_mcp::McpTransport>> =
            std::collections::HashMap::new();
        for server in servers {
            config = config
                .add_server(McpServerEntry {
                    server_id: server.server_id.clone(),
                    description: String::new(),
                    transport: McpTransportSpec::Stdio {
                        command: "/bin/true".into(),
                        args: vec![],
                        env: BTreeMap::new(),
                        cwd: None,
                    },
                    tool_patterns: None,
                    tool_schemas: BTreeMap::new(),
                })
                .unwrap();
            injected.insert(
                server.server_id.clone(),
                Arc::clone(server) as Arc<dyn cap_mcp::McpTransport>,
            );
        }
        Arc::new(McpClient::new_with_transports(
            Arc::new(config.build()),
            Arc::new(CleanLeak),
            injected,
        ))
    }

    /// A runtime whose root may reach `servers` alone, over `client`.
    fn root_reaching(client: Arc<McpClient>, servers: &str) -> Arc<McpRuntime> {
        let store = grant_store();
        grant_params(&store, "root", "mcp", &[("servers", servers)]);
        McpRuntime::for_test(
            client,
            mcp_gate(
                Arc::new(RecordingCheck::default()),
                store,
                WebRunMode::Standard,
            ),
            BTreeMap::new(),
        )
    }

    /// The tasks alive on the test's runtime.
    fn alive_tasks() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    /// Let the tasks a read started run to their end.
    async fn settle() {
        for _ in 0..64 {
            if alive_tasks() == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("background listings did not settle");
    }

    fn names_of(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("t{i}")).collect()
    }

    // The first read answers from the empty cache and lists the server the grant reaches in
    // the background. Once that listing is cached, a read starts no task at all; a server no
    // grant reaches is never listed.
    #[tokio::test]
    async fn a_read_of_a_cached_inventory_starts_no_listing() {
        let srv = ListingServer::new("srv", Some(vec!["echo".into()]));
        let other = ListingServer::new("other", Some(vec!["x".into()]));
        let inv = LiveCallableInventory::new(
            vec![],
            root_reaching(listing_client(&[srv.clone(), other.clone()]), "srv"),
        );

        assert!(mcp_names(&inv, "root").is_empty(), "the cache is empty");
        assert_eq!(alive_tasks(), 1, "the read starts one listing");
        settle().await;
        assert_eq!(srv.listings(), 1);

        assert_eq!(mcp_names(&inv, "root"), ["srv__echo"]);
        assert_eq!(
            alive_tasks(),
            0,
            "a read of a cached inventory starts nothing"
        );
        assert_eq!(mcp_names(&inv, "root"), ["srv__echo"]);
        assert_eq!(alive_tasks(), 0);
        settle().await;
        assert_eq!(srv.listings(), 1);
        assert_eq!(
            other.listings(),
            0,
            "a server no grant reaches is never listed"
        );
    }

    // A failed listing is not cached, so the next read lists the server again; while a
    // listing runs, a read starts no other.
    #[tokio::test]
    async fn a_failed_listing_is_tried_again_and_a_running_one_is_not_doubled() {
        let srv = ListingServer::new("srv", None);
        let inv = LiveCallableInventory::new(
            vec![],
            root_reaching(listing_client(&[srv.clone()]), "srv"),
        );
        mcp_names(&inv, "root");
        settle().await;
        assert_eq!(srv.listings(), 1);
        mcp_names(&inv, "root");
        settle().await;
        assert_eq!(srv.listings(), 2, "the failed listing is tried again");

        srv.answer(Some(vec!["echo".into()]));
        let release = srv.hold();
        mcp_names(&inv, "root");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(srv.listings(), 3, "the listing runs, held");
        assert!(mcp_names(&inv, "root").is_empty());
        assert_eq!(alive_tasks(), 1, "a read while it runs starts no other");
        release.notify_one();
        settle().await;
        assert_eq!(srv.listings(), 3);
        assert_eq!(mcp_names(&inv, "root"), ["srv__echo"]);
        assert_eq!(alive_tasks(), 0);
    }

    // A listing the tool cache cut is listed again once the cache has room for more of it,
    // and not before: one cut to its share of a full cache would be cut the same way.
    #[tokio::test]
    async fn a_cut_listing_is_listed_again_once_the_cache_has_room_for_it() {
        let srv = ListingServer::new("srv", Some(names_of(cap_mcp::MAX_TOOLS_PER_SERVER)));
        let client = listing_client(&[srv.clone()]);
        let full = |server: &str| -> Vec<cap_mcp::McpToolInfo> {
            names_of(cap_mcp::MAX_TOOLS_PER_SERVER)
                .iter()
                .map(|name| cached_tool(server, name, ""))
                .collect()
        };
        // Four other servers' listings, cached, crowd `srv` to its share of a full cache.
        client.store_cached_tools("srv", full("srv"));
        for hog in ["hog1", "hog2", "hog3", "hog4"] {
            client.store_cached_tools(hog, full(hog));
        }
        let cached_srv = {
            let client = Arc::clone(&client);
            move || {
                client
                    .cached_tools()
                    .into_iter()
                    .find(|listing| listing.server_id == "srv")
                    .expect("srv is cached")
            }
        };
        assert!(cached_srv().is_truncated());
        let inv = LiveCallableInventory::new(vec![], root_reaching(Arc::clone(&client), "srv"));
        assert_eq!(mcp_names(&inv, "root").len(), cached_srv().tools.len());
        assert_eq!(
            alive_tasks(),
            0,
            "a listing cut to its share is not listed again"
        );

        // One of them lists nothing now: the room it held is back.
        client.store_cached_tools("hog4", vec![]);
        mcp_names(&inv, "root");
        assert_eq!(alive_tasks(), 1, "the cut listing is listed again");
        settle().await;
        assert_eq!(srv.listings(), 1);
        assert!(!cached_srv().is_truncated());
        assert_eq!(mcp_names(&inv, "root").len(), cap_mcp::MAX_TOOLS_PER_SERVER);
        assert_eq!(alive_tasks(), 0);
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
        let sweep = control.remove_origins_not_in(&installed);
        assert_eq!(sweep.removed, ["srv.yaml"]);
        assert!(sweep.warnings.is_empty(), "{:?}", sweep.warnings);
        assert!(!ws.path().join(".advance/mcp-servers/srv.yaml").exists());
        assert!(ws.path().join(".advance/mcp-servers/ops.yaml").exists());
        installed.insert("p@1.0.0".into());
        sink.register(registration("srv", "p@1.0.0")).unwrap();
        assert_eq!(
            control.remove_origins_not_in(&installed),
            McpSweep::default()
        );
        assert!(ws.path().join(".advance/mcp-servers/srv.yaml").exists());
    }

    // The sweep reads each file's origin block alone: a stale pack file goes whether or not
    // the loader would serve it, hidden names included and past the server cap; what the
    // sweep cannot read it reports and leaves, following no symlink.
    #[cfg(unix)]
    #[test]
    fn stale_pack_files_are_swept_whatever_the_loader_makes_of_them() {
        let ws = tempfile::tempdir().unwrap();
        let dir = ws.path().join(".advance/mcp-servers");
        let gone = |id: &str| origin_block("gone@1.0.0", id);
        let mut stale: Vec<String> = Vec::new();
        for (name, body) in [
            // A stdio server while stdio is disabled.
            (
                "stdio.yaml",
                format!("server-id: stdio\n{STDIO}{}", gone("stdio")),
            ),
            // Over the loader's cap, under the sweep's.
            (
                "big.yaml",
                format!(
                    "server-id: big\n{STDIO}description: \"{}\"\n{}",
                    "x".repeat(MAX_MCP_SERVER_YAML_BYTES as usize),
                    gone("big")
                ),
            ),
            // Named after another server, a key the schema refuses, a hidden name.
            (
                "misnamed.yaml",
                format!("server-id: other\n{STDIO}{}", gone("other")),
            ),
            (
                "extra.yaml",
                format!(
                    "server-id: extra\n{STDIO}tool-patterns: [a]\n{}",
                    gone("extra")
                ),
            ),
            (
                ".hidden.yaml",
                format!("server-id: .hidden\n{STDIO}{}", gone(".hidden")),
            ),
        ] {
            server_file(ws.path(), name, &body);
            stale.push(name.to_string());
        }
        for n in 0..cap_mcp::MAX_SERVERS + 2 {
            let name = format!("s{n:04}.yaml");
            server_file(
                ws.path(),
                &name,
                &format!("server-id: s{n:04}\n{STDIO}{}", gone(&format!("s{n:04}"))),
            );
            stale.push(name);
        }
        stale.sort();
        // Left: an operator file, a file of an installed pack, and files whose origin cannot
        // be read: broken YAML, a symlink to a stale file outside, one over the sweep's bound.
        stdio_server(ws.path(), "ops");
        server_file(
            ws.path(),
            "kept.yaml",
            &format!(
                "server-id: kept\n{STDIO}{}",
                origin_block("here@1.0.0", "kept")
            ),
        );
        server_file(ws.path(), "broken.yaml", "server-id: [unclosed\n");
        let outside = ws.path().join("outside.yaml");
        std::fs::write(
            &outside,
            format!("server-id: linked\n{STDIO}{}", gone("linked")),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("linked.yaml")).unwrap();
        server_file(
            ws.path(),
            "huge.yaml",
            &format!(
                "server-id: huge\n{STDIO}# {}\n{}",
                "x".repeat(MAX_SWEEP_FILE_BYTES as usize),
                gone("huge")
            ),
        );

        let log = Arc::new(RecordingLog::default());
        let control = McpControlPlane::new(
            ws.path(),
            &McpConfig {
                allow_stdio: false,
                ..McpConfig::default()
            },
        )
        .with_log(LogHandle::new(log.clone()));
        let installed = BTreeSet::from(["here@1.0.0".to_string()]);
        let sweep = control.remove_origins_not_in(&installed);
        assert_eq!(sweep.removed, stale);
        for name in &stale {
            assert!(std::fs::symlink_metadata(dir.join(name)).is_err(), "{name}");
        }
        for name in [
            "ops.yaml",
            "kept.yaml",
            "broken.yaml",
            "linked.yaml",
            "huge.yaml",
        ] {
            assert!(std::fs::symlink_metadata(dir.join(name)).is_ok(), "{name}");
        }
        assert!(outside.is_file(), "the link's target is untouched");
        assert_eq!(sweep.warnings.len(), 3, "{:?}", sweep.warnings);
        let broken = one_warning(&sweep.warnings, "\"broken.yaml\"");
        assert!(
            broken.contains("is not swept: its origin cannot be read"),
            "{broken}"
        );
        let linked = one_warning(&sweep.warnings, "\"linked.yaml\"");
        assert!(linked.contains("symbolic link"), "{linked}");
        let huge = one_warning(&sweep.warnings, "\"huge.yaml\"");
        assert!(huge.contains("larger than"), "{huge}");
        let lines = log.lines();
        assert_eq!(lines.len(), stale.len(), "one line per removal: {lines:?}");
        assert!(lines.iter().all(
            |line| line.starts_with("advance: mcp: removed server file ")
                && line.ends_with(": its pack gone@1.0.0 is not installed")
        ));

        // Nothing left to sweep; a missing directory sweeps nothing and says nothing.
        assert_eq!(
            control.remove_origins_not_in(&installed).removed,
            [] as [&str; 0]
        );
        let absent = tempfile::tempdir().unwrap();
        assert_eq!(
            plane(absent.path()).remove_origins_not_in(&installed),
            McpSweep::default()
        );
    }

    /// The pack `pack`'s stdio registration of `id`.
    fn stdio_registration(id: &str, pack: &str) -> McpRegistration {
        McpRegistration {
            transport: McpTransportDecl::Stdio {
                command: "/bin/true".into(),
                args: vec!["--flag".into()],
                env: BTreeMap::new(),
                cwd: None,
            },
            ..registration(id, pack)
        }
    }

    /// The reason of a refused registration.
    fn refusal(result: Result<impl std::fmt::Debug, PackBridgeError>) -> String {
        match result {
            Err(PackBridgeError::Pack(PackError::ConstraintViolation { reason })) => reason,
            other => panic!("expected a constraint violation, got {other:?}"),
        }
    }

    // The sink writes nothing the loader would not serve: a hidden id, a stdio server while
    // stdio is disabled, a body over the cap, a body that does not re-parse.
    #[test]
    fn the_sink_refuses_what_the_loader_would_never_serve() {
        let ws = tempfile::tempdir().unwrap();
        let dir = ws.path().join(".advance/mcp-servers");
        let sink = ControlPlaneMcpSink::new(plane(ws.path()));
        let reason = refusal(sink.register(registration(".hidden", "p@1.0.0")));
        assert!(
            reason.contains("\".hidden\"") && reason.contains("not starting with '.'"),
            "{reason}"
        );
        let reason = refusal(sink.deregister(".hidden"));
        assert!(reason.contains("not starting with '.'"), "{reason}");

        let mut big = registration("big", "p@1.0.0");
        big.description = "x".repeat(MAX_MCP_SERVER_YAML_BYTES as usize + 1);
        let reason = refusal(sink.register(big));
        assert!(reason.contains("more than the 65536"), "{reason}");

        // Quoted into the file, a control character comes back out of it, and the schema
        // refuses it: the file would not describe this registration.
        let mut unparsable = registration("odd", "p@1.0.0");
        unparsable.description = "tab\there".into();
        let reason = refusal(sink.register(unparsable));
        assert!(
            reason.contains("does not round-trip") && reason.contains("control"),
            "{reason}"
        );
        assert!(!dir.exists(), "a refused registration writes nothing");

        let no_stdio = ControlPlaneMcpSink::new(McpControlPlane::new(
            ws.path(),
            &McpConfig {
                allow_stdio: false,
                ..McpConfig::default()
            },
        ));
        let reason = refusal(no_stdio.register(stdio_registration("local", "p@1.0.0")));
        assert!(reason.contains("mcp.allow-stdio: false"), "{reason}");
        assert!(!dir.exists());
        assert!(no_stdio
            .register(registration("remote", "p@1.0.0"))
            .unwrap()
            .created());
        assert!(dir.join("remote.yaml").is_file());
        assert!(sink
            .register(stdio_registration("local", "p@1.0.0"))
            .unwrap()
            .created());
    }

    // Every scalar is quoted, so an id or a secret-ref key that plain YAML would read as
    // another type comes back as the same string, and the loader serves the file.
    #[test]
    fn the_sink_writes_a_file_the_loader_reads_back_as_the_same_server() {
        let ws = tempfile::tempdir().unwrap();
        let path = ws.path().join(".advance/mcp-servers/-.yaml");
        let mut registration = stdio_registration("-", "p@1.0.0");
        registration.description = "a: b #c".into();
        registration.secret_refs = BTreeMap::from([
            ("null".to_string(), "k1".to_string()),
            ("TOKEN".to_string(), "k: 2".to_string()),
            ("no".to_string(), "k3".to_string()),
        ]);
        let sink = ControlPlaneMcpSink::new(plane(ws.path()));
        assert!(sink.register(registration.clone()).unwrap().created());
        let body = std::fs::read_to_string(&path).unwrap();
        let manifest = parse_mcp_server_manifest_str(&body).unwrap();
        assert_eq!(manifest.server_id, "-");
        assert_eq!(manifest.description, registration.description);
        assert_eq!(manifest.transport, registration.transport);
        assert_eq!(manifest.secret_refs, registration.secret_refs);
        assert!(matches_registration(&manifest, &registration), "{body}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        }
        assert!(
            !sink.register(registration).unwrap().created(),
            "the same registration again writes nothing"
        );
        let files = plane(ws.path()).scan();
        assert_eq!(files.server_ids(), ["-"]);
        assert!(files.warnings().is_empty(), "{:?}", files.warnings());
        assert!(
            std::fs::read_dir(ws.path().join(".advance/mcp-servers"))
                .unwrap()
                .all(|e| e.unwrap().file_name() == "-.yaml"),
            "no temporary file is left"
        );
    }

    // A stdio registration's `env` literals and `cwd` are written into its server file, every
    // name and value quoted, and read back unchanged: names and values that plain YAML would
    // read as another type or as more document, an empty value, spaces kept at both ends. The
    // loader serves the file with those literals over the daemon's baseline, in that directory;
    // a registration whose `env` or `cwd` differ is other content.
    #[test]
    fn env_literals_and_a_working_directory_round_trip_through_the_server_file() {
        let env = BTreeMap::from([
            ("null".to_string(), "~".to_string()),
            ("no".to_string(), "yes".to_string()),
            ("TRUE".to_string(), "123".to_string()),
            ("_1".to_string(), String::new()),
            (
                "QUOTED".to_string(),
                "'single' \"double\" back\\slash".to_string(),
            ),
            ("SHAPED".to_string(), "a: b #c - [d] {e}".to_string()),
            ("SPACED".to_string(), "  both ends  ".to_string()),
            ("ACCENT".to_string(), "caf\u{e9}".to_string()),
        ]);
        let cwd = "/srv/with space/#x: y".to_string();
        let registration = McpRegistration {
            transport: McpTransportDecl::Stdio {
                command: "/bin/true".into(),
                args: vec!["--flag".into()],
                env: env.clone(),
                cwd: Some(cwd.clone()),
            },
            ..registration("envy", "p@1.0.0")
        };

        let body = render_server_file(&registration);
        let manifest = parse_mcp_server_manifest_str(&body)
            .unwrap_or_else(|e| panic!("the rendered file parses: {e}\n{body}"));
        assert_eq!(manifest.transport, registration.transport, "{body}");
        assert!(matches_registration(&manifest, &registration), "{body}");

        let ws = tempfile::tempdir().unwrap();
        let sink = ControlPlaneMcpSink::new(plane(ws.path()));
        assert!(sink.register(registration.clone()).unwrap().created());
        let written =
            std::fs::read_to_string(ws.path().join(".advance/mcp-servers/envy.yaml")).unwrap();
        assert_eq!(written, body);
        assert!(!sink.register(registration.clone()).unwrap().created());
        for other in [
            McpTransportDecl::Stdio {
                command: "/bin/true".into(),
                args: vec!["--flag".into()],
                env: BTreeMap::new(),
                cwd: Some(cwd.clone()),
            },
            McpTransportDecl::Stdio {
                command: "/bin/true".into(),
                args: vec!["--flag".into()],
                env: env.clone(),
                cwd: None,
            },
        ] {
            let changed = McpRegistration {
                transport: other,
                ..registration.clone()
            };
            let reason = refusal(sink.register(changed));
            assert!(reason.contains("different content"), "{reason}");
        }

        let files = plane(ws.path()).scan();
        assert_eq!(files.server_ids(), ["envy"]);
        assert!(files.warnings().is_empty(), "{:?}", files.warnings());
        let servers = files.into_servers(None);
        match &servers.config.get("envy").unwrap().transport {
            McpTransportSpec::Stdio {
                env: child,
                cwd: dir,
                ..
            } => {
                assert_eq!(
                    child,
                    &stdio_child_env(std::env::vars_os(), &env, BTreeMap::new())
                );
                assert_eq!(dir.as_deref(), Some(Path::new(&cwd)));
            }
            other => panic!("envy is a stdio server: {other:?}"),
        }
    }

    // An operator's file is neither replaced nor removed by a pack, and a pack cannot
    // register the same server twice under two config refs or with other content.
    #[test]
    fn the_sink_leaves_an_operator_file_and_a_foreign_registration_alone() {
        let ws = tempfile::tempdir().unwrap();
        let dir = ws.path().join(".advance/mcp-servers");
        http_server(ws.path(), "ops", "https://mcp.example.com/ops");
        let before = std::fs::read_to_string(dir.join("ops.yaml")).unwrap();
        let sink = ControlPlaneMcpSink::new(plane(ws.path()));
        let reason = refusal(sink.register(registration("ops", "p@1.0.0")));
        assert!(reason.contains("operator file"), "{reason}");
        let reason = refusal(sink.deregister("ops"));
        assert!(reason.contains("operator file"), "{reason}");
        assert_eq!(
            std::fs::read_to_string(dir.join("ops.yaml")).unwrap(),
            before
        );

        assert!(sink
            .register(registration("srv", "p@1.0.0"))
            .unwrap()
            .created());
        let written = std::fs::read_to_string(dir.join("srv.yaml")).unwrap();
        let mut other_ref = registration("srv", "p@1.0.0");
        other_ref.origin_ref = "p@1.0.0/mcp-servers/again".into();
        let reason = refusal(sink.register(other_ref));
        assert!(
            reason.contains("p@1.0.0/mcp-servers/srv") && reason.contains("same pack"),
            "{reason}"
        );
        let mut changed = registration("srv", "p@1.0.0");
        changed.description = "something else".into();
        let reason = refusal(sink.register(changed));
        assert!(reason.contains("different content"), "{reason}");
        let reason = refusal(sink.register(registration("srv", "q@1.0.0")));
        assert!(reason.contains("belongs to pack p@1.0.0"), "{reason}");
        assert_eq!(
            std::fs::read_to_string(dir.join("srv.yaml")).unwrap(),
            written
        );
        sink.deregister("srv").unwrap();
        assert!(!dir.join("srv.yaml").exists());
        sink.deregister("srv")
            .unwrap_or_else(|e| panic!("a missing file is fine: {e}"));
    }

    // The sink reads an existing entry as the loader does and writes through a fresh file:
    // a symlink under a server's name is refused, never read or replaced; one planted under
    // the temporary name is removed as a name and its target is never written.
    #[cfg(unix)]
    #[test]
    fn the_sink_never_reads_or_writes_through_a_symlink() {
        let ws = tempfile::tempdir().unwrap();
        let dir = ws.path().join(".advance/mcp-servers");
        std::fs::create_dir_all(&dir).unwrap();
        let outside = ws.path().join("outside.yaml");
        let body = render_server_file(&registration("srv", "p@1.0.0"));
        std::fs::write(&outside, &body).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("srv.yaml")).unwrap();
        let sink = ControlPlaneMcpSink::new(plane(ws.path()));
        let reason = refusal(sink.register(registration("srv", "p@1.0.0")));
        assert!(
            reason.contains("cannot be read") && reason.contains("symbolic link"),
            "{reason}"
        );
        let reason = refusal(sink.deregister("srv"));
        assert!(reason.contains("symbolic link"), "{reason}");
        assert!(std::fs::symlink_metadata(dir.join("srv.yaml"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), body);

        let target = ws.path().join("target.txt");
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(".other.yaml.tmp")).unwrap();
        assert!(sink
            .register(registration("other", "p@1.0.0"))
            .unwrap()
            .created());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        assert!(std::fs::symlink_metadata(dir.join(".other.yaml.tmp")).is_err());
        let written = std::fs::symlink_metadata(dir.join("other.yaml")).unwrap();
        assert!(written.is_file() && !written.file_type().is_symlink());
    }

    // The http chain exempts the loopback endpoints of the files read at start and nothing
    // else: a loopback server that appears on a reload is refused with a warning, while one
    // whose endpoint was exempted at start loads.
    #[tokio::test]
    async fn a_loopback_server_that_appears_on_reload_is_refused() {
        let ws = tempfile::tempdir().unwrap();
        http_server(ws.path(), "local", "http://127.0.0.1:8931/mcp");
        http_server(ws.path(), "remote", "https://mcp.example.com/mcp");
        let client = || {
            Arc::new(McpClient::new(
                Arc::new(McpServersConfig::builder().build()),
                Arc::new(CleanLeak),
                None,
            ))
        };
        let gate = || {
            mcp_gate(
                Arc::new(RecordingCheck::default()),
                grant_store(),
                WebRunMode::Standard,
            )
        };
        async fn ids(client: &McpClient) -> Vec<String> {
            client
                .list_servers()
                .await
                .into_iter()
                .map(|s| s.id)
                .collect()
        }

        let log = Arc::new(RecordingLog::default());
        let fresh = client();
        let runtime = McpRuntime::for_test_over(
            Arc::clone(&fresh),
            gate(),
            BTreeMap::new(),
            plane(ws.path()).with_log(LogHandle::new(log.clone())),
            LoopbackExemptions::none(),
        );
        runtime.reload();
        assert_eq!(ids(&fresh).await, ["remote"]);
        let lines = log.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("server 'local' is skipped")
                && lines[0].contains("loopback")
                && lines[0].contains("restart the daemon"),
            "{lines:?}"
        );

        let mut exempt = LoopbackExemptions::none();
        assert!(exempt.allow_endpoint("http://127.0.0.1:8931/mcp"));
        let log = Arc::new(RecordingLog::default());
        let exempted = client();
        let runtime = McpRuntime::for_test_over(
            Arc::clone(&exempted),
            gate(),
            BTreeMap::new(),
            plane(ws.path()).with_log(LogHandle::new(log.clone())),
            exempt,
        );
        runtime.reload();
        assert_eq!(ids(&exempted).await, ["local", "remote"]);
        assert!(log.lines().is_empty(), "{:?}", log.lines());
    }

    // A reload prints only the warnings the latest load did not have: a file that keeps failing
    // is reported once, and again when it fails anew after a load without it.
    #[tokio::test]
    async fn a_reload_prints_a_warning_once_until_it_goes_away() {
        let ws = tempfile::tempdir().unwrap();
        let log = Arc::new(RecordingLog::default());
        let runtime = McpRuntime::for_test_over(
            Arc::new(McpClient::new(
                Arc::new(McpServersConfig::builder().build()),
                Arc::new(CleanLeak),
                None,
            )),
            mcp_gate(
                Arc::new(RecordingCheck::default()),
                grant_store(),
                WebRunMode::Standard,
            ),
            BTreeMap::new(),
            plane(ws.path()).with_log(LogHandle::new(log.clone())),
            LoopbackExemptions::none(),
        );
        let broken = server_file(ws.path(), "broken.yaml", "server-id: [unclosed\n");
        runtime.reload();
        runtime.reload();
        let lines = log.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("\"broken.yaml\" is skipped"), "{lines:?}");

        std::fs::remove_file(&broken).unwrap();
        runtime.reload();
        assert_eq!(log.lines().len(), 1, "{:?}", log.lines());
        server_file(ws.path(), "broken.yaml", "server-id: [unclosed\n");
        runtime.reload();
        assert_eq!(log.lines().len(), 2, "{:?}", log.lines());
    }
}
