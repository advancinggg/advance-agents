//! `agent-cli` backend class (ADR 2026-09-28): a vendor coding-agent CLI installed on this
//! host — Claude Code, Codex, Grok Build — driven per request as a **tools-disabled,
//! text-in/text-out** subprocess on the user's own subscription sign-in.
//!
//! Security posture (ADR 2026-08-17 "provider-shaped cut", never "engine-backed agent"):
//! - the gateway assembles the prompt and leak-scans it BEFORE hand-off (`gateway.rs`
//!   `dispatch_port` / `stream_begin_live` for `InferenceBackendClass::AgentCli`);
//! - every vendor recipe pins the no-tools flags; the reply is accepted only when the CLI's
//!   own output proves no tool ran (Claude `system/init` `tools == []` + `mcp_servers == []`;
//!   Codex: no tool item in the JSONL; Grok: a single turn) — anything else fails closed;
//! - the child inherits an ALLOWLISTED environment (never `*_API_KEY`, never OAuth tokens):
//!   the vendor binary finds its own sign-in (Keychain / `auth.json`) through `HOME` + `USER`;
//! - the prompt travels on stdin or a 0600 file in a per-request scratch directory, never on
//!   argv (visible to every process of the user);
//! - the child runs in its own process group; cancel / deadline / a dropped future kill the
//!   whole group (SIGTERM, then SIGKILL after [`KILL_GRACE`]).
//!
//! Nothing here reads, copies or forwards a vendor credential; the sign-in is the vendor CLI's
//! own flow (`claude auth login`, `codex login`, `grok login`).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime::config::{AgentCliSpec, AgentCliVendor};
use advance_shared_types::inference::{
    InferenceBackendError, InferenceBackendPort, InferenceChatRequest, InferenceChatResponse,
    InferenceEmbedRequest, InferenceEmbedResponse, InferenceStream, InferenceStreamClass,
    InferenceStreamHead, InferenceTextDelta,
};
use async_trait::async_trait;
use serde_json::Value;

/// Error prefix every failure of this backend carries (client-safe, vendor-neutral).
pub const AGENT_CLI_PREFIX: &str = "agent-cli:";
/// stdout is read up to this many bytes; a chattier child is cut fail-closed.
pub const MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
/// stderr is kept up to this many bytes (diagnostics only, never returned verbatim).
pub const MAX_STDERR_BYTES: usize = 64 * 1024;
/// A single call never outlives this, whatever the gateway deadline says.
pub const MAX_CALL_DURATION: Duration = Duration::from_secs(600);
/// SIGTERM → SIGKILL grace for the child's process group.
pub const KILL_GRACE: Duration = Duration::from_secs(2);
/// Sign-in probes are cheap local commands; bound them anyway.
pub const AUTH_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Poll interval of the supervising loop (cancel / deadline / drop).
const POLL: Duration = Duration::from_millis(50);

/// Environment variables copied from the daemon into the child. Everything else is dropped —
/// in particular every `*_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `CODEX_HOME`, proxy variables.
pub const ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL",
];

/// Extra PATH entries so a user-local vendor binary (and the `node` a Codex shim needs) is
/// found even when the daemon was launched with a minimal PATH.
const PATH_EXTRA: &[&str] = &["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"];

/// Grok Build honours these to keep MCP discovery, sub-agents, memory and auto-update off
/// (config-reference names; unknown names are ignored by older binaries).
const GROK_ENV: &[(&str, &str)] = &[
    ("GROK_CLAUDE_MCPS_ENABLED", "0"),
    ("GROK_CURSOR_MCPS_ENABLED", "0"),
    ("GROK_MANAGED_MCPS_ENABLED", "0"),
    ("GROK_SUBAGENTS", "0"),
    ("GROK_WEB_FETCH", "0"),
    ("GROK_MEMORY", "0"),
    ("GROK_DISABLE_AUTOUPDATER", "1"),
];

/// Codex feature flags flipped off so the turn cannot act (`--disable <feature>` ≡
/// `-c features.<name>=false`). Order is part of the fixture contract.
pub const CODEX_DISABLED_FEATURES: &[&str] = &[
    "shell_tool",
    "multi_agent",
    "apps",
    "plugins",
    "browser_use",
    "computer_use",
    "image_generation",
    "in_app_browser",
    "code_mode_host",
    "hooks",
    "tool_suggest",
    "goals",
    "memories",
];

/// Codex JSONL item types that mean the model ACTED instead of answering.
const CODEX_TOOL_ITEM_TYPES: &[&str] = &[
    "command_execution",
    "mcp_tool_call",
    "web_search",
    "file_change",
    "collab_tool_call",
    "todo_list",
    "patch",
    "apply_patch",
];

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Environment
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The allowlisted environment a child receives. Built once per backend from the daemon's
/// environment; `HOME` / `USER` fall back to the password database when the daemon itself
/// was started without them (launchd / cleared-env supervisors).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentCliEnv {
    vars: BTreeMap<String, String>,
}

impl AgentCliEnv {
    /// Snapshot the daemon's environment through the allowlist.
    pub fn from_process_env() -> Self {
        let mut vars = BTreeMap::new();
        for key in ENV_ALLOWLIST {
            if let Ok(v) = std::env::var(key) {
                if !v.is_empty() {
                    vars.insert((*key).to_string(), v);
                }
            }
        }
        Self::finish(vars)
    }

    /// Build from an explicit map (tests / product composition roots). Only allowlisted keys
    /// survive.
    pub fn from_map(map: &BTreeMap<String, String>) -> Self {
        let vars = map
            .iter()
            .filter(|(k, v)| ENV_ALLOWLIST.contains(&k.as_str()) && !v.is_empty())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Self::finish(vars)
    }

    fn finish(mut vars: BTreeMap<String, String>) -> Self {
        if !vars.contains_key("HOME") || !vars.contains_key("USER") {
            if let Some((user, home)) = passwd_identity() {
                vars.entry("HOME".into()).or_insert(home);
                vars.entry("USER".into()).or_insert(user);
            }
        }
        if let Some(user) = vars.get("USER").cloned() {
            vars.entry("LOGNAME".into()).or_insert(user);
        }
        let mut path: Vec<String> = vars
            .get("PATH")
            .map(|p| {
                p.split(':')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if let Some(home) = vars.get("HOME") {
            let local = format!("{home}/.local/bin");
            if !path.iter().any(|p| p == &local) {
                path.push(local);
            }
        }
        for extra in PATH_EXTRA {
            if !path.iter().any(|p| p == extra) {
                path.push((*extra).to_string());
            }
        }
        vars.insert("PATH".into(), path.join(":"));
        vars.insert("NO_COLOR".into(), "1".into());
        vars.insert("TERM".into(), "dumb".into());
        vars.insert("CI".into(), "1".into());
        Self { vars }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    pub fn vars(&self) -> &BTreeMap<String, String> {
        &self.vars
    }

    /// The daemon can only drive a signed-in CLI when the child can find the user's
    /// credential store: Claude Code needs `USER` (Keychain account), the others `HOME`.
    pub fn identity_complete(&self) -> bool {
        self.vars.contains_key("HOME") && self.vars.contains_key("USER")
    }

    fn apply(&self, cmd: &mut Command, vendor: AgentCliVendor) {
        cmd.env_clear();
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
        if vendor == AgentCliVendor::Grok {
            for (k, v) in GROK_ENV {
                cmd.env(k, v);
            }
        }
    }
}

#[cfg(unix)]
fn passwd_identity() -> Option<(String, String)> {
    use std::ffi::CStr;
    // SAFETY: getpwuid_r writes into caller-owned buffers; the returned pointers point into
    // `buf`, which outlives the CStr reads below.
    unsafe {
        let uid = libc::getuid();
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            uid,
            &mut pw,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        );
        if rc != 0 || result.is_null() {
            return None;
        }
        let name = CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned();
        let dir = CStr::from_ptr(pw.pw_dir).to_string_lossy().into_owned();
        if name.is_empty() || dir.is_empty() {
            return None;
        }
        Some((name, dir))
    }
}

#[cfg(not(unix))]
fn passwd_identity() -> Option<(String, String)> {
    None
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Prompt rendering
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// What the gateway's messages become for a single-turn CLI: the system text (if any) and one
/// user prompt. A multi-message history is rendered as a transcript the model answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedPrompt {
    pub system: Option<String>,
    pub user: String,
}

pub fn render_prompt(
    messages: &[advance_shared_types::inference::InferenceMessage],
) -> RenderedPrompt {
    let mut system_parts: Vec<&str> = Vec::new();
    let mut turns: Vec<(&str, &str)> = Vec::new();
    for m in messages {
        match m.role.as_str() {
            "system" => system_parts.push(m.content.as_str()),
            role => turns.push((role, m.content.as_str())),
        }
    }
    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    let user = match turns.as_slice() {
        [] => String::new(),
        [(_, only)] => (*only).to_string(),
        many => {
            let mut out = String::from(
                "The following is the conversation so far. Reply to the final user turn only; \
                 do not repeat the transcript.\n\n",
            );
            for (role, content) in many {
                let label = match *role {
                    "assistant" => "Assistant",
                    "user" => "User",
                    other => other,
                };
                out.push_str(&format!("[{label}]\n{content}\n\n"));
            }
            out
        }
    };
    RenderedPrompt { system, user }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Recipes (pure: argv per vendor)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Where the prompt goes for a vendor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptTransport {
    /// The user prompt is written to the child's stdin.
    Stdin,
    /// The user prompt is written to `prompt.txt` and named on argv (`--prompt-file`).
    File,
}

/// Paths a recipe may reference (all inside the per-request scratch directory).
#[derive(Clone, Debug)]
pub struct RecipeFiles {
    pub cwd: PathBuf,
    pub prompt_file: PathBuf,
    pub system_file: Option<PathBuf>,
}

pub fn prompt_transport(vendor: AgentCliVendor) -> PromptTransport {
    match vendor {
        AgentCliVendor::Claude | AgentCliVendor::Codex => PromptTransport::Stdin,
        AgentCliVendor::Grok => PromptTransport::File,
    }
}

/// Whether the vendor recipe carries system text on its own channel (`--system-prompt-file`
/// for Claude, `--system-prompt-override` for Grok). Codex has none: the system text is
/// folded into the stdin transcript by [`fold_system_into_user`].
pub fn has_system_channel(vendor: AgentCliVendor) -> bool {
    !matches!(vendor, AgentCliVendor::Codex)
}

/// The stdin text for a vendor without a system channel: the system block first, delimited,
/// then the user transcript.
pub fn fold_system_into_user(system: Option<&str>, user: &str) -> String {
    match system.map(str::trim).filter(|s| !s.is_empty()) {
        Some(sys) => {
            format!("[System instructions]\n{sys}\n\n[End of system instructions]\n\n{user}")
        }
        None => user.to_string(),
    }
}

/// The fixed no-tools argv for `vendor`; `extra` (the config's `agent-cli.args`) is appended
/// last so it can never precede or override the recipe's safety flags.
pub fn build_argv(
    vendor: AgentCliVendor,
    model: &str,
    files: &RecipeFiles,
    extra: &[String],
) -> Vec<String> {
    let mut argv: Vec<String> = match vendor {
        AgentCliVendor::Claude => {
            let mut v = vec![
                "-p".into(),
                "--output-format".into(),
                "stream-json".into(),
                "--verbose".into(),
                "--tools".into(),
                String::new(),
                "--restricted".into(),
                "--strict-mcp-config".into(),
                "--disable-slash-commands".into(),
                "--max-turns".into(),
                "1".into(),
                "--no-session-persistence".into(),
                "--model".into(),
                model.to_string(),
            ];
            if let Some(sys) = &files.system_file {
                v.push("--system-prompt-file".into());
                v.push(sys.to_string_lossy().into_owned());
            }
            v
        }
        AgentCliVendor::Codex => {
            let mut v = vec![
                "exec".into(),
                "--json".into(),
                "--ephemeral".into(),
                "--skip-git-repo-check".into(),
                "--ignore-user-config".into(),
                "-s".into(),
                "read-only".into(),
                "-C".into(),
                files.cwd.to_string_lossy().into_owned(),
                "-m".into(),
                model.to_string(),
                "-c".into(),
                "web_search=\"disabled\"".into(),
                "-c".into(),
                "mcp_servers={}".into(),
                "-c".into(),
                "approval_policy=\"never\"".into(),
            ];
            for feature in CODEX_DISABLED_FEATURES {
                v.push("--disable".into());
                v.push((*feature).to_string());
            }
            v.push("-".into());
            v
        }
        AgentCliVendor::Grok => {
            let mut v = vec![
                "--prompt-file".into(),
                files.prompt_file.to_string_lossy().into_owned(),
                "--output-format".into(),
                "json".into(),
                "--max-turns".into(),
                "1".into(),
                "--no-subagents".into(),
                "--disable-web-search".into(),
                "--no-plan".into(),
                "--verbatim".into(),
                "--permission-mode".into(),
                "dontAsk".into(),
                "--tools".into(),
                "todo_write".into(),
                "--disallowed-tools".into(),
                "todo_write,search_tool,use_tool,Agent".into(),
                "--model".into(),
                model.to_string(),
            ];
            if let Some(sys) = &files.system_file {
                // Grok has no file form; the override rides argv (system text only,
                // never the user prompt).
                if let Ok(text) = std::fs::read_to_string(sys) {
                    v.push("--system-prompt-override".into());
                    v.push(text);
                }
            }
            v
        }
    };
    argv.extend(extra.iter().cloned());
    argv
}

/// The vendor's sign-in probe: a cheap local command whose success means "signed in".
pub fn auth_probe_argv(vendor: AgentCliVendor) -> Vec<&'static str> {
    match vendor {
        AgentCliVendor::Claude => vec!["auth", "status"],
        AgentCliVendor::Codex => vec!["login", "status"],
        AgentCliVendor::Grok => vec!["models"],
    }
}

/// The interactive sign-in command a client should run in the user's terminal (never a
/// WebView, never a token paste): the vendor's own flow stores its own credential.
pub fn sign_in_argv(vendor: AgentCliVendor) -> Vec<&'static str> {
    match vendor {
        AgentCliVendor::Claude => vec!["auth", "login"],
        AgentCliVendor::Codex => vec!["login"],
        AgentCliVendor::Grok => vec!["login"],
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Output parsing (pure)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Token accounting a vendor reported for the turn (already folded into the gateway's
/// two-bucket model: cache reads/writes count as input).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CliUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
}

/// A parsed, accepted turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliTurn {
    pub text: String,
    pub model: Option<String>,
    pub usage: CliUsage,
    pub finish_reason: String,
    /// The vendor's own rate-limit / quota note when it reported one (client-safe text).
    pub quota_note: Option<String>,
}

fn u64_of(v: &Value) -> u64 {
    v.as_u64()
        .or_else(|| v.as_f64().map(|f| f.max(0.0) as u64))
        .unwrap_or(0)
}

fn err(msg: impl AsRef<str>) -> InferenceBackendError {
    InferenceBackendError::Provider(format!("{AGENT_CLI_PREFIX} {}", msg.as_ref()))
}

/// Classify a vendor error text into the gateway's typed error space. The subscription's
/// usage window is a NON-retryable pause (retrying would spawn the CLI in a loop); a
/// transient rate limit / overload is retryable.
pub fn classify_failure(text: &str) -> InferenceBackendError {
    let lower = text.to_lowercase();
    let quota = [
        "usage limit",
        "hit your limit",
        "hit your usage",
        "weekly limit",
        "resets at",
        "reset at",
        "try again at",
        "extra usage",
        "out of extra usage",
        "credits_required",
        "billing_error",
        "account_on_hold",
        "purchase more credits",
    ];
    if quota.iter().any(|q| lower.contains(q)) {
        return err(format!(
            "subscription usage limit reached ({})",
            squeeze(text)
        ));
    }
    let auth = [
        "not logged in",
        "not signed in",
        "please run /login",
        "please log in",
        "please login",
        "run codex login",
        "run `codex login`",
        "authentication_failed",
        "oauth_org_not_allowed",
        "invalid api key",
        "unauthorized",
        "401",
    ];
    if auth.iter().any(|q| lower.contains(q)) {
        return err(format!("not signed in ({})", squeeze(text)));
    }
    if lower.contains("context") && (lower.contains("too long") || lower.contains("exceed")) {
        return InferenceBackendError::ContextTooLong(format!(
            "{AGENT_CLI_PREFIX} {}",
            squeeze(text)
        ));
    }
    if lower.contains("prompt is too long") || lower.contains("input too long") {
        return InferenceBackendError::ContextTooLong(format!(
            "{AGENT_CLI_PREFIX} {}",
            squeeze(text)
        ));
    }
    let transient = [
        "rate limit",
        "rate_limit",
        "overloaded",
        "too many requests",
        "429",
        "529",
    ];
    if transient.iter().any(|q| lower.contains(q)) {
        return InferenceBackendError::RateLimited(format!("{AGENT_CLI_PREFIX} {}", squeeze(text)));
    }
    let model = [
        "not supported when using codex with a chatgpt account",
        "requires a newer version",
        "model not found",
        "unknown model",
        "not_found_error",
        "does not exist",
    ];
    if model.iter().any(|q| lower.contains(q)) {
        return InferenceBackendError::ModelNotAvailable(format!(
            "{AGENT_CLI_PREFIX} {}",
            squeeze(text)
        ));
    }
    err(squeeze(text))
}

/// One line, bounded, no control characters (client-safe).
fn squeeze(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if out.len() > 240 {
        let mut end = 240;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push('…');
    }
    out
}

/// Parse a vendor's stdout (and exit status) into an accepted turn or a typed failure.
pub fn parse_output(
    vendor: AgentCliVendor,
    stdout: &[u8],
    stderr: &[u8],
    exit_code: Option<i32>,
) -> Result<CliTurn, InferenceBackendError> {
    let out = String::from_utf8_lossy(stdout);
    let parsed = match vendor {
        AgentCliVendor::Claude => parse_claude(&out),
        AgentCliVendor::Codex => parse_codex(&out),
        AgentCliVendor::Grok => parse_grok(&out),
    };
    match parsed {
        Ok(turn) => Ok(turn),
        Err(e) => {
            // A non-zero exit with no parseable verdict: classify whatever the CLI said.
            if let InferenceBackendError::Provider(msg) = &e {
                if msg.ends_with("no result") {
                    let said = String::from_utf8_lossy(stderr);
                    let said = if said.trim().is_empty() {
                        out.clone()
                    } else {
                        said
                    };
                    if !said.trim().is_empty() {
                        return Err(classify_failure(&said));
                    }
                    return Err(err(format!(
                        "no result (exit {})",
                        exit_code
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "signal".into())
                    )));
                }
            }
            Err(e)
        }
    }
}

fn parse_claude(out: &str) -> Result<CliTurn, InferenceBackendError> {
    let mut init_seen = false;
    let mut tools_clean = false;
    let mut quota_note: Option<String> = None;
    let mut result: Option<Value> = None;
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // non-JSON chatter is ignored; the verdict is the result line
        };
        match v.get("type").and_then(Value::as_str) {
            Some("system") => {
                if v.get("subtype").and_then(Value::as_str) == Some("init") {
                    init_seen = true;
                    let tools_empty = v
                        .get("tools")
                        .and_then(Value::as_array)
                        .map_or(false, Vec::is_empty);
                    let mcp_empty = v
                        .get("mcp_servers")
                        .and_then(Value::as_array)
                        .map_or(false, Vec::is_empty);
                    tools_clean = tools_empty && mcp_empty;
                }
            }
            Some("rate_limit_event") => {
                let status = v
                    .pointer("/rate_limit_info/status")
                    .or_else(|| v.get("status"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let resets = v
                    .pointer("/rate_limit_info/resetsAt")
                    .or_else(|| v.get("resetsAt"))
                    .map(|r| r.to_string())
                    .unwrap_or_default();
                if !status.is_empty() {
                    quota_note = Some(squeeze(&format!("{status} resets_at={resets}")));
                }
            }
            Some("result") => result = Some(v),
            _ => {}
        }
    }
    let Some(r) = result else {
        return Err(err("no result"));
    };
    let is_error = r.get("is_error").and_then(Value::as_bool).unwrap_or(false);
    let subtype = r.get("subtype").and_then(Value::as_str).unwrap_or("");
    let text = r
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if is_error || subtype.starts_with("error") {
        let said = if text.is_empty() {
            subtype.to_string()
        } else {
            text
        };
        let api_status = r.get("api_error_status").and_then(Value::as_u64);
        let said = match api_status {
            Some(code) => format!("{said} (http {code})"),
            None => said,
        };
        return Err(classify_failure(&said));
    }
    if !init_seen {
        return Err(err("no tools proof (init line missing)"));
    }
    if !tools_clean {
        return Err(err(
            "tools proof failed (a tool or MCP server was available)",
        ));
    }
    let denials = r
        .get("permission_denials")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if denials > 0 {
        return Err(err("tools proof failed (permission denials recorded)"));
    }
    let turns = r.get("num_turns").and_then(Value::as_u64).unwrap_or(1);
    if turns > 1 {
        return Err(err("tools proof failed (more than one turn)"));
    }
    let usage = r.get("usage").cloned().unwrap_or(Value::Null);
    let cache_create = u64_of(&usage["cache_creation_input_tokens"]);
    let cache_read = u64_of(&usage["cache_read_input_tokens"]);
    let input = u64_of(&usage["input_tokens"]) + cache_create + cache_read;
    let output = u64_of(&usage["output_tokens"]);
    let model = r
        .get("modelUsage")
        .and_then(Value::as_object)
        .and_then(|m| m.keys().next().cloned());
    let finish = r
        .get("stop_reason")
        .and_then(Value::as_str)
        .unwrap_or("end_turn")
        .to_string();
    Ok(CliTurn {
        text,
        model,
        usage: CliUsage {
            input_tokens: input,
            output_tokens: output,
            cached_tokens: cache_read,
        },
        finish_reason: finish,
        quota_note,
    })
}

fn parse_codex(out: &str) -> Result<CliTurn, InferenceBackendError> {
    let mut text_parts: Vec<String> = Vec::new();
    let mut usage: Option<CliUsage> = None;
    let mut failure: Option<String> = None;
    let mut saw_turn = false;
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match v.get("type").and_then(Value::as_str) {
            Some("turn.started") => saw_turn = true,
            Some("item.completed") | Some("item.started") | Some("item.updated") => {
                let item = &v["item"];
                let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
                if CODEX_TOOL_ITEM_TYPES.contains(&kind) {
                    return Err(err(format!("tools proof failed (codex item {kind})")));
                }
                if kind == "agent_message" && v["type"] == "item.completed" {
                    if let Some(t) = item.get("text").and_then(Value::as_str) {
                        text_parts.push(t.to_string());
                    }
                }
            }
            Some("turn.completed") => {
                let u = &v["usage"];
                let input = u64_of(&u["input_tokens"]);
                let cached = u64_of(&u["cached_input_tokens"]);
                let output = u64_of(&u["output_tokens"]) + u64_of(&u["reasoning_output_tokens"]);
                usage = Some(CliUsage {
                    input_tokens: input,
                    output_tokens: output,
                    cached_tokens: cached,
                });
            }
            Some("turn.failed") => {
                let m = v
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("turn failed");
                failure = Some(m.to_string());
            }
            Some("error") => {
                let m = v.get("message").and_then(Value::as_str).unwrap_or("error");
                // "Reconnecting…" lines are transport chatter, not a verdict.
                if !m.to_lowercase().contains("reconnecting") {
                    failure = Some(m.to_string());
                }
            }
            _ => {}
        }
    }
    if let Some(f) = failure {
        if text_parts.is_empty() || usage.is_none() {
            return Err(classify_failure(&f));
        }
    }
    if !saw_turn && text_parts.is_empty() {
        return Err(err("no result"));
    }
    let Some(usage) = usage else {
        if text_parts.is_empty() {
            return Err(err("no result"));
        }
        return Err(err("turn ended without usage"));
    };
    Ok(CliTurn {
        text: text_parts.join("\n"),
        model: None,
        usage,
        finish_reason: "end_turn".into(),
        quota_note: None,
    })
}

fn parse_grok(out: &str) -> Result<CliTurn, InferenceBackendError> {
    let trimmed = out.trim();
    let v: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            // The object may be preceded by non-JSON chatter: take the last `{…}` block.
            match trimmed.find('{') {
                Some(i) => serde_json::from_str(&trimmed[i..]).map_err(|_| err("no result"))?,
                None => return Err(err("no result")),
            }
        }
    };
    if let Some(e) = v.get("error") {
        let m = e
            .as_str()
            .map(str::to_string)
            .or_else(|| e.get("message").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| e.to_string());
        return Err(classify_failure(&m));
    }
    let text = v
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if text.is_empty() && v.get("usage").is_none() {
        return Err(err("no result"));
    }
    let turns = v.get("num_turns").and_then(Value::as_u64).unwrap_or(1);
    if turns > 1 {
        return Err(err("tools proof failed (more than one turn)"));
    }
    let u = &v["usage"];
    let cache_read = u64_of(&u["cache_read_input_tokens"]);
    let cache_create = u64_of(&u["cache_creation_input_tokens"]);
    let input = u64_of(&u["input_tokens"]) + cache_read + cache_create;
    let output = u64_of(&u["output_tokens"]) + u64_of(&u["reasoning_tokens"]);
    let model = v
        .get("modelUsage")
        .and_then(Value::as_object)
        .and_then(|m| m.keys().next().cloned());
    Ok(CliTurn {
        text,
        model,
        usage: CliUsage {
            input_tokens: input,
            output_tokens: output,
            cached_tokens: cache_read,
        },
        finish_reason: v
            .get("stopReason")
            .and_then(Value::as_str)
            .unwrap_or("end_turn")
            .to_string(),
        quota_note: None,
    })
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Process supervision
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Kills the child's process group when the owning future is dropped (a gateway timeout drops
/// the `chat` future while the blocking supervisor is still running).
struct KillOnDrop(Arc<AtomicBool>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[cfg(unix)]
fn kill_group(pid: u32, signal: libc::c_int) {
    // SAFETY: plain syscall on a pgid we created with `process_group(0)`.
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}

#[cfg(not(unix))]
fn kill_group(_pid: u32, _signal: i32) {}

/// The captured outcome of one child run.
#[derive(Debug)]
pub struct ChildRun {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub stdout_truncated: bool,
    pub elapsed: Duration,
}

/// Why a run was stopped before the child exited on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    Cancelled,
    Deadline,
    Dropped,
}

fn reader_thread(
    mut src: impl Read + Send + 'static,
    cap: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut truncated = false;
        let mut buf = [0u8; 8192];
        loop {
            match src.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.len() < cap {
                        let take = n.min(cap - out.len());
                        out.extend_from_slice(&buf[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
            }
        }
        (out, truncated)
    })
}

/// Run `command argv` under supervision. Blocking; call from `spawn_blocking`.
#[allow(clippy::too_many_arguments)]
pub fn run_supervised(
    command: &Path,
    argv: &[String],
    env: &AgentCliEnv,
    vendor: AgentCliVendor,
    cwd: &Path,
    stdin_bytes: Option<Vec<u8>>,
    deadline: Instant,
    cancel: &AtomicBool,
    abort: &AtomicBool,
) -> Result<ChildRun, (StopReason, Duration)> {
    let started = Instant::now();
    let mut cmd = Command::new(command);
    cmd.args(argv)
        .current_dir(cwd)
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    env.apply(&mut cmd, vendor);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Ok(ChildRun {
                stdout: Vec::new(),
                stderr: format!("spawn failed: {e}").into_bytes(),
                exit_code: None,
                stdout_truncated: false,
                elapsed: started.elapsed(),
            })
        }
    };
    let pid = child.id();
    if let (Some(bytes), Some(mut stdin)) = (stdin_bytes, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
            let _ = stdin.flush();
            drop(stdin);
        });
    }
    let stdout_h = child
        .stdout
        .take()
        .map(|s| reader_thread(s, MAX_STDOUT_BYTES));
    let stderr_h = child
        .stderr
        .take()
        .map(|s| reader_thread(s, MAX_STDERR_BYTES));
    let hard_deadline = started + MAX_CALL_DURATION;
    let stop = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = stdout_h
                    .map(|h| h.join().unwrap_or_default())
                    .unwrap_or_default();
                let errb = stderr_h
                    .map(|h| h.join().unwrap_or_default())
                    .unwrap_or_default();
                return Ok(ChildRun {
                    stdout: out.0,
                    stderr: errb.0,
                    exit_code: status.code(),
                    stdout_truncated: out.1,
                    elapsed: started.elapsed(),
                });
            }
            Ok(None) => {}
            Err(_) => break StopReason::Dropped,
        }
        if abort.load(Ordering::SeqCst) {
            break StopReason::Dropped;
        }
        if cancel.load(Ordering::SeqCst) {
            break StopReason::Cancelled;
        }
        let now = Instant::now();
        if now >= deadline || now >= hard_deadline {
            break StopReason::Deadline;
        }
        std::thread::sleep(POLL);
    };
    kill_group(pid, libc::SIGTERM);
    let grace = Instant::now() + KILL_GRACE;
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if Instant::now() >= grace {
            kill_group(pid, libc::SIGKILL);
            let _ = child.wait();
            break;
        }
        std::thread::sleep(POLL);
    }
    if let Some(h) = stdout_h {
        let _ = h.join();
    }
    if let Some(h) = stderr_h {
        let _ = h.join();
    }
    Err((stop, started.elapsed()))
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Sign-in probe
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// What a sign-in probe found. `detail` is client-safe (no token, no email).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthProbe {
    pub signed_in: bool,
    pub cli_present: bool,
    pub detail: String,
}

/// Seam for the providers family: the production impl runs the vendor's status command;
/// tests inject a verdict.
pub trait AgentCliAuthProbe: Send + Sync {
    fn probe(&self, spec: &AgentCliSpec) -> AuthProbe;
}

/// Runs `<command> <auth-probe argv>` under the allowlisted environment.
pub struct ProcessAuthProbe {
    pub env: AgentCliEnv,
}

impl Default for ProcessAuthProbe {
    fn default() -> Self {
        Self {
            env: AgentCliEnv::from_process_env(),
        }
    }
}

impl AgentCliAuthProbe for ProcessAuthProbe {
    fn probe(&self, spec: &AgentCliSpec) -> AuthProbe {
        probe_auth(spec, &self.env)
    }
}

pub fn probe_auth(spec: &AgentCliSpec, env: &AgentCliEnv) -> AuthProbe {
    let command = Path::new(&spec.command);
    if !command.is_absolute() || !command.is_file() {
        return AuthProbe {
            signed_in: false,
            cli_present: false,
            detail: "cli-not-found".into(),
        };
    }
    if !env.identity_complete() {
        return AuthProbe {
            signed_in: false,
            cli_present: true,
            detail: "daemon-identity-unknown".into(),
        };
    }
    let argv: Vec<String> = auth_probe_argv(spec.vendor)
        .into_iter()
        .map(str::to_string)
        .collect();
    let cancel = AtomicBool::new(false);
    let abort = AtomicBool::new(false);
    let cwd = std::env::temp_dir();
    let run = run_supervised(
        command,
        &argv,
        env,
        spec.vendor,
        &cwd,
        None,
        Instant::now() + AUTH_PROBE_TIMEOUT,
        &cancel,
        &abort,
    );
    let run = match run {
        Ok(r) => r,
        Err((StopReason::Deadline, _)) => {
            return AuthProbe {
                signed_in: false,
                cli_present: true,
                detail: "timeout".into(),
            }
        }
        Err(_) => {
            return AuthProbe {
                signed_in: false,
                cli_present: true,
                detail: "cancelled".into(),
            }
        }
    };
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    let signed_in = match spec.vendor {
        AgentCliVendor::Claude => stdout
            .find('{')
            .and_then(|i| serde_json::from_str::<Value>(&stdout[i..]).ok())
            .and_then(|v| v.get("loggedIn").and_then(Value::as_bool))
            .unwrap_or(false),
        AgentCliVendor::Codex => {
            run.exit_code == Some(0) && stdout.to_lowercase().contains("logged in")
        }
        AgentCliVendor::Grok => run.exit_code == Some(0),
    };
    let detail = if signed_in {
        "signed-in".to_string()
    } else if run.exit_code.is_none() {
        "cli-failed".to_string()
    } else {
        let said = if stderr.trim().is_empty() {
            stdout.as_ref()
        } else {
            stderr.as_ref()
        };
        format!("not-signed-in ({})", squeeze(said))
    };
    AuthProbe {
        signed_in,
        cli_present: true,
        detail,
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Usage probe (subscription allowance)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A usage probe drives the vendor CLI's own account surface (no model turn, no token read):
/// Claude Code's `/usage` slash command through `-p` (a local command: zero tokens, zero cost),
/// Codex's `codex app-server` JSON-RPC `account/read` + `account/rateLimits/read`, and Grok
/// Build's ACP `authenticate` + `x.ai/billing` extension. Slower than the sign-in probe: the
/// CLIs talk to their vendor.
pub const USAGE_PROBE_TIMEOUT: Duration = Duration::from_secs(45);

/// One allowance window the vendor CLI reported. `used_percent` is 0..=100 as the vendor
/// states it (Claude and Codex report percentages; Grok reports `creditUsagePercent`).
#[derive(Clone, Debug, PartialEq)]
pub struct UsageWindow {
    /// `session` (Claude's 5-hour window) | `week` | `week-model` (Claude's per-model weekly
    /// cap) | `primary` / `secondary` (Codex's rolling windows) | `period` (Grok's weekly or
    /// monthly credit pool) | `other`.
    pub kind: String,
    /// The vendor's own wording (`Current week (all models)`, `5-hour`, `Weekly limit`).
    pub label: String,
    /// `week-model` only: the model the cap applies to.
    pub model: Option<String>,
    pub used_percent: f64,
    /// Unix milliseconds when the window resets, when the vendor states an instant.
    pub resets_at_ms: Option<u64>,
    /// The vendor's own reset wording when only text is known (`Sep 29 at 11pm (America/Los_Angeles)`).
    pub resets_label: Option<String>,
    /// The window's length when the vendor states it (Codex: 300 / 10080).
    pub window_minutes: Option<u64>,
}

/// What a usage probe found. `detail` is a fixed token: `ok` | `not-signed-in` |
/// `cli-not-found` | `daemon-identity-unknown` | `timeout` | `cancelled` | `cli-failed` |
/// `unparsed`. `account` is the signed-in account's own label (an email) — the user's own
/// device data, shown back to the user, never persisted by the probe.
#[derive(Clone, Debug, PartialEq)]
pub struct UsageProbe {
    pub ok: bool,
    pub detail: String,
    /// The plan the vendor names (`max`, `pro`, `plus`, `supergrok_heavy`, …), verbatim.
    pub plan: Option<String>,
    pub account: Option<String>,
    pub windows: Vec<UsageWindow>,
}

impl UsageProbe {
    fn failed(detail: &str) -> Self {
        Self {
            ok: false,
            detail: detail.to_string(),
            plan: None,
            account: None,
            windows: Vec::new(),
        }
    }
}

/// Seam for the providers family: the production impl runs the vendor CLI; tests inject.
pub trait AgentCliUsageProbe: Send + Sync {
    fn probe_usage(&self, spec: &AgentCliSpec) -> UsageProbe;
}

/// Runs the vendor's own usage surface under the allowlisted environment.
pub struct ProcessUsageProbe {
    pub env: AgentCliEnv,
}

impl Default for ProcessUsageProbe {
    fn default() -> Self {
        Self {
            env: AgentCliEnv::from_process_env(),
        }
    }
}

impl AgentCliUsageProbe for ProcessUsageProbe {
    fn probe_usage(&self, spec: &AgentCliSpec) -> UsageProbe {
        probe_usage(spec, &self.env)
    }
}

pub fn probe_usage(spec: &AgentCliSpec, env: &AgentCliEnv) -> UsageProbe {
    let command = Path::new(&spec.command);
    if !command.is_absolute() || !command.is_file() {
        return UsageProbe::failed("cli-not-found");
    }
    if !env.identity_complete() {
        return UsageProbe::failed("daemon-identity-unknown");
    }
    let deadline = Instant::now() + USAGE_PROBE_TIMEOUT;
    match spec.vendor {
        AgentCliVendor::Claude => probe_usage_claude(command, env, deadline),
        AgentCliVendor::Codex => probe_usage_codex(command, env, deadline),
        AgentCliVendor::Grok => probe_usage_grok(command, env, deadline),
    }
}

/// One supervised run with fresh cancel flags and the temp dir as cwd.
fn run_once(
    command: &Path,
    argv: &[&str],
    env: &AgentCliEnv,
    vendor: AgentCliVendor,
    stdin_bytes: Option<Vec<u8>>,
    deadline: Instant,
) -> Result<ChildRun, StopReason> {
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
    let cancel = AtomicBool::new(false);
    let abort = AtomicBool::new(false);
    let cwd = std::env::temp_dir();
    run_supervised(
        command,
        &argv,
        env,
        vendor,
        &cwd,
        stdin_bytes,
        deadline,
        &cancel,
        &abort,
    )
    .map_err(|(stop, _)| stop)
}

fn stop_detail(stop: StopReason) -> &'static str {
    match stop {
        StopReason::Deadline => "timeout",
        _ => "cancelled",
    }
}

// Claude Code: `auth status` for the plan and account, then `/usage` through `-p` (a local
// slash command: the result carries `num_turns: 0` and zero tokens).
fn probe_usage_claude(command: &Path, env: &AgentCliEnv, deadline: Instant) -> UsageProbe {
    let status = match run_once(
        command,
        &["auth", "status"],
        env,
        AgentCliVendor::Claude,
        None,
        deadline,
    ) {
        Ok(r) => r,
        Err(stop) => return UsageProbe::failed(stop_detail(stop)),
    };
    let status_json = String::from_utf8_lossy(&status.stdout)
        .find('{')
        .and_then(|i| {
            serde_json::from_str::<Value>(&String::from_utf8_lossy(&status.stdout)[i..]).ok()
        });
    let Some(status_json) = status_json else {
        return UsageProbe::failed(if status.exit_code.is_none() {
            "cli-failed"
        } else {
            "not-signed-in"
        });
    };
    if status_json.get("loggedIn").and_then(Value::as_bool) != Some(true) {
        return UsageProbe::failed("not-signed-in");
    }
    let plan = status_json
        .get("subscriptionType")
        .and_then(Value::as_str)
        .map(str::to_string);
    let account = status_json
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_string);
    let run = match run_once(
        command,
        &[
            "-p",
            "--output-format",
            "json",
            "--tools",
            "",
            "--max-turns",
            "1",
            "--no-session-persistence",
        ],
        env,
        AgentCliVendor::Claude,
        Some(b"/usage\n".to_vec()),
        deadline,
    ) {
        Ok(r) => r,
        Err(stop) => return UsageProbe::failed(stop_detail(stop)),
    };
    let stdout = String::from_utf8_lossy(&run.stdout);
    let text = stdout
        .find('{')
        .and_then(|i| serde_json::from_str::<Value>(&stdout[i..]).ok())
        .and_then(|v| v.get("result").and_then(Value::as_str).map(str::to_string));
    let Some(text) = text else {
        return UsageProbe::failed(if run.exit_code.is_none() {
            "cli-failed"
        } else {
            "unparsed"
        });
    };
    let windows = parse_claude_usage_text(&text);
    if windows.is_empty() {
        return UsageProbe {
            ok: false,
            detail: "unparsed".into(),
            plan,
            account,
            windows,
        };
    }
    UsageProbe {
        ok: true,
        detail: "ok".into(),
        plan,
        account,
        windows,
    }
}

/// The `/usage` lines: `Current session: 60% used · resets Sep 29 at 11pm (America/Los_Angeles)`,
/// `Current week (all models): 69% used · resets …`, `Current week (Fable): 79% used · resets …`.
/// Anything else with `% used` is kept as `other`.
pub fn parse_claude_usage_text(text: &str) -> Vec<UsageWindow> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        let Some((label, rest)) = line.split_once(": ") else {
            continue;
        };
        let Some(pct_end) = rest.find("% used") else {
            continue;
        };
        let Ok(used_percent) = rest[..pct_end].trim().parse::<f64>() else {
            continue;
        };
        let resets_label = rest
            .find("resets ")
            .map(|i| rest[i + "resets ".len()..].trim().to_string())
            .filter(|s| !s.is_empty());
        let (kind, model) = if label.starts_with("Current session") {
            ("session", None)
        } else if label.starts_with("Current week (all models)") {
            ("week", None)
        } else if let Some(inner) = label
            .strip_prefix("Current week (")
            .and_then(|s| s.strip_suffix(')'))
        {
            ("week-model", Some(inner.to_string()))
        } else {
            ("other", None)
        };
        out.push(UsageWindow {
            kind: kind.to_string(),
            label: label.to_string(),
            model,
            used_percent,
            resets_at_ms: None,
            resets_label,
            window_minutes: None,
        });
    }
    out
}

// Codex: the app-server over stdio. Requests are answered in order; the server exits on EOF,
// so the session keeps stdin open until every answer arrived.
fn probe_usage_codex(command: &Path, env: &AgentCliEnv, deadline: Instant) -> UsageProbe {
    let requests = vec![
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"advance-agent-cli","title":"Advance","version":env!("CARGO_PKG_VERSION")}}}),
        serde_json::json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"account/read","params":{}}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"account/rateLimits/read","params":{}}),
    ];
    match run_jsonrpc(
        command,
        &["app-server"],
        env,
        AgentCliVendor::Codex,
        &requests,
        deadline,
    ) {
        Ok(responses) => codex_usage_from_responses(&responses),
        Err(stop) => UsageProbe::failed(stop_detail(stop)),
    }
}

/// `account/read` (id 2) + `account/rateLimits/read` (id 3) → windows. Signed out answers a
/// JSON-RPC error `codex account authentication required …`.
pub fn codex_usage_from_responses(responses: &[Value]) -> UsageProbe {
    let by_id = |id: u64| {
        responses
            .iter()
            .find(|r| r.get("id").and_then(Value::as_u64) == Some(id))
    };
    let account = by_id(2)
        .and_then(|r| r.get("result"))
        .and_then(|r| r.get("account"));
    let mut plan = None;
    let mut account_label = None;
    if let Some(acc) = account.filter(|a| !a.is_null()) {
        match acc.get("type").and_then(Value::as_str) {
            Some("chatgpt") => {
                plan = acc
                    .get("planType")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                account_label = acc.get("email").and_then(Value::as_str).map(str::to_string);
            }
            Some(other) => plan = Some(other.to_string()),
            None => {}
        }
    }
    let Some(limits) = by_id(3) else {
        return UsageProbe::failed("unparsed");
    };
    if let Some(err) = limits.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        return UsageProbe::failed(if msg.contains("authentication required") {
            "not-signed-in"
        } else {
            "cli-failed"
        });
    }
    let Some(snapshot) = limits.get("result").and_then(|r| r.get("rateLimits")) else {
        return UsageProbe::failed("unparsed");
    };
    if plan.is_none() {
        plan = snapshot
            .get("planType")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    let mut windows = Vec::new();
    for kind in ["primary", "secondary"] {
        let Some(w) = snapshot.get(kind).filter(|w| !w.is_null()) else {
            continue;
        };
        let Some(used_percent) = w.get("usedPercent").and_then(Value::as_f64) else {
            continue;
        };
        let window_minutes = w.get("windowDurationMins").and_then(Value::as_u64);
        let label = match window_minutes {
            Some(300) => "5-hour".to_string(),
            Some(m) if m >= 7 * 24 * 60 => "Weekly".to_string(),
            Some(m) if m % 60 == 0 => format!("{}-hour", m / 60),
            Some(m) => format!("{m}-minute"),
            None => kind.to_string(),
        };
        windows.push(UsageWindow {
            kind: kind.to_string(),
            label,
            model: None,
            used_percent,
            resets_at_ms: w.get("resetsAt").and_then(Value::as_u64).map(|s| s * 1000),
            resets_label: None,
            window_minutes,
        });
    }
    if windows.is_empty() {
        return UsageProbe {
            ok: false,
            detail: "unparsed".into(),
            plan,
            account: account_label,
            windows,
        };
    }
    UsageProbe {
        ok: true,
        detail: "ok".into(),
        plan,
        account: account_label,
        windows,
    }
}

// Grok Build: the ACP server over stdio. `authenticate` with the CLI's own cached token, then
// the `x.ai/billing` extension (`_`-prefixed on the wire, as ACP spells extension methods).
fn probe_usage_grok(command: &Path, env: &AgentCliEnv, deadline: Instant) -> UsageProbe {
    let requests = vec![
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false},"clientInfo":{"name":"advance-agent-cli","version":env!("CARGO_PKG_VERSION")}}}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"authenticate","params":{"methodId":"cached_token"}}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"_x.ai/billing","params":{}}),
    ];
    match run_jsonrpc(
        command,
        &["agent", "stdio"],
        env,
        AgentCliVendor::Grok,
        &requests,
        deadline,
    ) {
        Ok(responses) => grok_usage_from_responses(&responses),
        Err(stop) => UsageProbe::failed(stop_detail(stop)),
    }
}

/// `authenticate` (id 2: `_meta.subscription_tier`, `_meta.email`) + `x.ai/billing` (id 3:
/// `config.creditUsagePercent`, `config.currentPeriod.{type,end}`, `subscription_tier`).
pub fn grok_usage_from_responses(responses: &[Value]) -> UsageProbe {
    let by_id = |id: u64| {
        responses
            .iter()
            .find(|r| r.get("id").and_then(Value::as_u64) == Some(id))
    };
    let Some(auth) = by_id(2) else {
        return UsageProbe::failed("unparsed");
    };
    if auth.get("error").is_some() {
        return UsageProbe::failed("not-signed-in");
    }
    let meta = auth.get("result").and_then(|r| r.get("_meta"));
    let mut plan = meta
        .and_then(|m| m.get("subscription_tier"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let account = meta
        .and_then(|m| m.get("email"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let Some(billing) = by_id(3) else {
        return UsageProbe::failed("unparsed");
    };
    if let Some(err) = billing.get("error") {
        let msg = serde_json::to_string(err)
            .unwrap_or_default()
            .to_lowercase();
        return UsageProbe::failed(if msg.contains("auth") {
            "not-signed-in"
        } else {
            "cli-failed"
        });
    }
    let result = billing.get("result").cloned().unwrap_or(Value::Null);
    if let Some(tier) = result.get("subscription_tier").and_then(Value::as_str) {
        plan = Some(tier.to_string());
    }
    let Some(config) = result.get("config").filter(|c| !c.is_null()) else {
        return UsageProbe {
            ok: false,
            detail: "unparsed".into(),
            plan,
            account,
            windows: Vec::new(),
        };
    };
    let Some(used_percent) = config.get("creditUsagePercent").and_then(Value::as_f64) else {
        return UsageProbe {
            ok: false,
            detail: "unparsed".into(),
            plan,
            account,
            windows: Vec::new(),
        };
    };
    let period = config.get("currentPeriod");
    let period_type = period
        .and_then(|p| p.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let (label, window_minutes) = if period_type.ends_with("WEEKLY") {
        ("Weekly limit".to_string(), Some(7 * 24 * 60))
    } else if period_type.ends_with("MONTHLY") {
        ("Monthly limit".to_string(), None)
    } else {
        ("Usage".to_string(), None)
    };
    let resets_at_ms = period
        .and_then(|p| p.get("end"))
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp_millis().max(0) as u64);
    UsageProbe {
        ok: true,
        detail: "ok".into(),
        plan,
        account,
        windows: vec![UsageWindow {
            kind: "period".into(),
            label,
            model: None,
            used_percent,
            resets_at_ms,
            resets_label: None,
            window_minutes,
        }],
    }
}

/// Drive a line-delimited JSON-RPC child: each request with an `id` is written and answered
/// before the next is sent; notifications are written straight away. Answers (and only
/// answers: lines carrying an `id`) come back in arrival order. The child is stopped with
/// its process group afterwards, whatever happened.
pub fn run_jsonrpc(
    command: &Path,
    argv: &[&str],
    env: &AgentCliEnv,
    vendor: AgentCliVendor,
    requests: &[Value],
    deadline: Instant,
) -> Result<Vec<Value>, StopReason> {
    let mut cmd = Command::new(command);
    cmd.args(argv)
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    env.apply(&mut cmd, vendor);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|_| StopReason::Dropped)?;
    let pid = child.id();
    let Some(mut stdin) = child.stdin.take() else {
        kill_group(pid, libc::SIGKILL);
        let _ = child.wait();
        return Err(StopReason::Dropped);
    };
    let lines: Arc<std::sync::Mutex<Vec<Value>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let reader = child.stdout.take().map(|out| {
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut total = 0usize;
            for line in std::io::BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                total += line.len();
                if total > MAX_STDOUT_BYTES {
                    break;
                }
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    if v.get("id").is_some() {
                        sink.lock().unwrap_or_else(|e| e.into_inner()).push(v);
                    }
                }
            }
        })
    });
    let mut stop: Option<StopReason> = None;
    'requests: for req in requests {
        let mut bytes = serde_json::to_vec(req).unwrap_or_default();
        bytes.push(b'\n');
        if stdin.write_all(&bytes).and_then(|_| stdin.flush()).is_err() {
            stop = Some(StopReason::Dropped);
            break;
        }
        let Some(id) = req.get("id").and_then(Value::as_u64) else {
            continue;
        };
        loop {
            if lines
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|v| v.get("id").and_then(Value::as_u64) == Some(id))
            {
                break;
            }
            if let Ok(Some(_)) = child.try_wait() {
                stop = Some(StopReason::Dropped);
                break 'requests;
            }
            if Instant::now() >= deadline {
                stop = Some(StopReason::Deadline);
                break 'requests;
            }
            std::thread::sleep(POLL);
        }
    }
    drop(stdin);
    kill_group(pid, libc::SIGTERM);
    let grace = Instant::now() + KILL_GRACE;
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if Instant::now() >= grace {
            kill_group(pid, libc::SIGKILL);
            let _ = child.wait();
            break;
        }
        std::thread::sleep(POLL);
    }
    if let Some(h) = reader {
        let _ = h.join();
    }
    let collected = lines.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match stop {
        Some(StopReason::Deadline) => Err(StopReason::Deadline),
        Some(StopReason::Dropped) if collected.is_empty() => Err(StopReason::Dropped),
        _ => Ok(collected),
    }
}

/// The per-user scratch root a composition root uses when it has no home-scoped one:
/// `<tmp>/advance-agent-cli-<uid>` (0700 on creation).
pub fn default_work_root() -> PathBuf {
    #[cfg(unix)]
    let uid = unsafe { libc::getuid() };
    #[cfg(not(unix))]
    let uid = 0u32;
    let root = std::env::temp_dir().join(format!("advance-agent-cli-{uid}"));
    let _ = std::fs::create_dir_all(&root);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
    }
    root
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The port
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `InferenceBackendPort` over one vendor CLI. Registered per `agent-cli` provider id.
pub struct AgentCliBackend {
    pub spec: AgentCliSpec,
    pub provider_id: String,
    /// Per-request scratch root (`<home>/.runtime/agent-cli/<provider-id>`); each call gets
    /// its own 0700 subdirectory that is removed afterwards.
    pub work_root: PathBuf,
    pub env: AgentCliEnv,
}

impl AgentCliBackend {
    pub fn new(spec: AgentCliSpec, provider_id: impl Into<String>, work_root: PathBuf) -> Self {
        Self {
            spec,
            provider_id: provider_id.into(),
            work_root,
            env: AgentCliEnv::from_process_env(),
        }
    }

    pub fn with_env(mut self, env: AgentCliEnv) -> Self {
        self.env = env;
        self
    }

    fn command_path(&self) -> &Path {
        Path::new(&self.spec.command)
    }

    fn request_dir(&self) -> Result<PathBuf, InferenceBackendError> {
        let id: u64 = rand::random();
        let dir = self.work_root.join(format!("req-{id:016x}"));
        std::fs::create_dir_all(&dir).map_err(|e| err(format!("scratch dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(dir)
    }

    fn write_private(path: &Path, text: &str) -> Result<(), InferenceBackendError> {
        std::fs::write(path, text).map_err(|e| err(format!("scratch file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// One supervised turn. Blocking work runs on the blocking pool; the returned future
    /// kills the child if it is dropped early.
    async fn run_turn(&self, req: InferenceChatRequest) -> Result<CliTurn, InferenceBackendError> {
        if req.tools.as_ref().is_some_and(|t| !t.is_empty()) {
            return Err(InferenceBackendError::UnsupportedCapability("tools".into()));
        }
        if !self.is_wired() {
            return Err(err(format!(
                "cli not found at {}",
                self.command_path().display()
            )));
        }
        if !self.env.identity_complete() {
            return Err(err(
                "daemon identity unknown (HOME/USER); cannot reach the vendor sign-in",
            ));
        }
        let rendered = render_prompt(&req.messages);
        let dir = self.request_dir()?;
        let prompt_file = dir.join("prompt.txt");
        let user_text = if has_system_channel(self.spec.vendor) {
            rendered.user.clone()
        } else {
            fold_system_into_user(rendered.system.as_deref(), &rendered.user)
        };
        Self::write_private(&prompt_file, &user_text)?;
        let system_file = match &rendered.system {
            Some(text) if !text.trim().is_empty() && has_system_channel(self.spec.vendor) => {
                let p = dir.join("system.txt");
                Self::write_private(&p, text)?;
                Some(p)
            }
            _ => None,
        };
        let files = RecipeFiles {
            cwd: dir.clone(),
            prompt_file: prompt_file.clone(),
            system_file,
        };
        let argv = build_argv(self.spec.vendor, &req.model, &files, &self.spec.args);
        let stdin_bytes = match prompt_transport(self.spec.vendor) {
            PromptTransport::Stdin => Some(user_text.into_bytes()),
            PromptTransport::File => None,
        };
        let abort = Arc::new(AtomicBool::new(false));
        let _guard = KillOnDrop(Arc::clone(&abort));
        let command = self.command_path().to_path_buf();
        let env = self.env.clone();
        let vendor = self.spec.vendor;
        let cancel = Arc::clone(&req.cancel);
        let deadline = req.deadline;
        let cwd = dir.clone();
        let abort_for_task = Arc::clone(&abort);
        let outcome = tokio::task::spawn_blocking(move || {
            run_supervised(
                &command,
                &argv,
                &env,
                vendor,
                &cwd,
                stdin_bytes,
                deadline,
                &cancel,
                &abort_for_task,
            )
        })
        .await
        .map_err(|e| err(format!("supervisor panicked: {e}")))?;
        let _ = std::fs::remove_dir_all(&dir);
        let run = match outcome {
            Ok(run) => run,
            Err((StopReason::Cancelled, _)) => return Err(err("cancelled")),
            Err((StopReason::Deadline, _)) => return Err(err("deadline-exceeded")),
            Err((StopReason::Dropped, _)) => return Err(err("dropped")),
        };
        if run.stdout_truncated {
            return Err(err("reply exceeded the output cap"));
        }
        parse_output(self.spec.vendor, &run.stdout, &run.stderr, run.exit_code)
    }
}

/// C241 snapshot stream: one terminal delta carrying the whole reply.
struct OneShotStream {
    chunk: Option<InferenceTextDelta>,
}

#[async_trait]
impl InferenceStream for OneShotStream {
    async fn next_chunk(&mut self) -> Option<Result<InferenceTextDelta, InferenceBackendError>> {
        self.chunk.take().map(Ok)
    }
    fn cancel(&mut self) {
        self.chunk = None;
    }
}

#[async_trait]
impl InferenceBackendPort for AgentCliBackend {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        let model_hint = req.model.clone();
        let turn = self.run_turn(req).await?;
        Ok(InferenceChatResponse {
            text: turn.text,
            model: turn.model.unwrap_or(model_hint),
            input_tokens: turn.usage.input_tokens,
            output_tokens: turn.usage.output_tokens,
            finish_reason: turn.finish_reason,
        })
    }

    async fn embed(
        &self,
        _req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        Err(InferenceBackendError::UnsupportedCapability(
            "embeddings (agent-cli)".into(),
        ))
    }

    async fn start_stream(
        &self,
        req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        let turn = self.run_turn(req).await?;
        let stream = OneShotStream {
            chunk: Some(InferenceTextDelta {
                text: turn.text,
                usage: Some(advance_shared_types::inference::NormalizedUsage {
                    input_tokens: turn.usage.input_tokens,
                    output_tokens: turn.usage.output_tokens,
                    cached_tokens: turn.usage.cached_tokens,
                }),
                terminal: true,
                finish_reason: Some(turn.finish_reason),
            }),
        };
        Ok((
            InferenceStreamHead {
                class: InferenceStreamClass::Success,
                snapshot_only: true,
            },
            Box::new(stream),
        ))
    }

    fn is_wired(&self) -> bool {
        let p = self.command_path();
        p.is_absolute() && p.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::inference::InferenceMessage;

    fn spec(vendor: AgentCliVendor, command: &str) -> AgentCliSpec {
        AgentCliSpec {
            vendor,
            command: command.into(),
            args: vec![],
        }
    }

    fn files(dir: &Path) -> RecipeFiles {
        RecipeFiles {
            cwd: dir.to_path_buf(),
            prompt_file: dir.join("prompt.txt"),
            system_file: None,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cap-llm-agent-cli-{name}-{}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_fake_cli(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("fake-cli.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    fn req(model: &str, messages: Vec<(&str, &str)>) -> InferenceChatRequest {
        InferenceChatRequest {
            provider_id: "sub".into(),
            model: model.into(),
            messages: messages
                .into_iter()
                .map(|(r, c)| InferenceMessage {
                    role: r.into(),
                    content: c.into(),
                })
                .collect(),
            temperature: None,
            max_tokens: None,
            stop_sequences: None,
            tools: None,
            output_schema: None,
            deadline: Instant::now() + Duration::from_secs(30),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn test_env() -> AgentCliEnv {
        let mut m = BTreeMap::new();
        m.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        m.insert("HOME".to_string(), "/tmp/agent-cli-home".to_string());
        m.insert("USER".to_string(), "tester".to_string());
        m.insert(
            "ANTHROPIC_API_KEY".to_string(),
            "sk-must-not-leak".to_string(),
        );
        AgentCliEnv::from_map(&m)
    }

    const CLAUDE_OK: &str = r#"{"type":"system","subtype":"init","tools":[],"mcp_servers":[],"model":"claude-opus-5-5"}
{"type":"assistant","message":{"content":[{"type":"text","text":"OK"}]}}
{"type":"result","subtype":"success","is_error":false,"result":"OK","stop_reason":"end_turn","num_turns":1,"permission_denials":[],"usage":{"input_tokens":2,"cache_creation_input_tokens":1339,"cache_read_input_tokens":531,"output_tokens":4},"modelUsage":{"claude-opus-5-5":{"inputTokens":2}},"total_cost_usd":0.01}"#;

    const CODEX_OK: &str = r#"{"type":"thread.started","thread_id":"t1"}
{"type":"turn.started"}
{"type":"error","message":"Reconnecting... 2/5 (tls handshake eof)"}
{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"OK"}}
{"type":"turn.completed","usage":{"input_tokens":7277,"cached_input_tokens":2432,"output_tokens":5,"reasoning_output_tokens":0}}"#;

    const GROK_OK: &str = r#"{"text":"OK","stopReason":"end_turn","sessionId":"s","usage":{"input_tokens":7967,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":13,"reasoning_tokens":12},"num_turns":1,"modelUsage":{"grok-4.6-build":{"modelCalls":1}}}"#;

    #[test]
    fn env_allowlist_drops_secrets_and_completes_identity() {
        let env = test_env();
        assert!(env.get("ANTHROPIC_API_KEY").is_none());
        assert_eq!(env.get("USER"), Some("tester"));
        assert_eq!(env.get("LOGNAME"), Some("tester"));
        assert!(env
            .get("PATH")
            .unwrap()
            .contains("/tmp/agent-cli-home/.local/bin"));
        assert!(env.get("PATH").unwrap().contains("/opt/homebrew/bin"));
        assert!(env.identity_complete());
    }

    #[test]
    fn env_from_process_derives_identity_from_passwd() {
        let env = AgentCliEnv::from_process_env();
        // Whatever the test runner's environment, a Unix host resolves HOME/USER.
        if cfg!(unix) {
            assert!(env.identity_complete());
        }
    }

    #[test]
    fn claude_argv_pins_no_tools_and_keeps_prompt_off_argv() {
        let dir = PathBuf::from("/tmp/x");
        let argv = build_argv(
            AgentCliVendor::Claude,
            "sonnet",
            &files(&dir),
            &["--effort".into(), "low".into()],
        );
        let joined = argv.join(" ");
        assert!(argv.starts_with(&["-p".to_string()]));
        assert!(joined.contains("--tools  --restricted"), "{joined}");
        assert!(joined.contains("--strict-mcp-config"));
        assert!(joined.contains("--max-turns 1"));
        assert!(joined.contains("--no-session-persistence"));
        assert!(joined.contains("--model sonnet"));
        assert!(joined.ends_with("--effort low"), "extra args ride last");
        assert!(!joined.contains("prompt.txt"), "claude reads stdin");
        assert_eq!(
            prompt_transport(AgentCliVendor::Claude),
            PromptTransport::Stdin
        );
    }

    #[test]
    fn codex_argv_disables_every_acting_feature() {
        let dir = PathBuf::from("/tmp/x");
        let argv = build_argv(AgentCliVendor::Codex, "gpt-5.6-terra", &files(&dir), &[]);
        let joined = argv.join(" ");
        assert!(joined.starts_with("exec --json --ephemeral --skip-git-repo-check --ignore-user-config -s read-only -C /tmp/x -m gpt-5.6-terra"), "{joined}");
        for f in CODEX_DISABLED_FEATURES {
            assert!(joined.contains(&format!("--disable {f}")), "{f}");
        }
        assert!(joined.contains("web_search=\"disabled\""));
        assert!(joined.contains("mcp_servers={}"));
        assert_eq!(
            argv.last().map(String::as_str),
            Some("-"),
            "prompt on stdin"
        );
    }

    #[test]
    fn grok_argv_allowlists_then_denies_and_reads_prompt_file() {
        let dir = PathBuf::from("/tmp/x");
        let argv = build_argv(AgentCliVendor::Grok, "grok-4.6", &files(&dir), &[]);
        let joined = argv.join(" ");
        assert!(joined.contains("--prompt-file /tmp/x/prompt.txt"));
        assert!(joined.contains(
            "--tools todo_write --disallowed-tools todo_write,search_tool,use_tool,Agent"
        ));
        assert!(joined.contains("--max-turns 1"));
        assert!(joined.contains("--no-subagents"));
        assert!(joined.contains("--disable-web-search"));
        assert_eq!(
            prompt_transport(AgentCliVendor::Grok),
            PromptTransport::File
        );
    }

    #[test]
    fn codex_folds_system_text_into_the_stdin_transcript() {
        assert!(!has_system_channel(AgentCliVendor::Codex));
        assert!(has_system_channel(AgentCliVendor::Claude));
        let folded = fold_system_into_user(Some("Be terse."), "say OK");
        assert!(folded.starts_with(
            "[System instructions]\nBe terse.\n\n[End of system instructions]\n\nsay OK"
        ));
        assert_eq!(fold_system_into_user(None, "say OK"), "say OK");
        assert_eq!(fold_system_into_user(Some("  "), "say OK"), "say OK");
    }

    #[test]
    fn render_prompt_splits_system_and_transcript() {
        let msgs = vec![
            InferenceMessage {
                role: "system".into(),
                content: "Be terse.".into(),
            },
            InferenceMessage {
                role: "user".into(),
                content: "hi".into(),
            },
            InferenceMessage {
                role: "assistant".into(),
                content: "hello".into(),
            },
            InferenceMessage {
                role: "user".into(),
                content: "bye".into(),
            },
        ];
        let r = render_prompt(&msgs);
        assert_eq!(r.system.as_deref(), Some("Be terse."));
        assert!(r.user.contains("[User]\nhi"));
        assert!(r.user.contains("[Assistant]\nhello"));
        assert!(r.user.ends_with("[User]\nbye\n\n"));
        let single = render_prompt(&msgs[1..2]);
        assert_eq!(single.user, "hi");
        assert!(single.system.is_none());
    }

    #[test]
    fn parse_claude_accepts_proven_no_tools_turn() {
        let t = parse_output(AgentCliVendor::Claude, CLAUDE_OK.as_bytes(), b"", Some(0)).unwrap();
        assert_eq!(t.text, "OK");
        assert_eq!(t.usage.input_tokens, 2 + 1339 + 531);
        assert_eq!(t.usage.output_tokens, 4);
        assert_eq!(t.usage.cached_tokens, 531);
        assert_eq!(t.model.as_deref(), Some("claude-opus-5-5"));
        assert_eq!(t.finish_reason, "end_turn");
    }

    #[test]
    fn parse_claude_fails_closed_without_init_or_with_tools() {
        let no_init = CLAUDE_OK.lines().skip(1).collect::<Vec<_>>().join("\n");
        let e = parse_output(AgentCliVendor::Claude, no_init.as_bytes(), b"", Some(0)).unwrap_err();
        assert!(e.to_string().contains("no tools proof"), "{e}");
        let with_tools = CLAUDE_OK.replace("\"tools\":[]", "\"tools\":[\"Bash\"]");
        let e =
            parse_output(AgentCliVendor::Claude, with_tools.as_bytes(), b"", Some(0)).unwrap_err();
        assert!(e.to_string().contains("tools proof failed"), "{e}");
    }

    #[test]
    fn parse_claude_not_logged_in_is_a_non_retryable_sign_in_error() {
        let out = r#"{"type":"result","subtype":"success","is_error":true,"result":"Not logged in · Please run /login","duration_api_ms":0,"num_turns":1,"usage":{}}"#;
        let e = parse_output(AgentCliVendor::Claude, out.as_bytes(), b"", Some(1)).unwrap_err();
        assert!(matches!(e, InferenceBackendError::Provider(_)));
        assert!(e.to_string().contains("not signed in"), "{e}");
    }

    #[test]
    fn classify_quota_window_is_not_a_transient_rate_limit() {
        let e = classify_failure("You've hit your usage limit. Try again at 3pm.");
        assert!(matches!(e, InferenceBackendError::Provider(_)), "{e}");
        assert!(e.to_string().contains("usage limit"));
        let e = classify_failure("overloaded_error: 529");
        assert!(matches!(e, InferenceBackendError::RateLimited(_)), "{e}");
        let e = classify_failure("prompt is too long: 250000 tokens > 200000");
        assert!(matches!(e, InferenceBackendError::ContextTooLong(_)), "{e}");
        let e = classify_failure(
            "model gpt-6 is not supported when using Codex with a ChatGPT account",
        );
        assert!(
            matches!(e, InferenceBackendError::ModelNotAvailable(_)),
            "{e}"
        );
    }

    #[test]
    fn parse_codex_accepts_message_only_turns_and_rejects_tool_items() {
        let t = parse_output(AgentCliVendor::Codex, CODEX_OK.as_bytes(), b"", Some(0)).unwrap();
        assert_eq!(t.text, "OK");
        assert_eq!(t.usage.input_tokens, 7277);
        assert_eq!(t.usage.cached_tokens, 2432);
        assert_eq!(t.usage.output_tokens, 5);
        let escaped = CODEX_OK.replace(
            "\"type\":\"agent_message\"",
            "\"type\":\"command_execution\"",
        );
        let e = parse_output(AgentCliVendor::Codex, escaped.as_bytes(), b"", Some(0)).unwrap_err();
        assert!(e.to_string().contains("tools proof failed"), "{e}");
        let failed = r#"{"type":"turn.started"}
{"type":"error","message":"You've hit your usage limit. try again at 5pm"}
{"type":"turn.failed","error":{"message":"You've hit your usage limit. try again at 5pm"}}"#;
        let e = parse_output(AgentCliVendor::Codex, failed.as_bytes(), b"", Some(1)).unwrap_err();
        assert!(e.to_string().contains("usage limit"), "{e}");
    }

    #[test]
    fn parse_grok_reads_single_object_and_reasoning_tokens() {
        let t = parse_output(AgentCliVendor::Grok, GROK_OK.as_bytes(), b"", Some(0)).unwrap();
        assert_eq!(t.text, "OK");
        assert_eq!(t.usage.input_tokens, 7967);
        assert_eq!(t.usage.output_tokens, 13 + 12);
        assert_eq!(t.model.as_deref(), Some("grok-4.6-build"));
    }

    #[test]
    fn no_output_uses_stderr_for_the_verdict() {
        let e = parse_output(
            AgentCliVendor::Codex,
            b"",
            b"error: not logged in, run codex login",
            Some(1),
        )
        .unwrap_err();
        assert!(e.to_string().contains("not signed in"), "{e}");
        let e = parse_output(AgentCliVendor::Grok, b"", b"", Some(2)).unwrap_err();
        assert!(e.to_string().contains("no result (exit 2)"), "{e}");
    }

    #[tokio::test]
    async fn fake_claude_round_trip_records_argv_env_and_stdin() {
        let dir = scratch("claude");
        let log = dir.join("log");
        let body = format!(
            "printf '%s\\n' \"$@\" > {log}.argv\nenv > {log}.env\ncat > {log}.stdin\ncat <<'EOF'\n{CLAUDE_OK}\nEOF",
            log = log.display()
        );
        let cli = write_fake_cli(&dir, &body);
        let backend = AgentCliBackend::new(
            spec(AgentCliVendor::Claude, cli.to_str().unwrap()),
            "sub",
            dir.join("work"),
        )
        .with_env(test_env());
        assert!(backend.is_wired());
        let resp = backend
            .chat(req(
                "sonnet",
                vec![("system", "Be terse."), ("user", "say OK")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.text, "OK");
        assert_eq!(resp.model, "claude-opus-5-5");
        assert_eq!(resp.input_tokens, 1872);
        let argv = std::fs::read_to_string(format!("{}.argv", log.display())).unwrap();
        assert!(argv.contains("--tools\n\n--restricted"), "{argv}");
        assert!(argv.contains("--system-prompt-file"));
        assert!(!argv.contains("say OK"), "prompt never on argv");
        let stdin = std::fs::read_to_string(format!("{}.stdin", log.display())).unwrap();
        assert_eq!(stdin, "say OK");
        let env = std::fs::read_to_string(format!("{}.env", log.display())).unwrap();
        assert!(!env.contains("ANTHROPIC_API_KEY"), "{env}");
        assert!(env.contains("USER=tester"));
        assert!(env.contains("NO_COLOR=1"));
        // The per-request scratch directory is gone.
        let left: Vec<_> = std::fs::read_dir(dir.join("work"))
            .map(|d| d.count())
            .unwrap_or(0)
            .to_string()
            .chars()
            .collect();
        assert_eq!(left, vec!['0']);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fake_grok_reads_prompt_file_and_reports_usage() {
        let dir = scratch("grok");
        let log = dir.join("log");
        let body = format!(
            "printf '%s\\n' \"$@\" > {log}.argv\nfor a in \"$@\"; do case \"$prev\" in --prompt-file) cp \"$a\" {log}.prompt;; esac; prev=\"$a\"; done\ncat <<'EOF'\n{GROK_OK}\nEOF",
            log = log.display()
        );
        let cli = write_fake_cli(&dir, &body);
        let backend = AgentCliBackend::new(
            spec(AgentCliVendor::Grok, cli.to_str().unwrap()),
            "sub",
            dir.join("work"),
        )
        .with_env(test_env());
        let (head, mut stream) = backend
            .start_stream(req("grok-4.6", vec![("user", "say OK")]))
            .await
            .unwrap();
        assert!(head.snapshot_only);
        let delta = stream.next_chunk().await.unwrap().unwrap();
        assert_eq!(delta.text, "OK");
        assert!(delta.terminal);
        assert_eq!(delta.usage.as_ref().map(|u| u.output_tokens), Some(25));
        assert!(stream.next_chunk().await.is_none());
        let prompt = std::fs::read_to_string(format!("{}.prompt", log.display())).unwrap();
        assert_eq!(prompt, "say OK");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancel_kills_the_child_group_promptly() {
        let dir = scratch("cancel");
        let cli = write_fake_cli(&dir, "sleep 30\necho never");
        let backend = AgentCliBackend::new(
            spec(AgentCliVendor::Codex, cli.to_str().unwrap()),
            "sub",
            dir.join("work"),
        )
        .with_env(test_env());
        let r = req("m", vec![("user", "x")]);
        let cancel = Arc::clone(&r.cancel);
        let started = Instant::now();
        let fut = backend.chat(r);
        let canceller = async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            cancel.store(true, Ordering::SeqCst);
        };
        let (res, _) = tokio::join!(fut, canceller);
        let e = res.unwrap_err();
        assert!(e.to_string().contains("cancelled"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deadline_stops_a_hung_child() {
        let dir = scratch("deadline");
        let cli = write_fake_cli(&dir, "sleep 30");
        let backend = AgentCliBackend::new(
            spec(AgentCliVendor::Claude, cli.to_str().unwrap()),
            "sub",
            dir.join("work"),
        )
        .with_env(test_env());
        let mut r = req("m", vec![("user", "x")]);
        r.deadline = Instant::now() + Duration::from_millis(400);
        let started = Instant::now();
        let e = backend.chat(r).await.unwrap_err();
        assert!(e.to_string().contains("deadline-exceeded"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tools_in_request_are_refused_before_spawn() {
        let dir = scratch("tools");
        let backend = AgentCliBackend::new(
            spec(AgentCliVendor::Claude, "/nonexistent/claude"),
            "sub",
            dir.join("work"),
        );
        assert!(!backend.is_wired());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut r = req("m", vec![("user", "x")]);
        r.tools = Some(vec![advance_shared_types::inference::InferenceTool {
            name: "t".into(),
            description: String::new(),
            parameters: Value::Null,
        }]);
        let e = rt.block_on(backend.chat(r)).unwrap_err();
        assert!(matches!(e, InferenceBackendError::UnsupportedCapability(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_probe_reports_missing_cli_and_parses_claude_status() {
        let missing = probe_auth(
            &spec(AgentCliVendor::Claude, "/nonexistent/claude"),
            &test_env(),
        );
        assert!(!missing.cli_present && !missing.signed_in);
        assert_eq!(missing.detail, "cli-not-found");
        let dir = scratch("probe");
        let cli = write_fake_cli(&dir, "[ \"$1\" = auth ] && [ \"$2\" = status ] && echo '{\"loggedIn\":true,\"authMethod\":\"claude.ai\"}'");
        let p = probe_auth(
            &spec(AgentCliVendor::Claude, cli.to_str().unwrap()),
            &test_env(),
        );
        assert!(p.cli_present && p.signed_in, "{p:?}");
        let cli2 = write_fake_cli(&dir, "echo 'Not logged in' >&2; exit 1");
        let p = probe_auth(
            &spec(AgentCliVendor::Codex, cli2.to_str().unwrap()),
            &test_env(),
        );
        assert!(p.cli_present && !p.signed_in, "{p:?}");
        assert!(p.detail.starts_with("not-signed-in"), "{p:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sign_in_and_probe_argv_are_the_vendors_own_flows() {
        assert_eq!(sign_in_argv(AgentCliVendor::Claude), vec!["auth", "login"]);
        assert_eq!(sign_in_argv(AgentCliVendor::Codex), vec!["login"]);
        assert_eq!(auth_probe_argv(AgentCliVendor::Grok), vec!["models"]);
    }
}
