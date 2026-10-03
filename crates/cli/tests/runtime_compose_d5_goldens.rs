//! MODULE-001-T111 (1)–(2) / MODULE-001-AC-30 — the v0.1.26 no-regression goldens of ADR
//! 2026-10-03 D5, captured from the unchanged v0.1.26 composition.
//!
//! What is pinned (golden files under `tests/goldens/runtime_compose_d5/`):
//! - the route table (method, path, exact / templated, session, mutation, scopes) of the
//!   production-composed Client API on an `fs` + `llm` home (H1) and on a home declaring every
//!   `KNOWN_CAPABILITIES` entry (H2), read in-process through `ClientApi::route_table`;
//! - the normalised stdout and stderr (one golden per stream) of the real `advance start` binary
//!   on H1 and H2, from spawn until EOF after SIGTERM;
//! - the byte format and mode of `.runtime/runtime.lock`, `.runtime/client-api` and
//!   `.runtime/selected-provider` while H1 runs, and which of them remain after exit;
//! - the exit status after a startup failure (missing runtime-config), after a failed readiness
//!   write (EPIPE on stdout) and after SIGTERM;
//! - one HTTP probe of every route of the route table (plus the session operations and the Web
//!   Console assets) through the real binary on five homes H1..H5.
//!
//! Normalisation masks ONLY volatile tokens, each after checking it where it can be checked:
//! the per-run temp root (`<ROOT>`; homes live at `<ROOT>/ws`, `HOME` at `<ROOT>/home`, `TMPDIR`
//! at `<ROOT>/tmp`), loopback ports (`127.0.0.1:<PORT>`), the child pid (only in the runtime
//! files, after checking it equals the spawned pid), the RFC 3339 timestamps and the OS /
//! process-start parts of `platform_uid` in `runtime.lock` (after checking their shape against
//! `std::env::consts::OS` and `ps -o lstart=`), and the thread id and source location of a std
//! panic message. Every other byte, line and stream is compared exactly.
//!
//! Golden update mode: goldens are written only when `ADVANCE_UPDATE_D5_GOLDENS=1` is set; a
//! missing golden fails the test otherwise. The goldens are v0.1.26 captures: later steps must
//! not re-capture the route-probe goldens; intended wire changes go through
//! [`D5_CHANGE_MATRIX`].
#![cfg(unix)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, Once};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use advance_cli::agent_config::KNOWN_CAPABILITIES;
use advance_client_api::{ClientApi, ClientApiConfig, Method, RouteTableEntry, Scope, API_VERSION};
use advance_runtime::bootstrap::RuntimeHostBuilder;
use serde_json::Value;
use tempfile::TempDir;
use wit_component::ComponentEncoder;

// ── Fixtures and budgets ──────────────────────────────────────────────────────────────────

/// The deployed driver: the committed wit-bindgen guest core module, encoded to a component the
/// way `start_msg_turn.rs` does (the daemon's `load_component` parses components only).
const MINIMAL_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");

const GOLDEN_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/goldens/runtime_compose_d5"
);
const UPDATE_ENV: &str = "ADVANCE_UPDATE_D5_GOLDENS";

const MASTER_KEY_ENV: &str = "ADVANCE_D5_GOLDEN_MASTER_KEY";
const MASTER_KEY_HEX: &str = "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5";

/// Cold-start budget until the last boot line (first-run engine compile on a cold cache).
const BOOT_TIMEOUT: Duration = Duration::from_secs(180);
/// After the last boot line, both streams must stay silent this long before SIGTERM.
const QUIET_PERIOD: Duration = Duration::from_millis(1500);
/// Upper bound for reaching the quiet period once the last boot line is seen.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a run gets to exit after SIGTERM before it is recorded as not exiting and SIGKILLed.
const SIGTERM_EXIT_BUDGET_SECS: u64 = 15;
/// How long a startup-failure run gets to exit on its own.
const FAILURE_EXIT_BUDGET: Duration = Duration::from_secs(180);
/// Per-request socket timeout of a route probe (a probe must never hang).
const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The value of every path parameter of a probed templated route.
const PROBE_PARAM: &str = "golden-probe-id";

// ── Pending-decision expectations (one constant each) ─────────────────────────────────────

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitOutcome {
    Code(i32),
    Signal(i32),
    /// Still running `SIGTERM_EXIT_BUDGET_SECS` after SIGTERM (the run was then SIGKILLed).
    NoExitAfterSigterm,
}

impl ExitOutcome {
    fn render(self) -> String {
        match self {
            ExitOutcome::Code(code) => format!("exit={code}"),
            ExitOutcome::Signal(signal) => format!("killed by signal {signal}"),
            ExitOutcome::NoExitAfterSigterm => {
                format!("no exit within {SIGTERM_EXIT_BUDGET_SECS}s of SIGTERM (then SIGKILLed)")
            }
        }
    }
}

/// An exit expectation the owner has not decided yet, kept in one constant so a later step can
/// change it in one place (the outcome and the golden that pins that scenario's streams).
struct PendingExpectation {
    outcome: ExitOutcome,
    golden: &'static str,
}

/// Exit status of `advance start` when the readiness line cannot be written (stdout's read end
/// closed right after spawn, so the first stdout write gets EPIPE). OWNER DECISION PENDING.
///
/// ADR D1 "Output", MODULE-001-AC-30 and T111 say this "still ends `advance start` with exit 1,
/// as today (`start.rs:367-374`)". The v0.1.26 base does not: the readiness line is written by
/// `println!`, which panics on the EPIPE before the exit-1 flush branch can run, so the process
/// exits 101 and stderr carries std's `failed printing to stdout: Broken pipe (os error 32)`
/// panic message. This constant records what v0.1.26 actually does.
const READINESS_WRITE_FAILURE: PendingExpectation = PendingExpectation {
    outcome: ExitOutcome::Code(101),
    golden: "exit.readiness_write_failure.golden",
};

/// Exit status after SIGTERM on H2 (every capability declared, a git repository). OWNER /
/// LANE DECISION PENDING.
///
/// T111 expects exit 0 after SIGTERM. On the v0.1.26 base H2 prints `advance: shutting down`,
/// removes `runtime.lock` and then never exits: dropping the current-thread runtime waits on its
/// blocking pool, where the git commit queue worker (`advance_git` `worker_loop`, a
/// `spawn_blocking` task) still waits in `blocking_recv` because a sender of its queue is still
/// held. It reproduces with `fs` + `llm` + `messaging` on a git repository; without `messaging`
/// or without a git repository the run exits 0. The ADR D1 shutdown sequence (git queue closed
/// and its worker joined) is expected to turn this into `ExitOutcome::Code(0)`.
const H2_SIGTERM_AFTER_READINESS: ExitOutcome = ExitOutcome::NoExitAfterSigterm;

// ── D5 change matrix overlay for the route-probe goldens ──────────────────────────────────

/// One explicit change of a v0.1.26 route-probe golden line (`<METHOD> <path> -> <outcome>`).
struct D5Change {
    /// Labels of the probe homes the change applies to (`h1_fs_llm`, …).
    homes: &'static [&'static str],
    method: &'static str,
    /// The route as it appears in the golden (template text for a templated route).
    path: &'static str,
    /// The v0.1.26 outcome recorded in the golden. The overlay refuses to apply when the golden
    /// says anything else, so it can only change what it names.
    before: &'static str,
    /// The outcome after the change.
    after: &'static str,
}

/// The route-probe overlay: the ADR 2026-10-03 D5 change matrix, "the intended wire changes for
/// a plain `advance start` (no extension), and nothing else":
///
/// | Route | Home | v0.1.26 | After |
/// |---|---|---|---|
/// | events, events/stream, run / task history | no `lifecycle` | `module_unavailable` | `data` (D4) |
/// | grants/pending | neither `lifecycle` nor `grant`; or `lifecycle` without `grant` | `module_unavailable` | `{requests: []}` |
/// | grants/pending | `grant` without `lifecycle` | `module_unavailable` | unchanged |
/// | tools | no deployed driver, or no `tools` | `module_unavailable` | `data` |
/// | llm/deltas/stream | `llm` without `lifecycle` | pages without a resume cursor | pages carry a resume cursor (the cursor codec is now installed on every home) |
///
/// Empty at the v0.1.26 capture: every golden must match exactly. The step that implements D4
/// adds one entry per (home, route) the table changes, with the v0.1.26 `before` text copied
/// from the golden. The llm/deltas/stream row has no line to change here: a plain GET of that
/// route answers `{subscribed}` both before and after, and the resume cursor rides WebSocket
/// delta pages, which these probes do not open.
const D5_CHANGE_MATRIX: &[D5Change] = &[];

// ── Homes ─────────────────────────────────────────────────────────────────────────────────

/// One home of the goldens.
struct HomeSpec {
    /// File-name label of the home's goldens.
    label: &'static str,
    /// Short name in golden headers (the full description is [`describe`]).
    name: &'static str,
    /// Declared capabilities; `None` = every `KNOWN_CAPABILITIES` entry.
    caps: Option<&'static [&'static str]>,
    /// Deploy the driver component.
    driver: bool,
    /// Make the home a git repository (one empty commit).
    git: bool,
    /// Turn the runtime GenUI flag on (`genui.enabled`), so a declared `genui` is wired.
    genui: bool,
}

const H1: HomeSpec = HomeSpec {
    label: "h1_fs_llm",
    name: "H1",
    caps: Some(&["fs", "llm"]),
    driver: true,
    git: false,
    genui: false,
};

const H2: HomeSpec = HomeSpec {
    label: "h2_all_capabilities",
    name: "H2",
    caps: None,
    driver: true,
    git: true,
    genui: true,
};

const H3: HomeSpec = HomeSpec {
    label: "h3_fs_llm_lifecycle",
    name: "H3",
    caps: Some(&["fs", "llm", "lifecycle"]),
    driver: true,
    git: false,
    genui: false,
};

const H4: HomeSpec = HomeSpec {
    label: "h4_fs_llm_grant",
    name: "H4",
    caps: Some(&["fs", "llm", "grant"]),
    driver: true,
    git: false,
    genui: false,
};

const H5: HomeSpec = HomeSpec {
    label: "h5_fs_llm_no_driver",
    name: "H5",
    caps: Some(&["fs", "llm"]),
    driver: false,
    git: false,
    genui: false,
};

fn runtime_yaml(spec: &HomeSpec) -> String {
    let mut yaml = format!(
        r#"wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt: gpt-4o
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: {MASTER_KEY_ENV}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    );
    if spec.genui {
        yaml.push_str("\ngenui:\n  enabled: true\n");
    }
    yaml
}

fn agent_yaml(spec: &HomeSpec) -> String {
    let mut yaml = String::from("capabilities:\n");
    for cap in declared_caps(spec) {
        let _ = writeln!(yaml, "  {cap}: true");
    }
    yaml
}

fn declared_caps(spec: &HomeSpec) -> Vec<&'static str> {
    match spec.caps {
        Some(caps) => caps.to_vec(),
        None => KNOWN_CAPABILITIES.to_vec(),
    }
}

/// The golden-header description of a home, derived from the spec itself.
fn describe(spec: &HomeSpec) -> String {
    let caps = declared_caps(spec).join(", ");
    let mut parts = vec![match spec.caps {
        Some(_) => format!("capabilities: {caps}"),
        None => format!("capabilities: every KNOWN_CAPABILITIES entry = {caps}"),
    }];
    if spec.genui {
        parts.push("genui.enabled: true".to_string());
    }
    parts.push(
        if spec.driver {
            "deployed driver"
        } else {
            "NO deployed driver"
        }
        .to_string(),
    );
    parts.push(
        if spec.git {
            "git repository"
        } else {
            "no git repository"
        }
        .to_string(),
    );
    format!("{} ({})", spec.name, parts.join("; "))
}

/// A home under a fresh temp root: `<root>/ws` (the workspace), `<root>/home` (the child's
/// `HOME`) and `<root>/tmp` (the child's `TMPDIR`).
struct TestHome {
    _dir: TempDir,
    /// The temp root as created (may differ from `root` by a symlinked prefix, e.g. macOS
    /// `/var` → `/private/var`).
    raw_root: PathBuf,
    root: PathBuf,
    ws: PathBuf,
}

impl TestHome {
    fn new_root() -> TestHome {
        let dir = tempfile::tempdir().expect("tempdir");
        let raw_root = dir.path().to_path_buf();
        let root = std::fs::canonicalize(&raw_root).expect("canonicalize temp root");
        std::fs::create_dir_all(root.join("home")).expect("create HOME dir");
        std::fs::create_dir_all(root.join("tmp")).expect("create TMPDIR dir");
        let ws = root.join("ws");
        TestHome {
            _dir: dir,
            raw_root,
            root,
            ws,
        }
    }

    /// The child environment: nothing inherited but `PATH` (`runtime.lock`'s liveness probe
    /// spawns `kill` and `ps`), with `HOME`, `TMPDIR` and the master key set explicitly.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_advance"));
        cmd.args(args)
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("TMPDIR", self.root.join("tmp"))
            .env(MASTER_KEY_ENV, MASTER_KEY_HEX)
            .stdin(Stdio::null());
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd
    }

    fn start_command(&self) -> Command {
        let ws = self.ws.to_str().expect("utf-8 workspace path").to_string();
        self.command(&["start", "--workspace", &ws])
    }

    fn masks(&self) -> Masks {
        let root = self.root.to_str().expect("utf-8 root").to_string();
        let raw_root = self.raw_root.to_str().expect("utf-8 raw root").to_string();
        let mut paths = vec![(root, "<ROOT>".to_string())];
        if paths[0].0 != raw_root {
            paths.push((raw_root, "<ROOT>".to_string()));
        }
        Masks { paths }
    }
}

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(MINIMAL_CORE)
        .expect("wrap core module")
        .encode()
        .expect("encode component")
}

fn init_git_repo(dir: &Path) {
    let repo = git2::Repository::init(dir).expect("git init");
    let mut cfg = repo.config().expect("repo config");
    cfg.set_str("user.name", "d5-golden").expect("user.name");
    cfg.set_str("user.email", "d5-golden@example.invalid")
        .expect("user.email");
    let sig = git2::Signature::now("d5-golden", "d5-golden@example.invalid").expect("signature");
    let tree_id = repo.index().expect("index").write_tree().expect("tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    repo.commit(Some("HEAD"), &sig, &sig, "init", &tree, &[])
        .expect("initial commit");
}

/// `advance init <root>/ws`, then the spec's runtime config, agent config, driver and git repo.
fn make_home(spec: &HomeSpec) -> TestHome {
    let home = TestHome::new_root();
    let ws = home.ws.to_str().expect("utf-8 workspace").to_string();
    let out = home
        .command(&["init", &ws])
        .output()
        .expect("spawn advance init");
    assert!(
        out.status.success(),
        "advance init failed: {:?}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(
        home.ws.join(".advance/runtime-config.yaml"),
        runtime_yaml(spec),
    )
    .expect("write runtime config");
    std::fs::write(home.ws.join(".agent/config.yaml"), agent_yaml(spec))
        .expect("write agent config");
    if spec.driver {
        std::fs::write(
            home.ws.join(".agent/behavior.component.wasm"),
            component_bytes(),
        )
        .expect("deploy driver component");
    }
    if spec.git {
        init_git_repo(&home.ws);
    }
    home
}

// ── Normalisation ─────────────────────────────────────────────────────────────────────────

struct Masks {
    /// Exact path prefixes → placeholder, longest (canonical) first.
    paths: Vec<(String, String)>,
}

impl Masks {
    fn apply(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (from, to) in &self.paths {
            out = out.replace(from.as_str(), to);
        }
        let out = mask_loopback_ports(&out);
        mask_std_panic_header(&out)
    }
}

/// `127.0.0.1:<digits>` → `127.0.0.1:<PORT>`.
fn mask_loopback_ports(text: &str) -> String {
    const HOST: &str = "127.0.0.1:";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(HOST) {
        let (head, tail) = rest.split_at(at + HOST.len());
        out.push_str(head);
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            out.push_str("<PORT>");
        }
        rest = &tail[digits..];
    }
    out.push_str(rest);
    out
}

/// std's panic header `thread '<name>' (<tid>) panicked at <file>:<line>:<col>:` →
/// `thread '<name>' (<TID>) panicked at <PANIC_LOCATION>:`. The thread id is per process (and a
/// toolchain that prints none renders the same `(<TID>)`), and the location is a std / toolchain
/// source position; the thread name and the panic message are kept.
fn mask_std_panic_header(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        match mask_panic_line(body) {
            Some(masked) => out.push_str(&masked),
            None => out.push_str(body),
        }
        out.push_str(newline);
    }
    out
}

fn mask_panic_line(line: &str) -> Option<String> {
    let rest = line.strip_prefix("thread '")?;
    let (name, rest) = rest.split_once("' ")?;
    let rest = match rest.strip_prefix('(') {
        Some(after) => {
            let (tid, after) = after.split_once(") ")?;
            if tid.is_empty() || !tid.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            after
        }
        None => rest,
    };
    let location = rest.strip_prefix("panicked at ")?.strip_suffix(':')?;
    if location.is_empty() {
        return None;
    }
    Some(format!(
        "thread '{name}' (<TID>) panicked at <PANIC_LOCATION>:"
    ))
}

// ── Golden files ──────────────────────────────────────────────────────────────────────────

fn update_mode() -> bool {
    std::env::var(UPDATE_ENV).map(|v| v == "1").unwrap_or(false)
}

fn golden_path(name: &str) -> PathBuf {
    Path::new(GOLDEN_DIR).join(name)
}

fn read_golden(name: &str) -> String {
    let path = golden_path(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "golden {} is missing or unreadable ({e}); goldens are captured on the v0.1.26 base \
             with {UPDATE_ENV}=1",
            path.display()
        )
    })
}

fn write_golden(name: &str, actual: &str) {
    std::fs::create_dir_all(GOLDEN_DIR).expect("create golden dir");
    std::fs::write(golden_path(name), actual).expect("write golden");
}

fn assert_text_eq(name: &str, expected: &str, actual: &str) {
    if expected == actual {
        return;
    }
    let expected_lines: Vec<&str> = expected.split('\n').collect();
    let actual_lines: Vec<&str> = actual.split('\n').collect();
    let first = expected_lines
        .iter()
        .zip(actual_lines.iter())
        .position(|(e, a)| e != a)
        .unwrap_or(expected_lines.len().min(actual_lines.len()));
    panic!(
        "golden {name} differs at line {}:\n  golden: {:?}\n  actual: {:?}\n\
         ----- golden -----\n{expected}\n----- actual -----\n{actual}",
        first + 1,
        expected_lines.get(first),
        actual_lines.get(first),
    );
}

/// Compare `actual` with the golden `name` (or write it in update mode).
fn check_golden(name: &str, actual: &str) {
    if update_mode() {
        write_golden(name, actual);
        return;
    }
    assert_text_eq(name, &read_golden(name), actual);
}

fn apply_overlay(changes: &[D5Change], home: &str, golden: &str) -> String {
    let mut lines: Vec<String> = golden.split('\n').map(str::to_string).collect();
    for change in changes.iter().filter(|c| c.homes.contains(&home)) {
        let key = format!("{} {} -> ", change.method, change.path);
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with(&key))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "D5 overlay {} {} on {home}: expected exactly one golden line",
            change.method,
            change.path
        );
        let line = &mut lines[hits[0]];
        let before = &line[key.len()..];
        assert_eq!(
            before, change.before,
            "D5 overlay {} {} on {home}: the golden's v0.1.26 outcome differs from the overlay's \
             `before`",
            change.method, change.path
        );
        *line = format!("{key}{}", change.after);
    }
    lines.join("\n")
}

/// Compare a route-probe result with its golden after the overlay `changes`
/// ([`D5_CHANGE_MATRIX`]).
fn check_probe_golden(changes: &[D5Change], home: &str, name: &str, actual: &str) {
    if update_mode() {
        assert!(
            changes.is_empty(),
            "route-probe goldens are v0.1.26 captures and are never re-captured once the D5 \
             overlay is in use; change D5_CHANGE_MATRIX instead"
        );
        write_golden(name, actual);
        return;
    }
    let expected = apply_overlay(changes, home, &read_golden(name));
    assert_text_eq(name, &expected, actual);
}

// ── Route table ───────────────────────────────────────────────────────────────────────────

fn method_name(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
    }
}

fn scope_name(scope: &Scope) -> String {
    serde_json::to_value(scope)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .expect("scope serializes to a string")
}

fn render_route_table(title: &str, table: &[RouteTableEntry]) -> String {
    let mut out = format!(
        "# MODULE-001-T111 (1) route table of the Client API composed in-process (RuntimeHostBuilder::new + wire_capabilities) on {title}\n\
         # method path | exact/templated session mutation scopes\n"
    );
    for entry in table {
        let scopes: Vec<String> = entry.required_scopes.iter().map(scope_name).collect();
        let _ = writeln!(
            out,
            "{} {} | {} session={} mutation={} scopes=[{}]",
            method_name(entry.method),
            entry.path,
            if entry.templated {
                "templated"
            } else {
                "exact"
            },
            entry.requires_session,
            entry.is_mutation,
            scopes.join(",")
        );
    }
    out
}

fn ensure_in_process_master_key() {
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var(MASTER_KEY_ENV, MASTER_KEY_HEX));
}

/// Compose `spec`'s home in-process through the production path and read the route table from
/// the composed server (the same `ClientApi` instance the loopback transport serves).
async fn composed_route_table(spec: &HomeSpec) -> Vec<RouteTableEntry> {
    ensure_in_process_master_key();
    let home = make_home(spec);
    let config_path = home.ws.join(".advance/runtime-config.yaml");
    let builder = RuntimeHostBuilder::new(&config_path, &home.ws)
        .await
        .expect("RuntimeHostBuilder::new");
    let (host, handles) = if declared_caps(spec).contains(&"messaging") {
        // Progress-lifecycle state goes under the test HOME, never the process HOME.
        advance_cli::wiring::wire_capabilities_with_home_for_test(
            builder,
            &home.ws,
            &home.root.join("home"),
        )
        .await
        .expect("wire_capabilities_with_home_for_test")
    } else {
        advance_cli::wiring::wire_capabilities(builder, &home.ws)
            .await
            .expect("wire_capabilities")
    };
    let table = handles
        .client_api_server
        .as_ref()
        .expect("the composition binds the Client API")
        .api()
        .route_table();
    drop(handles);
    drop(host);
    table
}

/// The table the route probes walk: a default-constructed `ClientApi` (the route set does not
/// depend on configuration or providers). The route-table tests check it equals the table of
/// the composed server on H1 and H2.
fn probe_route_table() -> Vec<RouteTableEntry> {
    ClientApi::new(ClientApiConfig::default()).route_table()
}

/// The route-table golden is also intentionally checked to be home-independent: the composed
/// table must equal the default-constructed one the probes walk.
async fn route_table_golden(spec: &HomeSpec) {
    let table = composed_route_table(spec).await;
    assert_eq!(
        table,
        probe_route_table(),
        "the composed route table equals the default-constructed one walked by the probes"
    );
    check_golden(
        &format!("route_table.{}.golden", spec.label),
        &render_route_table(&describe(spec), &table),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_t111_ac30_route_table_h1_fs_llm() {
    route_table_golden(&H1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_t111_ac30_route_table_h2_all_capabilities() {
    // Same declarations as the binary H2, minus the git repository: with `messaging` on a git
    // repository the composition's git commit worker outlives the runtime it was spawned on
    // (see `H2_SIGTERM_AFTER_READINESS`), which would hang this test's runtime drop. The route
    // table does not depend on the repository.
    route_table_golden(&HomeSpec { git: false, ..H2 }).await;
}

// ── `advance start` runs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
}

/// Everything a run wrote, as raw chunks (one `read_until('\n')` each) in arrival order.
#[derive(Default)]
struct Transcript {
    chunks: Vec<(Stream, Vec<u8>)>,
    last_activity: Option<Instant>,
}

impl Transcript {
    fn text(&self, stream: Stream) -> String {
        let bytes: Vec<u8> = self
            .chunks
            .iter()
            .filter(|(s, _)| *s == stream)
            .flat_map(|(_, b)| b.iter().copied())
            .collect();
        String::from_utf8(bytes).expect("utf-8 output")
    }

    fn has_line(&self, stream: Stream, prefix: &str) -> bool {
        self.chunks
            .iter()
            .any(|(s, b)| *s == stream && b.starts_with(prefix.as_bytes()))
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    stream: Stream,
    pipe: R,
    transcript: Arc<Mutex<Transcript>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        loop {
            let mut chunk = Vec::new();
            match reader.read_until(b'\n', &mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let mut t = transcript.lock().unwrap_or_else(|e| e.into_inner());
                    t.chunks.push((stream, chunk));
                    t.last_activity = Some(Instant::now());
                }
            }
        }
    })
}

/// The last step of the v0.1.26 boot sequence before `advance start` parks (the readiness walk).
fn boot_complete(t: &Transcript) -> bool {
    t.has_line(
        Stream::Stdout,
        "advance: continuous component reconciliation wired",
    ) || t.has_line(Stream::Stderr, "advance: readiness walk did not run")
        || t.has_line(Stream::Stderr, "advance: skipping readiness walk")
}

struct LiveRun {
    child: Child,
    transcript: Arc<Mutex<Transcript>>,
    readers: Vec<JoinHandle<()>>,
}

impl LiveRun {
    fn spawn(home: &TestHome) -> LiveRun {
        let mut child = home
            .start_command()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn advance start");
        let transcript = Arc::new(Mutex::new(Transcript::default()));
        let readers = vec![
            spawn_reader(
                Stream::Stdout,
                child.stdout.take().expect("stdout"),
                Arc::clone(&transcript),
            ),
            spawn_reader(
                Stream::Stderr,
                child.stderr.take().expect("stderr"),
                Arc::clone(&transcript),
            ),
        ];
        LiveRun {
            child,
            transcript,
            readers,
        }
    }

    fn snapshot(&self) -> (bool, Option<Instant>, String, String) {
        let t = self.transcript.lock().unwrap_or_else(|e| e.into_inner());
        (
            boot_complete(&t),
            t.last_activity,
            t.text(Stream::Stdout),
            t.text(Stream::Stderr),
        )
    }

    /// Wait for the last boot line, then for both streams to stay quiet for [`QUIET_PERIOD`].
    fn wait_until_settled(&mut self) {
        let start = Instant::now();
        loop {
            let (complete, _, out, err) = self.snapshot();
            if complete {
                break;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("advance start exited before boot completed ({status:?})\nstdout:\n{out}\nstderr:\n{err}");
            }
            if start.elapsed() > BOOT_TIMEOUT {
                let _ = self.child.kill();
                panic!("advance start did not complete boot within {BOOT_TIMEOUT:?}\nstdout:\n{out}\nstderr:\n{err}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let settle_start = Instant::now();
        loop {
            let (_, last, out, err) = self.snapshot();
            if last.is_some_and(|l| l.elapsed() >= QUIET_PERIOD) {
                return;
            }
            if settle_start.elapsed() > SETTLE_TIMEOUT {
                let _ = self.child.kill();
                panic!("advance start output did not settle within {SETTLE_TIMEOUT:?}\nstdout:\n{out}\nstderr:\n{err}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// SIGTERM, wait up to `SIGTERM_EXIT_BUDGET_SECS`, SIGKILL if still running, then read both
    /// streams to EOF.
    fn sigterm_and_collect(mut self) -> (ExitOutcome, String, String) {
        let pid = i32::try_from(self.child.id()).expect("pid fits i32");
        // SAFETY: kill(2) with SIGTERM on the child we spawned and have not reaped yet.
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill(SIGTERM): {}", std::io::Error::last_os_error());
        let deadline = Instant::now() + Duration::from_secs(SIGTERM_EXIT_BUDGET_SECS);
        let outcome = loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => break exit_outcome(status),
                None if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break ExitOutcome::NoExitAfterSigterm;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let (out, err) = self.join_readers();
        (outcome, out, err)
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.join_readers();
    }

    fn join_readers(&mut self) -> (String, String) {
        for reader in self.readers.drain(..) {
            reader.join().expect("reader thread");
        }
        let t = self.transcript.lock().unwrap_or_else(|e| e.into_inner());
        (t.text(Stream::Stdout), t.text(Stream::Stderr))
    }
}

fn exit_outcome(status: ExitStatus) -> ExitOutcome {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitOutcome::Code(code),
        (None, Some(signal)) => ExitOutcome::Signal(signal),
        (None, None) => panic!("exit status without code or signal: {status:?}"),
    }
}

/// Wait for a child that is expected to end on its own; read both pipes to EOF.
fn run_to_exit(mut child: Child) -> (ExitOutcome, String, String) {
    let transcript = Arc::new(Mutex::new(Transcript::default()));
    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        readers.push(spawn_reader(
            Stream::Stdout,
            stdout,
            Arc::clone(&transcript),
        ));
    }
    if let Some(stderr) = child.stderr.take() {
        readers.push(spawn_reader(
            Stream::Stderr,
            stderr,
            Arc::clone(&transcript),
        ));
    }
    let deadline = Instant::now() + FAILURE_EXIT_BUDGET;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let t = transcript.lock().unwrap_or_else(|e| e.into_inner());
                panic!(
                    "advance start did not exit within {FAILURE_EXIT_BUDGET:?}\nstdout:\n{}\nstderr:\n{}",
                    t.text(Stream::Stdout),
                    t.text(Stream::Stderr)
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    for reader in readers {
        reader.join().expect("reader thread");
    }
    let t = transcript.lock().unwrap_or_else(|e| e.into_inner());
    (
        exit_outcome(status),
        t.text(Stream::Stdout),
        t.text(Stream::Stderr),
    )
}

fn presence(path: &Path) -> &'static str {
    if std::fs::symlink_metadata(path).is_ok() {
        "present"
    } else {
        "absent"
    }
}

fn runtime_files_after_exit(ws: &Path) -> String {
    let dir = ws.join(".runtime");
    format!(
        "runtime.lock={} client-api={} selected-provider={}",
        presence(&dir.join("runtime.lock")),
        presence(&dir.join("client-api")),
        presence(&dir.join("selected-provider"))
    )
}

fn stream_golden(title: &str, stream: &str, masked: &str) -> String {
    format!(
        "# MODULE-001-T111 (1) `advance start` {stream} on {title} — normalised, spawn to EOF after SIGTERM\n{masked}"
    )
}

// ── Runtime files ─────────────────────────────────────────────────────────────────────────

fn file_mode(path: &Path) -> String {
    let meta = std::fs::symlink_metadata(path)
        .unwrap_or_else(|e| panic!("{} missing while running: {e}", path.display()));
    assert!(
        meta.file_type().is_file(),
        "{} is a regular file",
        path.display()
    );
    format!("{:04o}", meta.permissions().mode() & 0o7777)
}

/// The value of `key: <value>` on exactly one line of `body`.
fn field<'a>(body: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}: ");
    let hits: Vec<&str> = body
        .split('\n')
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .collect();
    assert_eq!(hits.len(), 1, "exactly one `{key}:` line in {body:?}");
    hits[0]
}

/// Replace the value of `key` (the whole remainder of its line) with `replacement`.
fn replace_field(body: &str, key: &str, replacement: &str) -> String {
    let prefix = format!("{key}: ");
    body.split('\n')
        .map(|l| {
            if l.starts_with(prefix.as_str()) {
                format!("{prefix}{replacement}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `ps -o lstart= -p <pid>` exactly as `runtime.lock`'s writer runs it (same environment shape).
fn ps_lstart(pid: u32) -> String {
    let mut cmd = Command::new("ps");
    cmd.args(["-o", "lstart=", "-p", &pid.to_string()])
        .env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    let out = cmd.output().expect("run ps");
    assert!(out.status.success(), "ps -o lstart= failed: {out:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn assert_rfc3339_utc(value: &str, what: &str) {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{what} is quoted: {value}"));
    let parsed = chrono::DateTime::parse_from_rfc3339(inner)
        .unwrap_or_else(|e| panic!("{what} is RFC 3339 ({inner}): {e}"));
    assert_eq!(
        parsed.offset().local_minus_utc(),
        0,
        "{what} is UTC: {inner}"
    );
    assert!(
        inner.ends_with("+00:00"),
        "{what} renders the +00:00 offset: {inner}"
    );
}

/// `.runtime/runtime.lock` while running: mask pid / platform_uid / timestamps after checking
/// them; the workspace path is masked by the path masks.
fn normalised_runtime_lock(body: &str, pid: u32, masks: &Masks) -> String {
    assert_eq!(field(body, "pid"), pid.to_string(), "runtime.lock pid");
    let uid = field(body, "platform_uid");
    let expected_uid = format!("\"{}:{}:{}\"", std::env::consts::OS, pid, ps_lstart(pid));
    assert_eq!(
        uid, expected_uid,
        "platform_uid = \"<os>:<pid>:<ps lstart>\""
    );
    let started = field(body, "started_at");
    let heartbeat = field(body, "heartbeat_at");
    assert_rfc3339_utc(started, "started_at");
    assert_rfc3339_utc(heartbeat, "heartbeat_at");
    let mut out = replace_field(body, "pid", "<PID>");
    out = replace_field(&out, "platform_uid", "\"<OS>:<PID>:<PS_LSTART>\"");
    out = replace_field(&out, "started_at", "\"<RFC3339_UTC>\"");
    out = replace_field(&out, "heartbeat_at", "\"<RFC3339_UTC>\"");
    // `replace_field` re-joins with '\n' exactly as split, so a (missing) trailing newline is
    // preserved byte for byte.
    masks.apply(&out)
}

fn normalised_pid_file(body: &str, pid: u32, masks: &Masks) -> String {
    assert_eq!(field(body, "pid"), pid.to_string(), "pid line");
    masks.apply(&replace_field(body, "pid", "<PID>"))
}

/// The bound Client API address from stderr's `advance: Client API and Web Console listening at
/// http://<addr>` line.
fn client_api_addr_from_stderr(stderr: &str) -> String {
    const PREFIX: &str = "advance: Client API and Web Console listening at http://";
    stderr
        .lines()
        .find_map(|l| l.strip_prefix(PREFIX))
        .unwrap_or_else(|| panic!("no Client API line on stderr:\n{stderr}"))
        .to_string()
}

fn render_runtime_files(title: &str, home: &TestHome, pid: u32, stderr_so_far: &str) -> String {
    let masks = home.masks();
    let dir = home.ws.join(".runtime");
    let lock = dir.join("runtime.lock");
    let discovery = dir.join("client-api");
    let selected = dir.join("selected-provider");
    let lock_body = std::fs::read_to_string(&lock).expect("read runtime.lock");
    let discovery_body = std::fs::read_to_string(&discovery).expect("read client-api");
    let selected_body = std::fs::read_to_string(&selected).expect("read selected-provider");
    assert_eq!(
        field(&discovery_body, "client_api_base"),
        format!("\"http://{}\"", client_api_addr_from_stderr(stderr_so_far)),
        "the discovery file names the bound Client API"
    );
    format!(
        "# MODULE-001-T111 (1) runtime files of `advance start` on {} while running\n\
         # bytes = the exact file content as a Rust string literal (no trailing newline unless shown)\n\
         .runtime/runtime.lock mode={} bytes={:?}\n\
         .runtime/client-api mode={} bytes={:?}\n\
         .runtime/selected-provider mode={} bytes={:?}\n",
        title,
        file_mode(&lock),
        normalised_runtime_lock(&lock_body, pid, &masks),
        file_mode(&discovery),
        normalised_pid_file(&discovery_body, pid, &masks),
        file_mode(&selected),
        normalised_pid_file(&selected_body, pid, &masks),
    )
}

/// One `advance start` run to EOF after SIGTERM: (outcome, stdout golden, stderr golden, runtime
/// files golden while running + after exit for H1).
struct StartRun {
    outcome: ExitOutcome,
    stdout: String,
    stderr: String,
    runtime_files: Option<String>,
}

fn start_run(spec: &HomeSpec, record_files: bool) -> StartRun {
    let home = make_home(spec);
    let mut run = LiveRun::spawn(&home);
    run.wait_until_settled();
    let runtime_files = record_files.then(|| {
        let (_, _, _, err) = run.snapshot();
        render_runtime_files(&describe(spec), &home, run.pid(), &err)
    });
    let (outcome, out, err) = run.sigterm_and_collect();
    let masks = home.masks();
    let runtime_files = runtime_files.map(|files| {
        format!(
            "{files}after exit: {}\n",
            runtime_files_after_exit(&home.ws)
        )
    });
    StartRun {
        outcome,
        stdout: stream_golden(&describe(spec), "stdout", &masks.apply(&out)),
        stderr: stream_golden(&describe(spec), "stderr", &masks.apply(&err)),
        runtime_files,
    }
}

/// Startup failure: the workspace exists but has no `.advance/runtime-config.yaml`.
fn missing_runtime_config_run() -> (ExitOutcome, String) {
    let home = TestHome::new_root();
    std::fs::create_dir_all(home.ws.join(".advance")).expect("create .advance");
    let child = home
        .start_command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn advance start");
    let (outcome, out, err) = run_to_exit(child);
    let masks = home.masks();
    let golden = format!(
        "# MODULE-001-T111 (1) `advance start` on a workspace without .advance/runtime-config.yaml\n\
         {}\n--- stdout ---\n{}--- stderr ---\n{}--- .runtime after exit ---\n{}\n",
        outcome.render(),
        masks.apply(&out),
        masks.apply(&err),
        runtime_files_after_exit(&home.ws)
    );
    (outcome, golden)
}

/// Readiness write failure: stdout's read end is closed right after spawn, so the first stdout
/// write (the readiness line; nothing reaches stdout before it) fails with EPIPE.
fn readiness_write_failure_run() -> (ExitOutcome, String) {
    let home = make_home(&H1);
    let mut child = home
        .start_command()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn advance start");
    drop(child.stdout.take().expect("stdout pipe"));
    let (outcome, _out, err) = run_to_exit(child);
    let masks = home.masks();
    let golden = format!(
        "# MODULE-001-T111 (1) `advance start` on {} with stdout's read end closed right after spawn (EPIPE on the readiness line)\n\
         {}\n--- stderr ---\n{}--- .runtime after exit ---\n{}\n",
        describe(&H1),
        outcome.render(),
        masks.apply(&err),
        runtime_files_after_exit(&home.ws)
    );
    (outcome, golden)
}

/// Render an exit row; a row bound to a pending constant renders the constant's name when the
/// observed outcome equals it (so the decision lives in that constant only).
fn exit_row(observed: ExitOutcome, pending: Option<(ExitOutcome, &str)>) -> String {
    match pending {
        Some((expected, name)) if observed == expected => format!("= {name}"),
        _ => observed.render(),
    }
}

#[test]
fn module_001_t111_ac30_start_stdout_stderr_files_and_exit_codes() {
    let h1 = std::thread::spawn(|| start_run(&H1, true));
    let h2 = std::thread::spawn(|| start_run(&H2, false));
    let missing = std::thread::spawn(missing_runtime_config_run);
    let readiness = std::thread::spawn(readiness_write_failure_run);
    let h1 = h1.join().expect("H1 run");
    let h2 = h2.join().expect("H2 run");
    let (missing_outcome, missing_golden) = missing.join().expect("missing-config run");
    let (readiness_outcome, readiness_golden) = readiness.join().expect("readiness run");

    // Exit codes first: a mismatch here explains a stream mismatch below.
    let exit_codes = format!(
        "# MODULE-001-T111 (1) exit status of `advance start` (`= NAME` rows are pinned by that constant in this file)\n\
         missing_runtime_config: {}\n\
         readiness_write_failure: {}\n\
         sigterm_after_readiness {}: {}\n\
         sigterm_after_readiness {}: {}\n",
        exit_row(missing_outcome, None),
        exit_row(
            readiness_outcome,
            Some((READINESS_WRITE_FAILURE.outcome, "READINESS_WRITE_FAILURE"))
        ),
        H1.label,
        exit_row(h1.outcome, None),
        H2.label,
        exit_row(
            h2.outcome,
            Some((H2_SIGTERM_AFTER_READINESS, "H2_SIGTERM_AFTER_READINESS"))
        ),
    );
    check_golden("exit_codes.golden", &exit_codes);
    check_golden("exit.missing_runtime_config.golden", &missing_golden);
    check_golden(READINESS_WRITE_FAILURE.golden, &readiness_golden);
    check_golden(&format!("start.{}.stdout.golden", H1.label), &h1.stdout);
    check_golden(&format!("start.{}.stderr.golden", H1.label), &h1.stderr);
    check_golden(&format!("start.{}.stdout.golden", H2.label), &h2.stdout);
    check_golden(&format!("start.{}.stderr.golden", H2.label), &h2.stderr);
    check_golden(
        &format!("runtime_files.{}.golden", H1.label),
        h1.runtime_files
            .as_deref()
            .expect("H1 records runtime files"),
    );
}

// ── Route probes over HTTP ────────────────────────────────────────────────────────────────

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn decode_chunked(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let size_text = std::str::from_utf8(&raw[..line_end]).expect("chunk size utf-8");
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .expect("chunk size hex");
        raw = &raw[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn http(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).expect("connect Client API");
    stream
        .set_read_timeout(Some(PROBE_IO_TIMEOUT))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(PROBE_IO_TIMEOUT))
        .expect("write timeout");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        let _ = write!(req, "{name}: {value}\r\n");
    }
    match body {
        Some(body) => {
            let _ = write!(
                req,
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
        None => req.push_str("\r\n"),
    }
    stream.write_all(req.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .unwrap_or_else(|e| panic!("{method} {path}: response read failed (probe hung?): {e}"));
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("{method} {path}: no header/body split"));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{method} {path}: bad status line in {head:?}"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut response = HttpResponse {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    };
    if response
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        response.body = decode_chunked(&response.body);
    }
    response
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// `<status> data {key: type, …}` (sorted keys) or `<status> error <code> "<message>"`, plus the
/// warning codes when there are any.
fn render_envelope(response: &HttpResponse) -> String {
    let envelope: Value = serde_json::from_slice(&response.body).unwrap_or_else(|e| {
        panic!(
            "non-JSON body ({e}): {}",
            String::from_utf8_lossy(&response.body)
        )
    });
    let mut out = format!("{} ", response.status);
    match (envelope.get("error"), envelope.get("data")) {
        (Some(error), _) if !error.is_null() => {
            let code = error["code"].as_str().expect("error code");
            let message = error["message"].as_str().expect("error message");
            let _ = write!(out, "error {code} {message:?}");
            if let Some(details) = error.get("details").and_then(Value::as_array) {
                if !details.is_empty() {
                    let _ = write!(out, " details={}", Value::Array(details.clone()));
                }
            }
        }
        (_, Some(data)) => {
            out.push_str("data ");
            match data {
                Value::Object(map) => {
                    let mut keys: Vec<(&String, &Value)> = map.iter().collect();
                    keys.sort_by(|a, b| a.0.cmp(b.0));
                    let fields: Vec<String> = keys
                        .iter()
                        .map(|(k, v)| format!("{k}: {}", json_type(v)))
                        .collect();
                    let _ = write!(out, "{{{}}}", fields.join(", "));
                }
                other => out.push_str(json_type(other)),
            }
        }
        _ => panic!("envelope with neither data nor error: {envelope}"),
    }
    let warnings: Vec<&str> = envelope
        .get("warnings")
        .and_then(Value::as_array)
        .map(|w| w.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    if !warnings.is_empty() {
        let _ = write!(out, " warnings=[{}]", warnings.join(","));
    }
    out
}

/// The concrete request path of a route: every `{name}` parameter becomes [`PROBE_PARAM`].
fn concrete_path(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = open
            + rest[open..]
                .find('}')
                .unwrap_or_else(|| panic!("unclosed parameter in {template}"));
        out.push_str(PROBE_PARAM);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The way a native client calls the desktop daemon: loopback, no browser `Origin`, the API
/// version header, a bearer session token.
struct NativeClient {
    addr: String,
    token: Option<String>,
    next_key: u32,
}

impl NativeClient {
    fn call(&mut self, method: &str, path: &str, mutation: bool) -> HttpResponse {
        let mut headers: Vec<(&str, String)> =
            vec![("x-advance-api-version", API_VERSION.to_string())];
        if let Some(token) = &self.token {
            headers.push(("authorization", format!("Bearer {token}")));
        }
        if mutation {
            self.next_key += 1;
            headers.push((
                "idempotency-key",
                format!("d5-golden-probe-{}", self.next_key),
            ));
        }
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = (method == "POST").then_some("{}");
        http(&self.addr, method, path, &borrowed, body)
    }

    /// `POST /client/session/login` with `{"platform":"mac"}`: credential-less on loopback.
    fn login(&mut self) -> HttpResponse {
        let response = http(
            &self.addr,
            "POST",
            "/client/session/login",
            &[("x-advance-api-version", API_VERSION)],
            Some(r#"{"platform":"mac"}"#),
        );
        self.adopt_token(&response);
        response
    }

    fn adopt_token(&mut self, response: &HttpResponse) {
        let envelope: Value = serde_json::from_slice(&response.body).expect("session envelope");
        self.token = Some(
            envelope["data"]["token"]
                .as_str()
                .unwrap_or_else(|| panic!("session token in {envelope}"))
                .to_string(),
        );
    }
}

/// The discovery file's `client_api_base` (`http://127.0.0.1:<port>`) → `127.0.0.1:<port>`.
fn discovered_client_api_addr(ws: &Path) -> String {
    let body = std::fs::read_to_string(ws.join(".runtime/client-api")).expect("read client-api");
    field(&body, "client_api_base")
        .trim_matches('"')
        .strip_prefix("http://")
        .expect("http base")
        .to_string()
}

fn probe_home(spec: &HomeSpec) -> String {
    let home = make_home(spec);
    let mut run = LiveRun::spawn(&home);
    run.wait_until_settled();
    let mut client = NativeClient {
        addr: discovered_client_api_addr(&home.ws),
        token: None,
        next_key: 0,
    };
    let mut out = format!(
        "# MODULE-001-T111 (2) route probes through `advance start` on {}\n\
         # native client: loopback, no Origin, x-advance-api-version: {API_VERSION}, bearer session;\n\
         # GET with no query; POST with body {{}} (+ idempotency-key for mutations); path params = {PROBE_PARAM:?}\n\
         # <METHOD> <route> -> <status> data {{sorted top-level keys of data: JSON type}} | error <code> \"<message>\"\n",
        describe(spec)
    );
    let login = client.login();
    let _ = writeln!(
        out,
        "== session\nPOST /client/session/login -> {}",
        render_envelope(&login)
    );

    // Reads first, then POST reads, then mutations: nothing probed can change what a later probe
    // sees (every mutation carries an empty body and/or a dummy id and is refused).
    let table = probe_route_table();
    let phases: [(&str, fn(&RouteTableEntry) -> bool); 3] = [
        ("== GET routes", |e| e.method == Method::Get),
        ("== POST reads", |e| {
            e.method == Method::Post && !e.is_mutation
        }),
        ("== POST mutations", |e| {
            e.method == Method::Post && e.is_mutation
        }),
    ];
    let mut probed = 0usize;
    for (header, in_phase) in &phases {
        let _ = writeln!(out, "{header}");
        for entry in table.iter().filter(|e| in_phase(e)) {
            let method = method_name(entry.method);
            let response = client.call(method, &concrete_path(&entry.path), entry.is_mutation);
            let _ = writeln!(
                out,
                "{method} {} -> {}",
                entry.path,
                render_envelope(&response)
            );
            probed += 1;
        }
    }
    assert_eq!(
        probed,
        table.len(),
        "every route of the route table is probed"
    );

    let _ = writeln!(out, "== transport-only routes (not in the route table)");
    for asset in ["/", "/index.html", "/app.js", "/styles.css"] {
        let response = http(&client.addr, "GET", asset, &[], None);
        let _ = writeln!(
            out,
            "GET {asset} -> {} content-type={}",
            response.status,
            response.header("content-type").unwrap_or("<none>")
        );
    }
    for stream in ["/client/events/stream", "/client/llm/deltas/stream"] {
        let _ = writeln!(
            out,
            "GET {stream} (WebSocket upgrade) -> not probed: needs a WebSocket handshake; the plain GET of this path is probed above"
        );
    }

    // Session-changing operations last: refresh rotates the token, logout revokes the session.
    let refresh = client.call("POST", "/client/session/refresh", false);
    let _ = writeln!(
        out,
        "== session (last)\nPOST /client/session/refresh -> {}",
        render_envelope(&refresh)
    );
    if refresh.status == 200 {
        client.adopt_token(&refresh);
    }
    let logout = client.call("POST", "/client/session/logout", false);
    let _ = writeln!(
        out,
        "POST /client/session/logout -> {}",
        render_envelope(&logout)
    );
    run.kill();
    out
}

fn route_probe_golden(spec: &HomeSpec) {
    let actual = probe_home(spec);
    check_probe_golden(
        D5_CHANGE_MATRIX,
        spec.label,
        &format!("route_probe.{}.golden", spec.label),
        &actual,
    );
}

#[test]
fn module_001_t111_ac30_route_probe_h1_fs_llm() {
    route_probe_golden(&H1);
}

#[test]
fn module_001_t111_ac30_route_probe_h2_all_capabilities() {
    route_probe_golden(&H2);
}

#[test]
fn module_001_t111_ac30_route_probe_h3_fs_llm_lifecycle() {
    route_probe_golden(&H3);
}

#[test]
fn module_001_t111_ac30_route_probe_h4_fs_llm_grant() {
    route_probe_golden(&H4);
}

#[test]
fn module_001_t111_ac30_route_probe_h5_fs_llm_no_driver() {
    route_probe_golden(&H5);
}

// ── Self-checks of the harness ────────────────────────────────────────────────────────────

#[test]
fn module_001_t111_ac30_masks_only_volatile_tokens() {
    let masks = Masks {
        paths: vec![
            ("/private/var/x/.tmpAB".to_string(), "<ROOT>".to_string()),
            ("/var/x/.tmpAB".to_string(), "<ROOT>".to_string()),
        ],
    };
    assert_eq!(
        masks.apply("ready (workspace=\"/private/var/x/.tmpAB/ws\") /var/x/.tmpAB/home\n"),
        "ready (workspace=\"<ROOT>/ws\") <ROOT>/home\n"
    );
    assert_eq!(
        masks.apply("http://127.0.0.1:60986/msg 127.0.0.1: 10.0.0.1:80\n"),
        "http://127.0.0.1:<PORT>/msg 127.0.0.1: 10.0.0.1:80\n"
    );
    assert_eq!(
        masks.apply(
            "\nthread 'main' (46930464) panicked at library/std/src/io/stdio.rs:1165:9:\nfailed printing to stdout: Broken pipe (os error 32)\n"
        ),
        "\nthread 'main' (<TID>) panicked at <PANIC_LOCATION>:\nfailed printing to stdout: Broken pipe (os error 32)\n"
    );
    assert_eq!(
        masks.apply("thread 'main' panicked at src/x.rs:1:2:\n"),
        "thread 'main' (<TID>) panicked at <PANIC_LOCATION>:\n"
    );
    // Not a panic header: kept byte for byte.
    assert_eq!(
        masks.apply("thread 'main' said hello\n"),
        "thread 'main' said hello\n"
    );
    assert_eq!(
        replace_field("pid: 1\nversion: \"0.1.0\"", "pid", "<PID>"),
        "pid: <PID>\nversion: \"0.1.0\""
    );
}

#[test]
fn module_001_t111_ac30_d5_overlay_changes_only_named_lines() {
    let golden = "# header\nGET /client/tools -> 503 error module_unavailable \"provider not wired\"\nGET /client/runs -> 200 data {runs: array}\n";
    assert_eq!(apply_overlay(&[], "h1_fs_llm", golden), golden);
    let change = D5Change {
        homes: &["h1_fs_llm"],
        method: "GET",
        path: "/client/tools",
        before: "503 error module_unavailable \"provider not wired\"",
        after: "200 data {mcp: array, skills: array, wasm: array}",
    };
    assert_eq!(
        apply_overlay(std::slice::from_ref(&change), "h1_fs_llm", golden),
        "# header\nGET /client/tools -> 200 data {mcp: array, skills: array, wasm: array}\nGET /client/runs -> 200 data {runs: array}\n"
    );
    // Another home: untouched.
    assert_eq!(
        apply_overlay(std::slice::from_ref(&change), "h2_all_capabilities", golden),
        golden
    );
    // A `before` that is not what the golden recorded refuses to apply.
    let stale = D5Change {
        before: "503 error module_unavailable \"something else\"",
        ..change
    };
    let refused = std::panic::catch_unwind(|| {
        apply_overlay(std::slice::from_ref(&stale), "h1_fs_llm", golden)
    });
    assert!(refused.is_err(), "a stale `before` must not apply");
}
