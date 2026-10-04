//! Shared harness of the MODULE-001-T111 / ADR 2026-10-03 D5 goldens, used by two test binaries:
//! `runtime_compose_d5_goldens.rs` (the real `advance start` binary) and
//! `runtime_compose_d5_route_table.rs` (the in-process route table, in its own binary because it
//! sets a process environment variable).
//!
//! It owns everything both binaries must agree on: the homes, the golden files and their sha256
//! pins, the pending-decision constants, the text masks of streams and files, and the lock that
//! serialises every child-process spawn.
#![cfg(unix)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};

use advance_cli::agent_config::KNOWN_CAPABILITIES;
use advance_client_api::{ClientApi, ClientApiConfig, Method, RouteTableEntry};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use wit_component::ComponentEncoder;

// ── Fixtures ──────────────────────────────────────────────────────────────────────────────

/// The deployed driver: the committed wit-bindgen guest core module, encoded to a component the
/// way `start_msg_turn.rs` does (the daemon's `load_component` parses components only).
const MINIMAL_CORE: &[u8] =
    include_bytes!("../../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");

pub const GOLDEN_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/goldens/runtime_compose_d5"
);
pub const UPDATE_ENV: &str = "ADVANCE_UPDATE_D5_GOLDENS";

pub const MASTER_KEY_ENV: &str = "ADVANCE_D5_GOLDEN_MASTER_KEY";
pub const MASTER_KEY_HEX: &str = "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5";

/// Where the goldens were captured. Every golden header carries it. (The version the bump went
/// to is named by its commit, not spelled out: no golden may contain the package version.)
pub const CAPTURED_ON: &str = "captured on the pre-lane OSS tree (main 678b7a77 = v0.1.26 + the sign-in retry fix + the workspace version bump after it, plus the read-only ClientApi::route_table accessor), before the runtime-compose move";

/// The package version of this tree. No golden may contain it (the lane bumps the version): a
/// version value must be masked, and every golden is checked for it before it is compared or
/// written.
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Pending decisions (one constant each) ─────────────────────────────────────────────────

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitOutcome {
    Code(i32),
    Signal(i32),
    /// Still running `SIGTERM_EXIT_BUDGET_SECS` after SIGTERM (the run was then SIGKILLed).
    NoExitAfterSigterm,
}

/// How long a run gets to exit after SIGTERM before it is recorded as not exiting and SIGKILLed.
pub const SIGTERM_EXIT_BUDGET_SECS: u64 = 15;

impl ExitOutcome {
    pub fn render(self) -> String {
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
/// change it in one place: the outcome, and the goldens that pin that scenario (each with its
/// sha256). Changing the decision is the only sanctioned way to re-capture those goldens: change
/// `outcome`, re-capture, and re-pin them here. Every other golden is pinned in
/// [`BASELINE_GOLDEN_SHA256`] and never changes.
pub struct PendingExpectation {
    pub outcome: ExitOutcome,
    pub goldens: &'static [(&'static str, &'static str)],
}

/// Exit status of `advance start` when the readiness line cannot be written (stdout's read end
/// closed right after spawn, so the first stdout write gets EPIPE). OWNER DECISION PENDING.
///
/// ADR D1 "Output", MODULE-001-AC-30 and T111 say this "still ends `advance start` with exit 1,
/// as today (`start.rs:367-374`)". The pre-move tree does not: the readiness line is written by
/// `println!`, which panics on the EPIPE before the exit-1 flush branch can run, so the process
/// exits 101 and stderr carries std's `failed printing to stdout: Broken pipe (os error 32)`
/// panic message. This constant records what the pre-move tree actually does.
pub const READINESS_WRITE_FAILURE: PendingExpectation = PendingExpectation {
    outcome: ExitOutcome::Code(101),
    goldens: &[(
        "exit.readiness_write_failure.golden",
        "b3b5e0738d80f27f0ebd5f3acbd845eba6ad39ee212dd80af543c4fbd4e7af0e",
    )],
};

/// Exit status after SIGTERM on H2 (every capability declared, a git repository). OWNER /
/// LANE DECISION PENDING.
///
/// T111 expects exit 0 after SIGTERM. On the pre-move tree H2 prints `advance: shutting down`,
/// removes `runtime.lock` and then never exits: dropping the current-thread runtime waits on its
/// blocking pool, where the git commit queue worker (`advance_git` `worker_loop`, a
/// `spawn_blocking` task) still waits in `blocking_recv` because a sender of its queue is still
/// held. It reproduces with `fs` + `llm` + `messaging` on a git repository; without `messaging`
/// or without a git repository the run exits 0. The ADR D1 shutdown sequence (git queue closed
/// and its worker joined) is expected to turn this into `ExitOutcome::Code(0)`; H2's streams and
/// its runtime files after exit are pinned with this decision.
pub const H2_SIGTERM_AFTER_READINESS: PendingExpectation = PendingExpectation {
    outcome: ExitOutcome::NoExitAfterSigterm,
    goldens: &[
        (
            "start.h2_all_capabilities.stdout.golden",
            "7cc5dc4b13a18851c9a9c99e9ff3047eb74291e3450f0e3787b42dd9c5034958",
        ),
        (
            "start.h2_all_capabilities.stderr.golden",
            "b58d40bc68a24c86e793cc7cb34d7b6ba224bbccd4659e7f2c355e7c45384601",
        ),
        (
            "runtime_files.h2_all_capabilities.golden",
            "bdec39e526a121a289b26ef9b655f083ffe9d48ae960aff81858091ad4a2d5d8",
        ),
    ],
};

/// The decisions above, for the pin lookup.
pub const PENDING_EXPECTATIONS: &[(&str, &PendingExpectation)] = &[
    ("READINESS_WRITE_FAILURE", &READINESS_WRITE_FAILURE),
    ("H2_SIGTERM_AFTER_READINESS", &H2_SIGTERM_AFTER_READINESS),
];

/// sha256 of every baseline golden as captured. A golden whose bytes differ from its pin fails
/// before it is compared (and before the D5 overlay is applied): the baselines are immutable, and
/// re-capturing one (update mode) cannot turn the test green without editing this table, which a
/// review sees. Intended wire changes go through the D5 change matrix in
/// `runtime_compose_d5_goldens.rs`; pending decisions through their constant above.
pub const BASELINE_GOLDEN_SHA256: &[(&str, &str)] = &[
    (
        "exit.malformed_runtime_config.golden",
        "61b8a1349ee4af073c29fb8ba85ddc520098e2779d29737d6ac977c378222834",
    ),
    (
        "exit.missing_runtime_config.golden",
        "75561a44f8a477838b201b41d158d76f1ba9135d48d2ce546fca9cb525fbdb9d",
    ),
    (
        "exit.runtime_lock_held.golden",
        "91b27e4385ec0694faa06a84d9c7f83a2bf40791180be3a202119283268a5b4b",
    ),
    (
        "exit_codes.golden",
        "4bc43af463468de8da775648d496996b82f986de3271006f16dfadb215249ed9",
    ),
    (
        "route_probe.h1_fs_llm.golden",
        "ed82460dfe188cc7a120b83f9c8d92a6943afdc8ea0f6097b5516bd6a9f7da26",
    ),
    (
        "route_probe.h2_all_capabilities.golden",
        "37d51e6e98499faacd5659903777d56e9d44620b9a2011c509cd3bb2f89f6be4",
    ),
    (
        "route_probe.h3_fs_llm_lifecycle.golden",
        "c7c518c09e72a67b5a5763fa076cbc435b78b5d4732782601fa76e1c7629ef69",
    ),
    (
        "route_probe.h4_fs_llm_grant.golden",
        "da8516c5f5f0b7f641b451c6f75b990dd1a83bca0c0427c40b609894d7599251",
    ),
    (
        "route_probe.h5_fs_llm_tools_no_driver.golden",
        "410672f64fa41d1549f652c518d348462457e6c23bb9918aae0575e5c4afa338",
    ),
    (
        "route_table.h1_fs_llm.golden",
        "cb17018a476db2a18097d8ad10ab8ce9e44d5206d6daf4b06c6dd79e0d1fd374",
    ),
    (
        "route_table.h2_all_capabilities.golden",
        "e64c49b0e5dd4bcd9427cde10057f14c1f6ce3e1e52831db3c919ace9169892d",
    ),
    (
        "runtime_files.h1_fs_llm.golden",
        "85fdb5db5e9569be29b39bd32db2feb2350a6c85de4d564d932c7abea31dbec6",
    ),
    (
        "start.h1_fs_llm.merged.golden",
        "62bff0c17a4c4a8c1ed48c51bd2ae6cc576ce3a15b25ddf127f2b98df8b07641",
    ),
    (
        "start.h1_fs_llm.stderr.golden",
        "84b477c1f8976d8b03b4815fdf803c6c1ffef5f3e94951c655526b569ebebe05",
    ),
    (
        "start.h1_fs_llm.stdout.golden",
        "9e1d0ba7c2961614ee206dacb5cdabc2d6494ffc4a6d94558b540a13859d8ec7",
    ),
    (
        "start.h3_fs_llm_lifecycle.stderr.golden",
        "9c0de9d7bef006a75c2e323a6b6d83a8d888cac5af9ed62f9ff563fb30a376e1",
    ),
    (
        "start.h3_fs_llm_lifecycle.stdout.golden",
        "798f8fbab02b9d35d3dcee0671e3aede8443879badd33725185fd9ce03141667",
    ),
    (
        "start.h4_fs_llm_grant.stderr.golden",
        "41dcf8a32d0f8798c6bf1ae70ef7f40ed7e006d46a99d77c81e41d4c5facfc86",
    ),
    (
        "start.h4_fs_llm_grant.stdout.golden",
        "a34c1dcde5bdd4c81057084be022374712af998a198444f962ae714fee3e198b",
    ),
    (
        "start.h5_fs_llm_tools_no_driver.stderr.golden",
        "f83e1d90655824af59157e47cae4e15c7927de09ea71bb929baf41956484e501",
    ),
    (
        "start.h5_fs_llm_tools_no_driver.stdout.golden",
        "fef5ca1acb6998bdb90b1181a76ee4c35305e64fc535b9517860dc9612d75e6a",
    ),
    (
        "start.h6_fs_llm_memory_no_git.stderr.golden",
        "f38239b52cbe16d921f8efec1f7b981379d9e86c0fdc8135e8561a83f8d06243",
    ),
    (
        "start.h6_fs_llm_memory_no_git.stdout.golden",
        "1b23dc207d7338622619f72f90e4c899c3540a753e5579d18598cb906b7e8ff2",
    ),
];

// ── Homes ─────────────────────────────────────────────────────────────────────────────────

/// One home of the goldens.
pub struct HomeSpec {
    /// File-name label of the home's goldens.
    pub label: &'static str,
    /// Short name in golden headers (the full description is [`describe`]).
    pub name: &'static str,
    /// Declared capabilities; `None` = every `KNOWN_CAPABILITIES` entry.
    pub caps: Option<&'static [&'static str]>,
    /// Deploy the driver component.
    pub driver: bool,
    /// Make the home a git repository (one empty commit).
    pub git: bool,
    /// Turn the runtime GenUI flag on (`genui.enabled`), so a declared `genui` is wired.
    pub genui: bool,
}

pub const H1: HomeSpec = HomeSpec {
    label: "h1_fs_llm",
    name: "H1",
    caps: Some(&["fs", "llm"]),
    driver: true,
    git: false,
    genui: false,
};

pub const H2: HomeSpec = HomeSpec {
    label: "h2_all_capabilities",
    name: "H2",
    caps: None,
    driver: true,
    git: true,
    genui: true,
};

pub const H3: HomeSpec = HomeSpec {
    label: "h3_fs_llm_lifecycle",
    name: "H3",
    caps: Some(&["fs", "llm", "lifecycle"]),
    driver: true,
    git: false,
    genui: false,
};

pub const H4: HomeSpec = HomeSpec {
    label: "h4_fs_llm_grant",
    name: "H4",
    caps: Some(&["fs", "llm", "grant"]),
    driver: true,
    git: false,
    genui: false,
};

/// `tools` declared but no deployed driver: isolates the D5 tools row's "no deployed driver"
/// case from its "no `tools`" case (H1).
pub const H5: HomeSpec = HomeSpec {
    label: "h5_fs_llm_tools_no_driver",
    name: "H5",
    caps: Some(&["fs", "llm", "tools"]),
    driver: false,
    git: false,
    genui: false,
};

/// `memory` on a home that is not a git repository (the memory git half is not wired and
/// `advance start` says so on stderr). Start-run goldens only.
pub const H6: HomeSpec = HomeSpec {
    label: "h6_fs_llm_memory_no_git",
    name: "H6",
    caps: Some(&["fs", "llm", "memory"]),
    driver: true,
    git: false,
    genui: false,
};

/// The homes whose every route is probed (the D5 change-matrix homes).
pub const PROBE_HOMES: [&HomeSpec; 5] = [&H1, &H2, &H3, &H4, &H5];

pub fn runtime_yaml(spec: &HomeSpec) -> String {
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

pub fn declared_caps(spec: &HomeSpec) -> Vec<&'static str> {
    match spec.caps {
        Some(caps) => caps.to_vec(),
        None => KNOWN_CAPABILITIES.to_vec(),
    }
}

pub fn declares(spec: &HomeSpec, cap: &str) -> bool {
    declared_caps(spec).contains(&cap)
}

/// The golden-header description of a home, derived from the spec itself.
pub fn describe(spec: &HomeSpec) -> String {
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

// ── Child processes ───────────────────────────────────────────────────────────────────────

/// Serialises every child spawn of a test binary. On macOS std creates a child's pipes with
/// `pipe()` + `FD_CLOEXEC` (not atomic), so a concurrent spawn on another test thread can inherit
/// the write end of this child's pipe and keep it open: the reader of this child would then miss
/// EOF until that other child exits. Pipe creation, spawn and the drop of the parent's write ends
/// happen under this lock.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

pub fn spawn_lock() -> MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `cmd.spawn()` under [`SPAWN_LOCK`]. `cmd` is dropped under the lock too (it owns the parent's
/// copies of any pipe ends handed to it).
pub fn spawn_locked(mut cmd: Command) -> Child {
    let _guard = spawn_lock();
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"));
    drop(cmd);
    child
}

/// `cmd.output()` with the spawn under [`SPAWN_LOCK`] (the wait is outside it).
pub fn output_locked(mut cmd: Command) -> Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let what = format!("{cmd:?}");
    spawn_locked(cmd)
        .wait_with_output()
        .unwrap_or_else(|e| panic!("wait for {what}: {e}"))
}

/// A home under a fresh temp root: `<root>/ws` (the workspace), `<root>/home` (the child's
/// `HOME`) and `<root>/tmp` (the child's `TMPDIR`).
pub struct TestHome {
    _dir: TempDir,
    /// The temp root as created (may differ from `root` by a symlinked prefix, e.g. macOS
    /// `/var` → `/private/var`).
    raw_root: PathBuf,
    pub root: PathBuf,
    pub ws: PathBuf,
}

impl TestHome {
    pub fn new_root() -> TestHome {
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
    pub fn command(&self, args: &[&str]) -> Command {
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

    pub fn start_command(&self) -> Command {
        let ws = self.ws.to_str().expect("utf-8 workspace path").to_string();
        self.command(&["start", "--workspace", &ws])
    }

    pub fn masks(&self) -> Masks {
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
pub fn make_home(spec: &HomeSpec) -> TestHome {
    let home = TestHome::new_root();
    let ws = home.ws.to_str().expect("utf-8 workspace").to_string();
    let out = output_locked(home.command(&["init", &ws]));
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

// ── Text masks (streams, files, rendered lines) ───────────────────────────────────────────

/// The text masks: the per-run temp root (`<ROOT>`), loopback ports (`127.0.0.1:<PORT>`) and
/// the thread id + source location of a std panic header. Value masks of route-probe answers are
/// a separate, closed list (`PROBE_MASKS` in `runtime_compose_d5_goldens.rs`).
pub struct Masks {
    /// Exact path prefixes → placeholder, longest (canonical) first.
    pub paths: Vec<(String, String)>,
}

impl Masks {
    pub fn apply(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (from, to) in &self.paths {
            out = out.replace(from.as_str(), to);
        }
        let out = mask_loopback_ports(&out);
        mask_std_panic_header(&out)
    }
}

/// `127.0.0.1:<digits>` → `127.0.0.1:<PORT>`.
pub fn mask_loopback_ports(text: &str) -> String {
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

/// The value of `key: <value>` on exactly one line of `body`.
pub fn field<'a>(body: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}: ");
    let hits: Vec<&str> = body
        .split('\n')
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .collect();
    assert_eq!(hits.len(), 1, "exactly one `{key}:` line in {body:?}");
    hits[0]
}

/// Replace the value of `key` (the whole remainder of its line) with `replacement`.
pub fn replace_field(body: &str, key: &str, replacement: &str) -> String {
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

// ── Golden files ──────────────────────────────────────────────────────────────────────────

pub fn update_mode() -> bool {
    std::env::var(UPDATE_ENV).map(|v| v == "1").unwrap_or(false)
}

pub fn golden_path(name: &str) -> PathBuf {
    Path::new(GOLDEN_DIR).join(name)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Where a golden is pinned: `Some((pin, owner))` with owner `BASELINE_GOLDEN_SHA256` or the
/// pending constant's name.
pub fn golden_pin(name: &str) -> Option<(&'static str, &'static str)> {
    let baseline = BASELINE_GOLDEN_SHA256
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, pin)| (*pin, "BASELINE_GOLDEN_SHA256"));
    let pending = PENDING_EXPECTATIONS.iter().find_map(|(owner, pending)| {
        pending
            .goldens
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, pin)| (*pin, *owner))
    });
    baseline.or(pending)
}

/// Read a golden and check its bytes against its sha256 pin.
pub fn read_pinned_golden(name: &str) -> String {
    let path = golden_path(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "golden {} is missing or unreadable ({e}); the goldens are {CAPTURED_ON}",
            path.display()
        )
    });
    let (pin, owner) = golden_pin(name)
        .unwrap_or_else(|| panic!("golden {name} has no sha256 pin (BASELINE_GOLDEN_SHA256)"));
    let actual = sha256_hex(&bytes);
    assert_eq!(
        actual, pin,
        "golden {name} does not match its sha256 pin in {owner}: the captured baselines are \
         immutable (intended wire changes go through D5_CHANGE_MATRIX, pending decisions through \
         their constant)"
    );
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("golden {name} is not utf-8: {e}"))
}

/// The first difference between `expected` and `actual`, with its line, column and context.
pub fn assert_text_eq(name: &str, expected: &str, actual: &str) {
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
    let golden_line = expected_lines.get(first).copied().unwrap_or("<no line>");
    let actual_line = actual_lines.get(first).copied().unwrap_or("<no line>");
    let column = golden_line
        .chars()
        .zip(actual_line.chars())
        .position(|(g, a)| g != a)
        .unwrap_or(golden_line.chars().count().min(actual_line.chars().count()));
    let window = |line: &str| -> String {
        line.chars()
            .skip(column.saturating_sub(40))
            .take(100)
            .collect()
    };
    panic!(
        "golden {name} differs at line {}, column {}:\n  golden: …{:?}…\n  actual: …{:?}…\n\
         ----- golden line -----\n{golden_line}\n----- actual line -----\n{actual_line}\n\
         ----- golden -----\n{expected}\n----- actual -----\n{actual}",
        first + 1,
        column + 1,
        window(golden_line),
        window(actual_line),
    );
}

/// The goldens one test checks. In update mode (`ADVANCE_UPDATE_D5_GOLDENS=1`) every golden is
/// written and [`Goldens::finish`] then panics: update mode is never green, and a re-captured
/// golden still fails its sha256 pin until the pin table is edited. Otherwise each golden is read,
/// checked against its pin, passed through `overlay` and compared with the actual text.
pub struct Goldens {
    written: Vec<(String, String)>,
    finished: bool,
}

impl Goldens {
    pub fn new() -> Goldens {
        Goldens {
            written: Vec::new(),
            finished: false,
        }
    }

    pub fn check(&mut self, name: &str, actual: &str) {
        self.check_with_overlay(name, actual, |golden| golden.to_string());
    }

    pub fn check_with_overlay(
        &mut self,
        name: &str,
        actual: &str,
        overlay: impl FnOnce(&str) -> String,
    ) {
        assert!(
            !actual.contains(PACKAGE_VERSION),
            "golden {name} would contain the package version {PACKAGE_VERSION}; mask it:\n{actual}"
        );
        if update_mode() {
            std::fs::create_dir_all(GOLDEN_DIR).expect("create golden dir");
            std::fs::write(golden_path(name), actual).expect("write golden");
            self.written
                .push((name.to_string(), sha256_hex(actual.as_bytes())));
            return;
        }
        let golden = read_pinned_golden(name);
        assert_text_eq(name, &overlay(&golden), actual);
    }

    pub fn finish(mut self) {
        self.finished = true;
        if update_mode() {
            let mut list = String::new();
            for (name, sha) in &self.written {
                let state = match golden_pin(name) {
                    Some((pin, _)) if pin == sha => "pin unchanged",
                    Some((_, owner)) => {
                        if owner == "BASELINE_GOLDEN_SHA256" {
                            "CHANGED (a baseline: never re-pin after the capture)"
                        } else {
                            "CHANGED (re-pin in its pending constant)"
                        }
                    }
                    None => "NEW (no pin yet)",
                };
                let _ = writeln!(list, "    (\"{name}\", \"{sha}\"), // {state}");
            }
            panic!(
                "{UPDATE_ENV}=1 wrote {} golden(s); update mode never passes. Pins:\n{list}",
                self.written.len()
            );
        }
    }
}

impl Drop for Goldens {
    fn drop(&mut self) {
        if !self.finished && update_mode() && !std::thread::panicking() {
            panic!("{UPDATE_ENV}=1: Goldens dropped without finish()");
        }
    }
}

// ── Route table ───────────────────────────────────────────────────────────────────────────

pub fn method_name(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
    }
}

/// The table the route probes walk: a default-constructed `ClientApi` (the route set does not
/// depend on configuration or providers). `runtime_compose_d5_route_table.rs` checks it equals
/// the table of the composed server on H1 and H2.
pub fn probe_route_table() -> Vec<RouteTableEntry> {
    ClientApi::new(ClientApiConfig::default()).route_table()
}
