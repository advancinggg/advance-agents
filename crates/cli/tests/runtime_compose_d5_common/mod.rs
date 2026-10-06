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

/// Where the goldens were captured. Every golden header carries it. (The base is named by its
/// commit, not by its version: no golden may contain the package version.)
pub const CAPTURED_ON: &str = "captured on the pre-lane OSS tree (main 84a82451, plus the read-only ClientApi::route_table accessor), before the runtime-compose move";

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
/// change it in one place.
///
/// Only the decision-dependent part of the scenario belongs to the constant: one golden holding
/// the rendered outcome and what the run does from the decision point on. Everything before that
/// point (boot lines, files while running, stderr before the failing write) is a separate golden
/// pinned in [`BASELINE_GOLDEN_SHA256`], which no decision re-pins, so a re-pin made for the
/// decision cannot absorb a regression of the decision-independent part.
///
/// The pins are keyed by outcome. The active pin is the entry of `outcome`; each outcome has
/// exactly one entry (checked), and an entry is never edited once captured, except by the
/// whole-tree re-capture below. Changing the decision is therefore the only sanctioned way to
/// change what a pending golden records: set `outcome` to the new decision, re-capture, and add a
/// new `(outcome, pins)` entry. A re-capture under an unchanged outcome has no entry to go to.
///
/// Whole-tree re-capture, the one in-place re-pin: when the lane moves to a new base, every golden
/// is re-captured on the new pre-move tree with [`CAPTURED_ON`] naming the new base commit, which
/// changes the header line of every golden. A golden whose only changed line is that header
/// (update mode labels it "only the CAPTURED_ON line changed") is re-pinned in place, in the
/// active entry of its pending constant or in [`BASELINE_GOLDEN_SHA256`]. A golden with any other
/// changed line is never re-pinned in place: the rules above apply to it.
pub struct PendingExpectation {
    pub outcome: ExitOutcome,
    pub pins_by_outcome: &'static [(ExitOutcome, &'static [(&'static str, &'static str)])],
}

impl PendingExpectation {
    /// The pins of the decided `outcome` (`None` = no entry captured for it yet).
    pub fn active_pins(&self) -> Option<&'static [(&'static str, &'static str)]> {
        self.pins_by_outcome
            .iter()
            .find(|(outcome, _)| *outcome == self.outcome)
            .map(|(_, pins)| *pins)
    }

    /// Whether any entry (of any outcome) names `golden`.
    pub fn owns(&self, golden: &str) -> bool {
        self.pins_by_outcome
            .iter()
            .any(|(_, pins)| pins.iter().any(|(name, _)| *name == golden))
    }
}

/// Baseline: the stderr of the readiness-failure run up to the failing write (through the Client
/// API line, the only line written before the readiness line).
pub const READINESS_BEFORE_WRITE_GOLDEN: &str = "exit.readiness_write_failure.golden";
/// Pending ([`READINESS_WRITE_FAILURE`]): the outcome, the stderr after the Client API line and
/// the `.runtime` files after exit.
pub const READINESS_AFTER_WRITE_GOLDEN: &str = "exit.readiness_write_failure.after_write.golden";
/// Pending ([`H2_SIGTERM_AFTER_READINESS`]): the outcome, stdout after `advance: shutting down`,
/// stderr after SIGTERM and the `.runtime` files after exit. H2's streams up to there and its
/// files while running are baseline goldens.
pub const H2_AFTER_SHUTDOWN_GOLDEN: &str = "start.h2_all_capabilities.after_shutdown.golden";

/// Exit status of `advance start` when the readiness line cannot be written (stdout's read end
/// closed right after spawn, so the first stdout write gets EPIPE). Decided (owner ruling
/// 2026-10-03): exit 1, the composition's `ComposeError::Readiness`, printed as
/// `advance start: failed to flush readiness signal: …`.
///
/// On the pre-move tree the readiness line was written by `println!`, which panicked on the
/// EPIPE before the exit-1 flush branch could run, so the process exited 101 and stderr carried
/// std's `failed printing to stdout: Broken pipe (os error 32)` panic message. The first entry
/// records that pre-move outcome.
pub const READINESS_WRITE_FAILURE: PendingExpectation = PendingExpectation {
    outcome: ExitOutcome::Code(1),
    pins_by_outcome: &[
        (
            ExitOutcome::Code(101),
            &[(
                READINESS_AFTER_WRITE_GOLDEN,
                "5f983305de98cf724c689f8baf5d09418dca70a4db89dcbd6201ec170ed257f3",
            )],
        ),
        (
            ExitOutcome::Code(1),
            &[(
                READINESS_AFTER_WRITE_GOLDEN,
                "a5b17d24f9613e11c66f6d759ef3ca1e75ea4cf464e9365d77caca4891cc0d6d",
            )],
        ),
    ],
};

/// Exit status after SIGTERM on H2 (every capability declared, a git repository). Decided
/// (owner ruling 2026-10-03): exit 0 once the git commit queue is closed and its worker joined.
///
/// On the pre-move tree H2 prints `advance: shutting down`, removes `runtime.lock` and then
/// never exits: dropping the current-thread runtime waits on its blocking pool, where the git
/// commit queue worker (`advance_git` `worker_loop`, a `spawn_blocking` task) still waits in
/// `blocking_recv` because a sender of its queue is still held — by reference cycles that keep
/// the wiring graph alive (the per-child manager and the host registry, through the capability
/// injector; the `data` store and the `.meta.yaml` maintainer; the `data` store and the tool
/// registry). The runtime-compose lane cuts them, and H2 now exits 0 with the same output. The
/// first entry records the pre-move outcome (no exit within the budget).
pub const H2_SIGTERM_AFTER_READINESS: PendingExpectation = PendingExpectation {
    outcome: ExitOutcome::Code(0),
    pins_by_outcome: &[
        (
            ExitOutcome::NoExitAfterSigterm,
            &[(
                H2_AFTER_SHUTDOWN_GOLDEN,
                "fad1479dbef4727cf33072ffd37761a4217a4f0398f700763bd7980f6a215fcd",
            )],
        ),
        (
            ExitOutcome::Code(0),
            &[(
                H2_AFTER_SHUTDOWN_GOLDEN,
                "8d393ac35a27cb99d2d701f6b8ffd23a16381e0baac94ac297bc300d5b7740f6",
            )],
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
/// `runtime_compose_d5_goldens.rs`; pending decisions through their constant above. The one
/// sanctioned edit of an entry is the whole-tree re-capture on a new base ([`PendingExpectation`]),
/// and only for a golden whose sole changed line is its [`CAPTURED_ON`] header.
pub const BASELINE_GOLDEN_SHA256: &[(&str, &str)] = &[
    (
        "exit.malformed_runtime_config.golden",
        "763b1c097b949f8ed67df26679c1817d01272b62c305e61feeec7a2371b4e819",
    ),
    (
        "exit.missing_runtime_config.golden",
        "15ecc6142aec7d7b489456508b0ca1db7817f9a97af6487d5f07ea0d1be5bcd3",
    ),
    (
        READINESS_BEFORE_WRITE_GOLDEN,
        "e052028dd26c1a38191e04aef60bc984a605ed2ec403e67d9d411109eb6ce717",
    ),
    (
        "exit.runtime_lock_held.golden",
        "f73a1780cab54ca7516607288c839c98787c2396059448274c4ee93e7f563b28",
    ),
    (
        "exit_codes.golden",
        "edb61af2e2aa0673d7ea95efcbd97f6abbdcf1bb09735be7a3300642ecc355aa",
    ),
    (
        "route_probe.h1_fs_llm.golden",
        "831cb55772ee6a2e2f42ee9672d98b5bbac50caea2fb1a9dc661729934d8a29c",
    ),
    (
        "route_probe.h2_all_capabilities.golden",
        "a7867005f8ab098fcd9e5fd456f250a11c3765b96a0de7824e40361ef14c3ea5",
    ),
    (
        "route_probe.h3_fs_llm_lifecycle.golden",
        "98b4bd9738c7299fef2b88a469f061fc1fe2d42e263dfe063609a38f7a65a7e1",
    ),
    (
        "route_probe.h4_fs_llm_grant.golden",
        "6c03a0c9bd793db9013c4c2193a809e329a1a924579c244d93d2c44c53ef2e6e",
    ),
    (
        "route_probe.h5_fs_llm_tools_no_driver.golden",
        "bf7be8af05a70c378bac5a2f6d0d49f7ab8866f1112fb829d7257b21a86ecb0c",
    ),
    (
        "route_table.h1_fs_llm.golden",
        "b09dd0ccf9a4604c400701df9d9ae477171ed3db2e1e3381bac8bce0bd545527",
    ),
    (
        "route_table.h2_all_capabilities.golden",
        "4331c411de5d7efc5448140d0ae59ab92fe19e73b06b9a731fcb84e54ef6be2e",
    ),
    (
        "runtime_files.h1_fs_llm.golden",
        "dc87407125376ac2fbba6f92c36a7850c07d8eba4c435dea1e84443d5bbd5c51",
    ),
    (
        "runtime_files.h2_all_capabilities.golden",
        "a9c7f78b0d31346c7400aa712b798a59954bbd627c1e8a8d8a76a01fe18cd5f4",
    ),
    (
        "start.h1_fs_llm.merged.golden",
        "7388bdeb144392afa2258feed36c55aa47dee7977cc5c301f4ebf58bdbda50e4",
    ),
    (
        "start.h1_fs_llm.stderr.golden",
        "4856ac3784caa2af51e5713e719476551f81c5c5ae52dc010e734023da55016d",
    ),
    (
        "start.h1_fs_llm.stdout.golden",
        "9e5442316f51dcb1fdb10ffedb33e0eb93a819f2b80585863273e044137a340f",
    ),
    (
        "start.h2_all_capabilities.stderr.golden",
        "36ebf25496e5b5d5b3253c42a5009958337d8b7088115753e377958a04f86606",
    ),
    (
        "start.h2_all_capabilities.stdout.golden",
        "b6732b8a6687b1de180524c6de7dba4b81b761c8e4f41bf8e384df9e155e3afc",
    ),
    (
        "start.h3_fs_llm_lifecycle.stderr.golden",
        "9322d7f2de4c61a757b990cd9db892f462afa857e786bcdbcfbf19e5cb6b376a",
    ),
    (
        "start.h3_fs_llm_lifecycle.stdout.golden",
        "7e42acf63e2ee25e5b61aa99c127deaa9d2250ecc7791598186f80b04ee1a6fa",
    ),
    (
        "start.h4_fs_llm_grant.stderr.golden",
        "e1dc685f0de9ea9e7c443d548410ffeceac91b0d847782c2f4021578129b9ba2",
    ),
    (
        "start.h4_fs_llm_grant.stdout.golden",
        "6a639eb50088e1143c58bbce063a82f213385104526874eea8f72b7b905c01ef",
    ),
    (
        "start.h5_fs_llm_tools_no_driver.stderr.golden",
        "d9812d126f5451defdbe9eb83e4d3947de5a20870120ad5b2763e45c84508af8",
    ),
    (
        "start.h5_fs_llm_tools_no_driver.stdout.golden",
        "ccf69ebfe218f0c3368d25084f36e70671e432e762f342a8e1c6e2cb3d3f24f5",
    ),
    (
        "start.h6_fs_llm_memory_no_git.stderr.golden",
        "59a48e475cc4e381f1805905decce6a6d09e0499b308da8206101bdcc2f91f1c",
    ),
    (
        "start.h6_fs_llm_memory_no_git.stdout.golden",
        "b883d6a2045c6d9838d35cf734b67c08bfa18514a8684403b446b50742b2292e",
    ),
];

// ── Homes ─────────────────────────────────────────────────────────────────────────────────

/// One home of the goldens.
pub struct HomeSpec {
    /// File-name label of the home's goldens.
    pub label: &'static str,
    /// Short name in golden headers (the full description is [`describe`]).
    pub name: &'static str,
    /// Declared capabilities; `None` = the set the goldens were captured with, which was every
    /// `KNOWN_CAPABILITIES` entry of that tree. A capability the runtime learned since is not
    /// declared, so what the home's goldens pin does not move.
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
    const CAPTURED: [&str; 10] = [
        "secrets",
        "fs",
        "skills",
        "memory",
        "grant",
        "llm",
        "tools",
        "messaging",
        "lifecycle",
        "genui",
    ];
    match spec.caps {
        Some(caps) => caps.to_vec(),
        None => {
            for cap in CAPTURED {
                assert!(
                    KNOWN_CAPABILITIES.contains(&cap),
                    "captured capability {cap:?} is no longer a KNOWN_CAPABILITIES entry"
                );
            }
            CAPTURED.to_vec()
        }
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

/// The pending constant (name, constant) any of whose outcome entries names `golden`.
pub fn pending_owner(golden: &str) -> Option<(&'static str, &'static PendingExpectation)> {
    PENDING_EXPECTATIONS
        .iter()
        .find(|(_, pending)| pending.owns(golden))
        .map(|(owner, pending)| (*owner, *pending))
}

/// Where a golden is pinned: `Some((pin, owner))` with owner `BASELINE_GOLDEN_SHA256` or the
/// pending constant's name (its entry for the decided outcome).
pub fn golden_pin(name: &str) -> Option<(&'static str, &'static str)> {
    let baseline = BASELINE_GOLDEN_SHA256
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, pin)| (*pin, "BASELINE_GOLDEN_SHA256"));
    let pending = PENDING_EXPECTATIONS.iter().find_map(|(owner, pending)| {
        pending
            .active_pins()?
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
    let (pin, owner) = golden_pin(name).unwrap_or_else(|| match pending_owner(name) {
        Some((owner, pending)) => panic!(
            "golden {name} belongs to {owner}, which has no pin entry for its decided outcome \
             {:?}: capture it and add the `(outcome, pins)` entry",
            pending.outcome
        ),
        None => panic!("golden {name} has no sha256 pin (BASELINE_GOLDEN_SHA256)"),
    });
    let actual = sha256_hex(&bytes);
    assert_eq!(
        actual, pin,
        "golden {name} does not match its sha256 pin in {owner}: the captured baselines are \
         immutable (intended wire changes go through D5_CHANGE_MATRIX; a pending golden is \
         re-pinned only with a new decided outcome, in a new entry of its constant; only a \
         whole-tree re-capture on a new base re-pins in place, and only a golden whose sole \
         changed line is its CAPTURED_ON header)"
    );
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("golden {name} is not utf-8: {e}"))
}

/// Whether `recaptured` differs from the `pinned` bytes of its golden in exactly one line: its
/// `# {CAPTURED_ON}` header, in place of an older `# captured on …` header. That is the one change
/// a whole-tree re-capture on a new base re-pins in place (see [`PendingExpectation`]).
pub fn only_captured_on_line_changed(pinned: &[u8], recaptured: &str) -> bool {
    let Ok(pinned) = std::str::from_utf8(pinned) else {
        return false;
    };
    let header = format!("# {CAPTURED_ON}");
    let pinned: Vec<&str> = pinned.split('\n').collect();
    let recaptured: Vec<&str> = recaptured.split('\n').collect();
    let Some(at) = recaptured.iter().position(|line| *line == header) else {
        return false;
    };
    pinned.len() == recaptured.len()
        && pinned[at] != header
        && pinned[at].starts_with("# captured on ")
        && pinned
            .iter()
            .zip(&recaptured)
            .enumerate()
            .all(|(i, (old, new))| i == at || old == new)
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
    /// Each golden written in update mode: its name, its new sha256, and whether its only changed
    /// line is the `CAPTURED_ON` header (`None`: no pinned bytes to compare with, because the
    /// golden was missing or no longer matched its pin before the write).
    written: Vec<(String, String, Option<bool>)>,
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
            let path = golden_path(name);
            // Compared with the pinned bytes, read before the write and only while they still
            // match the pin (a golden an earlier update run rewrote is not the pinned one).
            let captured_on_only = std::fs::read(&path)
                .ok()
                .filter(|bytes| golden_pin(name).is_some_and(|(pin, _)| sha256_hex(bytes) == pin))
                .map(|pinned| only_captured_on_line_changed(&pinned, actual));
            std::fs::write(&path, actual).expect("write golden");
            self.written.push((
                name.to_string(),
                sha256_hex(actual.as_bytes()),
                captured_on_only,
            ));
            return;
        }
        let golden = read_pinned_golden(name);
        assert_text_eq(name, &overlay(&golden), actual);
    }

    pub fn finish(mut self) {
        self.finished = true;
        if update_mode() {
            let mut list = String::new();
            for (name, sha, captured_on_only) in &self.written {
                let state = match (golden_pin(name), pending_owner(name), captured_on_only) {
                    (Some((pin, _)), _, _) if pin == sha => "pin unchanged",
                    (Some(_), _, Some(true)) => {
                        "only the CAPTURED_ON line changed (a whole-tree re-capture on a new \
                         base: re-pin this entry in place)"
                    }
                    (Some(_), _, None) => {
                        "CHANGED, and the golden was missing or no longer matched its pin before \
                         the write (restore the goldens from git, then re-capture)"
                    }
                    (Some((_, "BASELINE_GOLDEN_SHA256")), _, Some(false)) => {
                        "CHANGED (a baseline: never re-pin after the capture)"
                    }
                    (Some(_), _, Some(false)) => {
                        "CHANGED under an unchanged outcome (refused: a pending golden is \
                         re-pinned only in a new entry for a new decided outcome)"
                    }
                    (None, Some(_), _) => {
                        "NEW outcome (add its `(outcome, pins)` entry to the pending constant)"
                    }
                    (None, None, _) => "NEW (no pin yet)",
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
