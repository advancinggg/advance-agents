//! The home that declares every capability on a git repository (the D5 goldens' H2), built
//! the way the goldens build it: `advance init` through the real binary with a cleared
//! environment, then the runtime config, the agent config, the deployed driver and a git
//! repository with one empty commit. [`AllCapsHome::declaring`] builds the same home with
//! fewer capabilities.
//!
//! The pieces are copies of the goldens' own (`runtime_compose_d5_common`: `runtime_yaml(&H2)`,
//! `agent_yaml(&H2)`, the minimal driver, `init_git_repo`, `TestHome::command`), not shared
//! with them, so the goldens' harness stays untouched by the witnesses that use this home.
//!
//! Including test: `#[path = "support/all_caps_home.rs"] mod all_caps_home;`.
#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, Once};

use advance_cli::agent_config::KNOWN_CAPABILITIES;
use tempfile::TempDir;
use wit_component::ComponentEncoder;

/// The deployed driver: the committed wit-bindgen guest core module, encoded to a component.
const MINIMAL_CORE: &[u8] =
    include_bytes!("../../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");

/// The master key the home's runtime config names (`secrets.env-var-name`).
pub const MASTER_KEY_ENV: &str = "ADVANCE_D5_GOLDEN_MASTER_KEY";
pub const MASTER_KEY_HEX: &str = "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5";

/// Child spawns of one test binary are serialised: on macOS a child's pipes are created with
/// `pipe()` + `FD_CLOEXEC` (not atomic), so a concurrent spawn could inherit another child's
/// pipe end and hold it open.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Set the master key in this process's environment, once, for compositions run in-process
/// (the composition reads it from the environment named by the runtime config).
pub fn ensure_in_process_master_key() {
    static INIT: Once = Once::new();
    INIT.call_once(|| std::env::set_var(MASTER_KEY_ENV, MASTER_KEY_HEX));
}

/// A home under a fresh temp root: `<root>/ws` (the workspace), `<root>/home` (the `HOME` of
/// child processes, and the progress-lifecycle state root of an in-process composition) and
/// `<root>/tmp` (the children's `TMPDIR`).
pub struct AllCapsHome {
    _dir: TempDir,
    /// The canonical temp root.
    pub root: PathBuf,
    /// The workspace (`<root>/ws`).
    pub ws: PathBuf,
}

impl AllCapsHome {
    /// `advance init <root>/ws`, then H2's runtime config, agent config, driver and git repo.
    pub fn new() -> AllCapsHome {
        AllCapsHome::declaring(KNOWN_CAPABILITIES, true)
    }

    /// The same home declaring only `caps`, on a git repository when `git` is set.
    pub fn declaring(caps: &[&str], git: bool) -> AllCapsHome {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonicalize temp root");
        std::fs::create_dir_all(root.join("home")).expect("create HOME dir");
        std::fs::create_dir_all(root.join("tmp")).expect("create TMPDIR dir");
        let ws = root.join("ws");
        let home = AllCapsHome {
            _dir: dir,
            root,
            ws,
        };
        let ws_arg = home.ws.to_str().expect("utf-8 workspace").to_string();
        let out = {
            let mut cmd = home.command(&["init", &ws_arg]);
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            let child = {
                let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                cmd.spawn().expect("spawn advance init")
            };
            child.wait_with_output().expect("wait for advance init")
        };
        assert!(
            out.status.success(),
            "advance init failed: {:?}; stderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::write(home.config_path(), runtime_yaml()).expect("write runtime config");
        std::fs::write(home.ws.join(".agent/config.yaml"), agent_yaml(caps))
            .expect("write agent config");
        std::fs::write(
            home.ws.join(".agent/behavior.component.wasm"),
            component_bytes(),
        )
        .expect("deploy driver component");
        if git {
            init_git_repo(&home.ws);
        }
        home
    }

    /// `<root>/state` (created): the state root of an in-process composition of this home,
    /// so its platform state stays out of the process `HOME`.
    pub fn state_root(&self) -> PathBuf {
        let root = self.root.join("state");
        std::fs::create_dir_all(&root).expect("create the state root");
        root
    }

    /// `<ws>/.advance/runtime-config.yaml`.
    pub fn config_path(&self) -> PathBuf {
        self.ws.join(".advance/runtime-config.yaml")
    }

    /// `<root>/home`: the `HOME` of the children, and where an in-process composition keeps
    /// its progress-lifecycle anchor (never the process `HOME`).
    pub fn home_dir(&self) -> PathBuf {
        self.root.join("home")
    }

    /// The child environment: nothing inherited but `PATH` (`runtime.lock`'s liveness probe
    /// spawns `kill` and `ps`), with `HOME`, `TMPDIR` and the master key set explicitly.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_advance"));
        cmd.args(args)
            .env_clear()
            .env("HOME", self.home_dir())
            .env("TMPDIR", self.root.join("tmp"))
            .env(MASTER_KEY_ENV, MASTER_KEY_HEX)
            .stdin(Stdio::null());
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd
    }
}

/// Spawn `cmd` holding the binary's spawn lock (see [`SPAWN_LOCK`]).
pub fn spawn_locked(cmd: &mut Command) -> Child {
    let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    cmd.spawn().expect("spawn the advance binary")
}

/// The goldens' `runtime_yaml(&H2)`: one OpenAI provider, the master key from the
/// environment, and `genui.enabled: true` so the declared `genui` is wired.
fn runtime_yaml() -> String {
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
    yaml.push_str("\ngenui:\n  enabled: true\n");
    yaml
}

/// The goldens' `agent_yaml(&H2)` for `caps` (every `KNOWN_CAPABILITIES` entry for H2).
fn agent_yaml(caps: &[&str]) -> String {
    let mut yaml = String::from("capabilities:\n");
    for cap in caps {
        let _ = writeln!(yaml, "  {cap}: true");
    }
    yaml
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
