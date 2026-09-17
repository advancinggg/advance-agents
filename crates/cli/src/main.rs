#![forbid(unsafe_code)]

//! `advance` CLI — MODULE-001 runtime-host entry point (Slice F skeleton).
//!
//! Slice F ships `advance init` and `advance config check` fully; other
//! subcommands parse their spec §2.4 grammar but return exit code 3.

use clap::{Parser, Subcommand};
use std::process::ExitCode;

// Slice AG (2026-05-11): consume modules from the `advance_cli` lib target
// so integration tests in `crates/cli/tests/*.rs` and this binary share
// the same code path. (`wiring` is referenced by start::run via the
// fully-qualified path `advance_cli::wiring::wire_capabilities`; the
// `use` here just covers `commands`. Both modules are declared in
// `crates/cli/src/lib.rs`.)
use advance_cli::commands;

#[derive(Parser)]
#[command(name = "advance", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize a workspace with .advance/, .runtime/, .agent/ skeleton.
    Init { path: std::path::PathBuf },

    /// Validate runtime-config.yaml against schema.
    Config {
        #[command(subcommand)]
        sub: ConfigCmd,
    },

    /// Start the runtime: load runtime-config.yaml, acquire the single-active
    /// runtime lock, wire capabilities, autoload a deployed agent component (if
    /// present) and drive its single-turn agent loop, and serve an in-process
    /// `POST /msg` inbound message source — then park until SIGINT/SIGTERM.
    /// (Slice AE bootstrap → BS-3 guest autoload + agent-loop driver → WS-A
    /// message source.) See MODULE-001 §3.6.
    Start {
        #[arg(long)]
        workspace: Option<std::path::PathBuf>,
    },

    /// Import skills into the admin pool and materialize them into an
    /// agent-local layer (MODULE-017 §1.3.6). Admin/operator surface — not
    /// agent-callable.
    Skill {
        #[command(subcommand)]
        sub: SkillCmd,
    },

    /// Install, list and uninstall packs in the admin packs dir (MODULE-018
    /// §1.3.2). Admin/operator surface — not
    /// agent-callable. Wraps the same 8-step `Installer` the runtime's pack
    /// registry reads.
    Pack {
        #[command(subcommand)]
        sub: PackCmd,
    },

    /// Provision the on-disk encrypted secret store (admin surface, not
    /// agent-callable). Stored values are AES-256-GCM-encrypted under the
    /// keychain/env master key; `advance start` resolves them at LLM-request
    /// time. `set` reads the value from STDIN.
    Secrets {
        #[command(subcommand)]
        sub: SecretsCmd,
    },

    /// Stubbed: stops the runtime (not yet implemented).
    Stop,

    /// Stubbed: prints runtime status (not yet implemented).
    Status,

    /// Stubbed: circuit-breaker admin (not yet implemented).
    Breaker {
        #[command(subcommand)]
        sub: BreakerCmd,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Validate runtime-config.yaml; exits 0 on valid, 1 on error.
    Check {
        /// Path to runtime-config.yaml. Default resolution: $ADVANCE_WORKSPACE/.advance/runtime-config.yaml → ./.advance/runtime-config.yaml
        path: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum SkillCmd {
    /// Import a skill into the admin pool. Source is a git URL (file://,
    /// https://) or a local directory; or use --mcp-descriptor with a JSON
    /// McpImportSpec. Path A is knowledge-only (always Imported/Untrusted).
    Import {
        /// Git URL (file:// or https://) or local directory path. Omit when
        /// using --mcp-descriptor. Auto-detected: an existing directory is
        /// imported as a local path; otherwise treated as a git URL.
        source: Option<String>,
        /// Import from an McpImportSpec JSON descriptor instead of a
        /// source location (mutually exclusive with <source>).
        #[arg(long, value_name = "spec.json")]
        mcp_descriptor: Option<std::path::PathBuf>,
        /// Skill name in the admin pool. Defaults to the source basename
        /// (git/local) or the descriptor's source_name (MCP).
        #[arg(long)]
        name: Option<String>,
        /// Admin pool root. Default: $ADVANCE_WORKSPACE/.advance/skills →
        /// ./.advance/skills.
        #[arg(long)]
        pool: Option<std::path::PathBuf>,
        /// Trust level. Only `untrusted` is accepted for Path A imports.
        #[arg(long)]
        trust: Option<String>,
    },
    /// Materialize an admin-pool skill into an agent-local layer at
    /// <agent-root>/.agent/skills/<name>/.
    Materialize {
        /// Skill name in the admin pool.
        name: String,
        /// Agent root: the skill is written under <agent-root>/.agent/skills/.
        #[arg(long)]
        to: std::path::PathBuf,
        /// Admin pool root (source). Same default resolution as `import`.
        #[arg(long)]
        pool: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum PackCmd {
    /// Install a pack. `<source>` is a local directory, `git+<url>[@<ref>]`,
    /// a `.tar.gz` path, or `registry:<name>@<version>`. A pack that declares
    /// `required-capabilities` prompts for approval on stdin (see --no-input).
    /// Reinstalling an installed `name@version` is refused — uninstall first.
    Install {
        source: String,
        /// Packs dir. Default: `pack.packs-dir` from
        /// $ADVANCE_WORKSPACE/.advance/runtime-config.yaml when present, else
        /// $ADVANCE_WORKSPACE/.advance/packs → ./.advance/packs.
        #[arg(long)]
        packs_dir: Option<std::path::PathBuf>,
        /// Never read stdin: a pack that needs approval is rejected.
        #[arg(long)]
        no_input: bool,
    },
    /// List installed packs, one per line: `name@version<TAB>trust<TAB>installed-at`.
    List {
        /// Packs dir (same default resolution as `install`).
        #[arg(long)]
        packs_dir: Option<std::path::PathBuf>,
    },
    /// Uninstall `<name>@<version>`. Refused while another installed pack
    /// depends on it.
    Uninstall {
        /// `<name>@<version>` of an installed pack.
        spec: String,
        /// Packs dir (same default resolution as `install`).
        #[arg(long)]
        packs_dir: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum SecretsCmd {
    /// Store a secret. The value is read from STDIN (never argv, which would
    /// leak via `ps`/shell history).
    Set {
        /// Secret reference name (e.g. `anthropic-api-key`, matching an
        /// `llm-providers[].api-key-secret` in runtime-config.yaml).
        name: String,
        #[arg(long)]
        workspace: Option<std::path::PathBuf>,
    },
    /// List stored secret names (values are never printed).
    List {
        #[arg(long)]
        workspace: Option<std::path::PathBuf>,
    },
    /// Remove a stored secret by name.
    Remove {
        name: String,
        #[arg(long)]
        workspace: Option<std::path::PathBuf>,
    },
    /// Move the stored secrets between the File layout (`.advance/secrets.json` +
    /// `.advance/master.key`) and the iCloud-Keychain-synchronized layout
    /// (`keychain-sync`), verifying every name round-trips, then point
    /// `secrets.master-key-source` at the target. `keychain-sync` is Apple-only.
    Migrate {
        /// `file` or `keychain-sync`.
        #[arg(long)]
        to: String,
        #[arg(long)]
        workspace: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum BreakerCmd {
    Open {
        /// "<scope>:<target>" — scope ∈ {capability, component-type, agent}.
        scope_target: String,
        #[arg(long)]
        reason: String,
    },
    Close {
        /// "<scope>:<target>" — same grammar as `open`.
        scope_target: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { path } => commands::init::run(path),
        Cmd::Config {
            sub: ConfigCmd::Check { path },
        } => commands::config::check(path),
        Cmd::Start { workspace } => commands::start::run(workspace),
        Cmd::Skill { sub } => match sub {
            SkillCmd::Import {
                source,
                mcp_descriptor,
                name,
                pool,
                trust,
            } => commands::skill::run_import(source, mcp_descriptor, name, pool, trust),
            SkillCmd::Materialize { name, to, pool } => {
                commands::skill::run_materialize(name, to, pool)
            }
        },
        Cmd::Pack { sub } => match sub {
            PackCmd::Install {
                source,
                packs_dir,
                no_input,
            } => commands::pack::run_install(source, packs_dir, no_input),
            PackCmd::List { packs_dir } => commands::pack::run_list(packs_dir),
            PackCmd::Uninstall { spec, packs_dir } => {
                commands::pack::run_uninstall(spec, packs_dir)
            }
        },
        Cmd::Secrets { sub } => match sub {
            SecretsCmd::Set { name, workspace } => commands::secrets::run_set(name, workspace),
            SecretsCmd::List { workspace } => commands::secrets::run_list(workspace),
            SecretsCmd::Remove { name, workspace } => {
                commands::secrets::run_remove(name, workspace)
            }
            SecretsCmd::Migrate { to, workspace } => commands::secrets::run_migrate(to, workspace),
        },
        Cmd::Stop | Cmd::Status | Cmd::Breaker { .. } => {
            eprintln!(
                "advance: subcommand not yet implemented (this slice ships init + config check + start only)"
            );
            ExitCode::from(3)
        }
    }
}
