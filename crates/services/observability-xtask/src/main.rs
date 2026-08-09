//! `cargo xtask observability-lint` — enforces the AC-01 / AC-14 emit
//! convention across `cap-*` capability crates.
//!
//! Slice E (m019-slice-e, 2026-05-15) ships:
//! - `Lint::run(workspace, allowlist)` — the core algorithm (in `lint.rs`).
//! - `observability-lint` subcommand wrapping `Lint::run`.
//! - Schema validation for `observability-allowlist.toml`.
//!
//! Trust model: the lint matches direct + helper-call emit patterns inside
//! `HostFunctionHandler::call` bodies via `syn::visit::Visit`. Handlers that
//! emit via deeper delegation (cap-llm gateway, cap-grant resolver) must be
//! waived in `observability-allowlist.toml` with required `delegated_to:
//! <crate>::<module>::<function>` field; genuinely unwired handlers use
//! `pending_wiring_slice: <MODULE-NNN OR m<NNN>-slice-X OR docs/<path>>`.
//! PR review enforces semantic truthfulness of the audit fields.
//!
//! Exit code 0 on no unwaived violations; 1 on any malformed allowlist or
//! unwaived violation.

use clap::{Parser, Subcommand};

mod lint;

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "MODULE-019 observability tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the observability-lint check.
    ObservabilityLint(lint::Args),
}

fn main() -> anyhow::Result<std::process::ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Command::ObservabilityLint(args) => lint::run(args),
    }
}
