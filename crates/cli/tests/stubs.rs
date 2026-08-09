//! Integration tests for stubbed subcommands and top-level CLI surface.

use assert_cmd::Command;
use predicates::prelude::*;

fn advance() -> Command {
    Command::cargo_bin("advance").unwrap()
}

#[test]
fn stub_subcommand_returns_exit_3() {
    // Slice AE (2026-05-09): `start` is no longer a stub. The remaining stubs
    // are `stop`, `status`, and `breaker open|close` per `commands::main.rs`'s
    // catch-all arm. Use `stop` here as the canonical exit-3 stub witness.
    advance()
        .args(["stop"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("not yet implemented"));
}

#[test]
fn unknown_subcommand_returns_exit_2() {
    advance()
        .args(["bogus-subcommand"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn version_flag_prints_version() {
    advance()
        .args(["--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("advance"));
}
