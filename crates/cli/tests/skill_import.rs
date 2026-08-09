//! e2e integration tests for `advance skill import` / `advance skill materialize`
//! (MODULE-017 AC-18 + AC-28, Slice I — §3.3 T88–T93). This is the regression
//! net for the skill-storage substrate: import (local / git / MCP descriptor) →
//! admin pool, materialize → agent-local, two-layer separation, and the
//! fail-closed error contract. Drives the real `advance` binary end-to-end.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn advance() -> Command {
    Command::cargo_bin("advance").unwrap()
}

/// The checked-in knowledge-only fixture skill (SKILL.md + templates/intro.md).
fn fixture_skill() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/skill-knowledge")
}

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── si_01 (T88 + T91): import local → admin pool, then materialize → agent-local ───
#[test]
fn si_01_import_local_then_materialize() {
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let agent = tmp.path().join("agent");

    // `advance skill import <fixture> --name web-search --pool <pool>`
    advance()
        .args(["skill", "import"])
        .arg(fixture_skill())
        .args(["--name", "web-search"])
        .arg("--pool")
        .arg(&pool)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported skill 'web-search'"));

    // Admin pool layer: SKILL.md is a verbatim copy; .meta.yaml records
    // Imported/Untrusted provenance; the template sidecar is carried over.
    let pool_skill = pool.join("web-search/SKILL.md");
    assert!(pool_skill.is_file(), "admin pool SKILL.md missing");
    let fixture_md = fs::read_to_string(fixture_skill().join("SKILL.md")).unwrap();
    assert_eq!(
        fs::read_to_string(&pool_skill).unwrap(),
        fixture_md,
        "pool SKILL.md must be a verbatim copy of the source"
    );
    let pool_meta = fs::read_to_string(pool.join("web-search/.meta.yaml")).unwrap();
    assert!(
        pool_meta.contains("provenance: Imported"),
        "meta provenance: {pool_meta}"
    );
    assert!(
        pool_meta.contains("trust_level: Untrusted"),
        "meta trust_level: {pool_meta}"
    );
    assert!(
        pool.join("web-search/templates/intro.md").is_file(),
        "pool template sidecar missing"
    );

    // Agent layer is empty until an explicit materialize.
    assert!(
        !agent.join(".agent/skills/web-search").exists(),
        "agent layer populated before materialize"
    );

    // `advance skill materialize web-search --to <agent> --pool <pool>`
    advance()
        .args(["skill", "materialize", "web-search"])
        .arg("--to")
        .arg(&agent)
        .arg("--pool")
        .arg(&pool)
        .assert()
        .success()
        .stdout(predicate::str::contains("Materialized skill 'web-search'"));

    // Agent-local layer now holds the materialized two-part bundle
    // (knowledge SKILL.md + the template sidecar).
    let agent_skill = agent.join(".agent/skills/web-search/SKILL.md");
    assert!(agent_skill.is_file(), "materialized agent SKILL.md missing");
    assert!(
        fs::read_to_string(&agent_skill)
            .unwrap()
            .contains("# Web Search"),
        "materialized agent SKILL.md content mismatch"
    );
    assert!(
        agent
            .join(".agent/skills/web-search/templates/intro.md")
            .is_file(),
        "materialized template sidecar missing"
    );

    // Two-layer: the admin pool is a distinct path outside the agent layer.
    assert!(
        !pool.starts_with(agent.join(".agent")),
        "admin pool must be outside the agent layer"
    );
}

// ─── si_02 (T89): import from a file:// bare git repo (skips if git absent) ───
#[test]
fn si_02_import_git_file_url() {
    if !git_available() {
        eprintln!("skipping si_02: git binary not in PATH");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let repo_src = tmp.path().join("repo_src");
    let bare = tmp.path().join("repo.git");

    fs::create_dir_all(&repo_src).unwrap();
    fs::write(
        repo_src.join("SKILL.md"),
        "---\nname: from-git\ndescription: a git skill.\n---\n# From Git\nbody\n",
    )
    .unwrap();
    let git = |args: &[&str], cwd: &Path| {
        std::process::Command::new("git")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .current_dir(cwd)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(
        git(&["init", "-b", "main"], &repo_src).status.success(),
        "git init"
    );
    git(&["add", "SKILL.md"], &repo_src);
    assert!(
        git(&["commit", "-m", "initial"], &repo_src)
            .status
            .success(),
        "git commit"
    );
    assert!(
        std::process::Command::new("git")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .args(["clone", "--bare"])
            .arg(&repo_src)
            .arg(&bare)
            .output()
            .unwrap()
            .status
            .success(),
        "git clone --bare"
    );

    let url = format!("file://{}", bare.to_string_lossy());
    advance()
        .args(["skill", "import"])
        .arg(&url)
        .args(["--name", "from-git"])
        .arg("--pool")
        .arg(&pool)
        .assert()
        .success();

    let md = pool.join("from-git/SKILL.md");
    assert!(md.is_file(), "git-imported SKILL.md missing");
    assert!(fs::read_to_string(&md).unwrap().contains("# From Git"));
}

// ─── si_03 (T90): import from an McpImportSpec JSON descriptor ───
#[test]
fn si_03_import_mcp_descriptor() {
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let desc = tmp.path().join("spec.json");
    fs::write(
        &desc,
        r#"{"source_name":"mcp-skill","prompt_text":"Do the thing well.","description":"An MCP-sourced knowledge skill.","tags":["mcp","demo"]}"#,
    )
    .unwrap();

    advance()
        .args(["skill", "import", "--mcp-descriptor"])
        .arg(&desc)
        .arg("--pool")
        .arg(&pool)
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported skill 'mcp-skill'"));

    let md = fs::read_to_string(pool.join("mcp-skill/SKILL.md")).unwrap();
    assert!(
        md.contains("mcp-skill"),
        "synthesized frontmatter name missing: {md}"
    );
    assert!(
        md.contains("Do the thing well."),
        "synthesized body missing: {md}"
    );
}

// ─── si_04 (T92): import a directory missing SKILL.md → fail-closed ───
#[test]
fn si_04_import_missing_skill_md_fails() {
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let src = tmp.path().join("empty-src");
    fs::create_dir_all(&src).unwrap(); // exists (→ local path) but has no SKILL.md

    advance()
        .args(["skill", "import"])
        .arg(&src)
        .args(["--name", "broken"])
        .arg("--pool")
        .arg(&pool)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("SKILL.md"));

    assert!(
        !pool.join("broken").exists(),
        "no bundle should be created when import fails"
    );
}

// ─── si_05 (T92): import with a traversal --name → reject, no escape ───
#[test]
fn si_05_import_rejects_bad_name() {
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");

    advance()
        .args(["skill", "import"])
        .arg(fixture_skill())
        .args(["--name", "../escape"])
        .arg("--pool")
        .arg(&pool)
        .assert()
        .failure()
        .code(1); // library validate_skill_name rejects → SkillError::InvalidName → exit 1

    // The traversal target (pool/../escape == tmp/escape) must not be created.
    assert!(
        !tmp.path().join("escape").exists(),
        "a traversal --name must not create a sibling directory"
    );
}

// ─── si_06 (T92): materialize a name absent from the pool → fail-closed ───
#[test]
fn si_06_materialize_nonexistent_fails() {
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let agent = tmp.path().join("agent");
    fs::create_dir_all(&pool).unwrap(); // empty pool

    advance()
        .args(["skill", "materialize", "ghost"])
        .arg("--to")
        .arg(&agent)
        .arg("--pool")
        .arg(&pool)
        .assert()
        .failure()
        .code(1);

    assert!(
        !agent.join(".agent/skills/ghost").exists(),
        "no agent skill should exist after a failed materialize"
    );
}

// ─── si_07 (T93): import alone populates ONLY the admin pool (two-layer) ───
#[test]
fn si_07_two_layer_separation() {
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let agent = tmp.path().join("agent");

    advance()
        .args(["skill", "import"])
        .arg(fixture_skill())
        .args(["--name", "web-search"])
        .arg("--pool")
        .arg(&pool)
        .assert()
        .success();

    assert!(
        pool.join("web-search/SKILL.md").is_file(),
        "admin pool must contain the imported skill"
    );
    assert!(
        !agent.join(".agent/skills/web-search").exists(),
        "import alone must NOT write the agent layer (materialize is the only projection)"
    );
    // The §2.7 AC-28 route-absence premise: the admin pool lives outside the
    // agent's .agent/ tree (which cap-fs hides via the `.advance` rule).
    assert!(
        !pool.starts_with(agent.join(".agent")),
        "admin pool must be outside the agent's .agent/ tree"
    );
}

// ─── si_08 (T94): --mcp-descriptor symlink is refused (adversarial R1 W1) ───
#[cfg(unix)]
#[test]
fn si_08_mcp_descriptor_symlink_rejected() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let real = tmp.path().join("real.json");
    fs::write(
        &real,
        r#"{"source_name":"sym","prompt_text":"y","description":"d","tags":[]}"#,
    )
    .unwrap();
    let link = tmp.path().join("link.json");
    symlink(&real, &link).unwrap();

    advance()
        .args(["skill", "import", "--mcp-descriptor"])
        .arg(&link)
        .arg("--pool")
        .arg(&pool)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("symlink"));
    assert!(
        !pool.join("sym").exists(),
        "no bundle from a symlinked descriptor"
    );
}

// ─── si_09 (T94): --mcp-descriptor over the size cap is refused before parse (adversarial R1 W1) ───
#[test]
fn si_09_mcp_descriptor_oversize_rejected() {
    let tmp = TempDir::new().unwrap();
    let pool = tmp.path().join("pool");
    let big = tmp.path().join("big.json");
    // > 256 KiB descriptor → rejected by the size pre-check before read/parse.
    let huge = "x".repeat(300 * 1024);
    fs::write(
        &big,
        format!(r#"{{"source_name":"big","prompt_text":"{huge}","description":"d","tags":[]}}"#),
    )
    .unwrap();

    advance()
        .args(["skill", "import", "--mcp-descriptor"])
        .arg(&big)
        .arg("--pool")
        .arg(&pool)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("max"));
    assert!(
        !pool.join("big").exists(),
        "no bundle from an oversize descriptor"
    );
}
