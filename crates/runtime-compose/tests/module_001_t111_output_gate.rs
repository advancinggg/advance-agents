//! MODULE-001-T111 (5) / MODULE-001-AC-30 — the composition library owns no process I/O:
//! code in `crates/runtime-compose/src` installs no signal handler, never prints or writes
//! to stdout / stderr directly, never reads (or changes) the current directory and never
//! exits the process. Those belong to the host; `advance start` is a thin `main` over
//! `compose`, and every line the composition emits goes through its `ComposeLog`.
//!
//! The gate reads every `.rs` file under `src/` (unit-test modules included), drops the
//! comments (line, doc and block comments, and nothing inside a string or char literal) and
//! fails on any remaining line that contains a forbidden pattern. String literals stay in
//! the scanned text, so `"PWD"` (reading the shell's current directory) is caught.
//! The crate-level `#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro,
//! clippy::exit)]` enforces the same for every target through the CI clippy job.

#[path = "support/source_scan.rs"]
mod source_scan;

/// Each pattern, and what code containing it does.
const FORBIDDEN: &[(&str, &str)] = &[
    ("println!", "prints to stdout"),
    ("eprintln!", "prints to stderr"),
    ("print!(", "prints to stdout"),
    ("eprint!(", "prints to stderr"),
    ("dbg!(", "prints to stderr"),
    ("stdout()", "writes to stdout directly"),
    ("stderr()", "writes to stderr directly"),
    ("tokio::signal", "installs a signal handler"),
    ("signal_hook", "installs a signal handler"),
    ("ctrlc", "installs a signal handler"),
    ("libc::signal", "installs a signal handler"),
    ("sigaction", "installs a signal handler"),
    ("current_dir(", "reads the current directory"),
    ("set_current_dir", "changes the current directory"),
    ("\"PWD\"", "reads the current directory"),
    ("process::exit", "exits the process"),
    ("process::abort", "aborts the process"),
];

/// The source files the walk found when the gate was written: a smaller count means the
/// walk no longer sees the crate's sources.
const MIN_FILES: usize = 75;

/// Files the walk must reach (the crate root, the entry point, the graph and the wiring).
const ANCHORS: &[&str] = &["lib.rs", "compose.rs", "daemon/mod.rs", "wiring.rs"];

#[test]
fn module_001_ac30_t111_5_runtime_compose_src_has_no_process_io() {
    let src = source_scan::src_dir();
    let files = source_scan::rust_files(&src);
    for anchor in ANCHORS {
        assert!(
            files.iter().any(|(_, name)| name == anchor),
            "the walk of {} must reach src/{anchor}",
            src.display()
        );
    }
    assert!(
        files.len() >= MIN_FILES,
        "expected at least {MIN_FILES} source files under {}, found {}",
        src.display(),
        files.len()
    );

    let mut violations = Vec::new();
    for (file, name) in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (line, what) in violations_in(&text) {
            violations.push(format!("src/{name}:{line}: {what}"));
        }
    }
    assert!(
        violations.is_empty(),
        "crates/runtime-compose/src must not own process I/O (a host's job; route output \
         through ComposeLog):\n{}",
        violations.join("\n")
    );
}

/// Every pattern is seen in code, and no comment hides or produces a match.
#[test]
fn module_001_ac30_t111_5_gate_matches_each_pattern_outside_comments_only() {
    for (pattern, _) in FORBIDDEN {
        let code = format!("    let _ = {pattern};\n");
        assert_eq!(
            violations_in(&code).len(),
            1,
            "{pattern:?} in code must be one violation"
        );
        for comment in [
            format!("// {pattern}\n"),
            format!("/// {pattern}\n"),
            format!("//! {pattern}\n"),
            format!("let x = 1; // {pattern}\n"),
            format!("/* {pattern}\n {pattern} */ let y = 2;\n"),
            format!("/* outer /* {pattern} */ {pattern} */\n"),
        ] {
            assert!(
                violations_in(&comment).is_empty(),
                "{pattern:?} inside a comment is not a violation: {comment:?}"
            );
        }
    }

    // A comment marker inside a literal does not start a comment.
    let after_literal = [
        "let url = \"http://x\"; println!(\"{url}\");\n",
        "let c = '\"'; println!(\"{c}\");\n",
        "let q = '\\''; println!(\"{q}\");\n",
        "let r = r#\"a \" // b\"#; println!(\"{r}\");\n",
        "let s = \"a \\\" // b\"; println!(\"{s}\");\n",
        "fn f<'a>(x: &'a str) { println!(\"{x}\") }\n",
    ];
    for code in after_literal {
        assert_eq!(
            violations_in(code),
            vec![(1, "prints to stdout")],
            "{code:?}"
        );
    }

    // A string literal stays in the scanned text, and lines are numbered as in the file.
    let read_pwd = "fn f() {}\n/* a\nb */\nlet d = std::env::var_os(\"PWD\");\n";
    assert_eq!(
        violations_in(read_pwd),
        vec![(4, "reads the current directory")]
    );
}

/// `(line number, what it does)` of each line of `source`'s code that holds a forbidden
/// pattern.
fn violations_in(source: &str) -> Vec<(usize, &'static str)> {
    let code = source_scan::strip_comments(source);
    let mut found = Vec::new();
    for (index, line) in code.lines().enumerate() {
        if let Some((_, what)) = FORBIDDEN.iter().find(|(pattern, _)| line.contains(pattern)) {
            found.push((index + 1, *what));
        }
    }
    found
}
