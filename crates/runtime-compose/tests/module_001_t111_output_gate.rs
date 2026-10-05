//! MODULE-001-T111 (5) / MODULE-001-AC-30 — the composition library owns no process I/O:
//! code in `crates/runtime-compose/src` installs no signal handler, never prints or writes
//! to stdout / stderr directly, never reads (or changes) the current directory and never
//! exits the process. Those belong to the host; `advance start` is a thin `main` over
//! `compose`, and every line the composition emits goes through its `ComposeLog`.
//!
//! The gate reads every `.rs` file under `src/` (unit-test modules included), drops the
//! comments (line, doc and block comments, and nothing inside a string or char literal) and
//! fails on any remaining line that contains a forbidden pattern, or a name that installs a
//! signal handler however tokio's `signal` module was imported (a `signal::` path segment,
//! `ctrl_c`, `SignalKind`, or `signal` inside a `tokio::{…}` import group). String literals
//! stay in the scanned text, so `"PWD"` (reading the shell's current directory) is caught.
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

/// Names that install a signal handler however they were imported: after
/// `use tokio::{signal, …}` the calls read `signal::ctrl_c()` or
/// `signal::unix::signal(SignalKind::terminate())`, with no `tokio::signal` on their line.
/// The `signal::` path segment, `ctrl_c` and `SignalKind` are matched only where an
/// identifier starts (and, for `ctrl_c` and `SignalKind`, ends), so `readiness_signal::`
/// or `SignalKinds` is not one.
const FORBIDDEN_IDENTS: &[(&str, &str)] = &[
    ("signal::", "installs a signal handler"),
    ("ctrl_c", "installs a signal handler"),
    ("SignalKind", "installs a signal handler"),
];

/// What a `tokio::{…}` import group that names `signal` (on any of its lines) does.
const GROUPED_TOKIO_SIGNAL: &str = "installs a signal handler";

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

/// A signal handler is found however tokio's `signal` module was imported: each name in
/// code, never in a comment; a grouped `use tokio::{…, signal}` (on one line or several,
/// renamed or nested) and the calls through it; and nothing that merely contains one of
/// the names inside a longer identifier.
#[test]
fn module_001_ac30_t111_5_gate_matches_signal_handlers_however_imported() {
    const SIGNAL: &str = "installs a signal handler";
    for (name, _) in FORBIDDEN_IDENTS {
        let code = format!("    let _ = {name};\n");
        assert_eq!(
            violations_in(&code),
            vec![(1, SIGNAL)],
            "{name:?} in code must be one violation"
        );
        for comment in [
            format!("// {name}\n"),
            format!("/// {name}\n"),
            format!("let x = 1; // {name}\n"),
            format!("/* {name}\n {name} */ let y = 2;\n"),
        ] {
            assert!(
                violations_in(&comment).is_empty(),
                "{name:?} inside a comment is not a violation: {comment:?}"
            );
        }
    }

    let grouped = [
        "use tokio::{net::TcpListener, signal};",
        "async fn f() {",
        "    let _ = signal::ctrl_c().await;",
        "}",
    ]
    .join("\n");
    assert_eq!(violations_in(&grouped), vec![(1, SIGNAL), (3, SIGNAL)]);

    let across_lines = [
        "use tokio::{",
        "    net::TcpListener,",
        "    signal,",
        "};",
        "fn f() {",
        "    let _ = signal::unix::signal(signal::unix::SignalKind::terminate());",
        "}",
    ]
    .join("\n");
    assert_eq!(violations_in(&across_lines), vec![(3, SIGNAL), (6, SIGNAL)]);

    let nested = [
        "use tokio::{",
        "    signal::unix::{signal, SignalKind},",
        "    sync::Notify,",
        "};",
        "fn f() { let _ = signal(SignalKind::terminate()); }",
    ]
    .join("\n");
    assert_eq!(violations_in(&nested), vec![(2, SIGNAL), (5, SIGNAL)]);

    let renamed = [
        "use ::tokio::{signal as os_signal, sync::Notify};",
        "fn f() { let _ = os_signal::ctrl_c(); }",
    ]
    .join("\n");
    assert_eq!(violations_in(&renamed), vec![(1, SIGNAL), (2, SIGNAL)]);

    let lookalikes = [
        "use crate::readiness_signal::Flag;",
        "let readiness_signal = 1;",
        "let my_ctrl_c_count = 2;",
        "struct SignalKinds;",
        "use tokio::{sync::watch, time::sleep};",
        "use my_tokio::{signal};",
        "let text = \"failed to flush readiness signal: broken pipe\";",
    ]
    .join("\n");
    assert!(
        violations_in(&lookalikes).is_empty(),
        "{:?}",
        violations_in(&lookalikes)
    );
}

/// `(line number, what it does)` of each line of `source`'s code that holds a forbidden
/// pattern or name, or names `signal` inside a `tokio::{…}` import group (one entry per
/// line).
fn violations_in(source: &str) -> Vec<(usize, &'static str)> {
    let code = source_scan::strip_comments(source);
    let mut found = std::collections::BTreeMap::new();
    for (index, line) in code.lines().enumerate() {
        let what = FORBIDDEN
            .iter()
            .find(|(pattern, _)| line.contains(pattern))
            .or_else(|| {
                FORBIDDEN_IDENTS
                    .iter()
                    .find(|(name, _)| contains_name(line, name))
            });
        if let Some((_, what)) = what {
            found.insert(index + 1, *what);
        }
    }
    for line in grouped_tokio_signal_lines(&code) {
        found.entry(line).or_insert(GROUPED_TOKIO_SIGNAL);
    }
    found.into_iter().collect()
}

/// Whether `name` occurs in `text` where an identifier starts and, when `name` ends with
/// an identifier character, where one ends.
fn contains_name(text: &str, name: &str) -> bool {
    text.match_indices(name)
        .any(|(at, _)| is_name_at(text, at, name))
}

fn is_name_at(text: &str, at: usize, name: &str) -> bool {
    let starts = !text[..at].chars().next_back().is_some_and(is_ident_char);
    let ends_identifier = name.chars().next_back().is_some_and(is_ident_char);
    let runs_on = ends_identifier
        && text[at + name.len()..]
            .chars()
            .next()
            .is_some_and(is_ident_char);
    starts && !runs_on
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The lines (1-based) on which a `tokio::{…}` import group, which may span several lines
/// and nest further groups, names `signal`.
fn grouped_tokio_signal_lines(code: &str) -> Vec<usize> {
    const GROUP: &str = "tokio::{";
    let mut lines = Vec::new();
    for (start, _) in code.match_indices(GROUP) {
        if !is_name_at(code, start, "tokio") {
            continue;
        }
        let body = start + GROUP.len();
        let mut depth = 1usize;
        let mut end = code.len();
        for (offset, c) in code[body..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let group = &code[body..end];
        for (at, _) in group.match_indices("signal") {
            if is_name_at(group, at, "signal") {
                lines.push(code[..body + at].matches('\n').count() + 1);
            }
        }
    }
    lines
}
