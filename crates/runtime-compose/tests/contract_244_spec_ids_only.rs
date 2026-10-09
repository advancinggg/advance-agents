//! CONTRACT-244 — the runtime composition's sources cite public spec ids (an ADR date and its
//! D-numbers, `MODULE-…-AC-…`, `MODULE-…-T…`, `CONTRACT-…`, `SYS-AC-…`), never an internal
//! work-item label: the tag of a step, task, test leg or review item. Comments, strings,
//! identifiers and fixture text are all read; each hit names its file, line and token.
//!
//! Two sets of shapes (see [`labels_in`]):
//! - shapes no other code of the workspace uses: a lettered step, with or without its task
//!   number; a numbered task of a lettered step; a lettered build step; a dashed decision,
//!   review, error or unit-test item; an indexed step; a numbered leg after a SYS-AC id; the
//!   work's upper-case name; a design section. Read in every text file under `crates/` and
//!   `.github/`.
//! - also the short tags that older parts of the workspace still carry: a bare step, build
//!   step, review round, part, hold, unit or leg number; a SYS-AC test or helper named by its
//!   leg; a plan section; the work named as a lane. Read in this crate, the CONTRACT-210
//!   bridge, every MODULE-001-AC-30..34 and SYS-J-83 witness, and [`ADDED_ELSEWHERE`]. The
//!   composition files in [`OLDER_TAGS`] carry tags of that kind from before this contract
//!   and get the first set only.

use std::path::{Path, PathBuf};

/// Composition files that predate CONTRACT-244 and keep the workspace's older short tags.
const OLDER_TAGS: &[&str] = &[
    "crates/runtime-compose/src/auto_wiring.rs",
    "crates/runtime-compose/src/await_wiring.rs",
    "crates/runtime-compose/src/context_wiring.rs",
    "crates/runtime-compose/src/daemon/mod.rs",
    "crates/runtime-compose/src/lib.rs",
    "crates/runtime-compose/src/pack_bridges/mod.rs",
    "crates/runtime-compose/src/pack_production.rs",
    "crates/runtime-compose/src/pack_registry_client.rs",
    "crates/runtime-compose/src/pack_wiring.rs",
    "crates/runtime-compose/src/perchild_daemon.rs",
    "crates/runtime-compose/src/runnable_hook_factory.rs",
    "crates/runtime-compose/src/runnable_walk.rs",
    "crates/runtime-compose/src/wiring.rs",
];

/// Files CONTRACT-244 added outside its two crates whose names do not follow the
/// `module_001_ac3…` / `sys_j83_…` witness convention.
const ADDED_ELSEWHERE: &[&str] = &[
    "crates/capabilities/cap-llm/src/gateway/preflight_provider_tests.rs",
    "crates/capabilities/cap-llm/src/test_marker.rs",
    "crates/capabilities/cap-llm/src/vlm/catalog_tests.rs",
    "crates/capabilities/cap-mcp/src/test_marker.rs",
    "crates/cli/tests/support/live_daemon.rs",
    "crates/client-api/src/agents/admits_tests.rs",
    "crates/client-api/src/families.rs",
    "crates/client-api/src/listener_proof.rs",
    "crates/client-api/src/providers/read_view_tests.rs",
    "crates/client-api/tests/extension_families.rs",
    "crates/client-api/tests/in_process_admission.rs",
    "crates/client-api/tests/listener_retire.rs",
    "crates/client-api/tests/poll_stream.rs",
    "crates/client-api/tests/trust_model_comment.rs",
    "crates/runtime/src/capability_injector/call_typed_tests.rs",
    "crates/runtime/src/component_loader/pulley_tests.rs",
    "crates/runtime/src/process_probe.rs",
    "crates/shared-types/src/process_policy.rs",
];

/// Files the walk must reach: a smaller walk would pass without reading the sources.
const ANCHORS: &[&str] = &[
    "crates/runtime-compose/src/compose.rs",
    "crates/runtime-compose/tests/fixtures/spawn_sites.tsv",
    "crates/embedded-runtime-bridge/src/lib.rs",
    "crates/system-acceptance/tests/sys_j83_sys_ac_337_compose_journey.rs",
    ".github/workflows/ci.yml",
];

/// The text files the walk found when this check was written (fewer means it no longer sees
/// the workspace).
const MIN_FILES: usize = 1500;

#[test]
fn contract_244_sources_cite_spec_ids_not_work_item_labels() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for dir in ["crates", ".github"] {
        walk(&root.join(dir), &mut files);
    }
    let files: Vec<(String, String)> = files
        .into_iter()
        .filter_map(|path| {
            let bytes =
                std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let text = String::from_utf8(bytes)
                .ok()
                .filter(|t| !t.contains('\0'))?;
            let relative = path
                .strip_prefix(&root)
                .expect("under the workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            Some((relative, text))
        })
        .collect();
    for anchor in ANCHORS {
        assert!(
            files.iter().any(|(name, _)| name == anchor),
            "the walk must reach {anchor}"
        );
    }
    assert!(
        files.len() >= MIN_FILES,
        "expected at least {MIN_FILES} text files under crates/ and .github/, found {}",
        files.len()
    );
    for listed in OLDER_TAGS.iter().chain(ADDED_ELSEWHERE) {
        assert!(
            files.iter().any(|(name, _)| name == listed),
            "{listed} is listed here but no longer exists: update the list"
        );
    }

    let mut hits = Vec::new();
    for (name, text) in &files {
        let own = is_own(name) && !OLDER_TAGS.contains(&name.as_str());
        for (index, line) in text.lines().enumerate() {
            for (token, shape) in labels_in(line, own) {
                hits.push(format!("{name}:{}: {token:?} ({shape})", index + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "work-item labels where a spec id or a plain statement belongs:\n{}",
        hits.join("\n")
    );
}

/// The shapes themselves. Every label below is assembled from two pieces, so this file never
/// spells one.
#[test]
fn contract_244_label_shapes_flag_work_items_and_pass_spec_ids() {
    let everywhere = [
        concat!("S", "3c startup legs"),
        concat!("(S", "5a-11a desktop)"),
        concat!("owns it; S", "5a-9b"),
        concat!("C", "5c-4 adds"),
        concat!("# B", "7a: drives"),
        concat!("released (D", "-13)."),
        concat!("pinned by U", "-S1"),
        concat!("U", "-L1/U", "-L2"),
        concat!("expect(\"R", "-16 recovery\")"),
        concat!("IB", "4b consumes"),
        concat!("expect_err(\"E", "-1\")"),
        concat!("SYS-AC-338 M", "1, a registration refusal"),
        concat!("SYS-AC-337 L", "4: a turn"),
        concat!("RUNTIME", "-COMPOSE.review"),
        concat!("design", " §2.2"),
    ];
    for text in everywhere {
        assert!(!labels_in(text, false).is_empty(), "not flagged: {text}");
    }
    let own_only = [
        concat!("then S", "2's body"),
        concat!("(S", "4, 2026-07-29)"),
        concat!("helpers for B", "6 tests"),
        concat!("R", "9: legs"),
        concat!("(A", "8)"),
        concat!("\"G", "1 hold\""),
        concat!("\"U", "1 payload\""),
        concat!("leg (P", "2)"),
        concat!("refusal legs (M", "1)"),
        concat!("async fn sys_ac_337_l", "1_gates() {"),
        concat!("sys_ac_338_j83_m", "7_login"),
        concat!("assert_l", "3_read_families("),
        concat!("plan", " §1"),
        concat!("lane runtime", "-compose adds 1"),
    ];
    for text in own_only {
        assert!(labels_in(text, false).is_empty(), "flagged outside: {text}");
        assert!(!labels_in(text, true).is_empty(), "not flagged: {text}");
    }
    let spec_ids = [
        "MODULE-001-AC-31",
        "MODULE-001-T112 (a)",
        "MODULE-001-T113 (3) spawn-site CI gate",
        "ADR 2026-10-03 D3",
        "CONTRACT-244 D2(b)",
        "SYS-AC-337: a turn",
        "SYS-J-83",
        "MODULE-001 §1.4.7",
        "(Val::S8(_), Type::S8) | (Val::U8(_), Type::U8)",
        "after the L1 grant check; the L0 registry; M011 L6",
        "fn module_001_ac31_t112_d1_ext_event()",
        "fn module_001_ac31_t112c_l1_denied_call()",
        "fn sys_ac_337_j83_turn_routed_to_extension_inference_backend()",
        "fn sys_ac_337_journey_production_compose_fs_llm_home()",
        concat!("fn sys_ac_079_l", "1_full_skill_md_read()"),
        "spawn_named(\"l6-git-bridge\")",
        "0xB6, P256, U16, S32, A2A",
        "runtime-compose crate",
    ];
    for text in spec_ids {
        let hits = labels_in(text, false);
        assert!(hits.is_empty(), "{text}: {hits:?}");
        if !text.contains("sys_ac_079") {
            let hits = labels_in(text, true);
            assert!(hits.is_empty(), "{text}: {hits:?}");
        }
    }
}

/// Every file under `dir` but build output and hidden directories, sorted.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    let mut paths: Vec<(PathBuf, std::fs::FileType)> = entries
        .map(|entry| {
            let entry = entry.unwrap_or_else(|e| panic!("entry in {}: {e}", dir.display()));
            let kind = entry
                .file_type()
                .unwrap_or_else(|e| panic!("file_type {}: {e}", entry.path().display()));
            (entry.path(), kind)
        })
        .collect();
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, kind) in paths {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let hidden_or_build = name
            .as_deref()
            .is_some_and(|n| n == "target" || n == "node_modules" || n.starts_with('.'));
        if kind.is_dir() && !hidden_or_build {
            walk(&path, out);
        } else if kind.is_file() {
            out.push(path);
        }
    }
}

/// This contract's own files: its two crates, its witnesses by name, and [`ADDED_ELSEWHERE`].
fn is_own(name: &str) -> bool {
    let file = name.rsplit('/').next().unwrap_or(name);
    name.starts_with("crates/runtime-compose/")
        || name.starts_with("crates/embedded-runtime-bridge/")
        || file.starts_with("module_001_ac3")
        || file.starts_with("sys_j83_")
        || ADDED_ELSEWHERE.contains(&name)
}

/// The labels in `line`, each with the shape it has. `own` adds the short tags.
fn labels_in(line: &str, own: bool) -> Vec<(String, &'static str)> {
    let mut hits = Vec::new();
    for token in line
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|token| !token.is_empty())
    {
        let shape = if lettered_step(token) {
            Some("lettered step")
        } else if step_task(token) {
            Some("task of a lettered step")
        } else if lettered_build_step(token) {
            Some("lettered build step")
        } else if dashed_item(token) {
            Some("dashed item")
        } else if unit_test_tag(token) {
            Some("unit-test tag")
        } else if indexed_step(token) {
            Some("indexed step")
        } else if token.starts_with(concat!("RUNTIME", "-COMPOSE")) {
            Some("the work's name")
        } else if own && short_tag(token) {
            Some("short tag")
        } else if own && leg_identifier(token) {
            Some("leg in a test name")
        } else {
            None
        };
        if let Some(shape) = shape {
            hits.push((token.to_owned(), shape));
        }
    }
    if let Some(leg) = sys_ac_leg(line) {
        hits.push((leg, "SYS-AC leg"));
    }
    let mut phrases = vec![(concat!("design", " §"), "design section")];
    if own {
        phrases.push((concat!("plan", " §"), "plan section"));
        phrases.push((
            concat!("lane runtime", "-compose"),
            "the work named as a lane",
        ));
    }
    for (phrase, shape) in phrases {
        if line.contains(phrase) {
            hits.push((phrase.to_owned(), shape));
        }
    }
    hits
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// Digits and at most one trailing lower-case letter.
fn task_number(text: &str) -> bool {
    digits(
        text.strip_suffix(|c: char| c.is_ascii_lowercase())
            .unwrap_or(text),
    )
}

/// `S` + 2..=5 + a..=e, optionally `-` + a task number.
fn lettered_step(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() >= 3
        && b[0] == b'S'
        && (b'2'..=b'5').contains(&b[1])
        && (b'a'..=b'e').contains(&b[2])
        && (b.len() == 3 || token[3..].strip_prefix('-').is_some_and(task_number))
}

/// `C` + digits + a..=e + `-` + digits.
fn step_task(token: &str) -> bool {
    let Some((step, task)) = token
        .strip_prefix('C')
        .and_then(|rest| rest.split_once('-'))
    else {
        return false;
    };
    step.strip_suffix(|c: char| ('a'..='e').contains(&c))
        .is_some_and(digits)
        && digits(task)
}

/// `B` + one digit + one lower-case letter.
fn lettered_build_step(token: &str) -> bool {
    matches!(token.as_bytes(), [b'B', d, l] if d.is_ascii_digit() && l.is_ascii_lowercase())
}

/// `D-`, `R-` or `E-` + digits.
fn dashed_item(token: &str) -> bool {
    ["D-", "R-", "E-"]
        .iter()
        .any(|prefix| token.strip_prefix(prefix).is_some_and(digits))
}

/// `U-` + one upper-case letter, optionally + one digit.
fn unit_test_tag(token: &str) -> bool {
    match token.strip_prefix("U-").map(str::as_bytes) {
        Some([letter]) => letter.is_ascii_uppercase(),
        Some([letter, digit]) => letter.is_ascii_uppercase() && digit.is_ascii_digit(),
        _ => false,
    }
}

/// `IB` + one digit, optionally + one lower-case letter.
fn indexed_step(token: &str) -> bool {
    matches!(
        token.strip_prefix("IB").map(str::as_bytes),
        Some([d]) if d.is_ascii_digit()
    ) || matches!(
        token.strip_prefix("IB").map(str::as_bytes),
        Some([d, l]) if d.is_ascii_digit() && l.is_ascii_lowercase()
    )
}

/// One upper-case letter and a number: `S` + 2..=5; `B`, `G` or `P` + one digit; `U` or `M`
/// + 1..=7; `R` or `A` + digits.
fn short_tag(token: &str) -> bool {
    match token.as_bytes() {
        [b'S', d] => (b'2'..=b'5').contains(d),
        [b'B' | b'G' | b'P', d] => d.is_ascii_digit(),
        [b'U' | b'M', d] => (b'1'..=b'7').contains(d),
        [b'R' | b'A', rest @ ..] => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// A SYS-AC test or helper named by a lettered leg: `sys_ac_<n>_[j<n>_]<l|m><d>…` or
/// `assert_<l|m><d>…`.
fn leg_identifier(token: &str) -> bool {
    fn leg(rest: &str) -> bool {
        matches!(rest.as_bytes(), [b'l' | b'm', d, tail @ ..]
            if d.is_ascii_digit() && tail.first().is_none_or(|c| !c.is_ascii_alphanumeric()))
    }
    if let Some(rest) = token.strip_prefix("assert_") {
        return leg(rest);
    }
    let Some((number, rest)) = token
        .strip_prefix("sys_ac_")
        .and_then(|rest| rest.split_once('_'))
    else {
        return false;
    };
    let rest = match rest.strip_prefix('j').and_then(|r| r.split_once('_')) {
        Some((journey, after)) if digits(journey) => after,
        _ => rest,
    };
    digits(number) && leg(rest)
}

/// `SYS-AC-<n> L<d>` or `SYS-AC-<n> M<d>`, a leg number after a SYS-AC id.
fn sys_ac_leg(line: &str) -> Option<String> {
    let mut rest = line;
    while let Some(at) = rest.find("SYS-AC-") {
        let after = &rest[at + "SYS-AC-".len()..];
        let number_len = after.bytes().take_while(u8::is_ascii_digit).count();
        let tail = &after[number_len..];
        if number_len > 0 {
            if let [b' ', b'L' | b'M', d, more @ ..] = tail.as_bytes() {
                if d.is_ascii_digit() && more.first().is_none_or(|c| !c.is_ascii_alphanumeric()) {
                    return Some(format!("SYS-AC-{}", &after[..number_len + 3]));
                }
            }
        }
        rest = after;
    }
    None
}
