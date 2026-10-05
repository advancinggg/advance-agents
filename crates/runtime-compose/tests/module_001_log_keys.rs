//! MODULE-001-AC-30 — every line the composition emits carries a stable machine key, and
//! the catalogue (`log_keys::ALL`) is exactly the set of keys the production code emits.
//!
//! The scan reads every file under `src/` (production code: comments and `#[cfg(test)]`
//! items left out). An emission is a `.out(` / `.err(` call with arguments (the
//! composition's log handle; a key may sit on the next line, where rustfmt puts it) or a
//! `log.ready(` call (the readiness line, key `start.ready`). Every emission must name a
//! `log_keys::` constant, every constant it names must be in `ALL`, and every key of `ALL`
//! must be emitted somewhere.

#[path = "support/source_scan.rs"]
mod source_scan;

use std::collections::{BTreeMap, BTreeSet};

use advance_runtime_compose::log_keys;

/// The emissions the production code had when the catalogue was written: fewer means the
/// scan no longer sees them.
const MIN_EMISSIONS: usize = 58;

#[test]
fn module_001_ac30_log_keys_catalogue_is_exact() {
    let src = source_scan::src_dir();

    // The catalogue as written: each key constant and the names `ALL` lists, in order.
    let catalogue =
        std::fs::read_to_string(src.join("api/compose_log.rs")).expect("read the catalogue");
    let (constants, all) = parse_catalogue(&source_scan::strip_comments(&catalogue));
    let listed: Vec<&str> = all
        .iter()
        .map(|name| {
            constants
                .get(name)
                .unwrap_or_else(|| panic!("ALL lists {name}, which is not a key constant"))
                .as_str()
        })
        .collect();
    assert_eq!(
        listed,
        log_keys::ALL,
        "the parsed catalogue agrees with the compiled one"
    );
    let unlisted: Vec<&String> = constants
        .keys()
        .filter(|name| !all.contains(*name))
        .collect();
    assert!(
        unlisted.is_empty(),
        "key constants missing from ALL: {unlisted:?}"
    );

    // Every emission of the production code.
    let mut emitted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unkeyed = Vec::new();
    let mut emissions = 0;
    for (file, name) in source_scan::rust_files(&src) {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let code = source_scan::production_code(&text);
        for (offset, key) in emissions_in(&code) {
            let line = code[..offset].matches('\n').count() + 1;
            let site = format!("src/{name}:{line}");
            emissions += 1;
            match key {
                Some(key) => emitted.entry(key).or_default().push(site),
                None => unkeyed.push(site),
            }
        }
    }
    assert!(
        unkeyed.is_empty(),
        "emissions without a log_keys constant (every line needs a catalogued key): {unkeyed:?}"
    );
    let unknown: Vec<(&String, &Vec<String>)> = emitted
        .iter()
        .filter(|(key, _)| !all.contains(*key))
        .collect();
    assert!(
        unknown.is_empty(),
        "emitted keys missing from log_keys::ALL: {unknown:?}"
    );
    let unused: Vec<&String> = all
        .iter()
        .filter(|key| !emitted.contains_key(*key))
        .collect();
    assert!(
        unused.is_empty(),
        "catalogued keys no production code emits: {unused:?}"
    );
    assert!(
        emissions >= MIN_EMISSIONS,
        "expected at least {MIN_EMISSIONS} emissions, found {emissions}"
    );
}

/// The scan itself: a key on the next line is found, an argument-less `.err()` is not an
/// emission, an unkeyed one is reported, and test items are left out.
#[test]
fn module_001_ac30_log_keys_scan_finds_keys_across_lines_and_skips_tests() {
    let code = source_scan::production_code(
        "fn f(log: &LogHandle) {\n\
         \x20   log.out(log_keys::ONE, \"a\");\n\
         \x20   log.err(\n\
         \x20       log_keys::TWO,\n\
         \x20       format!(\"b\"),\n\
         \x20   );\n\
         \x20   let _ = result.err();\n\
         \x20   log.err(\"no key\", \"c\");\n\
         \x20   log.ready(\"d\");\n\
         }\n\
         #[cfg(test)]\n\
         mod tests {\n\
         \x20   fn g(log: &LogHandle) { log.out(log_keys::THREE, \"e\"); }\n\
         }\n",
    );
    let keys: Vec<Option<String>> = emissions_in(&code).into_iter().map(|(_, k)| k).collect();
    assert_eq!(
        keys,
        vec![
            Some("ONE".to_owned()),
            Some("TWO".to_owned()),
            None,
            Some("READY".to_owned()),
        ]
    );
}

/// `(offset, Some(key constant))` of each emission in `code`; `None` when the call names
/// no `log_keys::` constant.
fn emissions_in(code: &str) -> Vec<(usize, Option<String>)> {
    let mut found = Vec::new();
    for marker in [".out(", ".err("] {
        for (offset, _) in code.match_indices(marker) {
            let rest = code[offset + marker.len()..].trim_start();
            if rest.starts_with(')') {
                continue; // `Result::err()` and the like: not an emission.
            }
            found.push((offset, rest.strip_prefix("log_keys::").map(key_name)));
        }
    }
    for (offset, _) in code.match_indices("log.ready(") {
        found.push((offset, Some("READY".to_owned())));
    }
    found.sort();
    found
}

fn key_name(rest: &str) -> String {
    rest.chars()
        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
        .collect()
}

/// The `pub const NAME: &str = "value";` constants of `mod log_keys`, and the names its
/// `ALL` lists, in order.
fn parse_catalogue(code: &str) -> (BTreeMap<String, String>, Vec<String>) {
    let start = code
        .find("pub mod log_keys {")
        .expect("the catalogue module");
    let body = &code[start..];
    let mut constants = BTreeMap::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": &str = ") else {
            continue;
        };
        let value = value.trim_end_matches(';').trim_matches('"').to_owned();
        constants.insert(name.to_owned(), value);
    }
    let all_start = body.find("pub const ALL: &[&str] = &[").expect("ALL");
    let all_body = &body[all_start..];
    let all_end = all_body.find("];").expect("end of ALL");
    let all: Vec<String> = all_body[..all_end]
        .lines()
        .skip(1)
        .map(|line| line.trim().trim_end_matches(','))
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    let distinct: BTreeSet<&String> = all.iter().collect();
    assert_eq!(distinct.len(), all.len(), "ALL lists a key twice");
    (constants, all)
}
