//! MODULE-001-T113 (3) spawn-site CI gate: crate-set closure, site discovery, class checks.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

const NEEDLES: &[&str] = &[
    "Command::new(",
    "Command::from(",
    "posix_spawn",
    "libc::fork",
    "libc::vfork",
    "libc::exec",
    "libc::system(",
    "libc::popen",
    ".exec()",
];

const MIN_SITES: usize = 25;
const MIN_CRATES: usize = 31;

const REQUIRED_CLASSES: &[&str] = &[
    "policy-checked",
    "test-only",
    "separate-binary",
    "unreachable-from-compose",
    "build-tool",
    "v1-only",
    "types-only",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SiteKey {
    pub path: String,
    pub line: String,
    pub occurrence: usize,
}

#[derive(Clone, Debug)]
pub struct ListRow {
    pub key: SiteKey,
    pub class: String,
    pub note: String,
    pub unreached: Vec<String>,
    pub allow: Vec<String>,
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

pub fn assert_list() {
    let root = repo_root();
    let crates = crate_set(&root).unwrap_or_else(|e| panic!("{e}"));
    let relative_crates: Vec<String> = crates.iter().map(|p| rel(&root, p)).collect();
    assert!(
        crates.len() >= MIN_CRATES,
        "crate set has {} crates (need ≥ {MIN_CRATES}):\n{}",
        crates.len(),
        relative_crates.join("\n")
    );

    let files = rust_files(&crates);
    let test_only_files = collect_test_only_files(&root, &files);
    let sites = discover_sites(&root, &files);
    let process_api = process_api_files(&files);
    let listed = parse_tsv(&read_tsv(&root));

    let found_keys: BTreeSet<SiteKey> = sites.iter().cloned().collect();
    let listed_site_keys: BTreeSet<SiteKey> = listed
        .iter()
        .filter(|row| row.class != "types-only")
        .map(|row| row.key.clone())
        .collect();

    let missing: Vec<&SiteKey> = found_keys.difference(&listed_site_keys).collect();
    let stale: Vec<&SiteKey> = listed_site_keys.difference(&found_keys).collect();
    if !missing.is_empty() || !stale.is_empty() {
        let mut msg = String::from("spawn-site list drifted\n");
        if !missing.is_empty() {
            msg.push_str("missing (ready to paste):\n");
            for key in &missing {
                msg.push_str(&format!(
                    "{}\t{}\t{}\tCLASS\tNOTE\n",
                    key.path, key.line, key.occurrence
                ));
            }
        }
        if !stale.is_empty() {
            msg.push_str("stale:\n");
            for key in &stale {
                msg.push_str(&format!("{}\t{}\t{}\n", key.path, key.line, key.occurrence));
            }
        }
        msg.push_str(&format!(
            "crate set ({}):\n{}",
            crates.len(),
            relative_crates.join("\n")
        ));
        panic!("{msg}");
    }

    assert!(
        found_keys.len() >= MIN_SITES,
        "found {} sites (need ≥ {MIN_SITES})",
        found_keys.len()
    );

    let mut classes: BTreeSet<&str> = BTreeSet::new();
    for row in &listed {
        classes.insert(row.class.as_str());
        check_class(&root, &files, &test_only_files, row);
        if row.class == "types-only" {
            assert!(
                !found_keys.contains(&row.key),
                "{} is types-only but has a site",
                row.key.path
            );
        }
    }
    for required in REQUIRED_CLASSES {
        assert!(
            classes.contains(required),
            "missing class {required} (have {classes:?})"
        );
    }

    for file in &process_api {
        let rel = rel(&root, file);
        let has_row = listed.iter().any(|row| row.key.path == rel);
        assert!(
            has_row,
            "process-API file {rel} has no list row\ncrate set:\n{}",
            relative_crates.join("\n")
        );
    }
}

pub fn self_test() {
    let a = "#[cfg(test)]\nuse x::Y;\n\nfn prod() {\n    let c = Command::new(\"x\");\n}\n";
    let a_sites = sites_in("src/lib.rs", a);
    assert_eq!(a_sites.len(), 1);
    assert!(
        !is_test_only_site("src/lib.rs", a, &a_sites[0], &HashSet::new()),
        "production Command::new after a cfg(test) use is not test-only"
    );

    let b =
        "#[cfg(test)]\nmod tests {\n    fn t() {\n        let c = Command::new(\"x\");\n    }\n}\n";
    let b_sites = sites_in("src/lib.rs", b);
    assert_eq!(b_sites.len(), 1);
    assert!(is_test_only_site(
        "src/lib.rs",
        b,
        &b_sites[0],
        &HashSet::new()
    ));

    let mods = module_files(Path::new("crates/demo/src/lib.rs"), "tests");
    assert!(mods.iter().any(|p| p.ends_with("src/tests.rs")));
    assert!(mods.iter().any(|p| p.ends_with("src/tests/mod.rs")));

    let d = "#[cfg(test)]\nmod tests {\n    fn t() {\n        let _ = \"{\";\n        let _ = '}';\n        // }\n        let c = Command::new(\"x\");\n    }\n}\n";
    let d_sites = sites_in("src/lib.rs", d);
    assert_eq!(d_sites.len(), 1);
    assert!(
        is_test_only_site("src/lib.rs", d, &d_sites[0], &HashSet::new()),
        "string/comment braces must not close the test module"
    );

    let e = "fn a() { p.admit(SpawnSite::X) }\nfn b() { Command::new(\"y\") }\n";
    let e_sites = sites_in("src/x.rs", e);
    assert_eq!(e_sites.len(), 1);
    let e_line = line_index_of_occurrence(e, &e_sites[0].line, e_sites[0].occurrence);
    assert!(
        !policy_checked(&blank(e), e_line, "admit(SpawnSite::X)"),
        "b's site fails policy-checked"
    );

    let err = parse_manifest_deps(
        Path::new("/tmp/crate/Cargo.toml"),
        "[package]\nname = \"x\"\n[dependencies.foo]\npath = \"../foo\"\n",
    )
    .expect_err("table header");
    assert!(err.contains("dependencies.foo"), "{err}");

    let g = "fn f() { McpClient::new_with_transports(); }\n";
    assert!(!blanked_has_ident(&blank(g), "new"));
    assert!(blanked_has_ident(&blank(g), "new_with_transports"));
}

fn read_tsv(root: &Path) -> String {
    let path = root.join("crates/runtime-compose/tests/fixtures/spawn_sites.tsv");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn parse_tsv(text: &str) -> Vec<ListRow> {
    let mut rows = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        assert!(
            cols.len() >= 5,
            "tsv line {}: need path, line, occurrence, class, note",
            i + 1
        );
        let occurrence: usize = cols[2]
            .parse()
            .unwrap_or_else(|_| panic!("tsv line {}: occurrence", i + 1));
        let mut unreached = Vec::new();
        let mut allow = Vec::new();
        for extra in &cols[5..] {
            if let Some(rest) = extra.strip_prefix("unreached=") {
                unreached.extend(
                    rest.split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                );
            } else if let Some(rest) = extra.strip_prefix("allow=") {
                allow.extend(
                    rest.split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                );
            } else {
                panic!("tsv line {}: unknown field {extra}", i + 1);
            }
        }
        rows.push(ListRow {
            key: SiteKey {
                path: cols[0].to_string(),
                line: cols[1].to_string(),
                occurrence,
            },
            class: cols[3].to_string(),
            note: cols[4].to_string(),
            unreached,
            allow,
        });
    }
    rows
}

fn crate_set(root: &Path) -> Result<Vec<PathBuf>, String> {
    let starts = [
        root.join("crates/runtime-compose/Cargo.toml"),
        root.join("crates/embedded-runtime-bridge/Cargo.toml"),
    ];
    let mut seen = BTreeSet::new();
    let mut stack: Vec<PathBuf> = starts
        .into_iter()
        .map(|m| m.parent().expect("manifest dir").to_path_buf())
        .collect();
    while let Some(dir) = stack.pop() {
        let canon = dir
            .canonicalize()
            .map_err(|e| format!("canonicalize {}: {e}", dir.display()))?;
        if !seen.insert(canon.clone()) {
            continue;
        }
        let manifest = canon.join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest)
            .map_err(|e| format!("read {}: {e}", manifest.display()))?;
        for dep in parse_manifest_deps(&manifest, &text)? {
            stack.push(dep);
        }
    }
    Ok(seen.into_iter().collect())
}

fn parse_manifest_deps(manifest: &Path, text: &str) -> Result<Vec<PathBuf>, String> {
    let dir = manifest.parent().expect("manifest dir");
    let mut in_deps = false;
    let mut deps = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let stripped = strip_toml_comment(raw);
        let trimmed = stripped.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let header = &trimmed[1..trimmed.len() - 1];
            if header.starts_with("dependencies.") {
                return Err(format!(
                    "{}:{}: [dependencies.<name>] table header {header:?} is refused",
                    manifest.display(),
                    i + 1
                ));
            }
            in_deps = header == "dependencies"
                || (header.starts_with("target.") && header.ends_with(".dependencies"));
            continue;
        }
        if !in_deps {
            continue;
        }
        if let Some(rel) = path_from_dep_line(trimmed) {
            deps.push(dir.join(rel));
        }
    }
    Ok(deps)
}

fn strip_toml_comment(line: &str) -> String {
    let mut out = String::new();
    let mut in_str = false;
    for c in line.chars() {
        if c == '"' {
            in_str = !in_str;
            out.push(c);
        } else if c == '#' && !in_str {
            break;
        } else {
            out.push(c);
        }
    }
    out
}

fn path_from_dep_line(line: &str) -> Option<String> {
    let eq = line.find('=')?;
    let rhs = line[eq + 1..].trim();
    if !rhs.starts_with('{') {
        return None;
    }
    let mut i = 0;
    let bytes = rhs.as_bytes();
    while i + 4 < bytes.len() {
        if rhs[i..].starts_with("path") {
            let rest = rhs[i + 4..].trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('"') {
                    let end = rest.find('"')?;
                    return Some(rest[..end].to_string());
                }
            }
        }
        i += 1;
    }
    None
}

fn rust_files(crates: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for crate_dir in crates {
        let src = crate_dir.join("src");
        if src.is_dir() {
            collect_rs(&src, &mut files);
        }
    }
    files.sort();
    files
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn discover_sites(root: &Path, files: &[PathBuf]) -> Vec<SiteKey> {
    let mut sites = Vec::new();
    for file in files {
        let raw = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        sites.extend(sites_in(&rel(root, file), &raw));
    }
    sites
}

fn sites_in(path: &str, raw: &str) -> Vec<SiteKey> {
    let blanked = blank(raw);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut sites = Vec::new();
    for (raw_line, blank_line) in raw.lines().zip(blanked.lines()) {
        if NEEDLES.iter().any(|n| blank_line.contains(n)) {
            let trimmed = raw_line.trim().to_string();
            let occurrence = counts.entry(trimmed.clone()).or_insert(0);
            *occurrence += 1;
            sites.push(SiteKey {
                path: path.to_string(),
                line: trimmed,
                occurrence: *occurrence,
            });
        }
    }
    sites
}

fn process_api_files(files: &[PathBuf]) -> Vec<PathBuf> {
    files
        .iter()
        .filter(|file| {
            let raw = std::fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
            is_process_api(&blank(&raw))
        })
        .cloned()
        .collect()
}

fn is_process_api(blanked: &str) -> bool {
    if blanked.contains("tokio::process") || blanked.contains("std::process::Command") {
        return true;
    }
    let mut rest = blanked;
    while let Some(at) = rest.find("std::process::{") {
        let after = &rest[at + "std::process::{".len()..];
        if let Some(end) = after.find('}') {
            let inside = &after[..end];
            if ident_tokens(inside)
                .iter()
                .any(|t| t == "Command" || t == "Child")
            {
                return true;
            }
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    false
}

fn collect_test_only_files(root: &Path, files: &[PathBuf]) -> HashSet<String> {
    let mut out = HashSet::new();
    for file in files {
        let raw = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for name in declared_test_modules(&raw) {
            for candidate in module_files(file, &name) {
                if candidate.is_file() {
                    out.insert(rel(root, &candidate));
                }
            }
        }
    }
    out
}

fn declared_test_modules(raw: &str) -> Vec<String> {
    let blanked = blank(raw);
    cfg_test_regions(&blanked)
        .into_iter()
        .filter_map(|region| match region {
            CfgRegion::ModDecl { name } => Some(name),
            _ => None,
        })
        .collect()
}

enum CfgRegion {
    Span { start_line: usize, end_line: usize },
    ModDecl { name: String },
    Lines { start_line: usize, end_line: usize },
}

fn cfg_test_regions(blanked: &str) -> Vec<CfgRegion> {
    let lines: Vec<&str> = blanked.lines().collect();
    let mut regions = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        if !is_cfg_test_attr(trimmed) {
            i += 1;
            continue;
        }
        let attr_line = i;
        let mut j = i + 1;
        while j < lines.len() {
            let t = lines[j].trim();
            if t.is_empty() || t.starts_with("#[") {
                j += 1;
                continue;
            }
            break;
        }
        if j >= lines.len() {
            i += 1;
            continue;
        }
        let (ch, offset) = first_brace_or_semi(&lines, j);
        match ch {
            '{' => {
                let end = match_brace_line(&lines, offset);
                regions.push(CfgRegion::Span {
                    start_line: attr_line,
                    end_line: end,
                });
            }
            ';' => {
                let item = lines[j..=offset.0].join("\n");
                if let Some(name) = mod_decl_name(&item) {
                    regions.push(CfgRegion::ModDecl { name });
                } else {
                    regions.push(CfgRegion::Lines {
                        start_line: attr_line,
                        end_line: offset.0,
                    });
                }
            }
            _ => {}
        }
        i = attr_line + 1;
    }
    regions
}

fn is_cfg_test_attr(trimmed: &str) -> bool {
    trimmed == "#[cfg(test)]" || (trimmed.starts_with("#[cfg(all(test,") && trimmed.ends_with(")]"))
}

fn first_brace_or_semi(lines: &[&str], start: usize) -> (char, (usize, usize)) {
    let mut paren = 0i32;
    let mut bracket = 0i32;
    for (li, line) in lines.iter().enumerate().skip(start) {
        for (ci, c) in line.char_indices() {
            match c {
                '(' => paren += 1,
                ')' => paren -= 1,
                '[' => bracket += 1,
                ']' => bracket -= 1,
                '{' | ';' if paren == 0 && bracket == 0 => return (c, (li, ci)),
                _ => {}
            }
        }
    }
    ('\0', (start, 0))
}

fn match_brace_line(lines: &[&str], start: (usize, usize)) -> usize {
    let mut depth = 0i32;
    for (li, line) in lines.iter().enumerate().skip(start.0) {
        let chars: String = if li == start.0 {
            line[start.1..].to_string()
        } else {
            (*line).to_string()
        };
        for c in chars.chars() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return li;
                    }
                }
                _ => {}
            }
        }
    }
    lines.len().saturating_sub(1)
}

fn mod_decl_name(item: &str) -> Option<String> {
    let t = blank(item).replace('\n', " ");
    let idx = t.find("mod ")?;
    let rest = t[idx + 4..].trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    rest[name.len()..]
        .trim_start()
        .starts_with(';')
        .then_some(name)
}

fn module_files(declaring: &Path, name: &str) -> Vec<PathBuf> {
    let file_name = declaring.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let dir = if matches!(file_name, "lib.rs" | "main.rs" | "mod.rs") {
        declaring.parent().unwrap_or(declaring).to_path_buf()
    } else {
        let stem = declaring
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("x");
        declaring.parent().unwrap_or(declaring).join(stem)
    };
    vec![
        dir.join(format!("{name}.rs")),
        dir.join(name).join("mod.rs"),
    ]
}

fn is_test_only_site(path: &str, raw: &str, site: &SiteKey, extra_files: &HashSet<String>) -> bool {
    extra_files.contains(path)
        || extra_files.contains(&site.path)
        || in_test_only_region(
            &blank(raw),
            line_index_of_occurrence(raw, &site.line, site.occurrence),
        )
}

fn in_test_only_region(blanked: &str, line_idx: usize) -> bool {
    cfg_test_regions(blanked)
        .into_iter()
        .any(|region| match region {
            CfgRegion::Span {
                start_line,
                end_line,
            }
            | CfgRegion::Lines {
                start_line,
                end_line,
            } => line_idx >= start_line && line_idx <= end_line,
            CfgRegion::ModDecl { .. } => false,
        })
}

fn line_index_of_occurrence(raw: &str, trimmed: &str, occurrence: usize) -> usize {
    let mut seen = 0;
    for (i, line) in raw.lines().enumerate() {
        if line.trim() == trimmed {
            seen += 1;
            if seen == occurrence {
                return i;
            }
        }
    }
    panic!("missing occurrence {occurrence} of {trimmed}");
}

fn policy_checked(blanked: &str, site_line: usize, needle: &str) -> bool {
    let Some((fn_line, _)) = enclosing_fn(blanked, site_line) else {
        return false;
    };
    blanked
        .lines()
        .enumerate()
        .any(|(i, line)| i >= fn_line && i < site_line && line.contains(needle))
}

fn enclosing_fn(blanked: &str, site_line: usize) -> Option<(usize, usize)> {
    let lines: Vec<&str> = blanked.lines().collect();
    for i in (0..=site_line).rev() {
        if !fn_header_match(lines[i]) {
            continue;
        }
        let (ch, offset) = first_brace_or_semi(&lines, i);
        if ch != '{' {
            continue;
        }
        let end = match_brace_line(&lines, offset);
        if site_line >= i && site_line <= end {
            return Some((i, end));
        }
    }
    None
}

fn fn_header_match(line: &str) -> bool {
    let mut s = line.trim_start();
    if let Some(rest) = s.strip_prefix("pub") {
        s = rest;
        if let Some(rest) = s.strip_prefix('(') {
            let end = match rest.find(')') {
                Some(end) => end,
                None => return false,
            };
            let inner = &rest[..end];
            if !inner.chars().all(|c| c.is_ascii_lowercase()) {
                return false;
            }
            s = &rest[end + 1..];
        }
        s = s.trim_start();
    }
    if let Some(rest) = s.strip_prefix("const") {
        s = rest.trim_start();
    }
    if let Some(rest) = s.strip_prefix("async") {
        s = rest.trim_start();
    }
    if let Some(rest) = s.strip_prefix("unsafe") {
        s = rest.trim_start();
    }
    if let Some(rest) = s.strip_prefix("extern") {
        s = rest.trim_start();
        if !s.starts_with('"') {
            return false;
        }
        let end = match s[1..].find('"') {
            Some(end) => end,
            None => return false,
        };
        s = s[1 + end + 1..].trim_start();
    }
    s.starts_with("fn ") || s.starts_with("fn\t")
}

fn check_class(root: &Path, files: &[PathBuf], test_only_files: &HashSet<String>, row: &ListRow) {
    match row.class.as_str() {
        "policy-checked" => {
            let path = root.join(&row.key.path);
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let line_idx = line_index_of_occurrence(&raw, &row.key.line, row.key.occurrence);
            assert!(
                policy_checked(&blank(&raw), line_idx, &row.note),
                "{} occurrence {} is not guarded by {} in its enclosing fn",
                row.key.path,
                row.key.occurrence,
                row.note
            );
            check_unreached(root, files, row);
        }
        "test-only" => {
            let path = root.join(&row.key.path);
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            assert!(
                is_test_only_site(&row.key.path, &raw, &row.key, test_only_files),
                "{} occurrence {} is not in a test-only region",
                row.key.path,
                row.key.occurrence
            );
        }
        "test-support" => {
            assert!(
                is_test_support_path(&row.key.path),
                "{} is not src/test_support.rs or under src/test_support/",
                row.key.path
            );
            let crate_dir = crate_dir_of(root, &row.key.path);
            assert!(
                lib_declares_test_support(&crate_dir.join("src/lib.rs")),
                "{} crate does not declare mod test_support under #[cfg(feature = \"test-support\")]",
                row.key.path
            );
        }
        "separate-binary" => {
            assert!(
                is_separate_binary(&row.key.path),
                "{} is not src/main.rs or under src/bin/",
                row.key.path
            );
            let crate_dir = crate_dir_of(root, &row.key.path);
            assert!(
                !crate_names_main(&crate_dir, &row.key.path),
                "{} is named by a #[path] or mod main in the crate",
                row.key.path
            );
        }
        "unreachable-from-compose" | "build-tool" | "v1-only" => {
            assert!(
                !row.unreached.is_empty(),
                "{} needs unreached=",
                row.key.path
            );
            check_unreached(root, files, row);
        }
        "types-only" => {
            assert_eq!(row.key.occurrence, 0, "types-only occurrence is 0");
            assert_eq!(row.key.line, "*", "types-only line is *");
        }
        other => panic!("unknown class {other} for {}", row.key.path),
    }
}

fn check_unreached(root: &Path, files: &[PathBuf], row: &ListRow) {
    if row.unreached.is_empty() {
        return;
    }
    for file in files {
        let rel = rel(root, file);
        if row.allow.iter().any(|p| rel.starts_with(p.as_str())) {
            continue;
        }
        let raw = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let blanked = blank(&raw);
        for sym in &row.unreached {
            assert!(
                !blanked_has_ident(&blanked, sym),
                "{rel} names unreached symbol {sym} (row {} allow={:?})",
                row.key.path,
                row.allow
            );
        }
    }
}

fn is_test_support_path(path: &str) -> bool {
    path.ends_with("/src/test_support.rs") || path.contains("/src/test_support/")
}

fn lib_declares_test_support(lib: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(lib) else {
        return false;
    };
    let blanked = blank(&raw);
    let lines: Vec<&str> = blanked.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(feature = \"test-support\")]" {
            let mut j = i + 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() || t.starts_with("#[") {
                    j += 1;
                    continue;
                }
                return t.contains("mod test_support");
            }
        }
    }
    false
}

fn is_separate_binary(path: &str) -> bool {
    path.ends_with("/src/main.rs") || path.contains("/src/bin/")
}

fn crate_names_main(crate_dir: &Path, bin_path: &str) -> bool {
    let src = crate_dir.join("src");
    let mut files = Vec::new();
    if src.is_dir() {
        collect_rs(&src, &mut files);
    }
    let bin_name = Path::new(bin_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("main");
    for file in files {
        let rel = file
            .strip_prefix(crate_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if bin_path.ends_with(rel.as_str()) {
            continue;
        }
        let raw = std::fs::read_to_string(&file).unwrap_or_default();
        let blanked = blank(&raw);
        if ident_tokens(&blanked)
            .windows(2)
            .any(|w| w[0] == "mod" && w[1] == "main")
        {
            return true;
        }
        for line in blanked.lines() {
            if line.contains("#[path") && line.contains(bin_name) {
                return true;
            }
        }
    }
    false
}

fn crate_dir_of(root: &Path, rel_path: &str) -> PathBuf {
    let path = root.join(rel_path);
    let mut dir = path.parent().unwrap();
    while dir != root {
        if dir.join("Cargo.toml").is_file() {
            return dir.to_path_buf();
        }
        dir = dir.parent().unwrap();
    }
    panic!("no crate dir for {rel_path}");
}

fn ident_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_ascii_alphabetic() || c == '_' || (!cur.is_empty() && c.is_ascii_digit()) {
            cur.push(c);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn blanked_has_ident(blanked: &str, ident: &str) -> bool {
    ident_tokens(blanked).iter().any(|t| t == ident)
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Comments and the contents of string / byte-string / raw-string / char literals
/// become spaces; quotes and newlines stay, so line numbers hold.
pub fn blank(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = chars.clone();
    let mut i = 0;
    while i < n {
        if chars[i] == '/' && i + 1 < n && chars[i + 1] == '/' {
            i += 2;
            while i < n && chars[i] != '\n' {
                out[i] = ' ';
                i += 1;
            }
            continue;
        }
        if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
            out[i] = ' ';
            out[i + 1] = ' ';
            i += 2;
            let mut depth = 1;
            while i < n && depth > 0 {
                if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i += 2;
                    depth += 1;
                } else if chars[i] == '*' && i + 1 < n && chars[i + 1] == '/' {
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i += 2;
                    depth -= 1;
                } else {
                    if chars[i] != '\n' {
                        out[i] = ' ';
                    }
                    i += 1;
                }
            }
            continue;
        }
        if let Some(end) = take_string(&chars, i) {
            let mut keep = HashSet::new();
            mark_delimiters(&chars, i, end, &mut keep);
            for (k, slot) in out.iter_mut().enumerate().take(end).skip(i) {
                if keep.contains(&k) || chars[k] == '\n' {
                    continue;
                }
                *slot = ' ';
            }
            i = end;
            continue;
        }
        i += 1;
    }
    out.into_iter().collect()
}

fn ident_boundary(chars: &[char], i: usize) -> bool {
    i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_')
}

fn take_string(chars: &[char], i: usize) -> Option<usize> {
    let n = chars.len();
    if !ident_boundary(chars, i) {
        return take_quote(chars, i);
    }
    let mut k = i;
    if (chars[k] == 'b' || chars[k] == 'c') && k + 1 < n {
        k += 1;
    }
    if k < n && chars[k] == 'r' {
        let mut hashes = 0usize;
        let mut j = k + 1;
        while j < n && chars[j] == '#' {
            hashes += 1;
            j += 1;
        }
        if j < n && chars[j] == '"' {
            j += 1;
            while j < n {
                if chars[j] == '"' {
                    let mut h = 0;
                    let mut p = j + 1;
                    while h < hashes && p < n && chars[p] == '#' {
                        h += 1;
                        p += 1;
                    }
                    if h == hashes {
                        return Some(p);
                    }
                }
                j += 1;
            }
            return Some(n);
        }
    }
    take_quote(chars, i)
}

fn take_quote(chars: &[char], i: usize) -> Option<usize> {
    let n = chars.len();
    let mut k = i;
    if ident_boundary(chars, k) && k < n && (chars[k] == 'b' || chars[k] == 'c') && k + 1 < n {
        k += 1;
    }
    if k >= n {
        return None;
    }
    match chars[k] {
        '"' => {
            let mut j = k + 1;
            while j < n {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '"' {
                    return Some(j + 1);
                }
                j += 1;
            }
            Some(n)
        }
        '\'' => {
            let j = k + 1;
            if j >= n {
                return None;
            }
            if chars[j] == '\\' {
                let mut p = j + 1;
                while p < n && chars[p] != '\'' {
                    p += 1;
                }
                return (p < n).then_some(p + 1);
            }
            if j + 1 < n && chars[j + 1] == '\'' {
                return Some(j + 2);
            }
            None
        }
        _ => None,
    }
}

fn mark_delimiters(chars: &[char], start: usize, end: usize, keep: &mut HashSet<usize>) {
    for i in start..end.min(start + 8) {
        if matches!(chars[i], 'b' | 'c' | 'r' | '#' | '"' | '\'') {
            keep.insert(i);
        } else {
            break;
        }
    }
    if end > start {
        let mut i = end - 1;
        loop {
            if matches!(chars[i], '#' | '"' | '\'') {
                keep.insert(i);
            } else {
                break;
            }
            if i == start {
                break;
            }
            i -= 1;
        }
    }
}
