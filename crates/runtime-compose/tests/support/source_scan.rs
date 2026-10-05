//! Reading `crates/runtime-compose/src` for the source gates: the files, their code without
//! comments (string and char literals kept), and their production code (also without the
//! `#[cfg(test)]` items).
//!
//! Included by each gate binary: `#[path = "support/source_scan.rs"] mod source_scan;`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The crate's `src` directory.
pub fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `dir`, sorted, as (path, path relative to `dir` with `/`).
pub fn rust_files(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    collect(dir, &mut files);
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let relative = file
                .strip_prefix(dir)
                .expect("under the walked directory")
                .to_string_lossy()
                .replace('\\', "/");
            (file, relative)
        })
        .collect()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// What a character of a source file belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Code,
    /// A string, raw-string, byte-string or char literal (delimiters included).
    Literal,
    Comment,
}

/// `source` with every comment replaced by spaces (newlines kept, so line numbers hold).
/// A comment marker inside a literal does not start a comment.
pub fn strip_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    render(&chars, &classify(&chars))
}

/// [`strip_comments`], and every item under a `#[cfg(test)]` attribute (a test module, a
/// test-only function) blanked out as well.
pub fn production_code(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut parts = classify(&chars);
    let marker: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut i = 0;
    while i + marker.len() <= chars.len() {
        let is_marker = chars[i..i + marker.len()] == marker[..]
            && parts[i..i + marker.len()].iter().all(|p| *p == Part::Code);
        if !is_marker {
            i += 1;
            continue;
        }
        // The item ends at its first `;` or at the `}` matching its first `{` (or before
        // the `}` that closes the block it sits in).
        let mut end = i + marker.len();
        let mut depth = 0usize;
        while end < chars.len() {
            if parts[end] == Part::Code {
                match chars[end] {
                    '{' => depth += 1,
                    '}' if depth == 0 => break,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end += 1;
                            break;
                        }
                    }
                    ';' if depth == 0 => {
                        end += 1;
                        break;
                    }
                    _ => {}
                }
            }
            end += 1;
        }
        let end = end.min(chars.len());
        for part in &mut parts[i..end] {
            *part = Part::Comment;
        }
        i = end;
    }
    render(&chars, &parts)
}

fn render(chars: &[char], parts: &[Part]) -> String {
    chars
        .iter()
        .zip(parts)
        .map(|(c, part)| match part {
            Part::Comment if *c != '\n' => ' ',
            _ => *c,
        })
        .collect()
}

fn classify(chars: &[char]) -> Vec<Part> {
    let mut parts = vec![Part::Code; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let start = i;
        let part = if c == '/' && next == Some('/') {
            // Line comment (`//`, `///`, `//!`).
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            Part::Comment
        } else if c == '/' && next == Some('*') {
            // Block comment, nested.
            let mut depth = 0usize;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            Part::Comment
        } else if let Some(hashes) = raw_string_start(chars, i) {
            // `r"…"` / `r#"…"#` (also after a `b`): ends at `"` + the same number of `#`.
            i += 2 + hashes;
            while i < chars.len() {
                if chars[i] == '"' && (1..=hashes).all(|k| chars.get(i + k) == Some(&'#')) {
                    i += 1 + hashes;
                    break;
                }
                i += 1;
            }
            Part::Literal
        } else if c == '"' {
            // String or byte string: ends at an unescaped `"`.
            i += 1;
            while i < chars.len() {
                match chars[i] {
                    '\\' => i += 2,
                    '"' => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            Part::Literal
        } else if c == '\'' && next == Some('\\') {
            // Escaped char literal (`'\n'`, `'\''`, `'\u{…}'`).
            i += 2;
            while i < chars.len() {
                match chars[i] {
                    '\\' => i += 2,
                    '\'' => {
                        i += 1;
                        break;
                    }
                    _ => i += 1,
                }
            }
            Part::Literal
        } else if c == '\'' && chars.get(i + 2) == Some(&'\'') {
            // Plain char literal; a lone `'` is a lifetime or a label.
            i += 3;
            Part::Literal
        } else {
            i += 1;
            Part::Code
        };
        let end = i.min(chars.len());
        for slot in &mut parts[start..end] {
            *slot = part;
        }
    }
    parts
}

/// The number of `#`s when a raw string starts at `i` (`r`, then `#`s, then `"`), unless the
/// `r` ends an identifier.
fn raw_string_start(chars: &[char], i: usize) -> Option<usize> {
    if chars[i] != 'r' {
        return None;
    }
    // `r` after an identifier character is part of that identifier, except a lone `b`
    // prefix (`br"…"`).
    if i > 0 && is_ident_char(chars[i - 1]) {
        let byte_prefix = chars[i - 1] == 'b' && (i < 2 || !is_ident_char(chars[i - 2]));
        if !byte_prefix {
            return None;
        }
    }
    let mut hashes = 0;
    while chars.get(i + 1 + hashes) == Some(&'#') {
        hashes += 1;
    }
    (chars.get(i + 1 + hashes) == Some(&'"')).then_some(hashes)
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
