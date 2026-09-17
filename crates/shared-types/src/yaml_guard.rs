//! Pre-parse guards for YAML documents that come from untrusted sources (pack manifests,
//! frontmatter blocks): reject alias references (libyml does not bound alias expansion — a
//! billion-laughs document balloons during `from_str`, before any post-parse cap can fire)
//! and bound nesting depth (deeply nested flow collections cost minutes per MiB to parse).
//!
//! Both checks are byte scans: no allocation proportional to the input, no parsing.

/// Maximum flow-collection nesting (`[`/`{`) and block indentation depth accepted.
pub const MAX_YAML_NESTING: usize = 64;

/// `true` if the text contains what looks like a YAML alias reference (`*name`).
///
/// A `*` followed by an ASCII identifier byte, `-`, or any non-ASCII byte counts. Quoted
/// strings that legitimately contain `*x` are a documented false positive: the flat documents
/// this runtime accepts have no need for anchors or aliases.
pub fn yaml_has_alias_refs(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next.is_ascii_alphanumeric() || next == b'_' || next == b'-' || !next.is_ascii() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `true` if flow nesting and leading-indentation depth both stay within
/// [`MAX_YAML_NESTING`].
pub fn yaml_nesting_within_bound(text: &str) -> bool {
    let mut flow_depth: usize = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for line in text.split_inclusive('\n') {
        // Indentation depth (two-space units is the common style; count raw spaces / 2 and
        // tabs as a unit each, generously).
        let indent = line
            .bytes()
            .take_while(|b| *b == b' ' || *b == b'\t')
            .count();
        if indent / 2 > MAX_YAML_NESTING {
            return false;
        }
        for b in line.bytes() {
            if in_double {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_double = false;
                }
                continue;
            }
            if in_single {
                if b == b'\'' {
                    in_single = false;
                }
                continue;
            }
            match b {
                b'"' => in_double = true,
                b'\'' => in_single = true,
                b'#' => break,
                b'[' | b'{' => {
                    flow_depth += 1;
                    if flow_depth > MAX_YAML_NESTING {
                        return false;
                    }
                }
                b']' | b'}' => flow_depth = flow_depth.saturating_sub(1),
                _ => {}
            }
        }
        // A quoted scalar cannot span lines in the flat documents we accept; reset.
        in_single = false;
        in_double = false;
        escaped = false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_refs() {
        assert!(yaml_has_alias_refs("a: &a [x]\nb: *a\n"));
        assert!(yaml_has_alias_refs("b: *kebab-name\n"));
        assert!(!yaml_has_alias_refs("a: 2 * 3\n"));
        assert!(!yaml_has_alias_refs("a: 2 ** 3\n"));
        // Documented false positive: `*x` inside a quoted scalar still counts.
        assert!(yaml_has_alias_refs("note: '**bold**'\n"));
    }

    #[test]
    fn nesting_bound() {
        assert!(yaml_nesting_within_bound("a:\n  b:\n    c: [1, {d: 2}]\n"));
        let deep = "a: ".to_string() + &"[".repeat(MAX_YAML_NESTING + 1);
        assert!(!yaml_nesting_within_bound(&deep));
        let quoted = format!("a: \"{}\"\n", "[".repeat(MAX_YAML_NESTING + 5));
        assert!(
            yaml_nesting_within_bound(&quoted),
            "brackets inside quotes do not nest"
        );
        let indented = " ".repeat((MAX_YAML_NESTING + 1) * 2) + "x: 1\n";
        assert!(!yaml_nesting_within_bound(&indented));
    }
}
