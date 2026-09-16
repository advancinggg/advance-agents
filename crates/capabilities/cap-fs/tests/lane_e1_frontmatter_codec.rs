#![cfg(feature = "lane-e1")]
//! Lane E1 — frontmatter parse / canonicalize / normalize.

use cap_fs::frontmatter::{
    canonicalize, normalize, parse_frontmatter, FrontmatterError, MAX_FRONTMATTER_BLOCK_BYTES,
    MAX_ITEMS_PER_FILE,
};
use cap_fs::meta_schema::{AutoRule, MetaSchema, MetaSchemaLoader};

fn schema() -> MetaSchema {
    let loader = MetaSchemaLoader::from_yaml(
        std::path::PathBuf::from("/nonexistent/meta-schema.yaml"),
        "optional:\n  status:\n    type: string\n  due:\n    type: string\n  priority:\n    type: integer\n    default: 0\n",
    )
    .expect("schema");
    (*loader.current()).clone()
}

struct Counter(u32);
impl cap_fs::frontmatter::IdSource for Counter {
    fn next_id(&mut self) -> String {
        self.0 += 1;
        format!("e-{:026}", self.0)
    }
}

const DOC: &str = "---\ntitle: Launch\ntype: project\nstatus: doing\nitems:\n  - title: b\n    type: work-item\n    status: todo\n  - type: event\n    title: a\n    starts: 2026-09-22T10:00:00+08:00\n---\n# body\n\nkeep me exactly\r\n";

#[test]
fn e1_parse_splits_block_from_body_at_byte_offset() {
    let (doc, body_offset) = parse_frontmatter(DOC.as_bytes())
        .expect("parses")
        .expect("has frontmatter");
    assert_eq!(&DOC[body_offset..], "# body\n\nkeep me exactly\r\n");
    assert_eq!(doc.items.len(), 2);
    assert!(parse_frontmatter(b"# no frontmatter\n").unwrap().is_none());
}

#[test]
fn e1_canonical_is_schema_ordered_and_idempotent() {
    let (doc, _) = parse_frontmatter(DOC.as_bytes()).unwrap().unwrap();
    let once = canonicalize(&doc, &schema());
    // Required keys first in schema order (id, type, title …), then declared optional fields
    // in declaration order, then undeclared keys alphabetically; items keep the same rule.
    let type_at = once.find("\ntype:").or_else(|| once.find("type:")).unwrap();
    let title_at = once.find("title:").unwrap();
    let status_at = once.find("status:").unwrap();
    assert!(type_at < title_at && title_at < status_at, "{once}");
    let (again, _) = parse_frontmatter(format!("---\n{once}---\n").as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        canonicalize(&again, &schema()),
        once,
        "canonical form is a fixed point"
    );
}

#[test]
fn e1_normalize_assigns_ids_validates_and_preserves_body() {
    let out = normalize(DOC.as_bytes(), &schema(), &mut Counter(0)).expect("normalize");
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.ends_with("---\n# body\n\nkeep me exactly\r\n"),
        "body bytes untouched: {text:?}"
    );
    assert_eq!(
        text.matches("id: e-").count(),
        3,
        "file + 2 items each got an id: {text}"
    );
    // Re-normalizing an already canonical document is a no-op (ids are kept, not reassigned).
    let again = normalize(text.as_bytes(), &schema(), &mut Counter(100)).unwrap();
    assert_eq!(again, text.as_bytes());

    let bad = DOC.replace("status: doing", "priority: high");
    let err = normalize(bad.as_bytes(), &schema(), &mut Counter(0)).unwrap_err();
    assert!(matches!(err, FrontmatterError::Schema(_)), "{err:?}");
}

#[test]
fn e1_items_are_one_level_and_bounded() {
    let nested = "---\ntype: project\nitems:\n  - type: work-item\n    items:\n      - type: work-item\n---\n";
    assert!(matches!(
        parse_frontmatter(nested.as_bytes()).unwrap_err(),
        FrontmatterError::NestingTooDeep
    ));
    let mut many = String::from("---\ntype: project\nitems:\n");
    for i in 0..=MAX_ITEMS_PER_FILE {
        many.push_str(&format!("  - type: work-item\n    title: t{i}\n"));
    }
    many.push_str("---\n");
    assert!(matches!(
        parse_frontmatter(many.as_bytes()).unwrap_err(),
        FrontmatterError::TooManyItems { .. }
    ));
}

#[test]
fn e1_block_size_and_alias_bomb_are_rejected() {
    let big = format!(
        "---\ntype: project\nnote: {}\n---\n",
        "x".repeat(MAX_FRONTMATTER_BLOCK_BYTES)
    );
    assert!(matches!(
        parse_frontmatter(big.as_bytes()).unwrap_err(),
        FrontmatterError::BlockTooLarge { .. }
    ));
    let bomb = "---\na: &a [x, x]\nb: *a\n---\n";
    assert!(matches!(
        parse_frontmatter(bomb.as_bytes()).unwrap_err(),
        FrontmatterError::AliasRejected
    ));
}

#[test]
fn e1_ulid_auto_rule_exists_and_is_deterministic_in_shape() {
    let s = MetaSchema::default();
    assert_eq!(
        s.required.get("id").map(|f| f.auto.clone()),
        Some(Some(AutoRule::Ulid)),
        "`id` is a required field auto-populated by the ulid rule"
    );
    let v = s
        .auto_generate("id", "x.md", b"---\ntype: document\n---\n")
        .unwrap();
    assert!(v.starts_with("e-") && v.len() == 28, "{v}");
}
