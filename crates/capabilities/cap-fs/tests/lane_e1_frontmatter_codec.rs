//! Lane E1 — frontmatter parse / canonicalize / normalize.
//! The schema is the shipped `packs/agenda` aspect file, so the codec is exercised against the
//! exact vocabulary the first-party pack declares (transitions, derive, ensure included).

use std::path::PathBuf;

use cap_fs::frontmatter::{
    canonicalize, normalize, parse_frontmatter, FrontmatterDoc, FrontmatterError, IdSource,
    MAX_FRONTMATTER_BLOCK_BYTES, MAX_ITEMS_PER_FILE,
};
use cap_fs::meta_schema::{AutoRule, MetaSchema, MetaSchemaLoader};
use chrono::{DateTime, Utc};

const AGENDA_YAML: &str =
    include_str!("../../../../packs/agenda/meta-schema-extensions/agenda.yaml");

fn schema() -> MetaSchema {
    let loader =
        MetaSchemaLoader::from_yaml(PathBuf::from("/nonexistent/meta-schema.yaml"), AGENDA_YAML)
            .expect("the shipped agenda aspect file parses with the v2 grammar");
    (*loader.current()).clone()
}

fn now() -> DateTime<Utc> {
    "2026-09-17T08:00:00Z".parse().unwrap()
}

struct Counter(u32);
impl IdSource for Counter {
    fn next_id(&mut self) -> String {
        self.0 += 1;
        format!("e-{:026}", self.0)
    }
}

fn doc(text: &str) -> FrontmatterDoc {
    parse_frontmatter(text.as_bytes())
        .expect("parses")
        .expect("has frontmatter")
        .0
}

const DOC: &str = "---\ntitle: Launch\ntype: project\nstatus: doing\nitems:\n  - title: b\n    type: work-item\n    status: todo\n  - type: meeting\n    title: a\n    starts: 2026-09-22T10:00:00+08:00\n---\n# body\n\nkeep me exactly\r\n";

#[test]
fn e1_parse_splits_block_from_body_at_byte_offset() {
    let (parsed, body_offset) = parse_frontmatter(DOC.as_bytes())
        .expect("parses")
        .expect("has frontmatter");
    assert_eq!(&DOC[body_offset..], "# body\n\nkeep me exactly\r\n");
    assert_eq!(parsed.items.len(), 2);
    assert!(parse_frontmatter(b"# no frontmatter\n").unwrap().is_none());
}

#[test]
fn e1_canonical_is_schema_ordered_and_idempotent() {
    let parsed = doc(DOC);
    let once = canonicalize(&parsed, &schema());
    // Required keys first in schema order (id, type, title …), then declared optional fields
    // in declaration order, then undeclared keys alphabetically; items keep the same rule.
    let type_at = once.find("type:").unwrap();
    let title_at = once.find("title:").unwrap();
    let status_at = once.find("status:").unwrap();
    assert!(type_at < title_at && title_at < status_at, "{once}");
    let again = doc(&format!("---\n{once}---\n"));
    assert_eq!(
        canonicalize(&again, &schema()),
        once,
        "canonical form is a fixed point"
    );
}

#[test]
fn e1_normalize_assigns_ids_validates_and_preserves_body() {
    let out =
        normalize(DOC.as_bytes(), None, &schema(), &mut Counter(0), now()).expect("normalize");
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
    let again = normalize(
        text.as_bytes(),
        Some(&doc(&text)),
        &schema(),
        &mut Counter(100),
        now(),
    )
    .unwrap();
    assert_eq!(again, text.as_bytes());

    let bad = DOC.replace("status: doing", "priority: high");
    let err = normalize(bad.as_bytes(), None, &schema(), &mut Counter(0), now()).unwrap_err();
    assert!(matches!(err, FrontmatterError::Schema(_)), "{err:?}");
}

#[test]
fn e1_normalize_checks_status_transitions_against_the_previous_document() {
    let previous = doc("---\nid: e-1\ntype: work-item\ntitle: t\nstatus: done\n---\n");
    let err = normalize(
        b"---\nid: e-1\ntype: work-item\ntitle: t\nstatus: doing\n---\n",
        Some(&previous),
        &schema(),
        &mut Counter(0),
        now(),
    )
    .unwrap_err();
    assert!(
        matches!(&err, FrontmatterError::Transition { field, from, to, .. } if field == "status" && from == "done" && to == "doing"),
        "done -> doing is not declared: {err:?}"
    );
    assert!(err.to_string().contains("transition"));
    // done -> todo is declared; a brand-new document (no previous) may start anywhere.
    normalize(
        b"---\nid: e-1\ntype: work-item\ntitle: t\nstatus: todo\n---\n",
        Some(&previous),
        &schema(),
        &mut Counter(0),
        now(),
    )
    .expect("declared transition");
    normalize(
        b"---\ntype: work-item\ntitle: t\nstatus: done\n---\n",
        None,
        &schema(),
        &mut Counter(0),
        now(),
    )
    .expect("new document");
}

#[test]
fn e1_normalize_derives_completed_at_from_status() {
    let out = normalize(
        b"---\ntype: work-item\ntitle: t\nstatus: done\n---\n",
        None,
        &schema(),
        &mut Counter(0),
        now(),
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("completed_at: 2026-09-17T08:00:00Z\n"),
        "derive fills completed_at with the injected now: {text}"
    );
    let reopened = normalize(
        text.replace("status: done", "status: todo").as_bytes(),
        Some(&doc(&text)),
        &schema(),
        &mut Counter(0),
        now(),
    )
    .unwrap();
    let reopened = String::from_utf8(reopened).unwrap();
    assert!(
        !reopened.contains("completed_at"),
        "`else: unset` clears it again: {reopened}"
    );
}

#[test]
fn e1_normalize_enforces_ensure_between_sibling_fields() {
    let bad = b"---\ntype: meeting\ntitle: m\nstarts: 2026-09-22T10:00:00Z\nends: 2026-09-22T09:00:00Z\n---\n";
    let err = normalize(bad, None, &schema(), &mut Counter(0), now()).unwrap_err();
    assert!(
        matches!(&err, FrontmatterError::Schema(m) if m.contains("ends")),
        "{err:?}"
    );
}

#[test]
fn e1_items_are_one_level_and_bounded() {
    let nested =
        "---\ntype: project\nitems:\n  - type: work-item\n    items:\n      - type: work-item\n---\n";
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
