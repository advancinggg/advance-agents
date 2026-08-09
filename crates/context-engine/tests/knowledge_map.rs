//! AC-16 — knowledge-map cap (T20: 3 caps + determinism + documented
//! drop-order + Trojan-Source sanitization sub-assertion).

use advance_context_engine::{
    build_knowledge_map_section, KnowledgeMap, KnowledgeTopic, TaskSynthesis,
};

/// `chars/4` rule-of-thumb (same as the crate's `chars_to_tokens`).
fn est_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

fn topic(name: &str, body: &str) -> KnowledgeTopic {
    KnowledgeTopic {
        name: name.into(),
        body: body.into(),
    }
}
fn synth(task: &str, body: &str) -> TaskSynthesis {
    TaskSynthesis {
        task_id: task.into(),
        body: body.into(),
    }
}

/// Canonical T20 fixture: 15 topics (~60 tok each: ~240-char bodies) + 8
/// syntheses (~200 tok each: ~800-char bodies). One topic carries a BiDi
/// override (U+202E) for the round-4 W5 sanitization sub-assertion.
fn fixture() -> KnowledgeMap {
    let topic_body = "x".repeat(236); // +name/punct ≈ 240 chars ≈ 60 tok
    let synth_body = "y".repeat(796); // ≈ 800 chars ≈ 200 tok
    let mut topics: Vec<KnowledgeTopic> = (0..15)
        .map(|i| topic(&format!("topic-{i}"), &topic_body))
        .collect();
    // Inject a Trojan-Source BiDi RIGHT-TO-LEFT OVERRIDE into topic 0's body.
    topics[0] = topic("topic-0", &format!("evil\u{202E}reversed {topic_body}"));
    let task_syntheses: Vec<TaskSynthesis> = (0..8)
        .map(|i| synth(&format!("task-{i}"), &synth_body))
        .collect();
    KnowledgeMap {
        topics,
        task_syntheses,
    }
}

#[test]
fn t20_three_caps_determinism_drop_order_and_sanitization() {
    let km = fixture();

    // (a) determinism — two calls byte-for-byte equal (the real precedence
    // proof: a fixed drop-order ⇒ identical output).
    let (s1, t1) = build_knowledge_map_section(&km, 5000);
    let (s2, t2) = build_knowledge_map_section(&km, 5000);
    assert_eq!(s1, s2, "non-deterministic output");
    assert_eq!(t1, t2);

    let (section, truncated) = (s1, t1);

    // (b) ≤ 500 tokens (effective_cap = min(5000,500) = 500), INCLUDING the
    // truncation marker.
    assert!(
        est_tokens(&section) <= 500,
        "section is {} tok, must be <= 500",
        est_tokens(&section)
    );

    // (c)/(d) count caps fired: at most 10 topic lines + at most 5 synthesis
    // lines (here the token cap is even tighter, but the count caps must not
    // be exceeded).
    let topic_lines = section
        .lines()
        .filter(|l| l.starts_with("- topic-"))
        .count();
    let synth_lines = section
        .lines()
        .filter(|l| l.starts_with("- [task-"))
        .count();
    assert!(
        topic_lines <= 10,
        "topic count cap (10) exceeded: {topic_lines}"
    );
    assert!(
        synth_lines <= 5,
        "synthesis count cap (5) exceeded: {synth_lines}"
    );
    assert!(topic_lines >= 1, "at least one topic should render");

    // (e) truncation marker present (15>10 count cap AND token cap bind).
    assert!(truncated, "truncated flag must be set");
    assert!(
        section.contains("(knowledge-map truncated)"),
        "truncation marker missing"
    );

    // (f) documented drop-order: syntheses are dropped BEFORE topics. The
    // topics exhaust the 500-tok budget here, so ZERO syntheses render — no
    // synthesis line may appear while topics were token-dropped.
    assert_eq!(
        synth_lines, 0,
        "syntheses must be dropped before topics under a tight budget"
    );

    // (g) round-4 W5: the BiDi override (U+202E) in topic-0 is neutralized
    // (sanitize_description substitutes it to a space) — never emitted raw.
    assert!(
        !section.contains('\u{202E}'),
        "BiDi RLO must be sanitized out of the knowledge-map section"
    );
}

/// Round-6 AUDIT Warning 1+2 regression lock: the "output never > cap
/// including the marker" invariant must hold for EVERY caller budget, not
/// just the `KNOWLEDGE_MAP_MAX_TOKENS=500` constant the assembler passes
/// today. Parametric sweep over a small range that covers the
/// previously-broken regime (budgets < header+marker tokens).
#[test]
fn cap_invariant_holds_for_every_budget() {
    let km = fixture();
    for budget in 0_usize..=600 {
        let (section, _truncated) = build_knowledge_map_section(&km, budget);
        let effective_cap = budget.min(500);
        let actual = est_tokens(&section);
        assert!(
            actual <= effective_cap,
            "cap violated at budget={budget}: effective_cap={effective_cap}, \
             section is {actual} tok, section starts: {:?}",
            section.chars().take(80).collect::<String>()
        );
    }
}

/// A small map well under all caps renders fully with NO truncation marker.
#[test]
fn small_map_not_truncated() {
    let km = KnowledgeMap {
        topics: vec![topic("t", "short")],
        task_syntheses: vec![synth("task-a", "brief")],
    };
    let (section, truncated) = build_knowledge_map_section(&km, 5000);
    assert!(!truncated);
    assert!(!section.contains("(knowledge-map truncated)"));
    assert!(section.contains("- t: short"));
    assert!(section.contains("- [task-a] brief"));
}
