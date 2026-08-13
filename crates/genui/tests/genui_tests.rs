use advance_genui::*;
use advance_genui::corpus::*;
use advance_genui::degrade::degrade_to_text;
use advance_genui::document::{validate_depth, A2uiVersion, ComponentNode, DocumentId, GenUiDocument, MAX_DOCUMENT_BYTES};
use serde_json::json;

fn gate(enabled: bool) -> GenUiGate {
    GenUiGate::new(enabled, MAX_DOCUMENT_BYTES, seed_catalog())
}

// T01: Valid corpus documents pass catalog validation (AC-01)
#[test]
fn t01_valid_corpus_renders_through_catalog() {
    let g = gate(true);
    for (i, doc) in corpus_valid_documents().iter().enumerate() {
        g.admit(doc).unwrap_or_else(|e| panic!("corpus doc {i} failed: {e}"));
    }
}

// T02: Catalog gate rejects invalid documents (AC-02)
#[test]
fn t02_catalog_gate_rejects_invalid() {
    let g = gate(true);
    for (doc, desc) in corpus_invalid_documents() {
        assert!(
            g.admit(&doc).is_err(),
            "expected rejection for: {desc}"
        );
    }
}

#[test]
fn t02_script_injection_rejected() {
    let g = gate(true);
    let doc = GenUiDocument {
        protocol_version: A2uiVersion::V0_9_1,
        document_id: DocumentId("xss-test".into()),
        root: vec![ComponentNode {
            component: "Text".into(),
            props: json!({"content": "<SCRIPT>alert('XSS')</SCRIPT>"}),
            children: vec![],
        }],
    };
    assert!(g.admit(&doc).is_err(), "case-insensitive script injection must be rejected");
}

// T04: Degradation produces expected text (AC-04)
#[test]
fn t04_degradation_corpus() {
    let catalog = seed_catalog();
    for (doc, expected) in corpus_degradation_vectors() {
        let text = degrade_to_text(&doc, &catalog);
        assert_eq!(text, expected, "degradation mismatch for doc {:?}", doc.document_id);
    }
}

#[test]
fn t04_degradation_never_empty_for_valid() {
    let catalog = seed_catalog();
    for doc in corpus_valid_documents() {
        let text = degrade_to_text(&doc, &catalog);
        assert!(!text.is_empty(), "degradation produced empty output");
    }
}

#[test]
fn t04_degradation_never_raw_json() {
    let catalog = seed_catalog();
    for doc in corpus_valid_documents() {
        let text = degrade_to_text(&doc, &catalog);
        assert!(
            serde_json::from_str::<serde_json::Value>(&text).is_err(),
            "degradation should not be valid JSON"
        );
    }
}

// T06: Seed catalog contains all §3.9/§4 vocabulary (AC-06)
#[test]
fn t06_seed_catalog_vocabulary() {
    let catalog = seed_catalog();
    let expected = [
        "Text", "Heading", "Button", "Section", "Row", "Column",
        "EntityCard", "DataTable", "TreeView", "Callout", "Stat", "StatGroup",
    ];
    for name in &expected {
        assert!(catalog.lookup(name).is_some(), "missing seed component: {name}");
    }
}

#[test]
fn t06_seed_actions_present() {
    let catalog = seed_catalog();
    let expected_actions = [
        "navigate", "refresh_data", "copy_to_clipboard",
        "open_entity", "approve_grant", "dismiss",
    ];
    for name in &expected_actions {
        let action = ActionRef { name: name.to_string(), params: json!({}), confirm: None };
        // non-catalog actions should fail, so these should at least not fail with "not in catalog"
        // (they may fail on params validation for actions that require params)
        let result = catalog.validate_action(&action);
        if let Err(GenUiError::InvalidAction { name: n, reason }) = &result {
            assert!(
                !reason.contains("not in catalog"),
                "action {n} should be in catalog"
            );
        }
    }
}

#[test]
fn t06_agent_vocabulary_nonempty() {
    let catalog = seed_catalog();
    let vocab = catalog.agent_vocabulary();
    assert!(vocab.contains("Text"), "vocabulary should mention Text");
    assert!(vocab.contains("DataTable"), "vocabulary should mention DataTable");
    assert!(vocab.contains("navigate"), "vocabulary should mention navigate action");
}

// T07: GenUiGate enabled=false returns Denied (AC-07 mechanism)
#[test]
fn t07_gate_denied_when_disabled() {
    let g = gate(false);
    let doc = corpus_valid_documents().into_iter().next().unwrap();
    match g.admit(&doc) {
        Err(GenUiError::Denied) => {}
        other => panic!("expected Denied, got: {other:?}"),
    }
}

#[test]
fn t07_gate_passes_when_enabled() {
    let g = gate(true);
    let doc = corpus_valid_documents().into_iter().next().unwrap();
    g.admit(&doc).expect("enabled gate should accept valid document");
}

// T08: Action validation (AC-08)
#[test]
fn t08_catalog_action_passes() {
    let catalog = seed_catalog();
    let action = ActionRef {
        name: "navigate".into(),
        params: json!({"path": "/dashboard"}),
        confirm: None,
    };
    catalog.validate_action(&action).expect("valid action should pass");
}

#[test]
fn t08_non_catalog_action_rejected() {
    let catalog = seed_catalog();
    let action = ActionRef {
        name: "hack_the_planet".into(),
        params: json!({}),
        confirm: None,
    };
    assert!(catalog.validate_action(&action).is_err());
}

#[test]
fn t08_confirm_required_action_rejected_without_confirm() {
    let catalog = seed_catalog();
    let action = ActionRef {
        name: "approve_grant".into(),
        params: json!({"grant_id": "g-1"}),
        confirm: None,
    };
    assert!(
        catalog.validate_action(&action).is_err(),
        "confirm-required action should fail without confirm metadata"
    );
}

// T09: Flag honesty (AC-09)
#[test]
fn t09_flag_honesty_disabled() {
    let g = GenUiGate::new(false, MAX_DOCUMENT_BYTES, seed_catalog());
    let doc = corpus_valid_documents().into_iter().next().unwrap();
    match g.admit(&doc) {
        Err(GenUiError::Denied) => {}
        other => panic!("expected Denied with enabled=false, got: {other:?}"),
    }
}

#[test]
fn t09_flag_honesty_enabled() {
    let g = GenUiGate::new(true, MAX_DOCUMENT_BYTES, seed_catalog());
    let doc = corpus_valid_documents().into_iter().next().unwrap();
    g.admit(&doc).expect("enabled=true should proceed to validation");
}

// T10: Schema round-trip (AC-10)
#[test]
fn t10_document_roundtrip() {
    for doc in corpus_valid_documents() {
        let json = serde_json::to_string(&doc).expect("serialize");
        let back: GenUiDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(doc, back, "round-trip mismatch");
    }
}

#[test]
fn t10_error_roundtrip() {
    let errors = vec![
        GenUiError::Denied,
        GenUiError::InvalidComponent { name: "Foo".into() },
        GenUiError::DocumentTooLarge { bytes: 300_000, max: 262_144 },
        GenUiError::DocumentTooDeep { depth: 9, max: 8 },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).expect("serialize error");
        let back: GenUiError = serde_json::from_str(&json).expect("deserialize error");
        assert_eq!(err, back);
    }
}

// Depth validation
#[test]
fn depth_8_accepted() {
    let mut current = ComponentNode {
        component: "Text".into(),
        props: json!({"content": "leaf"}),
        children: vec![],
    };
    for _ in 0..7 {
        current = ComponentNode {
            component: "Section".into(),
            props: json!({"title": "level"}),
            children: vec![current],
        };
    }
    validate_depth(&[current], 1).expect("depth 8 should be accepted");
}

#[test]
fn depth_9_rejected() {
    let mut current = ComponentNode {
        component: "Text".into(),
        props: json!({"content": "leaf"}),
        children: vec![],
    };
    for _ in 0..8 {
        current = ComponentNode {
            component: "Section".into(),
            props: json!({"title": "level"}),
            children: vec![current],
        };
    }
    match validate_depth(&[current], 1) {
        Err(GenUiError::DocumentTooDeep { .. }) => {}
        other => panic!("expected DocumentTooDeep, got: {other:?}"),
    }
}

// UTF-8 safe truncation
#[test]
fn degradation_truncation_safe_on_multibyte() {
    let catalog = seed_catalog();
    let long_content = "x".repeat(4000) + &"\u{1F600}".repeat(100);
    let doc = GenUiDocument {
        protocol_version: A2uiVersion::V0_9_1,
        document_id: DocumentId("utf8-test".into()),
        root: vec![ComponentNode {
            component: "Text".into(),
            props: json!({"content": long_content}),
            children: vec![],
        }],
    };
    let text = degrade_to_text(&doc, &catalog);
    assert!(text.len() <= 4096, "degradation should be bounded");
    assert!(text.ends_with("...(truncated)"), "should be truncated");
}

// Version validation
#[test]
fn unknown_version_rejected() {
    let g = gate(true);
    let doc = GenUiDocument {
        protocol_version: A2uiVersion::Unknown("99.0.0".into()),
        document_id: DocumentId("v99".into()),
        root: vec![ComponentNode {
            component: "Text".into(),
            props: json!({"content": "hello"}),
            children: vec![],
        }],
    };
    assert!(g.admit(&doc).is_err(), "unknown version should be rejected");
}

// Button with non-catalog action rejected at document level
#[test]
fn button_non_catalog_action_rejected_in_document() {
    let g = gate(true);
    let doc = GenUiDocument {
        protocol_version: A2uiVersion::V0_9_1,
        document_id: DocumentId("bad-action".into()),
        root: vec![ComponentNode {
            component: "Button".into(),
            props: json!({"label": "Hack", "action": {"name": "delete_everything"}}),
            children: vec![],
        }],
    };
    assert!(g.admit(&doc).is_err(), "button with non-catalog action should be rejected");
}

// Size validation
#[test]
fn size_within_limit_passes() {
    let doc = corpus_valid_documents().into_iter().next().unwrap();
    doc.validate_size(MAX_DOCUMENT_BYTES).expect("small doc should pass size check");
}

#[test]
fn size_over_limit_rejected() {
    let doc = GenUiDocument {
        protocol_version: A2uiVersion::V0_9_1,
        document_id: DocumentId("big".into()),
        root: vec![ComponentNode {
            component: "Text".into(),
            props: json!({"content": "x".repeat(300_000)}),
            children: vec![],
        }],
    };
    assert!(doc.validate_size(MAX_DOCUMENT_BYTES).is_err());
}
