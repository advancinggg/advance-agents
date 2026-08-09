//! Serde + wire-format tests for `advance_shared_types::skills`.

use advance_shared_types::security_validator::TrustLevel;
use advance_shared_types::skills::{Provenance, SkillInfo};

#[test]
fn provenance_round_trip() {
    for p in [Provenance::AgentCreated, Provenance::Imported] {
        let json = serde_json::to_string(&p).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}

#[test]
fn provenance_wire_format_lock() {
    assert_eq!(
        serde_json::to_string(&Provenance::AgentCreated).unwrap(),
        "\"AgentCreated\""
    );
    assert_eq!(
        serde_json::to_string(&Provenance::Imported).unwrap(),
        "\"Imported\""
    );
}

#[test]
fn skill_info_round_trip() {
    let s = SkillInfo {
        skill_id: "foo".to_string(),
        version: 3,
        name: "Foo skill".to_string(),
        provenance: Provenance::Imported,
        trust_level: TrustLevel::Trusted,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: SkillInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn skill_info_deny_unknown_fields() {
    let bad = r#"{"skill_id":"x","version":1,"name":"y","provenance":"Imported","trust_level":"Trusted","extra":true}"#;
    let err = serde_json::from_str::<SkillInfo>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn trust_level_reexport_from_skills_compiles() {
    // Both paths resolve to the same nominal type (canonical in security_validator,
    // re-exported from skills).
    let _sv: advance_shared_types::security_validator::TrustLevel = TrustLevel::Trusted;
    let _sk: advance_shared_types::skills::TrustLevel = TrustLevel::Untrusted;
}
