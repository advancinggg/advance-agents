//! MODULE-001-AC-31 — the loopback trust-model comment names the host socket, not a relay.

#[test]
fn module_001_ac31_loopback_trust_comment_corrected() {
    let src = include_str!("../src/api.rs");
    assert!(
        !src.contains("presents its requests as loopback"),
        "the loopback flag must not be described as a relay presenting requests as loopback"
    );
    assert!(
        !src.contains("Noise"),
        "the loopback trust-model comment must not name a product transport"
    );
    assert!(
        src.contains("loopback socket of this host"),
        "the loopback trust-model comment must name the host's loopback socket"
    );
}
