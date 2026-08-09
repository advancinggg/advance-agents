//! notify-WIT structural tripwire (T-B36). **NOT AC-02 evidence.**
//!
//! AC-02 ("notify WIT: notify-agent / notify-channel … all 6 methods
//! callable", canonical §3.3 T01) needs the deferred host_fn registration —
//! AC-02 later **passed** (notify21; historical untested SUPERSEDED). This test
//! only guards that the `notify` interface block exists and is
//! byte-identical between the host WIT and the guest-fixture mirror, so a
//! future edit that diverges them (which would break
//! `module_001_t47_wit_parity_and_fixture_size_guards`) is caught here too
//! with a more specific message.

const HOST_WIT: &str = include_str!("../../runtime/wit/advance.wit");
const FIXTURE_WIT: &str =
    include_str!("../../runtime/tests/fixtures/guest-rust-minimal/wit/advance.wit");

fn notify_block(src: &str) -> String {
    let start = src
        .find("interface notify {")
        .expect("interface notify block present");
    // Find the closing brace of the interface (first "\n}" after start).
    let rest = &src[start..];
    let end = rest.find("\n}").expect("interface notify closing brace") + 2;
    rest[..end].to_string()
}

// T-B36 — notify interface present, both methods + all 4 §2.3-canonical
// notify-error arms, host == fixture byte-identical.
#[test]
fn t_b36_notify_wit_structural() {
    for src in [HOST_WIT, FIXTURE_WIT] {
        assert!(
            src.contains("interface notify {"),
            "interface notify present"
        );
        assert!(
            src.contains(
                "notify-agent: func(agent-id: string, payload: list<u8>, context: option<message-context>)"
            ),
            "notify-agent signature present"
        );
        assert!(
            src.contains(
                "notify-channel: func(channel-id: string, user-id: string, payload: list<u8>, context: option<message-context>)"
            ),
            "notify-channel signature present"
        );
        // §2.3 canonical 4-variant notify-error.
        assert!(
            src.contains("variant notify-error {"),
            "notify-error variant present"
        );
        assert!(
            src.contains("invalid-target(string),"),
            "invalid-target arm"
        );
        assert!(src.contains("mailbox-full,"), "mailbox-full arm");
        assert!(
            src.contains("capability-denied(string),"),
            "capability-denied arm"
        );
        assert!(
            src.contains("identity-unknown(string),"),
            "identity-unknown arm"
        );
        // Negative: the §1.3.1-drift 5-variant arms must NOT be present in
        // the notify block (slice B follows the §2.3 4-variant canonical).
        let block = notify_block(src);
        assert!(
            !block.contains("invalid-context"),
            "notify block must not carry the §1.3.1-drift invalid-context arm"
        );
        assert!(
            !block.contains("circuit-breaker-open"),
            "notify block must not carry the §1.3.1-drift circuit-breaker-open arm"
        );
    }
    assert_eq!(
        notify_block(HOST_WIT),
        notify_block(FIXTURE_WIT),
        "host and fixture notify blocks must be byte-identical"
    );
}
