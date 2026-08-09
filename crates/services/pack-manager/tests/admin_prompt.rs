//! Admin approval prompt integration tests (Slice B, AC-07).
//!
//! T18-T20 + T20b: InteractiveApproval behavior across (empty caps short-circuit,
//! non-empty caps prompt, prompt content, bounded ASCII line read).

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use advance_pack_manager::{
    install::{ApprovalStrategy, AutoApprove},
    manifest::PackManifest,
    InteractiveApproval, TrustLevel,
};

const PACK_YAML_WITH_CAPS: &str = r#"name: research-pack
version: 1.2.0
runtime-version: ">=0.0.1, <2.0.0"
dependencies: []
provides:
  behavior-binaries: []
required-capabilities:
  - fs
  - llm
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;

const PACK_YAML_NO_CAPS: &str = r#"name: trivial-pack
version: 1.0.0
runtime-version: ">=0.0.1"
dependencies: []
provides:
  behavior-binaries: []
trust-level: untrusted
checksums:
  algo: sha256
  files: {}
"#;

#[tokio::test]
async fn t18_interactive_approval_y_accepts_install() {
    let m = PackManifest::from_yaml(PACK_YAML_WITH_CAPS).unwrap();
    let writer = Vec::<u8>::new();
    let reader = Cursor::new(b"y\n".to_vec());
    let approval = InteractiveApproval::new(writer, reader);
    let ok = approval.approve(&m).await.unwrap();
    assert!(ok, "y should accept");
}

#[tokio::test]
async fn t18_interactive_approval_n_rejects_install() {
    let m = PackManifest::from_yaml(PACK_YAML_WITH_CAPS).unwrap();
    let writer = Vec::<u8>::new();
    let reader = Cursor::new(b"n\n".to_vec());
    let approval = InteractiveApproval::new(writer, reader);
    let ok = approval.approve(&m).await.unwrap();
    assert!(!ok, "n should reject");
}

#[tokio::test]
async fn t18_interactive_approval_default_reject_on_empty_line() {
    let m = PackManifest::from_yaml(PACK_YAML_WITH_CAPS).unwrap();
    let writer = Vec::<u8>::new();
    let reader = Cursor::new(b"\n".to_vec());
    let approval = InteractiveApproval::new(writer, reader);
    let ok = approval.approve(&m).await.unwrap();
    assert!(!ok, "empty line should default-reject");
}

#[tokio::test]
async fn t19_empty_required_capabilities_short_circuits_approve() {
    let m = PackManifest::from_yaml(PACK_YAML_NO_CAPS).unwrap();
    let writer = Vec::<u8>::new();
    // Empty reader — if the implementation tries to read, it would fail on EOF;
    // but the short-circuit returns Ok(true) without reading.
    let reader = Cursor::new(Vec::<u8>::new());
    let approval = InteractiveApproval::new(writer, reader);
    let ok = approval.approve(&m).await.unwrap();
    assert!(
        ok,
        "empty required-capabilities should short-circuit Ok(true)"
    );
}

#[tokio::test]
async fn t19_empty_caps_short_circuit_prints_nothing() {
    let m = PackManifest::from_yaml(PACK_YAML_NO_CAPS).unwrap();
    // Wrap writer in shared Mutex so we can inspect after the call.
    let writer_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let writer = SharedWriter(writer_buf.clone());
    let reader = Cursor::new(Vec::<u8>::new());
    let approval = InteractiveApproval::new(writer, reader);
    let _ = approval.approve(&m).await.unwrap();
    let captured = writer_buf.lock().unwrap();
    assert!(
        captured.is_empty(),
        "no output expected for short-circuit; got {:?}",
        String::from_utf8_lossy(&captured)
    );
}

#[tokio::test]
async fn t20_interactive_approval_prompt_content() {
    let m = PackManifest::from_yaml(PACK_YAML_WITH_CAPS).unwrap();
    let writer_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let writer = SharedWriter(writer_buf.clone());
    let reader = Cursor::new(b"y\n".to_vec());
    let approval = InteractiveApproval::new(writer, reader);
    let _ = approval.approve(&m).await.unwrap();
    let captured = writer_buf.lock().unwrap();
    let s = String::from_utf8_lossy(&captured);
    assert!(
        s.contains("Pack: research-pack@1.2.0"),
        "prompt missing pack id: {s}"
    );
    assert!(
        s.contains("Required capabilities: [fs, llm]"),
        "prompt missing caps: {s}"
    );
    assert!(
        s.contains("Trust level: untrusted"),
        "prompt missing trust level: {s}"
    );
    assert!(
        s.contains("Approve? [y/N]"),
        "prompt missing approval line: {s}"
    );
}

#[tokio::test]
async fn t20b_interactive_approval_bounded_read_caps_at_16_bytes() {
    // 20 'y' bytes — the bounded read consumes 16 and the 17th-20th remain.
    // After trim+lowercase the 16 'y' bytes still parse as "yyyyy...yyyy" not
    // "y" or "yes", so the result is reject (false).
    let m = PackManifest::from_yaml(PACK_YAML_WITH_CAPS).unwrap();
    let writer = Vec::<u8>::new();
    let reader = Cursor::new(b"yyyyyyyyyyyyyyyyEXTRA".to_vec());
    let approval = InteractiveApproval::new(writer, reader);
    let ok = approval.approve(&m).await.unwrap();
    assert!(!ok, "16 y's does NOT equal 'y' or 'yes'; should reject");
}

#[tokio::test]
async fn t20b_interactive_approval_rejects_non_ascii_input() {
    // Reader provides a non-ASCII byte; read_bounded_line errors → AdminRejected.
    let m = PackManifest::from_yaml(PACK_YAML_WITH_CAPS).unwrap();
    let writer = Vec::<u8>::new();
    let reader = Cursor::new(vec![b'y', 0xFF, b'\n']);
    let approval = InteractiveApproval::new(writer, reader);
    match approval.approve(&m).await {
        Err(advance_pack_manager::PackError::AdminRejected) => {}
        other => panic!("expected AdminRejected on non-ASCII input, got {other:?}"),
    }
}

#[tokio::test]
async fn t20b_existing_auto_strategies_still_work() {
    // Regression: AutoApprove/AutoReject still satisfy the trait (no API break).
    let m = PackManifest::from_yaml(PACK_YAML_WITH_CAPS).unwrap();
    assert!(
        AutoApprove.approve(&m).await.unwrap(),
        "AutoApprove should approve"
    );
    // Slice A's AutoReject baseline is at install.rs; behavior unchanged.
    // No new assertion needed beyond compile-success.
    // Slice B compatibility assertion: PackManifest fields used by InteractiveApproval
    // are unchanged.
    assert_eq!(m.name, "research-pack");
    assert_eq!(
        m.required_capabilities,
        vec!["fs".to_string(), "llm".to_string()]
    );
    assert_eq!(m.trust_level, TrustLevel::Untrusted);
}
