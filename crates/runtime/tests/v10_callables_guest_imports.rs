//! V10 — `guest-rust-callables` import table, size, regen README, CREATE_DRIVER copy.

use wasmtime::{Engine, ExternType, Module};

const CORE: &[u8] = include_bytes!("fixtures/guest-rust-callables.core.wasm");
const DRIVER: &[u8] = include_bytes!("../../advance-home/src/fixtures/behavior.core.wasm");
const README: &str = include_str!("fixtures/guest-rust-callables/README.md");

#[test]
fn v10_callables_guest_imports_size_and_regen() {
    assert!(
        CORE.len() < 500 * 1024,
        "artifact must stay under 500 KiB, got {} bytes",
        CORE.len()
    );
    assert_eq!(&CORE[0..4], b"\0asm", "committed artifact is a wasm binary");
    assert_eq!(
        CORE, DRIVER,
        "CREATE_DRIVER bytes must match guest-rust-callables.core.wasm"
    );

    let engine = Engine::default();
    let module = Module::from_binary(&engine, CORE).expect("core module parses");
    let mut imports: Vec<(String, String)> = module
        .imports()
        .filter(|imp| matches!(imp.ty(), ExternType::Func(_)))
        .map(|imp| (imp.module().to_string(), imp.name().to_string()))
        .collect();
    imports.sort();
    assert_eq!(
        imports,
        vec![
            (
                "advance:runtime/agent-callables@0.1.0".into(),
                "invoke-callable".into()
            ),
            (
                "advance:runtime/agent-callables@0.1.0".into(),
                "list-callables".into()
            ),
            ("advance:runtime/agent-llm@0.1.0".into(), "generate".into()),
        ],
        "CREATE_DRIVER imports exactly generate + list-callables + invoke-callable"
    );

    assert!(
        README.contains("Regen procedure"),
        "fixture README documents regen"
    );
    assert!(
        README.contains("world advance-host-callables"),
        "fixture README names the guest world"
    );
    assert!(
        README.contains("behavior.core.wasm"),
        "fixture README copies the artifact onto CREATE_DRIVER"
    );
    assert!(
        README.contains("wasm-tools print"),
        "fixture README shows the wasm-tools import check"
    );
    assert!(
        README.contains("RUSTFLAGS=\"-C debuginfo=0\""),
        "fixture README regen command is the rustc 1.91-stable form"
    );
    assert!(
        !README.contains("split-debuginfo=unpacked"),
        "unpacked split-debuginfo is unstable for wasm32 on rustc 1.91"
    );

    let hash = README
        .lines()
        .find_map(|l| l.strip_prefix("Committed artifact sha256: "))
        .unwrap_or_else(|| panic!("README records Committed artifact sha256"));
    assert_eq!(hash.len(), 64, "README hash is 64 hex chars, got {hash:?}");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "README hash is hex: {hash}"
    );
    let actual = sha256_hex(CORE);
    assert_eq!(
        hash, actual,
        "README-documented hash equals the committed CORE artifact"
    );
    assert_eq!(
        sha256_hex(DRIVER),
        actual,
        "CREATE_DRIVER hash equals the committed CORE artifact"
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}
