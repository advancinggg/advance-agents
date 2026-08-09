#[test]
fn module_001_t47_wit_parity_and_fixture_size_guards() {
    let host_wit = include_str!("../wit/advance.wit");
    let fixture_wit = include_str!("fixtures/guest-rust-minimal/wit/advance.wit");
    assert_eq!(
        host_wit, fixture_wit,
        "host WIT and fixture WIT have diverged — run the regen procedure in \
         crates/runtime/tests/fixtures/guest-rust-minimal/README.md step 2"
    );

    let rust_fixture = include_bytes!("fixtures/guest-rust-minimal.core.wasm");
    assert!(
        rust_fixture.len() < 500_000,
        "Rust guest fixture size regression: {} bytes (limit 500 KiB)",
        rust_fixture.len()
    );

    let tinygo_fixture = include_bytes!("fixtures/guest-tinygo-smoke.component.wasm");
    assert!(
        tinygo_fixture.len() < 2_000_000,
        "TinyGo guest fixture size regression: {} bytes (limit 2 MiB)",
        tinygo_fixture.len()
    );
}
