//! Integration tests for HostRegistry (CONTRACT-001 data-only portion).

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
    InMemoryHostRegistry, MAX_CAPABILITIES, MAX_SPECS_PER_CAPABILITY, MAX_SPEC_STRING_LEN,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::thread;
use wasmtime::component::Val;

struct StubHandler;
impl HostFunctionHandler for StubHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

fn spec(cap: &str, ns: &str, name: &str) -> HostFunctionSpec {
    HostFunctionSpec {
        capability: cap.to_string(),
        namespace: ns.to_string(),
        name: name.to_string(),
        handler: Arc::new(StubHandler),
        idempotent: false,
    }
}

#[test]
fn default_new_returns_empty() {
    let r = InMemoryHostRegistry::new();
    assert!(r.lookup("foo").is_empty());
    assert_eq!(r.capability_count(), 0);
}

#[test]
fn register_then_lookup_single() {
    let r = InMemoryHostRegistry::new();
    r.register(spec("cap-fs", "wasi:fs", "read"));
    let got = r.lookup("cap-fs");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].capability, "cap-fs");
    assert_eq!(got[0].name, "read");
}

#[test]
fn lookup_unknown_returns_empty() {
    let r = InMemoryHostRegistry::new();
    r.register(spec("cap-a", "ns", "fn1"));
    assert!(r.lookup("cap-b").is_empty());
}

#[test]
fn register_multiple_under_same_cap() {
    let r = InMemoryHostRegistry::new();
    r.register(spec("cap-fs", "wasi:fs", "read"));
    r.register(spec("cap-fs", "wasi:fs", "write"));
    r.register(spec("cap-fs", "wasi:fs", "stat"));
    let got = r.lookup("cap-fs");
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].name, "read");
    assert_eq!(got[1].name, "write");
    assert_eq!(got[2].name, "stat");
}

#[test]
fn register_multiple_caps() {
    let r = InMemoryHostRegistry::new();
    r.register(spec("cap-a", "ns", "fn1"));
    r.register(spec("cap-b", "ns", "fn1"));
    r.register(spec("cap-c", "ns", "fn1"));
    assert_eq!(r.capability_count(), 3);
    assert_eq!(r.lookup("cap-a").len(), 1);
    assert_eq!(r.lookup("cap-b").len(), 1);
    assert_eq!(r.lookup("cap-c").len(), 1);
}

#[test]
fn clone_of_spec_preserves_handler_arc() {
    let r = InMemoryHostRegistry::new();
    let original = spec("cap-fs", "ns", "fn1");
    let original_ptr = Arc::as_ptr(&original.handler);
    r.register(original);
    let got = r.lookup("cap-fs");
    assert_eq!(got.len(), 1);
    assert_eq!(Arc::as_ptr(&got[0].handler), original_ptr);
}

#[test]
fn concurrent_register_and_lookup() {
    let r = Arc::new(InMemoryHostRegistry::new());
    let mut handles = Vec::new();
    // 4 writer threads, each registering 100 specs under a distinct per-thread
    // capability — 400 unique capabilities total, deterministic regardless of
    // interleaving.
    for t in 0..4 {
        let r = r.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                r.register(spec(&format!("cap-{t}-{i}"), "ns", &format!("fn-{i}")));
            }
        }));
    }
    // 4 reader threads performing concurrent lookups
    for _ in 0..4 {
        let r = r.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = r.lookup("cap-0-0");
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
    assert_eq!(r.capability_count(), 400);
}

#[test]
fn registry_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InMemoryHostRegistry>();
}

#[test]
fn trait_is_object_safe() {
    let _: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
}

#[test]
fn duplicate_register_accumulates_append_only() {
    // Locks in the documented append-only behavior (rustdoc on
    // HostFunctionSpec): register does NOT dedup by (capability,
    // namespace, name). Callers are responsible for deduping at their
    // boundary; CapabilityInjector will fail hard on duplicate
    // (namespace, name) linker wiring once it lands.
    let r = InMemoryHostRegistry::new();
    r.register(spec("cap-fs", "wasi:fs", "read"));
    r.register(spec("cap-fs", "wasi:fs", "read"));
    let got = r.lookup("cap-fs");
    assert_eq!(
        got.len(),
        2,
        "register is append-only; duplicates accumulate"
    );
    assert_eq!(got[0].name, "read");
    assert_eq!(got[1].name, "read");
}

#[test]
fn host_function_spec_debug_redacts_handler() {
    let s = spec("cap-fs", "wasi:fs", "read");
    let out = format!("{s:?}");
    assert!(out.contains("<HostFunctionHandler>"), "got: {out}");
    assert!(out.contains("cap-fs"));
    assert!(out.contains("wasi:fs"));
    assert!(out.contains("read"));
}

#[test]
#[should_panic(expected = "MAX_CAPABILITIES")]
fn register_panics_on_max_capabilities_exceeded() {
    let r = InMemoryHostRegistry::new();
    for i in 0..=MAX_CAPABILITIES {
        r.register(spec(&format!("cap-{i}"), "ns", "fn"));
    }
}

#[test]
#[should_panic(expected = "MAX_SPECS_PER_CAPABILITY")]
fn register_panics_on_max_specs_per_capability_exceeded() {
    let r = InMemoryHostRegistry::new();
    for i in 0..=MAX_SPECS_PER_CAPABILITY {
        r.register(spec("cap", "ns", &format!("fn-{i}")));
    }
}

#[test]
#[should_panic(expected = "MAX_SPEC_STRING_LEN")]
fn register_panics_on_oversized_capability_string() {
    let r = InMemoryHostRegistry::new();
    let long = "x".repeat(MAX_SPEC_STRING_LEN + 1);
    r.register(spec(&long, "ns", "fn"));
}

#[test]
#[should_panic(expected = "MAX_SPEC_STRING_LEN")]
fn register_panics_on_oversized_namespace_string() {
    let r = InMemoryHostRegistry::new();
    let long = "x".repeat(MAX_SPEC_STRING_LEN + 1);
    r.register(spec("cap", &long, "fn"));
}

#[test]
#[should_panic(expected = "MAX_SPEC_STRING_LEN")]
fn register_panics_on_oversized_name_string() {
    let r = InMemoryHostRegistry::new();
    let long = "x".repeat(MAX_SPEC_STRING_LEN + 1);
    r.register(spec("cap", "ns", &long));
}

#[test]
fn register_accepts_strings_at_max_boundary() {
    let r = InMemoryHostRegistry::new();
    let max = "x".repeat(MAX_SPEC_STRING_LEN);
    r.register(spec(&max, "ns", "fn")); // exactly MAX_SPEC_STRING_LEN — allowed
    assert_eq!(r.capability_count(), 1);
}

#[test]
fn at_max_capabilities_can_still_register_under_existing() {
    // Slice I migration regression check: contains_key(&str) via Borrow<str>
    // must still work when registry is at MAX_CAPABILITIES, allowing
    // additional specs under an EXISTING capability without tripping the
    // distinct-capability cap.
    let r = InMemoryHostRegistry::new();
    for i in 0..MAX_CAPABILITIES {
        r.register(spec(&format!("cap-{i}"), "ns", "fn"));
    }
    assert_eq!(r.capability_count(), MAX_CAPABILITIES);
    // Adding more specs under cap-0 (existing) must succeed, NOT panic
    // with MAX_CAPABILITIES exceeded — the contains_key(.as_str()) probe
    // sees the existing key via Borrow<str>.
    r.register(spec("cap-0", "ns", "fn-extra"));
    assert_eq!(r.capability_count(), MAX_CAPABILITIES);
    assert_eq!(r.lookup("cap-0").len(), 2);
}
