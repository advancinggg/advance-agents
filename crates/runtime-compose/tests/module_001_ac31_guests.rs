//! MODULE-001-AC-31 — llm-noerr guest import set matches hello-llm.

use std::collections::BTreeSet;

use advance_runtime_compose::test_support::fixture::{hello_llm_core, llm_noerr_core};
use wit_component::{decode, ComponentEncoder, DecodedWasm};

#[test]
fn module_001_ac31_llm_noerr_guest_import_set_matches_hello_llm() {
    let hello = decode_world(hello_llm_core());
    let noerr = decode_world(llm_noerr_core());
    assert_eq!(hello.imports, noerr.imports, "same WIT world import set");
    assert!(
        hello
            .imports
            .iter()
            .any(|name| name == "advance:runtime/agent-llm@0.1.0"),
        "imports={:?}",
        hello.imports
    );
    assert_eq!(
        hello.function_imports,
        BTreeSet::from(["advance:runtime/agent-llm@0.1.0".to_owned()]),
        "agent-llm is the only function-bearing import: {:?}",
        hello.function_imports
    );
    assert_eq!(hello.function_imports, noerr.function_imports);
    assert_eq!(hello.exports, noerr.exports);
    assert!(
        hello
            .exports
            .iter()
            .any(|name| name.contains("message-driven")),
        "exports={:?}",
        hello.exports
    );
    assert!(
        hello.exports.iter().any(|name| name.contains("runnable")),
        "exports={:?}",
        hello.exports
    );
}

struct WorldIo {
    imports: BTreeSet<String>,
    function_imports: BTreeSet<String>,
    exports: BTreeSet<String>,
}

fn decode_world(core: &[u8]) -> WorldIo {
    let component = ComponentEncoder::default()
        .validate(true)
        .module(core)
        .expect("core module accepted by ComponentEncoder")
        .encode()
        .expect("encode component");
    let DecodedWasm::Component(resolve, world) = decode(&component).expect("decode component")
    else {
        panic!("decoded a WIT package, not a component");
    };
    let world = &resolve.worlds[world];
    let mut imports = BTreeSet::new();
    for (key, _) in &world.imports {
        imports.insert(resolve.name_world_key(key));
    }
    let mut function_imports = BTreeSet::new();
    for (id, iface) in resolve.interfaces.iter() {
        if iface.functions.is_empty() {
            continue;
        }
        if let Some(name) = resolve.id_of(id) {
            if imports.contains(&name) {
                function_imports.insert(name);
            }
        }
    }
    let mut exports = BTreeSet::new();
    for (key, _) in &world.exports {
        exports.insert(resolve.name_world_key(key));
    }
    WorldIo {
        imports,
        function_imports,
        exports,
    }
}
