//! Shared helpers of the MODULE-001-T112 (c) host-function / native-tool witnesses.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use advance_runtime_compose::test_support::fixture::{
    ext_probe_core, mint_session, post_msg, CapDecl, FixtureDriver, FixtureHomeSpec,
};
use advance_runtime_compose::test_support::ComposeProbe;
use advance_runtime_compose::ComposedRuntime;
use serde_json::Value;

pub fn h_c() -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![
            CapDecl::Granted("fs"),
            CapDecl::Granted("tools"),
            CapDecl::Granted("fixture.probe"),
        ],
        driver: FixtureDriver::Core(ext_probe_core()),
        git: true,
        providers_yaml: None,
    }
}

pub fn h_c_min() -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![
            CapDecl::Granted("fs"),
            CapDecl::Granted("tools"),
            CapDecl::Granted("fixture.probe"),
        ],
        driver: FixtureDriver::Minimal,
        git: true,
        providers_yaml: None,
    }
}

pub fn h_deny() -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![
            CapDecl::Granted("fs"),
            CapDecl::Granted("tools"),
            CapDecl::DeclaredNoGrant("fixture.probe"),
        ],
        driver: FixtureDriver::Core(ext_probe_core()),
        git: true,
        providers_yaml: None,
    }
}

pub fn h_notools() -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("fixture.probe")],
        driver: FixtureDriver::Core(ext_probe_core()),
        git: true,
        providers_yaml: None,
    }
}

pub fn h_nodecl() -> FixtureHomeSpec {
    FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("tools")],
        driver: FixtureDriver::Core(ext_probe_core()),
        git: true,
        providers_yaml: None,
    }
}

pub fn write_pack(root: &Path, name: &str, required: &[&str]) -> PathBuf {
    let dir = root.join(format!("{name}-src"));
    std::fs::create_dir_all(dir.join("behavior-binaries")).unwrap();
    std::fs::write(dir.join("behavior-binaries/dummy.wasm"), b"\0asm\x01\0\0\0").unwrap();
    let mut yaml = format!(
        "name: {name}\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides:\n  behavior-binaries:\n    - dummy\nchecksums:\n  algo: sha256\n  files: {{}}\n"
    );
    if !required.is_empty() {
        yaml.push_str("required-capabilities:\n");
        for cap in required {
            yaml.push_str(&format!("  - {cap}\n"));
        }
    }
    std::fs::write(dir.join("pack.yaml"), yaml).unwrap();
    dir
}

pub fn events(home: &Path) -> Vec<Value> {
    let dir = home.join(".runtime/events/jsonl");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries {
        let path = entry.expect("jsonl entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read jsonl");
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("jsonl line in {}: {error}: {line}", path.display())
            }));
        }
    }
    out
}

pub fn api(rt: &ComposedRuntime) -> (SocketAddr, String) {
    let endpoint = rt.client_api().expect("client api");
    let token = mint_session(&endpoint);
    (endpoint.socket_addr, token)
}

pub async fn msg(probe: &ComposeProbe, payload: &str) -> (u16, String) {
    let addr = probe
        .record()
        .listener("post_msg")
        .expect("POST /msg is bound");
    post_msg(addr, payload).await
}

pub fn subsequence(haystack: &[&str], needle: &[&str]) -> bool {
    let mut rest = haystack;
    for wanted in needle {
        match rest.iter().position(|got| got == wanted) {
            Some(index) => rest = &rest[index + 1..],
            None => return false,
        }
    }
    true
}

pub fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

pub const POLL: Duration = Duration::from_millis(10);
