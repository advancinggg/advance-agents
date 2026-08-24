//! Locate the cap-llm `local-sidecar-fixture` binary and snapshot its
//! listening loopback sockets. SYS-J-74 daemon-altitude helpers.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Absolute path to cap-llm's std-only `local-sidecar-fixture` binary.
pub fn local_sidecar_fixture_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(resolve_fixture_bin).clone()
}

fn resolve_fixture_bin() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_local-sidecar-fixture") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return pb.canonicalize().unwrap_or(pb);
        }
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_local-sidecar-fixture") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return pb.canonicalize().unwrap_or(pb);
        }
    }
    if let Some(p) = fixture_in_target() {
        return p;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(&cargo)
        .args([
            "build",
            "-p",
            "cap-llm",
            "--bin",
            "local-sidecar-fixture",
            "--quiet",
        ])
        .status()
        .expect("spawn cargo build -p cap-llm --bin local-sidecar-fixture");
    assert!(
        status.success(),
        "cargo build -p cap-llm --bin local-sidecar-fixture failed"
    );
    fixture_in_target().unwrap_or_else(|| {
        panic!(
            "missing local-sidecar-fixture after cargo build -p cap-llm --bin local-sidecar-fixture"
        )
    })
}

fn fixture_in_target() -> Option<PathBuf> {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut candidates = Vec::new();
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(
            PathBuf::from(dir)
                .join(profile)
                .join("local-sidecar-fixture"),
        );
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidates.push(
        manifest
            .join("../..")
            .join("target")
            .join(profile)
            .join("local-sidecar-fixture"),
    );
    for p in candidates {
        if p.is_file() {
            return Some(p.canonicalize().unwrap_or(p));
        }
    }
    None
}

/// Fixture processes that listen on 127.0.0.1 (pid, listen addr).
///
/// Identity is kernel exe path (`/proc/pid/exe` or macOS `lsof -d txt`) ending in
/// `/local-sidecar-fixture`, falling back to Darwin 16-byte `comm` prefix
/// `local-sidecar-fi`, **and** a TCP LISTEN on 127.0.0.1. Nested
/// `cargo build --bin local-sidecar-fixture` matches argv but has no LISTEN.
pub fn snapshot_listening_sidecars() -> Vec<(u32, SocketAddr)> {
    let bin = local_sidecar_fixture_bin();
    let mut out = Vec::new();
    let ps = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .expect("ps");
    let text = String::from_utf8_lossy(&ps.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((pid_s, cmd)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let Ok(pid) = pid_s.trim().parse::<u32>() else {
            continue;
        };
        if !pid_is_fixture(pid, cmd, &bin) {
            continue;
        }
        if let Some(addr) = listen_addr_127(pid) {
            out.push((pid, addr));
        }
    }
    out
}

/// Kernel exe path (`/proc/pid/exe` or macOS `lsof -d txt`) wins over argv0.
/// argv0 is only a cheap prefilter so we do not `lsof` every pid on the box.
fn pid_is_fixture(pid: u32, cmd: &str, bin: &Path) -> bool {
    if !argv0_looks_like_fixture(cmd, bin) && !comm_prefix_fixture(pid) {
        return false;
    }
    match kernel_exe(pid) {
        Some(exe) => exe == *bin || path_ends_with_fixture(&exe),
        None => false,
    }
}

fn argv0_looks_like_fixture(cmd: &str, bin: &Path) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("");
    let first_path = Path::new(first);
    let Ok(canon) = first_path.canonicalize() else {
        return first_path == bin || first.ends_with("/local-sidecar-fixture");
    };
    canon == *bin
}

fn path_ends_with_fixture(p: &Path) -> bool {
    p.file_name().and_then(|s| s.to_str()) == Some("local-sidecar-fixture")
}

fn comm_prefix_fixture(pid: u32) -> bool {
    let out = Command::new("ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .output();
    let Ok(out) = out else {
        return false;
    };
    let comm = String::from_utf8_lossy(&out.stdout);
    comm.trim().starts_with("local-sidecar-fi")
}

fn kernel_exe(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-d", "txt", "-Fn"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut current_pid: Option<u32> = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix('p') {
                current_pid = rest.trim().parse().ok();
                continue;
            }
            if current_pid != Some(pid) {
                continue;
            }
            let Some(rest) = line.strip_prefix('n') else {
                continue;
            };
            let pb = PathBuf::from(rest);
            if path_ends_with_fixture(&pb) {
                return Some(pb);
            }
        }
        None
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Loopback LISTEN for one owned pid (not a box-wide fixture census).
pub fn listen_addr_for_pid(pid: u32) -> Option<SocketAddr> {
    listen_addr_127(pid)
}

/// `lsof` can lag the PORT= handshake by a few milliseconds.
pub fn wait_listen_addr_for_pid(pid: u32, budget: std::time::Duration) -> Option<SocketAddr> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Some(addr) = listen_addr_127(pid) {
            return Some(addr);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn listen_addr_127(pid: u32) -> Option<SocketAddr> {
    // macOS lsof ORs selection lists unless `-a` is set. Without it, `-p PID -iTCP`
    // dumps every TCP listener on the box (first n-line is some other daemon).
    let out = Command::new("lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fn",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut current_pid: Option<u32> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            current_pid = rest.trim().parse().ok();
            continue;
        }
        if current_pid != Some(pid) {
            continue;
        }
        let Some(rest) = line.strip_prefix('n') else {
            continue;
        };
        // `127.0.0.1:PORT` or `127.0.0.1:PORT->...`
        // LISTEN name is `127.0.0.1:PORT` — skip connected `addr->addr` lines.
        if rest.contains("->") {
            continue;
        }
        let hostport = rest.trim();
        if let Ok(addr) = hostport.parse::<SocketAddr>() {
            if addr.ip() == Ipv4Addr::LOCALHOST {
                return Some(addr);
            }
        }
        if let Some((h, p)) = hostport.rsplit_once(':') {
            if h == "127.0.0.1" {
                if let Ok(port) = p.parse::<u16>() {
                    return Some(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
                }
            }
        }
    }
    None
}

/// New fixture listeners that appeared after `before`.
pub fn sidecar_diff(
    before: &[(u32, SocketAddr)],
    after: &[(u32, SocketAddr)],
) -> Vec<(u32, SocketAddr)> {
    after
        .iter()
        .copied()
        .filter(|(pid, addr)| {
            !before.iter().any(|(b, _)| b == pid) && !before.iter().any(|(_, a)| a == addr)
        })
        .collect()
}
