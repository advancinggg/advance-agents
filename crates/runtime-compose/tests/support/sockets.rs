//! LISTEN TCP sockets of this process (MODULE-001-T113 (4)).
#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(target_os = "macos")]
use std::process::Command;

/// Live TCP LISTEN addresses of this process. Linux: `/proc/self/fd` inodes matched
/// against `/proc/self/net/tcp{,6}` rows in state `0A`. macOS: `lsof`. Other OS: `None`.
pub fn listening_sockets() -> Option<Vec<SocketAddr>> {
    #[cfg(target_os = "linux")]
    {
        Some(listening_sockets_linux())
    }
    #[cfg(target_os = "macos")]
    {
        Some(listening_sockets_macos())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn listening_sockets_linux() -> Vec<SocketAddr> {
    let mut inodes = Vec::new();
    let fd_dir = match std::fs::read_dir("/proc/self/fd") {
        Ok(dir) => dir,
        Err(_) => return Vec::new(),
    };
    for entry in fd_dir.flatten() {
        let path = entry.path();
        let Ok(target) = std::fs::read_link(&path) else {
            continue;
        };
        let Some(text) = target.to_str() else {
            continue;
        };
        let Some(inode) = text
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        inodes.push(inode);
    }
    inodes.sort_unstable();
    inodes.dedup();

    let mut addrs = Vec::new();
    parse_proc_net_tcp("/proc/self/net/tcp", false, &inodes, &mut addrs);
    parse_proc_net_tcp("/proc/self/net/tcp6", true, &inodes, &mut addrs);
    addrs.sort();
    addrs.dedup();
    addrs
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp(path: &str, v6: bool, inodes: &[u64], out: &mut Vec<SocketAddr>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            continue;
        }
        let cols: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st ... inode
        if cols.len() < 10 {
            continue;
        }
        if cols[3] != "0A" {
            continue;
        }
        let Ok(inode) = cols[9].parse::<u64>() else {
            continue;
        };
        if inodes.binary_search(&inode).is_err() {
            continue;
        }
        if let Some(addr) = parse_proc_local(cols[1], v6) {
            out.push(addr);
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_local(local: &str, v6: bool) -> Option<SocketAddr> {
    let (ip, port) = local.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if v6 {
        if ip.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in ip.as_bytes().chunks(8).enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            let be = word.to_be_bytes();
            bytes[i * 4..i * 4 + 4].copy_from_slice(&be);
        }
        Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(bytes),
            port,
            0,
            0,
        )))
    } else {
        if ip.len() != 8 {
            return None;
        }
        let word = u32::from_str_radix(ip, 16).ok()?;
        let b = word.to_le_bytes();
        Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(b[0], b[1], b[2], b[3]),
            port,
        )))
    }
}

#[cfg(target_os = "macos")]
fn listening_sockets_macos() -> Vec<SocketAddr> {
    let pid = std::process::id().to_string();
    let output = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN"])
        .output()
        .or_else(|_| {
            Command::new("/usr/sbin/lsof")
                .args(["-nP", "-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN"])
                .output()
        })
        .expect("lsof LISTEN sockets");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut addrs = Vec::new();
    for line in stdout.lines().skip(1) {
        if let Some(addr) = parse_lsof_listen(line) {
            addrs.push(addr);
        }
    }
    addrs.sort();
    addrs.dedup();
    addrs
}

#[cfg(target_os = "macos")]
fn parse_lsof_listen(line: &str) -> Option<SocketAddr> {
    let trimmed = line.trim();
    let without = trimmed.strip_suffix("(LISTEN)")?.trim();
    let name = without.split_whitespace().last()?;
    if let Ok(addr) = name.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Some((host, port)) = name.rsplit_once(':') {
        let port: u16 = port.parse().ok()?;
        if host == "*" {
            return Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                port,
            )));
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
        if let Ok(ip) = host.parse::<Ipv6Addr>() {
            return Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));
        }
    }
    None
}
