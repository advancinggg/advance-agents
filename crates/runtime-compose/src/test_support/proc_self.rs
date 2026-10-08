//! Live children of this process (`/proc/self/task/*/children`) and `/proc/self/maps`
//! helpers. Std only; no `Command`. The pure parts compile on every OS.

/// One line of `/proc/<pid>/maps`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcMapping {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub path: String,
}

impl ProcMapping {
    /// `perms` has `x` in the third column.
    pub fn executable(&self) -> bool {
        self.perms.as_bytes().get(2) == Some(&b'x')
    }

    /// Backed by a real file: `path` starts with `/` and is not a `/memfd:` region.
    pub fn file_backed(&self) -> bool {
        self.path.starts_with('/') && !self.path.starts_with("/memfd:")
    }
}

/// Parses `/proc/<pid>/maps` text: `start-end perms offset dev inode [path]`; the path is the rest
/// of the line after the fifth field, trimmed (it may contain spaces).
pub fn parse_maps(text: &str) -> Vec<ProcMapping> {
    text.lines().filter_map(parse_maps_line).collect()
}

fn parse_maps_line(line: &str) -> Option<ProcMapping> {
    let mut rest = line;
    let range = next_field(&mut rest)?;
    let perms = next_field(&mut rest)?.to_string();
    let _offset = next_field(&mut rest)?;
    let _dev = next_field(&mut rest)?;
    let _inode = next_field(&mut rest)?;
    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    Some(ProcMapping {
        start,
        end,
        perms,
        path: rest.trim().to_string(),
    })
}

fn next_field<'a>(rest: &mut &'a str) -> Option<&'a str> {
    *rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    match rest.find(char::is_whitespace) {
        Some(i) => {
            let field = &rest[..i];
            *rest = &rest[i..];
            Some(field)
        }
        None => {
            let field = *rest;
            *rest = "";
            Some(field)
        }
    }
}

/// `parse_maps(fs::read_to_string("/proc/self/maps")?)`.
#[cfg(target_os = "linux")]
pub fn read_self_maps() -> std::io::Result<Vec<ProcMapping>> {
    let text = std::fs::read_to_string("/proc/self/maps")?;
    Ok(parse_maps(&text))
}

/// Mappings of `after` that are executable and not in `before` (same start, end, perms and path).
pub fn new_executable(before: &[ProcMapping], after: &[ProcMapping]) -> Vec<ProcMapping> {
    after
        .iter()
        .filter(|m| m.executable() && !before.contains(m))
        .cloned()
        .collect()
}

/// Live children of this process not yet reaped. Linux: `Some`, the union of
/// `/proc/self/task/<tid>/children`. A thread that exits during the walk is skipped, but the
/// main thread's file (`tid == std::process::id()`) must be readable, else this panics naming
/// the path (a kernel without `CONFIG_PROC_CHILDREN` must never pass silently). Other OSes:
/// `None`.
pub fn child_pids() -> Option<Vec<u32>> {
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
    #[cfg(target_os = "linux")]
    {
        Some(child_pids_linux())
    }
}

#[cfg(target_os = "linux")]
fn child_pids_linux() -> Vec<u32> {
    let main_tid = std::process::id();
    let main_path = format!("/proc/self/task/{main_tid}/children");
    let main = std::fs::read_to_string(&main_path)
        .unwrap_or_else(|e| panic!("unreadable {main_path}: {e}"));
    let mut pids = parse_children(&main);
    let Ok(task_dir) = std::fs::read_dir("/proc/self/task") else {
        pids.sort_unstable();
        pids.dedup();
        return pids;
    };
    for entry in task_dir.flatten() {
        let tid = match entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            Some(tid) if tid != main_tid => tid,
            _ => continue,
        };
        let path = format!("/proc/self/task/{tid}/children");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        pids.extend(parse_children(&text));
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

#[cfg(target_os = "linux")]
fn parse_children(text: &str) -> Vec<u32> {
    text.split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_001_ac32_proc_maps_parser_flags_new_non_file_executable_mappings() {
        let before = parse_maps(
            "\
00400000-0040c000 r-xp 00000000 08:01 1234 /usr/bin/test
0040c000-0040d000 r--p 0000c000 08:01 1234 /usr/bin/test
7f0000000000-7f0000010000 rw-p 00000000 00:00 0 [heap]
",
        );
        let after = parse_maps(
            "\
00400000-0040c000 r-xp 00000000 08:01 1234 /usr/bin/test
0040c000-0040d000 r--p 0000c000 08:01 1234 /usr/bin/test
7f1000000000-7f1000010000 r-xp 00000000 00:00 0
7f2000000000-7f2000010000 r-xp 00000000 00:01 5 /memfd:x (deleted)
7f3000000000-7f3000020000 r-xp 00000000 08:01 99 /usr/lib/a b.so
7f0000000000-7f0000020000 rw-p 00000000 00:00 0 [heap]
",
        );
        let added = new_executable(&before, &after);
        assert_eq!(
            added
                .iter()
                .map(|m| (m.start, m.end, m.perms.as_str(), m.path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (0x7f1000000000, 0x7f1000010000, "r-xp", ""),
                (0x7f2000000000, 0x7f2000010000, "r-xp", "/memfd:x (deleted)"),
                (0x7f3000000000, 0x7f3000020000, "r-xp", "/usr/lib/a b.so"),
            ]
        );
        let anon: Vec<_> = added.iter().filter(|m| !m.file_backed()).collect();
        assert_eq!(anon.len(), 2);
        assert_eq!(anon[0].path, "");
        assert_eq!(anon[1].path, "/memfd:x (deleted)");
        assert_eq!(added[2].path, "/usr/lib/a b.so");
        assert!(added[2].file_backed());
    }
}
