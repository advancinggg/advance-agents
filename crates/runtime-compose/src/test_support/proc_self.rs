//! Live children of this process (`/proc/self/task/*/children`). Std only; no `Command`.

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
