use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);

pub struct Marker {
    dir: PathBuf,
    script: PathBuf,
}

impl Marker {
    pub fn new() -> Self {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("cap-llm-ac32-{}-{n}", std::process::id()));
        std::fs::create_dir(&dir).expect("marker dir");
        let script = dir.join("run.sh");
        let body = format!("#!/bin/sh\n: > '{}/ran'\nexit 0\n", dir.display());
        std::fs::write(&script, body).expect("write run.sh");
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o700);
        std::fs::set_permissions(&script, perms).unwrap();
        Self { dir, script }
    }

    pub fn script(&self) -> &Path {
        &self.script
    }

    pub fn ran(&self) -> bool {
        self.dir.join("ran").is_file()
    }
}

impl Drop for Marker {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
