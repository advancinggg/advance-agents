use std::path::{Path, PathBuf};

pub struct Marker {
    dir: tempfile::TempDir,
    script: PathBuf,
}

impl Marker {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("marker dir");
        let script = dir.path().join("run.sh");
        let body = format!("#!/bin/sh\n: > '{}/ran'\nexit 0\n", dir.path().display());
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
        self.dir.path().join("ran").is_file()
    }
}
