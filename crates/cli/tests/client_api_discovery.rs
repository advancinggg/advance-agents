//! CLI discovery helper is the same writer used after bind.

use advance_along_home::write_client_api_discovery;

#[test]
fn client_api_discovery_0600_pid_url() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    std::fs::create_dir_all(home.join(".runtime")).unwrap();
    write_client_api_discovery(home, 4242, "http://127.0.0.1:9").unwrap();
    let raw = std::fs::read_to_string(home.join(".runtime").join("client-api")).unwrap();
    assert!(raw.contains("pid: 4242"));
    assert!(raw.contains("http://127.0.0.1:9"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(home.join(".runtime").join("client-api"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
