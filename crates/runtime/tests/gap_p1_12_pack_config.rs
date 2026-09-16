#![cfg(feature = "gap-p1")]
//! GAP-12 (P1, unit half) — `PackConfig` defaults + validation.
//! The e2e half (through `advance init` +
//! `load_config`) lives in crates/cli/tests/gap_p1_12_pack_config_e2e.rs.

use advance_runtime::config::{PackApprovalPolicy, PackConfig};

#[test]
fn pc_01_defaults_are_the_documented_ones_and_validate() {
    let d = PackConfig::default();
    assert_eq!(d.packs_dir, ".advance/packs");
    assert_eq!(d.fetch_timeout_sec, 120);
    assert_eq!(d.approval, PackApprovalPolicy::Interactive);
    assert!(d.trust_roots.is_empty());
    assert!(d.registry_url.is_none());
    d.validate().expect("defaults validate");
}

#[test]
fn pc_02_yaml_shape_kebab_case_and_deny_unknown_fields() {
    let cfg: PackConfig = serde_yml::from_str(
        "packs-dir: .advance/packs\nfetch-timeout-sec: 30\napproval: auto-reject\ntrust-roots:\n  - abababababababababababababababababababababababababababababababab\nregistry-url: https://registry.example.com\n",
    )
    .expect("full section parses");
    assert_eq!(cfg.fetch_timeout_sec, 30);
    assert_eq!(cfg.approval, PackApprovalPolicy::AutoReject);
    assert_eq!(cfg.trust_roots.len(), 1);
    assert_eq!(
        cfg.registry_url.as_deref(),
        Some("https://registry.example.com")
    );
    cfg.validate().expect("valid");

    let empty: PackConfig = serde_yml::from_str("{}").expect("all fields default");
    assert_eq!(empty, PackConfig::default());

    assert!(
        serde_yml::from_str::<PackConfig>("approval: auto-approve\n").is_err(),
        "no auto-approve variant exists"
    );
    assert!(
        serde_yml::from_str::<PackConfig>("packs_dir: x\n").is_err(),
        "snake_case / unknown keys are rejected"
    );
}

#[test]
fn pc_03_validate_rejects_bad_shapes() {
    let cases: Vec<(&str, Box<dyn Fn(&mut PackConfig)>)> = vec![
        (
            "absolute packs-dir",
            Box::new(|c| c.packs_dir = "/etc/packs".into()),
        ),
        (
            "parent traversal",
            Box::new(|c| c.packs_dir = ".advance/../packs".into()),
        ),
        ("empty packs-dir", Box::new(|c| c.packs_dir = String::new())),
        ("zero timeout", Box::new(|c| c.fetch_timeout_sec = 0)),
        (
            "timeout over an hour",
            Box::new(|c| c.fetch_timeout_sec = 3601),
        ),
        (
            "non-hex trust root",
            Box::new(|c| c.trust_roots = vec!["zz".repeat(32)]),
        ),
        (
            "short trust root",
            Box::new(|c| c.trust_roots = vec!["ab".repeat(16)]),
        ),
        (
            "plain http registry on a public host",
            Box::new(|c| c.registry_url = Some("http://registry.example.com".into())),
        ),
        (
            "non-http scheme",
            Box::new(|c| c.registry_url = Some("ftp://registry.example.com".into())),
        ),
    ];
    for (why, mutate) in cases {
        let mut c = PackConfig::default();
        mutate(&mut c);
        assert!(c.validate().is_err(), "must reject: {why}");
    }
    let mut loopback = PackConfig::default();
    loopback.registry_url = Some("http://127.0.0.1:8080".into());
    loopback
        .validate()
        .expect("plain http is allowed on loopback for dev registries");
}
