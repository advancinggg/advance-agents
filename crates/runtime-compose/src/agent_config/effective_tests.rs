use super::*;
use crate::effective_capabilities::EffectiveCapabilities;

fn names(caps: &[CapRequest]) -> Vec<&str> {
    caps.iter().map(|c| c.capability.as_str()).collect()
}

#[test]
fn module_001_ac31_active_capabilities_with_default_equals_active_capabilities() {
    let corpus: &[Option<&[u8]>] = &[
        Some(b"capabilities:\n  fs: true\n  llm: true\n"),
        Some(b"capabilities:\n  fs: true\n"),
        Some(b"capabilities:\n  fs: false\n  llm: true\n"),
        None,
        Some(b"capabilities:\n  secrets:\n    auto-grant: false\n  fs: true\n"),
        Some(b"agent_id: foo\n"),
        Some(b"{ this is not: valid: yaml"),
        Some(b"capabilities:\n  genui: true\n"),
        Some(b"capabilities:\n  messaging: true\n"),
        Some(b"capabilities:\n  fs: true\n  llm: true\n"),
        Some(b"{ not: valid: yaml ["),
        Some(b"capabilities:\n  fs: true\n  fs: false\n"),
        Some(b"capabilities:\n  secrets:\n    auto-grant: false\n"),
        Some(b""),
        Some(b"capabilities: true\n"),
    ];
    let default = EffectiveCapabilities::default();
    for yaml in corpus {
        assert_eq!(
            names(&active_capabilities_with(*yaml, &default)),
            names(&active_capabilities(*yaml)),
        );
    }

    let set = EffectiveCapabilities::from_extension_entries(&[(
        "fixture",
        &["fixture.probe", "fixture.echo"],
    )]);
    for yaml in corpus {
        let Some(bytes) = *yaml else {
            assert!(active_capabilities_with(None, &set).is_empty());
            continue;
        };
        let got_caps = active_capabilities_with(Some(bytes), &set);
        let got = names(&got_caps);
        let mut expected: Vec<&str> = KNOWN_CAPABILITIES
            .iter()
            .copied()
            .filter(|cap| yaml_declares_active_capability(bytes, cap))
            .collect();
        for name in ["fixture.probe", "fixture.echo"] {
            if yaml_declares_active_capability(bytes, name) {
                expected.push(name);
            }
        }
        assert_eq!(got, expected, "{}", String::from_utf8_lossy(bytes));
    }

    let declared = b"capabilities:\n  fs: true\n  fixture.probe: true\n  fixture.echo: false\n";
    let declared_caps = active_capabilities_with(Some(declared), &set);
    assert_eq!(names(&declared_caps), vec!["fs", "fixture.probe"]);

    let mapping = b"capabilities:\n  fixture.probe:\n    auto-grant: false\n";
    assert_eq!(
        names(&active_capabilities_with(Some(mapping), &set)),
        vec!["fixture.probe"]
    );

    let child = b"\
agents:
  - alias: r
    template: explorer
    target-path: r
    capabilities: [fixture.probe]
";
    let err = parse_agents_config_with(Some(child), &EffectiveCapabilities::default()).unwrap_err();
    assert!(
        matches!(err, AgentConfigError::InvalidCapability(ref c) if c == "fixture.probe"),
        "{err:?}"
    );
    let decls = parse_agents_config_with(Some(child), &set).unwrap();
    assert_eq!(decls[0].capabilities, vec!["fixture.probe".to_string()]);

    for bad in [
        "capabilities: [\"a b\"]",
        "capabilities: [\"cap:x\"]",
        "capabilities: [fs, fs]",
        "capabilities: [\"\"]",
    ] {
        let yaml = format!(
            "agents:\n  - alias: r\n    template: explorer\n    target-path: r\n    {bad}\n"
        );
        let default_err = parse_agents_config(Some(yaml.as_bytes())).unwrap_err();
        let with_err = parse_agents_config_with(Some(yaml.as_bytes()), &set).unwrap_err();
        assert_eq!(default_err.to_string(), with_err.to_string(), "{bad}");
    }
}
