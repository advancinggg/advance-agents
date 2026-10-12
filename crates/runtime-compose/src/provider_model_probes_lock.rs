//! AM-T23: source-lock for the production provider-admin constructor.

#[test]
fn am_t23_wiring_uses_compose_helper() {
    let wiring = include_str!("wiring.rs");
    assert!(
        wiring.contains("compose_provider_admin"),
        "wiring must call compose_provider_admin"
    );
    assert!(
        wiring.contains("started.claimed_preflight"),
        "wiring must store the claimed-preflight stopper"
    );
    assert!(
        !wiring.contains("WiredProviderAdmin::new"),
        "wiring must not construct WiredProviderAdmin inline"
    );
    assert!(
        !wiring.contains("ComposedClaimedPreflight::new"),
        "wiring must not construct ComposedClaimedPreflight inline"
    );

    let probes = include_str!("provider_model_probes.rs");
    let impl_half = probes.split("#[cfg(test)]").next().expect("impl half");
    for needle in [
        "with_hot_reload",
        "with_chatgpt_sign_in",
        "with_claimable_local_entries",
        "with_local_sidecar_binder",
        "with_claimed_preflight",
        "attach_live_model_probes",
        "ComposedClaimedPreflight::new",
    ] {
        assert!(
            impl_half.contains(needle),
            "provider_model_probes impl half missing {needle}"
        );
    }
}
