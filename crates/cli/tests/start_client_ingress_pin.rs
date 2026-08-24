//! MSG-06: production `try_spawn_agent_loop` must reuse `client_ingress_store`.

#[test]
fn production_agent_loop_uses_client_ingress_store() {
    let src = include_str!("../src/commands/start.rs");
    assert!(
        src.contains("client_ingress_store.clone()"),
        "run_async must pass client_ingress_store into try_spawn_agent_loop"
    );
    let forbidden = format!("{}{}", "wiring_handles.", "messaging_store.clone()");
    assert!(
        !src.contains(&forbidden),
        "run_async must not pass messaging_store.clone() as the serve-loop mailbox"
    );
}
