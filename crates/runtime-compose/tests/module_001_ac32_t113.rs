//! MODULE-001-T113 — spawn-site CI gate. Composing legs land in later commits.

#[path = "support/spawn_gate.rs"]
mod spawn_gate;

#[test]
fn module_001_ac32_t113_3_spawn_site_gate_lists_every_site_with_its_policy_check() {
    spawn_gate::assert_list();
}

#[test]
fn module_001_ac32_spawn_site_gate_self_test() {
    spawn_gate::self_test();
}
