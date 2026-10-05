//! MODULE-001-T111 (6) / MODULE-001-AC-30, on a multi-thread runtime (an embedder's
//! flavour): the same witness as `module_001_t111_recompose.rs`.
//!
//! The only test of its binary: it checks process-wide state.

#[path = "support/t111.rs"]
mod t111;

#[path = "support/recompose.rs"]
mod recompose;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac30_t111_6_recompose_after_ordered_shutdown_multi_thread() {
    recompose::t111_6_recompose_after_ordered_shutdown().await;
}
