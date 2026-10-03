//! SAT-C (slice satC-l6) — L6 consolidation production construction at the cli
//! composition root.
//!
//! Three pieces, all kept HERE (cli) rather than in cap-memory so cap-memory
//! retains NO dependency on `advance-git` (the committer) or `advance-scheduler`
//! (the `component.error` emit) — preserving the acyclic crate graph:
//!
//! 1. [`GitQueueL6Committer`] — a production `cap_memory::L6Committer` over
//!    `advance_git::GitCommitQueue` (CONTRACT-020): a REAL on-disk commit with
//!    `CommitType::L6`. The trait method is SYNC but `submit()` returns an async
//!    `oneshot::Receiver`. Because the CLI runtime is current-thread (tokio
//!    `oneshot::blocking_recv` PANICS in-async, `block_in_place` panics on a
//!    current-thread runtime, and `Handle::block_on` re-enters), a FRESH std
//!    thread — spawned via `std::thread::Builder::spawn` so a thread-creation
//!    failure maps to an `L6CommitError` instead of panicking — builds a tiny
//!    `current_thread` runtime and AWAITS the oneshot under
//!    `tokio::time::timeout(L6_COMMIT_TIMEOUT)`, returning the outcome over a std
//!    mpsc. The timeout bounds BOTH ends — the caller AND the helper thread (it
//!    exits on timeout) — so a wedged/contended git worker can neither hang the
//!    turn indefinitely nor leak a parked helper thread across retries. The git
//!    worker runs on tokio's INDEPENDENT `spawn_blocking` pool and resolves the
//!    oneshot regardless of the parked helper, so the bridge is deadlock-free.
//!    See §3.8 note 19(c).
//!
//! 2. [`L6DispatchAdapter`] — a `cap_memory::L6Dispatch` that builds the
//!    `L6Context`, awaits `L6Runnable::handle` on the live turn, and on `Err`
//!    emits `component.error` via `advance_scheduler::emit_component_error`
//!    (returning `false` so Step-9 skips `mark_l6_ran` → the next trigger
//!    retries, SYS-AC-216 shape).
//!
//! 3. [`attach_l6`] — wires the above onto a `Components`, SHARING the live
//!    `store` / `lease` / `l6_emitter` (the `EventBusL6Emitter`) / `clock` Arcs
//!    (HARD REQUIREMENT — a fresh lease would make Step-9 confirm + the
//!    runnable's lease gate diverge → `LeaseLost` every run) and a ROOTED
//!    cursor store (durable Step-5a flush).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use advance_shared_types::memory::{L6Context, L6Error, L6Handler};

/// SAT-C adversarial r1 (#1): upper bound on how long the SYNC git-commit bridge
/// may park the (current-thread) CLI runtime waiting for the async commit reply.
/// Normal L6 commits of small memory files resolve in milliseconds; this only
/// bounds a pathological case (git worker stuck on the per-repo coord mutex /
/// libgit2 / a slow filesystem) so a hung commit cannot hang the agent turn
/// INDEFINITELY — it fails the L6 run (lease released → next trigger retries)
/// instead. L6 fires rarely (post `mark_l6_ran`), so a 30 s ceiling is generous.
const L6_COMMIT_TIMEOUT: Duration = Duration::from_secs(30);
use advance_shared_types::agent_tree::AgentTreeSnapshot;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use cap_fs::{DefaultVirtualPathResolver, VirtualPathResolver};
use cap_memory::l6::{CommitFile, FileBlobResolver};
use cap_memory::{Components, L6CommitError, L6Committer, L6Dispatch};

/// Production `L6Committer`: translate the L6 `CommitFile` set into a single
/// `advance_git` `CommitRequest` (`CommitType::L6`, initiator `runtime:l6`) and
/// commit it through the live `GitCommitQueue`, bridging the async oneshot reply
/// to this SYNC trait method on an off-runtime thread.
pub struct GitQueueL6Committer {
    queue: Arc<dyn advance_git::GitCommitQueue>,
    /// Resolves a relative `CommitFile.vpath` against the git workdir root. In
    /// the production (`fs_root`-rooted) path the runnable emits ABSOLUTE vpaths,
    /// so this is only the fallback for a relative vpath.
    workspace_root: PathBuf,
}

impl GitQueueL6Committer {
    pub fn new(queue: Arc<dyn advance_git::GitCommitQueue>, workspace_root: PathBuf) -> Self {
        Self {
            queue,
            workspace_root,
        }
    }
}

impl L6Committer for GitQueueL6Committer {
    fn commit(
        &self,
        agent_id: &str,
        batch_id: &str,
        files: &[CommitFile],
    ) -> Result<String, L6CommitError> {
        let paths: Vec<PathBuf> = files
            .iter()
            .map(|f| {
                let p = Path::new(&f.vpath);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    self.workspace_root.join(p)
                }
            })
            .collect();
        let req = advance_git::CommitRequest::new(
            agent_id,
            // The queue prepends `[<type>] [<initiator>] ` (commit_queue.rs),
            // so the message here is just the free-form trailing text — the
            // final commit reads `[l6] [runtime:l6] L6 consolidation batch <id>`.
            format!("L6 consolidation batch {batch_id}"),
            paths,
            advance_git::CommitType::L6,
            "runtime:l6",
        );
        let rx = self.queue.submit(req);
        // Async->sync bridge (adversarial r1 #1 + r2): the SYNC trait method must
        // wait for the async oneshot reply, but on the current-thread CLI runtime
        // tokio's `block_in_place`/`oneshot::blocking_recv` panic in-async, and
        // `Handle::current().block_on` re-enters. So a FRESH std thread (no tokio
        // context) builds a tiny single-thread runtime and AWAITS the oneshot
        // under `tokio::time::timeout(L6_COMMIT_TIMEOUT)`, mapping the outcome to
        // a `Result<String, L6CommitError>` it sends back over a std mpsc.
        //
        // The timeout bounds BOTH ends (r2 fix — no leaked detached thread): the
        // caller parks only until the helper reports, and the helper itself EXITS
        // within ~L6_COMMIT_TIMEOUT even if the git worker is wedged forever (the
        // timeout drops `rx` and the helper returns), so repeated L6 failures
        // against a stuck worker cannot accumulate permanently-parked OS threads.
        // The git worker runs on tokio's INDEPENDENT spawn_blocking pool, so it
        // resolves the oneshot regardless of the parked helper (deadlock-free). On
        // failure/timeout the L6 run errors, the lease releases, and the next
        // trigger retries (SYS-AC-216 shape).
        let (tx, done) = mpsc::channel::<Result<String, L6CommitError>>();
        // `Builder::spawn` (NOT `thread::spawn`) so an OS thread-creation failure
        // (thread/fd exhaustion) maps to an `L6CommitError` instead of PANICKING
        // out of the sync trait method and aborting the agent turn (adversarial
        // r3). The commit was already `submit`ted to the queue, so on spawn
        // failure the worker may still commit (idempotent on `l6_batch_id` if the
        // next trigger retries) — but the bridge never panics.
        let spawned = std::thread::Builder::new()
            .name("l6-git-bridge".to_string())
            .spawn(move || {
                let outcome = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(rt) => rt.block_on(async {
                        // timeout(dur, rx).await:
                        //   Result<Result<Result<Oid, GitError>, RecvError>, Elapsed>
                        match tokio::time::timeout(L6_COMMIT_TIMEOUT, rx).await {
                            Ok(Ok(Ok(oid))) => Ok(oid.to_string()),
                            Ok(Ok(Err(e))) => Err(L6CommitError::Failed(format!("{e:?}"))),
                            Ok(Err(_canceled)) => Err(L6CommitError::Failed(
                                "git commit worker closed (oneshot canceled)".to_string(),
                            )),
                            Err(_elapsed) => Err(L6CommitError::Failed(format!(
                                "git commit timed out after {}s",
                                L6_COMMIT_TIMEOUT.as_secs()
                            ))),
                        }
                    }),
                    Err(e) => Err(L6CommitError::Failed(format!(
                        "git commit bridge runtime build failed: {e}"
                    ))),
                };
                let _ = tx.send(outcome);
            });
        if spawned.is_err() {
            return Err(L6CommitError::Failed(
                "git commit bridge thread spawn failed (host thread exhaustion)".to_string(),
            ));
        }
        // Belt-and-suspenders: the helper self-bounds to ~L6_COMMIT_TIMEOUT, so a
        // small slack here only catches a helper that never reports (e.g. its
        // runtime build hung) — never a normal slow commit.
        match done.recv_timeout(L6_COMMIT_TIMEOUT.saturating_add(Duration::from_secs(5))) {
            Ok(result) => result,
            Err(_) => Err(L6CommitError::Failed(
                "git commit bridge did not report a result in time".to_string(),
            )),
        }
    }
}

/// Production `L6Dispatch`: run the L6 consolidation on the live turn and
/// surface a `handle()` failure as `component.error`.
pub struct L6DispatchAdapter {
    handler: Arc<dyn L6Handler + Send + Sync>,
    /// `Arc<dyn EventBusEmit>` is the exact type `emit_component_error` takes
    /// (the trait's `Send + Sync` supertraits make `dyn EventBusEmit` itself
    /// `Send + Sync`, so the adapter stays `Send + Sync`).
    bus: Arc<dyn EventBusEmit>,
    clock: Arc<dyn cap_memory::Clock + Send + Sync>,
}

impl L6DispatchAdapter {
    /// Construct an adapter from a runnable handler, the `component.error`
    /// emit bus, and the clock used for `L6Context.triggered_at`.
    pub fn new(
        handler: Arc<dyn L6Handler + Send + Sync>,
        bus: Arc<dyn EventBusEmit>,
        clock: Arc<dyn cap_memory::Clock + Send + Sync>,
    ) -> Self {
        Self {
            handler,
            bus,
            clock,
        }
    }
}

#[async_trait]
impl L6Dispatch for L6DispatchAdapter {
    async fn dispatch(&self, agent_id: &str, lease_token: &str) -> bool {
        let ctx = L6Context {
            agent_id: agent_id.to_string(),
            triggered_at: self.clock.now(),
            cursor: None,
            lease_token: lease_token.to_string(),
        };
        match self.handler.handle(ctx).await {
            Ok(_) => true,
            Err(e) => {
                // component.error lives here (cli) so cap-memory keeps no
                // scheduler dependency. component_id == the L6 component id
                // ("memory.l6" — same id the runnable was built with).
                //
                // adversarial r1 (#3): emit a COARSE, variant-based reason — NOT
                // the raw `{e:?}` Debug, whose StorageError/GitCommitFailed
                // strings embed ABSOLUTE filesystem paths (OS username + workspace
                // layout). Those would otherwise reach every observability-bus
                // consumer (the scheduler helper only truncates, it does not
                // redact). The coarse reason carries the failure class for triage
                // without disclosing on-disk paths/PII.
                let reason = coarse_l6_error(&e);
                advance_scheduler::emit_component_error(Some(&self.bus), "memory.l6", "l6", reason);
                false
            }
        }
    }
}

/// Map an `L6Error` to a fixed, path-free reason string for the `component.error`
/// observability payload (adversarial r1 #3 — no absolute paths / PII on the bus).
fn coarse_l6_error(e: &L6Error) -> &'static str {
    match e {
        L6Error::LlmFailure(_) => "l6 classify or synthesis failure",
        L6Error::StorageError(_) => "l6 storage write failed",
        L6Error::GitCommitFailed(_) => "l6 git commit failed",
        L6Error::LeaseLost => "l6 lease lost",
        L6Error::BudgetExhausted => "l6 budget exhausted",
    }
}

/// Production `FileBlobResolver` (Wave-9 Lane B): resolve a file-ref's `(agent_id, vpath)`
/// to a physical path via the MODULE-002 `VirtualPathResolver`, then compute the CURRENT
/// git blob OID of the on-disk content via `advance_git::blob_oid_of_file`. This is the
/// "MODULE-002 blob lookup" the L6 `ResolverStalenessProbe` (cap-memory) consumes.
///
/// **Conservative fail-safe**: `resolve_read` enforces the real territory/traversal/
/// symlink/ASCII/depth/hidden defenses — ANY reject (or a missing/unreadable file) yields
/// `None`, which the probe treats as "not resolved" ⇒ Stale ⇒ orphaned. The only divergence
/// direction is over-orphaning (never a false Valid), the safe failure mode for a staleness
/// probe whose downstream effect is exclude-from-synthesis. The blob identity itself is the
/// REAL git blob OID of current content (causal, not a seeded set).
pub struct GitBlobFileResolver {
    resolver: Arc<dyn VirtualPathResolver>,
}

impl GitBlobFileResolver {
    pub fn new(resolver: Arc<dyn VirtualPathResolver>) -> Self {
        Self { resolver }
    }
}

impl FileBlobResolver for GitBlobFileResolver {
    fn current_blob(&self, agent_id: &str, vpath: &str) -> Option<String> {
        // resolve_read applies the full MODULE-002 path-safety policy; any Err
        // (unknown agent / `..` / absolute / non-ASCII / depth>32 / hidden-`.advance` /
        // symlinked component) → None → Stale (fail-safe, never falsely Valid).
        let physical = self.resolver.resolve_read(agent_id, vpath).ok()?;
        // `None` if the file is gone / unreadable (the conservative "no current blob").
        advance_git::blob_oid_of_file(&physical)
    }
}

/// Build the production L6 stale-resolver: the `GitBlobFileResolver` over a real
/// MODULE-002 `DefaultVirtualPathResolver`. `agent_tree` is the live MODULE-005 snapshot
/// (Some iff `fs` declared); when absent we fall back to `EmptyAgentTree` (every
/// `resolve_read` → NotFound → None → Stale — conservative, identical to the pre-Lane-B
/// empty-stub behaviour) — mirroring the start.rs:740 substitution. We ALWAYS build the
/// real resolver on the production path (NOT gated on `agent_tree.is_some()`) so the probe
/// is never silently wired-out under an llm-but-no-fs agent (the sole FileRef producer is
/// the llm-gated VLM `DescriptionIndexer`, not fs-gated). The empty-stub path is reached
/// only by the harness's byte-identical [`attach_l6`] shim (which passes `None`).
pub fn build_l6_stale_resolver(
    workspace_root: PathBuf,
    agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
) -> Arc<dyn FileBlobResolver> {
    let tree: Arc<dyn AgentTreeSnapshot> =
        agent_tree.unwrap_or_else(|| Arc::new(crate::context_wiring::EmptyAgentTree));
    let resolver: Arc<dyn VirtualPathResolver> =
        Arc::new(DefaultVirtualPathResolver::new(workspace_root, tree));
    Arc::new(GitBlobFileResolver::new(resolver))
}

/// Wire the production L6 construction onto `components` and return it.
///
/// Shares the live `store` / `lease` / `l6_emitter` / `clock` Arcs out of
/// `components` (HARD REQUIREMENT), roots the cursor store at `mem_root`
/// (durable Step-5a flush; coordinates with the WIT rollback handler via the
/// same on-disk root), builds the [`GitQueueL6Committer`] + [`L6Runnable`] +
/// [`L6DispatchAdapter`], and attaches the dispatch handler.
///
/// `workspace_root` is the git workdir (for the committer's relative-vpath
/// fallback); `mem_root` is `<workspace>/.agent/memory` (the runnable's fs_root
/// + the cursor root + the skill-candidate store root).
///
/// `classifier` is INJECTED (slice wave6-laneB): production passes the real
/// `LlmL6Classifier` (dials MODULE-009 CONTRACT-081); the system-acceptance harness
/// passes `StubL6Classifier` so the scripted-FIFO loopback is NOT consumed
/// (SYS-AC-070/215 stay green). This is also the seam the 069/216 harvest injects a
/// fake gateway into. Keeping the swap inside `attach_l6`'s signature (not a hardcode)
/// is the round-1 plan-eval Critical fix — an internal stub→Llm swap would have
/// regressed 070/215 by desyncing the harness loopback FIFO.
pub fn attach_l6(
    components: Components,
    classifier: Arc<dyn cap_memory::l6::L6Classifier + Send + Sync>,
    git_queue: Arc<dyn advance_git::GitCommitQueue>,
    workspace_root: PathBuf,
    mem_root: PathBuf,
) -> Components {
    // Byte-identical delegating shim (Wave-9 Lane B): a `None` stale-resolver ⇒ the
    // historical empty `InMemoryStalenessProbe`. The system-acceptance harness calls THIS
    // form, so its empty-stub→orphaned→069-deferred behaviour is UNCHANGED (zero flip).
    attach_l6_with_stale_resolver(
        components,
        classifier,
        git_queue,
        workspace_root,
        mem_root,
        None,
    )
}

/// Like [`attach_l6`] but with an optional production `FileBlobResolver` (Wave-9 Lane B).
/// `Some(resolver)` ⇒ the L6 Step-1 probe is the real `ResolverStalenessProbe` (MODULE-002
/// blob lookup); `None` ⇒ the historical empty `InMemoryStalenessProbe` (the harness path).
/// Production (`build_live_post_processor`) ALWAYS passes `Some(build_l6_stale_resolver(..))`.
pub fn attach_l6_with_stale_resolver(
    mut components: Components,
    classifier: Arc<dyn cap_memory::l6::L6Classifier + Send + Sync>,
    git_queue: Arc<dyn advance_git::GitCommitQueue>,
    workspace_root: PathBuf,
    mem_root: PathBuf,
    stale_resolver: Option<Arc<dyn FileBlobResolver>>,
) -> Components {
    // Step-1 staleness probe: the real MODULE-002-backed `ResolverStalenessProbe` when a
    // resolver is supplied (production), else the empty `InMemoryStalenessProbe` (harness
    // path — byte-identical to pre-Lane-B). This is the ONLY behavioural delta vs the
    // pre-split `attach_l6`; everything below is moved verbatim.
    let staleness: Arc<dyn cap_memory::l6::StalenessProbe + Send + Sync> = match stale_resolver {
        Some(resolver) => Arc::new(cap_memory::l6::ResolverStalenessProbe::new(resolver)),
        None => Arc::new(cap_memory::l6::InMemoryStalenessProbe::new()),
    };

    // Share the live Arcs by reference (NOT fresh constructions).
    let store = Arc::clone(&components.store);
    let lease = Arc::clone(&components.lease);
    let emitter = Arc::clone(&components.l6_emitter);
    let clock = Arc::clone(&components.clock);

    // Rooted cursor store: durable `_knowledge_cursor.yaml` Step-5a flush; the
    // SAME Arc is shared onto `Components.cursor_store` (the WIT rollback reset
    // destination within the post-processor). Full in-memory-Arc unification
    // with the separately-registered WIT rollback handler stays deferred
    // (SYS-AC-160) — they coordinate via the on-disk file (same root).
    let cursor = Arc::new(cap_memory::l6::L6CursorStore::with_root(mem_root.clone()));
    components.cursor_store = Arc::clone(&cursor);

    let committer: Arc<dyn L6Committer + Send + Sync> =
        Arc::new(GitQueueL6Committer::new(git_queue, workspace_root));

    let runnable = cap_memory::l6::L6Runnable::new(
        "memory.l6",
        Arc::clone(&clock),
        Arc::new(cap_memory::l6::UuidBatchIdSource),
        store,
        lease,
        staleness,
        Arc::new(cap_memory::l6::L6ClusterBuilder::new()),
        classifier,
        Arc::new(cap_memory::l6::StubSynthesisGenerator),
        Arc::new(Mutex::new(cap_memory::l6::KnowledgeMap::new())),
        Arc::new(Mutex::new(HashMap::new())),
        committer,
        emitter,
        cursor,
    )
    .with_fs_root(mem_root.clone())
    // slice wave6-laneB (186): the L6 producer writes skill candidates to
    // `<mem_root>/_skill_candidates.jsonl` — the SAME flat file the cap-skills
    // consumer host-fns read (leg 3, wired via `with_candidate_dir(<ws>/.agent/memory)`
    // in `wiring.rs`). Built from `mem_root` (borrowed) before it is consumed above.
    .with_skill_candidate_store(Arc::new(cap_memory::SkillCandidateStore::in_dir(&mem_root)));

    let handler: Arc<dyn L6Handler + Send + Sync> = Arc::new(runnable);
    // `Components.event_bus` is `Arc<dyn EventBusEmit + Send + Sync>`; coerce to
    // the plain `Arc<dyn EventBusEmit>` that `emit_component_error` consumes.
    // The coercion (drop the redundant Send+Sync auto-trait annotation — the
    // trait already requires them) must happen at a plain `let`-binding, NOT
    // through `Arc::clone` (which fixes its return type to the argument type).
    let bus_ss = Arc::clone(&components.event_bus);
    let bus: Arc<dyn EventBusEmit> = bus_ss;
    let adapter = L6DispatchAdapter {
        handler,
        bus,
        clock,
    };
    components.with_l6_handler(Arc::new(adapter))
}

#[cfg(test)]
mod adv_r1_tests {
    use super::coarse_l6_error;
    use advance_shared_types::memory::L6Error;

    /// SAT-C adversarial r1 (#3): the `component.error` reason is a fixed,
    /// path-free string per L6Error variant — it never forwards the raw `{e:?}`
    /// Debug (which embeds absolute filesystem paths / OS username) onto the bus.
    #[test]
    fn coarse_l6_error_is_path_free_and_variant_mapped() {
        // A StorageError whose inner string contains an absolute path must NOT
        // leak that path through the coarse reason.
        let leaky = L6Error::StorageError(
            "synthesis write: /Users/secret/.agent/memory/abc/syntheses/x.md: ENOSPC".to_string(),
        );
        let reason = coarse_l6_error(&leaky);
        assert_eq!(reason, "l6 storage write failed");
        assert!(
            !reason.contains('/'),
            "reason must not contain any path: {reason}"
        );
        assert!(
            !reason.contains("secret"),
            "reason must not leak inner content"
        );

        assert_eq!(
            coarse_l6_error(&L6Error::GitCommitFailed("/abs/path: boom".into())),
            "l6 git commit failed"
        );
        assert_eq!(coarse_l6_error(&L6Error::LeaseLost), "l6 lease lost");
        assert_eq!(
            coarse_l6_error(&L6Error::BudgetExhausted),
            "l6 budget exhausted"
        );
        assert_eq!(
            coarse_l6_error(&L6Error::LlmFailure("x".into())),
            "l6 classify or synthesis failure"
        );
        // Every variant's reason is path-free.
        for e in [
            L6Error::LlmFailure("/x".into()),
            L6Error::StorageError("/x".into()),
            L6Error::GitCommitFailed("/x".into()),
            L6Error::LeaseLost,
            L6Error::BudgetExhausted,
        ] {
            assert!(!coarse_l6_error(&e).contains('/'));
        }
    }
}
