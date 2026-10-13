//! Git-family PR-1 — the composition bootstraps the workspace repository.
//!
//! (1) An initialized home WITHOUT `.git` is bootstrapped at compose time: `.git` exists,
//!     `HEAD` targets `refs/heads/main`, the commit queue is spawned, the status is `Ready`.
//! (2) A home whose repository has `HEAD → refs/heads/other` is NOT rewritten: `HEAD` stays,
//!     the status is `NotMain { observed }`, and the `wiring.git_repo_not_main` line is logged.
//!
//! The compositions of this binary run one at a time (process-wide git-queue registry).

use std::sync::Arc;

use advance_git::GitRepoStatus;
use advance_runtime_compose::compose;
use advance_runtime_compose::log_keys;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn home_without_git() -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs")],
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home")
}

#[tokio::test(flavor = "current_thread")]
async fn module_003_git_pr1_compose_bootstraps_a_missing_repository() {
    let _serial = SERIAL.lock().await;
    let home = home_without_git();
    assert!(
        !home.home().join(".git").exists(),
        "the fixture starts without a repository"
    );
    assert_eq!(
        advance_git::repo_status(home.home()),
        GitRepoStatus::Missing
    );

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        Vec::new(),
    )
    .await
    .expect("compose");

    let record = probe.record();
    assert_eq!(record.git_repo_status, Some(GitRepoStatus::Ready));
    assert!(home.home().join(".git").is_dir(), ".git was created");
    let head = std::fs::read_to_string(home.home().join(".git/HEAD")).expect("HEAD");
    assert_eq!(head.trim(), "ref: refs/heads/main");
    assert!(
        home.home().join(".gitignore").is_file(),
        "the bootstrap installs .gitignore"
    );
    assert!(
        record
            .git_queue
            .as_ref()
            .is_some_and(|queue| queue.strong_count() > 0),
        "the commit queue is spawned on the bootstrapped repository"
    );
    assert_eq!(log.count(log_keys::GIT_REPO_NOT_MAIN), 0);
    assert_eq!(log.count(log_keys::GIT_REPO_UNREADABLE), 0);
    assert_eq!(advance_git::repo_status(home.home()), GitRepoStatus::Ready);

    runtime.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;

    // A second composition opens the existing repository (idempotent, no re-init).
    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        Vec::new(),
    )
    .await
    .expect("compose again");
    assert_eq!(probe.record().git_repo_status, Some(GitRepoStatus::Ready));
    runtime.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn module_003_git_pr1_compose_reports_not_main_without_rewriting() {
    let _serial = SERIAL.lock().await;
    let home = home_without_git();
    {
        let mut opts = git2::RepositoryInitOptions::new();
        opts.initial_head("other");
        git2::Repository::init_opts(home.home(), &opts).expect("init on `other`");
    }
    let head_before = std::fs::read_to_string(home.home().join(".git/HEAD")).expect("HEAD");
    assert_eq!(head_before.trim(), "ref: refs/heads/other");

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let runtime = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        Vec::new(),
    )
    .await
    .expect("compose");

    assert_eq!(
        probe.record().git_repo_status,
        Some(GitRepoStatus::NotMain {
            observed: "refs/heads/other".to_string()
        })
    );
    let head_after = std::fs::read_to_string(home.home().join(".git/HEAD")).expect("HEAD");
    assert_eq!(
        head_before, head_after,
        "HEAD is reported, never re-pointed"
    );
    assert!(
        !home.home().join(".gitignore").exists(),
        "an existing repository is not rewritten"
    );
    assert_eq!(log.count(log_keys::GIT_REPO_NOT_MAIN), 1);
    let line = log
        .lines()
        .into_iter()
        .find(|line| line.key == log_keys::GIT_REPO_NOT_MAIN)
        .expect("the not-main line");
    assert!(line.text.contains("refs/heads/other"), "{}", line.text);

    runtime.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}
