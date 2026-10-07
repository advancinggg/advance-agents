//! CONTRACT-244 / ADR 2026-10-03 D3: whether OSS code may start child processes, the places it
//! does, and the typed refusal. Every spawn site checks its policy immediately before it builds
//! the child's `Command`; the CI gate (runtime-compose tests) lists every site and its check.

use std::fmt;

/// The `details` token of a Client API refusal and the leading token of every port refusal text.
pub const PROCESS_FORBIDDEN: &str = "process_forbidden";

/// Whether this host lets the runtime start child processes. iOS / Android hosts: `Forbid`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ProcessPolicy {
    #[default]
    Allow,
    Forbid,
}

/// Every kind of child process OSS starts (one per spec item of ADR D3 "No child process under Forbid").
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpawnSite {
    /// CONTRACT-238 local inference sidecar (cap-llm `ProcessSupervisor`).
    LocalSidecar,
    /// Vendor `agent-cli` turns and its auth / usage probes (cap-llm `backend_cli`).
    AgentCli,
    /// MCP stdio servers (cap-mcp `StdioMcpTransport`).
    McpStdio,
    /// `git` for `git+…` pack sources (pack-manager `fetch`).
    PackGitSource,
    /// CONTRACT-243 `advance start` launcher (advance-home `connect`).
    DaemonLauncher,
    /// `kill -0` / `ps -o lstart=` of the pid lock (advance-runtime `runtime_lock`).
    PidLockProbe,
}

impl SpawnSite {
    /// The six, in declaration order; `ALL[i].index() == i` (pinned by the const assert below).
    pub const ALL: [SpawnSite; 6] = [
        SpawnSite::LocalSidecar,
        SpawnSite::AgentCli,
        SpawnSite::McpStdio,
        SpawnSite::PackGitSource,
        SpawnSite::DaemonLauncher,
        SpawnSite::PidLockProbe,
    ];

    /// "local sidecar" | "agent-cli" | "MCP stdio server" | "git pack source" | "daemon launcher" | "pid-lock probe"
    pub const fn name(self) -> &'static str {
        match self {
            SpawnSite::LocalSidecar => "local sidecar",
            SpawnSite::AgentCli => "agent-cli",
            SpawnSite::McpStdio => "MCP stdio server",
            SpawnSite::PackGitSource => "git pack source",
            SpawnSite::DaemonLauncher => "daemon launcher",
            SpawnSite::PidLockProbe => "pid-lock probe",
        }
    }

    const fn index(self) -> usize {
        match self {
            SpawnSite::LocalSidecar => 0,
            SpawnSite::AgentCli => 1,
            SpawnSite::McpStdio => 2,
            SpawnSite::PackGitSource => 3,
            SpawnSite::DaemonLauncher => 4,
            SpawnSite::PidLockProbe => 5,
        }
    }
}

const _: () = {
    let mut i = 0;
    while i < SpawnSite::ALL.len() {
        assert!(SpawnSite::ALL[i].index() == i);
        i += 1;
    }
};

/// A spawn refused by [`ProcessPolicy::Forbid`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessForbidden {
    pub site: SpawnSite,
}

impl fmt::Display for ProcessForbidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{PROCESS_FORBIDDEN}: this host forbids child processes ({})",
            self.site.name()
        )
    }
}

impl std::error::Error for ProcessForbidden {}

impl ProcessPolicy {
    pub const fn is_forbid(self) -> bool {
        matches!(self, ProcessPolicy::Forbid)
    }

    /// `Err` under `Forbid` (counted as one refusal at `site` with the `spawn-counter`
    /// feature); `Ok` under `Allow` (counts nothing). Use it for an early, deterministic refusal.
    pub fn check(self, site: SpawnSite) -> Result<(), ProcessForbidden> {
        if self.is_forbid() {
            #[cfg(feature = "spawn-counter")]
            spawn_counter::count_refused(site);
            Err(ProcessForbidden { site })
        } else {
            Ok(())
        }
    }

    /// [`check`], and on `Ok` count one admitted spawn attempt at `site`. Call it immediately
    /// before the child's `Command` is built, in the same function (the CI gate checks this).
    pub fn admit(self, site: SpawnSite) -> Result<(), ProcessForbidden> {
        self.check(site)?;
        #[cfg(feature = "spawn-counter")]
        spawn_counter::count_admitted(site);
        Ok(())
    }
}

/// Process-wide counters of admitted and refused spawn attempts (tests only).
#[cfg(feature = "spawn-counter")]
pub mod spawn_counter {
    use super::SpawnSite;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ADMITTED: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
    static REFUSED: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SpawnCounts {
        admitted: [u64; 6],
        refused: [u64; 6],
    }

    impl SpawnCounts {
        pub fn admitted(&self, site: SpawnSite) -> u64 {
            self.admitted[site.index()]
        }

        pub fn refused(&self, site: SpawnSite) -> u64 {
            self.refused[site.index()]
        }

        pub fn admitted_total(&self) -> u64 {
            self.admitted.iter().sum()
        }

        pub fn refused_total(&self) -> u64 {
            self.refused.iter().sum()
        }

        /// Per-site `self - earlier` (saturating).
        pub fn since(&self, earlier: &SpawnCounts) -> SpawnCounts {
            let mut admitted = [0u64; 6];
            let mut refused = [0u64; 6];
            for i in 0..6 {
                admitted[i] = self.admitted[i].saturating_sub(earlier.admitted[i]);
                refused[i] = self.refused[i].saturating_sub(earlier.refused[i]);
            }
            SpawnCounts { admitted, refused }
        }

        #[cfg(test)]
        pub(super) fn all_max() -> Self {
            Self {
                admitted: [u64::MAX; 6],
                refused: [u64::MAX; 6],
            }
        }
    }

    /// A copy of the counters now (`Relaxed` loads). Monotonic; never reset.
    pub fn snapshot() -> SpawnCounts {
        let mut admitted = [0u64; 6];
        let mut refused = [0u64; 6];
        for i in 0..6 {
            admitted[i] = ADMITTED[i].load(Ordering::Relaxed);
            refused[i] = REFUSED[i].load(Ordering::Relaxed);
        }
        SpawnCounts { admitted, refused }
    }

    pub(super) fn count_admitted(site: SpawnSite) {
        ADMITTED[site.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn count_refused(site: SpawnSite) {
        REFUSED[site.index()].fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod module_001_ac32_tests {
    use super::*;
    use spawn_counter::snapshot;

    #[test]
    fn module_001_ac32_process_policy_check_admit_and_counter() {
        assert_eq!(SpawnSite::ALL.len(), 6);
        let mut names = std::collections::HashSet::new();
        for (i, site) in SpawnSite::ALL.iter().copied().enumerate() {
            assert_eq!(site.index(), i);
            assert!(
                names.insert(site.name()),
                "duplicate SpawnSite name {}",
                site.name()
            );
        }

        assert!(!ProcessPolicy::Allow.is_forbid());
        assert!(ProcessPolicy::Forbid.is_forbid());
        assert_eq!(ProcessPolicy::default(), ProcessPolicy::Allow);

        for site in SpawnSite::ALL {
            let before = snapshot();

            assert!(ProcessPolicy::Allow.check(site).is_ok());
            let after_check = snapshot().since(&before);
            assert_eq!(after_check.admitted(site), 0);
            assert_eq!(after_check.refused(site), 0);

            assert!(ProcessPolicy::Allow.admit(site).is_ok());
            let after_admit = snapshot().since(&before);
            assert_eq!(after_admit.admitted(site), 1);
            assert_eq!(after_admit.refused(site), 0);

            let err = ProcessPolicy::Forbid
                .check(site)
                .expect_err("Forbid.check refuses");
            assert_eq!(err.site, site);
            let text = err.to_string();
            assert!(
                text.starts_with(PROCESS_FORBIDDEN),
                "Display must start with {PROCESS_FORBIDDEN}: {text}"
            );
            assert!(
                text.contains(site.name()),
                "Display must name the site: {text}"
            );
            let after_forbid_check = snapshot().since(&before);
            assert_eq!(after_forbid_check.admitted(site), 1);
            assert_eq!(after_forbid_check.refused(site), 1);

            let err = ProcessPolicy::Forbid
                .admit(site)
                .expect_err("Forbid.admit refuses");
            assert_eq!(err.site, site);
            let after_forbid_admit = snapshot().since(&before);
            assert_eq!(after_forbid_admit.admitted(site), 1);
            assert_eq!(after_forbid_admit.refused(site), 2);
        }

        let later = snapshot();
        let saturated = later.since(&spawn_counter::SpawnCounts::all_max());
        for site in SpawnSite::ALL {
            assert_eq!(saturated.admitted(site), 0);
            assert_eq!(saturated.refused(site), 0);
        }
    }
}
