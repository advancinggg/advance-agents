//! When stored vectors may be caught up.
//!
//! A turn end embeds what is NEW — the turn's digest, a brief whose text changed
//! — right away. Everything else is catch-up: embedding again a text that did
//! not change — a turn's digest, a task's brief — because its vector is missing
//! or comes from another model than the one the agent's queries are made with
//! now (a reader compares vectors of one model only, so until then the row is
//! invisible to recall and to task routing).
//!
//! Catch-up is the part that could turn one failing provider, or an agent whose
//! provider keeps changing, into a stream of requests. So it is paced here, per
//! agent:
//!
//! - it **rests** for [`EMBEDDING_REST`] when the service is failing — a request
//!   failed and the request before it had not got a vector either —, after the
//!   agent's embedding model changed (an agent served by two entries in turn
//!   never chases its own vectors back and forth), after the index could not be
//!   read or written, and after a pass that asked for vectors and got none;
//! - a request that fails right after another one got its vector may be failing
//!   over its text, not over the service. That is not known, so nothing is given
//!   up: the text is **put off** — asked about again, but only after every row
//!   that was not — and catch-up goes on behind it;
//! - a text the service **refused** as a text
//!   ([`crate::EmbedderError::Refused`]) is **set aside**: it is not asked about
//!   again under this model;
//! - one pass makes at most [`VECTORS_PER_TURN_END`] requests, starts none once
//!   it has run for [`CATCH_UP_TIME`], and is over by then: a request still
//!   unanswered is cut off and counts as failed;
//! - once a pass finds nothing left to embed the agent is **settled**, and the
//!   index is not searched again until a row is written that needs a vector.
//!
//! Put off or set aside is a text, never a row: the same row with another text
//! is a row like any other.
//!
//! Process memory only. After a restart catch-up starts over, which costs
//! nothing for the rows already done (they are of the model in use and are not
//! listed again) and one request for each text set aside before.

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// How long catch-up rests (see the module doc for what starts a rest).
pub const EMBEDDING_REST: Duration = Duration::from_secs(600);

/// Rows — task briefs and turn digests together — given a vector per turn end.
/// Each is one embedding request made while the agent's next turn waits for the
/// post-processor, so the number is small; the most recent rows go first.
pub const VECTORS_PER_TURN_END: usize = 8;

/// How long one pass of catch-up may take. The agent's next turn waits for the
/// pass, so a service that answers slowly — or not at all, or only after the
/// gateway's retries — costs a turn end this much at most: no request starts
/// after it, and one still unanswered then is cut off.
pub const CATCH_UP_TIME: Duration = Duration::from_secs(15);

/// Texts remembered as set aside, and as put off, per agent — each list on its
/// own. Past it the text kept back longest is forgotten, and is asked about
/// once more when its turn comes.
const MAX_KEPT_BACK: usize = 256;

/// Agents tracked at once. One post-processor serves one agent, so this is
/// headroom, not a working limit; past it everything tracked is forgotten
/// (catch-up for those agents starts over, exactly as after a restart).
const MAX_TRACKED_AGENTS: usize = 256;

/// A row of one agent's index whose vector is caught up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VectorRow {
    /// The brief of a task.
    Task { task_id: String },
    /// The digest of a turn.
    Turn { task_id: String, turn: u32 },
}

/// Where the text a row holds stands with catch-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Asked about in its turn, the most recently written row first.
    Open,
    /// Its request failed: asked about after every open row. `place` is its
    /// place among the texts put off — `0` was put off longest ago and goes
    /// first.
    PutOff { place: usize },
    /// The service refused it: not asked about.
    SetAside,
}

/// A text kept back: the row, and a mark of the text it held then.
#[derive(Clone, Debug, PartialEq, Eq)]
struct KeptBack {
    row: VectorRow,
    text: u64,
}

impl KeptBack {
    fn new(row: VectorRow, text: &str) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut hasher);
        Self {
            row,
            text: hasher.finish(),
        }
    }
}

/// Keep `entry` back in `list`, as the text kept back last. A row holds one
/// text, so what the list said about the row before is replaced.
fn keep_back(list: &mut VecDeque<KeptBack>, entry: KeptBack) {
    list.retain(|kept| kept.row != entry.row);
    if list.len() >= MAX_KEPT_BACK {
        list.pop_front();
    }
    list.push_back(entry);
}

#[derive(Default)]
struct AgentUpkeep {
    /// The embedding model seen at the last check.
    model: Option<String>,
    /// When the current rest began.
    resting_since: Option<SystemTime>,
    /// Every row a reader reaches is of `model` or holds a text set aside (as of
    /// the last pass).
    settled: bool,
    /// The agent's last embedding request got a vector: the service was
    /// answering a moment ago.
    served_last: bool,
    /// Texts the service refused under `model`.
    set_aside: VecDeque<KeptBack>,
    /// Texts whose request failed under `model` while the service was
    /// answering, the one put off longest ago first.
    put_off: VecDeque<KeptBack>,
}

impl AgentUpkeep {
    fn resting(&mut self, now: SystemTime) -> bool {
        let Some(since) = self.resting_since else {
            return false;
        };
        match now.duration_since(since) {
            Ok(elapsed) if elapsed >= EMBEDDING_REST => {
                self.resting_since = None;
                false
            }
            Ok(_) => true,
            // The clock went back past the start of the rest: rest one full
            // period from the new time rather than for as long as the clock is
            // behind.
            Err(_) => {
                self.resting_since = Some(now);
                true
            }
        }
    }
}

/// The pacing state of [`crate::Components`]' vector catch-up. See the module
/// doc.
#[derive(Default)]
pub struct EmbeddingUpkeep {
    agents: Mutex<HashMap<String, AgentUpkeep>>,
}

impl std::fmt::Debug for EmbeddingUpkeep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tracked = self.agents.lock().map(|agents| agents.len()).unwrap_or(0);
        f.debug_struct("EmbeddingUpkeep")
            .field("tracked_agents", &tracked)
            .finish()
    }
}

impl EmbeddingUpkeep {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, agent_id: &str, act: impl FnOnce(&mut AgentUpkeep) -> R) -> R {
        let mut agents = self
            .agents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !agents.contains_key(agent_id) && agents.len() >= MAX_TRACKED_AGENTS {
            agents.clear();
        }
        act(agents.entry(agent_id.to_owned()).or_default())
    }

    /// Whether catch-up for `agent_id`, whose vectors come from `model` now, may
    /// run at `now`. Also the one place a model change is noticed: called at
    /// every turn end that has a model, it starts a rest when `model` is not the
    /// one seen before (the first model seen after a start is not a change).
    /// What was learned under the model before — texts refused, texts put off,
    /// a service that was answering — says nothing about this one. (What the
    /// turn end learned before the first model was seen here was learned under
    /// that first model, and stays.)
    pub fn may_catch_up(&self, agent_id: &str, model: &str, now: SystemTime) -> bool {
        self.with(agent_id, |agent| {
            if agent.model.as_deref() != Some(model) {
                let changed = agent.model.is_some();
                agent.model = Some(model.to_owned());
                agent.settled = false;
                if changed {
                    agent.set_aside.clear();
                    agent.put_off.clear();
                    agent.served_last = false;
                    agent.resting_since = Some(now);
                }
            }
            !agent.resting(now)
        })
    }

    /// Catch-up for `agent_id` rests from `now` (see the module doc for when).
    pub fn rest(&self, agent_id: &str, now: SystemTime) {
        self.with(agent_id, |agent| agent.resting_since = Some(now));
    }

    /// `row` of `agent_id` was written with a text, its vector being of
    /// `row_model` (`None`: no vector, or one of no recorded model). A row that is
    /// not of the model in use is one more row to catch up on — unless its text
    /// is set aside: `text` is what catch-up would ask about for the row (a
    /// brief, a digest), and a text set aside is not asked about again, so
    /// writing it once more leaves a settled agent settled.
    pub fn row_written(
        &self,
        agent_id: &str,
        row: &VectorRow,
        text: &str,
        row_model: Option<&str>,
    ) {
        let entry = KeptBack::new(row.clone(), text);
        self.with(agent_id, |agent| {
            if agent.model.as_deref() != row_model && !agent.set_aside.contains(&entry) {
                agent.settled = false;
            }
        });
    }

    /// Whether the last pass found nothing left to embed for `agent_id`, and no
    /// row was written since that needs a vector.
    pub fn is_settled(&self, agent_id: &str) -> bool {
        self.with(agent_id, |agent| agent.settled)
    }

    /// A pass over `agent_id`'s rows found nothing left to embed.
    pub fn settle(&self, agent_id: &str) {
        self.with(agent_id, |agent| agent.settled = true);
    }

    /// A request made for `agent_id` got its vector — the text `row` holds was
    /// embedded. The service is answering, and nothing is held against the row
    /// any more.
    pub fn request_served(&self, agent_id: &str, row: &VectorRow) {
        self.with(agent_id, |agent| {
            agent.served_last = true;
            agent.put_off.retain(|kept| &kept.row != row);
            agent.set_aside.retain(|kept| &kept.row != row);
        });
    }

    /// The request for `text`, which `row` of `agent_id` holds, failed, and the
    /// service did not say it refused the text. Says whether catch-up rests now:
    ///
    /// - the request before this one got its vector — the service was answering
    ///   a moment ago, so this may be about the text. The text is put off, and
    ///   catch-up does not rest (`false`);
    /// - otherwise the service is failing: catch-up rests from `now` (`true`),
    ///   and nothing is held against the text.
    pub fn request_failed(
        &self,
        agent_id: &str,
        row: VectorRow,
        text: &str,
        now: SystemTime,
    ) -> bool {
        self.with(agent_id, |agent| {
            if agent.served_last {
                agent.served_last = false;
                keep_back(&mut agent.put_off, KeptBack::new(row, text));
                false
            } else {
                agent.resting_since = Some(now);
                true
            }
        })
    }

    /// The service refused `text`, which `row` of `agent_id` holds: it is not
    /// asked about again under this model.
    pub fn set_aside(&self, agent_id: &str, row: VectorRow, text: &str) {
        self.with(agent_id, |agent| {
            agent.put_off.retain(|kept| kept.row != row);
            keep_back(&mut agent.set_aside, KeptBack::new(row, text));
        });
    }

    /// Where `text`, which `row` of `agent_id` holds, stands.
    pub fn standing(&self, agent_id: &str, row: &VectorRow, text: &str) -> Standing {
        let entry = KeptBack::new(row.clone(), text);
        self.with(agent_id, |agent| {
            if agent.set_aside.contains(&entry) {
                Standing::SetAside
            } else if let Some(place) = agent.put_off.iter().position(|kept| kept == &entry) {
                Standing::PutOff { place }
            } else {
                Standing::Open
            }
        })
    }

    /// How many texts of `agent_id` are kept back — set aside or put off. A
    /// search for rows to embed asks for this many more, so that it finds a full
    /// pass of open rows behind them.
    pub fn kept_back(&self, agent_id: &str) -> usize {
        self.with(agent_id, |agent| {
            agent.set_aside.len() + agent.put_off.len()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }
    fn after(secs: u64) -> SystemTime {
        t0() + Duration::from_secs(secs)
    }
    const REST: u64 = EMBEDDING_REST.as_secs();

    fn turn(turn: u32) -> VectorRow {
        VectorRow::Turn {
            task_id: "t1".into(),
            turn,
        }
    }
    fn task() -> VectorRow {
        VectorRow::Task {
            task_id: "t1".into(),
        }
    }

    #[test]
    fn the_first_model_seen_is_not_a_change_and_a_later_one_rests() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        assert!(upkeep.may_catch_up("a", "embed-a", after(1)));

        // Another model: a rest of one full period, counted from the change.
        assert!(!upkeep.may_catch_up("a", "embed-b", after(10)));
        assert!(!upkeep.may_catch_up("a", "embed-b", after(10 + REST - 1)));
        assert!(upkeep.may_catch_up("a", "embed-b", after(10 + REST)));
        assert!(upkeep.may_catch_up("a", "embed-b", after(10 + REST + 1)));
    }

    /// An agent served by two entries in turn: every change renews the rest, so
    /// catch-up never runs while the model keeps moving.
    #[test]
    fn a_model_that_keeps_changing_never_gets_to_catch_up() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        let mut now = 0;
        for round in 0..20 {
            now += REST - 1;
            let model = if round % 2 == 0 { "embed-b" } else { "embed-a" };
            assert!(
                !upkeep.may_catch_up("a", model, after(now)),
                "round {round}"
            );
        }
        // It settles on one model: one period later catch-up may run.
        let last = "embed-a";
        assert!(!upkeep.may_catch_up("a", last, after(now + REST - 1)));
        assert!(upkeep.may_catch_up("a", last, after(now + REST)));
    }

    #[test]
    fn a_rest_lasts_one_period_from_its_start() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        upkeep.rest("a", after(5));
        assert!(!upkeep.may_catch_up("a", "embed-a", after(5)));
        assert!(!upkeep.may_catch_up("a", "embed-a", after(5 + REST - 1)));
        // A rest started during the rest starts the period again.
        upkeep.rest("a", after(100));
        assert!(!upkeep.may_catch_up("a", "embed-a", after(5 + REST)));
        assert!(upkeep.may_catch_up("a", "embed-a", after(100 + REST)));

        // A rest started before any model was seen rests the first check too.
        upkeep.rest("b", t0());
        assert!(!upkeep.may_catch_up("b", "embed-a", after(1)));
        assert!(upkeep.may_catch_up("b", "embed-a", after(REST)));
    }

    /// A clock set back past the start of a rest does not stretch the rest to
    /// the size of the jump: it runs one period from the new time.
    #[test]
    fn a_clock_set_back_rests_one_period_not_the_jump() {
        let upkeep = EmbeddingUpkeep::new();
        upkeep.rest("a", after(1_000_000));
        assert!(!upkeep.may_catch_up("a", "embed-a", t0()));
        assert!(!upkeep.may_catch_up("a", "embed-a", after(REST - 1)));
        assert!(upkeep.may_catch_up("a", "embed-a", after(REST)));
    }

    #[test]
    fn agents_are_paced_apart() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        assert!(upkeep.may_catch_up("b", "embed-b", t0()));
        upkeep.rest("a", after(1));
        assert!(!upkeep.may_catch_up("a", "embed-a", after(2)));
        assert!(upkeep.may_catch_up("b", "embed-b", after(2)));

        // What one agent's requests showed says nothing about another's.
        upkeep.request_served("b", &turn(1));
        assert!(
            upkeep.request_failed("c", turn(1), "text", after(3)),
            "agent `c` has no served request to go by"
        );
        assert!(!upkeep.request_failed("b", turn(2), "text", after(3)));
    }

    #[test]
    fn settled_lasts_until_a_row_of_another_model_is_written_or_the_model_changes() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(!upkeep.is_settled("a"));
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        upkeep.settle("a");
        assert!(upkeep.is_settled("a"));

        upkeep.row_written("a", &turn(1), "text", Some("embed-a"));
        assert!(upkeep.is_settled("a"), "a row of the model changes nothing");
        upkeep.row_written("a", &turn(1), "text", None);
        assert!(!upkeep.is_settled("a"), "a row without a vector needs one");

        upkeep.settle("a");
        upkeep.row_written("a", &turn(1), "text", Some("embed-b"));
        assert!(!upkeep.is_settled("a"), "so does a row of another model");

        // A text set aside is not asked about again: writing it again is nothing
        // to catch up on. The same row with another text is.
        upkeep.set_aside("a", turn(2), "refused");
        upkeep.settle("a");
        upkeep.row_written("a", &turn(2), "refused", None);
        assert!(upkeep.is_settled("a"), "its text is set aside");
        upkeep.row_written("a", &turn(3), "refused", None);
        assert!(!upkeep.is_settled("a"), "set aside is a text of one row");
        upkeep.settle("a");
        upkeep.row_written("a", &turn(2), "another text", None);
        assert!(!upkeep.is_settled("a"), "another text of the row");

        upkeep.settle("a");
        let _ = upkeep.may_catch_up("a", "embed-b", after(1));
        assert!(
            !upkeep.is_settled("a"),
            "and every row, once the model moved"
        );
    }

    /// A failure right after a served request puts the text off and does not
    /// rest; a failure after a failure — or with nothing to go by — is the
    /// service's, rests, and holds nothing against the text.
    #[test]
    fn one_failure_after_a_served_request_is_the_texts_and_a_second_is_the_services() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));

        // Nothing served yet: nothing says the service answers.
        assert!(upkeep.request_failed("a", turn(1), "one", after(1)));
        assert_eq!(upkeep.standing("a", &turn(1), "one"), Standing::Open);
        assert!(!upkeep.may_catch_up("a", "embed-a", after(2)), "resting");

        // A served request, then a failure: put off, no new rest.
        upkeep.request_served("a", &turn(9));
        assert!(!upkeep.request_failed("a", turn(2), "two", after(1 + REST)));
        assert_eq!(
            upkeep.standing("a", &turn(2), "two"),
            Standing::PutOff { place: 0 }
        );
        assert!(upkeep.may_catch_up("a", "embed-a", after(1 + REST)));

        // The next failure in a row is the service's.
        assert!(upkeep.request_failed("a", turn(3), "three", after(2 + REST)));
        assert_eq!(upkeep.standing("a", &turn(3), "three"), Standing::Open);
        assert!(!upkeep.may_catch_up("a", "embed-a", after(3 + REST)));
        assert_eq!(upkeep.kept_back("a"), 1);
    }

    #[test]
    fn texts_put_off_are_asked_about_in_the_order_they_were_put_off() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        for number in 1..=3 {
            upkeep.request_served("a", &turn(90 + number));
            assert!(!upkeep.request_failed("a", turn(number), "text", after(1)));
        }
        let place = |number: u32| upkeep.standing("a", &turn(number), "text");
        assert_eq!(place(1), Standing::PutOff { place: 0 });
        assert_eq!(place(2), Standing::PutOff { place: 1 });
        assert_eq!(place(3), Standing::PutOff { place: 2 });

        // Failing again moves a text behind the others.
        upkeep.request_served("a", &turn(99));
        assert!(!upkeep.request_failed("a", turn(1), "text", after(2)));
        assert_eq!(place(2), Standing::PutOff { place: 0 });
        assert_eq!(place(3), Standing::PutOff { place: 1 });
        assert_eq!(place(1), Standing::PutOff { place: 2 });
        assert_eq!(upkeep.kept_back("a"), 3, "one entry per row");

        // A vector for the row ends it.
        upkeep.request_served("a", &turn(2));
        assert_eq!(place(2), Standing::Open);
        assert_eq!(place(3), Standing::PutOff { place: 0 });
        assert_eq!(upkeep.kept_back("a"), 2);
    }

    #[test]
    fn a_text_is_kept_back_not_its_row_and_only_under_the_model_it_failed_with() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        upkeep.set_aside("a", turn(1), "refused text");
        upkeep.set_aside("a", turn(1), "refused text");
        upkeep.set_aside("a", turn(2), "refused text");
        // A task and a turn of that task are two rows.
        upkeep.set_aside("a", task(), "refused text");
        upkeep.request_served("a", &turn(9));
        assert!(!upkeep.request_failed("a", turn(3), "failed text", after(1)));
        assert_eq!(upkeep.kept_back("a"), 4);
        assert_eq!(
            upkeep.standing("a", &turn(1), "refused text"),
            Standing::SetAside
        );
        assert_eq!(
            upkeep.standing("a", &task(), "refused text"),
            Standing::SetAside
        );
        // The same row with another text is a row like any other ...
        assert_eq!(
            upkeep.standing("a", &task(), "another text"),
            Standing::Open
        );
        assert_eq!(
            upkeep.standing("a", &turn(3), "another text"),
            Standing::Open
        );
        // ... and so are another row and another agent.
        assert_eq!(
            upkeep.standing("a", &turn(4), "refused text"),
            Standing::Open
        );
        assert_eq!(
            upkeep.standing("b", &turn(1), "refused text"),
            Standing::Open
        );
        assert_eq!(upkeep.kept_back("b"), 0);

        // A row holds one text: what is said about its new text replaces what was
        // said about the old one.
        upkeep.set_aside("a", turn(3), "failed text");
        assert_eq!(
            upkeep.standing("a", &turn(3), "failed text"),
            Standing::SetAside
        );
        upkeep.set_aside("a", turn(1), "its next text");
        assert_eq!(
            upkeep.standing("a", &turn(1), "refused text"),
            Standing::Open
        );
        assert_eq!(upkeep.kept_back("a"), 4);

        // What one model refused says nothing about another.
        let _ = upkeep.may_catch_up("a", "embed-b", after(2));
        assert_eq!(upkeep.kept_back("a"), 0);
        assert_eq!(
            upkeep.standing("a", &turn(2), "refused text"),
            Standing::Open
        );
        // Nor does a service that answered under the old model.
        assert!(upkeep.request_failed("a", turn(5), "text", after(3)));
    }

    /// A turn end writes its new rows before it catches up on old ones: what the
    /// writers learn — a text refused, a text put off, a service that answers —
    /// before the model is first seen is not thrown away when it is.
    #[test]
    fn what_is_learned_before_the_model_is_first_seen_stays() {
        let upkeep = EmbeddingUpkeep::new();
        upkeep.set_aside("a", turn(1), "refused text");
        upkeep.request_served("a", &turn(9));
        assert!(!upkeep.request_failed("a", turn(2), "failed text", t0()));

        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        assert_eq!(
            upkeep.standing("a", &turn(1), "refused text"),
            Standing::SetAside
        );
        assert_eq!(
            upkeep.standing("a", &turn(2), "failed text"),
            Standing::PutOff { place: 0 }
        );
        assert_eq!(upkeep.kept_back("a"), 2);
    }

    #[test]
    fn the_texts_kept_back_are_bounded_and_the_oldest_is_forgotten_first() {
        let upkeep = EmbeddingUpkeep::new();
        assert!(upkeep.may_catch_up("a", "embed-a", t0()));
        let over = MAX_KEPT_BACK as u32 + 3;
        for number in 0..over {
            upkeep.set_aside("a", turn(number), "refused");
            upkeep.request_served("a", &turn(1_000_000));
            assert!(!upkeep.request_failed("a", turn(500_000 + number), "failed", after(1)));
            assert!(upkeep.kept_back("a") <= 2 * MAX_KEPT_BACK);
        }
        assert_eq!(upkeep.kept_back("a"), 2 * MAX_KEPT_BACK);
        for forgotten in 0..3 {
            assert_eq!(
                upkeep.standing("a", &turn(forgotten), "refused"),
                Standing::Open
            );
            assert_eq!(
                upkeep.standing("a", &turn(500_000 + forgotten), "failed"),
                Standing::Open
            );
        }
        assert_eq!(
            upkeep.standing("a", &turn(3), "refused"),
            Standing::SetAside
        );
        assert_eq!(
            upkeep.standing("a", &turn(500_003), "failed"),
            Standing::PutOff { place: 0 }
        );
        assert_eq!(
            upkeep.standing("a", &turn(over - 1), "refused"),
            Standing::SetAside
        );
    }

    #[test]
    fn the_number_of_tracked_agents_is_bounded() {
        let upkeep = EmbeddingUpkeep::new();
        for n in 0..(MAX_TRACKED_AGENTS * 3) {
            upkeep.rest(&format!("agent-{n}"), t0());
            let tracked = upkeep.agents.lock().unwrap().len();
            assert!(tracked <= MAX_TRACKED_AGENTS, "{tracked} agents tracked");
        }
        // The newest agent is tracked; the rest its entry displaced start over.
        let newest = format!("agent-{}", MAX_TRACKED_AGENTS * 3 - 1);
        assert!(!upkeep.may_catch_up(&newest, "embed-a", after(1)));
    }
}
