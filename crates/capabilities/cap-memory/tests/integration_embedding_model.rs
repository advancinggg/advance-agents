//! The index binds every vector to the embedding model that produced it, an
//! embedding that cannot be computed never costs a turn its index rows, and a
//! row left without a usable vector — a turn's digest or a task's brief, of the
//! task at hand or of one that gets no further turn — gets one at a later turn
//! end.
//!
//! Drives the real `Components::sync_turn_index` / `sync_task_index` /
//! `heal_vectors` seams and the real `PostProcessor::run` pipeline with a
//! scripted [`Embedder`] whose model can change, disappear (nothing to embed
//! with), whose requests can fail — all of them, or those for some texts — or
//! be refused over their text, on an injected clock; and with an index that can
//! be made unreadable or unwritable.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use advance_shared_types::mailbox::{ActionResult, Message, MessageContext, MessageKind};
use advance_shared_types::memory::PostProcessorHook;
use cap_memory::post_processor::CANONICAL_STEPS;
use cap_memory::summary::{Summary, SummaryMeta};
use cap_memory::task_storage::TASK_TURN_INDEX_FILENAME;
use cap_memory::turn_index::{Importance, LogOffset, TurnEntry, TurnIndex, TurnIndexMeta};
use cap_memory::{
    CatchUpError, Components, Embedder, EmbedderError, Extraction, FailureCooldown,
    InMemorySimilarityIndex, InMemorySqliteIndex, IndexUnavailable, MemoryEntry, MemoryIndexRow,
    MemoryStatus, MemoryStore, MemoryType, MutableClock, PostProcessor, Reconciler, SqliteIndex,
    StubBatchExtractor, TaskIndexRow, TurnIndexRow, CATCH_UP_TIME, DEFAULT_MAX_ACTIVE_PER_AGENT,
    DEFAULT_THRESHOLD, EMBEDDING_REST, RECENT_TURN_WINDOW, VECTORS_PER_TURN_END,
};

// ── the scripted embedder ──

/// An embedder with a switchable model. `None` → nothing to embed with (an empty
/// vector, no request); `failing` → every request fails; a request for a text in
/// `failing_texts` fails whatever else is set, and one for a text in `refused`
/// is refused as a text.
struct ScriptedEmbedder {
    model: Mutex<Option<String>>,
    failing: AtomicBool,
    failing_texts: Mutex<Vec<String>>,
    refused: Mutex<Vec<String>>,
    /// `(n, model)`: the n-th request from now on is already answered by `model`
    /// — `None`: it finds nothing to embed with any more.
    moves: Mutex<Option<(usize, Option<String>)>>,
    /// Vectors come back without the name of their model.
    unnamed: AtomicBool,
    /// Every request takes this long, on this clock.
    slow: Mutex<Option<(Arc<MutableClock>, Duration)>>,
    /// A request for one of these texts is never answered.
    hanging: Mutex<Vec<String>>,
    /// Every request that is answered is answered this long after it was made, on
    /// tokio's clock.
    answered_after: Mutex<Duration>,
    requests: AtomicUsize,
    /// Every text a request was made for, in order.
    requested: Mutex<Vec<String>>,
}

impl ScriptedEmbedder {
    fn new(model: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            model: Mutex::new(model.map(str::to_string)),
            failing: AtomicBool::new(false),
            failing_texts: Mutex::new(Vec::new()),
            refused: Mutex::new(Vec::new()),
            moves: Mutex::new(None),
            unnamed: AtomicBool::new(false),
            slow: Mutex::new(None),
            hanging: Mutex::new(Vec::new()),
            answered_after: Mutex::new(Duration::ZERO),
            requests: AtomicUsize::new(0),
            requested: Mutex::new(Vec::new()),
        })
    }
    fn set_model(&self, model: Option<&str>) {
        *self.model.lock().unwrap() = model.map(str::to_string);
    }
    /// Every request fails (the service is down).
    fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
    /// Requests for these texts fail, and the service does not say why.
    fn fail_on(&self, texts: &[&str]) {
        *self.failing_texts.lock().unwrap() = texts.iter().map(|t| t.to_string()).collect();
    }
    /// Requests for these texts are refused over the text.
    fn refuse(&self, texts: &[&str]) {
        *self.refused.lock().unwrap() = texts.iter().map(|t| t.to_string()).collect();
    }
    fn move_to_at_request(&self, nth: usize, model: &str) {
        *self.moves.lock().unwrap() = Some((self.requests() + nth, Some(model.to_string())));
    }
    fn lose_the_model_at_request(&self, nth: usize) {
        *self.moves.lock().unwrap() = Some((self.requests() + nth, None));
    }
    fn set_unnamed(&self, unnamed: bool) {
        self.unnamed.store(unnamed, Ordering::SeqCst);
    }
    fn take_per_request(&self, clock: &Arc<MutableClock>, takes: Duration) {
        *self.slow.lock().unwrap() = Some((clock.clone(), takes));
    }
    /// Requests for these texts are never answered.
    fn hang_on(&self, texts: &[&str]) {
        *self.hanging.lock().unwrap() = texts.iter().map(|t| t.to_string()).collect();
    }
    /// Requests are answered this long after they are made, on tokio's clock.
    fn answer_after(&self, wait: Duration) {
        *self.answered_after.lock().unwrap() = wait;
    }
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
    fn requested(&self) -> Vec<String> {
        self.requested.lock().unwrap().clone()
    }
    /// The vector model `model` gives `text`: distinct per model and per text.
    fn vector(model: &str, text: &str) -> Vec<f32> {
        vec![model.len() as f32, text.len() as f32, 1.0]
    }
}

#[async_trait]
impl Embedder for ScriptedEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedderError> {
        Ok(self.embed_recorded(text).await?.0)
    }
    async fn embed_recorded(
        &self,
        text: &str,
    ) -> Result<(Vec<f32>, Option<String>), EmbedderError> {
        if self.model.lock().unwrap().is_none() {
            return Ok((Vec::new(), None));
        }
        let nth = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
        self.requested.lock().unwrap().push(text.to_string());
        if let Some((clock, takes)) = &*self.slow.lock().unwrap() {
            clock.advance(*takes);
        }
        let hangs = self.hanging.lock().unwrap().iter().any(|t| t == text);
        if hangs {
            std::future::pending::<()>().await;
        }
        let wait = *self.answered_after.lock().unwrap();
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        let moved = self.moves.lock().unwrap().clone();
        if let Some((at, model)) = moved {
            if nth >= at {
                self.set_model(model.as_deref());
                *self.moves.lock().unwrap() = None;
            }
        }
        if self.refused.lock().unwrap().iter().any(|t| t == text) {
            return Err(EmbedderError::Refused("too long for the model".into()));
        }
        if self.failing.load(Ordering::SeqCst)
            || self.failing_texts.lock().unwrap().iter().any(|t| t == text)
        {
            return Err(EmbedderError::Upstream("upstream 503".into()));
        }
        let Some(model) = self.model.lock().unwrap().clone() else {
            return Ok((Vec::new(), None));
        };
        let vector = Self::vector(&model, text);
        if self.unnamed.load(Ordering::SeqCst) {
            return Ok((vector, None));
        }
        Ok((vector, Some(model)))
    }
    fn current_model(&self) -> Option<String> {
        self.model.lock().unwrap().clone()
    }
}

// ── an index that says how it was searched ──

/// One search for rows a query cannot be compared with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Search {
    Tasks { limit: usize },
    Turns { window: usize, limit: usize },
}

/// What one catch-up pass with nothing set aside searches: both tables, for a
/// full pass of rows each, turn rows within the window a reader scans.
fn one_pass() -> Vec<Search> {
    vec![
        Search::Tasks {
            limit: VECTORS_PER_TURN_END,
        },
        Search::Turns {
            window: RECENT_TURN_WINDOW,
            limit: VECTORS_PER_TURN_END,
        },
    ]
}

/// The in-memory index, recording every search for rows not of a model — and
/// failing those searches, or the writes of a vector, when told to.
#[derive(Default)]
struct WatchedIndex {
    inner: InMemorySqliteIndex,
    searches: Mutex<Vec<Search>>,
    unreadable: AtomicBool,
    unwritable: AtomicBool,
}

impl WatchedIndex {
    fn searches(&self) -> Vec<Search> {
        self.searches.lock().unwrap().clone()
    }
    /// Catch-up passes that searched the index (a pass searches both tables).
    fn passes(&self) -> usize {
        let searches = self.searches();
        assert_eq!(searches.len() % 2, 0, "{searches:?}");
        searches.len() / 2
    }
    fn set_unreadable(&self, unreadable: bool) {
        self.unreadable.store(unreadable, Ordering::SeqCst);
    }
    fn set_unwritable(&self, unwritable: bool) {
        self.unwritable.store(unwritable, Ordering::SeqCst);
    }
    fn locked() -> IndexUnavailable {
        IndexUnavailable("database is locked".into())
    }
}

impl SqliteIndex for WatchedIndex {
    fn upsert_turn(&self, row: TurnIndexRow) {
        self.inner.upsert_turn(row)
    }
    fn upsert_task(&self, row: TaskIndexRow) {
        self.inner.upsert_task(row)
    }
    fn upsert_memory(&self, row: MemoryIndexRow) {
        self.inner.upsert_memory(row)
    }
    fn get_turn(&self, agent_id: &str, task_id: &str, turn: u32) -> Option<TurnIndexRow> {
        self.inner.get_turn(agent_id, task_id, turn)
    }
    fn get_task(&self, agent_id: &str, task_id: &str) -> Option<TaskIndexRow> {
        self.inner.get_task(agent_id, task_id)
    }
    fn get_memory(&self, agent_id: &str, memory_id: &str) -> Option<MemoryIndexRow> {
        self.inner.get_memory(agent_id, memory_id)
    }
    fn list_turns_for_agent(&self, agent_id: &str) -> Vec<TurnIndexRow> {
        self.inner.list_turns_for_agent(agent_id)
    }
    fn list_tasks_for_agent(&self, agent_id: &str) -> Vec<TaskIndexRow> {
        self.inner.list_tasks_for_agent(agent_id)
    }
    fn list_memory_for_agent(&self, agent_id: &str) -> Vec<MemoryIndexRow> {
        self.inner.list_memory_for_agent(agent_id)
    }
    fn list_turns_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        window: usize,
        limit: usize,
    ) -> Result<Vec<TurnIndexRow>, IndexUnavailable> {
        self.searches
            .lock()
            .unwrap()
            .push(Search::Turns { window, limit });
        if self.unreadable.load(Ordering::SeqCst) {
            return Err(Self::locked());
        }
        self.inner
            .list_turns_not_of_model(agent_id, model, window, limit)
    }
    fn list_tasks_not_of_model(
        &self,
        agent_id: &str,
        model: &str,
        limit: usize,
    ) -> Result<Vec<TaskIndexRow>, IndexUnavailable> {
        self.searches.lock().unwrap().push(Search::Tasks { limit });
        if self.unreadable.load(Ordering::SeqCst) {
            return Err(Self::locked());
        }
        self.inner.list_tasks_not_of_model(agent_id, model, limit)
    }
    fn set_turn_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
        digest: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        if self.unwritable.load(Ordering::SeqCst) {
            return Err(Self::locked());
        }
        self.inner
            .set_turn_embedding(agent_id, task_id, turn, digest, embedding, model)
    }
    fn set_task_brief_embedding(
        &self,
        agent_id: &str,
        task_id: &str,
        brief: &str,
        embedding: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        if self.unwritable.load(Ordering::SeqCst) {
            return Err(Self::locked());
        }
        self.inner
            .set_task_brief_embedding(agent_id, task_id, brief, embedding, model)
    }
    fn forget_agent(&self, agent_id: &str) -> Result<(), IndexUnavailable> {
        self.inner.forget_agent(agent_id)
    }
}

// ── fixtures ──

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

struct Rig {
    c: Components,
    embedder: Arc<ScriptedEmbedder>,
    clock: Arc<MutableClock>,
    index: Arc<WatchedIndex>,
}

impl Rig {
    /// Let the rest after a failed request or a model change run out.
    fn rest(&self) {
        self.clock.advance(EMBEDDING_REST);
    }
    fn tick(&self) {
        self.clock.advance(Duration::from_secs(1));
    }
    fn turn_row(&self, turn: u32) -> TurnIndexRow {
        self.index.get_turn("a", "t1", turn).expect("turn row")
    }
    fn task_row(&self) -> TaskIndexRow {
        self.task_row_of("t1")
    }
    fn task_row_of(&self, task: &str) -> TaskIndexRow {
        self.index.get_task("a", task).expect("task row")
    }
    /// A row as an index written by an older version holds it: a vector, and no
    /// record of the model that produced it.
    fn seed_row_of_no_recorded_model(&self, turn: u32, digest: &str) {
        self.tick();
        self.index.upsert_turn(TurnIndexRow {
            agent_id: "a".into(),
            task_id: "t1".into(),
            turn,
            digest: digest.into(),
            embedding: vec![0.25, 0.5],
            embedding_model: None,
            reference_count: turn,
            updated_at: cap_memory::clock_now_rfc3339_z(&*self.clock),
        });
    }
    /// The same for a task `agent` worked on: a brief, its vector, no model.
    fn seed_task_of_no_recorded_model(&self, agent: &str, task: &str, brief: &str) {
        self.tick();
        let now = cap_memory::clock_now_rfc3339_z(&*self.clock);
        self.index.upsert_task(TaskIndexRow {
            task_id: task.into(),
            agent_id: agent.into(),
            last_turn_at: now.clone(),
            turns_total: 7,
            updated_at: now,
            brief_snapshot: brief.into(),
            brief_embedding: Some(vec![0.25, 0.5]),
            brief_embedding_model: None,
        });
    }
    /// The task-side half of a turn end of task `t1`: its row is written, then
    /// older rows are caught up. Says how many rows were caught up.
    async fn task_turn_end(&self, brief: &str, turns_total: u32) -> usize {
        self.c
            .sync_task_index(&summary(brief, turns_total))
            .await
            .expect("the task row is written");
        self.c.heal_vectors("a").await.expect("catch-up")
    }
}

fn rig(model: Option<&str>) -> Rig {
    let embedder = ScriptedEmbedder::new(model);
    let clock = Arc::new(MutableClock::new(t0()));
    let index = Arc::new(WatchedIndex::default());
    let c = Components::with_l6_defaults(
        Arc::new(StubBatchExtractor::with_extraction(Default::default())),
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD),
        Arc::new(MemoryStore::new()),
        Arc::new(FailureCooldown::new(600)),
        clock.clone(),
    )
    .with_embedder(embedder.clone())
    .with_sqlite_index(index.clone());
    Rig {
        c,
        embedder,
        clock,
        index,
    }
}

/// A turn as Step 7 hands it to the index, with a digest and no collapsed view.
fn turn(turn: u32, digest: &str) -> TurnEntry {
    TurnEntry {
        turn,
        timestamp: "2026-11-17T00:00:00Z".into(),
        agent_id: "a".into(),
        task_id: "t1".into(),
        log_offset: LogOffset {
            start_line: 0,
            end_line: 0,
        },
        has_user_instruction: false,
        has_user_correction: false,
        has_tool_use: false,
        has_decision: false,
        importance: Importance::Normal,
        digest: digest.into(),
        collapsed_view: String::new(),
        git_commit: "0000000".into(),
        git_diff_summary: String::new(),
        git_checkpoints: vec![],
        reference_count: 0,
        content_identifiers: vec![],
        read_file_versions: vec![],
        tokens_digest: 0,
        tokens_collapse_excerpt: 0,
        tokens_l0_processed: 0,
    }
}

fn summary_of(agent: &str, task: &str, brief: &str, turns_total: u32) -> Summary {
    Summary {
        meta: SummaryMeta {
            task_id: task.into(),
            agent_id: agent.into(),
            title: "task".into(),
            status: "active".into(),
            profile: "test".into(),
            turns_total,
            last_updated: "2026-11-17T00:00:00Z".into(),
            last_turn_at: "2026-11-17T00:00:00Z".into(),
            last_brief_update: 0,
            last_decisions_update: 0,
            last_state_update: 0,
        },
        brief: brief.into(),
        key_decisions: vec![],
        findings: vec![],
        open_questions: vec![],
        current_state: String::new(),
        errors_and_corrections: vec![],
        workflow: String::new(),
    }
}

fn summary(brief: &str, turns_total: u32) -> Summary {
    summary_of("a", "t1", brief, turns_total)
}

// ── vectors carry their model ──

/// A turn row and a task row store the model their vector came from; a turn's
/// vector is computed from its digest and its collapsed view.
#[tokio::test]
async fn rows_record_the_model_of_their_vector() {
    let rig = rig(Some("embed-a"));

    let mut with_view = turn(1, "digest one");
    with_view.collapsed_view = "view".into();
    rig.c.sync_turn_index("a", &with_view).await.unwrap();
    rig.c
        .sync_turn_index("a", &turn(2, "digest two"))
        .await
        .unwrap();
    rig.c
        .sync_task_index(&summary("the brief", 2))
        .await
        .unwrap();

    let row = rig.turn_row(1);
    assert_eq!(row.embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        row.embedding,
        ScriptedEmbedder::vector("embed-a", "digest one\nview")
    );
    assert_eq!(
        rig.turn_row(2).embedding,
        ScriptedEmbedder::vector("embed-a", "digest two\n")
    );
    let task = rig.task_row();
    assert_eq!(task.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        task.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "the brief"))
    );
}

/// An unchanged brief is not embedded again while the model stays the same. Once
/// the embedder names another model it IS — otherwise the task's vector would
/// stay in a model no query is made with any more — but only after the rest that
/// follows a change of model.
#[tokio::test]
async fn an_unchanged_brief_is_embedded_again_once_the_rest_after_a_model_change_is_over() {
    let rig = rig(Some("embed-a"));

    assert_eq!(rig.task_turn_end("the brief", 1).await, 0);
    assert_eq!(rig.task_turn_end("the brief", 2).await, 0);
    assert_eq!(
        rig.embedder.requests(),
        1,
        "same brief, same model: no request"
    );

    rig.embedder.set_model(Some("embed-bb"));
    assert_eq!(rig.task_turn_end("the brief", 3).await, 0);
    assert_eq!(rig.embedder.requests(), 1, "the change starts a rest");
    let resting = rig.task_row();
    assert_eq!(resting.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(resting.turns_total, 3, "the rest of the row keeps up");

    rig.clock.advance(EMBEDDING_REST - Duration::from_secs(1));
    assert_eq!(rig.task_turn_end("the brief", 4).await, 0);
    assert_eq!(rig.embedder.requests(), 1, "still resting");

    rig.tick();
    assert_eq!(rig.task_turn_end("the brief", 5).await, 1);
    assert_eq!(rig.embedder.requests(), 2, "the rest is over: embedded");
    let task = rig.task_row();
    assert_eq!(task.brief_embedding_model.as_deref(), Some("embed-bb"));
    assert_eq!(
        task.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-bb", "the brief"))
    );
    assert_eq!(task.turns_total, 5);

    assert_eq!(rig.task_turn_end("the brief", 6).await, 0);
    assert_eq!(rig.embedder.requests(), 2, "settled on the new model");
}

/// The writer of a task row never embeds an unchanged brief itself, whatever
/// model its vector is of: the row keeps vector and model verbatim, and getting
/// a vector of the model in use is left to the catch-up.
#[tokio::test]
async fn writing_a_task_row_keeps_the_vector_of_an_unchanged_brief_as_it_is() {
    let rig = rig(Some("embed-a"));
    rig.c
        .sync_task_index(&summary("the brief", 1))
        .await
        .unwrap();
    let written = rig.task_row();

    rig.embedder.set_model(Some("embed-bb"));
    for turns_total in 2..6 {
        rig.rest();
        rig.c
            .sync_task_index(&summary("the brief", turns_total))
            .await
            .unwrap();
    }
    assert_eq!(rig.embedder.requests(), 1, "the writer made no request");
    let kept = rig.task_row();
    assert_eq!(kept.brief_embedding, written.brief_embedding);
    assert_eq!(kept.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(kept.turns_total, 5);
    assert!(rig.index.searches().is_empty(), "and searched nothing");
}

/// A brief whose TEXT changed is new text: it is embedded at once, by the model
/// in use, even during the rest that follows a change of model.
#[tokio::test]
async fn a_changed_brief_is_embedded_at_once_even_while_catch_up_rests() {
    let rig = rig(Some("embed-a"));
    assert_eq!(rig.task_turn_end("the brief", 1).await, 0);
    rig.embedder.set_model(Some("embed-bb"));
    assert_eq!(rig.task_turn_end("the brief", 2).await, 0);
    assert_eq!(rig.embedder.requests(), 1, "resting");

    assert_eq!(rig.task_turn_end("a new brief", 3).await, 0, "resting");
    assert_eq!(rig.embedder.requests(), 2);
    let task = rig.task_row();
    assert_eq!(task.brief_embedding_model.as_deref(), Some("embed-bb"));
    assert_eq!(
        task.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-bb", "a new brief"))
    );
}

// ── nothing to embed with ──

/// With nothing to embed with, rows are written WITHOUT a vector (no request is
/// made) — and both pick a vector up at the first turn end that has a model.
#[tokio::test]
async fn without_a_model_rows_are_written_without_a_vector_and_get_one_later() {
    let rig = rig(None);

    rig.c
        .sync_turn_index("a", &turn(1, "digest one"))
        .await
        .expect("no model is not an error");
    rig.c
        .sync_task_index(&summary("the brief", 1))
        .await
        .expect("no model is not an error");
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 0, "no request without a model");
    assert!(rig.index.searches().is_empty(), "and nothing is looked for");

    let row = rig.turn_row(1);
    assert_eq!(row.digest, "digest one");
    assert!(row.embedding.is_empty());
    assert_eq!(row.embedding_model, None);
    let task = rig.task_row();
    assert_eq!(task.brief_snapshot, "the brief");
    assert_eq!(task.brief_embedding, None);
    assert_eq!(task.brief_embedding_model, None);

    // A model appears; neither text changed. Both rows were written at the same
    // moment: the brief goes first.
    rig.embedder.set_model(Some("embed-a"));
    assert_eq!(rig.task_turn_end("the brief", 2).await, 2);
    assert_eq!(rig.embedder.requested(), ["the brief", "digest one\n"]);
    let task = rig.task_row();
    assert_eq!(task.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        task.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "the brief"))
    );
    let row = rig.turn_row(1);
    assert_eq!(row.embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        row.embedding,
        ScriptedEmbedder::vector("embed-a", "digest one\n")
    );
}

/// A vector that describes the CURRENT text survives a period with nothing to
/// embed with; a vector of the PREVIOUS brief text is dropped rather than left
/// standing for a brief it does not describe.
#[tokio::test]
async fn losing_the_model_keeps_a_current_vector_and_drops_a_stale_one() {
    let rig = rig(Some("embed-a"));
    rig.c
        .sync_turn_index("a", &turn(1, "digest one"))
        .await
        .unwrap();
    rig.c
        .sync_task_index(&summary("the brief", 1))
        .await
        .unwrap();
    let good_turn = rig.turn_row(1);
    let good_task = rig.task_row();

    rig.embedder.set_model(None);
    // Same turn digest, same brief: both vectors still describe the text.
    let mut again = turn(1, "digest one");
    again.reference_count = 4;
    rig.c.sync_turn_index("a", &again).await.unwrap();
    rig.c
        .sync_task_index(&summary("the brief", 2))
        .await
        .unwrap();
    let kept_turn = rig.turn_row(1);
    assert_eq!(kept_turn.embedding, good_turn.embedding);
    assert_eq!(kept_turn.embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(kept_turn.reference_count, 4, "the rest of the row updates");
    let kept_task = rig.task_row();
    assert_eq!(kept_task.brief_embedding, good_task.brief_embedding);
    assert_eq!(kept_task.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(kept_task.turns_total, 2);

    // The texts change while there is still no model: the old vectors go.
    rig.c
        .sync_turn_index("a", &turn(1, "digest rewritten"))
        .await
        .unwrap();
    rig.c
        .sync_task_index(&summary("another brief", 3))
        .await
        .unwrap();
    let turn_row = rig.turn_row(1);
    assert_eq!(turn_row.digest, "digest rewritten");
    assert!(turn_row.embedding.is_empty());
    assert_eq!(turn_row.embedding_model, None);
    let task = rig.task_row();
    assert_eq!(task.brief_snapshot, "another brief");
    assert_eq!(task.brief_embedding, None);
    assert_eq!(task.brief_embedding_model, None);
    assert_eq!(
        rig.embedder.requests(),
        2,
        "no request was made without a model"
    );
}

/// A text with nothing in it is never sent for embedding: the row is written
/// without a vector, and no later turn end asks for one either.
#[tokio::test]
async fn a_text_with_nothing_in_it_is_not_sent_for_embedding() {
    let rig = rig(Some("embed-a"));

    rig.c.sync_turn_index("a", &turn(1, "")).await.unwrap();
    rig.c.sync_turn_index("a", &turn(2, " \t\n")).await.unwrap();
    rig.c.sync_task_index(&summary("", 1)).await.unwrap();
    rig.c.sync_task_index(&summary("", 2)).await.unwrap();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 0);
    assert!(rig.turn_row(1).embedding.is_empty());
    assert!(rig.turn_row(2).embedding.is_empty());
    assert_eq!(rig.task_row().brief_embedding, None);
    assert_eq!(rig.task_row().turns_total, 2);

    // The brief gets a text, then loses it again: the vector goes with the text.
    rig.c.sync_task_index(&summary("a brief", 3)).await.unwrap();
    assert_eq!(rig.embedder.requests(), 1);
    assert!(rig.task_row().brief_embedding.is_some());
    rig.c
        .sync_task_index(&summary("\u{3000} ", 4))
        .await
        .unwrap();
    assert_eq!(rig.embedder.requests(), 1);
    let blank = rig.task_row();
    assert_eq!(blank.brief_snapshot, "\u{3000} ");
    assert_eq!(blank.brief_embedding, None);
    assert_eq!(blank.brief_embedding_model, None);

    // Rows without a text are nothing to catch up on: the pass that looks finds
    // nothing, and no later turn end looks again.
    let passes = rig.index.passes();
    for turns_total in 5..8 {
        rig.rest();
        assert_eq!(rig.task_turn_end("\u{3000} ", turns_total).await, 0);
    }
    assert_eq!(rig.embedder.requests(), 1);
    assert_eq!(rig.index.passes(), passes);
}

// ── a refused embedding request ──

/// A refused embedding request is reported, but only AFTER the rows are written:
/// the turn stays listed (without a vector) and the task row keeps tracking the
/// task. The texts did not change, so getting their vectors is catch-up: it waits
/// for the rest after the failure, then fills both in.
#[tokio::test]
async fn a_refused_embedding_request_still_writes_the_rows() {
    let rig = rig(Some("embed-a"));
    rig.embedder.set_failing(true);

    let turn_err = rig.c.sync_turn_index("a", &turn(1, "digest one")).await;
    assert!(matches!(turn_err, Err(EmbedderError::Upstream(_))));
    let task_err = rig.c.sync_task_index(&summary("the brief", 1)).await;
    assert!(matches!(task_err, Err(EmbedderError::Upstream(_))));
    assert_eq!(rig.embedder.requests(), 2);

    let row = rig.turn_row(1);
    assert_eq!(row.digest, "digest one");
    assert!(row.embedding.is_empty());
    assert_eq!(row.embedding_model, None);
    let task = rig.task_row();
    assert_eq!(task.brief_snapshot, "the brief");
    assert_eq!(task.turns_total, 1);
    assert_eq!(task.brief_embedding, None);

    // The provider recovers at once; catch-up still rests.
    rig.embedder.set_failing(false);
    assert_eq!(rig.task_turn_end("the brief", 2).await, 0);
    assert_eq!(rig.embedder.requests(), 2, "no request while resting");
    assert_eq!(rig.task_row().brief_embedding, None);
    assert_eq!(rig.task_row().turns_total, 2);
    assert!(rig.turn_row(1).embedding.is_empty());

    // The rest is over: the unchanged brief and the turn get their vectors.
    rig.rest();
    assert_eq!(rig.task_turn_end("the brief", 3).await, 2);
    assert_eq!(rig.embedder.requests(), 4);
    let task = rig.task_row();
    assert_eq!(task.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        task.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "the brief"))
    );
    assert_eq!(task.turns_total, 3);
    let row = rig.turn_row(1);
    assert_eq!(row.embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        row.embedding,
        ScriptedEmbedder::vector("embed-a", "digest one\n")
    );
}

/// A refused request never erases a vector that still describes the text, is not
/// repeated at every turn end, and never leaves the vector of an older brief
/// standing for a new one.
#[tokio::test]
async fn a_refused_request_keeps_a_current_vector_and_drops_a_stale_one() {
    let rig = rig(Some("embed-a"));
    assert_eq!(rig.task_turn_end("the brief", 1).await, 0);
    let good = rig.task_row();

    // The model changes and, once the rest is over, the request for the
    // unchanged brief is refused: the old vector (of the same brief, of the old
    // model) stays.
    rig.embedder.set_model(Some("embed-bb"));
    rig.embedder.set_failing(true);
    assert_eq!(
        rig.task_turn_end("the brief", 2).await,
        0,
        "resting: no request, nothing to report"
    );
    rig.rest();
    rig.c
        .sync_task_index(&summary("the brief", 3))
        .await
        .expect("the writer makes no request for an unchanged brief");
    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(rig.embedder.requests(), 2);
    let kept = rig.task_row();
    assert_eq!(kept.brief_embedding, good.brief_embedding);
    assert_eq!(kept.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(kept.turns_total, 3);

    // The next turn ends do not ask again until one more rest has passed.
    for turns_total in 4..10 {
        rig.tick();
        assert_eq!(
            rig.task_turn_end("the brief", turns_total).await,
            0,
            "resting: no request, nothing to report"
        );
    }
    assert_eq!(rig.embedder.requests(), 2, "not repeated at every turn end");
    rig.rest();
    rig.c
        .sync_task_index(&summary("the brief", 10))
        .await
        .unwrap();
    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(rig.embedder.requests(), 3, "asked again after the rest");

    // The brief changes and the request is refused: no vector of the old text.
    assert!(rig
        .c
        .sync_task_index(&summary("new brief", 11))
        .await
        .is_err());
    assert_eq!(rig.embedder.requests(), 4, "new text is always tried");
    let dropped = rig.task_row();
    assert_eq!(dropped.brief_snapshot, "new brief");
    assert_eq!(dropped.brief_embedding, None);
    assert_eq!(dropped.brief_embedding_model, None);
}

/// New text is embedded at once even while catch-up rests after a failure: only
/// the older rows wait.
#[tokio::test]
async fn new_text_is_embedded_at_once_even_while_catch_up_rests() {
    let rig = rig(Some("embed-a"));
    rig.embedder.set_failing(true);
    assert!(rig
        .c
        .sync_turn_index("a", &turn(1, "digest one"))
        .await
        .is_err());

    rig.embedder.set_failing(false);
    rig.tick();
    rig.c
        .sync_turn_index("a", &turn(2, "digest two"))
        .await
        .unwrap();
    rig.c
        .sync_task_index(&summary("the brief", 2))
        .await
        .unwrap();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    assert_eq!(rig.embedder.requests(), 3);
    assert_eq!(rig.turn_row(2).embedding_model.as_deref(), Some("embed-a"));
    assert!(rig.task_row().brief_embedding.is_some());
    assert!(rig.turn_row(1).embedding.is_empty(), "the older row waits");

    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 1);
    assert_eq!(
        rig.turn_row(1).embedding,
        ScriptedEmbedder::vector("embed-a", "digest one\n")
    );
}

// ── rows a query cannot be compared with ──

/// After the agent's embedding model changed, its turn rows are embedded again
/// by the new model — once the rest after the change is over, a few per turn
/// end, most recent first — and each row keeps everything else it had. When
/// nothing is left the index is not searched again.
#[tokio::test]
async fn turn_rows_of_another_model_are_embedded_again_a_few_per_turn_end() {
    let rig = rig(Some("embed-a"));
    let total = 2 * VECTORS_PER_TURN_END as u32 + 4;
    for n in 1..=total {
        rig.tick();
        let mut entry = turn(n, &format!("digest {n}"));
        entry.reference_count = n;
        rig.c.sync_turn_index("a", &entry).await.unwrap();
    }
    // Every row is of the model in use: one pass over both tables, then none.
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.index.searches(), one_pass());
    let before: Vec<TurnIndexRow> = (1..=total).map(|n| rig.turn_row(n)).collect();
    let written = rig.embedder.requests();
    assert_eq!(written, total as usize);

    // The model changes: nothing during the rest ...
    rig.embedder.set_model(Some("embed-bb"));
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    rig.clock.advance(EMBEDDING_REST - Duration::from_secs(1));
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), written, "no request while resting");
    assert_eq!(rig.index.passes(), 1, "and no search either");

    // ... then the most recent rows first.
    rig.tick();
    let of_new_model = |rig: &Rig| -> Vec<u32> {
        (1..=total)
            .filter(|n| rig.turn_row(*n).embedding_model.as_deref() == Some("embed-bb"))
            .collect()
    };
    let per = VECTORS_PER_TURN_END as u32;
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), VECTORS_PER_TURN_END);
    assert_eq!(
        of_new_model(&rig),
        ((total - per + 1)..=total).collect::<Vec<_>>()
    );
    assert_eq!(
        rig.embedder.requested()[written..],
        ((total - per + 1)..=total)
            .rev()
            .map(|n| format!("digest {n}\n"))
            .collect::<Vec<_>>()[..],
        "most recent first, each computed from its digest"
    );
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), VECTORS_PER_TURN_END);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 4);
    assert_eq!(of_new_model(&rig), (1..=total).collect::<Vec<_>>());
    assert_eq!(rig.embedder.requests(), written + total as usize);

    // Only the vector and its model moved.
    for old in &before {
        let new = rig.turn_row(old.turn);
        assert_eq!(
            new.embedding,
            ScriptedEmbedder::vector("embed-bb", &format!("{}\n", old.digest))
        );
        assert_eq!(
            (&new.digest, new.reference_count, &new.updated_at),
            (&old.digest, old.reference_count, &old.updated_at),
            "turn {}",
            old.turn
        );
    }

    // Nothing left: one pass finds that out, and no turn end searches again.
    let passes = rig.index.passes();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.index.passes(), passes + 1);
    for _ in 0..5 {
        rig.tick();
        rig.c
            .sync_turn_index("a", &turn(total + 1, "one more"))
            .await
            .unwrap();
        assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    }
    assert_eq!(rig.index.passes(), passes + 1);
    // Every pass asked each table for one pass of rows, no more.
    assert_eq!(
        rig.index.searches(),
        one_pass().repeat(rig.index.passes()),
        "bounded searches"
    );
}

/// Write `turns` as the `turn-index.yaml` of the task directory `dir`.
fn write_turn_index(dir: &std::path::Path, turns: &[TurnEntry]) {
    std::fs::create_dir_all(dir).expect("the task directory");
    let index = TurnIndex {
        meta: TurnIndexMeta {
            last_epoch_turn: 0,
            last_epoch_at: String::new(),
        },
        turns: turns.to_vec(),
        epochs: Vec::new(),
    };
    let yaml = serde_yml::to_string(&index).expect("the index as YAML");
    std::fs::write(dir.join(TASK_TURN_INDEX_FILENAME), yaml).expect("write the index");
}

/// A turn is caught up from the text its turn end embedded: its digest, then its
/// collapsed view. The row keeps no view, so catch-up reads it back from the
/// `turn-index.yaml` of the row's task, where Step 7 wrote it (MODULE-010 B1), or from
/// the index's archive when the index moved the turn out (an entry in both is the
/// index's). A turn whose view cannot be read back is caught up from its digest alone,
/// and catch-up creates nothing: here a turn neither its task's index nor its archive
/// holds, a turn of a task whose directory is a link, a turn its task's index holds for
/// another agent, and a turn of a task with no directory.
#[cfg(unix)]
#[tokio::test]
async fn a_turn_is_caught_up_from_its_digest_and_the_view_its_task_keeps() {
    let tasks = tempfile::tempdir().expect("the tasks root");
    let elsewhere = tempfile::tempdir().expect("a directory outside it");
    let rig = rig(Some("embed-a"));
    let rig = Rig {
        c: rig.c.with_tasks_root(tasks.path()),
        ..rig
    };
    let entry = |task: &str, n: u32, digest: &str, view: &str| {
        let mut entry = turn(n, digest);
        entry.task_id = task.into();
        entry.collapsed_view = view.into();
        entry
    };
    let kept = entry(
        "t1",
        1,
        "digest one",
        "[user] \"plan the beds\"\n→ \"done\"",
    );
    let dropped = entry("t1", 2, "digest two", "[user] \"water them\"\n→ \"done\"");
    let linked = entry("t2", 1, "digest three", "[user] \"prune\"\n→ \"done\"");
    let foreign = entry("t4", 1, "digest five", "[user] \"sow\"\n→ \"done\"");
    let homeless = entry("t3", 1, "digest four", "[user] \"weed\"\n→ \"done\"");
    let archived = entry("t1", 3, "digest six", "[user] \"harvest\"\n→ \"done\"");
    write_turn_index(&tasks.path().join("t1"), std::slice::from_ref(&kept));
    let mut stale = kept.clone();
    stale.collapsed_view = "an older view".into();
    cap_memory::task_storage::append_turn_index_archive(
        &tasks
            .path()
            .join("t1")
            .join(cap_memory::task_storage::TASK_TURN_INDEX_ARCHIVE_FILENAME),
        &[stale, archived.clone()],
    )
    .expect("the index's archive");
    write_turn_index(&elsewhere.path().join("t2"), std::slice::from_ref(&linked));
    std::os::unix::fs::symlink(elsewhere.path().join("t2"), tasks.path().join("t2"))
        .expect("link t2 into the tasks root");
    let mut of_another_agent = foreign.clone();
    of_another_agent.agent_id = "b".into();
    write_turn_index(&tasks.path().join("t4"), &[of_another_agent]);
    let rows = [&kept, &dropped, &linked, &foreign, &homeless, &archived];
    for row in rows {
        rig.tick();
        rig.c.sync_turn_index("a", row).await.unwrap();
    }
    let written = rig.embedder.requests();
    assert_eq!(
        rig.embedder.requested(),
        rows.map(|row| format!("{}\n{}", row.digest, row.collapsed_view)),
        "each turn end embeds the digest and then the view"
    );
    // Every row is of the model in use (and catch-up has seen it).
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);

    // The model changes; once the rest is over, every row is caught up.
    rig.embedder.set_model(Some("embed-bb"));
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), rows.len());
    let mut caught_up = rig.embedder.requested()[written..].to_vec();
    caught_up.sort();
    assert_eq!(
        caught_up,
        [
            "digest five\n".to_string(),
            "digest four\n".to_string(),
            format!("digest one\n{}", kept.collapsed_view),
            format!("digest six\n{}", archived.collapsed_view),
            "digest three\n".to_string(),
            "digest two\n".to_string(),
        ]
    );
    assert_eq!(
        rig.turn_row(1).embedding,
        ScriptedEmbedder::vector("embed-bb", &format!("digest one\n{}", kept.collapsed_view)),
        "the vector the turn end would compute"
    );
    assert!(
        !tasks.path().join("t3").exists(),
        "catch-up creates nothing"
    );
}

/// An index written by an older version holds vectors of no recorded model. A
/// query is never compared with those, so they are embedded again — from the
/// first turn end on (there was no change of model to rest after).
#[tokio::test]
async fn rows_of_no_recorded_model_are_embedded_again_from_the_first_turn_end() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    let before: Vec<TurnIndexRow> = (1..=3).map(|n| rig.turn_row(n)).collect();

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3);
    for old in &before {
        let new = rig.turn_row(old.turn);
        assert_eq!(new.embedding_model.as_deref(), Some("embed-a"));
        assert_eq!(
            new.embedding,
            ScriptedEmbedder::vector("embed-a", &format!("{}\n", old.digest))
        );
        assert_eq!(
            (&new.digest, new.reference_count, &new.updated_at),
            (&old.digest, old.reference_count, &old.updated_at)
        );
    }
    // Another agent's rows are not this agent's to embed.
    assert_eq!(rig.c.heal_vectors("someone-else").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 3);
}

/// A text the service refuses as a text is set aside: the rows behind it get
/// their vectors in the same pass, it is never asked about again under this
/// model, and when it is all that is left the catch-up is done.
#[tokio::test]
async fn a_text_the_service_refuses_is_set_aside_and_the_rows_behind_it_go_on() {
    let rig = rig(Some("embed-a"));
    for n in 1..=4 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.seed_row_of_no_recorded_model(5, "refused");
    rig.embedder.refuse(&["refused\n"]);

    // The most recent row goes first and is refused: reported, and the pass
    // goes on behind it.
    let refusal = rig.c.heal_vectors("a").await;
    assert!(
        matches!(
            refusal,
            Err(CatchUpError::Embedding(EmbedderError::Refused(_)))
        ),
        "{refusal:?}"
    );
    assert_eq!(
        rig.embedder.requested(),
        [
            "refused\n",
            "old digest 4\n",
            "old digest 3\n",
            "old digest 2\n",
            "old digest 1\n"
        ]
    );
    for n in 1..=4 {
        assert_eq!(
            rig.turn_row(n).embedding_model.as_deref(),
            Some("embed-a"),
            "turn {n}"
        );
    }
    assert_eq!(rig.turn_row(5).embedding_model, None);

    // It is all that is left: one pass finds that out — asking each table for
    // one row more, to see past it — and no turn end asks or searches again.
    let passes = rig.index.passes();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(
        rig.index.searches()[2 * passes..],
        [
            Search::Tasks {
                limit: VECTORS_PER_TURN_END + 1
            },
            Search::Turns {
                window: RECENT_TURN_WINDOW,
                limit: VECTORS_PER_TURN_END + 1
            }
        ]
    );
    for _ in 0..5 {
        rig.rest();
        assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    }
    assert_eq!(rig.embedder.requests(), 5, "never asked about again");
    assert_eq!(rig.index.passes(), passes + 1, "settled");

    // What one model refused says nothing about another.
    rig.embedder.refuse(&[]);
    rig.embedder.set_model(Some("embed-bb"));
    assert_eq!(
        rig.c.heal_vectors("a").await.unwrap(),
        0,
        "the change rests"
    );
    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 5);
    assert_eq!(
        rig.turn_row(5).embedding,
        ScriptedEmbedder::vector("embed-bb", "refused\n")
    );
}

/// A new text the service refuses is written without a vector and is not asked
/// about again by the catch-up. The refusal starts no rest: it says nothing
/// against the service.
#[tokio::test]
async fn a_new_text_the_service_refuses_is_not_asked_about_again() {
    let rig = rig(Some("embed-a"));
    rig.seed_row_of_no_recorded_model(1, "old digest 1");
    rig.embedder.refuse(&["too long\n", "a brief too long"]);
    rig.tick();

    let refused = rig.c.sync_turn_index("a", &turn(2, "too long")).await;
    assert!(
        matches!(refused, Err(EmbedderError::Refused(_))),
        "{refused:?}"
    );
    assert!(rig
        .c
        .sync_task_index(&summary("a brief too long", 2))
        .await
        .is_err());
    assert_eq!(rig.embedder.requests(), 2);
    assert!(rig.turn_row(2).embedding.is_empty());
    assert_eq!(rig.task_row().brief_embedding, None);

    // The older row is caught up at this very turn end, and the two refused
    // texts are left alone.
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 1);
    assert_eq!(rig.embedder.requested()[2..], ["old digest 1\n"]);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 3);
}

/// A pass that asked for vectors and got none rests, whatever the service said:
/// a service that refuses every text is not asked about the next eight at the
/// next turn end.
#[tokio::test]
async fn a_pass_that_gets_no_vector_rests() {
    let rig = rig(Some("embed-a"));
    let total = 2 * VECTORS_PER_TURN_END as u32;
    let texts: Vec<String> = (1..=total).map(|n| format!("old digest {n}\n")).collect();
    for n in 1..=total {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.embedder
        .refuse(&texts.iter().map(String::as_str).collect::<Vec<_>>());

    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(rig.embedder.requests(), VECTORS_PER_TURN_END);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    assert_eq!(rig.embedder.requests(), VECTORS_PER_TURN_END);

    rig.rest();
    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(
        rig.embedder.requested()[VECTORS_PER_TURN_END..],
        texts[..VECTORS_PER_TURN_END]
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>()[..],
        "the next eight, not the same ones"
    );

    rig.rest();
    assert_eq!(
        rig.c.heal_vectors("a").await.unwrap(),
        0,
        "nothing but refused texts is left"
    );
    assert_eq!(rig.embedder.requests(), 2 * VECTORS_PER_TURN_END);
}

/// A text whose request fails — the service does not say why — while the
/// service answers for the texts around it is put off, not given up: the rows
/// behind it get their vectors in the same pass, and it is asked about again
/// after them, once per rest for as long as it fails.
#[tokio::test]
async fn a_text_whose_request_keeps_failing_is_put_off_behind_the_other_rows() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.seed_row_of_no_recorded_model(4, "poison");
    rig.seed_row_of_no_recorded_model(5, "old digest 5");
    rig.embedder.fail_on(&["poison\n"]);

    // Row 5 gets its vector, then row 4 fails: right after a served request, so
    // it may be the text. It is put off and the pass goes on.
    let failure = rig.c.heal_vectors("a").await;
    assert!(
        matches!(
            failure,
            Err(CatchUpError::Embedding(EmbedderError::Upstream(_)))
        ),
        "{failure:?}"
    );
    assert_eq!(
        rig.embedder.requested(),
        [
            "old digest 5\n",
            "poison\n",
            "old digest 3\n",
            "old digest 2\n",
            "old digest 1\n"
        ]
    );
    assert_eq!(rig.turn_row(4).embedding_model, None);
    for n in [1, 2, 3, 5] {
        assert_eq!(
            rig.turn_row(n).embedding_model.as_deref(),
            Some("embed-a"),
            "turn {n}"
        );
    }

    // It is all that is left, and fails again. A pass that got no vector rests.
    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(rig.embedder.requests(), 6);
    for _ in 0..5 {
        rig.tick();
        assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    }
    assert_eq!(rig.embedder.requests(), 6, "not at every turn end");
    rig.rest();
    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(rig.embedder.requests(), 7, "once per rest");
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");

    // Rows written in the meantime are not held up by it: they go first.
    rig.rest();
    rig.seed_row_of_no_recorded_model(6, "old digest 6");
    assert!(rig
        .c
        .sync_turn_index("a", &turn(7, "digest 7"))
        .await
        .is_ok());
    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(
        rig.embedder.requested()[7..],
        ["digest 7\n", "old digest 6\n", "poison\n"]
    );
    assert_eq!(rig.turn_row(6).embedding_model.as_deref(), Some("embed-a"));

    // The service takes it at last: nothing is held against the row any more.
    rig.embedder.fail_on(&[]);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 1);
    assert_eq!(
        rig.turn_row(4).embedding,
        ScriptedEmbedder::vector("embed-a", "poison\n")
    );
    let passes = rig.index.passes();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.index.passes(), passes + 1, "settled");
    assert_eq!(rig.embedder.requests(), 11);
}

/// Two requests failing in a row are the service's failure, not the texts': the
/// pass ends there and catch-up rests. Only the first of the two — it failed
/// right after a served request — is put off; after the rest the rows are asked
/// about again, that one last.
#[tokio::test]
async fn two_failures_in_a_row_end_the_pass_and_rest() {
    let rig = rig(Some("embed-a"));
    for n in 1..=6 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.embedder.fail_on(&["old digest 4\n", "old digest 3\n"]);

    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(
        rig.embedder.requested(),
        [
            "old digest 6\n",
            "old digest 5\n",
            "old digest 4\n",
            "old digest 3\n"
        ],
        "rows 2 and 1 are not asked about"
    );
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    assert_eq!(rig.embedder.requests(), 4);

    rig.embedder.fail_on(&[]);
    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 4);
    assert_eq!(
        rig.embedder.requested()[4..],
        [
            "old digest 3\n",
            "old digest 2\n",
            "old digest 1\n",
            "old digest 4\n"
        ],
        "the row put off goes after the others"
    );
}

/// An index that cannot be read is not an index with nothing left in it: the
/// agent is not settled, the failure is reported, and — after a rest — the rows
/// are caught up.
#[tokio::test]
async fn an_index_that_cannot_be_read_is_not_taken_for_nothing_left() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.index.set_unreadable(true);

    let outcome = rig.c.heal_vectors("a").await;
    assert!(
        matches!(outcome, Err(CatchUpError::Index(_))),
        "{outcome:?}"
    );
    assert_eq!(rig.embedder.requests(), 0);
    // A failing index is not asked again at every turn end ...
    let searched = rig.index.searches().len();
    for _ in 0..3 {
        rig.tick();
        assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    }
    assert_eq!(rig.index.searches().len(), searched);

    // ... and the agent is not settled: once the index can be read, the rows
    // get their vectors.
    rig.index.set_unreadable(false);
    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3);
}

/// A vector that cannot be written says nothing about the row: the pass stops,
/// reports the index, rests — and asks again later.
#[tokio::test]
async fn a_vector_that_cannot_be_written_stops_the_pass() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.index.set_unwritable(true);

    let outcome = rig.c.heal_vectors("a").await;
    assert!(
        matches!(outcome, Err(CatchUpError::Index(_))),
        "{outcome:?}"
    );
    assert_eq!(
        rig.embedder.requests(),
        1,
        "one request, then the pass stops"
    );
    assert_eq!(rig.turn_row(3).embedding_model, None);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");

    rig.index.set_unwritable(false);
    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3);
    assert_eq!(rig.embedder.requests(), 4);
}

/// An embedder that says which model it embeds with, yet returns a vector
/// without naming its model, is at fault: the vector cannot be stored as one of
/// the model in use, so the pass stops and rests rather than ask for it at
/// every turn end.
#[tokio::test]
async fn a_vector_of_no_named_model_is_a_failure_of_the_embedder() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    let before = rig.turn_row(3);
    rig.embedder.set_unnamed(true);

    let outcome = rig.c.heal_vectors("a").await;
    assert!(
        matches!(
            outcome,
            Err(CatchUpError::Embedding(EmbedderError::Upstream(_)))
        ),
        "{outcome:?}"
    );
    assert_eq!(rig.embedder.requests(), 1);
    assert_eq!(rig.turn_row(3), before, "the row is as it was");
    for _ in 0..3 {
        rig.tick();
        assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    }
    assert_eq!(rig.embedder.requests(), 1);
}

/// A pass starts no request once it has run for `CATCH_UP_TIME`: a service that
/// answers slowly costs a turn end that much, and the rest of the rows wait for
/// the next turn end — without a rest, nothing failed.
#[tokio::test]
async fn a_slow_service_ends_the_pass_early() {
    let rig = rig(Some("embed-a"));
    for n in 1..=6 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    // Each request takes a third of what a pass may run.
    rig.embedder.take_per_request(&rig.clock, CATCH_UP_TIME / 3);

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3);
    assert_eq!(rig.embedder.requests(), 3);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 6);
}

/// A pass is over by `CATCH_UP_TIME` of real time whatever a request is doing
/// then: one left unanswered — a service that hangs, a gateway still retrying — is
/// cut off and counts as a failed request, and the rows behind it wait for the
/// next turn end. Right after a served request it may be the text: it is put off,
/// and the next pass takes the rows behind it first. The time is the pass's, not each
/// request's: the request served first took most of it.
#[tokio::test(start_paused = true)]
async fn a_request_left_unanswered_is_cut_off_when_the_pass_runs_out_of_time() {
    let rig = rig(Some("embed-a"));
    for n in 1..=4 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.embedder.hang_on(&["old digest 3\n"]);
    rig.embedder.answer_after(CATCH_UP_TIME * 2 / 3);

    let began = tokio::time::Instant::now();
    // (Bounded here too, so that a pass with no deadline fails the test, not hangs it.)
    let cut_off = tokio::time::timeout(2 * CATCH_UP_TIME, rig.c.heal_vectors("a"))
        .await
        .expect("the pass ends by its deadline");
    let took = began.elapsed();
    assert!(
        took >= CATCH_UP_TIME && took < CATCH_UP_TIME + Duration::from_millis(10),
        "the pass took all of its time and no more: {took:?}"
    );
    assert!(
        matches!(
            cut_off,
            Err(CatchUpError::Embedding(EmbedderError::Upstream(_)))
        ),
        "{cut_off:?}"
    );
    assert_eq!(
        rig.embedder.requested(),
        ["old digest 4\n", "old digest 3\n"],
        "rows 2 and 1 are not asked about"
    );
    assert_eq!(rig.turn_row(4).embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(rig.turn_row(3).embedding_model, None);

    rig.embedder.hang_on(&[]);
    rig.embedder.answer_after(Duration::ZERO);
    rig.tick();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3, "no rest");
    assert_eq!(
        rig.embedder.requested()[2..],
        ["old digest 2\n", "old digest 1\n", "old digest 3\n"]
    );
}

/// A pass cut off at its first request got no vector: it rests, as any pass that
/// asked for vectors and got none.
#[tokio::test(start_paused = true)]
async fn a_pass_cut_off_before_any_vector_rests() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.embedder.hang_on(&["old digest 3\n"]);

    let cut_off = tokio::time::timeout(2 * CATCH_UP_TIME, rig.c.heal_vectors("a"))
        .await
        .expect("the pass ends by its deadline");
    assert!(cut_off.is_err());
    assert_eq!(rig.embedder.requests(), 1);
    rig.embedder.hang_on(&[]);
    rig.tick();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    assert_eq!(rig.embedder.requests(), 1);

    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3);
    for n in 1..=3 {
        assert_eq!(
            rig.turn_row(n).embedding_model.as_deref(),
            Some("embed-a"),
            "turn {n}"
        );
    }
}

/// Nothing to embed with any more in the middle of a pass: the pass ends there,
/// quietly — no failure, no rest —, and goes on when there is a model again.
#[tokio::test]
async fn losing_the_model_during_a_pass_ends_the_pass_quietly() {
    let rig = rig(Some("embed-a"));
    for n in 1..=4 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.embedder.lose_the_model_at_request(3);

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 2);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "no model");
    rig.embedder.set_model(Some("embed-a"));
    assert_eq!(
        rig.c.heal_vectors("a").await.unwrap(),
        2,
        "no rest was started"
    );
    for n in 1..=4 {
        assert_eq!(
            rig.turn_row(n).embedding_model.as_deref(),
            Some("embed-a"),
            "turn {n}"
        );
    }
}

/// A row written without a vector after everything was caught up is noticed:
/// the index is searched again and the row gets its vector. Here the service is
/// down for two turn ends — the second failure in a row starts a rest.
#[tokio::test]
async fn a_row_written_without_a_vector_reopens_the_catch_up() {
    let rig = rig(Some("embed-a"));
    rig.c
        .sync_turn_index("a", &turn(1, "digest one"))
        .await
        .unwrap();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.index.passes(), 1, "settled");

    rig.embedder.set_failing(true);
    for (number, digest) in [(2, "digest two"), (3, "digest three")] {
        rig.tick();
        assert!(rig
            .c
            .sync_turn_index("a", &turn(number, digest))
            .await
            .is_err());
    }
    rig.embedder.set_failing(false);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    assert_eq!(rig.index.passes(), 1);

    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 2);
    assert_eq!(rig.index.passes(), 2);
    // The row nothing is held against goes first, then the one put off (its
    // request failed right after a served one).
    assert_eq!(
        rig.embedder.requested()[3..],
        ["digest three\n", "digest two\n"]
    );
    for (number, text) in [(2, "digest two\n"), (3, "digest three\n")] {
        assert_eq!(
            rig.turn_row(number).embedding,
            ScriptedEmbedder::vector("embed-a", text)
        );
    }
}

/// One failed request right after a served one does not rest the catch-up: the
/// text is put off, and — the service answering again — gets its vector at the
/// next turn end.
#[tokio::test]
async fn a_single_failed_request_does_not_rest_the_catch_up() {
    let rig = rig(Some("embed-a"));
    rig.c
        .sync_turn_index("a", &turn(1, "digest one"))
        .await
        .unwrap();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);

    rig.embedder.set_failing(true);
    rig.tick();
    assert!(rig
        .c
        .sync_turn_index("a", &turn(2, "digest two"))
        .await
        .is_err());
    rig.embedder.set_failing(false);

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 1, "not resting");
    assert_eq!(
        rig.turn_row(2).embedding,
        ScriptedEmbedder::vector("embed-a", "digest two\n")
    );
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 3);
}

/// The same for a task: a brief whose text changed while its request failed is
/// left without a vector, and gets one at a later turn end — whichever task
/// that turn belongs to.
#[tokio::test]
async fn a_brief_written_without_a_vector_reopens_the_catch_up() {
    let rig = rig(Some("embed-a"));
    assert_eq!(rig.task_turn_end("the brief", 1).await, 0);
    assert_eq!(rig.task_turn_end("the brief", 2).await, 0);
    assert_eq!(rig.index.passes(), 1, "settled");

    rig.embedder.set_failing(true);
    rig.tick();
    assert!(rig
        .c
        .sync_task_index(&summary("a new brief", 3))
        .await
        .is_err());
    assert_eq!(rig.task_row().brief_embedding, None);
    // The turn ends that follow belong to another task; this one gets no more.
    // The first of them still finds the service down.
    rig.tick();
    assert!(rig
        .c
        .sync_task_index(&summary_of("a", "t2", "another task", 1))
        .await
        .is_err());
    rig.embedder.set_failing(false);
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    assert_eq!(rig.index.passes(), 1);

    rig.rest();
    rig.c
        .sync_task_index(&summary_of("a", "t2", "another task", 2))
        .await
        .unwrap();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 2);
    assert_eq!(rig.index.passes(), 2);
    let task = rig.task_row();
    assert_eq!(task.brief_snapshot, "a new brief");
    assert_eq!(task.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        task.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "a new brief"))
    );
    assert_eq!(
        task.turns_total, 3,
        "the row is otherwise as it was written"
    );
    assert_eq!(
        rig.task_row_of("t2").brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "another task"))
    );
}

/// A reference bump makes a row recent again. If its vector is not of the model
/// in use — the catch-up never reached it — it is one more row to catch up on,
/// and a settled catch-up starts again.
#[tokio::test]
async fn a_bumped_row_of_another_model_reopens_the_catch_up() {
    let rig = rig(Some("embed-a"));
    rig.c
        .sync_turn_index("a", &turn(1, "digest one"))
        .await
        .unwrap();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.index.passes(), 1, "settled");
    // A row the catch-up never reached (as one beyond the window a reader scans
    // is left): nothing looks for it.
    rig.seed_row_of_no_recorded_model(7, "old digest 7");
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.index.passes(), 1);

    // A bump of a row of the model in use changes nothing ...
    assert!(rig.c.bump_turn_reference("a", "t1", 1));
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.index.passes(), 1);
    // ... a bump of the other one makes it a row to catch up on.
    rig.tick();
    assert!(rig.c.bump_turn_reference("a", "t1", 7));
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 1);
    let row = rig.turn_row(7);
    assert_eq!(row.embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(
        row.embedding,
        ScriptedEmbedder::vector("embed-a", "old digest 7\n")
    );
    assert_eq!(row.reference_count, 8, "the bump is kept");
}

// ── tasks that get no further turn ──

/// The gap this closes: after the agent's embedding model changed, a task the
/// agent is no longer working on would keep a brief vector no query is compared
/// with — nothing writes its row again. The turn ends of whatever task the agent
/// IS working on catch it up, and leave the rest of its row alone.
#[tokio::test]
async fn the_brief_of_a_task_that_gets_no_further_turn_is_embedded_again() {
    let rig = rig(Some("embed-a"));
    rig.c
        .sync_task_index(&summary_of("a", "t-old", "what the old task was about", 9))
        .await
        .unwrap();
    let old = rig.task_row_of("t-old");
    assert_eq!(old.brief_embedding_model.as_deref(), Some("embed-a"));
    rig.tick();
    assert_eq!(rig.task_turn_end("the brief", 1).await, 0);
    let written = rig.embedder.requests();
    assert_eq!(written, 2);

    // The model changes. Every turn end from here on belongs to task `t1`.
    rig.embedder.set_model(Some("embed-bb"));
    rig.tick();
    assert_eq!(rig.task_turn_end("the brief", 2).await, 0, "resting");
    rig.rest();
    assert_eq!(rig.task_turn_end("the brief", 3).await, 2);
    assert_eq!(
        rig.embedder.requested()[written..],
        ["the brief", "what the old task was about"],
        "the task at hand first, then the older one"
    );

    let healed = rig.task_row_of("t-old");
    assert_eq!(healed.brief_embedding_model.as_deref(), Some("embed-bb"));
    assert_eq!(
        healed.brief_embedding,
        Some(ScriptedEmbedder::vector(
            "embed-bb",
            "what the old task was about"
        ))
    );
    assert_eq!(
        TaskIndexRow {
            brief_embedding: old.brief_embedding.clone(),
            brief_embedding_model: old.brief_embedding_model.clone(),
            ..healed
        },
        old,
        "only the vector and its model moved"
    );

    // Nothing left: the next turn end finds that out, and none looks again.
    let passes = rig.index.passes();
    for turns_total in 4..8 {
        rig.tick();
        assert_eq!(rig.task_turn_end("the brief", turns_total).await, 0);
    }
    assert_eq!(rig.embedder.requests(), written + 2);
    assert_eq!(rig.index.passes(), passes + 1);
}

/// An index written by an older version holds brief vectors of no recorded
/// model. A query is never compared with those, so they are embedded again from
/// the first turn end on — this agent's, not another's under the same task id.
#[tokio::test]
async fn briefs_of_no_recorded_model_are_embedded_again_from_the_first_turn_end() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_task_of_no_recorded_model("a", &format!("t-{n}"), &format!("old brief {n}"));
    }
    rig.seed_task_of_no_recorded_model("someone-else", "t-3", "not this agent's");
    let theirs = rig.index.get_task("someone-else", "t-3").unwrap();
    let before: Vec<TaskIndexRow> = (1..=3)
        .map(|n| rig.task_row_of(&format!("t-{n}")))
        .collect();

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 3);
    assert_eq!(
        rig.embedder.requested(),
        ["old brief 3", "old brief 2", "old brief 1"],
        "most recently written first"
    );
    for old in before {
        let new = rig.task_row_of(&old.task_id);
        assert_eq!(new.brief_embedding_model.as_deref(), Some("embed-a"));
        assert_eq!(
            new.brief_embedding,
            Some(ScriptedEmbedder::vector("embed-a", &old.brief_snapshot))
        );
        assert_eq!(
            TaskIndexRow {
                brief_embedding: old.brief_embedding.clone(),
                brief_embedding_model: None,
                ..new
            },
            old
        );
    }
    assert_eq!(
        rig.index.get_task("someone-else", "t-3"),
        Some(theirs),
        "another agent's row is not this agent's to embed"
    );
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 3);
}

/// Briefs and digests are caught up together, the most recently written first
/// whichever table they are in, and share the one allowance of a turn end.
#[tokio::test]
async fn briefs_and_digests_share_one_allowance_most_recent_first() {
    let rig = rig(Some("embed-a"));
    // Six briefs and six digests written in turn, oldest first.
    for n in 1..=6 {
        rig.seed_task_of_no_recorded_model("a", &format!("t-{n}"), &format!("brief {n}"));
        rig.seed_row_of_no_recorded_model(n, &format!("digest {n}"));
    }
    assert_eq!(VECTORS_PER_TURN_END, 8, "the lists below assume it");

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 8);
    assert_eq!(
        rig.embedder.requested(),
        [
            "digest 6\n",
            "brief 6",
            "digest 5\n",
            "brief 5",
            "digest 4\n",
            "brief 4",
            "digest 3\n",
            "brief 3"
        ]
    );
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 4);
    assert_eq!(
        rig.embedder.requested()[8..],
        ["digest 2\n", "brief 2", "digest 1\n", "brief 1"]
    );
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 12);
    assert_eq!(rig.index.searches(), one_pass().repeat(3));
}

/// A brief the service refuses is set aside like a digest is: the rows behind
/// it — the turns of that very task among them — get their vectors in the same
/// pass. Set aside is the text: the brief with another text is embedded like
/// any other.
#[tokio::test]
async fn a_brief_the_service_refuses_is_set_aside_until_its_text_changes() {
    let rig = rig(Some("embed-a"));
    for n in 1..=3 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    // The most recent row: the brief of the task those turns belong to.
    rig.seed_task_of_no_recorded_model("a", "t1", "refused");
    rig.embedder.refuse(&["refused"]);

    assert!(rig.c.heal_vectors("a").await.is_err());
    assert_eq!(
        rig.embedder.requested(),
        [
            "refused",
            "old digest 3\n",
            "old digest 2\n",
            "old digest 1\n"
        ]
    );
    assert_eq!(rig.task_row().brief_embedding_model, None);
    // With a text kept back, a pass asks each table for one row more.
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(
        rig.index.searches()[2..],
        [
            Search::Tasks {
                limit: VECTORS_PER_TURN_END + 1
            },
            Search::Turns {
                window: RECENT_TURN_WINDOW,
                limit: VECTORS_PER_TURN_END + 1
            }
        ]
    );
    rig.rest();
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    assert_eq!(rig.embedder.requests(), 4, "not asked about again");

    // Turn ends of its task write the same brief again: nothing new to catch up
    // on, and the index is not searched for it.
    let searches = rig.index.searches().len();
    for turns_total in 8..=10 {
        rig.tick();
        rig.c
            .sync_task_index(&summary("refused", turns_total))
            .await
            .unwrap();
        assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0);
    }
    assert_eq!(rig.index.searches().len(), searches, "still settled");
    assert_eq!(rig.embedder.requests(), 4);

    // A new text is embedded at once, on its own account.
    rig.c
        .sync_task_index(&summary("a brief that fits", 8))
        .await
        .unwrap();
    assert_eq!(rig.embedder.requests(), 5);
    assert_eq!(
        rig.task_row().brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "a brief that fits"))
    );
}

/// The agent's model moves while rows are being embedded: the vector is stored
/// under the model that really produced it, the pass stops there, and the change
/// starts a rest like any other.
#[tokio::test]
async fn a_model_that_moves_during_a_pass_stops_the_pass() {
    let rig = rig(Some("embed-a"));
    for n in 1..=5 {
        rig.seed_row_of_no_recorded_model(n, &format!("old digest {n}"));
    }
    rig.embedder.move_to_at_request(2, "embed-bb");

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 2);
    assert_eq!(rig.embedder.requests(), 2);
    assert_eq!(rig.turn_row(5).embedding_model.as_deref(), Some("embed-a"));
    let moved = rig.turn_row(4);
    assert_eq!(moved.embedding_model.as_deref(), Some("embed-bb"));
    assert_eq!(
        moved.embedding,
        ScriptedEmbedder::vector("embed-bb", "old digest 4\n")
    );
    assert_eq!(rig.turn_row(3).embedding_model, None);

    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 0, "resting");
    assert_eq!(rig.embedder.requests(), 2);
    rig.rest();
    // Rows 5 (of the old model) and 3, 2, 1 are not of the model in use.
    assert_eq!(rig.c.heal_vectors("a").await.unwrap(), 4);
    for n in 1..=5 {
        assert_eq!(
            rig.turn_row(n).embedding_model.as_deref(),
            Some("embed-bb"),
            "turn {n}"
        );
    }
}

// ── one task id, two agents ──

/// Two agents working under ONE task id (a parent and the child it handed the
/// task to share the home's index) each keep their own task row: the child's
/// turn end does not replace the parent's brief, vector or turn count, and the
/// parent's unchanged brief is not embedded again because of it.
#[tokio::test]
async fn two_agents_under_one_task_id_keep_their_own_task_rows() {
    let rig = rig(Some("embed-a"));

    rig.c
        .sync_task_index(&summary_of("parent", "shared", "the parent's brief", 3))
        .await
        .unwrap();
    rig.c
        .sync_task_index(&summary_of("child", "shared", "what the child did", 1))
        .await
        .unwrap();
    assert_eq!(rig.embedder.requests(), 2);

    let parent = rig.index.get_task("parent", "shared").expect("parent row");
    assert_eq!(parent.brief_snapshot, "the parent's brief");
    assert_eq!(parent.turns_total, 3);
    assert_eq!(
        parent.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "the parent's brief"))
    );
    let child = rig.index.get_task("child", "shared").expect("child row");
    assert_eq!(child.brief_snapshot, "what the child did");
    assert_eq!(child.turns_total, 1);
    assert_eq!(
        child.brief_embedding,
        Some(ScriptedEmbedder::vector("embed-a", "what the child did"))
    );
    assert_eq!(rig.index.list_tasks_for_agent("parent"), vec![parent]);
    assert_eq!(rig.index.list_tasks_for_agent("child"), vec![child]);

    // The parent's next turn: its brief did not change, whatever the child wrote.
    rig.c
        .sync_task_index(&summary_of("parent", "shared", "the parent's brief", 4))
        .await
        .unwrap();
    assert_eq!(
        rig.embedder.requests(),
        2,
        "the parent's brief is unchanged"
    );
    let parent = rig.index.get_task("parent", "shared").unwrap();
    assert_eq!(parent.turns_total, 4);
    assert_eq!(parent.brief_snapshot, "the parent's brief");
    assert_eq!(
        rig.index.get_task("child", "shared").unwrap().turns_total,
        1
    );
}

/// A failed request of one agent rests that agent's catch-up, not another's.
#[tokio::test]
async fn one_agents_failed_request_does_not_rest_another_agent() {
    let rig = rig(Some("embed-a"));
    rig.seed_row_of_no_recorded_model(1, "old digest");
    rig.embedder.set_failing(true);
    assert!(rig
        .c
        .sync_task_index(&summary_of("other", "t9", "a brief", 1))
        .await
        .is_err());
    rig.embedder.set_failing(false);

    assert_eq!(
        rig.c.heal_vectors("a").await.unwrap(),
        1,
        "agent `a` is not resting"
    );
}

// ── the whole pipeline ──

fn message() -> Message {
    Message {
        id: "msg-1".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:root".into(),
        payload: b"hello".to_vec(),
        context: Some(MessageContext {
            task_id: Some("t1".into()),
            run_id: None,
            execution_id: None,
            trace_id: None,
            in_reply_to: None,
            correlation_id: None,
        }),
        timestamp: SystemTime::UNIX_EPOCH,
        origin: None,
    }
}

fn extraction() -> Extraction {
    Extraction {
        descriptions: vec![],
        knowledge: vec![MemoryEntry {
            id: "k-1".into(),
            agent_id: "a".into(),
            entry_type: MemoryType::Fact,
            content: "the parser was refactored".into(),
            tags: vec![],
            created_at: "2026-11-17T00:00:00Z".into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        }],
        digest: Some("Refactored the tokenizer".into()),
    }
}

fn no_actions() -> ActionResult {
    ActionResult {
        new_state: vec![],
        actions: vec![],
    }
}

/// A post-processor writing under `write_id` into `index`, with its own memory
/// root.
fn pipeline(
    root: &std::path::Path,
    write_id: &str,
    embedder: Arc<ScriptedEmbedder>,
    clock: Arc<MutableClock>,
    index: Arc<dyn SqliteIndex + Send + Sync>,
) -> PostProcessor {
    let store = Arc::new(MemoryStore::open(root, DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap());
    let c = Components::with_l6_defaults(
        Arc::new(StubBatchExtractor::with_extraction(extraction())),
        Reconciler::from_concrete(Arc::new(InMemorySimilarityIndex::new()), DEFAULT_THRESHOLD),
        store,
        Arc::new(FailureCooldown::new(600)),
        clock,
    )
    .with_tasks_root(root.join("tasks"))
    .with_write_agent_id(write_id)
    .with_embedder(embedder)
    .with_sqlite_index(index);
    PostProcessor::with_components(c)
}

/// Through the real `PostProcessor::run`: a refused embedding request makes the
/// run report an error, yet the turn row, the task row AND the memory rows of
/// Step 8 are all written, and Step 9 (L6 evaluation) still runs. A later run —
/// after the rest — is clean, embeds its own turn and catches up on the one the
/// failure left without a vector.
#[tokio::test]
async fn a_refused_embedding_request_does_not_cost_the_turn_its_index_or_step_9() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let embedder = ScriptedEmbedder::new(Some("embed-a"));
    embedder.set_failing(true);
    let clock = Arc::new(MutableClock::new(t0()));
    let index: Arc<dyn SqliteIndex + Send + Sync> = Arc::new(InMemorySqliteIndex::default());
    let pp = pipeline(&root, "a", embedder.clone(), clock.clone(), index.clone());

    let outcome = pp.run("a", &message(), &no_actions()).await;
    assert!(outcome.is_err(), "the refused request is reported");

    let turns = index.list_turns_for_agent("a");
    assert_eq!(turns.len(), 1, "the turn row is written");
    assert_eq!(turns[0].digest, "Refactored the tokenizer");
    assert!(turns[0].embedding.is_empty());
    assert_eq!(index.list_tasks_for_agent("a").len(), 1, "the task row too");
    assert!(
        !index.list_memory_for_agent("a").is_empty(),
        "the memory rows are synced after the failed embedding"
    );
    let expected: Vec<String> = CANONICAL_STEPS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        pp.trace_snapshot(),
        expected,
        "all nine steps ran, Step 9 included"
    );
    let failed_requests = embedder.requests();

    // The provider is back, but catch-up rests: the next run embeds its OWN turn
    // and leaves the older rows alone.
    embedder.set_failing(false);
    clock.advance(Duration::from_secs(1));
    pp.run("a", &message(), &no_actions())
        .await
        .expect("run Ok");
    assert_eq!(embedder.requests(), failed_requests + 1);
    let second = index.get_turn("a", "t1", 2).expect("turn 2");
    assert_eq!(second.embedding_model.as_deref(), Some("embed-a"));
    assert!(index.get_turn("a", "t1", 1).unwrap().embedding.is_empty());
    assert_eq!(index.get_task("a", "t1").unwrap().brief_embedding, None);

    // After the rest a run also catches up: turn 1 and the brief get vectors.
    clock.advance(EMBEDDING_REST);
    pp.run("a", &message(), &no_actions())
        .await
        .expect("run Ok");
    assert_eq!(index.list_turns_for_agent("a").len(), 3);
    // Each vector is computed from the digest and the collapsed view Step 7 wrote in
    // the task's `turn-index.yaml` (MODULE-010 B1) — turn 1's, caught up, as well.
    let yaml = std::fs::read_to_string(root.join("tasks/t1").join(TASK_TURN_INDEX_FILENAME))
        .expect("the task's turn index");
    let written: TurnIndex = serde_yml::from_str(&yaml).expect("a turn index");
    for n in 1..=3 {
        let row = index.get_turn("a", "t1", n).expect("turn row");
        assert_eq!(row.embedding_model.as_deref(), Some("embed-a"), "turn {n}");
        let view = &written
            .turns
            .iter()
            .find(|entry| entry.turn == n)
            .expect("the turn's entry")
            .collapsed_view;
        assert!(view.contains("hello"), "turn {n}: {view:?}");
        assert_eq!(
            row.embedding,
            ScriptedEmbedder::vector("embed-a", &format!("Refactored the tokenizer\n{view}")),
            "turn {n}"
        );
    }
    let task = index.get_task("a", "t1").expect("task row");
    assert_eq!(task.brief_embedding_model.as_deref(), Some("embed-a"));
    assert_eq!(task.turns_total, 3);
    // Turn 3, the brief, turn 1 — and nothing more on the next run but its turn.
    assert_eq!(embedder.requests(), failed_requests + 4);
    pp.run("a", &message(), &no_actions())
        .await
        .expect("run Ok");
    assert_eq!(embedder.requests(), failed_requests + 5);
}

/// Through the real `PostProcessor::run`: a catch-up that is kept from a row's
/// vector is reported by the run that made it — after everything else of the
/// turn end is done — and not by the runs after it (the refused text is not
/// asked about again).
#[tokio::test]
async fn a_catch_up_failure_is_reported_by_the_run_that_made_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".agent/memory");
    let embedder = ScriptedEmbedder::new(Some("embed-a"));
    let clock = Arc::new(MutableClock::new(t0()));
    let index: Arc<dyn SqliteIndex + Send + Sync> = Arc::new(InMemorySqliteIndex::default());
    // A row of an earlier task, whose text the service refuses.
    index.upsert_turn(TurnIndexRow {
        agent_id: "a".into(),
        task_id: "t0".into(),
        turn: 1,
        digest: "poison".into(),
        embedding: Vec::new(),
        embedding_model: None,
        reference_count: 0,
        updated_at: "2026-01-01T00:00:00+00:00".into(),
    });
    embedder.refuse(&["poison\n"]);
    let pp = pipeline(&root, "a", embedder.clone(), clock.clone(), index.clone());

    let reported = pp
        .run("a", &message(), &no_actions())
        .await
        .expect_err("the refusal is reported");
    assert!(
        format!("{reported:?}").contains("refused the text"),
        "{reported:?}"
    );
    // The turn's own rows are written and embedded all the same.
    let own = index.get_turn("a", "t1", 1).expect("the turn's row");
    assert_eq!(own.embedding_model.as_deref(), Some("embed-a"));
    assert!(index
        .get_task("a", "t1")
        .expect("the task row")
        .brief_embedding
        .is_some());
    let expected: Vec<String> = CANONICAL_STEPS.iter().map(|s| s.to_string()).collect();
    assert_eq!(pp.trace_snapshot(), expected, "all nine steps ran");
    assert!(index.get_turn("a", "t0", 1).unwrap().embedding.is_empty());

    // Past the rest that pass earned (it asked and got no vector): what keeps the
    // refused text from being asked about again is that it is set aside.
    let asked = embedder.requests();
    clock.advance(EMBEDDING_REST);
    pp.run("a", &message(), &no_actions())
        .await
        .expect("nothing to report");
    assert_eq!(embedder.requests(), asked + 1, "its own turn, nothing else");
}

/// Through the real `PostProcessor::run`: a parent and a child end turns under
/// the SAME task id, writing into the one index a home's agents share. Each has
/// its own task row and its own turn rows; neither run touches the other's.
#[tokio::test]
async fn a_parent_and_a_child_under_one_task_id_do_not_share_a_task_row() {
    let tmp = tempfile::tempdir().unwrap();
    let embedder = ScriptedEmbedder::new(Some("embed-a"));
    let clock = Arc::new(MutableClock::new(t0()));
    let index: Arc<dyn SqliteIndex + Send + Sync> = Arc::new(InMemorySqliteIndex::default());
    let parent = pipeline(
        &tmp.path().join("parent/.agent/memory"),
        "parent",
        embedder.clone(),
        clock.clone(),
        index.clone(),
    );
    let child = pipeline(
        &tmp.path().join("child/.agent/memory"),
        "child",
        embedder.clone(),
        clock.clone(),
        index.clone(),
    );

    for _ in 0..2 {
        clock.advance(Duration::from_secs(1));
        parent
            .run("agent:parent", &message(), &no_actions())
            .await
            .expect("parent run");
    }
    let parent_row = index
        .get_task("parent", "t1")
        .expect("the parent's task row");
    assert_eq!(parent_row.turns_total, 2);

    clock.advance(Duration::from_secs(1));
    child
        .run("agent:child", &message(), &no_actions())
        .await
        .expect("child run");

    let child_row = index.get_task("child", "t1").expect("the child's task row");
    assert_eq!(child_row.agent_id, "child");
    assert_eq!(child_row.turns_total, 1);
    assert_eq!(
        index.get_task("parent", "t1"),
        Some(parent_row),
        "the child's turn end left the parent's row as it was"
    );
    assert_eq!(index.list_tasks_for_agent("parent").len(), 1);
    assert_eq!(index.list_tasks_for_agent("child").len(), 1);
    assert_eq!(index.list_turns_for_agent("parent").len(), 2);
    assert_eq!(index.list_turns_for_agent("child").len(), 1);
}
