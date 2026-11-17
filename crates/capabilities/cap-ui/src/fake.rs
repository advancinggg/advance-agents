//! Fake drivers (the M025 pattern): deterministic, in-memory implementations of
//! [`BrowserDriverPort`] and [`ScreenDriverPort`] over fixture pages / windows.
//! The conformance suite runs on them and on every product driver alike.
//!
//! Semantics the fakes pin down for product drivers:
//! - refs are `e1`, `e2`, … in snapshot order and stay valid for the page /
//!   window they were taken from; after a navigation (or before the first
//!   snapshot of a target) any ref is [`UiError::StaleRef`];
//! - `generation` is bumped by every state-changing action, including ones
//!   that keep the element set (typing, toggling);
//! - typing into a [`UiState::Secure`] element without `allow_secure` is
//!   [`UiError::SecureField`]; the value of such an element is reported to the
//!   family, which masks it;
//! - action results carry the target afterwards (URL / title), so a
//!   navigation is visible in the one-line result.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use advance_shared_types::ui::{
    BrowserAction, BrowserDriverPort, HistoryAction, ScreenAction, ScreenDriverPort,
    SnapshotOptions, TabAction, UiActionResult, UiElement, UiError, UiReadResult, UiSnapshot,
    UiState, UiTargetInfo, UiTargetKind, WaitCondition,
};
use async_trait::async_trait;

/// One element of a fixture page / window.
#[derive(Clone, Debug)]
pub struct ElementSpec {
    pub role: String,
    pub name: String,
    pub value: Option<String>,
    pub states: Vec<UiState>,
    /// Click → navigate here (links, buttons).
    pub href: Option<String>,
    /// Typing with `submit` (or Enter while focused) → navigate here.
    pub submit_to: Option<String>,
    /// Combobox / listbox options.
    pub options: Vec<String>,
}

impl ElementSpec {
    pub fn new(role: &str, name: &str) -> Self {
        Self {
            role: role.to_string(),
            name: name.to_string(),
            value: None,
            states: Vec::new(),
            href: None,
            submit_to: None,
            options: Vec::new(),
        }
    }

    fn interactive(mut self) -> Self {
        self.states.push(UiState::Interactive);
        self
    }

    pub fn heading(name: &str) -> Self {
        Self::new("heading", name)
    }

    pub fn text(name: &str) -> Self {
        Self::new("text", name)
    }

    pub fn link(name: &str, href: &str) -> Self {
        let mut e = Self::new("link", name).interactive();
        e.href = Some(href.to_string());
        e
    }

    pub fn button(name: &str) -> Self {
        Self::new("button", name).interactive()
    }

    pub fn button_to(name: &str, href: &str) -> Self {
        let mut e = Self::button(name);
        e.href = Some(href.to_string());
        e
    }

    pub fn textbox(name: &str) -> Self {
        let mut e = Self::new("textbox", name).interactive();
        e.value = Some(String::new());
        e
    }

    pub fn textbox_submit(name: &str, submit_to: &str) -> Self {
        let mut e = Self::textbox(name);
        e.submit_to = Some(submit_to.to_string());
        e
    }

    pub fn password(name: &str, value: &str) -> Self {
        let mut e = Self::new("textbox", name).interactive();
        e.states.push(UiState::Secure);
        e.value = Some(value.to_string());
        e
    }

    pub fn checkbox(name: &str, checked: bool) -> Self {
        let mut e = Self::new("checkbox", name).interactive();
        if checked {
            e.states.push(UiState::Checked);
        }
        e
    }

    pub fn combobox(name: &str, options: &[&str]) -> Self {
        let mut e = Self::new("combobox", name).interactive();
        e.options = options.iter().map(|s| s.to_string()).collect();
        e.value = options.first().map(|s| s.to_string());
        e
    }

    pub fn with_value(mut self, value: &str) -> Self {
        self.value = Some(value.to_string());
        self
    }

    fn is(&self, state: UiState) -> bool {
        self.states.contains(&state)
    }

    fn typeable(&self) -> bool {
        matches!(
            self.role.as_str(),
            "textbox" | "searchbox" | "combobox" | "textarea"
        )
    }

    fn to_element(&self, index: usize) -> UiElement {
        UiElement {
            r#ref: format!("e{}", index + 1),
            role: self.role.clone(),
            name: self.name.clone(),
            value: self.value.clone(),
            bounds: None,
            states: self.states.clone(),
            depth: 1,
        }
    }

    fn read_text(&self) -> String {
        match &self.value {
            Some(v) if !v.is_empty() => format!("{} {}", self.name, v),
            _ => self.name.clone(),
        }
    }
}

fn snapshot_elements(
    elements: &[ElementSpec],
    options: &SnapshotOptions,
) -> (Vec<UiElement>, bool) {
    let mut out: Vec<UiElement> = elements
        .iter()
        .enumerate()
        .filter(|(_, e)| !options.interactive_only || e.is(UiState::Interactive))
        .map(|(i, e)| e.to_element(i))
        .collect();
    let truncated = out.len() > options.max_elements;
    out.truncate(options.max_elements);
    (out, truncated)
}

fn parse_ref(r: &str, len: usize) -> Result<usize, UiError> {
    let n: usize = r
        .strip_prefix('e')
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| UiError::UnknownRef {
            r#ref: r.to_string(),
        })?;
    if n == 0 || n > len {
        return Err(UiError::UnknownRef {
            r#ref: r.to_string(),
        });
    }
    Ok(n - 1)
}

fn toggle_checked(states: &mut Vec<UiState>) {
    if let Some(i) = states.iter().position(|s| *s == UiState::Checked) {
        states.remove(i);
    } else {
        states.push(UiState::Checked);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ─────────────────────────────────────────────────────────────────────────
// Browser
// ─────────────────────────────────────────────────────────────────────────

/// A fixture page.
#[derive(Clone, Debug, Default)]
pub struct PageSpec {
    pub title: String,
    pub text: String,
    pub elements: Vec<ElementSpec>,
}

impl PageSpec {
    pub fn new(title: &str, text: &str) -> Self {
        Self {
            title: title.to_string(),
            text: text.to_string(),
            elements: Vec::new(),
        }
    }

    pub fn with(mut self, element: ElementSpec) -> Self {
        self.elements.push(element);
        self
    }
}

fn page_key(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

#[derive(Clone, Debug)]
struct Tab {
    id: String,
    url: Option<String>,
    title: String,
    text: String,
    elements: Vec<ElementSpec>,
    history: Vec<String>,
    pos: usize,
    load_gen: u64,
    snapshot_gen: Option<u64>,
    focused: Option<usize>,
}

impl Tab {
    fn blank(id: String, generation: u64) -> Self {
        Self {
            id,
            url: None,
            title: "about:blank".to_string(),
            text: String::new(),
            elements: Vec::new(),
            history: Vec::new(),
            pos: 0,
            load_gen: generation,
            snapshot_gen: None,
            focused: None,
        }
    }

    fn info(&self, active: bool) -> UiTargetInfo {
        UiTargetInfo {
            id: self.id.clone(),
            kind: UiTargetKind::Tab,
            title: self.title.clone(),
            url: self.url.clone(),
            app: None,
            active,
        }
    }

    fn page_text(&self) -> String {
        format!("{}\n{}", self.title, self.text)
    }
}

#[derive(Debug)]
struct BrowserState {
    pages: HashMap<String, PageSpec>,
    tabs: Vec<Tab>,
    selected: usize,
    generation: u64,
    log: Vec<String>,
    next_tab: u32,
}

impl BrowserState {
    fn tab_index(&self, tab: Option<&str>) -> Result<usize, UiError> {
        match tab {
            None => Ok(self.selected),
            Some(id) => {
                self.tabs
                    .iter()
                    .position(|t| t.id == id)
                    .ok_or_else(|| UiError::UnknownTarget {
                        target: id.to_string(),
                    })
            }
        }
    }

    /// Load a fixture page into a tab; `push` records it in the tab's history.
    fn load(&mut self, idx: usize, url: &str, push: bool) -> Result<(), UiError> {
        let page = self
            .pages
            .get(&page_key(url))
            .cloned()
            .ok_or_else(|| UiError::Driver {
                message: format!("fake: no fixture page at {url}"),
            })?;
        self.generation += 1;
        let generation = self.generation;
        let tab = &mut self.tabs[idx];
        tab.url = Some(url.to_string());
        tab.title = page.title;
        tab.text = page.text;
        tab.elements = page.elements;
        tab.load_gen = generation;
        tab.snapshot_gen = None;
        tab.focused = None;
        if push {
            if !tab.history.is_empty() {
                tab.history.truncate(tab.pos + 1);
            }
            tab.history.push(url.to_string());
            tab.pos = tab.history.len() - 1;
        }
        Ok(())
    }

    fn result(
        &self,
        idx: usize,
        changed: bool,
        sensitive: bool,
        note: Option<String>,
    ) -> UiActionResult {
        UiActionResult {
            generation: self.generation,
            changed,
            sensitive,
            note,
            target: Some(self.tabs[idx].info(idx == self.selected)),
        }
    }

    /// Resolve a ref against the tab's current page; stale before the first
    /// snapshot of a page load.
    fn element(&self, idx: usize, r: &str) -> Result<usize, UiError> {
        let tab = &self.tabs[idx];
        let stale = match tab.snapshot_gen {
            None => true,
            Some(g) => g < tab.load_gen,
        };
        if stale {
            return Err(UiError::StaleRef {
                r#ref: r.to_string(),
                generation: self.generation,
            });
        }
        parse_ref(r, tab.elements.len())
    }
}

/// In-memory browser over fixture pages.
pub struct FakeBrowserDriver {
    state: Mutex<BrowserState>,
    surface_kind: &'static str,
}

impl Default for FakeBrowserDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBrowserDriver {
    /// One blank tab, no pages.
    pub fn new() -> Self {
        Self::with_fixture(Vec::new())
    }

    pub fn with_fixture(pages: Vec<(String, PageSpec)>) -> Self {
        Self {
            state: Mutex::new(BrowserState {
                pages: pages.into_iter().map(|(u, p)| (page_key(&u), p)).collect(),
                tabs: vec![Tab::blank("tab-1".to_string(), 0)],
                selected: 0,
                generation: 0,
                log: Vec::new(),
                next_tab: 2,
            }),
            surface_kind: "in-app",
        }
    }

    /// Report another surface kind (`external`) to exercise the grant's `surfaces`.
    pub fn with_surface_kind(mut self, kind: &'static str) -> Self {
        self.surface_kind = kind;
        self
    }

    pub fn add_page(&self, url: &str, page: PageSpec) {
        lock(&self.state).pages.insert(page_key(url), page);
    }

    /// Every driver call so far, in order (`navigate https://…`, `snapshot …`).
    pub fn log(&self) -> Vec<String> {
        lock(&self.state).log.clone()
    }

    pub fn generation(&self) -> u64 {
        lock(&self.state).generation
    }

    pub fn current_url(&self) -> Option<String> {
        let s = lock(&self.state);
        s.tabs[s.selected].url.clone()
    }
}

#[async_trait]
impl BrowserDriverPort for FakeBrowserDriver {
    fn surface_kind(&self) -> &'static str {
        self.surface_kind
    }

    async fn tabs(&self, action: TabAction) -> Result<Vec<UiTargetInfo>, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("tabs {action:?}"));
        match action {
            TabAction::List => {}
            TabAction::New { url } => {
                let id = format!("tab-{}", s.next_tab);
                s.next_tab += 1;
                let generation = s.generation;
                s.tabs.push(Tab::blank(id, generation));
                let idx = s.tabs.len() - 1;
                s.selected = idx;
                if let Some(u) = url {
                    s.load(idx, &u, true)?;
                }
            }
            TabAction::Close { tab_id } => {
                let idx = s.tab_index(Some(&tab_id))?;
                if s.tabs.len() == 1 {
                    return Err(UiError::Unsupported {
                        reason: "cannot close the last tab".to_string(),
                    });
                }
                s.tabs.remove(idx);
                if s.selected >= s.tabs.len() {
                    s.selected = s.tabs.len() - 1;
                }
                s.generation += 1;
            }
            TabAction::Select { tab_id } => {
                let idx = s.tab_index(Some(&tab_id))?;
                s.selected = idx;
            }
        }
        let sel = s.selected;
        Ok(s.tabs
            .iter()
            .enumerate()
            .map(|(i, t)| t.info(i == sel))
            .collect())
    }

    async fn current(&self, tab: Option<&str>) -> Result<UiTargetInfo, UiError> {
        let s = lock(&self.state);
        let idx = s.tab_index(tab)?;
        Ok(s.tabs[idx].info(idx == s.selected))
    }

    async fn navigate(&self, tab: Option<&str>, url: &str) -> Result<UiActionResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("navigate {url}"));
        let idx = s.tab_index(tab)?;
        s.load(idx, url, true)?;
        Ok(s.result(idx, true, false, None))
    }

    async fn history(
        &self,
        tab: Option<&str>,
        action: HistoryAction,
    ) -> Result<UiActionResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("history {action:?}"));
        let idx = s.tab_index(tab)?;
        let (pos, len) = (s.tabs[idx].pos, s.tabs[idx].history.len());
        match action {
            HistoryAction::Back => {
                if len == 0 || pos == 0 {
                    return Ok(s.result(idx, false, false, Some("no earlier page".to_string())));
                }
                let url = s.tabs[idx].history[pos - 1].clone();
                s.load(idx, &url, false)?;
                s.tabs[idx].pos = pos - 1;
            }
            HistoryAction::Forward => {
                if len == 0 || pos + 1 >= len {
                    return Ok(s.result(idx, false, false, Some("no later page".to_string())));
                }
                let url = s.tabs[idx].history[pos + 1].clone();
                s.load(idx, &url, false)?;
                s.tabs[idx].pos = pos + 1;
            }
            HistoryAction::Reload => {
                let Some(url) = s.tabs[idx].url.clone() else {
                    return Ok(s.result(idx, false, false, Some("blank tab".to_string())));
                };
                s.load(idx, &url, false)?;
            }
        }
        Ok(s.result(idx, true, false, None))
    }

    async fn snapshot(
        &self,
        tab: Option<&str>,
        options: SnapshotOptions,
    ) -> Result<UiSnapshot, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("snapshot {options:?}"));
        let idx = s.tab_index(tab)?;
        let generation = s.generation;
        let sel = s.selected;
        let tab = &mut s.tabs[idx];
        tab.snapshot_gen = Some(generation);
        let (elements, truncated) = snapshot_elements(&tab.elements, &options);
        Ok(UiSnapshot {
            generation,
            target: tab.info(idx == sel),
            elements,
            text: tab.url.as_ref().map(|_| tab.page_text()),
            truncated,
        })
    }

    async fn act(
        &self,
        tab: Option<&str>,
        action: BrowserAction,
    ) -> Result<UiActionResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("act {action:?}"));
        let idx = s.tab_index(tab)?;
        match action {
            BrowserAction::Click { r#ref, .. } => {
                let i = s.element(idx, &r#ref)?;
                s.tabs[idx].focused = Some(i);
                let el = s.tabs[idx].elements[i].clone();
                if let Some(href) = &el.href {
                    s.load(idx, href, true)?;
                    return Ok(s.result(idx, true, false, None));
                }
                if el.role == "checkbox" {
                    toggle_checked(&mut s.tabs[idx].elements[i].states);
                    s.generation += 1;
                    return Ok(s.result(idx, true, false, None));
                }
                Ok(s.result(
                    idx,
                    false,
                    false,
                    Some(format!(
                        "clicked {} {:?}; nothing changed",
                        el.role, el.name
                    )),
                ))
            }
            BrowserAction::Type {
                r#ref,
                text,
                submit,
                clear,
                allow_secure,
            } => {
                let i = s.element(idx, &r#ref)?;
                let el = s.tabs[idx].elements[i].clone();
                if !el.typeable() {
                    return Err(UiError::Unsupported {
                        reason: format!("cannot type into a {}", el.role),
                    });
                }
                let secure = el.is(UiState::Secure);
                if secure && !allow_secure {
                    return Err(UiError::SecureField { r#ref });
                }
                {
                    let slot = &mut s.tabs[idx].elements[i];
                    let mut v = if clear {
                        String::new()
                    } else {
                        slot.value.clone().unwrap_or_default()
                    };
                    v.push_str(&text);
                    slot.value = Some(v);
                }
                s.tabs[idx].focused = Some(i);
                s.generation += 1;
                if submit {
                    if let Some(to) = &el.submit_to {
                        s.load(idx, to, true)?;
                    }
                }
                Ok(s.result(idx, true, secure, None))
            }
            BrowserAction::Press { key } => {
                if key.eq_ignore_ascii_case("enter") {
                    if let Some(i) = s.tabs[idx].focused {
                        if let Some(to) = s.tabs[idx].elements[i].submit_to.clone() {
                            s.load(idx, &to, true)?;
                            return Ok(s.result(idx, true, false, None));
                        }
                    }
                }
                Ok(s.result(idx, false, false, Some(format!("pressed {key}"))))
            }
            BrowserAction::Scroll { r#ref, dx, dy } => {
                if let Some(r) = &r#ref {
                    s.element(idx, r)?;
                }
                Ok(s.result(idx, false, false, Some(format!("scrolled by {dx},{dy}"))))
            }
            BrowserAction::Select { r#ref, values } => {
                let i = s.element(idx, &r#ref)?;
                let el = s.tabs[idx].elements[i].clone();
                if el.role != "combobox" && el.role != "listbox" {
                    return Err(UiError::Unsupported {
                        reason: format!("cannot select in a {}", el.role),
                    });
                }
                for v in &values {
                    if !el.options.iter().any(|o| o == v) {
                        return Err(UiError::Unsupported {
                            reason: format!("option {v:?} is not one of {:?}", el.options),
                        });
                    }
                }
                s.tabs[idx].elements[i].value = Some(values.join(","));
                s.generation += 1;
                Ok(s.result(idx, true, false, None))
            }
            BrowserAction::Hover { r#ref } => {
                s.element(idx, &r#ref)?;
                Ok(s.result(idx, false, false, Some("hovered".to_string())))
            }
        }
    }

    async fn read(&self, tab: Option<&str>, r#ref: Option<&str>) -> Result<UiReadResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("read {ref:?}", ref = r#ref));
        let idx = s.tab_index(tab)?;
        let text = match r#ref {
            None => s.tabs[idx].page_text(),
            Some(r) => {
                let i = s.element(idx, r)?;
                s.tabs[idx].elements[i].read_text()
            }
        };
        Ok(UiReadResult {
            generation: s.generation,
            text,
            truncated: false,
        })
    }

    async fn wait(
        &self,
        tab: Option<&str>,
        condition: WaitCondition,
    ) -> Result<UiActionResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("wait {condition:?}"));
        let idx = s.tab_index(tab)?;
        match condition.text {
            Some(t) => {
                let found = s.tabs[idx].page_text().contains(&t)
                    || s.tabs[idx].elements.iter().any(|e| e.name.contains(&t));
                if !found {
                    return Err(UiError::Timeout);
                }
                Ok(s.result(idx, true, false, Some(format!("{t:?} is present"))))
            }
            None => Ok(s.result(
                idx,
                false,
                false,
                Some(format!("waited {} ms", condition.ms)),
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Screen
// ─────────────────────────────────────────────────────────────────────────

/// A fixture window.
#[derive(Clone, Debug)]
pub struct WindowSpec {
    pub id: String,
    pub app: String,
    pub title: String,
    pub text: String,
    pub elements: Vec<ElementSpec>,
}

impl WindowSpec {
    pub fn new(id: &str, app: &str, title: &str, text: &str) -> Self {
        Self {
            id: id.to_string(),
            app: app.to_string(),
            title: title.to_string(),
            text: text.to_string(),
            elements: Vec::new(),
        }
    }

    pub fn with(mut self, element: ElementSpec) -> Self {
        self.elements.push(element);
        self
    }
}

#[derive(Debug)]
struct Window {
    spec: WindowSpec,
    elements: Vec<ElementSpec>,
    snapshot_gen: Option<u64>,
    focused: Option<usize>,
}

impl Window {
    fn info(&self, active: bool) -> UiTargetInfo {
        UiTargetInfo {
            id: self.spec.id.clone(),
            kind: UiTargetKind::Window,
            title: self.spec.title.clone(),
            url: None,
            app: Some(self.spec.app.clone()),
            active,
        }
    }
}

#[derive(Debug)]
struct ScreenState {
    windows: Vec<Window>,
    current: Option<usize>,
    generation: u64,
    log: Vec<String>,
}

impl ScreenState {
    fn find(&self, target: &str) -> Result<usize, UiError> {
        self.windows
            .iter()
            .position(|w| w.spec.id == target)
            .ok_or_else(|| UiError::UnknownTarget {
                target: target.to_string(),
            })
    }

    fn target_index(&self, target: Option<&str>) -> Result<usize, UiError> {
        match target {
            Some(t) => self.find(t),
            None => self.current.ok_or_else(|| UiError::UnknownTarget {
                target: "(current)".to_string(),
            }),
        }
    }

    fn element(&self, idx: usize, r: &str) -> Result<usize, UiError> {
        let w = &self.windows[idx];
        if w.snapshot_gen.is_none() {
            return Err(UiError::StaleRef {
                r#ref: r.to_string(),
                generation: self.generation,
            });
        }
        parse_ref(r, w.elements.len())
    }

    fn result(
        &self,
        idx: usize,
        changed: bool,
        sensitive: bool,
        note: Option<String>,
    ) -> UiActionResult {
        UiActionResult {
            generation: self.generation,
            changed,
            sensitive,
            note,
            target: Some(self.windows[idx].info(self.current == Some(idx))),
        }
    }
}

/// In-memory screen over fixture windows.
pub struct FakeScreenDriver {
    state: Mutex<ScreenState>,
}

impl FakeScreenDriver {
    pub fn with_fixture(windows: Vec<WindowSpec>) -> Self {
        Self {
            state: Mutex::new(ScreenState {
                windows: windows
                    .into_iter()
                    .map(|spec| Window {
                        elements: spec.elements.clone(),
                        spec,
                        snapshot_gen: None,
                        focused: None,
                    })
                    .collect(),
                current: None,
                generation: 0,
                log: Vec::new(),
            }),
        }
    }

    pub fn log(&self) -> Vec<String> {
        lock(&self.state).log.clone()
    }

    pub fn generation(&self) -> u64 {
        lock(&self.state).generation
    }
}

#[async_trait]
impl ScreenDriverPort for FakeScreenDriver {
    async fn list_targets(&self) -> Result<Vec<UiTargetInfo>, UiError> {
        let mut s = lock(&self.state);
        s.log.push("list_targets".to_string());
        let cur = s.current;
        Ok(s.windows
            .iter()
            .enumerate()
            .map(|(i, w)| w.info(cur == Some(i)))
            .collect())
    }

    async fn current(&self) -> Result<Option<UiTargetInfo>, UiError> {
        let s = lock(&self.state);
        Ok(s.current.map(|i| s.windows[i].info(true)))
    }

    async fn describe(
        &self,
        target: &str,
        options: SnapshotOptions,
    ) -> Result<UiSnapshot, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("describe {target} {options:?}"));
        let idx = s.find(target)?;
        s.current = Some(idx);
        let generation = s.generation;
        let w = &mut s.windows[idx];
        w.snapshot_gen = Some(generation);
        let (elements, truncated) = snapshot_elements(&w.elements, &options);
        Ok(UiSnapshot {
            generation,
            target: w.info(true),
            elements,
            text: Some(format!("{}\n{}", w.spec.title, w.spec.text)),
            truncated,
        })
    }

    async fn act(
        &self,
        target: Option<&str>,
        action: ScreenAction,
    ) -> Result<UiActionResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("act {target:?} {action:?}"));
        let idx = s.target_index(target)?;
        match action {
            ScreenAction::Focus => {
                s.current = Some(idx);
                s.generation += 1;
                Ok(s.result(idx, true, false, None))
            }
            ScreenAction::Click { r#ref, .. } => {
                let i = s.element(idx, &r#ref)?;
                s.windows[idx].focused = Some(i);
                let role = s.windows[idx].elements[i].role.clone();
                match role.as_str() {
                    "checkbox" => {
                        toggle_checked(&mut s.windows[idx].elements[i].states);
                        s.generation += 1;
                        Ok(s.result(idx, true, false, None))
                    }
                    "button" => {
                        s.generation += 1;
                        Ok(s.result(idx, true, false, Some("pressed".to_string())))
                    }
                    _ => Ok(s.result(
                        idx,
                        false,
                        false,
                        Some(format!("clicked {role}; nothing changed")),
                    )),
                }
            }
            ScreenAction::Type {
                r#ref,
                text,
                replace,
                allow_secure,
            } => {
                let i = match r#ref {
                    Some(r) => s.element(idx, &r)?,
                    None => s.windows[idx].focused.ok_or_else(|| UiError::Unsupported {
                        reason: "no focused element; name a ref".to_string(),
                    })?,
                };
                let el = s.windows[idx].elements[i].clone();
                if !el.typeable() {
                    return Err(UiError::Unsupported {
                        reason: format!("cannot type into a {}", el.role),
                    });
                }
                let secure = el.is(UiState::Secure);
                if secure && !allow_secure {
                    return Err(UiError::SecureField {
                        r#ref: format!("e{}", i + 1),
                    });
                }
                let slot = &mut s.windows[idx].elements[i];
                let mut v = if replace {
                    String::new()
                } else {
                    slot.value.clone().unwrap_or_default()
                };
                v.push_str(&text);
                slot.value = Some(v);
                s.windows[idx].focused = Some(i);
                s.generation += 1;
                Ok(s.result(idx, true, secure, None))
            }
            ScreenAction::Key { keys, .. } => {
                Ok(s.result(idx, false, false, Some(format!("pressed {keys}"))))
            }
            ScreenAction::Scroll { r#ref, dx, dy } => {
                s.element(idx, &r#ref)?;
                Ok(s.result(idx, false, false, Some(format!("scrolled by {dx},{dy}"))))
            }
        }
    }

    async fn read(&self, target: Option<&str>, r#ref: &str) -> Result<UiReadResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("read {target:?} {ref}", ref = r#ref));
        let idx = s.target_index(target)?;
        let i = s.element(idx, r#ref)?;
        Ok(UiReadResult {
            generation: s.generation,
            text: s.windows[idx].elements[i].read_text(),
            truncated: false,
        })
    }

    async fn wait(&self, target: Option<&str>, ms: u64) -> Result<UiActionResult, UiError> {
        let mut s = lock(&self.state);
        s.log.push(format!("wait {target:?} {ms}"));
        let idx = s.target_index(target)?;
        Ok(s.result(idx, false, false, Some(format!("waited {ms} ms"))))
    }
}
