use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use advance_shared_types::web_search::{WebRunMode, WebSearchHit};

const MAX_ENTRIES: usize = 1024;

#[derive(Clone, Debug)]
pub struct CacheKey {
    pub tenant: String,
    pub principal: String,
    pub mode: WebRunMode,
    pub provider: String,
    pub query: String,
    pub filters: String,
}

impl CacheKey {
    pub fn encode(&self) -> String {
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.tenant,
            self.principal,
            self.mode.as_str(),
            self.provider,
            self.query,
            self.filters
        )
    }
}

pub struct QueryCache {
    inner: Mutex<Inner>,
}

struct Inner {
    map: HashMap<String, Vec<WebSearchHit>>,
    order: VecDeque<String>,
}

impl QueryCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<Vec<WebSearchHit>> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.map.get(&key.encode()).cloned()
    }

    pub fn put(&self, key: CacheKey, hits: Vec<WebSearchHit>) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let enc = key.encode();
        if g.map.insert(enc.clone(), hits).is_none() {
            g.order.push_back(enc);
            while g.order.len() > MAX_ENTRIES {
                if let Some(old) = g.order.pop_front() {
                    g.map.remove(&old);
                }
            }
        }
    }
}

impl Default for QueryCache {
    fn default() -> Self {
        Self::new()
    }
}
