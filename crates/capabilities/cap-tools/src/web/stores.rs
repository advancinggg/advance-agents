use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

const MAX_REFS: usize = 4096;
const MAX_EVIDENCE: usize = 4096;

fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(prefix.len() + 32);
    hex.push_str(prefix);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

#[derive(Clone, Debug)]
pub struct ResultRefRecord {
    pub url: String,
    pub rank: u32,
    pub tenant: String,
    pub needs_fetch: bool,
    pub cached_body: Option<String>,
}

pub struct ResultRefStore {
    inner: Mutex<StoreInner<ResultRefRecord>>,
}

struct StoreInner<T> {
    map: HashMap<String, T>,
    order: VecDeque<String>,
    cap: usize,
}

impl<T> StoreInner<T> {
    fn insert(&mut self, key: String, val: T) {
        if self.map.insert(key.clone(), val).is_none() {
            self.order.push_back(key.clone());
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

impl ResultRefStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(StoreInner {
                map: HashMap::new(),
                order: VecDeque::new(),
                cap: MAX_REFS,
            }),
        }
    }

    pub fn mint(&self, rec: ResultRefRecord) -> String {
        let token = random_token("wr_");
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.insert(token.clone(), rec);
        token
    }

    pub fn get(&self, token: &str, tenant: &str) -> Option<ResultRefRecord> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.map.get(token).cloned().filter(|r| r.tenant == tenant)
    }
}

impl Default for ResultRefStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct EvidenceIdStore {
    inner: Mutex<StoreInner<()>>,
}

impl EvidenceIdStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(StoreInner {
                map: HashMap::new(),
                order: VecDeque::new(),
                cap: MAX_EVIDENCE,
            }),
        }
    }

    pub fn mint(&self) -> String {
        let token = random_token("ev_");
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.insert(token.clone(), ());
        token
    }

    pub fn contains(&self, id: &str) -> bool {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.map.contains_key(id)
    }

    pub fn issued(&self) -> Vec<String> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.order.iter().cloned().collect()
    }
}

impl Default for EvidenceIdStore {
    fn default() -> Self {
        Self::new()
    }
}
