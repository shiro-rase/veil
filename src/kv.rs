use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone, Default)]
pub struct KvStore {
    data: Arc<RwLock<HashMap<String, String>>>,
}

impl KvStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set(&self, key: impl Into<String>, val: impl Into<String>) {
        let mut store = self.data.write().await;
        store.insert(key.into(), val.into());
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let store = self.data.read().await;
        store.get(key).cloned()
    }

    pub async fn delete(&self, key: &str) -> bool {
        let mut store = self.data.write().await;
        store.remove(key).is_some()
    }

    pub async fn list(&self) -> HashMap<String, String> {
        let store = self.data.read().await;
        store.clone()
    }

    pub async fn bulk_load(&self, entries: HashMap<String, String>) {
        let mut store = self.data.write().await;
        for (k, v) in entries {
            store.insert(k, v);
        }
    }
}
