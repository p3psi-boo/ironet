//! Deterministic bounded component cache.

use super::*;

/// Bounded LRU cache for compiled components. Keeping recency separate from
/// the map makes eviction deterministic rather than depending on HashMap's
/// randomized iteration order.
pub(super) struct ComponentCache {
    entries: HashMap<[u8; 32], Arc<Component>>,
    least_recently_used: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl ComponentCache {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            least_recently_used: VecDeque::new(),
            capacity,
        }
    }

    pub(super) fn get(&mut self, digest: &[u8; 32]) -> Option<Arc<Component>> {
        let component = self.entries.get(digest).cloned()?;
        self.touch(*digest);
        Some(component)
    }

    pub(super) fn insert(&mut self, digest: [u8; 32], component: Arc<Component>) -> Arc<Component> {
        if let Some(existing) = self.get(&digest) {
            return existing;
        }
        while self.entries.len() >= self.capacity {
            let evicted = self
                .least_recently_used
                .pop_front()
                .expect("non-empty cache has an LRU entry");
            self.entries.remove(&evicted);
        }
        self.least_recently_used.push_back(digest);
        self.entries.insert(digest, Arc::clone(&component));
        component
    }

    fn touch(&mut self, digest: [u8; 32]) {
        if let Some(index) = self
            .least_recently_used
            .iter()
            .position(|candidate| *candidate == digest)
        {
            self.least_recently_used.remove(index);
        }
        self.least_recently_used.push_back(digest);
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }
}
