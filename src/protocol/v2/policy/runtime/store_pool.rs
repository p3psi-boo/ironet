//! Reusable Wasmtime store and component-instance pools.

use super::*;

pub(super) struct HostState {
    limits: StoreLimits,
}

pub(super) struct StoreSlot {
    pub(super) store: Store<HostState>,
    pub(super) policy: Policy,
}

/// Reusable store/instance pool for one compiled policy.
#[derive(Clone)]
pub struct StorePool {
    inner: Arc<StorePoolInner>,
}

struct StorePoolInner {
    engine: PolicyEngine,
    component: CompiledPolicy,
    maximum_memory_bytes: usize,
    capacity: usize,
    slots: Mutex<Vec<StoreSlot>>,
}

impl StorePool {
    pub fn new(
        engine: PolicyEngine,
        component: CompiledPolicy,
        maximum_memory_bytes: u64,
        capacity: usize,
    ) -> Result<Self> {
        let pool = Self {
            inner: Arc::new(StorePoolInner {
                engine,
                component,
                maximum_memory_bytes: usize::try_from(maximum_memory_bytes)
                    .context("maximum policy memory does not fit usize")?,
                capacity: capacity.max(1),
                slots: Mutex::new(Vec::new()),
            }),
        };
        // Instantiate one store eagerly.  This makes missing exports and ABI
        // mismatches loader errors rather than first-tick errors.
        let slot = pool.new_slot()?;
        pool.put(slot);
        Ok(pool)
    }

    fn linker(&self) -> Linker<HostState> {
        Linker::new(self.inner.engine.engine())
    }

    fn new_slot(&self) -> Result<StoreSlot> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.inner.maximum_memory_bytes)
            .instances(1)
            .memories(1)
            .tables(1)
            .table_elements(10_000)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(self.inner.engine.engine(), HostState { limits });
        store.limiter(|state| &mut state.limits);
        // Instantiation itself should not be stopped by the call deadline.
        store.set_epoch_deadline(u64::MAX / 2);
        let policy =
            Policy::instantiate(&mut store, self.inner.component.component(), &self.linker())
                .map_err(|error| anyhow!("instantiating policy component: {error}"))?;
        Ok(StoreSlot { store, policy })
    }

    pub(super) fn take(&self) -> Result<StoreSlot> {
        if let Some(slot) = self
            .inner
            .slots
            .lock()
            .expect("policy store pool poisoned")
            .pop()
        {
            return Ok(slot);
        }
        self.new_slot()
    }

    pub(super) fn put(&self, slot: StoreSlot) {
        let mut slots = self.inner.slots.lock().expect("policy store pool poisoned");
        if slots.len() < self.inner.capacity {
            slots.push(slot);
        }
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    pub fn available(&self) -> usize {
        self.inner
            .slots
            .lock()
            .expect("policy store pool poisoned")
            .len()
    }
}
