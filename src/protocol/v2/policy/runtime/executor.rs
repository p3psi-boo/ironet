//! Bounded worker-pool orchestration for policy calls.

use super::*;

/// A request sent to the fixed worker pool.
struct ExecutorRequest {
    peer_key: String,
    input: PolicyInputV1,
    deadline: Instant,
    response: SyncSender<Result<PolicyOutputV1, PolicyFaultV1>>,
}

/// Executor configuration. Workers are ordinary OS threads, never Tokio core
/// workers, and requests are bounded by `queue_capacity`.
#[derive(Debug, Clone)]
pub struct PolicyExecutorConfig {
    pub workers: usize,
    pub queue_capacity: usize,
    pub deadline: Duration,
}

impl Default for PolicyExecutorConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            queue_capacity: 64,
            deadline: Duration::from_millis(10),
        }
    }
}

/// A one-shot result returned by [`PolicyExecutor::submit`].
pub type PolicyResponse = Receiver<Result<PolicyOutputV1, PolicyFaultV1>>;

/// Bounded, fixed-size policy worker pool.
pub struct PolicyExecutor {
    requests: Option<crossbeam_channel::Sender<ExecutorRequest>>,
    workers: Vec<JoinHandle<()>>,
    config: PolicyExecutorConfig,
}

impl PolicyExecutor {
    pub fn new<B>(backend: B, config: PolicyExecutorConfig) -> Self
    where
        B: PolicyBackend + 'static,
    {
        let config = PolicyExecutorConfig {
            workers: config.workers.max(1),
            queue_capacity: config.queue_capacity.max(1),
            deadline: config.deadline.max(Duration::from_millis(1)),
        };
        let backend: Arc<Mutex<Box<dyn PolicyBackend>>> = Arc::new(Mutex::new(Box::new(backend)));
        let (sender, receiver) = crossbeam_channel::bounded(config.queue_capacity);
        let mut workers = Vec::with_capacity(config.workers);
        for index in 0..config.workers {
            let receiver = receiver.clone();
            let backend = Arc::clone(&backend);
            workers.push(
                thread::Builder::new()
                    .name(format!("ironet-policy-worker-{index}"))
                    .spawn(move || worker_loop(receiver, backend))
                    .expect("spawning policy worker"),
            );
        }
        Self {
            requests: Some(sender),
            workers,
            config,
        }
    }

    pub fn with_defaults<B>(backend: B) -> Self
    where
        B: PolicyBackend + 'static,
    {
        Self::new(backend, PolicyExecutorConfig::default())
    }

    pub fn submit(&self, peer_key: impl Into<String>, input: PolicyInputV1) -> PolicyResponse {
        let Some(requests) = &self.requests else {
            let (sender, response) = mpsc::sync_channel(1);
            let _ = sender.send(Err(PolicyFaultV1::Unavailable));
            return response;
        };
        let (sender, response) = mpsc::sync_channel(1);
        let request = ExecutorRequest {
            peer_key: peer_key.into(),
            input,
            deadline: Instant::now() + self.config.deadline,
            response: sender,
        };
        if requests.try_send(request).is_err() {
            // The queue is full or the executor is shutting down.  Return a
            // ready oneshot so the caller can immediately use its baseline.
            let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
            let _ = ready_sender.send(Err(PolicyFaultV1::Unavailable));
            return ready_receiver;
        }
        response
    }

    pub fn config(&self) -> &PolicyExecutorConfig {
        &self.config
    }

    pub fn queue_capacity(&self) -> usize {
        self.config.queue_capacity
    }

    pub fn queue_depth(&self) -> usize {
        self.requests
            .as_ref()
            .map_or(0, crossbeam_channel::Sender::len)
    }
}

impl Drop for PolicyExecutor {
    fn drop(&mut self) {
        // Closing the sender lets every worker leave its blocking receive
        // loop.  Joining keeps the executor's fixed thread pool bounded over
        // repeated policy reloads.
        self.requests.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn worker_loop(
    receiver: crossbeam_channel::Receiver<ExecutorRequest>,
    backend: Arc<Mutex<Box<dyn PolicyBackend>>>,
) {
    while let Ok(request) = receiver.recv() {
        let _peer_key = request.peer_key;
        if Instant::now() >= request.deadline {
            let _ = request.response.send(Err(PolicyFaultV1::Unavailable));
            continue;
        }
        let result = match backend.lock() {
            Ok(mut backend) if Instant::now() < request.deadline => backend.decide(&request.input),
            Ok(_) => Err(PolicyFaultV1::Unavailable),
            Err(_) => Err(PolicyFaultV1::Internal),
        };
        let result = if Instant::now() >= request.deadline {
            Err(PolicyFaultV1::Unavailable)
        } else {
            result
        };
        let _ = request.response.send(result);
    }
}
