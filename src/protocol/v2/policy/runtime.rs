//! Wasmtime Component runtime for policy ABI V1.
//!
//! The runtime deliberately keeps all guest state in the ABI records.  A
//! compiled component is shareable, while a store and its instance belong to
//! one call at a time and are discarded after a Wasmtime trap or resource
//! failure.  No WASI imports are linked into the policy world.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use super::{
    api::{
        Bbr3PresetV1, BbrCandidateV1, BbrEffectiveV1, CandidateActionV1, CoverCandidateV1,
        CoverEffectiveV1, CoverProfileV1, EffectiveActionViewV1, EgressAllocationViewV1,
        EgressRequestV1, FecCandidateV1, FecEffectiveV1, FecPresetFamilyV1, HostCapabilitiesV1,
        HostLimitsV1, HostUtilityV1, PathReliabilityV1, PolicyBackend, PolicyBackendKindV1,
        PolicyDecisionKindV1, PolicyDiagnosticsV1, PolicyExtensionV1, PolicyFaultV1,
        PolicyIdentityV1, PolicyInputV1, PolicyLabelV1, PolicyOutputV1, PolicyTelemetryV1,
        ProtectionResponsibilityV1, RepairCandidateV1, RepairEffectiveV1, RepairWaitPolicyV1,
        RxCandidateV1, RxEffectiveV1, SchedulerCandidateV1, SchedulerEffectiveV1,
        SchedulerPresetHintV1, TxCandidateV1, TxEffectiveV1,
    },
    package::{POLICY_ABI_WORLD_V1, PackageLimits, PolicyManifestV1, PolicyPackage},
    signature::TrustStoreV1,
    status::PolicyRuntimeStatusV1,
};
use crate::config::AutotuneWasmConfig;

wasmtime::component::bindgen!({
    path: "crates/ironet-policy-abi/wit",
    world: "policy",
});

use self::ironet::policy::types as wit;

mod backend;
mod cache;
mod conversion;
mod executor;
mod loader;
mod store_pool;

pub use backend::WasmPolicyBackend;
pub use executor::{PolicyExecutor, PolicyExecutorConfig, PolicyResponse};
pub use loader::PolicyLoader;
pub use store_pool::StorePool;

#[cfg(test)]
use backend::micros;
use cache::ComponentCache;
use conversion::*;
use store_pool::HostState;

/// Initial fuel budget used by fixtures and by manifests that request the
/// normal builtin budget.  The manifest is still a request: the host caps it
/// at [`MAXIMUM_FUEL_BUDGET`].
pub const DEFAULT_FUEL_BUDGET: u64 = 1_000_000;
/// Prevent a manifest from turning one slow policy tick into an unbounded
/// deterministic computation.
pub const MAXIMUM_FUEL_BUDGET: u64 = 10_000_000;
/// The ticker granularity.  A deadline is expressed in these epoch ticks.
pub const EPOCH_TICK: Duration = Duration::from_millis(1);
/// Maximum number of compiled components retained by one engine.
pub const DEFAULT_COMPONENT_CACHE_CAPACITY: usize = 32;
/// Number of stores retained by a pool when the caller does not specify one.
pub const DEFAULT_STORE_POOL_CAPACITY: usize = 1;
/// Component-model records have a fixed canonical area; this headroom covers
/// scalar fields and list descriptors before variable payloads are counted.
const INPUT_FIXED_OVERHEAD_BYTES: usize = 2 * 1024;
const OUTPUT_FIXED_OVERHEAD_BYTES: usize = 2 * 1024;

/// The committed builtin policy component and its BLAKE3 sidecar, embedded
/// at compile time. Rebuild both with `scripts/build-policy-guest.sh` when
/// the guest or `ironet-policy-core` changes; the package tests pin the pair.
const BUILTIN_WASM_V1: &[u8] =
    include_bytes!("../../../../crates/ironet-policy-builtin/builtin.wasm");
const BUILTIN_WASM_BLAKE3_V1: &str =
    include_str!("../../../../crates/ironet-policy-builtin/builtin.wasm.blake3");

/// Shared Wasmtime engine, component cache and epoch ticker.
#[derive(Clone)]
pub struct PolicyEngine {
    inner: Arc<PolicyEngineInner>,
}

struct PolicyEngineInner {
    engine: Engine,
    components: Mutex<ComponentCache>,
    ticker_stop: Arc<AtomicBool>,
    ticker: Mutex<Option<JoinHandle<()>>>,
}

impl PolicyEngine {
    /// Builds the deterministic Pulley-targeted engine selected by the Phase 0
    /// spike.
    pub fn new() -> Self {
        Self::try_new().expect("building the policy Wasmtime engine")
    }

    /// Fallible constructor useful to callers that do not want engine setup to
    /// panic during daemon startup.
    pub fn try_new() -> Result<Self> {
        let mut config = Config::new();
        configure_engine(&mut config)?;
        let engine = Engine::new(&config)
            .map_err(|error| anyhow!("creating policy Wasmtime engine: {error}"))?;
        Ok(Self::from_engine(engine, DEFAULT_COMPONENT_CACHE_CAPACITY))
    }

    /// Creates an engine wrapper from an already configured Wasmtime engine.
    /// This is primarily useful for embedding and deterministic runtime tests.
    pub fn from_engine(engine: Engine, component_cache_capacity: usize) -> Self {
        let component_cache_capacity = component_cache_capacity.max(1);
        let ticker_stop = Arc::new(AtomicBool::new(false));
        let ticker_engine = engine.clone();
        let ticker_stop_for_thread = Arc::clone(&ticker_stop);
        let ticker = thread::Builder::new()
            .name("ironet-policy-epoch".to_owned())
            .spawn(move || {
                while !ticker_stop_for_thread.load(Ordering::Acquire) {
                    thread::sleep(EPOCH_TICK);
                    if !ticker_stop_for_thread.load(Ordering::Acquire) {
                        ticker_engine.increment_epoch();
                    }
                }
            })
            .expect("spawning the policy epoch ticker");
        Self {
            inner: Arc::new(PolicyEngineInner {
                engine,
                components: Mutex::new(ComponentCache::new(component_cache_capacity)),
                ticker_stop,
                ticker: Mutex::new(Some(ticker)),
            }),
        }
    }

    /// The shared Wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &self.inner.engine
    }

    /// Compiles and caches a component by the package digest.
    pub fn compile(&self, digest: [u8; 32], bytes: &[u8]) -> Result<CompiledPolicy> {
        if let Some(component) = self
            .inner
            .components
            .lock()
            .expect("policy component cache poisoned")
            .get(&digest)
        {
            return Ok(CompiledPolicy { digest, component });
        }

        let component = Arc::new(
            Component::new(self.engine(), bytes)
                .map_err(|error| anyhow!("compiling policy component: {error}"))?,
        );
        let mut cache = self
            .inner
            .components
            .lock()
            .expect("policy component cache poisoned");
        let component = cache.insert(digest, component);
        Ok(CompiledPolicy { digest, component })
    }

    /// Number of compiled components currently retained.
    pub fn component_cache_len(&self) -> usize {
        self.inner
            .components
            .lock()
            .expect("policy component cache poisoned")
            .len()
    }

    /// Configured cache bound.
    pub fn component_cache_capacity(&self) -> usize {
        self.inner
            .components
            .lock()
            .expect("policy component cache poisoned")
            .capacity()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PolicyEngineInner {
    fn drop(&mut self) {
        self.ticker_stop.store(true, Ordering::Release);
        if let Some(ticker) = self
            .ticker
            .get_mut()
            .expect("policy ticker mutex poisoned")
            .take()
        {
            let _ = ticker.join();
        }
    }
}

fn configure_engine(config: &mut Config) -> Result<()> {
    config
        .target("pulley64")
        .map_err(|error| anyhow!("configuring Wasmtime target pulley64: {error}"))?;
    config.wasm_relaxed_simd(false);
    config.wasm_simd(false);
    config.wasm_memory64(false);
    config.wasm_multi_memory(false);
    config.wasm_component_model(true);
    config.cranelift_nan_canonicalization(true);
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.memory_reservation(8 << 20);
    config.memory_reservation_for_growth(0);
    config.memory_guard_size(64 << 10);
    config.memory_may_move(false);
    config.memory_init_cow(true);
    config.max_wasm_stack(512 << 10);
    config.wasm_backtrace_max_frames(None);
    config.native_unwind_info(false);
    config.generate_address_map(false);
    Ok(())
}

/// A compiled component retained by the shared engine cache.
#[derive(Clone)]
pub struct CompiledPolicy {
    digest: [u8; 32],
    component: Arc<Component>,
}

impl CompiledPolicy {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn component(&self) -> &Component {
        &self.component
    }
}

fn encoded_input_size(input: &PolicyInputV1) -> usize {
    INPUT_FIXED_OVERHEAD_BYTES
        .saturating_add(input.state.len())
        .saturating_add(
            input
                .extensions
                .iter()
                .map(|entry| entry.payload.len().saturating_add(8))
                .sum::<usize>(),
        )
}

fn encoded_output_size(output: &wit::PolicyOutput) -> usize {
    OUTPUT_FIXED_OVERHEAD_BYTES
        .saturating_add(output.next_state.len())
        .saturating_add(
            output
                .candidate
                .extensions
                .iter()
                .map(|entry| entry.payload.len().saturating_add(8))
                .sum::<usize>(),
        )
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use ironet_policy_abi::{
        POLICY_INPUT_BUDGET_BYTES, POLICY_OUTPUT_BUDGET_BYTES, PolicyHealthV1,
    };

    const TEST_NOW: &str = "2026-08-21T00:00:00Z";

    fn fixture(name: &str) -> &'static [u8] {
        match name {
            "echo" => include_bytes!("../../../../tests/fixtures/policy/malicious/echo.wasm"),
            "loop" => include_bytes!("../../../../tests/fixtures/policy/malicious/loop.wasm"),
            "fuel-burn" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/fuel-burn.wasm")
            }
            "memory-grow" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/memory-grow.wasm")
            }
            "trap" => include_bytes!("../../../../tests/fixtures/policy/malicious/trap.wasm"),
            "oversized-state" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/oversized-state.wasm")
            }
            "oversized-output" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/oversized-output.wasm")
            }
            "invalid-enum" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/invalid-enum.wasm")
            }
            "overflow-action" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/overflow-action.wasm")
            }
            "all-maximums" => {
                include_bytes!("../../../../tests/fixtures/policy/malicious/all-maximums.wasm")
            }
            "non-deterministic-attempt" => include_bytes!(
                "../../../../tests/fixtures/policy/malicious/non-deterministic-attempt.wasm"
            ),
            other => panic!("unknown policy fixture {other}"),
        }
    }

    fn fixture_backend(name: &str, self_check: bool) -> WasmPolicyBackend {
        let bytes = fixture(name);
        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let trust = TrustStoreV1::with_digest_pins([package.digest]);
        PolicyLoader::new(PolicyEngine::new())
            .load_from_bytes_inner(
                bytes,
                &config,
                &trust,
                TEST_NOW.parse().unwrap(),
                self_check,
            )
            .unwrap()
    }

    #[test]
    fn engine_uses_shared_component_cache_and_echo_is_bit_exact() {
        let engine = PolicyEngine::new();
        let bytes = fixture("echo");
        let digest = PolicyPackage::parse(bytes, PackageLimits::default())
            .unwrap()
            .digest;
        let first = engine.compile(digest, bytes).unwrap();
        let second = engine.compile(digest, bytes).unwrap();
        assert_eq!(first.digest(), second.digest());
        assert_eq!(engine.component_cache_len(), 1);

        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let trust = TrustStoreV1::with_digest_pins([package.digest]);
        let mut backend = PolicyLoader::new(engine)
            .load_from_bytes(bytes, &config, &trust, TEST_NOW.parse().unwrap())
            .unwrap();
        let input = PolicyInputV1 {
            logical_tick: 11,
            deterministic_seed: 22,
            peer_hash: [3; 32],
            state: vec![1, 2, 3, 4],
            ..PolicyInputV1::default()
        };
        let first_started = Instant::now();
        let first = backend.decide(&input).unwrap();
        let first_call_us = micros(first_started.elapsed());
        let mut steady_latencies_us = Vec::with_capacity(1_000);
        let mut steady_fuel = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            let started = Instant::now();
            assert_eq!(backend.decide(&input).unwrap(), first);
            steady_latencies_us.push(micros(started.elapsed()));
            steady_fuel.push(backend.fuel_consumed());
        }
        assert_eq!(backend.health(), PolicyHealthV1::Healthy);
        assert!(backend.last_call_micros() > 0);
        steady_latencies_us.sort_unstable();
        steady_fuel.sort_unstable();
        let percentile = |samples: &[u64], percentile: usize| {
            samples[(samples.len() * percentile / 100).min(samples.len() - 1)]
        };
        println!(
            "policy_runtime_perf first_call_us={} steady_p50_us={} steady_p99_us={} \
             fuel_p50={} fuel_p99={} cache_len={}",
            first_call_us,
            percentile(&steady_latencies_us, 50),
            percentile(&steady_latencies_us, 99),
            percentile(&steady_fuel, 50),
            percentile(&steady_fuel, 99),
            backend.store_pool().available()
        );
    }

    #[test]
    fn loader_rejects_unsigned_without_pin_and_accepts_pin() {
        let bytes = fixture("echo");
        let config = AutotuneWasmConfig::default();
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let require_signature =
            TrustStoreV1::with_signers(Vec::<super::super::signature::TrustedSigner>::new())
                .unwrap();
        assert!(
            PolicyLoader::new(PolicyEngine::new())
                .load_from_bytes(
                    bytes,
                    &config,
                    &require_signature,
                    TEST_NOW.parse().unwrap()
                )
                .is_err()
        );

        let pin = TrustStoreV1::with_digest_pins([package.digest]);
        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let backend = PolicyLoader::new(PolicyEngine::new())
            .load_from_bytes(bytes, &config, &pin, TEST_NOW.parse().unwrap())
            .unwrap();
        assert_eq!(backend.identity().backend, PolicyBackendKindV1::Wasm);
    }

    #[test]
    fn self_check_rejects_faulting_guest() {
        for name in ["loop", "fuel-burn", "memory-grow", "trap"] {
            let bytes = fixture(name);
            let config = AutotuneWasmConfig {
                require_signature: false,
                ..AutotuneWasmConfig::default()
            };
            let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
            let pin = TrustStoreV1::with_digest_pins([package.digest]);
            assert!(
                PolicyLoader::new(PolicyEngine::new())
                    .load_from_bytes(bytes, &config, &pin, TEST_NOW.parse().unwrap())
                    .is_err(),
                "faulting fixture {name} passed self-check"
            );
        }
    }

    #[test]
    fn fault_state_machine_quarantines_after_three_failures() {
        let mut backend = fixture_backend("trap", false);
        for expected_health in [PolicyHealthV1::Degraded, PolicyHealthV1::Degraded] {
            assert_eq!(
                backend.decide(&PolicyInputV1::default()),
                Err(PolicyFaultV1::Trap)
            );
            assert_eq!(backend.health(), expected_health);
        }
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Trap)
        );
        assert_eq!(backend.health(), PolicyHealthV1::Quarantined);
        assert_eq!(backend.faults_total(), 3);
        assert_eq!(backend.quarantines_total(), 1);
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Unavailable)
        );
        assert_eq!(backend.faults_total(), 3);
    }

    #[test]
    fn guest_fault_fixture_matrix_is_bounded_and_counted() {
        for (name, expected) in [
            ("fuel-burn", PolicyFaultV1::FuelExhausted),
            ("memory-grow", PolicyFaultV1::OutOfMemory),
            ("oversized-state", PolicyFaultV1::StateTooLarge),
            ("oversized-output", PolicyFaultV1::OutputTooLarge),
            ("invalid-enum", PolicyFaultV1::InvalidOutput),
            ("overflow-action", PolicyFaultV1::InvalidOutput),
            ("all-maximums", PolicyFaultV1::InvalidOutput),
        ] {
            let mut backend = fixture_backend(name, false);
            let result = backend.decide(&PolicyInputV1::default());
            assert_eq!(result, Err(expected), "fixture {name}");
            assert_eq!(backend.faults_total(), 1, "fixture {name}");
            assert_eq!(backend.health(), PolicyHealthV1::Degraded, "fixture {name}");
        }
    }

    #[test]
    fn timeout_and_input_budgets_are_separate_faults() {
        let bytes = fixture("loop");
        let config = AutotuneWasmConfig {
            require_signature: false,
            deadline_millis: 1,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let pin = TrustStoreV1::with_digest_pins([package.digest]);
        let mut backend = PolicyLoader::new(PolicyEngine::new())
            .load_from_bytes_inner(bytes, &config, &pin, TEST_NOW.parse().unwrap(), false)
            .unwrap();
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Timeout)
        );
        assert_eq!(backend.timeouts_total(), 1);

        let mut echo = fixture_backend("echo", true);
        let input = PolicyInputV1 {
            extensions: vec![PolicyExtensionV1 {
                tag: 1,
                payload: vec![0; usize::try_from(POLICY_INPUT_BUDGET_BYTES).unwrap()],
            }],
            ..PolicyInputV1::default()
        };
        assert_eq!(echo.decide(&input), Err(PolicyFaultV1::InputTooLarge));
    }

    #[test]
    fn nondeterministic_attempt_stays_bit_exact() {
        let mut backend = fixture_backend("non-deterministic-attempt", true);
        let input = PolicyInputV1::default();
        let expected = backend.decide(&input).unwrap();
        for _ in 0..100 {
            assert_eq!(backend.decide(&input).unwrap(), expected);
        }
    }

    struct SlowBackend;

    impl PolicyBackend for SlowBackend {
        fn identity(&self) -> &PolicyIdentityV1 {
            static IDENTITY: std::sync::OnceLock<PolicyIdentityV1> = std::sync::OnceLock::new();
            IDENTITY.get_or_init(|| PolicyIdentityV1::native("slow", "1"))
        }

        fn decide(&mut self, _: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
            thread::sleep(Duration::from_millis(25));
            Ok(PolicyOutputV1::default())
        }
    }

    #[test]
    fn executor_queue_full_and_deadline_return_unavailable() {
        let executor = PolicyExecutor::new(
            SlowBackend,
            PolicyExecutorConfig {
                workers: 1,
                queue_capacity: 1,
                deadline: Duration::from_millis(5),
            },
        );
        let first = executor.submit("peer-a", PolicyInputV1::default());
        let second = executor.submit("peer-b", PolicyInputV1::default());
        let third = executor.submit("peer-c", PolicyInputV1::default());
        assert_eq!(third.recv().unwrap(), Err(PolicyFaultV1::Unavailable));
        assert_eq!(first.recv().unwrap(), Err(PolicyFaultV1::Unavailable));
        assert_eq!(second.recv().unwrap(), Err(PolicyFaultV1::Unavailable));
        assert_eq!(executor.queue_depth(), 0);
    }

    #[test]
    fn status_exposes_fault_and_execution_counters() {
        let mut backend = fixture_backend("trap", false);
        assert_eq!(
            backend.decide(&PolicyInputV1::default()),
            Err(PolicyFaultV1::Trap)
        );
        let status = backend.status();
        assert_eq!(status.health, PolicyHealthV1::Degraded);
        assert_eq!(status.faults_total, 1);
        assert_eq!(status.last_fault, Some(PolicyFaultV1::Trap));
        assert_eq!(status.backend, PolicyBackendKindV1::Wasm);
    }

    #[test]
    fn output_budget_constant_is_at_least_state_budget() {
        const {
            assert!(POLICY_OUTPUT_BUDGET_BYTES >= ironet_policy_abi::POLICY_STATE_MAX_BYTES);
        }
    }

    /// The embedded builtin component loads through the verified loader with
    /// its trust anchored to the checked-in digest sidecar — independent of
    /// the operator's signature settings (plan Phase 6 promotion).
    #[test]
    fn load_builtin_embedded_component_via_digest_sidecar() {
        let backend = PolicyLoader::new(PolicyEngine::new())
            .load_builtin(&AutotuneWasmConfig::default())
            .unwrap();
        let identity = backend.identity();
        assert_eq!(identity.backend, PolicyBackendKindV1::Wasm);
        assert_eq!(identity.policy_id, "bandit-vivace@1");
        assert_eq!(identity.state_schema, ironet_policy_core::STATE_SCHEMA_V1);
        assert!(identity.digest.is_some());
        // The default config requires signatures; the builtin is trusted by
        // its pinned digest instead.
        assert!(AutotuneWasmConfig::default().require_signature);
    }
}
