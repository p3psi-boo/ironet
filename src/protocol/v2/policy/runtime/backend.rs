//! Wasmtime-backed policy execution and health accounting.

use super::*;

/// Startup validation must prove the component can execute, but it must not
/// inherit the production tick deadline: cold Wasmtime component calls can
/// exceed a short policy budget on a contended CI host. The normal `decide`
/// path restores and enforces the configured deadline immediately afterward.
const SELF_CHECK_DEADLINE_TICKS: u64 = 1_000;

/// Wasmtime-backed implementation of [`PolicyBackend`].
pub struct WasmPolicyBackend {
    identity: PolicyIdentityV1,
    manifest: PolicyManifestV1,
    pool: StorePool,
    maximum_state_bytes: usize,
    fuel_budget: u64,
    epoch_deadline_ticks: u64,
    health: PolicyHealthState,
}

#[derive(Debug, Clone, Copy, Default)]
struct PolicyHealthState {
    health: ironet_policy_abi::PolicyHealthV1,
    consecutive_faults: u32,
    faults_total: u64,
    timeouts_total: u64,
    quarantines_total: u64,
    last_call_micros: u64,
    fuel_consumed: u64,
    last_fault: Option<PolicyFaultV1>,
}

impl WasmPolicyBackend {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_verified(
        engine: PolicyEngine,
        component: CompiledPolicy,
        manifest: PolicyManifestV1,
        digest: [u8; 32],
        signer_id: Option<String>,
        config: &AutotuneWasmConfig,
        store_pool_capacity: usize,
    ) -> Result<Self> {
        let pool = StorePool::new(
            engine,
            component,
            config.maximum_memory_bytes,
            store_pool_capacity,
        )?;
        let maximum_state_bytes = usize::try_from(
            config
                .maximum_state_bytes
                .min(u64::from(manifest.maximum_state_bytes))
                .min(u64::from(ironet_policy_abi::POLICY_STATE_MAX_BYTES)),
        )
        .context("maximum policy state does not fit usize")?;
        let fuel_budget = manifest.requested_fuel.clamp(1, MAXIMUM_FUEL_BUDGET);
        let epoch_deadline_ticks = config.deadline_millis.max(1);
        let identity = PolicyIdentityV1 {
            backend: PolicyBackendKindV1::Wasm,
            policy_id: manifest.policy_id.clone(),
            policy_version: manifest.policy_version.to_string(),
            digest: Some(digest),
            signer_id,
            abi_world: manifest.abi_world.clone(),
            state_schema: manifest.state_schema,
            module_generation: 0,
        };
        Ok(Self {
            identity,
            manifest,
            pool,
            maximum_state_bytes,
            fuel_budget,
            epoch_deadline_ticks,
            health: PolicyHealthState {
                health: ironet_policy_abi::PolicyHealthV1::Healthy,
                ..PolicyHealthState::default()
            },
        })
    }

    pub(super) fn self_check(&mut self) -> Result<()> {
        let configured_deadline = self.epoch_deadline_ticks;
        self.epoch_deadline_ticks = configured_deadline.max(SELF_CHECK_DEADLINE_TICKS);
        let result = (|| {
            let empty = PolicyInputV1::default();
            self.decide(&empty)
                .map_err(|fault| anyhow!("empty policy self-check failed: {fault}"))?;
            // The state blob must be a *valid* encoding (empty = cold start):
            // guests that keep typed state — the builtin among them — report
            // corrupt state as a fault by design (plan section 12.2), so feeding
            // garbage here would reject every stateful policy at load time.
            // Corrupt-state handling is exercised by the fault-path tests instead.
            let fixture = PolicyInputV1 {
                logical_tick: 1,
                deterministic_seed: 0x0123_4567_89ab_cdef,
                peer_hash: [0xa5; 32],
                path_epoch: 7,
                ..PolicyInputV1::default()
            };
            self.decide(&fixture)
                .map_err(|fault| anyhow!("fixed policy self-check failed: {fault}"))?;
            Ok(())
        })();
        self.epoch_deadline_ticks = configured_deadline;
        result
    }

    pub fn manifest(&self) -> &PolicyManifestV1 {
        &self.manifest
    }

    pub fn health(&self) -> ironet_policy_abi::PolicyHealthV1 {
        self.health.health
    }

    pub fn consecutive_faults(&self) -> u32 {
        self.health.consecutive_faults
    }

    pub fn faults_total(&self) -> u64 {
        self.health.faults_total
    }

    pub fn timeouts_total(&self) -> u64 {
        self.health.timeouts_total
    }

    pub fn quarantines_total(&self) -> u64 {
        self.health.quarantines_total
    }

    pub fn last_call_micros(&self) -> u64 {
        self.health.last_call_micros
    }

    pub fn fuel_consumed(&self) -> u64 {
        self.health.fuel_consumed
    }

    pub fn last_fault(&self) -> Option<PolicyFaultV1> {
        self.health.last_fault
    }

    pub fn status(&self) -> PolicyRuntimeStatusV1 {
        PolicyRuntimeStatusV1::from_backend(
            &self.identity,
            self.health.health,
            self.health.faults_total,
            self.health.timeouts_total,
            self.health.quarantines_total,
            self.health.last_call_micros,
            self.health.fuel_consumed,
            self.health.last_fault,
        )
    }

    pub fn fuel_budget(&self) -> u64 {
        self.fuel_budget
    }

    pub fn epoch_deadline_ticks(&self) -> u64 {
        self.epoch_deadline_ticks
    }

    pub fn store_pool(&self) -> &StorePool {
        &self.pool
    }

    fn record_success(&mut self, elapsed: Duration, fuel_consumed: u64) {
        self.health.health = ironet_policy_abi::PolicyHealthV1::Healthy;
        self.health.consecutive_faults = 0;
        self.health.last_fault = None;
        self.health.last_call_micros = micros(elapsed);
        self.health.fuel_consumed = fuel_consumed;
    }

    fn record_failure(&mut self, fault: PolicyFaultV1, elapsed: Duration, fuel_consumed: u64) {
        self.health.faults_total = self.health.faults_total.saturating_add(1);
        if fault == PolicyFaultV1::Timeout {
            self.health.timeouts_total = self.health.timeouts_total.saturating_add(1);
        }
        self.health.consecutive_faults = self.health.consecutive_faults.saturating_add(1);
        self.health.last_call_micros = micros(elapsed);
        self.health.fuel_consumed = fuel_consumed;
        self.health.last_fault = Some(fault);
        if self.health.consecutive_faults >= 3 {
            if self.health.health != ironet_policy_abi::PolicyHealthV1::Quarantined {
                self.health.quarantines_total = self.health.quarantines_total.saturating_add(1);
            }
            self.health.health = ironet_policy_abi::PolicyHealthV1::Quarantined;
        } else {
            self.health.health = ironet_policy_abi::PolicyHealthV1::Degraded;
        }
    }
}

impl PolicyBackend for WasmPolicyBackend {
    fn identity(&self) -> &PolicyIdentityV1 {
        &self.identity
    }

    fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        if self.health.health == ironet_policy_abi::PolicyHealthV1::Quarantined {
            return Err(PolicyFaultV1::Unavailable);
        }
        let started = Instant::now();
        if input.state.len() > self.maximum_state_bytes {
            let fault = PolicyFaultV1::StateTooLarge;
            self.record_failure(fault, started.elapsed(), 0);
            return Err(fault);
        }
        if encoded_input_size(input)
            > usize::try_from(ironet_policy_abi::POLICY_INPUT_BUDGET_BYTES).unwrap_or(usize::MAX)
        {
            let fault = PolicyFaultV1::InputTooLarge;
            self.record_failure(fault, started.elapsed(), 0);
            return Err(fault);
        }

        let wit_input = wit_input(input);
        let mut slot = match self.pool.take() {
            Ok(slot) => slot,
            Err(_) => {
                let fault = PolicyFaultV1::Internal;
                self.record_failure(fault, started.elapsed(), 0);
                return Err(fault);
            }
        };
        let mut reusable = true;
        let set_fuel = slot.store.set_fuel(self.fuel_budget);
        if set_fuel.is_err() {
            let fault = PolicyFaultV1::Internal;
            self.record_failure(fault, started.elapsed(), 0);
            return Err(fault);
        }
        slot.store.set_epoch_deadline(self.epoch_deadline_ticks);
        let result = slot.policy.call_decide(&mut slot.store, &wit_input);
        let fuel_consumed = fuel_consumed(&slot.store, self.fuel_budget);
        let mapped = match result {
            Ok(Ok(output)) => {
                if output.next_state.len() > self.maximum_state_bytes {
                    Some(Err(PolicyFaultV1::StateTooLarge))
                } else if encoded_output_size(&output)
                    > usize::try_from(ironet_policy_abi::POLICY_OUTPUT_BUDGET_BYTES)
                        .unwrap_or(usize::MAX)
                {
                    Some(Err(PolicyFaultV1::OutputTooLarge))
                } else {
                    match output_from_wit(output, input) {
                        Ok(output) => {
                            if let Err(entries) = output.candidate.validate(&input.limits) {
                                let _ = entries;
                                Some(Err(PolicyFaultV1::InvalidOutput))
                            } else if output.diagnostics.state_schema != 0
                                && output.diagnostics.state_schema != self.manifest.state_schema
                            {
                                Some(Err(PolicyFaultV1::InvalidOutput))
                            } else {
                                Some(Ok(output))
                            }
                        }
                        Err(_) => Some(Err(PolicyFaultV1::InvalidOutput)),
                    }
                }
            }
            Ok(Err(fault)) => Some(Err(policy_fault_from_wit(fault))),
            Err(error) => {
                reusable = false;
                Some(Err(map_wasmtime_error(&error)))
            }
        };

        if reusable {
            self.pool.put(slot);
        }
        match mapped.expect("policy call always produces a result") {
            Ok(output) => {
                self.record_success(started.elapsed(), fuel_consumed);
                Ok(output)
            }
            Err(fault) => {
                self.record_failure(fault, started.elapsed(), fuel_consumed);
                Err(fault)
            }
        }
    }

    fn fuel_consumed(&self) -> u64 {
        self.health.fuel_consumed
    }
}

pub(super) fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn fuel_consumed(store: &Store<HostState>, budget: u64) -> u64 {
    store
        .get_fuel()
        .map(|remaining| budget.saturating_sub(remaining))
        .unwrap_or(budget)
}

fn map_wasmtime_error(error: &wasmtime::Error) -> PolicyFaultV1 {
    if let Some(trap) = error.downcast_ref::<wasmtime::Trap>() {
        return match trap {
            wasmtime::Trap::OutOfFuel => PolicyFaultV1::FuelExhausted,
            wasmtime::Trap::Interrupt => PolicyFaultV1::Timeout,
            wasmtime::Trap::MemoryOutOfBounds => PolicyFaultV1::OutOfMemory,
            _ => PolicyFaultV1::Trap,
        };
    }
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("fuel") {
        PolicyFaultV1::FuelExhausted
    } else if text.contains("epoch") || text.contains("interrupt") || text.contains("deadline") {
        PolicyFaultV1::Timeout
    } else if text.contains("memory")
        || text.contains("resource limit")
        || text.contains("resource limiter")
        || text.contains("grow")
    {
        PolicyFaultV1::OutOfMemory
    } else {
        PolicyFaultV1::Trap
    }
}
