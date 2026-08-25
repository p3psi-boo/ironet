//! Per-peer, per-tick policy pipeline over the unified [`PolicyBackend`]
//! (plan sections 0.2, 6.3, 7.4 and 8.1, Phase 1).
//!
//! ```text
//! raw telemetry
//!   -> AutoTunerV2::observe_at        filter -> native candidate -> guardrails
//!                                     -> transition -> final guardrail
//!                                     = host baseline (TuneDecisionV2)
//!   -> UtilityEstimator::observe      host reward of the interval just ended
//!   -> PolicyInputV1                  baseline as `previous`, utility as
//!                                     `previous_utility` (+ f64 TLV), limits,
//!                                     capabilities, egress view, state blob
//!   -> PolicySlotV1::decide           Box<dyn PolicyBackend>, health machine,
//!                                     state carried in/out
//!   -> GuardrailsV1::apply            candidate over the baseline effective
//!                                     action, node egress cap included
//!   -> EffectiveActionV1              the only thing that may reach the
//!                                     data plane (`to_tune_decision`)
//!   -> ShadowEvaluatorV2              same input, shadow=true, own state and
//!                                     utility; never written to the wire
//! ```
//!
//! Nothing here depends on tokio, a QUIC connection or the runtime metrics:
//! [`PolicyTickV1::run`] takes one telemetry sample, the wire cost of the
//! interval and a monotonic instant and returns a [`TickOutcomeV1`]. The
//! runtime loop publishes the decision, the status fields and the tap record
//! from that outcome.
//!
//! `previous` deliberately carries the host baseline of **this** tick rather
//! than the effective action of the previous tick: that is what the core
//! learner (and every golden trace) treats as the conservative host
//! proposal it explores against. Phase 1 keeps that contract bit-exact.

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ironet_policy_core::{
    CorePolicy, EXTENSION_TAG_HOST_UTILITY_F64_V1, LearnerTraceV1, PolicySpecV1,
    host_utility_extension, preset_name,
};

use super::{
    learner::{ContextKeyV2, LearnerModeV2, LearnerTraceV2, policy_utility_weights},
    policy::{
        api::{
            Bbr3PresetV1, CandidateActionV1, ClampEntryV1, ClampFieldV1, ClampReasonV1,
            ClampReportV1, EffectiveActionV1, EffectiveHostExt, EgressAllocationViewV1,
            HostCapabilitiesV1, HostLimitsV1, HostUtilityV1, POLICY_ABI_MAJOR_V1,
            POLICY_ABI_MINOR_V1, POLICY_STATE_MAX_BYTES, PolicyBackend, PolicyBackendKindV1,
            PolicyDecisionKindV1, PolicyDiagnosticsV1, PolicyFaultV1, PolicyHealthV1,
            PolicyIdentityV1, PolicyInputV1, PolicyLabelV1, PolicyOutputV1, PolicyTelemetryV1,
            TelemetryHostExt, UtilityHostExt,
        },
        canonical_spec_digest,
        egress::EGRESS_ASSIGNMENT_FLOOR_BYTES_PER_SECOND,
        state::NATIVE_MODULE_DIGEST,
    },
    tuning::{AutoTunerV2, Bbr3PresetV2, ForcedActionV2, PathTelemetryV2, TuneDecisionV2},
    utility::{Objective, UtilityEstimator, UtilitySample, UtilityWeights, WireCostV2},
};

/// Consecutive faults that move a `Degraded` backend to `Quarantined`
/// (plan section 7.4).
pub const QUARANTINE_CONSECUTIVE_FAULTS: u32 = 3;
/// Bound on the remembered clamp reasons per slot.
pub const LAST_CLAMP_REASONS_LIMIT: usize = 8;

// ---------------------------------------------------------------------------
// Seeds and hashes
// ---------------------------------------------------------------------------

/// Which slot a backend serves; part of the seed derivation so a live and a
/// shadow instance of the same policy do not replay identical exploration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySlotKindV1 {
    Live,
    Shadow,
}

impl PolicySlotKindV1 {
    fn seed_context(self) -> &'static str {
        match self {
            Self::Live => "ironet autotune policy seed v1 live",
            Self::Shadow => "ironet autotune policy seed v1 shadow",
        }
    }
}

/// Opaque, non-invertible peer bucket hash handed to policies.
pub fn peer_hash(endpoint_id: &[u8]) -> [u8; 32] {
    *blake3::hash(endpoint_id).as_bytes()
}

/// Deterministic seed per plan section 5.2: derived from the policy id, the
/// state schema, the peer hash and the path epoch (never from the module
/// digest, so a rebuild does not reset the exploration sequence).
pub fn derive_policy_seed(
    slot: PolicySlotKindV1,
    policy_id: &str,
    state_schema: u32,
    peer_hash: &[u8; 32],
    path_epoch: u64,
) -> u64 {
    let mut hasher = blake3::Hasher::new_derive_key(slot.seed_context());
    hasher.update(policy_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(&state_schema.to_le_bytes());
    hasher.update(peer_hash);
    hasher.update(&path_epoch.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(
        digest.as_bytes()[..8]
            .try_into()
            .expect("BLAKE3 digests are 32 bytes"),
    )
}

/// Maps monotonic instants onto the core's logical ticks: the first instant
/// is tick 0, later ones are `floor(seconds since origin)`, never
/// decreasing. One tick is one second, matching the one-second tuner loop
/// and the replay/golden tooling.
#[derive(Debug, Default, Clone, Copy)]
pub struct TickClock {
    origin: Option<Instant>,
    last: u64,
}

impl TickClock {
    pub fn tick(&mut self, now: Instant) -> u64 {
        let origin = *self.origin.get_or_insert(now);
        let tick = now.saturating_duration_since(origin).as_secs();
        self.last = self.last.max(tick);
        self.last
    }

    pub fn last(&self) -> u64 {
        self.last
    }
}

// ---------------------------------------------------------------------------
// Native core backend wrapper
// ---------------------------------------------------------------------------

/// Side channel through which the native core backend surfaces its
/// full-precision learner trace (status, tap, golden). Generic backends have
/// no probe; their trace is reconstructed from `PolicyDiagnosticsV1`.
pub type TraceProbeV1 = Arc<Mutex<Option<LearnerTraceV1>>>;

/// Host wrapper around [`ironet_policy_core::CorePolicy`].
///
/// It only forwards `decide` and captures the full-precision learner trace
/// through the probe. The candidate materialisation the pre-ABI runtime did
/// around the learner (shadow counterfactual of the proposed arm, On-mode
/// application-action merge) lives in `CorePolicy::decide_traced` itself, so
/// the in-process backend and the `builtin.wasm` guest are bit-identical.
pub struct CorePolicyBackendV1 {
    core: CorePolicy,
    probe: TraceProbeV1,
}

impl CorePolicyBackendV1 {
    pub fn new(spec: PolicySpecV1, mode: LearnerModeV2) -> (Self, TraceProbeV1) {
        let probe: TraceProbeV1 = Arc::new(Mutex::new(None));
        (
            Self {
                core: CorePolicy::new(spec, mode.into()),
                probe: Arc::clone(&probe),
            },
            probe,
        )
    }

    /// Boxed backend plus its trace probe.
    pub fn boxed(
        spec: PolicySpecV1,
        mode: LearnerModeV2,
    ) -> (Box<dyn PolicyBackend>, TraceProbeV1) {
        let (backend, probe) = Self::new(spec, mode);
        (Box::new(backend), probe)
    }

    pub fn spec(&self) -> &PolicySpecV1 {
        self.core.spec()
    }
}

impl fmt::Debug for CorePolicyBackendV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CorePolicyBackendV1")
            .field("identity", self.core.identity())
            .field("mode", &self.core.mode())
            .finish()
    }
}

impl PolicyBackend for CorePolicyBackendV1 {
    fn identity(&self) -> &PolicyIdentityV1 {
        self.core.identity()
    }

    fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        let (output, trace) = self.core.decide_traced(input)?;
        *self
            .probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(trace);
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// Native rules backend (plan Phase 6)
// ---------------------------------------------------------------------------

/// Policy id of the host-native conservative rules backend.
pub const NATIVE_RULES_POLICY_ID_V1: &str = "native-conservative@1";

/// The explicit `native` policy selection: host-side conservative rules with
/// no learner.
///
/// It proposes nothing: the empty overlay leaves the tick's host baseline —
/// the reactive `NativePolicyV1` rules that already ran through the
/// guardrails — as the effective action. It is stateless and never faults,
/// which makes it the dependency-free baseline for an explicit `native`
/// selection and for a genuinely faulted/quarantined slot.  Rejected external
/// components instead fall back to the native-core `builtin` policy.
#[derive(Debug)]
pub struct NativeRulesBackendV1 {
    identity: PolicyIdentityV1,
}

impl Default for NativeRulesBackendV1 {
    fn default() -> Self {
        Self {
            identity: PolicyIdentityV1::native(NATIVE_RULES_POLICY_ID_V1, "1"),
        }
    }
}

impl PolicyBackend for NativeRulesBackendV1 {
    fn identity(&self) -> &PolicyIdentityV1 {
        &self.identity
    }

    fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        let baseline = preset_name(input.previous.bbr.preset);
        Ok(PolicyOutputV1 {
            candidate: CandidateActionV1::default(),
            next_state: Vec::new(),
            diagnostics: PolicyDiagnosticsV1 {
                decision_kind: PolicyDecisionKindV1::Hold,
                baseline_arm_label: PolicyLabelV1::truncated(baseline),
                applied_arm_label: PolicyLabelV1::truncated(baseline),
                ..PolicyDiagnosticsV1::default()
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Health state machine (plan section 7.4)
// ---------------------------------------------------------------------------

/// Minimal fault state machine of one backend slot:
///
/// ```text
/// Healthy    -- fault --> Degraded
/// Degraded   -- ok    --> Healthy
/// Degraded   -- 3rd consecutive fault --> Quarantined (backend no longer
///                                          called; host baseline is used)
/// Quarantined -- module replaced --> Healthy
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackendHealthV1 {
    pub state: PolicyHealthV1,
    pub consecutive_faults: u32,
    pub faults_total: u64,
    pub timeouts_total: u64,
    pub quarantines_total: u64,
    pub last_fault: Option<PolicyFaultV1>,
}

impl BackendHealthV1 {
    pub fn record_success(&mut self) {
        self.consecutive_faults = 0;
        if self.state == PolicyHealthV1::Degraded {
            self.state = PolicyHealthV1::Healthy;
        }
    }

    pub fn record_fault(&mut self, fault: PolicyFaultV1) -> PolicyHealthV1 {
        self.faults_total = self.faults_total.saturating_add(1);
        if fault == PolicyFaultV1::Timeout {
            self.timeouts_total = self.timeouts_total.saturating_add(1);
        }
        self.consecutive_faults = self.consecutive_faults.saturating_add(1);
        self.last_fault = Some(fault);
        self.state = match self.state {
            PolicyHealthV1::Quarantined => PolicyHealthV1::Quarantined,
            _ if self.consecutive_faults >= QUARANTINE_CONSECUTIVE_FAULTS => {
                self.quarantines_total = self.quarantines_total.saturating_add(1);
                PolicyHealthV1::Quarantined
            }
            _ => PolicyHealthV1::Degraded,
        };
        self.state
    }

    pub fn is_quarantined(&self) -> bool {
        self.state == PolicyHealthV1::Quarantined
    }

    /// A new module was installed: start healthy again (Phase 3 will route
    /// through `ShadowWarmup`).
    pub fn reset_for_new_module(&mut self) {
        self.state = PolicyHealthV1::Healthy;
        self.consecutive_faults = 0;
        self.last_fault = None;
    }
}

pub fn health_name(health: PolicyHealthV1) -> &'static str {
    match health {
        PolicyHealthV1::Healthy => "healthy",
        PolicyHealthV1::Degraded => "degraded",
        PolicyHealthV1::Quarantined => "quarantined",
        PolicyHealthV1::ShadowWarmup => "shadow-warmup",
    }
}

pub fn backend_kind_name(kind: PolicyBackendKindV1) -> &'static str {
    match kind {
        PolicyBackendKindV1::Native => "native",
        PolicyBackendKindV1::Wasm => "wasm",
    }
}

pub fn clamp_reason_name(reason: ClampReasonV1) -> &'static str {
    match reason {
        ClampReasonV1::BelowFloor => "below-floor",
        ClampReasonV1::AboveCap => "above-cap",
        ClampReasonV1::InvalidValue => "invalid-value",
        ClampReasonV1::Overflow => "overflow",
        ClampReasonV1::CrossFieldConstraint => "cross-field",
        ClampReasonV1::UnknownExtension => "unknown-extension",
        ClampReasonV1::ExtensionTooLarge => "extension-too-large",
        ClampReasonV1::TooManyExtensions => "too-many-extensions",
        ClampReasonV1::ReliableUnderlay => "reliable-underlay",
        ClampReasonV1::CpuPressure => "cpu-pressure",
        ClampReasonV1::QueuePressure => "queue-pressure",
        ClampReasonV1::Capability => "capability",
        ClampReasonV1::MemoryBudget => "memory-budget",
        ClampReasonV1::WireOverhead => "wire-overhead",
        ClampReasonV1::EgressArbitration => "egress-arbitration",
        ClampReasonV1::TransitionHold => "transition-hold",
        ClampReasonV1::Unsupported => "unsupported",
    }
}

// ---------------------------------------------------------------------------
// Slot: backend + state + health + counters
// ---------------------------------------------------------------------------

/// Per-slot counters reported in status (plan section 13).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlotStatsV1 {
    pub calls: u64,
    pub last_call_micros: u64,
    pub clamped_fields_total: u64,
    /// Most recent distinct clamp reasons, newest last, bounded.
    pub last_clamp_reasons: Vec<ClampReasonV1>,
}

/// Snapshot of a slot for status publication.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySlotStatusV1 {
    pub backend: String,
    pub policy_id: String,
    pub policy_version: String,
    pub abi_version: String,
    pub module_digest: String,
    pub signer_id: String,
    pub module_generation: u64,
    pub state_schema: u32,
    pub state_bytes: u64,
    pub last_call_micros: u64,
    pub fuel_consumed: u64,
    pub faults_total: u64,
    pub timeouts_total: u64,
    pub quarantines_total: u64,
    pub clamped_fields_total: u64,
    pub last_clamp_reasons: String,
    pub health: String,
}

/// One backend instance with the state, health and counters of one peer.
pub struct PolicySlotV1 {
    backend: Box<dyn PolicyBackend>,
    probe: Option<TraceProbeV1>,
    identity: PolicyIdentityV1,
    module_digest: String,
    state: Vec<u8>,
    state_dirty: bool,
    health: BackendHealthV1,
    stats: SlotStatsV1,
}

impl fmt::Debug for PolicySlotV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicySlotV1")
            .field("identity", &self.identity)
            .field("module_digest", &self.module_digest)
            .field("state_bytes", &self.state.len())
            .field("health", &self.health)
            .field("stats", &self.stats)
            .finish()
    }
}

impl PolicySlotV1 {
    pub fn new(
        backend: Box<dyn PolicyBackend>,
        probe: Option<TraceProbeV1>,
        module_digest: impl Into<String>,
    ) -> Self {
        let identity = backend.identity().clone();
        Self {
            backend,
            probe,
            identity,
            module_digest: module_digest.into(),
            state: Vec::new(),
            state_dirty: false,
            health: BackendHealthV1::default(),
            stats: SlotStatsV1::default(),
        }
    }

    /// The native core backend for `spec` in `mode`.
    pub fn core(spec: PolicySpecV1, mode: LearnerModeV2, module_digest: impl Into<String>) -> Self {
        let (backend, probe) = CorePolicyBackendV1::boxed(spec, mode);
        Self::new(backend, Some(probe), module_digest)
    }

    /// The host-native conservative rules backend (plan Phase 6): no
    /// learner, no state, never faults.
    pub fn native_rules() -> Self {
        Self::new(
            Box::new(NativeRulesBackendV1::default()),
            None,
            NATIVE_MODULE_DIGEST,
        )
    }

    pub fn identity(&self) -> &PolicyIdentityV1 {
        &self.identity
    }

    pub fn module_digest(&self) -> &str {
        &self.module_digest
    }

    pub fn state(&self) -> &[u8] {
        &self.state
    }

    /// Install a persisted/warm-started state (not dirty).
    pub fn set_state(&mut self, state: Vec<u8>) {
        self.state = state;
        self.state_dirty = false;
    }

    pub fn is_dirty(&self) -> bool {
        self.state_dirty
    }

    pub fn mark_flushed(&mut self) {
        self.state_dirty = false;
    }

    pub fn health(&self) -> BackendHealthV1 {
        self.health
    }

    pub fn stats(&self) -> &SlotStatsV1 {
        &self.stats
    }

    /// Replace the backend (hot switch). State handling follows plan section
    /// 8.2: the same `policy_id` keeps the state when the `state_schema` is
    /// unchanged, or when the incoming module declares the current schema in
    /// `state_schema_accepts` (the guest then migrates the blob itself);
    /// anything else restarts from empty. Returns whether the state was kept.
    pub fn replace(
        &mut self,
        backend: Box<dyn PolicyBackend>,
        probe: Option<TraceProbeV1>,
        module_digest: impl Into<String>,
        state_schema_accepts: &[u32],
    ) -> bool {
        let next = backend.identity().clone();
        let keep_state = next.policy_id == self.identity.policy_id
            && (next.state_schema == self.identity.state_schema
                || state_schema_accepts.contains(&self.identity.state_schema));
        if !keep_state {
            self.state.clear();
            self.state_dirty = false;
        }
        let generation = self.identity.module_generation.saturating_add(1);
        self.backend = backend;
        self.probe = probe;
        self.identity = next;
        self.identity.module_generation = generation;
        self.module_digest = module_digest.into();
        self.health.reset_for_new_module();
        keep_state
    }

    /// Run one `decide`. The slot fills `input.state`, measures the call,
    /// carries `next_state` forward and drives the health machine. A
    /// quarantined slot is not called and yields `Unavailable` without
    /// touching the counters.
    pub fn decide(&mut self, input: &mut PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
        if self.health.is_quarantined() {
            return Err(PolicyFaultV1::Unavailable);
        }
        input.state.clone_from(&self.state);
        let started = Instant::now();
        let result = self.backend.decide(input);
        self.stats.last_call_micros = micros(started.elapsed());
        self.stats.calls = self.stats.calls.saturating_add(1);
        match result {
            Ok(output) => {
                if output.next_state != self.state {
                    self.state.clone_from(&output.next_state);
                    self.state_dirty = true;
                }
                self.health.record_success();
                Ok(output)
            }
            Err(fault) => {
                self.health.record_fault(fault);
                if matches!(
                    fault,
                    PolicyFaultV1::StateTooLarge
                        | PolicyFaultV1::Internal
                        | PolicyFaultV1::InvalidOutput
                ) && !self.state.is_empty()
                {
                    // Plan section 8.2: a rejected/corrupt state restarts
                    // from empty instead of being retried forever.
                    self.state.clear();
                    self.state_dirty = true;
                }
                Err(fault)
            }
        }
    }

    /// Consume the slot and hand out the backend, probe and module digest.
    /// Warmup promotion (plan section 8.3) moves the warmed-up backend into
    /// the live slot unchanged; the warmup state itself is discarded and the
    /// live slot's section 8.2 rules decide the state to keep.
    pub fn into_backend(self) -> (Box<dyn PolicyBackend>, Option<TraceProbeV1>, String) {
        (self.backend, self.probe, self.module_digest)
    }

    /// Full-precision trace of the last call, when the backend offers one.
    pub fn last_trace(&self) -> Option<LearnerTraceV1> {
        self.probe.as_ref().and_then(|probe| {
            *probe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
    }

    pub fn record_clamps(&mut self, report: &ClampReportV1) {
        self.stats.clamped_fields_total = self
            .stats
            .clamped_fields_total
            .saturating_add(report.entries.len() as u64);
        for entry in &report.entries {
            if self.stats.last_clamp_reasons.last() == Some(&entry.reason) {
                continue;
            }
            self.stats
                .last_clamp_reasons
                .retain(|reason| *reason != entry.reason);
            self.stats.last_clamp_reasons.push(entry.reason);
            if self.stats.last_clamp_reasons.len() > LAST_CLAMP_REASONS_LIMIT {
                self.stats.last_clamp_reasons.remove(0);
            }
        }
    }

    pub fn status(&self) -> PolicySlotStatusV1 {
        PolicySlotStatusV1 {
            backend: backend_kind_name(self.identity.backend).to_owned(),
            policy_id: self.identity.policy_id.clone(),
            policy_version: self.identity.policy_version.clone(),
            abi_version: format!("{POLICY_ABI_MAJOR_V1}.{POLICY_ABI_MINOR_V1}"),
            module_digest: self.module_digest.clone(),
            signer_id: self.identity.signer_id.clone().unwrap_or_default(),
            module_generation: self.identity.module_generation,
            state_schema: self.identity.state_schema,
            state_bytes: self.state.len() as u64,
            last_call_micros: self.stats.last_call_micros,
            fuel_consumed: self.backend.fuel_consumed(),
            faults_total: self.health.faults_total,
            timeouts_total: self.health.timeouts_total,
            quarantines_total: self.health.quarantines_total,
            clamped_fields_total: self.stats.clamped_fields_total,
            last_clamp_reasons: self
                .stats
                .last_clamp_reasons
                .iter()
                .map(|reason| clamp_reason_name(*reason))
                .collect::<Vec<_>>()
                .join(","),
            health: health_name(self.health.state).to_owned(),
        }
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Input construction and trace reconstruction
// ---------------------------------------------------------------------------

/// Static per-peer inputs of the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyTickConfigV1 {
    pub objective: Objective,
    pub mode: LearnerModeV2,
    pub forced: Option<ForcedActionV2>,
    /// Node-wide egress cap (bytes/s); folded into the host limits as the
    /// BBR pacing cap and reported in the egress view.
    pub max_egress_bytes_per_second: Option<u64>,
    /// `autotune.wasm.maximum_state_bytes`.
    pub state_cap_bytes: u32,
    pub peer_hash: [u8; 32],
    /// Fixed seed instead of the derived one (replay/golden).
    pub seed_override: Option<u64>,
}

impl PolicyTickConfigV1 {
    pub fn new(objective: Objective, mode: LearnerModeV2) -> Self {
        Self {
            objective,
            mode,
            forced: None,
            max_egress_bytes_per_second: None,
            state_cap_bytes: POLICY_STATE_MAX_BYTES,
            peer_hash: [0; 32],
            seed_override: None,
        }
    }
}

/// The egress view a peer sees when no node coordinator runs: the assigned
/// rate is the static node cap (0 = unknown/uncapped).
pub fn uncoordinated_egress_view(limits: &HostLimitsV1) -> EgressAllocationViewV1 {
    let cap = limits.pacing_cap_bytes_per_second;
    EgressAllocationViewV1 {
        assigned_rate_bytes_per_second: cap,
        node_cap_bytes_per_second: cap,
        ..EgressAllocationViewV1::default()
    }
}

/// Plan section 9.1 merge: the effective pacing cap is the minimum of the
/// guarded candidate cap and the coordinator-assigned rate. Assignments
/// below the BBR3 controller floor are left untouched: the controller floors
/// any non-zero cap at 64 KiB/s, so clamping lower would make the effective
/// action describe something the data plane does not execute.
fn clamp_pacing_to_assigned(
    view: &EgressAllocationViewV1,
    effective: &mut EffectiveActionV1,
    clamps: &mut ClampReportV1,
) {
    let assigned = view.assigned_rate_bytes_per_second;
    if assigned == 0 || assigned < EGRESS_ASSIGNMENT_FLOOR_BYTES_PER_SECOND {
        return;
    }
    let requested = effective.bbr.pacing_cap_bytes_per_second;
    if requested == 0 || requested > assigned {
        clamps.entries.push(ClampEntryV1::new(
            ClampFieldV1::BbrPacingCapBytesPerSecond,
            i64::try_from(requested).unwrap_or(i64::MAX),
            i64::try_from(assigned).unwrap_or(i64::MAX),
            ClampReasonV1::EgressArbitration,
        ));
        effective.bbr.pacing_cap_bytes_per_second = assigned;
    }
}

/// Build the per-tick policy input. `state` is filled by the slot.
/// `egress` is the node coordinator view for the coming tick (plan section
/// 9); callers without a coordinator pass
/// [`crate::protocol::v2::policy_tick::uncoordinated_egress_view`].
#[allow(clippy::too_many_arguments)]
pub fn build_policy_input(
    logical_tick: u64,
    deterministic_seed: u64,
    peer_hash: [u8; 32],
    telemetry: &PathTelemetryV2,
    baseline: &EffectiveActionV1,
    utility: &UtilitySample,
    objective: Objective,
    limits: &HostLimitsV1,
    shadow: bool,
    egress: &EgressAllocationViewV1,
) -> PolicyInputV1 {
    PolicyInputV1 {
        logical_tick,
        deterministic_seed,
        peer_hash,
        path_epoch: telemetry.path_epoch,
        reliability: telemetry.reliability.into(),
        telemetry: PolicyTelemetryV1::from_runtime(telemetry),
        previous: baseline.clone(),
        previous_utility: HostUtilityV1::from_sample(objective, utility),
        limits: limits.clone(),
        capabilities: HostCapabilitiesV1 {
            shadow,
            egress_coordinator: egress.node_cap_bytes_per_second != 0,
            extension_tags: vec![EXTENSION_TAG_HOST_UTILITY_F64_V1],
            ..HostCapabilitiesV1::default()
        },
        egress: egress.clone(),
        extensions: vec![host_utility_extension(utility.total)],
        state: Vec::new(),
    }
}

fn preset_from_label(label: &PolicyLabelV1) -> Option<Bbr3PresetV2> {
    let text = label.text();
    Bbr3PresetV1::ALL
        .into_iter()
        .find(|preset| preset_name(*preset) == text)
        .map(Into::into)
}

/// Trace of a tick whose backend produced no usable output (fault,
/// quarantine): the host baseline is applied, nothing was proposed.
pub fn baseline_trace(
    mode: LearnerModeV2,
    telemetry: &PathTelemetryV2,
    baseline_preset: Bbr3PresetV2,
) -> LearnerTraceV2 {
    LearnerTraceV2 {
        mode,
        context: ContextKeyV2::classify(telemetry),
        baseline_preset,
        proposed_preset: baseline_preset,
        applied_preset: baseline_preset,
        predicted_advantage: 0.0,
        exploring: false,
        rollback: false,
        rollbacks: 0,
        fine_up_gain_delta_milli: 0,
        fine_headroom_delta_milli: 0,
        fine_cwnd_gain_delta_milli: 0,
    }
}

/// Reconstruct a host trace from the bounded diagnostics of a generic
/// backend (no probe).
pub fn trace_from_diagnostics(
    mode: LearnerModeV2,
    telemetry: &PathTelemetryV2,
    baseline_preset: Bbr3PresetV2,
    effective_preset: Bbr3PresetV2,
    diagnostics: &PolicyDiagnosticsV1,
) -> LearnerTraceV2 {
    let proposed = preset_from_label(&diagnostics.applied_arm_label).unwrap_or(effective_preset);
    LearnerTraceV2 {
        mode,
        context: ContextKeyV2::classify(telemetry),
        baseline_preset,
        proposed_preset: proposed,
        applied_preset: if mode == LearnerModeV2::On {
            effective_preset
        } else {
            baseline_preset
        },
        predicted_advantage: f64::from(diagnostics.predicted_advantage_milli) / 1_000.0,
        exploring: diagnostics.exploring,
        rollback: diagnostics.rollback,
        rollbacks: u64::from(diagnostics.rollbacks),
        fine_up_gain_delta_milli: 0,
        fine_headroom_delta_milli: 0,
        fine_cwnd_gain_delta_milli: 0,
    }
}

fn slot_trace(
    slot: &PolicySlotV1,
    mode: LearnerModeV2,
    telemetry: &PathTelemetryV2,
    baseline_preset: Bbr3PresetV2,
    effective_preset: Bbr3PresetV2,
    diagnostics: &PolicyDiagnosticsV1,
) -> LearnerTraceV2 {
    slot.last_trace().map_or_else(
        || {
            trace_from_diagnostics(
                mode,
                telemetry,
                baseline_preset,
                effective_preset,
                diagnostics,
            )
        },
        Into::into,
    )
}

// ---------------------------------------------------------------------------
// Shadow evaluator
// ---------------------------------------------------------------------------

/// One shadow evaluation: the guarded counterfactual decision, the shadow's
/// own utility sample and its trace. Never published to the data plane.
#[derive(Debug, Clone, Copy)]
pub struct ShadowEvaluationV2 {
    pub decision: TuneDecisionV2,
    pub utility: UtilitySample,
    pub trace: LearnerTraceV2,
    pub fault: Option<PolicyFaultV1>,
    pub call_micros: u64,
    pub clamped_fields: u32,
}

/// Backend-agnostic shadow evaluator: a second [`PolicySlotV1`] with its own
/// state, utility estimator and advantage statistics that receives the live
/// input (with `capabilities.shadow = true`) and whose output is constrained
/// by the same guardrails but never written to the wire.
#[derive(Debug)]
pub struct ShadowEvaluatorV2 {
    slot: PolicySlotV1,
    utility: UtilityEstimator,
    objective: Objective,
    policy_id: String,
    digest: String,
    seed_override: Option<u64>,
    peer_hash: [u8; 32],
    clock: TickClock,
    advantage_sum: f64,
    samples: u64,
}

impl ShadowEvaluatorV2 {
    /// Shadow-evaluate a canonical policy spec through the native core
    /// backend. This is tooling/test support; production shadow policies use
    /// their loaded WASM backend directly.
    pub fn new(policy: PolicySpecV1, objective: Objective, seed: u64) -> Self {
        let digest = canonical_spec_digest(&policy)
            .expect("canonical policy spec passed to a shadow evaluator must validate");
        let slot = PolicySlotV1::core(policy.clone(), LearnerModeV2::Shadow, digest.clone());
        let mut evaluator = Self::from_slot(
            slot,
            policy_utility_weights(&policy, objective),
            objective,
            policy.id.clone(),
            digest,
        );
        evaluator.seed_override = Some(seed);
        evaluator
    }

    /// Shadow-evaluate an arbitrary backend slot.
    pub fn from_slot(
        slot: PolicySlotV1,
        weights: UtilityWeights,
        objective: Objective,
        policy_id: String,
        digest: String,
    ) -> Self {
        Self {
            slot,
            utility: UtilityEstimator::with_weights(weights),
            objective,
            policy_id,
            digest,
            seed_override: None,
            peer_hash: [0; 32],
            clock: TickClock::default(),
            advantage_sum: 0.0,
            samples: 0,
        }
    }

    pub fn set_peer_hash(&mut self, peer_hash: [u8; 32]) {
        self.peer_hash = peer_hash;
    }

    pub fn set_seed_override(&mut self, seed: Option<u64>) {
        self.seed_override = seed;
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn slot(&self) -> &PolicySlotV1 {
        &self.slot
    }

    pub fn slot_mut(&mut self) -> &mut PolicySlotV1 {
        &mut self.slot
    }

    /// Consume the evaluator and return the inner slot (warmup promotion,
    /// plan section 8.3).
    pub fn into_slot(self) -> PolicySlotV1 {
        self.slot
    }

    /// Mean predicted advantage over every evaluation so far.
    pub fn mean_advantage(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            self.advantage_sum / self.samples as f64
        }
    }

    /// Hot-switch to another canonical policy spec (state per plan section
    /// 8.2). The spec digest is derived from its canonical JSON bytes.
    pub fn replace_policy(&mut self, policy: PolicySpecV1, objective: Objective) {
        let digest = canonical_spec_digest(&policy)
            .expect("canonical policy spec passed to a shadow evaluator must validate");
        if digest == self.digest {
            return;
        }
        let (backend, probe) = CorePolicyBackendV1::boxed(policy.clone(), LearnerModeV2::Shadow);
        self.slot.replace(backend, Some(probe), digest.clone(), &[]);
        self.utility
            .set_weights(policy_utility_weights(&policy, objective));
        self.objective = objective;
        self.policy_id = policy.id;
        self.digest = digest;
    }

    /// Hot-switch to another backend slot.
    #[allow(clippy::too_many_arguments)]
    pub fn replace_slot(
        &mut self,
        backend: Box<dyn PolicyBackend>,
        probe: Option<TraceProbeV1>,
        module_digest: impl Into<String>,
        weights: UtilityWeights,
        policy_id: String,
        digest: String,
        state_schema_accepts: &[u32],
    ) -> bool {
        let kept = self
            .slot
            .replace(backend, probe, module_digest, state_schema_accepts);
        self.utility.set_weights(weights);
        self.policy_id = policy_id;
        self.digest = digest;
        kept
    }

    fn seed(&self, path_epoch: u64) -> u64 {
        self.seed_override.unwrap_or_else(|| {
            derive_policy_seed(
                PolicySlotKindV1::Shadow,
                &self.slot.identity.policy_id,
                self.slot.identity.state_schema,
                &self.peer_hash,
                path_epoch,
            )
        })
    }

    /// Stand-alone evaluation (tests, tooling): builds the input the live
    /// pipeline would have built from `baseline` and `telemetry`.
    pub fn observe(
        &mut self,
        now: Instant,
        tuner: &AutoTunerV2,
        telemetry: &PathTelemetryV2,
        wire: &WireCostV2,
        baseline: TuneDecisionV2,
    ) -> ShadowEvaluationV2 {
        let tick = self.clock.tick(now);
        let baseline_effective = EffectiveActionV1::from_tune_decision(&baseline);
        let placeholder = UtilitySample::default();
        let input = build_policy_input(
            tick,
            0,
            self.peer_hash,
            telemetry,
            &baseline_effective,
            &placeholder,
            self.objective,
            tuner.limits(),
            false,
            &uncoordinated_egress_view(tuner.limits()),
        );
        self.observe_input(tuner, &input, telemetry, wire, baseline)
    }

    /// Evaluate against the live input of this tick. Only `capabilities.
    /// shadow`, the seed, the reward (own estimator) and the state differ
    /// from what the live backend saw.
    pub fn observe_input(
        &mut self,
        tuner: &AutoTunerV2,
        live_input: &PolicyInputV1,
        telemetry: &PathTelemetryV2,
        wire: &WireCostV2,
        baseline: TuneDecisionV2,
    ) -> ShadowEvaluationV2 {
        let utility = self.utility.observe(telemetry, &baseline, wire);
        let mut input = live_input.clone();
        input.capabilities.shadow = true;
        input.deterministic_seed = self.seed(telemetry.path_epoch);
        input.previous_utility = HostUtilityV1::from_sample(self.objective, &utility);
        input.extensions = vec![host_utility_extension(utility.total)];
        input.state.clear();
        let baseline_effective = input.previous.clone();
        let baseline_preset = baseline.bbr.preset;
        let evaluation = match self.slot.decide(&mut input) {
            Ok(output) => {
                let (effective, clamps) =
                    tuner.constrain_candidate(*telemetry, &output.candidate, &baseline_effective);
                self.slot.record_clamps(&clamps);
                let trace = slot_trace(
                    &self.slot,
                    LearnerModeV2::Shadow,
                    telemetry,
                    baseline_preset,
                    effective.bbr.preset.into(),
                    &output.diagnostics,
                );
                ShadowEvaluationV2 {
                    decision: effective.to_tune_decision(),
                    utility,
                    trace,
                    fault: None,
                    call_micros: self.slot.stats.last_call_micros,
                    clamped_fields: u32::try_from(clamps.entries.len()).unwrap_or(u32::MAX),
                }
            }
            Err(fault) => ShadowEvaluationV2 {
                decision: baseline,
                utility,
                trace: baseline_trace(LearnerModeV2::Shadow, telemetry, baseline_preset),
                fault: Some(fault),
                call_micros: self.slot.stats.last_call_micros,
                clamped_fields: 0,
            },
        };
        if evaluation.trace.predicted_advantage.is_finite() {
            self.advantage_sum += evaluation.trace.predicted_advantage;
            self.samples = self.samples.saturating_add(1);
        }
        evaluation
    }
}

// ---------------------------------------------------------------------------
// The tick pipeline
// ---------------------------------------------------------------------------

/// Everything one tick produced.
#[derive(Debug, Clone)]
pub struct TickOutcomeV1 {
    pub logical_tick: u64,
    /// Host baseline of this tick (`AutoTunerV2`).
    pub baseline: TuneDecisionV2,
    /// Raw live candidate (`None` when the backend faulted or is
    /// quarantined).
    pub candidate: Option<CandidateActionV1>,
    /// Host-authoritative action after the guardrails.
    pub effective: EffectiveActionV1,
    /// `effective` projected onto the data-plane decision.
    pub decision: TuneDecisionV2,
    pub clamps: ClampReportV1,
    pub utility: UtilitySample,
    pub trace: LearnerTraceV2,
    pub fault: Option<PolicyFaultV1>,
    pub call_micros: u64,
    pub shadow: Option<ShadowEvaluationV2>,
}

/// The per-peer pipeline: tuner (baseline), live slot, utility estimator and
/// optional shadow evaluator. Pure with respect to I/O.
#[derive(Debug)]
pub struct PolicyTickV1 {
    tuner: AutoTunerV2,
    config: PolicyTickConfigV1,
    live: PolicySlotV1,
    utility: UtilityEstimator,
    shadow: Option<ShadowEvaluatorV2>,
    /// Node egress coordinator view for the coming tick (plan section 9);
    /// the uncoordinated placeholder until `set_egress_view` is called.
    egress_view: EgressAllocationViewV1,
    clock: TickClock,
}

impl PolicyTickV1 {
    pub fn new(
        mut tuner: AutoTunerV2,
        live: PolicySlotV1,
        weights: UtilityWeights,
        config: PolicyTickConfigV1,
    ) -> Self {
        let mut limits = tuner.limits().clone();
        limits.pacing_cap_bytes_per_second = config.max_egress_bytes_per_second.unwrap_or(0);
        limits.state_cap_bytes = config.state_cap_bytes.clamp(1, POLICY_STATE_MAX_BYTES);
        tuner.set_limits(limits.clone());
        let egress_view = uncoordinated_egress_view(&limits);
        Self {
            tuner,
            config,
            live,
            utility: UtilityEstimator::with_weights(weights),
            shadow: None,
            egress_view,
            clock: TickClock::default(),
        }
    }

    pub fn config(&self) -> &PolicyTickConfigV1 {
        &self.config
    }

    pub fn tuner(&self) -> &AutoTunerV2 {
        &self.tuner
    }

    pub fn live(&self) -> &PolicySlotV1 {
        &self.live
    }

    pub fn live_mut(&mut self) -> &mut PolicySlotV1 {
        &mut self.live
    }

    pub fn shadow(&self) -> Option<&ShadowEvaluatorV2> {
        self.shadow.as_ref()
    }

    pub fn set_shadow(&mut self, shadow: Option<ShadowEvaluatorV2>) {
        self.shadow = shadow.map(|mut shadow| {
            shadow.set_peer_hash(self.config.peer_hash);
            shadow
        });
    }

    pub fn logical_tick(&self) -> u64 {
        self.clock.last()
    }

    /// Install the node egress coordinator view for the coming ticks (plan
    /// section 9). The view feeds both the policy input and the pacing-cap
    /// arbitration clamp.
    pub fn set_egress_view(&mut self, view: EgressAllocationViewV1) {
        self.egress_view = view;
    }

    /// The egress view currently in force.
    pub fn egress_view(&self) -> &EgressAllocationViewV1 {
        &self.egress_view
    }

    /// Limits handed to the policy and enforced by the guardrails.
    pub fn limits(&self) -> &HostLimitsV1 {
        self.tuner.limits()
    }

    /// Hot-switch the live backend; utility weights follow the new policy.
    /// `state_schema_accepts` is the incoming module's migration list (plan
    /// section 8.2); native/JSON callers pass `&[]`.
    pub fn replace_live(
        &mut self,
        backend: Box<dyn PolicyBackend>,
        probe: Option<TraceProbeV1>,
        module_digest: impl Into<String>,
        weights: UtilityWeights,
        state_schema_accepts: &[u32],
    ) -> bool {
        let kept = self
            .live
            .replace(backend, probe, module_digest, state_schema_accepts);
        self.utility.set_weights(weights);
        kept
    }

    /// Telemetry is unavailable this tick: conservative host fallback, no
    /// policy call.
    pub fn fallback_for_missing_telemetry(&mut self) -> TuneDecisionV2 {
        self.tuner.fallback_for_missing_telemetry()
    }

    fn live_seed(&self, path_epoch: u64) -> u64 {
        self.config.seed_override.unwrap_or_else(|| {
            derive_policy_seed(
                PolicySlotKindV1::Live,
                &self.live.identity.policy_id,
                self.live.identity.state_schema,
                &self.config.peer_hash,
                path_epoch,
            )
        })
    }

    /// One tick: baseline, utility, live decide, guardrails, shadow.
    pub fn run(
        &mut self,
        telemetry: PathTelemetryV2,
        wire: &WireCostV2,
        now: Instant,
    ) -> TickOutcomeV1 {
        let baseline_effective =
            self.tuner
                .observe_effective_at_with_force(telemetry, now, self.config.forced);
        let baseline = baseline_effective.to_tune_decision();
        let utility = self.utility.observe(&telemetry, &baseline, wire);
        let logical_tick = self.clock.tick(now);
        let mode = self.config.mode;
        let mut input = build_policy_input(
            logical_tick,
            self.live_seed(telemetry.path_epoch),
            self.config.peer_hash,
            &telemetry,
            &baseline_effective,
            &utility,
            self.config.objective,
            self.tuner.limits(),
            // Anything but On is a shadow evaluation: the backend learns
            // from the live input but its candidate must not reach the
            // wire. This is also the only mode channel a WASM guest has.
            mode != LearnerModeV2::On,
            &self.egress_view,
        );
        let baseline_preset = baseline.bbr.preset;
        let (candidate, effective, clamps, trace, fault) = match self.live.decide(&mut input) {
            Ok(output) => {
                // Shadow/Off: the candidate is observability-only; the wire
                // keeps this tick's host baseline, still guardrail-checked
                // (the egress arbitration clamp applies to it as well).
                let (mut effective, mut clamps) = if mode == LearnerModeV2::On {
                    self.tuner.constrain_candidate(
                        telemetry,
                        &output.candidate,
                        &baseline_effective,
                    )
                } else {
                    self.tuner.reapply_effective(telemetry, &baseline_effective)
                };
                clamp_pacing_to_assigned(&self.egress_view, &mut effective, &mut clamps);
                self.live.record_clamps(&clamps);
                let trace = slot_trace(
                    &self.live,
                    mode,
                    &telemetry,
                    baseline_preset,
                    effective.bbr.preset.into(),
                    &output.diagnostics,
                );
                (Some(output.candidate), effective, clamps, trace, None)
            }
            Err(fault) => {
                // Fault tick: the host baseline of this tick (plan 7.4), still
                // through the final guardrail pass so the node egress cap
                // applies.
                let (mut effective, mut clamps) =
                    self.tuner.reapply_effective(telemetry, &baseline_effective);
                clamp_pacing_to_assigned(&self.egress_view, &mut effective, &mut clamps);
                (
                    None,
                    effective,
                    clamps,
                    baseline_trace(mode, &telemetry, baseline_preset),
                    Some(fault),
                )
            }
        };
        let decision = effective.to_tune_decision();
        let shadow = self
            .shadow
            .as_mut()
            .map(|shadow| shadow.observe_input(&self.tuner, &input, &telemetry, wire, baseline));
        TickOutcomeV1 {
            logical_tick,
            baseline,
            candidate,
            effective,
            decision,
            clamps,
            utility,
            trace,
            fault,
            call_micros: self.live.stats.last_call_micros,
            shadow,
        }
    }
}

/// Build an in-process core slot from a validated canonical spec.
///
/// Its `module_digest` identifies the canonical [`PolicySpecV1`], not a
/// WASM package.  The explicit `native` rules slot is constructed separately
/// with [`PolicySlotV1::native_rules`].
pub fn core_slot_from_spec(spec: &PolicySpecV1, mode: LearnerModeV2) -> PolicySlotV1 {
    let digest = canonical_spec_digest(spec)
        .expect("canonical policy spec passed to a core slot must validate");
    PolicySlotV1::core(spec.clone(), mode, digest)
}

/// Build the default `builtin` policy slot without creating a WASM engine.
///
/// The backend reports `backend=native` because it is the in-process
/// [`CorePolicyBackendV1`], while its id, version, state schema and digest
/// remain those of `PolicySpecV1::builtin()`.
pub fn builtin_core_slot(mode: LearnerModeV2) -> PolicySlotV1 {
    let spec = PolicySpecV1::builtin();
    let digest =
        canonical_spec_digest(&spec).expect("embedded builtin PolicySpecV1 must always validate");
    PolicySlotV1::core(spec, mode, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::{
        policy::{api::PolicyDecisionKindV1, canonical_spec_digest},
        tuning::{AutoTuneBoundsV2, tests_fixture},
    };

    fn telemetry() -> PathTelemetryV2 {
        tests_fixture::sample(1)
    }

    fn builtin_tick(mode: LearnerModeV2, seed: Option<u64>) -> PolicyTickV1 {
        let policy = PolicySpecV1::builtin();
        let slot = core_slot_from_spec(&policy, mode);
        let mut config = PolicyTickConfigV1::new(Objective::Balanced, mode);
        config.seed_override = seed;
        PolicyTickV1::new(
            AutoTunerV2::new(AutoTuneBoundsV2::default(), 1),
            slot,
            policy_utility_weights(&policy, Objective::Balanced),
            config,
        )
    }

    #[test]
    fn builtin_core_slot_is_native_and_canonically_identified() {
        let spec = PolicySpecV1::builtin();
        let digest = canonical_spec_digest(&spec).unwrap();
        let slot = builtin_core_slot(LearnerModeV2::Shadow);
        let status = slot.status();

        assert_eq!(status.backend, "native");
        assert_eq!(status.policy_id, spec.id);
        assert_eq!(status.policy_version, spec.version);
        assert_eq!(status.state_schema, ironet_policy_core::STATE_SCHEMA_V1);
        assert_eq!(status.module_digest, digest);
        assert!(status.signer_id.is_empty());
    }

    #[test]
    fn on_mode_applies_the_learned_action_through_the_guardrails_only() {
        // Drive the On-mode pipeline for long enough that the learner
        // evaluates arms; every effective action must equal what the
        // guardrails make of the candidate over the baseline, and the node
        // egress cap must bind the pacing cap.
        let policy = PolicySpecV1::builtin();
        let slot = core_slot_from_spec(&policy, LearnerModeV2::On);
        let mut config = PolicyTickConfigV1::new(Objective::Balanced, LearnerModeV2::On);
        config.seed_override = Some(3);
        config.max_egress_bytes_per_second = Some(5_000_000);
        let mut tick = PolicyTickV1::new(
            AutoTunerV2::new(AutoTuneBoundsV2::default(), 1),
            slot,
            policy_utility_weights(&policy, Objective::Balanced),
            config,
        );
        let start = Instant::now();
        for second in 0..40_u64 {
            let outcome = tick.run(
                telemetry(),
                &WireCostV2::default(),
                start + Duration::from_secs(second),
            );
            assert_eq!(outcome.fault, None);
            let candidate = outcome.candidate.clone().unwrap();
            let (expected, _) = tick.tuner().constrain_candidate(
                telemetry(),
                &candidate,
                &EffectiveActionV1::from_tune_decision(&outcome.baseline),
            );
            let mut expected = expected.to_tune_decision();
            expected.bbr.pacing_cap_bytes_per_second =
                match expected.bbr.pacing_cap_bytes_per_second {
                    0 => 5_000_000,
                    learned => learned.min(5_000_000),
                };
            assert_eq!(outcome.decision, expected, "second {second}");
            assert_eq!(outcome.decision.bbr.pacing_cap_bytes_per_second, 5_000_000);
            assert_eq!(outcome.trace.mode, LearnerModeV2::On);
        }
    }

    #[test]
    fn coordinator_assigned_rate_binds_the_pacing_cap_with_arbitration_clamp() {
        // Plan section 9.1 merge: the coordinator-assigned rate clamps the
        // effective pacing cap below the static node cap, reported as an
        // EgressArbitration clamp entry.
        let policy = PolicySpecV1::builtin();
        let slot = core_slot_from_spec(&policy, LearnerModeV2::On);
        let mut config = PolicyTickConfigV1::new(Objective::Balanced, LearnerModeV2::On);
        config.seed_override = Some(3);
        config.max_egress_bytes_per_second = Some(5_000_000);
        let mut tick = PolicyTickV1::new(
            AutoTunerV2::new(AutoTuneBoundsV2::default(), 1),
            slot,
            policy_utility_weights(&policy, Objective::Balanced),
            config,
        );
        tick.set_egress_view(EgressAllocationViewV1 {
            assigned_rate_bytes_per_second: 2_000_000,
            node_cap_bytes_per_second: 5_000_000,
            node_demand_bytes_per_second: 7_000_000,
            pressure_per_mille: 1_400,
            active_peers: 2,
            allocation_generation: 7,
        });
        let start = Instant::now();
        let outcome = tick.run(telemetry(), &WireCostV2::default(), start);
        assert_eq!(outcome.fault, None);
        assert_eq!(outcome.decision.bbr.pacing_cap_bytes_per_second, 2_000_000);
        assert!(outcome.clamps.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::BbrPacingCapBytesPerSecond
                && entry.reason == ClampReasonV1::EgressArbitration
                && entry.effective == 2_000_000
        }));
        // Idempotent while the assignment holds.
        let outcome = tick.run(
            telemetry(),
            &WireCostV2::default(),
            start + Duration::from_secs(1),
        );
        assert_eq!(outcome.decision.bbr.pacing_cap_bytes_per_second, 2_000_000);
        // Uncoordinated again (0 = no assignment): the node cap rules.
        tick.set_egress_view(EgressAllocationViewV1 {
            node_cap_bytes_per_second: 5_000_000,
            ..EgressAllocationViewV1::default()
        });
        let outcome = tick.run(
            telemetry(),
            &WireCostV2::default(),
            start + Duration::from_secs(2),
        );
        assert_eq!(outcome.decision.bbr.pacing_cap_bytes_per_second, 5_000_000);
    }

    #[test]
    fn shadow_counterfactual_is_the_proposed_arm_and_never_the_live_decision() {
        let mut policy = PolicySpecV1::builtin();
        let t = telemetry();
        let context = ContextKeyV2::classify_with(&t, &policy.contexts);
        policy.priors.insert(
            format!(
                "r{}-b{}-l{}-{}",
                context.rtt_class,
                context.rate_class,
                context.loss_class,
                if context.reliable {
                    "reliable"
                } else {
                    "datagram"
                }
            ),
            std::collections::BTreeMap::from([(
                "private-aggressive".to_owned(),
                ironet_policy_core::PosteriorSpecV1 {
                    observations: 100,
                    mean: 100.0,
                },
            )]),
        );
        let mut tick = builtin_tick(LearnerModeV2::Shadow, Some(1));
        tick.set_shadow(Some(ShadowEvaluatorV2::new(
            policy,
            Objective::Balanced,
            17,
        )));
        let start = Instant::now();
        // Tick 0 creates the context; the ten-second dwell and the eight
        // sample gate close at tick 10, where the arms are (re)sampled.
        let mut outcome = tick.run(t, &WireCostV2::default(), start);
        for second in 1..=10_u64 {
            outcome = tick.run(
                t,
                &WireCostV2::default(),
                start + Duration::from_secs(second),
            );
        }
        let shadow = outcome.shadow.unwrap();
        assert_eq!(shadow.trace.mode, LearnerModeV2::Shadow);
        assert_eq!(shadow.trace.applied_preset, outcome.baseline.bbr.preset);
        assert_eq!(
            shadow.trace.proposed_preset,
            Bbr3PresetV2::PrivateAggressive
        );
        assert_eq!(shadow.decision.bbr.preset, Bbr3PresetV2::PrivateAggressive);
        assert_eq!(shadow.decision.train_target_bytes, 64 * 1024);
        assert_eq!(shadow.decision.bulk_quantum_cells, 4);
        // The live decision stayed on the host baseline arm.
        assert_eq!(outcome.decision.bbr.preset, outcome.baseline.bbr.preset);
        assert_ne!(shadow.decision, outcome.decision);
        assert!(tick.shadow().unwrap().mean_advantage().is_finite());
    }

    struct FaultyBackend {
        identity: PolicyIdentityV1,
        faults_left: u32,
    }

    impl PolicyBackend for FaultyBackend {
        fn identity(&self) -> &PolicyIdentityV1 {
            &self.identity
        }

        fn decide(&mut self, input: &PolicyInputV1) -> Result<PolicyOutputV1, PolicyFaultV1> {
            if self.faults_left > 0 {
                self.faults_left -= 1;
                return Err(PolicyFaultV1::Trap);
            }
            Ok(PolicyOutputV1 {
                candidate: CandidateActionV1::default(),
                next_state: input.state.iter().copied().chain([1]).collect(),
                diagnostics: PolicyDiagnosticsV1 {
                    decision_kind: PolicyDecisionKindV1::Hold,
                    state_schema: 7,
                    ..PolicyDiagnosticsV1::default()
                },
            })
        }
    }

    fn faulty_tick(faults: u32) -> PolicyTickV1 {
        let mut identity = PolicyIdentityV1::native("faulty@1", "0");
        identity.state_schema = 7;
        let slot = PolicySlotV1::new(
            Box::new(FaultyBackend {
                identity,
                faults_left: faults,
            }),
            None,
            "faulty",
        );
        PolicyTickV1::new(
            AutoTunerV2::new(AutoTuneBoundsV2::default(), 1),
            slot,
            Objective::Balanced.weights(),
            PolicyTickConfigV1::new(Objective::Balanced, LearnerModeV2::On),
        )
    }

    #[test]
    fn faults_use_the_baseline_and_three_in_a_row_quarantine_the_backend() {
        let mut tick = faulty_tick(2);
        let start = Instant::now();
        let first = tick.run(telemetry(), &WireCostV2::default(), start);
        assert_eq!(first.fault, Some(PolicyFaultV1::Trap));
        assert_eq!(first.decision, first.baseline);
        assert_eq!(first.trace.proposed_preset, first.baseline.bbr.preset);
        assert_eq!(tick.live().health().state, PolicyHealthV1::Degraded);
        let second = tick.run(
            telemetry(),
            &WireCostV2::default(),
            start + Duration::from_secs(1),
        );
        assert_eq!(second.fault, Some(PolicyFaultV1::Trap));
        assert_eq!(tick.live().health().consecutive_faults, 2);
        // Recovery: a successful call returns to Healthy and the generic
        // trace is reconstructed from the diagnostics.
        let third = tick.run(
            telemetry(),
            &WireCostV2::default(),
            start + Duration::from_secs(2),
        );
        assert_eq!(third.fault, None);
        assert_eq!(third.decision, third.baseline);
        assert_eq!(tick.live().health().state, PolicyHealthV1::Healthy);
        assert_eq!(tick.live().health().faults_total, 2);
        assert_eq!(tick.live().state(), &[1]);
        assert!(tick.live().is_dirty());
        assert_eq!(third.trace.applied_preset, third.baseline.bbr.preset);
        let status = tick.live().status();
        assert_eq!(status.backend, "native");
        assert_eq!(status.policy_id, "faulty@1");
        assert_eq!(status.state_schema, 7);
        assert_eq!(status.state_bytes, 1);
        assert_eq!(status.faults_total, 2);
        assert_eq!(status.health, "healthy");
        assert_eq!(status.abi_version, "1.0");
        assert_eq!(status.module_digest, "faulty");
        assert!(status.signer_id.is_empty());
        assert_eq!(status.module_generation, 0);
        assert_eq!(
            status.fuel_consumed, 0,
            "native backends have no fuel meter"
        );
        assert_eq!(status.timeouts_total, 0, "trap faults are not timeouts");
        assert_eq!(status.quarantines_total, 0);

        let mut tick = faulty_tick(u32::MAX);
        for second in 0..5_u64 {
            let outcome = tick.run(
                telemetry(),
                &WireCostV2::default(),
                start + Duration::from_secs(second),
            );
            assert_eq!(outcome.decision, outcome.baseline);
            if second >= 3 {
                assert_eq!(outcome.fault, Some(PolicyFaultV1::Unavailable));
            } else {
                assert_eq!(outcome.fault, Some(PolicyFaultV1::Trap));
            }
        }
        let health = tick.live().health();
        assert_eq!(health.state, PolicyHealthV1::Quarantined);
        assert_eq!(health.faults_total, 3, "a quarantined slot is not called");
        assert_eq!(health.quarantines_total, 1);
        assert_eq!(tick.live().status().quarantines_total, 1);
        assert_eq!(tick.live().stats().calls, 3);
    }

    #[test]
    fn health_counts_timeouts_separately_from_other_faults() {
        let mut health = BackendHealthV1::default();
        health.record_fault(PolicyFaultV1::Timeout);
        health.record_fault(PolicyFaultV1::Trap);
        health.record_fault(PolicyFaultV1::Timeout);
        assert_eq!(health.faults_total, 3);
        assert_eq!(health.timeouts_total, 2);
        assert_eq!(health.quarantines_total, 1);
    }

    #[test]
    fn hot_switch_keeps_state_only_for_the_same_policy_id_and_schema() {
        let policy = PolicySpecV1::builtin();
        let mut tick = builtin_tick(LearnerModeV2::Shadow, Some(1));
        let start = Instant::now();
        tick.run(telemetry(), &WireCostV2::default(), start);
        let state = tick.live().state().to_vec();
        assert!(!state.is_empty());

        // Same id + schema, different digest: state continues.
        let mut same = policy.clone();
        same.priors.clear();
        let (backend, probe) = CorePolicyBackendV1::boxed(same.clone(), LearnerModeV2::Shadow);
        assert!(tick.replace_live(
            backend,
            Some(probe),
            canonical_spec_digest(&same).unwrap(),
            policy_utility_weights(&same, Objective::Balanced),
            &[]
        ));
        assert_eq!(tick.live().state(), state.as_slice());
        assert_eq!(tick.live().identity().module_generation, 1);

        // Different id: empty state.
        let mut other = policy;
        other.id = "bandit-vivace@2".to_owned();
        let (backend, probe) = CorePolicyBackendV1::boxed(other.clone(), LearnerModeV2::Shadow);
        assert!(!tick.replace_live(
            backend,
            Some(probe),
            canonical_spec_digest(&other).unwrap(),
            policy_utility_weights(&other, Objective::Balanced),
            &[]
        ));
        assert!(tick.live().state().is_empty());
        assert_eq!(tick.live().identity().policy_id, "bandit-vivace@2");
        assert_eq!(tick.live().identity().module_generation, 2);
        let outcome = tick.run(
            telemetry(),
            &WireCostV2::default(),
            start + Duration::from_secs(1),
        );
        assert_eq!(outcome.fault, None);
    }

    #[test]
    fn warmup_promotion_moves_the_backend_and_applies_live_state_rules() {
        // A candidate that survived shadow warmup is promoted by moving its
        // backend into the live slot unchanged; the warmup state is discarded
        // and the section 8.2 rules decide which live state survives.
        let policy = PolicySpecV1::builtin();
        let mut tick = builtin_tick(LearnerModeV2::Shadow, Some(1));
        let start = Instant::now();
        tick.run(telemetry(), &WireCostV2::default(), start);
        assert!(!tick.live().state().is_empty());

        let slot = core_slot_from_spec(&policy, LearnerModeV2::Shadow);
        let mut warmup = ShadowEvaluatorV2::from_slot(
            slot,
            policy_utility_weights(&policy, Objective::Balanced),
            Objective::Balanced,
            policy.id.clone(),
            canonical_spec_digest(&policy).unwrap(),
        );
        let baseline = tick
            .run(telemetry(), &WireCostV2::default(), start)
            .baseline;
        let live_state = tick.live().state().to_vec();
        let evaluation = warmup.observe(
            start,
            tick.tuner(),
            &telemetry(),
            &WireCostV2::default(),
            baseline,
        );
        assert_eq!(evaluation.fault, None);

        let (backend, probe, digest) = warmup.into_slot().into_backend();
        assert_eq!(digest, canonical_spec_digest(&policy).unwrap());
        let kept = tick.replace_live(
            backend,
            probe,
            digest,
            policy_utility_weights(&policy, Objective::Balanced),
            &[],
        );
        // Same policy_id + schema: the live state is kept, and the promoted
        // backend is the warmed-up instance (module generation advanced).
        assert!(kept);
        assert_eq!(tick.live().state(), live_state.as_slice());
        assert_eq!(
            tick.live().module_digest(),
            canonical_spec_digest(&policy).unwrap()
        );
        assert_eq!(tick.live().identity().module_generation, 1);
        let outcome = tick.run(
            telemetry(),
            &WireCostV2::default(),
            start + Duration::from_secs(1),
        );
        assert_eq!(outcome.fault, None);
    }

    #[test]
    fn hot_switch_state_schema_accepts_allows_guest_side_migration() {
        let mut tick = faulty_tick(0);
        tick.live_mut().set_state(vec![1, 2, 3]);
        let mut identity = PolicyIdentityV1::native("faulty@1", "0");
        identity.state_schema = 8;
        // New schema declares it accepts the old one: state is handed over.
        let next = FaultyBackend {
            identity: identity.clone(),
            faults_left: 0,
        };
        assert!(
            tick.live_mut()
                .replace(Box::new(next), None, "migrated", &[7])
        );
        assert_eq!(tick.live().state(), &[1, 2, 3]);
        assert_eq!(tick.live().identity().state_schema, 8);

        // Another schema bump that does not accept the current one: the
        // state restarts empty.
        identity.state_schema = 9;
        let next = FaultyBackend {
            identity,
            faults_left: 0,
        };
        assert!(!tick.live_mut().replace(Box::new(next), None, "reset", &[]));
        assert!(tick.live().state().is_empty());
    }

    #[test]
    fn seeds_are_stable_and_distinguish_slot_policy_schema_peer_and_epoch() {
        let peer = peer_hash(b"peer-a");
        let base = derive_policy_seed(PolicySlotKindV1::Live, "p@1", 1, &peer, 1);
        assert_eq!(
            base,
            derive_policy_seed(PolicySlotKindV1::Live, "p@1", 1, &peer, 1)
        );
        assert_ne!(
            base,
            derive_policy_seed(PolicySlotKindV1::Shadow, "p@1", 1, &peer, 1)
        );
        assert_ne!(
            base,
            derive_policy_seed(PolicySlotKindV1::Live, "p@2", 1, &peer, 1)
        );
        assert_ne!(
            base,
            derive_policy_seed(PolicySlotKindV1::Live, "p@1", 2, &peer, 1)
        );
        assert_ne!(
            base,
            derive_policy_seed(PolicySlotKindV1::Live, "p@1", 1, &peer_hash(b"peer-b"), 1)
        );
        assert_ne!(
            base,
            derive_policy_seed(PolicySlotKindV1::Live, "p@1", 1, &peer, 2)
        );
        let mut clock = TickClock::default();
        let origin = Instant::now();
        assert_eq!(clock.tick(origin + Duration::from_secs(5)), 0);
        assert_eq!(clock.tick(origin + Duration::from_millis(6_999)), 1);
        assert_eq!(clock.tick(origin + Duration::from_secs(15)), 10);
        assert_eq!(clock.tick(origin), 10, "ticks never decrease");
    }

    #[test]
    fn clamp_reasons_are_bounded_and_deduplicated() {
        let mut tick = faulty_tick(0);
        let mut report = ClampReportV1::default();
        for reason in ClampReasonV1::ALL {
            report
                .entries
                .push(crate::protocol::v2::policy::api::ClampEntryV1::new(
                    crate::protocol::v2::policy::api::ClampFieldV1::BbrPreset,
                    0,
                    0,
                    reason,
                ));
        }
        let first = report.entries[0];
        report.entries.push(first);
        tick.live_mut().record_clamps(&report);
        let stats = tick.live().stats();
        assert_eq!(
            stats.clamped_fields_total,
            ClampReasonV1::ALL.len() as u64 + 1
        );
        assert_eq!(stats.last_clamp_reasons.len(), LAST_CLAMP_REASONS_LIMIT);
        assert_eq!(
            stats.last_clamp_reasons.last(),
            Some(&ClampReasonV1::BelowFloor)
        );
        assert!(
            tick.live()
                .status()
                .last_clamp_reasons
                .contains("below-floor")
        );
    }

    /// Plan Phase 6: the native rules backend proposes nothing — the
    /// effective action is exactly the guardrail-checked host baseline on
    /// every tick, the slot stays stateless and never faults.
    #[test]
    fn native_rules_backend_tracks_the_host_baseline_without_state() {
        let mut tick = PolicyTickV1::new(
            AutoTunerV2::new(AutoTuneBoundsV2::default(), 1),
            PolicySlotV1::native_rules(),
            Objective::Balanced.weights(),
            PolicyTickConfigV1::new(Objective::Balanced, LearnerModeV2::On),
        );
        let start = Instant::now();
        for index in 0..4_u32 {
            let outcome = tick.run(
                tests_fixture::sample(u64::from(index) + 1),
                &WireCostV2::default(),
                start + Duration::from_secs(u64::from(index)),
            );
            assert_eq!(outcome.candidate, Some(CandidateActionV1::default()));
            assert_eq!(outcome.fault, None);
            assert_eq!(outcome.decision, outcome.baseline);
        }
        assert!(tick.live().state().is_empty());
        assert!(!tick.live().is_dirty());
        let status = tick.live().status();
        assert_eq!(status.backend, "native");
        assert_eq!(status.policy_id, NATIVE_RULES_POLICY_ID_V1);
        assert_eq!(status.state_schema, 0);
    }
}
