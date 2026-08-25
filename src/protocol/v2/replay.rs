//! Deterministic offline replay for autotune tap records.

use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    fec::FecGeometryV2,
    learner::LearnerModeV2,
    policy::{api::CandidateActionV1, api::ClampReportV1},
    policy_tick::{PolicySlotV1, PolicyTickConfigV1, PolicyTickV1},
    tuning::{
        AutoTuneBoundsV2, AutoTunerV2, Bbr3PresetV2, CoverTrafficProfileV2, PathReliability,
        PathTelemetryV2, TuneDecisionV2, TuneReasonV2,
    },
    utility::{Objective, UtilityWeights, WireCostV2},
};

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayTapSampleV2 {
    #[serde(default = "default_tap_schema")]
    pub schema_version: u32,
    pub sampled_unix_micros: u64,
    pub telemetry: ReplayTelemetryV2,
    #[serde(default)]
    pub utility: Option<ReplayUtilityV2>,
    #[serde(default)]
    pub wire_cost: Option<ReplayWireCostV2>,
}

const fn default_tap_schema() -> u32 {
    3
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplayTelemetryV2 {
    pub path_epoch: u64,
    pub reliability: ReplayReliabilityV2,
    pub rtt_micros: u64,
    pub min_rtt_micros: u64,
    pub queue_delay_micros: u64,
    pub loss_ppm: u32,
    pub burst_loss_cells: u16,
    pub reorder_ppm: u32,
    pub receiver_goodput_bytes_per_second: u64,
    pub residual_loss_ppm: u32,
    pub latency_sojourn_p95_micros: u64,
    pub latency_sojourn_p50_micros: u64,
    pub latency_sojourn_p99_micros: u64,
    pub latency_queue_recently_nonempty: bool,
    pub delivery_rate_bytes_per_second: u64,
    pub controller_pacing_rate_bytes_per_second: u64,
    pub controller_send_quantum_bytes: u64,
    pub controller_state: u8,
    pub controller_bw_bytes_per_second: u64,
    pub controller_inflight_longterm_bytes: u64,
    pub controller_guard_transitions_delta: u64,
    pub controller_app_limited: bool,
    pub controller_tunables_generation: u64,
    pub controller_params_generation: u64,
    pub controller_clamped_writes: u64,
    pub receive_rate_bytes_per_second: u64,
    pub packets_per_second: u64,
    pub tun_ingress_bytes_per_second: u64,
    pub average_record_bytes: u64,
    pub gso_ingress_ratio_ppm: u32,
    pub packet_train_queue_bytes: u64,
    pub latency_queue_bytes: u64,
    pub reassembly_pressure_evictions: u64,
    pub remote_expired_stripes_delta: u64,
    pub train_build_bytes_per_second: u64,
    pub bulk_preemption_delay_average_micros: u64,
    pub cpu_utilization_per_mille: u16,
    pub wasted_parity_per_mille: u16,
    pub fec_recovery_per_mille: u16,
    pub repair_hit_per_mille: u16,
    pub repair_completed_requests: u64,
    pub repair_response_latency_micros: u64,
    pub real_traffic_bytes_per_second: u64,
}

impl ReplayTelemetryV2 {
    pub fn into_runtime(self) -> PathTelemetryV2 {
        PathTelemetryV2 {
            path_epoch: self.path_epoch,
            reliability: self.reliability.into(),
            rtt: Duration::from_micros(self.rtt_micros),
            min_rtt: Duration::from_micros(self.min_rtt_micros),
            queue_delay: Duration::from_micros(self.queue_delay_micros),
            loss_ppm: self.loss_ppm,
            burst_loss_cells: self.burst_loss_cells,
            reorder_ppm: self.reorder_ppm,
            receiver_goodput_bytes_per_second: self.receiver_goodput_bytes_per_second,
            residual_loss_ppm: self.residual_loss_ppm,
            latency_sojourn_p95_micros: self.latency_sojourn_p95_micros,
            latency_sojourn_p50_micros: self.latency_sojourn_p50_micros,
            latency_sojourn_p99_micros: self.latency_sojourn_p99_micros,
            latency_queue_recently_nonempty: self.latency_queue_recently_nonempty,
            delivery_rate_bytes_per_second: self.delivery_rate_bytes_per_second,
            controller_pacing_rate_bytes_per_second: self.controller_pacing_rate_bytes_per_second,
            controller_send_quantum_bytes: self.controller_send_quantum_bytes,
            controller_state: self.controller_state,
            controller_bw_bytes_per_second: self.controller_bw_bytes_per_second,
            controller_inflight_longterm_bytes: self.controller_inflight_longterm_bytes,
            controller_guard_transitions_delta: self.controller_guard_transitions_delta,
            controller_app_limited: self.controller_app_limited,
            controller_tunables_generation: self.controller_tunables_generation,
            controller_params_generation: self.controller_params_generation,
            controller_clamped_writes: self.controller_clamped_writes,
            receive_rate_bytes_per_second: self.receive_rate_bytes_per_second,
            packets_per_second: self.packets_per_second,
            tun_ingress_bytes_per_second: self.tun_ingress_bytes_per_second,
            average_record_bytes: self.average_record_bytes,
            gso_ingress_ratio_ppm: self.gso_ingress_ratio_ppm,
            packet_train_queue_bytes: self.packet_train_queue_bytes,
            latency_queue_bytes: self.latency_queue_bytes,
            reassembly_pressure_evictions: self.reassembly_pressure_evictions,
            remote_expired_stripes_delta: self.remote_expired_stripes_delta,
            train_build_bytes_per_second: self.train_build_bytes_per_second,
            bulk_preemption_delay_average_micros: self.bulk_preemption_delay_average_micros,
            cpu_utilization_per_mille: self.cpu_utilization_per_mille,
            wasted_parity_per_mille: self.wasted_parity_per_mille,
            fec_recovery_per_mille: self.fec_recovery_per_mille,
            repair_hit_per_mille: self.repair_hit_per_mille,
            repair_completed_requests: self.repair_completed_requests,
            repair_response_latency: Duration::from_micros(self.repair_response_latency_micros),
            real_traffic_bytes_per_second: self.real_traffic_bytes_per_second,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayReliabilityV2 {
    #[default]
    Datagram,
    ReliableRelay,
}

impl From<ReplayReliabilityV2> for PathReliability {
    fn from(value: ReplayReliabilityV2) -> Self {
        match value {
            ReplayReliabilityV2::Datagram => Self::Datagram,
            ReplayReliabilityV2::ReliableRelay => Self::ReliableRelay,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ReplayUtilityV2 {
    pub total: f64,
    pub components: [f64; 8],
    pub goodput_bytes_per_second: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplayWireCostV2 {
    pub payload_bytes: u64,
    pub parity_bytes: u64,
    pub repair_bytes: u64,
    pub cover_bytes: u64,
    pub cell_envelope_bytes: u64,
}

impl From<ReplayWireCostV2> for WireCostV2 {
    fn from(value: ReplayWireCostV2) -> Self {
        Self {
            payload_bytes: value.payload_bytes,
            parity_bytes: value.parity_bytes,
            repair_bytes: value.repair_bytes,
            cover_bytes: value.cover_bytes,
            cell_envelope_bytes: value.cell_envelope_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFecV2 {
    pub data_cells: usize,
    pub parity_cells: usize,
}

/// Complete `TuneDecisionV2` in the production replay report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDecisionV2 {
    pub reason: String,
    pub path_epoch: u64,
    pub sample_count: u32,
    pub train_target_bytes: usize,
    pub bulk_quantum_cells: usize,
    pub fec: Option<ReplayFecV2>,
    pub repair_cache_bytes: usize,
    pub send_buffer_bytes: usize,
    pub receive_buffer_bytes: usize,
    pub receive_batch: usize,
    pub cover_profile: String,
    pub cover_overhead_per_mille: u16,
    pub cover_padding_bytes_per_second: u64,
    pub bbr: ReplayBbrProposalV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBbrProposalV2 {
    pub preset: Bbr3PresetV2,
    pub up_gain_milli: u32,
    pub headroom_milli: u32,
    pub cwnd_gain_milli: u32,
    pub pacing_cap_bytes_per_second: u64,
    pub loss_is_congestion: bool,
}

/// Schema of the [`replay_ticks`] report.
pub const TICK_REPLAY_SCHEMA_V2: u32 = 1;

/// Report of a [`PolicyTickV1`]-driven replay (plan section 4.3): the fixture
/// runs through the exact production `PolicyBackend`/guardrail pipeline, so
/// `builtin`, `native`, JSON artifacts and `.wasm` components compare on the
/// same terms. Every field is deterministic — wall-clock call durations are
/// deliberately excluded so `--golden` comparisons are bit-exact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TickReplayReportV2 {
    pub schema_version: u32,
    pub policy_id: String,
    pub state_schema: u32,
    pub module_digest: String,
    pub backend: String,
    pub objective: String,
    pub mode: String,
    pub seed: u64,
    pub samples: usize,
    pub faults: u64,
    pub clamped_fields_total: u64,
    /// Mean host utility over all samples, as IEEE bits.
    pub mean_utility_bits: u64,
    /// BLAKE3 of the JSON-serialized per-sample trace.
    pub trace_digest: String,
    pub trace: Vec<TickReplaySampleV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TickReplaySampleV2 {
    pub index: usize,
    pub offset_micros: u64,
    pub utility_total_bits: u64,
    /// Host baseline of this tick.
    pub baseline: ReplayDecisionV2,
    /// Host-authoritative action after the guardrails.
    pub effective: ReplayDecisionV2,
    /// Raw backend candidate (`None` on fault).
    pub candidate: Option<CandidateActionV1>,
    pub clamps: ClampReportV1,
    pub fault: Option<String>,
}

/// Replay `samples` through the production tick pipeline with `slot` as the
/// live backend. Samples without a recorded wire cost use a zero cost (their
/// utility is still deterministic but not comparable to a recorded one).
pub fn replay_ticks(
    samples: &[ReplayTapSampleV2],
    slot: PolicySlotV1,
    weights: UtilityWeights,
    objective: Objective,
    mode: LearnerModeV2,
    seed: u64,
) -> Result<TickReplayReportV2> {
    ensure!(!samples.is_empty(), "autotune replay input has no samples");
    let status = slot.status();
    let mut config = PolicyTickConfigV1::new(objective, mode);
    config.seed_override = Some(seed);
    let mut tick = PolicyTickV1::new(
        AutoTunerV2::new(AutoTuneBoundsV2::default(), 1),
        slot,
        weights,
        config,
    );
    let first_micros = samples[0].sampled_unix_micros;
    let start = Instant::now();
    let mut previous_micros = first_micros;
    let mut trace = Vec::with_capacity(samples.len());
    let mut faults = 0_u64;
    let mut clamped_fields_total = 0_u64;
    let mut utility_sum = 0.0;
    for (index, sample) in samples.iter().enumerate() {
        ensure!(
            matches!(sample.schema_version, 3..=5),
            "sample {index} uses unsupported tap schema {}",
            sample.schema_version
        );
        ensure!(
            sample.sampled_unix_micros >= previous_micros,
            "sample {index} timestamp moves backwards"
        );
        previous_micros = sample.sampled_unix_micros;
        let offset_micros = sample.sampled_unix_micros - first_micros;
        let now = start + Duration::from_micros(offset_micros);
        let telemetry = sample.telemetry.into_runtime();
        ensure!(
            telemetry.path_epoch != 0,
            "sample {index} has zero path epoch"
        );
        let wire: WireCostV2 = sample.wire_cost.map(Into::into).unwrap_or_default();
        let outcome = tick.run(telemetry, &wire, now);
        faults = faults.saturating_add(u64::from(outcome.fault.is_some()));
        clamped_fields_total =
            clamped_fields_total.saturating_add(outcome.clamps.entries.len() as u64);
        utility_sum += outcome.utility.total;
        trace.push(TickReplaySampleV2 {
            index,
            offset_micros,
            utility_total_bits: outcome.utility.total.to_bits(),
            baseline: decision_golden(outcome.baseline),
            effective: decision_golden(outcome.decision),
            candidate: outcome.candidate,
            clamps: outcome.clamps,
            fault: outcome.fault.map(|fault| fault.to_string()),
        });
    }
    let trace_digest = blake3::hash(&serde_json::to_vec(&trace)?)
        .to_hex()
        .to_string();
    Ok(TickReplayReportV2 {
        schema_version: TICK_REPLAY_SCHEMA_V2,
        policy_id: status.policy_id,
        state_schema: status.state_schema,
        module_digest: status.module_digest,
        backend: status.backend,
        objective: objective_name(objective).to_owned(),
        mode: learner_mode_name(mode).to_owned(),
        seed,
        samples: samples.len(),
        faults,
        clamped_fields_total,
        mean_utility_bits: (utility_sum / samples.len() as f64).to_bits(),
        trace_digest,
        trace,
    })
}

fn learner_mode_name(mode: LearnerModeV2) -> &'static str {
    match mode {
        LearnerModeV2::Off => "off",
        LearnerModeV2::Shadow => "shadow",
        LearnerModeV2::On => "on",
    }
}

fn reason_name(reason: TuneReasonV2) -> &'static str {
    match reason {
        TuneReasonV2::ColdStart => "cold-start",
        TuneReasonV2::TelemetryUnavailable => "telemetry-unavailable",
        TuneReasonV2::PathChanged => "path-changed",
        TuneReasonV2::HealthyLowLoss => "healthy-low-loss",
        TuneReasonV2::RandomLoss => "random-loss",
        TuneReasonV2::BurstLoss => "burst-loss",
        TuneReasonV2::Congested => "congested",
        TuneReasonV2::CpuLimited => "cpu-limited",
        TuneReasonV2::ReliablePath => "reliable-path",
    }
}

fn cover_profile_name(profile: CoverTrafficProfileV2) -> &'static str {
    match profile {
        CoverTrafficProfileV2::Idle => "idle",
        CoverTrafficProfileV2::LiveBroadcast => "live-broadcast",
        CoverTrafficProfileV2::InteractiveVideo => "interactive-video",
        CoverTrafficProfileV2::GenericH3Bulk => "generic-h3-bulk",
    }
}

pub(crate) fn decision_golden(decision: TuneDecisionV2) -> ReplayDecisionV2 {
    ReplayDecisionV2 {
        reason: reason_name(decision.reason).to_owned(),
        path_epoch: decision.path_epoch,
        sample_count: decision.sample_count,
        train_target_bytes: decision.train_target_bytes,
        bulk_quantum_cells: decision.bulk_quantum_cells,
        fec: decision.fec.map(|geometry: FecGeometryV2| ReplayFecV2 {
            data_cells: geometry.data_cells,
            parity_cells: geometry.parity_cells,
        }),
        repair_cache_bytes: decision.repair_cache_bytes,
        send_buffer_bytes: decision.send_buffer_bytes,
        receive_buffer_bytes: decision.receive_buffer_bytes,
        receive_batch: decision.receive_batch,
        cover_profile: cover_profile_name(decision.cover_profile).to_owned(),
        cover_overhead_per_mille: decision.cover_overhead_per_mille,
        cover_padding_bytes_per_second: decision.cover_padding_bytes_per_second,
        bbr: ReplayBbrProposalV2 {
            preset: decision.bbr.preset,
            up_gain_milli: decision.bbr.up_gain_milli,
            headroom_milli: decision.bbr.headroom_milli,
            cwnd_gain_milli: decision.bbr.cwnd_gain_milli,
            pacing_cap_bytes_per_second: decision.bbr.pacing_cap_bytes_per_second,
            loss_is_congestion: decision.bbr.loss_is_congestion,
        },
    }
}

fn objective_name(objective: Objective) -> &'static str {
    match objective {
        Objective::Balanced => "balanced",
        Objective::Throughput => "throughput",
        Objective::Latency => "latency",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::learner::policy_utility_weights;
    use ironet_policy_core::PolicySpecV1;

    fn builtin_tick_slot(policy: &PolicySpecV1, mode: LearnerModeV2) -> PolicySlotV1 {
        crate::protocol::v2::policy_tick::core_slot_from_spec(policy, mode)
    }

    #[test]
    fn tick_replay_matches_the_checked_in_golden() {
        let input = include_str!("../../../tests/fixtures/autotune-replay-v1.json");
        let samples: Vec<ReplayTapSampleV2> = serde_json::from_str(input).unwrap();
        let policy = PolicySpecV1::builtin();
        let golden: TickReplayReportV2 = serde_json::from_str(include_str!(
            "../../../tests/fixtures/autotune-golden-v1.json"
        ))
        .unwrap();
        let report = replay_ticks(
            &samples,
            builtin_tick_slot(&policy, LearnerModeV2::Shadow),
            policy_utility_weights(&policy, Objective::Balanced),
            Objective::Balanced,
            LearnerModeV2::Shadow,
            1,
        )
        .unwrap();
        assert_eq!(report, golden);
    }

    #[test]
    fn tick_replay_is_deterministic_and_rejects_time_travel() {
        let input = include_str!("../../../tests/fixtures/autotune-replay-v1.json");
        let samples: Vec<ReplayTapSampleV2> = serde_json::from_str(input).unwrap();
        let policy = PolicySpecV1::builtin();
        let run = || {
            replay_ticks(
                &samples,
                builtin_tick_slot(&policy, LearnerModeV2::Shadow),
                policy_utility_weights(&policy, Objective::Balanced),
                Objective::Balanced,
                LearnerModeV2::Shadow,
                7,
            )
            .unwrap()
        };
        let first = run();
        let second = run();
        assert_eq!(first, second);
        assert_eq!(first.trace_digest, second.trace_digest);

        let mut reversed = samples;
        reversed[1].sampled_unix_micros = reversed[0].sampled_unix_micros - 1;
        assert!(
            replay_ticks(
                &reversed,
                builtin_tick_slot(&policy, LearnerModeV2::Shadow),
                policy_utility_weights(&policy, Objective::Balanced),
                Objective::Balanced,
                LearnerModeV2::Shadow,
                7,
            )
            .is_err()
        );
    }

    /// A `.wasm` component replays through the same tick pipeline, via the
    /// verified `PolicyLoader` path.
    #[test]
    fn tick_replay_accepts_a_wasm_backend() {
        use crate::{
            config::AutotuneWasmConfig,
            protocol::v2::policy::{
                api::PolicyBackend,
                package::{PackageLimits, PolicyPackage},
                runtime::{PolicyEngine, PolicyLoader},
                signature::TrustStoreV1,
            },
        };

        let input = include_str!("../../../tests/fixtures/autotune-replay-v1.json");
        let samples: Vec<ReplayTapSampleV2> = serde_json::from_str(input).unwrap();
        let bytes = include_bytes!("../../../tests/fixtures/policy/malicious/echo.wasm");
        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let trust = TrustStoreV1::with_digest_pins([package.digest]);
        let backend = PolicyLoader::new(PolicyEngine::new())
            .load_from_bytes(bytes, &config, &trust, chrono::Utc::now())
            .unwrap();
        let policy_id = backend.identity().policy_id.clone();
        let run = || {
            let backend = PolicyLoader::new(PolicyEngine::new())
                .load_from_bytes(bytes, &config, &trust, chrono::Utc::now())
                .unwrap();
            replay_ticks(
                &samples,
                PolicySlotV1::new(Box::new(backend), None, "echo-fixture"),
                Objective::Balanced.weights(),
                Objective::Balanced,
                LearnerModeV2::Shadow,
                1,
            )
            .unwrap()
        };
        let first = run();
        let second = run();
        assert_eq!(first, second);
        assert_eq!(first.policy_id, policy_id);
        assert_eq!(first.backend, "wasm");
        assert_eq!(first.samples, samples.len());
        assert_eq!(first.faults, 0);
        assert!(first.trace.iter().all(|sample| sample.candidate.is_some()));
    }

    /// Plan Phase 6: `native` replays as the host conservative rules — no
    /// learner, no state, effective equals the host baseline on every sample.
    #[test]
    fn tick_replay_native_rules_tracks_the_baseline() {
        let input = include_str!("../../../tests/fixtures/autotune-replay-v1.json");
        let samples: Vec<ReplayTapSampleV2> = serde_json::from_str(input).unwrap();
        let report = replay_ticks(
            &samples,
            crate::protocol::v2::policy_tick::PolicySlotV1::native_rules(),
            Objective::Balanced.weights(),
            Objective::Balanced,
            LearnerModeV2::On,
            1,
        )
        .unwrap();
        assert_eq!(report.backend, "native");
        assert_eq!(report.state_schema, 0);
        assert_eq!(report.faults, 0);
        assert_eq!(report.samples, samples.len());
        for sample in &report.trace {
            assert_eq!(sample.effective, sample.baseline, "sample {}", sample.index);
            assert_eq!(sample.candidate, Some(CandidateActionV1::default()));
            assert_eq!(sample.fault, None);
        }
    }

    /// Phase 6 promotion-gate evidence: the committed builtin component,
    /// executed through the verified wasmtime pipeline, reproduces the
    /// in-process core backend sample by sample in both learner modes — same
    /// candidates, clamps, effective actions and utilities, so the whole
    /// per-sample trace and its digest are bit-identical.
    #[test]
    fn builtin_wasm_matches_the_in_process_core_bit_exactly() {
        use crate::{
            config::AutotuneWasmConfig,
            protocol::v2::policy::{
                package::{PackageLimits, PolicyPackage},
                runtime::{PolicyEngine, PolicyLoader},
                signature::TrustStoreV1,
            },
        };

        let input = include_str!("../../../tests/fixtures/autotune-replay-v1.json");
        let samples: Vec<ReplayTapSampleV2> = serde_json::from_str(input).unwrap();
        let policy = PolicySpecV1::builtin();
        let bytes = include_bytes!("../../../crates/ironet-policy-builtin/builtin.wasm");
        let config = AutotuneWasmConfig {
            require_signature: false,
            ..AutotuneWasmConfig::default()
        };
        let package = PolicyPackage::parse(bytes, PackageLimits::from_config(&config)).unwrap();
        let trust = TrustStoreV1::with_digest_pins([package.digest]);
        let loader = PolicyLoader::new(PolicyEngine::new());
        for mode in [LearnerModeV2::On, LearnerModeV2::Shadow] {
            let expected = replay_ticks(
                &samples,
                builtin_tick_slot(&policy, mode),
                policy_utility_weights(&policy, Objective::Balanced),
                Objective::Balanced,
                mode,
                1,
            )
            .unwrap();
            let backend = loader
                .load_from_bytes(bytes, &config, &trust, chrono::Utc::now())
                .unwrap();
            let actual = replay_ticks(
                &samples,
                PolicySlotV1::new(Box::new(backend), None, "builtin.wasm"),
                policy_utility_weights(&policy, Objective::Balanced),
                Objective::Balanced,
                mode,
                1,
            )
            .unwrap();
            assert_eq!(actual.backend, "wasm");
            assert_eq!(actual.samples, expected.samples);
            assert_eq!(actual.faults, 0);
            assert_eq!(actual.clamped_fields_total, expected.clamped_fields_total);
            assert_eq!(actual.mean_utility_bits, expected.mean_utility_bits);
            assert_eq!(
                actual.trace, expected.trace,
                "builtin.wasm diverged from the in-process core in {mode:?} mode"
            );
            assert_eq!(actual.trace_digest, expected.trace_digest);
        }
    }
}
