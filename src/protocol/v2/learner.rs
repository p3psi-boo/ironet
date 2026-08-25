//! Host projections for the canonical learner in `ironet-policy-core`.
//!
//! Learning state and decisions have a single implementation in the core
//! crate. This module only converts runtime telemetry, traces and configured
//! actions at the host boundary.

use anyhow::{Result, ensure};
use ironet_policy_core::{
    ActionSpecV1, ContextKeyV1, ContextSchemaSpecV1, LearnerModeV1, LearnerTraceV1, PolicySpecV1,
};
use serde::{Deserialize, Serialize};

use super::{
    policy::api::{PolicyTelemetryV1, TelemetryHostExt},
    tuning::{Bbr3PresetV2, ForcedActionV2, PathTelemetryV2},
    utility::{Objective, UtilityWeights},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnerModeV2 {
    Off,
    Shadow,
    On,
}

impl From<LearnerModeV2> for LearnerModeV1 {
    fn from(mode: LearnerModeV2) -> Self {
        match mode {
            LearnerModeV2::Off => Self::Off,
            LearnerModeV2::Shadow => Self::Shadow,
            LearnerModeV2::On => Self::On,
        }
    }
}

impl From<LearnerModeV1> for LearnerModeV2 {
    fn from(mode: LearnerModeV1) -> Self {
        match mode {
            LearnerModeV1::Off => Self::Off,
            LearnerModeV1::Shadow => Self::Shadow,
            LearnerModeV1::On => Self::On,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContextKeyV2 {
    pub rtt_class: u8,
    pub rate_class: u8,
    pub loss_class: u8,
    pub reliable: bool,
    #[serde(default)]
    pub host_rtt: bool,
}

impl ContextKeyV2 {
    pub fn classify(t: &PathTelemetryV2) -> Self {
        Self::classify_with(t, &ContextSchemaSpecV1::builtin())
    }

    pub fn classify_with(t: &PathTelemetryV2, schema: &ContextSchemaSpecV1) -> Self {
        ContextKeyV1::classify(
            &PolicyTelemetryV1::from_runtime(t),
            t.reliability.into(),
            schema,
        )
        .into()
    }
}

impl From<ContextKeyV1> for ContextKeyV2 {
    fn from(key: ContextKeyV1) -> Self {
        Self {
            rtt_class: key.rtt_class,
            rate_class: key.rate_class,
            loss_class: key.loss_class,
            reliable: key.reliable,
            host_rtt: key.host_rtt,
        }
    }
}

impl From<ContextKeyV2> for ContextKeyV1 {
    fn from(key: ContextKeyV2) -> Self {
        Self {
            rtt_class: key.rtt_class,
            rate_class: key.rate_class,
            loss_class: key.loss_class,
            reliable: key.reliable,
            host_rtt: key.host_rtt,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LearnerTraceV2 {
    pub mode: LearnerModeV2,
    pub context: ContextKeyV2,
    pub baseline_preset: Bbr3PresetV2,
    pub proposed_preset: Bbr3PresetV2,
    pub applied_preset: Bbr3PresetV2,
    pub predicted_advantage: f64,
    pub exploring: bool,
    pub rollback: bool,
    pub rollbacks: u64,
    pub fine_up_gain_delta_milli: i16,
    pub fine_headroom_delta_milli: i16,
    pub fine_cwnd_gain_delta_milli: i16,
}

impl From<LearnerTraceV1> for LearnerTraceV2 {
    fn from(trace: LearnerTraceV1) -> Self {
        Self {
            mode: trace.mode.into(),
            context: trace.context.into(),
            baseline_preset: trace.baseline_preset.into(),
            proposed_preset: trace.proposed_preset.into(),
            applied_preset: trace.applied_preset.into(),
            predicted_advantage: trace.predicted_advantage,
            exploring: trace.exploring,
            rollback: trace.rollback,
            rollbacks: trace.rollbacks,
            fine_up_gain_delta_milli: trace.fine_up_gain_delta_milli,
            fine_headroom_delta_milli: trace.fine_headroom_delta_milli,
            fine_cwnd_gain_delta_milli: trace.fine_cwnd_gain_delta_milli,
        }
    }
}

fn action_to_runtime(action: ActionSpecV1) -> ForcedActionV2 {
    ForcedActionV2 {
        bbr_preset: None,
        fec: action
            .fec_data_cells
            .zip(action.fec_parity_cells)
            .map(|(data, parity)| {
                if data == 0 && parity == 0 {
                    None
                } else {
                    Some(super::fec::FecGeometryV2 {
                        data_cells: usize::from(data),
                        parity_cells: usize::from(parity),
                    })
                }
            }),
        train_target_bytes: action.train_target_bytes.map(|value| value as usize),
        bulk_quantum_cells: action.bulk_quantum_cells.map(usize::from),
        cover_profile: None,
        cover_overhead_per_mille: action.cover_overhead_per_mille,
    }
}

pub fn forced_action_for_preset(
    policy: &PolicySpecV1,
    preset: Bbr3PresetV2,
) -> Option<ForcedActionV2> {
    policy.action(preset.into()).map(action_to_runtime)
}

pub fn policy_utility_weights(policy: &PolicySpecV1, objective: Objective) -> UtilityWeights {
    let key = match objective {
        Objective::Balanced => "balanced",
        Objective::Throughput => "throughput",
        Objective::Latency => "latency",
    };
    let weights = policy
        .weights
        .get(key)
        .expect("validated canonical policy defines every utility objective");
    UtilityWeights {
        throughput: weights.throughput,
        queue_delay: weights.queue_delay,
        latency_sojourn: weights.latency_sojourn,
        residual_loss: weights.residual_loss,
        jitter: weights.jitter,
        cpu: weights.cpu,
        wire_overhead: weights.wire_overhead,
        memory: weights.memory,
    }
}

pub fn ensure_policy_objective(policy: &PolicySpecV1, objective: Objective) -> Result<()> {
    ensure!(
        policy
            .objective
            .is_none_or(|trained| Objective::from(trained) == objective),
        "autotune policy objective {:?} does not match runtime objective {:?}",
        policy.objective,
        objective
    );
    Ok(())
}

pub fn preset_is_eligible(context: ContextKeyV2, preset: Bbr3PresetV2) -> bool {
    ironet_policy_core::preset_is_eligible(context.into(), preset.into())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn telemetry() -> PathTelemetryV2 {
        super::super::tuning::tests_fixture::sample(1)
    }

    #[test]
    fn builtin_spec_is_the_adapter_source_of_truth() {
        let spec = PolicySpecV1::builtin();
        spec.validate().unwrap();
        assert_eq!(spec.contexts, ContextSchemaSpecV1::builtin());
    }

    #[test]
    fn context_separates_asymmetric_rate_loss_and_rtt_classes() {
        let mut telemetry = telemetry();
        telemetry.min_rtt = Duration::from_millis(150);
        telemetry.delivery_rate_bytes_per_second = 80_000_000;
        telemetry.burst_loss_cells = 3;
        let key = ContextKeyV2::classify(&telemetry);
        assert_eq!((key.rtt_class, key.rate_class, key.loss_class), (3, 3, 2));
    }

    #[test]
    fn severe_loss_takes_precedence_over_low_rtt() {
        let context = ContextKeyV2 {
            rtt_class: 0,
            rate_class: 2,
            loss_class: 3,
            reliable: false,
            host_rtt: true,
        };
        assert!(preset_is_eligible(context, Bbr3PresetV2::Policer));
        assert!(preset_is_eligible(context, Bbr3PresetV2::LossyRadio));
        assert!(!preset_is_eligible(context, Bbr3PresetV2::LowRttHost));
    }

    #[test]
    fn low_rtt_host_requires_a_sub_two_millisecond_path() {
        let mut telemetry = telemetry();
        telemetry.min_rtt = Duration::from_millis(4);
        assert!(!ContextKeyV2::classify(&telemetry).host_rtt);
        telemetry.min_rtt = Duration::from_micros(800);
        assert!(ContextKeyV2::classify(&telemetry).host_rtt);
    }
}
