//! Canonical pure-data policy specification.
//!
//! `PolicySpecV1` is the only serialized policy contract shared by offline
//! training, native replay and the builtin WASM guest.  Package signatures,
//! deployment provenance and module digests belong to the package/runtime
//! layers rather than a second host-side policy envelope.

use std::collections::BTreeMap;

use ironet_policy_abi::{
    Bbr3PresetV1, FEC_DATA_CELLS_MAX, FEC_PARITY_CELLS_MAX, FEC_PARITY_PER_MILLE_CAP, ObjectiveV1,
};
use serde::{Deserialize, Serialize};

/// Algorithm identifier every V1 spec must carry.
pub const POLICY_ALGORITHM_BANDIT_VIVACE: &str = "bandit-vivace";
/// Stable policy identifier of the embedded builtin bandit policy.
pub const BANDIT_POLICY_ID_V1: &str = "bandit-vivace@1";

/// Context bucketing thresholds. Each list is strictly increasing; a value
/// falls into the index of the first threshold it is below (or `len()`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSchemaSpecV1 {
    pub rtt_millis: Vec<u32>,
    pub rate_mbps: Vec<u32>,
    pub loss_ppm: Vec<u32>,
}

impl ContextSchemaSpecV1 {
    /// Thresholds of the built-in policy (also the legacy defaults of the
    /// host's `ContextKeyV2::classify`).
    pub fn builtin() -> Self {
        Self {
            rtt_millis: vec![10, 40, 120],
            rate_mbps: vec![10, 100, 500],
            loss_ppm: vec![1_000, 10_000, 30_000],
        }
    }
}

/// The five learner-controlled BBRv3 knobs plus the preset they belong to
/// (mirror of the host's `Bbr3ProposalV2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BbrProposalSpecV1 {
    pub preset: Bbr3PresetV1,
    pub up_gain_milli: u32,
    pub headroom_milli: u32,
    pub cwnd_gain_milli: u32,
    pub pacing_cap_bytes_per_second: u64,
    pub loss_is_congestion: bool,
}

impl BbrProposalSpecV1 {
    /// Hard-coded fallback table used when a spec does not define a preset
    /// (mirror of the host's `Bbr3ProposalV2::for_preset`).
    pub fn for_preset(preset: Bbr3PresetV1, controller_bw_bytes_per_second: u64) -> Self {
        match preset {
            Bbr3PresetV1::SharedConservative => Self {
                preset,
                up_gain_milli: 1_150,
                headroom_milli: 250,
                cwnd_gain_milli: 2_000,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV1::PrivateAggressive => Self {
                preset,
                up_gain_milli: 1_350,
                headroom_milli: 100,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV1::LossyRadio => Self {
                preset,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV1::Policer => Self {
                preset,
                up_gain_milli: 1_100,
                headroom_milli: 250,
                cwnd_gain_milli: 2_000,
                pacing_cap_bytes_per_second: controller_bw_bytes_per_second.saturating_mul(970)
                    / 1_000,
                // A drop policer is governed by the explicit gross-wire cap;
                // feeding the same drops into BBR's inflight response applies
                // the signal twice and ratchets the delivery model downward.
                loss_is_congestion: false,
            },
            Bbr3PresetV1::LongFat => Self {
                preset,
                up_gain_milli: 1_250,
                headroom_milli: 150,
                cwnd_gain_milli: 3_000,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV1::RelayReliable => Self {
                preset,
                up_gain_milli: 1_100,
                headroom_milli: 300,
                cwnd_gain_milli: 1_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
            Bbr3PresetV1::LowRttHost => Self {
                preset,
                up_gain_milli: 1_350,
                headroom_milli: 100,
                cwnd_gain_milli: 2_500,
                pacing_cap_bytes_per_second: 0,
                loss_is_congestion: false,
            },
        }
    }
}

/// Application-layer action attached to a preset. `None` inherits the host
/// baseline; FEC `Some(0)`/`Some(0)` explicitly disables parity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActionSpecV1 {
    pub fec_data_cells: Option<u8>,
    pub fec_parity_cells: Option<u8>,
    pub train_target_bytes: Option<u32>,
    pub bulk_quantum_cells: Option<u16>,
    pub cover_overhead_per_mille: Option<u16>,
}

/// One arm of the bandit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetSpecV1 {
    pub name: String,
    pub proposal: BbrProposalSpecV1,
    #[serde(default)]
    pub action: ActionSpecV1,
}

/// Offline prior for one (context, preset) pair.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosteriorSpecV1 {
    pub observations: u32,
    pub mean: f64,
}

/// Utility weights per objective (the host computes utility; carried here so
/// the spec stays a faithful copy of the artifact).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtilityWeightsSpecV1 {
    pub throughput: f64,
    pub queue_delay: f64,
    pub latency_sojourn: f64,
    pub residual_loss: f64,
    pub jitter: f64,
    pub cpu: f64,
    pub wire_overhead: f64,
    pub memory: f64,
}

/// Exploration and safety knobs of the learner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorationSpecV1 {
    pub minimum_dwell_millis: u64,
    pub minimum_rtt_rounds: u32,
    pub minimum_samples: u32,
    pub maximum_cpu_per_mille: u16,
    pub rollback_regression_per_mille: u16,
}

/// Complete learner specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpecV1 {
    /// Stable policy identifier, e.g. `bandit-vivace@1`.
    pub id: String,
    /// Algorithm family; only [`POLICY_ALGORITHM_BANDIT_VIVACE`] is known.
    pub algorithm: String,
    /// Human-readable version string (the artifact's `built_at`).
    pub version: String,
    /// Objective the artifact was trained for, if restricted.
    #[serde(default)]
    pub objective: Option<ObjectiveV1>,
    pub contexts: ContextSchemaSpecV1,
    pub presets: Vec<PresetSpecV1>,
    /// `context policy key -> preset name -> prior`.
    #[serde(default)]
    pub priors: BTreeMap<String, BTreeMap<String, PosteriorSpecV1>>,
    /// `objective name -> weights`.
    #[serde(default)]
    pub weights: BTreeMap<String, UtilityWeightsSpecV1>,
    pub exploration: ExplorationSpecV1,
}

/// Validation failure of a [`PolicySpecV1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecError(pub &'static str);

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for SpecError {}

impl PolicySpecV1 {
    /// The embedded policy.  `config/autotune-policy-v1.json` is a canonical
    /// serde fixture asserted against this constructor by the host tests; it
    /// never supplies production policy data.
    pub fn builtin() -> Self {
        use Bbr3PresetV1::*;
        let proposal = |preset, up, headroom, cwnd, loss_is_congestion| BbrProposalSpecV1 {
            preset,
            up_gain_milli: up,
            headroom_milli: headroom,
            cwnd_gain_milli: cwnd,
            pacing_cap_bytes_per_second: 0,
            loss_is_congestion,
        };
        let action = |fec: Option<(u8, u8)>, train: u32, quantum: u16| ActionSpecV1 {
            fec_data_cells: fec.map(|(data, _)| data),
            fec_parity_cells: fec.map(|(_, parity)| parity),
            train_target_bytes: Some(train),
            bulk_quantum_cells: Some(quantum),
            cover_overhead_per_mille: Some(0),
        };
        let preset = |name: &str, proposal, action| PresetSpecV1 {
            name: name.to_owned(),
            proposal,
            action,
        };
        let weights = |throughput, queue_delay, latency_sojourn| UtilityWeightsSpecV1 {
            throughput,
            queue_delay,
            latency_sojourn,
            residual_loss: 1.0,
            jitter: 0.3,
            cpu: 0.3,
            wire_overhead: 0.4,
            memory: 0.1,
        };
        Self {
            id: BANDIT_POLICY_ID_V1.to_owned(),
            algorithm: POLICY_ALGORITHM_BANDIT_VIVACE.to_owned(),
            version: "2026-08-20T00:00:00Z".to_owned(),
            objective: None,
            contexts: ContextSchemaSpecV1::builtin(),
            presets: vec![
                preset(
                    "shared-conservative",
                    proposal(SharedConservative, 1_150, 250, 2_000, false),
                    ActionSpecV1::default(),
                ),
                preset(
                    "private-aggressive",
                    proposal(PrivateAggressive, 1_350, 100, 2_500, false),
                    action(Some((0, 0)), 65_536, 4),
                ),
                preset(
                    "lossy-radio",
                    proposal(LossyRadio, 1_250, 150, 2_500, false),
                    action(Some((8, 2)), 32_768, 2),
                ),
                preset(
                    "policer",
                    proposal(Policer, 1_100, 250, 2_000, false),
                    action(Some((0, 0)), 16_384, 1),
                ),
                preset(
                    "long-fat",
                    proposal(LongFat, 1_250, 150, 3_000, false),
                    action(Some((8, 1)), 65_536, 4),
                ),
                preset(
                    "relay-reliable",
                    proposal(RelayReliable, 1_100, 300, 1_500, false),
                    action(Some((0, 0)), 32_768, 2),
                ),
                preset(
                    "low-rtt-host",
                    proposal(LowRttHost, 1_350, 100, 2_500, false),
                    action(Some((0, 0)), 65_536, 4),
                ),
            ],
            priors: BTreeMap::new(),
            weights: BTreeMap::from([
                ("balanced".to_owned(), weights(1.0, 0.8, 0.8)),
                ("latency".to_owned(), weights(0.6, 1.5, 1.5)),
                ("throughput".to_owned(), weights(1.5, 0.4, 0.2)),
            ]),
            exploration: ExplorationSpecV1 {
                minimum_dwell_millis: 10_000,
                minimum_rtt_rounds: 8,
                minimum_samples: 8,
                maximum_cpu_per_mille: 900,
                rollback_regression_per_mille: 100,
            },
        }
    }

    /// Structural validation (the numeric bounds the host enforces on its
    /// JSON artifact). The host remains responsible for digest and file
    /// integrity; this only guards the learner against nonsensical data.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.id.trim().is_empty() {
            return Err(SpecError("policy id is empty"));
        }
        if self.algorithm != POLICY_ALGORITHM_BANDIT_VIVACE {
            return Err(SpecError("unsupported policy algorithm"));
        }
        for thresholds in [
            &self.contexts.rtt_millis,
            &self.contexts.rate_mbps,
            &self.contexts.loss_ppm,
        ] {
            if thresholds.len() > 16 {
                return Err(SpecError("too many context thresholds"));
            }
            if !thresholds.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(SpecError("context thresholds must be strictly increasing"));
            }
        }
        if self.presets.is_empty() {
            return Err(SpecError("policy has no presets"));
        }
        let mut kinds = 0_u8;
        for preset in &self.presets {
            if preset.name.trim().is_empty() {
                return Err(SpecError("preset name is empty"));
            }
            if self
                .presets
                .iter()
                .filter(|other| other.name == preset.name)
                .count()
                != 1
            {
                return Err(SpecError("duplicate preset name"));
            }
            let bit = 1_u8 << preset_index(preset.proposal.preset);
            if kinds & bit != 0 {
                return Err(SpecError("duplicate preset kind"));
            }
            kinds |= bit;
            let proposal = preset.proposal;
            if !(1_050..=1_500).contains(&proposal.up_gain_milli)
                || !(50..=400).contains(&proposal.headroom_milli)
                || !(1_200..=3_500).contains(&proposal.cwnd_gain_milli)
                || (proposal.pacing_cap_bytes_per_second != 0
                    && proposal.pacing_cap_bytes_per_second < 64 * 1024)
            {
                return Err(SpecError("BBR proposal outside safe bounds"));
            }
            validate_action(preset.action)?;
        }
        if kinds != 0x7f {
            return Err(SpecError(
                "policy must define every BBR preset exactly once",
            ));
        }
        for (context, priors) in &self.priors {
            validate_context_key(context)?;
            for (name, posterior) in priors {
                if !self.presets.iter().any(|preset| &preset.name == name) {
                    return Err(SpecError("prior references unknown preset"));
                }
                if !posterior.mean.is_finite() {
                    return Err(SpecError("prior contains non-finite reward"));
                }
            }
        }
        for objective in ["balanced", "throughput", "latency"] {
            if !self.weights.contains_key(objective) {
                return Err(SpecError("policy must define all utility objectives"));
            }
        }
        if self.weights.values().any(|weights| {
            [
                weights.throughput,
                weights.queue_delay,
                weights.latency_sojourn,
                weights.residual_loss,
                weights.jitter,
                weights.cpu,
                weights.wire_overhead,
                weights.memory,
            ]
            .into_iter()
            .any(|value| !value.is_finite() || !(0.0..=10.0).contains(&value))
        }) {
            return Err(SpecError("policy contains invalid utility weights"));
        }
        let exploration = self.exploration;
        if !(1_000..=300_000).contains(&exploration.minimum_dwell_millis)
            || !(1..=64).contains(&exploration.minimum_rtt_rounds)
            || !(4..=600).contains(&exploration.minimum_samples)
            || !(100..=1_000).contains(&exploration.maximum_cpu_per_mille)
            || !(10..=500).contains(&exploration.rollback_regression_per_mille)
        {
            return Err(SpecError("exploration knobs outside safe bounds"));
        }
        Ok(())
    }

    /// Proposal of `preset` as defined by this spec.
    pub fn preset(&self, preset: Bbr3PresetV1) -> Option<BbrProposalSpecV1> {
        self.presets
            .iter()
            .find(|candidate| candidate.proposal.preset == preset)
            .map(|candidate| candidate.proposal)
    }

    /// Application action of `preset` as defined by this spec.
    pub fn action(&self, preset: Bbr3PresetV1) -> Option<ActionSpecV1> {
        self.presets
            .iter()
            .find(|candidate| candidate.proposal.preset == preset)
            .map(|candidate| candidate.action)
    }
}

fn validate_action(action: ActionSpecV1) -> Result<(), SpecError> {
    if action.fec_data_cells.is_some() != action.fec_parity_cells.is_some() {
        return Err(SpecError(
            "policy FEC action must specify both data and parity",
        ));
    }
    if let (Some(data), Some(parity)) = (action.fec_data_cells, action.fec_parity_cells)
        && (data != 0 || parity != 0)
        && (!(2..=FEC_DATA_CELLS_MAX).contains(&data)
            || parity > FEC_PARITY_CELLS_MAX
            || u16::from(parity).saturating_mul(1_000)
                > u16::from(data).saturating_mul(FEC_PARITY_PER_MILLE_CAP))
    {
        return Err(SpecError("policy FEC action outside safe bounds"));
    }
    if action
        .train_target_bytes
        .is_some_and(|bytes| !(8 * 1024..=64 * 1024).contains(&bytes))
    {
        return Err(SpecError("policy train action outside safe bounds"));
    }
    if action
        .bulk_quantum_cells
        .is_some_and(|cells| !(1..=4).contains(&cells))
    {
        return Err(SpecError("policy quantum action outside safe bounds"));
    }
    if action
        .cover_overhead_per_mille
        .is_some_and(|overhead| overhead > 50)
    {
        return Err(SpecError("policy cover action outside safe bounds"));
    }
    Ok(())
}

fn validate_context_key(value: &str) -> Result<(), SpecError> {
    let mut parts = value.split('-');
    for prefix in ['r', 'b', 'l'] {
        let Some(part) = parts.next() else {
            return Err(SpecError("policy prior context is incomplete"));
        };
        let Some(class) = part.strip_prefix(prefix) else {
            return Err(SpecError("policy prior context has invalid class prefix"));
        };
        let Ok(class) = class.parse::<u8>() else {
            return Err(SpecError("policy prior context class is invalid"));
        };
        if class > 3 {
            return Err(SpecError("policy prior context class exceeds 3"));
        }
    }
    if !matches!(parts.next(), Some("datagram" | "reliable")) {
        return Err(SpecError("policy prior context has invalid reliability"));
    }
    if !matches!(parts.next(), None | Some("host")) || parts.next().is_some() {
        return Err(SpecError("policy prior context has invalid trailing data"));
    }
    Ok(())
}

/// Kebab-case preset name as used by spec files and diagnostics labels.
pub fn preset_name(preset: Bbr3PresetV1) -> &'static str {
    match preset {
        Bbr3PresetV1::SharedConservative => "shared-conservative",
        Bbr3PresetV1::PrivateAggressive => "private-aggressive",
        Bbr3PresetV1::LossyRadio => "lossy-radio",
        Bbr3PresetV1::Policer => "policer",
        Bbr3PresetV1::LongFat => "long-fat",
        Bbr3PresetV1::RelayReliable => "relay-reliable",
        Bbr3PresetV1::LowRttHost => "low-rtt-host",
    }
}

/// Arm index of a preset (declaration order of `Bbr3PresetV1`).
pub fn preset_index(preset: Bbr3PresetV1) -> usize {
    match preset {
        Bbr3PresetV1::SharedConservative => 0,
        Bbr3PresetV1::PrivateAggressive => 1,
        Bbr3PresetV1::LossyRadio => 2,
        Bbr3PresetV1::Policer => 3,
        Bbr3PresetV1::LongFat => 4,
        Bbr3PresetV1::RelayReliable => 5,
        Bbr3PresetV1::LowRttHost => 6,
    }
}

/// Resolve the BBR proposal the learner publishes for `preset`: the spec's
/// definition when present, otherwise the fallback table, with the policer
/// pacing cap filled from the live controller bandwidth when the spec left it
/// at zero. Shared by the learner step and the host's shadow materialization.
pub fn resolve_preset_proposal(
    spec_proposal: Option<BbrProposalSpecV1>,
    preset: Bbr3PresetV1,
    controller_bw_bytes_per_second: u64,
) -> BbrProposalSpecV1 {
    let mut proposal = spec_proposal
        .unwrap_or_else(|| BbrProposalSpecV1::for_preset(preset, controller_bw_bytes_per_second));
    if proposal.preset == Bbr3PresetV1::Policer && proposal.pacing_cap_bytes_per_second == 0 {
        proposal.pacing_cap_bytes_per_second =
            controller_bw_bytes_per_second.saturating_mul(970) / 1_000;
    }
    proposal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_spec_is_valid_and_complete() {
        let spec = PolicySpecV1::builtin();
        spec.validate().unwrap();
        assert_eq!(spec.presets.len(), 7);
        for preset in Bbr3PresetV1::ALL {
            assert!(spec.preset(preset).is_some());
            assert_eq!(spec.preset(preset).unwrap().preset, preset);
            assert_eq!(spec.presets[preset_index(preset)].name, preset_name(preset));
        }
        let lossy = spec.action(Bbr3PresetV1::LossyRadio).unwrap();
        assert_eq!(lossy.train_target_bytes, Some(32 * 1024));
        assert_eq!(lossy.fec_parity_cells, Some(2));
        assert_eq!(spec.weights.len(), 3);
    }

    #[test]
    fn validation_rejects_bad_specs() {
        let mut spec = PolicySpecV1::builtin();
        spec.presets[0].proposal.up_gain_milli = 2_000;
        assert!(spec.validate().is_err());

        let mut spec = PolicySpecV1::builtin();
        spec.presets.pop();
        assert!(spec.validate().is_err());

        let mut spec = PolicySpecV1::builtin();
        spec.contexts.rtt_millis = vec![40, 10];
        assert!(spec.validate().is_err());

        let mut spec = PolicySpecV1::builtin();
        spec.priors.insert(
            "r0-b0-l0-datagram".to_owned(),
            BTreeMap::from([(
                "unknown".to_owned(),
                PosteriorSpecV1 {
                    observations: 1,
                    mean: 0.0,
                },
            )]),
        );
        assert!(spec.validate().is_err());
    }

    #[test]
    fn policer_fallback_fills_pacing_cap_from_controller_bandwidth() {
        let resolved = resolve_preset_proposal(None, Bbr3PresetV1::Policer, 1_000_000);
        assert_eq!(resolved.pacing_cap_bytes_per_second, 970_000);
        assert!(!resolved.loss_is_congestion);
        let spec = PolicySpecV1::builtin();
        let policer = spec
            .presets
            .iter()
            .find(|preset| preset.proposal.preset == Bbr3PresetV1::Policer)
            .expect("built-in policer preset");
        assert_eq!(policer.action.fec_data_cells, Some(0));
        assert_eq!(policer.action.fec_parity_cells, Some(0));
        let resolved = resolve_preset_proposal(
            spec.preset(Bbr3PresetV1::Policer),
            Bbr3PresetV1::Policer,
            2_000,
        );
        assert_eq!(resolved.pacing_cap_bytes_per_second, 1_940);
        let resolved = resolve_preset_proposal(
            spec.preset(Bbr3PresetV1::LongFat),
            Bbr3PresetV1::LongFat,
            2_000,
        );
        assert_eq!(resolved.pacing_cap_bytes_per_second, 0);
    }
}
