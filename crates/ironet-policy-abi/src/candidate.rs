//! Untrusted action proposal plus the pure overlay and validation passes.

use serde::{Deserialize, Serialize};

use crate::{
    Bbr3PresetV1, BbrEffectiveV1, ClampEntryV1, ClampFieldV1, ClampReasonV1, CoverProfileV1,
    EffectiveActionV1, FecPresetFamilyV1, HostLimitsV1, PolicyExtensionV1,
    ProtectionResponsibilityV1, RepairWaitPolicyV1, SchedulerPresetHintV1, i64_saturating,
};

/// BBRv3 candidate. Field names and units follow `Bbr3Tunables`; every field
/// is optional and an unset field keeps the previous effective value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbrCandidateV1 {
    /// Preset hint; explicit fields below override what the preset implies.
    pub preset: Option<Bbr3PresetV1>,
    /// ProbeBW up-phase pacing gain (1000 = 1.0).
    pub probe_bw_up_pacing_gain_milli: Option<u32>,
    /// ProbeBW down-phase pacing gain (1000 = 1.0).
    pub probe_bw_down_pacing_gain_milli: Option<u32>,
    /// ProbeBW cruise pacing gain (1000 = 1.0).
    pub cruise_pacing_gain_milli: Option<u32>,
    /// Default cwnd gain (1000 = 1.0).
    pub default_cwnd_gain_milli: Option<u32>,
    /// ProbeBW up-phase cwnd gain (1000 = 1.0).
    pub probe_bw_up_cwnd_gain_milli: Option<u32>,
    /// Bandwidth headroom kept free (1000 = 100%).
    pub headroom_milli: Option<u32>,
    /// Multiplicative decrease on loss (1000 = 1.0).
    pub beta_milli: Option<u32>,
    /// Loss ratio treated as congestion (1000 = 100%).
    pub loss_threshold_milli: Option<u32>,
    /// Treat loss above the threshold as a congestion signal.
    pub loss_is_congestion: Option<bool>,
    /// Queue-delay guard inflation ratio (1000 = 100% of min RTT).
    pub queue_guard_inflation_milli: Option<u32>,
    /// Queue-delay guard absolute slack.
    pub queue_guard_slack_micros: Option<u64>,
    /// ProbeRTT interval.
    pub probe_rtt_interval_millis: Option<u64>,
    /// ProbeRTT duration.
    pub probe_rtt_duration_millis: Option<u64>,
    /// ProbeRTT cwnd gain (1000 = 1.0).
    pub probe_rtt_cwnd_gain_milli: Option<u32>,
    /// Minimum wait before the next bandwidth probe.
    pub min_probe_wait_millis: Option<u64>,
    /// Maximum random extra wait before the next bandwidth probe.
    pub max_added_probe_wait_millis: Option<u64>,
    /// Pacing rate cap (0 = uncapped).
    pub pacing_cap_bytes_per_second: Option<u64>,
    /// cwnd floor (0 = controller default).
    pub cwnd_floor_bytes: Option<u64>,
    /// cwnd cap (0 = uncapped).
    pub cwnd_cap_bytes: Option<u64>,
    /// Startup bandwidth hint (0 = none).
    pub startup_bw_hint_bytes_per_second: Option<u64>,
}

impl BbrCandidateV1 {
    fn apply_to(&self, target: &mut BbrEffectiveV1) {
        macro_rules! overlay {
            ($($field:ident),* $(,)?) => {
                $( if let Some(value) = self.$field { target.$field = value; } )*
            };
        }
        overlay!(
            preset,
            probe_bw_up_pacing_gain_milli,
            probe_bw_down_pacing_gain_milli,
            cruise_pacing_gain_milli,
            default_cwnd_gain_milli,
            probe_bw_up_cwnd_gain_milli,
            headroom_milli,
            beta_milli,
            loss_threshold_milli,
            loss_is_congestion,
            queue_guard_inflation_milli,
            queue_guard_slack_micros,
            probe_rtt_interval_millis,
            probe_rtt_duration_millis,
            probe_rtt_cwnd_gain_milli,
            min_probe_wait_millis,
            max_added_probe_wait_millis,
            pacing_cap_bytes_per_second,
            cwnd_floor_bytes,
            cwnd_cap_bytes,
            startup_bw_hint_bytes_per_second,
        );
    }
}

/// Scheduler candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerCandidateV1 {
    /// Target PacketTrain size.
    pub train_target_bytes: Option<u32>,
    /// Bulk cells dequeued per scheduler quantum.
    pub bulk_quantum_cells: Option<u16>,
    /// Bulk bytes admitted ahead of latency traffic per window (0 = host
    /// default).
    pub bulk_admission_window_bytes: Option<u32>,
    /// Behaviour hint.
    pub preset_hint: Option<SchedulerPresetHintV1>,
}

/// FEC candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecCandidateV1 {
    /// Enable parity; `Some(false)` explicitly turns FEC off.
    pub enabled: Option<bool>,
    /// Systematic data cells per stripe (2..=cap).
    pub data_cells: Option<u8>,
    /// Parity cells per stripe (0..=cap).
    pub parity_cells: Option<u8>,
    /// Geometry family hint.
    pub preset_family: Option<FecPresetFamilyV1>,
}

/// Repair candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCandidateV1 {
    /// Repair cache size.
    pub cache_bytes: Option<u64>,
    /// How long Cells stay repairable after transmission (0 = host default).
    pub retention_target_millis: Option<u32>,
    /// When to request Repair for a gap.
    pub wait_policy: Option<RepairWaitPolicyV1>,
    /// FEC versus Repair responsibility hint.
    pub responsibility: Option<ProtectionResponsibilityV1>,
}

/// Transmit-side candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxCandidateV1 {
    /// Producer-admission (send) buffer.
    pub send_buffer_bytes: Option<u64>,
    /// Datagram admission budget per interval (0 = host default).
    pub datagram_admission_bytes: Option<u32>,
    /// Producer window ahead of the controller (0 = host default).
    pub producer_window_bytes: Option<u64>,
}

/// Receive-side candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RxCandidateV1 {
    /// Reassembly (receive) buffer.
    pub receive_buffer_bytes: Option<u64>,
    /// Cells coalesced per receive batch (>= 1).
    pub receive_batch: Option<u16>,
    /// Aggregate reassembly byte budget (0 = follow `receive_buffer_bytes`).
    pub reassembly_budget_bytes: Option<u64>,
    /// Maximum concurrently open PacketTrains (0 = host default).
    pub active_train_budget: Option<u16>,
}

/// Cover-traffic candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverCandidateV1 {
    /// Shaping profile.
    pub profile: Option<CoverProfileV1>,
    /// Cover overhead relative to real traffic.
    pub overhead_per_mille: Option<u16>,
    /// Absolute cover padding rate.
    pub padding_bytes_per_second: Option<u64>,
}

/// Egress demand submitted to the node coordinator. This is a complete
/// request, so its fields are not individually optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRequestV1 {
    /// Rate the policy wants for this peer (0 = whatever is left).
    pub desired_rate_bytes_per_second: u64,
    /// Rate below which the peer degrades (<= desired when desired != 0).
    pub minimum_rate_bytes_per_second: u64,
    /// Priority 0..=`EGRESS_PRIORITY_MAX`; higher wins ties.
    pub priority: u8,
    /// The request is part of an exploration and may be pre-empted first.
    pub exploring: bool,
}

/// Untrusted action proposal. Every domain is optional; an absent domain or
/// field means "keep the previous effective value".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateActionV1 {
    pub bbr: Option<BbrCandidateV1>,
    pub scheduler: Option<SchedulerCandidateV1>,
    pub fec: Option<FecCandidateV1>,
    pub repair: Option<RepairCandidateV1>,
    pub tx: Option<TxCandidateV1>,
    pub rx: Option<RxCandidateV1>,
    pub cover: Option<CoverCandidateV1>,
    pub egress_request: Option<EgressRequestV1>,
    /// TLV extension bag for domains not in V1.
    pub extensions: Vec<PolicyExtensionV1>,
}

impl CandidateActionV1 {
    /// Pure merge: every `Some` field overrides `base`, nothing is clamped.
    /// `reason`, `path_epoch` and `sample_count` are inherited from `base`;
    /// the guardrail pipeline sets them afterwards. Extensions are not
    /// merged (they have no effective-side representation in V1).
    pub fn apply_over(&self, base: &EffectiveActionV1) -> EffectiveActionV1 {
        let mut out = base.clone();
        if let Some(bbr) = &self.bbr {
            bbr.apply_to(&mut out.bbr);
        }
        if let Some(scheduler) = &self.scheduler {
            if let Some(value) = scheduler.train_target_bytes {
                out.scheduler.train_target_bytes = value;
            }
            if let Some(value) = scheduler.bulk_quantum_cells {
                out.scheduler.bulk_quantum_cells = value;
            }
            if let Some(value) = scheduler.bulk_admission_window_bytes {
                out.scheduler.bulk_admission_window_bytes = value;
            }
            if let Some(value) = scheduler.preset_hint {
                out.scheduler.preset_hint = value;
            }
        }
        if let Some(fec) = &self.fec {
            if let Some(value) = fec.enabled {
                out.fec.enabled = value;
            }
            if let Some(value) = fec.data_cells {
                out.fec.data_cells = value;
            }
            if let Some(value) = fec.parity_cells {
                out.fec.parity_cells = value;
            }
            if let Some(value) = fec.preset_family {
                out.fec.preset_family = value;
            }
        }
        if let Some(repair) = &self.repair {
            if let Some(value) = repair.cache_bytes {
                out.repair.cache_bytes = value;
            }
            if let Some(value) = repair.retention_target_millis {
                out.repair.retention_target_millis = value;
            }
            if let Some(value) = repair.wait_policy {
                out.repair.wait_policy = value;
            }
            if let Some(value) = repair.responsibility {
                out.repair.responsibility = value;
            }
        }
        if let Some(tx) = &self.tx {
            if let Some(value) = tx.send_buffer_bytes {
                out.tx.send_buffer_bytes = value;
            }
            if let Some(value) = tx.datagram_admission_bytes {
                out.tx.datagram_admission_bytes = value;
            }
            if let Some(value) = tx.producer_window_bytes {
                out.tx.producer_window_bytes = value;
            }
        }
        if let Some(rx) = &self.rx {
            if let Some(value) = rx.receive_buffer_bytes {
                out.rx.receive_buffer_bytes = value;
            }
            if let Some(value) = rx.receive_batch {
                out.rx.receive_batch = value;
            }
            if let Some(value) = rx.reassembly_budget_bytes {
                out.rx.reassembly_budget_bytes = value;
            }
            if let Some(value) = rx.active_train_budget {
                out.rx.active_train_budget = value;
            }
        }
        if let Some(cover) = &self.cover {
            if let Some(value) = cover.profile {
                out.cover.profile = value;
            }
            if let Some(value) = cover.overhead_per_mille {
                out.cover.overhead_per_mille = value;
            }
            if let Some(value) = cover.padding_bytes_per_second {
                out.cover.padding_bytes_per_second = value;
            }
        }
        if let Some(egress) = &self.egress_request {
            out.egress = egress.clone();
        }
        out
    }

    /// First, pure guardrail pass: structural validity against `limits`.
    /// Returns every violation; it never rewrites the candidate. Business
    /// clamps (CPU, queue, reliable underlay, egress arbitration, transition
    /// hold) are a later stage and are not evaluated here.
    pub fn validate(&self, limits: &HostLimitsV1) -> Result<(), Vec<ClampEntryV1>> {
        let mut report = Vec::new();
        if let Some(bbr) = &self.bbr {
            validate_bbr(bbr, &mut report);
        }
        if let Some(scheduler) = &self.scheduler {
            validate_scheduler(scheduler, limits, &mut report);
        }
        if let Some(fec) = &self.fec {
            validate_fec(fec, limits, &mut report);
        }
        if let Some(repair) = &self.repair
            && let Some(cache) = repair.cache_bytes
            && limits.repair_cache_cap_bytes != 0
            && cache > limits.repair_cache_cap_bytes
        {
            report.push(ClampEntryV1::new(
                ClampFieldV1::RepairCacheBytes,
                i64_saturating(cache),
                i64_saturating(limits.repair_cache_cap_bytes),
                ClampReasonV1::AboveCap,
            ));
        }
        if let Some(tx) = &self.tx
            && let Some(send) = tx.send_buffer_bytes
        {
            check_range_u64(
                ClampFieldV1::TxSendBufferBytes,
                send,
                limits.send_buffer_floor_bytes,
                limits.send_buffer_cap_bytes,
                &mut report,
            );
        }
        if let Some(rx) = &self.rx {
            if let Some(receive) = rx.receive_buffer_bytes {
                check_range_u64(
                    ClampFieldV1::RxReceiveBufferBytes,
                    receive,
                    limits.receive_buffer_floor_bytes,
                    limits.receive_buffer_cap_bytes,
                    &mut report,
                );
            }
            if let Some(batch) = rx.receive_batch {
                check_range_u64(
                    ClampFieldV1::RxReceiveBatch,
                    u64::from(batch),
                    1,
                    u64::from(limits.receive_batch_cap),
                    &mut report,
                );
            }
        }
        if let Some(cover) = &self.cover {
            if let Some(overhead) = cover.overhead_per_mille
                && overhead > limits.cover_overhead_cap_per_mille
            {
                report.push(ClampEntryV1::new(
                    ClampFieldV1::CoverOverheadPerMille,
                    i64::from(overhead),
                    i64::from(limits.cover_overhead_cap_per_mille),
                    ClampReasonV1::AboveCap,
                ));
            }
            if let Some(padding) = cover.padding_bytes_per_second
                && limits.cover_padding_cap_bytes_per_second != 0
                && padding > limits.cover_padding_cap_bytes_per_second
            {
                report.push(ClampEntryV1::new(
                    ClampFieldV1::CoverPaddingBytesPerSecond,
                    i64_saturating(padding),
                    i64_saturating(limits.cover_padding_cap_bytes_per_second),
                    ClampReasonV1::AboveCap,
                ));
            }
        }
        if let Some(egress) = &self.egress_request {
            if egress.priority > limits.egress_priority_cap {
                report.push(ClampEntryV1::new(
                    ClampFieldV1::EgressPriority,
                    i64::from(egress.priority),
                    i64::from(limits.egress_priority_cap),
                    ClampReasonV1::AboveCap,
                ));
            }
            if egress.desired_rate_bytes_per_second != 0
                && egress.minimum_rate_bytes_per_second > egress.desired_rate_bytes_per_second
            {
                report.push(ClampEntryV1::new(
                    ClampFieldV1::EgressMinimumRateBytesPerSecond,
                    i64_saturating(egress.minimum_rate_bytes_per_second),
                    i64_saturating(egress.desired_rate_bytes_per_second),
                    ClampReasonV1::CrossFieldConstraint,
                ));
            }
        }
        if self.extensions.len() > usize::from(limits.extension_count_cap) {
            report.push(ClampEntryV1::new(
                ClampFieldV1::Extension,
                i64::try_from(self.extensions.len()).unwrap_or(i64::MAX),
                i64::from(limits.extension_count_cap),
                ClampReasonV1::TooManyExtensions,
            ));
        }
        for extension in &self.extensions {
            if u64::try_from(extension.payload.len()).unwrap_or(u64::MAX)
                > u64::from(limits.extension_payload_cap_bytes)
            {
                report.push(ClampEntryV1::new(
                    ClampFieldV1::Extension,
                    i64::from(extension.tag),
                    i64::from(limits.extension_payload_cap_bytes),
                    ClampReasonV1::ExtensionTooLarge,
                ));
            }
        }
        if report.is_empty() {
            Ok(())
        } else {
            Err(report)
        }
    }
}

fn check_range_u64(
    field: ClampFieldV1,
    value: u64,
    floor: u64,
    cap: u64,
    report: &mut Vec<ClampEntryV1>,
) {
    if value < floor {
        report.push(ClampEntryV1::new(
            field,
            i64_saturating(value),
            i64_saturating(floor),
            ClampReasonV1::BelowFloor,
        ));
    } else if cap != 0 && value > cap {
        report.push(ClampEntryV1::new(
            field,
            i64_saturating(value),
            i64_saturating(cap),
            ClampReasonV1::AboveCap,
        ));
    }
}

/// Gains that must be strictly positive: a zero gain freezes the controller.
fn check_positive_gain(field: ClampFieldV1, value: Option<u32>, report: &mut Vec<ClampEntryV1>) {
    if value == Some(0) {
        report.push(ClampEntryV1::new(field, 0, 1, ClampReasonV1::InvalidValue));
    }
}

/// Ratios whose meaning is "fraction of 1": anything above 1000 overflows the
/// controller arithmetic.
fn check_fraction(field: ClampFieldV1, value: Option<u32>, report: &mut Vec<ClampEntryV1>) {
    if let Some(value) = value
        && value > 1_000
    {
        report.push(ClampEntryV1::new(
            field,
            i64::from(value),
            1_000,
            ClampReasonV1::Overflow,
        ));
    }
}

fn validate_bbr(bbr: &BbrCandidateV1, report: &mut Vec<ClampEntryV1>) {
    check_positive_gain(
        ClampFieldV1::BbrProbeBwUpPacingGainMilli,
        bbr.probe_bw_up_pacing_gain_milli,
        report,
    );
    check_positive_gain(
        ClampFieldV1::BbrProbeBwDownPacingGainMilli,
        bbr.probe_bw_down_pacing_gain_milli,
        report,
    );
    check_positive_gain(
        ClampFieldV1::BbrCruisePacingGainMilli,
        bbr.cruise_pacing_gain_milli,
        report,
    );
    check_positive_gain(
        ClampFieldV1::BbrDefaultCwndGainMilli,
        bbr.default_cwnd_gain_milli,
        report,
    );
    check_positive_gain(
        ClampFieldV1::BbrProbeBwUpCwndGainMilli,
        bbr.probe_bw_up_cwnd_gain_milli,
        report,
    );
    check_positive_gain(
        ClampFieldV1::BbrProbeRttCwndGainMilli,
        bbr.probe_rtt_cwnd_gain_milli,
        report,
    );
    check_fraction(ClampFieldV1::BbrHeadroomMilli, bbr.headroom_milli, report);
    check_fraction(ClampFieldV1::BbrBetaMilli, bbr.beta_milli, report);
    check_fraction(
        ClampFieldV1::BbrLossThresholdMilli,
        bbr.loss_threshold_milli,
        report,
    );
    if let (Some(duration), Some(interval)) =
        (bbr.probe_rtt_duration_millis, bbr.probe_rtt_interval_millis)
        && duration > interval
    {
        report.push(ClampEntryV1::new(
            ClampFieldV1::BbrProbeRttDurationMillis,
            i64_saturating(duration),
            i64_saturating(interval),
            ClampReasonV1::CrossFieldConstraint,
        ));
    }
    if let (Some(floor), Some(cap)) = (bbr.cwnd_floor_bytes, bbr.cwnd_cap_bytes)
        && cap != 0
        && floor > cap
    {
        report.push(ClampEntryV1::new(
            ClampFieldV1::BbrCwndFloorBytes,
            i64_saturating(floor),
            i64_saturating(cap),
            ClampReasonV1::CrossFieldConstraint,
        ));
    }
}

fn validate_scheduler(
    scheduler: &SchedulerCandidateV1,
    limits: &HostLimitsV1,
    report: &mut Vec<ClampEntryV1>,
) {
    if let Some(train) = scheduler.train_target_bytes {
        check_range_u64(
            ClampFieldV1::SchedulerTrainTargetBytes,
            u64::from(train),
            u64::from(limits.train_target_floor_bytes),
            u64::from(limits.train_target_cap_bytes),
            report,
        );
    }
    if let Some(quantum) = scheduler.bulk_quantum_cells {
        check_range_u64(
            ClampFieldV1::SchedulerBulkQuantumCells,
            u64::from(quantum),
            u64::from(limits.bulk_quantum_floor_cells.max(1)),
            u64::from(limits.bulk_quantum_cap_cells),
            report,
        );
    }
}

fn validate_fec(fec: &FecCandidateV1, limits: &HostLimitsV1, report: &mut Vec<ClampEntryV1>) {
    if let Some(data) = fec.data_cells {
        check_range_u64(
            ClampFieldV1::FecDataCells,
            u64::from(data),
            2,
            u64::from(limits.fec_data_cells_cap),
            report,
        );
    }
    if let Some(parity) = fec.parity_cells
        && parity > limits.fec_parity_cells_cap
    {
        report.push(ClampEntryV1::new(
            ClampFieldV1::FecParityCells,
            i64::from(parity),
            i64::from(limits.fec_parity_cells_cap),
            ClampReasonV1::AboveCap,
        ));
    }
    if let (Some(data), Some(parity)) = (fec.data_cells, fec.parity_cells)
        && data >= 2
        && u32::from(parity) * 1_000 > u32::from(data) * u32::from(limits.fec_parity_per_mille_cap)
    {
        let allowed = u32::from(data) * u32::from(limits.fec_parity_per_mille_cap) / 1_000;
        report.push(ClampEntryV1::new(
            ClampFieldV1::FecParityCells,
            i64::from(parity),
            i64::from(allowed),
            ClampReasonV1::CrossFieldConstraint,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{POLICY_EXTENSION_MAX_COUNT, POLICY_EXTENSION_MAX_PAYLOAD_BYTES};

    fn filled_effective() -> EffectiveActionV1 {
        EffectiveActionV1 {
            reason: ActionReasonV1::RandomLoss,
            path_epoch: 7,
            sample_count: 42,
            bbr: BbrEffectiveV1::expand_preset(
                Bbr3PresetV1::LossyRadio,
                1_250,
                150,
                2_500,
                9_000_000,
                false,
            ),
            scheduler: SchedulerEffectiveV1 {
                train_target_bytes: 32 * 1024,
                bulk_quantum_cells: 2,
                bulk_admission_window_bytes: 0,
                preset_hint: SchedulerPresetHintV1::HostDefault,
            },
            fec: FecEffectiveV1 {
                enabled: true,
                data_cells: 8,
                parity_cells: 2,
                preset_family: FecPresetFamilyV1::Unspecified,
            },
            repair: RepairEffectiveV1 {
                cache_bytes: 4 * 1024 * 1024,
                ..RepairEffectiveV1::default()
            },
            tx: TxEffectiveV1 {
                send_buffer_bytes: 512 * 1024,
                ..TxEffectiveV1::default()
            },
            rx: RxEffectiveV1 {
                receive_buffer_bytes: 16 * 1024 * 1024,
                receive_batch: 32,
                ..RxEffectiveV1::default()
            },
            cover: CoverEffectiveV1 {
                profile: CoverProfileV1::InteractiveVideo,
                overhead_per_mille: 25,
                padding_bytes_per_second: 12_000,
            },
            egress: EgressRequestV1::default(),
        }
    }

    use crate::{
        ActionReasonV1, CoverEffectiveV1, FecEffectiveV1, RepairEffectiveV1, RxEffectiveV1,
        SchedulerEffectiveV1, TxEffectiveV1,
    };

    #[test]
    fn apply_over_overlays_only_set_fields() {
        let base = filled_effective();
        assert_eq!(CandidateActionV1::default().apply_over(&base), base);

        let candidate = CandidateActionV1 {
            bbr: Some(BbrCandidateV1 {
                preset: Some(Bbr3PresetV1::Policer),
                headroom_milli: Some(300),
                ..BbrCandidateV1::default()
            }),
            fec: Some(FecCandidateV1 {
                enabled: Some(false),
                ..FecCandidateV1::default()
            }),
            cover: Some(CoverCandidateV1 {
                overhead_per_mille: Some(0),
                ..CoverCandidateV1::default()
            }),
            egress_request: Some(EgressRequestV1 {
                desired_rate_bytes_per_second: 5,
                minimum_rate_bytes_per_second: 1,
                priority: 2,
                exploring: true,
            }),
            ..CandidateActionV1::default()
        };
        let merged = candidate.apply_over(&base);
        assert_eq!(merged.bbr.preset, Bbr3PresetV1::Policer);
        assert_eq!(merged.bbr.headroom_milli, 300);
        // Unset BBR fields keep the base expansion, not the preset table.
        assert_eq!(
            merged.bbr.queue_guard_inflation_milli,
            base.bbr.queue_guard_inflation_milli
        );
        assert!(!merged.fec.enabled);
        assert_eq!(merged.fec.data_cells, 8);
        assert_eq!(merged.cover.overhead_per_mille, 0);
        assert_eq!(merged.cover.profile, CoverProfileV1::InteractiveVideo);
        assert_eq!(merged.egress.priority, 2);
        assert_eq!(merged.reason, base.reason);
        assert_eq!(merged.sample_count, base.sample_count);
    }

    #[test]
    fn validate_rejects_out_of_range_candidates() {
        let limits = HostLimitsV1::default();
        assert!(CandidateActionV1::default().validate(&limits).is_ok());

        let candidate = CandidateActionV1 {
            bbr: Some(BbrCandidateV1 {
                cruise_pacing_gain_milli: Some(0),
                headroom_milli: Some(1_500),
                probe_rtt_interval_millis: Some(100),
                probe_rtt_duration_millis: Some(200),
                cwnd_floor_bytes: Some(20_000),
                cwnd_cap_bytes: Some(10_000),
                ..BbrCandidateV1::default()
            }),
            scheduler: Some(SchedulerCandidateV1 {
                train_target_bytes: Some(4 * 1024),
                bulk_quantum_cells: Some(0),
                ..SchedulerCandidateV1::default()
            }),
            fec: Some(FecCandidateV1 {
                enabled: Some(true),
                data_cells: Some(1),
                parity_cells: Some(9),
                preset_family: None,
            }),
            repair: Some(RepairCandidateV1 {
                cache_bytes: Some(u64::MAX),
                ..RepairCandidateV1::default()
            }),
            tx: Some(TxCandidateV1 {
                send_buffer_bytes: Some(64 * 1024 * 1024),
                ..TxCandidateV1::default()
            }),
            rx: Some(RxCandidateV1 {
                receive_buffer_bytes: Some(1),
                receive_batch: Some(0),
                ..RxCandidateV1::default()
            }),
            cover: Some(CoverCandidateV1 {
                overhead_per_mille: Some(999),
                ..CoverCandidateV1::default()
            }),
            egress_request: Some(EgressRequestV1 {
                desired_rate_bytes_per_second: 100,
                minimum_rate_bytes_per_second: 200,
                priority: 9,
                exploring: false,
            }),
            extensions: vec![PolicyExtensionV1 {
                tag: 4,
                payload: vec![0; POLICY_EXTENSION_MAX_PAYLOAD_BYTES as usize + 1],
            }],
        };
        let entries = candidate.validate(&limits).unwrap_err();
        let has = |field: ClampFieldV1, reason: ClampReasonV1| {
            entries
                .iter()
                .any(|entry| entry.field == field && entry.reason == reason)
        };
        assert!(has(
            ClampFieldV1::BbrCruisePacingGainMilli,
            ClampReasonV1::InvalidValue
        ));
        assert!(has(ClampFieldV1::BbrHeadroomMilli, ClampReasonV1::Overflow));
        assert!(has(
            ClampFieldV1::BbrProbeRttDurationMillis,
            ClampReasonV1::CrossFieldConstraint
        ));
        assert!(has(
            ClampFieldV1::BbrCwndFloorBytes,
            ClampReasonV1::CrossFieldConstraint
        ));
        assert!(has(
            ClampFieldV1::SchedulerTrainTargetBytes,
            ClampReasonV1::BelowFloor
        ));
        assert!(has(
            ClampFieldV1::SchedulerBulkQuantumCells,
            ClampReasonV1::BelowFloor
        ));
        assert!(has(ClampFieldV1::FecDataCells, ClampReasonV1::BelowFloor));
        assert!(has(ClampFieldV1::FecParityCells, ClampReasonV1::AboveCap));
        assert!(has(ClampFieldV1::RepairCacheBytes, ClampReasonV1::AboveCap));
        assert!(has(
            ClampFieldV1::TxSendBufferBytes,
            ClampReasonV1::AboveCap
        ));
        assert!(has(
            ClampFieldV1::RxReceiveBufferBytes,
            ClampReasonV1::BelowFloor
        ));
        assert!(has(ClampFieldV1::RxReceiveBatch, ClampReasonV1::BelowFloor));
        assert!(has(
            ClampFieldV1::CoverOverheadPerMille,
            ClampReasonV1::AboveCap
        ));
        assert!(has(ClampFieldV1::EgressPriority, ClampReasonV1::AboveCap));
        assert!(has(
            ClampFieldV1::EgressMinimumRateBytesPerSecond,
            ClampReasonV1::CrossFieldConstraint
        ));
        assert!(has(
            ClampFieldV1::Extension,
            ClampReasonV1::ExtensionTooLarge
        ));
        let repair = entries
            .iter()
            .find(|entry| entry.field == ClampFieldV1::RepairCacheBytes)
            .unwrap();
        assert_eq!(repair.requested, i64::MAX);
        assert_eq!(repair.effective, 32 * 1024 * 1024);

        // Parity ratio guard: parity may equal, but not exceed, data cells.
        let maximum_ratio = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(true),
                data_cells: Some(4),
                parity_cells: Some(4),
                preset_family: None,
            }),
            ..CandidateActionV1::default()
        };
        assert!(maximum_ratio.validate(&limits).is_ok());

        let ratio = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(true),
                data_cells: Some(4),
                parity_cells: Some(5),
                preset_family: None,
            }),
            ..CandidateActionV1::default()
        };
        let entries = ratio.validate(&limits).unwrap_err();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].field, ClampFieldV1::FecParityCells);
        assert_eq!(entries[0].reason, ClampReasonV1::CrossFieldConstraint);
        assert_eq!(entries[0].effective, 4);

        // cwnd cap of zero means "no cap", so any floor is fine.
        let uncapped = CandidateActionV1 {
            bbr: Some(BbrCandidateV1 {
                cwnd_floor_bytes: Some(1 << 30),
                cwnd_cap_bytes: Some(0),
                ..BbrCandidateV1::default()
            }),
            ..CandidateActionV1::default()
        };
        assert!(uncapped.validate(&limits).is_ok());

        let too_many = CandidateActionV1 {
            extensions: (0..=POLICY_EXTENSION_MAX_COUNT)
                .map(|tag| PolicyExtensionV1 {
                    tag,
                    payload: Vec::new(),
                })
                .collect(),
            ..CandidateActionV1::default()
        };
        let entries = too_many.validate(&limits).unwrap_err();
        assert!(
            entries
                .iter()
                .any(|entry| entry.reason == ClampReasonV1::TooManyExtensions)
        );
    }

    #[test]
    fn default_limits_accept_eight_cell_bulk_quantum_and_reject_nine() {
        let limits = HostLimitsV1::default();
        assert_eq!(limits.bulk_quantum_cap_cells, 8);

        let mut candidate = CandidateActionV1 {
            scheduler: Some(SchedulerCandidateV1 {
                bulk_quantum_cells: Some(8),
                ..SchedulerCandidateV1::default()
            }),
            ..CandidateActionV1::default()
        };
        assert!(candidate.validate(&limits).is_ok());

        candidate.scheduler.as_mut().unwrap().bulk_quantum_cells = Some(9);
        let entries = candidate.validate(&limits).unwrap_err();
        assert!(entries.iter().any(|entry| {
            entry.field == ClampFieldV1::SchedulerBulkQuantumCells
                && entry.reason == ClampReasonV1::AboveCap
                && entry.effective == 8
        }));
    }

    /// The guardrails fuzz target (`fuzz/fuzz_targets/v2_policy_guardrails.rs`)
    /// decodes its input with postcard; these seeds pin the encoding so the
    /// harness starts from decodable inputs.
    #[test]
    fn fuzz_seed_corpus_decodes_as_postcard() {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus/v2_policy_guardrails");
        // 40 context bytes trail the candidate in every seed.
        let decode = |name: &str| -> CandidateActionV1 {
            let bytes = std::fs::read(corpus.join(name)).expect("seed corpus is generated");
            postcard::from_bytes(&bytes[..bytes.len() - 40]).expect("seed decodes as postcard")
        };

        let empty = decode("candidate-empty");
        assert_eq!(empty, CandidateActionV1::default());

        let family = decode("candidate-fec-family");
        let fec = family.fec.expect("fec domain is set");
        assert_eq!(fec.enabled, Some(true));
        assert_eq!(fec.data_cells, None);
        assert_eq!(fec.parity_cells, None);
        assert_eq!(fec.preset_family, Some(FecPresetFamilyV1::Balanced));

        let rx_repair = decode("candidate-rx-repair");
        let repair = rx_repair.repair.expect("repair domain is set");
        assert_eq!(repair.retention_target_millis, Some(5_000));
        assert_eq!(repair.wait_policy, Some(RepairWaitPolicyV1::Patient));
        let rx = rx_repair.rx.expect("rx domain is set");
        assert_eq!(rx.receive_buffer_bytes, Some(16 * 1024 * 1024));
        assert_eq!(rx.reassembly_budget_bytes, Some(4 * 1024 * 1024));
        assert_eq!(rx.active_train_budget, Some(64));
    }
}
