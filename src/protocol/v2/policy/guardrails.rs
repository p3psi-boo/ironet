//! Host guardrails: the single boundary that turns an untrusted
//! [`CandidateActionV1`] into a host-authoritative [`EffectiveActionV1`].
//!
//! Every policy output -- the native rule set, a fixed-action experiment
//! override, a learned action and (later) a Wasm guest -- passes through
//! [`GuardrailsV1::apply`]. The pass is pure: the same `(candidate, base,
//! ctx)` always yields the same effective action and [`ClampReportV1`], and
//! applying the result again with an empty candidate is the identity (see
//! the property tests). The auto-tuner relies on that idempotence for its
//! final pass.
//!
//! Rules, in application order:
//!
//! 1. **BBR** -- node-wide pacing cap, `cwnd floor <= cwnd cap`.
//! 2. **Scheduler** -- train target within `[floor, cap]`; Bulk quantum is
//!    one Cell while latency traffic is queued, otherwise within
//!    `[floor, cap]`; under a live CPU emergency the candidate may not
//!    batch more than the host baseline (`base`).
//! 3. **FEC** -- a reliable underlay or host CPU pressure forces protection
//!    off; under a live loss emergency a candidate may not switch the base
//!    protection off; a preset family without explicit cells maps to the
//!    host geometry table; the geometry must be valid and its parity ratio
//!    within the wire-overhead cap.
//! 4. **Repair** -- the cache is host-derived from the effective geometry,
//!    never taken from the candidate; the retention target is capped and the
//!    wait policy passes through.
//! 5. **TX/RX** -- send/receive buffers and the receive batch within the
//!    host memory budget; the reassembly budget never exceeds the effective
//!    receive buffer and the active-train budget is capped by the wire
//!    limit.
//! 6. **Cover** -- suppressed while the host classifies the path as CPU,
//!    queue, loss or idle constrained; a base without cover cannot be
//!    raised; overhead within the cap; an idle profile carries no cover;
//!    padding is host-derived from the real traffic rate.
//! 7. **Egress** -- priority cap and `minimum <= desired`.
//! 8. Domains the data plane does not execute in this build (scheduler
//!    admission window and preset hint, TX datagram admission and producer
//!    window, Repair responsibility) are reset to their host defaults and
//!    reported as `Unsupported`.

use crate::protocol::v2::{
    policy::api::*,
    tuning::{AutoTuneBoundsV2, FilteredTelemetryV1, PathReliability, repair_cache_target_bytes},
};

/// Largest Repair retention a candidate may request. The host default is the
/// 2 s cache TTL; one minute covers even pathological reordering without
/// letting a guest pin the cache forever.
pub const REPAIR_RETENTION_CAP_MILLIS: u32 = 60_000;
/// Smallest explicit aggregate reassembly budget. Below this the per-epoch
/// share could not hold a single maximum-size train.
pub const REASSEMBLY_BUDGET_FLOOR_BYTES: u64 = 1024 * 1024;
/// Largest explicit active-train budget; matches the negotiated wire limit
/// (`WireLimitsV2::max_active_trains`).
pub const ACTIVE_TRAIN_BUDGET_CAP: u16 = 1_024;

/// Host geometry table for a FEC preset family the candidate requested
/// without explicit cell counts. Every entry is valid under the default
/// limits (data <= 16, parity <= 8, ratio <= 1,000 per mille).
fn fec_family_geometry(family: FecPresetFamilyV1) -> Option<(u8, u8)> {
    match family {
        FecPresetFamilyV1::Unspecified => None,
        // ~6% overhead over a long stripe.
        FecPresetFamilyV1::Sparse => Some((16, 1)),
        // 25% overhead for random-loss WANs.
        FecPresetFamilyV1::Balanced => Some((8, 2)),
        // 50% overhead for bursty radio paths.
        FecPresetFamilyV1::Dense => Some((8, 4)),
    }
}

/// Live host facts the guardrails need beyond the static limits. Built from
/// the filtered telemetry of the current tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardrailContextV1 {
    /// Path underlay already retransmits: FEC/Repair add no value.
    pub reliable: bool,
    /// Smoothed host CPU at or above 90%: protection and cover are
    /// suppressed.
    pub cpu_limited: bool,
    /// Live host CPU at or above 90%: a candidate may not raise scheduler
    /// batching above the host baseline.
    pub cpu_emergency: bool,
    /// The live sample carries protection evidence and crosses the loss
    /// threshold: a candidate may not switch base protection off.
    pub protection_emergency: bool,
    /// Latency traffic is queued: Bulk may not overtake it.
    pub latency_queue_active: bool,
    /// Why cover is suppressed this tick, if it is.
    pub cover_suppression: Option<ClampReasonV1>,
    /// Live real traffic rate the cover padding is derived from.
    pub real_traffic_bytes_per_second: u64,
    /// Smoothed RTT the Repair cache horizon is derived from.
    pub rtt_micros: u64,
    /// Smoothed local TX wire rate.
    pub delivery_rate_bytes_per_second: u64,
    /// Smoothed local offered (TUN ingress) rate.
    pub offered_rate_bytes_per_second: u64,
}

impl GuardrailContextV1 {
    /// Derive the context from the filtered telemetry of the current tick.
    pub fn from_filtered(filtered: &FilteredTelemetryV1) -> Self {
        let raw = &filtered.raw;
        let cover_suppression = if filtered.cpu_limited() {
            Some(ClampReasonV1::CpuPressure)
        } else if filtered.queue_inflated() || raw.packet_train_queue_bytes > 0 {
            Some(ClampReasonV1::QueuePressure)
        } else if raw.loss_ppm >= 5_000 {
            Some(ClampReasonV1::WireOverhead)
        } else if raw.real_traffic_bytes_per_second == 0 {
            Some(ClampReasonV1::InvalidValue)
        } else {
            None
        };
        Self {
            reliable: filtered.reliable(),
            cpu_limited: filtered.cpu_limited(),
            cpu_emergency: filtered.cpu_emergency(),
            protection_emergency: filtered.protection_emergency(),
            latency_queue_active: filtered.latency_queue_active(),
            cover_suppression,
            real_traffic_bytes_per_second: raw.real_traffic_bytes_per_second,
            rtt_micros: filtered.rtt_micros,
            delivery_rate_bytes_per_second: filtered.delivery_rate_bytes_per_second,
            offered_rate_bytes_per_second: filtered.tun_ingress_bytes_per_second,
        }
    }

    fn reliability(&self) -> PathReliability {
        if self.reliable {
            PathReliability::ReliableRelay
        } else {
            PathReliability::Datagram
        }
    }
}

/// Host guardrails parameterised by the static [`HostLimitsV1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailsV1 {
    limits: HostLimitsV1,
}

impl GuardrailsV1 {
    pub fn new(limits: HostLimitsV1) -> Self {
        Self { limits }
    }

    pub fn from_bounds(bounds: &AutoTuneBoundsV2) -> Self {
        Self::new(HostLimitsV1::from_bounds(bounds))
    }

    pub fn limits(&self) -> &HostLimitsV1 {
        &self.limits
    }

    /// Re-run every guardrail over an already effective action (the final
    /// pass of the pipeline). Equivalent to applying an empty candidate.
    pub fn reapply(
        &self,
        action: &EffectiveActionV1,
        ctx: &GuardrailContextV1,
    ) -> (EffectiveActionV1, ClampReportV1) {
        self.apply(&CandidateActionV1::default(), action, ctx)
    }

    /// Overlay `candidate` on `base`, then clamp every field the host does
    /// not accept as requested. `reason`, `path_epoch` and `sample_count`
    /// are inherited from `base`.
    pub fn apply(
        &self,
        candidate: &CandidateActionV1,
        base: &EffectiveActionV1,
        ctx: &GuardrailContextV1,
    ) -> (EffectiveActionV1, ClampReportV1) {
        let limits = &self.limits;
        let mut out = candidate.apply_over(base);
        let mut report = ClampReportV1::default();

        self.guard_bbr(&mut out, &mut report);
        self.guard_scheduler(candidate, base, ctx, &mut out, &mut report);
        self.guard_fec(candidate, base, ctx, &mut out, &mut report);
        self.guard_repair(candidate, ctx, &mut out, &mut report);
        self.guard_tx_rx(candidate, &mut out, &mut report);
        self.guard_cover(candidate, base, ctx, &mut out, &mut report);
        self.guard_egress(&mut out, &mut report);
        if candidate.extensions.len() > usize::from(limits.extension_count_cap) {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::Extension,
                i64::try_from(candidate.extensions.len()).unwrap_or(i64::MAX),
                i64::from(limits.extension_count_cap),
                ClampReasonV1::TooManyExtensions,
            ));
        }
        for extension in &candidate.extensions {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::Extension,
                i64::from(extension.tag),
                0,
                ClampReasonV1::Unsupported,
            ));
        }
        (out, report)
    }

    fn guard_bbr(&self, out: &mut EffectiveActionV1, report: &mut ClampReportV1) {
        // Every numeric knob is clamped to the range the BBR3 controller
        // accepts (`Bbr3Params::from_tunables`), so the effective action is
        // exactly what the data plane executes; the controller keeps its own
        // clamp as the second line of defence on the shared tunables.
        out.bbr.probe_bw_up_pacing_gain_milli = clamp_reported(
            ClampFieldV1::BbrProbeBwUpPacingGainMilli,
            u64::from(out.bbr.probe_bw_up_pacing_gain_milli),
            1_050,
            1_500,
            report,
        ) as u32;
        out.bbr.probe_bw_down_pacing_gain_milli = clamp_reported(
            ClampFieldV1::BbrProbeBwDownPacingGainMilli,
            u64::from(out.bbr.probe_bw_down_pacing_gain_milli),
            700,
            950,
            report,
        ) as u32;
        out.bbr.cruise_pacing_gain_milli = clamp_reported(
            ClampFieldV1::BbrCruisePacingGainMilli,
            u64::from(out.bbr.cruise_pacing_gain_milli),
            950,
            1_020,
            report,
        ) as u32;
        out.bbr.default_cwnd_gain_milli = clamp_reported(
            ClampFieldV1::BbrDefaultCwndGainMilli,
            u64::from(out.bbr.default_cwnd_gain_milli),
            1_200,
            3_000,
            report,
        ) as u32;
        out.bbr.probe_bw_up_cwnd_gain_milli = clamp_reported(
            ClampFieldV1::BbrProbeBwUpCwndGainMilli,
            u64::from(out.bbr.probe_bw_up_cwnd_gain_milli),
            1_500,
            3_500,
            report,
        ) as u32;
        out.bbr.headroom_milli = clamp_reported(
            ClampFieldV1::BbrHeadroomMilli,
            u64::from(out.bbr.headroom_milli),
            50,
            400,
            report,
        ) as u32;
        out.bbr.beta_milli = clamp_reported(
            ClampFieldV1::BbrBetaMilli,
            u64::from(out.bbr.beta_milli),
            500,
            900,
            report,
        ) as u32;
        out.bbr.loss_threshold_milli = clamp_reported(
            ClampFieldV1::BbrLossThresholdMilli,
            u64::from(out.bbr.loss_threshold_milli),
            5,
            100,
            report,
        ) as u32;
        out.bbr.queue_guard_inflation_milli = clamp_reported(
            ClampFieldV1::BbrQueueGuardInflationMilli,
            u64::from(out.bbr.queue_guard_inflation_milli),
            200,
            1_500,
            report,
        ) as u32;
        out.bbr.probe_rtt_cwnd_gain_milli = clamp_reported(
            ClampFieldV1::BbrProbeRttCwndGainMilli,
            u64::from(out.bbr.probe_rtt_cwnd_gain_milli),
            100,
            3_500,
            report,
        ) as u32;
        out.bbr.queue_guard_slack_micros = clamp_reported(
            ClampFieldV1::BbrQueueGuardSlackMicros,
            out.bbr.queue_guard_slack_micros,
            2_000,
            50_000,
            report,
        );
        out.bbr.probe_rtt_interval_millis = clamp_reported(
            ClampFieldV1::BbrProbeRttIntervalMillis,
            out.bbr.probe_rtt_interval_millis,
            2_000,
            30_000,
            report,
        );
        out.bbr.probe_rtt_duration_millis = clamp_reported(
            ClampFieldV1::BbrProbeRttDurationMillis,
            out.bbr.probe_rtt_duration_millis,
            100,
            500,
            report,
        );
        out.bbr.min_probe_wait_millis = clamp_reported(
            ClampFieldV1::BbrMinProbeWaitMillis,
            out.bbr.min_probe_wait_millis,
            1_000,
            10_000,
            report,
        );
        out.bbr.max_added_probe_wait_millis = clamp_reported(
            ClampFieldV1::BbrMaxAddedProbeWaitMillis,
            out.bbr.max_added_probe_wait_millis,
            0,
            5_000,
            report,
        );
        // A pacing cap below one maximum-size train per second would starve
        // the path; zero means uncapped (then the node cap applies).
        if out.bbr.pacing_cap_bytes_per_second != 0
            && out.bbr.pacing_cap_bytes_per_second < 64 * 1024
        {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::BbrPacingCapBytesPerSecond,
                i64_sat(out.bbr.pacing_cap_bytes_per_second),
                64 * 1024,
                ClampReasonV1::BelowFloor,
            ));
            out.bbr.pacing_cap_bytes_per_second = 64 * 1024;
        }
        let node_cap = self.limits.pacing_cap_bytes_per_second;
        let requested = out.bbr.pacing_cap_bytes_per_second;
        if node_cap != 0 && (requested == 0 || requested > node_cap) {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::BbrPacingCapBytesPerSecond,
                i64_sat(requested),
                i64_sat(node_cap),
                ClampReasonV1::AboveCap,
            ));
            out.bbr.pacing_cap_bytes_per_second = node_cap;
        }
        // A cwnd cap below four minimum MTUs is not a usable window; zero
        // means uncapped.
        if out.bbr.cwnd_cap_bytes != 0 && out.bbr.cwnd_cap_bytes < 4 * 1_200 {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::BbrCwndCapBytes,
                i64_sat(out.bbr.cwnd_cap_bytes),
                4 * 1_200,
                ClampReasonV1::BelowFloor,
            ));
            out.bbr.cwnd_cap_bytes = 4 * 1_200;
        }
        if out.bbr.cwnd_cap_bytes != 0 && out.bbr.cwnd_floor_bytes > out.bbr.cwnd_cap_bytes {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::BbrCwndFloorBytes,
                i64_sat(out.bbr.cwnd_floor_bytes),
                i64_sat(out.bbr.cwnd_cap_bytes),
                ClampReasonV1::CrossFieldConstraint,
            ));
            out.bbr.cwnd_floor_bytes = out.bbr.cwnd_cap_bytes;
        }
    }

    fn guard_scheduler(
        &self,
        candidate: &CandidateActionV1,
        base: &EffectiveActionV1,
        ctx: &GuardrailContextV1,
        out: &mut EffectiveActionV1,
        report: &mut ClampReportV1,
    ) {
        let limits = &self.limits;
        out.scheduler.train_target_bytes = clamp_reported(
            ClampFieldV1::SchedulerTrainTargetBytes,
            u64::from(out.scheduler.train_target_bytes),
            u64::from(limits.train_target_floor_bytes),
            u64::from(limits.train_target_cap_bytes),
            report,
        ) as u32;
        if ctx.latency_queue_active {
            if out.scheduler.bulk_quantum_cells != 1 {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::SchedulerBulkQuantumCells,
                    i64::from(out.scheduler.bulk_quantum_cells),
                    1,
                    ClampReasonV1::QueuePressure,
                ));
                out.scheduler.bulk_quantum_cells = 1;
            }
        } else {
            out.scheduler.bulk_quantum_cells = clamp_reported(
                ClampFieldV1::SchedulerBulkQuantumCells,
                u64::from(out.scheduler.bulk_quantum_cells),
                u64::from(limits.bulk_quantum_floor_cells.max(1)),
                u64::from(limits.bulk_quantum_cap_cells),
                report,
            ) as u16;
        }
        if ctx.cpu_emergency {
            if out.scheduler.train_target_bytes > base.scheduler.train_target_bytes {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::SchedulerTrainTargetBytes,
                    i64::from(out.scheduler.train_target_bytes),
                    i64::from(base.scheduler.train_target_bytes),
                    ClampReasonV1::CpuPressure,
                ));
                out.scheduler.train_target_bytes = base.scheduler.train_target_bytes;
            }
            if out.scheduler.bulk_quantum_cells > base.scheduler.bulk_quantum_cells {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::SchedulerBulkQuantumCells,
                    i64::from(out.scheduler.bulk_quantum_cells),
                    i64::from(base.scheduler.bulk_quantum_cells),
                    ClampReasonV1::CpuPressure,
                ));
                out.scheduler.bulk_quantum_cells = base.scheduler.bulk_quantum_cells;
            }
        }
        let requested = candidate.scheduler.as_ref();
        if out.scheduler.bulk_admission_window_bytes != 0 {
            if let Some(value) = requested.and_then(|s| s.bulk_admission_window_bytes) {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::SchedulerBulkAdmissionWindowBytes,
                    i64::from(value),
                    0,
                    ClampReasonV1::Unsupported,
                ));
            }
            out.scheduler.bulk_admission_window_bytes = 0;
        }
        if out.scheduler.preset_hint != SchedulerPresetHintV1::HostDefault {
            if let Some(value) = requested.and_then(|s| s.preset_hint) {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::SchedulerPresetHint,
                    enum_index(&SchedulerPresetHintV1::ALL, &value),
                    0,
                    ClampReasonV1::Unsupported,
                ));
            }
            out.scheduler.preset_hint = SchedulerPresetHintV1::HostDefault;
        }
    }

    fn guard_fec(
        &self,
        candidate: &CandidateActionV1,
        base: &EffectiveActionV1,
        ctx: &GuardrailContextV1,
        out: &mut EffectiveActionV1,
        report: &mut ClampReportV1,
    ) {
        let limits = &self.limits;
        let requested_off = candidate
            .fec
            .as_ref()
            .is_some_and(|fec| fec.enabled == Some(false));
        // A preset family without explicit cell counts resolves through the
        // host geometry table, on the pass that requests it. The recorded
        // family is whatever the overlay left in `out.fec` (the candidate's
        // when set, otherwise the base's), so an empty re-pass is a fixed
        // point.
        let mut family = out.fec.preset_family;
        let family_requested = candidate
            .fec
            .as_ref()
            .and_then(|fec| fec.preset_family)
            .is_some_and(|requested| requested != FecPresetFamilyV1::Unspecified);
        if family_requested
            && candidate
                .fec
                .as_ref()
                .is_some_and(|fec| fec.data_cells.is_none() && fec.parity_cells.is_none())
            && let Some((data, parity)) = fec_family_geometry(family)
        {
            out.fec.data_cells = data;
            out.fec.parity_cells = parity;
        }
        let mut geometry = out.fec.to_geometry();
        if ctx.reliable || ctx.cpu_limited {
            if geometry.is_some() {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::FecEnabled,
                    1,
                    0,
                    if ctx.reliable {
                        ClampReasonV1::ReliableUnderlay
                    } else {
                        ClampReasonV1::CpuPressure
                    },
                ));
                geometry = None;
            }
        } else if ctx.protection_emergency && requested_off && base.fec.enabled {
            // Emergency protection is a guardrail, not a policy choice: the
            // base geometry comes back with the base's own family hint.
            geometry = base.fec.to_geometry();
            family = base.fec.preset_family;
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::FecEnabled,
                0,
                1,
                ClampReasonV1::BelowFloor,
            ));
        } else if let Some(requested) = geometry {
            let data = requested.data_cells;
            let parity = requested.parity_cells;
            let violation = if data < 2 || data > usize::from(limits.fec_data_cells_cap) {
                Some((
                    ClampFieldV1::FecDataCells,
                    data,
                    ClampReasonV1::InvalidValue,
                ))
            } else if parity > usize::from(limits.fec_parity_cells_cap) {
                Some((
                    ClampFieldV1::FecParityCells,
                    parity,
                    ClampReasonV1::AboveCap,
                ))
            } else if parity.saturating_mul(1_000)
                > data.saturating_mul(usize::from(limits.fec_parity_per_mille_cap))
            {
                Some((
                    ClampFieldV1::FecParityCells,
                    parity,
                    ClampReasonV1::CrossFieldConstraint,
                ))
            } else {
                None
            };
            if let Some((field, requested, reason)) = violation {
                report.entries.push(ClampEntryV1::new(
                    field,
                    i64::try_from(requested).unwrap_or(i64::MAX),
                    0,
                    reason,
                ));
                geometry = None;
            }
        }
        // Canonical form: disabled protection carries zero cells and no
        // family hint, so equal geometries compare equal downstream. An
        // enabled geometry keeps the family the candidate asked for.
        let mut fec = FecEffectiveV1::from_geometry(geometry);
        if geometry.is_some() {
            fec.preset_family = family;
        }
        out.fec = fec;
    }

    fn guard_repair(
        &self,
        candidate: &CandidateActionV1,
        ctx: &GuardrailContextV1,
        out: &mut EffectiveActionV1,
        report: &mut ClampReportV1,
    ) {
        let cache = u64::try_from(repair_cache_target_bytes(
            ctx.reliability(),
            out.fec.to_geometry(),
            ctx.rtt_micros,
            ctx.delivery_rate_bytes_per_second,
            ctx.offered_rate_bytes_per_second,
        ))
        .unwrap_or(u64::MAX);
        let requested = candidate.repair.as_ref();
        if let Some(value) = requested.and_then(|r| r.cache_bytes)
            && value != cache
        {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::RepairCacheBytes,
                i64_sat(value),
                i64_sat(cache),
                ClampReasonV1::Unsupported,
            ));
        }
        out.repair.cache_bytes = cache;
        // Retention is open (0 = host default TTL) but capped: a guest may
        // not pin the repair cache forever.
        if out.repair.retention_target_millis != 0
            && out.repair.retention_target_millis > REPAIR_RETENTION_CAP_MILLIS
        {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::RepairRetentionTargetMillis,
                i64::from(out.repair.retention_target_millis),
                i64::from(REPAIR_RETENTION_CAP_MILLIS),
                ClampReasonV1::AboveCap,
            ));
            out.repair.retention_target_millis = REPAIR_RETENTION_CAP_MILLIS;
        }
        // The wait policy is a closed enum and passes through; the host maps
        // it onto the Repair request minimum age.
        if out.repair.responsibility != ProtectionResponsibilityV1::HostDefault {
            if let Some(value) = requested.and_then(|r| r.responsibility) {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::RepairResponsibility,
                    enum_index(&ProtectionResponsibilityV1::ALL, &value),
                    0,
                    ClampReasonV1::Unsupported,
                ));
            }
            out.repair.responsibility = ProtectionResponsibilityV1::HostDefault;
        }
    }

    fn guard_tx_rx(
        &self,
        candidate: &CandidateActionV1,
        out: &mut EffectiveActionV1,
        report: &mut ClampReportV1,
    ) {
        let limits = &self.limits;
        out.tx.send_buffer_bytes = clamp_reported(
            ClampFieldV1::TxSendBufferBytes,
            out.tx.send_buffer_bytes,
            limits.send_buffer_floor_bytes,
            limits.send_buffer_cap_bytes,
            report,
        );
        if out.tx.datagram_admission_bytes != 0 {
            if let Some(value) = candidate
                .tx
                .as_ref()
                .and_then(|tx| tx.datagram_admission_bytes)
            {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::TxDatagramAdmissionBytes,
                    i64::from(value),
                    0,
                    ClampReasonV1::Unsupported,
                ));
            }
            out.tx.datagram_admission_bytes = 0;
        }
        if out.tx.producer_window_bytes != 0 {
            if let Some(value) = candidate
                .tx
                .as_ref()
                .and_then(|tx| tx.producer_window_bytes)
            {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::TxProducerWindowBytes,
                    i64_sat(value),
                    0,
                    ClampReasonV1::Unsupported,
                ));
            }
            out.tx.producer_window_bytes = 0;
        }
        out.rx.receive_buffer_bytes = clamp_reported(
            ClampFieldV1::RxReceiveBufferBytes,
            out.rx.receive_buffer_bytes,
            limits.receive_buffer_floor_bytes,
            limits.receive_buffer_cap_bytes,
            report,
        );
        out.rx.receive_batch = clamp_reported(
            ClampFieldV1::RxReceiveBatch,
            u64::from(out.rx.receive_batch),
            1,
            u64::from(limits.receive_batch_cap.max(1)),
            report,
        ) as u16;
        // The reassembly budget is open (0 = follow the receive buffer) but
        // bounded twice: it must hold at least one maximum-size train and it
        // may never exceed the effective receive buffer, so an explicit
        // budget can only shrink the RX memory footprint, never grow it.
        if out.rx.reassembly_budget_bytes != 0 {
            let cap = limits
                .receive_buffer_cap_bytes
                .min(out.rx.receive_buffer_bytes);
            let floor = REASSEMBLY_BUDGET_FLOOR_BYTES.min(cap);
            out.rx.reassembly_budget_bytes = clamp_reported(
                ClampFieldV1::RxReassemblyBudgetBytes,
                out.rx.reassembly_budget_bytes,
                floor,
                cap,
                report,
            );
        }
        // The active-train budget is open (0 = negotiated wire limit) and
        // capped by that same wire limit.
        if out.rx.active_train_budget != 0 {
            out.rx.active_train_budget = clamp_reported(
                ClampFieldV1::RxActiveTrainBudget,
                u64::from(out.rx.active_train_budget),
                1,
                u64::from(ACTIVE_TRAIN_BUDGET_CAP),
                report,
            ) as u16;
        }
    }

    fn guard_cover(
        &self,
        candidate: &CandidateActionV1,
        base: &EffectiveActionV1,
        ctx: &GuardrailContextV1,
        out: &mut EffectiveActionV1,
        report: &mut ClampReportV1,
    ) {
        let cap = self.limits.cover_overhead_cap_per_mille;
        let requested = out.cover.overhead_per_mille;
        let clamp_overhead = |out: &mut EffectiveActionV1,
                              report: &mut ClampReportV1,
                              effective: u16,
                              reason: ClampReasonV1| {
            if out.cover.overhead_per_mille != effective {
                report.entries.push(ClampEntryV1::new(
                    ClampFieldV1::CoverOverheadPerMille,
                    i64::from(requested),
                    i64::from(effective),
                    reason,
                ));
                out.cover.overhead_per_mille = effective;
            }
        };
        if let Some(reason) = ctx.cover_suppression {
            clamp_overhead(out, report, 0, reason);
        } else if base.cover.overhead_per_mille == 0 {
            // The host already suppressed cover on the baseline this
            // candidate is applied over; a candidate cannot re-enable it.
            clamp_overhead(out, report, 0, ClampReasonV1::AboveCap);
        } else if out.cover.overhead_per_mille > cap {
            clamp_overhead(out, report, cap, ClampReasonV1::AboveCap);
        }
        if out.cover.profile == CoverProfileV1::Idle {
            clamp_overhead(out, report, 0, ClampReasonV1::CrossFieldConstraint);
        }
        let padding = ctx
            .real_traffic_bytes_per_second
            .saturating_mul(u64::from(out.cover.overhead_per_mille))
            / 1_000;
        if let Some(value) = candidate
            .cover
            .as_ref()
            .and_then(|cover| cover.padding_bytes_per_second)
            && value != padding
        {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::CoverPaddingBytesPerSecond,
                i64_sat(value),
                i64_sat(padding),
                ClampReasonV1::CrossFieldConstraint,
            ));
        }
        out.cover.padding_bytes_per_second = padding;
    }

    fn guard_egress(&self, out: &mut EffectiveActionV1, report: &mut ClampReportV1) {
        let cap = self.limits.egress_priority_cap;
        if out.egress.priority > cap {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::EgressPriority,
                i64::from(out.egress.priority),
                i64::from(cap),
                ClampReasonV1::AboveCap,
            ));
            out.egress.priority = cap;
        }
        if out.egress.desired_rate_bytes_per_second != 0
            && out.egress.minimum_rate_bytes_per_second > out.egress.desired_rate_bytes_per_second
        {
            report.entries.push(ClampEntryV1::new(
                ClampFieldV1::EgressMinimumRateBytesPerSecond,
                i64_sat(out.egress.minimum_rate_bytes_per_second),
                i64_sat(out.egress.desired_rate_bytes_per_second),
                ClampReasonV1::CrossFieldConstraint,
            ));
            out.egress.minimum_rate_bytes_per_second = out.egress.desired_rate_bytes_per_second;
        }
    }
}

/// `value` clamped to `[floor, cap]` (`cap == 0` means no cap), recording a
/// clamp entry when the value moved.
fn clamp_reported(
    field: ClampFieldV1,
    value: u64,
    floor: u64,
    cap: u64,
    report: &mut ClampReportV1,
) -> u64 {
    if value < floor {
        report.entries.push(ClampEntryV1::new(
            field,
            i64_sat(value),
            i64_sat(floor),
            ClampReasonV1::BelowFloor,
        ));
        floor
    } else if cap != 0 && value > cap {
        report.entries.push(ClampEntryV1::new(
            field,
            i64_sat(value),
            i64_sat(cap),
            ClampReasonV1::AboveCap,
        ));
        cap
    } else {
        value
    }
}

fn i64_sat(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn enum_index<T: PartialEq>(all: &[T], value: &T) -> i64 {
    all.iter()
        .position(|candidate| candidate == value)
        .map_or(-1, |index| i64::try_from(index).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::{
        fec::FecGeometryV2,
        tuning::{RepairWaitPolicyV2, TuneDecisionV2, TuneReasonV2},
    };

    /// Small deterministic generator so the property tests need no extra
    /// dependency and reproduce from a fixed seed.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound.max(1)
        }

        fn chance(&mut self, per_cent: u64) -> bool {
            self.below(100) < per_cent
        }

        fn option<T>(&mut self, value: impl FnOnce(&mut Self) -> T) -> Option<T> {
            if self.chance(75) {
                Some(value(self))
            } else {
                None
            }
        }

        fn pick<T: Copy>(&mut self, all: &[T]) -> T {
            all[self.below(all.len() as u64) as usize]
        }
    }

    fn limits() -> HostLimitsV1 {
        HostLimitsV1::from_bounds(&AutoTuneBoundsV2::default())
    }

    fn context() -> GuardrailContextV1 {
        GuardrailContextV1 {
            reliable: false,
            cpu_limited: false,
            cpu_emergency: false,
            protection_emergency: false,
            latency_queue_active: false,
            cover_suppression: None,
            real_traffic_bytes_per_second: 10_000_000,
            rtt_micros: 30_000,
            delivery_rate_bytes_per_second: 10_000_000,
            offered_rate_bytes_per_second: 9_000_000,
        }
    }

    fn random_context(rng: &mut Rng) -> GuardrailContextV1 {
        let cpu_limited = rng.chance(20);
        // `from_filtered` always suppresses cover under CPU pressure; keep
        // the random contexts inside that invariant.
        let cover_suppression = if cpu_limited {
            Some(ClampReasonV1::CpuPressure)
        } else {
            rng.chance(30).then(|| rng.pick(&ClampReasonV1::ALL))
        };
        GuardrailContextV1 {
            reliable: rng.chance(20),
            cpu_limited,
            cpu_emergency: rng.chance(20),
            protection_emergency: rng.chance(30),
            latency_queue_active: rng.chance(30),
            cover_suppression,
            real_traffic_bytes_per_second: rng.below(200_000_000),
            rtt_micros: rng.below(400_000),
            delivery_rate_bytes_per_second: rng.below(200_000_000),
            offered_rate_bytes_per_second: rng.below(200_000_000),
        }
    }

    fn base() -> EffectiveActionV1 {
        EffectiveActionV1::from_tune_decision(&TuneDecisionV2 {
            reason: TuneReasonV2::HealthyLowLoss,
            path_epoch: 3,
            sample_count: 9,
            train_target_bytes: 32 * 1024,
            bulk_quantum_cells: 2,
            fec: Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            }),
            repair_cache_bytes: 4 * 1024 * 1024,
            send_buffer_bytes: 1024 * 1024,
            receive_buffer_bytes: 16 * 1024 * 1024,
            receive_batch: 32,
            cover_profile: CoverProfileV1::InteractiveVideo.into(),
            cover_overhead_per_mille: 30,
            cover_padding_bytes_per_second: 300_000,
            repair_retention_millis: 0,
            repair_wait_policy: RepairWaitPolicyV2::HostDefault,
            reassembly_budget_bytes: 0,
            active_train_budget: 0,
            bbr: BbrEffectiveV1::default().to_proposal(),
        })
    }

    fn random_candidate(rng: &mut Rng) -> CandidateActionV1 {
        let wide = |rng: &mut Rng, bound: u64| -> u64 {
            match rng.below(4) {
                0 => 0,
                1 => rng.below(bound),
                2 => rng.below(bound.saturating_mul(4)),
                _ => u64::MAX - rng.below(1_000),
            }
        };
        CandidateActionV1 {
            bbr: rng.chance(60).then(|| BbrCandidateV1 {
                preset: rng.option(|r| r.pick(&Bbr3PresetV1::ALL)),
                probe_bw_up_pacing_gain_milli: rng.option(|r| r.below(4_000) as u32),
                headroom_milli: rng.option(|r| r.below(2_000) as u32),
                default_cwnd_gain_milli: rng.option(|r| r.below(4_000) as u32),
                pacing_cap_bytes_per_second: rng.option(|r| wide(r, 100_000_000)),
                cwnd_floor_bytes: rng.option(|r| wide(r, 8_000_000)),
                cwnd_cap_bytes: rng.option(|r| wide(r, 8_000_000)),
                ..BbrCandidateV1::default()
            }),
            scheduler: rng.chance(75).then(|| SchedulerCandidateV1 {
                train_target_bytes: rng.option(|r| wide(r, 128 * 1024) as u32),
                bulk_quantum_cells: rng.option(|r| r.below(12) as u16),
                bulk_admission_window_bytes: rng.option(|r| r.below(1 << 20) as u32),
                preset_hint: rng.option(|r| r.pick(&SchedulerPresetHintV1::ALL)),
            }),
            fec: rng.chance(75).then(|| FecCandidateV1 {
                enabled: rng.option(|r| r.chance(70)),
                data_cells: rng.option(|r| r.below(40) as u8),
                parity_cells: rng.option(|r| r.below(16) as u8),
                preset_family: rng.option(|r| r.pick(&FecPresetFamilyV1::ALL)),
            }),
            repair: rng.chance(50).then(|| RepairCandidateV1 {
                cache_bytes: rng.option(|r| wide(r, 64 << 20)),
                retention_target_millis: rng.option(|r| wide(r, 120_000) as u32),
                wait_policy: rng.option(|r| r.pick(&RepairWaitPolicyV1::ALL)),
                responsibility: rng.option(|r| r.pick(&ProtectionResponsibilityV1::ALL)),
            }),
            tx: rng.chance(75).then(|| TxCandidateV1 {
                send_buffer_bytes: rng.option(|r| wide(r, 64 << 20)),
                datagram_admission_bytes: rng.option(|r| r.below(1 << 20) as u32),
                producer_window_bytes: rng.option(|r| wide(r, 1 << 20)),
            }),
            rx: rng.chance(75).then(|| RxCandidateV1 {
                receive_buffer_bytes: rng.option(|r| wide(r, 64 << 20)),
                receive_batch: rng.option(|r| r.below(300) as u16),
                reassembly_budget_bytes: rng.option(|r| wide(r, 64 << 20)),
                active_train_budget: rng.option(|r| wide(r, 2_000) as u16),
            }),
            cover: rng.chance(75).then(|| CoverCandidateV1 {
                profile: rng.option(|r| r.pick(&CoverProfileV1::ALL)),
                overhead_per_mille: rng.option(|r| r.below(1_200) as u16),
                padding_bytes_per_second: rng.option(|r| wide(r, 10_000_000)),
            }),
            egress_request: rng.chance(30).then(|| EgressRequestV1 {
                desired_rate_bytes_per_second: wide(rng, 100_000_000),
                minimum_rate_bytes_per_second: wide(rng, 100_000_000),
                priority: rng.below(20) as u8,
                exploring: rng.chance(50),
            }),
            extensions: Vec::new(),
        }
    }

    const CASES: u64 = 4_000;

    fn for_each_case(
        mut check: impl FnMut(
            &CandidateActionV1,
            &GuardrailContextV1,
            &EffectiveActionV1,
            &ClampReportV1,
        ),
    ) {
        let guardrails = GuardrailsV1::new(limits());
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let base = base();
        for _ in 0..CASES {
            let candidate = random_candidate(&mut rng);
            let ctx = random_context(&mut rng);
            let (effective, report) = guardrails.apply(&candidate, &base, &ctx);
            check(&candidate, &ctx, &effective, &report);
        }
    }

    #[test]
    fn property_effective_is_within_hard_bounds() {
        let limits = limits();
        for_each_case(|_, _, effective, _| {
            let train = effective.scheduler.train_target_bytes;
            assert!(
                train >= limits.train_target_floor_bytes && train <= limits.train_target_cap_bytes
            );
            let quantum = effective.scheduler.bulk_quantum_cells;
            assert!(quantum >= 1 && quantum <= limits.bulk_quantum_cap_cells);
            let send = effective.tx.send_buffer_bytes;
            assert!(send >= limits.send_buffer_floor_bytes && send <= limits.send_buffer_cap_bytes);
            let batch = effective.rx.receive_batch;
            assert!(batch >= 1 && batch <= limits.receive_batch_cap);
            assert!(effective.cover.overhead_per_mille <= limits.cover_overhead_cap_per_mille);
            assert!(effective.egress.priority <= limits.egress_priority_cap);
            assert!(effective.repair.retention_target_millis <= REPAIR_RETENTION_CAP_MILLIS);
            assert!(
                effective.egress.desired_rate_bytes_per_second == 0
                    || effective.egress.minimum_rate_bytes_per_second
                        <= effective.egress.desired_rate_bytes_per_second
            );
        });
    }

    #[test]
    fn property_cwnd_floor_never_exceeds_cap() {
        for_each_case(|_, _, effective, _| {
            assert!(
                effective.bbr.cwnd_cap_bytes == 0
                    || effective.bbr.cwnd_floor_bytes <= effective.bbr.cwnd_cap_bytes
            );
        });
    }

    #[test]
    fn property_fec_geometry_is_valid_and_within_wire_overhead() {
        let limits = limits();
        for_each_case(|_, _, effective, _| {
            if let Some(geometry) = effective.fec.to_geometry() {
                assert!(geometry.validate().is_ok());
                assert!(geometry.data_cells <= usize::from(limits.fec_data_cells_cap));
                assert!(geometry.parity_cells <= usize::from(limits.fec_parity_cells_cap));
                assert!(
                    geometry.parity_cells * 1_000
                        <= geometry.data_cells * usize::from(limits.fec_parity_per_mille_cap)
                );
                assert!(effective.fec.enabled);
            } else {
                // Canonical disabled form.
                assert_eq!(effective.fec, FecEffectiveV1::default());
            }
        });
    }

    #[test]
    fn property_reliable_underlay_forces_fec_off() {
        let base = base();
        for_each_case(|candidate, ctx, effective, report| {
            if ctx.reliable {
                assert!(!effective.fec.enabled);
                assert_eq!(effective.repair.cache_bytes, 1024 * 1024);
                if candidate.apply_over(&base).fec.enabled {
                    assert!(report.entries.iter().any(|entry| {
                        entry.field == ClampFieldV1::FecEnabled
                            && entry.reason == ClampReasonV1::ReliableUnderlay
                    }));
                }
            }
        });
    }

    #[test]
    fn property_cpu_and_queue_emergencies_dominate_the_candidate() {
        let base = base();
        for_each_case(|_, ctx, effective, _| {
            if ctx.cpu_limited {
                assert!(!effective.fec.enabled, "CPU pressure suppresses parity");
                assert_eq!(effective.cover.overhead_per_mille, 0);
            }
            if ctx.cpu_emergency {
                assert!(
                    effective.scheduler.train_target_bytes <= base.scheduler.train_target_bytes
                );
                assert!(
                    effective.scheduler.bulk_quantum_cells <= base.scheduler.bulk_quantum_cells
                );
            }
            if ctx.latency_queue_active {
                assert_eq!(effective.scheduler.bulk_quantum_cells, 1);
            }
            if ctx.cover_suppression.is_some() {
                assert_eq!(effective.cover.overhead_per_mille, 0);
                assert_eq!(effective.cover.padding_bytes_per_second, 0);
            }
        });
    }

    #[test]
    fn property_emergency_protection_cannot_be_switched_off() {
        let base = base();
        for_each_case(|candidate, ctx, effective, _| {
            let requested_off = candidate
                .fec
                .as_ref()
                .is_some_and(|fec| fec.enabled == Some(false));
            if ctx.protection_emergency && requested_off && !ctx.reliable && !ctx.cpu_limited {
                assert_eq!(effective.fec, base.fec);
            }
        });
    }

    #[test]
    fn property_receive_memory_stays_within_local_budget() {
        let limits = limits();
        for_each_case(|_, _, effective, _| {
            assert!(effective.rx.receive_buffer_bytes >= limits.receive_buffer_floor_bytes);
            assert!(effective.rx.receive_buffer_bytes <= limits.receive_buffer_cap_bytes);
            // An explicit reassembly budget can only shrink the RX memory
            // footprint below the effective receive buffer, never grow it.
            let budget = effective.rx.reassembly_budget_bytes;
            if budget != 0 {
                assert!(
                    budget >= REASSEMBLY_BUDGET_FLOOR_BYTES.min(effective.rx.receive_buffer_bytes)
                );
                assert!(budget <= effective.rx.receive_buffer_bytes);
            }
            assert!(effective.rx.active_train_budget <= ACTIVE_TRAIN_BUDGET_CAP);
            assert!(effective.repair.cache_bytes <= limits.repair_cache_cap_bytes);
        });
    }

    #[test]
    fn property_cover_is_host_derived_and_within_budget() {
        let limits = limits();
        for_each_case(|_, ctx, effective, _| {
            assert!(effective.cover.overhead_per_mille <= limits.cover_overhead_cap_per_mille);
            assert_eq!(
                effective.cover.padding_bytes_per_second,
                ctx.real_traffic_bytes_per_second
                    .saturating_mul(u64::from(effective.cover.overhead_per_mille))
                    / 1_000
            );
            if effective.cover.profile == CoverProfileV1::Idle {
                assert_eq!(effective.cover.overhead_per_mille, 0);
            }
        });
    }

    #[test]
    fn property_apply_is_idempotent_and_report_is_honest() {
        let guardrails = GuardrailsV1::new(limits());
        let base = base();
        for_each_case(|candidate, ctx, effective, report| {
            let (again, again_report) = guardrails.reapply(effective, ctx);
            assert_eq!(&again, effective, "final pass must be a fixed point");
            assert!(again_report.is_empty(), "{again_report:?}");
            // An empty report means the candidate was accepted verbatim over
            // the base, apart from the host-derived fields.
            if report.is_empty() {
                let mut overlay = candidate.apply_over(&base);
                overlay.repair.cache_bytes = effective.repair.cache_bytes;
                overlay.cover.padding_bytes_per_second = effective.cover.padding_bytes_per_second;
                // Host normalization of the FEC domain: an explicit preset
                // family without cell counts resolves through the host
                // geometry table, and the canonical form keeps the family
                // hint only while protection is on.
                if let Some(fec) = &candidate.fec
                    && let Some(requested) = fec.preset_family
                    && requested != FecPresetFamilyV1::Unspecified
                    && fec.data_cells.is_none()
                    && fec.parity_cells.is_none()
                    && let Some((data, parity)) = fec_family_geometry(requested)
                {
                    overlay.fec.data_cells = data;
                    overlay.fec.parity_cells = parity;
                }
                let family = overlay.fec.preset_family;
                overlay.fec = FecEffectiveV1::from_geometry(overlay.fec.to_geometry());
                if overlay.fec.enabled {
                    overlay.fec.preset_family = family;
                }
                assert_eq!(&overlay, effective);
            }
            assert_eq!(effective.reason, base.reason);
            assert_eq!(effective.path_epoch, base.path_epoch);
            assert_eq!(effective.sample_count, base.sample_count);
        });
    }

    #[test]
    fn empty_candidate_over_a_guarded_base_is_identity() {
        let guardrails = GuardrailsV1::new(limits());
        let ctx = context();
        let (effective, report) = guardrails.apply(&CandidateActionV1::default(), &base(), &ctx);
        assert!(report.is_empty(), "{report:?}");
        let mut expected = base();
        expected.repair.cache_bytes = u64::try_from(repair_cache_target_bytes(
            PathReliability::Datagram,
            expected.fec.to_geometry(),
            ctx.rtt_micros,
            ctx.delivery_rate_bytes_per_second,
            ctx.offered_rate_bytes_per_second,
        ))
        .unwrap();
        assert_eq!(effective, expected);
    }

    #[test]
    fn invalid_geometry_is_rejected_not_repaired() {
        let guardrails = GuardrailsV1::new(limits());
        let maximum_ratio = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(true),
                data_cells: Some(4),
                parity_cells: Some(4),
                preset_family: None,
            }),
            ..CandidateActionV1::default()
        };
        let (effective, report) = guardrails.apply(&maximum_ratio, &base(), &context());
        assert!(effective.fec.enabled);
        assert_eq!(effective.fec.data_cells, 4);
        assert_eq!(effective.fec.parity_cells, 4);
        assert!(report.entries.iter().all(|entry| {
            entry.field != ClampFieldV1::FecParityCells
                || entry.reason != ClampReasonV1::CrossFieldConstraint
        }));

        let candidate = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(true),
                data_cells: Some(4),
                parity_cells: Some(5),
                preset_family: None,
            }),
            ..CandidateActionV1::default()
        };
        let (effective, report) = guardrails.apply(&candidate, &base(), &context());
        assert!(!effective.fec.enabled);
        assert_eq!(effective.repair.cache_bytes, 0);
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::FecParityCells
                && entry.reason == ClampReasonV1::CrossFieldConstraint
        }));
    }

    #[test]
    fn suppressed_base_cover_cannot_be_raised() {
        let guardrails = GuardrailsV1::new(limits());
        let mut base = base();
        base.cover.overhead_per_mille = 0;
        let candidate = CandidateActionV1 {
            cover: Some(CoverCandidateV1 {
                profile: Some(CoverProfileV1::LiveBroadcast),
                overhead_per_mille: Some(40),
                padding_bytes_per_second: None,
            }),
            ..CandidateActionV1::default()
        };
        let (effective, report) = guardrails.apply(&candidate, &base, &context());
        assert_eq!(effective.cover.profile, CoverProfileV1::LiveBroadcast);
        assert_eq!(effective.cover.overhead_per_mille, 0);
        assert_eq!(effective.cover.padding_bytes_per_second, 0);
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::CoverOverheadPerMille && entry.requested == 40
        }));
    }

    #[test]
    fn fec_preset_family_resolves_through_host_geometry_table() {
        let guardrails = GuardrailsV1::new(limits());
        let candidate = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: None,
                data_cells: None,
                parity_cells: None,
                preset_family: Some(FecPresetFamilyV1::Balanced),
            }),
            ..CandidateActionV1::default()
        };
        let (effective, _) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(effective.fec.data_cells, 8);
        assert_eq!(effective.fec.parity_cells, 2);
        assert_eq!(effective.fec.preset_family, FecPresetFamilyV1::Balanced);
        // The resolved geometry is a fixed point for the final pass.
        let (again, again_report) = guardrails.reapply(&effective, &context());
        assert_eq!(again, effective);
        assert!(again_report.is_empty(), "{again_report:?}");
    }

    #[test]
    fn fec_explicit_cells_win_over_preset_family() {
        let guardrails = GuardrailsV1::new(limits());
        let candidate = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(true),
                data_cells: Some(4),
                parity_cells: Some(1),
                preset_family: Some(FecPresetFamilyV1::Dense),
            }),
            ..CandidateActionV1::default()
        };
        let (effective, _) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(effective.fec.data_cells, 4);
        assert_eq!(effective.fec.parity_cells, 1);
        assert_eq!(effective.fec.preset_family, FecPresetFamilyV1::Dense);
    }

    #[test]
    fn fec_family_enables_protection_over_a_disabled_base() {
        let guardrails = GuardrailsV1::new(limits());
        let mut base = base();
        base.fec = FecEffectiveV1::default();
        let candidate = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(true),
                data_cells: None,
                parity_cells: None,
                preset_family: Some(FecPresetFamilyV1::Sparse),
            }),
            ..CandidateActionV1::default()
        };
        let (effective, _) = guardrails.apply(&candidate, &base, &context());
        assert!(effective.fec.enabled);
        assert_eq!(effective.fec.data_cells, 16);
        assert_eq!(effective.fec.parity_cells, 1);
        assert_eq!(effective.fec.preset_family, FecPresetFamilyV1::Sparse);
    }

    #[test]
    fn disabled_fec_carries_no_family_hint() {
        let guardrails = GuardrailsV1::new(limits());
        let candidate = CandidateActionV1 {
            fec: Some(FecCandidateV1 {
                enabled: Some(false),
                data_cells: None,
                parity_cells: None,
                preset_family: Some(FecPresetFamilyV1::Dense),
            }),
            ..CandidateActionV1::default()
        };
        let (effective, _) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(effective.fec, FecEffectiveV1::default());
    }

    #[test]
    fn repair_retention_is_capped_and_wait_policy_passes_through() {
        let guardrails = GuardrailsV1::new(limits());
        let candidate = CandidateActionV1 {
            repair: Some(RepairCandidateV1 {
                cache_bytes: None,
                retention_target_millis: Some(120_000),
                wait_policy: Some(RepairWaitPolicyV1::Patient),
                responsibility: None,
            }),
            ..CandidateActionV1::default()
        };
        let (effective, report) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(
            effective.repair.retention_target_millis,
            REPAIR_RETENTION_CAP_MILLIS
        );
        assert_eq!(effective.repair.wait_policy, RepairWaitPolicyV1::Patient);
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::RepairRetentionTargetMillis
                && entry.reason == ClampReasonV1::AboveCap
        }));
        // A retention inside the cap passes through untouched.
        let candidate = CandidateActionV1 {
            repair: Some(RepairCandidateV1 {
                cache_bytes: None,
                retention_target_millis: Some(5_000),
                wait_policy: Some(RepairWaitPolicyV1::Eager),
                responsibility: None,
            }),
            ..CandidateActionV1::default()
        };
        let (effective, _) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(effective.repair.retention_target_millis, 5_000);
        assert_eq!(effective.repair.wait_policy, RepairWaitPolicyV1::Eager);
    }

    #[test]
    fn reassembly_budget_never_exceeds_the_effective_receive_buffer() {
        let guardrails = GuardrailsV1::new(limits());
        // The base carries a 16 MiB receive buffer.
        let candidate = CandidateActionV1 {
            rx: Some(RxCandidateV1 {
                receive_buffer_bytes: None,
                receive_batch: None,
                reassembly_budget_bytes: Some(32 * 1024 * 1024),
                active_train_budget: None,
            }),
            ..CandidateActionV1::default()
        };
        let (effective, report) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(effective.rx.receive_buffer_bytes, 16 * 1024 * 1024);
        assert_eq!(
            effective.rx.reassembly_budget_bytes,
            16 * 1024 * 1024,
            "the budget clamps down to the effective receive buffer"
        );
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::RxReassemblyBudgetBytes
                && entry.reason == ClampReasonV1::AboveCap
        }));
        // Below the floor the budget rises to hold one maximum-size train.
        let candidate = CandidateActionV1 {
            rx: Some(RxCandidateV1 {
                receive_buffer_bytes: None,
                receive_batch: None,
                reassembly_budget_bytes: Some(512 * 1024),
                active_train_budget: None,
            }),
            ..CandidateActionV1::default()
        };
        let (effective, report) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(
            effective.rx.reassembly_budget_bytes,
            REASSEMBLY_BUDGET_FLOOR_BYTES
        );
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::RxReassemblyBudgetBytes
                && entry.reason == ClampReasonV1::BelowFloor
        }));
        // Zero follows the receive buffer and reports nothing.
        let (effective, report) =
            guardrails.apply(&CandidateActionV1::default(), &base(), &context());
        assert_eq!(effective.rx.reassembly_budget_bytes, 0);
        assert!(report.is_empty(), "{report:?}");
    }

    #[test]
    fn active_train_budget_is_capped_by_the_wire_limit() {
        let guardrails = GuardrailsV1::new(limits());
        let candidate = CandidateActionV1 {
            rx: Some(RxCandidateV1 {
                receive_buffer_bytes: None,
                receive_batch: None,
                reassembly_budget_bytes: None,
                active_train_budget: Some(2_000),
            }),
            ..CandidateActionV1::default()
        };
        let (effective, report) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(effective.rx.active_train_budget, ACTIVE_TRAIN_BUDGET_CAP);
        assert!(report.entries.iter().any(|entry| {
            entry.field == ClampFieldV1::RxActiveTrainBudget
                && entry.reason == ClampReasonV1::AboveCap
        }));
        let candidate = CandidateActionV1 {
            rx: Some(RxCandidateV1 {
                receive_buffer_bytes: None,
                receive_batch: None,
                reassembly_budget_bytes: None,
                active_train_budget: Some(64),
            }),
            ..CandidateActionV1::default()
        };
        let (effective, _) = guardrails.apply(&candidate, &base(), &context());
        assert_eq!(effective.rx.active_train_budget, 64);
    }
}
