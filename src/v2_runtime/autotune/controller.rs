//! BBR effective-action finalization and adaptive congestion-window floor.

use super::*;

const ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES: u64 = 16 * 1024;
const ADAPTIVE_CWND_FLOOR_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub(in crate::v2_runtime) const LOW_RTT_CWND_FLOOR_BYTES: u64 = 512 * 1024;
pub(super) const CAPACITY_PROBE_EDGE_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum AdaptiveCwndFloorModeV2 {
    #[default]
    Probe,
    Track,
}

/// Host-owned hysteresis for the telemetry-driven BBR floor.
///
/// A pure one-sample rule made a saturated flow alternate between a large
/// floor and zero: the large floor drained the producer queue or briefly
/// raised RTT, which removed the floor on the next one-second sample. Keep a
/// small amount of per-path state so those expected consequences of probing
/// become a transition to measured-BDP tracking instead of an on/off switch.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct AdaptiveCwndFloorStateV2 {
    pub(super) path_epoch: u64,
    pub(super) mode: AdaptiveCwndFloorModeV2,
    pub(super) held_bytes: u64,
    pub(super) inactive_ticks: u8,
}

pub(super) fn quantize_adaptive_cwnd_floor(bytes: u64) -> u64 {
    bytes
        .min(ADAPTIVE_CWND_FLOOR_MAX_BYTES)
        .div_ceil(ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES)
        .saturating_mul(ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES)
        .min(ADAPTIVE_CWND_FLOOR_MAX_BYTES)
}

pub(super) fn measured_cwnd_floor(telemetry: PathTelemetryV2, effective: &BbrEffectiveV1) -> u64 {
    let demand_rate = telemetry
        .tun_ingress_bytes_per_second
        .max(telemetry.delivery_rate_bytes_per_second)
        .max(telemetry.real_traffic_bytes_per_second);
    cwnd_floor_for_rate(demand_rate, telemetry.min_rtt, effective)
}

pub(super) fn cwnd_floor_for_rate(
    rate_bytes_per_second: u64,
    min_rtt: Duration,
    effective: &BbrEffectiveV1,
) -> u64 {
    let bdp = u128::from(rate_bytes_per_second).saturating_mul(min_rtt.as_micros()) / 1_000_000;
    quantize_adaptive_cwnd_floor(
        bdp.saturating_mul(u128::from(effective.default_cwnd_gain_milli))
            .div_ceil(1_000)
            .min(u128::from(ADAPTIVE_CWND_FLOOR_MAX_BYTES)) as u64,
    )
}

impl AdaptiveCwndFloorStateV2 {
    pub(super) fn clear(&mut self, path_epoch: u64) -> u64 {
        self.path_epoch = path_epoch;
        self.mode = AdaptiveCwndFloorModeV2::Probe;
        self.held_bytes = 0;
        self.inactive_ticks = 0;
        0
    }

    pub(super) fn update(
        &mut self,
        telemetry: PathTelemetryV2,
        effective: &BbrEffectiveV1,
        congestion_window_bytes: u64,
    ) -> u64 {
        if self.path_epoch != telemetry.path_epoch {
            self.clear(telemetry.path_epoch);
        }
        if telemetry.reliability != PathReliability::Datagram
            || effective.loss_is_congestion
            || telemetry.controller_app_limited
            || telemetry.cpu_utilization_per_mille >= 900
            || telemetry.min_rtt.is_zero()
        {
            return self.clear(telemetry.path_epoch);
        }

        let demand_rate = telemetry
            .tun_ingress_bytes_per_second
            .max(telemetry.delivery_rate_bytes_per_second)
            .max(telemetry.real_traffic_bytes_per_second);
        if demand_rate == 0 && telemetry.packet_train_queue_bytes == 0 {
            self.inactive_ticks = self.inactive_ticks.saturating_add(1);
            if self.inactive_ticks >= 2 {
                return self.clear(telemetry.path_epoch);
            }
            return self.held_bytes;
        }
        self.inactive_ticks = 0;

        let measured = measured_cwnd_floor(telemetry, effective);
        let modeled = cwnd_floor_for_rate(
            telemetry.controller_bw_bytes_per_second,
            telemetry.min_rtt,
            effective,
        );
        let queue_budget = Duration::from_millis(5).max(telemetry.min_rtt / 2);
        let queue_inflated = telemetry.queue_delay > queue_budget;
        let producer_queued = telemetry.packet_train_queue_bytes >= TX_ADMISSION_BATCH_BYTES as u64;
        let cwnd_matches_model = modeled != 0
            && u128::from(congestion_window_bytes).saturating_mul(4)
                >= u128::from(modeled).saturating_mul(3)
            && u128::from(congestion_window_bytes).saturating_mul(4)
                <= u128::from(modeled).saturating_mul(5);
        let controller_model_is_serving_demand =
            telemetry.controller_bw_bytes_per_second >= demand_rate;
        // Startup is itself an active capacity probe.  A model that happens
        // to match its still-growing cwnd must not retire the host floor: the
        // producer backlog is evidence that Startup still needs room to
        // discover capacity.  Once Startup has exited, matching model/cwnd
        // evidence is sufficient to switch to bounded BDP tracking.
        let controller_has_exited_startup = telemetry.controller_state != 0;

        self.held_bytes = match self.mode {
            AdaptiveCwndFloorModeV2::Probe if queue_inflated => {
                // The probe found the bottleneck. Retire its overshoot, but
                // retain the measured BDP instead of dropping to zero.
                self.mode = AdaptiveCwndFloorModeV2::Track;
                measured
            }
            AdaptiveCwndFloorModeV2::Probe
                if controller_has_exited_startup
                    && producer_queued
                    && cwnd_matches_model
                    && controller_model_is_serving_demand =>
            {
                // BBR already has a capacity model and its current cwnd is
                // within one bounded step of that model's BDP. Doubling here
                // is not discovery: it is a host-created overshoot. Track the
                // larger of live demand and the controller model directly.
                self.mode = AdaptiveCwndFloorModeV2::Track;
                measured.max(modeled)
            }
            AdaptiveCwndFloorModeV2::Probe if producer_queued => {
                // Recovery from an underfilled model still needs an explicit
                // upward probe; a measured-only floor can be self-limiting.
                let probe = congestion_window_bytes
                    .max(ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES)
                    .saturating_mul(2);
                measured.max(quantize_adaptive_cwnd_floor(probe))
            }
            AdaptiveCwndFloorModeV2::Probe => {
                // Draining one admission batch is not proof that producer
                // demand ended. Hold the last probe until the queue returns or
                // all traffic-rate evidence becomes idle.
                if self.held_bytes == 0 {
                    0
                } else {
                    self.held_bytes.max(measured)
                }
            }
            AdaptiveCwndFloorModeV2::Track if queue_inflated => {
                // Congestion may reduce immediately to the measured target;
                // it must never increase a held floor.
                self.held_bytes.min(measured)
            }
            AdaptiveCwndFloorModeV2::Track => {
                // Smooth rate-estimator noise while retaining bounded upward
                // adaptation after a real capacity increase.
                let lower = quantize_adaptive_cwnd_floor(self.held_bytes.saturating_mul(3) / 4);
                let upper =
                    quantize_adaptive_cwnd_floor(self.held_bytes.saturating_mul(5).div_ceil(4));
                measured.clamp(lower, upper)
            }
        };
        self.held_bytes
    }
}

#[cfg(test)]
pub(super) fn adaptive_cwnd_floor(
    telemetry: PathTelemetryV2,
    effective: &BbrEffectiveV1,
    congestion_window_bytes: u64,
) -> u64 {
    AdaptiveCwndFloorStateV2::default().update(telemetry, effective, congestion_window_bytes)
}

/// Finalize the host-owned, telemetry-dependent BBR floor before publication.
///
/// Policy guardrails already produced every static BBR value. The host adds
/// the live adaptive floor exactly once here, then constrains the combined
/// value to an explicit nonzero cap. The return value remains the
/// telemetry-only addition for the autotune tap; `effective` is the complete
/// value subsequently written to the controller.
#[cfg(test)]
pub(super) fn finalize_bbr3_effective(
    telemetry: PathTelemetryV2,
    congestion_window_bytes: u64,
    effective: &mut BbrEffectiveV1,
) -> u64 {
    let adaptive_cwnd_floor = adaptive_cwnd_floor(telemetry, effective, congestion_window_bytes);
    let combined_floor = effective.cwnd_floor_bytes.max(adaptive_cwnd_floor);
    effective.cwnd_floor_bytes = if effective.cwnd_cap_bytes == 0 {
        combined_floor
    } else {
        combined_floor.min(effective.cwnd_cap_bytes)
    };
    adaptive_cwnd_floor
}

pub(super) fn finalize_bbr3_effective_with_state(
    state: &mut AdaptiveCwndFloorStateV2,
    telemetry: PathTelemetryV2,
    congestion_window_bytes: u64,
    effective: &mut BbrEffectiveV1,
) -> u64 {
    let adaptive_cwnd_floor = state.update(telemetry, effective, congestion_window_bytes);
    let combined_floor = effective.cwnd_floor_bytes.max(adaptive_cwnd_floor);
    effective.cwnd_floor_bytes = if effective.cwnd_cap_bytes == 0 {
        combined_floor
    } else {
        combined_floor.min(effective.cwnd_cap_bytes)
    };
    adaptive_cwnd_floor
}

/// Write an already-finalized BBR action onto the shared controller tunables.
/// The controller re-reads the tunables at the next packet-timed round
/// boundary, so a partially published snapshot never takes effect mid-round.
/// Returns whether any tunable changed (and bumps the generation then).
pub(super) fn apply_bbr3_effective(tunables: &Bbr3Tunables, effective: &BbrEffectiveV1) -> bool {
    pub(super) fn update_u32(value: &AtomicU32, next: u32) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    pub(super) fn update_u64(value: &AtomicU64, next: u64) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    pub(super) fn update_u8(value: &AtomicU8, next: u8) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }

    let mut changed = false;
    changed |= update_u32(
        &tunables.probe_bw_up_pacing_gain_milli,
        effective.probe_bw_up_pacing_gain_milli,
    );
    changed |= update_u32(
        &tunables.probe_bw_down_pacing_gain_milli,
        effective.probe_bw_down_pacing_gain_milli,
    );
    changed |= update_u32(
        &tunables.cruise_pacing_gain_milli,
        effective.cruise_pacing_gain_milli,
    );
    changed |= update_u32(
        &tunables.default_cwnd_gain_milli,
        effective.default_cwnd_gain_milli,
    );
    changed |= update_u32(
        &tunables.probe_bw_up_cwnd_gain_milli,
        effective.probe_bw_up_cwnd_gain_milli,
    );
    changed |= update_u32(&tunables.headroom_milli, effective.headroom_milli);
    changed |= update_u32(&tunables.beta_milli, effective.beta_milli);
    changed |= update_u32(&tunables.loss_thresh_milli, effective.loss_threshold_milli);
    changed |= update_u8(
        &tunables.loss_is_congestion,
        u8::from(effective.loss_is_congestion),
    );
    changed |= update_u32(
        &tunables.queue_delay_guard_inflation_milli,
        effective.queue_guard_inflation_milli,
    );
    changed |= update_u64(
        &tunables.queue_delay_guard_slack_micros,
        effective.queue_guard_slack_micros,
    );
    changed |= update_u64(
        &tunables.probe_rtt_interval_millis,
        effective.probe_rtt_interval_millis,
    );
    changed |= update_u64(
        &tunables.probe_rtt_duration_millis,
        effective.probe_rtt_duration_millis,
    );
    changed |= update_u32(
        &tunables.probe_rtt_cwnd_gain_milli,
        effective.probe_rtt_cwnd_gain_milli,
    );
    changed |= update_u64(
        &tunables.min_probe_wait_millis,
        effective.min_probe_wait_millis,
    );
    changed |= update_u64(
        &tunables.max_added_probe_wait_millis,
        effective.max_added_probe_wait_millis,
    );
    changed |= update_u64(
        &tunables.pacing_rate_cap_bytes_per_second,
        effective.pacing_cap_bytes_per_second,
    );
    changed |= update_u64(&tunables.cwnd_floor_bytes, effective.cwnd_floor_bytes);
    changed |= update_u64(&tunables.cwnd_cap_bytes, effective.cwnd_cap_bytes);
    changed |= update_u64(
        &tunables.startup_bw_hint_bytes_per_second,
        effective.startup_bw_hint_bytes_per_second,
    );
    if changed {
        tunables.generation.fetch_add(1, Ordering::Release);
    }
    changed
}

/// Publish one capacity-discovery edge without waiting for a full policy tick.
pub(super) fn publish_capacity_probe(tunables: &Bbr3Tunables) {
    tunables
        .capacity_probe_generation
        .fetch_add(1, Ordering::Relaxed);
    tunables.generation.fetch_add(1, Ordering::Release);
}

/// Publish policy tunables and an optional real-TUN capacity-discovery edge
/// as one controller-visible generation. The dedicated generation is bumped
/// before the release publication so BBR cannot observe a request half-way
/// through the tunable update.
pub(super) fn publish_bbr3_effective(
    tunables: &Bbr3Tunables,
    effective: &BbrEffectiveV1,
    request_capacity_probe: bool,
) -> bool {
    if request_capacity_probe {
        tunables
            .capacity_probe_generation
            .fetch_add(1, Ordering::Relaxed);
    }
    let changed = apply_bbr3_effective(tunables, effective);
    if request_capacity_probe && !changed {
        // `apply_bbr3_effective` did not publish a generation for the probe.
        // The capacity generation was already incremented above, so only the
        // paired Release store remains here.
        tunables.generation.fetch_add(1, Ordering::Release);
    }
    changed || request_capacity_probe
}
