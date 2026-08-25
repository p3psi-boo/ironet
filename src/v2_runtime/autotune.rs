//! Autotune execution, policy loading, and tuning telemetry for the V2 runtime.
//!
//! This module deliberately keeps the existing mechanical runtime lifecycle: the
//! outer runtime owns task spawning, while this module owns the complete
//! per-connection autotune loop and its policy/WASM/state helpers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{
    EndpointId, TransportAddr,
    endpoint::{Bbr3Tunables, Connection, ControllerSnapshot},
};
use ironet_policy_core::{BANDIT_POLICY_ID_V1, LearnerMemoryV1, LearnerStateV1, STATE_SCHEMA_V1};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::{
    V2RuntimeState,
    dataplane::{TX_ADMISSION_BATCH_BYTES, repair_minimum_age_for_rtt},
    status_projection::TuneStatusSampleV2,
    telemetry::{
        RemoteFeedbackSnapshot, RuntimeMetrics, SampleCounterSnapshot, StatusCounterSnapshot,
        TxByteSnapshotV2, counter_delta, histogram_percentile_micros, jain_fairness_ppm,
        path_endpoint_identity,
    },
};
use crate::{
    config::{AutotuneMode, AutotuneObjective},
    derp::DerpAddr,
    protocol::v2::{
        fec::FecGeometryV2,
        learner::{LearnerModeV2, LearnerTraceV2},
        memory::load as load_autotune_memory,
        policy::{
            api::{BbrEffectiveV1, PolicyBackend, PolicyFaultV1},
            runtime::WasmPolicyBackend,
            signature::{TrustStoreV1, encode_digest},
            state::PolicyStateStoreV1,
        },
        policy_tick::{
            PolicySlotKindV1, PolicySlotV1, PolicyTickConfigV1, PolicyTickV1, ShadowEvaluationV2,
            ShadowEvaluatorV2, builtin_core_slot, derive_policy_seed,
            peer_hash as policy_peer_hash,
        },
        tuning::{
            AutoTuneBoundsV2, AutoTunerV2, Bbr3PresetV2, CoverTrafficProfileV2, ForcedActionV2,
            PathReliability, PathTelemetryV2, TuneDecisionV2,
        },
        utility::{Objective, UtilitySample, WireCostV2},
    },
};

const ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES: u64 = 16 * 1024;
const ADAPTIVE_CWND_FLOOR_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const LOW_RTT_CWND_FLOOR_BYTES: u64 = 512 * 1024;
const CAPACITY_PROBE_EDGE_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum AdaptiveCwndFloorModeV2 {
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
struct AdaptiveCwndFloorStateV2 {
    path_epoch: u64,
    mode: AdaptiveCwndFloorModeV2,
    held_bytes: u64,
    inactive_ticks: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum InitialBulkProbeV2 {
    /// No initial Bulk service has reached either edge detector yet.
    #[default]
    AwaitingEdge,
    /// The first Bulk edge was observed inside the current telemetry window.
    /// Cross the next sample boundary without publishing from that partial
    /// interval. A hard-safe pressure observation may be retained for the
    /// complete interval's one-shot decision.
    AwaitingSampleBoundary,
    /// The edge is now aligned to a sample boundary; the following tick is
    /// the first complete post-edge interval and may make the decision.
    AwaitingCompleteTick,
    /// The initial epoch's one-shot decision has been consumed.
    Consumed,
}

/// Per-connection edge detector for serviced Bulk traffic.
///
/// Control and latency traffic never increment the Bulk service counter, so
/// this cross-layer signal can request capacity discovery without asking BBR
/// to infer application semantics from ACK timing.
#[derive(Debug, Clone, Copy, Default)]
struct CapacityProbeStateV2 {
    path_epoch: u64,
    bulk_service_counter: u64,
    bulk_active: bool,
    bulk_idle_ticks: u8,
    bulk_idle_verified: bool,
    bulk_service_since_tick: bool,
    /// An explicit path reset, or a fast edge that could not be published,
    /// still owes the controller one capacity-discovery request. Initial
    /// connection traffic is deliberately not represented by this flag.
    probe_pending: bool,
    initial_bulk_probe: InitialBulkProbeV2,
    /// A partial initial-Bulk interval showed clean demand above the current
    /// controller pacing rate. It is evidence only: publication still waits
    /// for a complete, currently safe interval.
    initial_clean_demand_seen: bool,
    /// Set by `update` when this tick only establishes the initial Bulk
    /// sample boundary. Other edge detectors must ignore the same partial
    /// telemetry window so it cannot seed a later duplicate restart.
    initial_sample_incomplete: bool,
    previous_pacing_cap_bytes_per_second: Option<u64>,
    loss_episode: bool,
    loss_signal_latched: bool,
    consecutive_clean_loss_ticks: u8,
}

fn controller_policer_episode_active(policer_pacing_transitions: u64) -> bool {
    // A fixed absolute ceiling can be active at a 1.0 multiplicative scale.
    // The controller's one-way transition counter is the episode marker.
    policer_pacing_transitions != 0
}

impl CapacityProbeStateV2 {
    fn initialize_bulk_service_counter(&mut self, path_epoch: u64, counter: u64) {
        self.path_epoch = path_epoch;
        self.bulk_service_counter = counter;
        self.initial_bulk_probe = InitialBulkProbeV2::AwaitingEdge;
        self.initial_clean_demand_seen = false;
        self.initial_sample_incomplete = false;
    }

    fn reset_for_path(&mut self, path_epoch: u64) {
        let bulk_service_counter = self.bulk_service_counter;
        *self = Self {
            path_epoch,
            bulk_service_counter,
            probe_pending: true,
            initial_bulk_probe: InitialBulkProbeV2::Consumed,
            ..Self::default()
        };
    }

    /// Observe the cumulative Bulk service byte counter on the lightweight
    /// edge tick. Initial Bulk traffic only marks a one-shot decision pending:
    /// the complete one-second telemetry sample decides whether native Startup
    /// underestimated clean demand without racing shallow-policer
    /// classification. A later increase requests discovery only after the
    /// ordinary telemetry path has verified a complete idle horizon (or an
    /// explicit path reset left a request pending).
    fn update_bulk_service_counter(&mut self, counter: u64) -> bool {
        let increased = counter > self.bulk_service_counter;
        self.bulk_service_counter = counter;
        if !increased {
            return false;
        }

        self.bulk_service_since_tick = true;
        if self.bulk_active {
            // Sustained service is positive application-epoch evidence even
            // if ingress accounting momentarily lags. It must cancel any
            // partial idle horizon rather than allowing a false re-edge.
            self.bulk_idle_ticks = 0;
            self.bulk_idle_verified = false;
            return false;
        }

        let verified_new_epoch = self.bulk_idle_verified;
        let request_capacity_probe = verified_new_epoch || self.probe_pending;
        if !request_capacity_probe && self.initial_bulk_probe == InitialBulkProbeV2::AwaitingEdge {
            self.initial_bulk_probe = InitialBulkProbeV2::AwaitingSampleBoundary;
        }
        self.bulk_active = true;
        self.bulk_idle_ticks = 0;
        self.bulk_idle_verified = false;
        self.probe_pending = false;
        // Whether this was the initial epoch or a verified reactivation, the
        // edge has been consumed. A later backlog observation belongs to the
        // same epoch and must not restart Startup again.
        request_capacity_probe
    }

    fn cancel_bulk_service_edge(&mut self) {
        self.bulk_active = false;
        self.bulk_idle_ticks = 0;
        self.bulk_idle_verified = false;
        self.bulk_service_since_tick = false;
        // This method is called only after a requested fast publication could
        // not find controller tunables. Preserve that explicit request for
        // the normal telemetry path without pretending idle was verified.
        self.probe_pending = true;
    }

    fn update(
        &mut self,
        telemetry: PathTelemetryV2,
        controller_policer_episode_active: bool,
    ) -> bool {
        self.initial_sample_incomplete = false;
        if self.path_epoch == 0 {
            // The first observed path is connection initialization, not a
            // path migration. Its native controller Startup is sufficient.
            self.path_epoch = telemetry.path_epoch;
        } else if self.path_epoch != telemetry.path_epoch {
            self.reset_for_path(telemetry.path_epoch);
        }

        let tun_ingress = telemetry.tun_ingress_bytes_per_second;
        let producer_backlogged =
            telemetry.packet_train_queue_bytes >= TX_ADMISSION_BATCH_BYTES as u64;
        let bulk_serviced = std::mem::take(&mut self.bulk_service_since_tick);
        // A retained controller-internal queue keeps an established Bulk
        // epoch active, but cannot create an application epoch by itself.
        let bulk_activity =
            tun_ingress > 0 || bulk_serviced || (self.bulk_active && producer_backlogged);
        let initial_probe_state = self.initial_bulk_probe;
        let initial_complete_tick = initial_probe_state == InitialBulkProbeV2::AwaitingCompleteTick;
        let initial_clean_demand_seen = self.initial_clean_demand_seen;
        if initial_probe_state == InitialBulkProbeV2::AwaitingSampleBoundary {
            // This sample may contain almost a full second from before the
            // fast edge. Never publish from it, but retain a hard-safe clean
            // pressure observation so a rate fall in the next full interval
            // does not erase evidence that native Startup under-estimated the
            // initial demand.
            self.initial_clean_demand_seen =
                initial_bulk_clean_demand_is_safe(telemetry, controller_policer_episode_active);
            self.initial_bulk_probe = InitialBulkProbeV2::AwaitingCompleteTick;
            self.initial_sample_incomplete = true;
        } else if initial_complete_tick {
            // Exactly one complete telemetry interval may decide the initial
            // epoch. A later clean sample must never resurrect a decision
            // suppressed by Startup, loss, or a policer transition.
            self.initial_bulk_probe = InitialBulkProbeV2::Consumed;
            self.initial_clean_demand_seen = false;
        }
        let verified_new_epoch = self.bulk_idle_verified;
        if bulk_activity && self.bulk_active {
            // A renewed Bulk byte or retained admission backlog belongs to
            // the current epoch; a one-tick producer lull must not rearm a
            // second capacity probe.
            self.bulk_idle_ticks = 0;
            self.bulk_idle_verified = false;
            if initial_complete_tick {
                return initial_bulk_capacity_probe_is_safe(
                    telemetry,
                    controller_policer_episode_active,
                    initial_clean_demand_seen,
                );
            }
        }
        let new_active_epoch = bulk_activity && !self.bulk_active;
        if new_active_epoch {
            let initial_partial_tick = initial_probe_state == InitialBulkProbeV2::AwaitingEdge;
            if initial_partial_tick {
                // Without a preceding fast edge this is still the first
                // boundary at which initial Bulk is known to be active. The
                // following interval is the first one allowed to publish.
                self.initial_clean_demand_seen =
                    initial_bulk_clean_demand_is_safe(telemetry, controller_policer_episode_active);
                self.initial_bulk_probe = InitialBulkProbeV2::AwaitingCompleteTick;
                self.initial_sample_incomplete = true;
            }
            let request_capacity_probe = verified_new_epoch
                || self.probe_pending
                || (initial_complete_tick
                    && initial_bulk_capacity_probe_is_safe(
                        telemetry,
                        controller_policer_episode_active,
                        initial_clean_demand_seen,
                    ));
            self.bulk_active = true;
            self.bulk_idle_verified = false;
            self.probe_pending = false;
            return request_capacity_probe;
        }
        if !bulk_activity && self.bulk_active {
            self.bulk_idle_ticks = self.bulk_idle_ticks.saturating_add(1);
            let idle_horizon = if controller_policer_episode_active {
                5
            } else {
                2
            };
            if self.bulk_idle_ticks >= idle_horizon {
                self.bulk_active = false;
                self.bulk_idle_ticks = 0;
                self.bulk_idle_verified = true;
            }
        }
        false
    }

    fn update_loss_episode(
        &mut self,
        telemetry: PathTelemetryV2,
        controller_policer_episode_active: bool,
    ) -> bool {
        if telemetry.path_epoch != self.path_epoch {
            self.reset_for_path(telemetry.path_epoch);
            return false;
        }
        // A controller-confirmed shallow-policer episode is expected to turn
        // a lossy probe into clean delivery. Treating those clean ticks as a
        // recovery edge would restart Startup, discard the fixed ceiling and
        // recreate the same loss. A true idle/new-Bulk epoch is still handled
        // by `update`/the fast Bulk service edge, and a path change resets all
        // state above.
        if controller_policer_episode_active {
            self.loss_episode = false;
            self.loss_signal_latched = false;
            self.consecutive_clean_loss_ticks = 0;
            return false;
        }
        if telemetry.tun_ingress_bytes_per_second == 0 {
            self.loss_episode = false;
            self.loss_signal_latched = false;
            self.consecutive_clean_loss_ticks = 0;
            return false;
        }

        const LOSS_EPISODE_THRESHOLD_PPM: u32 = 10_000;
        let episode_signal = telemetry.loss_ppm >= LOSS_EPISODE_THRESHOLD_PPM
            || telemetry.residual_loss_ppm >= LOSS_EPISODE_THRESHOLD_PPM
            || telemetry.burst_loss_cells >= 3;
        if !episode_signal {
            self.loss_signal_latched = false;
        } else if !self.loss_signal_latched {
            self.loss_signal_latched = true;
            self.loss_episode = true;
            self.consecutive_clean_loss_ticks = 0;
            return false;
        }
        if !self.loss_episode {
            return false;
        }
        if telemetry.loss_ppm != 0 || telemetry.residual_loss_ppm != 0 {
            self.consecutive_clean_loss_ticks = 0;
            return false;
        }

        self.consecutive_clean_loss_ticks = self.consecutive_clean_loss_ticks.saturating_add(1);
        if self.consecutive_clean_loss_ticks < 2 {
            return false;
        }
        self.loss_episode = false;
        self.consecutive_clean_loss_ticks = 0;
        true
    }

    fn update_loss_episode_if_complete(
        &mut self,
        telemetry: PathTelemetryV2,
        controller_policer_episode_active: bool,
    ) -> bool {
        !self.initial_sample_incomplete
            && self.update_loss_episode(telemetry, controller_policer_episode_active)
    }

    fn update_pacing_cap(&mut self, pacing_cap_bytes_per_second: u64, tun_active: bool) -> bool {
        let released = tun_active
            && self
                .previous_pacing_cap_bytes_per_second
                .is_some_and(|previous| previous > 0 && pacing_cap_bytes_per_second == 0);
        self.previous_pacing_cap_bytes_per_second = Some(pacing_cap_bytes_per_second);
        released
    }

    fn update_pacing_cap_if_complete(
        &mut self,
        pacing_cap_bytes_per_second: u64,
        tun_active: bool,
    ) -> bool {
        if self.initial_sample_incomplete {
            // A cap transition inside the discarded partial interval is not
            // a capacity-discovery edge. Still advance the remembered value:
            // otherwise a release that happened in this interval would be
            // reported one tick late, after the complete initial-Bulk sample
            // has already made its own one-shot decision.
            self.previous_pacing_cap_bytes_per_second = Some(pacing_cap_bytes_per_second);
            return false;
        }
        self.update_pacing_cap(pacing_cap_bytes_per_second, tun_active)
    }
}

fn initial_bulk_capacity_probe_is_safe(
    telemetry: PathTelemetryV2,
    controller_policer_episode_active: bool,
    initial_clean_demand_seen: bool,
) -> bool {
    initial_bulk_sample_is_safe(telemetry, controller_policer_episode_active)
        && (initial_clean_demand_seen
            || telemetry.tun_ingress_bytes_per_second
                > telemetry.controller_pacing_rate_bytes_per_second)
}

fn initial_bulk_clean_demand_is_safe(
    telemetry: PathTelemetryV2,
    controller_policer_episode_active: bool,
) -> bool {
    initial_bulk_sample_is_safe(telemetry, controller_policer_episode_active)
        && telemetry.tun_ingress_bytes_per_second
            > telemetry.controller_pacing_rate_bytes_per_second
}

fn initial_bulk_sample_is_safe(
    telemetry: PathTelemetryV2,
    controller_policer_episode_active: bool,
) -> bool {
    !controller_policer_episode_active
        && telemetry.controller_state != 0
        && telemetry.loss_ppm == 0
        && telemetry.residual_loss_ppm == 0
        && telemetry.burst_loss_cells == 0
}

fn fast_capacity_probe_path_matches(current_identity: &str, selected_identity: &str) -> bool {
    // Before the first complete sample there is no path-owned state to
    // publish. During migration, let the normal tick advance the path epoch
    // and reset the state before any edge can touch the new path's tunables.
    !current_identity.is_empty() && current_identity == selected_identity
}

#[derive(Debug, Clone, Copy)]
struct AutotuneTapSampleV2<'a> {
    sampled_unix_micros: u64,
    sample_elapsed: Duration,
    telemetry: PathTelemetryV2,
    decision: TuneDecisionV2,
    utility: UtilitySample,
    wire_cost: WireCostV2,
    force_applied: bool,
    learner: Option<LearnerTraceV2>,
    policy_id: &'a str,
    policy_source: &'a str,
    shadow_policy_id: Option<&'a str>,
    shadow: Option<ShadowEvaluationV2>,
    path_identity: &'a str,
    controller_cwnd_bytes: u64,
    adaptive_cwnd_floor_bytes: u64,
}

fn autotune_tap_record(
    peer: EndpointId,
    ticket_partition: &str,
    sample: AutotuneTapSampleV2<'_>,
) -> serde_json::Value {
    let AutotuneTapSampleV2 {
        sampled_unix_micros,
        sample_elapsed,
        telemetry,
        decision,
        utility,
        wire_cost,
        force_applied,
        learner,
        policy_id,
        policy_source,
        shadow_policy_id,
        shadow,
        path_identity,
        controller_cwnd_bytes,
        adaptive_cwnd_floor_bytes,
    } = sample;
    serde_json::json!({
        "schema_version": 5,
        "peer": peer.to_string(),
        "tls_ticket_partition": ticket_partition,
        "sampled_unix_micros": sampled_unix_micros,
        "sample_interval_micros": sample_elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
        "force_applied": force_applied,
        "path_identity": path_identity,
        "controller": {
            "congestion_window_bytes": controller_cwnd_bytes,
            "adaptive_cwnd_floor_bytes": adaptive_cwnd_floor_bytes,
        },
        "policy": {
            "id": policy_id,
            "source": policy_source,
            "shadow_id": shadow_policy_id,
        },
        "telemetry": {
            "path_epoch": telemetry.path_epoch,
            "reliability": format!("{:?}", telemetry.reliability),
            "rtt_micros": telemetry.rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            "min_rtt_micros": telemetry.min_rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            "queue_delay_micros": telemetry.queue_delay.as_micros().min(u128::from(u64::MAX)) as u64,
            "loss_ppm": telemetry.loss_ppm,
            "burst_loss_cells": telemetry.burst_loss_cells,
            "reorder_ppm": telemetry.reorder_ppm,
            "receiver_goodput_bytes_per_second": telemetry.receiver_goodput_bytes_per_second,
            "residual_loss_ppm": telemetry.residual_loss_ppm,
            "latency_sojourn_p95_micros": telemetry.latency_sojourn_p95_micros,
            "latency_sojourn_p50_micros": telemetry.latency_sojourn_p50_micros,
            "latency_sojourn_p99_micros": telemetry.latency_sojourn_p99_micros,
            "latency_queue_recently_nonempty": telemetry.latency_queue_recently_nonempty,
            "delivery_rate_bytes_per_second": telemetry.delivery_rate_bytes_per_second,
            "controller_pacing_rate_bytes_per_second": telemetry.controller_pacing_rate_bytes_per_second,
            "controller_send_quantum_bytes": telemetry.controller_send_quantum_bytes,
            "controller_state": telemetry.controller_state,
            "controller_bw_bytes_per_second": telemetry.controller_bw_bytes_per_second,
            "controller_inflight_longterm_bytes": telemetry.controller_inflight_longterm_bytes,
            "controller_guard_transitions_delta": telemetry.controller_guard_transitions_delta,
            "controller_app_limited": telemetry.controller_app_limited,
            "controller_tunables_generation": telemetry.controller_tunables_generation,
            "controller_params_generation": telemetry.controller_params_generation,
            "controller_clamped_writes": telemetry.controller_clamped_writes,
            "receive_rate_bytes_per_second": telemetry.receive_rate_bytes_per_second,
            "packets_per_second": telemetry.packets_per_second,
            "tun_ingress_bytes_per_second": telemetry.tun_ingress_bytes_per_second,
            "average_record_bytes": telemetry.average_record_bytes,
            "gso_ingress_ratio_ppm": telemetry.gso_ingress_ratio_ppm,
            "packet_train_queue_bytes": telemetry.packet_train_queue_bytes,
            "latency_queue_bytes": telemetry.latency_queue_bytes,
            "reassembly_pressure_evictions": telemetry.reassembly_pressure_evictions,
            "remote_expired_stripes_delta": telemetry.remote_expired_stripes_delta,
            "train_build_bytes_per_second": telemetry.train_build_bytes_per_second,
            "bulk_preemption_delay_average_micros": telemetry.bulk_preemption_delay_average_micros,
            "cpu_utilization_per_mille": telemetry.cpu_utilization_per_mille,
            "wasted_parity_per_mille": telemetry.wasted_parity_per_mille,
            "fec_recovery_per_mille": telemetry.fec_recovery_per_mille,
            "repair_hit_per_mille": telemetry.repair_hit_per_mille,
            "repair_completed_requests": telemetry.repair_completed_requests,
            "repair_response_latency_micros": telemetry.repair_response_latency.as_micros().min(u128::from(u64::MAX)) as u64,
            "real_traffic_bytes_per_second": telemetry.real_traffic_bytes_per_second,
        },
        "decision": {
            "reason": format!("{:?}", decision.reason),
            "path_epoch": decision.path_epoch,
            "sample_count": decision.sample_count,
            "train_target_bytes": decision.train_target_bytes,
            "bulk_quantum_cells": decision.bulk_quantum_cells,
            "fec": decision.fec.map(|geometry| serde_json::json!({
                "data_cells": geometry.data_cells,
                "parity_cells": geometry.parity_cells,
            })),
            "repair_cache_bytes": decision.repair_cache_bytes,
            "send_buffer_bytes": decision.send_buffer_bytes,
            "receive_buffer_bytes": decision.receive_buffer_bytes,
            "receive_batch": decision.receive_batch,
            "cover_profile": format!("{:?}", decision.cover_profile),
            "cover_overhead_per_mille": decision.cover_overhead_per_mille,
            "cover_padding_bytes_per_second": decision.cover_padding_bytes_per_second,
            "bbr": {
                "preset": format!("{:?}", decision.bbr.preset),
                "up_gain_milli": decision.bbr.up_gain_milli,
                "headroom_milli": decision.bbr.headroom_milli,
                "cwnd_gain_milli": decision.bbr.cwnd_gain_milli,
                "pacing_cap_bytes_per_second": decision.bbr.pacing_cap_bytes_per_second,
                "loss_is_congestion": decision.bbr.loss_is_congestion,
            },
        },
        "utility": {
            "total": utility.total,
            "components": utility.components,
            "goodput_bytes_per_second": utility.goodput_bytes_per_second,
        },
        "wire_cost": {
            "payload_bytes": wire_cost.payload_bytes,
            "parity_bytes": wire_cost.parity_bytes,
            "repair_bytes": wire_cost.repair_bytes,
            "cover_bytes": wire_cost.cover_bytes,
            "cell_envelope_bytes": wire_cost.cell_envelope_bytes,
        },
        "learner": learner.map(|trace| serde_json::json!({
            "mode": format!("{:?}", trace.mode),
            "context": {
                "rtt_class": trace.context.rtt_class,
                "rate_class": trace.context.rate_class,
                "loss_class": trace.context.loss_class,
                "reliable": trace.context.reliable,
                "host_rtt": trace.context.host_rtt,
            },
            "baseline_preset": format!("{:?}", trace.baseline_preset),
            "proposed_preset": format!("{:?}", trace.proposed_preset),
            "applied_preset": format!("{:?}", trace.applied_preset),
            "predicted_advantage": trace.predicted_advantage,
            "exploring": trace.exploring,
            "rollback": trace.rollback,
            "rollbacks": trace.rollbacks,
            "fine_up_gain_delta_milli": trace.fine_up_gain_delta_milli,
            "fine_headroom_delta_milli": trace.fine_headroom_delta_milli,
            "fine_cwnd_gain_delta_milli": trace.fine_cwnd_gain_delta_milli,
        })),
        "shadow": shadow.map(|candidate| serde_json::json!({
            "policy_id": shadow_policy_id,
            "utility": {
                "total": candidate.utility.total,
                "components": candidate.utility.components,
                "goodput_bytes_per_second": candidate.utility.goodput_bytes_per_second,
            },
            "decision": {
                "train_target_bytes": candidate.decision.train_target_bytes,
                "bulk_quantum_cells": candidate.decision.bulk_quantum_cells,
                "fec": candidate.decision.fec.map(|geometry| serde_json::json!({
                    "data_cells": geometry.data_cells,
                    "parity_cells": geometry.parity_cells,
                })),
                "cover_profile": format!("{:?}", candidate.decision.cover_profile),
                "cover_overhead_per_mille": candidate.decision.cover_overhead_per_mille,
                "bbr": {
                    "preset": format!("{:?}", candidate.decision.bbr.preset),
                    "up_gain_milli": candidate.decision.bbr.up_gain_milli,
                    "headroom_milli": candidate.decision.bbr.headroom_milli,
                    "cwnd_gain_milli": candidate.decision.bbr.cwnd_gain_milli,
                    "pacing_cap_bytes_per_second": candidate.decision.bbr.pacing_cap_bytes_per_second,
                },
            },
            "trace": {
                "context": {
                    "rtt_class": candidate.trace.context.rtt_class,
                    "rate_class": candidate.trace.context.rate_class,
                    "loss_class": candidate.trace.context.loss_class,
                    "reliable": candidate.trace.context.reliable,
                    "host_rtt": candidate.trace.context.host_rtt,
                },
                "baseline_preset": format!("{:?}", candidate.trace.baseline_preset),
                "proposed_preset": format!("{:?}", candidate.trace.proposed_preset),
                "predicted_advantage": candidate.trace.predicted_advantage,
                "exploring": candidate.trace.exploring,
            },
        })),
    })
}

fn quantize_adaptive_cwnd_floor(bytes: u64) -> u64 {
    bytes
        .min(ADAPTIVE_CWND_FLOOR_MAX_BYTES)
        .div_ceil(ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES)
        .saturating_mul(ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES)
        .min(ADAPTIVE_CWND_FLOOR_MAX_BYTES)
}

fn measured_cwnd_floor(telemetry: PathTelemetryV2, effective: &BbrEffectiveV1) -> u64 {
    let demand_rate = telemetry
        .tun_ingress_bytes_per_second
        .max(telemetry.delivery_rate_bytes_per_second)
        .max(telemetry.real_traffic_bytes_per_second);
    cwnd_floor_for_rate(demand_rate, telemetry.min_rtt, effective)
}

fn cwnd_floor_for_rate(
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
    fn clear(&mut self, path_epoch: u64) -> u64 {
        self.path_epoch = path_epoch;
        self.mode = AdaptiveCwndFloorModeV2::Probe;
        self.held_bytes = 0;
        self.inactive_ticks = 0;
        0
    }

    fn update(
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
fn adaptive_cwnd_floor(
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
fn finalize_bbr3_effective(
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

fn finalize_bbr3_effective_with_state(
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
fn apply_bbr3_effective(tunables: &Bbr3Tunables, effective: &BbrEffectiveV1) -> bool {
    fn update_u32(value: &AtomicU32, next: u32) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    fn update_u64(value: &AtomicU64, next: u64) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    fn update_u8(value: &AtomicU8, next: u8) -> bool {
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
fn publish_capacity_probe(tunables: &Bbr3Tunables) {
    tunables
        .capacity_probe_generation
        .fetch_add(1, Ordering::Relaxed);
    tunables.generation.fetch_add(1, Ordering::Release);
}

/// Publish policy tunables and an optional real-TUN capacity-discovery edge
/// as one controller-visible generation. The dedicated generation is bumped
/// before the release publication so BBR cannot observe a request half-way
/// through the tunable update.
fn publish_bbr3_effective(
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

fn parse_forced_usize(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<usize>> {
    object
        .get(field)
        .map(|value| {
            let number = value
                .as_u64()
                .with_context(|| format!("IRONET_AUTOTUNE_FORCE.{field} must be an integer"))?;
            usize::try_from(number)
                .with_context(|| format!("IRONET_AUTOTUNE_FORCE.{field} is too large"))
        })
        .transpose()
}

fn parse_forced_fec(value: &serde_json::Value) -> Result<Option<FecGeometryV2>> {
    if value.is_null() || value.as_str() == Some("off") {
        return Ok(None);
    }
    let geometry = if let Some(text) = value.as_str() {
        let (data, parity) = text
            .split_once('+')
            .context("IRONET_AUTOTUNE_FORCE.fec must be off or DATA+PARITY")?;
        FecGeometryV2 {
            data_cells: data
                .parse()
                .context("IRONET_AUTOTUNE_FORCE.fec data count is invalid")?,
            parity_cells: parity
                .parse()
                .context("IRONET_AUTOTUNE_FORCE.fec parity count is invalid")?,
        }
    } else {
        let object = value
            .as_object()
            .context("IRONET_AUTOTUNE_FORCE.fec must be null, a string, or an object")?;
        ensure!(
            object
                .keys()
                .all(|key| key == "data_cells" || key == "parity_cells"),
            "IRONET_AUTOTUNE_FORCE.fec has an unknown field"
        );
        FecGeometryV2 {
            data_cells: parse_forced_usize(object, "data_cells")?
                .context("IRONET_AUTOTUNE_FORCE.fec.data_cells is required")?,
            parity_cells: parse_forced_usize(object, "parity_cells")?
                .context("IRONET_AUTOTUNE_FORCE.fec.parity_cells is required")?,
        }
    };
    geometry
        .validate()
        .context("IRONET_AUTOTUNE_FORCE.fec is outside V2 geometry bounds")?;
    ensure!(
        geometry.parity_cells.saturating_mul(1_000) <= geometry.data_cells.saturating_mul(500),
        "IRONET_AUTOTUNE_FORCE.fec exceeds the 50% wire-overhead guard"
    );
    Ok(Some(geometry))
}

fn parse_autotune_force(input: &str) -> Result<ForcedActionV2> {
    let value: serde_json::Value =
        serde_json::from_str(input).context("parsing IRONET_AUTOTUNE_FORCE JSON")?;
    let object = value
        .as_object()
        .context("IRONET_AUTOTUNE_FORCE must be a JSON object")?;
    const FIELDS: [&str; 6] = [
        "bbr_preset",
        "fec",
        "train_target_bytes",
        "bulk_quantum_cells",
        "cover_profile",
        "cover_overhead_per_mille",
    ];
    ensure!(
        object.keys().all(|key| FIELDS.contains(&key.as_str())),
        "IRONET_AUTOTUNE_FORCE has an unknown field"
    );
    let cover_profile = object
        .get("cover_profile")
        .map(|value| {
            match value
                .as_str()
                .context("IRONET_AUTOTUNE_FORCE.cover_profile must be a string")?
            {
                "idle" => Ok(CoverTrafficProfileV2::Idle),
                "live-broadcast" => Ok(CoverTrafficProfileV2::LiveBroadcast),
                "interactive-video" => Ok(CoverTrafficProfileV2::InteractiveVideo),
                "generic-h3-bulk" => Ok(CoverTrafficProfileV2::GenericH3Bulk),
                _ => bail!("IRONET_AUTOTUNE_FORCE.cover_profile is unknown"),
            }
        })
        .transpose()?;
    let cover_overhead_per_mille = object
        .get("cover_overhead_per_mille")
        .map(|value| {
            let value = value
                .as_u64()
                .context("IRONET_AUTOTUNE_FORCE.cover_overhead_per_mille must be an integer")?;
            u16::try_from(value)
                .context("IRONET_AUTOTUNE_FORCE.cover_overhead_per_mille is too large")
        })
        .transpose()?;
    let bbr_preset = object
        .get("bbr_preset")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value::<Bbr3PresetV2>(value.clone())
                .context("IRONET_AUTOTUNE_FORCE.bbr_preset is unknown")
        })
        .transpose()?;
    let forced = ForcedActionV2 {
        bbr_preset,
        fec: object.get("fec").map(parse_forced_fec).transpose()?,
        train_target_bytes: parse_forced_usize(object, "train_target_bytes")?,
        bulk_quantum_cells: parse_forced_usize(object, "bulk_quantum_cells")?,
        cover_profile,
        cover_overhead_per_mille,
    };
    ensure!(
        forced != ForcedActionV2::default(),
        "IRONET_AUTOTUNE_FORCE must override at least one action"
    );
    Ok(forced)
}

/// True only for an external component path.  The builtin policy is a
/// `PolicySpecV1` executed in-process; it never reaches `PolicyLoader`.
fn is_external_wasm_policy_path(path: &std::path::Path) -> bool {
    path.is_absolute()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
}

fn is_external_wasm_policy_selection(selection: &str) -> bool {
    is_external_wasm_policy_path(std::path::Path::new(selection))
}

/// Select a non-WASM live policy.  `builtin` is the default in-process core
/// learner; only an explicit `native` selection uses conservative rules.
fn non_wasm_live_slot(
    selection: &str,
    learner_mode: LearnerModeV2,
    policy_source: &mut String,
) -> PolicySlotV1 {
    match selection {
        crate::config::AUTOTUNE_POLICY_BUILTIN => builtin_core_slot(learner_mode),
        crate::config::AUTOTUNE_POLICY_NATIVE => PolicySlotV1::native_rules(),
        _ => {
            warn!(
                configured = %selection,
                "invalid non-WASM autotune policy reached the runtime; using the native conservative baseline"
            );
            *policy_source = crate::config::AUTOTUNE_POLICY_NATIVE.to_owned();
            PolicySlotV1::native_rules()
        }
    }
}

/// Plan section 8.3: a freshly loaded candidate component shadows the live
/// input for this many consecutive fault-free ticks before it is promoted at
/// a sample boundary. Any fault aborts the warmup and the last known-good
/// component stays live.
const WASM_WARMUP_TICKS: u64 = 5;

/// A verified candidate component running shadow warmup (plan section 8.3):
/// it observes the live input without influencing the wire until it has
/// survived [`WASM_WARMUP_TICKS`] fault-free ticks.
struct WasmWarmupV1 {
    evaluator: ShadowEvaluatorV2,
    /// The candidate's `state_schema_accepts` manifest list, applied when it
    /// is promoted (plan section 8.2).
    accepts: Vec<u32>,
    healthy_ticks: u64,
}

/// Read and verified-load a `.wasm` policy component: read into a private
/// buffer, parse/verify against the sealed trust store, compile (cached by
/// package digest), instantiate and self-check. Also returns the whole-file
/// BLAKE3 for reload change detection. Runs synchronously; callers on a tick
/// path must offload it.
fn load_wasm_backend(
    runtime_state: &V2RuntimeState,
    path: &std::path::Path,
) -> Result<(WasmPolicyBackend, [u8; 32])> {
    ensure!(
        is_external_wasm_policy_path(path),
        "external WASM policy path must be absolute and end in .wasm: {}",
        path.display()
    );
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let file_hash = *blake3::hash(&bytes).as_bytes();
    let trust = TrustStoreV1::from_config(&runtime_state.autotune.wasm)?;
    let loader = runtime_state
        .policy_loader()
        .context("policy WASM engine unavailable")?;
    let backend = loader.load_from_bytes(
        &bytes,
        &runtime_state.autotune.wasm,
        &trust,
        chrono::Utc::now(),
    )?;
    Ok((backend, file_hash))
}

/// Load a `.wasm` policy component into a live slot (see
/// [`load_wasm_backend`]).
fn load_wasm_live_slot(
    runtime_state: &V2RuntimeState,
    path: &std::path::Path,
) -> Result<(PolicySlotV1, [u8; 32])> {
    let (backend, file_hash) = load_wasm_backend(runtime_state, path)?;
    let digest = backend
        .identity()
        .digest
        .map(|digest| encode_digest(&digest))
        .unwrap_or_default();
    Ok((
        PolicySlotV1::new(Box::new(backend), None, digest),
        file_hash,
    ))
}

/// Shadow evaluator around a verified WASM backend: it observes the live
/// input without influencing the wire.
fn shadow_evaluator_for_backend(
    backend: WasmPolicyBackend,
    objective: Objective,
    peer_hash: [u8; 32],
) -> ShadowEvaluatorV2 {
    let identity = backend.identity().clone();
    let digest = identity
        .digest
        .map(|digest| encode_digest(&digest))
        .unwrap_or_default();
    let slot = PolicySlotV1::new(Box::new(backend), None, digest.clone());
    let mut shadow = ShadowEvaluatorV2::from_slot(
        slot,
        objective.weights(),
        objective,
        identity.policy_id,
        digest,
    );
    shadow.set_peer_hash(peer_hash);
    shadow
}

/// Restore the live slot state for `peer`: the new state file when present,
/// otherwise a one-time warm start from the legacy `memory.rs` JSON file
/// (only meaningful for the bandit learner's state schema, whether it ran
/// through the native core builtin slot or an external component).
fn restore_policy_state(
    store: &PolicyStateStoreV1,
    slot: &mut PolicySlotV1,
    legacy_dir: &std::path::Path,
    peer: &str,
    peer_hash: [u8; 32],
) {
    let identity = slot.identity().clone();
    if let Some(state) = store.load(&identity.policy_id, identity.state_schema, peer) {
        debug!(
            peer,
            policy_id = %identity.policy_id,
            state_schema = identity.state_schema,
            state_bytes = state.len(),
            "restored V2 policy state"
        );
        slot.set_state(state);
        return;
    }
    if identity.state_schema != STATE_SCHEMA_V1 || identity.policy_id != BANDIT_POLICY_ID_V1 {
        return;
    }
    match load_autotune_memory(legacy_dir, peer, &identity.policy_id) {
        Ok(Some(memory)) => {
            let seed = derive_policy_seed(
                PolicySlotKindV1::Live,
                &identity.policy_id,
                identity.state_schema,
                &peer_hash,
                1,
            );
            match LearnerStateV1::from_memory(&LearnerMemoryV1::from(&memory.learner), seed, 0)
                .encode()
            {
                Ok(state) => {
                    info!(
                        peer,
                        policy_id = %identity.policy_id,
                        contexts = memory.learner.contexts.len(),
                        "warm-started V2 policy state from legacy autotune memory"
                    );
                    slot.set_state(state);
                    slot.mark_dirty();
                }
                Err(error) => warn!(peer, %error, "ignored legacy V2 autotune memory"),
            }
        }
        Ok(None) => {}
        Err(error) => warn!(peer, %error, "ignored invalid V2 autotune memory"),
    }
}

fn flush_policy_state(
    store: &PolicyStateStoreV1,
    slot: &mut PolicySlotV1,
    peer: &str,
) -> Result<()> {
    let identity = slot.identity();
    store.save(
        &identity.policy_id,
        identity.state_schema,
        peer,
        slot.module_digest(),
        slot.state(),
    )?;
    slot.mark_flushed();
    Ok(())
}

fn autotune_force_from_env() -> Result<Option<ForcedActionV2>> {
    match std::env::var("IRONET_AUTOTUNE_FORCE") {
        Ok(value) => parse_autotune_force(&value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("IRONET_AUTOTUNE_FORCE is not valid UTF-8")
        }
    }
}

/// Compatibility helper for the runtime unit test that exercises canonical
/// policy-action projection. Production ticks use `PolicyTickV1` and never
/// pass a `TuneDecisionV2` candidate directly to a data-plane applier.
#[cfg(test)]
fn constrain_learned_policy_action(
    tuner: &AutoTunerV2,
    policy: &ironet_policy_core::PolicySpecV1,
    telemetry: PathTelemetryV2,
    learned: TuneDecisionV2,
    trace: LearnerTraceV2,
) -> TuneDecisionV2 {
    if trace.mode != LearnerModeV2::On {
        return learned;
    }

    use crate::protocol::v2::policy::api::{
        CandidateActionV1, CandidateHostExt, EffectiveActionV1, EffectiveHostExt,
    };

    let mut candidate = CandidateActionV1::from_tune_decision(&learned);
    if let Some(action) =
        crate::protocol::v2::learner::forced_action_for_preset(policy, trace.applied_preset)
    {
        let application = action.to_candidate(telemetry.controller_bw_bytes_per_second);
        candidate.scheduler = application.scheduler;
        candidate.fec = application.fec;
        candidate.cover = application.cover;
    }
    let base = EffectiveActionV1::from_tune_decision(&learned);
    tuner
        .constrain_candidate(telemetry, &candidate, &base)
        .0
        .to_tune_decision()
}

pub(super) async fn tuner_loop(
    connection: Connection,
    metrics: Arc<RuntimeMetrics>,
    sender: watch::Sender<Option<TuneDecisionV2>>,
    runtime_state: Arc<V2RuntimeState>,
    ticket_partition: String,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut capacity_probe_edge_interval = tokio::time::interval(CAPACITY_PROBE_EDGE_INTERVAL);
    capacity_probe_edge_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let bounds = AutoTuneBoundsV2::default();
    let tuner = AutoTunerV2::new(bounds, 1);
    let objective = match runtime_state.autotune.objective {
        AutotuneObjective::Balanced => Objective::Balanced,
        AutotuneObjective::Throughput => Objective::Throughput,
        AutotuneObjective::Latency => Objective::Latency,
    };
    let forced_action = autotune_force_from_env()?;
    let learner_mode = if forced_action.is_some() {
        LearnerModeV2::Off
    } else {
        match runtime_state.autotune.mode {
            AutotuneMode::Off => LearnerModeV2::Off,
            AutotuneMode::Shadow => LearnerModeV2::Shadow,
            AutotuneMode::On => LearnerModeV2::On,
        }
    };
    // `native` is the explicit host-side conservative rules backend (no
    // learner). `builtin` is the in-process `PolicySpecV1` core learner;
    // only external absolute `.wasm` components enter the verified Wasmtime
    // loader. External JSON artifacts are gone.
    // Utility is host-computed with the canonical objective weights in all
    // cases — a component carries no weight bag of its own.
    let selection = runtime_state.autotune.policy.as_str();
    let wasm_selection = is_external_wasm_policy_selection(selection);
    let peer_hash = policy_peer_hash(connection.remote_id().as_bytes());
    let utility_weights = objective.weights();
    let mut policy_source = selection.to_owned();
    // Whole-file digest of the live component, for reload change detection.
    let mut wasm_seen_hash: Option<[u8; 32]> = None;
    let live_slot = if wasm_selection {
        let path = std::path::Path::new(selection);
        match load_wasm_live_slot(&runtime_state, path) {
            Ok((slot, file_hash)) => {
                info!(
                    peer = %connection.remote_id(),
                    policy_id = %slot.identity().policy_id,
                    policy_version = %slot.identity().policy_version,
                    state_schema = slot.identity().state_schema,
                    module_digest = %slot.module_digest(),
                    "loaded WASM autotune policy"
                );
                wasm_seen_hash = Some(file_hash);
                slot
            }
            Err(error) => {
                warn!(
                    configured = %selection,
                    error = %format_args!("{error:#}"),
                    "rejected external V2 WASM autotune policy and fell back to the native-core builtin policy"
                );
                policy_source = crate::protocol::v2::policy::BUILTIN_POLICY_SOURCE_V2.to_owned();
                builtin_core_slot(learner_mode)
            }
        }
    } else {
        non_wasm_live_slot(selection, learner_mode, &mut policy_source)
    };
    let mut tick_config = PolicyTickConfigV1::new(objective, learner_mode);
    tick_config.forced = forced_action;
    tick_config.max_egress_bytes_per_second = runtime_state.max_egress_bytes_per_second;
    tick_config.state_cap_bytes =
        u32::try_from(runtime_state.autotune.wasm.maximum_state_bytes).unwrap_or(u32::MAX);
    tick_config.peer_hash = peer_hash;
    let mut tick = PolicyTickV1::new(tuner, live_slot, utility_weights, tick_config);
    info!(
        policy_id = %tick.live().identity().policy_id,
        policy_version = %tick.live().identity().policy_version,
        %policy_source,
        backend = %tick.live().status().backend,
        state_schema = tick.live().identity().state_schema,
        module_digest = %tick.live().module_digest(),
        ?objective,
        mode = ?runtime_state.autotune.mode,
        memory = runtime_state.autotune.memory,
        "loaded V2 autotune policy"
    );
    // Optional shadow policy (`.wasm` only since Phase 6): observes the live
    // input without influencing the wire. Reloaded on change like the live
    // component, minus the warmup stage — a shadow is already off-wire.
    let shadow_selection = runtime_state
        .autotune
        .shadow_policy
        .as_deref()
        .filter(|path| is_external_wasm_policy_path(path));
    let mut last_shadow_reload_error: Option<String> = None;
    let mut shadow_seen_hash: Option<[u8; 32]> = None;
    if let Some(shadow_path) = shadow_selection {
        match load_wasm_backend(&runtime_state, shadow_path) {
            Ok((backend, file_hash)) => {
                let shadow = shadow_evaluator_for_backend(backend, objective, peer_hash);
                info!(
                    peer = %connection.remote_id(),
                    shadow_policy_id = %shadow.policy_id(),
                    source = %shadow_path.display(),
                    "loaded V2 WASM shadow autotune policy"
                );
                shadow_seen_hash = Some(file_hash);
                tick.set_shadow(Some(shadow));
            }
            Err(error) => {
                let message = format!("{error:#}");
                warn!(
                    source = %shadow_path.display(),
                    error = %message,
                    "ignored invalid V2 WASM shadow autotune policy"
                );
                last_shadow_reload_error = Some(message);
            }
        }
    }
    let peer_name = connection.remote_id().to_string();
    let state_store = runtime_state.autotune.memory.then(|| {
        PolicyStateStoreV1::new(
            &runtime_state.autotune_state_dir,
            Duration::from_secs(runtime_state.autotune.wasm.state_flush_interval_secs),
            usize::try_from(runtime_state.autotune.wasm.maximum_state_bytes).unwrap_or(usize::MAX),
        )
    });
    if let Some(store) = &state_store {
        restore_policy_state(
            store,
            tick.live_mut(),
            &runtime_state.autotune_state_dir,
            &peer_name,
            peer_hash,
        );
    }
    let mut last_state_flush = Instant::now();
    let mut last_policy_fault: Option<PolicyFaultV1> = None;
    if let Some(forced_action) = forced_action {
        info!(
            peer = %connection.remote_id(),
            ?forced_action,
            "enabled guarded IRONET_AUTOTUNE_FORCE experiment"
        );
    }
    let mut previous = connection.stats();
    let initial_sample_at = Instant::now();
    let initial_tx_bytes = TxByteSnapshotV2::load(&metrics, previous.udp_tx.bytes);
    let initial_sample_counters =
        SampleCounterSnapshot::capture_with_tx(&metrics, initial_tx_bytes);
    let mut sample_counters = initial_sample_counters;
    let mut previous_sample_at = initial_sample_at;
    let mut status_counters = StatusCounterSnapshot::capture_with_tx(
        &metrics,
        initial_tx_bytes,
        initial_sample_counters.real_bytes,
        Instant::now(),
    );
    let remote_feedback_sequence = metrics.remote_feedback_sequence.load(Ordering::Acquire);
    let mut remote_feedback =
        RemoteFeedbackSnapshot::capture(&metrics, remote_feedback_sequence, Instant::now());
    let mut remote_wasted_parity_per_mille = 0_u16;
    let mut remote_fec_recovery_per_mille = 0_u16;
    let mut remote_repair_hit_per_mille = 0_u16;
    let mut remote_repair_response_latency = Duration::ZERO;
    let mut remote_receiver_goodput_bytes_per_second = 0_u64;
    let mut remote_reorder_ppm = 0_u32;
    let mut remote_residual_loss_ppm = 0_u32;
    let mut remote_burst_loss_cells = 0_u16;
    let mut path_identity = String::new();
    let mut path_epoch = 1_u64;
    let mut adaptive_cwnd_floor_state = AdaptiveCwndFloorStateV2::default();
    let mut capacity_probe_state = CapacityProbeStateV2::default();
    capacity_probe_state.initialize_bulk_service_counter(
        path_epoch,
        metrics.bulk_service_bytes.load(Ordering::Relaxed),
    );
    let mut minimum_rtt = Duration::MAX;
    let mut previous_controller_guard_transitions = 0_u64;
    let mut telemetry_failures = 0_u64;
    let mut policy_reload_tick = 0_u8;
    let mut wasm_pending: Option<tokio::task::JoinHandle<Result<WasmPolicyBackend>>> = None;
    let mut wasm_warmup: Option<WasmWarmupV1> = None;
    let mut last_wasm_reload_error: Option<String> = None;
    let mut shadow_pending: Option<tokio::task::JoinHandle<Result<WasmPolicyBackend>>> = None;
    interval.tick().await;
    capacity_probe_edge_interval.tick().await;
    loop {
        let full_policy_tick = tokio::select! {
            biased;
            _ = interval.tick() => true,
            _ = capacity_probe_edge_interval.tick() => false,
        };
        if !full_policy_tick {
            let bulk_service_counter = metrics.bulk_service_bytes.load(Ordering::Relaxed);
            let path_sample = selected_path_sample(&connection).ok();
            let path_matches = path_sample.as_ref().is_some_and(|sample| {
                fast_capacity_probe_path_matches(&path_identity, &sample.identity)
            });
            if path_matches
                && capacity_probe_state.update_bulk_service_counter(bulk_service_counter)
            {
                let published = path_sample
                    .and_then(|sample| sample.controller_tunables)
                    .is_some_and(|tunables| {
                        publish_capacity_probe(&tunables);
                        true
                    });
                if !published {
                    // The normal one-second telemetry path remains the
                    // fallback if a selected BBR path was transiently absent.
                    capacity_probe_state.cancel_bulk_service_edge();
                }
            }
            continue;
        }
        let sampled_at = Instant::now();
        policy_reload_tick = policy_reload_tick.wrapping_add(1);
        if wasm_selection {
            // Plan section 8.3: the candidate component is read into a
            // private buffer, verified, compiled and self-checked on a
            // blocking worker while the active component keeps deciding. A
            // finished candidate then enters shadow warmup: it observes the
            // live input for `WASM_WARMUP_TICKS` fault-free ticks before it
            // is promoted at a sample boundary. Failures only update the
            // error state — the active (last known-good) component is never
            // replaced by a bad file or an unhealthy candidate.
            if let Some(handle) = wasm_pending.as_mut()
                && handle.is_finished()
            {
                let handle = wasm_pending.take().expect("pending handle checked above");
                match handle.await {
                    Ok(Ok(backend)) => {
                        let accepts = backend.manifest().state_schema_accepts.clone();
                        let new_policy_id = backend.identity().policy_id.clone();
                        let digest = backend
                            .identity()
                            .digest
                            .map(|digest| encode_digest(&digest))
                            .unwrap_or_default();
                        let slot = PolicySlotV1::new(Box::new(backend), None, digest.clone());
                        let mut evaluator = ShadowEvaluatorV2::from_slot(
                            slot,
                            objective.weights(),
                            objective,
                            new_policy_id.clone(),
                            digest,
                        );
                        evaluator.set_peer_hash(peer_hash);
                        wasm_warmup = Some(WasmWarmupV1 {
                            evaluator,
                            accepts,
                            healthy_ticks: 0,
                        });
                        info!(
                            peer = %connection.remote_id(),
                            new_policy_id = %new_policy_id,
                            source = %runtime_state.autotune.policy,
                            warmup_ticks = WASM_WARMUP_TICKS,
                            "V2 WASM autotune policy candidate entered shadow warmup"
                        );
                    }
                    Ok(Err(error)) => {
                        let message = format!("{error:#}");
                        if last_wasm_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            last_wasm_reload_error = Some(message);
                        }
                    }
                    Err(error) => {
                        let message = format!("WASM policy load task failed: {error}");
                        if last_wasm_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            last_wasm_reload_error = Some(message);
                        }
                    }
                }
            }
            if policy_reload_tick.is_multiple_of(5)
                && wasm_pending.is_none()
                && wasm_warmup.is_none()
                && let Some(loader) = runtime_state.policy_loader().cloned()
            {
                let path = std::path::PathBuf::from(&runtime_state.autotune.policy);
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let file_hash = *blake3::hash(&bytes).as_bytes();
                        if Some(file_hash) != wasm_seen_hash {
                            // Remember the hash before loading: a bad file is
                            // reported once and not retried until it changes.
                            wasm_seen_hash = Some(file_hash);
                            match TrustStoreV1::from_config(&runtime_state.autotune.wasm) {
                                Ok(trust) => {
                                    let config = runtime_state.autotune.wasm.clone();
                                    wasm_pending = Some(tokio::task::spawn_blocking(move || {
                                        loader.load_from_bytes(
                                            &bytes,
                                            &config,
                                            &trust,
                                            chrono::Utc::now(),
                                        )
                                    }));
                                }
                                Err(error) => {
                                    let message = format!("{error:#}");
                                    if last_wasm_reload_error.as_deref() != Some(&message) {
                                        warn!(
                                            peer = %connection.remote_id(),
                                            source = %runtime_state.autotune.policy,
                                            error = %message,
                                            "invalid WASM trust store; retained last known-good V2 autotune policy"
                                        );
                                        last_wasm_reload_error = Some(message);
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        let message = format!("reading {}: {error}", path.display());
                        if last_wasm_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            last_wasm_reload_error = Some(message);
                        }
                    }
                }
            }
        }
        if let Some(shadow_path) = shadow_selection {
            // Verified background load like the live component, minus the
            // warmup stage — a shadow is already off-wire. Failures only
            // update the error state; the last known-good shadow stays.
            if let Some(handle) = shadow_pending.as_mut()
                && handle.is_finished()
            {
                let handle = shadow_pending.take().expect("pending handle checked above");
                match handle.await {
                    Ok(Ok(backend)) => {
                        let shadow = shadow_evaluator_for_backend(backend, objective, peer_hash);
                        info!(
                            peer = %connection.remote_id(),
                            new_shadow_policy_id = %shadow.policy_id(),
                            source = %shadow_path.display(),
                            "hot-switched V2 WASM shadow autotune policy at sample boundary"
                        );
                        tick.set_shadow(Some(shadow));
                    }
                    Ok(Err(error)) => {
                        let message = format!("{error:#}");
                        if last_shadow_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            last_shadow_reload_error = Some(message);
                        }
                    }
                    Err(error) => {
                        let message = format!("WASM shadow policy load task failed: {error}");
                        if last_shadow_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            last_shadow_reload_error = Some(message);
                        }
                    }
                }
            }
            if policy_reload_tick.is_multiple_of(5)
                && shadow_pending.is_none()
                && let Some(loader) = runtime_state.policy_loader().cloned()
            {
                match std::fs::read(shadow_path) {
                    Ok(bytes) => {
                        let file_hash = *blake3::hash(&bytes).as_bytes();
                        if Some(file_hash) != shadow_seen_hash {
                            // Remember the hash before loading: a bad file is
                            // reported once and not retried until it changes.
                            shadow_seen_hash = Some(file_hash);
                            match TrustStoreV1::from_config(&runtime_state.autotune.wasm) {
                                Ok(trust) => {
                                    let config = runtime_state.autotune.wasm.clone();
                                    shadow_pending = Some(tokio::task::spawn_blocking(move || {
                                        loader.load_from_bytes(
                                            &bytes,
                                            &config,
                                            &trust,
                                            chrono::Utc::now(),
                                        )
                                    }));
                                }
                                Err(error) => {
                                    let message = format!("{error:#}");
                                    if last_shadow_reload_error.as_deref() != Some(&message) {
                                        warn!(
                                            peer = %connection.remote_id(),
                                            source = %shadow_path.display(),
                                            error = %message,
                                            "invalid WASM trust store; retained last known-good V2 shadow autotune policy"
                                        );
                                        last_shadow_reload_error = Some(message);
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        let message = format!("reading {}: {error}", shadow_path.display());
                        if last_shadow_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            last_shadow_reload_error = Some(message);
                        }
                    }
                }
            }
        }
        let sample_elapsed = sampled_at.saturating_duration_since(previous_sample_at);
        let current = connection.stats();
        let path = match selected_path_sample(&connection) {
            Ok(sample) => {
                if telemetry_failures != 0 {
                    info!(
                        peer = %connection.remote_id(),
                        failures = telemetry_failures,
                        "V2 path telemetry recovered without replacing the logical session"
                    );
                    telemetry_failures = 0;
                }
                sample
            }
            Err(error) => {
                telemetry_failures = telemetry_failures.saturating_add(1);
                let decision = tick.fallback_for_missing_telemetry();
                metrics
                    .receive_buffer_bytes
                    .store(decision.receive_buffer_bytes as u64, Ordering::Relaxed);
                if sender.send(Some(decision)).is_err() {
                    if let Some(store) = &state_store
                        && tick.live().is_dirty()
                    {
                        flush_policy_state(store, tick.live_mut(), &peer_name)?;
                    }
                    return Ok(());
                }
                if telemetry_failures == 1 || telemetry_failures.is_multiple_of(10) {
                    warn!(
                        peer = %connection.remote_id(),
                        failures = telemetry_failures,
                        path_epoch = decision.path_epoch,
                        reason = ?decision.reason,
                        %error,
                        "V2 path telemetry unavailable; applied bounded conservative tuning"
                    );
                }
                let current_sample_counters =
                    SampleCounterSnapshot::capture(&metrics, current.udp_tx.bytes);
                previous = current;
                previous_sample_at = sampled_at;
                sample_counters = current_sample_counters;
                continue;
            }
        };
        let SelectedPathSampleV2 {
            identity,
            reliability,
            rtt,
            congestion_window_bytes,
            current_mtu,
            controller_pacing_rate_bytes_per_second,
            controller_send_quantum_bytes,
            controller_queue_delay_guard_transitions,
            controller_policer_pacing_scale_per_mille,
            controller_policer_pacing_transitions,
            controller_snapshot,
            controller_tunables,
        } = path;
        let route_capacity_bytes_per_second = controller_snapshot
            .map(|snapshot| snapshot.bw.max(snapshot.max_bw))
            .filter(|capacity| *capacity != 0)
            .or(controller_pacing_rate_bytes_per_second)
            .unwrap_or(0);
        metrics.route_capacity_bps.store(
            route_capacity_bytes_per_second.saturating_mul(8),
            Ordering::Relaxed,
        );
        // PathId is a QUIC controller identity, while `path_identity` below is
        // deliberately a stable network-locator epoch. noq may recycle PathId
        // without changing the locator, so never cache its path-local BBR
        // handle across samples.
        let bbr_tunables = controller_tunables;
        if identity != path_identity {
            let migrated = !path_identity.is_empty();
            let previous_identity = std::mem::replace(&mut path_identity, identity);
            if migrated {
                path_epoch = path_epoch.wrapping_add(1).max(1);
            }
            minimum_rtt = rtt;
            previous_controller_guard_transitions =
                controller_snapshot.map_or(0, |snapshot| snapshot.guard_transitions);
            if migrated {
                info!(
                    path_epoch,
                    ?reliability,
                    previous_path = %previous_identity,
                    selected_path = %path_identity,
                    "V2 QUIC path migrated without replacing the logical session"
                );
            }
        }
        minimum_rtt = minimum_rtt.min(rtt);
        metrics.repair_minimum_age_micros.store(
            repair_minimum_age_for_rtt(rtt)
                .as_micros()
                .min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        let sent_packets = counter_delta(current.udp_tx.datagrams, previous.udp_tx.datagrams);
        let received_packets = counter_delta(current.udp_rx.datagrams, previous.udp_rx.datagrams);
        let lost_packets = counter_delta(current.lost_packets, previous.lost_packets);
        let loss_ppm = ratio_per_million(lost_packets, sent_packets.saturating_add(lost_packets));
        let sent_bytes = counter_delta(current.udp_tx.bytes, previous.udp_tx.bytes);
        let received_bytes = counter_delta(current.udp_rx.bytes, previous.udp_rx.bytes);
        let sent_bytes_per_second = rate_per_second(sent_bytes, sample_elapsed);
        let received_bytes_per_second = rate_per_second(received_bytes, sample_elapsed);
        let current_sample_counters =
            SampleCounterSnapshot::capture(&metrics, current.udp_tx.bytes);
        let sample_delta = current_sample_counters.saturating_delta(sample_counters);
        let real_bytes = current_sample_counters.real_bytes;
        let real_delta = sample_delta.real_bytes;
        let tun_ingress_records_delta = sample_delta.tun_ingress_records;
        let tun_ingress_bytes_delta = sample_delta.tun_ingress_bytes;
        let gso_input_bytes_delta = sample_delta.gso_input_bytes;
        let reassembly_pressure_evictions_delta = sample_delta.reassembly_pressure_evictions;
        let train_build_bytes_per_second =
            rate_per_second(sample_delta.train_build_bytes, sample_elapsed);
        let bulk_preemption_delta = sample_delta.bulk_preemptions;
        let bulk_preemption_delay_average_micros = sample_delta
            .bulk_preemption_delay_micros
            .checked_div(bulk_preemption_delta)
            .unwrap_or_default();
        let tun_ingress_bytes_per_second = rate_per_second(tun_ingress_bytes_delta, sample_elapsed);
        let average_record_bytes = tun_ingress_bytes_delta
            .checked_div(tun_ingress_records_delta)
            .unwrap_or_default();
        let gso_ingress_ratio_ppm =
            ratio_per_million(gso_input_bytes_delta, tun_ingress_bytes_delta);
        let train_queue_bytes = metrics.train_queue_bytes.load(Ordering::Relaxed);
        let latency_queue_bytes = metrics.latency_queue_bytes.load(Ordering::Relaxed);
        let cpu_utilization_per_mille = runtime_state
            .cpu_utilization_per_mille
            .load(Ordering::Relaxed)
            .min(1_000) as u16;
        let current_remote_feedback_sequence =
            metrics.remote_feedback_sequence.load(Ordering::Acquire);
        let mut remote_expired_stripes_delta = 0;
        if current_remote_feedback_sequence != remote_feedback.sequence {
            let current_remote_feedback = RemoteFeedbackSnapshot::capture(
                &metrics,
                current_remote_feedback_sequence,
                sampled_at,
            );
            let remote_delta = current_remote_feedback.counter_delta(remote_feedback);
            let feedback_elapsed = sampled_at.saturating_duration_since(remote_feedback.at);
            remote_expired_stripes_delta = remote_delta.expired_trains;
            remote_receiver_goodput_bytes_per_second =
                rate_per_second(remote_delta.delivered_payload, feedback_elapsed);
            remote_reorder_ppm =
                ratio_per_million(remote_delta.reorder_cells, remote_delta.sent_data_cells);
            remote_residual_loss_ppm =
                ratio_per_million(remote_delta.missing_cells, remote_delta.sent_data_cells);
            let loss_runs = remote_delta
                .loss_run_1
                .saturating_add(remote_delta.loss_run_2)
                .saturating_add(remote_delta.loss_run_3_4)
                .saturating_add(remote_delta.loss_run_5_plus);
            let weighted_loss_cells = remote_delta
                .loss_run_1
                .saturating_add(remote_delta.loss_run_2.saturating_mul(2))
                .saturating_add(remote_delta.loss_run_3_4.saturating_mul(4))
                .saturating_add(remote_delta.loss_run_5_plus.saturating_mul(5));
            remote_burst_loss_cells = weighted_loss_cells
                .checked_div(loss_runs)
                .unwrap_or_default()
                .min(u64::from(u16::MAX)) as u16;
            if remote_delta.fec_parity != 0 {
                remote_wasted_parity_per_mille =
                    ratio_per_thousand(remote_delta.fec_wasted, remote_delta.fec_parity);
                remote_fec_recovery_per_mille =
                    ratio_per_thousand(remote_delta.fec_recovered, remote_delta.fec_parity);
            }
            if remote_delta.repair_completed_requested != 0 {
                remote_repair_hit_per_mille = ratio_per_thousand(
                    remote_delta.repair_received,
                    remote_delta.repair_completed_requested,
                );
            }
            if remote_delta.repair_completed != 0 {
                remote_repair_response_latency = Duration::from_micros(
                    remote_delta
                        .repair_latency_micros
                        .checked_div(remote_delta.repair_completed)
                        .unwrap_or_default(),
                );
            }
            remote_feedback = current_remote_feedback;
        }
        let latency_sojourn_delta = sample_delta.latency_sojourn;
        let latency_sojourn_p50_micros = histogram_percentile_micros(&latency_sojourn_delta, 50);
        let latency_sojourn_p95_micros = histogram_percentile_micros(&latency_sojourn_delta, 95);
        let latency_sojourn_p99_micros = histogram_percentile_micros(&latency_sojourn_delta, 99);
        let latency_queue_recently_nonempty =
            latency_queue_bytes != 0 || latency_sojourn_delta.iter().any(|count| *count != 0);
        let controller_guard_transitions =
            controller_snapshot.map_or(0, |snapshot| snapshot.guard_transitions);
        let controller_guard_transitions_delta =
            controller_guard_transitions.saturating_sub(previous_controller_guard_transitions);
        previous_controller_guard_transitions = controller_guard_transitions;
        let controller_tunables_generation = bbr_tunables
            .as_ref()
            .map_or(0, |tunables| tunables.generation.load(Ordering::Relaxed));
        let controller_clamped_writes = bbr_tunables.as_ref().map_or(0, |tunables| {
            tunables.clamped_writes.load(Ordering::Relaxed)
        });
        let telemetry = PathTelemetryV2 {
            path_epoch,
            reliability,
            rtt,
            min_rtt: minimum_rtt,
            queue_delay: rtt.saturating_sub(minimum_rtt),
            loss_ppm,
            burst_loss_cells: remote_burst_loss_cells,
            reorder_ppm: remote_reorder_ppm,
            receiver_goodput_bytes_per_second: remote_receiver_goodput_bytes_per_second,
            residual_loss_ppm: remote_residual_loss_ppm,
            latency_sojourn_p95_micros,
            latency_sojourn_p50_micros,
            latency_sojourn_p99_micros,
            latency_queue_recently_nonempty,
            delivery_rate_bytes_per_second: sent_bytes_per_second,
            controller_pacing_rate_bytes_per_second: controller_pacing_rate_bytes_per_second
                .unwrap_or_default(),
            controller_send_quantum_bytes: controller_send_quantum_bytes.unwrap_or_default(),
            controller_state: controller_snapshot.map_or(0, |snapshot| snapshot.state),
            controller_bw_bytes_per_second: controller_snapshot.map_or(0, |snapshot| snapshot.bw),
            controller_inflight_longterm_bytes: controller_snapshot
                .map_or(0, |snapshot| snapshot.inflight_longterm),
            controller_guard_transitions_delta,
            controller_app_limited: controller_snapshot
                .is_some_and(|snapshot| snapshot.app_limited_in_round),
            controller_tunables_generation,
            controller_params_generation: controller_snapshot
                .map_or(0, |snapshot| snapshot.params_generation),
            controller_clamped_writes,
            receive_rate_bytes_per_second: received_bytes_per_second,
            // Receive coalescing is driven by the busier direction. This is
            // essential for asymmetric paths: a gateway receiving a Bulk
            // stream may transmit little more than QUIC ACKs itself.
            packets_per_second: sent_packets.max(received_packets),
            tun_ingress_bytes_per_second,
            average_record_bytes,
            gso_ingress_ratio_ppm,
            packet_train_queue_bytes: train_queue_bytes,
            latency_queue_bytes,
            reassembly_pressure_evictions: reassembly_pressure_evictions_delta,
            remote_expired_stripes_delta,
            train_build_bytes_per_second,
            bulk_preemption_delay_average_micros,
            cpu_utilization_per_mille,
            wasted_parity_per_mille: remote_wasted_parity_per_mille,
            fec_recovery_per_mille: remote_fec_recovery_per_mille,
            repair_hit_per_mille: remote_repair_hit_per_mille,
            repair_completed_requests: remote_feedback.repair_completed,
            repair_response_latency: remote_repair_response_latency,
            real_traffic_bytes_per_second: rate_per_second(real_delta, sample_elapsed),
        };
        let controller_policer_episode_active =
            controller_policer_episode_active(controller_policer_pacing_transitions);
        let bulk_capacity_probe =
            capacity_probe_state.update(telemetry, controller_policer_episode_active);
        let loss_recovery_probe = capacity_probe_state
            .update_loss_episode_if_complete(telemetry, controller_policer_episode_active);
        let wire_cost = current_sample_counters
            .utility_tx_bytes
            .delta(sample_counters.utility_tx_bytes)
            .breakdown()
            .wire_cost();
        // Baseline -> PolicyInputV1 -> backend decide -> guardrails ->
        // EffectiveActionV1 -> TuneDecisionV2 (and the shadow evaluation),
        // see `protocol::v2::policy_tick`.
        // Plan section 9: read the node egress view for this tick before the
        // pipeline runs; publish the guarded request afterwards. Both are
        // lock-protected shared state, so a slow or faulting guest on
        // another peer can never block this tick.
        let egress_peer_key = tick.config().peer_hash;
        tick.set_egress_view(
            runtime_state
                .egress_coordinator
                .view(egress_peer_key, sampled_at),
        );
        let mut outcome = tick.run(telemetry, &wire_cost, sampled_at);
        let adaptive_cwnd_floor_bytes = finalize_bbr3_effective_with_state(
            &mut adaptive_cwnd_floor_state,
            telemetry,
            congestion_window_bytes,
            &mut outcome.effective.bbr,
        );
        let pacing_cap_release_probe = capacity_probe_state.update_pacing_cap_if_complete(
            outcome.effective.bbr.pacing_cap_bytes_per_second,
            telemetry.tun_ingress_bytes_per_second > 0,
        );
        // Bulk and loss state machines consume prohibited edges at their
        // source. Verified-idle Bulk epochs and explicit cap releases retain
        // independent authority to restart discovery.
        let request_capacity_probe =
            bulk_capacity_probe || loss_recovery_probe || pacing_cap_release_probe;
        let egress_requested_bytes_per_second =
            outcome.effective.egress.desired_rate_bytes_per_second;
        runtime_state.egress_coordinator.publish(
            egress_peer_key,
            outcome.effective.egress,
            sampled_at,
        );
        // Plan section 8.3 shadow warmup: the candidate observes this tick's
        // live input without influencing the wire; any fault aborts it and
        // `WASM_WARMUP_TICKS` consecutive healthy ticks promote it to live.
        if let Some(warmup) = wasm_warmup.as_mut() {
            let evaluation = warmup.evaluator.observe(
                sampled_at,
                tick.tuner(),
                &telemetry,
                &wire_cost,
                outcome.baseline,
            );
            if let Some(fault) = evaluation.fault {
                warn!(
                    peer = %connection.remote_id(),
                    policy_id = %warmup.evaluator.policy_id(),
                    healthy_ticks = warmup.healthy_ticks,
                    %fault,
                    "aborted V2 WASM policy warmup; retained last known-good"
                );
                wasm_warmup = None;
            } else {
                warmup.healthy_ticks = warmup.healthy_ticks.saturating_add(1);
                if warmup.healthy_ticks >= WASM_WARMUP_TICKS {
                    let warmup = wasm_warmup.take().expect("warmup checked above");
                    let policy_id = warmup.evaluator.policy_id().to_owned();
                    let (backend, probe, digest) = warmup.evaluator.into_slot().into_backend();
                    if let Some(store) = &state_store
                        && tick.live().is_dirty()
                        && let Err(error) = flush_policy_state(store, tick.live_mut(), &peer_name)
                    {
                        warn!(
                            peer = %connection.remote_id(),
                            %error,
                            "failed persisting V2 policy state before hot switch"
                        );
                    }
                    let kept_state = tick.replace_live(
                        backend,
                        probe,
                        digest,
                        objective.weights(),
                        &warmup.accepts,
                    );
                    if !kept_state && let Some(store) = &state_store {
                        let identity = tick.live().identity().clone();
                        if let Some(state) =
                            store.load(&identity.policy_id, identity.state_schema, &peer_name)
                        {
                            tick.live_mut().set_state(state);
                        }
                    }
                    last_wasm_reload_error = None;
                    info!(
                        peer = %connection.remote_id(),
                        new_policy_id = %policy_id,
                        source = %runtime_state.autotune.policy,
                        kept_state,
                        warmup_ticks = WASM_WARMUP_TICKS,
                        "promoted V2 WASM autotune policy after shadow warmup"
                    );
                }
            }
        }
        let decision = outcome.decision;
        if outcome.fault != last_policy_fault {
            match outcome.fault {
                Some(fault) => {
                    let health = tick.live().health();
                    warn!(
                        peer = %connection.remote_id(),
                        %fault,
                        health = ?health.state,
                        faults_total = health.faults_total,
                        "V2 policy backend fault; applied the host baseline"
                    );
                }
                None => info!(
                    peer = %connection.remote_id(),
                    "V2 policy backend recovered"
                ),
            }
            last_policy_fault = outcome.fault;
        }
        if let Some(tunables) = bbr_tunables.as_deref() {
            publish_bbr3_effective(tunables, &outcome.effective.bbr, request_capacity_probe);
        }
        let utility = outcome.utility;
        let learner_trace = outcome.trace;
        let shadow_evaluation = outcome.shadow;
        let shadow_policy_id = tick.shadow().map(|shadow| shadow.policy_id().to_owned());
        let live_policy_id = tick.live().identity().policy_id.clone();
        let egress_assigned_bytes_per_second = tick.egress_view().assigned_rate_bytes_per_second;
        runtime_state.publish_tune_status(
            connection.remote_id(),
            TuneStatusSampleV2 {
                decision,
                utility,
                learner: learner_trace,
                policy_id: &live_policy_id,
                policy_source: &policy_source,
                shadow_policy_id: shadow_policy_id.as_deref(),
                shadow: shadow_evaluation,
                live: tick.live().status(),
                shadow_slot: tick.shadow().map(|shadow| shadow.slot().status()),
                egress_requested_bytes_per_second,
                egress_assigned_bytes_per_second,
            },
        );
        if tracing::enabled!(target: "ironet::autotune", tracing::Level::DEBUG) {
            let sampled_unix_micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            let record = autotune_tap_record(
                connection.remote_id(),
                &ticket_partition,
                AutotuneTapSampleV2 {
                    sampled_unix_micros,
                    sample_elapsed,
                    telemetry,
                    decision,
                    utility,
                    wire_cost,
                    force_applied: forced_action.is_some(),
                    learner: Some(learner_trace),
                    policy_id: &live_policy_id,
                    policy_source: &policy_source,
                    shadow_policy_id: shadow_policy_id.as_deref(),
                    shadow: shadow_evaluation,
                    path_identity: &path_identity,
                    controller_cwnd_bytes: congestion_window_bytes,
                    adaptive_cwnd_floor_bytes,
                },
            );
            debug!(
                target: "ironet::autotune",
                record = %record,
                "V2 autotune tap"
            );
        }
        metrics
            .receive_buffer_bytes
            .store(decision.receive_buffer_bytes as u64, Ordering::Relaxed);
        metrics
            .reassembly_budget_bytes
            .store(decision.reassembly_budget_bytes as u64, Ordering::Relaxed);
        metrics
            .active_train_budget
            .store(u64::from(decision.active_train_budget), Ordering::Relaxed);
        metrics.repair_wait_policy.store(
            decision.repair_wait_policy.to_metrics_code(),
            Ordering::Relaxed,
        );
        if sender.send(Some(decision)).is_err() {
            if let Some(store) = &state_store
                && tick.live().is_dirty()
            {
                flush_policy_state(store, tick.live_mut(), &peer_name)?;
            }
            return Ok(());
        }
        if let Some(store) = &state_store
            && tick.live().is_dirty()
            && sampled_at.saturating_duration_since(last_state_flush) >= store.flush_interval()
        {
            match flush_policy_state(store, tick.live_mut(), &peer_name) {
                Ok(()) => last_state_flush = sampled_at,
                Err(error) => warn!(
                    peer = %connection.remote_id(),
                    %error,
                    "failed persisting V2 policy state"
                ),
            }
        }
        if decision.sample_count.is_multiple_of(10) {
            let now = Instant::now();
            let status_current =
                StatusCounterSnapshot::capture(&metrics, current.udp_tx.bytes, real_bytes, now);
            let status_delta = status_current.saturating_delta(status_counters);
            let status_elapsed = now.saturating_duration_since(status_counters.at);
            let tx_bytes = status_delta.tx_bytes.breakdown();
            let repair_tx_bytes = tx_bytes
                .repair_request_bytes
                .saturating_add(tx_bytes.repair_response_bytes);
            let quic_transport_residual_per_mille = ratio_per_thousand(
                tx_bytes.quic_transport_residual_bytes,
                tx_bytes.quic_udp_payload_bytes,
            );
            let cell_envelope_overhead_per_mille =
                ratio_per_thousand(tx_bytes.cell_envelope_bytes, tx_bytes.data_cell_bytes);
            let tun_ingress_records = status_current.tun_ingress_records;
            let tun_ingress_bytes = status_current.tun_ingress_bytes;
            let gso_input_bytes = status_current.gso_input_bytes;
            let tun_ingress_records_delta = status_delta.tun_ingress_records;
            let tun_ingress_bytes_delta = status_delta.tun_ingress_bytes;
            let gso_input_bytes_delta = status_delta.gso_input_bytes;
            let tun_ingress_bytes_per_second =
                rate_per_second(tun_ingress_bytes_delta, status_elapsed);
            let gso_ingress_ratio_ppm =
                ratio_per_million(gso_input_bytes_delta, tun_ingress_bytes_delta);
            let average_record_bytes = tun_ingress_bytes_delta
                .checked_div(tun_ingress_records_delta)
                .unwrap_or_default();
            let cover_bytes = status_current.cover_bytes;
            let cover_delta = status_delta.cover_bytes;
            let status_real_delta = status_delta.real_bytes;
            let actual_cover_overhead_per_mille =
                ratio_per_thousand(cover_delta, status_real_delta);
            let actual_cover_overhead_ppm = ratio_per_million(cover_delta, status_real_delta);
            let data_cell_bytes = status_current.data_cell_bytes;
            let data_cell_payload_bytes = status_current.data_cell_payload_bytes;
            let fec_bytes = status_current.fec_bytes;
            let data_cell_delta = status_delta.data_cell_bytes;
            let data_cell_payload_delta = status_delta.data_cell_payload_bytes;
            let fec_delta = status_delta.fec_bytes;
            let actual_cell_wire_utilization_per_mille =
                ratio_per_thousand(data_cell_payload_delta, data_cell_delta);
            let actual_fec_wire_overhead_per_mille = ratio_per_thousand(fec_delta, data_cell_delta);
            let trains_delta = status_delta.trains_built;
            let records_delta = status_delta.records_built;
            let record_bytes_delta = status_delta.record_bytes_built;
            let cells_delta = status_delta.cells_built;
            let cell_payload_built_delta = status_delta.cell_payload_built_bytes;
            let unused_cell_capacity_delta = status_delta.unused_cell_capacity_bytes;
            let cell_payload_utilization_per_mille = ratio_per_thousand(
                record_bytes_delta,
                cell_payload_built_delta.saturating_add(unused_cell_capacity_delta),
            );
            let cells_per_megabyte = ratio_scaled_u64(cells_delta, record_bytes_delta, 1_000_000);
            let records_per_train_milli = ratio_scaled_u64(records_delta, trains_delta, 1_000);
            let fec_parity_rx = status_current.fec_parity_rx;
            let fec_recovered_cells = status_current.fec_recovered_cells;
            let fec_wasted_parity = status_current.fec_wasted_parity;
            let repair_requested_cells = metrics.repair_requested_cells.load(Ordering::Relaxed);
            let repair_received_cells = status_current.repair_received_cells;
            let repair_completed_requests = status_current.repair_completed_requests;
            let repair_completed_requested_cells = status_current.repair_completed_requested_cells;
            let incoming_parity_delta = status_delta.fec_parity_rx;
            let incoming_recovered_delta = status_delta.fec_recovered_cells;
            let incoming_wasted_delta = status_delta.fec_wasted_parity;
            let repair_received_delta = status_delta.repair_received_cells;
            let repair_completed_delta = status_delta.repair_completed_requests;
            let repair_completed_requested_delta = status_delta.repair_completed_requested_cells;
            let repair_latency_delta = status_delta.repair_latency_micros;
            let incoming_repair_response_latency_average_micros = repair_latency_delta
                .checked_div(repair_completed_delta)
                .unwrap_or_default();
            let incoming_fec_recovery_per_mille =
                ratio_per_thousand(incoming_recovered_delta, incoming_parity_delta);
            let incoming_wasted_parity_per_mille =
                ratio_per_thousand(incoming_wasted_delta, incoming_parity_delta);
            let incoming_repair_hit_per_mille =
                ratio_per_thousand(repair_received_delta, repair_completed_requested_delta);
            let bulk_service_delta = status_delta.bulk_service_bytes;
            let latency_service_delta = status_delta.latency_service_bytes;
            let bulk_service_share_ppm = ratio_per_million(
                bulk_service_delta,
                bulk_service_delta.saturating_add(latency_service_delta),
            );
            let latency_sojourn_delta = status_delta.latency_sojourn;
            let latency_queue_sojourn_p50_micros =
                histogram_percentile_micros(&latency_sojourn_delta, 50);
            let latency_queue_sojourn_p95_micros =
                histogram_percentile_micros(&latency_sojourn_delta, 95);
            let latency_queue_sojourn_p99_micros =
                histogram_percentile_micros(&latency_sojourn_delta, 99);
            let bulk_flow_service_delta = status_delta.bulk_flow_service;
            let bulk_fairness_ppm = jain_fairness_ppm(&bulk_flow_service_delta);
            let bulk_preemptions = status_current.bulk_preemptions;
            let bulk_preemption_delay_delta = status_delta.bulk_preemption_delay_micros;
            let bulk_preemption_delta = status_delta.bulk_preemptions;
            let bulk_preemption_delay_average_micros = bulk_preemption_delay_delta
                .checked_div(bulk_preemption_delta)
                .unwrap_or_default();
            info!(
                peer = %connection.remote_id(),
                controller_queue_delay_guard_transitions,
                controller_policer_pacing_scale_per_mille,
                controller_policer_pacing_transitions,
                "V2 automatic controller guard status"
            );
            info!(
                peer = %connection.remote_id(),
                reason = ?decision.reason,
                path_epoch = decision.path_epoch,
                samples = decision.sample_count,
                sample_age_millis = 0,
                rtt_micros = rtt.as_micros(),
                minimum_rtt_micros = minimum_rtt.as_micros(),
                congestion_window_bytes,
                current_path_mtu_bytes = current_mtu,
                controller_pacing_rate_bytes_per_second =
                    controller_pacing_rate_bytes_per_second.unwrap_or(0),
                controller_send_quantum_bytes = controller_send_quantum_bytes.unwrap_or(0),
                loss_ppm,
                tx_bytes_per_second = sent_bytes_per_second,
                rx_bytes_per_second = received_bytes_per_second,
                packets_per_second = sent_packets.max(received_packets),
                tun_ingress_bytes_per_second,
                tun_ingress_records,
                tun_ingress_bytes,
                tun_admission_drop_records = metrics
                    .tun_admission_drop_records
                    .load(Ordering::Relaxed),
                tun_admission_drop_bytes = metrics
                    .tun_admission_drop_bytes
                    .load(Ordering::Relaxed),
                average_record_bytes,
                gso_ingress_ratio_ppm,
                train_queue_bytes,
                latency_queue_bytes,
                bulk_service_share_ppm,
                bulk_fairness_ppm,
                bulk_service_quantums = metrics.bulk_service_quantums.load(Ordering::Relaxed),
                latency_service_quantums = metrics
                    .latency_service_quantums
                    .load(Ordering::Relaxed),
                bulk_preemptions,
                bulk_preemption_delay_average_micros,
                bulk_preemption_max_delay_micros = metrics
                    .bulk_preemption_max_delay_micros
                    .load(Ordering::Relaxed),
                latency_queue_sojourn_p50_micros,
                latency_queue_sojourn_p95_micros,
                latency_queue_sojourn_p99_micros,
                cpu_utilization_per_mille,
                train_target_bytes = decision.train_target_bytes,
                train_minimum_bytes = bounds.minimum_train_bytes,
                train_maximum_bytes = bounds.maximum_train_bytes,
                bulk_quantum_cells = decision.bulk_quantum_cells,
                fec = ?decision.fec,
                repair_cache_bytes = decision.repair_cache_bytes,
                send_buffer_bytes = decision.send_buffer_bytes,
                datagram_admission_bytes = connection.datagram_send_buffer_limit(),
                receive_buffer_bytes = decision.receive_buffer_bytes,
                receive_buffer_target_bytes = metrics.receive_buffer_bytes.load(Ordering::Relaxed),
                reassembly_pressure_evictions = metrics
                    .reassembly_pressure_evictions
                    .load(Ordering::Relaxed),
                receive_batch = decision.receive_batch,
                receive_batch_maximum = bounds.maximum_receive_batch,
                cover_profile = ?decision.cover_profile,
                cover_budget_per_mille = decision.cover_overhead_per_mille,
                cover_padding_bytes_per_second = decision.cover_padding_bytes_per_second,
                cover_tx_bytes = cover_bytes,
                cover_rx_bytes = metrics.cover_rx_bytes.load(Ordering::Relaxed),
                actual_cover_overhead_per_mille,
                actual_cover_overhead_ppm,
                interval_quic_udp_payload_tx_bytes = tx_bytes.quic_udp_payload_bytes,
                interval_real_record_tx_bytes = tx_bytes.real_record_bytes,
                interval_packet_train_metadata_tx_bytes = tx_bytes.packet_train_metadata_bytes,
                interval_cell_envelope_tx_bytes = tx_bytes.cell_envelope_bytes,
                interval_fec_tx_bytes = tx_bytes.fec_bytes,
                interval_repair_tx_bytes = repair_tx_bytes,
                interval_repair_request_tx_bytes = tx_bytes.repair_request_bytes,
                interval_repair_response_tx_bytes = tx_bytes.repair_response_bytes,
                interval_other_control_record_tx_bytes = tx_bytes.other_control_record_bytes,
                interval_padding_tx_bytes = tx_bytes.padding_bytes,
                interval_quic_transport_residual_tx_bytes =
                    tx_bytes.quic_transport_residual_bytes,
                interval_accounting_lag_bytes = tx_bytes.interval_accounting_lag_bytes,
                quic_transport_residual_per_mille,
                cell_envelope_overhead_per_mille,
                control_record_tx_bytes = metrics
                    .control_record_tx_bytes
                    .load(Ordering::Relaxed),
                control_record_rx_bytes = metrics
                    .control_record_rx_bytes
                    .load(Ordering::Relaxed),
                repair_request_tx_bytes = metrics
                    .repair_request_tx_bytes
                    .load(Ordering::Relaxed),
                repair_request_rx_bytes = metrics
                    .repair_request_rx_bytes
                    .load(Ordering::Relaxed),
                repair_response_tx_bytes = metrics
                    .repair_response_tx_bytes
                    .load(Ordering::Relaxed),
                repair_response_rx_bytes = metrics
                    .repair_response_rx_bytes
                    .load(Ordering::Relaxed),
                data_cell_tx_bytes = data_cell_bytes,
                data_cell_payload_tx_bytes = data_cell_payload_bytes,
                actual_cell_wire_utilization_per_mille,
                cell_payload_utilization_per_mille,
                cells_per_megabyte,
                records_per_train_milli,
                fec_tx_bytes = fec_bytes,
                fec_stripes_built = metrics.fec_stripes_built.load(Ordering::Relaxed),
                fec_protected_data_cells = metrics
                    .fec_protected_data_cells
                    .load(Ordering::Relaxed),
                fec_parity_cells_built = metrics
                    .fec_parity_cells_built
                    .load(Ordering::Relaxed),
                fec_encode_copy_bytes = metrics.fec_encode_copy_bytes.load(Ordering::Relaxed),
                fec_unprotected_tail_cells = metrics
                    .fec_unprotected_tail_cells
                    .load(Ordering::Relaxed),
                actual_fec_wire_overhead_per_mille,
                incoming_fec_parity_cells = fec_parity_rx,
                incoming_fec_recovered_cells = fec_recovered_cells,
                incoming_fec_wasted_parity = fec_wasted_parity,
                incoming_fec_recovery_per_mille,
                incoming_wasted_parity_per_mille,
                incoming_repair_requested_cells = repair_requested_cells,
                incoming_repair_received_cells = repair_received_cells,
                incoming_repair_hit_per_mille,
                incoming_repair_completed_requests = repair_completed_requests,
                incoming_repair_completed_requested_cells = repair_completed_requested_cells,
                incoming_repair_response_latency_average_micros,
                incoming_repair_response_latency_max_micros = metrics
                    .repair_latency_max_micros
                    .load(Ordering::Relaxed),
                incoming_repair_stale_responses = metrics
                    .repair_stale_responses
                    .load(Ordering::Relaxed),
                incoming_fec_decode_copy_bytes = metrics
                    .fec_decode_copy_bytes
                    .load(Ordering::Relaxed),
                incoming_fec_expired_stripes = metrics
                    .fec_expired_stripes
                    .load(Ordering::Relaxed),
                gso_input_bytes,
                gso_preserved_bytes = metrics.gso_preserved_bytes.load(Ordering::Relaxed),
                gso_fallback_splits = metrics.gso_fallback_splits.load(Ordering::Relaxed),
                protocol_datagram_errors = metrics
                    .protocol_datagram_errors
                    .load(Ordering::Relaxed),
                route_gate_drops = metrics.route_gate_drops.load(Ordering::Relaxed),
                tls_ticket_partition = %ticket_partition,
                zero_rtt_policy = "disabled",
                zero_rtt_accepted = 0_u64,
                zero_rtt_rejected = 0_u64,
                remote_feedback_sequence = remote_feedback.sequence,
                outgoing_fec_remote_wasted_parity_per_mille =
                    remote_wasted_parity_per_mille,
                outgoing_fec_remote_recovery_per_mille = remote_fec_recovery_per_mille,
                outgoing_repair_remote_hit_per_mille = remote_repair_hit_per_mille,
                outgoing_repair_remote_completed_requests = remote_feedback.repair_completed,
                outgoing_repair_remote_response_latency_micros =
                    remote_repair_response_latency.as_micros(),
                outgoing_fec_remote_expired_stripes = metrics
                    .remote_fec_expired_stripes
                    .load(Ordering::Relaxed),
                "V2 automatic tuning status"
            );
            status_counters = status_current;
        }
        previous = current;
        previous_sample_at = sampled_at;
        sample_counters = current_sample_counters;
    }
}

#[derive(Debug)]
struct SelectedPathSampleV2 {
    identity: String,
    reliability: PathReliability,
    rtt: Duration,
    congestion_window_bytes: u64,
    current_mtu: u16,
    controller_pacing_rate_bytes_per_second: Option<u64>,
    controller_send_quantum_bytes: Option<u64>,
    controller_queue_delay_guard_transitions: u64,
    controller_policer_pacing_scale_per_mille: u16,
    controller_policer_pacing_transitions: u64,
    controller_snapshot: Option<ControllerSnapshot>,
    controller_tunables: Option<Arc<Bbr3Tunables>>,
}

fn selected_path_sample(connection: &Connection) -> Result<SelectedPathSampleV2> {
    let paths = connection.paths();
    let path = paths
        .iter()
        .find(|path| path.is_selected())
        .context("V2 connection has no selected path")?;
    let reliability = path_reliability(path.is_relay(), path.remote_addr());
    let stats = path.stats();
    let controller = connection
        .congestion_state(path.id())
        .map(|controller| controller.metrics());
    let controller_tunables = connection
        .congestion_tunables(path.id())
        .and_then(|handle| handle.downcast::<Bbr3Tunables>().ok());
    Ok(SelectedPathSampleV2 {
        identity: path_endpoint_identity(path.remote_addr()),
        reliability,
        rtt: stats.rtt,
        congestion_window_bytes: stats.cwnd,
        current_mtu: stats.current_mtu,
        controller_pacing_rate_bytes_per_second: controller
            .as_ref()
            .and_then(|metrics| metrics.pacing_rate),
        controller_send_quantum_bytes: controller.as_ref().and_then(|metrics| metrics.send_quantum),
        controller_queue_delay_guard_transitions: controller
            .as_ref()
            .map_or(0, |metrics| metrics.queue_delay_guard_transitions),
        controller_policer_pacing_scale_per_mille: controller
            .as_ref()
            .map_or(1_000, |metrics| metrics.policer_pacing_scale_per_mille),
        controller_policer_pacing_transitions: controller
            .as_ref()
            .map_or(0, |metrics| metrics.policer_pacing_transitions),
        controller_snapshot: controller.as_ref().and_then(|metrics| metrics.snapshot),
        controller_tunables,
    })
}

pub(super) fn path_reliability(is_iroh_relay: bool, remote: &TransportAddr) -> PathReliability {
    if is_iroh_relay
        || matches!(
            remote,
            TransportAddr::Custom(address) if DerpAddr::from_custom(address).is_ok()
        )
    {
        PathReliability::ReliableRelay
    } else {
        PathReliability::Datagram
    }
}

fn ratio_per_million(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(1_000_000)
        .checked_div(denominator)
        .unwrap_or(u64::MAX)
        .min(1_000_000) as u32
}

fn ratio_per_thousand(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(1_000)
        .checked_div(denominator)
        .unwrap_or(u64::MAX)
        .min(1_000) as u16
}

fn ratio_scaled_u64(numerator: u64, denominator: u64, scale: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (u128::from(numerator) * u128::from(scale) / u128::from(denominator)).min(u128::from(u64::MAX))
        as u64
}

fn rate_per_second(value: u64, elapsed: Duration) -> u64 {
    if elapsed.is_zero() {
        return 0;
    }
    (u128::from(value) * 1_000_000_000 / elapsed.as_nanos()).min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::super::V2RuntimeConfig;
    use super::*;
    use crate::{
        derp::DerpPublicKey,
        protocol::v2::{policy::api::BbrHostExt, tuning::Bbr3ProposalV2},
    };

    fn product_config() -> crate::config::Config {
        toml::from_str(include_str!("../../config/example.toml")).unwrap()
    }

    #[test]
    fn builtin_selection_uses_the_native_core_without_initializing_wasmtime() {
        let runtime = V2RuntimeConfig::from_product_config(&product_config()).unwrap();
        let state = V2RuntimeState::new(&runtime, SecretKey::from_bytes(&[47; 32]).public());
        let mut source = runtime.autotune.policy.clone();
        let selection = source.clone();

        assert_eq!(source, crate::config::AUTOTUNE_POLICY_BUILTIN);
        assert!(state.policy_loader.get().is_none());
        let slot = non_wasm_live_slot(&selection, LearnerModeV2::Shadow, &mut source);
        let status = slot.status();
        let builtin = ironet_policy_core::PolicySpecV1::builtin();
        let digest = crate::protocol::v2::policy::canonical_spec_digest(&builtin).unwrap();

        assert_eq!(source, crate::config::AUTOTUNE_POLICY_BUILTIN);
        assert_eq!(status.backend, "native");
        assert_eq!(status.policy_id, builtin.id);
        assert_eq!(status.policy_version, builtin.version);
        assert_eq!(status.state_schema, ironet_policy_core::STATE_SCHEMA_V1);
        assert_eq!(status.module_digest, digest);
        assert!(state.policy_loader.get().is_none());
    }

    #[test]
    fn autotune_tap_is_versioned_complete_and_json_roundtrips() {
        let peer = SecretKey::from_bytes(&[63; 32]).public();
        let telemetry = PathTelemetryV2 {
            path_epoch: 7,
            reliability: PathReliability::Datagram,
            rtt: Duration::from_millis(85),
            min_rtt: Duration::from_millis(80),
            queue_delay: Duration::from_millis(5),
            loss_ppm: 12_000,
            burst_loss_cells: 2,
            reorder_ppm: 300,
            receiver_goodput_bytes_per_second: 4_700_000,
            residual_loss_ppm: 1_200,
            latency_sojourn_p95_micros: 8_000,
            latency_sojourn_p50_micros: 4_000,
            latency_sojourn_p99_micros: 12_000,
            latency_queue_recently_nonempty: true,
            delivery_rate_bytes_per_second: 6_000_000,
            controller_pacing_rate_bytes_per_second: 5_500_000,
            controller_send_quantum_bytes: 64_000,
            controller_state: 5,
            controller_bw_bytes_per_second: 5_000_000,
            controller_inflight_longterm_bytes: 512_000,
            controller_guard_transitions_delta: 1,
            controller_app_limited: false,
            controller_tunables_generation: 9,
            controller_params_generation: 9,
            controller_clamped_writes: 2,
            receive_rate_bytes_per_second: 50_000_000,
            packets_per_second: 4_000,
            tun_ingress_bytes_per_second: 5_000_000,
            average_record_bytes: 1_400,
            gso_ingress_ratio_ppm: 500_000,
            packet_train_queue_bytes: 32_000,
            latency_queue_bytes: 64,
            reassembly_pressure_evictions: 1,
            remote_expired_stripes_delta: 2,
            train_build_bytes_per_second: 4_900_000,
            bulk_preemption_delay_average_micros: 750,
            cpu_utilization_per_mille: 420,
            wasted_parity_per_mille: 900,
            fec_recovery_per_mille: 80,
            repair_hit_per_mille: 950,
            repair_completed_requests: 11,
            repair_response_latency: Duration::from_millis(90),
            real_traffic_bytes_per_second: 4_800_000,
        };
        let decision = AutoTunerV2::new(AutoTuneBoundsV2::default(), 7).observe(telemetry);
        let record = autotune_tap_record(
            peer,
            "partition",
            AutotuneTapSampleV2 {
                sampled_unix_micros: 1_234_567,
                sample_elapsed: Duration::from_secs(1),
                telemetry,
                decision,
                utility: UtilitySample {
                    total: 1.25,
                    components: [2.0, -0.1, -0.2, -0.1, -0.1, -0.1, -0.1, -0.05],
                    goodput_bytes_per_second: 4_700_000,
                },
                wire_cost: WireCostV2 {
                    payload_bytes: 4_700_000,
                    parity_bytes: 120_000,
                    repair_bytes: 8_000,
                    cover_bytes: 0,
                    cell_envelope_bytes: 40_000,
                },
                force_applied: false,
                learner: None,
                policy_id: "bandit-vivace@1",
                policy_source: "builtin",
                shadow_policy_id: None,
                shadow: None,
                path_identity: "ip:2001:db8::1",
                controller_cwnd_bytes: 512_000,
                adaptive_cwnd_floor_bytes: 256_000,
            },
        );
        let encoded = serde_json::to_string(&record).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded["schema_version"], 5);
        assert_eq!(decoded["force_applied"], false);
        assert_eq!(decoded["path_identity"], "ip:2001:db8::1");
        assert_eq!(decoded["policy"]["id"], "bandit-vivace@1");
        assert_eq!(decoded["sample_interval_micros"], 1_000_000);
        assert_eq!(decoded["telemetry"]["reorder_ppm"], 300);
        assert_eq!(decoded["utility"]["goodput_bytes_per_second"], 4_700_000);
        assert_eq!(decoded["wire_cost"]["parity_bytes"], 120_000);
        assert_eq!(
            decoded["telemetry"]["real_traffic_bytes_per_second"],
            4_800_000
        );
        assert_eq!(decoded["decision"]["path_epoch"], 7);
        assert!(decoded["decision"].get("fec").is_some());
        assert_eq!(decoded["decision"]["bbr"]["preset"], "LossyRadio");
        assert_eq!(decoded["controller"]["congestion_window_bytes"], 512_000);
        assert_eq!(decoded["controller"]["adaptive_cwnd_floor_bytes"], 256_000);
        assert!(decoded.get("shadow").is_some());
    }

    #[test]
    fn shadow_evaluator_runs_independent_policy_without_changing_wire_action() {
        let telemetry = crate::protocol::v2::tuning::tests_fixture::sample(1);
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut baseline = tuner.observe(telemetry);
        baseline.sample_count = 8;
        let mut policy = ironet_policy_core::PolicySpecV1::builtin();
        let context =
            crate::protocol::v2::learner::ContextKeyV2::classify_with(&telemetry, &policy.contexts);
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
        let mut shadow = ShadowEvaluatorV2::new(policy, Objective::Balanced, 17);
        let start = Instant::now();
        shadow.observe(start, &tuner, &telemetry, &WireCostV2::default(), baseline);
        let evaluation = shadow.observe(
            start + Duration::from_secs(20),
            &tuner,
            &telemetry,
            &WireCostV2::default(),
            baseline,
        );
        assert_eq!(evaluation.trace.mode, LearnerModeV2::Shadow);
        assert_eq!(evaluation.trace.applied_preset, baseline.bbr.preset);
        assert_eq!(
            evaluation.trace.proposed_preset,
            Bbr3PresetV2::PrivateAggressive
        );
        assert_eq!(
            evaluation.decision.bbr.preset,
            Bbr3PresetV2::PrivateAggressive
        );
        assert_eq!(evaluation.decision.train_target_bytes, 64 * 1024);
        assert_eq!(evaluation.decision.bulk_quantum_cells, 4);
        assert_ne!(evaluation.decision, baseline);
        assert!(evaluation.utility.total.is_finite());
    }

    /// Raw snapshot of every shared controller tunable.
    fn tunables_snapshot(tunables: &Bbr3Tunables) -> [u64; 20] {
        [
            u64::from(
                tunables
                    .probe_bw_up_pacing_gain_milli
                    .load(Ordering::Relaxed),
            ),
            u64::from(
                tunables
                    .probe_bw_down_pacing_gain_milli
                    .load(Ordering::Relaxed),
            ),
            u64::from(tunables.cruise_pacing_gain_milli.load(Ordering::Relaxed)),
            u64::from(tunables.default_cwnd_gain_milli.load(Ordering::Relaxed)),
            u64::from(tunables.probe_bw_up_cwnd_gain_milli.load(Ordering::Relaxed)),
            u64::from(tunables.headroom_milli.load(Ordering::Relaxed)),
            u64::from(tunables.beta_milli.load(Ordering::Relaxed)),
            u64::from(tunables.loss_thresh_milli.load(Ordering::Relaxed)),
            u64::from(tunables.loss_is_congestion.load(Ordering::Relaxed)),
            u64::from(
                tunables
                    .queue_delay_guard_inflation_milli
                    .load(Ordering::Relaxed),
            ),
            tunables
                .queue_delay_guard_slack_micros
                .load(Ordering::Relaxed),
            tunables.probe_rtt_interval_millis.load(Ordering::Relaxed),
            tunables.probe_rtt_duration_millis.load(Ordering::Relaxed),
            u64::from(tunables.probe_rtt_cwnd_gain_milli.load(Ordering::Relaxed)),
            tunables.min_probe_wait_millis.load(Ordering::Relaxed),
            tunables.max_added_probe_wait_millis.load(Ordering::Relaxed),
            tunables
                .pacing_rate_cap_bytes_per_second
                .load(Ordering::Relaxed),
            tunables.cwnd_floor_bytes.load(Ordering::Relaxed),
            tunables.cwnd_cap_bytes.load(Ordering::Relaxed),
            tunables
                .startup_bw_hint_bytes_per_second
                .load(Ordering::Relaxed),
        ]
    }

    fn effective_tunables_snapshot(effective: &BbrEffectiveV1) -> [u64; 20] {
        [
            u64::from(effective.probe_bw_up_pacing_gain_milli),
            u64::from(effective.probe_bw_down_pacing_gain_milli),
            u64::from(effective.cruise_pacing_gain_milli),
            u64::from(effective.default_cwnd_gain_milli),
            u64::from(effective.probe_bw_up_cwnd_gain_milli),
            u64::from(effective.headroom_milli),
            u64::from(effective.beta_milli),
            u64::from(effective.loss_threshold_milli),
            u64::from(effective.loss_is_congestion),
            u64::from(effective.queue_guard_inflation_milli),
            effective.queue_guard_slack_micros,
            effective.probe_rtt_interval_millis,
            effective.probe_rtt_duration_millis,
            u64::from(effective.probe_rtt_cwnd_gain_milli),
            effective.min_probe_wait_millis,
            effective.max_added_probe_wait_millis,
            effective.pacing_cap_bytes_per_second,
            effective.cwnd_floor_bytes,
            effective.cwnd_cap_bytes,
            effective.startup_bw_hint_bytes_per_second,
        ]
    }

    fn queued_adaptive_floor_telemetry() -> PathTelemetryV2 {
        let mut telemetry = crate::protocol::v2::tuning::tests_fixture::sample(1);
        telemetry.controller_app_limited = false;
        telemetry.min_rtt = Duration::from_millis(20);
        telemetry.rtt = Duration::from_millis(22);
        telemetry.queue_delay = Duration::from_millis(2);
        telemetry.packet_train_queue_bytes = 256 * 1024;
        telemetry.tun_ingress_bytes_per_second = 4_000_000;
        telemetry.delivery_rate_bytes_per_second = 4_200_000;
        telemetry.real_traffic_bytes_per_second = 3_800_000;
        telemetry
    }

    #[test]
    fn finalized_bbr_effective_is_tunable_authority_and_idempotent() {
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let mut effective = BbrEffectiveV1::from_proposal(&proposal);
        let adaptive_floor =
            finalize_bbr3_effective(queued_adaptive_floor_telemetry(), 96 * 1024, &mut effective);

        assert_eq!(adaptive_floor, 208 * 1024);
        assert_eq!(effective.cwnd_floor_bytes, adaptive_floor);

        let tunables = Bbr3Tunables::default();
        assert!(apply_bbr3_effective(&tunables, &effective));
        assert_eq!(
            tunables_snapshot(&tunables),
            effective_tunables_snapshot(&effective)
        );
        assert_eq!(tunables.generation.load(Ordering::Acquire), 1);
        assert!(!apply_bbr3_effective(&tunables, &effective));
        assert_eq!(tunables.generation.load(Ordering::Acquire), 1);
    }

    #[test]
    fn bursty_single_empty_tick_does_not_repeat_capacity_probe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;

        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, false));

        telemetry.tun_ingress_bytes_per_second = 0;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, false));
        assert!(state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, 1);

        // One empty producer sample between bursts remains the same active
        // epoch, so it cannot ask BBR to reprobe a second time.
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
        assert!(!state.update(telemetry, false));
        assert_eq!(state.bulk_idle_ticks, 0);

        telemetry.tun_ingress_bytes_per_second = 0;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, false));
        assert!(state.bulk_active);
        assert!(!state.update(telemetry, false));
        assert!(!state.bulk_active);

        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
        assert!(state.update(telemetry, false));
    }

    #[test]
    fn bulk_service_counter_edge_fires_once_and_rearms_after_idle() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 0;
        telemetry.packet_train_queue_bytes = 0;
        let mut state = CapacityProbeStateV2::default();
        let tunables = Bbr3Tunables::default();
        state.initialize_bulk_service_counter(telemetry.path_epoch, 100);

        // Control/latency traffic and repeated polls do not change the Bulk
        // counter, so neither can request capacity discovery.
        assert!(!state.update_bulk_service_counter(100));
        assert!(!state.update_bulk_service_counter(100));

        if state.update_bulk_service_counter(101) {
            publish_capacity_probe(&tunables);
        }
        assert_eq!(
            tunables.capacity_probe_generation.load(Ordering::Acquire),
            0
        );
        assert!(state.bulk_active);
        // Further bytes in the same active epoch are coalesced.
        assert!(!state.update_bulk_service_counter(102));
        assert!(!state.update_bulk_service_counter(103));

        // The first full tick consumes service observed by the fast path, so
        // it is active rather than the first idle tick.
        assert!(!state.update(telemetry, false));
        assert!(state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, 0);
        assert!(!state.update(telemetry, false));
        assert!(state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, 1);
        assert!(!state.update(telemetry, false));
        assert!(!state.bulk_active);
        assert!(state.bulk_idle_verified);

        if state.update_bulk_service_counter(104) {
            publish_capacity_probe(&tunables);
        }
        assert_eq!(
            tunables.capacity_probe_generation.load(Ordering::Acquire),
            1
        );
        assert!(!state.update_bulk_service_counter(105));
    }

    #[test]
    fn clean_underestimated_initial_bulk_requests_one_delayed_probe() {
        let mut state = CapacityProbeStateV2::default();
        state.initialize_bulk_service_counter(1, 100);
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.controller_state = 3; // ProbeBW Cruise.
        telemetry.controller_pacing_rate_bytes_per_second = 40_000_000;
        telemetry.tun_ingress_bytes_per_second = 80_000_000;
        telemetry.loss_ppm = 0;
        telemetry.residual_loss_ppm = 0;
        telemetry.burst_loss_cells = 0;

        assert!(!state.update_bulk_service_counter(101));
        assert_eq!(
            state.initial_bulk_probe,
            InitialBulkProbeV2::AwaitingSampleBoundary
        );
        let mut partial = telemetry;
        partial.tun_ingress_bytes_per_second = 1_000_000;
        assert!(!state.update(partial, false));
        assert_eq!(
            state.initial_bulk_probe,
            InitialBulkProbeV2::AwaitingCompleteTick
        );
        assert!(state.update(telemetry, false));
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
        // The decision is one-shot even while demand remains above pacing.
        assert!(!state.update(telemetry, false));
        assert!(!state.update_bulk_service_counter(102));
        assert!(state.bulk_active);
    }

    #[test]
    fn home_like_partial_pressure_is_retained_until_the_clean_complete_tick() {
        let mut state = CapacityProbeStateV2::default();
        let mut partial = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(partial.path_epoch, 100);
        partial.controller_state = 3; // ProbeBW Cruise.
        partial.controller_pacing_rate_bytes_per_second = 308_267;
        partial.tun_ingress_bytes_per_second = 653_600;
        partial.loss_ppm = 0;
        partial.residual_loss_ppm = 0;
        partial.burst_loss_cells = 0;

        assert!(!state.update_bulk_service_counter(101));
        assert!(!state.update(partial, false));
        assert!(state.initial_sample_incomplete);
        assert!(state.initial_clean_demand_seen);
        assert!(!state.update_loss_episode_if_complete(partial, false));

        let mut complete = partial;
        complete.controller_state = 5;
        complete.controller_pacing_rate_bytes_per_second = 507_945;
        complete.tun_ingress_bytes_per_second = 424_041;
        assert!(
            complete.tun_ingress_bytes_per_second
                < complete.controller_pacing_rate_bytes_per_second
        );
        assert!(state.update(complete, false));
        assert!(!state.initial_clean_demand_seen);
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);

        assert!(!state.update(complete, false));
        assert!(!state.update_loss_episode_if_complete(complete, false));
    }

    #[test]
    fn p2_like_partial_without_pressure_and_lossy_complete_is_suppressed() {
        let mut state = CapacityProbeStateV2::default();
        let mut partial = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(partial.path_epoch, 100);
        partial.controller_state = 3; // ProbeBW Cruise.
        partial.controller_pacing_rate_bytes_per_second = 875_843;
        partial.tun_ingress_bytes_per_second = 394_628;
        partial.loss_ppm = 0;
        partial.residual_loss_ppm = 0;
        partial.burst_loss_cells = 0;

        assert!(!state.update_bulk_service_counter(101));
        assert!(!state.update(partial, false));
        assert!(state.initial_sample_incomplete);
        assert!(!state.initial_clean_demand_seen);
        assert!(!state.update_loss_episode_if_complete(partial, false));

        let mut complete = partial;
        complete.controller_pacing_rate_bytes_per_second = 300_000;
        complete.tun_ingress_bytes_per_second = 600_000;
        complete.loss_ppm = 40_523;
        assert!(!state.update(complete, false));
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
        assert!(!state.update_loss_episode_if_complete(complete, false));
        assert!(state.loss_episode);

        // A later clean high-pressure sample cannot resurrect the consumed
        // initial decision. The complete tick's real loss episode remains
        // independently owned by the loss-recovery state machine.
        complete.loss_ppm = 0;
        for _ in 0..3 {
            assert!(!state.update(complete, false));
        }
    }

    #[test]
    fn lossy_partial_initial_bulk_sample_cannot_seed_a_second_recovery_probe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
        telemetry.controller_state = 3; // ProbeBW Cruise.
        telemetry.controller_pacing_rate_bytes_per_second = 4_000_000;
        telemetry.tun_ingress_bytes_per_second = 8_000_000;
        telemetry.loss_ppm = 0;
        telemetry.residual_loss_ppm = 0;
        telemetry.burst_loss_cells = 0;

        assert!(!state.update_bulk_service_counter(101));

        let mut partial = telemetry;
        partial.loss_ppm = 20_000;
        assert!(!state.update(partial, false));
        assert!(state.initial_sample_incomplete);
        assert!(!state.update_loss_episode_if_complete(partial, false));
        assert!(!state.loss_episode);

        // The first complete clean interval makes exactly the initial-Bulk
        // decision. The discarded partial loss must not mature into a second
        // loss-recovery restart on later clean intervals.
        assert!(state.update(telemetry, false));
        assert!(!state.update_loss_episode_if_complete(telemetry, false));
        let mut requests = 1;
        for _ in 0..3 {
            requests += usize::from(state.update(telemetry, false));
            requests += usize::from(state.update_loss_episode_if_complete(telemetry, false));
        }
        assert_eq!(requests, 1);
        assert!(!state.loss_episode);
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    }

    #[test]
    fn startup_lossy_partial_then_probebw_clean_complete_probes_only_once() {
        let mut state = CapacityProbeStateV2::default();
        let mut partial = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(partial.path_epoch, 100);
        partial.controller_state = 0; // Native Startup owns the partial tick.
        partial.controller_pacing_rate_bytes_per_second = 4_000_000;
        partial.tun_ingress_bytes_per_second = 8_000_000;
        partial.loss_ppm = 20_000;

        assert!(!state.update_bulk_service_counter(101));
        assert!(!state.update(partial, false));
        assert!(state.initial_sample_incomplete);
        assert!(!state.update_loss_episode_if_complete(partial, false));
        assert!(!state.loss_episode);

        let mut complete = partial;
        complete.controller_state = 3; // ProbeBW Cruise.
        complete.loss_ppm = 0;
        complete.residual_loss_ppm = 0;
        complete.burst_loss_cells = 0;
        assert!(state.update(complete, false));
        assert!(!state.update_loss_episode_if_complete(complete, false));
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);

        for _ in 0..3 {
            assert!(!state.update(complete, false));
            assert!(!state.update_loss_episode_if_complete(complete, false));
        }
        assert!(!state.loss_episode);
    }

    #[test]
    fn initial_bulk_probe_decision_is_consumed_only_once() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.controller_state = 3; // ProbeBW Cruise.
        telemetry.controller_pacing_rate_bytes_per_second = 4_000_000;
        telemetry.tun_ingress_bytes_per_second = 8_000_000;
        telemetry.loss_ppm = 0;
        telemetry.residual_loss_ppm = 0;
        telemetry.burst_loss_cells = 0;

        // The normal path may observe initial Bulk first, but that first
        // sample is still a partial window. Only the following complete tick
        // may make the one-shot decision.
        assert!(!state.update(telemetry, false));
        assert_eq!(
            state.initial_bulk_probe,
            InitialBulkProbeV2::AwaitingCompleteTick
        );
        assert!(state.update(telemetry, false));
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, false));
    }

    #[test]
    fn lossy_initial_bulk_tick_is_permanently_suppressed() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
        telemetry.controller_state = 3; // ProbeBW Cruise.
        telemetry.controller_pacing_rate_bytes_per_second = 8_000_000;
        telemetry.tun_ingress_bytes_per_second = 12_000_000;
        telemetry.loss_ppm = 20_000;

        assert!(!state.update_bulk_service_counter(101));
        let mut partial = telemetry;
        partial.loss_ppm = 0;
        assert!(!state.update(partial, false));
        assert!(!state.update(telemetry, false));
        telemetry.loss_ppm = 0;
        assert!(!state.update(telemetry, false));
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    }

    #[test]
    fn native_startup_permanently_suppresses_initial_bulk_probe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
        telemetry.controller_state = 0; // Startup is already probing.
        telemetry.controller_pacing_rate_bytes_per_second = 8_000_000;
        telemetry.tun_ingress_bytes_per_second = 12_000_000;

        assert!(!state.update_bulk_service_counter(101));
        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, false));
        telemetry.controller_state = 3;
        assert!(!state.update(telemetry, false));
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    }

    #[test]
    fn initial_bulk_probe_is_suppressed_during_controller_policer_episode() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
        telemetry.controller_state = 3;
        telemetry.controller_pacing_rate_bytes_per_second = 8_000_000;
        telemetry.tun_ingress_bytes_per_second = 12_000_000;

        assert!(!state.update_bulk_service_counter(101));
        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, true));
        assert!(!state.update(telemetry, false));
        assert_eq!(state.initial_bulk_probe, InitialBulkProbeV2::Consumed);
    }

    #[test]
    fn fast_capacity_probe_requires_the_current_selected_path_identity() {
        assert!(!fast_capacity_probe_path_matches("", "ip:2001:db8::1"));
        assert!(fast_capacity_probe_path_matches(
            "ip:2001:db8::1",
            "ip:2001:db8::1"
        ));
        assert!(!fast_capacity_probe_path_matches(
            "ip:2001:db8::1",
            "ip:2001:db8::2"
        ));
    }

    #[test]
    fn bulk_service_clears_a_partial_confirmed_idle_horizon() {
        let mut state = CapacityProbeStateV2::default();
        state.initialize_bulk_service_counter(1, 100);
        assert!(!state.update_bulk_service_counter(101));

        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 0;
        telemetry.packet_train_queue_bytes = 0;
        // Consume the fast-path service observation, then begin idling.
        assert!(!state.update(telemetry, true));
        assert!(!state.update(telemetry, true));
        assert_eq!(state.bulk_idle_ticks, 1);

        assert!(!state.update_bulk_service_counter(102));
        assert_eq!(state.bulk_idle_ticks, 0);
        assert!(!state.bulk_idle_verified);
        assert!(state.bulk_active);
    }

    #[test]
    fn confirmed_epoch_requires_five_complete_idle_ticks_before_reprobe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, true));

        telemetry.tun_ingress_bytes_per_second = 0;
        for expected in 1..5 {
            assert!(!state.update(telemetry, true));
            assert!(state.bulk_active);
            assert_eq!(state.bulk_idle_ticks, expected);
            assert!(!state.bulk_idle_verified);
        }
        assert!(!state.update(telemetry, true));
        assert!(!state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, 0);
        assert!(state.bulk_idle_verified);

        telemetry.tun_ingress_bytes_per_second = 1;
        assert!(state.update(telemetry, true));
        assert!(state.bulk_active);
        assert!(!state.bulk_idle_verified);
    }

    #[test]
    fn unconfirmed_epoch_rearms_after_two_complete_idle_ticks() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, false));

        telemetry.tun_ingress_bytes_per_second = 0;
        assert!(!state.update(telemetry, false));
        assert!(state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, 1);
        assert!(!state.bulk_idle_verified);
        assert!(!state.update(telemetry, false));
        assert!(!state.bulk_active);
        assert!(state.bulk_idle_verified);

        telemetry.tun_ingress_bytes_per_second = 1;
        assert!(state.update(telemetry, false));
        assert!(!state.bulk_idle_verified);
    }

    #[test]
    fn confirmed_first_backlog_is_consumed_without_request() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, true));

        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
        assert!(!state.update(telemetry, true));
        // Disabling the controller marker cannot resurrect the consumed edge.
        assert!(!state.update(telemetry, false));
    }

    #[test]
    fn cancelled_fast_edge_preserves_request_without_fabricating_verified_idle() {
        let mut state = CapacityProbeStateV2::default();
        state.initialize_bulk_service_counter(1, 100);
        state.bulk_idle_verified = true;

        assert!(state.update_bulk_service_counter(101));
        state.cancel_bulk_service_edge();
        assert!(!state.bulk_active);
        assert!(!state.bulk_idle_verified);
        assert!(state.update_bulk_service_counter(102));
        assert!(!state.bulk_idle_verified);
        assert!(!state.update_bulk_service_counter(103));
    }

    #[test]
    fn verified_idle_allows_one_confirmed_fast_publish() {
        let mut state = CapacityProbeStateV2::default();
        let tunables = Bbr3Tunables::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, true));
        telemetry.tun_ingress_bytes_per_second = 0;
        for _ in 0..5 {
            assert!(!state.update(telemetry, true));
        }
        assert!(state.bulk_idle_verified);

        state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
        if state.update_bulk_service_counter(101) {
            publish_capacity_probe(&tunables);
        }
        assert_eq!(
            tunables.capacity_probe_generation.load(Ordering::Acquire),
            1
        );
        assert!(!state.bulk_idle_verified);
        assert!(!state.update_bulk_service_counter(102));
        assert_eq!(
            tunables.capacity_probe_generation.load(Ordering::Acquire),
            1
        );
    }

    #[test]
    fn fast_capacity_probe_publication_is_one_release_generation() {
        let tunables = Bbr3Tunables::default();

        publish_capacity_probe(&tunables);

        assert_eq!(
            tunables.capacity_probe_generation.load(Ordering::Acquire),
            1
        );
        assert_eq!(tunables.generation.load(Ordering::Acquire), 1);
    }

    #[test]
    fn initial_unverified_backlog_cannot_request_or_repeat_a_probe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = 0;

        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, false));

        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64 - 1;
        assert!(!state.update(telemetry, false));
        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, false));
    }

    #[test]
    fn backlog_present_on_first_tun_tick_needs_no_extra_reprobe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;

        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, false));
    }

    #[test]
    fn bulk_probe_rearms_only_after_idle_or_path_reset() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 1;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, false));
        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
        assert!(!state.update(telemetry, false));

        // A nominally idle tick with a retained producer queue does not start
        // a new epoch. The queue must drain below the protection threshold.
        telemetry.tun_ingress_bytes_per_second = 0;
        assert!(!state.update(telemetry, false));
        assert!(state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, 0);
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, false));
        assert!(state.bulk_active);
        assert_eq!(state.bulk_idle_ticks, 1);
        assert!(!state.update(telemetry, false));
        assert!(!state.bulk_active);

        telemetry.tun_ingress_bytes_per_second = 1;
        assert!(state.update(telemetry, false));
        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
        assert!(!state.update(telemetry, false));

        telemetry.path_epoch += 1;
        telemetry.packet_train_queue_bytes = 0;
        assert!(state.update(telemetry, false));
        assert_eq!(state.bulk_idle_ticks, 0);
        telemetry.packet_train_queue_bytes = TX_ADMISSION_BATCH_BYTES as u64;
        assert!(!state.update(telemetry, false));
    }

    #[test]
    fn idle_control_traffic_cannot_request_capacity_probe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 0;
        // Even a controller-internal train backlog is not evidence of TUN
        // demand when no TUN bytes crossed this connection.
        telemetry.packet_train_queue_bytes = 8 * TX_ADMISSION_BATCH_BYTES as u64;

        assert!(!state.update(telemetry, false));
        assert!(!state.bulk_active);
    }

    #[test]
    fn active_tun_step_cap_release_requests_capacity_probe() {
        let mut state = CapacityProbeStateV2::default();
        let telemetry = queued_adaptive_floor_telemetry();
        assert!(!state.update(telemetry, false));

        assert!(!state.update_pacing_cap(6_500_000, true));
        assert!(state.update_pacing_cap(0, true));
        assert!(!state.update_pacing_cap(0, true));

        // A cap disappearing while the connection has no TUN demand is not
        // a capacity-discovery event.
        assert!(!state.update_pacing_cap(65_536, false));
        assert!(!state.update_pacing_cap(0, false));
    }

    #[test]
    fn partial_initial_bulk_sample_absorbs_pacing_cap_release_without_replay() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        state.initialize_bulk_service_counter(telemetry.path_epoch, 100);
        assert!(!state.update_pacing_cap(6_500_000, true));
        assert!(!state.update_bulk_service_counter(101));

        assert!(!state.update(telemetry, false));
        assert!(state.initial_sample_incomplete);
        assert!(!state.update_pacing_cap_if_complete(0, true));
        assert_eq!(state.previous_pacing_cap_bytes_per_second, Some(0));

        telemetry.controller_state = 0;
        assert!(!state.update(telemetry, false));
        assert!(!state.update_pacing_cap_if_complete(0, true));
    }

    #[test]
    fn active_loss_episode_requests_one_probe_after_two_clean_ticks() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        assert!(!state.update(telemetry, false));

        telemetry.loss_ppm = 10_000;
        assert!(!state.update_loss_episode(telemetry, false));
        assert!(state.loss_episode);

        telemetry.loss_ppm = 0;
        assert!(!state.update_loss_episode(telemetry, false));
        assert_eq!(state.consecutive_clean_loss_ticks, 1);
        assert!(state.update_loss_episode(telemetry, false));
        assert!(!state.loss_episode);
        assert_eq!(state.consecutive_clean_loss_ticks, 0);
        assert!(!state.update_loss_episode(telemetry, false));
    }

    #[test]
    fn confirmed_controller_policer_episode_suppresses_clean_recovery_probe() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        assert!(!state.update(telemetry, false));

        telemetry.loss_ppm = 10_000;
        assert!(!state.update_loss_episode(telemetry, false));
        assert!(state.loss_episode);

        telemetry.loss_ppm = 0;
        assert!(!state.update_loss_episode(telemetry, false));
        assert_eq!(state.consecutive_clean_loss_ticks, 1);
        assert!(!state.update_loss_episode(telemetry, true));
        assert!(!state.loss_episode);
        assert!(!state.loss_signal_latched);
        assert_eq!(state.consecutive_clean_loss_ticks, 0);

        // Releasing the guard cannot publish a stale edge from the old
        // episode; a real idle/new-Bulk transition still uses `update`.
        assert!(!state.update_loss_episode(telemetry, false));
        telemetry.tun_ingress_bytes_per_second = 0;
        telemetry.packet_train_queue_bytes = 0;
        assert!(!state.update(telemetry, false));
        assert!(!state.update(telemetry, false));
        telemetry.tun_ingress_bytes_per_second = 1;
        assert!(state.update(telemetry, false));
    }

    #[test]
    fn controller_policer_episode_activity_depends_on_transition_not_scale() {
        assert!(!controller_policer_episode_active(0));
        assert!(controller_policer_episode_active(1));

        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        assert!(!state.update(telemetry, false));
        telemetry.loss_ppm = 10_000;
        assert!(!state.update_loss_episode(telemetry, false));
        telemetry.loss_ppm = 0;
        assert!(!state.update_loss_episode(telemetry, controller_policer_episode_active(1),));
        assert!(!state.loss_episode);
    }

    #[test]
    fn residual_or_burst_loss_arms_but_isolated_clean_and_idle_do_not_trigger() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        state.update(telemetry, false);

        telemetry.residual_loss_ppm = 10_000;
        assert!(!state.update_loss_episode(telemetry, false));
        telemetry.residual_loss_ppm = 0;
        assert!(!state.update_loss_episode(telemetry, false));
        telemetry.loss_ppm = 1;
        assert!(!state.update_loss_episode(telemetry, false));
        assert_eq!(state.consecutive_clean_loss_ticks, 0);

        telemetry.loss_ppm = 0;
        telemetry.burst_loss_cells = 3;
        assert!(!state.update_loss_episode(telemetry, false));
        assert!(!state.update_loss_episode(telemetry, false));
        assert!(state.update_loss_episode(telemetry, false));
        assert!(!state.update_loss_episode(telemetry, false));
        telemetry.burst_loss_cells = 0;

        telemetry.tun_ingress_bytes_per_second = 0;
        assert!(!state.update_loss_episode(telemetry, false));
        assert!(!state.loss_episode);
        assert_eq!(state.consecutive_clean_loss_ticks, 0);
    }

    #[test]
    fn loss_recovery_does_not_cross_path_epochs() {
        let mut state = CapacityProbeStateV2::default();
        let mut telemetry = queued_adaptive_floor_telemetry();
        state.update(telemetry, false);
        telemetry.loss_ppm = 10_000;
        state.update_loss_episode(telemetry, false);

        telemetry.path_epoch += 1;
        telemetry.loss_ppm = 0;
        assert!(state.update(telemetry, false));
        assert!(!state.update_loss_episode(telemetry, false));
        assert!(!state.update_loss_episode(telemetry, false));
        assert!(!state.loss_episode);
    }

    #[test]
    fn capacity_probe_request_is_published_even_when_policy_tunables_are_unchanged() {
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let effective = BbrEffectiveV1::from_proposal(&proposal);
        let tunables = Bbr3Tunables::default();
        assert!(apply_bbr3_effective(&tunables, &effective));
        let before = tunables.generation.load(Ordering::Acquire);

        assert!(publish_bbr3_effective(&tunables, &effective, true));

        assert_eq!(
            tunables.capacity_probe_generation.load(Ordering::Acquire),
            1
        );
        assert_eq!(tunables.generation.load(Ordering::Acquire), before + 1);
    }

    #[test]
    fn finalization_respects_cwnd_cap_and_preserves_low_rtt_preset_floor() {
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let mut capped = BbrEffectiveV1::from_proposal(&proposal);
        capped.cwnd_cap_bytes = 128 * 1024;
        assert_eq!(
            finalize_bbr3_effective(queued_adaptive_floor_telemetry(), 96 * 1024, &mut capped),
            208 * 1024
        );
        assert_eq!(capped.cwnd_floor_bytes, capped.cwnd_cap_bytes);
        assert!(capped.cwnd_cap_bytes != 0);

        let capped_tunables = Bbr3Tunables::default();
        assert!(apply_bbr3_effective(&capped_tunables, &capped));
        assert_eq!(
            tunables_snapshot(&capped_tunables),
            effective_tunables_snapshot(&capped)
        );

        let low_rtt = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LowRttHost, 0);
        let mut low_rtt_effective = BbrEffectiveV1::from_proposal(&low_rtt);
        let mut no_adaptive_telemetry = queued_adaptive_floor_telemetry();
        no_adaptive_telemetry.reliability = PathReliability::ReliableRelay;
        let adaptive_floor =
            finalize_bbr3_effective(no_adaptive_telemetry, 96 * 1024, &mut low_rtt_effective);
        assert_eq!(adaptive_floor, 0);
        assert_eq!(low_rtt_effective.cwnd_floor_bytes, LOW_RTT_CWND_FLOOR_BYTES);

        let low_rtt_tunables = Bbr3Tunables::default();
        assert!(apply_bbr3_effective(&low_rtt_tunables, &low_rtt_effective));
        assert_eq!(
            tunables_snapshot(&low_rtt_tunables),
            effective_tunables_snapshot(&low_rtt_effective)
        );
    }

    #[test]
    fn queued_demand_sets_a_quantized_bdp_cwnd_floor_without_operator_input() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let mut effective = BbrEffectiveV1::from_proposal(&proposal);

        let floor = finalize_bbr3_effective(telemetry, 96 * 1024, &mut effective);
        assert_eq!(floor, 208 * 1024);
        assert_eq!(effective.cwnd_floor_bytes, floor);
        let tunables = Bbr3Tunables::default();
        assert!(apply_bbr3_effective(&tunables, &effective));
        assert_eq!(
            tunables.cwnd_floor_bytes.load(Ordering::Relaxed),
            208 * 1024
        );

        telemetry.queue_delay = Duration::from_millis(11);
        let mut queue_delayed = BbrEffectiveV1::from_proposal(&proposal);
        assert_eq!(
            finalize_bbr3_effective(telemetry, 96 * 1024, &mut queue_delayed),
            208 * 1024
        );
        assert_eq!(queue_delayed.cwnd_floor_bytes, 208 * 1024);
        telemetry.queue_delay = Duration::from_millis(2);
        telemetry.packet_train_queue_bytes = 0;
        let mut queue_empty = BbrEffectiveV1::from_proposal(&proposal);
        assert_eq!(
            finalize_bbr3_effective(telemetry, 96 * 1024, &mut queue_empty),
            0
        );
        assert_eq!(queue_empty.cwnd_floor_bytes, 0);
    }

    #[test]
    fn adaptive_floor_tracks_measured_bdp_after_probe_overshoot_without_toggling() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let effective = BbrEffectiveV1::from_proposal(&proposal);
        let mut state = AdaptiveCwndFloorStateV2::default();

        let probe = state.update(telemetry, &effective, 512 * 1024);
        assert_eq!(probe, 1024 * 1024);
        assert_eq!(state.mode, AdaptiveCwndFloorModeV2::Probe);

        telemetry.queue_delay = Duration::from_millis(11);
        telemetry.rtt = telemetry.min_rtt + telemetry.queue_delay;
        let tracked = state.update(telemetry, &effective, probe);
        assert_eq!(tracked, 208 * 1024);
        assert_eq!(state.mode, AdaptiveCwndFloorModeV2::Track);

        // The large probe drained one producer batch. Active rate evidence
        // keeps the measured floor instead of recreating the old 0/high
        // alternation.
        telemetry.queue_delay = Duration::from_millis(2);
        telemetry.rtt = telemetry.min_rtt + telemetry.queue_delay;
        telemetry.packet_train_queue_bytes = 0;
        assert_eq!(state.update(telemetry, &effective, tracked), tracked);
    }

    #[test]
    fn adaptive_floor_tracks_an_already_modeled_bdp_without_doubling_cwnd() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.controller_state = 3; // ProbeBW Cruise.
        telemetry.controller_bw_bytes_per_second = telemetry.delivery_rate_bytes_per_second;
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let effective = BbrEffectiveV1::from_proposal(&proposal);
        let mut state = AdaptiveCwndFloorStateV2::default();
        let modeled = cwnd_floor_for_rate(
            telemetry.delivery_rate_bytes_per_second,
            telemetry.min_rtt,
            &effective,
        );
        let current_cwnd = modeled * 15 / 16;

        let floor = state.update(telemetry, &effective, current_cwnd);

        assert_eq!(floor, modeled);
        assert_eq!(state.mode, AdaptiveCwndFloorModeV2::Track);
        assert!(floor < current_cwnd * 2);
    }

    #[test]
    fn startup_with_self_demand_probes_even_when_cwnd_matches_the_current_model() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.controller_state = 0; // Startup.
        telemetry.controller_bw_bytes_per_second = telemetry.delivery_rate_bytes_per_second;
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let effective = BbrEffectiveV1::from_proposal(&proposal);
        let mut state = AdaptiveCwndFloorStateV2::default();
        let modeled = cwnd_floor_for_rate(
            telemetry.delivery_rate_bytes_per_second,
            telemetry.min_rtt,
            &effective,
        );
        let current_cwnd = modeled * 15 / 16;
        let expected_probe = quantize_adaptive_cwnd_floor(current_cwnd * 2);

        let floor = state.update(telemetry, &effective, current_cwnd);

        assert!(floor >= expected_probe);
        assert_eq!(state.mode, AdaptiveCwndFloorModeV2::Probe);
    }

    #[test]
    fn startup_with_inflated_queue_tracks_the_measured_floor() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.controller_state = 0; // Startup.
        telemetry.controller_bw_bytes_per_second = telemetry.delivery_rate_bytes_per_second;
        telemetry.queue_delay = Duration::from_millis(11);
        telemetry.rtt = telemetry.min_rtt + telemetry.queue_delay;
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let effective = BbrEffectiveV1::from_proposal(&proposal);
        let mut state = AdaptiveCwndFloorStateV2::default();
        let measured = measured_cwnd_floor(telemetry, &effective);

        let floor = state.update(telemetry, &effective, 512 * 1024);

        assert_eq!(floor, measured);
        assert_eq!(state.mode, AdaptiveCwndFloorModeV2::Track);
    }

    #[test]
    fn adaptive_floor_still_probes_when_cwnd_is_below_a_valid_model() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        telemetry.tun_ingress_bytes_per_second = 128 * 1024;
        telemetry.delivery_rate_bytes_per_second = 128 * 1024;
        telemetry.real_traffic_bytes_per_second = 128 * 1024;
        telemetry.controller_bw_bytes_per_second = 4_200_000;
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let effective = BbrEffectiveV1::from_proposal(&proposal);
        let mut state = AdaptiveCwndFloorStateV2::default();

        assert_eq!(state.update(telemetry, &effective, 48 * 1024), 96 * 1024);
        assert_eq!(state.mode, AdaptiveCwndFloorModeV2::Probe);
    }

    #[test]
    fn tracked_adaptive_floor_bounds_growth_and_clears_on_invalid_evidence() {
        let mut telemetry = queued_adaptive_floor_telemetry();
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let effective = BbrEffectiveV1::from_proposal(&proposal);
        let mut state = AdaptiveCwndFloorStateV2 {
            mode: AdaptiveCwndFloorModeV2::Track,
            path_epoch: telemetry.path_epoch,
            held_bytes: 208 * 1024,
            ..AdaptiveCwndFloorStateV2::default()
        };
        telemetry.tun_ingress_bytes_per_second *= 4;
        telemetry.delivery_rate_bytes_per_second *= 4;
        telemetry.real_traffic_bytes_per_second *= 4;
        assert_eq!(state.update(telemetry, &effective, 208 * 1024), 272 * 1024);

        telemetry.tun_ingress_bytes_per_second = 0;
        telemetry.delivery_rate_bytes_per_second = 0;
        telemetry.real_traffic_bytes_per_second = 0;
        telemetry.packet_train_queue_bytes = 0;
        assert_eq!(state.update(telemetry, &effective, 208 * 1024), 272 * 1024);
        assert_eq!(state.update(telemetry, &effective, 208 * 1024), 0);

        telemetry.tun_ingress_bytes_per_second = 4 * 1024 * 1024;
        telemetry.delivery_rate_bytes_per_second = 4 * 1024 * 1024;
        telemetry.real_traffic_bytes_per_second = 4 * 1024 * 1024;
        telemetry.packet_train_queue_bytes = 256 * 1024;
        assert_ne!(state.update(telemetry, &effective, 48 * 1024), 0);
        telemetry.controller_app_limited = true;
        assert_eq!(state.update(telemetry, &effective, 208 * 1024), 0);
        assert_eq!(state.mode, AdaptiveCwndFloorModeV2::Probe);

        telemetry.controller_app_limited = false;
        telemetry.path_epoch += 1;
        let reprobe = state.update(telemetry, &effective, 48 * 1024);
        assert!(reprobe >= 96 * 1024);
        assert_eq!(state.path_epoch, telemetry.path_epoch);

        let mut policer = effective;
        policer.loss_is_congestion = true;
        assert_eq!(state.update(telemetry, &policer, reprobe), 0);
    }

    #[test]
    fn queued_loss_limited_startup_probes_above_measured_bdp() {
        let mut telemetry = crate::protocol::v2::tuning::tests_fixture::sample(1);
        telemetry.controller_app_limited = false;
        telemetry.min_rtt = Duration::from_millis(20);
        telemetry.rtt = Duration::from_millis(22);
        telemetry.queue_delay = Duration::from_millis(2);
        telemetry.packet_train_queue_bytes = 256 * 1024;
        telemetry.tun_ingress_bytes_per_second = 128 * 1024;
        telemetry.delivery_rate_bytes_per_second = 128 * 1024;
        telemetry.real_traffic_bytes_per_second = 128 * 1024;
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let mut effective = BbrEffectiveV1::from_proposal(&proposal);

        assert_eq!(
            finalize_bbr3_effective(telemetry, 48 * 1024, &mut effective),
            96 * 1024
        );
        assert_eq!(effective.cwnd_floor_bytes, 96 * 1024);
    }

    #[test]
    fn learner_on_applies_complete_policy_action_while_shadow_keeps_baseline() {
        let telemetry = crate::protocol::v2::tuning::tests_fixture::sample(1);
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let baseline = tuner.observe(telemetry);
        let policy = ironet_policy_core::PolicySpecV1::builtin();
        let trace = LearnerTraceV2 {
            mode: LearnerModeV2::On,
            context: crate::protocol::v2::learner::ContextKeyV2::classify(&telemetry),
            baseline_preset: baseline.bbr.preset,
            proposed_preset: Bbr3PresetV2::LossyRadio,
            applied_preset: Bbr3PresetV2::LossyRadio,
            predicted_advantage: 0.1,
            exploring: true,
            rollback: false,
            rollbacks: 0,
            fine_up_gain_delta_milli: 0,
            fine_headroom_delta_milli: 0,
            fine_cwnd_gain_delta_milli: 0,
        };
        let mut learned = baseline;
        learned.bbr = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let applied = constrain_learned_policy_action(&tuner, &policy, telemetry, learned, trace);
        assert_eq!(applied.fec.unwrap().parity_cells, 2);
        assert_eq!(applied.train_target_bytes, 32 * 1024);
        assert_eq!(applied.bulk_quantum_cells, 2);

        let shadow = LearnerTraceV2 {
            mode: LearnerModeV2::Shadow,
            ..trace
        };
        assert_eq!(
            constrain_learned_policy_action(&tuner, &policy, telemetry, baseline, shadow),
            baseline
        );
    }

    #[test]
    fn autotune_force_parser_is_strict_and_distinguishes_fec_off() {
        let forced = parse_autotune_force(
            r#"{"bbr_preset":"lossy-radio","fec":"8+1","train_target_bytes":32768,"bulk_quantum_cells":2,"cover_profile":"live-broadcast","cover_overhead_per_mille":30}"#,
        )
        .unwrap();
        assert_eq!(forced.bbr_preset, Some(Bbr3PresetV2::LossyRadio));
        assert_eq!(
            forced.fec,
            Some(Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            }))
        );
        assert_eq!(forced.train_target_bytes, Some(32 * 1024));
        assert_eq!(forced.bulk_quantum_cells, Some(2));
        assert_eq!(
            forced.cover_profile,
            Some(CoverTrafficProfileV2::LiveBroadcast)
        );
        assert_eq!(forced.cover_overhead_per_mille, Some(30));

        assert_eq!(
            parse_autotune_force(r#"{"fec":null}"#).unwrap().fec,
            Some(None)
        );
        assert!(parse_autotune_force("{}").is_err());
        assert!(parse_autotune_force(r#"{"unknown":1}"#).is_err());
        assert!(parse_autotune_force(r#"{"fec":"2+2"}"#).is_err());
        assert!(parse_autotune_force(r#"{"bbr_preset":"unknown"}"#).is_err());
    }

    #[test]
    fn loss_ratio_is_bounded_and_handles_no_sample() {
        assert_eq!(ratio_per_million(0, 0), 0);
        assert_eq!(ratio_per_million(1, 100), 10_000);
        assert_eq!(ratio_per_million(u64::MAX, 1), 1_000_000);
        assert_eq!(ratio_per_thousand(3, 100), 30);
        assert_eq!(ratio_per_thousand(1, 0), 0);
        assert_eq!(ratio_scaled_u64(17, 4, 1_000), 4_250);
        assert_eq!(ratio_scaled_u64(1, 0, 1_000_000), 0);
        assert_eq!(ratio_scaled_u64(u64::MAX, 1, u64::MAX), u64::MAX);
        assert_eq!(rate_per_second(1_000, Duration::from_millis(500)), 2_000);
        assert_eq!(rate_per_second(1, Duration::ZERO), 0);
        assert_eq!(counter_delta(120, 100), 20);
        assert_eq!(counter_delta(7, 100), 7);
    }

    #[test]
    fn derp_and_iroh_relay_paths_are_reliable_for_fec_tuning() {
        let derp = TransportAddr::Custom(
            DerpAddr {
                region_id: crate::derp::RegionId(7),
                public_key: DerpPublicKey::from_bytes([9; 32]),
            }
            .to_custom(),
        );
        assert_eq!(
            path_reliability(false, &derp),
            PathReliability::ReliableRelay
        );
        assert_eq!(
            path_reliability(false, &TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            PathReliability::Datagram
        );
        assert_eq!(
            path_reliability(true, &TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            PathReliability::ReliableRelay
        );
        assert_eq!(
            path_endpoint_identity(&TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            path_endpoint_identity(&TransportAddr::Ip("192.0.2.1:5443".parse().unwrap()))
        );
        assert_ne!(
            path_endpoint_identity(&TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            path_endpoint_identity(&derp)
        );
    }
}
