//! Bulk-service and loss-edge state machine for BBR capacity discovery.

use super::*;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum InitialBulkProbeV2 {
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
pub(super) struct CapacityProbeStateV2 {
    pub(super) path_epoch: u64,
    pub(super) bulk_service_counter: u64,
    /// Cumulative bytes admitted to the classified Bulk scheduler lane. This
    /// is deliberately distinct from post-send service: it is the direct
    /// application-demand edge needed when a stale controller model cannot
    /// transmit enough data to create a service edge yet.
    pub(super) bulk_admission_counter: u64,
    /// A classifier-confirmed Bulk admission was observed since the last
    /// full telemetry tick.  This must not be inferred from total TUN ingress:
    /// control and latency flows share that counter and used to consume the
    /// one-shot Bulk discovery epoch before the application transfer began.
    pub(super) bulk_admission_since_tick: bool,
    pub(super) bulk_active: bool,
    pub(super) bulk_idle_ticks: u8,
    pub(super) bulk_idle_verified: bool,
    pub(super) bulk_service_since_tick: bool,
    /// Bytes serviced from the first Bulk epoch before its first telemetry
    /// boundary. This is direct demand evidence, unlike a connection's
    /// control-plane delivery model.
    pub(super) initial_bulk_serviced_bytes: u64,
    /// Number of lightweight edge samples that contributed to
    /// `initial_bulk_serviced_bytes`.
    pub(super) initial_bulk_service_edges: u8,
    /// Classifier-confirmed Bulk demand collected before the first capacity
    /// probe. This is a separate evidence source from service bytes, so it
    /// can break a loss-induced startup lock without treating control or
    /// latency traffic as Bulk.
    pub(super) initial_bulk_admitted_bytes: u64,
    pub(super) initial_bulk_admission_edges: u8,
    /// An explicit path reset, or a fast edge that could not be published,
    /// still owes the controller one capacity-discovery request. Initial
    /// connection traffic is deliberately not represented by this flag.
    pub(super) probe_pending: bool,
    pub(super) initial_bulk_probe: InitialBulkProbeV2,
    /// A partial initial-Bulk interval showed clean demand above the current
    /// controller pacing rate. It is evidence only: publication still waits
    /// for a complete, currently safe interval.
    pub(super) initial_clean_demand_seen: bool,
    /// Set by `update` when this tick only establishes the initial Bulk
    /// sample boundary. Other edge detectors must ignore the same partial
    /// telemetry window so it cannot seed a later duplicate restart.
    pub(super) initial_sample_incomplete: bool,
    pub(super) previous_pacing_cap_bytes_per_second: Option<u64>,
    pub(super) loss_episode: bool,
    pub(super) loss_signal_latched: bool,
    pub(super) consecutive_clean_loss_ticks: u8,
}

pub(super) fn controller_policer_episode_active(policer_pacing_transitions: u64) -> bool {
    // A fixed absolute ceiling can be active at a 1.0 multiplicative scale.
    // The controller's one-way transition counter is the episode marker.
    policer_pacing_transitions != 0
}

impl CapacityProbeStateV2 {
    pub(super) fn initialize_bulk_service_counter(&mut self, path_epoch: u64, counter: u64) {
        self.path_epoch = path_epoch;
        self.bulk_service_counter = counter;
        self.initial_bulk_probe = InitialBulkProbeV2::AwaitingEdge;
        self.initial_clean_demand_seen = false;
        self.initial_sample_incomplete = false;
        self.initial_bulk_serviced_bytes = 0;
        self.initial_bulk_service_edges = 0;
    }

    pub(super) fn initialize_bulk_admission_counter(&mut self, counter: u64) {
        self.bulk_admission_counter = counter;
        self.bulk_admission_since_tick = false;
        self.initial_bulk_admitted_bytes = 0;
        self.initial_bulk_admission_edges = 0;
    }

    pub(super) fn reset_for_path(&mut self, path_epoch: u64) {
        let bulk_service_counter = self.bulk_service_counter;
        let bulk_admission_counter = self.bulk_admission_counter;
        *self = Self {
            path_epoch,
            bulk_service_counter,
            bulk_admission_counter,
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
    pub(super) fn update_bulk_service_counter(&mut self, counter: u64) -> bool {
        let serviced_bytes = counter.saturating_sub(self.bulk_service_counter);
        let increased = serviced_bytes != 0;
        self.bulk_service_counter = counter;
        if !increased {
            return false;
        }

        self.bulk_service_since_tick = true;
        if self.initial_bulk_probe != InitialBulkProbeV2::Consumed {
            self.initial_bulk_serviced_bytes = self
                .initial_bulk_serviced_bytes
                .saturating_add(serviced_bytes);
            self.initial_bulk_service_edges = self.initial_bulk_service_edges.saturating_add(1);
        }
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

    /// Observe classified Bulk admission independently of post-send service.
    /// A backlog behind a cold or loss-reduced congestion window can otherwise
    /// wait several RTTs before its first service byte, which is too late for
    /// a one-shot initial capacity discovery decision.
    pub(super) fn update_bulk_admission_counter(&mut self, counter: u64) {
        let admitted_bytes = counter.saturating_sub(self.bulk_admission_counter);
        self.bulk_admission_counter = counter;
        if admitted_bytes == 0 {
            return;
        }

        self.bulk_admission_since_tick = true;
        if self.initial_bulk_probe == InitialBulkProbeV2::Consumed {
            return;
        }

        self.initial_bulk_admitted_bytes = self
            .initial_bulk_admitted_bytes
            .saturating_add(admitted_bytes);
        self.initial_bulk_admission_edges = self.initial_bulk_admission_edges.saturating_add(1);
    }

    /// Request discovery as soon as a connection that already left native
    /// Startup has either admitted or serviced sustained TUN Bulk traffic.
    /// Waiting for post-send service or the next one-second telemetry tick
    /// used to make this edge depend on a loss-free interval. On an
    /// asymmetric or radio upload the stale control-plane model can prevent
    /// that first send and permanently strand BBR at a low rate.
    ///
    /// The byte-and-edge threshold rejects a one-packet transfer. Native
    /// Startup and a confirmed policer episode retain ownership of their own
    /// discovery, so this remains one semantic Bulk-epoch restart rather than
    /// a second congestion response.
    pub(super) fn sustained_initial_bulk_requires_probe(
        &mut self,
        controller_state: u8,
        controller_policer_episode_active: bool,
    ) -> bool {
        const MIN_BULK_BYTES: u64 = (TX_ADMISSION_BATCH_BYTES / 8) as u64;
        const MIN_BULK_EDGES: u8 = 2;
        let sustained_service = self.initial_bulk_service_edges >= MIN_BULK_EDGES
            && self.initial_bulk_serviced_bytes >= MIN_BULK_BYTES;
        let sustained_admission = self.initial_bulk_admission_edges >= MIN_BULK_EDGES
            && self.initial_bulk_admitted_bytes >= MIN_BULK_BYTES;

        if self.initial_bulk_probe == InitialBulkProbeV2::Consumed
            || controller_state == 0
            || controller_policer_episode_active
            || !(sustained_service || sustained_admission)
        {
            return false;
        }

        self.initial_bulk_probe = InitialBulkProbeV2::Consumed;
        self.initial_clean_demand_seen = false;
        self.initial_sample_incomplete = false;
        true
    }

    pub(super) fn cancel_bulk_service_edge(&mut self) {
        self.bulk_active = false;
        self.bulk_idle_ticks = 0;
        self.bulk_idle_verified = false;
        self.bulk_service_since_tick = false;
        // This method is called only after a requested fast publication could
        // not find controller tunables. Preserve that explicit request for
        // the normal telemetry path without pretending idle was verified.
        self.probe_pending = true;
    }

    pub(super) fn update(
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

        let producer_backlogged =
            telemetry.packet_train_queue_bytes >= TX_ADMISSION_BATCH_BYTES as u64;
        let bulk_serviced = std::mem::take(&mut self.bulk_service_since_tick);
        let bulk_admitted = std::mem::take(&mut self.bulk_admission_since_tick);
        // A retained controller-internal queue keeps an established Bulk
        // epoch active, but cannot create an application epoch by itself.
        // Both edge counters are classified at the scheduler boundary, so
        // latency/control TUN ingress cannot contaminate Bulk state.
        let bulk_activity =
            bulk_admitted || bulk_serviced || (self.bulk_active && producer_backlogged);
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

    pub(super) fn update_loss_episode(
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

    pub(super) fn update_loss_episode_if_complete(
        &mut self,
        telemetry: PathTelemetryV2,
        controller_policer_episode_active: bool,
    ) -> bool {
        !self.initial_sample_incomplete
            && self.update_loss_episode(telemetry, controller_policer_episode_active)
    }

    pub(super) fn update_pacing_cap(
        &mut self,
        pacing_cap_bytes_per_second: u64,
        tun_active: bool,
    ) -> bool {
        let released = tun_active
            && self
                .previous_pacing_cap_bytes_per_second
                .is_some_and(|previous| previous > 0 && pacing_cap_bytes_per_second == 0);
        self.previous_pacing_cap_bytes_per_second = Some(pacing_cap_bytes_per_second);
        released
    }

    pub(super) fn update_pacing_cap_if_complete(
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

pub(super) fn initial_bulk_capacity_probe_is_safe(
    telemetry: PathTelemetryV2,
    controller_policer_episode_active: bool,
    initial_clean_demand_seen: bool,
) -> bool {
    initial_bulk_sample_is_safe(telemetry, controller_policer_episode_active)
        && (initial_clean_demand_seen
            || telemetry.tun_ingress_bytes_per_second
                > telemetry.controller_pacing_rate_bytes_per_second)
}

pub(super) fn initial_bulk_clean_demand_is_safe(
    telemetry: PathTelemetryV2,
    controller_policer_episode_active: bool,
) -> bool {
    initial_bulk_sample_is_safe(telemetry, controller_policer_episode_active)
        && telemetry.tun_ingress_bytes_per_second
            > telemetry.controller_pacing_rate_bytes_per_second
}

pub(super) fn initial_bulk_sample_is_safe(
    telemetry: PathTelemetryV2,
    controller_policer_episode_active: bool,
) -> bool {
    !controller_policer_episode_active
        && telemetry.controller_state != 0
        && telemetry.loss_ppm == 0
        && telemetry.residual_loss_ppm == 0
        && telemetry.burst_loss_cells == 0
}

pub(super) fn fast_capacity_probe_path_matches(
    current_identity: &str,
    selected_identity: &str,
) -> bool {
    // Before the first complete sample there is no path-owned state to
    // publish. During migration, let the normal tick advance the path epoch
    // and reset the state before any edge can touch the new path's tunables.
    !current_identity.is_empty() && current_identity == selected_identity
}
