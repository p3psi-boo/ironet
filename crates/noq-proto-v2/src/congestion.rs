//! Logic for controlling the rate at which data is sent

use crate::connection::RttEstimator;
use crate::{Duration, Instant};
use std::any::Any;
use std::sync::Arc;

mod bbr3;
mod cubic;
mod new_reno;

pub use bbr3::{Bbr3, Bbr3Config, Bbr3Params, Bbr3Tunables};
pub use cubic::{Cubic, CubicConfig};
pub use new_reno::{NewReno, NewRenoConfig};

/// Common interface for different congestion controllers
pub trait Controller: Send + Sync + std::fmt::Debug {
    /// A validated backup path became available for application traffic.
    ///
    /// Controllers may discard an application-limited standby model and restart safe
    /// capacity discovery. The default preserves controller state.
    fn on_path_activated(&mut self) {}

    /// One or more packets were just sent
    #[allow(unused_variables)]
    fn on_sent(&mut self, now: Instant, bytes: u64, largest_pn: u64) {}

    /// One packet was just sent
    #[allow(unused_variables)]
    fn on_packet_sent(&mut self, now: Instant, bytes: u16, pn: u64) {}

    /// Packet deliveries were confirmed
    ///
    /// `app_limited` indicates whether the connection was blocked on outgoing
    /// application data prior to receiving these acknowledgements.
    #[allow(unused_variables)]
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        pn: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
    }

    /// Packets are acked in batches, all with the same `now` argument. This indicates one of those batches has completed.
    #[allow(unused_variables)]
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
    }

    /// Packets were deemed lost or marked congested
    ///
    /// `in_persistent_congestion` indicates whether all packets sent within the persistent
    /// congestion threshold period ending when the most recent packet in this batch was sent were
    /// lost.
    /// `lost_bytes` indicates how many bytes were lost. This value will be 0 for ECN triggers.
    /// `largest_lost_pn` indicates the packet number of the packet with the highest packet number
    /// in the congestion event.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
        largest_lost_pn: u64,
    );

    /// One packet was just lost
    #[allow(unused_variables)]
    fn on_packet_lost(&mut self, lost_bytes: u16, pn: u64, now: Instant) {}

    /// Packets were incorrectly deemed lost
    ///
    /// This function is called when all packets that were deemed lost (for instance because
    /// of packet reordering) are acknowledged after the congestion event was raised.
    fn on_spurious_congestion_event(&mut self) {}

    /// The known MTU for the current network path has been updated
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// The peer's ACK-frequency parameters have changed
    ///
    /// `ack_eliciting_threshold` is the number of ack-eliciting packets the peer may receive
    /// before being required to send an immediate ACK (per the QUIC ACK frequency extension).
    /// `requested_max_ack_delay` is the maximum delay we asked the peer to wait before sending
    /// an ACK when the threshold hasn't been reached.
    ///
    /// Controllers can use this to refine estimates that depend on peer ACK behavior (e.g.
    /// BBR's offload budget).
    #[allow(unused_variables)]
    fn on_ack_frequency_update(
        &mut self,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: Duration,
    ) {
    }

    /// Number of ack-eliciting bytes that may be in flight
    fn window(&self) -> u64;

    /// Retrieve implementation-specific metrics used to populate `qlog` traces when they are enabled
    /// This is also used to alter the pacing of the connection with
    /// `pacing_rate` and `send_quantum`
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: None,
            send_quantum: None,
            queue_delay_guard_transitions: 0,
            policer_pacing_scale_per_mille: 1_000,
            policer_pacing_transitions: 0,
            snapshot: None,
        }
    }

    /// Runtime tuning handle for controllers that support lock-free updates.
    fn tunables(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        None
    }

    /// Duplicate the controller's state
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Initial congestion window
    fn initial_window(&self) -> u64;

    /// Returns Self for use in down-casting to extract implementation details
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Common congestion controller metrics used both for logging purposes
/// but also to alter the pacing of the connection with
/// `pacing_rate` and `send_quantum`
#[derive(Default)]
#[non_exhaustive]
pub struct ControllerMetrics {
    /// Congestion window (bytes)
    pub congestion_window: u64,
    /// Slow start threshold (bytes)
    pub ssthresh: Option<u64>,
    /// Pacing rate (bytes/s)
    pub pacing_rate: Option<u64>,
    /// Send Quantum (bytes) used to control the size of packet bursts
    pub send_quantum: Option<u64>,
    /// Number of controller state transitions caused by automatic queue-delay
    /// protection. Controllers without such a guard report zero.
    pub queue_delay_guard_transitions: u64,
    /// Automatic pacing scale learned from sustained loss on a short-RTT
    /// shallow policer. A value of 1000 means no policer cap.
    pub policer_pacing_scale_per_mille: u16,
    /// Number of automatic policer pacing reductions applied so far.
    pub policer_pacing_transitions: u64,
    /// Detailed model snapshot for controllers that expose one.
    pub snapshot: Option<ControllerSnapshot>,
}

/// Read-only congestion-controller model state for slow-path telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct ControllerSnapshot {
    /// Controller state: Startup=0, Drain=1, ProbeBW Down/Cruise/Refill/Up=2..5, ProbeRTT=6.
    pub state: u8,
    /// Current bounded bandwidth estimate in bytes/s.
    pub bw: u64,
    /// Maximum recent bandwidth estimate in bytes/s.
    pub max_bw: u64,
    /// Minimum RTT estimate.
    pub min_rtt: Duration,
    /// Smoothed RTT estimate.
    pub srtt: Duration,
    /// Current bandwidth-delay product in bytes.
    pub bdp: u64,
    /// Long-term inflight bound in bytes.
    pub inflight_longterm: u64,
    /// Short-term inflight bound in bytes.
    pub inflight_shortterm: u64,
    /// Packet-timed round counter.
    pub round_count: u64,
    /// ProbeBW cycle counter.
    pub cycle_count: u64,
    /// Whether the current rate sample was application-limited.
    pub app_limited_in_round: bool,
    /// Lost bytes observed in the current round.
    pub lost_in_round: u64,
    /// Delivered bytes observed over the connection lifetime.
    pub delivered_in_round: u64,
    /// Number of ProbeRTT entries.
    pub probe_rtt_entries: u64,
    /// Number of queue-delay guard transitions.
    pub guard_transitions: u64,
    /// Measured fraction of transmitted bytes that arrived, in parts per mille.
    pub erasure_measured_arrival_per_mille: u16,
    /// Arrival fraction currently applied to pacing and cwnd, in parts per mille.
    /// Values below 1000 mean the gross wire budget is being compensated.
    pub erasure_applied_arrival_per_mille: u16,
    /// Number of causal erasure-compensation adjustments.
    pub erasure_compensation_transitions: u64,
    /// Number of untrusted tuning values clamped by the controller.
    pub clamped_writes: u64,
    /// Last tuning generation applied by the controller.
    pub params_generation: u64,
}

/// Constructs controllers on demand
pub trait ControllerFactory {
    /// Construct a fresh `Controller`
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller>;
}

const BASE_DATAGRAM_SIZE: u64 = 1200;
