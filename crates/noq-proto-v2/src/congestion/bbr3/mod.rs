mod max_filter;
mod tunables;

pub use tunables::{Bbr3Params, Bbr3Tunables};

use crate::RttEstimator;
use crate::congestion::bbr3::max_filter::MaxFilter;
use crate::congestion::{Controller, ControllerFactory, ControllerMetrics, ControllerSnapshot};
use crate::{Duration, Instant};
use rand::{RngExt, SeedableRng};
use rand_pcg::Pcg32;
use std::any::Any;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Number of complete ProbeBW cycles retained by the maximum-delivery filter.
///
/// Two cycles are sufficient for a lossless flow, but on an 80-180 ms tunnel
/// with burst loss one low four-packet phase can expire the only capacity
/// sample before ProbeUp has time to repair it. Pacing and cwnd then shrink
/// together and recovery takes minutes. Ten cycles is still bounded, matches
/// the traditional BBR max-bandwidth horizon, and path migration constructs a
/// fresh controller so stale capacity is not carried across route changes.
const MAX_BW_FILTER_LEN: usize = 10;

/// equivalent to BBR.ExtraAckedFilterLen <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.11>
const EXTRA_ACKED_FILTER_LEN: usize = 10;

/// safety mechanism to flag packets as stale within our tracking VecDeque. rounds refer to <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1>.
/// The value of 10 rounds is picked because normally after max(kTimeThreshold * max(smoothed_rtt, latest_rtt), kGranularity) <https://datatracker.ietf.org/doc/html/rfc9002#section-6.1.2>
/// the packet should have been declared lost already, this is just to guarantee that the VecDeque doesn't grow indefinitely.
const ROUND_COUNT_WINDOW: u64 = 10;

/// the minimum for the maximum datagram size <https://datatracker.ietf.org/doc/html/rfc9000#section-14>
const MIN_MAX_DATAGRAM_SIZE: u16 = 1200;

/// the maximum for the maximum datagram size <https://datatracker.ietf.org/doc/html/rfc9000#section-18.2>
const MAX_DATAGRAM_SIZE: u64 = 65527;

/// 1.2Mbps converted to bytes/sec, used to determine `send_quantum`.
/// this is the pacing rate used where we don't authorize a burst bigger than a full packet
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const PACING_RATE_1_2MBPS: f64 = 1_200_000.0 / 8.0;

/// 24Mbps converted to bytes/sec.
/// this is the pacing rate used where we don't authorize a burst bigger than two full packets
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const PACING_RATE_24MBPS: f64 = 24_000_000.0 / 8.0;

/// 64 Kb in bytes
/// this is the maximum size we want for a quantum in `set_send_quantum`
/// inspired by a previous version of BBR2 used in cloudflare's quiche
const HIGH_PACE_MAX_QUANTUM: u64 = 64 * 1000;

/// High-rate pacer wakeups per second. A 5 ms quantum amortizes userspace
/// timer/send-call overhead while the 64 KB ceiling bounds each burst.
const HIGH_PACE_QUANTUMS_PER_SECOND: f64 = 200.0;

/// A host-managed steady-state cap uses a one-millisecond aggregate budget
/// capped at twelve SMSS. This avoids the persistent throughput loss of the
/// stricter publication-edge drain budget below.
const EXTERNAL_CAP_QUANTUMS_PER_SECOND: f64 = 1_000.0;
const EXTERNAL_CAP_MAX_QUANTUM_PACKETS: u64 = 12;
/// When a cap is first published, briefly shrink the aggregate burst to drain
/// packets queued by the previously uncapped quantum before settling at the
/// sustainable external-cap budget.
const EXTERNAL_CAP_DRAIN_QUANTUMS_PER_SECOND: f64 = 1_500.0;
const EXTERNAL_CAP_DRAIN_MAX_QUANTUM_PACKETS: u64 = 6;
const EXTERNAL_CAP_DRAIN_ROUNDS: u8 = 4;
/// A bounded host-requested capacity probe uses the same one-millisecond,
/// twelve-SMSS budget as a shallow policer. This also protects the first
/// paced quantum while the request is still waiting for a round refresh.
const CAPACITY_PROBE_QUANTUMS_PER_SECOND: f64 = 1_000.0;
const CAPACITY_PROBE_MAX_QUANTUM_PACKETS: u64 = 12;
/// A bounded host-requested reprobe on a short path protects its first
/// ordinary quantum only while the prior model is below 32 MiB/s. Above that
/// rate, the smaller timer interval is more likely to cost throughput than to
/// protect a shallow queue.
const CAPACITY_PROBE_QUANTUM_MAX_BW: f64 = 32.0 * 1024.0 * 1024.0;
/// Before outcome classification, a correlated loss declaration needs a
/// sustainable one-millisecond bound so another oversized quantum is not
/// emitted during the active Bulk episode.
const SHALLOW_LOSS_QUANTUMS_PER_SECOND: f64 = 1_000.0;
const SHALLOW_LOSS_MAX_QUANTUM_PACKETS: u64 = 12;

/// equivalent to BBR.StartupPacingGain: A constant specifying the minimum gain value for calculating the pacing rate that will allow
/// the sending rate to double each round (4 * ln(2) ~= 2.77)
/// BBRStartupPacingGain; used in Startup mode for BBR.pacing_gain. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
const STARTUP_PACING_GAIN: f64 = 2.773;

/// equivalent to BBR.PacingMarginPercent: The static discount factor of 1% used to scale BBR.bw to produce C.pacing_rate.
const PACING_MARGIN_PERCENT: f64 = 1.0;

/// equivalent to BBR.DefaultCwndGain: A constant specifying the minimum gain value that allows the sending rate to double each round (2) BBRStartupCwndGain.
/// Used by default in most phases for BBR.cwnd_gain.
const DEFAULT_CWND_GAIN: f64 = 2.0;

/// equivalent to BBR.DrainPacingGain: A constant specifying the pacing gain value used in Drain mode,
/// to attempt to drain the estimated queue at the bottleneck link in one round-trip or less.
/// As noted in BBRDrainPacingGain, any value at or below 1 / BBRStartupCwndGain = 1 / 2 = 0.5 will theoretically achieve this.
/// BBR uses the value 0.5, which has been shown to offer good performance when compared with other alternatives.
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.4>
/// <https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_drain_gain.pdf>
const DRAIN_PACING_GAIN: f64 = 1.0 / DEFAULT_CWND_GAIN;

// A short-RTT shallow policer drops instead of retaining a measurable queue,
// so the RTT guard cannot distinguish it from random radio loss. Aggregate
// outcomes over 500 ms so QUIC's delayed/batched loss declarations remain in
// the same sample as their ACKs. A <=10 ms path with sustained >=2% loss may
// trial a frozen model below the high-rate Wi-Fi boundary; confirmed episodes
// retain that fixed model unless sustained loss disproves it. Other paths stay
// on the FEC/Repair path.
const POLICER_RTT_CEILING: Duration = Duration::from_millis(20);
const POLICER_SAMPLE_WINDOW: Duration = Duration::from_millis(500);
const POLICER_MIN_SAMPLE_BYTES: u64 = 64 * 1024;
const POLICER_LOSS_THRESHOLD: f64 = 0.02;
const POLICER_CLEAN_THRESHOLD: f64 = 0.005;
/// A confirmed shallow-policer episode retains modest headroom below BBR's
/// windowed maximum delivery-rate model. Episode activity is represented by
/// the transition counter rather than a multiplicative live-bandwidth scale.
const POLICER_EPISODE_PACING_SCALE: f64 = 1.0;
/// Discount BBR's windowed maximum during the bounded drain trial. A clean
/// confirmation restores most of that estimator margin while retaining a
/// small fixed headroom below the frozen model.
const POLICER_TRIAL_MAX_BW_SCALE: f64 = 0.92;
const POLICER_CONFIRMED_MAX_BW_SCALE: f64 = 0.98;
const POLICER_FALLBACK_TRIAL_SCALE: f64 = 1.10;
/// After one drain/warmup outcome, allow four complete confirmation outcomes
/// so pre-cap delayed loss cannot decide classification.
const POLICER_TRIAL_CONFIRMATION_WINDOWS: u8 = 4;
const POLICER_FALLBACK_MIN_RTT_CEILING: Duration = Duration::from_millis(10);
/// Persistent loss disproves the fixed-policer hypothesis. Requiring ten
/// consecutive complete outcomes tolerates isolated delayed-loss phases on a
/// real shallow policer while retiring an interference false positive in
/// about five seconds.
const POLICER_CONFIRMED_LOSS_REVOKE_WINDOWS: u8 = 10;
const SHALLOW_LOSS_BURST_PACKETS: u64 = 16;

// BBR estimates the rate that arrives while its pacer controls the rate put on
// the wire. On a path with rate-independent erasure those differ by the arrival
// rate, so feeding the unadjusted delivery estimate back into the pacer makes
// the estimate decay once more every round. Compensate only one tenth at a time
// and require the preceding step to have raised delivery before taking another
// one. This is the causal guard that prevents a drop policer from turning loss
// into an unbounded positive-feedback loop.
const ERASURE_COMPENSATION_STEP: f64 = 0.9;
const ERASURE_MIN_ARRIVAL_RATE: f64 = 0.15;
const ERASURE_OUTCOME_DECAY: f64 = 0.75;
const ERASURE_MIN_SAMPLE_PACKETS: u64 = 32;

/// equivalent to BBR.MinRTTFilterLen: A constant specifying the length of the BBR.min_rtt min filter window, BBR.MinRTTFilterLen is 10 secs.
const MIN_RTT_FILTER_LEN: u64 = 10;

/// multiplier used to check growth when validating if the full bandwidth has been reached
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
const FULL_BW_GROWTH: f64 = 1.25;

/// maximum number of rounds needed before we consider that the pipe is full <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
const MAX_FULL_BW_COUNT: u64 = 3;

/// Number of valid, non-application-limited packet-timed rounds for which a
/// host-requested capacity reprobe ignores a flat delivery-rate sample.
///
/// A semantic bulk/backlog edge can arrive while BBR's retained model still
/// describes sparse control traffic. Three flat samples at that tiny rate can
/// otherwise end Startup before the higher-gain flight is acknowledged. Eight
/// rounds cover the bounded exponential discovery needed by the high-RTT
/// matrix while the independent RTT queue guard can still end Startup early.
const CAPACITY_PROBE_GRACE_ROUNDS: u8 = 8;

/// when setting `bw_probe_up_rounds` when raising our inflight long term slope we don't go above this
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
const MAX_LONG_TERM_PROBE_UP_ROUNDS: u32 = 30;

/// max number of rounds used when deciding to coexist with Reno / CUBIC <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.1>
const MAX_RENO_ROUNDS: u64 = 63;

/// Substates when probing bandwidth
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProbeBwSubstate {
    /// Deceleration: sends slower than delivery rate to reduce queue
    /// equivalent to ProbeBW_DOWN <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.1>
    Down,

    /// Cruising: sends at delivery rate to maintain high utilization
    /// equivalent to ProbeBW_CRUISE <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.2>
    Cruise,

    /// Refill: sends at BBR.bw for one RTT to fill pipe before probing up
    /// equivalent to ProbeBW_REFILL <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.3>
    Refill,

    /// Acceleration: sends faster than delivery rate to probe for more bandwidth
    /// equivalent to ProbeBW_UP <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.4>
    Up,
}

/// State Machine description from BBR3
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BbrState {
    /// Initial state: rapidly probes for bandwidth using high pacing_gain
    /// equivalent to Startup <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1>
    Startup,

    /// Drains queue created during Startup by using low pacing_gain (< 1.0)
    /// equivalent to Drain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.2>
    Drain,

    /// Steady-state phase that cycles through bandwidth probing tactics
    /// equivalent to ProbeBW states <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3>
    ProbeBw(ProbeBwSubstate),

    /// Temporarily reduces inflight to measure true min_rtt
    /// equivalent to ProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4>
    ProbeRtt,
}

/// Ack phases used during ProbeBW states
/// equivalent to BBR.ack_phase states <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6>
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AckPhase {
    /// equivalent to ACKS_PROBE_STARTING
    ProbeStarting,
    /// equivalent to ACKS_PROBE_STOPPING
    ProbeStopping,
    /// equivalent to ACKS_REFILLING
    Refilling,
    /// equivalent to ACKS_PROBE_FEEDBACK
    ProbeFeedback,
}

/// Description of a packet for the purposes of analysis through BBR3
/// all volumes of data use bytes, all rates of data use bytes/sec
/// equivalent to P <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.1.2>
#[derive(Debug, Clone, Copy)]
struct BbrPacket {
    /// equivalent to P.delivered: C.delivered when the packet was sent from transport connection C.
    delivered: u64,
    /// equivalent to P.delivered_time: C.delivered_time when the packet was sent.
    delivered_time: Instant,
    /// equivalent to P.first_send_time: C.first_send_time when the packet was sent.
    first_send_time: Instant,
    /// equivalent to P.send_time: The pacing departure time selected when the packet was scheduled to be sent.
    send_time: Instant,
    /// equivalent to P.is_app_limited: true if C.app_limited was non-zero when the packet was sent, else false.
    is_app_limited: bool,
    /// equivalent to P.tx_in_flight: C.inflight immediately after the transmission of packet P.
    tx_in_flight: u64,
    /// packet number from the connection
    packet_number: u64,
    /// packet size in bytes
    size: u16,
    /// equivalent to P.lost: C.lost when the packet was sent
    lost: u64,
    /// used to flag acknowledgement within our VecDeque, a packet can be flagged lost after having been flagged acknowledged
    /// hence the necessity of this flag being set before we remove it from packets.
    acknowledged: bool,
    /// used to mark packets stale if they're far from the current round <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1>
    round_count: u64,
}

/// Description of a per-ack rate sample state that will allow us to determine a short term evolution of the connection
/// equivalent to RS <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.2>
#[derive(Debug, Clone, Copy)]
struct BbrRateSample {
    /// equivalent to RS.delivery_rate: The delivery rate (aka bandwidth) sample obtained from the packet that has just been ACKed.
    delivery_rate: f64,
    /// equivalent to RS.is_app_limited: The P.is_app_limited from the most recent packet
    ///    delivered; indicates whether the rate sample is application-limited.
    is_app_limited: bool,
    /// equivalent to RS.interval: The length of the sampling interval.
    interval: Duration,
    /// equivalent to RS.delivered: The volume of data delivered between the transmission of the packet that has just been ACKed and the current time.
    delivered: u64,
    /// equivalent to RS.prior_delivered: The P.delivered count from the most recent packet delivered.
    prior_delivered: u64,
    /// equivalent to RS.prior_time: The P.delivered_time from the most recent packet delivered.
    prior_time: Instant,
    /// equivalent to RS.send_elapsed: Send time interval calculated from the most recent
    ///    packet delivered (see the "Send Rate" section above).
    send_elapsed: Duration,
    /// equivalent to RS.ack_elapsed: ACK time interval calculated from the most recent
    ///    packet delivered (see the "ACK Rate" section above).
    ack_elapsed: Duration,
    /// equivalent to RS.rtt: The RTT sample calculated based on the most recently-sent packet of the packets that have just been ACKed.
    rtt: Duration,
    /// equivalent to RS.tx_in_flight: C.inflight at the time of the transmission of the packet that has just been ACKed
    /// (the most recently sent packet among packets ACKed by the ACK that was just received).
    tx_in_flight: u64,
    /// equivalent to RS.newly_acked: The volume of data in bytes cumulatively or selectively acknowledged upon the ACK that was just received.
    newly_acked: u64,
    /// equivalent to RS.newly_lost: The volume of data in bytes newly marked lost upon the ACK that was just received.
    newly_lost: u64,
    /// equivalent to RS.lost: The volume of data in bytes that was declared lost between the transmission
    /// and acknowledgment of the packet that has just been ACKed (the most recently sent packet among packets ACKed by the ACK that was just received).
    lost: u64,
    /// equivalent to RS.last_end_seq
    last_end_seq: u64,
    /// represents the last packet that was used in the generation of this rate sample
    last_packet: BbrPacket,
}

/// Experimental! Use at your own risk.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html>
/// equivalent to a combination of BBR and C states
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.4>
/// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.1>
#[derive(Debug, Clone)]
pub struct Bbr3 {
    /// Path-local runtime tuning handle. Cloned controllers intentionally
    /// share it; separately constructed paths receive separate handles.
    tunables: Arc<Bbr3Tunables>,
    /// Validated parameters refreshed only at packet-timed round boundaries.
    params: Bbr3Params,
    params_generation: u64,
    /// equivalent to C.SMSS The Sender Maximum Send Size in bytes. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.1>
    /// <https://www.rfc-editor.org/rfc/rfc9000#name-datagram-size>
    smss: u64,
    /// equivalent to C.InitialCwnd: The initial congestion window set by the transport protocol implementation for the connection at initialization time.
    initial_cwnd: u64,
    /// equivalent to C.delivered: The total amount of data delivered so far over the lifetime of the transport connection C.
    /// This MUST NOT include pure ACK packets. It SHOULD include spurious retransmissions that have been acknowledged as delivered.
    delivered: u64,
    /// equivalent to C.inflight: The connection's best estimate of the number of bytes outstanding in the network.
    /// This includes the number of bytes that have been sent and have not been acknowledged or marked as lost since their last transmission
    /// (e.g. "pipe" from RFC6675 or "bytes_in_flight" from RFC9002). This MUST NOT include pure ACK packets.
    inflight: u64,
    /// equivalent to C.is_cwnd_limited: True if the connection has fully utilized C.cwnd at any point in the last packet-timed round trip.
    is_cwnd_limited: bool,
    /// equivalent to BBR.cycle_count: The virtual time used by the BBR.max_bw filter window.
    /// since the BBR.max_bw_filter only needs to track samples from two time slots: the previous ProbeBW cycle and the current ProbeBW cycle.
    cycle_count: u64,
    /// equivalent to C.cwnd: The transport sender's congestion window. When transmitting data, the sending connection ensures that C.inflight does not exceed C.cwnd.
    cwnd: u64,
    /// equivalent to C.pacing_rate: The current pacing rate for a BBR flow, which controls inter-packet spacing.
    pacing_rate: f64,
    /// equivalent to C.send_quantum: The maximum size of a data aggregate scheduled and transmitted together as a unit, e.g., to amortize per-packet transmission overheads.
    send_quantum: u64,
    /// equivalent to BBR.pacing_gain: The dynamic gain factor used to scale BBR.bw to produce C.pacing_rate.
    pacing_gain: f64,
    /// default pacing gain is 1, when cruising, probing for RTT or refilling <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    default_pacing_gain: f64,
    /// pacing gain when probing bandwidth down <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_bw_down_pacing_gain: f64,
    /// pacing gain when probing bandwidth up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_bw_up_pacing_gain: f64,
    /// equivalent to BBR.StartupPacingGain: A constant specifying the minimum gain value for calculating the pacing rate that will allow
    /// the sending rate to double each round (4 * ln(2) ~= 2.77)
    /// BBRStartupPacingGain; used in Startup mode for BBR.pacing_gain. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    startup_pacing_gain: f64,
    /// equivalent to BBR.DrainPacingGain: A constant specifying the pacing gain value used in Drain mode,
    /// to attempt to drain the estimated queue at the bottleneck link in one round-trip or less.
    /// As noted in BBRDrainPacingGain, any value at or below 1 / BBRStartupCwndGain = 1 / 2 = 0.5 will theoretically achieve this.
    /// BBR uses the value 0.5, which has been shown to offer good performance when compared with other alternatives.
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    drain_pacing_gain: f64,
    /// equivalent to BBR.PacingMarginPercent: The static discount factor of 1% used to scale BBR.bw to produce C.pacing_rate.
    pacing_margin_percent: f64,
    /// equivalent to BBR.cwnd_gain: The dynamic gain factor used to scale the estimated BDP to produce a congestion window (C.cwnd).
    cwnd_gain: f64,
    /// equivalent to BBR.DefaultCwndGain: A constant specifying the minimum gain value that allows the sending rate to double each round (2) BBRStartupCwndGain.
    /// Used by default in most phases for BBR.cwnd_gain.
    default_cwnd_gain: f64,
    /// used to generate random numbers when deciding how long to wait before probing again
    /// using Pcg32 as it's a fast general purpose random number generator and fits our purpose here
    /// these numbers will not be security critical as they're only used to decide when to probe the connection next.
    probe_rng: Pcg32,
    /// cwnd gain used when probing up <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_bw_up_cwnd_gain: f64,
    /// cwnd gain used when probing RTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.1>
    probe_rtt_cwnd_gain: f64,
    /// equivalent to BBR.state: The current state of a BBR flow in the BBR state machine. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-3.3>
    state: BbrState,
    /// equivalent to BBR.undo_state: The state of a BBR flow in the BBR state machine saved in case a loss episode is later declared spurious. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-3.3>
    undo_state: BbrState,
    /// equivalent to BBR.round_count: Count of packet-timed round trips elapsed so far.
    round_count: u64,
    /// equivalent to BBR.round_start: A boolean that BBR sets to true once per packet-timed round trip, on ACKs that advance BBR.round_count.
    round_start: bool,
    /// equivalent to BBR.next_round_delivered: P.delivered value denoting the end of a packet-timed round trip.
    next_round_delivered: u64,
    /// equivalent to BBR.idle_restart: A boolean that is true if and only if a connection is restarting after being idle.
    idle_restart: bool,
    /// equivalent to BBR.MinPipeCwnd: The minimal C.cwnd value BBR targets, to allow pipelining with endpoints that follow an "ACK every other packet" delayed-ACK policy: 4 * C.SMSS.
    min_pipe_cwnd: u64,
    /// equivalent to BBR.max_bw: The windowed maximum recent bandwidth sample, obtained using the BBR delivery rate sampling algorithm in
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1>,
    /// measured during the current or previous bandwidth probing cycle (or during Startup, if the flow is still in that state). (Part of the long-term model.)
    max_bw: f64,
    /// equivalent to BBR.bw_shortterm: The short-term maximum sending bandwidth that the algorithm estimates is safe for matching the current network path delivery rate,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_bw. (Part of the short-term model.)
    bw_shortterm: f64,
    /// equivalent to BBR.undo_bw_shortterm: The short-term maximum sending bandwidth that the algorithm estimates is safe for matching the current network path delivery rate,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_bw. (Part of the short-term model.)
    /// saved state in case a loss episode is later declared spurious
    undo_bw_shortterm: f64,
    /// equivalent to BBR.bw: The maximum sending bandwidth that the algorithm estimates is appropriate for matching the current network path delivery rate,
    /// given all available signals in the model, at any time scale. It is the min() of max_bw and bw_shortterm.
    bw: f64,
    /// equivalent to BBR.min_rtt: The windowed minimum round-trip time sample measured over the last BBR.MinRTTFilterLen = 10 seconds.
    /// This attempts to estimate the two-way propagation delay of the network path when all connections sharing a bottleneck are using BBR,
    /// but also allows BBR to estimate the value required for a BBR.bdp estimate that allows full throughput if there are legacy loss-based Reno or CUBIC flows sharing the bottleneck.
    min_rtt: Duration,
    /// equivalent to BBR.bdp: The estimate of the network path's BDP (Bandwidth-Delay Product), computed as: BBR.bdp = BBR.bw * BBR.min_rtt.
    bdp: u64,
    /// equivalent to BBR.extra_acked: A volume of data that is the estimate of the recent degree of aggregation in the network path.
    extra_acked: u64,
    /// equivalent to BBR.offload_budget: The estimate of the minimum volume of data necessary to achieve full throughput when using sender
    /// (TSO/GSO) and receiver (LRO, GRO) host offload mechanisms.
    offload_budget: u64,
    /// equivalent to BBR.max_inflight: The estimate of C.inflight required to fully utilize the bottleneck bandwidth available to the flow,
    /// based on the BDP estimate (BBR.bdp), the aggregation estimate (BBR.extra_acked), the offload budget (BBR.offload_budget), and BBR.MinPipeCwnd.
    max_inflight: u64,
    /// equivalent to BBR.inflight_longterm: The long-term maximum inflight that the algorithm estimates will produce acceptable queue pressure,
    /// based on signals in the current or previous bandwidth probing cycle, as measured by loss. That is, if a flow is probing for bandwidth,
    /// and observes that sending a particular inflight causes a loss rate higher than the loss rate threshold,
    /// it sets inflight_longterm to that volume of data. (Part of the long-term model.)
    inflight_longterm: u64,
    /// equivalent to BBR.inflight_longterm: The long-term maximum inflight that the algorithm estimates will produce acceptable queue pressure,
    /// based on signals in the current or previous bandwidth probing cycle, as measured by loss. That is, if a flow is probing for bandwidth,
    /// and observes that sending a particular inflight causes a loss rate higher than the loss rate threshold,
    /// it sets inflight_longterm to that volume of data. (Part of the long-term model.)
    /// saved state in case a loss episode is later declared spurious
    undo_inflight_longterm: u64,
    /// equivalent to BBR.inflight_shortterm: Analogous to BBR.bw_shortterm,
    /// the short-term maximum inflight that the algorithm estimates is safe for matching the current network path delivery process,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_inflight or inflight_longterm. (Part of the short-term model.)
    inflight_shortterm: u64,
    /// equivalent to BBR.undo_inflight_shortterm: Analogous to BBR.bw_shortterm,
    /// the short-term maximum inflight that the algorithm estimates is safe for matching the current network path delivery process,
    /// based on any loss signals in the current bandwidth probing cycle. This is generally lower than max_inflight or inflight_longterm. (Part of the short-term model.)
    /// saved state in case a loss episode is later declared spurious
    undo_inflight_shortterm: u64,
    /// equivalent to BBR.bw_latest: a 1-round-trip max of delivered bandwidth (RS.delivery_rate).
    bw_latest: f64,
    /// equivalent to BBR.inflight_latest: a 1-round-trip max of delivered volume of data (RS.delivered).
    inflight_latest: u64,
    /// equivalent to BBR.max_bw_filter: A windowed max filter for RS.delivery_rate samples, for estimating BBR.max_bw.
    max_bw_filter: MaxFilter,
    /// equivalent to BBR.extra_acked_interval_start: The start of the time interval for estimating the excess amount of data acknowledged due to aggregation effects.
    extra_acked_interval_start: Option<Instant>,
    /// equivalent to BBR.extra_acked_delivered: The volume of data marked as delivered since BBR.extra_acked_interval_start.
    extra_acked_delivered: u64,
    /// equivalent to BBR.extra_acked_filter: A windowed max filter for tracking the degree of aggregation in the path.
    extra_acked_filter: MaxFilter,
    /// equivalent to BBR.full_bw_reached: A boolean that records whether BBR estimates that it has ever fully utilized its available bandwidth over the lifetime of the connection.
    full_bw_reached: bool,
    /// equivalent to BBR.full_bw_now: A boolean that records whether BBR estimates that it has fully utilized its available bandwidth since it most recetly started looking.
    full_bw_now: bool,
    /// equivalent to BBR.full_bw: A recent baseline BBR.max_bw to estimate if BBR has "filled the pipe" in Startup.
    full_bw: f64,
    /// equivalent to BBR.full_bw_count: The number of non-app-limited round trips without large increases in BBR.full_bw.
    full_bw_count: u64,
    /// Valid packet-timed rounds left in a host-requested capacity-discovery
    /// grace period. Ordinary path activation and Startup leave this at zero.
    capacity_probe_grace_rounds_remaining: u8,
    /// equivalent to BBR.min_rtt_stamp: The wall clock time at which the current BBR.min_rtt sample was obtained.
    min_rtt_stamp: Option<Instant>,
    /// equivalent to BBR.ProbeRTTDuration: A constant specifying the minimum duration for which ProbeRTT state holds C.inflight to BBR.MinPipeCwnd or fewer packets: 200 ms.
    probe_rtt_duration: Duration,
    /// equivalent to BBR.ProbeRTTInterval: A constant specifying the minimum time interval between ProbeRTT states: 5 secs.
    probe_rtt_interval: Duration,
    /// equivalent to BBR.probe_rtt_min_delay: The minimum RTT sample recorded in the last ProbeRTTInterval.
    probe_rtt_min_delay: Duration,
    /// equivalent to BBR.probe_rtt_min_stamp: The wall clock time at which the current BBR.probe_rtt_min_delay sample was obtained.
    probe_rtt_min_stamp: Option<Instant>,
    /// equivalent to BBR.probe_rtt_expired: A boolean recording whether the BBR.probe_rtt_min_delay has expired and
    /// is due for a refresh with an application idle period or a transition into ProbeRTT state.
    probe_rtt_expired: bool,
    /// equivalent to C.delivered_time: The wall clock time when C.delivered was last updated. <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.1.2.1>
    delivered_time: Option<Instant>,
    /// equivalent to C.first_send_time: If packets are in flight, then this holds the send time of the packet that was most recently marked as delivered.
    /// Else, if the connection was recently idle, then this holds the send time of most recently sent packet.
    first_send_time: Option<Instant>,
    /// equivalent to C.app_limited: The index of the last transmitted packet marked as application-limited, or 0 if the connection is not currently application-limited.
    app_limited: u64,
    /// equivalent to C.lost: the number of bytes that have been lost during the lifetime of this connection
    lost: u64,
    /// equivalent to C.srtt: The smoothed RTT, an exponentially weighted moving average of the observed RTT of the connection.
    srtt: Duration,
    /// collection of packets in flight or just acknowledged / lost.
    packets: VecDeque<BbrPacket>,
    /// equivalent to RS: Per-ACK Rate Sample State <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.2>
    rs: Option<BbrRateSample>,
    /// equivalent to BBR.rounds_since_bw_probe: rounds since last bw probe state.
    rounds_since_bw_probe: u64,
    /// equivalent to BBR.bw_probe_wait: random wait time before entering probing state again
    bw_probe_wait: Duration,
    /// equivalent to BBR.bw_probe_up_rounds: number of rounds that have been executed in probe up state
    bw_probe_up_rounds: u32,
    /// equivalent to BBR.bw_probe_up_acks: volume of data in bytes that has been acknowledged during probe up state
    bw_probe_up_acks: u64,
    /// equivalent to BBR.probe_up_cnt: count of the number of times we've grown the cwnd during probe up state
    probe_up_cnt: u64,
    /// equivalent to BBR.cycle_stamp: timestamp when we start probing down state
    cycle_stamp: Option<Instant>,
    /// equivalent to BBR.ack_phase: ACK phase during probing states
    ack_phase: AckPhase,
    /// equivalent to BBR.bw_probe_samples: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2>
    bw_probe_samples: bool,
    /// equivalent to BBR.loss_round_delivered: C.delivered during the first loss of the round
    loss_round_delivered: u64,
    /// equivalent to BBR.loss_in_round: flag set to true when loss occurs during the round
    loss_in_round: bool,
    /// True after the transport reports ECN in the current model-update interval. ECN is an
    /// explicit congestion signal, so it must never use the relaxed random-loss threshold.
    explicit_congestion_in_round: bool,
    /// ACKed/lost wire outcomes accumulated until the next packet-timed round.
    /// They are separate from BBR's loss accounting: every loss still reaches
    /// the inner model for bytes-in-flight bookkeeping.
    erasure_round_acked_bytes: u64,
    erasure_round_lost_bytes: u64,
    erasure_acked_weight: f64,
    erasure_lost_weight: f64,
    /// Measured and causally-applied arrival fractions. The applied value starts
    /// at one and approaches the measured value only when each preceding step
    /// bought a higher delivery rate.
    erasure_measured_arrival: f64,
    erasure_applied_arrival: f64,
    erasure_compensation_round: u64,
    erasure_delivered_at_compensation: f64,
    erasure_compensation_transitions: u64,
    erasure_compensation_changed: bool,
    /// ECN suppresses erasure compensation through the next completed round;
    /// `explicit_congestion_in_round` is reset earlier by the BBR model update.
    erasure_explicit_congestion_in_round: bool,
    /// equivalent to BBR.probe_rtt_done_stamp: timestamp when probe RTT state is finished
    probe_rtt_done_stamp: Option<Instant>,
    /// equivalent to BBR.probe_rtt_round_done: set once per round when BBR.probe_rtt_done_stamp to check if we need to switch state
    probe_rtt_round_done: bool,
    /// equivalent to BBR.prior_cwnd: cwnd from last round
    prior_cwnd: u64,
    /// equivalent to BBR.loss_round_start: flag set to true at the very beginning of a round where loss occurred
    loss_round_start: bool,
    /// equivalent to BBR.drain_start_round: The value of round_count when Drain state started.
    drain_start_round: u64,
    /// Number of ack-eliciting packets the peer may receive before sending an immediate ACK,
    /// as requested via the QUIC ACK frequency extension. Used when computing `offload_budget`
    /// per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.8.2>.
    ack_eliciting_threshold: u64,
    /// `max_ack_delay` we requested the peer to use via the QUIC ACK frequency extension.
    /// Used when computing `offload_budget` per
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.8.2>.
    max_ack_delay: Duration,
    /// Optional host/datacenter fast-path threshold. Below this measured RTT,
    /// BBR still controls inflight but lets the socket/kernel scheduler drain
    /// a complete QUIC send quantum without userspace pacing timer churn.
    pacing_bypass_below_rtt: Option<Duration>,
    low_rtt_cwnd_floor: u64,
    /// Cumulative automatic Startup/ProbeBW transitions caused by measured
    /// queue delay. Exposed read-only for tuning/profile evidence.
    queue_delay_guard_transitions: u64,
    probe_rtt_entries: u64,
    /// Time-bounded outcome window used to identify a shallow policer without
    /// treating long-haul/radio loss as congestion.
    policer_window_started: Option<Instant>,
    policer_window_acked_bytes: u64,
    policer_window_lost_bytes: u64,
    policer_pacing_scale: f64,
    policer_pacing_transitions: u64,
    /// The first trusted lossy outcome arms confirmation from BBR's existing
    /// windowed max-bandwidth model.
    policer_pacing_candidate_armed: bool,
    /// A burst-edge safety trial discards its first complete outcome so
    /// delayed losses from the pre-cap flight cannot decide confirmation.
    policer_pacing_candidate_warmup_windows_remaining: u8,
    /// Complete post-warmup outcomes still available to confirm a bounded
    /// safety trial before it is rejected for this semantic Bulk episode.
    policer_pacing_candidate_confirmation_windows_remaining: u8,
    /// Sticky evidence that at least one complete confirmation outcome had
    /// the bounded-horizon short-path latency signature.
    policer_pacing_candidate_saw_low_latency_window: bool,
    /// Consecutive fixed-ceiling outcomes with at least two-percent loss. A
    /// sufficiently long streak disproves the fixed-policer hypothesis.
    policer_pacing_consecutive_loss_windows: u8,
    /// Prevents repeated bounded trials after one exhausts its confirmation
    /// horizon. Only a semantic capacity/path/external reset clears it.
    policer_pacing_trial_rejected: bool,
    /// Absolute wire-rate ceiling confirmed from the windowed max-bandwidth
    /// model. Keeping the snapshot avoids following later model changes.
    policer_pacing_ceiling_bytes_per_second: f64,
    pacing_bypass_armed: bool,
    /// Keeps a short-path host capacity probe on its safe paced quantum until
    /// a complete policer window classifies the probe as clean or lossy.
    capacity_probe_quantum_guard_armed: bool,
    /// Packet-timed rounds remaining in the strict drain phase after a host
    /// pacing cap is first published. Positive-to-positive cap updates do not
    /// restart this phase.
    external_cap_drain_rounds_remaining: u8,
    /// Packet loss declared at one transport timestamp is a protection burst,
    /// not classification evidence. Sixteen SMSS immediately disables pacing
    /// bypass; only an already-lossy aggregate opens the temporary quantum
    /// guard/trial. Later complete outcomes independently classify the path.
    shallow_loss_declaration_stamp: Option<Instant>,
    shallow_loss_declaration_bytes: u64,
    shallow_loss_quantum_guard: bool,
}

impl Bbr3 {
    fn new(config: Arc<Bbr3Config>, current_mtu: u16) -> Self {
        let probe_rng: Pcg32;
        if let Some(probe_seed) = config.probe_rng_seed {
            probe_rng = Pcg32::from_seed(probe_seed);
        } else {
            probe_rng = Pcg32::from_rng(&mut rand::rng());
        }
        let smss = min(
            max(MIN_MAX_DATAGRAM_SIZE, current_mtu) as u64,
            MAX_DATAGRAM_SIZE,
        );
        let tunables = Arc::new(
            config
                .tunables_template
                .as_deref()
                .map(Bbr3Tunables::copy_from)
                .unwrap_or_default(),
        );
        // Preserve the pre-runtime-tuning builder API by applying its explicit
        // values to the path-local template before taking the first snapshot.
        if let Some(value) = config.default_pacing_gain {
            tunables
                .cruise_pacing_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_bw_down_pacing_gain {
            tunables
                .probe_bw_down_pacing_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_bw_up_pacing_gain {
            tunables
                .probe_bw_up_pacing_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.default_cwnd_gain {
            tunables
                .default_cwnd_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_bw_up_cwnd_gain {
            tunables
                .probe_bw_up_cwnd_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        if let Some(value) = config.probe_rtt_cwnd_gain {
            tunables
                .probe_rtt_cwnd_gain_milli
                .store((value * 1_000.0).round() as u32, Ordering::Relaxed);
        }
        let (mut params, mut clamped) = Bbr3Params::from_tunables(&tunables);
        let min_cwnd = 4 * smss;
        if params.cwnd_cap_bytes > 0 && params.cwnd_cap_bytes < min_cwnd {
            params.cwnd_cap_bytes = min_cwnd;
            clamped += 1;
        }
        if params.cwnd_cap_bytes > 0 && params.cwnd_floor_bytes > params.cwnd_cap_bytes {
            params.cwnd_floor_bytes = params.cwnd_cap_bytes;
            clamped += 1;
        }
        tunables
            .clamped_writes
            .fetch_add(clamped, Ordering::Relaxed);
        let params_generation = tunables.generation.load(Ordering::Relaxed);
        let hinted_cwnd = params.startup_bw_hint_bytes_per_second.saturating_mul(333) / 1_000;
        let mut initial_cwnd = config.initial_window.max(hinted_cwnd);
        if params.cwnd_cap_bytes > 0 {
            initial_cwnd = initial_cwnd.min(params.cwnd_cap_bytes);
        }
        initial_cwnd = initial_cwnd.max(4 * smss);
        if params.cwnd_floor_bytes > 0 {
            initial_cwnd = initial_cwnd.max(params.cwnd_floor_bytes);
        }
        let startup_pacing_gain = config.startup_pacing_gain.unwrap_or(STARTUP_PACING_GAIN);
        let default_pacing_gain = params.cruise_pacing_gain;
        let probe_bw_down_pacing_gain = params.probe_bw_down_pacing_gain;
        let probe_bw_up_pacing_gain = params.probe_bw_up_pacing_gain;
        let drain_pacing_gain = config.drain_pacing_gain.unwrap_or(DRAIN_PACING_GAIN);
        let pacing_margin_percent = config
            .pacing_margin_percent
            .unwrap_or(PACING_MARGIN_PERCENT);
        let default_cwnd_gain = params.default_cwnd_gain;
        let probe_bw_up_cwnd_gain = params.probe_bw_up_cwnd_gain;
        let probe_rtt_cwnd_gain = params.probe_rtt_cwnd_gain;
        // the calculation for initial pacing rate described here <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-5>
        let nominal_bandwidth = if params.startup_bw_hint_bytes_per_second > 0 {
            params.startup_bw_hint_bytes_per_second as f64
        } else {
            initial_cwnd as f64 / 0.001
        };
        let mut pacing_rate = startup_pacing_gain * nominal_bandwidth;
        if params.pacing_rate_cap_bytes_per_second > 0 {
            pacing_rate = pacing_rate.min(params.pacing_rate_cap_bytes_per_second as f64);
        }
        Self {
            tunables,
            params,
            params_generation,
            smss,
            initial_cwnd,
            delivered: 0,
            inflight: 0,
            is_cwnd_limited: false,
            cycle_count: 0,
            cwnd: initial_cwnd,
            pacing_rate,
            send_quantum: 2 * smss, // we start high, but it will be adjusted in set_send_quantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.3>
            pacing_gain: startup_pacing_gain,
            startup_pacing_gain,
            default_pacing_gain,
            probe_bw_down_pacing_gain,
            probe_bw_up_pacing_gain,
            drain_pacing_gain,
            pacing_margin_percent,
            cwnd_gain: default_cwnd_gain,
            default_cwnd_gain,
            probe_rng,
            probe_bw_up_cwnd_gain,
            state: BbrState::Startup,
            undo_state: BbrState::Startup,
            round_count: 0,
            round_start: true,
            next_round_delivered: 0,
            idle_restart: false,
            min_pipe_cwnd: 4 * smss, // 4 * C.SMSS as defined in <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-2.7-4>
            max_bw: 0.0,
            bw_shortterm: f64::INFINITY,
            undo_bw_shortterm: f64::INFINITY,
            bw: 0.0,
            min_rtt: Duration::from_secs(u64::MAX),
            bdp: 0,
            extra_acked: 0,
            offload_budget: 0,
            max_inflight: 0,
            inflight_longterm: u64::MAX,
            undo_inflight_longterm: u64::MAX,
            inflight_shortterm: u64::MAX,
            undo_inflight_shortterm: u64::MAX,
            bw_latest: 0.0,
            inflight_latest: 0,
            max_bw_filter: MaxFilter::new(MAX_BW_FILTER_LEN as u64),
            extra_acked_interval_start: None,
            extra_acked_delivered: 0,
            extra_acked_filter: MaxFilter::new(EXTRA_ACKED_FILTER_LEN as u64),
            full_bw_reached: false,
            full_bw_now: false,
            full_bw: 0.0,
            full_bw_count: 0,
            capacity_probe_grace_rounds_remaining: 0,
            min_rtt_stamp: None,
            probe_rtt_cwnd_gain,
            probe_rtt_duration: params.probe_rtt_duration,
            probe_rtt_interval: params.probe_rtt_interval,
            probe_rtt_min_delay: Duration::ZERO,
            probe_rtt_min_stamp: None,
            probe_rtt_expired: false,
            delivered_time: None,
            first_send_time: None,
            app_limited: 0,
            lost: 0,
            srtt: Duration::ZERO,
            rs: None,
            packets: VecDeque::new(),
            rounds_since_bw_probe: 0,
            bw_probe_wait: Duration::ZERO,
            bw_probe_up_rounds: 0,
            bw_probe_up_acks: 0,
            probe_up_cnt: 0,
            cycle_stamp: None,
            ack_phase: AckPhase::ProbeStarting,
            bw_probe_samples: false,
            loss_round_delivered: 0,
            loss_in_round: false,
            explicit_congestion_in_round: false,
            erasure_round_acked_bytes: 0,
            erasure_round_lost_bytes: 0,
            erasure_acked_weight: 0.0,
            erasure_lost_weight: 0.0,
            erasure_measured_arrival: 1.0,
            erasure_applied_arrival: 1.0,
            erasure_compensation_round: 0,
            erasure_delivered_at_compensation: 0.0,
            erasure_compensation_transitions: 0,
            erasure_compensation_changed: false,
            erasure_explicit_congestion_in_round: false,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            prior_cwnd: 0,
            loss_round_start: false,
            drain_start_round: 0,
            // Conservative defaults that match RFC 9000 §13.2.2 behavior (ACK every other
            // ack-eliciting packet) and the default QUIC `max_ack_delay` of 25ms. Overridden
            // when the connection supplies peer ACK-frequency parameters.
            ack_eliciting_threshold: 1,
            max_ack_delay: Duration::from_millis(25),
            pacing_bypass_below_rtt: config.pacing_bypass_below_rtt,
            low_rtt_cwnd_floor: config.low_rtt_cwnd_floor,
            queue_delay_guard_transitions: 0,
            probe_rtt_entries: 0,
            policer_window_started: None,
            policer_window_acked_bytes: 0,
            policer_window_lost_bytes: 0,
            policer_pacing_scale: 1.0,
            policer_pacing_transitions: 0,
            policer_pacing_candidate_armed: false,
            policer_pacing_candidate_warmup_windows_remaining: 0,
            policer_pacing_candidate_confirmation_windows_remaining: 0,
            policer_pacing_candidate_saw_low_latency_window: false,
            policer_pacing_consecutive_loss_windows: 0,
            policer_pacing_trial_rejected: false,
            policer_pacing_ceiling_bytes_per_second: 0.0,
            pacing_bypass_armed: false,
            capacity_probe_quantum_guard_armed: false,
            external_cap_drain_rounds_remaining: 0,
            shallow_loss_declaration_stamp: None,
            shallow_loss_declaration_bytes: 0,
            shallow_loss_quantum_guard: false,
        }
    }

    /// Refresh the controller-local parameter snapshot. This is called only
    /// after `update_round` has identified a packet-timed round boundary.
    fn refresh_params(&mut self) {
        // Pair with the writer's Release publication so every preceding
        // relaxed tunable write, including capacity_probe_generation, is
        // visible before this snapshot is accepted.
        let generation = self.tunables.generation.load(Ordering::Acquire);
        if generation == self.params_generation {
            return;
        }
        let (mut params, mut clamped) = Bbr3Params::from_tunables(&self.tunables);
        let min_cwnd = 4 * self.smss;
        if params.cwnd_cap_bytes > 0 && params.cwnd_cap_bytes < min_cwnd {
            params.cwnd_cap_bytes = min_cwnd;
            clamped += 1;
        }
        if params.cwnd_cap_bytes > 0 && params.cwnd_floor_bytes > params.cwnd_cap_bytes {
            params.cwnd_floor_bytes = params.cwnd_cap_bytes;
            clamped += 1;
        }
        let capacity_probe_requested =
            params.capacity_probe_generation != self.params.capacity_probe_generation;
        let external_cap_published = self.params.pacing_rate_cap_bytes_per_second == 0
            && params.pacing_rate_cap_bytes_per_second > 0;
        let external_cap_removed = self.params.pacing_rate_cap_bytes_per_second > 0
            && params.pacing_rate_cap_bytes_per_second == 0;
        let arm_capacity_probe_quantum_guard = capacity_probe_requested
            && params.pacing_rate_cap_bytes_per_second == 0
            && self.capacity_probe_quantum_guard_candidate();
        self.tunables
            .clamped_writes
            .fetch_add(clamped, Ordering::Relaxed);
        self.params = params;
        self.params_generation = generation;
        if external_cap_published {
            self.external_cap_drain_rounds_remaining = EXTERNAL_CAP_DRAIN_ROUNDS;
        } else if external_cap_removed {
            self.external_cap_drain_rounds_remaining = 0;
        }
        if params.pacing_rate_cap_bytes_per_second > 0 {
            // Host policy now owns shallow-policer pacing. Avoid retaining a
            // stale controller-local guard after that cap is later removed.
            self.reset_policer_pacing_episode();
            self.policer_pacing_trial_rejected = false;
            self.clear_shallow_loss_quantum_guard();
            self.capacity_probe_quantum_guard_armed = false;
        }

        self.default_pacing_gain = params.cruise_pacing_gain;
        self.probe_bw_down_pacing_gain = params.probe_bw_down_pacing_gain;
        self.probe_bw_up_pacing_gain = params.probe_bw_up_pacing_gain;
        self.default_cwnd_gain = params.default_cwnd_gain;
        self.probe_bw_up_cwnd_gain = params.probe_bw_up_cwnd_gain;
        self.probe_rtt_cwnd_gain = params.probe_rtt_cwnd_gain;
        self.probe_rtt_duration = params.probe_rtt_duration;
        self.probe_rtt_interval = params.probe_rtt_interval;

        match self.state {
            BbrState::Startup => {
                self.pacing_gain = self.startup_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::Drain => {
                self.pacing_gain = self.drain_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::ProbeBw(ProbeBwSubstate::Down) => {
                self.pacing_gain = self.probe_bw_down_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise | ProbeBwSubstate::Refill) => {
                self.pacing_gain = self.default_pacing_gain;
                self.cwnd_gain = self.default_cwnd_gain;
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) => {
                self.pacing_gain = self.probe_bw_up_pacing_gain;
                self.cwnd_gain = self.probe_bw_up_cwnd_gain;
            }
            BbrState::ProbeRtt => {
                self.pacing_gain = self.default_pacing_gain;
                self.cwnd_gain = self.probe_rtt_cwnd_gain;
            }
        }
        if capacity_probe_requested {
            // Transport-level idle restart can be observed during short
            // sender gaps inside one application Bulk epoch. A new host
            // capacity-probe generation is the explicit semantic boundary
            // that retires both confirmed/candidate policer state and the
            // protective loss-burst guard before fresh discovery.
            self.reset_policer_pacing_episode();
            self.clear_shallow_loss_quantum_guard();
            self.restart_capacity_discovery();
            self.capacity_probe_grace_rounds_remaining = CAPACITY_PROBE_GRACE_ROUNDS;
            self.capacity_probe_quantum_guard_armed = arm_capacity_probe_quantum_guard;
            if self.capacity_probe_quantum_guard_armed {
                // Classify the probe from a complete outcome window. Reusing
                // a nearly finished pre-probe window could release the latch
                // before the newly paced traffic has been observed.
                self.policer_window_started = None;
                self.policer_window_acked_bytes = 0;
                self.policer_window_lost_bytes = 0;
            }
            // A host-requested capacity probe must be packet paced. Keeping a
            // previously armed low-RTT bypass would make the restart retain
            // the very burst behavior it is intended to re-evaluate.
            self.pacing_bypass_armed = false;
        }
        // Unlike an ordinary BBR model update, an explicit host pacing cap is
        // authoritative in Startup too. `set_pacing_rate_with_gain` normally
        // refuses a downward rate change until full bandwidth is reached, so
        // enforce a newly published cap at this parameter boundary and keep
        // the pacer's aggregate budget coherent with the clamped rate.
        if self.params.pacing_rate_cap_bytes_per_second > 0 {
            self.pacing_rate = self
                .pacing_rate
                .min(self.params.pacing_rate_cap_bytes_per_second as f64);
        }
        self.set_send_quantum();
    }

    /// equivalent to BBREnterStartup <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.1-3>
    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
        self.pacing_gain = self.startup_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRResetFullBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-4>
    fn reset_full_bw(&mut self) {
        self.full_bw = 0.0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// equivalent to BBRNoteLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    fn note_loss(&mut self) {
        if !self.loss_in_round {
            self.loss_round_delivered = self.delivered;
        }
        self.save_state_upon_loss();
        self.loss_in_round = true;
    }

    /// equivalent to BBRSaveStateUponLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.11.1>
    /// Save state in case a loss episode is later declared spurious
    fn save_state_upon_loss(&mut self) {
        self.undo_state = self.state;
        self.undo_bw_shortterm = self.bw_shortterm;
        self.undo_inflight_shortterm = self.inflight_shortterm;
        self.undo_inflight_longterm = self.inflight_longterm;
    }

    /// equivalent to BBRInflightAtLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    /// We check at what prefix of packet did losses exceed `loss_thresh`
    fn inflight_at_loss(&mut self, packet_size: u64) -> u64 {
        if let Some(rate_sample) = self.rs {
            let loss_thresh = self.params.loss_thresh;
            let inflight_prev = rate_sample.tx_in_flight.saturating_sub(packet_size);
            let inflight_prev_threshold = loss_thresh * inflight_prev as f64;
            let lost_prev = rate_sample.lost.saturating_sub(packet_size);
            let compared_loss = (inflight_prev_threshold.round() as u64).saturating_sub(lost_prev);
            let lost_prefix = compared_loss as f64 / (1.0 - loss_thresh);
            let inflight_at_loss = inflight_prev + lost_prefix as u64;
            return inflight_at_loss;
        }
        0
    }

    /// equivalent to BBRSaveCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.4-13>
    fn save_cwnd(&mut self) {
        if !self.loss_in_round && self.state != BbrState::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = max(self.prior_cwnd, self.cwnd);
        }
    }

    /// equivalent to BBRRestoreCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.4-13>
    fn restore_cwnd(&mut self) {
        self.cwnd = max(self.cwnd, self.prior_cwnd);
    }

    /// equivalent to BBRProbeRTTCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.5-1>
    fn probe_rtt_cwnd(&mut self) -> u64 {
        let mut probe_rtt_cwnd = self.bdp_multiple(self.bw, self.probe_rtt_cwnd_gain);
        probe_rtt_cwnd = max(probe_rtt_cwnd, self.min_pipe_cwnd);
        probe_rtt_cwnd
    }

    /// equivalent to BBRBoundCwndForProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.5-1>
    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRtt {
            self.cwnd = min(self.cwnd, self.probe_rtt_cwnd());
        }
    }

    /// equivalent to BBRTargetInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn target_inflight(&self) -> u64 {
        min(self.bdp, self.cwnd)
    }

    /// equivalent to BBRHandleInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    fn handle_inflight_too_high(&mut self, now: Instant) {
        self.bw_probe_samples = false;
        if let Some(rate_sample) = self.rs
            && !rate_sample.is_app_limited
        {
            self.inflight_longterm = max(
                rate_sample.tx_in_flight,
                (self.target_inflight() as f64 * self.params.beta) as u64,
            );
        }

        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            self.start_probe_bw_down(now);
        }
    }

    /// equivalent to IsInflightTooHigh <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-1>
    fn is_inflight_too_high(&self) -> bool {
        // Packet loss alone is ambiguous on radio, Wi-Fi, long-haul and
        // shallow-policer paths. Let the delivery-rate model converge on the
        // usable capacity and let V2 FEC/repair absorb non-congestive loss.
        // Queue growth is handled independently by `check_queue_delay_guard`;
        // using the same transient loss to also cap inflight creates a positive
        // feedback loop where the cap and measured bandwidth shrink together.
        // Only authenticated ECN is authoritative enough to install a lasting
        // loss-based inflight cap.
        if !self.explicit_congestion_in_round && !self.params.loss_is_congestion {
            return false;
        }
        if let Some(rate_sample) = self.rs {
            return rate_sample.lost as f64
                > rate_sample.tx_in_flight as f64 * self.params.loss_thresh;
        }
        false
    }

    /// Whether the controller's own RTT estimator proves that the current
    /// upward probe is building a queue rather than discovering propagation
    /// delay. The dual relative/absolute allowance avoids reacting to normal
    /// timestamp noise on either short or long RTT paths.
    fn queue_delay_guard_triggered(&self) -> bool {
        if self.min_rtt == Duration::from_secs(u64::MAX)
            || self.min_rtt.is_zero()
            || self.srtt.is_zero()
            // The first RTT sample precedes the first usable delivery-rate
            // sample. Entering Drain at that point would mark full bandwidth
            // reached with a zero pacing rate and could arm an infinite pacer
            // deadline. Wait until BBR has an actual bandwidth estimate.
            || !self.bw.is_finite()
            || self.bw <= 0.0
        {
            return false;
        }

        // Startup and ProbeBW-Up are intentionally queue-building phases. On
        // a path whose policy says random loss is not congestion, applying
        // the steady-state 0.5*min_rtt guard here repeatedly aborts bandwidth
        // discovery at a fraction of capacity (especially behind a shaped
        // home uplink). Startup retains enough room to discover the pipe, but
        // later ProbeBW-Up cycles use a tighter allowance so they cannot keep
        // recreating a large steady-state queue. Drain/Cruise and
        // loss-as-congestion presets retain the strict latency guard.
        let guard_multiplier = match (self.params.loss_is_congestion, self.state) {
            (false, BbrState::Startup) => 4.0,
            (false, BbrState::ProbeBw(ProbeBwSubstate::Up)) => 2.0,
            _ => 1.0,
        };
        let upward_loss_tolerant_probe = guard_multiplier > 1.0;
        let relative_slack = self
            .min_rtt
            .mul_f64(self.params.queue_delay_guard_inflation * guard_multiplier);
        let absolute_slack = if upward_loss_tolerant_probe {
            max(
                self.params.queue_delay_guard_slack,
                Duration::from_millis(20),
            )
        } else {
            self.params.queue_delay_guard_slack
        };
        let slack = max(relative_slack, absolute_slack);
        self.srtt
            > self
                .min_rtt
                .checked_add(slack)
                .unwrap_or(Duration::from_secs(u64::MAX))
    }

    /// Bound queue growth without disabling BBR's later bandwidth discovery.
    /// Startup moves to Drain immediately; a ProbeBW upward phase moves to
    /// Down. Subsequent ProbeBW cycles can still test for newly available
    /// bandwidth after the queue has drained.
    fn check_queue_delay_guard(&mut self, now: Instant) {
        if !self.queue_delay_guard_triggered() {
            return;
        }

        match self.state {
            BbrState::Startup => {
                self.full_bw_now = true;
                self.full_bw_reached = true;
                self.queue_delay_guard_transitions += 1;
                self.enter_drain();
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) => {
                self.queue_delay_guard_transitions += 1;
                self.start_probe_bw_down(now);
            }
            _ => {}
        }
    }

    fn erasure_compensation_allowed(&self, explicit_congestion: bool) -> bool {
        !self.params.loss_is_congestion
            && !explicit_congestion
            && self.state != BbrState::ProbeRtt
            && self.params.pacing_rate_cap_bytes_per_second == 0
            && self.policer_learned_wire_rate_ceiling().is_none()
            // Compensation must not run ahead of the independent delay brake.
            // Until both RTT estimates exist that brake has no signal.
            && !self.min_rtt.is_zero()
            && self.min_rtt != Duration::from_secs(u64::MAX)
            && !self.srtt.is_zero()
    }

    fn erasure_control_arrival_rate(&self) -> f64 {
        if self.erasure_compensation_allowed(self.erasure_explicit_congestion_in_round) {
            self.erasure_applied_arrival
                .clamp(ERASURE_MIN_ARRIVAL_RATE, 1.0)
        } else {
            1.0
        }
    }

    fn erasure_delay_brake(&self) -> f64 {
        let arrival_rate = self.erasure_control_arrival_rate();
        // This is a brake on *erasure compensation*, not an independent
        // startup RTT controller.  On the first ACK the transport's SRTT may
        // still carry its initial value while min_rtt already contains a
        // sub-millisecond sample. Applying min_rtt / queue_delay at that point
        // can round the exported pacing rate to zero and make the pacer return
        // Duration::MAX. Wait until compensation has actually increased the
        // gross wire budget before braking it.
        if arrival_rate >= 1.0 - f64::EPSILON
            || self.params.loss_is_congestion
            || self.min_rtt.is_zero()
            || self.min_rtt == Duration::from_secs(u64::MAX)
            || self.srtt <= self.min_rtt
        {
            return 1.0;
        }

        // Permit at most one propagation RTT of queue. Past that point the
        // response is continuous: min_rtt / queue_delay. Apply this after
        // erasure compensation because the queue holds wire bytes, not only the
        // fraction that eventually arrives.
        let queue_delay = self.srtt.saturating_sub(self.min_rtt);
        if queue_delay <= self.min_rtt {
            1.0
        } else {
            // Withdraw the extra 1/arrival wire budget as the queue grows,
            // but leave ordinary BBR pacing to BBR's own queue guard. RTT
            // jitter must not turn a tiny erasure correction into a large
            // reduction below the delivery model's baseline rate.
            (self.min_rtt.as_secs_f64() / queue_delay.as_secs_f64())
                .clamp(0.0, 1.0)
                .max(arrival_rate)
        }
    }

    fn set_erasure_applied_arrival(&mut self, arrival: f64) {
        let arrival = arrival.clamp(ERASURE_MIN_ARRIVAL_RATE, 1.0);
        if (arrival - self.erasure_applied_arrival).abs() <= f64::EPSILON {
            return;
        }
        self.erasure_applied_arrival = arrival;
        self.erasure_compensation_transitions =
            self.erasure_compensation_transitions.saturating_add(1);
        self.erasure_compensation_changed = true;
    }

    fn reset_erasure_path_model(&mut self) {
        self.erasure_round_acked_bytes = 0;
        self.erasure_round_lost_bytes = 0;
        self.erasure_acked_weight = 0.0;
        self.erasure_lost_weight = 0.0;
        self.erasure_measured_arrival = 1.0;
        self.erasure_applied_arrival = 1.0;
        self.erasure_compensation_round = 0;
        self.erasure_delivered_at_compensation = 0.0;
        self.erasure_compensation_transitions = 0;
        self.erasure_compensation_changed = false;
        self.erasure_explicit_congestion_in_round = false;
    }

    /// Move the wire-rate correction towards the measured arrival rate one
    /// packet-timed round at a time. Every increase in compensation is a small,
    /// falsifiable probe: the next increase is refused unless delivery rose.
    fn update_erasure_compensation(&mut self) {
        let acked = std::mem::take(&mut self.erasure_round_acked_bytes);
        let lost = std::mem::take(&mut self.erasure_round_lost_bytes);
        let explicit_congestion = std::mem::take(&mut self.erasure_explicit_congestion_in_round);
        let sample_bytes = acked.saturating_add(lost);
        let minimum_sample_bytes = self.smss.saturating_mul(ERASURE_MIN_SAMPLE_PACKETS);

        let delivered = self
            .rs
            .filter(|sample| sample.delivery_rate.is_finite() && sample.delivery_rate > 0.0)
            .map_or_else(|| self.bw.max(0.0), |sample| sample.delivery_rate);

        if !self.erasure_compensation_allowed(explicit_congestion) {
            self.set_erasure_applied_arrival(1.0);
            return;
        }

        if sample_bytes < minimum_sample_bytes {
            self.erasure_round_acked_bytes = self.erasure_round_acked_bytes.saturating_add(acked);
            self.erasure_round_lost_bytes = self.erasure_round_lost_bytes.saturating_add(lost);
            return;
        }

        self.erasure_acked_weight =
            self.erasure_acked_weight * ERASURE_OUTCOME_DECAY + acked as f64;
        self.erasure_lost_weight = self.erasure_lost_weight * ERASURE_OUTCOME_DECAY + lost as f64;
        let outcome_weight = self.erasure_acked_weight + self.erasure_lost_weight;
        if !outcome_weight.is_finite() || outcome_weight <= 0.0 {
            return;
        }
        self.erasure_measured_arrival =
            (self.erasure_acked_weight / outcome_weight).clamp(ERASURE_MIN_ARRIVAL_RATE, 1.0);
        // Share the policer model's clean-window threshold. Compensating
        // sub-0.5% background loss adds negligible goodput, but it disables
        // the proven low-RTT pacing bypass and can cost far more throughput
        // than it recovers on fast LAN/Wi-Fi paths.
        let wanted = if 1.0 - self.erasure_measured_arrival <= POLICER_CLEAN_THRESHOLD {
            1.0
        } else {
            self.erasure_measured_arrival
        };

        if wanted >= self.erasure_applied_arrival {
            // Less compensation can only reduce pressure, so take it at once.
            self.set_erasure_applied_arrival(wanted);
            self.erasure_delivered_at_compensation = delivered;
            self.erasure_compensation_round = self.round_count;
            return;
        }

        if self.round_count == self.erasure_compensation_round {
            return;
        }
        if delivered <= self.erasure_delivered_at_compensation {
            // The last step bought no delivery. Hold and re-arm at the current
            // operating point so a later path improvement can still be followed.
            self.erasure_delivered_at_compensation = delivered;
            self.erasure_compensation_round = self.round_count;
            return;
        }

        let next = (self.erasure_applied_arrival * ERASURE_COMPENSATION_STEP).max(wanted);
        self.set_erasure_applied_arrival(next);
        self.erasure_delivered_at_compensation = delivered;
        self.erasure_compensation_round = self.round_count;
    }

    fn record_shallow_loss_declaration(&mut self, now: Instant, lost_bytes: u64) {
        // A same-timestamp loss burst is a protection signal, not policer
        // classification evidence by itself. Even an inflated or long-RTT
        // path must stop bypassing the pacer before another oversized burst.
        let trial_eligible = self.policer_trial_model_is_trustworthy();
        let high_rate_trial_rejected = self.policer_trial_model_is_too_fast();
        let burst_threshold = self.smss.saturating_mul(SHALLOW_LOSS_BURST_PACKETS);
        let previous_burst_bytes = if self.shallow_loss_declaration_stamp == Some(now) {
            self.shallow_loss_declaration_bytes
        } else {
            0
        };
        if self.shallow_loss_declaration_stamp == Some(now) {
            self.shallow_loss_declaration_bytes = self
                .shallow_loss_declaration_bytes
                .saturating_add(lost_bytes);
        } else {
            self.shallow_loss_declaration_stamp = Some(now);
            self.shallow_loss_declaration_bytes = lost_bytes;
        }

        if !self.shallow_loss_quantum_guard
            && previous_burst_bytes < burst_threshold
            && self.shallow_loss_declaration_bytes >= burst_threshold
        {
            // `on_packet_lost` records each packet in the outcome counters
            // after calling this function. Thus these counters include the
            // first fifteen declared losses but not the threshold-crossing
            // packet. Snapshot them before resetting the post-burst window.
            // A burst may accelerate an already trustworthy aggregate, but
            // its packet count alone never classifies a policer.
            let aggregate_total = self
                .policer_window_acked_bytes
                .saturating_add(self.policer_window_lost_bytes);
            let aggregate_is_lossy = aggregate_total >= POLICER_MIN_SAMPLE_BYTES
                && self.policer_window_lost_bytes as f64 / aggregate_total as f64
                    >= POLICER_LOSS_THRESHOLD;
            let aggregate_elapsed = self
                .policer_window_started
                .map_or(Duration::ZERO, |started| {
                    now.saturating_duration_since(started)
                });
            let aggregate_ceiling =
                self.policer_trial_ceiling(self.policer_window_acked_bytes, aggregate_elapsed);
            self.pacing_bypass_armed = false;
            if aggregate_is_lossy
                && aggregate_ceiling.is_some()
                && high_rate_trial_rejected
                && self.policer_pacing_transitions == 0
            {
                // A short, high-rate Wi-Fi path is not a shallow policer.
                // Latch the rejection before a later degraded model falls
                // below the admission boundary and becomes ambiguous.
                self.policer_pacing_trial_rejected = true;
            }
            if trial_eligible
                && aggregate_is_lossy
                && self.policer_pacing_transitions == 0
                && !self.policer_pacing_trial_rejected
                && let Some(ceiling) = aggregate_ceiling
            {
                // The complete pre-reset aggregate plus a trusted short
                // minimum RTT warrants one bounded safety trial, not
                // confirmation. An incomplete burst leaves the running
                // outcome intact so the normal 500 ms path can classify it.
                self.policer_window_started = Some(now);
                self.policer_window_acked_bytes = 0;
                self.policer_window_lost_bytes = 0;
                self.policer_pacing_candidate_armed = true;
                self.policer_pacing_candidate_warmup_windows_remaining = 1;
                self.policer_pacing_candidate_confirmation_windows_remaining =
                    POLICER_TRIAL_CONFIRMATION_WINDOWS;
                self.policer_pacing_candidate_saw_low_latency_window = false;
                self.policer_pacing_ceiling_bytes_per_second = ceiling;
                self.shallow_loss_quantum_guard = true;
                self.clamp_pacing_rate_to_policer_wire_rate();
            }
        }
    }

    fn policer_trial_ceiling(&self, acked: u64, sample_elapsed: Duration) -> Option<f64> {
        if sample_elapsed < POLICER_SAMPLE_WINDOW
            || acked == 0
            || self.max_bw <= 0.0
            || !self.max_bw.is_finite()
        {
            return None;
        }
        let trial_ceiling = self.max_bw * POLICER_TRIAL_MAX_BW_SCALE;
        if trial_ceiling <= 0.0 || !trial_ceiling.is_finite() {
            return None;
        }
        Some(trial_ceiling)
    }

    fn short_policer_min_rtt_is_trustworthy(&self) -> bool {
        self.min_rtt != Duration::from_secs(u64::MAX)
            && !self.min_rtt.is_zero()
            && self.min_rtt <= POLICER_RTT_CEILING
    }

    fn policer_trial_model_is_trustworthy(&self) -> bool {
        self.short_policer_min_rtt_is_trustworthy()
            && self.min_rtt <= POLICER_FALLBACK_MIN_RTT_CEILING
            && self.max_bw > 0.0
            && self.max_bw.is_finite()
            && self.max_bw < CAPACITY_PROBE_QUANTUM_MAX_BW
    }

    fn policer_trial_model_is_too_fast(&self) -> bool {
        self.short_policer_min_rtt_is_trustworthy()
            && self.min_rtt <= POLICER_FALLBACK_MIN_RTT_CEILING
            && self.max_bw.is_finite()
            && self.max_bw >= CAPACITY_PROBE_QUANTUM_MAX_BW
    }

    fn shallow_queue_rtt_is_trustworthy(&self) -> bool {
        let shallow_queue_rtt_ceiling = self
            .min_rtt
            .saturating_add((self.min_rtt / 2).max(Duration::from_millis(5)));
        self.short_policer_min_rtt_is_trustworthy() && self.srtt <= shallow_queue_rtt_ceiling
    }

    fn bounded_horizon_policer_fallback_is_trustworthy(&self) -> bool {
        let queue_allowance = (self.min_rtt / 2).max(Duration::from_millis(5));
        self.min_rtt <= POLICER_FALLBACK_MIN_RTT_CEILING
            && self.srtt
                <= self
                    .min_rtt
                    .saturating_add(queue_allowance.saturating_mul(3))
    }

    fn clamp_pacing_rate_to_policer_wire_rate(&mut self) {
        if let Some(wire_rate) = self.policer_learned_wire_rate_ceiling() {
            self.pacing_rate = self.pacing_rate.min(wire_rate);
        }
    }

    fn apply_fixed_policer_pacing_ceiling(&mut self) {
        if self.policer_pacing_transitions > 0 && self.state != BbrState::ProbeRtt {
            self.pacing_rate = self.policer_pacing_ceiling_bytes_per_second;
        }
        self.clamp_pacing_rate_to_policer_wire_rate();
        self.set_send_quantum();
    }

    fn policer_learned_wire_rate_ceiling(&self) -> Option<f64> {
        if self.policer_pacing_transitions == 0 && !self.policer_pacing_candidate_armed {
            return None;
        }
        let mut wire_rate = self.policer_pacing_ceiling_bytes_per_second;
        if wire_rate <= 0.0 || !wire_rate.is_finite() {
            return None;
        }
        if self.params.pacing_rate_cap_bytes_per_second > 0 {
            wire_rate = wire_rate.min(self.params.pacing_rate_cap_bytes_per_second as f64);
        }
        Some(wire_rate)
    }

    fn reset_policer_pacing_episode(&mut self) {
        self.policer_pacing_scale = 1.0;
        self.policer_pacing_transitions = 0;
        self.policer_pacing_candidate_armed = false;
        self.policer_pacing_candidate_warmup_windows_remaining = 0;
        self.policer_pacing_candidate_confirmation_windows_remaining = 0;
        self.policer_pacing_candidate_saw_low_latency_window = false;
        self.policer_pacing_consecutive_loss_windows = 0;
        self.policer_pacing_ceiling_bytes_per_second = 0.0;
    }

    fn clear_shallow_loss_quantum_guard(&mut self) {
        self.shallow_loss_quantum_guard = false;
        self.shallow_loss_declaration_stamp = None;
        self.shallow_loss_declaration_bytes = 0;
    }

    /// Learn the usable wire rate of a shallow policer from transport-level
    /// outcomes. This caps pacing only; it never installs a lasting cwnd or
    /// max-bandwidth bound, and the existing path/episode reset removes it.
    fn update_policer_pacing(&mut self, now: Instant) {
        if self.params.pacing_rate_cap_bytes_per_second > 0 {
            // The host policy's explicit cap is already the authoritative
            // shallow-policer response. Applying the controller-local loss
            // scale as well makes the two feedback loops multiply and can
            // ratchet the delivery-rate model below the usable wire rate.
            // Discard this window too, so removing the external cap starts a
            // fresh observation interval rather than immediately applying
            // loss accumulated while the cap was active.
            self.policer_window_acked_bytes = 0;
            self.policer_window_lost_bytes = 0;
            self.policer_window_started = Some(now);
            self.reset_policer_pacing_episode();
            self.policer_pacing_trial_rejected = false;
            self.pacing_bypass_armed = false;
            self.capacity_probe_quantum_guard_armed = false;
            self.clear_shallow_loss_quantum_guard();
            return;
        }

        let started = self.policer_window_started.get_or_insert(now);
        let sample_elapsed = now.saturating_duration_since(*started);
        if sample_elapsed < POLICER_SAMPLE_WINDOW {
            return;
        }

        let acked = std::mem::take(&mut self.policer_window_acked_bytes);
        let lost = std::mem::take(&mut self.policer_window_lost_bytes);
        self.policer_window_started = Some(now);

        if self.min_rtt == Duration::from_secs(u64::MAX)
            || self.min_rtt.is_zero()
            || self.min_rtt > POLICER_RTT_CEILING
        {
            self.reset_policer_pacing_episode();
            self.pacing_bypass_armed = false;
            self.clear_shallow_loss_quantum_guard();
            return;
        }

        let total = acked.saturating_add(lost);
        if total < POLICER_MIN_SAMPLE_BYTES {
            return;
        }
        let loss_ratio = lost as f64 / total as f64;
        if self.policer_pacing_transitions == 0 && self.policer_pacing_candidate_armed {
            if self.policer_pacing_candidate_warmup_windows_remaining > 0 {
                // The first full post-burst outcome can still contain losses
                // declared for the pre-cap flight. Drain it without changing
                // the trial ceiling or guard; the next complete window is the
                // first causal confirmation sample.
                self.policer_pacing_candidate_warmup_windows_remaining -= 1;
                self.clamp_pacing_rate_to_policer_wire_rate();
                return;
            }
            // Confirmation is causal rather than merely temporal. A shallow
            // trial becomes fixed only when a full outcome within the bounded
            // horizon remains at shallow RTT and is clean. Delayed loss or a
            // transient queue may consume a window without releasing the
            // protective trial cap.
            self.policer_pacing_candidate_saw_low_latency_window |=
                self.bounded_horizon_policer_fallback_is_trustworthy();
            if self.shallow_queue_rtt_is_trustworthy() && loss_ratio <= POLICER_CLEAN_THRESHOLD {
                let confirmed_ceiling = self.policer_pacing_ceiling_bytes_per_second
                    / POLICER_TRIAL_MAX_BW_SCALE
                    * POLICER_CONFIRMED_MAX_BW_SCALE;
                if confirmed_ceiling <= 0.0 || !confirmed_ceiling.is_finite() {
                    self.reset_policer_pacing_episode();
                    self.policer_pacing_trial_rejected = true;
                    self.capacity_probe_quantum_guard_armed = false;
                    self.clear_shallow_loss_quantum_guard();
                    return;
                }
                self.policer_pacing_candidate_armed = false;
                self.policer_pacing_candidate_warmup_windows_remaining = 0;
                self.policer_pacing_candidate_confirmation_windows_remaining = 0;
                self.policer_pacing_candidate_saw_low_latency_window = false;
                // Promote from the model frozen at trial entry rather than a
                // later live max_bw sample.
                self.policer_pacing_ceiling_bytes_per_second = confirmed_ceiling;
                self.policer_pacing_scale = POLICER_EPISODE_PACING_SCALE;
                self.policer_pacing_transitions = 1;
                self.capacity_probe_quantum_guard_armed = false;
                self.shallow_loss_quantum_guard = true;
                self.pacing_bypass_armed = false;
                self.apply_fixed_policer_pacing_ceiling();
            } else {
                if self.policer_pacing_candidate_confirmation_windows_remaining > 1 {
                    self.policer_pacing_candidate_confirmation_windows_remaining -= 1;
                    self.clamp_pacing_rate_to_policer_wire_rate();
                } else if self.policer_pacing_candidate_saw_low_latency_window {
                    // A very short path can retain a small residual queue for
                    // every bounded confirmation window even after the trial
                    // has removed the shallow-shaper overshoot. At the horizon
                    // only, accept that narrow causal signature. Long-minimum
                    // and deeply queued paths are excluded by the RTT bounds;
                    // high-rate Wi-Fi was excluded before trial admission.
                    // At the bounded horizon, restore a modest amount of the
                    // conservative trial margin without consulting a later
                    // live max_bw sample.
                    let fallback_ceiling =
                        self.policer_pacing_ceiling_bytes_per_second * POLICER_FALLBACK_TRIAL_SCALE;
                    if fallback_ceiling > 0.0 && fallback_ceiling.is_finite() {
                        self.policer_pacing_candidate_armed = false;
                        self.policer_pacing_candidate_warmup_windows_remaining = 0;
                        self.policer_pacing_candidate_confirmation_windows_remaining = 0;
                        self.policer_pacing_candidate_saw_low_latency_window = false;
                        self.policer_pacing_ceiling_bytes_per_second = fallback_ceiling;
                        self.policer_pacing_scale = POLICER_EPISODE_PACING_SCALE;
                        self.policer_pacing_transitions = 1;
                        self.capacity_probe_quantum_guard_armed = false;
                        self.shallow_loss_quantum_guard = true;
                        self.pacing_bypass_armed = false;
                        self.apply_fixed_policer_pacing_ceiling();
                    } else {
                        self.reset_policer_pacing_episode();
                        self.policer_pacing_trial_rejected = true;
                        self.capacity_probe_quantum_guard_armed = false;
                        self.clear_shallow_loss_quantum_guard();
                    }
                } else {
                    // One semantic Bulk episode gets one bounded safety
                    // trial. Later bursts may protect one window, but cannot
                    // repeatedly re-enter a Wi-Fi/interference trial.
                    self.reset_policer_pacing_episode();
                    self.policer_pacing_trial_rejected = true;
                    self.capacity_probe_quantum_guard_armed = false;
                    self.clear_shallow_loss_quantum_guard();
                }
            }
            return;
        }
        if self.policer_pacing_transitions > 0 {
            if loss_ratio >= POLICER_LOSS_THRESHOLD {
                self.policer_pacing_consecutive_loss_windows = self
                    .policer_pacing_consecutive_loss_windows
                    .saturating_add(1);
                if self.policer_pacing_consecutive_loss_windows
                    >= POLICER_CONFIRMED_LOSS_REVOKE_WINDOWS
                {
                    // Persistent loss disproves a shallow policer. Retire the
                    // fixed ceiling and guard for this semantic Bulk episode.
                    self.reset_policer_pacing_episode();
                    self.policer_pacing_trial_rejected = true;
                    self.capacity_probe_quantum_guard_armed = false;
                    self.clear_shallow_loss_quantum_guard();
                    return;
                }
            } else {
                self.policer_pacing_consecutive_loss_windows = 0;
            }
            self.apply_fixed_policer_pacing_ceiling();
            return;
        }
        if loss_ratio >= POLICER_LOSS_THRESHOLD {
            // Only a short path whose frozen BBR model is below the known
            // high-rate Wi-Fi regime may enter a bounded safety trial.
            if !self.policer_trial_model_is_trustworthy() {
                if self.policer_pacing_transitions == 0 && self.policer_trial_model_is_too_fast() {
                    self.policer_pacing_trial_rejected = true;
                    self.pacing_bypass_armed = false;
                }
                self.clear_shallow_loss_quantum_guard();
                return;
            }
            self.capacity_probe_quantum_guard_armed = false;
            self.shallow_loss_quantum_guard = true;
            self.pacing_bypass_armed = false;
            if self.policer_pacing_transitions == 0 {
                if self.policer_pacing_trial_rejected {
                    self.clear_shallow_loss_quantum_guard();
                    return;
                }
                // A complete trustworthy lossy window starts one bounded
                // trial from the conservative frozen max_bw estimate. The
                // strict quantum remains armed throughout its confirmation
                // horizon.
                let Some(ceiling) = self.policer_trial_ceiling(acked, sample_elapsed) else {
                    self.clear_shallow_loss_quantum_guard();
                    return;
                };
                self.policer_pacing_candidate_armed = true;
                // Discard the first post-cap outcome so delayed loss from the
                // uncapped flight cannot contaminate confirmation.
                self.policer_pacing_candidate_warmup_windows_remaining = 1;
                self.policer_pacing_candidate_confirmation_windows_remaining =
                    POLICER_TRIAL_CONFIRMATION_WINDOWS;
                self.policer_pacing_candidate_saw_low_latency_window = false;
                self.policer_pacing_ceiling_bytes_per_second = ceiling;
            }
            // Clamp immediately for the trial; a clean complete outcome
            // within the bounded horizon promotes the same frozen model.
            self.clamp_pacing_rate_to_policer_wire_rate();
        } else if loss_ratio <= POLICER_CLEAN_THRESHOLD {
            self.capacity_probe_quantum_guard_armed = false;
            if self.policer_pacing_transitions == 0
                && !self.shallow_loss_quantum_guard
                && self.policer_pacing_scale >= 1.0
                && self
                    .pacing_bypass_below_rtt
                    .is_some_and(|threshold| self.min_rtt < threshold)
            {
                // Do not bypass the timer from a single optimistic RTT
                // sample. One clean half-second window distinguishes a LAN or
                // Wi-Fi path from a shallow policer before allowing bursts.
                self.pacing_bypass_armed = true;
            }
            // An active episode retains its fixed wire ceiling. Clean
            // windows neither ratchet it down nor recover it upward; only an
            // episode/path reset returns to unscaled discovery.
        }
        if self.policer_pacing_transitions == 0 && !self.policer_pacing_candidate_armed {
            // A burst without enough prior short-path evidence is protection
            // for one complete outcome only. Do not leave Wi-Fi/interference
            // traffic permanently constrained by the shallow quantum.
            self.clear_shallow_loss_quantum_guard();
        }
    }

    fn pacing_bypass_active(&self) -> bool {
        self.state != BbrState::ProbeRtt
            && self.pacing_bypass_armed
            && self.policer_pacing_scale >= 1.0
            // An erasure-compensated or delay-braked path needs the pacer: the
            // gross wire rate, rather than cwnd alone, is the control variable.
            && self.erasure_control_arrival_rate() >= 1.0 - f64::EPSILON
            && self.erasure_delay_brake() >= 1.0 - f64::EPSILON
            && self
                .pacing_bypass_below_rtt
                .is_some_and(|threshold| self.min_rtt < threshold)
    }

    /// equivalent to BBRCheckStartupHighLoss <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.3>
    fn check_startup_high_loss(&mut self) {
        if self.full_bw_reached {
            return;
        }

        if self.is_inflight_too_high() {
            let mut new_inflight_hi = self.bdp.max(self.inflight_latest);
            if let Some(rate_sample) = self.rs
                && new_inflight_hi < rate_sample.delivered
            {
                new_inflight_hi = rate_sample.delivered;
            }
            self.inflight_longterm = new_inflight_hi;
            self.full_bw_reached = true;
        }
    }

    /// equivalent to BBREnterProbeBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6>
    fn enter_probe_bw(&mut self, now: Instant) {
        self.cwnd_gain = self.default_cwnd_gain;
        self.start_probe_bw_down(now);
    }

    /// equivalent to BBRPickProbeWait <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn pick_probe_wait(&mut self) {
        // 0 or 1
        self.rounds_since_bw_probe = self.probe_rng.random_bool(0.5) as u64;
        let max_added_millis = self.params.max_added_probe_wait.as_millis() as u64;
        self.bw_probe_wait = self.params.min_probe_wait
            + Duration::from_millis(self.probe_rng.random_range(0..=max_added_millis));
    }

    /// equivalent to BBRHasElapsedInPhase <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn has_elapsed_in_phase(&mut self, interval: Duration, now: Instant) -> bool {
        if let Some(cycle_stamp) = self.cycle_stamp {
            now > cycle_stamp.checked_add(interval).unwrap_or(cycle_stamp)
        } else {
            true
        }
    }

    /// equivalent to BBRExitProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.4>
    fn exit_probe_rtt(&mut self, now: Instant) {
        self.reset_short_term_model();
        if self.full_bw_reached {
            self.start_probe_bw_down(now);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    /// equivalent to BBRCheckProbeRTTDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn check_probe_rtt_done(&mut self, now: Instant) {
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp
            && now > probe_rtt_done_stamp
        {
            self.probe_rtt_min_stamp = Some(now);
            self.restore_cwnd();
            self.exit_probe_rtt(now);
        }
    }

    /// equivalent to BBRIsTimeToProbeBW <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn maybe_enter_probe_bw_refill(&mut self, now: Instant) -> bool {
        if self.has_elapsed_in_phase(self.bw_probe_wait, now)
            || self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill();
            return true;
        }
        false
    }

    /// equivalent to BBRIsTimeToGoDown <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-6>
    fn maybe_go_down(&mut self) -> bool {
        if self.is_cwnd_limited && self.cwnd >= self.inflight_longterm {
            self.reset_full_bw();
            if let Some(rate_sample) = self.rs {
                self.full_bw = rate_sample.delivery_rate;
            }
        } else if self.full_bw_now {
            return true;
        }
        false
    }

    /// equivalent to BBRIsRenoCoexistenceProbeTime <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.5.3-6>
    fn is_reno_coexistence_probe_time(&self) -> bool {
        let reno_rounds = self.target_inflight();
        let rounds = min(reno_rounds, MAX_RENO_ROUNDS);
        self.rounds_since_bw_probe >= rounds
    }

    /// equivalent to BBRBDPMultiple <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn bdp_multiple(&mut self, bw: f64, gain: f64) -> u64 {
        if self.min_rtt == Duration::from_secs(u64::MAX) {
            return self.initial_cwnd;
        }
        self.bdp = (bw * self.min_rtt.as_secs_f64()).round() as u64;
        (gain * self.bdp as f64) as u64
    }

    /// equivalent to BBRUpdateOffloadBudget for QUIC per
    /// <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.8.2>.
    ///
    /// The delayed-ACK term accounts for the QUIC ACK frequency extension:
    /// `min(Ack-Eliciting Threshold, Requested Max Ack Delay * BBR.max_bw)`.
    fn update_offload_budget(&mut self) {
        let base = self.send_quantum;

        // Ack-Eliciting Threshold is a packet count in the ACK_FREQUENCY frame; convert to
        // bytes using the current SMSS. A threshold of 0 requires an immediate ACK per packet,
        // so the delayed-ACK term contributes nothing in that case.
        let threshold_bytes = self.ack_eliciting_threshold.saturating_mul(self.smss);
        let delay_bytes = (self.max_ack_delay.as_secs_f64() * self.max_bw).round() as u64;
        let delayed_ack_term = min(threshold_bytes, delay_bytes);

        self.offload_budget = base.saturating_add(delayed_ack_term);
    }

    /// equivalent to BBRQuantizationBudget <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn quantization_budget(&mut self, inflight_cap: u64) -> u64 {
        self.update_offload_budget();
        let mut inflight_cap = max(inflight_cap, self.offload_budget);
        inflight_cap = max(inflight_cap, self.min_pipe_cwnd);
        if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
            inflight_cap += 2 * self.smss;
        }
        inflight_cap
    }

    /// equivalent to BBRInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn get_inflight(&mut self, gain: f64) -> u64 {
        let inflight_cap = self.bdp_multiple(self.max_bw, gain);
        self.quantization_budget(inflight_cap)
    }

    /// equivalent to BBRUpdateMaxInflight <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.2-2>
    fn update_max_inflight(&mut self) {
        let mut inflight_cap = self.bdp_multiple(self.max_bw, self.cwnd_gain);
        inflight_cap += self.extra_acked;
        self.max_inflight = self.quantization_budget(inflight_cap);
    }

    /// equivalent to BBRResetCongestionSignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.explicit_congestion_in_round = false;
        self.bw_latest = 0.0;
        self.inflight_latest = 0;
    }

    /// equivalent to BBRStartRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1-9>
    fn start_round(&mut self) {
        self.next_round_delivered = self.delivered;
        self.is_cwnd_limited = false;
    }

    /// equivalent to BBRUpdateRound <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.1-9>
    fn update_round(&mut self, packet: BbrPacket) {
        if packet.delivered >= self.next_round_delivered {
            self.start_round();
            self.round_count += 1;
            self.rounds_since_bw_probe += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    /// equivalent to BBRStartProbeBW_DOWN <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-4>
    fn start_probe_bw_down(&mut self, now: Instant) {
        self.reset_congestion_signals();
        self.probe_up_cnt = u64::MAX;
        self.pick_probe_wait();
        self.cycle_stamp = Some(now);
        self.ack_phase = AckPhase::ProbeStopping;
        self.start_round();
        self.pacing_gain = self.probe_bw_down_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Down);
    }

    /// equivalent to BBRInflightWithHeadroom <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == u64::MAX {
            return u64::MAX;
        }
        let total_headroom = max(
            self.smss,
            (self.params.headroom * self.inflight_longterm as f64) as u64,
        );
        if let Some(inflight_with_headroom) = self.inflight_longterm.checked_sub(total_headroom) {
            max(inflight_with_headroom, self.min_pipe_cwnd)
        } else {
            self.min_pipe_cwnd
        }
    }

    /// equivalent to BBRSetPacingRateWithGain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-7>
    fn set_pacing_rate_with_gain(&mut self, gain: f64) {
        let learned_policer_ceiling = self.policer_learned_wire_rate_ceiling();
        // The episode scale is represented by the absolute learned ceiling.
        // Applying it to the live bandwidth model too would compound loss-
        // driven max_bw reductions and ratchet pacing below that ceiling.
        let model_scale = if learned_policer_ceiling.is_some() {
            1.0
        } else {
            self.policer_pacing_scale
        };
        let arrival_rate = self.erasure_control_arrival_rate();
        let erasure_scale = 1.0 / arrival_rate;
        let mut rate = gain * self.bw * (100.0 - self.pacing_margin_percent) / 100.0
            * model_scale
            * erasure_scale;
        // A runtime cwnd floor represents host-authoritative evidence that
        // the delivery-rate model is trapped below a queued flow's usable
        // BDP.  Raising only cwnd cannot escape that trap because the pacer
        // continues feeding the old low bandwidth estimate.  Keep the two
        // controls coherent by pacing at least one gain-adjusted floor BDP
        // per minimum RTT; the explicit pacing cap remains authoritative.
        if self.params.cwnd_floor_bytes > 0
            && !self.min_rtt.is_zero()
            && self.min_rtt != Duration::from_secs(u64::MAX)
        {
            let floor_rate = self.params.cwnd_floor_bytes as f64
                / self.cwnd_gain.max(1.0)
                / self.min_rtt.as_secs_f64()
                * model_scale
                * erasure_scale;
            rate = rate.max(floor_rate);
        }
        if self.params.pacing_rate_cap_bytes_per_second > 0 {
            rate = rate.min(self.params.pacing_rate_cap_bytes_per_second as f64);
        }
        if let Some(ceiling) = learned_policer_ceiling {
            // The bounded pacer now owns this shallow-policer episode. A
            // loss-depressed short-term bandwidth model must not underfeed
            // the known sustainable rate in ProbeBW Down/Cruise. ProbeRTT
            // retains its intentional drain behavior. `ceiling` already
            // incorporates any lower explicit host cap.
            rate = if self.state == BbrState::ProbeRtt {
                rate.min(ceiling)
            } else {
                ceiling
            };
        }
        let delay_brake = self.erasure_delay_brake();
        rate *= delay_brake;
        let erasure_control_active = arrival_rate < 1.0 - f64::EPSILON
            || delay_brake < 1.0 - f64::EPSILON
            || self.erasure_compensation_changed;
        if learned_policer_ceiling.is_some()
            || self.full_bw_reached
            || rate > self.pacing_rate
            || erasure_control_active
        {
            self.pacing_rate = rate;
        }
        self.erasure_compensation_changed = false;
    }

    /// equivalent to BBRRaiseInflightLongtermSlope <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn raise_inflight_long_term_slope(&mut self) {
        let growth_this_round = self
            .smss
            .checked_shl(self.bw_probe_up_rounds)
            .unwrap_or(u64::MAX);
        self.bw_probe_up_rounds = min(self.bw_probe_up_rounds + 1, MAX_LONG_TERM_PROBE_UP_ROUNDS);
        self.probe_up_cnt = max(self.cwnd / growth_this_round, 1);
    }

    /// equivalent to BBRProbeInflightLongtermUpward <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn probe_inflight_long_term_upward(&mut self) {
        if !self.is_cwnd_limited || self.cwnd < self.inflight_longterm {
            return;
        }
        if let Some(rate_sample) = self.rs {
            self.bw_probe_up_acks += rate_sample.newly_acked;
        }
        if self.bw_probe_up_acks >= self.probe_up_cnt && self.probe_up_cnt > 0 {
            let delta = self.bw_probe_up_acks / self.probe_up_cnt;
            self.bw_probe_up_acks -= delta * self.probe_up_cnt;
            self.inflight_longterm += delta;
            if self.round_start {
                self.raise_inflight_long_term_slope();
            }
        }
    }

    /// equivalent to BBRAdvanceMaxBwFilter <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.6>
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count = self.cycle_count.saturating_add(1);
    }

    /// equivalent to BBRAdaptLongTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn adapt_long_term_model(&mut self) {
        if self.ack_phase == AckPhase::ProbeStarting && self.round_start {
            self.ack_phase = AckPhase::ProbeFeedback;
        }
        if self.ack_phase == AckPhase::ProbeStopping
            && self.round_start
            && let BbrState::ProbeBw(_) = self.state
            && let Some(rate_sample) = self.rs
            && !rate_sample.is_app_limited
        {
            self.advance_max_bw_filter();
            // `cycle_count` is virtual time in complete ProbeBW cycles, not
            // packet-timed rounds.  ProbeStopping otherwise remains set for
            // the whole Down/Cruise interval and expires the two-cycle max-bw
            // filter after only a few RTTs.  Mark this transition consumed;
            // the next Refill/Up/Down cycle will arm ProbeStopping again.
            self.ack_phase = AckPhase::ProbeFeedback;
        }
        if !self.is_inflight_too_high() {
            if self.inflight_longterm == u64::MAX {
                return;
            }
            if let Some(rate_sample) = self.rs
                && rate_sample.tx_in_flight > self.inflight_longterm
            {
                self.inflight_longterm = rate_sample.tx_in_flight;
            }
            if self.state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                self.probe_inflight_long_term_upward();
            }
        }
    }

    /// equivalent to BBRIsTimeToCruise <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-8>
    fn maybe_update_budget_and_time_to_cruise(&mut self) -> bool {
        if self.inflight > self.inflight_with_headroom() {
            return false;
        }
        if self.inflight > self.get_inflight(1.0) {
            return false;
        }
        true
    }

    /// equivalent to BBRStartProbeBW_CRUISE <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.4-4>
    fn start_probe_bw_cruise(&mut self) {
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
    }

    /// equivalent to BBRResetShortTermModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = f64::INFINITY;
        self.inflight_shortterm = u64::MAX;
    }

    /// equivalent to BBRInitLowerBounds <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn init_lower_bounds(&mut self) {
        if self.bw_shortterm == f64::INFINITY {
            self.bw_shortterm = self.max_bw;
        }
        if self.inflight_shortterm == u64::MAX {
            self.inflight_shortterm = self.cwnd;
        }
    }

    /// equivalent to BBRLossLowerBounds <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn loss_lower_bounds(&mut self) {
        // gives max of both f64
        self.bw_shortterm = [self.bw_latest, self.params.beta * self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::max);
        self.inflight_shortterm = max(
            self.inflight_latest,
            (self.params.beta * self.inflight_shortterm as f64) as u64,
        );
    }

    /// equivalent to BBRBoundBWForModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn bound_bw_for_model(&mut self) {
        // gives min of both f64
        self.bw = [self.max_bw, self.bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::min);
    }

    /// equivalent to BBRStartProbeBW_REFILL <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-4>
    fn start_probe_bw_refill(&mut self) {
        self.reset_short_term_model();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.ack_phase = AckPhase::Refilling;
        self.start_round();
        self.cwnd_gain = self.default_cwnd_gain;
        self.pacing_gain = self.default_pacing_gain;
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Refill);
    }

    /// equivalent to BBRStartProbeBW_UP <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-4>
    fn start_probe_bw_up(&mut self) {
        self.ack_phase = AckPhase::ProbeStarting;
        self.start_round();
        self.reset_full_bw();
        if let Some(rate_sample) = self.rs {
            self.full_bw = rate_sample.delivery_rate;
        }
        self.state = BbrState::ProbeBw(ProbeBwSubstate::Up);
        self.pacing_gain = self.probe_bw_up_pacing_gain;
        self.cwnd_gain = self.probe_bw_up_cwnd_gain;
        self.raise_inflight_long_term_slope();
    }

    /// equivalent to BBREnterProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn enter_probe_rtt(&mut self) {
        self.probe_rtt_entries = self.probe_rtt_entries.saturating_add(1);
        self.state = BbrState::ProbeRtt;
        self.pacing_gain = self.default_pacing_gain;
        self.cwnd_gain = self.probe_rtt_cwnd_gain;
    }

    fn restart_capacity_discovery(&mut self) {
        // Path activation uses ordinary Startup semantics. Only a new host
        // capacity-probe generation arms the bounded grace after this reset.
        self.capacity_probe_grace_rounds_remaining = 0;
        self.capacity_probe_quantum_guard_armed = false;
        self.enter_startup();
        self.reset_full_bw();
        self.full_bw_reached = false;
        self.reset_congestion_signals();
        self.inflight_longterm = u64::MAX;
        self.inflight_shortterm = u64::MAX;
        self.bw_shortterm = f64::INFINITY;
        self.reset_policer_pacing_episode();
        self.policer_pacing_trial_rejected = false;
        self.cwnd = self.cwnd.max(self.initial_cwnd);

        let nominal_bandwidth = if self.params.startup_bw_hint_bytes_per_second > 0 {
            self.params.startup_bw_hint_bytes_per_second as f64
        } else {
            let initial_window_rate =
                if !self.min_rtt.is_zero() && self.min_rtt != Duration::from_secs(u64::MAX) {
                    self.initial_cwnd as f64 / self.min_rtt.as_secs_f64()
                } else {
                    0.0
                };
            self.max_bw.max(initial_window_rate)
        };
        // A brand-new path activation has neither a delivery model nor an RTT
        // sample yet. Preserve its constructor pacing in that case; a later
        // host-requested reprobe has a measured RTT and enters through the
        // bounded model/IW-per-minRTT baseline above.
        if nominal_bandwidth > 0.0 {
            self.pacing_rate = self.startup_pacing_gain * nominal_bandwidth;
        }
        if self.params.pacing_rate_cap_bytes_per_second > 0 {
            self.pacing_rate = self
                .pacing_rate
                .min(self.params.pacing_rate_cap_bytes_per_second as f64);
        }
        self.set_send_quantum();
    }

    /// equivalent to BBRHandleRestartFromIdle <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.4.1>
    fn handle_restart_from_idle(&mut self, now: Instant) {
        if self.inflight != 0 {
            return;
        }
        if self.app_limited == 0 {
            return;
        }
        // Transport inflight can briefly drain inside one application Bulk
        // epoch. Preserve candidate/fixed policer state and its protective
        // quantum guard; an explicit capacity-probe generation, path
        // activation, or external pacing authority defines the real reset.
        self.idle_restart = true;
        self.extra_acked_interval_start = Some(now);
        match self.state {
            BbrState::ProbeBw(_) => {
                self.set_pacing_rate_with_gain(1.0);
            }
            BbrState::ProbeRtt => {
                self.check_probe_rtt_done(now);
            }
            _ => {}
        }
    }

    /// equivalent to BBRUpdateProbeBWCyclePhase <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.3.6-6>
    fn update_probe_bw_cycle_phase(&mut self, now: Instant) {
        if !self.full_bw_reached {
            return;
        }
        self.adapt_long_term_model();
        let state = self.state;
        match state {
            BbrState::ProbeBw(ProbeBwSubstate::Down) => {
                if self.maybe_enter_probe_bw_refill(now) {
                    return;
                }
                if self.maybe_update_budget_and_time_to_cruise() {
                    self.start_probe_bw_cruise();
                }
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise) if self.maybe_enter_probe_bw_refill(now) => {
            }
            BbrState::ProbeBw(ProbeBwSubstate::Refill) if self.round_start => {
                self.bw_probe_samples = true;
                self.start_probe_bw_up();
            }
            BbrState::ProbeBw(ProbeBwSubstate::Up) if self.maybe_go_down() => {
                self.start_probe_bw_down(now);
            }
            _ => {}
        }
    }

    /// equivalent to BBRUpdateLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn update_latest_delivery_signals(&mut self) {
        self.loss_round_start = false;
        if let Some(rate_sample) = self.rs {
            self.bw_latest = [self.bw_latest, rate_sample.delivery_rate]
                .iter()
                .copied()
                .fold(f64::NAN, f64::max);
            self.inflight_latest = max(self.inflight_latest, rate_sample.delivered);

            if rate_sample.prior_delivered >= self.loss_round_delivered {
                self.loss_round_delivered = self.delivered;
                self.loss_round_start = true;
            }
        }
    }

    /// equivalent to BBRAdaptLowerBoundsFromCongestion <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn adapt_lower_bounds_from_congestion(&mut self) {
        match self.state {
            BbrState::ProbeBw(ProbeBwSubstate::Refill)
            | BbrState::ProbeBw(ProbeBwSubstate::Up)
            | BbrState::Startup => {}
            _ => {
                // Loss still retires bytes-in-flight and feeds the erasure
                // estimator, but it must not depress BBR's bandwidth/inflight
                // lower bounds unless policy explicitly classifies loss as
                // congestion or the transport reported ECN.
                if self.loss_in_round
                    && (self.params.loss_is_congestion || self.erasure_explicit_congestion_in_round)
                {
                    self.init_lower_bounds();
                    self.loss_lower_bounds();
                }
            }
        }
    }

    /// equivalent to BBRUpdateMaxBw <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.5>
    fn update_max_bw(&mut self, p: BbrPacket) {
        self.update_round(p);
        if let Some(rate_sample) = self.rs
            && rate_sample.delivery_rate > 0.0
            && (rate_sample.delivery_rate >= self.max_bw || !rate_sample.is_app_limited)
        {
            self.max_bw_filter
                .update_max(self.cycle_count, rate_sample.delivery_rate.round() as u64);

            self.max_bw = self.max_bw_filter.get_max() as f64;
        }
    }

    /// equivalent to BBRUpdateCongestionSignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn update_congestion_signals(&mut self, p: BbrPacket) {
        self.update_max_bw(p);
        if !self.loss_round_start {
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        self.loss_in_round = false;
    }

    /// equivalent to BBRUpdateACKAggregation <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.9>
    fn update_ack_aggregation(&mut self, now: Instant) {
        let interval;
        if let Some(extra_acked_interval_start) = self.extra_acked_interval_start {
            interval = now - extra_acked_interval_start;
        } else {
            interval = Duration::from_secs(0);
        }
        let mut expected_delivered = (self.bw * interval.as_secs_f64()) as u64;
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = Some(now);
            expected_delivered = 0;
        }
        if let Some(rate_sample) = self.rs {
            self.extra_acked_delivered += rate_sample.newly_acked;
        }

        let mut extra = self
            .extra_acked_delivered
            .saturating_sub(expected_delivered);
        extra = min(extra, self.cwnd);
        if self.full_bw_reached {
            self.extra_acked_filter.update_max(self.round_count, extra);
            self.extra_acked = self.extra_acked_filter.get_max();
        } else {
            self.extra_acked = extra; // In startup, just remember 1 round
        }
    }

    /// equivalent to BBRCheckFullBWReached <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.2-6>
    fn check_full_bw_reached(&mut self) {
        if self.full_bw_now || !self.round_start {
            return;
        }
        let mut capacity_probe_grace_round = false;
        if let Some(rate_sample) = self.rs {
            if rate_sample.is_app_limited {
                return;
            }
            if self.state == BbrState::Startup
                && self.capacity_probe_grace_rounds_remaining > 0
                && rate_sample.delivery_rate.is_finite()
                && rate_sample.delivery_rate > 0.0
            {
                self.capacity_probe_grace_rounds_remaining -= 1;
                capacity_probe_grace_round = true;
            }
            if rate_sample.delivery_rate >= self.full_bw * FULL_BW_GROWTH {
                self.reset_full_bw();
                self.full_bw = rate_sample.delivery_rate;
                return;
            }

            if capacity_probe_grace_round {
                return;
            }

            // On a long-RTT random-loss path, a lossy round is not evidence
            // that Startup found the bottleneck. Correlated radio/cross-
            // carrier loss can suppress three consecutive delivery samples
            // while the sender is still orders of magnitude below capacity;
            // counting those rounds exits Startup at a few packets of cwnd
            // and leaves ProbeBW to recover for minutes. Keep probing until
            // either clean plateau rounds prove full bandwidth or the
            // independent RTT queue guard proves that probing built a queue.
            // Short-RTT policers retain the normal three-round exit and are
            // subsequently bounded by the automatic policer pacing loop.
            let high_rtt_ambiguous_loss = self.min_rtt > POLICER_RTT_CEILING
                && (rate_sample.newly_lost > 0 || rate_sample.lost > 0)
                && !self.queue_delay_guard_triggered();
            if high_rtt_ambiguous_loss {
                return;
            }
        }
        if self.state == BbrState::Startup && self.capacity_probe_grace_rounds_remaining > 0 {
            // A round without a usable rate sample is not one of the eight
            // valid rounds and is not evidence of a delivery-rate plateau.
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= MAX_FULL_BW_COUNT;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    /// equivalent to BBREnterDrain <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.2>
    fn enter_drain(&mut self) {
        self.capacity_probe_grace_rounds_remaining = 0;
        self.state = BbrState::Drain;
        self.pacing_gain = self.drain_pacing_gain;
        self.cwnd_gain = self.default_cwnd_gain;
        self.drain_start_round = self.round_count;
    }

    /// equivalent to BBRCheckStartupDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.1.1-6>
    fn check_startup_done(&mut self) {
        self.check_startup_high_loss();
        if self.state == BbrState::Startup && self.full_bw_reached {
            self.enter_drain();
        }
    }

    /// equivalent to BBRCheckDrainDone <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.2-3>
    fn check_drain_done(&mut self, now: Instant) {
        if self.state == BbrState::Drain
            && (self.inflight <= self.get_inflight(1.0)
                || self.round_count > self.drain_start_round + 3)
        {
            self.enter_probe_bw(now);
        }
    }

    /// equivalent to BBRUpdateMinRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3>
    fn update_min_rtt(&mut self, now: Instant) {
        if let Some(probe_rtt_min_stamp) = self.probe_rtt_min_stamp {
            self.probe_rtt_expired = now
                > probe_rtt_min_stamp
                    .checked_add(self.probe_rtt_interval)
                    .unwrap_or(probe_rtt_min_stamp);
        } else {
            self.probe_rtt_expired = true;
        }
        if let Some(rate_sample) = self.rs
            && rate_sample.rtt >= Duration::from_secs(0)
            && (rate_sample.rtt < self.probe_rtt_min_delay || self.probe_rtt_expired)
        {
            self.probe_rtt_min_delay = rate_sample.rtt;
            self.probe_rtt_min_stamp = Some(now);
        }

        let min_rtt_expired;
        if let Some(min_rtt_stamp) = self.min_rtt_stamp {
            min_rtt_expired = now
                > min_rtt_stamp
                    .checked_add(Duration::from_secs(MIN_RTT_FILTER_LEN))
                    .unwrap_or(min_rtt_stamp);
        } else {
            min_rtt_expired = true;
        }
        if self.probe_rtt_min_delay < self.min_rtt || min_rtt_expired {
            self.min_rtt = self.probe_rtt_min_delay;
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    /// equivalent to BBRHandleProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn handle_probe_rtt(&mut self, now: Instant) {
        if self.probe_rtt_done_stamp.is_none() && self.inflight <= self.probe_rtt_cwnd() {
            self.probe_rtt_done_stamp =
                Some(now.checked_add(self.probe_rtt_duration).unwrap_or(now));
            self.probe_rtt_round_done = false;
            self.start_round();
        } else if self.probe_rtt_done_stamp.is_some() {
            if self.round_start {
                self.probe_rtt_round_done = true;
            }
            if self.probe_rtt_round_done {
                self.check_probe_rtt_done(now);
            }
        }
    }

    /// equivalent to BBRCheckProbeRTT <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.3.4.3-4>
    fn check_probe_rtt(&mut self, now: Instant) {
        match self.state {
            BbrState::ProbeRtt => {
                self.handle_probe_rtt(now);
            }
            _ => {
                // A confirmed shallow-policer ceiling is learned from full
                // outcome windows. Entering ProbeRTT mid-episode drains below
                // that ceiling and can invalidate the confirmation signal.
                // Keep the expiry latched so the first update after the
                // episode ends enters ProbeRTT immediately.
                if self.probe_rtt_expired
                    && !self.idle_restart
                    && self.policer_pacing_transitions == 0
                {
                    self.enter_probe_rtt();
                    self.save_cwnd();
                    self.probe_rtt_done_stamp = None;
                    self.ack_phase = AckPhase::ProbeStopping;
                    self.start_round();
                }
            }
        }
        if let Some(rate_sample) = self.rs
            && rate_sample.delivered > 0
        {
            self.idle_restart = false;
        }
    }

    /// equivalent to BBRAdvanceLatestDeliverySignals <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.3-8>
    fn advance_latest_delivery_signals(&mut self) {
        if self.loss_round_start
            && let Some(rate_sample) = self.rs
        {
            self.bw_latest = rate_sample.delivery_rate;
            self.inflight_latest = rate_sample.delivered;
        }
    }

    /// equivalent to BBRUpdateModelAndState <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.2.3>
    fn update_model_and_state(&mut self, p: BbrPacket, now: Instant) {
        self.update_latest_delivery_signals();
        self.reset_congestion_signals();
        self.update_congestion_signals(p);
        if self.round_start {
            self.advance_external_cap_drain_transition();
            self.refresh_params();
            self.update_erasure_compensation();
        }
        self.update_ack_aggregation(now);
        self.check_full_bw_reached();
        self.check_startup_done();
        self.check_drain_done(now);
        self.update_probe_bw_cycle_phase(now);
        self.update_min_rtt(now);
        self.check_queue_delay_guard(now);
        self.check_probe_rtt(now);
        self.advance_latest_delivery_signals();
        self.bound_bw_for_model();
    }

    fn advance_external_cap_drain_transition(&mut self) {
        self.external_cap_drain_rounds_remaining =
            self.external_cap_drain_rounds_remaining.saturating_sub(1);
    }

    /// equivalent to BBRSetPacingRate <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.2-7>
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// equivalent to BBRSetSendQuantum <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.3>
    /// this version is based on a version of bbr2 from quiche
    fn set_send_quantum(&mut self) {
        let external_cap = self.params.pacing_rate_cap_bytes_per_second;
        let shaping_rate = if external_cap > 0 {
            self.pacing_rate.min(external_cap as f64)
        } else {
            self.pacing_rate
        };
        self.send_quantum = self.send_quantum_for(
            shaping_rate,
            external_cap > 0,
            external_cap > 0 && self.external_cap_drain_rounds_remaining > 0,
            self.shallow_loss_quantum_guard,
            self.capacity_probe_quantum_guard_armed,
        );
    }

    fn capacity_probe_quantum_guard_candidate(&self) -> bool {
        self.max_bw < CAPACITY_PROBE_QUANTUM_MAX_BW
            && (self.pacing_bypass_armed
                || self
                    .pacing_bypass_below_rtt
                    .is_some_and(|threshold| self.min_rtt < threshold))
    }

    fn capacity_probe_quantum_guard(&self, capacity_probe_pending: bool) -> bool {
        self.capacity_probe_quantum_guard_armed
            || (capacity_probe_pending && self.capacity_probe_quantum_guard_candidate())
    }

    fn send_quantum_for(
        &self,
        pacing_rate: f64,
        external_cap_safe: bool,
        external_cap_drain_safe: bool,
        shallow_loss_safe: bool,
        capacity_probe_safe: bool,
    ) -> u64 {
        match pacing_rate {
            rate if rate < PACING_RATE_1_2MBPS => self.smss,
            rate if rate < PACING_RATE_24MBPS => 2 * self.smss,
            rate => {
                let normal_quantum = min(
                    (rate / HIGH_PACE_QUANTUMS_PER_SECOND) as u64,
                    HIGH_PACE_MAX_QUANTUM,
                );
                if external_cap_drain_safe {
                    // A newly published cap first drains any queue left by
                    // the uncapped quantum with a stricter bounded burst.
                    min(
                        normal_quantum,
                        min(
                            (rate / EXTERNAL_CAP_DRAIN_QUANTUMS_PER_SECOND) as u64,
                            self.smss
                                .saturating_mul(EXTERNAL_CAP_DRAIN_MAX_QUANTUM_PACKETS),
                        ),
                    )
                } else if shallow_loss_safe {
                    // A correlated loss declaration acts before outcome
                    // classification. Keep its active-episode safety mode at
                    // one millisecond and at most twelve packets.
                    min(
                        normal_quantum,
                        min(
                            (rate / SHALLOW_LOSS_QUANTUMS_PER_SECOND) as u64,
                            self.smss.saturating_mul(SHALLOW_LOSS_MAX_QUANTUM_PACKETS),
                        ),
                    )
                } else if external_cap_safe {
                    // Once the publication edge has drained, a host-managed
                    // cap uses its sustainable one-millisecond budget.
                    min(
                        normal_quantum,
                        min(
                            (rate / EXTERNAL_CAP_QUANTUMS_PER_SECOND) as u64,
                            self.smss.saturating_mul(EXTERNAL_CAP_MAX_QUANTUM_PACKETS),
                        ),
                    )
                } else if capacity_probe_safe {
                    // A bounded short-path reprobe protects both its pending
                    // first quantum and its grace period with the same strict
                    // one-millisecond, twelve-packet shallow-queue budget.
                    min(
                        normal_quantum,
                        min(
                            (rate / CAPACITY_PROBE_QUANTUMS_PER_SECOND) as u64,
                            self.smss.saturating_mul(CAPACITY_PROBE_MAX_QUANTUM_PACKETS),
                        ),
                    )
                } else {
                    normal_quantum
                }
            }
        }
    }

    /// equivalent to BBRBoundCwndForModel <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.7>
    fn bound_cwnd_for_model(&mut self) {
        let mut cap = u64::MAX;
        match self.state {
            BbrState::ProbeRtt => {
                cap = self.inflight_with_headroom();
            }
            BbrState::ProbeBw(ProbeBwSubstate::Cruise) => {
                cap = self.inflight_with_headroom();
            }
            BbrState::ProbeBw(_) => {
                cap = self.inflight_longterm;
            }
            _ => {}
        }
        cap = min(cap, self.inflight_shortterm);
        cap = max(cap, self.min_pipe_cwnd);
        self.cwnd = min(self.cwnd, cap);
    }

    /// equivalent to BBRSetCwnd <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.6.4.6>
    fn set_cwnd(&mut self) {
        self.update_max_inflight();
        if self.full_bw_reached {
            if let Some(rate_sample) = self.rs {
                self.cwnd = min(self.cwnd + rate_sample.newly_acked, self.max_inflight);
            } else {
                self.cwnd = min(self.cwnd, self.max_inflight);
            }
        } else if (self.cwnd < self.max_inflight || self.delivered < self.initial_cwnd)
            && let Some(rate_sample) = self.rs
        {
            self.cwnd += rate_sample.newly_acked;
        }
        self.cwnd = max(self.cwnd, self.min_pipe_cwnd);
        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
        // ProbeRTT must be allowed to drain to probe_rtt_cwnd before its
        // measurement timer can start. A runtime throughput floor is useful
        // in every other state, but applying it here can hold the effective
        // window permanently above the completion predicate.
        if self.state != BbrState::ProbeRtt && self.params.cwnd_floor_bytes > 0 {
            self.cwnd = self.cwnd.max(self.params.cwnd_floor_bytes);
        }
        if self.params.cwnd_cap_bytes > 0 {
            self.cwnd = self.cwnd.min(self.params.cwnd_cap_bytes);
        }
    }

    /// equivalent to BBRUpdateControlParameters <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.2.3>
    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    /// equivalent to IsNewestPacket <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.3-3>
    fn is_newest_packet(&self, send_time: Instant, end_seq: u64) -> bool {
        if let Some(first_send_time) = self.first_send_time {
            if send_time > first_send_time {
                return true;
            }
            if let Some(rate_sample) = self.rs
                && end_seq > rate_sample.last_end_seq
            {
                return true;
            }
        }
        false
    }

    /// equivalent to BBRHandleLostPacket <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.10.2-11>
    fn process_lost_packet(&mut self, lost_bytes: u64, packet_index: usize, now: Instant) {
        let p = self.packets[packet_index];
        self.note_loss();
        if !self.bw_probe_samples {
            self.packets.remove(packet_index);
            return;
        }
        if let Some(mut rate_sample) = self.rs {
            rate_sample.newly_lost += lost_bytes;
            rate_sample.tx_in_flight = p.tx_in_flight;
            rate_sample.lost = self.lost.saturating_sub(p.lost);
            rate_sample.is_app_limited = p.is_app_limited;
            self.rs = Some(rate_sample);
            if self.is_inflight_too_high() {
                let inflight_at_loss = self.inflight_at_loss(p.size as u64);
                if let Some(rate_sample) = self.rs.as_mut() {
                    rate_sample.tx_in_flight = inflight_at_loss;
                }
                self.handle_inflight_too_high(now);
            }
        }
        self.packets.remove(packet_index);
    }
}
impl Controller for Bbr3 {
    fn on_path_activated(&mut self) {
        self.clear_shallow_loss_quantum_guard();
        self.external_cap_drain_rounds_remaining = 0;
        self.reset_erasure_path_model();
        self.restart_capacity_discovery();
    }

    fn on_packet_sent(&mut self, now: Instant, bytes: u16, pn: u64) {
        if self.inflight == 0 {
            self.first_send_time = Some(now);
            self.delivered_time = Some(now);
            // BBR's idle-restart predicate is defined against the pre-send inflight value.
            // Calling this after incrementing `inflight` made the predicate impossible, which
            // could leave a connection parked in ProbeRTT when bulk traffic resumed after an
            // idle/control-only interval.
            self.handle_restart_from_idle(now);
        }
        let added_bytes = bytes as u64;
        self.inflight += added_bytes;
        self.packets.push_back(BbrPacket {
            delivered: self.delivered,
            delivered_time: self.delivered_time.unwrap_or(now),
            first_send_time: self.first_send_time.unwrap_or(now),
            send_time: now,
            is_app_limited: self.app_limited != 0,
            tx_in_flight: self.inflight,
            packet_number: pn,
            size: bytes,
            lost: self.lost,
            acknowledged: false,
            round_count: self.round_count,
        });
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        pn: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.policer_window_acked_bytes = self.policer_window_acked_bytes.saturating_add(bytes);
        self.erasure_round_acked_bytes = self.erasure_round_acked_bytes.saturating_add(bytes);
        self.delivered = self.delivered.saturating_add(bytes);
        self.delivered_time = Some(now);
        if let Some(mut rate_sample) = self.rs {
            rate_sample.newly_acked += bytes;
            self.rs = Some(rate_sample);
        }
        let p_index_result = self.packets.binary_search_by_key(&pn, |p| p.packet_number);
        let is_newest_packet = self.is_newest_packet(sent, pn);
        if let Ok(p_index) = p_index_result
            && let Some(p) = self.packets.get_mut(p_index)
        {
            p.acknowledged = true;
            if let Some(mut rate_sample) = self.rs {
                rate_sample.rtt = now - p.send_time;
                if is_newest_packet {
                    self.srtt = rtt.get();
                    rate_sample.prior_delivered = p.delivered;
                    rate_sample.prior_time = p.delivered_time;
                    rate_sample.is_app_limited = p.is_app_limited;
                    rate_sample.tx_in_flight = p.tx_in_flight;
                    rate_sample.send_elapsed = p.send_time - p.first_send_time;
                    rate_sample.ack_elapsed = self.delivered_time.unwrap_or(now) - p.delivered_time;
                    rate_sample.last_end_seq = pn;
                    self.first_send_time = Some(p.send_time);
                    rate_sample.last_packet = *p;
                    self.rs = Some(rate_sample);
                }
            } else {
                let rate_sample = BbrRateSample {
                    rtt: now.saturating_duration_since(p.send_time),
                    prior_time: p.delivered_time,
                    interval: Duration::ZERO,
                    delivery_rate: 0.0,
                    is_app_limited: p.is_app_limited,
                    delivered: 0,
                    prior_delivered: p.delivered,
                    tx_in_flight: p.tx_in_flight,
                    send_elapsed: p.send_time - p.first_send_time,
                    ack_elapsed: self.delivered_time.unwrap_or(now) - p.delivered_time,
                    newly_acked: bytes,
                    newly_lost: 0,
                    lost: 0,
                    last_end_seq: pn,
                    last_packet: *p,
                };
                self.rs = Some(rate_sample);
                self.first_send_time = Some(p.send_time);
                self.srtt = rtt.get();
            }
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inflight = in_flight;
        if let Some(largest_packet_num) = largest_packet_num_acked {
            if self.app_limited != 0 && largest_packet_num > self.app_limited {
                self.app_limited = 0;
            } else if app_limited {
                self.app_limited = self.app_limited.max(largest_packet_num);
            }
            // Packet numbers are inserted monotonically. Retire the contiguous
            // acknowledged/expired prefix instead of scanning the complete
            // inflight deque twice for every ACK batch. Out-of-order ACKed
            // entries remain behind the first live gap and are reclaimed when
            // that gap is ACKed, declared lost, or ages out. This makes the
            // normal ordered-ACK path amortized O(acked packets), independent
            // of BDP, while preserving loss lookups for unresolved packets.
            while self.packets.front().is_some_and(|packet| {
                packet.acknowledged
                    || self.round_count.saturating_sub(packet.round_count) > ROUND_COUNT_WINDOW
            }) {
                self.packets.pop_front();
            }
            if let Some(mut rate_sample) = self.rs {
                rate_sample.interval = max(rate_sample.send_elapsed, rate_sample.ack_elapsed);
                rate_sample.delivered = self.delivered.saturating_sub(rate_sample.prior_delivered);
                // ignore this condition on an initially high min rtt as per <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-4.1.2.3-5>
                let valid_interval = rate_sample.interval >= self.min_rtt
                    || self.min_rtt == Duration::from_secs(u64::MAX);
                if rate_sample.prior_delivered != 0
                    && valid_interval
                    && rate_sample.interval != Duration::ZERO
                {
                    rate_sample.delivery_rate =
                        rate_sample.delivered as f64 / rate_sample.interval.as_secs_f64();
                } else {
                    rate_sample.delivery_rate = 0.0;
                }
                if rate_sample.delivered >= self.cwnd {
                    self.is_cwnd_limited = true;
                }
                self.rs = Some(rate_sample);
                // BBR consumes exactly one completed delivery-rate sample per ACK
                // batch. Updating the model from `on_ack` used the preceding batch's
                // stale rate and ran once per ACK range before `interval`/`delivered`
                // had even been calculated.
                self.update_model_and_state(rate_sample.last_packet, now);
                self.update_policer_pacing(now);
                self.update_control_parameters();
                rate_sample.newly_acked = 0;
                rate_sample.lost = 0;
                rate_sample.newly_lost = 0;
                self.rs = Some(rate_sample);
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
        largest_lost_pn: u64,
    ) {
        // only process ecn here, regular packet loss is detected per packet in on_packet_lost.
        if is_ecn {
            self.policer_window_lost_bytes =
                self.policer_window_lost_bytes.saturating_add(lost_bytes);
            self.explicit_congestion_in_round = true;
            self.erasure_explicit_congestion_in_round = true;
            self.lost += lost_bytes;
            let p_index_result = self
                .packets
                .binary_search_by_key(&largest_lost_pn, |p| p.packet_number);
            if let Ok(p_index) = p_index_result {
                self.process_lost_packet(lost_bytes, p_index, now);
            }
            if is_persistent_congestion {
                self.cwnd = self.min_pipe_cwnd;
            }
        }
    }

    fn on_packet_lost(&mut self, lost_bytes: u16, pn: u64, now: Instant) {
        let lost_bytes_64 = lost_bytes as u64;
        self.record_shallow_loss_declaration(now, lost_bytes_64);
        self.policer_window_lost_bytes =
            self.policer_window_lost_bytes.saturating_add(lost_bytes_64);
        self.erasure_round_lost_bytes = self.erasure_round_lost_bytes.saturating_add(lost_bytes_64);
        self.lost += lost_bytes_64;
        let p_index_result = self.packets.binary_search_by_key(&pn, |p| p.packet_number);
        if let Ok(p_index) = p_index_result {
            self.process_lost_packet(lost_bytes_64, p_index, now);
        }
    }

    /// equivalent to BBRHandleSpuriousLossDetection: <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-05.html#section-5.5.11.2>
    fn on_spurious_congestion_event(&mut self) {
        self.loss_in_round = false;
        self.reset_full_bw();
        self.bw_shortterm = [self.bw_shortterm, self.undo_bw_shortterm]
            .iter()
            .copied()
            .fold(f64::NAN, f64::max);
        self.inflight_shortterm = max(self.inflight_shortterm, self.undo_inflight_shortterm);
        self.inflight_longterm = max(self.inflight_longterm, self.undo_inflight_longterm);
        if self.state != BbrState::ProbeRtt && self.state != self.undo_state {
            if self.undo_state == BbrState::Startup {
                self.enter_startup();
            } else if self.undo_state == BbrState::ProbeBw(ProbeBwSubstate::Up) {
                self.start_probe_bw_up();
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.smss = min(
            max(MIN_MAX_DATAGRAM_SIZE, new_mtu) as u64,
            MAX_DATAGRAM_SIZE,
        );
        self.set_send_quantum();
        self.set_cwnd();
    }

    fn on_ack_frequency_update(
        &mut self,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: Duration,
    ) {
        self.ack_eliciting_threshold = ack_eliciting_threshold;
        self.max_ack_delay = requested_max_ack_delay;
    }

    fn window(&self) -> u64 {
        let base = if self.pacing_bypass_active() {
            self.cwnd.max(self.low_rtt_cwnd_floor)
        } else {
            self.cwnd
        };
        let compensated = (base as f64 / self.erasure_control_arrival_rate())
            .round()
            .clamp(0.0, u64::MAX as f64) as u64;
        if self.params.cwnd_cap_bytes > 0 {
            compensated.min(self.params.cwnd_cap_bytes)
        } else {
            compensated
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        // The host publishes tunables with a Release generation store, while
        // BBR normally adopts them only on a packet-timed round boundary. A
        // newly detected shallow policer cannot safely wait for that boundary:
        // the old token bucket may still contain a 64 KB burst. Observe the
        // published cap here so the very next pacing check clamps both rate
        // and capacity. Other controller parameters retain round semantics.
        let live_generation = self.tunables.generation.load(Ordering::Acquire);
        let generation_pending = live_generation != self.params_generation;
        let capacity_probe_pending = generation_pending
            && self
                .tunables
                .capacity_probe_generation
                .load(Ordering::Relaxed)
                != self.params.capacity_probe_generation;
        let raw_live_cap = self
            .tunables
            .pacing_rate_cap_bytes_per_second
            .load(Ordering::Relaxed);
        let live_cap = if raw_live_cap == 0 || raw_live_cap >= 64 * 1024 {
            raw_live_cap
        } else {
            64 * 1024
        };
        let external_cap = if generation_pending {
            live_cap
        } else {
            self.params.pacing_rate_cap_bytes_per_second
        };
        let pacing_rate = if external_cap > 0 {
            self.pacing_rate.min(external_cap as f64)
        } else {
            self.pacing_rate
        };
        let capacity_probe_safe = self.capacity_probe_quantum_guard(capacity_probe_pending);
        let external_cap_drain_safe = external_cap > 0
            && (self.external_cap_drain_rounds_remaining > 0
                || (generation_pending
                    && self.params.pacing_rate_cap_bytes_per_second == 0
                    && live_cap > 0));
        let send_quantum = self.send_quantum_for(
            pacing_rate,
            external_cap > 0,
            external_cap_drain_safe,
            self.shallow_loss_quantum_guard,
            capacity_probe_safe,
        );
        // A live positive cap is authoritative even if the controller-local
        // low-RTT pacing bypass has not yet reached its next ACK update. The
        // host capacity-probe edge likewise resumes pacing before the next
        // packet-timed round adopts and restarts the controller model.
        let pacing_enabled = external_cap > 0
            || capacity_probe_safe
            || self.shallow_loss_quantum_guard
            || !self.pacing_bypass_active();
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: pacing_enabled.then_some(pacing_rate.round() as u64),
            send_quantum: pacing_enabled.then_some(send_quantum),
            queue_delay_guard_transitions: self.queue_delay_guard_transitions,
            policer_pacing_scale_per_mille: (self.policer_pacing_scale * 1_000.0)
                .round()
                .clamp(0.0, 1_000.0) as u16,
            policer_pacing_transitions: self.policer_pacing_transitions,
            snapshot: Some(ControllerSnapshot {
                state: match self.state {
                    BbrState::Startup => 0,
                    BbrState::Drain => 1,
                    BbrState::ProbeBw(ProbeBwSubstate::Down) => 2,
                    BbrState::ProbeBw(ProbeBwSubstate::Cruise) => 3,
                    BbrState::ProbeBw(ProbeBwSubstate::Refill) => 4,
                    BbrState::ProbeBw(ProbeBwSubstate::Up) => 5,
                    BbrState::ProbeRtt => 6,
                },
                bw: self.bw.max(0.0).round() as u64,
                max_bw: self.max_bw.max(0.0).round() as u64,
                min_rtt: self.min_rtt,
                srtt: self.srtt,
                bdp: self.bdp,
                inflight_longterm: self.inflight_longterm,
                inflight_shortterm: self.inflight_shortterm,
                round_count: self.round_count,
                cycle_count: self.cycle_count,
                app_limited_in_round: self.rs.is_some_and(|sample| sample.is_app_limited),
                lost_in_round: self.rs.map_or(0, |sample| sample.newly_lost),
                delivered_in_round: self.rs.map_or(0, |sample| sample.delivered),
                probe_rtt_entries: self.probe_rtt_entries,
                guard_transitions: self.queue_delay_guard_transitions,
                erasure_measured_arrival_per_mille: (self.erasure_measured_arrival * 1_000.0)
                    .round()
                    .clamp(0.0, 1_000.0) as u16,
                erasure_applied_arrival_per_mille: (self.erasure_control_arrival_rate() * 1_000.0)
                    .round()
                    .clamp(0.0, 1_000.0) as u16,
                erasure_compensation_transitions: self.erasure_compensation_transitions,
                clamped_writes: self.tunables.clamped_writes.load(Ordering::Relaxed),
                params_generation: self.params_generation,
            }),
        }
    }

    fn tunables(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        Some(self.tunables.clone())
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.initial_cwnd
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `Bbr3` congestion controller
///
/// Different pacing_gains can be set to modify the multiplier used to
/// increase the sending rates.
/// Different cwnd_gains can be set to modify the multiplier used to increase
/// the congestion windows.
/// All of these parameters are specific to different states of the algorithm: see `BbrState`
/// `pacing_margin_percent` is used to set a margin when calculating the `pacing_rate` in order
/// to not send at 100% capacity when calculating pacing.
#[derive(Debug, Clone)]
pub struct Bbr3Config {
    initial_window: u64,
    probe_rng_seed: Option<[u8; 16]>,
    startup_pacing_gain: Option<f64>,
    default_pacing_gain: Option<f64>,
    probe_bw_down_pacing_gain: Option<f64>,
    probe_bw_up_pacing_gain: Option<f64>,
    probe_bw_up_cwnd_gain: Option<f64>,
    probe_rtt_cwnd_gain: Option<f64>,
    drain_pacing_gain: Option<f64>,
    pacing_margin_percent: Option<f64>,
    default_cwnd_gain: Option<f64>,
    pacing_bypass_below_rtt: Option<Duration>,
    low_rtt_cwnd_floor: u64,
    tunables_template: Option<Arc<Bbr3Tunables>>,
}

impl Bbr3Config {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }

    /// Bypass BBR's userspace pacing timer after the measured path minimum RTT
    /// falls below `threshold`. Congestion-window accounting remains active.
    /// This is intended for host/datacenter paths where timer scheduling costs
    /// more than the sub-millisecond wire interval; Internet paths should keep
    /// the default (`None`).
    pub fn pacing_bypass_below_rtt(&mut self, threshold: Option<Duration>) -> &mut Self {
        self.pacing_bypass_below_rtt = threshold.filter(|value| !value.is_zero());
        self
    }

    /// Set the minimum congestion window used while the low-RTT pacing bypass
    /// is active. A larger window amortizes ACK scheduling and socket wakeups
    /// on host/datacenter paths without changing Internet-path BBR behavior.
    pub fn low_rtt_cwnd_floor(&mut self, bytes: u64) -> &mut Self {
        self.low_rtt_cwnd_floor = bytes;
        self
    }

    /// Set the initial runtime-tuning template. Each newly constructed path
    /// receives its own atomic handle copied from this template.
    pub fn tunables_template(&mut self, template: Option<Arc<Bbr3Tunables>>) -> &mut Self {
        self.tunables_template = template;
        self
    }
}

impl Default for Bbr3Config {
    fn default() -> Self {
        Self {
            initial_window: 14720.clamp(2 * MAX_DATAGRAM_SIZE, 10 * MAX_DATAGRAM_SIZE),
            probe_rng_seed: None,
            startup_pacing_gain: None,
            default_pacing_gain: None,
            probe_bw_down_pacing_gain: None,
            probe_bw_up_pacing_gain: None,
            probe_bw_up_cwnd_gain: None,
            probe_rtt_cwnd_gain: None,
            drain_pacing_gain: None,
            pacing_margin_percent: None,
            default_cwnd_gain: None,
            pacing_bypass_below_rtt: None,
            low_rtt_cwnd_floor: 0,
            tunables_template: None,
        }
    }
}

impl ControllerFactory for Bbr3Config {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr3::new(self, current_mtu))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_rate_sample(lost: u64, tx_in_flight: u64) -> BbrRateSample {
        let now = Instant::now();
        let packet = BbrPacket {
            delivered: 0,
            delivered_time: now,
            first_send_time: now,
            send_time: now,
            is_app_limited: false,
            tx_in_flight,
            packet_number: 0,
            size: MIN_MAX_DATAGRAM_SIZE,
            lost: 0,
            acknowledged: false,
            round_count: 0,
        };
        BbrRateSample {
            delivery_rate: 0.0,
            is_app_limited: false,
            interval: Duration::ZERO,
            delivered: 0,
            prior_delivered: 0,
            prior_time: now,
            send_elapsed: Duration::ZERO,
            ack_elapsed: Duration::ZERO,
            rtt: Duration::from_millis(28),
            tx_in_flight,
            newly_acked: 0,
            newly_lost: lost,
            lost,
            last_end_seq: 0,
            last_packet: packet,
        }
    }

    #[test]
    fn test_probe_rng() {
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = Bbr3Config {
            initial_window: 14720.clamp(2 * MAX_DATAGRAM_SIZE, 10 * MAX_DATAGRAM_SIZE),
            probe_rng_seed: Some(seed),
            startup_pacing_gain: None,
            default_pacing_gain: None,
            probe_bw_down_pacing_gain: None,
            probe_bw_up_pacing_gain: None,
            probe_bw_up_cwnd_gain: None,
            probe_rtt_cwnd_gain: None,
            drain_pacing_gain: None,
            pacing_margin_percent: None,
            default_cwnd_gain: None,
            pacing_bypass_below_rtt: None,
            low_rtt_cwnd_floor: 0,
            tunables_template: None,
        };
        let mut bbr3 = Bbr3::new(Arc::new(config), 2500);
        bbr3.pick_probe_wait();
        assert_eq!(bbr3.rounds_since_bw_probe, 1);
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2652));
        bbr3.pick_probe_wait();
        assert_eq!(bbr3.rounds_since_bw_probe, 1);
        assert_eq!(bbr3.bw_probe_wait, Duration::from_millis(2570));
    }

    #[test]
    fn pacing_bypass_is_automatic_only_below_configured_minimum_rtt() {
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(1)));
        config.low_rtt_cwnd_floor(512 * 1024);
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_400);

        assert!(
            bbr3.metrics().pacing_rate.is_some(),
            "pacing stays enabled until an RTT sample exists"
        );
        bbr3.min_rtt = Duration::from_micros(999);
        bbr3.cwnd = 64 * 1024;
        bbr3.pacing_bypass_armed = true;
        assert!(bbr3.metrics().pacing_rate.is_none());
        assert!(bbr3.metrics().send_quantum.is_none());
        assert_eq!(bbr3.window(), 512 * 1024);

        bbr3.policer_pacing_scale = 0.9;
        assert!(bbr3.metrics().pacing_rate.is_some());
        assert!(bbr3.metrics().send_quantum.is_some());
        assert_eq!(bbr3.window(), 64 * 1024);

        bbr3.policer_pacing_scale = 1.0;
        bbr3.min_rtt = Duration::from_millis(1);
        assert!(bbr3.metrics().pacing_rate.is_some());
        assert!(bbr3.metrics().send_quantum.is_some());
        assert_eq!(bbr3.window(), 64 * 1024);
    }

    #[test]
    fn erasure_compensation_advances_only_after_delivery_improves() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.min_rtt = Duration::from_millis(100);
        bbr3.srtt = Duration::from_millis(100);
        bbr3.bw = 1_000_000.0;
        bbr3.cwnd = 200_000;

        let mut sample = test_rate_sample(0, 200_000);
        sample.delivery_rate = 1_000_000.0;
        bbr3.rs = Some(sample);
        bbr3.round_count = 1;
        bbr3.erasure_round_acked_bytes = 58 * 1_200;
        bbr3.erasure_round_lost_bytes = 42 * 1_200;
        bbr3.update_erasure_compensation();

        assert!((bbr3.erasure_measured_arrival - 0.58).abs() < 1e-9);
        assert!((bbr3.erasure_applied_arrival - 0.9).abs() < 1e-9);
        bbr3.set_pacing_rate_with_gain(1.0);
        assert!((bbr3.pacing_rate - 1_100_000.0).abs() < 1.0);
        assert_eq!(bbr3.window(), 222_222);

        // A second request for compensation at the same delivered rate is a
        // policer-shaped outcome, so the controller holds the preceding probe.
        bbr3.round_count = 2;
        bbr3.erasure_round_acked_bytes = 58 * 1_200;
        bbr3.erasure_round_lost_bytes = 42 * 1_200;
        bbr3.update_erasure_compensation();
        assert!((bbr3.erasure_applied_arrival - 0.9).abs() < 1e-9);

        // Once the prior wire-rate increase buys delivery, one more bounded
        // step is earned rather than jumping directly to the measured 0.58.
        sample.delivery_rate = 1_100_000.0;
        bbr3.rs = Some(sample);
        bbr3.round_count = 3;
        bbr3.erasure_round_acked_bytes = 58 * 1_200;
        bbr3.erasure_round_lost_bytes = 42 * 1_200;
        bbr3.update_erasure_compensation();
        assert!((bbr3.erasure_applied_arrival - 0.81).abs() < 1e-9);

        let snapshot = bbr3.metrics().snapshot.expect("BBR3 snapshot");
        assert_eq!(snapshot.erasure_measured_arrival_per_mille, 580);
        assert_eq!(snapshot.erasure_applied_arrival_per_mille, 810);
        assert_eq!(snapshot.erasure_compensation_transitions, 2);
    }

    #[test]
    fn erasure_wire_budget_keeps_delay_and_policer_brakes_authoritative() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.min_rtt = Duration::from_millis(100);
        bbr3.srtt = Duration::from_millis(250);
        bbr3.bw = 1_000_000.0;

        // A stale/high initial SRTT must not brake ordinary BBR before the
        // erasure loop has requested any extra wire traffic.
        bbr3.set_pacing_rate_with_gain(1.0);
        assert!((bbr3.pacing_rate - 990_000.0).abs() < 1.0);

        bbr3.erasure_applied_arrival = 0.5;

        bbr3.srtt = Duration::from_millis(100);
        bbr3.set_pacing_rate_with_gain(1.0);
        assert!((bbr3.pacing_rate - 1_980_000.0).abs() < 1.0);

        // At 2.5x min RTT, queue delay is 1.5 RTT and continuously brakes the
        // compensated rate by 1/1.5 rather than waiting for packet loss.
        bbr3.srtt = Duration::from_millis(250);
        bbr3.set_pacing_rate_with_gain(1.0);
        assert!((bbr3.pacing_rate - 1_320_000.0).abs() < 1.0);

        // A deeper queue can withdraw all added erasure traffic, but the
        // erasure loop does not second-guess BBR below its own base rate.
        bbr3.srtt = Duration::from_millis(400);
        bbr3.set_pacing_rate_with_gain(1.0);
        assert!((bbr3.pacing_rate - 990_000.0).abs() < 1.0);

        // A learned shallow-policer ceiling owns the gross wire budget. It also
        // suppresses erasure window inflation, avoiding two coupled loops.
        bbr3.srtt = bbr3.min_rtt;
        bbr3.policer_pacing_candidate_armed = true;
        bbr3.policer_pacing_ceiling_bytes_per_second = 700_000.0;
        bbr3.cwnd = 200_000;
        bbr3.set_pacing_rate_with_gain(1.0);
        assert_eq!(bbr3.pacing_rate, 700_000.0);
        assert_eq!(bbr3.window(), 200_000);
        assert_eq!(
            bbr3.metrics()
                .snapshot
                .expect("BBR3 snapshot")
                .erasure_applied_arrival_per_mille,
            1_000
        );
    }

    #[test]
    fn erasure_compensation_waits_for_rtt_and_resets_on_path_activation() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.round_count = 1;
        bbr3.bw = 1_000_000.0;
        bbr3.erasure_round_acked_bytes = 58 * 1_200;
        bbr3.erasure_round_lost_bytes = 42 * 1_200;
        bbr3.update_erasure_compensation();
        assert_eq!(bbr3.erasure_applied_arrival, 1.0);

        bbr3.min_rtt = Duration::from_millis(100);
        bbr3.srtt = bbr3.min_rtt;
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.round_count = 2;
        bbr3.erasure_round_acked_bytes = 58 * 1_200;
        bbr3.erasure_round_lost_bytes = 42 * 1_200;
        bbr3.update_erasure_compensation();
        assert!(bbr3.erasure_applied_arrival < 1.0);

        bbr3.on_path_activated();
        assert_eq!(bbr3.erasure_measured_arrival, 1.0);
        assert_eq!(bbr3.erasure_applied_arrival, 1.0);
        assert_eq!(bbr3.erasure_compensation_transitions, 0);
    }

    #[test]
    fn erasure_clean_window_keeps_low_rtt_fast_path_eligible() {
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.min_rtt = Duration::from_millis(2);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.pacing_bypass_armed = true;
        bbr3.round_count = 1;
        bbr3.erasure_round_acked_bytes = 995 * 1_200;
        bbr3.erasure_round_lost_bytes = 5 * 1_200;

        bbr3.update_erasure_compensation();

        assert!((bbr3.erasure_measured_arrival - 0.995).abs() < 1e-9);
        assert_eq!(bbr3.erasure_applied_arrival, 1.0);
        assert!(bbr3.pacing_bypass_active());
    }

    #[test]
    fn pending_host_capacity_probe_resumes_low_rtt_pacing_before_round_refresh() {
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 13_000_000.0;
        bbr3.pacing_bypass_armed = true;
        assert!(bbr3.metrics().pacing_rate.is_none());
        assert!(bbr3.metrics().send_quantum.is_none());

        handle.capacity_probe_generation.store(1, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);

        let pending = bbr3.metrics();
        assert_eq!(bbr3.params_generation, 0);
        assert_eq!(pending.pacing_rate, Some(13_000_000));
        assert_eq!(pending.send_quantum, Some(13_000));

        bbr3.refresh_params();
        assert!(!bbr3.pacing_bypass_armed);
        assert!(bbr3.capacity_probe_quantum_guard_armed);
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS
        );
        assert!(bbr3.metrics().pacing_rate.is_some());
        assert_eq!(bbr3.metrics().send_quantum, Some(12 * 1_200));
    }

    #[test]
    fn pending_capacity_probe_quantum_guard_respects_short_low_bw_boundaries() {
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.pacing_rate = 100_000_000.0;
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.max_bw = CAPACITY_PROBE_QUANTUM_MAX_BW - 1.0;
        handle.capacity_probe_generation.store(1, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);

        assert_eq!(bbr3.metrics().send_quantum, Some(12 * 1_200));

        // An already high-bandwidth model does not need pending-probe burst
        // protection, even before the generation reaches a round refresh.
        bbr3.max_bw = CAPACITY_PROBE_QUANTUM_MAX_BW;
        assert_eq!(bbr3.metrics().send_quantum, Some(HIGH_PACE_MAX_QUANTUM));

        // The existing bypass boundary is exclusive: paths at the threshold
        // are not part of the short-RTT capacity-probe special case.
        bbr3.max_bw = CAPACITY_PROBE_QUANTUM_MAX_BW - 1.0;
        bbr3.min_rtt = Duration::from_millis(5);
        assert_eq!(bbr3.metrics().send_quantum, Some(HIGH_PACE_MAX_QUANTUM));
    }

    #[test]
    fn short_rtt_sustained_loss_automatically_caps_wire_pacing() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        assert_eq!(bbr3.params.pacing_rate_cap_bytes_per_second, 0);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.bw = 10_000_000.0;
        bbr3.max_bw = 2_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        assert!(!bbr3.full_bw_reached);
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert_eq!(bbr3.policer_pacing_scale, 1.0);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert!(bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 1_840_000.0);
        assert_eq!(bbr3.pacing_rate, 1_840_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
        assert_eq!(bbr3.policer_pacing_candidate_warmup_windows_remaining, 1);

        // An unguarded lossy outcome begins the cap, so its first full
        // post-cap outcome is a drain/warmup sample rather than confirmation.
        bbr3.policer_window_acked_bytes = 900_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
        assert!(bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_candidate_warmup_windows_remaining, 0);
        assert_eq!(bbr3.policer_pacing_transitions, 0);

        bbr3.policer_window_acked_bytes = 900_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 3);
        assert_eq!(bbr3.policer_pacing_scale, POLICER_EPISODE_PACING_SCALE);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 1_960_000.0);
        assert_eq!(bbr3.metrics().policer_pacing_scale_per_mille, 1_000);
        // The confirming outcome lowers Startup's retained monotonic rate
        // directly; no later set_pacing_rate_with_gain call is needed.
        assert_eq!(bbr3.pacing_rate, 1_960_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 2 * 1_200);
    }

    #[test]
    fn trial_ceiling_bounds_ack_compression_with_discounted_windowed_max_bw() {
        let start = Instant::now();
        for (first_acked, second_acked) in [(800_000, 4_200_000), (1_000_000, 5_000_000)] {
            let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
            bbr3.min_rtt = Duration::from_millis(5);
            bbr3.srtt = Duration::from_millis(8);
            bbr3.pacing_rate = 20_000_000.0;
            bbr3.max_bw = 10_000_000.0;
            bbr3.policer_window_started = Some(start);
            bbr3.policer_window_acked_bytes = first_acked;
            bbr3.policer_window_lost_bytes = 200_000;

            bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
            assert_eq!(bbr3.policer_pacing_transitions, 0);
            assert!(bbr3.policer_pacing_candidate_armed);
            assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 9_200_000.0);
            assert_eq!(bbr3.pacing_rate, 9_200_000.0);
            assert!(bbr3.shallow_loss_quantum_guard);

            // Warmup and confirmation may carry different ACK phases, while
            // the promoted ceiling still uses the model frozen at entry.
            bbr3.max_bw = 30_000_000.0;
            bbr3.policer_window_acked_bytes = second_acked;
            bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
            assert_eq!(bbr3.policer_pacing_transitions, 0);
            assert!(bbr3.policer_pacing_candidate_armed);

            bbr3.policer_window_acked_bytes = first_acked;
            bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 3);
            assert_eq!(bbr3.policer_pacing_transitions, 1);
            assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 9_800_000.0);
            assert_eq!(bbr3.pacing_rate, 9_800_000.0);
            assert!(bbr3.shallow_loss_quantum_guard);
        }
    }

    #[test]
    fn trial_ceiling_uses_only_the_frozen_windowed_model() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.max_bw = 2_000_000.0;

        assert_eq!(
            bbr3.policer_trial_ceiling(4_000_000, POLICER_SAMPLE_WINDOW),
            Some(1_840_000.0)
        );
    }

    #[test]
    fn trial_ceiling_rejects_incomplete_or_invalid_outcomes() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.max_bw = 10_000_000.0;

        assert_eq!(
            bbr3.policer_trial_ceiling(4_000_000, POLICER_SAMPLE_WINDOW - Duration::from_nanos(1)),
            None
        );
        assert_eq!(bbr3.policer_trial_ceiling(0, POLICER_SAMPLE_WINDOW), None);
        bbr3.max_bw = f64::NAN;
        assert_eq!(
            bbr3.policer_trial_ceiling(4_000_000, POLICER_SAMPLE_WINDOW),
            None
        );
    }

    #[test]
    fn no_burst_short_min_rtt_high_loss_arms_trial_despite_inflated_srtt() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(7);
        bbr3.srtt = Duration::from_millis(30);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);

        assert!(bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_candidate_warmup_windows_remaining, 1);
        assert_eq!(
            bbr3.policer_pacing_candidate_confirmation_windows_remaining,
            POLICER_TRIAL_CONFIRMATION_WINDOWS
        );
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 9_200_000.0);
        assert_eq!(bbr3.pacing_rate, 9_200_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
    }

    #[test]
    fn no_burst_loss_above_ten_ms_min_rtt_does_not_arm_trial() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(13);
        bbr3.srtt = Duration::from_millis(18);
        bbr3.bw = 10_000_000.0;
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);

        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_candidate_saw_low_latency_window);
        assert!(!bbr3.policer_pacing_trial_rejected);
        assert_eq!(bbr3.metrics().send_quantum, Some(HIGH_PACE_MAX_QUANTUM));
    }

    #[test]
    fn no_burst_short_min_rtt_loss_below_two_percent_does_not_arm_trial() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(7);
        bbr3.srtt = Duration::from_millis(30);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 990_000;
        bbr3.policer_window_lost_bytes = 10_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);

        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_trial_rejected);
    }

    #[test]
    fn high_rate_short_path_latches_trial_rejection_before_model_declines() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(7);
        bbr3.srtt = Duration::from_millis(10);
        bbr3.max_bw = CAPACITY_PROBE_QUANTUM_MAX_BW;
        bbr3.pacing_rate = 50_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);

        assert!(bbr3.policer_pacing_trial_rejected);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert_eq!(bbr3.policer_pacing_transitions, 0);

        // A later degraded delivery model cannot reinterpret the same Bulk
        // episode as a shallow policer and enter a delayed trial.
        bbr3.max_bw = 10_000_000.0;
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);

        assert!(bbr3.policer_pacing_trial_rejected);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
    }

    #[test]
    fn queue_inflation_on_confirmation_rejects_trial() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(7);
        bbr3.srtt = Duration::from_millis(10);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(bbr3.policer_pacing_candidate_armed);

        bbr3.srtt = Duration::from_micros(22_001);
        for window in 2..=6 {
            bbr3.policer_window_acked_bytes = 1_000_000;
            bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * window);
            if window < 6 {
                assert!(bbr3.policer_pacing_candidate_armed);
                assert_eq!(
                    bbr3.policer_pacing_candidate_confirmation_windows_remaining,
                    (6 - window) as u8
                );
                assert!(bbr3.shallow_loss_quantum_guard);
            }
        }
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_candidate_saw_low_latency_window);
        assert!(bbr3.policer_pacing_trial_rejected);
    }

    #[test]
    fn bounded_horizon_short_path_with_receded_queue_confirms_fallback_ceiling() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(7);
        bbr3.srtt = Duration::from_millis(22);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_pacing_candidate_armed = true;
        bbr3.policer_pacing_candidate_confirmation_windows_remaining = 1;
        bbr3.policer_pacing_ceiling_bytes_per_second = 10_400_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 4_200_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);

        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 11_440_000.0);
        assert_eq!(bbr3.pacing_rate, 11_440_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_candidate_saw_low_latency_window);
        assert!(!bbr3.policer_pacing_trial_rejected);

        // Later live model and loss samples do not recalibrate the frozen
        // confirmed ceiling.
        bbr3.max_bw = 30_000_000.0;
        bbr3.policer_window_acked_bytes = 4_200_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 11_440_000.0);
        assert_eq!(bbr3.policer_pacing_consecutive_loss_windows, 1);
    }

    #[test]
    fn bounded_horizon_remembers_middle_low_latency_window_across_final_spike() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(7);
        bbr3.srtt = Duration::from_millis(22);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_pacing_candidate_armed = true;
        bbr3.policer_pacing_candidate_confirmation_windows_remaining = 2;
        bbr3.policer_pacing_ceiling_bytes_per_second = 10_400_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 4_200_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(bbr3.policer_pacing_candidate_armed);
        assert!(bbr3.policer_pacing_candidate_saw_low_latency_window);
        assert_eq!(
            bbr3.policer_pacing_candidate_confirmation_windows_remaining,
            1
        );

        bbr3.srtt = Duration::from_millis(30);
        bbr3.policer_window_acked_bytes = 4_200_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);

        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 11_440_000.0);
        assert!(!bbr3.policer_pacing_candidate_saw_low_latency_window);
        assert!(!bbr3.policer_pacing_trial_rejected);
    }

    #[test]
    fn policer_episode_reset_clears_candidate_and_loss_streak() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.max_bw = 2_000_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert!(bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 1_840_000.0);
        bbr3.policer_pacing_candidate_saw_low_latency_window = true;
        bbr3.policer_pacing_consecutive_loss_windows = 2;

        bbr3.restart_capacity_discovery();
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.policer_pacing_candidate_saw_low_latency_window);
        assert_eq!(bbr3.policer_pacing_consecutive_loss_windows, 0);
    }

    #[test]
    fn transport_idle_restart_preserves_policer_state_and_protective_guard() {
        let now = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.policer_pacing_candidate_armed = true;
        bbr3.policer_pacing_ceiling_bytes_per_second = 1_960_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_pacing_trial_rejected = true;
        bbr3.shallow_loss_declaration_stamp = Some(now);
        bbr3.shallow_loss_declaration_bytes = 16 * 1_200;
        bbr3.app_limited = 1;
        assert_eq!(bbr3.inflight, 0);

        bbr3.handle_restart_from_idle(now);
        assert!(bbr3.idle_restart);
        assert!(bbr3.policer_pacing_candidate_armed);
        assert!(bbr3.policer_pacing_trial_rejected);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 1_960_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
        assert_eq!(bbr3.shallow_loss_declaration_stamp, Some(now));
        assert_eq!(bbr3.shallow_loss_declaration_bytes, 16 * 1_200);

        bbr3.policer_pacing_candidate_armed = false;
        bbr3.policer_pacing_transitions = 1;
        bbr3.handle_restart_from_idle(now + Duration::from_millis(1));
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 1_960_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
    }

    #[test]
    fn path_activation_clears_protective_guard() {
        let now = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_pacing_trial_rejected = true;
        bbr3.shallow_loss_declaration_stamp = Some(now);
        bbr3.shallow_loss_declaration_bytes = 16 * 1_200;
        bbr3.on_path_activated();
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_trial_rejected);
        assert_eq!(bbr3.shallow_loss_declaration_stamp, None);
        assert_eq!(bbr3.shallow_loss_declaration_bytes, 0);
    }

    #[test]
    fn learned_policer_wire_rate_is_a_persistent_pacing_target() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.bw = 10_000_000.0;
        bbr3.policer_pacing_scale = POLICER_EPISODE_PACING_SCALE;
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_pacing_ceiling_bytes_per_second = 8_910_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.pacing_rate = 20_000_000.0;
        assert!(!bbr3.full_bw_reached);

        // Startup and ProbeBW-Up gains cannot multiply a learned wire rate
        // back above the shallow policer.
        bbr3.set_pacing_rate_with_gain(STARTUP_PACING_GAIN);
        assert_eq!(bbr3.pacing_rate, 8_910_000.0);
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.set_pacing_rate_with_gain(bbr3.probe_bw_up_pacing_gain);
        assert_eq!(bbr3.pacing_rate, 8_910_000.0);

        // Later loss can depress the live bandwidth model, but it must not
        // recompute and ratchet the episode's absolute ceiling downward.
        bbr3.bw = 6_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.set_pacing_rate_with_gain(STARTUP_PACING_GAIN);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 8_910_000.0);
        assert_eq!(bbr3.pacing_rate, 8_910_000.0);

        // ProbeBW Down/Cruise must not follow a loss-depressed live model
        // below the sustainable fixed episode rate.
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.full_bw_reached = true;
        bbr3.set_pacing_rate_with_gain(1.0);
        assert_eq!(bbr3.pacing_rate, 8_910_000.0);

        // ProbeRTT remains the one intentional underfill state.
        bbr3.state = BbrState::ProbeRtt;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.set_pacing_rate_with_gain(0.5);
        assert_eq!(bbr3.pacing_rate, 2_970_000.0);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);

        // A clean outcome does not recover the episode-fixed ceiling.
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 1_000_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert_eq!(bbr3.policer_pacing_scale, POLICER_EPISODE_PACING_SCALE);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        bbr3.set_pacing_rate_with_gain(STARTUP_PACING_GAIN);
        assert_eq!(bbr3.pacing_rate, 8_910_000.0);

        // An explicit host cap remains authoritative when it is lower than
        // the fixed internal ceiling.
        bbr3.params.pacing_rate_cap_bytes_per_second = 7_000_000;
        bbr3.set_pacing_rate_with_gain(STARTUP_PACING_GAIN);
        assert_eq!(bbr3.pacing_rate, 7_000_000.0);
    }

    #[test]
    fn same_timestamp_low_evidence_burst_preserves_outcome_without_quantum_guard() {
        let now = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.pacing_rate = 13_000_000.0;
        bbr3.policer_window_started = Some(now - POLICER_SAMPLE_WINDOW);
        bbr3.policer_window_acked_bytes = 900_000;
        bbr3.policer_window_lost_bytes = 0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        for pn in 0..15 {
            bbr3.on_packet_lost(1_200, pn, now);
            assert!(!bbr3.shallow_loss_quantum_guard);
            assert_eq!(bbr3.metrics().send_quantum, Some(HIGH_PACE_MAX_QUANTUM));
        }
        bbr3.on_packet_lost(1_200, 15, now);

        assert!(!bbr3.shallow_loss_quantum_guard);
        assert_eq!(
            bbr3.policer_window_started,
            Some(now - POLICER_SAMPLE_WINDOW)
        );
        assert_eq!(bbr3.policer_window_acked_bytes, 900_000);
        assert_eq!(bbr3.policer_window_lost_bytes, 16 * 1_200);
        bbr3.on_packet_lost(1_200, 16, now);
        assert_eq!(bbr3.policer_window_lost_bytes, 17 * 1_200);
        assert_eq!(bbr3.metrics().pacing_rate, Some(13_000_000));
        assert_eq!(bbr3.metrics().send_quantum, Some(HIGH_PACE_MAX_QUANTUM));
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);
    }

    #[test]
    fn multiple_low_evidence_bursts_preserve_horizon_until_aggregate_arms_trial() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(30);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 900_000;

        let first_burst = start + Duration::from_millis(100);
        for pn in 0..16 {
            bbr3.on_packet_lost(1_200, pn, first_burst);
        }
        assert_eq!(bbr3.policer_window_started, Some(start));
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert!(!bbr3.shallow_loss_quantum_guard);

        // Additional ACKs keep the second burst's pre-threshold aggregate
        // below 2%, while its threshold-crossing packet makes the completed
        // 500 ms aggregate exceed 2%.
        bbr3.policer_window_acked_bytes += 950_000;
        let second_burst = start + Duration::from_millis(200);
        for pn in 16..32 {
            bbr3.on_packet_lost(1_200, pn, second_burst);
        }
        assert_eq!(bbr3.policer_window_started, Some(start));
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert!(!bbr3.shallow_loss_quantum_guard);

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);

        assert!(bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_candidate_warmup_windows_remaining, 1);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 9_200_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
    }

    #[test]
    fn lossy_aggregate_before_burst_enters_trial_before_counters_are_reset() {
        let now = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(30);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(now - POLICER_SAMPLE_WINDOW);
        bbr3.policer_window_acked_bytes = 900_000;
        bbr3.policer_window_lost_bytes = 20_000;

        for pn in 0..16 {
            bbr3.on_packet_lost(1_200, pn, now);
        }

        assert!(bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_candidate_warmup_windows_remaining, 1);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 9_200_000.0);
        assert_eq!(bbr3.pacing_rate, 9_200_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);
        assert_eq!(bbr3.policer_window_acked_bytes, 0);
        assert_eq!(bbr3.policer_window_lost_bytes, 1_200);
    }

    #[test]
    fn incomplete_lossy_aggregate_burst_waits_for_normal_window() {
        let now = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(30);
        bbr3.max_bw = 10_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(now - POLICER_SAMPLE_WINDOW / 2);
        bbr3.policer_window_acked_bytes = 900_000;
        bbr3.policer_window_lost_bytes = 20_000;

        for pn in 0..16 {
            bbr3.on_packet_lost(1_200, pn, now);
        }

        assert!(!bbr3.policer_pacing_candidate_armed);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert_eq!(
            bbr3.policer_window_started,
            Some(now - POLICER_SAMPLE_WINDOW / 2)
        );
        assert_eq!(bbr3.policer_window_acked_bytes, 900_000);
        assert_eq!(bbr3.policer_window_lost_bytes, 20_000 + 16 * 1_200);
    }

    #[test]
    fn deep_queued_short_path_gets_bounded_trial_then_rejects() {
        let now = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.bw = 10_000_000.0;
        bbr3.max_bw = 2_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.policer_window_started = Some(now);
        for pn in 0..15 {
            bbr3.on_packet_lost(1_200, pn, now);
        }
        assert_eq!(bbr3.shallow_loss_declaration_bytes, 15 * 1_200);

        // A burst without a complete preceding aggregate closes bypass and
        // resets the outcome window, but does not impose the q12 timer bound.
        bbr3.srtt = Duration::from_millis(30);
        bbr3.on_packet_lost(1_200, 15, now);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert_eq!(bbr3.pacing_rate, 20_000_000.0);
        assert_eq!(bbr3.shallow_loss_declaration_stamp, Some(now));
        assert_eq!(bbr3.shallow_loss_declaration_bytes, 16 * 1_200);

        // The next complete lossy outcome enters a temporary trial from the
        // short minimum RTT despite the currently inflated RTT.
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(now + POLICER_SAMPLE_WINDOW);
        assert!(bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_candidate_warmup_windows_remaining, 1);
        assert_eq!(
            bbr3.policer_pacing_candidate_confirmation_windows_remaining,
            POLICER_TRIAL_CONFIRMATION_WINDOWS
        );
        assert_eq!(bbr3.pacing_rate, 1_840_000.0);
        assert!(bbr3.shallow_loss_quantum_guard);

        // One drain outcome plus four complete inflated/lossy confirmation
        // outcomes exhaust the bounded trial without oscillating quantum.
        for attempt in 1..=POLICER_TRIAL_CONFIRMATION_WINDOWS + 1 {
            bbr3.policer_window_acked_bytes = 800_000;
            bbr3.policer_window_lost_bytes = 200_000;
            bbr3.update_policer_pacing(now + POLICER_SAMPLE_WINDOW * u32::from(attempt + 1));
            if attempt <= POLICER_TRIAL_CONFIRMATION_WINDOWS {
                assert!(bbr3.policer_pacing_candidate_armed);
                assert_eq!(
                    bbr3.policer_pacing_candidate_confirmation_windows_remaining,
                    POLICER_TRIAL_CONFIRMATION_WINDOWS + 1 - attempt
                );
                assert_eq!(bbr3.pacing_rate, 1_840_000.0);
                assert!(bbr3.shallow_loss_quantum_guard);
            }
        }
        assert_eq!(bbr3.policer_pacing_scale, 1.0);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(bbr3.policer_pacing_trial_rejected);
    }

    #[test]
    fn low_random_loss_burst_protects_one_window_without_starting_trial() {
        let start = Instant::now();
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.srtt = Duration::from_millis(6);
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 1_000_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(bbr3.pacing_bypass_armed);

        bbr3.bw = 10_000_000.0;
        bbr3.max_bw = 2_000_000.0;
        bbr3.pacing_rate = 20_000_000.0;
        // The current RTT may already be inflated, but neither it nor an old
        // bypass arm turns a burst into classification evidence.
        bbr3.srtt = Duration::from_millis(10);
        let burst = start + POLICER_SAMPLE_WINDOW + Duration::from_millis(1);
        for pn in 0..15 {
            bbr3.on_packet_lost(1_200, pn, burst);
            assert!(!bbr3.shallow_loss_quantum_guard);
            assert!(bbr3.pacing_bypass_armed);
        }
        bbr3.on_packet_lost(1_200, 15, burst);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.pacing_bypass_armed);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert_eq!(bbr3.pacing_rate, 20_000_000.0);

        // A complete low-random-loss outcome remains on ordinary BBR and can
        // never transition into a fixed policer episode.
        bbr3.policer_window_acked_bytes = 1_000_000;
        bbr3.policer_window_lost_bytes = 2_000;
        bbr3.update_policer_pacing(burst + POLICER_SAMPLE_WINDOW);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_trial_rejected);
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);
    }

    #[test]
    fn split_or_long_rtt_burst_without_aggregate_does_not_arm_quantum_guard() {
        let now = Instant::now();
        let mut split = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        split.min_rtt = Duration::from_millis(5);
        split.srtt = Duration::from_millis(8);
        for pn in 0..15 {
            split.on_packet_lost(1_200, pn, now);
        }
        split.on_packet_lost(1_200, 15, now + Duration::from_nanos(1));
        assert!(!split.shallow_loss_quantum_guard);
        assert_eq!(split.shallow_loss_declaration_bytes, 1_200);

        let mut long_rtt = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        long_rtt.min_rtt = Duration::from_millis(21);
        for pn in 0..16 {
            long_rtt.on_packet_lost(1_200, pn, now);
        }
        assert!(!long_rtt.shallow_loss_quantum_guard);
        assert_eq!(long_rtt.shallow_loss_declaration_bytes, 16 * 1_200);
    }

    #[test]
    fn low_evidence_burst_stays_unguarded_but_lossy_aggregate_fixes_ceiling() {
        let start = Instant::now();
        let mut clean = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        clean.min_rtt = Duration::from_millis(5);
        clean.srtt = Duration::from_millis(8);
        for pn in 0..16 {
            clean.on_packet_lost(1_200, pn, start);
        }
        clean.policer_window_acked_bytes = 4_000_000;
        clean.update_policer_pacing(start + POLICER_SAMPLE_WINDOW - Duration::from_nanos(1));
        assert!(!clean.shallow_loss_quantum_guard);
        clean.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(!clean.shallow_loss_quantum_guard);
        assert_eq!(clean.policer_pacing_transitions, 0);

        let mut policer = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        policer.min_rtt = Duration::from_millis(5);
        policer.srtt = Duration::from_millis(8);
        policer.bw = 10_000_000.0;
        policer.max_bw = 2_000_000.0;
        policer.policer_window_started = Some(start - POLICER_SAMPLE_WINDOW);
        policer.policer_window_acked_bytes = 800_000;
        policer.policer_window_lost_bytes = 200_000;
        for pn in 0..16 {
            policer.on_packet_lost(1_200, pn, start);
        }
        assert!(policer.shallow_loss_quantum_guard);
        assert!(policer.policer_pacing_candidate_armed);
        assert_eq!(policer.policer_pacing_candidate_warmup_windows_remaining, 1);
        assert_eq!(policer.policer_pacing_ceiling_bytes_per_second, 1_840_000.0);

        // The first clean window is still warmup and cannot confirm.
        policer.policer_window_acked_bytes = 1_000_000;
        policer.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(policer.shallow_loss_quantum_guard);
        assert!(policer.policer_pacing_candidate_armed);
        assert_eq!(policer.policer_pacing_candidate_warmup_windows_remaining, 0);
        assert_eq!(policer.policer_pacing_transitions, 0);

        // One non-causal outcome may follow warmup without dropping the cap.
        policer.srtt = Duration::from_millis(11);
        policer.policer_window_acked_bytes = 800_000;
        policer.policer_window_lost_bytes = 200_000;
        policer.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
        assert!(policer.shallow_loss_quantum_guard);
        assert!(policer.policer_pacing_candidate_armed);
        assert_eq!(
            policer.policer_pacing_candidate_confirmation_windows_remaining,
            3
        );
        assert_eq!(policer.policer_pacing_transitions, 0);

        // The second confirmation outcome is clean/currently shallow and fixes.
        policer.srtt = Duration::from_millis(8);
        policer.policer_window_acked_bytes = 1_000_000;
        policer.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 3);
        assert!(policer.shallow_loss_quantum_guard);
        assert!(!policer.policer_pacing_candidate_armed);
        assert_eq!(
            policer.policer_pacing_candidate_confirmation_windows_remaining,
            0
        );
        assert_eq!(policer.policer_pacing_transitions, 1);
        assert_eq!(policer.policer_pacing_ceiling_bytes_per_second, 1_960_000.0);
    }

    #[test]
    fn external_pacing_cap_disables_internal_policer_scale() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.params.pacing_rate_cap_bytes_per_second = 9_700_000;
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.policer_pacing_scale = 0.8;
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_pacing_candidate_armed = true;
        bbr3.policer_pacing_ceiling_bytes_per_second = 8_000_000.0;
        bbr3.policer_pacing_trial_rejected = true;
        bbr3.pacing_bypass_armed = true;
        bbr3.capacity_probe_quantum_guard_armed = true;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;

        let now = start + POLICER_SAMPLE_WINDOW;
        bbr3.update_policer_pacing(now);

        assert_eq!(bbr3.policer_pacing_scale, 1.0);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert!(!bbr3.policer_pacing_trial_rejected);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.pacing_bypass_armed);
        assert!(!bbr3.capacity_probe_quantum_guard_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_window_acked_bytes, 0);
        assert_eq!(bbr3.policer_window_lost_bytes, 0);
        assert_eq!(bbr3.policer_window_started, Some(now));

        bbr3.full_bw_reached = true;
        bbr3.bw = 10_000_000.0;
        bbr3.set_pacing_rate_with_gain(1.0);
        assert_eq!(bbr3.pacing_rate, 9_700_000.0);
    }

    #[test]
    fn clean_window_arms_low_rtt_bypass_but_policer_loss_disarms_it() {
        let start = Instant::now();
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        config.low_rtt_cwnd_floor(512 * 1024);
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.bw = 10_000_000.0;
        bbr3.max_bw = 2_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 1_000_000;

        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(bbr3.pacing_bypass_armed);
        assert!(bbr3.metrics().pacing_rate.is_none());
        assert_eq!(bbr3.window(), 512 * 1024);

        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
        assert!(!bbr3.pacing_bypass_armed);
        assert_eq!(bbr3.policer_pacing_scale, POLICER_EPISODE_PACING_SCALE);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert!(bbr3.policer_pacing_candidate_armed);
        assert!(bbr3.metrics().pacing_rate.is_some());

        bbr3.policer_window_acked_bytes = 900_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 3);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert!(bbr3.policer_pacing_candidate_armed);

        bbr3.policer_window_acked_bytes = 900_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 4);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 1_960_000.0);
    }

    #[test]
    fn confirmed_policer_ambiguous_loss_holds_ceiling() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.max_bw = 3_000_000.0;
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_pacing_ceiling_bytes_per_second = 2_000_000.0;
        bbr3.policer_window_started = Some(start);
        bbr3.policer_window_acked_bytes = 990_000;
        bbr3.policer_window_lost_bytes = 10_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 2_000_000.0);
        assert_eq!(bbr3.policer_pacing_consecutive_loss_windows, 0);
    }

    #[test]
    fn confirmed_policer_tenth_consecutive_loss_revokes_and_latches() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_pacing_ceiling_bytes_per_second = 2_000_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_window_started = Some(start);

        for window in 1..POLICER_CONFIRMED_LOSS_REVOKE_WINDOWS {
            bbr3.policer_window_acked_bytes = 800_000;
            bbr3.policer_window_lost_bytes = 200_000;
            bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * u32::from(window));
            assert_eq!(bbr3.policer_pacing_transitions, 1);
            assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 2_000_000.0);
            assert_eq!(bbr3.policer_pacing_consecutive_loss_windows, window);
            assert!(bbr3.shallow_loss_quantum_guard);
        }

        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(
            start + POLICER_SAMPLE_WINDOW * u32::from(POLICER_CONFIRMED_LOSS_REVOKE_WINDOWS),
        );
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert_eq!(bbr3.policer_pacing_consecutive_loss_windows, 0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(bbr3.policer_pacing_trial_rejected);
    }

    #[test]
    fn confirmed_policer_any_subthreshold_window_clears_loss_streak() {
        let start = Instant::now();
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(5);
        bbr3.srtt = Duration::from_millis(8);
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_pacing_ceiling_bytes_per_second = 2_000_000.0;
        bbr3.policer_window_started = Some(start);

        bbr3.policer_window_acked_bytes = 800_000;
        bbr3.policer_window_lost_bytes = 200_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert_eq!(bbr3.policer_pacing_consecutive_loss_windows, 1);

        bbr3.policer_window_acked_bytes = 990_000;
        bbr3.policer_window_lost_bytes = 10_000;
        bbr3.update_policer_pacing(start + POLICER_SAMPLE_WINDOW * 2);
        assert_eq!(bbr3.policer_pacing_consecutive_loss_windows, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 2_000_000.0);
        assert_eq!(bbr3.policer_pacing_transitions, 1);
    }

    #[test]
    fn send_quantum_uses_live_smss_and_bit_rate_thresholds() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);

        bbr3.pacing_rate = PACING_RATE_1_2MBPS - 1.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 1_200);

        bbr3.pacing_rate = PACING_RATE_1_2MBPS;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 2_400);

        bbr3.pacing_rate = PACING_RATE_24MBPS - 1.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 2_400);

        bbr3.pacing_rate = PACING_RATE_24MBPS;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 15_000);

        bbr3.pacing_rate = 6_120_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 30_600);

        bbr3.pacing_rate = 13_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        bbr3.pacing_rate = 32_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        bbr3.pacing_rate = 100_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        bbr3.pacing_rate = PACING_RATE_1_2MBPS;
        bbr3.on_mtu_update(1_452);
        assert_eq!(bbr3.send_quantum, 2_904);
    }

    #[test]
    fn shallow_loss_guard_uses_one_millisecond_twelve_smss_quantum() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.shallow_loss_quantum_guard = true;

        bbr3.pacing_rate = 13_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 13_000);

        bbr3.pacing_rate = 20_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 12 * 1_200);
        bbr3.on_mtu_update(1_452);
        assert_eq!(bbr3.send_quantum, 12 * 1_452);

        // The stricter budget is scoped to the shallow-loss episode. An
        // ordinary uncapped path returns to the normal high-rate quantum.
        bbr3.shallow_loss_quantum_guard = false;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);
    }

    #[test]
    fn external_pacing_cap_always_uses_safe_quantum_and_removal_restores_normal() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.params.pacing_rate_cap_bytes_per_second = 14_251_004;

        bbr3.pacing_rate = PACING_RATE_1_2MBPS - 1.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 1_200);

        bbr3.pacing_rate = PACING_RATE_1_2MBPS;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 2_400);

        bbr3.pacing_rate = PACING_RATE_24MBPS - 1.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 2_400);

        bbr3.pacing_rate = PACING_RATE_24MBPS;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 3_000);

        // A latched cap above the current controller model still defines the
        // active shaper and therefore retains the shallow-queue-safe quantum.
        bbr3.pacing_rate = 6_120_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 6_120);

        bbr3.pacing_rate = 14_251_004.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 14_251);

        // At a higher binding rate the twelve-packet guard follows the live
        // SMSS once the one-millisecond byte budget would exceed it.
        bbr3.params.pacing_rate_cap_bytes_per_second = 20_000_000;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 12 * 1_200);
        bbr3.on_mtu_update(1_452);
        assert_eq!(bbr3.send_quantum, 12 * 1_452);

        bbr3.params.pacing_rate_cap_bytes_per_second = 0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);
    }

    #[test]
    fn capacity_probe_quantum_guard_waits_for_clean_or_loss_outcome() {
        let start = Instant::now();
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        let config = Arc::new(config);

        let mut clean = Bbr3::new(config.clone(), 1_200);
        let clean_handle = clean.tunables.clone();
        clean.pacing_rate = 100_000_000.0;
        clean.min_rtt = Duration::from_millis(4);
        clean.max_bw = 10_000_000.0;
        clean.pacing_bypass_armed = true;
        clean_handle
            .capacity_probe_generation
            .store(1, Ordering::Relaxed);
        clean_handle.generation.store(1, Ordering::Release);
        clean.refresh_params();
        assert!(clean.capacity_probe_quantum_guard_armed);

        // Exhausting discovery grace, or a later inflated RTT/model sample,
        // cannot create an unprotected normal-quantum window.
        clean.capacity_probe_grace_rounds_remaining = 0;
        clean.min_rtt = Duration::from_millis(8);
        clean.max_bw = CAPACITY_PROBE_QUANTUM_MAX_BW * 2.0;
        clean.pacing_rate = 100_000_000.0;
        clean.set_send_quantum();
        assert_eq!(clean.send_quantum, 12 * 1_200);

        clean.min_rtt = Duration::from_millis(4);
        clean.policer_window_started = Some(start);
        clean.policer_window_acked_bytes = 1_000_000;
        clean.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(!clean.capacity_probe_quantum_guard_armed);
        assert!(!clean.shallow_loss_quantum_guard);
        assert!(clean.pacing_bypass_armed);
        assert!(clean.metrics().pacing_rate.is_none());

        let mut loss = Bbr3::new(config, 1_200);
        loss.capacity_probe_quantum_guard_armed = true;
        loss.min_rtt = Duration::from_millis(4);
        loss.srtt = Duration::from_millis(7);
        loss.max_bw = 2_000_000.0;
        loss.pacing_rate = 100_000_000.0;
        loss.policer_window_started = Some(start);
        loss.policer_window_acked_bytes = 800_000;
        loss.policer_window_lost_bytes = 200_000;
        loss.update_policer_pacing(start + POLICER_SAMPLE_WINDOW);
        assert!(!loss.capacity_probe_quantum_guard_armed);
        assert!(loss.shallow_loss_quantum_guard);
        assert!(!loss.pacing_bypass_armed);
        assert_eq!(loss.policer_pacing_transitions, 0);
        assert!(loss.policer_pacing_candidate_armed);
        assert_eq!(loss.metrics().send_quantum, Some(2 * 1_200));
    }

    #[test]
    fn high_bandwidth_capacity_probe_does_not_arm_quantum_guard() {
        let mut config = Bbr3Config::default();
        config.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.pacing_rate = 100_000_000.0;
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.max_bw = CAPACITY_PROBE_QUANTUM_MAX_BW;
        bbr3.pacing_bypass_armed = true;
        handle.capacity_probe_generation.store(1, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);

        assert!(bbr3.metrics().send_quantum.is_none());
        bbr3.refresh_params();
        assert!(!bbr3.capacity_probe_quantum_guard_armed);
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);
    }

    #[test]
    fn startup_applies_a_new_external_pacing_cap_immediately_and_resizes_quantum() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.state = BbrState::Startup;
        bbr3.full_bw_reached = false;
        bbr3.capacity_probe_grace_rounds_remaining = CAPACITY_PROBE_GRACE_ROUNDS;
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);
        bbr3.capacity_probe_quantum_guard_armed = true;

        handle
            .pacing_rate_cap_bytes_per_second
            .store(5_000_000, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);
        bbr3.refresh_params();

        assert_eq!(bbr3.state, BbrState::Startup);
        assert!(!bbr3.full_bw_reached);
        assert!(!bbr3.capacity_probe_quantum_guard_armed);
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS
        );
        assert_eq!(bbr3.pacing_rate, 5_000_000.0);
        assert_eq!(bbr3.send_quantum, 3_333);

        // Removing the cap does not invent a new bandwidth estimate, but it
        // immediately restores the uncapped quantum for the current rate.
        handle
            .pacing_rate_cap_bytes_per_second
            .store(0, Ordering::Relaxed);
        handle.generation.store(2, Ordering::Release);
        bbr3.refresh_params();
        assert_eq!(bbr3.pacing_rate, 5_000_000.0);
        assert_eq!(bbr3.send_quantum, 25_000);
    }

    #[test]
    fn metrics_observes_a_published_cap_before_round_refresh() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.pacing_rate = 20_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        handle
            .pacing_rate_cap_bytes_per_second
            .store(5_000_000, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);

        let metrics = bbr3.metrics();
        assert_eq!(bbr3.params_generation, 0);
        assert_eq!(bbr3.params.pacing_rate_cap_bytes_per_second, 0);
        assert_eq!(metrics.pacing_rate, Some(5_000_000));
        assert_eq!(metrics.send_quantum, Some(3_333));
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        // Cap publication also uses the safe quantum while the retained rate
        // is just below the new cap, matching the Drain-to-Policer edge that
        // otherwise exposed one more normal 5 ms burst.
        bbr3.pacing_rate = 13_000_000.0;
        handle
            .pacing_rate_cap_bytes_per_second
            .store(13_800_000, Ordering::Relaxed);
        handle.generation.store(2, Ordering::Release);
        let metrics = bbr3.metrics();
        assert_eq!(metrics.pacing_rate, Some(13_000_000));
        assert_eq!(metrics.send_quantum, Some(6 * 1_200));
    }

    #[test]
    fn nonbinding_cap_stays_safe_until_it_is_removed() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.pacing_rate = 13_000_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, HIGH_PACE_MAX_QUANTUM);

        handle
            .pacing_rate_cap_bytes_per_second
            .store(13_800_000, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);

        // The live, not-yet-adopted 0 -> positive edge immediately uses the
        // strict drain quantum.
        assert_eq!(bbr3.metrics().send_quantum, Some(6 * 1_200));
        bbr3.refresh_params();
        assert_eq!(bbr3.send_quantum, 6 * 1_200);
        assert_eq!(
            bbr3.external_cap_drain_rounds_remaining,
            EXTERNAL_CAP_DRAIN_ROUNDS
        );

        // Updating a positive cap does not restart the four-round drain.
        handle
            .pacing_rate_cap_bytes_per_second
            .store(14_000_000, Ordering::Relaxed);
        handle.generation.store(2, Ordering::Release);
        bbr3.refresh_params();
        assert_eq!(
            bbr3.external_cap_drain_rounds_remaining,
            EXTERNAL_CAP_DRAIN_ROUNDS
        );

        // Updates outside a packet-timed round do not consume the drain.
        let packet = test_rate_sample(0, 1_200).last_packet;
        bbr3.next_round_delivered = 1;
        bbr3.update_model_and_state(packet, Instant::now());
        assert_eq!(
            bbr3.external_cap_drain_rounds_remaining,
            EXTERNAL_CAP_DRAIN_ROUNDS
        );

        // Each packet-timed round consumes exactly one drain round. The
        // fourth boundary restores the steady one-millisecond/twelve-SMSS
        // external-cap quantum.
        bbr3.next_round_delivered = 0;
        for remaining in [3, 2, 1] {
            bbr3.update_model_and_state(packet, Instant::now());
            bbr3.set_send_quantum();
            assert_eq!(bbr3.external_cap_drain_rounds_remaining, remaining);
            assert_eq!(bbr3.send_quantum, 6 * 1_200);
        }
        bbr3.update_model_and_state(packet, Instant::now());
        bbr3.set_send_quantum();
        assert_eq!(bbr3.external_cap_drain_rounds_remaining, 0);
        assert_eq!(bbr3.send_quantum, 13_000);

        // Moving farther below the cap still computes the safe quantum from
        // the actual shaping rate rather than returning to the 5 ms budget.
        bbr3.pacing_rate = 6_120_000.0;
        bbr3.set_send_quantum();
        assert_eq!(bbr3.send_quantum, 6_120);

        // Removal keeps the current controller rate while immediately
        // restoring uncapped quantum semantics.
        handle
            .pacing_rate_cap_bytes_per_second
            .store(0, Ordering::Relaxed);
        handle.generation.store(3, Ordering::Release);
        let metrics = bbr3.metrics();
        assert_eq!(metrics.pacing_rate, Some(6_120_000));
        assert_eq!(metrics.send_quantum, Some(30_600));
        bbr3.refresh_params();
        assert_eq!(bbr3.send_quantum, 30_600);
        assert_eq!(bbr3.external_cap_drain_rounds_remaining, 0);
    }

    #[test]
    fn loss_caps_inflight_only_with_explicit_congestion() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.rs = Some(test_rate_sample(90_000, 100_000));

        assert!(!bbr3.is_inflight_too_high());

        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.srtt = Duration::from_millis(28);
        assert!(!bbr3.is_inflight_too_high());

        bbr3.rs = Some(test_rate_sample(3_000, 100_000));
        bbr3.srtt = Duration::from_millis(40);
        assert!(!bbr3.is_inflight_too_high());

        bbr3.srtt = Duration::from_millis(28);
        bbr3.explicit_congestion_in_round = true;
        assert!(bbr3.is_inflight_too_high());

        bbr3.explicit_congestion_in_round = false;
        bbr3.tunables.loss_is_congestion.store(1, Ordering::Relaxed);
        bbr3.tunables.generation.store(1, Ordering::Relaxed);
        bbr3.refresh_params();
        assert!(bbr3.is_inflight_too_high());
    }

    #[test]
    fn erasure_loss_does_not_depress_bbr_lower_bounds_without_ecn() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.max_bw = 1_000_000.0;
        bbr3.bw_latest = 400_000.0;
        bbr3.inflight_latest = 40_000;
        bbr3.cwnd = 100_000;
        bbr3.loss_in_round = true;

        bbr3.adapt_lower_bounds_from_congestion();
        assert!(bbr3.bw_shortterm.is_infinite());
        assert_eq!(bbr3.inflight_shortterm, u64::MAX);

        bbr3.erasure_explicit_congestion_in_round = true;
        bbr3.adapt_lower_bounds_from_congestion();
        assert_eq!(bbr3.bw_shortterm, 700_000.0);
        assert_eq!(bbr3.inflight_shortterm, 70_000);
    }

    #[test]
    fn isolated_random_loss_cannot_pin_an_already_small_flight() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(21);
        bbr3.rs = Some(test_rate_sample(1_200, 4_800));

        assert!(!bbr3.is_inflight_too_high());

        bbr3.explicit_congestion_in_round = true;
        assert!(bbr3.is_inflight_too_high());
    }

    #[test]
    fn high_latency_low_queue_path_does_not_treat_radio_loss_as_congestion() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(85);
        bbr3.srtt = Duration::from_millis(90);
        bbr3.rs = Some(test_rate_sample(40_000, 100_000));

        assert!(!bbr3.is_inflight_too_high());

        bbr3.srtt = Duration::from_millis(130);
        assert!(!bbr3.is_inflight_too_high());

        bbr3.explicit_congestion_in_round = true;
        assert!(bbr3.is_inflight_too_high());
    }

    #[test]
    fn high_rtt_loss_does_not_end_startup_before_capacity_is_discovered() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::Startup;
        bbr3.round_start = true;
        bbr3.min_rtt = Duration::from_millis(85);
        bbr3.srtt = Duration::from_millis(92);
        bbr3.bw = 100_000.0;
        bbr3.full_bw = 100_000.0;
        let mut lossy_sample = test_rate_sample(12_000, 100_000);
        lossy_sample.delivery_rate = 105_000.0;
        lossy_sample.newly_lost = 12_000;
        bbr3.rs = Some(lossy_sample);

        for _ in 0..MAX_FULL_BW_COUNT + 1 {
            bbr3.check_full_bw_reached();
        }
        assert_eq!(bbr3.full_bw_count, 0);
        assert!(!bbr3.full_bw_reached);

        let mut clean_sample = lossy_sample;
        clean_sample.lost = 0;
        clean_sample.newly_lost = 0;
        bbr3.rs = Some(clean_sample);
        for _ in 0..MAX_FULL_BW_COUNT {
            bbr3.check_full_bw_reached();
        }
        assert!(bbr3.full_bw_reached);
    }

    #[test]
    fn short_rtt_policer_loss_still_ends_startup_normally() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::Startup;
        bbr3.round_start = true;
        bbr3.min_rtt = Duration::from_millis(4);
        bbr3.srtt = Duration::from_millis(7);
        bbr3.bw = 100_000.0;
        bbr3.full_bw = 100_000.0;
        let mut sample = test_rate_sample(12_000, 100_000);
        sample.delivery_rate = 105_000.0;
        sample.newly_lost = 12_000;
        bbr3.rs = Some(sample);

        for _ in 0..MAX_FULL_BW_COUNT {
            bbr3.check_full_bw_reached();
        }
        assert!(bbr3.full_bw_reached);
    }

    #[test]
    fn low_queue_loss_ignores_even_an_old_packets_cumulative_history() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(35);
        bbr3.srtt = Duration::from_millis(37);
        let mut sample = test_rate_sample(20_000, 10_000);
        sample.newly_lost = 1_200;
        bbr3.rs = Some(sample);

        assert!(!bbr3.is_inflight_too_high());

        bbr3.srtt = Duration::from_millis(60);
        assert!(!bbr3.is_inflight_too_high());
    }

    #[test]
    fn queue_delay_guard_uses_live_minimum_rtt_without_an_operator_threshold() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.params.loss_is_congestion = true;

        assert!(!bbr3.queue_delay_guard_triggered());
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(30);
        bbr3.bw = 1_000_000.0;
        assert!(!bbr3.queue_delay_guard_triggered());

        bbr3.srtt = Duration::from_micros(30_001);
        assert!(bbr3.queue_delay_guard_triggered());
    }

    #[test]
    fn queue_delay_guard_drains_startup_and_stops_only_upward_probe_bw() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.params.loss_is_congestion = true;
        let now = Instant::now();
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.bw = 1_000_000.0;

        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::Drain);
        assert!(bbr3.full_bw_reached);
        assert_eq!(bbr3.queue_delay_guard_transitions, 1);

        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Up);
        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Down));
        assert_eq!(bbr3.queue_delay_guard_transitions, 2);

        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Cruise));
        assert_eq!(bbr3.queue_delay_guard_transitions, 2);
    }

    #[test]
    fn loss_tolerant_startup_keeps_four_x_queue_guard_allowance() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.bw = 1_000_000.0;

        assert!(!bbr3.params.loss_is_congestion);
        assert_eq!(bbr3.state, BbrState::Startup);
        assert!(!bbr3.queue_delay_guard_triggered());
        bbr3.srtt = Duration::from_millis(60);
        assert!(!bbr3.queue_delay_guard_triggered());
        bbr3.srtt = Duration::from_micros(60_001);
        assert!(bbr3.queue_delay_guard_triggered());
    }

    #[test]
    fn loss_tolerant_probe_bw_up_uses_two_x_queue_guard_and_enters_down() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Up);
        bbr3.full_bw_reached = true;
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.bw = 1_000_000.0;

        assert!(!bbr3.params.loss_is_congestion);
        assert!(!bbr3.queue_delay_guard_triggered());
        bbr3.srtt = Duration::from_micros(40_001);
        assert!(bbr3.queue_delay_guard_triggered());
        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Down));
        assert!(bbr3.full_bw_reached);
        assert_eq!(bbr3.queue_delay_guard_transitions, 1);
    }

    #[test]
    fn random_loss_during_probe_bw_does_not_restart_startup() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Up);
        bbr3.full_bw_reached = true;
        bbr3.min_rtt = Duration::from_millis(85);
        bbr3.srtt = Duration::from_millis(256);
        bbr3.bw = 1_000_000.0;
        bbr3.rs = Some(test_rate_sample(12_000, 100_000));

        assert!(!bbr3.is_inflight_too_high());
        bbr3.check_queue_delay_guard(now);
        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Down));
        assert!(bbr3.full_bw_reached);
    }

    #[test]
    fn inflight_at_loss_saturates_when_sample_is_already_over_threshold() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.rs = Some(test_rate_sample(50_000, 100_000));

        assert_eq!(bbr3.inflight_at_loss(1_200), 98_800);
    }

    #[test]
    fn lost_packet_publishes_updated_sample_before_threshold_decision() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.explicit_congestion_in_round = true;
        bbr3.rs = Some(test_rate_sample(0, 1_200));
        bbr3.bw_probe_samples = true;
        bbr3.on_packet_sent(now, 1_200, 1);

        bbr3.on_packet_lost(1_200, 1, now);

        assert!(!bbr3.bw_probe_samples);
        assert_eq!(bbr3.rs.expect("rate sample").lost, 1_200);
    }

    #[test]
    fn first_packet_after_idle_exits_an_expired_probe_rtt_before_accounting_send() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        bbr3.state = BbrState::ProbeRtt;
        bbr3.cwnd = bbr3.min_pipe_cwnd;
        bbr3.prior_cwnd = 64 * 1024;
        bbr3.app_limited = 1;
        bbr3.probe_rtt_done_stamp = now.checked_sub(Duration::from_millis(1));

        bbr3.on_packet_sent(now, 1_200, 1);

        assert!(bbr3.idle_restart);
        assert_eq!(bbr3.state, BbrState::Startup);
        assert_eq!(bbr3.cwnd, 64 * 1024);
        assert_eq!(bbr3.inflight, 1_200);
    }

    #[test]
    fn max_bw_virtual_time_advances_once_per_probe_bw_cycle() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Down);
        bbr3.ack_phase = AckPhase::ProbeStopping;
        bbr3.round_start = true;
        bbr3.rs = Some(test_rate_sample(1_000_000, 24_000));

        bbr3.adapt_long_term_model();
        assert_eq!(bbr3.cycle_count, 1);
        assert_eq!(bbr3.ack_phase, AckPhase::ProbeFeedback);

        // More packet-timed rounds in Down/Cruise are still part of the same
        // ProbeBW cycle and must not age the max-bw filter again.
        bbr3.adapt_long_term_model();
        assert_eq!(bbr3.cycle_count, 1);

        bbr3.start_probe_bw_down(Instant::now());
        bbr3.round_start = true;
        bbr3.rs = Some(test_rate_sample(1_100_000, 24_000));
        bbr3.adapt_long_term_model();
        assert_eq!(bbr3.cycle_count, 2);
    }

    #[test]
    fn no_hint_reprobe_uses_long_rtt_initial_window_rate_not_one_millisecond() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.min_rtt = Duration::from_millis(85);
        bbr3.max_bw = 25_000.0;
        let old_one_millisecond_rate = bbr3.startup_pacing_gain * bbr3.initial_cwnd as f64 / 0.001;
        let expected =
            bbr3.startup_pacing_gain * (bbr3.initial_cwnd as f64 / bbr3.min_rtt.as_secs_f64());

        bbr3.restart_capacity_discovery();

        assert!((bbr3.pacing_rate - expected).abs() < 1.0);
        assert!(bbr3.pacing_rate < old_one_millisecond_rate / 10.0);
    }

    #[test]
    fn established_idle_probe_keeps_its_validated_bandwidth_model() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.max_bw = 10_000_000.0;
        bbr3.bw = 10_000_000.0;
        bbr3.pacing_rate = 10_000_000.0;
        bbr3.app_limited = 1;

        bbr3.on_packet_sent(Instant::now(), 1_200, 2);

        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Cruise));
        assert!(bbr3.full_bw_reached);
    }

    #[test]
    fn loss_uses_packet_time_app_limited_marker() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        let mut sample = test_rate_sample(0, 1_200);
        sample.is_app_limited = true;
        bbr3.rs = Some(sample);
        bbr3.bw_probe_samples = true;
        bbr3.packets.push_back(BbrPacket {
            delivered: 0,
            delivered_time: now,
            first_send_time: now,
            send_time: now,
            is_app_limited: false,
            tx_in_flight: 1_200,
            packet_number: 1,
            size: 1_200,
            lost: 0,
            acknowledged: false,
            round_count: 0,
        });

        bbr3.process_lost_packet(1_200, 0, now);

        assert!(
            !bbr3.rs.expect("loss sample").is_app_limited,
            "losses and ACKs use their packet-time marker, not a later scheduler state"
        );
    }

    #[test]
    fn ack_batch_publishes_its_completed_delivery_rate_before_model_update() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let rtt = RttEstimator::new(Duration::from_millis(100));
        let start = Instant::now();

        bbr3.on_packet_sent(start, 1_200, 1);
        let first_ack = start + Duration::from_millis(10);
        bbr3.on_ack(first_ack, start, 1_200, 1, false, &rtt);
        assert_eq!(bbr3.delivered, 1_200, "the first ACK is delivered data too");
        bbr3.on_end_acks(first_ack, 0, false, Some(1));

        let second_sent = start + Duration::from_millis(11);
        let third_sent = start + Duration::from_millis(12);
        bbr3.on_packet_sent(second_sent, 1_200, 2);
        bbr3.on_packet_sent(third_sent, 1_200, 3);
        let batch_ack = start + Duration::from_millis(22);
        bbr3.on_ack(batch_ack, second_sent, 1_200, 2, false, &rtt);
        bbr3.on_ack(batch_ack, third_sent, 1_200, 3, false, &rtt);

        assert_eq!(
            bbr3.rs.expect("pending rate sample").delivery_rate,
            0.0,
            "per-packet ACK callbacks must not reuse the preceding batch's rate"
        );
        bbr3.on_end_acks(batch_ack, 0, false, Some(3));

        let sample = bbr3.rs.expect("completed rate sample");
        assert_eq!(sample.delivered, 2_400);
        assert_eq!(sample.interval, Duration::from_millis(11));
        let expected_rate = 2_400.0 / 0.011;
        assert!(
            (sample.delivery_rate - expected_rate).abs() < 0.001,
            "actual={} expected={expected_rate}",
            sample.delivery_rate
        );
        assert!((bbr3.max_bw - expected_rate.round()).abs() < 0.001);
    }

    #[test]
    fn ack_history_reclaims_only_the_contiguous_resolved_prefix() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        for packet_number in 1..=3 {
            bbr3.on_packet_sent(now, 1_200, packet_number);
        }

        bbr3.packets[1].acknowledged = true;
        bbr3.on_end_acks(now, 2_400, false, Some(2));
        assert_eq!(
            bbr3.packets.len(),
            3,
            "an unresolved prefix gap is retained"
        );

        bbr3.packets[0].acknowledged = true;
        bbr3.on_end_acks(now, 1_200, false, Some(2));
        assert_eq!(bbr3.packets.len(), 1);
        assert_eq!(bbr3.packets.front().unwrap().packet_number, 3);
    }

    #[test]
    fn runtime_params_refresh_only_after_generation_and_round_boundary() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let handle = bbr3.tunables.clone();
        handle
            .probe_bw_up_pacing_gain_milli
            .store(1_500, Ordering::Relaxed);

        bbr3.refresh_params();
        assert_eq!(bbr3.params.probe_bw_up_pacing_gain, 1.25);

        handle.generation.store(1, Ordering::Relaxed);
        bbr3.next_round_delivered = 10;
        let mut packet = test_rate_sample(0, 12_000).last_packet;
        packet.delivered = 9;
        bbr3.update_model_and_state(packet, Instant::now());
        assert_eq!(bbr3.params_generation, 0);

        packet.delivered = 10;
        bbr3.update_model_and_state(packet, Instant::now());
        assert_eq!(bbr3.params_generation, 1);
        assert_eq!(bbr3.params.probe_bw_up_pacing_gain, 1.5);
    }

    #[test]
    fn capacity_probe_generation_restarts_startup_once_per_published_request() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.full_bw = 100_000.0;
        bbr3.full_bw_count = 3;
        bbr3.min_rtt = Duration::from_millis(25);
        bbr3.max_bw = 100_000.0;
        bbr3.bw = 100_000.0;

        handle.capacity_probe_generation.store(1, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);
        bbr3.refresh_params();

        assert_eq!(bbr3.params.capacity_probe_generation, 1);
        assert_eq!(bbr3.state, BbrState::Startup);
        assert!(!bbr3.full_bw_reached);
        assert_eq!(bbr3.full_bw, 0.0);
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS
        );

        // Neither a packet-timed round without a rate sample nor an
        // application-limited sample consumes semantic discovery grace.
        bbr3.round_start = true;
        bbr3.check_full_bw_reached();
        let mut sample = test_rate_sample(0, 12_000);
        sample.delivery_rate = 100_000.0;
        sample.is_app_limited = true;
        bbr3.rs = Some(sample);
        bbr3.check_full_bw_reached();
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS
        );

        // A syntactically completed sample with no usable delivery-rate
        // estimate (for example the first ACK or a sub-min-RTT interval) is
        // not a valid discovery round either.
        sample.is_app_limited = false;
        sample.delivery_rate = 0.0;
        bbr3.rs = Some(sample);
        bbr3.check_full_bw_reached();
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS
        );
        assert_eq!(bbr3.full_bw_count, 0);
        assert!(!bbr3.full_bw_reached);

        sample.delivery_rate = 100_000.0;
        sample.is_app_limited = false;
        bbr3.rs = Some(sample);
        for _ in 0..MAX_FULL_BW_COUNT {
            bbr3.check_full_bw_reached();
        }
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS - MAX_FULL_BW_COUNT as u8
        );
        assert_eq!(bbr3.full_bw_count, 0);
        assert!(!bbr3.full_bw_reached);

        // Publishing unrelated tunable changes with the same request
        // generation must not repeatedly restart an established model.
        bbr3.enter_drain();
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        handle
            .probe_bw_up_pacing_gain_milli
            .store(1_300, Ordering::Relaxed);
        handle.generation.store(2, Ordering::Release);
        bbr3.refresh_params();

        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Cruise));
        assert!(bbr3.full_bw_reached);
        assert_eq!(bbr3.capacity_probe_grace_rounds_remaining, 0);
    }

    #[test]
    fn capacity_probe_generation_resets_candidate_fixed_and_protective_guard() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let handle = bbr3.tunables.clone();
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.policer_pacing_candidate_armed = true;
        bbr3.policer_pacing_scale = POLICER_EPISODE_PACING_SCALE;
        bbr3.policer_pacing_ceiling_bytes_per_second = 12_540_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_pacing_trial_rejected = true;
        bbr3.shallow_loss_declaration_stamp = Some(Instant::now());
        bbr3.shallow_loss_declaration_bytes = 16 * 1_200;

        handle.capacity_probe_generation.store(1, Ordering::Relaxed);
        handle.generation.store(1, Ordering::Release);
        bbr3.refresh_params();

        assert_eq!(bbr3.params.capacity_probe_generation, 1);
        assert_eq!(bbr3.state, BbrState::Startup);
        assert!(!bbr3.full_bw_reached);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_trial_rejected);
        assert_eq!(bbr3.shallow_loss_declaration_stamp, None);
        assert_eq!(bbr3.shallow_loss_declaration_bytes, 0);
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS
        );

        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_pacing_ceiling_bytes_per_second = 12_540_000.0;
        bbr3.shallow_loss_quantum_guard = true;
        bbr3.policer_pacing_trial_rejected = true;
        handle.capacity_probe_generation.store(2, Ordering::Relaxed);
        handle.generation.store(2, Ordering::Release);
        bbr3.refresh_params();

        assert_eq!(bbr3.state, BbrState::Startup);
        assert!(!bbr3.full_bw_reached);
        assert!(!bbr3.policer_pacing_candidate_armed);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.shallow_loss_quantum_guard);
        assert!(!bbr3.policer_pacing_trial_rejected);
        assert_eq!(
            bbr3.capacity_probe_grace_rounds_remaining,
            CAPACITY_PROBE_GRACE_ROUNDS
        );
    }

    #[test]
    fn capacity_probe_grace_updates_growth_then_requires_normal_plateau() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.restart_capacity_discovery();
        bbr3.capacity_probe_grace_rounds_remaining = CAPACITY_PROBE_GRACE_ROUNDS;
        bbr3.round_start = true;
        let mut sample = test_rate_sample(0, 12_000);
        let mut delivery_rate = 100_000.0;

        for expected_remaining in (0..CAPACITY_PROBE_GRACE_ROUNDS).rev() {
            sample.delivery_rate = delivery_rate;
            bbr3.rs = Some(sample);
            bbr3.check_full_bw_reached();
            assert_eq!(
                bbr3.capacity_probe_grace_rounds_remaining,
                expected_remaining
            );
            assert_eq!(bbr3.full_bw, delivery_rate);
            assert_eq!(bbr3.full_bw_count, 0);
            assert!(!bbr3.full_bw_reached);
            delivery_rate *= 2.0;
        }

        // Once all eight valid discovery rounds have elapsed, the unchanged
        // delivery rate uses the ordinary three-round Startup plateau rule.
        sample.delivery_rate = bbr3.full_bw;
        bbr3.rs = Some(sample);
        for expected_count in 1..MAX_FULL_BW_COUNT {
            bbr3.check_full_bw_reached();
            bbr3.check_startup_done();
            assert_eq!(bbr3.state, BbrState::Startup);
            assert_eq!(bbr3.full_bw_count, expected_count);
        }
        bbr3.check_full_bw_reached();
        bbr3.check_startup_done();
        assert_eq!(bbr3.state, BbrState::Drain);
        assert!(bbr3.full_bw_reached);
        assert_eq!(bbr3.capacity_probe_grace_rounds_remaining, 0);
    }

    #[test]
    fn queue_guard_can_end_capacity_probe_during_grace() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.restart_capacity_discovery();
        bbr3.capacity_probe_grace_rounds_remaining = CAPACITY_PROBE_GRACE_ROUNDS;
        bbr3.params.loss_is_congestion = true;
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.srtt = Duration::from_millis(40);
        bbr3.bw = 1_000_000.0;

        bbr3.check_queue_delay_guard(Instant::now());

        assert_eq!(bbr3.state, BbrState::Drain);
        assert!(bbr3.full_bw_reached);
        assert_eq!(bbr3.queue_delay_guard_transitions, 1);
        assert_eq!(bbr3.capacity_probe_grace_rounds_remaining, 0);
    }

    #[test]
    fn ordinary_startup_keeps_the_three_round_plateau_rule() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.restart_capacity_discovery();
        bbr3.round_start = true;
        bbr3.full_bw = 100_000.0;
        let mut sample = test_rate_sample(0, 12_000);
        sample.delivery_rate = 100_000.0;
        bbr3.rs = Some(sample);

        for _ in 0..MAX_FULL_BW_COUNT {
            bbr3.check_full_bw_reached();
        }

        assert_eq!(bbr3.capacity_probe_grace_rounds_remaining, 0);
        assert!(bbr3.full_bw_reached);
    }

    #[test]
    fn runtime_caps_apply_to_pacing_and_cwnd() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.tunables
            .pacing_rate_cap_bytes_per_second
            .store(200_000, Ordering::Relaxed);
        bbr3.tunables
            .cwnd_floor_bytes
            .store(20_000, Ordering::Relaxed);
        bbr3.tunables
            .cwnd_cap_bytes
            .store(24_000, Ordering::Relaxed);
        bbr3.tunables.generation.store(1, Ordering::Relaxed);
        bbr3.refresh_params();

        bbr3.full_bw_reached = true;
        bbr3.bw = 1_000_000.0;
        bbr3.pacing_rate = 1.0;
        bbr3.set_pacing_rate_with_gain(1.25);
        assert_eq!(bbr3.pacing_rate, 200_000.0);

        bbr3.cwnd = 1;
        bbr3.set_cwnd();
        assert_eq!(bbr3.cwnd, 20_000);
        bbr3.cwnd = 100_000;
        bbr3.set_cwnd();
        assert_eq!(bbr3.cwnd, 24_000);
    }

    #[test]
    fn runtime_cwnd_floor_also_unsticks_a_low_pacing_model() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.params.cwnd_floor_bytes = 200_000;
        bbr3.min_rtt = Duration::from_millis(20);
        bbr3.cwnd_gain = 2.0;
        bbr3.full_bw_reached = true;
        bbr3.bw = 100_000.0;
        bbr3.pacing_rate = 100_000.0;

        bbr3.set_pacing_rate_with_gain(1.0);

        assert_eq!(bbr3.pacing_rate, 5_000_000.0);
    }

    #[test]
    fn probe_rtt_window_ignores_runtime_and_bypass_floors_and_completes() {
        let mut config = Bbr3Config::default();
        config
            .pacing_bypass_below_rtt(Some(Duration::from_millis(5)))
            .low_rtt_cwnd_floor(256 * 1024);
        let mut bbr3 = Bbr3::new(Arc::new(config), 1_200);
        let now = Instant::now();
        bbr3.params.cwnd_floor_bytes = 512 * 1024;
        bbr3.min_rtt = Duration::from_millis(1);
        bbr3.bw = 10_000_000.0;
        bbr3.pacing_bypass_armed = true;
        bbr3.enter_probe_rtt();
        bbr3.cwnd = 1024 * 1024;

        let probe_cwnd = bbr3.probe_rtt_cwnd();
        bbr3.set_cwnd();
        assert_eq!(bbr3.cwnd, probe_cwnd);
        assert_eq!(bbr3.window(), probe_cwnd);
        assert!(!bbr3.pacing_bypass_active());

        bbr3.inflight = probe_cwnd;
        bbr3.handle_probe_rtt(now);
        assert!(bbr3.probe_rtt_done_stamp.is_some());
        bbr3.round_start = true;
        bbr3.handle_probe_rtt(now + bbr3.probe_rtt_duration + Duration::from_millis(1));
        assert_ne!(bbr3.state, BbrState::ProbeRtt);
    }

    #[test]
    fn confirmed_policer_defers_expired_probe_rtt_until_episode_ends() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        let now = Instant::now();
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.probe_rtt_expired = true;
        bbr3.policer_pacing_transitions = 1;

        bbr3.check_probe_rtt(now);
        assert_eq!(bbr3.state, BbrState::ProbeBw(ProbeBwSubstate::Cruise));
        assert!(bbr3.probe_rtt_expired);

        bbr3.policer_pacing_transitions = 0;
        bbr3.check_probe_rtt(now + Duration::from_millis(1));
        assert_eq!(bbr3.state, BbrState::ProbeRtt);
    }

    #[test]
    fn startup_hint_warms_pacing_and_window_and_handles_are_path_local() {
        let template = Arc::new(Bbr3Tunables::default());
        template
            .startup_bw_hint_bytes_per_second
            .store(1_000_000, Ordering::Relaxed);
        template
            .pacing_rate_cap_bytes_per_second
            .store(2_000_000, Ordering::Relaxed);
        let mut config = Bbr3Config::default();
        config.tunables_template(Some(template));
        let config = Arc::new(config);
        let first = Bbr3::new(config.clone(), 1_200);
        let second = Bbr3::new(config, 1_200);

        assert_eq!(first.initial_cwnd, 333_000);
        assert_eq!(first.pacing_rate, 2_000_000.0);
        assert!(!Arc::ptr_eq(&first.tunables, &second.tunables));
        let erased = first.tunables().expect("BBR3 tuning handle");
        assert!(erased.downcast::<Bbr3Tunables>().is_ok());
    }

    #[test]
    fn activating_warm_path_restarts_capacity_discovery() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.state = BbrState::ProbeBw(ProbeBwSubstate::Cruise);
        bbr3.full_bw_reached = true;
        bbr3.full_bw = 50_000.0;
        bbr3.full_bw_count = 3;
        bbr3.cwnd = bbr3.min_pipe_cwnd;
        bbr3.pacing_rate = 50_000.0;
        bbr3.inflight_longterm = bbr3.min_pipe_cwnd;
        bbr3.inflight_shortterm = bbr3.min_pipe_cwnd;
        bbr3.bw_shortterm = 50_000.0;
        bbr3.policer_pacing_scale = 0.5;
        bbr3.policer_pacing_transitions = 1;
        bbr3.policer_pacing_ceiling_bytes_per_second = 40_000.0;
        bbr3.capacity_probe_quantum_guard_armed = true;
        bbr3.external_cap_drain_rounds_remaining = EXTERNAL_CAP_DRAIN_ROUNDS;
        bbr3.delivered = 1_000_000;

        bbr3.on_path_activated();

        assert_eq!(bbr3.state, BbrState::Startup);
        assert!(!bbr3.full_bw_reached);
        assert_eq!(bbr3.full_bw, 0.0);
        assert_eq!(bbr3.full_bw_count, 0);
        assert!(bbr3.cwnd >= bbr3.initial_cwnd);
        assert_eq!(bbr3.inflight_longterm, u64::MAX);
        assert_eq!(bbr3.inflight_shortterm, u64::MAX);
        assert!(bbr3.bw_shortterm.is_infinite());
        assert_eq!(bbr3.policer_pacing_scale, 1.0);
        assert_eq!(bbr3.policer_pacing_transitions, 0);
        assert_eq!(bbr3.policer_pacing_ceiling_bytes_per_second, 0.0);
        assert!(!bbr3.capacity_probe_quantum_guard_armed);
        assert_eq!(bbr3.external_cap_drain_rounds_remaining, 0);
        // With neither an RTT sample nor a delivery model, activation keeps
        // the existing safe rate instead of synthesizing IW/1ms.
        assert_eq!(bbr3.pacing_rate, 50_000.0);
    }

    #[test]
    fn snapshot_reports_runtime_generation_and_clamps() {
        let mut bbr3 = Bbr3::new(Arc::new(Bbr3Config::default()), 1_200);
        bbr3.tunables
            .loss_thresh_milli
            .store(u32::MAX, Ordering::Relaxed);
        bbr3.tunables.generation.store(7, Ordering::Relaxed);
        bbr3.refresh_params();
        let snapshot = bbr3.metrics().snapshot.expect("BBR3 snapshot");
        assert_eq!(snapshot.params_generation, 7);
        assert_eq!(snapshot.clamped_writes, 1);
        assert_eq!(snapshot.state, 0);
    }
}
