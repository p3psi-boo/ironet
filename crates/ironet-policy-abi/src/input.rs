//! Everything the host hands to a policy for one `decide` call.

use serde::{Deserialize, Serialize};

use crate::{
    EGRESS_PRIORITY_MAX, EffectiveActionViewV1, FEC_DATA_CELLS_MAX, FEC_PARITY_CELLS_MAX,
    FEC_PARITY_PER_MILLE_CAP, ObjectiveV1, POLICY_ABI_MAJOR_V1, POLICY_ABI_MINOR_V1,
    POLICY_EXTENSION_MAX_COUNT, POLICY_EXTENSION_MAX_PAYLOAD_BYTES, POLICY_STATE_MAX_BYTES,
    PathReliabilityV1,
};

/// One TLV extension entry. Unknown tags are ignored by the receiver and, on
/// the candidate side, recorded in `ClampReportV1`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyExtensionV1 {
    /// Extension tag registered in the policy SDK.
    pub tag: u16,
    /// Opaque payload, at most [`POLICY_EXTENSION_MAX_PAYLOAD_BYTES`] bytes.
    pub payload: Vec<u8>,
}

/// Telemetry for one peer path, one tick, with the direction of every
/// measurement made explicit in its name.
///
/// `path_epoch` and `reliability` are not repeated here; they live on
/// [`PolicyInputV1`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyTelemetryV1 {
    // -- path --------------------------------------------------------------
    /// Smoothed path RTT.
    pub path_rtt_micros: u64,
    /// Minimum RTT observed for this path epoch.
    pub path_min_rtt_micros: u64,
    /// Estimated standing queue delay (`rtt - min_rtt` class signal).
    pub path_queue_delay_micros: u64,

    // -- local transmit direction -----------------------------------------
    /// Locally transmitted QUIC wire rate (delivery rate); all TX scheduling,
    /// FEC and producer-admission decisions derive from this direction.
    pub local_tx_wire_rate_bytes_per_second: u64,
    /// Application payload rate offered by the local TUN producer.
    pub local_tx_tun_ingress_bytes_per_second: u64,
    /// Local real (non-cover) traffic rate on the wire.
    pub local_tx_real_traffic_bytes_per_second: u64,
    /// Local PacketTrain build rate.
    pub local_tx_train_build_bytes_per_second: u64,
    /// Locally transmitted packets per second.
    pub local_tx_packets_per_second: u64,
    /// QUIC lost-packet ratio on the local transmit direction.
    pub local_tx_loss_ppm: u32,
    /// Longest consecutive lost Cell run seen in the latest interval.
    pub local_tx_burst_loss_cells: u16,
    /// Mean TUN record size entering the local scheduler.
    pub local_tx_average_record_bytes: u64,
    /// Share of local ingress that arrived as GSO super-records.
    pub local_tx_gso_ingress_ratio_ppm: u32,
    /// Bytes staged in the local PacketTrain (bulk) queue.
    pub local_tx_packet_train_queue_bytes: u64,
    /// Bytes staged in the local latency lane.
    pub local_tx_latency_queue_bytes: u64,
    /// Mean delay Bulk waited behind latency traffic.
    pub local_tx_bulk_preemption_delay_average_micros: u64,
    /// Controller pacing rate snapshot.
    pub local_tx_controller_pacing_rate_bytes_per_second: u64,
    /// Controller send quantum snapshot.
    pub local_tx_controller_send_quantum_bytes: u64,
    /// Controller state discriminant (BBR phase), opaque to the policy.
    pub local_tx_controller_state: u8,
    /// Controller long-term bandwidth estimate.
    pub local_tx_controller_bw_bytes_per_second: u64,
    /// Controller long-term in-flight estimate.
    pub local_tx_controller_inflight_longterm_bytes: u64,
    /// Queue-guard transitions since the previous tick.
    pub local_tx_controller_guard_transitions_delta: u64,
    /// Controller was application limited during the interval.
    pub local_tx_controller_app_limited: bool,
    /// Generation counter of the tunables the controller last read.
    pub local_tx_controller_tunables_generation: u64,
    /// Generation counter of the params the controller last published.
    pub local_tx_controller_params_generation: u64,
    /// Cumulative tunable writes the controller had to clamp.
    pub local_tx_controller_clamped_writes: u64,

    // -- local receive direction ------------------------------------------
    /// Locally received QUIC wire rate; sizes RX memory/coalescing only.
    pub local_rx_wire_rate_bytes_per_second: u64,
    /// Incomplete PacketTrains evicted by the local receiver since the prior
    /// tick because the aggregate byte budget was exhausted.
    pub local_rx_reassembly_pressure_evictions: u64,

    // -- remote feedback ---------------------------------------------------
    /// Payload bytes delivered by the remote receiver per second; the
    /// end-to-end goodput reward, excluding FEC/Repair/cover.
    pub remote_goodput_bytes_per_second: u64,
    /// Gaps that remained at the remote receiver when PacketTrains closed.
    pub remote_residual_loss_ppm: u32,
    /// Reordering ratio observed by the remote receiver.
    pub remote_reorder_ppm: u32,
    /// FEC stripes the remote receiver expired unrecovered since last tick.
    pub remote_expired_stripes_delta: u64,
    /// Parity the remote receiver discarded unused.
    pub remote_wasted_parity_per_mille: u16,
    /// Share of remote gaps recovered by FEC.
    pub remote_fec_recovery_per_mille: u16,
    /// Share of Repair requests the remote could satisfy from cache.
    pub remote_repair_hit_per_mille: u16,
    /// Cumulative matched Repair responses observed for this path epoch.
    pub remote_repair_completed_requests: u64,
    /// Mean Repair request-to-response latency in the latest interval; zero
    /// means no request completed.
    pub remote_repair_response_latency_micros: u64,

    // -- latency lane sojourn ----------------------------------------------
    /// Local semantic-latency queue sojourn p50 over the latest interval.
    pub latency_sojourn_p50_micros: u64,
    /// Local semantic-latency queue sojourn p95.
    pub latency_sojourn_p95_micros: u64,
    /// Local semantic-latency queue sojourn p99.
    pub latency_sojourn_p99_micros: u64,
    /// The latency lane was queued or served during the latest interval.
    pub latency_queue_recently_nonempty: bool,

    // -- host --------------------------------------------------------------
    /// Host CPU utilisation attributed to this daemon.
    pub host_cpu_utilization_per_mille: u16,
}

/// Host-computed utility of the previous tick. This is the only reward
/// signal promotion, shadow advantage and rollback accept. All values are
/// fixed point (`milli` = value x 1000), saturating.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostUtilityV1 {
    /// Objective whose weights produced the values below.
    pub objective: ObjectiveV1,
    /// `false` on the first tick of a path epoch (no previous sample).
    pub valid: bool,
    /// Weighted total utility x 1000 (signed).
    pub utility_milli: i32,
    /// Throughput term x 1000 (non-negative).
    pub throughput_milli: i32,
    /// Queue-delay penalty x 1000 (non-positive).
    pub queue_delay_milli: i32,
    /// Latency-lane sojourn penalty x 1000 (non-positive).
    pub latency_sojourn_milli: i32,
    /// Residual-loss penalty x 1000 (non-positive).
    pub residual_loss_milli: i32,
    /// Goodput jitter penalty x 1000 (non-positive).
    pub jitter_milli: i32,
    /// CPU penalty x 1000 (non-positive).
    pub cpu_milli: i32,
    /// Wire-overhead penalty x 1000 (non-positive).
    pub wire_overhead_milli: i32,
    /// Memory penalty x 1000 (non-positive).
    pub memory_milli: i32,
    /// Remote goodput the sample was computed from.
    pub goodput_bytes_per_second: u64,
}

impl HostUtilityV1 {
    /// Placeholder for a tick without a previous utility sample.
    pub fn unavailable(objective: ObjectiveV1) -> Self {
        Self {
            objective,
            ..Self::default()
        }
    }
}

/// Static bounds the host will enforce this tick. Candidates outside these
/// bounds are clamped and reported; the policy should treat them as the
/// action space. `0` in a `*_cap_*` field means "no cap".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLimitsV1 {
    /// Smallest PacketTrain target the scheduler accepts.
    pub train_target_floor_bytes: u32,
    /// Largest PacketTrain target the scheduler accepts.
    pub train_target_cap_bytes: u32,
    /// Smallest bulk quantum (>= 1).
    pub bulk_quantum_floor_cells: u16,
    /// Largest bulk quantum.
    pub bulk_quantum_cap_cells: u16,
    /// Smallest TX producer-admission buffer.
    pub send_buffer_floor_bytes: u64,
    /// Largest TX producer-admission buffer.
    pub send_buffer_cap_bytes: u64,
    /// Smallest RX reassembly buffer.
    pub receive_buffer_floor_bytes: u64,
    /// Largest RX reassembly buffer.
    pub receive_buffer_cap_bytes: u64,
    /// Largest RX batch (>= 1).
    pub receive_batch_cap: u16,
    /// Largest Repair cache.
    pub repair_cache_cap_bytes: u64,
    /// Largest FEC data cell count (floor is always 2).
    pub fec_data_cells_cap: u8,
    /// Largest FEC parity cell count.
    pub fec_parity_cells_cap: u8,
    /// Largest `parity / data` ratio.
    pub fec_parity_per_mille_cap: u16,
    /// Largest cover overhead.
    pub cover_overhead_cap_per_mille: u16,
    /// Largest cover padding rate.
    pub cover_padding_cap_bytes_per_second: u64,
    /// Node-wide pacing cap applied on top of any BBR candidate.
    pub pacing_cap_bytes_per_second: u64,
    /// Highest accepted egress priority.
    pub egress_priority_cap: u8,
    /// Largest `next_state`.
    pub state_cap_bytes: u32,
    /// Largest single extension payload.
    pub extension_payload_cap_bytes: u32,
    /// Largest number of extension entries.
    pub extension_count_cap: u16,
}

impl Default for HostLimitsV1 {
    /// Mirrors the host's `AutoTuneBoundsV2::default()` (the host crate
    /// asserts this in a test) plus the fixed FEC/extension budgets.
    fn default() -> Self {
        Self {
            train_target_floor_bytes: 8 * 1024,
            train_target_cap_bytes: 64 * 1024,
            bulk_quantum_floor_cells: 1,
            bulk_quantum_cap_cells: 8,
            send_buffer_floor_bytes: 512 * 1024,
            send_buffer_cap_bytes: 32 * 1024 * 1024,
            receive_buffer_floor_bytes: 8 * 1024 * 1024,
            receive_buffer_cap_bytes: 32 * 1024 * 1024,
            receive_batch_cap: 64,
            repair_cache_cap_bytes: 32 * 1024 * 1024,
            fec_data_cells_cap: FEC_DATA_CELLS_MAX,
            fec_parity_cells_cap: FEC_PARITY_CELLS_MAX,
            fec_parity_per_mille_cap: FEC_PARITY_PER_MILLE_CAP,
            cover_overhead_cap_per_mille: 50,
            cover_padding_cap_bytes_per_second: 0,
            pacing_cap_bytes_per_second: 0,
            egress_priority_cap: EGRESS_PRIORITY_MAX,
            state_cap_bytes: POLICY_STATE_MAX_BYTES,
            extension_payload_cap_bytes: POLICY_EXTENSION_MAX_PAYLOAD_BYTES,
            extension_count_cap: POLICY_EXTENSION_MAX_COUNT,
        }
    }
}

/// What this host offers to the policy this tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilitiesV1 {
    /// ABI major version of the host.
    pub abi_major: u16,
    /// ABI minor version of the host.
    pub abi_minor: u16,
    /// FEC domain is wired to the data plane.
    pub fec_supported: bool,
    /// Repair domain is wired to the data plane.
    pub repair_supported: bool,
    /// Cover domain is wired to the data plane.
    pub cover_supported: bool,
    /// The BBR candidate reaches a writable `Bbr3Tunables`.
    pub bbr_tunables_writable: bool,
    /// A node egress coordinator consumes `egress_request`.
    pub egress_coordinator: bool,
    /// This call is a shadow evaluation; the output will not be applied.
    pub shadow: bool,
    /// Extension tags present in `PolicyInputV1.extensions`.
    pub extension_tags: Vec<u16>,
}

impl Default for HostCapabilitiesV1 {
    fn default() -> Self {
        Self {
            abi_major: POLICY_ABI_MAJOR_V1,
            abi_minor: POLICY_ABI_MINOR_V1,
            fec_supported: true,
            repair_supported: true,
            cover_supported: true,
            bbr_tunables_writable: true,
            egress_coordinator: false,
            shadow: false,
            extension_tags: Vec::new(),
        }
    }
}

/// Node egress coordinator view for this peer. Read-only for the policy; it
/// can only submit an `EgressRequestV1`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressAllocationViewV1 {
    /// Rate the coordinator assigned to this peer last round (0 = no cap).
    pub assigned_rate_bytes_per_second: u64,
    /// Node-wide egress cap (0 = unlimited).
    pub node_cap_bytes_per_second: u64,
    /// Sum of desired rates across peers last round.
    pub node_demand_bytes_per_second: u64,
    /// `demand / cap` x 1000, saturating at `u16::MAX`; 0 when uncapped.
    pub pressure_per_mille: u16,
    /// Peers competing for node egress last round.
    pub active_peers: u32,
    /// Monotonic allocation round counter.
    pub allocation_generation: u64,
}

/// Everything a policy sees for one `decide` call. No endpoint identifiers,
/// wall clock, paths or secrets are included.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInputV1 {
    /// Monotonic per-peer tick counter; one tick per telemetry interval.
    pub logical_tick: u64,
    /// Seed derived by the host from `(policy_id, state_schema, peer,
    /// path_epoch)`; the only randomness source a guest may use.
    pub deterministic_seed: u64,
    /// Opaque peer bucket hash; stable for a peer, not invertible.
    pub peer_hash: [u8; 32],
    /// Path epoch; increments on path change and resets learner windows.
    pub path_epoch: u64,
    /// Underlay reliability of the current path.
    pub reliability: PathReliabilityV1,
    /// Filtered telemetry for this tick.
    pub telemetry: PolicyTelemetryV1,
    /// Effective action the host applied after the previous tick.
    pub previous: EffectiveActionViewV1,
    /// Host utility of the previous tick.
    pub previous_utility: HostUtilityV1,
    /// Bounds the host enforces this tick.
    pub limits: HostLimitsV1,
    /// Host feature set and extension tags.
    pub capabilities: HostCapabilitiesV1,
    /// Node egress view.
    pub egress: EgressAllocationViewV1,
    /// TLV extension bag; unknown tags must be ignored by the guest.
    pub extensions: Vec<PolicyExtensionV1>,
    /// Opaque policy state returned by the previous `decide` (empty on cold
    /// start or after a schema change).
    pub state: Vec<u8>,
}
