//! V2 control-plane status schema.
//!
//! These serializable DTOs are transport-neutral. They do not retain V1
//! counters, decoders, routing state, or reporter tasks.

use std::{fmt::Write as _, net::SocketAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::dns::DnsStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshNodeStatus {
    pub endpoint_id: String,
    pub sequence: u64,
    pub expires_unix_secs: u64,
    pub direct_addresses: Vec<SocketAddr>,
    pub node_addresses: Vec<IpNet>,
    pub prefixes: Vec<IpNet>,
    pub transit_enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MeshStatus {
    pub enabled: bool,
    pub directory_entries: usize,
    pub max_total_peers: usize,
    pub nodes: Vec<MeshNodeStatus>,
}

/// Live V2 gateway policy.  This is the policy currently owned by the running
/// dataplane, not a copy of an obsolete status file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayStatus {
    pub transit_enabled: bool,
    pub subnet_nat_enabled: bool,
    pub advertised_prefixes: Vec<IpNet>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeStatus {
    pub ready: bool,
    pub endpoint_id: String,
    pub started_unix: u64,
    pub updated_unix: u64,
    pub uptime_seconds: u64,
    #[serde(default = "default_true")]
    pub routes_ready: bool,
    #[serde(default)]
    pub routes: Vec<RouteStatus>,
    pub peers: Vec<PeerStatus>,
    #[serde(default)]
    pub mesh: MeshStatus,
    #[serde(default)]
    pub gateway: GatewayStatus,
    /// Records shed before next-hop attribution while the shared mesh TUN
    /// admission edge was overloaded.
    #[serde(default)]
    pub tun_admission_drop_records: u64,
    #[serde(default)]
    pub tun_admission_drop_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteStatus {
    pub prefix: String,
    pub present: bool,
}

/// Per-policy-slot state projected by the live V2 runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicySlotStatus {
    pub policy_id: String,
    /// Policy backend flavour (`native` or `wasm`).
    pub backend: String,
    pub policy_version: String,
    /// Policy ABI version (`major.minor`) the host speaks.
    pub abi_version: String,
    /// BLAKE3 digest of the policy module (empty for native).
    pub module_digest: String,
    /// Signer of the policy package signature (empty when unsigned).
    pub signer_id: String,
    /// Hot-swap generation of the policy module.
    pub module_generation: u64,
    /// Fault state machine (`healthy`, `degraded`, `quarantined`, or
    /// `shadow-warmup`).
    pub health: String,
    pub state_schema: u64,
    pub state_bytes: u64,
    pub last_call_micros: u64,
    /// Fuel consumed by the latest policy call (0 for native backends).
    pub fuel_consumed: u64,
    pub faults_total: u64,
    pub timeouts_total: u64,
    pub quarantines_total: u64,
    pub clamped_fields_total: u64,
    /// Recent distinct guardrail clamp reasons, comma separated, bounded.
    pub last_clamp_reasons: String,
}

/// Policy state owned by one peer. Both live and shadow slots reuse the same
/// canonical representation instead of maintaining mirrored scalar fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerPolicyStatus {
    pub live: PolicySlotStatus,
    pub policy_source: String,
    pub shadow: Option<PolicySlotStatus>,
    pub shadow_preset: String,
    pub shadow_advantage: f64,
}

/// Dataplane counters and gauges owned by one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerTrafficStatus {
    /// Original IP records admitted from the local TUN.
    pub tx_packets: u64,
    pub tx_bytes: u64,
    /// Completed IP records delivered to the local TUN.
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub trains_built: u64,
    pub cells_built: u64,
    pub data_cell_tx_datagrams: u64,
    pub full_payload_cells_built: u64,
    pub data_cell_tx_bytes: u64,
    pub cell_payload_tx_bytes: u64,
    pub unused_cell_capacity_bytes: u64,
    pub split_records_built: u64,
    pub fec_tx_cells: u64,
    pub fec_tx_bytes: u64,
    pub fec_rx_cells: u64,
    pub fec_recovered_cells: u64,
    pub fec_wasted_cells: u64,
    pub fec_expired_stripes: u64,
    pub fec_unprotected_tail_cells: u64,
    pub fec_encode_copy_bytes: u64,
    pub fec_decode_copy_bytes: u64,
    pub repair_requested_cells: u64,
    pub repair_suppressed_stripes: u64,
    pub repair_suppressed_cells: u64,
    pub repair_received_cells: u64,
    pub repair_completed_requests: u64,
    pub repair_latency_max_micros: u64,
    pub repair_stale_responses: u64,
    pub bulk_service_bytes: u64,
    pub latency_service_bytes: u64,
    pub bulk_preemptions: u64,
    pub packet_train_queue_bytes: u64,
    pub latency_queue_bytes: u64,
    pub receive_buffer_bytes: u64,
    pub cover_tx_bytes: u64,
    pub cover_rx_bytes: u64,
    pub control_tx_bytes: u64,
    pub control_rx_bytes: u64,
    pub protocol_datagram_errors: u64,
    pub route_gate_drops: u64,
    pub route_switches: u64,
    pub tun_admission_drop_records: u64,
    pub tun_admission_drop_bytes: u64,
    pub reassembly_pressure_evictions: u64,
    pub pmtu_drop_datagrams: u64,
    pub pmtu_drop_bytes: u64,
    pub gso_input_bytes: u64,
    pub gso_preserved_bytes: u64,
    pub gso_fallback_splits: u64,
    pub tun_mtu: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerStatus {
    pub name: String,
    pub endpoint_id: String,
    pub interface: String,
    #[serde(default)]
    pub protocol_major: u64,
    pub connected: bool,
    pub connection_events: u64,
    #[serde(default)]
    pub connection_errors: u64,
    #[serde(default)]
    pub traffic: PeerTrafficStatus,
    #[serde(default)]
    pub path_rtt_micros: u64,
    #[serde(default)]
    pub path_mtu: u64,
    #[serde(default)]
    pub path_cwnd_bytes: u64,
    #[serde(default)]
    pub selected_path_transport: String,
    #[serde(default)]
    pub selected_path_remote: String,
    #[serde(default)]
    pub open_paths: u64,
    #[serde(default)]
    pub tune_reason: String,
    #[serde(default)]
    pub fec_geometry: String,
    #[serde(default)]
    pub train_target_bytes: u64,
    #[serde(default)]
    pub bbr_preset: String,
    #[serde(default)]
    pub utility_total: f64,
    #[serde(default)]
    pub learner_mode: String,
    #[serde(default)]
    pub learner_context: String,
    #[serde(default)]
    pub learner_rollbacks: u64,
    #[serde(default)]
    pub policy: PeerPolicyStatus,
    /// Egress rate this peer requested from the node coordinator (bytes/s).
    #[serde(default)]
    pub egress_requested_bytes_per_second: u64,
    /// Egress rate the node coordinator assigned to this peer (bytes/s).
    #[serde(default)]
    pub egress_assigned_bytes_per_second: u64,
}

/// Render the live V2 runtime snapshot in Prometheus text exposition format.
/// Metric names intentionally start with `ironet_v2_`; none aliases the
/// removed V1 counter model.
pub fn render_prometheus(status: &RuntimeStatus) -> String {
    let mut out = String::new();
    let mut peers = status.peers.iter().collect::<Vec<_>>();
    peers.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
    macro_rules! scalar {
        ($name:literal, $kind:literal, $help:literal, $value:expr) => {{
            writeln!(out, concat!("# HELP ", $name, " ", $help)).unwrap();
            writeln!(out, concat!("# TYPE ", $name, " ", $kind)).unwrap();
            writeln!(out, concat!($name, " {}"), $value).unwrap();
        }};
    }
    macro_rules! peer_metric {
        ($name:literal, $kind:literal, $help:literal, $($field:ident).+) => {{
            writeln!(out, concat!("# HELP ", $name, " ", $help)).unwrap();
            writeln!(out, concat!("# TYPE ", $name, " ", $kind)).unwrap();
            for peer in &peers {
                writeln!(
                    out,
                    concat!($name, "{{endpoint_id=\"{}\",name=\"{}\"}} {}"),
                    prometheus_label(&peer.endpoint_id),
                    prometheus_label(&peer.name),
                    peer.$($field).+,
                )
                .unwrap();
            }
        }};
    }

    scalar!(
        "ironet_v2_ready",
        "gauge",
        "Whether the V2 runtime and every configured adjacency are ready.",
        u8::from(status.ready)
    );
    scalar!(
        "ironet_v2_routes_ready",
        "gauge",
        "Whether all required V2 kernel routes are installed.",
        u8::from(status.routes_ready)
    );
    scalar!(
        "ironet_v2_uptime_seconds",
        "gauge",
        "V2 runtime uptime in seconds.",
        status.uptime_seconds
    );
    scalar!(
        "ironet_v2_peers",
        "gauge",
        "Number of configured V2 peer adjacencies.",
        status.peers.len()
    );
    scalar!(
        "ironet_v2_connected_peers",
        "gauge",
        "Number of connected V2 peer adjacencies.",
        status.peers.iter().filter(|peer| peer.connected).count()
    );
    scalar!(
        "ironet_v2_tun_admission_drop_records_total",
        "counter",
        "Shared mesh TUN records shed before next-hop attribution.",
        status.tun_admission_drop_records
    );
    scalar!(
        "ironet_v2_tun_admission_drop_bytes_total",
        "counter",
        "Shared mesh TUN bytes shed before next-hop attribution.",
        status.tun_admission_drop_bytes
    );
    scalar!(
        "ironet_v2_presence_entries",
        "gauge",
        "Number of authenticated V2 Presence entries.",
        status.mesh.directory_entries
    );
    scalar!(
        "ironet_v2_gateway_transit_enabled",
        "gauge",
        "Whether this V2 node currently permits overlay transit.",
        u8::from(status.gateway.transit_enabled)
    );
    scalar!(
        "ironet_v2_gateway_subnet_nat_enabled",
        "gauge",
        "Whether this V2 node owns advertised-subnet NAT rules.",
        u8::from(status.gateway.subnet_nat_enabled)
    );
    scalar!(
        "ironet_v2_gateway_advertised_prefixes",
        "gauge",
        "Number of subnet prefixes currently advertised by this V2 node.",
        status.gateway.advertised_prefixes.len()
    );

    writeln!(
        out,
        "# HELP ironet_v2_gateway_advertised_prefix_info Advertised subnet owned by this V2 node."
    )
    .unwrap();
    writeln!(out, "# TYPE ironet_v2_gateway_advertised_prefix_info gauge").unwrap();
    let mut advertised_prefixes = status.gateway.advertised_prefixes.clone();
    advertised_prefixes
        .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
    for prefix in advertised_prefixes {
        writeln!(
            out,
            "ironet_v2_gateway_advertised_prefix_info{{prefix=\"{}\"}} 1",
            prometheus_label(&prefix.to_string())
        )
        .unwrap();
    }

    writeln!(
        out,
        "# HELP ironet_v2_route_present Whether a required kernel route is present."
    )
    .unwrap();
    writeln!(out, "# TYPE ironet_v2_route_present gauge").unwrap();
    let mut routes = status.routes.iter().collect::<Vec<_>>();
    routes.sort_by(|left, right| left.prefix.cmp(&right.prefix));
    for route in routes {
        writeln!(
            out,
            "ironet_v2_route_present{{prefix=\"{}\"}} {}",
            prometheus_label(&route.prefix),
            u8::from(route.present)
        )
        .unwrap();
    }

    writeln!(
        out,
        "# HELP ironet_v2_peer_info Stable V2 peer and selected QUIC path labels."
    )
    .unwrap();
    writeln!(out, "# TYPE ironet_v2_peer_info gauge").unwrap();
    for peer in &peers {
        writeln!(
            out,
            "ironet_v2_peer_info{{endpoint_id=\"{}\",name=\"{}\",interface=\"{}\",transport=\"{}\",remote=\"{}\",protocol_major=\"{}\"}} 1",
            prometheus_label(&peer.endpoint_id),
            prometheus_label(&peer.name),
            prometheus_label(&peer.interface),
            prometheus_label(&peer.selected_path_transport),
            prometheus_label(&peer.selected_path_remote),
            peer.protocol_major,
        )
        .unwrap();
    }

    writeln!(
        out,
        "# HELP ironet_v2_peer_connected Whether the V2 peer adjacency is connected."
    )
    .unwrap();
    writeln!(out, "# TYPE ironet_v2_peer_connected gauge").unwrap();
    for peer in &peers {
        writeln!(
            out,
            "ironet_v2_peer_connected{{endpoint_id=\"{}\",name=\"{}\"}} {}",
            prometheus_label(&peer.endpoint_id),
            prometheus_label(&peer.name),
            u8::from(peer.connected),
        )
        .unwrap();
    }
    peer_metric!(
        "ironet_v2_peer_connection_events_total",
        "counter",
        "Successful V2 peer connection events.",
        connection_events
    );
    peer_metric!(
        "ironet_v2_peer_connection_errors_total",
        "counter",
        "V2 peer connection errors.",
        connection_errors
    );
    peer_metric!(
        "ironet_v2_peer_tx_records_total",
        "counter",
        "Original IP records admitted from the local TUN.",
        traffic.tx_packets
    );
    peer_metric!(
        "ironet_v2_peer_tx_bytes_total",
        "counter",
        "Original IP bytes admitted from the local TUN.",
        traffic.tx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_rx_records_total",
        "counter",
        "Completed IP records delivered to the local TUN.",
        traffic.rx_packets
    );
    peer_metric!(
        "ironet_v2_peer_rx_bytes_total",
        "counter",
        "Completed IP bytes delivered to the local TUN.",
        traffic.rx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_packet_trains_total",
        "counter",
        "V2 PacketTrains built for transmission.",
        traffic.trains_built
    );
    peer_metric!(
        "ironet_v2_peer_cells_total",
        "counter",
        "V2 Cells built for transmission.",
        traffic.cells_built
    );
    peer_metric!(
        "ironet_v2_peer_data_cell_datagrams_total",
        "counter",
        "QUIC DATAGRAMs carrying V2 data Cells.",
        traffic.data_cell_tx_datagrams
    );
    peer_metric!(
        "ironet_v2_peer_full_payload_cells_total",
        "counter",
        "V2 data Cells whose payload filled the route/path Cell capacity.",
        traffic.full_payload_cells_built
    );
    peer_metric!(
        "ironet_v2_peer_data_cell_bytes_total",
        "counter",
        "Wire bytes in V2 data Cells.",
        traffic.data_cell_tx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_cell_payload_bytes_total",
        "counter",
        "Original payload bytes packed into V2 Cells.",
        traffic.cell_payload_tx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_unused_cell_capacity_bytes_total",
        "counter",
        "Unused payload capacity in emitted V2 Cells.",
        traffic.unused_cell_capacity_bytes
    );
    peer_metric!(
        "ironet_v2_peer_split_records_total",
        "counter",
        "IP records split across more than one V2 Cell.",
        traffic.split_records_built
    );
    peer_metric!(
        "ironet_v2_peer_fec_tx_cells_total",
        "counter",
        "FEC parity Cells transmitted.",
        traffic.fec_tx_cells
    );
    peer_metric!(
        "ironet_v2_peer_fec_tx_bytes_total",
        "counter",
        "FEC parity wire bytes transmitted.",
        traffic.fec_tx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_fec_rx_cells_total",
        "counter",
        "FEC parity Cells received.",
        traffic.fec_rx_cells
    );
    peer_metric!(
        "ironet_v2_peer_fec_recovered_cells_total",
        "counter",
        "Missing V2 Cells recovered by FEC.",
        traffic.fec_recovered_cells
    );
    peer_metric!(
        "ironet_v2_peer_fec_wasted_cells_total",
        "counter",
        "Received FEC parity Cells that were not needed.",
        traffic.fec_wasted_cells
    );
    peer_metric!(
        "ironet_v2_peer_fec_expired_stripes_total",
        "counter",
        "Expired incomplete FEC stripes.",
        traffic.fec_expired_stripes
    );
    peer_metric!(
        "ironet_v2_peer_fec_unprotected_tail_cells_total",
        "counter",
        "Tail Cells deliberately emitted without parity.",
        traffic.fec_unprotected_tail_cells
    );
    peer_metric!(
        "ironet_v2_peer_fec_encode_copy_bytes_total",
        "counter",
        "Bytes copied while encoding V2 FEC.",
        traffic.fec_encode_copy_bytes
    );
    peer_metric!(
        "ironet_v2_peer_fec_decode_copy_bytes_total",
        "counter",
        "Bytes copied while decoding V2 FEC.",
        traffic.fec_decode_copy_bytes
    );
    peer_metric!(
        "ironet_v2_peer_repair_requested_cells_total",
        "counter",
        "Missing Cells requested through reliable Repair.",
        traffic.repair_requested_cells
    );
    peer_metric!(
        "ironet_v2_peer_repair_suppressed_stripes_total",
        "counter",
        "Repair candidate stripes suppressed by the bounded sparse-hole gate.",
        traffic.repair_suppressed_stripes
    );
    peer_metric!(
        "ironet_v2_peer_repair_suppressed_cells_total",
        "counter",
        "Missing Cells left to the inner transport by the bounded Repair gate.",
        traffic.repair_suppressed_cells
    );
    peer_metric!(
        "ironet_v2_peer_repair_received_cells_total",
        "counter",
        "Repair Cells received.",
        traffic.repair_received_cells
    );
    peer_metric!(
        "ironet_v2_peer_repair_completed_requests_total",
        "counter",
        "Completed V2 Repair requests.",
        traffic.repair_completed_requests
    );
    peer_metric!(
        "ironet_v2_peer_repair_latency_max_microseconds",
        "gauge",
        "Maximum observed V2 Repair response latency.",
        traffic.repair_latency_max_micros
    );
    peer_metric!(
        "ironet_v2_peer_repair_stale_responses_total",
        "counter",
        "Unmatched or expired Repair responses.",
        traffic.repair_stale_responses
    );
    peer_metric!(
        "ironet_v2_peer_bulk_service_bytes_total",
        "counter",
        "Bytes served by the Bulk scheduler class.",
        traffic.bulk_service_bytes
    );
    peer_metric!(
        "ironet_v2_peer_latency_service_bytes_total",
        "counter",
        "Bytes served by the Latency scheduler class.",
        traffic.latency_service_bytes
    );
    peer_metric!(
        "ironet_v2_peer_bulk_preemptions_total",
        "counter",
        "Bulk quantums preempted by latency traffic.",
        traffic.bulk_preemptions
    );
    peer_metric!(
        "ironet_v2_peer_packet_train_queue_bytes",
        "gauge",
        "Bytes queued in V2 PacketTrains.",
        traffic.packet_train_queue_bytes
    );
    peer_metric!(
        "ironet_v2_peer_latency_queue_bytes",
        "gauge",
        "Bytes queued in the V2 Latency class.",
        traffic.latency_queue_bytes
    );
    peer_metric!(
        "ironet_v2_peer_receive_buffer_bytes",
        "gauge",
        "Current automatic V2 receive-memory budget.",
        traffic.receive_buffer_bytes
    );
    peer_metric!(
        "ironet_v2_peer_cover_tx_bytes_total",
        "counter",
        "V2 cover bytes transmitted.",
        traffic.cover_tx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_cover_rx_bytes_total",
        "counter",
        "V2 cover bytes received.",
        traffic.cover_rx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_control_tx_bytes_total",
        "counter",
        "Reliable V2 control bytes transmitted.",
        traffic.control_tx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_control_rx_bytes_total",
        "counter",
        "Reliable V2 control bytes received.",
        traffic.control_rx_bytes
    );
    peer_metric!(
        "ironet_v2_peer_protocol_datagram_errors_total",
        "counter",
        "Malformed V2 QUIC DATAGRAMs rejected.",
        traffic.protocol_datagram_errors
    );
    peer_metric!(
        "ironet_v2_peer_route_gate_drops_total",
        "counter",
        "V2 Cells rejected by the route-label gate.",
        traffic.route_gate_drops
    );
    peer_metric!(
        "ironet_v2_peer_route_switches_total",
        "counter",
        "Demand-aware flow lease switches to this first-hop peer.",
        traffic.route_switches
    );
    peer_metric!(
        "ironet_v2_peer_tun_admission_drop_records_total",
        "counter",
        "Local TUN records rejected by bounded admission.",
        traffic.tun_admission_drop_records
    );
    peer_metric!(
        "ironet_v2_peer_tun_admission_drop_bytes_total",
        "counter",
        "Local TUN bytes rejected by bounded admission.",
        traffic.tun_admission_drop_bytes
    );
    peer_metric!(
        "ironet_v2_peer_reassembly_pressure_evictions_total",
        "counter",
        "V2 PacketTrains evicted under receive-memory pressure.",
        traffic.reassembly_pressure_evictions
    );
    peer_metric!(
        "ironet_v2_peer_pmtu_drop_datagrams_total",
        "counter",
        "V2 DATAGRAMs rejected by the live PMTU ceiling.",
        traffic.pmtu_drop_datagrams
    );
    peer_metric!(
        "ironet_v2_peer_pmtu_drop_bytes_total",
        "counter",
        "V2 DATAGRAM bytes rejected by the live PMTU ceiling.",
        traffic.pmtu_drop_bytes
    );
    peer_metric!(
        "ironet_v2_peer_gso_input_bytes_total",
        "counter",
        "GSO bytes admitted from the local TUN.",
        traffic.gso_input_bytes
    );
    peer_metric!(
        "ironet_v2_peer_gso_preserved_bytes_total",
        "counter",
        "GSO bytes preserved end to end.",
        traffic.gso_preserved_bytes
    );
    peer_metric!(
        "ironet_v2_peer_gso_fallback_splits_total",
        "counter",
        "GSO records split by the fallback path.",
        traffic.gso_fallback_splits
    );
    peer_metric!(
        "ironet_v2_peer_tun_mtu_bytes",
        "gauge",
        "Configured V2 TUN MTU.",
        traffic.tun_mtu
    );
    peer_metric!(
        "ironet_v2_peer_path_rtt_microseconds",
        "gauge",
        "Selected QUIC path smoothed RTT.",
        path_rtt_micros
    );
    peer_metric!(
        "ironet_v2_peer_path_mtu_bytes",
        "gauge",
        "Selected QUIC path maximum UDP payload.",
        path_mtu
    );
    peer_metric!(
        "ironet_v2_peer_path_cwnd_bytes",
        "gauge",
        "Selected QUIC path congestion window.",
        path_cwnd_bytes
    );
    peer_metric!(
        "ironet_v2_peer_open_paths",
        "gauge",
        "Open QUIC paths for the V2 peer.",
        open_paths
    );
    peer_metric!(
        "ironet_v2_autotune_train_target_bytes",
        "gauge",
        "Current V2 autotune PacketTrain target in bytes.",
        train_target_bytes
    );
    peer_metric!(
        "ironet_v2_autotune_utility",
        "gauge",
        "Current signed V2 autotune utility.",
        utility_total
    );
    peer_metric!(
        "ironet_v2_autotune_rollbacks_total",
        "counter",
        "Number of V2 learner safety rollbacks.",
        learner_rollbacks
    );
    peer_metric!(
        "ironet_v2_autotune_shadow_advantage",
        "gauge",
        "Candidate shadow policy posterior advantage over the live baseline.",
        policy.shadow_advantage
    );
    peer_metric!(
        "ironet_v2_autotune_policy_faults_total",
        "counter",
        "Live policy backend decide faults (trap, timeout, invalid output, ...).",
        policy.live.faults_total
    );
    peer_metric!(
        "ironet_v2_autotune_policy_clamped_fields_total",
        "counter",
        "Candidate fields the host guardrails clamped for the live policy.",
        policy.live.clamped_fields_total
    );
    peer_metric!(
        "ironet_v2_autotune_policy_last_call_micros",
        "gauge",
        "Duration of the latest live policy decide call in microseconds.",
        policy.live.last_call_micros
    );
    peer_metric!(
        "ironet_v2_autotune_policy_state_bytes",
        "gauge",
        "Size of the live policy state blob carried between ticks.",
        policy.live.state_bytes
    );
    peer_metric!(
        "ironet_v2_autotune_policy_fuel_consumed",
        "gauge",
        "Fuel consumed by the latest live policy call (0 for native backends).",
        policy.live.fuel_consumed
    );
    peer_metric!(
        "ironet_v2_autotune_policy_timeouts_total",
        "counter",
        "Live policy decide calls that hit the deadline.",
        policy.live.timeouts_total
    );
    peer_metric!(
        "ironet_v2_autotune_policy_quarantines_total",
        "counter",
        "Times the live policy backend was quarantined.",
        policy.live.quarantines_total
    );
    peer_metric!(
        "ironet_v2_autotune_policy_module_generation",
        "gauge",
        "Hot-swap generation of the live policy module.",
        policy.live.module_generation
    );
    peer_metric!(
        "ironet_v2_peer_egress_requested_bytes_per_second",
        "gauge",
        "Egress rate the peer requested from the node coordinator.",
        egress_requested_bytes_per_second
    );
    peer_metric!(
        "ironet_v2_peer_egress_assigned_bytes_per_second",
        "gauge",
        "Egress rate the node coordinator assigned to the peer.",
        egress_assigned_bytes_per_second
    );

    writeln!(
        out,
        "# HELP ironet_v2_autotune_policy_info Live policy module identity."
    )
    .unwrap();
    writeln!(out, "# TYPE ironet_v2_autotune_policy_info gauge").unwrap();
    for peer in &peers {
        writeln!(
            out,
            "ironet_v2_autotune_policy_info{{endpoint_id=\"{}\",name=\"{}\",backend=\"{}\",module_digest=\"{}\",signer_id=\"{}\"}} 1",
            prometheus_label(&peer.endpoint_id),
            prometheus_label(&peer.name),
            prometheus_label(&peer.policy.live.backend),
            prometheus_label(&peer.policy.live.module_digest),
            prometheus_label(&peer.policy.live.signer_id),
        )
        .unwrap();
    }

    out
}

fn prometheus_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(character),
        }
    }
    escaped
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_output_is_v2_native_deterministic_and_escaped() {
        let status = RuntimeStatus {
            ready: true,
            routes_ready: true,
            uptime_seconds: 12,
            routes: vec![RouteStatus {
                prefix: "21.0.0.0/24".into(),
                present: true,
            }],
            peers: vec![PeerStatus {
                name: "edge\n\"a\\b".into(),
                endpoint_id: "endpoint-a".into(),
                interface: "ironet0".into(),
                protocol_major: 2,
                connected: true,
                traffic: PeerTrafficStatus {
                    tx_packets: 7,
                    rx_packets: 5,
                    trains_built: 3,
                    cells_built: 4,
                    ..PeerTrafficStatus::default()
                },
                selected_path_transport: "direct".into(),
                selected_path_remote: "ip:[2001:db8::1]:443".into(),
                ..PeerStatus::default()
            }],
            mesh: MeshStatus {
                enabled: true,
                directory_entries: 2,
                max_total_peers: 2,
                nodes: Vec::new(),
            },
            gateway: GatewayStatus {
                transit_enabled: true,
                subnet_nat_enabled: true,
                advertised_prefixes: vec!["10.0.0.0/24".parse().unwrap()],
            },
            ..RuntimeStatus::default()
        };
        let rendered = render_prometheus(&status);
        assert!(rendered.starts_with("# HELP ironet_v2_ready "));
        assert!(rendered.contains("ironet_v2_ready 1\n"));
        assert!(rendered.contains("ironet_v2_peer_tx_records_total{endpoint_id=\"endpoint-a\",name=\"edge\\n\\\"a\\\\b\"} 7\n"));
        assert!(rendered.contains(
            "ironet_v2_peer_connected{endpoint_id=\"endpoint-a\",name=\"edge\\n\\\"a\\\\b\"} 1\n"
        ));
        assert!(rendered.contains("ironet_v2_gateway_subnet_nat_enabled 1\n"));
        assert!(
            rendered
                .contains("ironet_v2_gateway_advertised_prefix_info{prefix=\"10.0.0.0/24\"} 1\n")
        );
        assert!(!rendered.contains("ironet_peer_"));
        assert!(!rendered.contains("capacity_probe"));
        assert!(!rendered.contains("recovery_shards"));
    }

    #[test]
    fn peer_status_serializes_traffic_and_policy_slots_as_nested_objects() {
        let peer = PeerStatus {
            name: "edge-a".into(),
            endpoint_id: "endpoint-a".into(),
            traffic: PeerTrafficStatus {
                tx_packets: 17,
                cell_payload_tx_bytes: 4_096,
                tun_mtu: 1_500,
                ..PeerTrafficStatus::default()
            },
            policy: PeerPolicyStatus {
                live: PolicySlotStatus {
                    policy_id: "builtin@1".into(),
                    backend: "native".into(),
                    policy_version: "1.0".into(),
                    abi_version: "1.0".into(),
                    module_digest: "digest-live".into(),
                    signer_id: "signer-live".into(),
                    module_generation: 4,
                    health: "healthy".into(),
                    state_schema: 1,
                    state_bytes: 96,
                    last_call_micros: 43,
                    fuel_consumed: 7,
                    faults_total: 2,
                    timeouts_total: 3,
                    quarantines_total: 5,
                    clamped_fields_total: 11,
                    last_clamp_reasons: "cwnd".into(),
                },
                policy_source: "builtin".into(),
                shadow: None,
                shadow_preset: String::new(),
                shadow_advantage: 0.0,
            },
            ..PeerStatus::default()
        };

        let value = serde_json::to_value(&peer).unwrap();
        assert_eq!(value["traffic"]["tx_packets"], 17);
        assert_eq!(value["traffic"]["tun_mtu"], 1_500);
        assert_eq!(value["policy"]["live"]["policy_id"], "builtin@1");
        assert_eq!(value["policy"]["live"]["backend"], "native");
        assert_eq!(value["policy"]["live"]["faults_total"], 2);
        assert_eq!(value["policy"]["policy_source"], "builtin");
        assert!(value["policy"]["shadow"].is_null());
        assert!(value.get("tx_packets").is_none());
        assert!(value.get("policy_id").is_none());

        let decoded: PeerStatus = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.traffic, peer.traffic);
        assert_eq!(decoded.policy, peer.policy);

        let mut unknown_traffic_field = value;
        unknown_traffic_field["traffic"]["obsolete_counter"] = serde_json::json!(1);
        assert!(serde_json::from_value::<PeerStatus>(unknown_traffic_field).is_err());
    }

    #[test]
    fn prometheus_keeps_metric_names_and_values_after_nested_projection() {
        let status = RuntimeStatus {
            peers: vec![PeerStatus {
                name: "edge-a".into(),
                endpoint_id: "endpoint-a".into(),
                traffic: PeerTrafficStatus {
                    tx_packets: 17,
                    ..PeerTrafficStatus::default()
                },
                policy: PeerPolicyStatus {
                    live: PolicySlotStatus {
                        backend: "wasm".into(),
                        module_digest: "digest-live".into(),
                        signer_id: "signer-live".into(),
                        faults_total: 7,
                        ..PolicySlotStatus::default()
                    },
                    shadow_advantage: 1.25,
                    ..PeerPolicyStatus::default()
                },
                ..PeerStatus::default()
            }],
            ..RuntimeStatus::default()
        };

        let rendered = render_prometheus(&status);
        assert!(rendered.contains(
            "ironet_v2_peer_tx_records_total{endpoint_id=\"endpoint-a\",name=\"edge-a\"} 17\n"
        ));
        assert!(rendered.contains(
            "ironet_v2_autotune_policy_faults_total{endpoint_id=\"endpoint-a\",name=\"edge-a\"} 7\n"
        ));
        assert!(rendered.contains(
            "ironet_v2_autotune_shadow_advantage{endpoint_id=\"endpoint-a\",name=\"edge-a\"} 1.25\n"
        ));
        assert!(rendered.contains(
            "ironet_v2_autotune_policy_info{endpoint_id=\"endpoint-a\",name=\"edge-a\",backend=\"wasm\",module_digest=\"digest-live\",signer_id=\"signer-live\"} 1\n"
        ));
    }
}
